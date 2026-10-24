"""Desktop workbench that projects and controls the existing pipeline."""
from __future__ import annotations

import json
import hashlib
import os
import platform
import time
import uuid
from types import SimpleNamespace
from datetime import datetime, timezone
from threading import Event
from pathlib import Path, PurePosixPath
from typing import Any

from PySide6.QtCore import QObject, QSettings, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtWidgets import (QComboBox, QDockWidget, QFileDialog, QHBoxLayout, QLabel, QVBoxLayout,
                               QListWidget, QMainWindow, QMessageBox, QPlainTextEdit,
                               QSplitter, QStackedWidget, QToolBar, QWidget, QPushButton, QLineEdit, QTabWidget)

from seclab.gui.controllers import ProjectController, VerificationController
from seclab.gui.pages import (DashboardPage, DynamicPage, CodeGenerationPage, FormalPage, FuzzingPage,
                               ModelPage, ReportPage, SpecificationPage, StaticPage,
                               RequirementsPage, SourcePage, StagesPage, SettingsPage)
from seclab.gui.pages.memory_page import MemoryPage
from seclab.gui.widgets import EvidenceViewer
from seclab.gui.i18n import (UI_TEXT, TECH_TERM, STATUS_HELP, MESSAGE_LABELS,
                             stage_label, status_label, log_label)
from seclab.gui.pages import AccuracyPage, EvidencePage, HistoryPage, ResultsPage, TraceabilityPage
from seclab.gui.pages.base import DataPage
from seclab.gui.session import SessionState, VerificationSession
from seclab.pipeline import PipelineOptions


def _read_fuzz_observations(report: Any, run_root: Path,
                            evidence_records: tuple[dict[str, Any], ...]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Load per-iteration observations while keeping filesystem work off the GUI thread."""
    manifest = {str(item.get("id", "")): item for item in evidence_records}
    stage = next((item for item in report.stage_summaries
                  if str(item.get("stage_id", "")).upper() == "FUZZING"), None)
    output = stage.get("output", {}) if stage else {}
    campaigns = output.get("campaigns", ()) if isinstance(output, dict) else ()
    if not campaigns and isinstance(output, dict) and output.get("strategy"):
        campaigns = (output,)
    observations: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    for campaign in campaigns:
        for record in campaign.get("execution_evidence", ()):
            evidence_id = str(record.get("evidence_id", ""))
            reference = manifest.get(evidence_id)
            if not reference:
                errors[evidence_id] = "Evidence ID is absent from run manifest."
                continue
            if reference.get("path") != record.get("path") or reference.get("hash") != record.get("sha256"):
                errors[evidence_id] = "Campaign evidence reference differs from the manifest."
                continue
            try:
                relative = PurePosixPath(str(reference["path"]))
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Evidence path is not a safe run-relative path.")
                path = (run_root / Path(*relative.parts)).resolve(strict=True)
                if not path.is_relative_to(run_root.resolve()):
                    raise ValueError("Evidence path escapes the run workspace.")
                payload = path.read_bytes()
                digest = hashlib.sha256(payload).hexdigest()
                if digest != reference.get("hash") or len(payload) != reference.get("size_bytes"):
                    raise ValueError("Evidence hash/size does not match the run manifest.")
                value = json.loads(payload.decode("utf-8"))
                if value.get("input_sha256") != record.get("input_sha256"):
                    raise ValueError("Observation input hash does not match campaign summary.")
                observations[evidence_id] = value
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                errors[evidence_id] = f"{type(exc).__name__}: {exc}"
    return observations, errors


def _default_workspace() -> Path:
    """Choose a persistent external run directory, preferring drive E on Windows."""
    override = os.environ.get("SECLAB_WORKSPACE")
    if override:
        return Path(override).expanduser().resolve()
    settings = QSettings("SecLab", "VerificationWorkbench")
    saved = settings.value("workspace", "", type=str).strip()
    if saved:
        return Path(saved).expanduser()
    if Path("E:/").is_dir():
        return Path("E:/seclab-verification-tool-runs")
    return Path.home() / ".seclab" / "runs"


def _specification_error_status(error: Exception) -> str:
    """Distinguish malformed native input from adapter dispatch failures."""
    from seclab.specification import SpecificationError, SpecificationErrorCode

    if isinstance(error, SpecificationError):
        return "FAILED"
    return "UNSUPPORTED" if "Unsupported explicit specification adapter" in str(error) else "FAILED"


class _RunWorker(QObject):
    progress = Signal(dict)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, controller: VerificationController, workspace: Path,
                 stages: tuple[str, ...] | None, options: PipelineOptions, cancellation_event: Event) -> None:
        super().__init__()
        self.controller, self.workspace, self.stages, self.options = controller, workspace, stages, options
        self.cancellation_event = cancellation_event

    @Slot()
    def run(self) -> None:
        try:
            callback = self.progress.emit
            if self.stages is None:
                report = self.controller.run_full(self.workspace, options=self.options,
                    cancellation_event=self.cancellation_event, progress_callback=callback)
            else:
                report = self.controller.run_stages(self.workspace, self.stages,
                    options=self.options, cancellation_event=self.cancellation_event,
                    progress_callback=callback)
            self.succeeded.emit(report)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.finished.emit()


class _BenchmarkWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, workspace: Path) -> None:
        super().__init__()
        self.workspace = workspace

    @Slot()
    def run(self) -> None:
        try:
            from seclab.benchmark.catalog import CASES
            from seclab.benchmark.production import execute_case
            from seclab.benchmark.runner import run_benchmark
            from seclab.benchmark.report import render_markdown

            execution_id = f"gui-{uuid.uuid4().hex}"
            run_root = self.workspace / "accuracy-benchmark" / execution_id
            run_metadata = {"execution_id": execution_id,
                "started_utc": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(), "python": platform.python_version()}
            report = run_benchmark(CASES, execute_case,
                workspace=run_root / "evidence", execution_id=execution_id,
                run_metadata=run_metadata)
            payload = report.to_dict()
            payload["run_metadata"] = run_metadata
            json_path = run_root / "benchmark-report.json"
            markdown_path = run_root / "benchmark-report.md"
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            markdown_path.write_text(render_markdown(payload), encoding="utf-8")
            self.succeeded.emit({"payload": payload, "json_path": str(json_path),
                                 "markdown_path": str(markdown_path)})
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.finished.emit()


class _HistoryWorker(QObject):
    loaded = Signal(object)
    finished = Signal()

    def __init__(self, controller: VerificationController, workspace: Path) -> None:
        super().__init__()
        self.controller, self.workspace = controller, workspace

    @Slot()
    def run(self) -> None:
        try:
            self.loaded.emit(self.controller.load_run_history(self.workspace))
        finally:
            self.finished.emit()


class _FuzzObservationWorker(QObject):
    loaded = Signal(str, object, object)
    finished = Signal()

    def __init__(self, report: Any, run_root: Path,
                 evidence_records: tuple[dict[str, Any], ...]) -> None:
        super().__init__()
        self.report, self.run_root, self.evidence_records = report, run_root, evidence_records

    @Slot()
    def run(self) -> None:
        try:
            observations, errors = _read_fuzz_observations(self.report, self.run_root, self.evidence_records)
            self.loaded.emit(self.report.run_id, observations, errors)
        except Exception as exc:
            self.loaded.emit(self.report.run_id, {}, {"*": f"{type(exc).__name__}: {exc}"})
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    PAGE_NAMES = (UI_TEXT["project"], UI_TEXT["specification"], UI_TEXT["requirements"], UI_TEXT["model"], UI_TEXT["codegen"],
                  UI_TEXT["formal"], UI_TEXT["static"], UI_TEXT["memory"], UI_TEXT["dynamic"],
                  UI_TEXT["coverage"], UI_TEXT["fuzzing"], UI_TEXT["results"], UI_TEXT["evidence"],
                  UI_TEXT["traceability"], UI_TEXT["accuracy"], UI_TEXT["report"], UI_TEXT["run_history"],
                  UI_TEXT["settings"])
    PAGE_STAGES = {UI_TEXT["model"]: ("MODEL",), UI_TEXT["codegen"]: ("CODEGEN", "BUILD"), UI_TEXT["formal"]: ("CTL", "BMC", "SMT"),
                   UI_TEXT["static"]: ("STATIC",), UI_TEXT["memory"]: ("MEMORY",),
                   UI_TEXT["dynamic"]: ("DYNAMIC",), UI_TEXT["coverage"]: ("COVERAGE",),
                   UI_TEXT["fuzzing"]: ("FUZZING",)}

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("SecLab — Bàn làm việc kiểm chứng")
        self.resize(1320, 860)
        self.project_controller = ProjectController()
        self.verification_controller = VerificationController(self.project_controller)
        self._workspace = _default_workspace()
        self.session = VerificationSession(workspace=self._workspace)
        self.verification_controller.workspace = self._workspace
        self._thread: QThread | None = None
        self._worker: _RunWorker | None = None
        self._benchmark_thread: QThread | None = None
        self._benchmark_worker: _BenchmarkWorker | None = None
        self._history_thread: QThread | None = None
        self._history_worker: _HistoryWorker | None = None
        self._history_reload_pending = False
        self._close_when_workers_finish = False
        self._fuzz_observation_thread: QThread | None = None
        self._fuzz_observation_worker: _FuzzObservationWorker | None = None
        self._fuzz_progress_timer = QTimer(self)
        self._fuzz_progress_timer.setSingleShot(True)
        self._fuzz_progress_timer.setInterval(80)
        self._fuzz_progress_timer.timeout.connect(self._flush_fuzz_progress)
        self._pending_fuzz_progress: dict[str, Any] | None = None
        self._live_result_records: dict[str, Any] = {}
        self._live_evidence_records: dict[str, dict[str, Any]] = {}
        self._live_static_evidence_loaded = False
        self._current_stage_status: dict[str, str] = {}
        self._last_log_index = 0
        self._log_lines: list[tuple[str, str]] = []
        self._log_view_cache_key: tuple[str, str, int] | None = None
        self._workflow_busy = False
        self._specification_reviewed = False
        self._build_ui()
        self._connect_ui()
        self.stages.runFullRequested.connect(self._run_full)
        self.stages.rerunRequested.connect(self._run_stage)
        self.stages.selectedStagesRequested.connect(self._run_selected_stages)
        self.stages.stageActivated.connect(self._show_stage_details)
        self.report_page.resultActivated.connect(self._open_result)
        self.report_page.accuracyReportRequested.connect(self._choose_accuracy_report)
        self._refresh_session_views()
        self.statusBar().showMessage(f"Thư mục chạy: {self._workspace}")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._history_thread is None:
            self._load_history_async()

    def closeEvent(self, event) -> None:
        """Do not destroy the window while one of its worker threads is alive."""
        threads = tuple(thread for thread in (
            self._thread, self._benchmark_thread, self._history_thread,
            self._fuzz_observation_thread,
        ) if thread is not None and thread.isRunning())
        if threads and getattr(self, "_cancellation_event", None) is not None:
            self._cancellation_event.set()
        for thread in threads:
            thread.quit()
        if threads:
            self._close_when_workers_finish = True
            event.ignore()
            self.statusBar().showMessage("Đang kết thúc tác vụ nền trước khi đóng cửa sổ.", 5000)
            return
        event.accept()

    def _close_after_workers_finish(self) -> None:
        if not self._close_when_workers_finish:
            return
        threads = (self._thread, self._benchmark_thread, self._history_thread,
                   self._fuzz_observation_thread)
        if any(thread is not None and thread.isRunning() for thread in threads):
            return
        self._close_when_workers_finish = False
        QTimer.singleShot(0, self.close)

    def _load_history_async(self) -> None:
        if self._history_thread is not None:
            # A live worker owns its controller/workspace snapshot. Avoid
            # overlapping scans when a new run finishes or the user switches
            # workspaces; its completion will trigger a fresh load if needed.
            self._history_reload_pending = True
            return
        self._history_reload_pending = False
        thread = QThread(self)
        worker = _HistoryWorker(self.verification_controller, self._workspace)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.loaded.connect(self._apply_history)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self._history_finished(thread))
        self._history_thread, self._history_worker = thread, worker
        thread.start()

    def _load_fuzz_observations(self, report: Any, run_root: Path,
                                evidence_records: tuple[dict[str, Any], ...]) -> None:
        if self._fuzz_observation_thread is not None:
            self._fuzz_observation_thread.requestInterruption()
        thread = QThread(self)
        worker = _FuzzObservationWorker(report, run_root, evidence_records)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.loaded.connect(self._apply_fuzz_observations)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: self._fuzz_observation_finished(thread))
        self._fuzz_observation_thread, self._fuzz_observation_worker = thread, worker
        thread.start()

    @Slot(str, object, object)
    def _apply_fuzz_observations(self, run_id: str, observations: dict[str, dict[str, Any]],
                                 errors: dict[str, str]) -> None:
        if self.session.run_id == run_id:
            self.fuzzing.set_execution_observations(observations, errors)

    def _fuzz_observation_finished(self, thread: QThread) -> None:
        if self._fuzz_observation_thread is thread:
            self._fuzz_observation_thread = None
            self._fuzz_observation_worker = None
        self._close_after_workers_finish()

    @Slot(object)
    def _apply_history(self, records) -> None:
        if self._history_worker and self._history_worker.workspace == self._workspace:
            self.report_page.set_history(records)
            self.history_page.set_history(records)

    def _history_finished(self, thread: QThread) -> None:
        if self._history_thread is thread:
            self._history_thread = None
            self._history_worker = None
            if getattr(self, "_history_reload_pending", False):
                self._load_history_async()
        self._close_after_workers_finish()

    def _build_ui(self) -> None:
        toolbar = QToolBar("Thanh công cụ")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self.project_label = QLabel("Chưa mở dự án")
        self._toolbar_actions = []
        toolbar.addWidget(self.project_label)
        toolbar.addSeparator()
        from PySide6.QtGui import QAction
        for label, slot in ((MESSAGE_LABELS["open_project"], self._choose_project),
                            (MESSAGE_LABELS["choose_specification"], self._choose_specification),
                            (MESSAGE_LABELS["workspace"], self._choose_workspace),
                            ("▶ " + MESSAGE_LABELS["run_all"], self._run_full)):
            action = QAction(label, self)
            action.triggered.connect(slot)
            toolbar.addAction(action)
            self._toolbar_actions.append(action)
        self.cancel_action = QAction(UI_TEXT["cancel_run"], self)
        self.cancel_action.setEnabled(False)
        self.cancel_action.triggered.connect(self._cancel_run)
        toolbar.addAction(self.cancel_action)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 4, 12, 4)
        header_layout.addWidget(QLabel("SECLAB  /  BÀN LÀM VIỆC KIỂM CHỨNG"))
        header_layout.addStretch(1)
        header_layout.addWidget(self.project_label)
        root_layout.addWidget(header)
        splitter = QSplitter()
        self.navigation = QListWidget()
        self.navigation.addItems(self.PAGE_NAMES)
        self.navigation.setFixedWidth(220)
        self.pages = QStackedWidget()
        self.dashboard = DashboardPage()
        self.specification = SpecificationPage()
        self.requirements = RequirementsPage()
        self.stages = StagesPage()
        self.source = SourcePage()
        self.model = ModelPage()
        self.codegen = CodeGenerationPage()
        self.formal = FormalPage()
        self.static = StaticPage()
        self.dynamic = DynamicPage()
        self.fuzzing = FuzzingPage()
        self.report_page = ReportPage()
        self.settings_page = SettingsPage()
        self.memory_page = MemoryPage()
        self.coverage_page = DataPage(UI_TEXT["coverage"], ("Giai đoạn (Stage)", "Chỉ số", "Giá trị", "Ghi chú"))
        self.results_page = ResultsPage()
        self.evidence_page = EvidencePage()
        self.traceability_page = TraceabilityPage()
        self.accuracy_page = AccuracyPage()
        self.history_page = HistoryPage()
        self.project_page = QWidget()
        project_layout = QVBoxLayout(self.project_page)
        project_layout.addWidget(QLabel("DỰ ÁN KIỂM CHỨNG"))
        self.project_info = QLabel("Dự án: Chưa xác thực\nĐặc tả: Chưa xác thực\nThư mục chạy: " + str(self._workspace))
        self.project_info.setWordWrap(True)
        project_layout.addWidget(self.project_info)
        self._project_controls = []
        for label, slot in (("Chọn thư mục dự án", self._choose_project),
                            ("Chọn tệp đặc tả JSON / Excel", self._choose_specification),
                            ("Chọn thư mục chạy", self._choose_workspace)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            project_layout.addWidget(button)
            self._project_controls.append(button)
        self.project_start = QPushButton("▶ Bắt đầu kiểm chứng")
        self.project_start.setMinimumHeight(44)
        self.project_start.clicked.connect(self._run_full)
        self.project_start.setEnabled(False)
        project_layout.addWidget(self.project_start)
        self.project_sources = QPlainTextEdit()
        self.project_sources.setReadOnly(True)
        self.project_sources.setPlaceholderText("Tệp mã nguồn sẽ xuất hiện sau khi chọn dự án.")
        project_layout.addWidget(self.project_sources, 1)
        self.project_tabs = QTabWidget()
        self.project_tabs.addTab(self.dashboard, "Tổng quan dự án")
        self.project_tabs.addTab(self.stages, "Tiến độ kiểm chứng")
        self.project_tabs.addTab(self.source, "Mã nguồn (Source)")
        project_layout.addWidget(self.project_tabs, 3)
        self.project_tabs.setMinimumHeight(360)
        project_layout.setStretch(0, 0)
        project_layout.setStretch(1, 0)
        self.page_widgets = (self.project_page, self.specification, self.requirements, self.model, self.codegen, self.formal,
                             self.static, self.memory_page, self.dynamic, self.coverage_page, self.fuzzing,
                             self.results_page, self.evidence_page, self.traceability_page,
                             self.accuracy_page, self.report_page, self.history_page, self.settings_page)
        for page in self.page_widgets:
            self.pages.addWidget(page)
        self._navigation_widgets = self.page_widgets
        splitter.addWidget(self.navigation)
        splitter.addWidget(self.pages)
        splitter.setStretchFactor(1, 1)
        root_layout.addWidget(splitter, 1)
        self.setCentralWidget(root)

        dock = QDockWidget("Nhật ký chạy", self)
        log_controls = QWidget()
        log_layout = QHBoxLayout(log_controls)
        log_layout.setContentsMargins(0, 0, 0, 0)
        self.log_level = QComboBox()
        self.log_level.addItem("Mọi mức", "ALL")
        for level in ("INFO", "WARNING", "ERROR", "DEBUG", "COMPLETED", "RUNNING", "SKIPPED", "FAILED"):
            self.log_level.addItem(status_label(level), level)
        self.log_filter = QLineEdit()
        self.log_filter.setPlaceholderText("Lọc nội dung nhật ký")
        clear_logs = QPushButton("Xóa")
        copy_logs = QPushButton("Sao chép")
        from PySide6.QtWidgets import QCheckBox
        self.log_autoscroll = QCheckBox("Tự cuộn")
        self.log_autoscroll.setChecked(True)
        for control in (self.log_level, self.log_filter, clear_logs, copy_logs, self.log_autoscroll):
            log_layout.addWidget(control)
        log_panel = QWidget()
        log_panel_layout = QVBoxLayout(log_panel)
        log_panel_layout.setContentsMargins(0, 0, 0, 0)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        log_panel_layout.addWidget(log_controls)
        log_panel_layout.addWidget(self.log_view)
        dock.setWidget(log_panel)
        clear_logs.clicked.connect(self._clear_logs)
        copy_logs.clicked.connect(self.log_view.copy)
        self.log_filter.textChanged.connect(self._set_log_filter)
        self.log_level.currentTextChanged.connect(self._set_log_filter)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        self._log_dock = dock
        self.statusBar().showMessage("Sẵn sàng")
        self.project_status = QLabel("Dự án: Chưa xác thực")
        self.spec_status = QLabel("Đặc tả: Chưa xác thực")
        self.run_status = QLabel("Lần chạy: —")
        self.stage_status = QLabel("Giai đoạn kiểm chứng: đang chờ")
        self.workflow_status = QLabel("Trạng thái: chưa có dự án")
        for label in (self.project_status, self.spec_status, self.run_status, self.stage_status,
                      self.workflow_status):
            self.statusBar().addPermanentWidget(label)
        self.navigation.setCurrentRow(0)

    def _connect_ui(self) -> None:
        self.navigation.currentRowChanged.connect(self._navigation_changed)
        self.dashboard.actionRequested.connect(self._dashboard_action)
        self.specification.actionRequested.connect(self._specification_action)
        self.specification.specificationChosen.connect(self._set_specification)
        self.report_page.evidenceActivated.connect(self._open_evidence)
        self.report_page.historyRequested.connect(self._load_history_run)
        self.report_page.evidenceVerifyRequested.connect(self._verify_evidence)
        self.fuzzing.evidenceActivated.connect(self._open_evidence)
        self.results_page.resultActivated.connect(self._open_result)
        self.evidence_page.evidenceActivated.connect(self._open_evidence)
        self.evidence_page.evidenceVerifyRequested.connect(self._verify_evidence)
        self.history_page.runActivated.connect(self._reopen_history_run)
        self.accuracy_page.reportRequested.connect(self._choose_accuracy_report)
        self.accuracy_page.runRequested.connect(self._run_accuracy_benchmark)
        self.codegen.runRequested.connect(self._run_with_codegen)
        self.fuzzing.runRequested.connect(self._run_with_fuzzing)

    def _run_with_codegen(self) -> None:
        self._run_full()

    def _run_with_fuzzing(self) -> None:
        self.settings_page.fuzz_enabled.setChecked(True)
        self._run_full()

    @Slot()
    def _choose_project(self) -> None:
        if self._thread is not None:
            return
        path = QFileDialog.getExistingDirectory(self, "Mở dự án", str(self.project_controller.project_path or Path.cwd()))
        if not path:
            return
        try:
            selected = self.project_controller.open_project(path)
        except Exception as exc:
            self.session.error = str(exc)
            self._show_error(exc)
            self._refresh_session_views()
            return
        self.specification.clear_file()
        self.specification.set_session_active(False)
        self.requirements.clear()
        self.session.open_project(selected, ())
        self.project_label.setText(str(selected))
        self.project_status.setText(f"Dự án: {selected.name}")
        self.spec_status.setText("Đặc tả: Chưa xác thực")
        self.project_info.setText(f"Dự án: {selected}\nXác thực dự án: Chưa xác thực\nĐặc tả: Chưa xác thực\nThư mục chạy: {self._workspace}")
        self.dashboard.set_project(str(selected), str(self.project_controller.specification_path or ""))
        self._refresh_session_views()
        self.statusBar().showMessage("Đã mở dự án", 4000)

    @Slot()
    def _choose_specification(self) -> None:
        if self._thread is not None:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Chọn đặc tả", "", "Đặc tả (*.json *.xlsx);;JSON (*.json);;Excel XLSX (*.xlsx)")
        if path:
            self._set_specification(path)

    @Slot(str)
    def _set_specification(self, path: str) -> None:
        if self._thread is not None:
            return
        try:
            # The session is authoritative; synchronize the legacy file controller
            # before it applies its own project-required guard.
            if self.session.project_path is None:
                QMessageBox.information(
                    self, "Chưa có dự án",
                    "Hãy mở một dự án trước khi chọn đặc tả.")
                return
            if self.project_controller.project_path != self.session.project_path:
                self.project_controller.open_project(self.session.project_path)
            selected = self.project_controller.select_specification(path)
            self.session.select_specification(selected)
            self.requirements.clear()
            loaded = self.project_controller.load()
            preview = self.project_controller.preview()
            self.specification.set_file(str(selected), preview)
            self._workflow_busy = True
            self._workflow_progress("LOAD_SPECIFICATION", "COMPLETED", f"Loaded {len(loaded.documents)} document(s)")
            self.project_controller.validate()
            self._workflow_progress("VALIDATE", "COMPLETED", "Specification schema and semantic checks completed")
            normalized = self.project_controller.normalize()
            adapter_info = self.project_controller.specification_info or {}
            self.session.set_validated_specification(normalized, loaded=self.project_controller.loaded,
                adapter_info={**adapter_info,
                    "raw_specification": self.project_controller.raw_specification})
            self.requirements.set_specification(normalized)
            self._workflow_progress("NORMALIZE", "COMPLETED", "Specification normalized in memory")
            self._workflow_progress("LEGACY_DETECTION",
                "COMPLETED" if adapter_info.get("adapter") else "NOT_APPLICABLE",
                f"Detected {adapter_info.get('format')} by document structure." if adapter_info.get("adapter") else
                "Native Specification Core document.")
            self._workflow_progress("LEGACY_ADAPTATION",
                "COMPLETED" if adapter_info.get("adapter") else "NOT_APPLICABLE",
                f"Mapped to canonical Specification schema {normalized.schema_version}." if adapter_info.get("adapter") else
                "No migration required.")
            self.session.model = self._preview_specification_model(normalized)
            if not self.session.model.get("states") and not self.session.model.get("transitions"):
                self.session.model.update(preview_status="NOT_APPLICABLE",
                    reason="Specification declares no state-machine elements; the model stage will be skipped.")
            preview_status = self.session.model.get("preview_status", "PREVIEW")
            self._workflow_progress("BUILD_SPECIFICATION_MODEL", preview_status,
                "Preview is derived only from normalized Specification states and transitions.")
            self._workflow_busy = False
            self._specification_reviewed = False
            self.specification.set_session_active(True)
            validation_message = (f"Legacy: {adapter_info.get('format')} · "
                f"Canonical ID: {normalized.id} · Schema: {normalized.schema_version} · Validation: PASS · "
                f"Adapter: {adapter_info.get('adapter')} · Source SHA-256: {adapter_info.get('original_sha256')} · "
                "Migration held in memory; original file unchanged"
                if adapter_info.get("adapter") else "Đặc tả hợp lệ và đã chuẩn hóa.")
            self.specification.set_validation(True, validation_message)
            self.spec_status.setText(f"Đặc tả: {status_label('READY FOR REVIEW')} — {selected.name}")
            self.project_info.setText(f"Dự án: {self.project_controller.project_path or 'Chưa xác thực'}\nĐặc tả: {selected}\nXác thực dự án: Chưa xác thực\nXác thực đặc tả: Chưa xác thực\nThư mục chạy: {self._workspace}")
            self.dashboard.set_project(str(self.project_controller.project_path or ""), str(selected))
            self.navigation.setCurrentRow(self.PAGE_NAMES.index(UI_TEXT["model"]))
            preview_model = self.session.model
            self.model.description.setText("Đang dựng mô hình trạng thái từ đặc tả…")
            QTimer.singleShot(0, lambda data=preview_model: self.model.show_specification_preview(data))
            self.statusBar().showMessage("Đặc tả đã chuẩn hóa; xem và duyệt model trước khi chạy pipeline", 6000)
            self._refresh_session_views()
        except Exception as exc:
            self._workflow_busy = False
            self.session.fail(f"{type(exc).__name__}: {exc}")
            self._specification_reviewed = False
            self.specification.set_session_active(False)
            status = _specification_error_status(exc)
            self._workflow_progress("LOAD_VALIDATE_NORMALIZE", status, str(exc))
            self._refresh_session_views()
            self.spec_status.setText(f"Đặc tả: {status}")
            self.specification.set_validation(False,
                f"{status}\nreason: {type(exc).__name__}: {exc}\n"
                f"evidence: {selected if 'selected' in locals() else path}\n"
                f"logs: {self.log_view.toPlainText()}")
            self._show_error(exc)

    @Slot()
    def _choose_workspace(self) -> None:
        if self._thread is not None:
            return
        path = QFileDialog.getExistingDirectory(self, "Chọn thư mục chạy", str(self._workspace))
        if path:
            self._workspace = Path(path).resolve()
            QSettings("SecLab", "VerificationWorkbench").setValue("workspace", str(self._workspace))
            self.session.workspace = self._workspace
            self.verification_controller.workspace = self._workspace
            self.project_info.setText(f"Dự án: {self.project_controller.project_path or 'Chưa xác thực'}\nĐặc tả: {self.project_controller.specification_path or 'Chưa xác thực'}\nThư mục chạy: {self._workspace}")
            self._load_history_async()
            self.statusBar().showMessage(f"Thư mục chạy: {self._workspace}", 5000)

    @Slot(str)
    def _dashboard_action(self, action: str) -> None:
        if action == "validate":
            self._specification_action("validate")
        elif action == "full":
            self._run_full()

    def _refresh_session_views(self) -> None:
        self.dashboard.set_session(self.session)
        self.stages.set_session(self.session)
        self.project_start.setEnabled(self.session.ready and self._thread is None)
        if self.session.project_path:
            project = self.session.project_path.name
        else:
            project = "Chưa chọn"
        if self.session.specification_path:
            specification = self.session.specification_path.name
        else:
            specification = "Chưa chọn"
        checks = [
            f"{'✓' if self.session.project_path else '○'} Dự án tồn tại",
            f"{'✓' if self.session.specification_path else '○'} Đặc tả đã chọn",
            f"{'✓' if self.session.normalized_specification else '○'} JSON / schema / kiểm tra ngữ nghĩa (semantic)",
            f"{'✓' if self.session.source_files else '○'} Mã nguồn được phát hiện ({len(self.session.source_files)} tệp)",
        ]
        self.project_status.setText(f"Dự án: {project}")
        self.spec_status.setText(f"Đặc tả: {specification}")
        self.run_status.setText(f"Mã lần chạy (Run ID): {self.session.run_id or '—'}")
        lifecycle = {
            SessionState.NO_PROJECT: "Chưa có dự án", SessionState.PROJECT_LOADED: "Đã mở dự án",
            SessionState.SPECIFICATION_LOADED: "Đang kiểm tra đặc tả", SessionState.VALIDATED: "Đã xác thực",
            SessionState.READY: "Sẵn sàng kiểm chứng", SessionState.RUNNING: "Đang kiểm chứng",
            SessionState.COMPLETED: "Hoàn tất", SessionState.PARTIAL: "Hoàn tất một phần",
            SessionState.ERROR: "Có lỗi · có thể thử lại",
        }
        self.workflow_status.setText(f"Trạng thái: {lifecycle[self.session.state]}")
        self.project_info.setText(
            f"Dự án: {self.session.project_path or project}\nĐặc tả: {self.session.specification_path or specification}\n"
            + "\n".join(checks) + "\n"
            f"Yêu cầu: {len(self.session.requirements)} · Thuộc tính: "
            f"{self.session.specification_info.get('properties', 0)} · "
            f"Mã nguồn: {len(self.session.source_files)} tệp\n"
            f"Trạng thái: {'Sẵn sàng kiểm chứng' if self.session.ready else lifecycle[self.session.state]}"
        )

    def _show_stage_details(self, stage_id: str) -> None:
        from seclab.gui.widgets import DetailDialog
        record = self.session.stage_results.get(stage_id, {"stage_id": stage_id, "status": "PENDING"})
        if record.get("status") in {"FAILED", "UNSUPPORTED", "ENVIRONMENT_LIMITED", "INCONCLUSIVE", "SKIPPED"}:
            record = {**record, "reason": record.get("reason") or record.get("output", {}).get("reason"),
                      "evidence": record.get("evidence_ids", ()), "logs": self.log_view.toPlainText()}
        DetailDialog(f"Stage · {stage_id}", record, self).exec()

    @Slot(str)
    def _specification_action(self, action: str) -> None:
        try:
            if action == "load":
                loaded = self.project_controller.load()
                self._workflow_progress("LOAD_SPECIFICATION", "COMPLETED", f"Loaded {len(loaded.documents)} document(s)")
                self.specification.set_validation(True, f"Loaded {len(loaded.documents)} specification document(s)")
            elif action == "validate":
                loaded = self.project_controller.validate()
                self._workflow_progress("VALIDATE", "COMPLETED", "Specification schema and semantic checks completed")
                self.spec_status.setText(f"Đặc tả: {status_label('VALIDATED')}")
                self.specification.set_validation(True, f"Đầu vào đặc tả hợp lệ ({len(loaded.documents)} tài liệu)")
                self.project_info.setText(f"Dự án: {self.project_controller.project_path or 'Chưa xác thực'}\nĐặc tả: {self.project_controller.specification_path}\nXác thực dự án: Chưa xác thực\nXác thực đặc tả: PASS — Hợp lệ\nThư mục chạy: {self._workspace}")
            elif action == "normalize":
                spec = self.project_controller.normalize()
                adapter_info = self.project_controller.specification_info or {}
                self.session.set_validated_specification(spec, loaded=self.project_controller.loaded,
                                                         adapter_info=adapter_info)
                self._workflow_progress("NORMALIZE", "COMPLETED", "Specification normalized in memory")
                self.spec_status.setText(f"Đặc tả: {status_label('READY FOR REVIEW')}")
                self.requirements.set_specification(spec)
                self.specification.set_validation(True, json.dumps(spec.to_dict(), ensure_ascii=False, indent=2))
                self.specification.preview.setPlainText(json.dumps(spec.to_dict(), ensure_ascii=False, indent=2))
                self._refresh_session_views()
        except Exception as exc:
            self.session.error = str(exc)
            status = _specification_error_status(exc)
            self._workflow_progress(action.upper(), status, str(exc))
            self.statusBar().showMessage("Thao tác với đặc tả thất bại", 5000)
            self._refresh_session_views()
            self.spec_status.setText(f"Đặc tả: {status}")
            self.project_info.setText(f"Dự án: {self.project_controller.project_path or 'Chưa xác thực'}\nXác thực đặc tả: ERROR — {type(exc).__name__}: {exc}\nThư mục chạy: {self._workspace}")
            # Keep the actionable diagnostic visible after session refresh.
            self.specification.set_validation(False,
                f"{status}\nreason: {type(exc).__name__}: {exc}\n"
                f"evidence: {self.session.specification_path or ''}\n"
                f"logs: {self.log_view.toPlainText()}")

    @Slot()
    def _run_full(self) -> None:
        self._start_run(None)

    def _build_review_model(self) -> None:
        """Preview only the model declared by the normalized Specification."""
        self.session.model = self._preview_specification_model(self.session.normalized_specification)
        preview_status = self.session.model.get("preview_status", "PREVIEW")
        if not self.session.model.get("states") and not self.session.model.get("transitions"):
            preview_status = "NOT_APPLICABLE"
            self.session.model.update(preview_status=preview_status,
                reason="Specification declares no state-machine elements; the model stage will be skipped.")
        self._workflow_progress("BUILD_SPECIFICATION_MODEL", preview_status,
            "Preview is derived only from normalized Specification states and transitions.")

    def _show_workflow_failure(self, stage: str, error: Exception) -> None:
        from seclab.gui.widgets import DetailDialog
        detail = {"stage_id": stage, "status": "FAILED", "reason": f"{type(error).__name__}: {error}",
                  "evidence": [], "logs": self.log_view.toPlainText()}
        self.session.update_workflow_step(detail)
        DetailDialog(f"{stage}: FAILED", detail, self).exec()

    @staticmethod
    def _preview_specification_model(specification: Any) -> dict[str, Any]:
        """Project the declared Specification graph; it is not inferred from source."""
        states = tuple({"id": item.id, "labels": list(item.labels),
                        "initial": item.id == specification.initial_state}
                       for item in specification.states)
        transitions = tuple({"id": item.id, "source": item.source, "target": item.target,
                             "label": item.label, "action": item.action}
                            for item in specification.transitions)
        initial = tuple(item["id"] for item in states if item.get("initial"))
        return {"states": states, "transitions": transitions, "initial_states": initial,
                "preview_status": "PREVIEW", "reason": "Review preview derived from normalized specification."}

    @Slot(str)
    def _run_stage(self, stage: str) -> None:
        # Stage reruns still reuse the open session context; the backend owns dependencies.
        self._start_run((stage,))

    @Slot(tuple)
    def _run_selected_stages(self, stages: tuple[str, ...]) -> None:
        self._start_run(stages)

    def _start_run(self, stages: tuple[str, ...] | None) -> None:
        self.session.reset_workflow()
        if self._thread is not None:
            self.statusBar().showMessage("Đang có một lần chạy kiểm chứng", 5000)
            return
        if self.session.project_path is None:
            QMessageBox.information(self, "Chưa chọn dự án", MESSAGE_LABELS["select_project"])
            return
        if self.session.specification_path is None:
            QMessageBox.information(self, "Chưa chọn đặc tả", MESSAGE_LABELS["select_specification"])
            return
        if not self.session.ready:
            QMessageBox.information(self, "Đặc tả chưa hợp lệ", MESSAGE_LABELS["invalid_specification"])
            return
        try:
            candidate_workspace = self._workspace.resolve()
            candidate_project = self.session.project_path.resolve()
            if candidate_workspace == candidate_project or candidate_workspace.is_relative_to(candidate_project):
                QMessageBox.critical(self, "Thư mục chạy không hợp lệ",
                                     "Thư mục lưu kết quả phải nằm ngoài thư mục mã nguồn của dự án.")
                return
        except OSError as exc:
            self._show_error(exc)
            return
        if not self._workspace.exists():
            try:
                self._workspace.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._show_error(exc)
                return
        try:
            spec_path = self.session.specification_path
            run_settings = self.settings_page.settings()
            options = run_settings.to_pipeline_options(spec_path)
            from dataclasses import replace
            options = replace(options, loaded_specification=self.project_controller.loaded,
                validated_specification=self.project_controller.validated_specification,
                normalized_specification=self.project_controller.specification,
                metadata={**options.metadata, "specification_provenance":
                          self.project_controller.specification_info or {},
                          "gui_run_configuration": {
                              "fuzz_enabled": run_settings.fuzz_enabled,
                              "fuzz_strategy": run_settings.fuzz_strategy,
                              "fuzz_iterations": run_settings.fuzz_iterations,
                              "fuzz_seed": run_settings.fuzz_seed,
                              "fuzz_config_created": options.fuzz_config is not None,
                          }})
            # Keep the exact run settings used in the session for history/review.
            self.session.specification_info["run_configuration"] = {
                "fuzz_config": str(options.fuzz_config) if options.fuzz_config else None,
            }
        except Exception as exc:
            self._show_error(exc)
            return
        self._current_stage_status.clear()
        self._live_result_records.clear()
        self._live_evidence_records.clear()
        self._live_static_evidence_loaded = False
        self.results_page.show_report(None)
        self.evidence_page.set_evidence(())
        self.formal.show_report(None)
        self.static.show_report(None)
        self.dynamic.show_report(None)
        self.codegen.show_report(None)
        self.static.load_evidence({"evidence": ()}, self._workspace)
        self.fuzzing.begin_run(options.fuzz_config)
        self._last_log_index = len(self.verification_controller.logs)
        self.session.workspace = self._workspace
        self.session.begin_run(stages or ("ALL",))
        self.stages.show_report(None)
        for label in self.dashboard.stage_labels:
            self.dashboard.stage_labels[label].setText(f"{label}\nChưa bắt đầu\nKết quả: Chưa kiểm tra")
            self._append_log("PIPELINE", "INFO", "Continuing the open project/specification workflow")
        self.run_status.setText("Lần chạy: ĐANG CHẠY")
        self.stage_status.setText("Giai đoạn kiểm chứng: đang chờ")
        self.statusBar().showMessage("Đang chạy kiểm chứng…")
        self._refresh_session_views()
        self._set_actions_enabled(False)
        self._thread = QThread(self)
        self._cancellation_event = Event()
        # Project and specification are already captured by the shared session.
        self.project_controller.project_path = self.session.project_path
        self.project_controller.specification_path = self.session.specification_path
        self._worker = _RunWorker(self.verification_controller, self._workspace, stages, options,
                                  self._cancellation_event)
        self._append_log("FUZZING", "INFO", f"GUI config: enabled={run_settings.fuzz_enabled}; "
                         f"strategy={run_settings.fuzz_strategy}; iterations={run_settings.fuzz_iterations}; "
                         f"seed={run_settings.fuzz_seed}; config_passed={options.fuzz_config is not None}")
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_stage_progress)
        self._worker.succeeded.connect(self._on_run_succeeded)
        self._worker.failed.connect(self._on_run_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._run_thread_finished)
        self._thread.start()

    @Slot()
    def _cancel_run(self) -> None:
        if self._cancellation_event is not None:
            self._cancellation_event.set()
            self.cancel_action.setEnabled(False)
            self.statusBar().showMessage("Đã yêu cầu dừng; giai đoạn đang chạy sẽ hoàn tất trước khi dừng.")

    @Slot(dict)
    def _on_stage_progress(self, stage: dict[str, Any]) -> None:
        progress_event = stage.get("progress_event")
        if progress_event:
            self._pending_fuzz_progress = progress_event
            target = progress_event.get("target") or progress_event.get("function_id") or "target"
            completed = progress_event.get("completed", progress_event.get("executed", 0))
            total = progress_event.get("requested", "?")
            current = progress_event.get("target_index", "?")
            count = progress_event.get("target_count", "?")
            self.statusBar().showMessage(f"Fuzzing · {target} · hàm {current}/{count} · lượt {completed}/{total}")
            event_name = str(progress_event.get("event", "")).lower()
            if event_name in {"target_finished", "fuzz_finished"}:
                self._flush_fuzz_progress()
            elif not self._fuzz_progress_timer.isActive():
                self._fuzz_progress_timer.start()
            return
        stage_results = tuple(stage.get("stage_results", ()))
        stage_evidence = tuple(stage.get("stage_evidence", ()))
        stage = {key: value for key, value in stage.items()
                 if key not in {"stage_results", "stage_evidence"}}
        stage_id = str(stage.get("stage_id", "UNKNOWN"))
        self.session.run_id = stage.get("run_id", self.session.run_id)
        self.session.update_stage(stage)
        if stage_results or stage_evidence:
            from seclab.results import VerificationResult

            for record in stage_results:
                result_id = str(record.get("id", ""))
                if result_id and result_id not in self._live_result_records:
                    self._live_result_records[result_id] = VerificationResult.from_dict(record)
            for record in stage_evidence:
                evidence_id = str(record.get("id", ""))
                if evidence_id:
                    self._live_evidence_records[evidence_id] = record
            self.results_page.append_live_results(stage_results)
            self.evidence_page.append_live_evidence(stage_evidence)
            self.session.evidence = tuple(self._live_evidence_records.values())
        if stage.get("status") in {"COMPLETED", "FAILED", "SKIPPED"}:
            self._render_live_stage(stage_id, stage)
        self.stage_status.setText(f"{stage_label(stage_id)} · {status_label(stage.get('status', 'RUNNING'))}")
        self._current_stage_status[stage_id] = str(stage.get("status", "UNKNOWN"))
        self._append_log(stage_id, str(stage.get("status", "INFO")), str(stage.get("reason") or "Stage finished"))
        if stage.get("status") in {"FAILED", "SKIPPED"}:
            self._append_log(stage_id, str(stage.get("status")),
                             f"reason={stage.get('reason') or 'No reason supplied'}; evidence={stage.get('evidence_ids', [])}; logs=see run log")
        self._append_controller_logs()
        # Stage records are rendered progressively, even before final report assembly.
        dashboard_progress = getattr(getattr(self, "dashboard", None), "set_stage_progress", None)
        if callable(dashboard_progress):
            dashboard_progress(stage_id, stage)
        stages_progress = getattr(getattr(self, "stages", None), "set_stage_progress", None)
        if callable(stages_progress):
            stages_progress(stage_id, stage)
        if stage_id == "FUZZING" and str(stage.get("status", "")).upper() == "RUNNING":
            begin_progress = getattr(getattr(self, "fuzzing", None), "begin_progress", None)
            if callable(begin_progress):
                begin_progress()
        if stage_id == "SOURCE":
            self._workflow_progress("SOURCE_DISCOVERY", str(stage.get("status", "UNKNOWN")),
                                    str(stage.get("reason") or stage.get("metadata", {})))
        if stage_id == "MODEL":
            self._workflow_progress("BUILD_SPECIFICATION_MODEL", str(stage.get("status", "UNKNOWN")),
                                    str(stage.get("reason") or stage.get("metadata", {})))
        if stage_id == "CODEGEN":
            self._workflow_progress("GENERATE_C", str(stage.get("status", "UNKNOWN")),
                                    str(stage.get("reason") or stage.get("metadata", {})))
        if stage_id == "BUILD":
            self._workflow_progress("BUILD_GENERATED_C", str(stage.get("status", "UNKNOWN")),
                                    str(stage.get("reason") or stage.get("metadata", {})))
        if stage_id in {"DYNAMIC", "COVERAGE", "FUZZING"}:
            self._workflow_progress({"DYNAMIC": "RUN_DYNAMIC_TESTS", "COVERAGE": "RUN_COVERAGE",
                                     "FUZZING": "RUN_FUZZING"}[stage_id],
                                    str(stage.get("status", "UNKNOWN")),
                                    str(stage.get("reason") or stage.get("metadata", {})))
        self.statusBar().showMessage(f"{stage_label(stage_id)}: {status_label(stage.get('status', 'RUNNING'))}")
        if stage_id == "SOURCE" and stage.get("status") in {"COMPLETED", "FAILED", "SKIPPED"}:
            self._refresh_session_views()

    def _render_live_stage(self, stage_id: str, stage: dict[str, Any]) -> None:
        """Render one completed stage from its real results while later stages continue."""
        summaries = tuple(self.session.stage_results.values())
        partial = SimpleNamespace(results=tuple(self._live_result_records.values()),
            stage_summaries=summaries, limitations=(), metadata={}, run_id=self.session.run_id or "RUNNING",
            duration_seconds=0.0, end_time=datetime.now(timezone.utc))
        run_root = (self._workspace / self.session.run_id).resolve() if self.session.run_id else None
        if stage_id in {"CTL", "BMC", "SMT"}:
            self.formal.show_report(partial)
        elif stage_id in {"STATIC", "MEMORY"}:
            if run_root is not None and stage_id == "STATIC" and not self._live_static_evidence_loaded:
                self.static.load_evidence({"evidence": tuple(self._live_evidence_records.values())}, run_root)
                self._live_static_evidence_loaded = True
            self.static.show_report(partial)
        elif stage_id in {"DYNAMIC", "COVERAGE"}:
            self.dynamic.show_report(partial)
        elif stage_id == "SOURCE":
            inventory_ref = next((item for item in self._live_evidence_records.values()
                                  if str(item.get("path", "")).endswith("source-inventory.json")), None)
            inventory = self._read_live_json(inventory_ref, run_root) if inventory_ref and run_root else None
            if inventory is not None:
                partial.metadata = {"source_inventory": inventory}
                self.source.show_report(partial)
                self.session.source_files = tuple(item.get("project_relative_path", "")
                                                  for item in inventory.get("files", ()))
                self.project_sources.setPlainText("\n".join(self.session.source_files))
        elif stage_id == "MODEL":
            model_ref = next((item for item in self._live_evidence_records.values()
                              if item.get("stage", "").upper() == "MODEL"
                              and str(item.get("path", "")).endswith("kripke.json")), None)
            model_data = self._read_live_json(model_ref, run_root) if model_ref and run_root else None
            if model_data is not None:
                self.session.model = model_data
                self.model.show_report(partial, model_data)
        elif stage_id in {"CODEGEN", "BUILD"}:
            self.codegen.show_report(partial, tuple(self._live_evidence_records.values()), run_root)

    @staticmethod
    def _read_live_json(evidence: dict[str, Any], run_root: Path) -> dict[str, Any] | None:
        try:
            relative = PurePosixPath(str(evidence.get("path", "")))
            if relative.is_absolute() or ".." in relative.parts:
                return None
            root = run_root.resolve(strict=True)
            selected = (root / Path(*relative.parts)).resolve(strict=True)
            if not selected.is_relative_to(root):
                return None
            payload = selected.read_bytes()
            if hashlib.sha256(payload).hexdigest() != evidence.get("hash"):
                return None
            value = json.loads(payload.decode("utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    @Slot(object)
    def _on_run_succeeded(self, report: Any) -> None:
        self.verification_controller.report = report
        self.session.complete_run(report)
        self.run_status.setText(f"Lần chạy: {report.run_id}")
        self.stage_status.setText("Giai đoạn kiểm chứng: hoàn tất")
        self._render_report(report)
        self._append_log("PIPELINE", "INFO", f"Run {report.run_id} report is ready")
        self._append_controller_logs()
        self.statusBar().showMessage(f"Lần chạy {report.run_id} đã hoàn tất", 8000)
        self._refresh_session_views()
        self._workflow_progress("VIEW_RESULTS", "COMPLETED", f"{len(report.results)} checker-scoped result(s) available.")
        self._workflow_progress("VIEW_EVIDENCE", "COMPLETED" if self.session.evidence else "UNSUPPORTED",
                                f"{len(self.session.evidence)} evidence item(s) available.")
        self._workflow_progress("VIEW_TRACEABILITY", "COMPLETED" if report.traceability else "UNRESOLVED",
                                f"{len(report.traceability)} requirement link(s) available.")
        self._workflow_progress("VIEW_REPORT", "COMPLETED", f"Run {report.run_id} report is available.")
        self._workflow_progress("SAVE_RUN_HISTORY", "COMPLETED" if report.run_id else "FAILED",
                                "Pipeline persisted report and manifest." if report.run_id else "Run ID is missing.")
        self._refresh_session_views()

    @Slot(str)
    def _on_run_failed(self, message: str) -> None:
        self.session.fail(message)
        self.run_status.setText(f"Lần chạy: {status_label('FAILED')}")
        self._append_log("PIPELINE", "ERROR", message)
        self.statusBar().showMessage("Kiểm chứng thất bại; xem Nhật ký chạy", 8000)
        error = {"stage_id": "PIPELINE", "error_type": "PipelineError", "reason": message,
                 "evidence": (), "logs": self.log_view.toPlainText()}
        show_error = getattr(self.dashboard, "show_error", None)
        if callable(show_error):
            show_error(error)
        else:
            self.dashboard.summary.setText(
                f"{status_label('FAILED')} · {message}")
            self.dashboard.input_summary.setText(
                "Pipeline thất bại. Xem Nhật ký chạy để biết chi tiết kỹ thuật.")
        self._workflow_progress("RUN_VERIFICATION", "FAILED", message)
        for step in ("VIEW_RESULTS", "VIEW_EVIDENCE", "VIEW_TRACEABILITY",
                     "VIEW_REPORT", "SAVE_RUN_HISTORY"):
            if self.session.workflow_step(step)["status"] == "NOT_RUN":
                self._workflow_progress(step, "SKIPPED", "Pipeline did not produce a run report.")
        from seclab.gui.widgets import DetailDialog
        DetailDialog(f"{status_label('FAILED')} · Kiểm chứng quy trình", {"status": "FAILED", "reason": message,
            "evidence": (), "logs": self.log_view.toPlainText()}, self).exec()
        self._refresh_session_views()

    @Slot()
    def _run_thread_finished(self) -> None:
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
        self._cancellation_event = None
        self._set_actions_enabled(True)
        self._close_after_workers_finish()

    def _render_report(self, report: Any) -> None:
        self.dashboard.set_project(str(self.session.project_path or ""),
                                   str(self.session.specification_path or self.session.specification_info.get("name", "")))
        self.dashboard.reset_stages()
        # Refreshing every hidden page builds potentially thousands of table
        # cells on the GUI thread. Pages render lazily when selected instead.
        current_page = self.pages.currentWidget()
        if current_page is not self.project_page and hasattr(current_page, "show_report"):
            current_page.show_report(report)
        coverage_stages = [stage for stage in report.stage_summaries if stage.get("stage_id") == "COVERAGE"]
        self.coverage_page.table.set_records([(stage_label(stage.get("stage_id", "")), key, value, stage.get("reason", ""))
            for stage in coverage_stages for key, value in stage.get("metadata", {}).items()])
        self.coverage_page.description.setText("Độ bao phủ (Coverage) là số đo thực thi; không phải kết luận về độ an toàn.")
        if self.session.normalized_specification is not None:
            self.requirements.set_specification(self.session.normalized_specification)
        else:
            self.requirements.clear()
        try:
            run_workspace = (self.verification_controller.workspace or self._workspace).resolve()
            run_root = (run_workspace / report.run_id).resolve(strict=True)
            if not run_root.is_relative_to(run_workspace):
                raise ValueError("Report run path escapes the selected workspace")
            manifest_path = (run_root / "evidence" / "manifest" / "run-manifest.json").resolve(strict=True)
            if not manifest_path.is_relative_to(run_root):
                raise ValueError("Run manifest path escapes the run workspace")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.settings_page.set_environment(manifest.get("environment", {}))
            records = tuple({**item, "created_at": item.get("timestamp", ""),
                             "size_bytes": item.get("size_bytes", ""),
                             "result_ids": [result.id for result in report.results
                                            if item.get("id", "") in result.evidence_ids]}
                            for item in manifest.get("evidence", ()))
            self._load_fuzz_observations(report, run_root, records)
            self.session.evidence = records
            self.static.load_evidence(manifest, run_root)
            model_ref = next((item for item in manifest.get("evidence", ())
                              if str(item.get("type", "")).upper() == "MODEL"
                              and str(item.get("stage", "")).upper() == "MODEL"
                              and str(item.get("path", "")).endswith("kripke.json")), None)
            if model_ref:
                model_path = (run_root / model_ref["path"]).resolve(strict=True)
                if model_path.is_relative_to(run_root):
                    self.session.model = json.loads(model_path.read_text(encoding="utf-8"))
            self.session.source_files = tuple(item.get("project_relative_path", "")
                for item in report.metadata.get("source_inventory", {}).get("files", ()))
            self.project_sources.setPlainText("\n".join(self.session.source_files) or "Không có mã nguồn được nạp trong lần chạy này.")
            self.session.traceability = dict(report.traceability)
        except (OSError, ValueError, TypeError):
            self.fuzzing.set_execution_observations({}, {"*": "Không tải được manifest/evidence cho lần chạy này."})
            self.report_page.set_evidence(())
            self.session.evidence = ()
            # Keep the CODEGEN stage visible even when its manifest cannot be
            # resolved; the page will report missing evidence instead of showing
            # a workspace path that may not exist.
        self._load_history_async()

    def _workflow_progress(self, stage: str, status: str, detail: str = "") -> None:
        """Present workflow bookkeeping only; verification decisions stay in the pipeline."""
        record = {"stage_id": stage, "status": status, "reason": detail,
                  "evidence_ids": self.session.stage_results.get(stage, {}).get("evidence_ids", ()),
                  "logs": "See run log"}
        self.session.update_workflow_step(record)
        if hasattr(self, "stages"):
            self.stages.set_workflow(self.session.workflow_steps)
        self._append_log(stage, status, detail or status)

    @Slot()
    def _flush_fuzz_progress(self) -> None:
        self._fuzz_progress_timer.stop()
        event, self._pending_fuzz_progress = self._pending_fuzz_progress, None
        if event is not None:
            update_progress = getattr(getattr(self, "fuzzing", None), "update_progress", None)
            if callable(update_progress):
                update_progress(event)

    def _set_actions_enabled(self, enabled: bool) -> None:
        for action in self._toolbar_actions:
            action.setEnabled(enabled)
        for control in self._project_controls:
            control.setEnabled(enabled)
        self.project_start.setEnabled(enabled and self.session.ready)
        self.dashboard.set_running(not enabled)
        self.stages.set_running(not enabled)
        self.specification.set_running(enabled)
        self.specification.set_session_active(self.session.specification_path is not None
                                              and self.session.state != SessionState.ERROR)
        self.settings_page.setEnabled(enabled)
        self.stages.set_session_ready(enabled and self.session.ready)
        self.cancel_action.setEnabled(not enabled)

    def _append_log(self, stage: str, level: str, message: str) -> None:
        from datetime import datetime
        self.log_view.appendPlainText(f"{datetime.now().astimezone().isoformat(timespec='seconds')}  {stage:<15} {level:<12} {message}")

    def _append_controller_logs(self) -> None:
        logs = self.verification_controller.logs
        for record in logs[self._last_log_index:]:
            self.log_view.appendPlainText(
                f"{record['timestamp']}  {record['stage']:<15} {record['level']:<12} {record['message']}"
            )
        self._last_log_index = len(logs)

    def _open_evidence(self, evidence_id: str) -> None:
        try:
            if self.session.report is not None:
                self.verification_controller.report = self.session.report
                self.verification_controller.workspace = self.session.workspace
            metadata = self.verification_controller.read_evidence_metadata(evidence_id)
            path = self.verification_controller.evidence_path(evidence_id)
            EvidenceViewer(metadata, path, self).exec()
        except Exception as exc:
            self._show_error(exc)

    def _open_result(self, result_id: str) -> None:
        report = self.session.current_run
        result = next((item for item in report.results if item.id == result_id), None) if report else None
        if result is not None:
            from seclab.gui.widgets import DetailDialog
            DetailDialog(f"Kết quả kiểm chứng (Verification Result) · {result.id}", result.to_dict(), self).exec()

    def _load_history_run(self, report_path: str, run_root: str) -> None:
        try:
            run_root_path = Path(run_root).resolve(strict=True)
            selected_report = Path(report_path).resolve(strict=True)
            workspace = self._workspace.resolve()
            if not run_root_path.is_relative_to(workspace) or not selected_report.is_relative_to(run_root_path):
                raise ValueError("Selected history run escapes the configured workspace")
            self._reopen_history_run(run_root_path.name)
        except Exception as exc:
            self._show_error(exc)

    def _reopen_history_run(self, run_id: str) -> None:
        try:
            report = self.verification_controller.reopen_run(self._workspace, run_id)
            self.session.open_saved_run(report, self._workspace)
            self.project_label.setText(str(self.session.project_path or ""))
            self._render_report(report)
            self._refresh_session_views()
            self.navigation.setCurrentRow(self.PAGE_NAMES.index(UI_TEXT["report"]))
        except Exception as exc:
            self._show_error(exc)

    @Slot()
    def _choose_accuracy_report(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Mở báo cáo benchmark / độ chính xác", "", "Báo cáo (*.md *.json)")
        if not path:
            return
        try:
            content = self.verification_controller.read_accuracy_report(path)
            self.report_page.set_accuracy_report(path, content)
            self.accuracy_page.show_accuracy_report(path, content)
            self.navigation.setCurrentRow(self.PAGE_NAMES.index(UI_TEXT["accuracy"]))
        except Exception as exc:
            self._show_error(exc)

    @Slot()
    def _run_accuracy_benchmark(self) -> None:
        if self._benchmark_thread is not None:
            return
        try:
            workspace = self._workspace.resolve()
            workspace.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._show_error(exc)
            return
        self.accuracy_page.set_benchmark_running()
        self._benchmark_thread = QThread(self)
        self._benchmark_worker = _BenchmarkWorker(workspace)
        self._benchmark_worker.moveToThread(self._benchmark_thread)
        self._benchmark_thread.started.connect(self._benchmark_worker.run)
        self._benchmark_worker.succeeded.connect(self._on_benchmark_succeeded)
        self._benchmark_worker.failed.connect(self._on_benchmark_failed)
        self._benchmark_worker.finished.connect(self._benchmark_thread.quit)
        self._benchmark_worker.finished.connect(self._benchmark_worker.deleteLater)
        self._benchmark_thread.finished.connect(self._benchmark_thread_finished)
        self._benchmark_thread.start()

    @Slot(object)
    def _on_benchmark_succeeded(self, result: dict[str, Any]) -> None:
        payload = result["payload"]
        json_path = result["json_path"]
        self.accuracy_page.show_benchmark_result(payload, json_path)
        self.report_page.set_accuracy_report(result["markdown_path"],
            Path(result["markdown_path"]).read_text(encoding="utf-8"))
        self.statusBar().showMessage(
            f"Benchmark xong: {payload.get('benchmark_count', 0)} fixture(s); report lưu tại {json_path}", 10000)

    @Slot(str)
    def _on_benchmark_failed(self, message: str) -> None:
        self.accuracy_page.run_button.setEnabled(True)
        self.accuracy_page.table.set_records((("FAILED", message, "Benchmark run error"),))
        self.accuracy_page.description.setText("Benchmark không hoàn tất. Chi tiết lỗi được hiển thị trong bảng.")
        self.statusBar().showMessage(f"Benchmark lỗi: {message}", 10000)

    @Slot()
    def _benchmark_thread_finished(self) -> None:
        if self._benchmark_thread is not None:
            self._benchmark_thread.deleteLater()
        self._benchmark_thread = None
        self._benchmark_worker = None
        self._close_after_workers_finish()

    def _show_error(self, error: Exception) -> None:
        QMessageBox.critical(self, "Không thể hoàn tất thao tác",
            f"Đã xảy ra lỗi khi thực hiện thao tác.\n\n{MESSAGE_LABELS['technical_detail']}: {type(error).__name__}: {error}")

    def _navigation_changed(self, row: int) -> None:
        if 0 <= row < len(self._navigation_widgets):
            page = self._navigation_widgets[row]
            self.pages.setCurrentWidget(page)
            report = self.session.report
            if report is not None and page is not self.project_page:
                if page is self.report_page:
                    page.show_report(report)
                    page.set_evidence(self.session.evidence)
                elif page is self.evidence_page:
                    page.set_evidence(self.session.evidence)
                elif page is self.source:
                    page.show_report(report)
                elif page is self.coverage_page:
                    coverage_stages = [stage for stage in report.stage_summaries
                                       if stage.get("stage_id") == "COVERAGE"]
                    page.table.set_records([
                        (stage_label(stage.get("stage_id", "")), key, value, stage.get("reason", ""))
                        for stage in coverage_stages
                        for key, value in stage.get("metadata", {}).items()])
                elif page is self.model:
                    page.show_report(report, self.session.model)
                elif page is self.codegen:
                    run_root = ((self.verification_controller.workspace or self._workspace) / report.run_id)
                    self.codegen.show_report(report, self.session.evidence, run_root)
                elif page is self.static:
                    run_root = ((self.verification_controller.workspace or self._workspace) / report.run_id)
                    manifest = {"evidence": self.session.evidence}
                    try:
                        page.load_evidence(manifest, run_root)
                    except (OSError, ValueError):
                        pass
                    page.show_report(report)
                elif page is self.history_page:
                    pass  # Preserve the independently loaded run history.
                elif page in {self.results_page, self.traceability_page}:
                    page.show_report(report)
                elif hasattr(page, "show_report"):
                    page.show_report(report)
            if self._thread is not None:
                # Browsing existing session data stays available while execution runs.
                self._refresh_session_views()

    def _list_project_sources(self, root: Path) -> tuple[str, ...]:
        try:
            files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
                           if path.is_file() and path.suffix.casefold() in {".c", ".h", ".cc", ".cpp", ".hpp"})
            self.project_sources.setPlainText("\n".join(files) if files else "Không tìm thấy tệp mã nguồn C/C++.")
            return tuple(files)
        except OSError as exc:
            self.project_sources.setPlainText(f"Không thể liệt kê mã nguồn: {exc}")
            return ()

    def _verify_evidence(self, evidence_id: str) -> None:
        result = self.verification_controller.verify_evidence(evidence_id)
        self.report_page.set_evidence_integrity(evidence_id, result["status"],
            result.get("error") or result.get("actual_sha256", ""))
        self.evidence_page.set_integrity(evidence_id, result["status"],
            result.get("error") or result.get("actual_sha256", ""))

    def _append_log(self, stage: str, level: str, message: str) -> None:
        from datetime import datetime
        line = f"{datetime.now().astimezone().isoformat(timespec='seconds')}  {log_label(stage, level, message)}"
        self._log_lines.append((level.upper(), line))
        self._log_view_cache_key = None
        self._set_log_filter()

    def _append_controller_logs(self) -> None:
        logs = self.verification_controller.logs
        for record in logs[self._last_log_index:]:
            line = f"{record['timestamp']}  {log_label(record['stage'], record['level'], record['message'])}"
            self._log_lines.append((record['level'].upper(), line))
        self._last_log_index = len(logs)
        if logs:
            self._log_view_cache_key = None
            self._set_log_filter()

    def _set_log_filter(self, _value: str = "") -> None:
        query = self.log_filter.text().casefold()
        selected = self.log_level.currentData()
        cache_key = (query, str(selected), len(self._log_lines))
        if cache_key == self._log_view_cache_key:
            return
        visible = (line for level, line in self._log_lines
                   if (selected == "ALL" or level == selected) and query in line.casefold())
        self.log_view.setPlainText("\n".join(visible))
        self._log_view_cache_key = cache_key
        if self.log_autoscroll.isChecked():
            from PySide6.QtGui import QTextCursor
            self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def _clear_logs(self) -> None:
        self._log_lines.clear()
        self._log_view_cache_key = None
        self.log_view.clear()
