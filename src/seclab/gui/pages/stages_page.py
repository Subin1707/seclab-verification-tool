from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QAbstractItemView, QLabel, QListWidget, QListWidgetItem,
                               QPushButton, QVBoxLayout, QWidget)

from .base import STAGES
from seclab.gui.i18n import stage_label, status_label


class StagesPage(QWidget):
    """Pipeline progress view; the backend orchestrator owns ordering/dependencies."""
    runFullRequested = Signal()
    rerunRequested = Signal(str)
    selectedStagesRequested = Signal(tuple)
    stageActivated = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.title = QLabel("Quy trình kiểm chứng (Pipeline)")
        self.title.setObjectName("pageTitle")
        layout.addWidget(self.title)
        self.progress = QLabel("Mở dự án và đặc tả hợp lệ để bắt đầu.")
        self.progress.setWordWrap(True)
        layout.addWidget(self.progress)
        self.current = QLabel("Chưa có lần chạy nào")
        layout.addWidget(self.current)
        self.items = QListWidget()
        self.items.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._records: dict[str, dict] = {}
        self._refresh()
        self.items.itemDoubleClicked.connect(self._activate)
        self.items.itemClicked.connect(self._select_stage)
        self.items.itemSelectionChanged.connect(lambda: self.run_selected.setEnabled(bool(self.items.selectedItems())))
        layout.addWidget(self.items, 1)
        self.workflow = QListWidget()
        self.workflow.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.workflow.setMaximumHeight(260)
        self.workflow.setToolTip("GUI workflow lifecycle; verification verdicts remain in checker results.")
        layout.addWidget(QLabel("GUI workflow lifecycle"))
        layout.addWidget(self.workflow)
        self.rerun_stage = QPushButton("Chạy lại giai đoạn đã chọn")
        self.rerun_stage.setEnabled(False)
        self.rerun_stage.clicked.connect(self._rerun)
        layout.addWidget(self.rerun_stage)
        self.run_selected = QPushButton("Chạy các giai đoạn đã chọn cùng điều kiện tiên quyết")
        self.run_selected.setEnabled(False)
        self.run_selected.clicked.connect(self._run_selected)
        layout.addWidget(self.run_selected)
        self.run_full = QPushButton("▶ Bắt đầu kiểm chứng")
        self.run_full.clicked.connect(self.runFullRequested.emit)
        layout.addWidget(self.run_full)

    def _refresh(self) -> None:
        self.items.clear()
        for index, stage in enumerate(STAGES, 1):
            record = self._records.get(stage, {})
            status = record.get("status", "PENDING")
            icon = {"COMPLETED": "✓", "RUNNING": "⏳", "SKIPPED": "—", "FAILED": "❌",
                    "PENDING": "○", "NOT_STARTED": "○"}.get(status, "○")
            detail = f"{record.get('duration_ms', 0) / 1000:.2f}s" if record.get("duration_ms") else "—"
            reason = f" · {record['reason']}" if record.get("reason") else ""
            item = QListWidgetItem(f"{index:02d}  {icon}  {stage_label(stage)}  ·  {status_label(status)}  ·  {detail}{reason}")
            item.setData(32, stage)
            item.setToolTip(f"{stage_label(stage)} [{stage}]\n{status_label(status)}\n{record.get('reason') or ''}")
            self.items.addItem(item)

    def set_stage_progress(self, stage_id: str, record: dict) -> None:
        self._records[stage_id] = dict(record)
        ordered = [stage for stage in STAGES if stage in self._records]
        current_index = ordered.index(stage_id) + 1 if stage_id in ordered else len(ordered)
        reason = str(record.get("reason") or "")
        evidence = ", ".join(record.get("evidence_ids", ()))
        tooltip = (f"{stage_label(stage_id)} [{stage_id}]\n{status_label(record.get('status', 'UNKNOWN'))}\n"
                   f"Lý do: {reason}\nBằng chứng: {evidence}\nNhật ký: xem nhật ký chạy")
        self.current.setToolTip(tooltip)
        self.current.setText(f"Đang thực hiện: {stage_label(stage_id)} · {current_index} / {len(STAGES)} giai đoạn\n{tooltip}")
        self.progress.setText("Đang kiểm chứng…")
        self._refresh()

    def show_report(self, report) -> None:
        if report is None:
            self.progress.setText("Mở dự án và đặc tả hợp lệ để bắt đầu.")
            self.current.setText("Chưa có lần chạy nào")
            return
        self._records = {str(item.get("stage_id", "")): dict(item) for item in report.stage_summaries}
        failed = any(item.get("status") == "FAILED" for item in report.stage_summaries)
        self.progress.setText("Lần chạy hoàn tất một phần." if failed else "Lần chạy đã hoàn tất.")
        self.current.setText(f"Mã lần chạy (Run ID): {report.run_id} · {report.duration_seconds:.2f}s")
        self._refresh()

    def set_running(self, running: bool) -> None:
        self.run_full.setEnabled(not running)
        self.rerun_stage.setEnabled(not running and bool(self.items.currentItem()))
        self.run_selected.setEnabled(not running and bool(self.items.selectedItems()))

    def set_session_ready(self, ready: bool) -> None:
        self.run_full.setEnabled(ready)

    def set_session(self, session) -> None:
        ready = session.ready
        self.run_full.setEnabled(ready)
        checks = session.validation_checks
        summary = (f"Dự án: {session.project_path or 'Chưa mở'}\n"
                   f"Đặc tả: {session.specification_path or 'Chưa chọn'}\n"
                   f"Kiểm tra: project {'✓' if checks.get('project') else '○'} · "
                   f"JSON/schema/semantic {'✓' if checks.get('semantic') else '○'} · "
                   f"Source {'✓' if checks.get('sources') else '—'}")
        self.progress.setText(summary if session.state.value != "RUNNING" else "Đang kiểm chứng…\n" + summary)
        self.set_workflow(session.workflow_steps)

    def set_workflow(self, steps: dict[str, dict]) -> None:
        self.workflow.clear()
        for name, record in steps.items():
            status = str(record.get("status", "NOT_RUN"))
            reason = str(record.get("reason") or "")
            evidence = ", ".join(str(item) for item in record.get("evidence_ids", ()))
            logs = str(record.get("logs") or "See run log")
            row = QListWidgetItem(f"{name} · {status}" + (f" · {reason}" if reason else ""))
            row.setToolTip(f"{name}\n{status}\nreason: {reason}\nevidence: {evidence}\nlogs: {logs}")
            self.workflow.addItem(row)

    def _activate(self, item: QListWidgetItem) -> None:
        self.stageActivated.emit(str(item.data(32)))

    def _select_stage(self, item: QListWidgetItem) -> None:
        self.rerun_stage.setEnabled(True)

    def _rerun(self) -> None:
        item = self.items.currentItem()
        if item is not None:
            self.rerunRequested.emit(str(item.data(32)))

    def _run_selected(self) -> None:
        selected = tuple(str(item.data(32)) for item in self.items.selectedItems())
        if selected:
            self.selectedStagesRequested.emit(selected)
