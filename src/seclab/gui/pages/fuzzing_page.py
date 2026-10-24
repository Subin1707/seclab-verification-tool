from __future__ import annotations

from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
                               QTabWidget, QVBoxLayout, QWidget, QPlainTextEdit)

from .base import DataPage
from seclab.gui.i18n import CHECKER_HELP, status_label
from seclab.gui.widgets import ReadOnlyTable


class FuzzFlowDiagram(QWidget):
    """Paint the selected, report-backed fuzz campaign and supported alternatives."""

    _STRATEGIES = ("BOUNDARY", "BLACKBOX", "MUTATION", "COVERAGE_GUIDED", "GRAMMAR", "CONCOLIC")
    _LABELS = {"BOUNDARY": "Boundary", "BLACKBOX": "Black-box", "MUTATION": "Mutation",
               "COVERAGE_GUIDED": "Coverage-guided", "GRAMMAR": "Grammar-based",
               "CONCOLIC": "White-box / Concolic"}
    _STATUS_COLORS = {"COMPLETED": "#d9edf8", "RUNNING": "#fff1b8", "READY": "#e7f2e8",
                      "FAILED": "#f4c7c3", "UNSUPPORTED": "#eadcf5", "NOT_SELECTED": "#f0f1f2",
                      "SKIPPED": "#f0f1f2", "NOT_RUN": "#f0f1f2", "WAITING": "#f4f5f6",
                      "INCONCLUSIVE": "#fce6cf"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(980, 340)
        self._statuses = {"TARGET": "NOT_RUN", "GENERATE": "NOT_RUN", "EXECUTION": "NOT_RUN",
                          "ORACLE": "NOT_RUN", "COVERAGE": "NOT_RUN", "CORPUS": "NOT_RUN",
                          "EVIDENCE": "NOT_RUN", **{item: "NOT_RUN" for item in self._STRATEGIES}}
        self._details: dict[str, str] = {}
        self._loop_progress = "Vòng lặp: sinh đầu vào → chạy chương trình → kiểm tra lỗi → cập nhật corpus."
        self._caption = "Mỗi chiến dịch chọn một chiến lược; các nhánh chưa chọn không được thực thi."

    def begin_progress(self) -> None:
        self._statuses.update({"TARGET": "RUNNING", "GENERATE": "NOT_RUN", "EXECUTION": "NOT_RUN",
            "ORACLE": "NOT_RUN", "CORPUS": "NOT_RUN", "EVIDENCE": "NOT_RUN"})
        self._progress_target = "Đang chuẩn bị danh sách hàm / ca kiểm thử"
        self._progress_counts = ""
        self._loop_progress = "Đang chuẩn bị mục tiêu trước khi bắt đầu vòng lặp."
        self._caption = "Tiến trình fuzzing trực tiếp · trạng thái nhận từ bộ máy thực thi."
        self.update()

    def update_progress(self, event: dict[str, Any]) -> None:
        event_name = str(event.get("event", "")).lower()
        if event_name == "target_started":
            self._statuses.update({key: "NOT_RUN" for key in
                ("GENERATE", "EXECUTION", "ORACLE", "CORPUS", "EVIDENCE")})
            self._statuses["TARGET"] = "RUNNING"
            self._loop_progress = "Đang chuẩn bị mục tiêu trước khi bắt đầu vòng lặp."
        elif event_name == "campaign_started":
            self._statuses.update({"TARGET": "COMPLETED", "GENERATE": "RUNNING"})
            self._loop_progress = f"BẮT ĐẦU VÒNG LẶP · yêu cầu {event.get('requested', '?')} lượt"
        elif event_name == "input_generated":
            self._statuses.update({"GENERATE": "COMPLETED", "EXECUTION": "RUNNING",
                                   "ORACLE": "NOT_RUN", "CORPUS": "NOT_RUN"})
            self._loop_progress = (f"LƯỢT {int(event.get('completed', 0) or 0) + 1}/"
                f"{event.get('requested', '?')} · đã sinh đầu vào {event.get('input_id', '—')}")
        elif event_name == "execution_completed":
            self._statuses.update({"EXECUTION": "COMPLETED", "ORACLE": "RUNNING"})
            self._loop_progress = (f"LƯỢT {event.get('completed', '?')}/{event.get('requested', '?')} · "
                f"đã chạy {event.get('executed', 0)} · phát hiện {event.get('failures', 0)}")
        elif event_name == "case_completed":
            self._statuses.update({"ORACLE": "COMPLETED", "CORPUS": "COMPLETED"})
            self._loop_progress = (f"Hoàn tất lượt {event.get('completed', '?')}/{event.get('requested', '?')} · "
                f"đầu vào duy nhất {event.get('unique_inputs', '—')} · phát hiện {event.get('failures', 0)}")
        elif event_name == "target_finished":
            if int(event.get("executed", 0) or 0) > 0:
                self._statuses.update({key: "COMPLETED" for key in
                    ("TARGET", "GENERATE", "EXECUTION", "ORACLE", "CORPUS")})
            else:
                terminal = "FAILED" if event.get("campaign_status") in {"BUILD_ERROR", "TOOL_ERROR"} else "UNSUPPORTED"
                self._statuses.update({"TARGET": "COMPLETED", "GENERATE": terminal,
                    "EXECUTION": terminal, "ORACLE": terminal, "CORPUS": terminal})
            self._statuses["EVIDENCE"] = "COMPLETED" if event.get("evidence_count") else "NOT_RUN"
            self._loop_progress = (f"KẾT THÚC VÒNG LẶP · {event.get('executed', 0)} lượt thực thi · "
                f"lý do dừng: {event.get('stop_reason', 'không rõ')}")
        elif event_name == "fuzz_finished":
            if int(event.get("executed", 0) or 0) > 0:
                self._statuses.update({key: "COMPLETED" for key in
                    ("TARGET", "GENERATE", "EXECUTION", "ORACLE", "CORPUS")})
            self._statuses["EVIDENCE"] = "COMPLETED" if event.get("evidence_count") else "NOT_RUN"
            self._loop_progress = (f"KẾT THÚC VÒNG LẶP · {event.get('executed', 0)} lượt thực thi · "
                f"phát hiện: {event.get('findings', event.get('failures', 0))} · "
                f"lý do dừng: {event.get('stop_reason', 'không rõ')}")
        target = event.get("target") or event.get("function_id") or event.get("test_case_id") or "target"
        self._progress_target = f"Mục tiêu {event.get('target_index', '?')}/{event.get('target_count', '?')} · {target}"
        done = event.get("completed", event.get("executed", 0))
        requested = event.get("requested", "?")
        self._progress_counts = f"{done}/{requested} lượt · {event.get('failures', 0)} phát hiện"
        if event_name in {"target_finished", "fuzz_finished"}:
            completed = event.get("completed_targets", event.get("target_index", 0))
            self._progress_counts = (f"{completed}/{event.get('target_count', 0)} mục tiêu · "
                f"{event.get('executed', 0)} lượt chạy · {event.get('findings', event.get('failures', 0))} phát hiện · "
                f"{event.get('stop_reason', '')}")
        self.update()

    def set_campaign(self, campaign: dict[str, Any] | None, source_ready: bool,
                     coverage_data: dict[str, Any] | None, evidence_count: int) -> None:
        self._statuses = {"TARGET": "NOT_RUN", "GENERATE": "NOT_RUN", "EXECUTION": "NOT_RUN",
                          "ORACLE": "NOT_RUN", "COVERAGE": "NOT_RUN", "CORPUS": "NOT_RUN",
                          "EVIDENCE": "NOT_RUN", **{item: "NOT_SELECTED" for item in self._STRATEGIES}}
        self._details = {}
        self._caption = "Mỗi chiến dịch chọn một chiến lược; các nhánh chưa chọn không được thực thi."
        if not campaign or not campaign.get("strategy"):
            self._caption = "Không có chiến dịch fuzzing nào trong báo cáo pipeline này."
            self._progress_target = "Chưa bắt đầu fuzzing."
            self._progress_counts = "Bật fuzzing và chạy pipeline để xem tiến độ trực tiếp."
            self._loop_progress = "Vòng lặp: sinh đầu vào → chạy → kiểm tra → cập nhật corpus → sinh đầu vào tiếp theo."

            self.update()
            return
        selected = str(campaign.get("strategy", "")).upper()
        iterations = int(campaign.get("iterations_executed", 0) or 0)
        failures = campaign.get("failures", ())
        finding_count = len(failures) if isinstance(failures, (list, tuple)) else 0
        selected_status = "COMPLETED" if iterations else "UNSUPPORTED"
        if selected == "CONCOLIC":
            selected_status = "UNSUPPORTED"
        elif campaign.get("errors") and not iterations:
            selected_status = "FAILED"
        if selected in self._STRATEGIES:
            self._statuses[selected] = selected_status
        self._statuses["TARGET"] = "COMPLETED"
        self._statuses["EXECUTION"] = "COMPLETED" if iterations else selected_status
        self._statuses["CORPUS"] = "COMPLETED" if iterations else selected_status
        self._statuses["EVIDENCE"] = "COMPLETED" if evidence_count else "WAITING"
        if selected == "COVERAGE_GUIDED":
            self._statuses["COVERAGE"] = "COMPLETED" if iterations else selected_status
        elif coverage_data and coverage_data.get("line_metrics"):
            self._statuses["COVERAGE"] = "READY"
        self._details = {
            "TARGET": "đã sẵn sàng mã nguồn/mẫu kiểm thử" if source_ready else "không có mã nguồn/mẫu kiểm thử",
            selected: f"{iterations} lượt thực thi · {finding_count} phát hiện duy nhất",
            "EXECUTION": f"đã chạy {iterations} đầu vào",
            "COVERAGE": (f"{len(campaign.get('coverage_delta', ())) } nhánh phản hồi"
                         if selected == "COVERAGE_GUIDED" else "chỉ đo lường; không dùng phản hồi để dẫn hướng"),
            "CORPUS": f"{campaign.get('corpus_size', 0)} đầu vào trong corpus · {campaign.get('stop_reason', '—')}",
            "EVIDENCE": f"{evidence_count} mục bằng chứng",
        }
        completed = "COMPLETED" if iterations else selected_status
        self._statuses.update({"GENERATE": completed, "ORACLE": completed})
        requested = campaign.get("iterations_requested", "?")
        self._loop_progress = (f"HOÀN TẤT VÒNG LẶP · {iterations}/{requested} lượt · "
            f"{finding_count} phát hiện · lý do dừng: {campaign.get('stop_reason', 'không rõ')}")
        if iterations:
            self._progress_target = campaign.get("target", campaign.get("function_id", ""))
            self._progress_counts = f"{iterations} lượt · {finding_count} phát hiện"
        if selected == "CONCOLIC":
            self._details[selected] = "CHƯA HỖ TRỢ · chưa truy vết nhánh / chạy lại đường đi cụ thể"
        elif selected == "GRAMMAR":
            self._details[selected] = f"đã chạy {iterations} đầu vào sinh theo ngữ pháp"
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("white"))
        title_font = QFont(self.font())
        title_font.setPointSize(12)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QColor("#172b3a"))
        painter.drawText(22, 28, "Fuzzing · tiến trình thực thi")
        painter.setFont(self.font())
        painter.setPen(QColor("#596b7b"))
        painter.drawText(22, 52, self._caption)
        nodes = (("TARGET", "Chọn hàm / ca kiểm thử"), ("GENERATE", "Sinh đầu vào"),
                 ("EXECUTION", "Chạy chương trình"), ("ORACLE", "Kiểm tra oracle / crash"),
                 ("CORPUS", "Cập nhật corpus"), ("EVIDENCE", "Lưu kết quả"))
        margin, top = 20, 86
        available = max(940, self.width() - margin * 2)
        width = min(210, max(135, (available - 5 * 14) // 6))
        gap = max(10, (available - 6 * width) // 5)
        x0 = margin
        rects = [(key, QRectF(x0 + index * (width + gap), top, width, 92), label)
                 for index, (key, label) in enumerate(nodes)]
        for (_, left, _), (_, right, _) in zip(rects, rects[1:]):
            self._arrow(painter, QPointF(left.right() + 1, left.center().y()),
                        QPointF(right.left() - 2, right.center().y()))
        for node in rects:
            self._node(painter, *node)
        painter.setPen(QColor("#476b53"))
        painter.drawText(22, 208, getattr(self, "_progress_target", ""))
        painter.drawText(22, 230, getattr(self, "_progress_counts", ""))
        corpus_rect = rects[4][1]
        generate_rect = rects[1][1]
        loop_start = QPointF(corpus_rect.center().x(), corpus_rect.bottom() + 2)
        loop_end = QPointF(generate_rect.center().x(), generate_rect.bottom() + 2)
        loop_y = 270
        loop_path = QPainterPath(loop_start)
        loop_path.lineTo(loop_start.x(), loop_y)
        loop_path.lineTo(loop_end.x(), loop_y)
        loop_path.lineTo(loop_end.x(), loop_end.y())
        loop_active = any(self._statuses.get(key) == "RUNNING"
                          for key in ("GENERATE", "EXECUTION", "ORACLE", "CORPUS"))
        loop_color = "#2679a8" if loop_active else "#397d55"
        painter.setPen(QPen(QColor(loop_color), 2.6))
        painter.drawPath(loop_path)
        painter.drawLine(loop_end, QPointF(loop_end.x() - 6, loop_end.y() + 9))
        painter.drawLine(loop_end, QPointF(loop_end.x() + 6, loop_end.y() + 9))
        painter.setPen(QColor(loop_color))
        painter.drawText(QRectF(loop_end.x() + 18, loop_y - 13,
                                max(120, loop_start.x() - loop_end.x() - 28), 22),
                         Qt.AlignmentFlag.AlignCenter, "VÒNG LẶP · ĐẦU VÀO TIẾP")
        painter.setPen(QColor("#476b53"))
        painter.drawText(22, 312, getattr(self, "_loop_progress", ""))
        painter.end()
    @staticmethod
    def _arrow(painter: QPainter, start: QPointF, end: QPointF) -> None:
        pen = QPen(QColor("#647786"), 2)
        painter.setPen(pen)
        painter.drawLine(start, end)
        painter.drawLine(end, QPointF(end.x() - 9, end.y() - 5))
        painter.drawLine(end, QPointF(end.x() - 9, end.y() + 5))

    def _node(self, painter: QPainter, key: str, rect: QRectF, title: str) -> None:
        state = self._statuses.get(key, "WAITING")
        border = {"RUNNING": "#2679a8", "COMPLETED": "#508b67", "FAILED": "#b9534b"}.get(state, "#82949c")
        painter.setPen(QPen(QColor(border), 2.8 if state == "RUNNING" else 1.6))
        painter.setBrush(QColor(self._STATUS_COLORS.get(state, "#f4f5f6")))
        painter.drawRoundedRect(rect, 12, 12)
        painter.setPen(QColor("#20313a"))
        font = QFont(self.font())
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect.adjusted(8, 8, -8, -38), Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, title)
        painter.setFont(self.font())
        painter.setPen(QColor("#52616b"))
        painter.drawText(rect.adjusted(6, rect.height() - 35, -6, -5), Qt.AlignmentFlag.AlignCenter,
                         _state_label(state))


class FuzzingPage(DataPage):
    runRequested = Signal()
    evidenceActivated = Signal(str)

    def __init__(self, parent=None):
        super().__init__("Kiểm thử mờ (Fuzzing)",
            ("Mục tiêu / hàm", "Seed", "Lượt chạy", "Đầu vào duy nhất", "Corpus", "Oracle lỗi",
             "Crash / hết thời gian", "Độ bao phủ mới", "Phát hiện", "Trạng thái / chi tiết"), parent)
        self.description.setText(CHECKER_HELP["FUZZING"])
        self.summary = QLabel("Chưa có chiến dịch fuzzing trong lần chạy hiện tại.", self)
        self.summary.setWordWrap(True)
        self.run_button = QPushButton("Bật fuzzing và chạy lại quy trình")
        self.run_button.clicked.connect(self.runRequested.emit)
        self.layout().insertWidget(2, self.summary)
        self.layout().insertWidget(3, self.run_button)

        self.tabs = QTabWidget(self)
        self.process_tab = QScrollArea(self.tabs)
        self.process_tab.setWidgetResizable(True)
        self.process_tab.setFrameShape(QFrame.Shape.NoFrame)
        process_content = QWidget()
        process_layout = QVBoxLayout(process_content)
        process_layout.setContentsMargins(10, 10, 10, 10)
        process_layout.setSpacing(10)
        self.flow_diagram = FuzzFlowDiagram()
        self.flow_diagram.setMinimumHeight(340)
        process_layout.addWidget(self.flow_diagram)
        self.finding_banner = QLabel("Báo cáo này chưa có lỗi cụ thể do fuzzing phát hiện.", process_content)
        self.finding_banner.setWordWrap(True)
        self.finding_banner.setMinimumHeight(44)
        self.finding_banner.setStyleSheet(
            "QLabel { background: #eef2f5; color: #253746; border-left: 6px solid #748796; "
            "padding: 9px 12px; font-weight: 600; }"
        )
        process_layout.addWidget(self.finding_banner)
        self.table.setParent(process_content)
        self.table.setMaximumHeight(170)
        self.table.setMinimumHeight(125)
        process_layout.addWidget(self.table)
        self.table.currentCellChanged.connect(self._show_selected_campaign)
        self.campaign_analysis = QPlainTextEdit(process_content)
        self.campaign_analysis.setReadOnly(True)
        self.campaign_analysis.setPlaceholderText("Chọn chiến dịch để xem phạm vi, kết quả oracle, độ bao phủ, lỗi và bằng chứng phát hiện.")
        self.campaign_analysis.setMinimumHeight(220)
        process_layout.addWidget(self.campaign_analysis)
        process_layout.addStretch(1)
        self.process_tab.setWidget(process_content)
        self.coverage_table = ReadOnlyTable(("Chỉ số", "Tệp", "Đã bao phủ", "Còn thiếu", "Tỷ lệ", "Công cụ", "Giới hạn"))
        self.coverage_description = QLabel("Độ bao phủ là phép đo trên các đầu vào đã chạy; không phải kết luận về an toàn. Black-box quan sát input/output/crash/timeout; white-box cần instrumentation. Vòng fuzz là số lượt thực thi, không phải vòng lặp trong target.")
        self.coverage_description.setWordWrap(True)
        coverage_tab = QWidget()
        coverage_layout = QVBoxLayout(coverage_tab)
        coverage_layout.addWidget(self.coverage_description)
        coverage_layout.addWidget(self.coverage_table, 1)
        self.technique_table = ReadOnlyTable(("Checker / strategy", "Khả năng / trạng thái chạy", "Kết quả", "Evidence", "Phạm vi / phản hồi"))
        self.cfg_description = QLabel("Mô hình trạng thái và chuyển tiếp được chiếu từ Đặc tả đã chuẩn hóa.")
        self.cfg_description.setWordWrap(True)
        self.cfg_table = ReadOnlyTable(("Vị trí mã nguồn", "Trạng thái mô hình", "Chuyển tiếp", "Nguồn gốc / trạng thái"))
        cfg_tab = QWidget()
        cfg_layout = QVBoxLayout(cfg_tab)
        cfg_layout.addWidget(self.cfg_description)
        cfg_layout.addWidget(self.cfg_table, 1)
        self.tabs.addTab(self.process_tab, "Quy trình")
        self.tabs.addTab(coverage_tab, "Độ bao phủ")
        self.tabs.addTab(self._table_tab(self.technique_table), "So sánh kỹ thuật")
        self.tabs.addTab(cfg_tab, "Bản đồ dòng / CFG (mã C)")
        self.execution_evidence_table = ReadOnlyTable(("Lượt", "Mã đầu vào", "SHA-256 đầu vào",
            "Phân loại", "Kết quả", "Đã chạy", "Mã bằng chứng", "SHA-256 tệp bằng chứng"))
        self.execution_evidence_table.cellDoubleClicked.connect(self._open_execution_evidence)
        evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(evidence_tab)
        evidence_layout.addWidget(QLabel(
            "Mỗi dòng là kết quả quan sát được lưu cho một đầu vào. Nhấp đúp để mở tệp bằng chứng; Workbench kiểm tra SHA-256 theo manifest trước khi đọc."))
        evidence_layout.addWidget(self.execution_evidence_table, 1)
        self.execution_evidence_table.currentCellChanged.connect(self._show_selected_execution)
        self.execution_analysis = QPlainTextEdit(evidence_tab)
        self.execution_analysis.setReadOnly(True)
        self.execution_analysis.setPlaceholderText("Chọn một lượt để xem đầu vào đã gửi, oracle kỳ vọng và kết quả thực tế.")
        self.execution_analysis.setMinimumHeight(180)
        evidence_layout.addWidget(self.execution_analysis, 2)
        self.tabs.addTab(evidence_tab, "Bằng chứng từng lượt")
        self.layout().addWidget(self.tabs, 1)
        self._ready_report(None)
        self._campaign_records: list[dict[str, Any]] = []
        self._execution_records: list[dict[str, Any]] = []
        self._execution_observations: dict[str, dict[str, Any]] = {}
        self._execution_observation_errors: dict[str, str] = {}

    def begin_progress(self) -> None:
        """Expose the flow widget's live-run API to MainWindow."""
        self.flow_diagram.begin_progress()

    def begin_run(self, fuzz_config: Any | None) -> None:
        """Clear the previous report and show the effective configuration for this run."""
        self.tabs.setCurrentWidget(self.process_tab)
        self.table.set_records(())
        self.coverage_table.set_records(())
        self.technique_table.set_records(())
        self.cfg_table.set_records(())
        self.execution_evidence_table.set_records(())
        self.campaign_analysis.clear()
        self.execution_analysis.clear()
        self._campaign_records = []
        self._execution_records = []
        self._execution_observations = {}
        self._execution_observation_errors = {}
        self.campaign_analysis.clear()
        self.execution_analysis.clear()
        if fuzz_config is None:
            self.summary.setText("FUZZING · DISABLED · Cấu hình fuzzing không được gửi tới pipeline.")
            self.flow_diagram.set_campaign(None, False, {}, 0)
            return
        self.summary.setText(
            f"FUZZING · RUNNING · strategy={fuzz_config.strategy.value} · "
            f"budget={fuzz_config.max_iterations} lượt / target · seed={fuzz_config.random_seed} · "
            "Đang chờ pipeline tới stage Fuzzing."
        )
        self.begin_progress()

    def update_progress(self, event: dict[str, Any]) -> None:
        """Forward pipeline fuzz events to the process diagram."""
        self.flow_diagram.update_progress(event)
        event_name = str(event.get("event", "")).lower()
        target = event.get("target") or event.get("function_id") or event.get("test_case_id") or "target"
        target_index = event.get("target_index", "?")
        target_count = event.get("target_count", "?")
        completed = event.get("completed", event.get("executed", 0))
        requested = event.get("requested", "?")
        self.summary.setText(
            f"FUZZING · RUNNING · target {target_index}/{target_count}: {target} · "
            f"{completed}/{requested} lượt · event={event_name or 'progress'}"
        )

    @staticmethod
    def _table_tab(table: ReadOnlyTable) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(table, 1)
        return tab

    def _open_execution_evidence(self, row: int, _column: int) -> None:
        item = self.execution_evidence_table.item(row, 6)
        if item is not None and item.text():
            self.evidenceActivated.emit(item.text())

    def _render_execution_evidence(self, campaigns: Any) -> None:
        if isinstance(campaigns, dict):
            campaigns = (campaigns,)
        rows = []
        self._execution_records = []
        for campaign in campaigns or ():
            for record in campaign.get("execution_evidence", ()):
                self._execution_records.append(dict(record))
                rows.append((record.get("iteration", "—"), record.get("input_id", "—"),
                    record.get("input_sha256", "—"), record.get("classification", "—"),
                    record.get("result_status", "—"), record.get("executed", False),
                    record.get("evidence_id", "—"), record.get("sha256", "—")))
        self.execution_evidence_table.set_records(tuple(rows))
        self.execution_analysis.setPlainText(
            f"Có {len(rows)} lượt có observation đã lưu. Chọn một lượt để xem chi tiết; nhấp đúp vào dòng để mở artifact đã kiểm SHA-256.")
        if rows:
            self.execution_evidence_table.setCurrentCell(0, 0)

    def set_execution_observations(self, observations: dict[str, dict[str, Any]],
                                   errors: dict[str, str] | None = None) -> None:
        self._execution_observations = dict(observations)
        self._execution_observation_errors = dict(errors or {})
        row = self.execution_evidence_table.currentRow()
        if row >= 0:
            self._show_selected_execution(row, 0, -1, -1)
        elif "*" in self._execution_observation_errors:
            self.execution_analysis.setPlainText(self._execution_observation_errors["*"])

    def _show_selected_campaign(self, row: int, _column: int, _previous_row: int, _previous_column: int) -> None:
        if not 0 <= row < len(self._campaign_records):
            return
        campaign = self._campaign_records[row]
        result = campaign.get("verification_result") or {}
        lines = [
            f"KẾT QUẢ: {result.get('status', 'UNKNOWN')} · {result.get('reason_code', 'NO_REASON_CODE')}",
            result.get("message", "Chưa có thông điệp checker."),
            f"Mục tiêu: {campaign.get('target', '—')} · phạm vi: {campaign.get('analysis_surface', 'PROJECT_FUNCTION')}",
            f"Ca kiểm thử: {campaign.get('test_case_id', '—')} · hàm: {campaign.get('function_id', '—')}",
            f"Các trạng thái mô hình: {', '.join(map(str, campaign.get('model_state_ids', ()))) or '—'}",
            f"Các chuyển tiếp: {', '.join(map(str, campaign.get('model_transition_ids', ()))) or '—'}",
            f"Chiến lược/seed: {campaign.get('strategy', '—')} / {campaign.get('seed', '—')}",
            f"Lượt thực thi: {campaign.get('iterations_executed', 0)} / {campaign.get('iterations_requested', 0)} · "
            f"đầu vào duy nhất: {campaign.get('unique_inputs', 0)} · kích thước corpus: {campaign.get('corpus_size', 0)}",
            f"Oracle thất bại: {campaign.get('oracle_failures', 0)} · crash: {campaign.get('crashes', 0)} · "
            f"quá thời hạn: {campaign.get('timeouts', 0)}",
            f"Lý do dừng: {campaign.get('stop_reason', '—')} · mã nguồn không bị thay đổi: "
            f"{campaign.get('source_integrity_unchanged', 'unknown')}",
            f"Độ bao phủ mới: {', '.join(map(str, campaign.get('coverage_delta', ()))) or 'không có dữ liệu'}",
            f"Tệp bằng chứng: {len(campaign.get('evidence_ids', ())) } · kết quả quan sát từng lượt: "
            f"{len(campaign.get('execution_evidence', ())) }",
        ]
        failures = campaign.get("failures", ())
        if failures:
            lines.append("\nCÁC LỖI PHÁT HIỆN:")
            for index, finding in enumerate(failures, start=1):
                signature = finding.get("signature") or {}
                input_record = finding.get("input") or {}
                minimized_record = finding.get("minimized_input") or {}
                result_record = finding.get("verification_result") or {}
                observation = finding.get("observation") or {}
                command = finding.get("command_diagnostic") or {}
                diagnosis = [f"{index}. Phân loại: {finding.get('classification', 'FINDING')} · "
                    f"dấu hiệu: {signature.get('kind', 'không rõ')}"]
                for key, label in (("sanitizer", "Bộ phát hiện lỗi"), ("oracle_id", "Oracle"),
                                   ("detail", "Chi tiết"), ("exit_code", "Mã thoát"), ("signal", "Tín hiệu")):
                    value = signature.get(key)
                    if value is not None:
                        diagnosis.append(f"{label}: {value}")
                if result_record.get("reason_code"):
                    diagnosis.append(f"Mã lý do: {result_record['reason_code']}")
                if result_record.get("message"):
                    diagnosis.append(f"Kết quả: {result_record['message']}")
                memory_findings = observation.get("memory_findings") or ()
                for item in memory_findings:
                    location = ":".join(str(value) for value in (item.get("file"), item.get("line")) if value)
                    diagnosis.append(f"LỖI: {item.get('tool', 'bộ kiểm tra lúc chạy')} {item.get('kind', 'vi phạm lúc chạy')}"
                        + (f" tại {location}" if location else "")
                        + (f" trong hàm {item.get('function')}" if item.get("function") else "")
                        + f" — {item.get('message', '')}")
                    if item.get("failure_site"):
                        diagnosis.append(f"Vị trí lỗi: {item['failure_site']}")
                    for frame in item.get("stack_trace", ())[:8]:
                        diagnosis.append(f"  {frame}")
                for check in (finding.get("oracle_evaluation") or {}).get("checks", ()):
                    if check.get("satisfied") is False:
                        diagnosis.append(f"ORACLE KHÔNG KHỚP [{check.get('oracle_type', 'oracle')}]: "
                            f"mong đợi={check.get('expected')!r}; thực tế={check.get('actual')!r}")
                        if check.get("message"):
                            diagnosis.append(f"Giải thích từ oracle: {check['message']}")
                diagnosis.append(f"Đầu vào gây lỗi ({input_record.get('id', '—')}): {self._fuzz_input_preview(input_record)}")
                if minimized_record:
                    diagnosis.append(f"Đầu vào tái hiện đã rút gọn: {self._fuzz_input_preview(minimized_record)}")
                if command.get("exit_code") is not None or command.get("execution_error"):
                    diagnosis.append(f"Tiến trình: mã thoát={command.get('exit_code')} · hết thời gian={command.get('timed_out')} · "
                        f"thời lượng={command.get('duration_ms')} ms · lỗi={command.get('execution_error') or 'không có'}")
                for name in ("stderr_preview", "stdout_preview"):
                    output = command.get(name)
                    if output:
                        diagnosis.append(f"{('stderr' if name.startswith('stderr') else 'stdout')}:\n{output.strip()}")
                    if command.get(name.replace("_preview", "_truncated")):
                        diagnosis.append(f"Phần còn lại của {('stderr' if name.startswith('stderr') else 'stdout')} nằm trong bằng chứng liên kết.")
                diagnosis.append(f"Đã rút gọn đầu vào: {finding.get('minimized', False)} · "
                    f"mã bằng chứng: {', '.join(finding.get('evidence_ids', ())) or 'không có'}")
                lines.extend(diagnosis)
                lines.extend(self._explain_fuzz_finding(finding))
        else:
            lines.extend(("", "Không tìm thấy lỗi trong ngân sách này. Đây là kết quả INCONCLUSIVE, "
                "không phải bằng chứng chứng minh mục tiêu an toàn."))
        if not failures:
            executed = int(campaign.get("iterations_executed", 0) or 0)
            requested = campaign.get("iterations_requested", 0)
            errors = campaign.get("errors", ())
            lines.extend(("", "PHÂN TÍCH KHI CHƯA PHÁT HIỆN LỖI",
                f"Phạm vi: mục tiêu={campaign.get('target') or campaign.get('function_id') or campaign.get('test_case_id') or 'không rõ'} · "
                f"chiến lược={campaign.get('strategy', 'không rõ')} · loại mục tiêu={campaign.get('analysis_surface', 'không rõ')}",
                f"Đã thực thi {executed}/{requested} lượt; đầu vào duy nhất={campaign.get('unique_inputs', 0)}; "
                f"kích thước corpus={campaign.get('corpus_size', 0)}.",
                f"Kết quả các bộ kiểm tra: crash={campaign.get('crashes', 0)}, "
                f"oracle thất bại={campaign.get('oracle_failures', 0)}, quá thời hạn={campaign.get('timeouts', 0)}.",
                f"Lý do dừng: {campaign.get('stop_reason', 'không rõ')}.",
            ))
            if executed == 0:
                lines.append("Diễn giải: chương trình mục tiêu chưa được chạy; lượt này không cung cấp bằng chứng về hành vi của nó.")
            else:
                lines.append("Diễn giải: không đầu vào nào tạo ra dấu hiệu lỗi mà các bộ kiểm tra crash, sanitizer hoặc oracle hiện cấu hình nhận diện được. Kết quả này không chứng minh mục tiêu an toàn.")
            if campaign.get("analysis_surface") == "MODEL_GENERATED_API":
                lines.append("Giới hạn phạm vi: campaign này chỉ kiểm tra độ bền/crash của API C sinh từ mô hình; nó không đánh giá các yêu cầu an toàn trong đặc tả. Xem trang Kiểm chứng hình thức (CTL) để xem negative control chạy trên mutant riêng và counterexample tương ứng.")
            if executed < int(requested or 0):
                lines.append("Chưa chạy hết số lượt dự kiến; hãy xem lý do dừng và lỗi chiến dịch trước khi coi lượt chạy là hoàn tất.")
            if errors:
                lines.append("Lỗi chiến dịch: " + "; ".join(map(str, errors)))
            if campaign.get("stop_reason") == "ITERATION_LIMIT":
                lines.append("Để tăng khả năng phát hiện, hãy cải thiện seed/ngữ pháp đầu vào và độ bao phủ của oracle; chỉ tăng số lượt không bảo đảm sẽ tìm thấy lỗi.")
        if campaign.get("errors"):
            lines.append("\nLỖI TRONG CHIẾN DỊCH: " + "; ".join(map(str, campaign["errors"])))
        self.campaign_analysis.setPlainText("\n".join(lines))

    @staticmethod
    def _explain_fuzz_finding(finding: dict[str, Any]) -> list[str]:
        """Explain the failure mechanism only to the level supported by recorded evidence."""
        signature = finding.get("signature") or {}
        observation = finding.get("observation") or {}
        memory_findings = observation.get("memory_findings") or ()
        checks = (finding.get("oracle_evaluation") or {}).get("checks", ())
        failed_check = next((item for item in checks if item.get("satisfied") is False), None)
        explanation = ["VÌ SAO ĐÂY LÀ LỖI"]
        if memory_findings:
            item = memory_findings[0]
            kind = str(item.get("kind", "UNDEFINED_BEHAVIOR")).upper()
            meanings = {
                "HEAP_BUFFER_OVERFLOW": "Một thao tác đọc/ghi vượt khỏi vùng nhớ được cấp phát trên heap. Đầu vào gây lỗi đã dẫn chương trình tới độ lệch hoặc độ dài không hợp lệ với vùng nhớ đó.",
                "STACK_BUFFER_OVERFLOW": "Một thao tác đọc/ghi vượt khỏi giới hạn object trên stack, tức truy cập ra ngoài vùng hợp lệ của biến cục bộ.",
                "GLOBAL_BUFFER_OVERFLOW": "Một thao tác đọc/ghi vượt khỏi giới hạn object toàn cục đã khai báo.",
                "HEAP_USE_AFTER_FREE": "Chương trình truy cập vùng nhớ heap sau khi vùng đó đã được giải phóng; con trỏ tại vị trí được báo cáo đã không còn hợp lệ.",
                "DOUBLE_FREE": "Cùng một vùng cấp phát bị giải phóng nhiều lần, làm hỏng trạng thái bộ cấp phát và có thể dẫn tới finding bộ nhớ tiếp theo.",
                "INVALID_FREE": "Chương trình đưa cho hàm giải phóng một con trỏ không trỏ tới vùng cấp phát còn hiệu lực (hoặc không phải địa chỉ đầu vùng cấp phát).",
                "MEMORY_LEAK": "Kết thúc lượt chạy vẫn còn vùng nhớ đã cấp phát nhưng chưa được giải phóng. Phát hiện này xác nhận rò rỉ trong lượt observation, không tự chứng minh lượng rò rỉ tăng vô hạn qua nhiều lần gọi.",
                "SIGNED_INTEGER_OVERFLOW": "Kết quả phép toán số nguyên có dấu vượt miền biểu diễn. Trong C đây là undefined behavior và có thể làm sai các kiểm tra giới hạn hoặc luồng điều khiển phía sau.",
                "DIVISION_BY_ZERO": "Biểu thức được thực thi đã chia cho 0; phép chia số nguyên như vậy là undefined behavior trong C.",
                "INVALID_SHIFT": "Số bit dịch hoặc giá trị bị dịch vi phạm quy tắc dịch hợp lệ của ngôn ngữ, gây undefined behavior.",
                "ALIGNMENT_VIOLATION": "Chương trình truy cập object qua địa chỉ không đáp ứng yêu cầu alignment của kiểu dữ liệu đó.",
                "OUT_OF_BOUNDS_ACCESS": "Truy cập bằng chỉ số hoặc con trỏ vượt giới hạn object mà runtime checker ghi nhận.",
                "UNDEFINED_BEHAVIOR": "Runtime checker ghi nhận thao tác có hành vi không được ngôn ngữ định nghĩa.",
            }
            next_steps = {
                "HEAP_BUFFER_OVERFLOW": "Kiểm tra phép tính length/offset và xác nhận chúng không vượt capacity trước mỗi lần truy cập.",
                "STACK_BUFFER_OVERFLOW": "Kiểm tra kích thước buffer cục bộ và giới hạn dữ liệu được chép/ghi vào đó.",
                "GLOBAL_BUFFER_OVERFLOW": "Kiểm tra chỉ số truy cập và kích thước mảng toàn cục tại dòng được báo.",
                "HEAP_USE_AFTER_FREE": "Rà soát ownership và vòng đời con trỏ; bảo đảm mọi nhánh không dùng con trỏ sau khi release.",
                "DOUBLE_FREE": "Rà soát ownership để chỉ một nơi chịu trách nhiệm release mỗi allocation và tránh release lặp qua alias.",
                "INVALID_FREE": "Chỉ release đúng địa chỉ gốc do allocator trả về và còn hiệu lực.",
                "MEMORY_LEAK": "Lần theo allocation chưa được release và kiểm tra mọi nhánh thoát có cleanup tương ứng.",
                "SIGNED_INTEGER_OVERFLOW": "Kiểm tra giới hạn trước phép cộng/nhân hoặc dùng phép toán có kiểm tra overflow.",
                "DIVISION_BY_ZERO": "Kiểm tra mẫu số trước phép chia và xác định cách xử lý khi mẫu số bằng 0.",
                "INVALID_SHIFT": "Kiểm tra số bit dịch nằm trong miền hợp lệ của kiểu dữ liệu trước khi dịch.",
                "ALIGNMENT_VIOLATION": "Dùng địa chỉ có alignment phù hợp với kiểu hoặc sao chép bytes vào object đã căn chỉnh.",
                "OUT_OF_BOUNDS_ACCESS": "Kiểm tra chỉ số và độ dài object tại điểm truy cập.",
            }
            explanation.append(f"Cơ chế lỗi: {meanings.get(kind, item.get('message', 'Bộ kiểm tra lúc chạy ghi nhận thao tác bộ nhớ không hợp lệ hoặc hành vi không xác định.'))}")
            location = ":".join(str(value) for value in (item.get("file"), item.get("line")) if value)
            if location:
                explanation.append(f"Vị trí lỗi do công cụ báo: {item.get('tool', 'bộ kiểm tra lúc chạy')} tại {location}.")
            elif item.get("stack_trace"):
                explanation.append(f"Evidence vị trí: chưa phân tích được tệp/dòng; có {len(item['stack_trace'])} khung ngăn xếp để lần theo.")
            else:
                explanation.append("Bằng chứng vị trí: báo cáo chưa có tệp/dòng hoặc khung ngăn xếp; cần mở bằng chứng sanitizer gốc được liên kết để tìm thao tác gây lỗi.")
            explanation.append("Mức kết luận: sanitizer xác định được cơ chế lỗi. Muốn khẳng định biểu thức nguồn cụ thể và vì sao giới hạn/vòng đời bộ nhớ sai, cần xem dòng được báo cùng mã nguồn xung quanh; chỉ riêng đầu vào không đủ để kết luận trường dữ liệu nào gây lỗi.")
            if kind in next_steps:
                explanation.append(f"Hướng kiểm tra/sửa thường gặp (cần đối chiếu với mã nguồn tại vị trí trên): {next_steps[kind]}")
        elif signature.get("sanitizer"):
            explanation.append(f"Bộ phát hiện báo lỗi: {signature['sanitizer']}. Đây là chẩn đoán lúc chạy của công cụ; do chưa phân tích được phát hiện có cấu trúc, bản ghi chưa cung cấp vị trí mã hoặc ngăn xếp truy cập để giải thích biểu thức nguồn cụ thể.")
            explanation.append("Mở bằng chứng stderr được liên kết để xem báo cáo sanitizer gốc và các khung ngăn xếp (nếu công cụ có ghi).")
        elif failed_check:
            explanation.append(f"Sai khác với yêu cầu kiểm thử: oracle {failed_check.get('oracle_type', 'không rõ')} mong đợi {failed_check.get('expected')!r}, nhưng thực tế nhận {failed_check.get('actual')!r}.")
            if failed_check.get("message"):
                explanation.append(f"Thông điệp oracle: {failed_check['message']}")
            explanation.append("Điều này chứng minh hành vi quan sát được vi phạm kỳ vọng đã khai báo trong bộ kiểm thử. Riêng kết quả oracle không chứng minh có hỏng bộ nhớ hay lỗ hổng bảo mật.")
            explanation.append("Hướng kiểm tra: xác nhận giá trị kỳ vọng đúng với yêu cầu; nếu đúng, sửa phần triển khai để trả về giá trị/hành vi mong đợi.")
        elif finding.get("classification") == "TIMEOUT":
            explanation.append("Chương trình mục tiêu không hoàn thành trong thời gian cho phép với đầu vào này. Đây là bằng chứng chương trình chạy quá lâu hoặc bị chặn; một lần quá thời hạn chưa đủ chứng minh có vòng lặp vô hạn hay xác định đoạn mã chậm.")
        elif finding.get("classification") == "CRASH":
            explanation.append(f"Tiến trình kết thúc bất thường (mã thoát {signature.get('exit_code')!r}, tín hiệu {signature.get('signal')!r}). Chưa có kết quả sanitizer hoặc oracle thất bại được phân tích để giải thích; bản ghi xác nhận chương trình bị crash nhưng chưa xác định nguyên nhân gốc.")
        elif finding.get("classification") == "UNEXPECTED_EXIT":
            explanation.append(f"Tiến trình trả mã thoát {signature.get('exit_code')!r}, trái với cấu hình yêu cầu chương trình không bị crash. Mã thoát khác 0 tự nó chưa chỉ ra lỗi bên trong mã nguồn.")
        else:
            explanation.append(f"Bộ máy phân loại lỗi là {finding.get('classification', 'không rõ')} với dấu hiệu {signature.get('kind', 'không rõ')}. Dữ liệu quan sát hiện có chưa đủ bằng chứng để kết luận cụ thể hơn.")
        if finding.get("minimized"):
            explanation.append("Bằng chứng tái hiện: quá trình rút gọn đầu vào vẫn giữ nguyên dấu hiệu lỗi; đầu vào rút gọn là một đầu vào kích hoạt nhỏ hơn đã được xác nhận trong môi trường chạy này.")
        else:
            explanation.append("Bằng chứng tái hiện: đầu vào ban đầu gây ra dấu hiệu này; chưa xác nhận được đầu vào tái hiện nhỏ hơn trong ngân sách rút gọn.")
        return explanation

    def _update_finding_banner(self, campaigns: list[dict[str, Any]]) -> None:
        first = next(((campaign, failure) for campaign in campaigns
                      for failure in campaign.get("failures", ())), None)
        if first is None:
            completed_campaigns = [item for item in campaigns if item.get("strategy")]
            if completed_campaigns:
                executed = sum(int(item.get("iterations_executed", 0) or 0) for item in completed_campaigns)
                requested = sum(int(item.get("iterations_requested", 0) or 0) for item in completed_campaigns)
                targets = ", ".join(str(item.get("target") or item.get("function_id") or
                    item.get("test_case_id") or "target") for item in completed_campaigns)
                stop_reasons = ", ".join(dict.fromkeys(str(item.get("stop_reason", "unknown"))
                    for item in completed_campaigns))
                crash = sum(int(item.get("crashes", 0) or 0) for item in completed_campaigns)
                timeouts = sum(int(item.get("timeouts", 0) or 0) for item in completed_campaigns)
                oracle_failures = sum(int(item.get("oracle_failures", 0) or 0) for item in completed_campaigns)
                complete_budget = all(
                    int(item.get("iterations_executed", 0) or 0) >= int(item.get("iterations_requested", 0) or 0)
                    and item.get("stop_reason") == "ITERATION_LIMIT" and not item.get("errors")
                    for item in completed_campaigns
                )
                label = "CHƯA TÌM THẤY LỖI TRONG ĐỦ NGÂN SÁCH" if complete_budget else "CHƯA TÌM THẤY LỖI TRƯỚC KHI CHIẾN DỊCH DỪNG"
                message = (f"{label} · {executed}/{requested} lượt · mục tiêu: {targets} · "
                    f"crash={crash}, oracle thất bại={oracle_failures}, quá thời hạn={timeouts} · "
                    f"lý do dừng={stop_reasons}. Kết quả chưa kết luận, không phải bằng chứng an toàn.")
                if executed == 0:
                    message = (f"CHƯA THỰC THI · mục tiêu: {targets} · lý do dừng={stop_reasons}. "
                        "Chiến dịch chưa chạy được mục tiêu nên lượt này không cung cấp bằng chứng về hành vi của chương trình.")
            else:
                message = "CHƯA CHẠY FUZZING · báo cáo này không có dữ liệu chiến dịch."
            self.finding_banner.setText(message)
            self.finding_banner.setStyleSheet(
                "QLabel { background: #fff4dc; color: #634b17; border-left: 6px solid #d39a22; "
                "padding: 9px 12px; font-weight: 600; }"
            )
            return
        campaign, finding = first
        signature = finding.get("signature") or {}
        observation = finding.get("observation") or {}
        memory = next(iter(observation.get("memory_findings", ())), {})
        failed_check = next((item for item in (finding.get("oracle_evaluation") or {}).get("checks", ())
                             if item.get("satisfied") is False), {})
        diagnosis = (memory.get("message") or signature.get("sanitizer") or signature.get("detail"))
        if not diagnosis and failed_check:
            diagnosis = (f"oracle {failed_check.get('oracle_type', 'không rõ')} không khớp: "
                         f"mong đợi {failed_check.get('expected')!r}, thực tế {failed_check.get('actual')!r}")
        diagnosis = diagnosis or signature.get("oracle_id") or signature.get("kind") or finding.get("classification", "lỗi")
        location = ":".join(str(value) for value in (memory.get("file"), memory.get("line")) if value)
        input_record = finding.get("minimized_input") or finding.get("input") or {}
        target = campaign.get("target") or campaign.get("function_id") or campaign.get("test_case_id") or "target"
        self.finding_banner.setText(
            f"PHÁT HIỆN LỖI FUZZING · {finding.get('classification', 'FAILURE')} · {diagnosis}"
            + (f" · {location}" if location else "")
            + f" · mục tiêu={target} · đầu vào tái hiện={self._fuzz_input_preview(input_record)}"
            + f" · {len(finding.get('evidence_ids', ()))} mục bằng chứng liên kết"
        )
        self.finding_banner.setStyleSheet(
            "QLabel { background: #fde8e7; color: #761f1b; border-left: 6px solid #bd3730; "
            "padding: 9px 12px; font-weight: 700; }"
        )

    @staticmethod
    def _fuzz_input_preview(record: dict[str, Any], limit: int = 160) -> str:
        """Render the reproducing payload instead of hiding it behind an input ID."""
        data = record.get("data")
        if isinstance(data, dict) and isinstance(data.get("base64"), str):
            import base64
            try:
                raw = base64.b64decode(data["base64"], validate=True)
                preview = raw[:limit].hex(" ")
                return f"{len(raw)} bytes, hex={preview}{' …' if len(raw) > limit else ''}"
            except (ValueError, TypeError):
                return "invalid base64 payload"
        rendered = repr(data)
        return rendered if len(rendered) <= limit else rendered[:limit] + "…"

    def _show_selected_execution(self, row: int, _column: int, _previous_row: int, _previous_column: int) -> None:
        if not 0 <= row < len(self._execution_records):
            return
        record = self._execution_records[row]
        evidence_id = str(record.get("evidence_id", ""))
        if evidence_id in self._execution_observation_errors:
            self.execution_analysis.setPlainText("KHÔNG XÁC THỰC ĐƯỢC ARTIFACT\n" +
                self._execution_observation_errors[evidence_id])
            return
        observation = self._execution_observations.get(evidence_id)
        if observation is None:
            self.execution_analysis.setPlainText(
                f"Dữ liệu quan sát {evidence_id or '—'} chưa được nạp từ tệp bằng chứng đã lưu. Nhấp đúp vào dòng để kiểm tra tệp bằng chứng.")
            return
        input_record = observation.get("input") or {}
        input_data = input_record.get("data")
        if isinstance(input_data, dict) and "base64" in input_data:
            encoded = str(input_data["base64"])
            import base64
            raw = base64.b64decode(encoded)
            preview = raw[:96].hex(" ")
            input_display = f"bytes={len(raw)} · hex[0:96]={preview}"
            if len(raw) > 96:
                input_display += " …"
        else:
            input_display = str(input_data)
        command = observation.get("command") or {}
        output = observation.get("observation") or {}
        iteration = observation.get("iteration")
        if iteration is None:
            iteration = record.get("iteration", "—")
        else:
            try:
                iteration = int(iteration) + 1
            except (TypeError, ValueError):
                iteration = record.get("iteration", iteration)
        lines = [
            f"LƯỢT {iteration} · "
            f"phân loại={observation.get('classification', 'UNKNOWN')} · kết quả={observation.get('result_status', 'UNKNOWN')}",
            f"Đầu vào: {observation.get('input_id', '—')} · loại={input_record.get('kind', '—')} · "
            f"nguồn={input_record.get('origin', '—')} · SHA-256={observation.get('input_sha256', '—')}",
            f"Dữ liệu đầu vào: {input_display}",
            f"Mục tiêu: {observation.get('target', '—')} · ca kiểm thử={observation.get('test_case_id', '—')} · "
            f"loại mục tiêu={observation.get('target_kind', '—')}",
            f"Đối số ca kiểm thử thực tế: {observation.get('test_case_inputs', '—')}",
            f"Đã thực thi: {observation.get('executed', False)} · mã kết quả={observation.get('result_id', '—')} · "
            f"mã lý do={observation.get('result_reason_code', '—')}",
            f"Oracle kỳ vọng: {observation.get('expected_oracle', '—')}",
            f"Kết quả quan sát được: {output or 'Không có dữ liệu quan sát dạng cấu trúc'}",
            f"Lệnh chạy: {' '.join(map(str, command.get('argv', ()))) or 'không có dữ liệu'}",
            f"Mã thoát={command.get('exit_code', '—')} · hết thời gian={command.get('timed_out', '—')} · "
            f"thời lượng (ms)={command.get('duration_ms', '—')} · lỗi={command.get('execution_error', '—')}",
            f"Đầu ra stdout: {command.get('stdout_preview', '')!r} · SHA-256={command.get('stdout_sha256', '—')}",
            f"Đầu ra stderr: {command.get('stderr_preview', '')!r} · SHA-256={command.get('stderr_sha256', '—')}",
            f"Mã evidence: {evidence_id} · SHA-256 artifact={record.get('sha256', '—')} (đã xác minh trước khi hiển thị)",
        ]
        self.execution_analysis.setPlainText("\n".join(lines))

    def show_report(self, report):
        # Keep the process model as the landing view; evidence inspection is a secondary tab.
        self.tabs.setCurrentWidget(self.process_tab)
        if report is None:
            self.summary.setText("Chưa có lần chạy. Nút bên dưới bật fuzzing với cấu hình hiện tại, giữ nguyên project/specification đã nạp.")
            self.table.set_records(())
            self.coverage_table.set_records(())
            self.technique_table.set_records(())
            self.cfg_table.set_records(())
            self.execution_evidence_table.set_records(())
            self._campaign_records = []
            self._execution_records = []
            self._execution_observations = {}
            self._execution_observation_errors = {}
            self._update_finding_banner([])
            self.campaign_analysis.clear()
            self.execution_analysis.clear()
            self.cfg_description.setText("Chưa có report để dựng source map/CFG. Không tự suy diễn CFG từ tên hàm.")
            self._ready_report(None)
            return
        self._execution_observations = {}
        self._execution_observation_errors = {}
        stages = {str(item.get("stage_id", "")).upper(): item for item in report.stage_summaries}
        self._campaign_records = []
        self.campaign_analysis.clear()
        self.execution_analysis.clear()
        self.description.setText(CHECKER_HELP["FUZZING"])
        stage = stages.get("FUZZING")
        if stage is None:
            self._update_finding_banner([])
            self.summary.setText("FUZZING · NOT_RUN — Stage không có trong report hiện tại.")
            self.table.set_records(())
            self.execution_evidence_table.set_records(())
            self._render_coverage(stages.get("COVERAGE", {}))
            self._render_techniques(report, stages, {}, None, None)
            self._render_cfg(stages, getattr(report, "metadata", {}).get("specification", {}))
            source_ready = bool(getattr(report, "metadata", {}).get("source_inventory", {}).get("files"))
            self.flow_diagram.set_campaign(None, source_ready, stages.get("COVERAGE", {}).get("output") or {}, 0)
            return
        status = str(stage.get("status", "UNKNOWN")).upper()
        reason = stage.get("reason") or (stage.get("output") or {}).get("skipped_reason") or ""
        campaign = stage.get("output") or {}
        campaigns = campaign.get("campaigns") if isinstance(campaign, dict) else None
        self._render_execution_evidence(campaigns if campaigns else campaign)
        if campaigns:
            self._campaign_records = [dict(item) for item in campaigns]
        elif isinstance(campaign, dict) and campaign.get("strategy"):
            self._campaign_records = [dict(campaign)]
        else:
            self._campaign_records = []
        self._update_finding_banner(self._campaign_records)
        if campaigns:
            campaign = campaigns[0]
        metadata = stage.get("metadata") or {}
        if status == "SKIPPED" and not reason:
            reason = "Chưa cấu hình campaign hoặc phần phụ thuộc của target chưa sẵn sàng."
        result = next((item for item in report.results if str(item.stage).upper() == "FUZZING"), None)
        result_metadata = result.metadata if result is not None else {}
        effective_strategy = (result_metadata.get("effective_strategy") or
            (campaign.get("verification_result") or {}).get("metadata", {}).get("effective_strategy") or
            campaign.get("strategy"))
        if not campaign.get("strategy"):
            gui_config = getattr(report, "metadata", {}).get("gui_run_configuration", {})
            configured = gui_config.get("fuzz_config_created")
            config_detail = (f"\nCấu hình GUI: đã bật={gui_config.get('fuzz_enabled')}, "
                f"strategy={gui_config.get('fuzz_strategy')}, số lượt={gui_config.get('fuzz_iterations')}."
                if gui_config else "")
            self.summary.setText(f"FUZZING · {status_label(status)} · Campaign chưa chạy." +
                                 (f"\nCấu hình pipeline: {'đã có' if configured else 'chưa có'}." if configured is not None else "") +
                                 config_detail +
                                 (f"\nLý do: {reason}" if reason else "") +
                                 "\nKiểm tra mã nguồn và mẫu kiểm thử nếu đã gửi cấu hình.")
            self.table.set_records((("—", "—", 0, 0, 0, 0, "—", 0, 0,
                f"{status_label(status)} · {reason or 'Không có dữ liệu campaign'}"),))
        else:
            finding_count = len(campaign.get("failures", ()))
            self.summary.setText(
                f"FUZZING · {status_label(status)} · strategy yêu cầu={result_metadata.get('requested_strategy', campaign.get('strategy', '—'))} · "
                f"strategy thực tế={effective_strategy or '—'} · "
                f"seed={campaign.get('seed', result_metadata.get('random_seed', '—'))} · "
                f"mã nguồn không bị thay đổi={campaign.get('source_integrity_unchanged', 'không rõ')} · "
                f"lý do dừng={campaign.get('stop_reason', result_metadata.get('stop_reason', '—'))}" +
                (f"\nGiới hạn/finding campaign: {'; '.join(campaign.get('errors', ())) }" if campaign.get("errors") else ""))
            target_name = campaign.get("target", "target")
            target_details = [value for value in (campaign.get("test_case_id"), campaign.get("function_id")) if value]
            target_details.extend(campaign.get("model_state_ids", ()))
            target_details.extend(campaign.get("model_transition_ids", ()))
            if target_details:
                target_name += " · " + ", ".join(map(str, target_details))
            finding_details = []
            for failure in campaign.get("failures", ()):
                signature = failure.get("signature") or {}
                memory = next(iter((failure.get("observation") or {}).get("memory_findings", ())), {})
                diagnostic = (memory.get("message") or signature.get("sanitizer") or
                              signature.get("detail") or signature.get("oracle_id") or
                              signature.get("kind", "signature unavailable"))
                finding_details.append(f"{failure.get('classification', 'finding')}: {diagnostic}")
            feedback = (f"{status_label(result.status.value) if result else status_label(status)} · "
                f"{campaign.get('stop_reason', '—')} · {len(campaign.get('evidence_ids', ())) } evidence")
            if campaign.get("oracle_failures"):
                feedback += f" · oracle thất bại={campaign['oracle_failures']}"
            if finding_details:
                feedback += " · " + "; ".join(finding_details)
            if campaign.get("errors"):
                feedback += " · finding=" + "; ".join(map(str, campaign["errors"]))
            self.table.set_records(((f"{target_name} · {campaign.get('analysis_surface', 'PROJECT_FUNCTION')}",
                campaign.get("seed", result_metadata.get("random_seed", "—")),
                campaign.get("iterations_executed", result_metadata.get("executions_completed", "—")),
                campaign.get("unique_inputs", "—"), campaign.get("corpus_size", result_metadata.get("corpus_size", "—")),
                campaign.get("oracle_failures", 0),
                f"{campaign.get('crashes', result_metadata.get('crashes', '—'))} / {campaign.get('timeouts', result_metadata.get('timeouts', '—'))}",
                len(campaign.get("coverage_delta", ())), finding_count if "failures" in campaign else result_metadata.get("finding_count", "—"),
                feedback),))
            if self._campaign_records:
                self.table.setCurrentCell(0, 0)
        self.description.setText(CHECKER_HELP["FUZZING"])
        if campaign.get("strategy") and not campaign.get("failures"):
            self.description.setText(self.description.text() +
                " Chiến dịch này chưa phát hiện lỗi trong ngân sách đã chạy (INCONCLUSIVE), không phải kết luận PASS.")
        if campaign.get("analysis_surface") == "MODEL_GENERATED_API":
            self.description.setText(self.description.text() +
                " Phạm vi chỉ là API C sinh tự động; các negative control cho vi phạm yêu cầu được hiển thị riêng trong bảng CTL.")
        evidence_meta = result_metadata
        if evidence_meta:
            written = evidence_meta.get("observation_evidence_written")
            limit = evidence_meta.get("observation_evidence_limit")
            if written is not None:
                self.description.setText(self.description.text() +
                    f" Đã lưu bằng chứng đầu vào/lệnh chạy/kết quả quan sát cho {written}/"
                    f"{campaign.get('iterations_executed', written)} lượt (giới hạn lưu {limit}).")
        coverage_stage = stages.get("COVERAGE", {})
        self._render_coverage(coverage_stage)
        self._render_techniques(report, stages, campaign, result, effective_strategy)
        self._render_cfg(stages, getattr(report, "metadata", {}).get("specification", {}))
        source_ready = bool(getattr(report, "metadata", {}).get("source_inventory", {}).get("files"))
        display_campaign = {**campaign, "strategy": effective_strategy or campaign.get("strategy")}
        self.flow_diagram.set_campaign(display_campaign, source_ready, coverage_stage.get("output") or {},
                                       len(campaign.get("evidence_ids", ())))
        if campaigns:
            total_runs = sum(int(item.get("iterations_executed", 0) or 0) for item in campaigns)
            total_findings = sum(len(item.get("failures", ())) for item in campaigns)
            self.summary.setText(f"FUZZING · {status_label(status)} · {len(campaigns)} testcase/hàm · "
                f"{total_runs} lượt thực thi · {total_findings} phát hiện")
            rows = []
            for item in campaigns:
                findings = len(item.get("failures", ()))
                surface = item.get("analysis_surface", "PROJECT_FUNCTION")
                state_ids = item.get("model_state_ids", ())
                transition_ids = item.get("model_transition_ids", ())
                scope = surface
                if state_ids or transition_ids:
                    scope += f" · {len(state_ids)} state · {len(transition_ids)} transition"
                case_details = [value for value in (item.get("test_case_id"), item.get("function_id")) if value]
                case_details.extend(state_ids)
                case_details.extend(transition_ids)
                target_label = item.get("target", "target")
                if case_details:
                    target_label += " · " + ", ".join(map(str, case_details))
                failure_details = []
                for failure in item.get("failures", ()):
                    signature = failure.get("signature") or {}
                    failure_details.append(f"{failure.get('classification', 'finding')}: "
                        f"{signature.get('key', signature.get('message', 'signature unavailable'))}")
                errors = item.get("errors", ())
                feedback = f"{scope} · {item.get('stop_reason', '—')}"
                if item.get("oracle_failures"):
                    feedback += f" · oracle failures={item['oracle_failures']}"
                if failure_details:
                    feedback += " · " + "; ".join(failure_details)
                if errors:
                    feedback += " · errors=" + "; ".join(map(str, errors))
                rows.append((f"{target_label} · {item.get('analysis_surface', 'PROJECT_FUNCTION')}",
                    item.get("seed", "—"), item.get("iterations_executed", 0),
                    item.get("unique_inputs", "—"), item.get("corpus_size", 0),
                    item.get("oracle_failures", 0),
                    f"{item.get('crash', 0)} / {item.get('timeouts', 0)}",
                    len(item.get("coverage_delta", ())), findings, feedback))
            self.table.set_records(rows)
            if rows:
                self.table.setCurrentCell(0, 0)
            self._progress_target = f"Đã phân tích {len(campaigns)} hàm / testcase"
            self._progress_counts = f"{total_runs} lượt · {total_findings} phát hiện · {sum(len(item.get('evidence_ids', ())) for item in campaigns)} mục evidence"
            self.flow_diagram._statuses.update({key: "COMPLETED" for key in
                ("TARGET", "GENERATE", "EXECUTION", "ORACLE", "CORPUS", "EVIDENCE")})
            self.flow_diagram.update()

    def _ready_report(self, campaign: dict[str, Any] | None) -> None:
        self.flow_diagram.set_campaign(campaign, False, None, 0)

    def _render_coverage(self, stage: dict[str, Any]) -> None:
        data = stage.get("output") or {}
        status = str(stage.get("status", "NOT_RUN")).upper()
        reason = stage.get("reason") or data.get("skipped_reason") or ""
        self.coverage_description.setText(
            f"Giai đoạn đo coverage · {status_label(status)}. Line = executable lines đã chạy / tổng executable lines; "
            "branch = arcs/nhánh được backend báo đã chạy / tổng arcs/nhánh. Đây là white-box coverage khi binary được instrument; "
            "không đồng nghĩa độ an toàn hay coverage trạng thái mô hình." +
            (f" Lý do: {reason}" if reason else " Bộ máy fuzzing chỉ dùng số đo này để dẫn hướng khi chọn COVERAGE_GUIDED."))
        rows = []
        for name, metric, count_key, total_key in (
            ("Dòng lệnh", data.get("line_metrics", {}), "covered_lines", "total_lines"),
            ("Nhánh", data.get("branch_metrics", {}), "covered_branches", "total_branches"),
        ):
            if not metric:
                continue
            total, covered = metric.get(total_key, 0), metric.get(count_key, 0)
            rows.append((name, "Tất cả tệp", covered, max(0, total - covered), metric.get("percentage", "—"),
                         data.get("backend", "—"), "; ".join(data.get("limitations", ()))))
            for item in metric.get("files", ()):
                file_total = item.get(total_key, item.get("total_lines", 0))
                file_covered = item.get(count_key, item.get("covered_lines", 0))
                rows.append((name, item.get("file", "—"), file_covered, max(0, file_total-file_covered),
                             item.get("percentage", "—"), data.get("backend", "—"),
                             "; ".join(data.get("limitations", ()))))
        if not rows:
            rows.append(("—", "—", "—", "—", "—", "—", reason or f"No coverage measurement ({status})."))
        self.coverage_table.set_records(rows)

    def _render_techniques(self, report: Any, stages: dict[str, Any], campaign: dict[str, Any],
                           fuzz_result: Any, effective_strategy: str | None) -> None:
        selected = str(effective_strategy or "").upper()
        strategy_rows = []
        for strategy in FuzzFlowDiagram._STRATEGIES:
            if strategy == "CONCOLIC":
                capability = "CHƯA HỖ TRỢ · chưa triển khai truy vết nhánh mã nguồn"
            elif strategy == selected:
                capability = f"ĐANG CHỌN · {status_label(fuzz_result.status.value) if fuzz_result else 'chưa có trạng thái campaign'}"
            else:
                capability = "ĐƯỢC HỖ TRỢ · CHƯA CHỌN"
            strategy_rows.append((f"Strategy fuzzing · {strategy}", capability,
                campaign.get("iterations_executed", "—") if strategy == selected else "—",
                len(campaign.get("evidence_ids", ())) if strategy == selected else 0,
                f"coverage mới={len(campaign.get('coverage_delta', ())) }" if strategy == selected else "chưa chạy"))
        checker_rows = []
        for stage_id in ("CTL", "BMC", "SMT", "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING"):
            stage = stages.get(stage_id, {})
            result_rows = [item for item in report.results if str(item.stage).upper().replace("-", "_") in
                           {stage_id, "DYNAMIC_TEST" if stage_id == "DYNAMIC" else stage_id}]
            verdicts = ", ".join(dict.fromkeys(item.status.value for item in result_rows)) or "không có kết quả checker"
            stage_and_checker = (f"giai đoạn {status_label(str(stage.get('status', 'NOT_RUN')).upper())} · "
                                 f"checker {verdicts}")
            checker_rows.append((stage_id, stage_and_checker,
                len(result_rows), sum(len(item.evidence_ids) for item in result_rows),
                "; ".join(dict.fromkeys(item.scope or "" for item in result_rows if item.scope)) or
                stage.get("reason", "Chưa ghi nhận phạm vi riêng của checker.")))
        self.technique_table.set_records((*strategy_rows, *checker_rows))

    def _render_cfg(self, stages: dict[str, Any], specification: dict[str, Any] | None = None) -> None:
        """Display only model states and transitions declared by Specification."""
        model_stage = stages.get("MODEL", {})
        metadata = model_stage.get("metadata") or {}
        specification = specification or {}
        states = specification.get("states") or ()
        transitions = specification.get("transitions") or ()
        if not states:
            status = metadata.get("model_status", "NOT_APPLICABLE")
            self.cfg_description.setText(
                f"Mô hình trạng thái từ Đặc tả · {status}. Đặc tả hiện tại không khai báo state machine.")
            self.cfg_table.set_records((("—", "—", "—", "No Specification model elements are available."),))
            return
        initial = specification.get("initial_state")
        rows = [("STATE", item.get("id", ""),
                 "INITIAL" if item.get("initial") or item.get("id") == initial else "",
                 ", ".join(item.get("labels", ()))) for item in states]
        rows.extend(("TRANSITION", item.get("id", ""),
                     f"{item.get('source', '')} → {item.get('target', '')}",
                     "; ".join(value for value in (item.get("guard"), item.get("action")) if value))
                    for item in transitions)
        self.cfg_description.setText(
            f"Mô hình từ Đặc tả: {len(states)} states / {len(transitions)} transitions. "
            "Các hàng được chiếu trực tiếp từ normalized Specification.")
        self.cfg_table.set_records(rows)
def _state_label(status: str) -> str:
    if status == "NOT_RUN":
        return "not run"
    if status == "NOT_RUN":
        return "not run"
    return {"COMPLETED": "xong", "RUNNING": "đang chạy", "READY": "sẵn sàng",
            "FAILED": "thất bại", "UNSUPPORTED": "UNSUPPORTED", "NOT_SELECTED": "không chọn",
            "INCONCLUSIVE": "INCONCLUSIVE", "SKIPPED": "bỏ qua", "WAITING": "chờ"}.get(status, status)











