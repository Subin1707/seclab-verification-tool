from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from .base import DataPage, STAGES
from seclab.gui.i18n import STATUS_HELP, status_label, stage_label


class DashboardPage(QWidget):
    actionRequested = Signal(str)
    stageRunRequested = Signal(str)
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        self.title = QLabel("Tổng quan kiểm chứng")
        self.title.setObjectName("pageTitle")
        self.project = QLabel("Dự án: —")
        self.spec = QLabel("Đặc tả: —")
        self.run = QLabel("Mã lần chạy: —")
        self.last = QLabel("Lần chạy gần nhất: —")
        self.duration = QLabel("Thời lượng: —")
        for item in (self.title, self.project, self.spec, self.run, self.last, self.duration): root.addWidget(item)
        self.input_summary = QLabel("Chọn dự án và đặc tả để xem trạng thái đầu vào.")
        self.input_summary.setWordWrap(True)
        root.addWidget(self.input_summary)
        self.start_verification = QPushButton("▶ Bắt đầu kiểm chứng")
        self.start_verification.setMinimumHeight(44)
        self.start_verification.clicked.connect(lambda: self.actionRequested.emit("full"))
        self.start_verification.setEnabled(False)
        root.addWidget(self.start_verification)
        root.addWidget(QLabel("Tổng quan các giai đoạn kiểm chứng"))
        self.stage_container = QWidget()
        self.stages = QGridLayout()
        self.stages.setContentsMargins(2, 2, 2, 2)
        self.stages.setHorizontalSpacing(8)
        self.stages.setVerticalSpacing(8)
        self.stage_labels: dict[str, QLabel] = {}
        for i, stage in enumerate(STAGES):
            label = QLabel(f"{stage_label(stage)}\nChưa bắt đầu\nKết quả: {status_label('NOT_RUN')}")
            label.setObjectName("stageCard")
            label.setWordWrap(True)
            label.setMinimumHeight(88)
            label.setMinimumWidth(0)
            label.setMargin(8)
            label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            self.stage_labels[stage] = label
            self.stages.addWidget(label, i // 3, i % 3)
            self.stages.setColumnStretch(i % 3, 1)
        self.stage_container.setLayout(self.stages)
        self.stage_container.setMinimumHeight(5 * 104)
        for row in range((len(STAGES) + 2) // 3):
            self.stages.setRowMinimumHeight(row, 96)
        self.stage_scroll = QScrollArea()
        self.stage_scroll.setWidgetResizable(True)
        self.stage_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self.stage_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.stage_scroll.setWidget(self.stage_container)
        root.addWidget(self.stage_scroll, 1)
        root.addWidget(QLabel("Tổng hợp kết quả riêng của các bộ kiểm tra"))
        self.summary = QLabel("ĐẠT (PASS): 0   KHÔNG ĐẠT (FAIL): 0   CHƯA KẾT LUẬN (INCONCLUSIVE): 0   CHƯA KIỂM TRA: 0")
        self.summary.setToolTip("\n".join(f"{key}: {value}" for key, value in STATUS_HELP.items()))
        root.addWidget(self.summary)

    def set_session(self, session) -> None:
        project_name = session.project_path.name if session.project_path else "Chưa chọn"
        spec_name = session.specification_path.name if session.specification_path else "Chưa chọn"
        info = session.specification_info
        source_count = len(session.source_files)
        self.input_summary.setText(
            f"Dự án: {project_name}\nĐặc tả: {spec_name}\n"
            f"Yêu cầu: {info.get('requirements', len(session.requirements))} · "
            f"Thuộc tính: {info.get('properties', 0)} · Mã nguồn: {source_count} tệp\n"
            f"Trạng thái: {'Sẵn sàng kiểm chứng' if session.ready else 'Cần dự án và đặc tả hợp lệ'}"
        )
        self.start_verification.setEnabled(session.ready)

    def set_running(self, running: bool) -> None:
        self.start_verification.setEnabled(not running)

    def set_project(self, project: str | None, spec: str | None) -> None:
        self.project.setText(f"Dự án: {project or '—'}")
        self.spec.setText(f"Đặc tả: {spec or '—'}")

    def set_stage_progress(self, stage_id: str, stage: dict[str, Any]) -> None:
        if stage_id in self.stage_labels:
            self.stage_labels[stage_id].setText(
                f"{stage_label(stage_id)}\nGiai đoạn: {status_label(stage.get('status', 'RUNNING'))}\nKết quả: đang chờ báo cáo"
            )

    def show_error(self, error: dict[str, Any]) -> None:
        """Project pipeline failures without requiring a report object."""
        message = str(error.get("reason") or "Pipeline failed without a diagnostic message.")
        self.summary.setText(f"{status_label('FAILED')} · {message}")
        self.input_summary.setText("Pipeline thất bại. Xem Nhật ký chạy để biết chi tiết kỹ thuật.")
        stage_id = str(error.get("stage_id", "PIPELINE"))
        if stage_id in self.stage_labels:
            self.stage_labels[stage_id].setText(
                f"{stage_label(stage_id)}\nGiai đoạn: {status_label('FAILED')}\nLý do: {message}")

    def reset_stages(self) -> None:
        for stage_id, label in self.stage_labels.items():
            label.setText(f"{stage_label(stage_id)}\nChưa bắt đầu\nKết quả: {status_label('NOT_RUN')}")

    def show_report(self, report: Any | None) -> None:
        if report is None:
            return
        self.run.setText(f"Mã lần chạy: {report.run_id}")
        self.last.setText(f"Lần chạy gần nhất: {report.end_time.isoformat(timespec='seconds')}")
        self.duration.setText(f"Thời lượng: {report.duration_seconds:.2f}s")
        stage_result_groups = {
            "SPECIFICATION": {"SPECIFICATION"}, "SOURCE": set(), "MODEL": set(),
            "CTL": {"CTL", "FORMAL"}, "BMC": {"BMC", "BOUNDED_MODEL_CHECKING"}, "SMT": {"SMT", "FORMAL"},
            "STATIC": {"STATIC_ANALYSIS"}, "MEMORY": {"SANITIZER", "MEMORY_ANALYSIS"},
            "DYNAMIC": {"DYNAMIC_TEST"}, "COVERAGE": {"COVERAGE"}, "FUZZING": {"FUZZING"},
        }
        for stage in report.stage_summaries:
            stage_id = stage["stage_id"]
            scope = stage_result_groups.get(stage_id, {stage_id})
            result_status = ", ".join(sorted({status_label(r.status.value) for r in report.results
                if r.stage.upper() in scope or r.technique.upper() == stage_id})) or status_label("NOT_RUN")
            self.stage_labels[stage_id].setText(f"{stage_label(stage_id)}\nGiai đoạn: {status_label(stage['status'])}\nKết quả: {result_status}")
        counts = report.status_counts
        values = {key: counts.get(key, 0) for key in ("PASS", "FAIL", "INCONCLUSIVE", "BUILD_ERROR", "TOOL_ERROR")}
        values["NOT_CHECKED"] = counts.get("NOT_RUN", 0)
        values["SKIPPED"] = sum(stage.get("status") == "SKIPPED" for stage in report.stage_summaries)
        labels = {"PASS": status_label("PASS"), "FAIL": status_label("FAIL"),
                  "INCONCLUSIVE": status_label("INCONCLUSIVE"), "BUILD_ERROR": status_label("BUILD_ERROR"),
                  "TOOL_ERROR": status_label("TOOL_ERROR"), "NOT_CHECKED": status_label("NOT_CHECKED"),
                  "SKIPPED": status_label("SKIPPED")}
        self.summary.setText("   ".join(f"{labels[k]}: {v}" for k, v in values.items()))



