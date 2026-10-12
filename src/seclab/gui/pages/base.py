from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from seclab.gui.widgets import ReadOnlyTable
from seclab.gui.i18n import stage_label, status_label


STAGES = ("SPECIFICATION", "MODEL", "CTL", "BMC", "SMT", "SOURCE", "CODEGEN", "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT")


class DataPage(QWidget):
    def __init__(self, title: str, headers: tuple[str, ...], parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.title = QLabel(title)
        self.title.setObjectName("pageTitle")
        self.description = QLabel("")
        self.description.setWordWrap(True)
        self.table = ReadOnlyTable(headers)
        layout.addWidget(self.title)
        layout.addWidget(self.description)
        layout.addWidget(self.table, 1)

    def show_report(self, report: Any | None) -> None:
        self.table.set_records(())
        self.description.setText("Mở dự án và chạy kiểm chứng để hiển thị dữ liệu tại đây.")

    def show_error(self, error: dict[str, Any]) -> None:
        self.table.set_records(((stage_label(error.get("stage_id", "PIPELINE")), error.get("error_type", "Error"),
                                 error.get("reason", "")),))
        self.description.setText(f"Giai đoạn kiểm chứng gặp lỗi {status_label('FAILED')}. Lý do, bằng chứng và nhật ký kỹ thuật được giữ để hỗ trợ gỡ lỗi.")


def results_for(report: Any, stages: set[str]) -> list[Any]:
    return [item for item in report.results if item.stage.upper() in stages or item.technique.upper() in stages]
