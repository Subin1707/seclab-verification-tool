from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from seclab.gui.widgets import ReadOnlyTable
from seclab.gui.i18n import status_label


class SourcePage(QWidget):
    """Read-only source inventory and lineage from a pipeline report."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.description = QLabel("Mã nguồn và dấu vết liên kết được lấy từ báo cáo của lần chạy đã chọn.")
        self.description.setWordWrap(True)
        self.table = ReadOnlyTable(("Tệp", "SHA-256 trước", "SHA-256 sau", "Toàn vẹn",
                                    "Chức năng", "Yêu cầu", "Kết quả phân tích"))
        layout = QVBoxLayout(self)
        layout.addWidget(self.description)
        layout.addWidget(self.table, 1)

    def show_report(self, report) -> None:
        if report is None:
            self.table.set_records(())
            return
        inventory = report.metadata.get("source_inventory", {})
        functions_by_file: dict[str, list[str]] = {}
        for function in inventory.get("functions", ()):
            functions_by_file.setdefault(function.get("file", ""), []).append(function.get("name", ""))
        self.table.set_records(tuple((item.get("project_relative_path", ""), item.get("before_sha256", item.get("sha256", "")),
            item.get("after_sha256", ""),
            status_label("CHANGED" if item.get("changed_during_run") else ("UNHASHED" if item.get("integrity_error") else "UNCHANGED")),
            ", ".join(functions_by_file.get(item.get("project_relative_path", ""), ())),
            ", ".join(item.get("requirement_ids", ())), item.get("analysis_results", ()))
            for item in inventory.get("files", ())))
        integrity = report.metadata.get("source_integrity", ())
        changed = sum(bool(item.get("changed_during_run") or item.get("error")) for item in integrity)
        self.description.setText(f"{len(inventory.get('files', ()))} tệp mã nguồn; {changed} tệp bị thay đổi hoặc không thể tính giá trị băm trong lần chạy. Hash mã nguồn và liên kết phân tích được lấy từ bằng chứng quy trình kiểm chứng (Pipeline).")
