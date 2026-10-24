from __future__ import annotations

from PySide6.QtWidgets import QTabWidget

from .base import DataPage
from seclab.gui.i18n import TECH_TERM, CHECKER_HELP, STATUS_LABELS, status_label


class FormalPage(DataPage):
    def __init__(self, parent=None):
        super().__init__("Kiểm chứng hình thức (Formal Verification)",
                         ("Logic", "Thuộc tính", "Công thức / ràng buộc", "Kết quả bộ giải (Solver)",
                          "Trạng thái kiểm chứng", "Phạm vi", "Mã bằng chứng (Evidence ID)"), parent)
        self.tabs = QTabWidget(self)
        self.formal_tables = {}
        for logic in ("CTL", "BMC", "SMT"):
            page = DataPage(TECH_TERM[logic], ("Thuộc tính", "Công thức / ràng buộc", "Kết quả bộ giải (Solver)",
                                    "Trạng thái kiểm chứng", "Phạm vi", "Nhân chứng / phản ví dụ", "Mã bằng chứng (Evidence ID)"))
            page.description.setText(CHECKER_HELP[logic])
            page.title.setToolTip(TECH_TERM[logic])
            page.table.setToolTip("\n".join(f"{key}: {value}" for key, value in STATUS_LABELS.items()))
            self.formal_tables[logic] = page.table
            self.tabs.addTab(page, logic)
        self.layout().insertWidget(2, self.tabs, 1)
        self.table.hide()
        self._show_empty_state()

    def _show_empty_state(self, stage_details=None):
        """Put the missing checker status or its skip reason directly in the table."""
        stage_details = stage_details or {}
        messages = {}
        for logic, table in self.formal_tables.items():
            details = stage_details.get(logic, {})
            status = str(details.get("status", "NOT_RUN")).upper()
            reason = details.get("reason")
            if status == "NOT_RUN":
                message = "Chưa chạy — chọn ‘Chạy toàn bộ’ để thực thi kiểm chứng hình thức."
            elif status == "SKIPPED":
                message = reason or "Giai đoạn này đã bị bỏ qua."
            elif status == "FAILED":
                message = reason or "Giai đoạn kiểm chứng gặp lỗi; xem Nhật ký chạy và bằng chứng."
            else:
                message = reason or "Không có kết quả cho logic này trong lần chạy."
            display_status = "Chưa chạy" if status == "NOT_RUN" else status_label(status)
            table.set_records((("—", "—", "—", display_status, "—", message, "—"),))
            messages[logic] = message
        if not stage_details:
            self.description.setText(
                "Chưa có kết quả kiểm chứng. Tải và xác thực đặc tả chỉ chuẩn bị đầu vào; "
                "hãy chọn ‘Chạy toàn bộ’ để chạy CTL, BMC và SMT. "
                "Chỉ logic có thuộc tính tương ứng trong đặc tả mới tạo kết quả."
            )
        return messages

    def show_report(self, report):
        if report is None:
            self._show_empty_state()
            return
        by_logic = {"CTL": [], "BMC": [], "SMT": []}
        stage_details = {str(item.get("stage_id", "")).upper(): item
                         for item in report.stage_summaries
                         if str(item.get("stage_id", "")).upper() in by_logic}
        for result in report.results:
            logic = result.technique.upper()
            if logic not in by_logic:
                continue
            metadata = result.metadata
            formula = metadata.get("formula", metadata.get("formula_text", metadata.get("bad_proposition", "")))
            if logic == "BMC":
                formula = f"{formula} (bound={metadata.get('bound', result.scope or 'unknown')})"
            by_logic[logic].append((result.property_id or "", formula,
                                    TECH_TERM.get(metadata.get("solver_outcome", "unavailable"),
                                                  metadata.get("solver_outcome", "Chưa có kết quả")),
                                    status_label(result.status.value), result.scope or "",
                                    result.counterexample or metadata.get("witness", ""),
                                    ", ".join(result.evidence_ids)))
        ctl_stage = stage_details.get("CTL", {})
        ctl_metadata = ctl_stage.get("metadata", {})
        negative_controls = ctl_metadata.get("negative_controls", ())
        for control in negative_controls:
            by_logic["CTL"].append((
                f"Negative control · {control.get('property_id', '')}",
                control.get("formula", ""), "MUTANT CHECK",
                status_label(control.get("status", "UNKNOWN")),
                "Mutant riêng; baseline không thay đổi",
                " → ".join(control.get("counterexample", ())) or control.get("reason", ""),
                control.get("evidence_id", "")))
        empty_messages = self._show_empty_state(stage_details)
        for logic, table in self.formal_tables.items():
            if by_logic[logic]:
                table.set_records(by_logic[logic])
            else:
                stage = stage_details.get(logic, {})
                table.set_records((("—", "—", "—", status_label(stage.get("status", "NO_RESULTS")),
                                   "—", empty_messages[logic], "—"),))
        if any(by_logic.values()):
            message = (
                "Kết quả bộ giải (Solver) và trạng thái kiểm chứng là hai thông tin độc lập. "
                "Logic không có dòng kết quả hiển thị trạng thái stage hoặc lý do bị bỏ qua."
            )
            if negative_controls:
                detected = sum(item.get("status") == "DETECTED" for item in negative_controls)
                message += (f" Negative control CTL: phát hiện {detected}/{len(negative_controls)} "
                            "vi phạm được cài trong mô hình mutant riêng; các verdict baseline không bị thay đổi.")
            self.description.setText(message)
