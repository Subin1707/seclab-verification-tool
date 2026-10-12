from __future__ import annotations

from .base import DataPage
from seclab.gui.i18n import stage_label, status_label


class MemoryPage(DataPage):
    """Present sanitizer outcomes and explain skipped or unavailable checks."""

    def __init__(self, parent=None):
        super().__init__("Phân tích bộ nhớ (Memory Analysis)",
                         ("Giai đoạn (Stage)", "Bộ kiểm tra (Checker)", "Trạng thái", "Chi tiết"), parent)

    def show_report(self, report):
        if report is None:
            self.table.set_records((("—", "—", "Chưa chạy",
                                     "Chọn ‘Chạy toàn bộ’ để chạy phân tích bộ nhớ."),))
            self.description.setText("Chưa có kết quả phân tích bộ nhớ.")
            return

        stage = next((item for item in report.stage_summaries
                      if str(item.get("stage_id", "")).upper() == "MEMORY"), None)
        rows = []
        seen = set()
        memory_stages = {"SANITIZER", "MEMORY", "MEMORY_ANALYSIS"}
        for result in report.results:
            result_stage = str(result.stage).upper().replace("-", "_")
            if result_stage not in memory_stages:
                continue
            key = (result.technique, result.reason_code, result.id)
            if key in seen:
                continue
            seen.add(key)
            detail = result.message
            evidence = ", ".join(result.evidence_ids)
            if evidence:
                detail += f" · Evidence: {evidence}"
            rows.append((stage_label(result.stage), result.technique,
                         status_label(result.status.value), detail))

        metadata = (stage or {}).get("metadata", {})
        capabilities = metadata.get("sanitizer_capabilities", ())
        known = {str(row[1]).casefold() for row in rows}
        for capability in capabilities:
            name = str(capability.get("sanitizer", "Sanitizer"))
            if name.casefold() in known:
                continue
            reason_code = capability.get("reason_code", "")
            capability_status = capability.get("capability_status", "UNKNOWN")
            detail = str(reason_code or capability_status)
            if capability.get("build_error"):
                detail += f" · Build: {capability['build_error']}"
            rows.append((stage_label("MEMORY"), name, status_label(capability_status), detail))

        if not rows:
            stage_status = str((stage or {}).get("status", "NO_RESULTS")).upper()
            reason = (stage or {}).get("reason")
            if not reason and stage_status == "COMPLETED":
                reason = "Stage hoàn tất nhưng không tạo kết quả sanitizer."
            elif not reason:
                reason = "Không có kết quả phân tích bộ nhớ trong lần chạy này."
            rows.append((stage_label("MEMORY"), "Pipeline", status_label(stage_status), reason))

        for limitation in report.limitations:
            if any(marker in str(limitation).casefold() for marker in
                   ("sanitizer", "struct layout", "memory", "addresssanitizer", "undefinedbehavior")):
                rows.append((stage_label("MEMORY"), "Giới hạn", status_label("INCONCLUSIVE"), str(limitation)))

        self.table.set_records(rows)
        self.description.setText(
            "Kết quả sanitizer chỉ phản ánh các lần build/chạy đã thực hiện. "
            "Trạng thái môi trường không hỗ trợ, bị bỏ qua và giới hạn được hiển thị riêng; "
            "không có phát hiện không đồng nghĩa với chứng minh an toàn bộ nhớ."
        )
