from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QTabWidget

from .base import DataPage
from seclab.gui.i18n import status_label


class StaticPage(DataPage):
    def __init__(self, parent=None):
        super().__init__("Phân tích tĩnh (Static Analysis) / Phân tích bộ nhớ (Memory Analysis)",
                         ("Bộ phân tích", "Trạng thái", "Lý do", "Số phát hiện", "Mức độ", "CWE", "Tệp", "Dòng", "Thông báo", "Bằng chứng (Evidence)"), parent)
        self.tabs = QTabWidget(self)
        self.static_table = DataPage("Phân tích tĩnh (Static Analysis)", ("Bộ phân tích", "Trạng thái", "Lý do", "Số phát hiện", "Mức độ", "CWE", "Tệp", "Dòng", "Thông báo", "Bằng chứng (Evidence)"))
        self.memory_table = DataPage("Phân tích bộ nhớ (Memory Analysis)", ("Công cụ", "Trạng thái", "Lý do", "Phát hiện", "Giới hạn", "Bằng chứng (Evidence)"))
        self.tabs.addTab(self.static_table, "Phân tích tĩnh (Static Analysis)")
        self.tabs.addTab(self.memory_table, "Phân tích bộ nhớ (Memory Analysis)")
        self.layout().insertWidget(2, self.tabs, 1)
        self.table.hide()
        self._evidence_cache: dict[str, tuple[dict, ...]] = {}

    def show_report(self, report):
        if report is None:
            self.static_table.table.set_records((("—", "Chưa chạy", "Chọn ‘Chạy toàn bộ’ để chạy phân tích tĩnh.",
                                                  0, "", "", "", "", "", ""),))
            self.memory_table.table.set_records(())
            self.description.setText("Chưa có kết quả. Phân tích tĩnh chạy trong pipeline sau khi nạp mã nguồn dự án.")
            return
        static_rows, memory_rows = [], []
        for result in report.results:
            meta = result.metadata
            result_stage = str(result.stage).upper().replace("-", "_")
            technique = str(result.technique).casefold()
            if result_stage in {"STATIC_ANALYSIS", "STATIC"} or technique in {
                "compiler", "cppcheck", "clang-tidy", "clang-static"
            }:
                findings = ()
                for evidence_id in result.evidence_ids:
                    if evidence_id not in self._evidence_cache:
                        continue
                    findings = (*findings, *self._evidence_cache[evidence_id])
                if not findings:
                    static_rows.append((meta.get("analyzer", result.technique), status_label(result.status.value),
                                        result.reason_code, len(meta.get("finding_ids", ())), "", "", "", "",
                                        result.message, ", ".join(result.evidence_ids)))
                for finding in findings:
                    cwe = finding.get("cwe")
                    if not isinstance(cwe, str) or not cwe.strip() or cwe.strip().casefold() == "null":
                        cwe = "Unclassified (tool provided no CWE)"
                    static_rows.append((meta.get("analyzer", result.technique), status_label(result.status.value),
                                        result.reason_code, len(findings), finding.get("severity", ""),
                                        cwe, finding.get("file", ""), finding.get("line", ""),
                                        finding.get("message", ""), ", ".join(result.evidence_ids)))
            elif result_stage in {"SANITIZER", "MEMORY", "MEMORY_ANALYSIS"}:
                memory_rows.append((result.technique, status_label(result.status.value), result.reason_code,
                                    len(meta.get("finding_ids", ())), meta.get("limitations", ()),
                                    ", ".join(result.evidence_ids)))
        for limitation in report.limitations:
            memory_rows.append(("Bộ phân tích cấu trúc / giới hạn pipeline", status_label("INCONCLUSIVE"), "LIMITATION", 0,
                                limitation, ""))
        static_stage = next((item for item in report.stage_summaries
                             if str(item.get("stage_id", "")).upper() == "STATIC"), None)
        if not static_rows:
            stage_status = str((static_stage or {}).get("status", "NO_RESULTS")).upper()
            reason = (static_stage or {}).get("reason")
            metadata = (static_stage or {}).get("metadata", {})
            if not reason and stage_status == "COMPLETED":
                analyzers = metadata.get("analyzers", ())
                reason = (f"Stage hoàn tất nhưng không trả kết quả từ bộ phân tích đã cấu hình: "
                          f"{', '.join(analyzers) if analyzers else 'không có bộ phân tích'}.")
            elif not reason:
                reason = "Không có kết quả phân tích tĩnh trong lần chạy này."
            static_rows.append(("Pipeline", status_label(stage_status), reason, 0, "", "", "", "", "", ""))
        self.static_table.table.set_records(static_rows)
        self.memory_table.table.set_records(memory_rows)
        self.description.setText("Trạng thái riêng của từng bộ phân tích và giới hạn do Windows/công cụ được lấy từ backend; nội dung chẩn đoán kỹ thuật gốc được giữ nguyên.")

    def load_evidence(self, manifest: dict, run_root: Path) -> None:
        cache = {}
        for item in manifest.get("evidence", ()):
            if str(item.get("stage", "")).lower().replace("-", "_") not in {"static", "static_analysis"}:
                continue
            try:
                path = (run_root / item["path"]).resolve(strict=True)
                if not path.is_relative_to(run_root.resolve()):
                    continue
                data = json.loads(path.read_text(encoding="utf-8"))
                cache[item["id"]] = tuple(data.get("findings", ()))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        self._evidence_cache = cache
