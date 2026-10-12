from __future__ import annotations

import json
import re
from pathlib import Path

from PySide6.QtCore import QMarginsF, Signal
from PySide6.QtGui import (QFont, QFontDatabase, QPageLayout, QPageSize, QTextBlockFormat, QTextCursor,
                           QTextDocument, QTextFormat)
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QPlainTextEdit,
                               QMenu, QMessageBox, QPushButton, QTabWidget, QVBoxLayout, QWidget)

from seclab.gui.widgets import ReadOnlyTable
from seclab.gui.i18n import TECH_TERM, STAGE_LABELS, STATUS_LABELS, checker_label, status_label, stage_label
from seclab.pipeline.teacher_report import render_teacher_report


class ReportPage(QWidget):
    evidenceActivated = Signal(str)
    resultActivated = Signal(str)
    historyRequested = Signal(str, str)
    accuracyReportRequested = Signal()
    evidenceVerifyRequested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._report = None
        self._evidence_ids: list[str] = []
        self._all_results = []
        self._visible_results = []
        root = QVBoxLayout(self)
        title = QLabel("Báo cáo kiểm chứng")
        title.setObjectName("pageTitle")
        self.description = QLabel("Tổng hợp từ quy trình kiểm chứng (Pipeline); không tạo kết luận PASS/FAIL chung cho toàn dự án.")
        self.description.setWordWrap(True)
        root.addWidget(title)
        self.description.setToolTip("Không tạo kết luận chung cho dự án; xem kết quả riêng của từng bộ kiểm tra và phạm vi cụ thể.")
        root.addWidget(self.description)

        controls = QHBoxLayout()
        self.history = QComboBox()
        self.open_history = QPushButton("Mở lần chạy đã chọn")
        self.open_history.clicked.connect(self._open_history)
        controls.addWidget(QLabel("Lịch sử chạy"))
        controls.addWidget(self.history, 1)
        controls.addWidget(self.open_history)
        self.export_json = QPushButton("Xuất báo cáo")
        self.export_json.setEnabled(False)
        export_menu = QMenu(self.export_json)
        export_menu.addAction("JSON đầy đủ", self._export)
        export_menu.addAction("Theo mẫu của thầy (Markdown)", self._export_teacher_report)
        export_menu.addAction("Theo mẫu của thầy (PDF)", self._export_teacher_pdf)
        self.export_json.setMenu(export_menu)
        controls.addWidget(self.export_json)
        self.open_accuracy_report = QPushButton("Mở báo cáo bộ đánh giá (Benchmark) / độ chính xác")
        self.open_accuracy_report.clicked.connect(self.accuracyReportRequested.emit)
        controls.addWidget(self.open_accuracy_report)
        for label in ("Xuất HTML",):
            button = QPushButton(label)
            button.setEnabled(False)
            button.setToolTip("Chưa có chức năng xuất báo cáo HTML.")
            controls.addWidget(button)
        self.export_pdf = QPushButton("Xuất PDF")
        self.export_pdf.setEnabled(False)
        self.export_pdf.setToolTip("Xuất báo cáo tích hợp theo mẫu của thầy thành PDF.")
        self.export_pdf.clicked.connect(self._export_teacher_pdf)
        controls.addWidget(self.export_pdf)
        root.addLayout(controls)

        tabs = QTabWidget()
        self.tabs = tabs
        self.run_table = ReadOnlyTable(("Mục", "Tên", "Chi tiết"))
        self.stage_filter = QComboBox()
        self.status_filter = QComboBox()
        self.stage_filter.addItem("Mọi giai đoạn")
        self.status_filter.addItem("Mọi trạng thái")
        self.stage_filter.currentTextChanged.connect(self._apply_result_filters)
        self.status_filter.currentTextChanged.connect(self._apply_result_filters)
        result_controls = QWidget()
        result_controls_layout = QHBoxLayout(result_controls)
        result_controls_layout.setContentsMargins(0, 0, 0, 0)
        result_controls_layout.addWidget(QLabel("Giai đoạn kiểm chứng"))
        result_controls_layout.addWidget(self.stage_filter)
        result_controls_layout.addWidget(QLabel("Trạng thái"))
        result_controls_layout.addWidget(self.status_filter)
        self.results_table = ReadOnlyTable(("Giai đoạn", "Bộ kiểm tra", "Mã thuộc tính / kiểm thử", "Trạng thái", "Mức độ",
                                            "Thời điểm giai đoạn", "Số bằng chứng", "Lý do"))
        self.evidence_table = ReadOnlyTable(("Mã bằng chứng", "Loại bằng chứng", "Nguồn tạo", "Mã kết quả", "Tệp bằng chứng",
                                             "SHA-256", "Dung lượng", "Thời điểm", "Toàn vẹn"))
        self.open_evidence = QPushButton("Mở tệp bằng chứng đã chọn")
        self.verify_evidence = QPushButton("Kiểm tra SHA-256")
        self.evidence_integrity = QLabel("Toàn vẹn: Chưa xác minh")
        self.trace_table = ReadOnlyTable(("Yêu cầu", "Thuộc tính / kiểm thử", "Kết quả", "Bằng chứng", "Mã nguồn"))
        self.accuracy_disclaimer = QLabel("Chỉ số được đo trên bộ fixture/benchmark hiện có; không chứng minh độ chính xác tổng quát của checker trên mọi hệ thống.")
        self.accuracy_disclaimer.setWordWrap(True)
        self.limits_table = ReadOnlyTable(("#", "Giới hạn"))
        self.history_table = ReadOnlyTable(("Mã lần chạy", "Thời điểm", "Dự án", "Đặc tả",
                                            "Stage / Kết quả / Bằng chứng", "Thư mục chạy", "Trạng thái"))
        self.accuracy_report = QPlainTextEdit()
        self.accuracy_report.setReadOnly(True)
        self.accuracy_report.setPlaceholderText("Mở báo cáo bộ đánh giá (Benchmark) hoặc độ chính xác (Markdown hoặc JSON). Nội dung báo cáo được giữ nguyên.")
        self.accuracy_report.textChanged.connect(self._ensure_accuracy_disclaimer)
        self.accuracy_tab = QWidget()
        accuracy_layout = QVBoxLayout(self.accuracy_tab)
        accuracy_layout.addWidget(QLabel("TP (True Positive) — Phát hiện đúng lỗi · TN (True Negative) — Xác định đúng trường hợp không lỗi · FP (False Positive) — Báo lỗi nhầm · FN (False Negative) — Bỏ sót lỗi.\nAccuracy — Độ chính xác · Precision — Độ chính xác trong cảnh báo · Recall — Khả năng phát hiện lỗi thực."))
        accuracy_layout.addWidget(self.accuracy_disclaimer)
        accuracy_layout.addWidget(self.accuracy_report, 1)
        for widget, label in ((self.run_table, "Tóm tắt lần chạy"), (self.results_table, "Kết quả"),
                              (self.evidence_table, "Bằng chứng kiểm chứng (Evidence)"), (self.trace_table, "Truy vết (Traceability)"),
                              (self.limits_table, "Giới hạn"), (self.history_table, "Lịch sử chạy"),
                              (self.accuracy_tab, "Bộ đánh giá (Benchmark) / Độ chính xác")):
            tabs.addTab(widget, label)
        self.results_tab = QWidget()
        results_layout = QVBoxLayout(self.results_tab)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.addWidget(result_controls)
        results_layout.addWidget(self.results_table, 1)
        tabs.removeTab(tabs.indexOf(self.results_table))
        tabs.insertTab(1, self.results_tab, "Kết quả")
        self.evidence_tab = QWidget()
        evidence_layout = QVBoxLayout(self.evidence_tab)
        evidence_layout.setContentsMargins(0, 0, 0, 0)
        evidence_layout.addWidget(self.evidence_table, 1)
        evidence_layout.addWidget(self.evidence_integrity)
        evidence_layout.addWidget(self.verify_evidence)
        evidence_layout.addWidget(self.open_evidence)
        self.trace_table.setToolTip("Yêu cầu → thuộc tính cần kiểm chứng → kiểm thử → kết quả → bằng chứng → mã nguồn")
        self.accuracy_disclaimer.setToolTip("Các chỉ số chỉ áp dụng cho bộ fixture/benchmark hiện có.")
        tabs.removeTab(tabs.indexOf(self.evidence_table))
        tabs.insertTab(2, self.evidence_tab, "Bằng chứng kiểm chứng (Evidence)")
        root.addWidget(tabs, 1)
        self.evidence_table.cellDoubleClicked.connect(self._activate_evidence)
        self.open_evidence.clicked.connect(self._open_selected_evidence)
        self.verify_evidence.clicked.connect(self._verify_selected_evidence)
        self.results_table.cellDoubleClicked.connect(self._activate_result)
        self.history_table.cellDoubleClicked.connect(self._select_history_row)

    def show_report(self, report) -> None:
        self._report = report
        self.export_json.setEnabled(report is not None)
        self.export_pdf.setEnabled(report is not None)
        if report is None:
            self.description.setText("Mở dự án và chạy kiểm chứng để hiển thị dữ liệu tại đây.")
            self._evidence_ids = []
            self._all_results = []
            self._visible_results = []
            for table in (self.run_table, self.results_table, self.evidence_table, self.trace_table,
                          self.limits_table, self.history_table):
                table.set_records(())
            return
        self.description.setText(f"Lần chạy {report.run_id} · {report.duration_seconds:.2f}s · không có kết luận chung cho toàn dự án")
        run_rows = [("Lần chạy", "Mã", report.run_id), ("Lần chạy", "Bắt đầu", report.start_time.isoformat()),
                    ("Lần chạy", "Kết thúc", report.end_time.isoformat()),
                    ("Lần chạy", "Thời lượng", f"{report.duration_seconds:.3f}s")]
        run_rows.extend(("Đặc tả", key, value) for key, value in report.specification_info.items())
        run_rows.extend(("Giai đoạn", stage_label(str(stage.get("stage_id"))),
                         f"{status_label(str(stage.get('status')))} · {stage.get('reason') or ''}") for stage in report.stage_summaries)
        run_rows.extend(("Tổng hợp trạng thái", status_label(key), count) for key, count in report.status_counts.items())
        run_rows.append(("Bản kê bằng chứng", "Đường dẫn", report.evidence_manifest.get("path", "")))
        self.run_table.set_records(run_rows)
        stage_times = {str(stage.get("stage_id")): stage.get("finished_at") or stage.get("end_time", "")
                       for stage in report.stage_summaries}
        self._all_results = [(item, self._result_stage(item), stage_times, self._severity(item))
                             for item in report.results]
        self._refresh_filter_values()
        self._apply_result_filters()
        evidence_rows = []
        self._evidence_ids = []
        for item in getattr(report, "evidence_records", ()):
            self._evidence_ids.append(item.get("id", ""))
            result_ids = [result.id for result in report.results if item.get("id", "") in result.evidence_ids]
            evidence_rows.append((item.get("id", ""), item.get("type", ""), item.get("source", ""),
                                  ", ".join(result_ids), item.get("path", ""), item.get("hash", ""),
                                  item.get("size_bytes", ""), item.get("created_at", ""), "Chưa xác minh toàn vẹn"))
        for item in report.results:
            for evidence_id in item.evidence_ids:
                if evidence_id not in self._evidence_ids:
                    self._evidence_ids.append(evidence_id)
                    evidence_rows.append((evidence_id, "Referenced", "", item.id, "", "", "",
                                          "Mở mục trong manifest", "Chưa xác minh toàn vẹn"))
        self.evidence_table.set_records(evidence_rows)
        trace_rows = []
        known_result_ids = {item.id for item in report.results}
        known_evidence_ids = set(self._evidence_ids)
        known_evidence_ids.update(evidence_id for item in report.results for evidence_id in item.evidence_ids)
        requirement_sources: dict[str, list[str]] = {}
        for source in report.metadata.get("source_inventory", {}).get("files", ()):
            source_label = f"{source.get('project_relative_path', '')} [{source.get('source_id', '')}]"
            for requirement_id in source.get("requirement_ids", ()):
                requirement_sources.setdefault(requirement_id, []).append(source_label)
        for requirement, value in report.traceability.items():
            if isinstance(value, dict):
                targets = value.get("targets", {})
                if targets:
                    for target_id, target in targets.items():
                        result_refs = tuple(target.get("results", ()))
                        evidence_refs = tuple(target.get("evidence_ids", ()))
                        broken = [f"result:{value}" for value in result_refs if value not in known_result_ids]
                        broken.extend(f"evidence:{value}" for value in evidence_refs if value not in known_evidence_ids)
                        status = f"BROKEN LINK: {', '.join(broken)}" if broken else target.get("status", "NOT_CHECKED")
                        trace_rows.append((requirement, target_id, status,
                            ", ".join(evidence_refs), ", ".join(requirement_sources.get(requirement, ()))))
                else:
                    result_refs = tuple(value.get("results", ()))
                    evidence_refs = tuple(value.get("evidence_ids", ()))
                    broken = [f"result:{item}" for item in result_refs if item not in known_result_ids]
                    broken.extend(f"evidence:{item}" for item in evidence_refs if item not in known_evidence_ids)
                    status = f"BROKEN LINK: {', '.join(broken)}" if broken else value.get("status", "NOT_CHECKED")
                    trace_rows.append((requirement, ", ".join(value.get("checker_refs", ())), status,
                        ", ".join(evidence_refs), ", ".join(requirement_sources.get(requirement, ()))))
            else:
                trace_rows.append((requirement, "", "UNRESOLVED: legacy trace entry", str(value), ""))
        self.trace_table.set_records(trace_rows)
        self.limits_table.set_records([(index, value) for index, value in enumerate(report.limitations, 1)])

    def set_history(self, history: tuple[dict, ...]) -> None:
        self.history.clear()
        self.history_table.set_records(tuple((item.get("run_id", ""), item.get("timestamp", item.get("date", "")),
            item.get("project", ""), item.get("specification", ""),
            f"{', '.join(f'{stage}={status}' for stage, status in item.get('stage_statuses', {}).items()) or item.get('stage_count', 0)} / {item.get('result_count', 'N/A')} / {item.get('evidence_count', 'N/A')}",
            item.get("workspace", ""), item.get("completion_state", "UNKNOWN"))
            for item in history))
        for item in history:
            self.history.addItem(f"{item.get('run_id', '')} · {item.get('timestamp', item.get('date', ''))}", item)

    def set_accuracy_report(self, path: str, content: str) -> None:
        self.accuracy_report.setPlainText(f"Báo cáo: {path}\n\n{content}")
        self.accuracy_disclaimer.setVisible(True)
        self.tabs.setCurrentWidget(self.accuracy_tab)

    def set_evidence_integrity(self, evidence_id: str, status: str, detail: str = "") -> None:
        display_status = TECH_TERM.get(status, status)
        self.evidence_integrity.setText(f"{evidence_id}: {display_status}" + (f" — {detail}" if detail else ""))

    def set_evidence(self, records: tuple[dict, ...]) -> None:
        self._evidence_ids = [str(item.get("id", "")) for item in records]
        self.evidence_table.set_records([
            (item.get("id", ""), item.get("type", ""), item.get("source", ""),
             ", ".join(item.get("result_ids", ())), item.get("path", ""), item.get("hash", ""),
             item.get("size_bytes", ""), item.get("created_at", ""), "Chưa xác minh toàn vẹn") for item in records
        ])

    def _open_history(self) -> None:
        item = self.history.currentData()
        if item:
            self.historyRequested.emit(item["report"], item.get("run_root", str(Path(item["manifest"]).parents[2])))

    def _select_history_row(self, row: int, _column: int) -> None:
        if 0 <= row < self.history.count():
            self.history.setCurrentIndex(row)
            self._open_history()

    def _activate_evidence(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._evidence_ids) and self._evidence_ids[row]:
            self.evidenceActivated.emit(self._evidence_ids[row])

    def _activate_result(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._visible_results):
            self.resultActivated.emit(self._visible_results[row].id)

    def _open_selected_evidence(self) -> None:
        row = self.evidence_table.currentRow()
        if 0 <= row < len(self._evidence_ids) and self._evidence_ids[row]:
            self.evidenceActivated.emit(self._evidence_ids[row])

    def _verify_selected_evidence(self) -> None:
        row = self.evidence_table.currentRow()
        if 0 <= row < len(self._evidence_ids) and self._evidence_ids[row]:
            self.evidenceVerifyRequested.emit(self._evidence_ids[row])

    def _ensure_accuracy_disclaimer(self) -> None:
        # Keep the fixture-specific scope visible whenever the report page is used.
        self.accuracy_disclaimer.setVisible(True)

    def _refresh_filter_values(self) -> None:
        selected_stage, selected_status = self.stage_filter.currentText(), self.status_filter.currentText()
        selected_status_id = self.status_filter.currentData() or selected_status.split(" — ", 1)[0]
        stages = sorted({self._result_stage(result) for result, *_ in self._all_results})
        statuses = sorted({"PASS", "FAIL", "INCONCLUSIVE", "TOOL_ERROR", "BUILD_ERROR", "NOT_RUN"}
                          | {result.status.value for result, *_ in self._all_results})
        self.stage_filter.blockSignals(True)
        self.status_filter.blockSignals(True)
        self.stage_filter.clear()
        localized_stages = [stage_label(stage) for stage in stages]
        self.stage_filter.addItems(("Mọi giai đoạn", *localized_stages))
        self.status_filter.clear()
        self.status_filter.addItem("Mọi trạng thái")
        for status in statuses:
            self.status_filter.addItem(status_label(status), status)
        display_stage = stage_label(selected_stage)
        if selected_stage in stages or selected_stage in localized_stages or selected_stage == "Mọi giai đoạn":
            self.stage_filter.setCurrentText(display_stage if selected_stage != "Mọi giai đoạn" else selected_stage)
        if selected_status_id in statuses:
            self.status_filter.setCurrentIndex(self.status_filter.findData(selected_status_id))
        elif selected_status == "Mọi trạng thái":
            self.status_filter.setCurrentText(selected_status)
        self.stage_filter.blockSignals(False)
        self.status_filter.blockSignals(False)

    def _apply_result_filters(self, _value: str = "") -> None:
        stage_filter = self.stage_filter.currentText()
        stage_filter_id = next((key for key, value in STAGE_LABELS.items() if value == stage_filter), stage_filter)
        status_filter = self.status_filter.currentData() or self.status_filter.currentText().split(" — ", 1)[0]
        self._visible_results = []
        rows = []
        for result, stage_id, stage_times, severity in self._all_results:
            if stage_filter != "Mọi giai đoạn" and stage_id != stage_filter_id:
                continue
            if status_filter != "Mọi trạng thái" and result.status.value != status_filter:
                continue
            self._visible_results.append(result)
            property_or_test = result.property_id or result.metadata.get("test_case_id") or result.metadata.get("target_id") or ""
            status = result.status.value
            rows.append((stage_label(stage_id), checker_label(result.technique), property_or_test, status_label(status), severity,
                         stage_times.get(stage_id, "") or "chưa ghi nhận", len(result.evidence_ids), result.reason_code))
        self.results_table.set_records(rows)

    @staticmethod
    def _result_stage(result) -> str:
        technique = result.technique.upper()
        if technique in {"CTL", "BMC", "SMT"}:
            return technique
        return {"STATIC_ANALYSIS": "STATIC", "SANITIZER": "MEMORY", "MEMORY_ANALYSIS": "MEMORY",
                "DYNAMIC_TEST": "DYNAMIC", "COVERAGE": "COVERAGE", "FUZZING": "FUZZING",
                "SPECIFICATION": "SPECIFICATION", "SOURCE": "SOURCE", "REPORT": "REPORT"}.get(
                    result.stage.upper(), result.stage.upper())

    @staticmethod
    def _severity(result) -> str:
        metadata = result.metadata
        value = metadata.get("severity", metadata.get("maximum_severity", metadata.get("severities", "")))
        if isinstance(value, (tuple, list, set)):
            return ", ".join(str(item) for item in value)
        return str(value or "")

    def _export(self) -> None:
        if self._report is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất báo cáo quy trình kiểm chứng", "pipeline-report.json", "JSON (*.json)")
        if path:
            target = Path(path)
            if target.suffix.lower() != ".json":
                target = target.with_suffix(".json")
            try:
                target.write_text(json.dumps(self._report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception as exc:
                QMessageBox.critical(self, "Không thể xuất báo cáo", f"Không ghi được tệp:\n{target}\n\n{exc}")
            else:
                QMessageBox.information(self, "Đã xuất báo cáo", f"Đã lưu JSON tại:\n{target}")

    def _export_teacher_report(self) -> None:
        if self._report is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất báo cáo theo mẫu", "verification-report-template.md",
                                              "Markdown (*.md)")
        if path:
            target = Path(path)
            if target.suffix.lower() != ".md":
                target = target.with_suffix(".md")
            try:
                content = render_teacher_report(self._report)
                target.write_text(content, encoding="utf-8")
            except Exception as exc:
                QMessageBox.critical(self, "Không thể xuất báo cáo", f"Không tạo/ghi được tệp:\n{target}\n\n{exc}")
            else:
                QMessageBox.information(self, "Đã xuất báo cáo", f"Đã lưu báo cáo Markdown tại:\n{target}")

    def _export_teacher_pdf(self) -> None:
        if self._report is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Xuất báo cáo PDF theo mẫu", "verification-report.pdf",
                                              "PDF (*.pdf)")
        if not path:
            return
        target = Path(path)
        if target.suffix.lower() != ".pdf":
            target = target.with_suffix(".pdf")
        try:
            markdown = render_teacher_report(self._report)
            # Qt prints CommonMark to PDF directly. Replace Mermaid source with a
            # concise note; the report's state/transition counts and edge evidence
            # remain in the PDF, while the Markdown export keeps the renderable graph.
            printable = re.sub(r"```mermaid\s+.*?```", "[Sơ đồ Mermaid được bảo toàn trong bản Markdown; PDF thể hiện mô hình bằng bảng trạng thái/chuyển tiếp.]",
                               markdown, flags=re.DOTALL)
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(str(target))
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setPageMargins(QMarginsF(16, 16, 16, 16), QPageLayout.Unit.Millimeter)
            specification_id = self._report.specification_info.get("id", "SecLab")
            printer.setDocName(f"SecLab verification report - {specification_id}")
            _load_pdf_font()
            document = QTextDocument(self)
            document.setDefaultFont(QFont("Segoe UI", 10))
            document.setDefaultStyleSheet("""
                body { font-family: "Segoe UI", sans-serif; font-size: 9.5pt; color: #263746; }
                h1 { color: #123b55; background-color: #eaf2f7; font-size: 25pt; text-align: center;
                     margin: 34pt 0 18pt; padding: 22pt 16pt; border-bottom: 4px solid #147d98; }
                h2 { color: #155e75; background-color: #edf4f7; font-size: 15pt; margin-top: 18pt;
                     padding: 7pt; border-bottom: 1px solid #8aa5b3; }
                h3 { color: #245a70; font-size: 11.5pt; margin-top: 12pt; }
                p { margin: 4pt 0; line-height: 1.2; }
                table { border-collapse: collapse; width: 100%; margin: 7pt 0 12pt; }
                th { background-color: #dceaf0; color: #173b50; font-weight: bold; }
                td, th { border: 1px solid #b8c7cf; padding: 4pt; }
                blockquote { color: #526777; background-color: #f1f5f7; margin: 7pt 0; padding: 7pt; }
                code, pre { font-family: Consolas, monospace; font-size: 8.5pt; color: #244c64; white-space: pre-wrap; }
                a { color: #087b9a; text-decoration: none; }
                li { margin: 2pt 0; }
            """)
            document.setMarkdown(printable)
            block = document.begin()
            while block.isValid():
                title = block.text().strip()
                is_section_heading = block.blockFormat().headingLevel() == 2 and re.match(r"^[1-7]\.\s", title)
                is_report_subsection = (block.blockFormat().headingLevel() == 3 and
                                        title.startswith(("Finding tiêu biểu", "Ma trận truy vết")))
                if is_section_heading or is_report_subsection:
                    block_format = QTextBlockFormat(block.blockFormat())
                    block_format.setPageBreakPolicy(QTextFormat.PageBreakFlag.PageBreak_AlwaysBefore)
                    QTextCursor(block).setBlockFormat(block_format)
                block = block.next()
            document.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())
            if not printer.isValid():
                raise OSError("Qt không khởi tạo được bộ ghi PDF.")
            document.print_(printer)
            if not target.is_file() or target.stat().st_size == 0:
                raise OSError("Qt không tạo được nội dung PDF.")
        except Exception as exc:
            QMessageBox.critical(self, "Không thể xuất PDF", f"Không tạo/ghi được tệp:\n{target}\n\n{exc}")
        else:
            QMessageBox.information(self, "Đã xuất PDF", f"Đã lưu báo cáo PDF tại:\n{target}")


def _load_pdf_font() -> None:
    """Register a real Windows font file so Qt's PDF backend embeds its glyphs."""
    import os
    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    for font_file in (windows_root / "Fonts" / "segoeui.ttf", windows_root / "Fonts" / "arial.ttf"):
        if font_file.is_file() and QFontDatabase.addApplicationFont(str(font_file)) >= 0:
            return



