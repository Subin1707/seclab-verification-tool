"""Dedicated read-only projections for run results, evidence, history, and accuracy."""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout

from .base import DataPage
from seclab.gui.i18n import MESSAGE_LABELS, stage_label, status_label


class ResultsPage(DataPage):
    resultActivated = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__("Kết quả kiểm chứng", ("Giai đoạn", "Bộ kiểm tra", "Thuộc tính / kiểm thử", "Trạng thái", "Lý do", "Bằng chứng"), parent)
        self.table.cellDoubleClicked.connect(self._activate)
        self._result_ids: list[str] = []
        self._live_result_ids: set[str] = set()

    def show_report(self, report: Any | None) -> None:
        self._result_ids = []
        self._live_result_ids.clear()
        if report is None:
            self.table.set_records(())
            self.description.setText("Hiển thị kết quả riêng của từng bộ kiểm tra; không tạo kết luận PASS/FAIL tổng thể cho dự án.")
            return
        rows = []
        for result in report.results:
            self._result_ids.append(result.id)
            target = result.property_id or result.metadata.get("test_case_id") or result.metadata.get("target_id", "")
            rows.append((stage_label(result.stage), result.technique, target, status_label(result.status.value),
                         result.message, ", ".join(result.evidence_ids)))
        self.table.set_records(rows)
        self.description.setText(f"{len(report.results)} kết quả trong lần chạy {report.run_id}; trạng thái được giữ riêng theo từng giai đoạn và bộ kiểm tra.")

    def append_live_results(self, records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> None:
        rows = []
        for result in records:
            result_id = str(result.get("id", ""))
            if not result_id or result_id in self._live_result_ids:
                continue
            self._live_result_ids.add(result_id)
            self._result_ids.append(result_id)
            target = result.get("property_id") or (result.get("metadata") or {}).get("test_case_id") \
                or (result.get("metadata") or {}).get("target_id", "")
            rows.append((stage_label(result.get("stage", "")), result.get("technique", ""), target,
                         status_label(str(result.get("status", "UNKNOWN"))), result.get("message", ""),
                         ", ".join(result.get("evidence_ids", ()))))
        if rows:
            self.table.append_records(rows)
            self.description.setText(f"Đang phân tích · đã nhận {len(self._live_result_ids)} kết quả từ các stage đã hoàn tất.")

    def _activate(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._result_ids):
            self.resultActivated.emit(self._result_ids[row])


class EvidencePage(DataPage):
    evidenceActivated = Signal(str)
    evidenceVerifyRequested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__("Bằng chứng kiểm chứng (Evidence)", ("Mã", "Loại", "Giai đoạn", "Bộ kiểm tra", "Đường dẫn", "SHA-256", "Dung lượng (byte)", "Mã lần chạy"), parent)
        self._ids: list[str] = []
        self._live_evidence_ids: set[str] = set()
        self.table.cellDoubleClicked.connect(self._activate)
        controls = QVBoxLayout()
        self.open_button = QPushButton("Mở bằng chứng đã chọn")
        self.verify_button = QPushButton("Kiểm tra tính toàn vẹn")
        controls.addWidget(self.open_button)
        controls.addWidget(self.verify_button)
        self.layout().addLayout(controls)
        self.integrity = QLabel("Chưa kiểm tra tính toàn vẹn của bằng chứng.")
        self.layout().addWidget(self.integrity)
        self.open_button.clicked.connect(self._open_selected)
        self.verify_button.clicked.connect(self._verify_selected)

    def set_evidence(self, records: tuple[dict[str, Any], ...]) -> None:
        self._live_evidence_ids = {str(item.get("id", "")) for item in records if item.get("id")}
        self._ids = [str(item.get("id", "")) for item in records]
        self.table.set_records([(item.get("id", ""), item.get("type", ""), stage_label(item.get("stage", "")),
            item.get("checker", ""), item.get("path", ""), item.get("hash", ""),
            item.get("size_bytes", ""), item.get("run_id", "")) for item in records])
        self.description.setText(f"Đã ghi {len(records)} mục bằng chứng trong bản kê chạy (Manifest).")

    def append_live_evidence(self, records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> None:
        rows = []
        for item in records:
            evidence_id = str(item.get("id", ""))
            if not evidence_id or evidence_id in self._live_evidence_ids:
                continue
            self._live_evidence_ids.add(evidence_id)
            self._ids.append(evidence_id)
            rows.append((evidence_id, item.get("type", ""), stage_label(item.get("stage", "")),
                         item.get("checker", ""), item.get("path", ""), item.get("hash", ""),
                         item.get("size_bytes", ""), item.get("run_id", "")))
        if rows:
            self.table.append_records(rows)
            self.description.setText(f"Đang phân tích · đã nhận {len(self._live_evidence_ids)} mục bằng chứng.")

    def set_integrity(self, evidence_id: str, status: str, detail: str = "") -> None:
        self.integrity.setText(f"{evidence_id}: {status_label(status)}" + (f" · {detail}" if detail else ""))

    def _selected_id(self) -> str | None:
        row = self.table.currentRow()
        return self._ids[row] if 0 <= row < len(self._ids) else None

    def _activate(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._ids):
            self.evidenceActivated.emit(self._ids[row])

    def _open_selected(self) -> None:
        selected = self._selected_id()
        if selected:
            self.evidenceActivated.emit(selected)

    def _verify_selected(self) -> None:
        selected = self._selected_id()
        if selected:
            self.evidenceVerifyRequested.emit(selected)


class TraceabilityPage(DataPage):
    def __init__(self, parent=None) -> None:
        super().__init__("Truy vết (Traceability)", ("Yêu cầu", "Thuộc tính / kiểm thử", "Mô hình", "Bộ kiểm tra / kết quả", "Bằng chứng", "Mã nguồn"), parent)

    def show_report(self, report: Any | None) -> None:
        if report is None:
            self.table.set_records(())
            return
        rows = []
        for requirement_id, record in report.traceability.items():
            model = record.get("model", {})
            sources = record.get("sources", ())
            targets = record.get("targets", {})
            if not targets:
                rows.append((requirement_id, ", ".join(record.get("checker_refs", ())),
                    model.get("model_hash", ""), ", ".join(record.get("results", ())),
                    ", ".join(record.get("evidence_ids", ())), ", ".join(item.get("path", "") for item in sources)))
            for target_id, target in targets.items():
                rows.append((requirement_id, target_id, model.get("model_hash", target.get("model_hash", "")),
                    ", ".join(target.get("results", ())) or stage_label(target.get("stage_id", "")),
                    ", ".join(target.get("evidence_ids", ())),
                    ", ".join(item.get("path", "") for item in sources)))
        self.table.set_records(rows)
        self.description.setText("Yêu cầu → Thuộc tính / Kiểm thử → Mô hình → Bộ kiểm tra → Kết quả → Bằng chứng → Mã nguồn")


class HistoryPage(DataPage):
    runActivated = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__("Lịch sử chạy", ("Mã lần chạy (Run ID)", "Thời điểm", "Dự án", "Đặc tả", "Số giai đoạn", "Số kết quả", "Số bằng chứng", "Thư mục lưu"), parent)
        self._run_ids: list[str] = []
        self.table.cellDoubleClicked.connect(self._activate)

    def set_history(self, history: tuple[dict[str, Any], ...]) -> None:
        self._run_ids = [str(item.get("run_id", "")) for item in history]
        self.table.set_records([(item.get("run_id", ""), item.get("timestamp", ""), item.get("project", ""),
            item.get("specification", ""), item.get("stage_count", 0), item.get("result_count", 0),
            item.get("evidence_count", 0), item.get("workspace", "")) for item in history])
        self.description.setText("Nhấp đúp vào một lần chạy để mở báo cáo đã lưu ở chế độ chỉ đọc.")

    def _activate(self, row: int, _column: int) -> None:
        if 0 <= row < len(self._run_ids):
            self.runActivated.emit(self._run_ids[row])


class AccuracyPage(DataPage):
    reportRequested = Signal()
    runRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__("Độ chính xác (Accuracy)", ("Chỉ số", "Giá trị", "Phạm vi"), parent)
        self.run_button = QPushButton("Chạy benchmark độ chính xác")
        self.open_button = QPushButton("Mở report benchmark đã lưu")
        self.layout().addWidget(self.run_button)
        self.layout().addWidget(self.open_button)
        self.run_button.clicked.connect(self.runRequested.emit)
        self.open_button.clicked.connect(self.reportRequested.emit)
        self.description.setText("Các chỉ số mô tả bộ đánh giá đã chạy; không tạo kết luận cho toàn dự án.")

    def show_accuracy_report(self, path: str, content: str) -> None:
        import json
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            payload = None
        metrics = payload.get("checker_metrics") if isinstance(payload, dict) else None
        if isinstance(metrics, dict) and metrics:
            rows = []
            for checker, values in sorted(metrics.items()):
                selected = {key: values.get(key) for key in (
                    "TP", "TN", "FP", "FN", "accuracy", "precision", "recall", "specificity",
                    "false_positive_rate", "false_negative_rate", "metrics_ready") if key in values}
                rows.append((checker, selected, f"Fixture-level only · {path}"))
            self.table.set_records(tuple(rows))
            self.description.setText(
                f"Benchmark đã nạp: {payload.get('benchmark_count', '—')} fixture(s). "
                "Chỉ số theo checker, không đại diện độ chính xác tổng quát."
            )
            return
        if isinstance(payload, dict):
            self.table.set_records((("Báo cáo JSON", "Không tìm thấy checker_metrics", path),))
            self.description.setText("Tệp JSON đã mở nhưng không có cấu trúc báo cáo Accuracy được nhận diện.")
            return
        metric_rows = []
        for line in content.splitlines():
            if not line.startswith("|") or "---" in line or "Checker" in line:
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) >= 7:
                metric_rows.append((cells[0],
                    {"TP": cells[1], "TN": cells[2], "FP": cells[3], "FN": cells[4],
                     "Accuracy": cells[5], "Precision": cells[6],
                     "Recall": cells[7] if len(cells) > 7 else "N/A"},
                    f"Fixture-level only · {path}"))
        if metric_rows:
            self.table.set_records(tuple(metric_rows))
            self.description.setText("Benchmark Markdown đã nạp. Chỉ số theo checker trên fixture được liệt kê; không đại diện độ chính xác tổng quát.")
        else:
            self.table.set_records((("Báo cáo", "Không tìm thấy bảng metrics", path),))
            self.description.setText("Tệp đã mở nhưng không có bảng metrics theo định dạng được nhận diện.")

    def set_benchmark_running(self) -> None:
        self.run_button.setEnabled(False)
        self.table.set_records((("RUNNING", "Benchmark đang chạy", "Bộ fixture chuẩn tích hợp; chạy nền."),))
        self.description.setText("Đang thực thi các case benchmark và lưu evidence. Giao diện vẫn hoạt động bình thường.")

    def show_benchmark_result(self, payload: dict[str, Any], path: str) -> None:
        self.run_button.setEnabled(True)
        metrics = payload.get("checker_metrics", {})
        cases = payload.get("expected_vs_actual", ())
        rows = []
        for checker, values in sorted(metrics.items()):
            summary = {key: values.get(key) for key in (
                "TP", "TN", "FP", "FN", "accuracy", "precision", "recall",
                "specificity", "inconclusive", "unsupported", "environment_limited",
                "tool_errors", "build_errors") if key in values}
            rows.append((checker, summary, "Fixture benchmark · per checker"))
        self.table.set_records(tuple(rows) or (("NO_RESULTS", "No checker metrics", path),))
        self.description.setText(
            f"Benchmark hoàn tất: {payload.get('benchmark_count', len(cases))} fixture(s), "
            f"{len(payload.get('mismatches', ())) } sai khác, {len(cases)} case có đối chiếu. "
            f"Kết quả chỉ áp dụng cho fixture; report và evidence: {path}"
        )

    def show_report(self, report: Any | None) -> None:
        if report is None:
            return super().show_report(report)
        self.table.set_records((("UNSUPPORTED", "—", "Pipeline không chạy benchmark; mở report Benchmark bên dưới để xem metrics."),))
        self.description.setText(
            "CHƯA CÓ BÁO CÁO ĐÁNH GIÁ (UNSUPPORTED): lần chạy này không tính Accuracy. "
            "Hãy mở báo cáo Benchmark riêng; không suy ra độ chính xác từ kết quả kiểm chứng."
        )
