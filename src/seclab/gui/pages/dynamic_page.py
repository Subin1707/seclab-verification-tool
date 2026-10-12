from __future__ import annotations

import json
from typing import Any

from PySide6.QtWidgets import QLabel, QTabWidget, QVBoxLayout, QWidget

from .base import DataPage
from seclab.gui.i18n import status_label
from seclab.gui.widgets import DetailDialog


class DynamicPage(DataPage):
    """Read-only analysis view over the pipeline's real dynamic and coverage data."""

    def __init__(self, parent=None):
        super().__init__("Kiểm thử động (Dynamic Testing) / Độ bao phủ (Coverage)",
                         ("Test case", "Function", "Source / model", "Input / model step", "Requirements",
                          "Build", "Executed", "Exit / return", "Expected (oracle)", "Observed output",
                          "Verdict", "Reason", "Evidence IDs", "Duration"), parent)
        self.tabs = QTabWidget(self)
        self.tests = DataPage("Kiểm thử động (Dynamic Testing)",
            ("Test case", "Function", "Source / model", "Input / model step", "Requirements",
             "Build", "Executed", "Exit / return", "Expected (oracle)", "Observed output",
             "Verdict", "Reason", "Evidence IDs", "Duration"))
        self.coverage = DataPage("Độ bao phủ (Coverage)",
            ("Chỉ số", "Tệp", "Được bao phủ", "Bỏ sót", "Tỷ lệ", "Công cụ", "Giới hạn"))
        self.tests.description.setText("Mỗi dòng là một testcase và verdict trong phạm vi testcase đó. Chọn dòng để xem observation thực, oracle, result và evidence.")
        self.coverage.description.setText("Coverage là phép đo trên các lần chạy đã thực hiện; nó không phải kết luận an toàn.")
        self.tabs.addTab(self.tests, "Kiểm thử động (Dynamic Testing)")
        self.tabs.addTab(self.coverage, "Độ bao phủ (Coverage)")
        self.layout().insertWidget(2, self.tabs, 1)
        self.table.hide()
        self.summary = QLabel("Chưa có lần chạy để phân tích.", self)
        self.summary.setWordWrap(True)
        self.summary.setObjectName("analysisSummary")
        self.layout().insertWidget(2, self.summary)
        self.tests.table.cellDoubleClicked.connect(self._show_test_detail)
        self._result_by_row: list[Any] = []
        self._execution_by_row: list[dict[str, Any]] = []
        self.tests.table.setHorizontalScrollMode(self.tests.table.ScrollMode.ScrollPerPixel)
        for column, width in enumerate((190, 190, 145, 240, 150, 190, 100, 160, 300, 340, 145, 300, 260, 110)):
            self.tests.table.setColumnWidth(column, width)

    def show_report(self, report):
        if report is None:
            self.summary.setText("Chưa có lần chạy. Mở dự án, nạp đặc tả và chạy pipeline để thu thập observation và coverage.")
            self.tests.table.set_records(())
            self.coverage.table.set_records(())
            self.description.setText("Chưa có dữ liệu kiểm thử động hoặc coverage.")
            self._result_by_row = []
            return

        stages = {str(item.get("stage_id", "")).upper(): item for item in report.stage_summaries}
        dynamic_stage = stages.get("DYNAMIC", {})
        coverage_stage = stages.get("COVERAGE", {})
        dynamic_results = [item for item in report.results
                           if str(item.stage).upper().replace("-", "_") in {"DYNAMIC", "DYNAMIC_TEST"}]
        execution_index = getattr(report, "metadata", {}).get("execution_index", {})
        executed = [item for item in dynamic_results if item.metadata.get("executed") is True]
        statuses: dict[str, int] = {}
        for result in dynamic_results:
            statuses[result.status.value] = statuses.get(result.status.value, 0) + 1
        dmeta = dynamic_stage.get("metadata") or {}
        counts = ", ".join(f"{status_label(name)}: {count}" for name, count in sorted(statuses.items())) or "chưa có result"
        dynamic_status = str(dynamic_stage.get("status", "NOT_RUN")).upper()
        reason = dynamic_stage.get("reason") or dmeta.get("reason") or ""
        if not reason and dynamic_status == "COMPLETED" and not dynamic_results:
            reason = "Stage hoàn tất nhưng report không chứa dynamic result; chưa có verdict testcase để phân tích."
        dynamic_line = (f"Dynamic · {status_label(dynamic_status)} · testcase: {dmeta.get('test_count', len(dynamic_results))} · "
                        f"đã thực thi: {dmeta.get('executed_count', len(executed))} · {counts}")
        if reason:
            dynamic_line += f"\nLý do/giới hạn: {reason}"

        cstatus = str(coverage_stage.get("status", "NOT_RUN")).upper()
        cdata = coverage_stage.get("output") or {}
        if cstatus == "COMPLETED" and cdata.get("line_metrics"):
            lm, bm = cdata.get("line_metrics", {}), cdata.get("branch_metrics", {})
            coverage_line = (f"Coverage · {status_label(cstatus)} · line {lm.get('covered_lines', 0)}/{lm.get('total_lines', 0)} "
                             f"({lm.get('percentage', '—')}%) · branch {bm.get('covered_branches', 0)}/"
                             f"{bm.get('total_branches', 0)} ({bm.get('percentage', '—')}%) · backend {cdata.get('backend', '—')}")
        else:
            coverage_line = f"Coverage · {status_label(cstatus)} · chưa có số đo coverage."
            creason = coverage_stage.get("reason") or (coverage_stage.get("metadata") or {}).get("reason")
            if creason:
                coverage_line += f" Lý do: {creason}"
        self.summary.setText(dynamic_line + "\n" + coverage_line + "\nDouble-click một testcase để mở chi tiết observation và evidence.")

        rows = []
        self._result_by_row = []
        self._execution_by_row = []
        for result in dynamic_results:
            metadata = result.metadata
            execution = execution_index.get(metadata.get("execution_id"), {})
            observation = execution.get("observation") or metadata.get("observation")
            executed_value = execution.get("executed", metadata.get("executed"))
            executed = "Yes" if executed_value is True else "No" if executed_value is False else "Unknown"
            source_kind = metadata.get("source_kind") or "Not recorded"
            generated = metadata.get("generated") is True or source_kind == "GENERATED_MODEL"
            function = metadata.get("function") or metadata.get("function_id") or "Not linked"
            if generated:
                function = "Generated model transition"
            model_refs = {key: metadata[key] for key in ("model_state_ids", "model_transition_ids")
                          if metadata.get(key)}
            input_value = metadata.get("input")
            if input_value is None and model_refs:
                input_value = model_refs
            if input_value is None:
                input_value = "No explicit input recorded"
            build_value = metadata.get("build_status") or ("Generated model runtime" if generated else "Not recorded")
            exit_return = _execution_summary(observation)
            observed_output = _observed_output(observation)
            evidence_ids = list(dict.fromkeys((
                *result.evidence_ids,
                *execution.get("evidence_ids", ()),
                *([execution["test_case_evidence_id"]] if execution.get("test_case_evidence_id") else []),
                *([execution["observation_evidence_id"]] if execution.get("observation_evidence_id") else []),
            )))
            rows.append((metadata.get("test_case_id") or result.property_id or result.id,
                         function, source_kind, _detail(input_value),
                         ", ".join(metadata.get("requirement_ids", ())) or
                         (result.requirement_id or "Not linked"), build_value, executed, exit_return,
                         _detail(metadata.get("oracle") or "No oracle recorded"), observed_output,
                         status_label(result.status.value), result.reason_code or result.message,
                         ", ".join(evidence_ids) or "No evidence linked",
                         f"{result.duration_ms:.2f} ms" if result.duration_ms is not None else "Not recorded"))
            self._result_by_row.append(result)
            self._execution_by_row.append(execution)
        if not rows:
            rows.append(("—",) * 13 + ("Chưa có dynamic result.",))
        self.tests.table.set_records(rows)

        data = coverage_stage.get("output") or {}
        coverage_rows = []
        lines, branches = data.get("line_metrics", {}), data.get("branch_metrics", {})
        if cstatus == "COMPLETED" and (lines or branches):
            for name, metric, count_key, total_key in (
                ("Line", lines, "covered_lines", "total_lines"),
                ("Branch", branches, "covered_branches", "total_branches"),
            ):
                total, covered = metric.get(total_key, 0), metric.get(count_key, 0)
                coverage_rows.append((name, "Tất cả tệp", covered, max(0, total - covered),
                                      metric.get("percentage", "—"), data.get("backend", "—"),
                                      _short(data.get("limitations", ()))))
                for item in metric.get("files", ()):
                    file_total = item.get(total_key, item.get("total_lines", 0))
                    file_covered = item.get(count_key, item.get("covered_lines", 0))
                    coverage_rows.append((name, item.get("file", "—"), file_covered,
                                          max(0, file_total - file_covered), item.get("percentage", "—"),
                                          data.get("backend", "—"), _short(data.get("limitations", ()))))
        if not coverage_rows:
            coverage_rows.append(("—", "—", "—", "—", "—", "—",
                                  coverage_stage.get("reason") or f"Stage coverage: {cstatus}; không có số đo được lưu."))
        self.coverage.table.set_records(coverage_rows)
        self.description.setText(f"Run ID: {report.run_id}. Dynamic verdicts và coverage measurements được trình bày riêng; coverage chỉ đo phần đã thực thi.")

    def _show_test_detail(self, row: int, _column: int) -> None:
        if not 0 <= row < len(self._result_by_row):
            return
        result = self._result_by_row[row]
        payload = result.to_dict()
        payload["execution"] = self._execution_by_row[row]
        payload["observation"] = self._execution_by_row[row].get("observation")
        payload["explanation"] = "Observation/evidence fields are copied from the stored checker result. Oracle expectations are shown separately and are not an observation."
        DetailDialog(f"Dynamic testcase · {result.metadata.get('test_case_id', result.id)}", payload, self).exec()


def _short(value: Any) -> str:
    if isinstance(value, str):
        return value if len(value) <= 180 else value[:177] + "..."
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
        return text if len(text) <= 180 else text[:177] + "..."
    except (TypeError, ValueError):
        return str(value)


def _execution_summary(observation: Any) -> str:
    if not isinstance(observation, dict):
        return "No observation recorded"
    available = observation.get("available", True)
    if available is False:
        return f"Unavailable: {observation.get('reason') or 'no reason recorded'}"
    fields = []
    if observation.get("exit_code") is not None:
        fields.append(f"exit={observation['exit_code']}")
    returned = observation.get("returned_value", observation.get("return_value"))
    if observation.get("return_value_available", returned is not None):
        fields.append(f"return={returned}")
    if observation.get("crashed"):
        fields.append("crash")
    if observation.get("timed_out"):
        fields.append("timeout")
    return ", ".join(fields) or "Execution recorded; see observed output"


def _observed_output(observation: Any) -> str:
    if not isinstance(observation, dict):
        return "No observation recorded"
    fields = {}
    for key in ("stdout", "stderr", "structured_output", "memory_findings"):
        value = observation.get(key)
        if value not in (None, "", [], {}):
            fields[key] = value
    if observation.get("return_value_available", observation.get("returned_value", observation.get("return_value")) is not None):
        fields["returned_value"] = observation.get("returned_value")
        if fields["returned_value"] is None:
            fields["returned_value"] = observation.get("return_value")
    if observation.get("crashed") is not None:
        fields["crashed"] = observation["crashed"]
    if observation.get("timed_out"):
        fields["timed_out"] = True
    return _detail(fields) if fields else "No output captured"


def _detail(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)

