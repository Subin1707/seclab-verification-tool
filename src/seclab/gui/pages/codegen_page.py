from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QFileDialog, QLabel, QMessageBox, QPushButton,
                               QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget)

from seclab.gui.i18n import status_label
from seclab.gui.widgets import ReadOnlyTable


class CodeGenerationPage(QWidget):
    """Present generated C/Python sources and their verified evidence links."""

    runRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.title = QLabel("Mã nguồn sinh tự động (Code Generation)")
        self.title.setObjectName("pageTitle")
        self.summary = QLabel("Chưa có dữ liệu sinh mã trong lần chạy hiện tại.")
        self.summary.setWordWrap(True)
        self.description = QLabel(
            "Artifact được sinh từ Specification/model. Function ứng dụng chỉ được sinh khi Specification khai báo contract thực thi.")
        self.description.setWordWrap(True)
        self.run_button = QPushButton("Bắt đầu pipeline xác minh")
        self.run_button.clicked.connect(self.runRequested.emit)
        self.export_button = QPushButton("Xuất mã nguồn đang xem")
        self.export_button.clicked.connect(self._export_selected_source)

        self.tabs = QTabWidget(self)
        self.preview = QPlainTextEdit(self)
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("Mã C đã xác minh sẽ hiển thị sau khi chạy.")
        self.python_preview = QPlainTextEdit(self)
        self.python_preview.setReadOnly(True)
        self.python_preview.setPlaceholderText("Python model runtime sẽ hiển thị sau khi chạy CODEGEN.")
        self.functions = ReadOnlyTable(("Function ID", "Name", "Language", "Kind", "Status",
            "Requirements", "Declared CWE", "Source binding", "Generation reason", "Declared metadata (not a finding)", "Artifact", "SHA-256"))
        self.files = ReadOnlyTable(("Artifact path", "Phân loại", "SHA-256", "Evidence ID"))
        self.source_map = ReadOnlyTable(("Generated file", "Mapping", "Specification/model element"))
        self.builds = ReadOnlyTable(("Target", "Loại", "Trạng thái", "Exit code", "Thời lượng ms",
            "stdout / stderr", "Tệp thực thi", "Evidence ID"))
        self.tabs.addTab(self.preview, "C source")
        self.tabs.addTab(self.python_preview, "Python source")
        self.tabs.addTab(self.functions, "Functions")
        self.tabs.addTab(self.files, "Generated artifacts")
        self.tabs.addTab(self.source_map, "Source map")
        self.tabs.addTab(self.builds, "Build / execute")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.title)
        layout.addWidget(self.summary)
        layout.addWidget(self.description)
        layout.addWidget(self.run_button)
        layout.addWidget(self.export_button)
        layout.addWidget(self.tabs, 1)
        self.files.cellDoubleClicked.connect(self._open_selected_artifact)
        self.files.cellClicked.connect(self._open_selected_artifact)
        self._artifact_by_row: list[tuple[dict[str, Any], Path, str, str]] = []
        self._selected_source_path = ""
        self.functions.setHorizontalScrollMode(self.functions.ScrollMode.ScrollPerPixel)
        for column, width in enumerate((205, 190, 95, 130, 250, 170, 145, 220, 330, 360, 230, 275)):
            self.functions.setColumnWidth(column, width)

    def show_report(self, report: Any | None, evidence: tuple[dict[str, Any], ...] = (),
                    run_root: Path | None = None) -> None:
        if report is None:
            self.summary.setText("Chưa có lần chạy. Hãy chạy CODEGEN với project/Specification đang mở.")
            self._clear_data()
            return
        stage = next((item for item in report.stage_summaries
                      if str(item.get("stage_id", "")).upper() == "CODEGEN"), None)
        if stage is None:
            self.summary.setText("CODEGEN  NOT_RUN  Run này chưa có stage sinh mã.")
            self._clear_data()
            return
        status = str(stage.get("status", "UNKNOWN")).upper()
        output = stage.get("output") or {}
        metadata = stage.get("metadata") or {}
        reason = stage.get("reason") or output.get("skipped_reason") or ""
        manifest = output.get("manifest") or {}
        generated_files = tuple(manifest.get("files", ()))
        source_map_data = output.get("source_map") or {}
        generation_data = output.get("generation_metadata") or {}
        function_generation = (manifest.get("functions") or source_map_data.get("function_generation")
                               or generation_data.get("function_generation") or ())
        unsupported = sum(str(item.get("status", "")).startswith("UNSUPPORTED")
                          for item in function_generation)
        self.summary.setText(
            f"CODEGEN  {status_label(status)}  artifacts={len(generated_files)}  "
            f"functions={len(function_generation)}  function bodies unsupported={unsupported}  "
            f"generator={metadata.get('generator_version', manifest.get('generator_version', ''))}"
            + (f"\nReason: {reason}" if reason else ""))
        self.description.setText(
            "C/Python model runtime là mã sinh từ mô hình, không phải implementation của application function. "
            "Function thiếu executable contract được ghi rõ trong tab Functions.")

        evidence_by_path = {str(item.get("metadata", {}).get("generated_path", "")): item
                            for item in evidence if item.get("metadata", {}).get("generated_path")}
        hash_by_path = {str(item.get("path", "")): str(item.get("sha256", "")) for item in generated_files}
        function_rows = []
        for function in function_generation:
            function_path = str(function.get("generated_path") or "")
            declared_metadata = function.get("declared_metadata") or {}
            metadata_text = json.dumps(declared_metadata, ensure_ascii=False, sort_keys=True) if declared_metadata else "Not declared"
            function_rows.append((function.get("function_id", ""), function.get("name", ""),
                function.get("language", "UNSPECIFIED"), function.get("kind") or "Not declared",
                function.get("status", "UNSUPPORTED_NO_EXECUTABLE_CONTRACT"),
                ", ".join(function.get("requirement_ids", ())) or "Not linked",
                ", ".join(function.get("declared_cwe_ids", ())) or "Not declared",
                function.get("source_location") or function.get("file") or "Not supplied",
                function.get("reason") or "Not available", metadata_text,
                function_path or "Not generated", hash_by_path.get(function_path, "Not generated")))
        self.functions.set_records(function_rows)

        self._artifact_by_row = []
        file_rows = []
        for generated in generated_files:
            relative = str(generated.get("path", ""))
            record = evidence_by_path.get(relative)
            file_rows.append((relative, generated.get("artifact_class", "GENERATED_ARTIFACT"),
                generated.get("sha256", ""), record.get("id", "EVIDENCE_UNRESOLVED") if record else "EVIDENCE_UNRESOLVED"))
            if record and run_root is not None:
                self._artifact_by_row.append((record, run_root, str(generated.get("sha256", "")), relative))
            else:
                self._artifact_by_row.append(({}, Path(), str(generated.get("sha256", "")), relative))
        self.files.set_records(file_rows)
        self._render_source_map(source_map_data)

        # Prefer the C runtime in the main preview; the Python model runtime is
        # available from the Python tab and is linked through the same manifest.
        preferred = ("source/model.c",)
        selected_row = next((index for path in preferred for index, item in enumerate(generated_files)
                             if str(item.get("path", "")).replace("\\", "/") == path), None)
        if selected_row is None:
            selected_row = next((index for index, item in enumerate(generated_files)
                                 if str(item.get("path", "")).casefold().endswith((".c", ".py"))), None)
        if selected_row is not None:
            self._open_selected_artifact(selected_row, 0)
        elif generated_files:
            self.preview.setPlainText("No generated C/Python source artifact is available.")
        else:
            self.preview.setPlainText("No generated source artifact was produced. Check CODEGEN status and reason.")

        build_stage = next((item for item in report.stage_summaries
                            if str(item.get("stage_id", "")).upper() == "BUILD"), None)
        build_metadata = (build_stage or {}).get("metadata") or {}
        build_rows = []
        for item in build_metadata.get("compiler_runs", ()):
            build_rows.append((item.get("compiler", ""), "MODEL_BUILD", item.get("status", ""),
                item.get("exit_code", ""), item.get("duration_ms", ""),
                _short(item.get("stderr", "") or item.get("stdout", "")),
                item.get("artifact", ""), item.get("evidence_id", "")))
        for item in metadata.get("function_build_runs", ()):
            build_rows.append((item.get("target", ""), item.get("kind", ""),
                item.get("runtime_observation", item.get("build_status", item.get("status", ""))),
                item.get("exit_code", ""), item.get("duration_ms", ""),
                _short(item.get("stderr", "") or item.get("stdout", "")), item.get("artifact", ""),
                item.get("evidence_id", "")))
        for item in build_metadata.get("python_model_runs", ()):
            build_rows.append((item.get("interpreter", "Python"), "PYTHON_MODEL_RUNTIME",
                item.get("status", ""), item.get("exit_code", ""), item.get("duration_ms", ""),
                _short(item.get("stderr", "") or item.get("stdout", "")),
                item.get("artifact", ""), item.get("evidence_id", "")))
        self.builds.set_records(build_rows)

        # Keep the run context visible on the Functions tab as well as in the
        # artifact tables. These are generation/build facts, not checker findings.
        build_status = str((build_stage or {}).get("status", "NOT_RUN")).upper()
        compiler_status = ", ".join(
            f"{item.get('compiler', 'compiler')}: {item.get('status', 'UNKNOWN')}"
            for item in build_metadata.get("compiler_runs", ())) or "none recorded"
        python_status = ", ".join(
            f"{item.get('interpreter', 'Python')}: {item.get('status', 'UNKNOWN')}"
            for item in build_metadata.get("python_model_runs", ())) or "none recorded"
        spec_hash = (manifest.get("specification_hash") or generation_data.get("specification_hash")
                     or source_map_data.get("specification_hash") or "unavailable")
        model_hash = (manifest.get("model_hash") or generation_data.get("model_hash")
                      or source_map_data.get("model_hash") or "unavailable")
        self.summary.setText(self.summary.text() +
            f"\nBUILD: {build_status} · C: {compiler_status} · Python: {python_status}"
            f"\nSpecification SHA-256: {spec_hash} · Model SHA-256: {model_hash}")

    def _clear_data(self) -> None:
        self.functions.set_records(())
        self.files.set_records(())
        self.source_map.set_records(())
        self.builds.set_records(())
        self.preview.clear()
        self.python_preview.clear()
        self._artifact_by_row = []
        self._selected_source_path = ""

    def _render_source_map(self, source_map: dict[str, Any]) -> None:
        rows = []
        for path, data in sorted((source_map.get("files") or {}).items()):
            for state in data.get("states", ()):
                rows.append((path, "state", state.get("state_id", "")))
            for transition in data.get("transitions", ()):
                rows.append((path, "transition",
                    f"{transition.get('transition_id')}  {transition.get('source_state_id')}  {transition.get('target_state_id')}"))
            for line in data.get("generated_lines", ()):
                element = line.get("element_id") or line.get("model_id") or line.get("requirement_id") or "mapped element"
                rows.append((path, f"generated line {line.get('generated_line', line.get('line', ''))}", element))
        for requirement in source_map.get("requirements", ()):
            for location in requirement.get("generated_locations", ()):
                rows.append((location.get("path", ""),
                    f"generated line {location.get('generated_line', '')}",
                    f"requirement {requirement.get('requirement_id', '')}"))
        for function in source_map.get("function_generation", ()):
            rows.append((function.get("generated_path") or "", function.get("status", "UNSUPPORTED"),
                f"{function.get('function_id', '')}  {function.get('name', '')}  "
                f"{function.get('reason') or function.get('probe_class', 'No implementation metadata')}"))
        self.source_map.set_records(rows)

    def _open_selected_artifact(self, row: int, _column: int) -> None:
        if not 0 <= row < len(self._artifact_by_row):
            return
        record, run_root, generated_hash, relative_path = self._artifact_by_row[row]
        self._selected_source_path = relative_path
        target = self.python_preview if relative_path.casefold().endswith(".py") else self.preview
        self.tabs.setCurrentWidget(target)
        if not record:
            target.setPlainText("Generated artifact does not have a resolved manifest evidence entry.")
            return
        try:
            path = (run_root / str(record.get("path", ""))).resolve(strict=True)
            if not path.is_relative_to(run_root.resolve()):
                raise ValueError("Evidence path escapes the run directory")
            content = path.read_bytes()
            expected = str(record.get("hash", ""))
            actual = hashlib.sha256(content).hexdigest()
            if not expected or actual != expected or (generated_hash and actual != generated_hash):
                raise ValueError(f"Generated/evidence hash mismatch: generated={generated_hash or 'missing'}, "
                                 f"evidence={expected or 'missing'}, actual={actual}")
            text = content.decode("utf-8")
            target.setPlainText(f"/* GENERATED_ARTIFACT  {relative_path}  sha256={actual} */\n" + text)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            target.setPlainText(f"Generated evidence unavailable: {type(exc).__name__}: {exc}")

    def _on_tab_changed(self, _index: int) -> None:
        if self.tabs.currentWidget() is self.python_preview:
            row = next((index for index, item in enumerate(self._artifact_by_row)
                        if item[3].casefold().endswith(".py")), None)
            if row is None:
                self.python_preview.setPlainText(
                    "This run did not produce a Python source artifact. Check the Functions tab for "
                    "declared function languages and generation statuses.")
            else:
                self._open_selected_artifact(row, 0)
        elif self.tabs.currentWidget() is self.preview and not self._selected_source_path:
            row = next((index for index, item in enumerate(self._artifact_by_row)
                        if item[3].replace("\\", "/") == "source/model.c"), None)
            if row is not None:
                self._open_selected_artifact(row, 0)

    def _export_selected_source(self) -> None:
        if not self._selected_source_path:
            QMessageBox.information(self, "Xut m ngun", "Hy chn artifact C/Python t danh sch trc.")
            return
        suffix = Path(self._selected_source_path).suffix or ".txt"
        default_name = Path(self._selected_source_path).name
        path, _ = QFileDialog.getSaveFileName(self, "Xut m ngun  sinh", default_name,
                                               f"Source (*{suffix});;All files (*)")
        if not path:
            return
        editor = self.python_preview if suffix.casefold() == ".py" else self.preview
        content = editor.toPlainText()
        marker_end = content.find("\n")
        if content.startswith("/* GENERATED_ARTIFACT ") and marker_end >= 0:
            content = content[marker_end + 1:]
        try:
            Path(path).write_text(content, encoding="utf-8", newline="\n")
        except OSError as exc:
            QMessageBox.critical(self, "Xut m ngun tht bi", f"{type(exc).__name__}: {exc}")


def _short(value: Any) -> str:
    if isinstance(value, str):
        return value if len(value) <= 120 else value[:117] + "..."
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
        return text if len(text) <= 120 else text[:117] + "..."
    except (TypeError, ValueError):
        return str(value)

