"""GUI projections and explicit run actions for optional CODEGEN/FUZZING stages."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from seclab.gui.main_window import MainWindow
from seclab.gui.main_window import _default_workspace
from seclab.gui.pages.codegen_page import CodeGenerationPage
from seclab.gui.pages.fuzzing_page import FuzzFlowDiagram, FuzzingPage
from seclab.results import VerificationResult, VerificationStatus


@pytest.fixture(scope="module")
def application():
    return QApplication.instance() or QApplication([])


def test_fuzz_page_explains_skipped_campaign_and_has_run_action(application):
    page = FuzzingPage()
    report = SimpleNamespace(results=(), stage_summaries=({"stage_id": "FUZZING", "status": "SKIPPED",
        "reason": "No fuzz configuration was provided."},))
    page.show_report(report)
    assert "SKIPPED" in page.summary.text()
    assert "No fuzz configuration" in page.summary.text()
    assert page.table.rowCount() == 1
    assert page.tabs.count() == 5
    assert page.tabs.currentWidget() is page.process_tab
    assert page.flow_diagram.parent() is not None
    assert page.flow_diagram._statuses["TARGET"] == "NOT_RUN"
    assert page.flow_diagram._statuses["CONCOLIC"] == "NOT_SELECTED"
    assert "no specification model elements" in page.cfg_table.item(0, 3).text().lower()
    requested = []
    page.runRequested.connect(lambda: requested.append(True))
    page.run_button.click()
    assert requested == [True]
    page.close()


def test_fuzz_page_exposes_live_progress_callbacks(application):
    page = FuzzingPage()
    from seclab.fuzzing import FuzzConfig, FuzzStrategy
    page.begin_run(FuzzConfig(FuzzStrategy.BLACKBOX, 7, 1.0, 42, 128))
    assert "RUNNING" in page.summary.text()
    assert "budget=7" in page.summary.text()
    page.begin_progress()
    page.update_progress({"event": "campaign_started", "target": "generated-model-api"})
    assert page.flow_diagram._statuses["GENERATE"] == "RUNNING"
    assert "generated-model-api" in page.summary.text()
    page.close()


def test_fuzz_page_clears_old_skip_when_new_run_begins(application):
    page = FuzzingPage()
    report = SimpleNamespace(results=(), stage_summaries=({"stage_id": "FUZZING", "status": "SKIPPED",
        "reason": "No fuzz configuration was provided."},), metadata={})
    page.show_report(report)
    assert page.tabs.currentWidget() is page.process_tab
    assert "SKIPPED" in page.summary.text()
    from seclab.fuzzing import FuzzConfig, FuzzStrategy
    page.begin_run(FuzzConfig(FuzzStrategy.BLACKBOX, 5, 1.0, 1, 128))
    assert "RUNNING" in page.summary.text()
    assert "SKIPPED" not in page.summary.text()
    assert page.table.rowCount() == 0
    page.close()


def test_workspace_environment_override_is_honored(tmp_path, monkeypatch):
    selected = tmp_path / "workspace-on-e"
    monkeypatch.setenv("SECLAB_WORKSPACE", str(selected))
    assert _default_workspace() == selected.resolve()


def test_fuzz_page_clears_campaign_when_stage_is_absent(application):
    page = FuzzingPage()
    report = SimpleNamespace(results=(), stage_summaries=(), metadata={})
    page.show_report(report)
    assert "NOT_RUN" in page.summary.text()
    assert page.table.rowCount() == 0
    assert page.coverage_table.rowCount() == 1
    assert "NOT_RUN" in page.coverage_description.text()
    assert page.flow_diagram._statuses["TARGET"] == "NOT_RUN"
    assert page.flow_diagram._statuses["CONCOLIC"] == "NOT_SELECTED"
    assert "no checker result" in page.technique_table.item(page.technique_table.rowCount() - 1, 1).text().lower()
    page.close()


def test_fuzz_flow_tracks_live_campaign_phases(application):
    flow = FuzzFlowDiagram()
    phases = ("TARGET", "GENERATE", "EXECUTION", "ORACLE", "CORPUS", "EVIDENCE")
    assert all(flow._statuses[key] == "NOT_RUN" for key in phases)

    flow.begin_progress()
    flow.update_progress({"event": "target_started", "target": "parse_value",
        "target_index": 1, "target_count": 2})
    assert flow._statuses["TARGET"] == "RUNNING"
    assert all(flow._statuses[key] == "NOT_RUN" for key in phases[1:])

    flow.update_progress({"event": "campaign_started", "target": "parse_value"})
    assert flow._statuses["GENERATE"] == "RUNNING"
    flow.update_progress({"event": "input_generated", "target": "parse_value"})
    assert flow._statuses["GENERATE"] == "COMPLETED"
    assert flow._statuses["EXECUTION"] == "RUNNING"
    flow.update_progress({"event": "execution_completed", "target": "parse_value", "executed": 1})
    assert flow._statuses["EXECUTION"] == "COMPLETED"
    assert flow._statuses["ORACLE"] == "RUNNING"
    flow.update_progress({"event": "case_completed", "target": "parse_value", "completed": 1})
    assert flow._statuses["ORACLE"] == "COMPLETED"
    assert flow._statuses["CORPUS"] == "COMPLETED"
    flow.update_progress({"event": "target_finished", "target": "parse_value",
        "target_index": 1, "target_count": 2, "executed": 1, "evidence_count": 4})
    assert flow._statuses["EVIDENCE"] == "COMPLETED"
    assert flow._statuses["TARGET"] == "COMPLETED"
    flow.close()


def test_codegen_page_verifies_and_previews_generated_evidence(application, tmp_path):
    run_root = tmp_path / "run-1"
    artifact_path = run_root / "evidence" / "codegen" / "model.c"
    artifact_path.parent.mkdir(parents=True)
    content = b"/* generated */\nint model(void) { return 0; }\n"
    artifact_path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    evidence = ({"id": "ev-generated", "path": "evidence/codegen/model.c", "hash": digest,
                 "metadata": {"generated_path": "source/model.c", "artifact_role": "GENERATED_ARTIFACT"}},)
    codegen_stage = {
        "stage_id": "CODEGEN", "status": "COMPLETED",
        "output": {
            "manifest": {"model_id": "model-1", "generator_version": "1.1", "files": [
                {"path": "source/model.c", "sha256": digest, "artifact_class": "GENERATED_SOURCE"}]},
            "source_map": {"files": {"source/model.c": {
                "states": [{"state_id": "S0"}],
                "transitions": [{"transition_id": "T0", "source_state_id": "S0", "target_state_id": "S1"}]}},
                "function_generation": [{"function_id": "FN-probe", "name": "probe",
                    "status": "UNSUPPORTED_NO_IMPLEMENTATION_BODY", "reason": "No function body."}]},
        },
        "metadata": {"model_id": "model-1", "generator_version": "1.1"},
    }
    build_stage = {"stage_id": "BUILD", "status": "COMPLETED", "metadata": {
        "compiler_runs": [{"compiler": "gcc", "status": "COMPLETED", "exit_code": 0,
            "duration_ms": 3.0, "artifact": "generated/build/app.exe", "evidence_id": "ev-build"}]}}
    report = SimpleNamespace(stage_summaries=(codegen_stage, build_stage))
    page = CodeGenerationPage()
    page.show_report(report, evidence, run_root)
    assert "model runtime" in page.description.text()
    assert "function bodies unsupported=1" in page.summary.text()
    assert page.files.rowCount() == 1
    assert page.source_map.rowCount() == 3
    assert "UNSUPPORTED_NO_IMPLEMENTATION_BODY" in page.source_map.item(2, 1).text()
    assert page.builds.rowCount() == 1
    assert page.builds.columnCount() == 8
    assert page.builds.item(0, 6).text() == "generated/build/app.exe"
    assert page.tabs.currentWidget() is page.preview
    assert "GENERATED_ARTIFACT" in page.preview.toPlainText()
    assert "int model" in page.preview.toPlainText()
    page.files.cellDoubleClicked.emit(0, 0)
    assert "GENERATED_ARTIFACT" in page.preview.toPlainText()
    assert "int model" in page.preview.toPlainText()
    artifact_path.write_bytes(b"modified after hashing")
    page.files.cellDoubleClicked.emit(0, 0)
    assert "hash mismatch" in page.preview.toPlainText().lower()
    page.close()


def test_codegen_python_tab_loads_hash_verified_python_artifact(application, tmp_path):
    run_root = tmp_path / "python-run"
    artifact_path = run_root / "evidence" / "codegen" / "python.py"
    artifact_path.parent.mkdir(parents=True)
    content = b"def generated(value):\n    return value + 1\n"
    artifact_path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    evidence = ({"id": "ev-python", "path": "evidence/codegen/python.py", "hash": digest,
        "metadata": {"generated_path": "python/generated_functions.py"}},)
    stage = {"stage_id": "CODEGEN", "status": "COMPLETED", "output": {
        "manifest": {"files": [{"path": "python/generated_functions.py", "sha256": digest,
            "artifact_class": "GENERATED_ARTIFACT"}]}, "source_map": {}}, "metadata": {}}
    page = CodeGenerationPage()
    page.show_report(SimpleNamespace(stage_summaries=(stage,)), evidence, run_root)
    page.tabs.setCurrentWidget(page.python_preview)
    assert "def generated" in page.python_preview.toPlainText()
    assert "sha256=" in page.python_preview.toPlainText()
    page.close()


def test_codegen_build_tab_reads_compiler_and_python_runs_from_build_stage(application):
    codegen = {"stage_id": "CODEGEN", "status": "COMPLETED", "output": {
        "manifest": {"files": [], "functions": []}, "source_map": {}}, "metadata": {}}
    build = {"stage_id": "BUILD", "status": "COMPLETED", "metadata": {
        "compiler_runs": [
            {"compiler": "gcc", "status": "COMPLETED", "exit_code": 0,
             "duration_ms": 12.5, "stdout": "", "stderr": "", "artifact": "build/model-gcc.exe",
             "evidence_id": "ev-gcc"},
            {"compiler": "clang", "status": "TOOL_ERROR", "exit_code": None,
             "duration_ms": 1.0, "stdout": "", "stderr": "not installed", "artifact": "",
             "evidence_id": "ev-clang"}],
        "python_model_runs": [{"interpreter": "python.exe", "status": "PASS", "exit_code": 0,
            "duration_ms": 3.0, "stdout": '{"state_count": 0}', "stderr": "",
            "artifact": "generated/python/model.py", "evidence_id": "ev-python"}]}}
    page = CodeGenerationPage()
    page.show_report(SimpleNamespace(stage_summaries=(codegen, build)))
    assert page.builds.rowCount() == 3
    assert page.builds.item(0, 0).text() == "gcc"
    assert page.builds.item(0, 2).text() == "COMPLETED"
    assert page.builds.item(1, 2).text() == "TOOL_ERROR"
    assert page.builds.item(2, 1).text() == "PYTHON_MODEL_RUNTIME"
    assert page.builds.item(2, 2).text() == "PASS"
    assert "BUILD: COMPLETED" in page.summary.text()
    assert "gcc: COMPLETED" in page.summary.text()
    assert "python.exe: PASS" in page.summary.text()
    assert "Specification SHA-256" in page.summary.text()
    page.close()


def test_codegen_function_table_displays_declared_contract_metadata(application):
    functions = [{"function_id": "FN-copy", "name": "copy_value", "language": "c", "kind": "copy",
        "status": "UNSUPPORTED_NO_EXECUTABLE_CONTRACT", "requirement_ids": ["REQ-1"],
        "declared_cwe_ids": ["CWE-120"], "source_location": "src/copy.c",
        "reason": "No typed signature or executable behavior contract is declared.",
        "declared_metadata": {"parameters": ["source", "destination"], "buffer_size": 16}}]
    stage = {"stage_id": "CODEGEN", "status": "COMPLETED", "output": {
        "manifest": {"files": [], "functions": functions}, "source_map": {}}, "metadata": {}}
    page = CodeGenerationPage()
    page.show_report(SimpleNamespace(stage_summaries=(stage,)))
    assert page.functions.columnCount() == 12
    assert page.functions.rowCount() == 1
    assert page.functions.item(0, 0).text() == "FN-copy"
    assert page.functions.item(0, 3).text() == "copy"
    assert page.functions.item(0, 5).text() == "REQ-1"
    assert page.functions.item(0, 6).text() == "CWE-120"
    assert page.functions.item(0, 7).text() == "src/copy.c"
    assert "buffer_size" in page.functions.item(0, 9).text()
    assert "not a finding" in page.functions.horizontalHeaderItem(9).text().lower()
    page.close()


def test_codegen_page_reports_unresolved_artifact_without_showing_fake_path(application):
    stage = {"stage_id": "CODEGEN", "status": "COMPLETED", "output": {
        "manifest": {"files": [{"path": "source/model.c", "sha256": "abc"}]},
        "source_map": {},
    }, "metadata": {}}
    page = CodeGenerationPage()
    page.show_report(SimpleNamespace(stage_summaries=(stage,)), (), None)
    assert "source/model.c" not in page.preview.toPlainText()
    assert "does not have a resolved manifest evidence entry" in page.preview.toPlainText()
    page.close()


def test_codegen_page_prefers_model_c_over_alphabetically_first_header(application, tmp_path):
    run_root = tmp_path / "run-c"
    evidence_root = run_root / "evidence" / "codegen"
    evidence_root.mkdir(parents=True)
    header = b"/* HEADER_CONTENT */\n"
    source = b"/* SOURCE_CONTENT */\nint model(void) { return 7; }\n"
    header_hash = hashlib.sha256(header).hexdigest()
    source_hash = hashlib.sha256(source).hexdigest()
    (evidence_root / "header.h").write_bytes(header)
    (evidence_root / "source.c").write_bytes(source)
    evidence = (
        {"id": "ev-header", "path": "evidence/codegen/header.h", "hash": header_hash,
         "metadata": {"generated_path": "include/model.h"}},
        {"id": "ev-source", "path": "evidence/codegen/source.c", "hash": source_hash,
         "metadata": {"generated_path": "source/model.c"}},
    )
    stage = {"stage_id": "CODEGEN", "status": "COMPLETED", "output": {
        "manifest": {"files": [
            {"path": "include/model.h", "sha256": header_hash},
            {"path": "source/model.c", "sha256": source_hash},
        ]},
        "source_map": {},
    }, "metadata": {}}
    page = CodeGenerationPage()
    page.show_report(SimpleNamespace(stage_summaries=(stage,)), evidence, run_root)
    assert "SOURCE_CONTENT" in page.preview.toPlainText()
    assert "HEADER_CONTENT" not in page.preview.toPlainText()
    page.close()


def test_fuzz_page_shows_bounded_campaign_metrics_and_checker_verdict(application):
    result = VerificationResult(id="fuzz-result", stage="FUZZING", technique="BLACKBOX",
        status=VerificationStatus.INCONCLUSIVE, reason_code="NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET",
        message="No finding within budget.", scope="20 executions", evidence_ids=("fuzz-evidence",),
        metadata={"random_seed": 19, "stop_reason": "ITERATION_LIMIT", "crashes": 0,
                  "timeouts": 0, "executions_completed": 20, "requested_strategy": "BLACKBOX"})
    campaign = {"strategy": "BLACKBOX", "seed": 19, "iterations_requested": 20,
        "iterations_executed": 20, "unique_inputs": 18, "corpus_size": 3, "failures": [],
        "crashes": 0, "timeouts": 0, "coverage_delta": [], "stop_reason": "ITERATION_LIMIT",
        "evidence_ids": ["fuzz-evidence"], "source_integrity_unchanged": True,
        "target": "parse_value", "test_case_id": "CASE-1", "function_id": "F-parse",
        "analysis_surface": "PROJECT_FUNCTION", "oracle_failures": 0}
    report = SimpleNamespace(results=(result,), stage_summaries=({"stage_id": "FUZZING",
        "status": "COMPLETED", "output": campaign, "metadata": {"executed_count": 20}},))
    page = FuzzingPage()
    page.show_report(report)
    assert "seed=19" in page.summary.text()
    assert "INCONCLUSIVE" in page.table.item(0, 9).text()
    assert page.table.item(0, 2).text() == "20"
    assert "parse_value" in page.table.item(0, 0).text()
    assert "F-parse" in page.table.item(0, 0).text()
    assert page.table.item(0, 3).text() == "18"
    assert page.flow_diagram._statuses["BLACKBOX"] == "COMPLETED"
    assert page.flow_diagram._statuses["BOUNDARY"] == "NOT_SELECTED"
    assert page.flow_diagram._statuses["EXECUTION"] == "COMPLETED"
    assert page.flow_diagram._statuses["EVIDENCE"] == "COMPLETED"
    assert any(page.coverage_table.item(row, 6).text().startswith("No coverage measurement")
               for row in range(page.coverage_table.rowCount()))
    assert page.technique_table.rowCount() == 14
    assert "UNSUPPORTED" in page.technique_table.item(5, 1).text()
    assert "INCONCLUSIVE" in page.technique_table.item(13, 1).text()
    page.flow_diagram.resize(1450, 535)
    page.flow_diagram.show()
    application.processEvents()
    page.close()


def test_fuzz_loop_progress_and_timeout_finding_explanation_are_visible(application):
    page = FuzzingPage()
    page.flow_diagram.update_progress({"event": "input_generated", "completed": 0,
        "requested": 3, "input_id": "loop-input-1"})
    assert "LƯỢT 1/3" in page.flow_diagram._loop_progress
    assert "loop-input-1" in page.flow_diagram._loop_progress
    assert page.flow_diagram._statuses["EXECUTION"] == "RUNNING"

    campaign = {"strategy": "MUTATION", "target": "looping_target",
        "iterations_requested": 3, "iterations_executed": 1, "unique_inputs": 1,
        "corpus_size": 1, "failures": [{
            "classification": "TIMEOUT", "signature": {"kind": "TIMEOUT", "key": "timeout-signature"},
            "input": {"id": "loop-input-1", "kind": "TEXT", "data": "repeat", "origin": "SEED"},
            "minimized_input": None, "minimized": False,
            "verification_result": {"status": "INCONCLUSIVE", "reason_code": "TEST_EXECUTION_TIMEOUT",
                "message": "Execution exceeded the per-input timeout."},
            "oracle_evaluation": {"checks": []}, "observation": {"timed_out": True, "memory_findings": []},
            "command_diagnostic": {"timed_out": True, "exit_code": None, "duration_ms": 50},
            "evidence_ids": ["timeout-evidence"],
        }], "crashes": 0, "timeouts": 1, "oracle_failures": 0,
        "coverage_delta": [], "stop_reason": "FIRST_FAILURE", "evidence_ids": ["timeout-evidence"]}
    report = SimpleNamespace(results=(), stage_summaries=({"stage_id": "FUZZING",
        "status": "INCONCLUSIVE", "output": campaign},), metadata={})
    page.show_report(report)
    assert "FUZZ FINDING" in page.finding_banner.text()
    details = page.campaign_analysis.toPlainText()
    assert "VÌ SAO ĐÂY LÀ LỖI" in details
    assert "timeout" in details.casefold()
    assert "vòng lặp vô hạn" in details
    page.close()


def test_fuzz_page_lists_clickable_per_iteration_evidence(application):
    page = FuzzingPage()
    campaign = {"strategy": "BLACKBOX", "seed": 4, "iterations_executed": 1,
        "unique_inputs": 1, "corpus_size": 1, "failures": [], "crashes": 0, "timeouts": 0,
        "coverage_delta": [], "stop_reason": "ITERATION_LIMIT", "evidence_ids": ["ev-observation"],
        "execution_evidence": [{"evidence_id": "ev-observation", "path": "evidence/fuzz/observation.json",
            "sha256": "a" * 64, "iteration": 1, "input_id": "input-1", "input_sha256": "b" * 64,
            "classification": "NONE", "result_status": "INCONCLUSIVE", "executed": True}]}
    report = SimpleNamespace(results=(), stage_summaries=({"stage_id": "FUZZING", "status": "COMPLETED",
        "output": campaign},), metadata={})
    opened = []
    page.evidenceActivated.connect(opened.append)
    page.show_report(report)
    assert page.execution_evidence_table.rowCount() == 1
    page.execution_evidence_table.cellDoubleClicked.emit(0, 0)
    assert opened == ["ev-observation"]
    assert page.execution_evidence_table.item(0, 7).text() == "a" * 64
    page.close()


def test_fuzz_page_renders_verified_observation_as_analysis(application, tmp_path):
    import json
    import hashlib

    page = FuzzingPage()
    observation = {"iteration": 1, "input_id": "input-1", "input_sha256": "b" * 64,
        "input": {"kind": "BYTES", "origin": "BLACKBOX", "data": {"base64": "AAEC", "size_bytes": 3}},
        "target": "generated-model-api", "test_case_id": "MODEL-API-1", "target_kind": "EXECUTABLE",
        "test_case_inputs": {"stdin": {"base64": "AAEC"}}, "executed": True,
        "result_status": "INCONCLUSIVE", "result_reason_code": "NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET",
        "result_id": "result-1", "expected_oracle": {"checks": ["NO_CRASH"]},
        "observation": {"exit_code": 0, "timed_out": False}, "classification": "NONE",
        "command": {"argv": ["model-fuzz.exe"], "exit_code": 0, "timed_out": False,
            "duration_ms": 2, "stdout_preview": "", "stderr_preview": "",
            "stdout_sha256": "c" * 64, "stderr_sha256": "d" * 64}}
    payload = json.dumps(observation, sort_keys=True).encode()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    path = evidence_dir / "observation.json"
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    record = {"evidence_id": "ev-observation", "path": "evidence/observation.json", "sha256": digest,
        "iteration": 1, "input_id": "input-1", "input_sha256": "b" * 64,
        "classification": "NONE", "result_status": "INCONCLUSIVE", "executed": True}
    campaign = {"strategy": "BLACKBOX", "target": "generated-model-api", "iterations_requested": 1,
        "iterations_executed": 1, "unique_inputs": 1, "corpus_size": 1, "failures": [],
        "evidence_ids": ["ev-observation"], "execution_evidence": [record],
        "verification_result": {"status": "INCONCLUSIVE", "reason_code": "NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET",
            "message": "No failure within budget."}}
    report = SimpleNamespace(results=(), stage_summaries=({"stage_id": "FUZZING", "status": "COMPLETED",
        "output": campaign},), metadata={})
    page.show_report(report)
    host = SimpleNamespace(fuzzing=page)
    MainWindow._load_fuzz_observations(host, report, tmp_path,
        ({"id": "ev-observation", "path": "evidence/observation.json", "hash": digest,
          "size_bytes": len(payload)},))
    assert "Command: model-fuzz.exe" in page.execution_analysis.toPlainText()
    assert "Expected oracle" in page.execution_analysis.toPlainText()
    assert "Actual testcase arguments" in page.execution_analysis.toPlainText()
    MainWindow._load_fuzz_observations(host, report, tmp_path,
        ({"id": "ev-observation", "path": "evidence/observation.json", "hash": "0" * 64,
          "size_bytes": len(payload)},))
    assert "KHÔNG XÁC THỰC ĐƯỢC ARTIFACT" in page.execution_analysis.toPlainText()
    page.close()


def test_fuzz_page_projects_coverage_and_specification_model(application):
    report = SimpleNamespace(results=(), metadata={"source_inventory": {"files": [{"path": "main.c"}]},
        "specification": {"initial_state": "S0", "states": [{"id": "S0", "initial": True, "labels": ["safe"]}],
                          "transitions": [{"id": "T0", "source": "S0", "target": "S0", "guard": "ready", "action": "done = true"}]}},
        stage_summaries=(
            {"stage_id": "FUZZING", "status": "COMPLETED", "output": {"strategy": "COVERAGE_GUIDED",
                "seed": 3, "iterations_executed": 2, "corpus_size": 2, "failures": [],
                "coverage_delta": ["main.c:12"], "evidence_ids": ["ev-1"], "source_integrity_unchanged": True}},
            {"stage_id": "COVERAGE", "status": "COMPLETED", "output": {"backend": "gcov",
                "line_metrics": {"covered_lines": 3, "total_lines": 4, "percentage": 75,
                                  "files": [{"file": "main.c", "covered_lines": 3, "total_lines": 4, "percentage": 75}]},
                "branch_metrics": {"covered_branches": 1, "total_branches": 2, "percentage": 50, "files": []}}},
            {"stage_id": "MODEL", "status": "COMPLETED", "metadata": {"model_status": "BUILT"}},
        ))
    page = FuzzingPage()
    page.show_report(report)
    assert page.flow_diagram._statuses["COVERAGE"] == "COMPLETED"
    assert page.coverage_table.rowCount() == 3
    assert "75" in page.coverage_table.item(0, 4).text()
    assert page.cfg_table.item(0, 0).text() == "STATE"
    assert page.cfg_table.item(1, 1).text() == "T0"
    assert "normalized Specification" in page.cfg_description.text()
    page.close()


def test_main_window_actions_enable_optional_stages_without_reloading(application, monkeypatch):
    window = MainWindow()
    calls = []
    monkeypatch.setattr(window, "_run_full", lambda: calls.append("run"))
    assert not hasattr(window.settings_page, "generate_c_model")
    assert window.settings_page.fuzz_enabled.isChecked()
    assert window.settings_page.settings().to_pipeline_options().fuzz_config is not None
    window.codegen.run_button.click()
    window.settings_page.fuzz_enabled.setChecked(False)
    window.fuzzing.run_button.click()
    assert window.settings_page.fuzz_enabled.isChecked()
    assert calls == ["run", "run"]
    assert window.PAGE_STAGES[window.PAGE_NAMES[4]] == ("CODEGEN", "BUILD")
    window.close()
