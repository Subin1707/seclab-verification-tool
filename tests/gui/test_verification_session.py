from pathlib import Path
from types import SimpleNamespace

import pytest

from seclab.gui.session import SessionState, VerificationSession


def test_session_retains_project_specification_and_normalized_requirements(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec_path = tmp_path / "spec.json"
    spec_path.write_text("{}", encoding="utf-8")
    session = VerificationSession(workspace=tmp_path / "runs")
    session.open_project(project, ("main.c",))
    session.select_specification(spec_path)
    normalized = SimpleNamespace(id="spec-1", name="Demo", requirements=("REQ-1",), properties=("PROP-1",))
    loaded = object()
    session.set_validated_specification(normalized, loaded=loaded, adapter_info={
        "format": "Smart-EV Teacher Specification", "adapter": "Smart-EV Adapter",
        "original_sha256": "a" * 64})

    assert session.project_path == project.resolve()
    assert session.specification_path == spec_path.resolve()
    assert session.normalized_specification is normalized
    assert session.requirements == ("REQ-1",)
    assert session.loaded_specification is loaded
    assert session.specification_format == "Smart-EV Teacher Specification"
    assert session.adapter_name == "Smart-EV Adapter"
    assert session.original_spec_hash == "a" * 64
    assert session.ready and session.state is SessionState.READY


def test_session_lifecycle_stores_progress_results_evidence_and_traceability(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    session = VerificationSession(workspace=tmp_path / "runs")
    session.open_project(project)
    session.select_specification(tmp_path / "spec.json")
    session.set_validated_specification(SimpleNamespace(id="S", name="S", requirements=(), properties=()))
    session.begin_run()
    session.update_stage({"stage_id": "CTL", "status": "RUNNING"})
    assert session.state is SessionState.RUNNING
    assert session.stage_results["CTL"]["status"] == "RUNNING"

    report = SimpleNamespace(run_id="run-1", stage_summaries=({"stage_id": "CTL", "status": "COMPLETED"},),
        traceability={"REQ-1": {"results": ["RES-1"]}}, specification_info={"id": "S"},
        status_counts={"PASS": 1})
    evidence = ({"id": "EVD-1", "hash": "a" * 64},)
    session.complete_run(report, evidence)
    assert session.state is SessionState.COMPLETED
    assert session.run_id == "run-1" and session.report is report
    assert session.evidence == evidence
    assert session.traceability == report.traceability


def test_session_open_saved_run_needs_no_current_project_or_spec_reload(tmp_path):
    report = SimpleNamespace(run_id="old-run", metadata={"project": str(tmp_path / "old-project")},
        stage_summaries=(), traceability={}, specification_info={"id": "old-spec"}, status_counts={})
    session = VerificationSession()
    session.open_saved_run(report, tmp_path / "runs")
    assert session.project_path == tmp_path / "old-project"
    assert session.specification_path is None
    assert session.run_id == "old-run"
    assert session.specification_info["id"] == "old-spec"
    assert session.state is SessionState.COMPLETED


def test_session_reset_on_new_project_and_invalid_specification_is_not_ready(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    session = VerificationSession()
    session.open_project(first)
    session.select_specification(tmp_path / "spec.json")
    with pytest.raises(ValueError, match="valid specification"):
        session.begin_run()
    session.open_project(second)
    assert session.project_path == second.resolve()
    assert session.specification_path is None
    assert session.run_id is None
    assert session.state is SessionState.PROJECT_LOADED


def test_session_retains_independent_workflow_lifecycle_steps():
    session = VerificationSession()
    session.update_workflow_step({"stage_id": "BUILD_SPECIFICATION_MODEL", "status": "UNSUPPORTED",
                                  "reason": "No explicit source target"})
    assert session.workflow_step("BUILD_SPECIFICATION_MODEL")["status"] == "UNSUPPORTED"
    assert session.workflow_step("RUN_FUZZING")["status"] == "NOT_RUN"
    session.reset_workflow()
    assert session.workflow_step("BUILD_SPECIFICATION_MODEL")["status"] == "NOT_RUN"
