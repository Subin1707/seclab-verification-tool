from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

import pytest

from seclab.gui.controllers import GuiRunSettings, ProjectController, VerificationController, parse_tool_list
from seclab.evidence import ArtifactStore, EvidenceType, RunManifest


def _spec(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema_version": "1.0", "id": "gui-demo", "name": "GUI demo",
        "initial_state": "S0", "states": [{"id": "S0", "labels": ["safe"]}],
        "requirements": [{"id": "R1", "description": "Remain safe"}],
        "properties": [{"id": "P1", "logic": "CTL", "formula": "AG(safe)",
                        "requirement_ids": ["R1"]}],
    }), encoding="utf-8")
    return path


def test_project_controller_load_validate_normalize_and_preview(tmp_path):
    spec_path = _spec(tmp_path / "spec.json")
    controller = ProjectController()
    assert controller.open_project(tmp_path) == tmp_path.resolve()
    assert controller.select_specification(spec_path) == spec_path.resolve()
    assert "gui-demo" in controller.preview()
    loaded = controller.load()
    assert len(loaded.documents) == 1
    assert controller.validate() == loaded
    assert controller.normalize().id == "gui-demo"


def test_gui_specification_model_preview_uses_normalized_specification_data():
    from seclab.gui.main_window import MainWindow
    from seclab.specification import StateSpec, Specification, TransitionSpec
    specification = Specification(schema_version="1.0", id="preview", name="Preview",
        initial_state="S0", states=(StateSpec(id="S0", labels=("ready",)), StateSpec(id="S1")),
        transitions=(TransitionSpec(id="T0", source="S0", target="S1", label="go"),))
    preview = MainWindow._preview_specification_model(specification)
    assert preview["initial_states"] == ("S0",)
    assert preview["states"][0]["labels"] == ["ready"]
    assert preview["transitions"][0]["source"] == "S0"


def test_project_controller_adapts_teacher_format_in_memory_and_preserves_source(tmp_path):
    source = tmp_path / "teacher.json"
    raw = {"name": "EV teacher", "requirements": [], "safety_properties": [],
           "state_machine": {"states": ["READY"], "initial": ["READY"],
                             "labeling": {"READY": ["safe"]}, "transitions": []}}
    original = json.dumps(raw).encode()
    source.write_bytes(original)
    controller = ProjectController()
    controller.open_project(tmp_path)
    controller.select_specification(source)
    controller.adapter = "smart-ev-teacher"

    spec = controller.normalize()
    assert controller.specification_info["adapter"] == "Smart-EV Adapter"
    assert controller.specification_info["format"] == "Smart-EV Teacher Specification"
    assert spec.id == "EV-teacher"
    assert controller.verify_original_unchanged()
    assert source.read_bytes() == original


def test_unsupported_external_specification_is_rejected_before_pipeline(tmp_path):
    source = tmp_path / "unknown.json"
    source.write_text(json.dumps({"vendor": "unknown", "records": []}), encoding="utf-8")
    controller = ProjectController()
    controller.open_project(tmp_path)
    controller.select_specification(source)
    with pytest.raises(Exception, match="SCHEMA_VALIDATION_FAILED.*Missing required properties"):
        controller.normalize()


@pytest.mark.parametrize("raw, expected", [
    ({"schema_version": "1.0", "id": "incomplete"}, "Missing required property 'name'"),
    ({"schema_version": "9.0", "id": "future", "name": "Future"}, "is not one of"),
    ({"vendor": "unknown", "records": []}, "Missing required properties"),
])
def test_generic_specification_errors_reach_canonical_schema_validator(tmp_path, raw, expected):
    from seclab.specification import SpecificationError
    source = tmp_path / "invalid.json"
    source.write_text(json.dumps(raw), encoding="utf-8")
    controller = ProjectController()
    controller.open_project(tmp_path)
    controller.select_specification(source)
    with pytest.raises(SpecificationError, match=expected):
        controller.normalize()


def test_malformed_json_reports_parse_error_not_adapter_format_error(tmp_path):
    from seclab.specification import SpecificationError, SpecificationErrorCode
    source = tmp_path / "malformed.json"
    source.write_text('{"schema_version":', encoding="utf-8")
    controller = ProjectController()
    controller.open_project(tmp_path)
    controller.select_specification(source)
    with pytest.raises(SpecificationError) as error:
        controller.normalize()
    assert error.value.code == SpecificationErrorCode.INVALID_JSON
    assert error.value.location == "line 1, column 19"


def test_project_controller_exposes_invalid_specification_errors(tmp_path):
    spec_path = tmp_path / "bad.json"
    spec_path.write_text("{broken", encoding="utf-8")
    controller = ProjectController(specification_path=spec_path)
    with pytest.raises(Exception):
        controller.validate()


def test_project_and_spec_selection_clear_stale_normalized_state(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _spec(first)
    _spec(second)
    project = tmp_path / "project"
    project.mkdir()
    controller = ProjectController()
    controller.open_project(project)
    controller.select_specification(first)
    controller.normalize()
    assert controller.specification is not None
    controller.select_specification(second)
    assert controller.loaded is None and controller.specification is None
    controller.normalize()
    controller.open_project(project)
    assert controller.specification_path is None
    assert controller.loaded is None and controller.specification is None


def test_gui_run_settings_map_only_to_generic_pipeline_options():
    settings = GuiRunSettings(static_analyzers=("compiler",), toolchain_tools=parse_tool_list("gcc, gcov"),
                              run_memory=False, run_coverage=True, fuzz_enabled=True,
                              fuzz_strategy="BLACKBOX", fuzz_iterations=7, fuzz_seed=19,
                              )
    options = settings.to_pipeline_options("spec.json")
    assert options.specification_paths == (Path("spec.json"),)
    assert options.static_analyzers == ("compiler",)
    assert options.toolchain_tools == ("gcc", "gcov")
    assert not options.run_memory and options.run_coverage
    assert options.fuzz_config is not None
    assert options.fuzz_config.max_iterations == 7 and options.fuzz_config.random_seed == 19
    assert options.generate_c_model is True  # compatibility default; the GUI cannot disable CODEGEN
    assert parse_tool_list("  ") is None


def test_gui_run_settings_do_not_expose_benchmark_as_verification_option():
    from seclab.fuzzing import FuzzInput, InputKind, InputOrigin
    seed = FuzzInput("seed-1", {"value": 0}, InputKind.SCALARS, InputOrigin.SEED)
    settings = GuiRunSettings(fuzz_seeds=(seed,))
    options = settings.to_pipeline_options("spec.json")
    assert not hasattr(options, "run_accuracy")
    assert options.fuzz_seeds == (seed,)


def test_cli_pipeline_config_rejects_source_derived_verification_models(tmp_path):
    import pytest
    from seclab.cli import _load_config
    config = tmp_path / "pipeline.json"
    config.write_text(json.dumps({"source_model_target": "step",
        "source_model_parameter_domains": {"mode": [0, 1]}, "source_model_loop_bound": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported pipeline config key"):
        _load_config(config)


def test_verification_controller_passes_stage_selection_and_progress(monkeypatch, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec = _spec(tmp_path / "spec.json")
    controller = ProjectController(project_path=project, specification_path=spec)
    verification = VerificationController(controller)
    seen = {}
    class Expected:
        stage_summaries = ()

    expected = Expected()

    def fake_run(project_arg, workspace_arg, **kwargs):
        seen.update(project=project_arg, workspace=workspace_arg, **kwargs)
        return expected

    monkeypatch.setattr("seclab.gui.controllers.verification_controller.run_full_verification", fake_run)
    callback = lambda _record: None
    result = verification.run_stages(tmp_path / "runs", ("CTL",), progress_callback=callback)
    assert result is expected
    assert seen["stage_ids"] == ("CTL",)
    assert seen["progress_callback"] is callback
    assert seen["options"].specification_paths == (spec,)


def test_verification_controller_requires_project():
    with pytest.raises(ValueError, match="Open a project first"):
        VerificationController(ProjectController()).run_full("unused")


def test_report_deserialization_is_controller_boundary(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({
        "run_id": "history-run", "start_time": "2025-01-01T00:00:00+00:00",
        "end_time": "2025-01-01T00:00:01+00:00", "duration_seconds": 1,
        "specification_info": {}, "stage_summaries": [], "results": [], "status_counts": {},
        "evidence_manifest": {}, "traceability": {}, "limitations": [], "metadata": {},
    }), encoding="utf-8")
    controller = VerificationController(ProjectController())
    assert controller.load_report(report_path).run_id == "history-run"


def test_report_loading_stays_inside_selected_workspace(tmp_path):
    workspace = tmp_path / "runs"
    workspace.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    controller = VerificationController(ProjectController())
    controller.workspace = workspace
    with pytest.raises(ValueError, match="escapes the selected run workspace"):
        controller.load_report(outside)


def test_accuracy_report_reader_accepts_markdown_and_rejects_other_formats(tmp_path):
    report = tmp_path / "accuracy.md"
    report.write_text("# Per-checker metrics", encoding="utf-8")
    controller = VerificationController(ProjectController())
    assert controller.read_accuracy_report(report) == "# Per-checker metrics"
    unsupported = tmp_path / "input.txt"
    unsupported.write_text("not a report", encoding="utf-8")
    with pytest.raises(ValueError, match="Markdown or JSON"):
        controller.read_accuracy_report(unsupported)


def _write_run_report(path: Path, run_id: str, specification_info=None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "run_id": run_id, "start_time": "2025-01-01T00:00:00+00:00",
        "end_time": "2025-01-01T00:00:01+00:00", "duration_seconds": 1,
        "specification_info": specification_info or {}, "stage_summaries": [], "results": [],
        "status_counts": {}, "evidence_manifest": {}, "traceability": {},
        "limitations": [], "metadata": {},
    }), encoding="utf-8")


def _write_manifest(run_root: Path, run_id: str, *, project=None, metadata=None, evidence=()) -> None:
    manifest = RunManifest(run_id, project or {"name": "generic-project", "path": "/sut"},
        datetime.now(timezone.utc), evidence=tuple(evidence), metadata=metadata or {})
    manifest_path = run_root / "evidence" / "manifest" / "run-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")


def test_evidence_open_resolves_workspace_path_and_checks_sha256(tmp_path):
    workspace = tmp_path / "runs"
    run_root = workspace / "run-1"
    store = ArtifactStore(run_root)
    evidence = store.write_text("static", "finding.txt", "finding details", evidence_type=EvidenceType.LOG)
    _write_manifest(run_root, "run-1", evidence=(evidence,))
    report_path = run_root / "evidence" / "report" / "pipeline-report.json"
    _write_run_report(report_path, "run-1")
    controller = VerificationController(ProjectController())
    controller.workspace = workspace
    controller.load_report(report_path)
    metadata, path = controller.read_evidence(evidence.id)
    assert metadata["id"] == evidence.id
    assert metadata["source"] == evidence.source
    assert path.read_text(encoding="utf-8") == "finding details"
    assert controller.verify_evidence(evidence.id)["status"] == "VERIFIED"
    path.write_text("tampered", encoding="utf-8")
    assert controller.verify_evidence(evidence.id)["status"] == "INTEGRITY_ERROR"
    with pytest.raises(ValueError, match="SHA-256"):
        controller.evidence_path(evidence.id)


def test_evidence_hash_verification_reports_missing_artifact(tmp_path):
    workspace = tmp_path / "runs"
    run_root = workspace / "run-missing"
    store = ArtifactStore(run_root)
    evidence = store.write_text("static", "finding.txt", "finding", evidence_type=EvidenceType.LOG)
    _write_manifest(run_root, "run-missing", evidence=(evidence,))
    report_path = run_root / "evidence" / "report" / "pipeline-report.json"
    _write_run_report(report_path, "run-missing")
    controller = VerificationController(ProjectController())
    controller.workspace = workspace
    controller.load_report(report_path)
    (run_root / evidence.path).unlink()
    assert controller.verify_evidence(evidence.id)["status"] == "MISSING"


def test_run_history_includes_project_specification_and_stage_statuses(tmp_path):
    workspace = tmp_path / "runs"
    run_root = workspace / "run-history"
    _write_manifest(run_root, "run-history", project={"name": "C sample", "path": "/projects/c-sample"},
        metadata={"stage_statuses": {"SOURCE": "COMPLETED", "CTL": "SKIPPED"}})
    _write_run_report(run_root / "evidence" / "report" / "pipeline-report.json", "run-history",
                      {"id": "generic-spec", "name": "Generic spec"})
    controller = VerificationController(ProjectController())
    controller.workspace = workspace
    (items,) = controller.load_run_history()
    assert items["run_id"] == "run-history"
    assert items["project"] == "C sample"
    assert items["project_path"] == "/projects/c-sample"
    assert items["specification"] == "generic-spec"
    assert items["stage_statuses"] == {"SOURCE": "COMPLETED", "CTL": "SKIPPED"}
    assert Path(items["run_root"]) == run_root
    assert Path(items["report"]).is_file()
