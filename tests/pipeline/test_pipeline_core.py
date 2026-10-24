from __future__ import annotations

import json
import hashlib
from pathlib import Path

from seclab.pipeline import FunctionalStage, PipelineOptions, PipelineOrchestrator, StageOutput, StageStatus, run_full_verification
from seclab.config import Toolchain
from seclab.evidence import RunManifest
from seclab.fuzzing import FuzzConfig, FuzzInput, FuzzStrategy, InputKind, InputOrigin
import pytest


def test_full_pipeline_without_optional_spec_still_runs_source_stages(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text('#include <stdio.h>\nint main(void) { puts("ready"); return 0; }\n', encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="no-spec",
        options=PipelineOptions(run_memory=False, run_coverage=False, static_analyzers=()))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SPECIFICATION"]["status"] == StageStatus.SKIPPED
    assert stages["SOURCE"]["status"] == StageStatus.COMPLETED
    assert stages["CTL"]["status"] == StageStatus.SKIPPED
    assert stages["CROSS_CHECK"]["status"] == StageStatus.COMPLETED
    matrix = report.metadata["cross_check_matrix"]
    assert matrix["aggregation"] == "NONE" and "overall_verdict" not in matrix
    assert any(row["id"] == "MODEL_SOURCE" and row["status"] == "UNRESOLVED"
               for row in matrix["relations"])
    assert "overall_status" not in report.to_dict()
    assert "accuracy" not in report.to_dict()
    assert "ACCURACY" not in {item["stage_id"] for item in report.stage_summaries}
    assert not {"overall_verdict", "overall_status", "project_pass", "project_fail"}.intersection(report.to_dict())
    manifest = json.loads((tmp_path / "workspace/no-spec/evidence/manifest/run-manifest.json").read_text())
    assert "results" in manifest and "evidence" in manifest


def test_invalid_spec_failure_is_recorded_without_blocking_source_analysis(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec = tmp_path / "broken.json"
    spec.write_text("{ invalid", encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="invalid-spec",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SPECIFICATION"]["status"] == StageStatus.FAILED
    assert stages["SOURCE"]["status"] == StageStatus.COMPLETED
    assert stages["STATIC"]["status"] == StageStatus.SKIPPED
    assert stages["STATIC"]["reason"] == "No static analyzers were configured."
    assert stages["MODEL"]["status"] == StageStatus.SKIPPED
    assert any(result.reason_code == "INVALID_SPECIFICATION" for result in report.results)
    diagnostic = json.loads((tmp_path / "workspace/invalid-spec/evidence/pipeline/specification-error.json").read_text())
    assert diagnostic["result"] == "INVALID"
    assert diagnostic["diagnostics"][0]["code"] == "INVALID_JSON"
    assert diagnostic["input_hashes"][0]["sha256"] == hashlib.sha256(spec.read_bytes()).hexdigest()


def test_stage_exception_keeps_partial_artifacts_linked_as_evidence(tmp_path, monkeypatch):
    from seclab.pipeline import stages as pipeline_stages
    from seclab.fuzzing import FuzzConfig, FuzzStrategy

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "partial", "name": "Partial",
        "initial_state": "S", "states": [{"id": "S", "initial": True, "labels": ["safe"]}],
        "tests": [{"id": "T", "input": {"target": "program", "argv": []},
                   "expected": {"exit_code": 0}}]}), encoding="utf-8")

    def fail_after_writing(ctx, _options):
        ctx.artifact_store.write_json("fuzz-campaigns", "partial-campaign.json", {"phase": "started"})
        raise RuntimeError("controlled stage failure after an evidence write")

    monkeypatch.setattr(pipeline_stages.PipelineStages, "fuzzing", staticmethod(fail_after_writing))
    report = run_full_verification(project, tmp_path / "runs", run_id="partial-artifacts",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False, run_coverage=False,
            static_analyzers=(), fuzz_config=FuzzConfig(FuzzStrategy.BLACKBOX, 1, 1, 7, 16)))
    stage = next(row for row in report.stage_summaries if row["stage_id"] == "FUZZING")
    assert stage["status"] == "FAILED"
    manifest = json.loads((tmp_path / "runs/partial-artifacts/evidence/manifest/run-manifest.json").read_text())
    partial = next(item for item in manifest["evidence"] if item["path"].endswith("partial-campaign.json"))
    assert partial["id"] in stage["evidence_ids"] + stage["output_refs"]
    assert report.metadata["traceability_integrity"]["valid"]


def test_pipeline_validates_and_normalizes_specification_once(tmp_path, monkeypatch):
    from seclab.pipeline import stages as pipeline_stages
    from seclab.specification import validate_specification as validate

    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "once", "name": "Once"}), encoding="utf-8")
    calls = []

    def counted(loaded, schema_path=None):
        calls.append(loaded)
        return validate(loaded, schema_path=schema_path)

    monkeypatch.setattr(pipeline_stages, "validate_specification", counted)
    report = run_full_verification(project, tmp_path / "workspace", run_id="once",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    assert len(calls) == 1
    stage = next(item for item in report.stage_summaries if item["stage_id"] == "SPECIFICATION")
    assert stage["metadata"]["validation_result"] == "VALID"
    assert stage["metadata"]["normalized_sha256"]


def test_pipeline_scans_project_once_and_reuses_context_across_stages(tmp_path, monkeypatch):
    from seclab.pipeline import stages as pipeline_stages
    from seclab.source import SourceLoader
    from seclab.specification import load_specification, validate_specification, normalize_specification

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({"schema_version": "1.0", "id": "reuse", "name": "Reuse",
        "states": [{"id": "S0", "initial": True}]}), encoding="utf-8")
    calls = {"source_roots": [], "model": 0}
    original_loader = SourceLoader.load_source_tree
    original_model = pipeline_stages.generate_kripke_structure

    def counted_scan(self, root):
        calls["source_roots"].append(Path(root).resolve())
        return original_loader(self, root)

    def counted_model(specification, **kwargs):
        calls["model"] += 1
        return original_model(specification, **kwargs)

    monkeypatch.setattr(SourceLoader, "load_source_tree", counted_scan)
    monkeypatch.setattr(pipeline_stages, "generate_kripke_structure", counted_model)
    report = run_full_verification(project, tmp_path / "workspace", run_id="reuse-context",
        options=PipelineOptions(specification_paths=(spec_path,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    assert calls["source_roots"].count(project.resolve()) == 1
    assert calls["model"] == 1
    assert all(row["status"] in {"COMPLETED", "SKIPPED", "FAILED"} and row["reason"]
               for row in report.stage_summaries)


def test_orchestrator_passes_one_verification_context_through_the_run(tmp_path, monkeypatch):
    from seclab.pipeline import FunctionalStage, VerificationContext

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    observed_contexts = []
    execute = FunctionalStage.execute

    def capture_context(stage, context):
        observed_contexts.append(context)
        return execute(stage, context)

    monkeypatch.setattr(FunctionalStage, "execute", capture_context)
    report = run_full_verification(project, tmp_path / "workspace", run_id="single-context",
        options=PipelineOptions(run_memory=False, run_coverage=False, static_analyzers=()))

    assert observed_contexts
    context = observed_contexts[0]
    assert isinstance(context, VerificationContext)
    assert all(item is context for item in observed_contexts)
    assert context.run_id == report.run_id == "single-context"
    assert context.project == project.resolve()
    assert context.workspace == (tmp_path / "workspace/single-context").resolve()
    assert context.options is not None


def test_selecting_single_formal_stage_runs_prerequisites_automatically(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "deps", "name": "Dependencies",
        "initial_state": "S0", "states": [{"id": "S0", "labels": ["safe"]}],
        "properties": [{"id": "P1", "logic": "CTL", "formula": "AG(safe)"}]}), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="single-ctl",
        stage_ids=("CTL",), options=PipelineOptions(specification_paths=(spec,),
            run_memory=False, run_coverage=False, static_analyzers=()))
    stages = {row["stage_id"]: row for row in report.stage_summaries}
    assert all(stages[item]["status"] == StageStatus.COMPLETED for item in ("SPECIFICATION", "MODEL", "CTL"))
    assert stages["BMC"]["status"] == StageStatus.SKIPPED
    assert stages["BMC"]["selected"] is False
    assert stages["CROSS_CHECK"]["status"] == StageStatus.COMPLETED
    assert "overall_verdict" not in report.metadata["cross_check_matrix"]


def test_model_stage_persists_provenance_summary_validation_graph_and_trace_links(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "model-evidence",
        "name": "Model evidence", "initial_state": "A",
        "states": [{"id": "A", "labels": ["ready"]}, {"id": "B", "labels": ["done"]}],
        "transitions": [{"id": "AB", "source": "A", "target": "B", "action": "advance"}],
        "requirements": [{"id": "R1", "description": "A traceable requirement"}]}), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="model-evidence",
        stage_ids=("MODEL",), options=PipelineOptions(specification_paths=(spec,),
            run_memory=False, run_coverage=False, static_analyzers=()))
    evidence_root = tmp_path / "workspace/model-evidence/evidence/model"
    model = json.loads((evidence_root / "kripke.json").read_text(encoding="utf-8"))
    summary = json.loads((evidence_root / "model-summary.json").read_text(encoding="utf-8"))
    validation = json.loads((evidence_root / "model-validation.json").read_text(encoding="utf-8"))
    graph = (evidence_root / "model-graph.dot").read_text(encoding="utf-8")
    assert model["model_id"] == summary["model_id"]
    assert model["specification_hash"] == summary["specification_hash"]
    assert model["source_specification_paths"] == [str(spec)]
    assert validation["status"] == "PASS" and validation["statistics"]["proposition_count"] == 2
    assert '"A" -> "B"' in graph
    requirement = report.traceability["R1"]["model"]
    assert requirement["model_hash"] == model["model_hash"]
    manifest = json.loads((tmp_path / "workspace/model-evidence/evidence/manifest/run-manifest.json").read_text())
    model_artifacts = [item for item in manifest["evidence"] if item.get("stage") == "model"]
    assert {Path(item["path"]).name for item in model_artifacts} >= {
        "kripke.json", "model-summary.json", "model-validation.json", "model-graph.dot"}


def test_cancelled_pipeline_skips_pending_stages_and_still_persists_report(tmp_path):
    from threading import Event

    project = tmp_path / "project"
    project.mkdir()
    cancellation = Event()
    cancellation.set()
    report = run_full_verification(project, tmp_path / "workspace", run_id="cancelled-run",
        stage_ids=("CTL",), cancellation_event=cancellation)
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SPECIFICATION"]["status"] == StageStatus.SKIPPED
    assert stages["CTL"]["status"] == StageStatus.SKIPPED
    assert stages["REPORT"]["status"] == StageStatus.COMPLETED
    assert stages["CROSS_CHECK"]["status"] == StageStatus.COMPLETED
    assert report.metadata["cancelled"] is True
    assert (tmp_path / "workspace/cancelled-run/evidence/report/pipeline-report.json").is_file()


def test_opt_in_generic_c_codegen_persists_classified_reproducible_outputs(tmp_path, monkeypatch):
    from seclab.pipeline import stages as pipeline_stages
    original_model_builder = pipeline_stages.generate_kripke_structure
    model_builds = []

    def count_model_build(specification, **kwargs):
        model_builds.append(specification.id)
        return original_model_builder(specification, **kwargs)

    monkeypatch.setattr(pipeline_stages, "generate_kripke_structure", count_model_build)
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "model.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "generic", "name": "Generic",
        "functions": [{"id": "PY-FUNCTION", "name": "declared_python", "language": "python"}],
        "states": [{"id": "S0", "initial": True, "labels": ["ready"]}, {"id": "S1"}],
        "transitions": [{"id": "STEP", "source": "S0", "target": "S1"}]}), encoding="utf-8")
    options = PipelineOptions(specification_paths=(spec,), run_memory=True, run_coverage=True,
        coverage_backend="gcov", static_analyzers=("compiler",),
        fuzz_config=FuzzConfig(FuzzStrategy.BLACKBOX, max_iterations=1,
            timeout_per_input=2, random_seed=19, max_input_size=16),
        generate_c_model=True, generate_c_fuzz_harness=True)
    report = run_full_verification(project, tmp_path / "workspace", run_id="generic-codegen", options=options)
    stage = next(item for item in report.stage_summaries if item["stage_id"] == "CODEGEN")
    generated = tmp_path / "workspace/generic-codegen/generated"
    assert stage["status"] == StageStatus.COMPLETED
    assert "compiler_runs" not in stage["metadata"]
    assert "generated_executable" not in stage["metadata"]
    assert (generated / "source/model.c").is_file()
    assert (generated / "python/model.py").is_file()
    assert (generated / "include/model.h").is_file()
    assert (generated / "tests/model_test.c").is_file()
    assert (generated / "fuzz/model_fuzz.c").is_file()
    evidence = [item for item in report.to_dict()["metadata"]["artifact_classes"]["GENERATED_SOURCE"]]
    assert evidence
    manifest = json.loads((generated / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_hash"] == stage["metadata"]["model_hash"]
    assert manifest["run_id"] == "generic-codegen"
    assert manifest["functions"][0]["language"] == "python"
    assert manifest["functions"][0]["status"] == "UNSUPPORTED_NO_EXECUTABLE_CONTRACT"
    assert manifest["model_code_consistency"]["status"] == "PASS"
    assert (generated / "requirements-map.json").is_file()
    build = next(item for item in report.stage_summaries if item["stage_id"] == "BUILD")
    assert build["metadata"]["generated_executable"]
    assert build["metadata"]["generated_fuzz_executable"]
    assert any(row["status"] == "COMPLETED" for row in build["metadata"]["fuzz_compiler_runs"])
    assert build["metadata"]["python_model_runs"][0]["status"] == "PASS"
    assert {row["compiler"] for row in build["metadata"]["compiler_runs"]} == {"gcc", "clang"}
    assert model_builds == ["generic"]
    dynamic = next(item for item in report.stage_summaries if item["stage_id"] == "DYNAMIC")
    assert dynamic["metadata"]["generated_model_test_count"] == 1
    assert dynamic["metadata"]["generated_model_executed_count"] == 1
    static = next(item for item in report.stage_summaries if item["stage_id"] == "STATIC")
    assert "source/model.c" in static["metadata"]["generated_model_files"]
    memory = next(item for item in report.stage_summaries if item["stage_id"] == "MEMORY")
    assert "source/model.c" in memory["metadata"]["generated_model_files"]
    coverage = next(item for item in report.stage_summaries if item["stage_id"] == "COVERAGE")
    assert coverage["metadata"]["target_scope"] == "MODEL_GENERATED"
    coverage_result = next((item for item in report.results
                            if item.technique == "COVERAGE_MEASUREMENT"), None)
    if coverage["metadata"]["has_report"]:
        assert coverage_result is None or coverage_result.status.value == "INCONCLUSIVE"
    else:
        # A host/backend build failure is retained as measurement evidence and
        # must never be represented as zero or successful coverage.
        assert coverage["output"] is None
        assert coverage_result is not None
        assert coverage_result.status.value in {"BUILD_ERROR", "TOOL_ERROR", "INCONCLUSIVE"}
        assert coverage_result.evidence_ids
    fuzzing = next(item for item in report.stage_summaries if item["stage_id"] == "FUZZING")
    assert fuzzing["metadata"]["target_scope"] == "MODEL_GENERATED"
    assert fuzzing["metadata"]["target_count"] == 1
    assert fuzzing["metadata"]["executed_count"] == 1
    campaigns = fuzzing["output"].get("campaigns", (fuzzing["output"],))
    assert {item["analysis_surface"] for item in campaigns} == {"MODEL_GENERATED_API"}
    api_campaign = campaigns[0]
    assert api_campaign["target"] == "generated-model-api"
    assert api_campaign["model_state_ids"] == ["S0", "S1"]
    assert api_campaign["model_transition_ids"] == ["STEP"]


def test_smt_pipeline_does_not_use_scenario_expected_outcome_as_observation(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "satisfiable.json"
    spec.write_text(json.dumps({
        "schema_version": "1.0", "id": "satisfiable", "name": "Satisfiable",
        "variables": [{"id": "x", "domain": {"type": "integer", "minimum": 0, "maximum": 10}}],
        "properties": [{"id": "P-SAT", "logic": "SMT", "formula": "x <= 5",
            "metadata": {"query_intent": "SATISFIABILITY",
                         "expected_solver_outcome": "UNSAT",
                         "satisfiability_check": {"expected_solver_outcome": "UNSAT"}}}],
    }), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="observed-sat",
        stage_ids=("SMT",), options=PipelineOptions(specification_paths=(spec,),
            static_analyzers=(), run_memory=False, run_coverage=False))
    result = next(item for item in report.results if item.technique == "SMT")
    assert result.status.value == "INCONCLUSIVE"
    assert result.metadata["solver_outcome"] == "SAT"
    assert result.reason_code == "QUERY_INTENT_UNCLASSIFIED"
    assert result.metadata["formal_run"]["inputs"]["query_intent"] == "SATISFIABILITY"


def test_missing_initial_state_fails_spec_and_skips_formal_dependents(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec = tmp_path / "missing-initial.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "bad-init", "name": "Bad init",
                                "states": [{"id": "S0"}],
                                "properties": [{"id": "P1", "logic": "CTL", "formula": "true"}]}),
                    encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="missing-init",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SPECIFICATION"]["status"] == StageStatus.FAILED
    assert stages["MODEL"]["status"] == StageStatus.SKIPPED
    assert stages["CTL"]["status"] == StageStatus.SKIPPED
    assert stages["SOURCE"]["status"] == StageStatus.COMPLETED


def test_formal_stages_skip_with_reasons_when_spec_declares_no_properties(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec = tmp_path / "no-properties.json"
    spec.write_text(json.dumps({
        "schema_version": "1.0", "id": "empty-check-set", "name": "Empty check set",
        "initial_state": "READY", "states": [{"id": "READY", "labels": ["ready"]}],
        "transitions": [{"id": "LOOP", "source": "READY", "target": "READY"}],
    }), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="empty-check-set",
        options=PipelineOptions(specification_paths=(spec,), static_analyzers=(), run_memory=False,
                                run_coverage=False))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    for stage_id, reason in (
        ("CTL", "The specification declares no CTL properties."),
        ("BMC", "The specification declares no BMC properties."),
        ("SMT", "The specification declares no SMT properties."),
    ):
        assert stages[stage_id]["status"] == StageStatus.SKIPPED
        assert stages[stage_id]["reason"] == reason


def test_missing_project_source_still_keeps_generated_model_scope_separate(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "no-source", "name": "No source",
        "tests": [{"id": "T1", "input": {"stdin": ""}, "expected": {"exit_code": 0}}]}), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="missing-source",
        options=PipelineOptions(specification_paths=(spec,), run_memory=True, run_coverage=True,
            fuzz_config=FuzzConfig(FuzzStrategy.BLACKBOX, 1, 1, 1, 8), static_analyzers=()))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SOURCE"]["status"] == StageStatus.SKIPPED
    assert stages["SOURCE"]["reason"] == "No supported source files were found in the project."
    assert stages["STATIC"]["status"] == StageStatus.SKIPPED
    assert stages["MEMORY"]["status"] in {StageStatus.COMPLETED, StageStatus.SKIPPED}
    assert all(stages[key]["status"] == StageStatus.SKIPPED for key in
               ("DYNAMIC", "COVERAGE", "FUZZING"))


def test_memory_stage_runs_existing_analyzers_and_persists_limitations(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source = project / "main.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    report = run_full_verification(project, tmp_path / "workspace", run_id="memory-run",
        options=PipelineOptions(run_memory=True, run_coverage=False, static_analyzers=(),
                                toolchain_tools=("gcc", "clang", "g++", "clang++")))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["MEMORY"]["status"] == StageStatus.COMPLETED
    assert stages["MEMORY"]["evidence_ids"]
    assert any("Struct layout" in item for item in report.limitations)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert (tmp_path / "workspace/memory-run/evidence/memory/struct-analysis.json").is_file()
    memory_records = [item for item in report.metadata["cross_check_matrix"]["checker_records"]
                      if item["stage"] in {"MEMORY_ANALYSIS", "SANITIZER"}]
    assert memory_records
    assert all(item["checker_contract"]["runtime_scope"] for item in memory_records)


def test_pipeline_rejects_artifact_workspace_inside_source_tree(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError, match="outside"):
        run_full_verification(project, project / "artifacts", run_id="unsafe")


def test_pipeline_stage_order_is_stable():
    first = PipelineOrchestrator.full()._ordered_ids()
    second = PipelineOrchestrator.full()._ordered_ids()
    assert first == second
    assert first[0] == "SPECIFICATION" and first[-1] == "REPORT"
    assert first == ("SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN", "BUILD", "STATIC",
                     "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT")


def test_pipeline_rejects_cyclic_stage_graph():
    stages = (
        FunctionalStage("SPECIFICATION", "A", lambda _context: StageOutput(), ("MODEL",)),
        FunctionalStage("MODEL", "B", lambda _context: StageOutput(), ("SPECIFICATION",)),
    )
    with pytest.raises(ValueError, match="cycle"):
        PipelineOrchestrator(stages)


def test_report_stage_can_run_without_expanding_to_full_pipeline(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", stage_ids=("REPORT",),
                                   run_id="report-only")
    statuses = {item["stage_id"]: item["status"] for item in report.stage_summaries}
    assert statuses["REPORT"] == StageStatus.COMPLETED
    assert all(status == StageStatus.SKIPPED for stage, status in statuses.items() if stage != "REPORT")
    assert all(next(item for item in report.stage_summaries if item["stage_id"] == stage)["reason"]
               for stage in statuses if stage != "REPORT")


def test_report_verifies_all_pre_manifest_artifact_hashes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="hash-check",
        options=PipelineOptions(static_analyzers=(), run_memory=False, run_coverage=False))
    checks = report.metadata["artifact_integrity"]
    assert checks and all(item["valid"] for item in checks)
    assert all(item["actual_sha256"] == item["expected_sha256"] for item in checks)


def test_final_manifest_and_report_artifact_hashes_remain_valid(tmp_path, monkeypatch):
    from seclab.pipeline import orchestrator as orchestrator_module

    captured = []
    original = orchestrator_module.TrackedArtifactStore.write_json

    def capture(store, stage, filename, content, **kwargs):
        item = original(store, stage, filename, content, **kwargs)
        if stage == "manifest" and filename == "run-manifest.json":
            captured.append(item)
        return item

    monkeypatch.setattr(orchestrator_module.TrackedArtifactStore, "write_json", capture)
    project = tmp_path / "project"
    project.mkdir()
    report = run_full_verification(project, tmp_path / "workspace", run_id="final-hashes",
                                   stage_ids=("REPORT",))
    run_root = tmp_path / "workspace" / "final-hashes"
    manifest_path = run_root / "evidence" / "manifest" / "run-manifest.json"
    assert len(captured) == 1
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == captured[0].hash
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_ref = next(item for item in manifest["evidence"]
                      if item["path"] == "evidence/report/pipeline-report.json")
    report_path = run_root / report_ref["path"]
    assert hashlib.sha256(report_path.read_bytes()).hexdigest() == report_ref["hash"]
    assert manifest["metadata"]["result_traceability"] == {}
    assert report.evidence_manifest["path"] == "evidence/manifest/run-manifest.json"


def test_artifact_hash_mismatch_is_a_scoped_report_result(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    def tamper(context):
        ref = context.artifact_store.write_text("specification", "normalized.json", "original")
        (context.workspace / ref.path).write_text("modified", encoding="utf-8")
        return StageOutput(evidence=(ref,))

    stages = (
        FunctionalStage("SPECIFICATION", "Specification", tamper),
        FunctionalStage("REPORT", "Report", lambda _ctx: StageOutput()),
    )
    report = PipelineOrchestrator(stages).run(project, tmp_path / "workspace", run_id="tampered-artifact")
    integrity = [item for item in report.metadata["artifact_integrity"] if not item["valid"]]
    assert len(integrity) == 1
    result = next(item for item in report.results if item.technique == "ARTIFACT_INTEGRITY")
    assert result.stage == "REPORT"
    assert result.reason_code == "ARTIFACT_HASH_MISMATCH"


def test_missing_artifact_is_reported_and_does_not_abort_manifest(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    def remove_artifact(context):
        ref = context.artifact_store.write_text("specification", "missing.txt", "present")
        (context.workspace / ref.path).unlink()
        return StageOutput(evidence=(ref,))

    stages = (FunctionalStage("SPECIFICATION", "Specification", remove_artifact),
              FunctionalStage("REPORT", "Report", lambda _ctx: StageOutput()))
    report = PipelineOrchestrator(stages).run(project, tmp_path / "workspace", run_id="missing-artifact")
    invalid = [row for row in report.metadata["artifact_integrity"] if not row["valid"]]
    assert len(invalid) == 1
    assert "FileNotFoundError" in invalid[0]["error"]
    assert any(item.technique == "ARTIFACT_INTEGRITY" for item in report.results)
    assert (tmp_path / "workspace/missing-artifact/evidence/manifest/run-manifest.json").is_file()


def test_broken_result_evidence_reference_is_explicitly_reported(tmp_path):
    from seclab.results import VerificationResult, VerificationStatus

    project = tmp_path / "project"
    project.mkdir()
    result = VerificationResult("broken-result", "SPECIFICATION", "TEST", VerificationStatus.FAIL,
                                "BROKEN", "missing evidence", evidence_ids=("does-not-exist",))
    stages = (FunctionalStage("SPECIFICATION", "Specification",
                              lambda _ctx: StageOutput(results=(result,))),
              FunctionalStage("REPORT", "Report", lambda _ctx: StageOutput()))
    report = PipelineOrchestrator(stages).run(project, tmp_path / "workspace", run_id="broken-reference")
    assert any(item.technique == "ARTIFACT_INTEGRITY" for item in report.results)
    assert report.metadata["traceability_integrity"]["broken_references"] == []
    manifest = json.loads((tmp_path / "workspace/broken-reference/evidence/manifest/run-manifest.json").read_text())
    assert "does-not-exist" in manifest["metadata"]["result_traceability"]["broken-result"]["unresolved_evidence_ids"]


def test_artifact_symlink_escape_fails_workspace_integrity(tmp_path):
    from dataclasses import replace
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("external", encoding="utf-8")

    def replace_with_escape(context):
        ref = context.artifact_store.write_text("specification", "escape.txt", "internal")
        (context.workspace / ref.path).unlink()
        forged = replace(ref, path="../outside.txt")
        return StageOutput(evidence=(forged,))

    stages = (FunctionalStage("SPECIFICATION", "Specification", replace_with_escape),
              FunctionalStage("REPORT", "Report", lambda _ctx: StageOutput()))
    report = PipelineOrchestrator(stages).run(project, tmp_path / "workspace", run_id="escape-artifact")
    invalid = [row for row in report.metadata["artifact_integrity"] if not row["valid"]]
    assert len(invalid) == 1
    assert "outside" in invalid[0]["error"]


def test_manifest_artifact_records_have_size_checker_and_run_id(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    report = run_full_verification(project, tmp_path / "workspace", run_id="metadata-fields",
                                   stage_ids=("REPORT",))
    manifest = json.loads((tmp_path / "workspace/metadata-fields/evidence/manifest/run-manifest.json").read_text())
    for item in manifest["evidence"]:
        assert item["size_bytes"] is not None
        assert item["checker"]
        assert item["run_id"] == report.run_id


def test_every_stage_has_provenance_evidence_and_reproducible_input_fingerprint(tmp_path):
    from seclab.pipeline import load_previous_run

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    options = PipelineOptions(run_memory=False, run_coverage=False, static_analyzers=(),
        fuzz_config=FuzzConfig(FuzzStrategy.BLACKBOX, 1, 1, 77, 8, minimize_failures=False))
    first = run_full_verification(project, tmp_path / "workspace-a", run_id="provenance-a",
                                  stage_ids=("SOURCE",), options=options)
    second = run_full_verification(project, tmp_path / "workspace-b", run_id="provenance-b",
                                   stage_ids=("SOURCE",), options=options)
    assert first.metadata["reproducibility"]["reproducibility_id"] == second.metadata["reproducibility"]["reproducibility_id"]
    changed_seed = PipelineOptions(run_memory=False, run_coverage=False, static_analyzers=(),
        fuzz_config=FuzzConfig(FuzzStrategy.BLACKBOX, 1, 1, 78, 8, minimize_failures=False))
    third = run_full_verification(project, tmp_path / "workspace-c", run_id="provenance-c",
                                  stage_ids=("SOURCE",), options=changed_seed)
    assert first.metadata["reproducibility"]["reproducibility_id"] != third.metadata["reproducibility"]["reproducibility_id"]

    run_root = tmp_path / "workspace-a" / "provenance-a"
    manifest = json.loads((run_root / "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
    evidence_by_id = {item["id"]: item for item in manifest["evidence"]}
    stage_records = manifest["metadata"]["stage_records"]
    assert stage_records
    for record in stage_records:
        evidence_id = record["metadata"]["execution_evidence_id"]
        envelope = evidence_by_id[evidence_id]
        assert envelope["run_id"] == first.run_id
        assert len(envelope["hash"]) == 64
        assert envelope["path"].startswith("evidence/")
        assert envelope["metadata"]["status"] == record["status"]
        artifact = json.loads((run_root / envelope["path"]).read_text(encoding="utf-8"))
        assert artifact["run_id"] == first.run_id
        assert artifact["stage_id"] == record["stage_id"]
        assert artifact["status"] == record["status"]
        assert artifact["source_set_sha256"]
        assert artifact["configuration_sha256"]
        assert isinstance(artifact["tool_versions"], dict)

    for item in manifest["evidence"]:
        assert item["id"] and item["type"] and item["path"] and len(item["hash"]) == 64
        assert item["timestamp"] and item["run_id"] == first.run_id and item["checker"]
        provenance = item["metadata"]["provenance"]
        assert provenance["run_id"] == first.run_id
        assert provenance["status"]
        assert isinstance(provenance["source_sha256"], dict)
        assert isinstance(provenance["tool_versions"], dict)
        assert provenance["configuration"] and provenance["configuration_sha256"]
        artifact = (run_root / item["path"]).resolve(strict=True)
        assert artifact.is_relative_to(run_root.resolve())
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == item["hash"]
    integrity = json.loads((run_root / "evidence/manifest/run-integrity.json").read_text(encoding="utf-8"))
    assert integrity["manifest_evidence"]["sha256"] == integrity["manifest"]["sha256"]
    reopened = load_previous_run(tmp_path / "workspace-a", "provenance-a")
    assert reopened.metadata["reproducibility"]["reproducibility_id"] == first.metadata["reproducibility"]["reproducibility_id"]
    assert not {"overall_verdict", "overall_status", "project_pass", "project_fail"}.intersection(first.to_dict())


def test_previous_run_rejects_stage_record_with_missing_execution_evidence(tmp_path):
    from seclab.pipeline import load_previous_run

    project = tmp_path / "project"
    project.mkdir()
    run_full_verification(project, tmp_path / "workspace", run_id="broken-stage-evidence",
                          stage_ids=("REPORT",))
    run_root = tmp_path / "workspace" / "broken-stage-evidence"
    manifest_path = run_root / "evidence/manifest/run-manifest.json"
    integrity_path = run_root / "evidence/manifest/run-integrity.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["stage_records"][0]["metadata"].pop("execution_evidence_id")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
    integrity["manifest"]["sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    integrity["manifest"]["size_bytes"] = manifest_path.stat().st_size
    integrity_path.write_text(json.dumps(integrity, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no resolvable execution evidence"):
        load_previous_run(tmp_path / "workspace", "broken-stage-evidence")


def test_previous_run_reopens_read_only_and_rejects_corruption(tmp_path, monkeypatch):
    from seclab.pipeline import load_previous_run
    from seclab.specification import load_specification as must_not_load_spec
    import seclab.pipeline.stages as stage_module

    project = tmp_path / "project"
    project.mkdir()
    report = run_full_verification(project, tmp_path / "workspace", run_id="reopen-run",
                                   stage_ids=("REPORT",))
    monkeypatch.setattr(stage_module, "load_specification", must_not_load_spec)
    reopened = load_previous_run(tmp_path / "workspace", "reopen-run")
    assert reopened.to_dict() == report.to_dict()
    report_file = tmp_path / "workspace/reopen-run/evidence/report/pipeline-report.json"
    report_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        load_previous_run(tmp_path / "workspace", "reopen-run")


def test_full_pipeline_specification_model_ctl_traceability(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "schema_version": "1.0", "id": "demo", "name": "Demo", "initial_state": "S0",
        "requirements": [{"id": "R1", "description": "Do not fail"}],
        "states": [{"id": "S0", "labels": ["safe"]}],
        "properties": [{"id": "P1", "logic": "CTL", "formula": "AG(safe)", "requirement_ids": ["R1"]}],
    }), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="ctl-run",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["MODEL"]["status"] == StageStatus.COMPLETED
    assert stages["CTL"]["status"] == StageStatus.COMPLETED
    assert report.traceability["R1"]["checker_refs"] == ["P1"]
    ctl_result = next(result for result in report.results if result.property_id == "P1")
    assert report.traceability["R1"]["results"] == [ctl_result.id]
    assert (tmp_path / "workspace/ctl-run/evidence/report/pipeline-report.json").is_file()


def test_ctl_specification_error_keeps_error_evidence_and_result_trace(tmp_path, monkeypatch):
    from seclab.formal.ctl.errors import CTLError, CTLErrorCode
    from seclab.pipeline import stages as stages_module

    def fail_check(_model, _formula):
        raise CTLError(CTLErrorCode.MODEL_CHECK_ERROR, "injected adapter error")

    monkeypatch.setattr(stages_module.model_checker, "check", fail_check)
    project = tmp_path / "project"
    project.mkdir()
    spec = tmp_path / "unknown-atom.json"
    spec.write_text(json.dumps({
        "schema_version": "1.0", "id": "unknown-atom", "name": "Unknown atom",
        "initial_state": "S0", "states": [{"id": "S0", "labels": ["safe"]}],
        "properties": [{"id": "P-UNKNOWN", "logic": "CTL", "formula": "AG(safe)"}],
    }), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="ctl-error-trace",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False,
                                run_coverage=False, static_analyzers=()))
    result = next(item for item in report.results if item.property_id == "P-UNKNOWN")
    assert result.status.value == "TOOL_ERROR"
    assert result.evidence_ids
    run_root = tmp_path / "workspace" / "ctl-error-trace"
    manifest = json.loads((run_root / "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
    evidence_by_id = {item["id"]: item for item in manifest["evidence"]}
    assert set(result.evidence_ids) <= set(evidence_by_id)
    trace = manifest["metadata"]["result_traceability"][result.id]
    assert trace["run_id"] == report.run_id
    assert trace["checker"] == "CTL"
    assert trace["evidence"][0]["hash"] == evidence_by_id[result.evidence_ids[0]]["hash"]


def test_full_pipeline_integrates_ctl_bmc_smt_compiler_dynamic_and_manifest(tmp_path):
    pytest.importorskip("z3")
    if Toolchain(["gcc", "clang", "g++", "clang++"]).compiler_for("C") is None:
        pytest.skip("No supported C compiler is installed")
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text(
        "int add(int a, int b) { int unused; return a + b; }\n", encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "schema_version": "1.0", "id": "integration", "name": "Pipeline integration",
        "initial_state": "S0",
        "requirements": [{"id": "R1", "description": "addition returns the sum"}],
        "variables": [{"id": "x", "domain": {"type": "integer", "minimum": 0, "maximum": 10}}],
        "constraints": [{"id": "C1", "expression": "x >= 0"}],
        "states": [{"id": "S0", "labels": ["safe"]}, {"id": "S1", "labels": ["error"]}],
        "transitions": [{"id": "T01", "source": "S0", "target": "S1"}],
        "properties": [
            {"id": "P-CTL", "logic": "CTL", "formula": "AG(safe)", "requirement_ids": ["R1"]},
                {"id": "P-CTL-PASS", "logic": "CTL", "formula": "AG(true)"},
            {"id": "P-BMC", "logic": "BMC", "formula": "error", "bound": 0},
            {"id": "P-SMT", "logic": "SMT", "formula": "x <= 10"},
            {"id": "P-SMT-SAT", "logic": "SMT", "formula": "x <= 5"},
        ],
        "functions": [{"id": "F1", "name": "add"}],
        "tests": [
            {"id": "T1", "function_id": "F1", "requirement_ids": ["R1"],
             "input": {"args": {"a": 2, "b": 3}}, "expected": {"return_value": 5}},
            {"id": "T2", "function_id": "F1", "requirement_ids": ["R1"],
             "input": {"args": {"a": 2, "b": 3}}, "expected": {"return_value": 6}},
        ],
    }), encoding="utf-8")
    report = run_full_verification(project, tmp_path / "workspace", run_id="full-run",
        options=PipelineOptions(specification_paths=(spec,), run_memory=False, run_coverage=True,
                                coverage_backend="gcov", static_analyzers=("compiler",),
                                toolchain_tools=("gcc", "gcov", "clang", "z3"),
                                fuzz_config=FuzzConfig(FuzzStrategy.COVERAGE_GUIDED, max_iterations=1,
                                    timeout_per_input=2, random_seed=7, max_input_size=128),
                                    fuzz_seeds=(FuzzInput("seed-add", {"a": 2, "b": 3}, InputKind.SCALARS,
                                    InputOrigin.SEED),)))
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert all(stages[key]["status"] == StageStatus.COMPLETED for key in
               ("CTL", "BMC", "SMT", "STATIC", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK"))
    assert stages["COVERAGE"]["metadata"]["has_report"] is True
    assert {item.technique for item in report.results} >= {"CTL", "BMC", "SMT", "TEST_ORACLE", "COMPILER-DIAGNOSTICS", "COVERAGE_GUIDED"}
    assert any(item.status.value == "FAIL" and item.metadata.get("test_case_id") == "T2" for item in report.results)
    sat_property = next(item for item in report.results if item.property_id == "P-SMT-SAT")
    assert sat_property.status.value == "FAIL"
    ctl_fail = next(item for item in report.results if item.property_id == "P-CTL")
    ctl_pass = next(item for item in report.results if item.property_id == "P-CTL-PASS")
    bmc_incomplete = next(item for item in report.results if item.property_id == "P-BMC")
    assert ctl_fail.status.value == "FAIL" and ctl_pass.status.value == "PASS"
    assert bmc_incomplete.status.value == "INCONCLUSIVE"
    static_result = next(item for item in report.results if item.technique == "COMPILER-DIAGNOSTICS")
    assert static_result.status.value == "INCONCLUSIVE"
    assert static_result.metadata["finding_ids"]
    fuzz_result = next(item for item in report.results if item.stage == "FUZZING")
    assert fuzz_result.status.value == "INCONCLUSIVE"
    source_file = project / "main.c"
    assert hashlib.sha256(source_file.read_bytes()).hexdigest() == report.metadata["source_inventory"]["files"][0]["sha256"]
    assert [path.name for path in project.iterdir()] == ["main.c"]
    assert report.traceability["R1"]["status"] == "CHECKED"
    manifest_path = tmp_path / "workspace/full-run/evidence/manifest/run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    parsed_manifest = RunManifest.from_dict(manifest)
    evidence_ids = {item["id"] for item in manifest["evidence"]}
    assert parsed_manifest.run_id == "full-run"
    assert all(set(item.evidence_ids) <= evidence_ids for item in report.results)
    matrix = report.metadata["cross_check_matrix"]
    checker_names = {item["checker"] for item in matrix["checker_records"]}
    assert {"CTL", "BMC", "SMT", "TEST_ORACLE", "COMPILER-DIAGNOSTICS", "COVERAGE_GUIDED"} <= checker_names
    assert "overall_verdict" not in matrix
    by_property = {item["property_id"]: item for item in matrix["checker_records"] if item["property_id"]}
    assert by_property["P-CTL"]["checker_contract"]["counterexample_validation"] == "VALIDATED"
    assert by_property["P-BMC"]["checker_contract"]["completeness_threshold"] is not None
    assert by_property["P-SMT-SAT"]["checker_contract"]["query_hashes"]
    coverage_record = next(item for item in matrix["measurements"] if item["kind"] == "COVERAGE_MEASUREMENT")
    assert coverage_record["measurement_only"] is True
    fuzz_record = next(item for item in matrix["checker_records"] if item["checker"] == "COVERAGE_GUIDED")
    assert fuzz_record["checker_contract"]["bounded_campaign"] is True
    dynamic_record = next(item for item in matrix["checker_records"] if item["checker"] == "TEST_ORACLE")
    assert dynamic_record["checker_contract"]["executed"] is True
    assert dynamic_record["checker_contract"]["observation"]["return_value_available"] is True
    cross_ref = report.metadata["cross_check_matrix_evidence_id"]
    assert cross_ref in evidence_ids


def test_explicit_cross_check_conflict_is_reported_without_rewriting_checker_results(tmp_path):
    from seclab.testing import TestCase

    pytest.importorskip("z3")
    if Toolchain(["gcc", "clang"]).compiler_for("C") is None:
        pytest.skip("No supported C compiler is installed")
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.c").write_text("int value(void) { return 7; }\n", encoding="utf-8")
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"schema_version": "1.0", "id": "cross-check-demo", "name": "Cross check",
        "states": [{"id": "S0", "initial": True}],
        "properties": [{"id": "P1", "logic": "CTL", "formula": "AG(true)",
                        "metadata": {"cross_check_key": "claim-value-is-7"}}]}), encoding="utf-8")
    case = TestCase("value-test", "wrong explicit oracle", "value", {}, {"return_value": 8},
                    property_id="P1", metadata={"cross_check_key": "claim-value-is-7"})
    report = run_full_verification(project, tmp_path / "workspace", run_id="cross-check-conflict",
        options=PipelineOptions(specification_paths=(spec,), test_cases=(case,), run_memory=False,
            run_coverage=False, static_analyzers=(), toolchain_tools=("gcc", "clang", "z3")))
    matrix = report.metadata["cross_check_matrix"]
    relation = next(item for item in matrix["relations"] if item["id"] == "DYNAMIC_FORMAL")
    assert relation["status"] == "INCONSISTENCY"
    assert "overall_verdict" not in report.metadata["cross_check_matrix"]
    assert next(item for item in report.results if item.property_id == "P1" and item.technique == "CTL").status.value == "PASS"
    assert next(item for item in report.results if item.technique == "TEST_ORACLE").status.value == "FAIL"
    cross_result = next(item for item in report.results if item.technique == "CROSS_CHECK_MATRIX")
    assert cross_result.reason_code == "CROSS_CHECK_INCONSISTENCY"
    assert cross_result.status.value == "INCONCLUSIVE"
