from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from seclab.fuzzing import FuzzConfig, FuzzStrategy
from seclab.pipeline import (FunctionalStage, PipelineOptions, PipelineOrchestrator,
                             StageOutput, StageStatus)
from seclab.workflows.teacher import WorkflowChapter, run_chapter_verification


FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "teacher-workflow"
PROJECT = FIXTURE / "project"
SPECIFICATION = FIXTURE / "specification.json"


def _options(**kwargs) -> PipelineOptions:
    defaults = {"specification_paths": (SPECIFICATION,), "static_analyzers": (),
                "run_memory": False, "run_coverage": False}
    defaults.update(kwargs)
    return PipelineOptions(**defaults)


def _stages(report):
    return {row["stage_id"]: row for row in report.stage_summaries}


def test_ch1_specification_model_ctl_bmc_and_evidence(tmp_path):
    report = run_chapter_verification("CH1", PROJECT, tmp_path / "runs", options=_options(), run_id="ch1")
    stages = _stages(report)
    assert [row["stage_id"] for row in report.stage_summaries if row["selected"]] == [
        "SPECIFICATION", "MODEL", "CTL", "BMC", "CROSS_CHECK", "REPORT"]
    assert all(stages[name]["status"] == StageStatus.COMPLETED for name in ("SPECIFICATION", "MODEL", "CTL", "BMC"))
    assert stages["MODEL"]["output_refs"]
    assert {item.technique for item in report.results} >= {"CTL", "BMC"}
    manifest = json.loads((tmp_path / "runs/ch1/evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
    assert all(item.evidence_ids for item in report.results)
    assert {item["type"] for item in manifest["evidence"]} >= {"SPECIFICATION", "MODEL"}


def test_ch2_source_function_static_memory_lineage_and_hashes(tmp_path):
    report = run_chapter_verification("CH2", PROJECT, tmp_path / "runs", options=_options(), run_id="ch2")
    stages = _stages(report)
    assert stages["SOURCE"]["status"] == StageStatus.COMPLETED
    assert stages["STATIC"]["status"] == StageStatus.SKIPPED
    assert stages["STATIC"]["reason"] == "No static analyzers were configured."
    assert stages["MEMORY"]["status"] == StageStatus.SKIPPED
    assert stages["SOURCE"]["input_refs"] == [str(PROJECT.resolve())]
    lineage = report.metadata["source_inventory"]
    source = lineage["files"][0]
    assert source["artifact_class"] == "PRODUCTION_SOURCE"
    assert source["source_id"].startswith("SRC-")
    assert source["function_ids"] == ["FUNC-ADD"]
    assert source["requirement_ids"] == ["REQ-ADD-01", "REQ-ADD-TEST-01"]
    assert source["sha256"] == source["before_sha256"] == source["after_sha256"]
    assert source["changed_during_run"] is False
    assert source["source_inventory_evidence_id"] in stages["SOURCE"]["output_refs"]
    assert report.metadata["source_integrity"][0]["changed_during_run"] is False
    generated_classes = {item["artifact_class"] for item in lineage["generated_artifacts"]}
    assert "TEST_HARNESS" in generated_classes
    assert not {"TOOL_CAPABILITY_EVIDENCE", "BUG_INJECTED_PROBE", "PROBE_ONLY", "PROBE"} & generated_classes
    assert report.traceability["REQ-ADD-01"]["sources"][0]["source_id"] == source["source_id"]


def test_ch3_smt_query_results_are_evidence_backed(tmp_path):
    report = run_chapter_verification(WorkflowChapter.CH3, PROJECT, tmp_path / "runs",
                                      options=_options(), run_id="ch3")
    stages = _stages(report)
    assert stages["SMT"]["status"] == StageStatus.COMPLETED
    result = next(item for item in report.results if item.technique == "SMT")
    assert result.property_id == "PROP-SMT-NONNEGATIVE"
    assert result.evidence_ids
    assert report.traceability["REQ-ADD-01"]["targets"]["PROP-SMT-NONNEGATIVE"]["stage_id"] == "SMT"
    assert "workflow_chapter" not in report.metadata
    assert report.metadata["workflow"]["workflow_chapter"] == "CH3"


def test_ch4_dynamic_oracle_and_coverage_measurement_are_distinct(tmp_path):
    report = run_chapter_verification("CH4", PROJECT, tmp_path / "runs",
        options=_options(run_coverage=True, coverage_backend="gcov"), run_id="ch4")
    stages = _stages(report)
    assert stages["DYNAMIC"]["status"] == StageStatus.COMPLETED
    assert stages["COVERAGE"]["status"] == StageStatus.COMPLETED
    dynamic = next(item for item in report.results if item.stage == "DYNAMIC_TEST")
    assert dynamic.status.value == "PASS"
    assert stages["COVERAGE"]["metadata"]["measurement_only"] is True
    assert stages["COVERAGE"]["metadata"]["has_report"] is True
    assert report.traceability["REQ-ADD-TEST-01"]["targets"]["TEST-ADD-2-3"]["results"] == [dynamic.id]
    assert stages["COVERAGE"]["output_refs"]


def test_ch5_blackbox_fuzzing_does_not_require_coverage_success(tmp_path):
    fuzz = FuzzConfig(FuzzStrategy.BLACKBOX, max_iterations=1, timeout_per_input=2,
                      random_seed=7, max_input_size=64)
    report = run_chapter_verification("CH5", PROJECT, tmp_path / "runs",
                                      options=_options(fuzz_config=fuzz, run_coverage=True), run_id="ch5")
    stages = _stages(report)
    assert stages["DYNAMIC"]["status"] == StageStatus.COMPLETED
    assert stages["COVERAGE"]["status"] == StageStatus.SKIPPED
    assert stages["COVERAGE"]["reason"] == "Stage was not selected for this run."
    assert stages["FUZZING"]["status"] == StageStatus.COMPLETED
    assert stages["FUZZING"]["output_refs"]


def test_ch6_full_order_traceability_integrity_and_no_overall_verdict(tmp_path):
    fuzz = FuzzConfig(FuzzStrategy.BLACKBOX, max_iterations=1, timeout_per_input=2,
                      random_seed=7, max_input_size=64)
    report = run_chapter_verification("CH6", PROJECT, tmp_path / "runs",
        options=_options(run_coverage=True, coverage_backend="gcov", fuzz_config=fuzz), run_id="ch6")
    stages = _stages(report)
    executed = [row["stage_id"] for row in report.stage_summaries if row["selected"]]
    assert executed == ["SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN", "BUILD",
                        "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT"]
    for row in report.stage_summaries:
        if row["status"] != "NOT_STARTED":
            assert "input_refs" in row and "output_refs" in row
            assert "start_time" in row and "end_time" in row
    assert stages["MEMORY"]["status"] == StageStatus.SKIPPED
    assert all(item["changed_during_run"] is False for item in report.metadata["source_integrity"])
    trace = report.traceability["REQ-ADD-TEST-01"]
    assert "TEST-ADD-2-3" in trace["checker_refs"]
    assert trace["targets"]["TEST-ADD-2-3"]["results"]
    assert trace["targets"]["TEST-ADD-2-3"]["evidence_ids"]
    source = report.metadata["source_inventory"]["files"][0]
    dynamic_lineage = next(item for item in source["analysis_results"] if item["stage_id"] == "DYNAMIC")
    assert dynamic_lineage["result_id"] == trace["targets"]["TEST-ADD-2-3"]["results"][0]
    assert dynamic_lineage["scope"] == "FUNCTION"
    assert report.metadata["workflow"]["workflow_chapter"] == "CH6"
    payload = report.to_dict()
    assert not ({"overall_pass", "overall_fail", "overall_status", "project_verdict"} & payload.keys())
    for item in report.results:
        for evidence_id in item.evidence_ids:
            assert evidence_id
    run_root = (tmp_path / "runs/ch6").resolve()
    for path in run_root.rglob("*"):
        assert path.resolve().is_relative_to(run_root)
    manifest = json.loads((run_root / "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
    evidence_by_id = {item["id"]: item for item in manifest["evidence"]}
    for result in report.results:
        for evidence_id in result.evidence_ids:
            ref = evidence_by_id[evidence_id]
            artifact = (run_root / ref["path"]).resolve(strict=True)
            assert artifact.is_relative_to(run_root)
            assert hashlib.sha256(artifact.read_bytes()).hexdigest() == ref["hash"]
    stage_records = {item["stage_id"]: item for item in manifest["metadata"]["stage_records"]}
    assert stage_records["REPORT"]["output_refs"] == [
        "path:evidence/manifest/run-manifest.json", "path:evidence/report/pipeline-report.json"]


def test_stage_failure_skip_and_unrelated_continuation_are_explicit(tmp_path):
    def fail(_context):
        raise RuntimeError("deliberate stage adapter failure")

    stages = (
        FunctionalStage("SPECIFICATION", "Spec", fail),
        FunctionalStage("MODEL", "Dependent model", lambda _context: StageOutput(value={"should": "not run"}),
                        ("SPECIFICATION",)),
        FunctionalStage("SOURCE", "Independent source", lambda _context: StageOutput(value={"ok": True})),
    )
    report = PipelineOrchestrator(stages, options=_options()).run(PROJECT, tmp_path / "runs", run_id="isolated")
    by_id = _stages(report)
    assert by_id["SPECIFICATION"]["status"] == StageStatus.FAILED
    assert by_id["MODEL"]["status"] == StageStatus.SKIPPED
    assert by_id["MODEL"]["reason"]
    assert by_id["SOURCE"]["status"] == StageStatus.COMPLETED
    assert by_id["SPECIFICATION"]["output_refs"]
    assert "overall_status" not in report.to_dict()


def test_unknown_chapter_is_rejected_without_fabricating_run(tmp_path):
    with pytest.raises(ValueError, match="Unknown workflow chapter"):
        run_chapter_verification("CH7", PROJECT, tmp_path / "runs", options=_options())
    assert not (tmp_path / "runs").exists()


def test_coverage_stage_failure_does_not_block_blackbox_fuzzing(monkeypatch, tmp_path):
    from seclab.coverage import CoverageRunner

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("coverage adapter unavailable")

    monkeypatch.setattr(CoverageRunner, "run", unavailable)
    fuzz = FuzzConfig(FuzzStrategy.COVERAGE_GUIDED, max_iterations=1, timeout_per_input=2,
                      random_seed=7, max_input_size=64, fallback_to_blackbox=True)
    report = run_chapter_verification("CH6", PROJECT, tmp_path / "runs",
        options=_options(run_coverage=True, fuzz_config=fuzz), run_id="optional-failure")
    stages = _stages(report)
    assert stages["COVERAGE"]["status"] == StageStatus.FAILED
    assert stages["FUZZING"]["status"] == StageStatus.COMPLETED
    fuzz_result = next(item for item in report.results if item.stage == "FUZZING")
    assert fuzz_result.metadata["effective_strategy"] == "BLACKBOX"
    assert fuzz_result.metadata["coverage_fallback_used"] is True
