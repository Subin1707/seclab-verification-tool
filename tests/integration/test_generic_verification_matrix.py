from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from seclab.cli import _load_config
from seclab.pipeline import PipelineOptions, run_full_verification


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = (
    "generic-c-project",
    "generic-c-memory-project",
    "generic-cpp-project",
    "generic-state-machine-project",
    "generic-smt-project",
    "generic-bmc-project",
    "generic-dynamic-project",
    "generic-coverage-project",
    "generic-fuzz-project",
    "generic-full-pipeline-project",
)


@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_generic_fixture_pipeline_integrity(tmp_path: Path, fixture_name: str) -> None:
    fixture = ROOT / "examples" / fixture_name
    config = _load_config(fixture / "pipeline-config.json")
    config["specification_paths"] = (fixture / "specification.json",)
    config["build_timeout"] = 15.0
    config["analysis_timeout"] = 15.0
    options = PipelineOptions(**config)

    report = run_full_verification(fixture, tmp_path / "runs", options=options, run_id=fixture_name)
    report_data = report.to_dict()
    run_root = tmp_path / "runs" / fixture_name
    manifest_path = run_root / report.evidence_manifest["path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_path = run_root / "evidence" / "report" / "pipeline-report.json"
    persisted_report = json.loads(report_path.read_text(encoding="utf-8"))
    stages = {stage["stage_id"]: stage for stage in report.stage_summaries}
    evidence = {item["id"]: item for item in manifest["evidence"]}
    results = {item.id: item for item in report.results}

    assert len(results) == len(report.results)
    assert report.evidence_manifest["evidence_count"] > 0
    assert not {"overall_verdict", "overall_status"} & _all_keys(report_data)
    assert not {"overall_verdict", "overall_status"} & _all_keys(persisted_report)
    assert set(stages) == {"SPECIFICATION", "MODEL", "CTL", "BMC", "SOURCE", "CODEGEN", "BUILD",
                           "STATIC", "MEMORY", "SMT", "DYNAMIC", "COVERAGE", "FUZZING",
                           "CROSS_CHECK", "REPORT"}
    assert all(stage["reason"] for stage in stages.values() if stage["status"] == "SKIPPED")
    assert all(result.status.value in {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "TOOL_ERROR",
                                       "SPEC_ERROR", "BUILD_ERROR"} for result in report.results)
    assert sum(report.status_counts.values()) == len(report.results)

    assert manifest["project"]["path"] == str(fixture.resolve())
    assert str((fixture / "specification.json").resolve()) in manifest["input_artifacts"]
    assert evidence
    spec_stage = stages["SPECIFICATION"]
    assert spec_stage["metadata"]["validation_result"] == "VALID"
    assert spec_stage["metadata"]["validation_diagnostics"] == []
    assert spec_stage["metadata"]["input_hashes"][0]["sha256"] == hashlib.sha256(
        (fixture / "specification.json").read_bytes()).hexdigest()
    validation_artifact = next((run_root / item["path"] for item in evidence.values()
                                if item["path"].endswith("specification-validation.json")), None)
    normalized_artifact = next((run_root / item["path"] for item in evidence.values()
                                if item["path"].endswith("pipeline/specification.json")), None)
    assert validation_artifact is not None and normalized_artifact is not None
    validation_payload = json.loads(validation_artifact.read_text(encoding="utf-8"))
    normalized_payload = json.loads(normalized_artifact.read_text(encoding="utf-8"))
    assert validation_payload["result"] == "VALID"
    assert validation_payload["diagnostics"] == []
    assert validation_payload["normalized_sha256"] == spec_stage["metadata"]["normalized_sha256"]
    assert normalized_payload["normalized_sha256"] == validation_payload["normalized_sha256"]
    assert all((run_root / item["path"]).is_file()
               and hashlib.sha256((run_root / item["path"]).read_bytes()).hexdigest() == item["hash"]
               for item in evidence.values())
    assert all(set(result.evidence_ids) <= evidence.keys() for result in report.results)
    for result in report.results:
        if result.technique not in {"CTL", "BMC", "SMT"}:
            continue
        formal = result.metadata["formal_run"]
        assert formal["run_id"] == report.run_id
        assert formal["checker"] == result.technique
        assert formal["property_id"] == result.property_id
        assert formal["observed_status"] == result.status.value
        assert formal["reason_code"] == result.reason_code
        assert formal["inputs"]
        assert formal["artifact_references"]
        assert list(formal["evidence_ids"]) == list(result.evidence_ids)
        assert formal["timing_ms"] is not None
        if result.metadata.get("backend") or result.technique == "CTL":
            assert formal["tool_version"]
    for stage in stages.values():
        assert set(stage["evidence_ids"]) <= evidence.keys()
        assert set(stage["result_ids"]) <= results.keys()
    assert all(ref.startswith("path:") or ref in evidence
               for stage in stages.values() for ref in stage["output_refs"])

    assert report.metadata["source_inventory"]["files"]
    integrity = report.metadata["source_integrity"]
    assert integrity
    assert all(item["before_sha256"] == item["after_sha256"] and not item["changed_during_run"]
               for item in integrity)
    assert all(item["source_id"].startswith("SRC-") and item["path"] for item in integrity)
    assert all(result_id in results for row in report.traceability.values()
               for result_id in row["results"])
    assert all(evidence_id in evidence for row in report.traceability.values()
               for evidence_id in row["evidence_ids"])
    for row in report.traceability.values():
        for target in row["targets"].values():
            assert set(target["results"]) <= results.keys()
            assert set(target["evidence_ids"]) <= evidence.keys()

    assert persisted_report["run_id"] == report.run_id
    assert "overall_verdict" not in manifest
    assert "overall_status" not in manifest

    if fixture_name == "generic-c-project":
        assert stages["CTL"]["status"] == "COMPLETED"
        assert stages["SMT"]["status"] == "COMPLETED"
        assert not any(item.stage == "SMT" for item in report.results)
        assert stages["BMC"]["status"] == "SKIPPED"
        assert stages["STATIC"]["status"] == "SKIPPED"
        assert stages["MEMORY"]["status"] == "SKIPPED"
        assert stages["COVERAGE"]["status"] == "SKIPPED"
        assert stages["FUZZING"]["status"] == "SKIPPED"
        assert any(item.stage == "DYNAMIC_TEST" and item.status.value == "PASS" for item in report.results)
    elif fixture_name == "generic-c-memory-project":
        assert stages["MEMORY"]["status"] == "COMPLETED"
        assert any(item.stage == "DYNAMIC_TEST" and item.status.value == "PASS" for item in report.results)
    elif fixture_name == "generic-cpp-project":
        assert stages["SOURCE"]["metadata"]["language"].upper() == "C++"
        assert any(item.stage == "DYNAMIC_TEST" and item.status.value == "PASS" for item in report.results)
    elif fixture_name == "generic-state-machine-project":
        assert stages["MODEL"]["metadata"]["state_count"] == 3
        assert len(stages["MODEL"]["metadata"]["model_hash"]) == 64
        model_artifact = next((run_root / item["path"] for item in evidence.values()
                               if item["path"].endswith("kripke.json")), None)
        assert model_artifact is not None
        model_payload = json.loads(model_artifact.read_text(encoding="utf-8"))
        assert model_payload["model_hash"] == stages["MODEL"]["metadata"]["model_hash"]
        assert model_payload["traceability"]["state_ids"] == stages["MODEL"]["metadata"]["state_ids"]
        assert stages["CTL"]["status"] == "COMPLETED"
        assert {item.status.value for item in report.results if item.technique == "CTL"} <= {"PASS", "FAIL"}
        assert all(item.evidence_ids for item in report.results if item.technique == "CTL")
    elif fixture_name == "generic-smt-project":
        by_property = {item.property_id: item for item in report.results if item.technique == "SMT"}
        assert by_property["PROP-RANGE"].status.value == "PASS"
        assert by_property["PROP-BOUND"].status.value == "FAIL"
        assert by_property["PROP-BOOLEAN"].status.value == "PASS"
        assert all(by_property[key].evidence_ids for key in by_property)
    elif fixture_name == "generic-bmc-project":
        by_property = {item.property_id: item for item in report.results if item.technique == "BMC"}
        assert by_property["PROP-TERMINAL-SHALLOW"].status.value == "INCONCLUSIVE"
        assert by_property["PROP-TERMINAL-BOUND"].status.value == "FAIL"
        assert by_property["PROP-TERMINAL-BOUND"].counterexample
        assert by_property["PROP-ALARM-COMPLETE"].status.value == "FAIL"
        assert by_property["PROP-ALARM-COMPLETE"].metadata.get("checked_bound") == 2
    elif fixture_name == "generic-dynamic-project":
        by_case = {item.metadata.get("test_case_id"): item for item in report.results
                   if item.stage == "DYNAMIC_TEST"}
        assert by_case["TEST-ORACLE-PASS"].status.value == "PASS"
        assert by_case["TEST-ORACLE-FAIL"].status.value == "FAIL"
        assert by_case["TEST-TIMEOUT"].status.value == "INCONCLUSIVE"
        assert by_case["TEST-BUILD-FAIL"].status.value == "BUILD_ERROR"
    elif fixture_name == "generic-coverage-project":
        assert any(item.stage == "DYNAMIC_TEST" and item.status.value == "FAIL" for item in report.results)
        coverage_artifacts = [item for item in evidence.values() if item["stage"].startswith("coverage")]
        assert coverage_artifacts
        payloads = [json.loads((run_root / item["path"]).read_text(encoding="utf-8"))
                    for item in coverage_artifacts if item["path"].endswith(".json")]
        config = next(item for item in payloads if "instrumentation_flags" in item)
        assert config["source_files"] == ["src/branching.c"]
        coverage = next((item for item in payloads if "line_metrics" in item), None)
        if coverage is not None:
            assert coverage["source_files"]
            sut_paths = {"src/branching.c"}
            assert set(coverage["source_files"]) == sut_paths
            measured_line_paths = {item["file"] for item in coverage["line_metrics"]["files"]}
            measured_branch_paths = {item["file"] for item in coverage["branch_metrics"]["files"]}
            assert measured_line_paths <= sut_paths
            assert measured_branch_paths <= sut_paths
            harness_paths = set(coverage.get("generated_harness_files", []))
            assert harness_paths.isdisjoint(measured_line_paths | measured_branch_paths)
        else:
            assert coverage is None or not coverage.get("complete")
            assert any(item.status.value in {"BUILD_ERROR", "TOOL_ERROR", "INCONCLUSIVE"}
                       for item in report.results if item.stage == "COVERAGE")
    elif fixture_name == "generic-fuzz-project":
        fuzz_stage = stages["FUZZING"]
        if fuzz_stage["status"] == "COMPLETED":
            fuzz_results = [item for item in report.results if item.stage == "FUZZING"]
            assert fuzz_results
            assert all("REQ-NO-ABNORMAL-EXIT" in report.traceability for _ in fuzz_results)
            assert any(item["stage"].startswith("fuzz") for item in evidence.values())
            if fuzz_stage["metadata"]["executed_count"] == 0:
                assert any(item.status.value in {"TOOL_ERROR", "INCONCLUSIVE"} for item in fuzz_results)
                assert fuzz_stage["metadata"]["stop_reason"] == "COVERAGE_FEEDBACK_UNAVAILABLE"
        else:
            assert fuzz_stage["reason"]
    elif fixture_name == "generic-full-pipeline-project":
        assert stages["SPECIFICATION"]["status"] == "COMPLETED"
        assert stages["MODEL"]["status"] == "COMPLETED"
        assert stages["SOURCE"]["status"] == "COMPLETED"
        assert any(item.technique == "CTL" for item in report.results)
        assert any(item.technique == "BMC" for item in report.results)
        assert any(item.technique == "SMT" for item in report.results)
        assert any(item.stage == "DYNAMIC_TEST" for item in report.results)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for item in value.values():
            result |= _all_keys(item)
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result |= _all_keys(item)
        return result
    return set()
