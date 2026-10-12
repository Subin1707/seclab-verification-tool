from __future__ import annotations

import json
from pathlib import Path

from seclab.pipeline import PipelineOptions, TraceabilityIndex, run_full_verification


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples" / "generic-c-project"


def test_pipeline_traceability_query_uses_recorded_ids_and_links(tmp_path: Path) -> None:
    workspace = tmp_path / "runs"
    report = run_full_verification(FIXTURE, workspace, run_id="trace-run", options=PipelineOptions(
        specification_paths=(FIXTURE / "specification.json",), static_analyzers=(), run_memory=False,
        run_coverage=False, execution_timeout=3, build_timeout=15))
    manifest_path = workspace / "trace-run" / "evidence/manifest/run-manifest.json"
    import json
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    index = TraceabilityIndex(report, run_root=workspace / "trace-run", manifest=manifest)
    assert index.requirement("REQ-COUNTER-NONNEGATIVE")["status"] == "RESOLVED"
    requirement = index.requirement("REQ-COUNTER-INCREMENT")
    assert requirement["status"] == "RESOLVED"
    assert requirement["results"]
    assert all(item["status"] == "RESOLVED" for item in requirement["results"])
    assert all(item["status"] == "RESOLVED" for item in requirement["evidence"])
    model_state = index.model_state("READY")
    assert model_state["status"] == "RESOLVED"
    assert model_state["results"]
    assert index.specification_property("PROP-COUNTER-NONNEGATIVE")["declared"]
    assert index.specification_property("unknown-property")["status"] == "UNRESOLVED"
    assert report.metadata["traceability_integrity"]["valid"]
    for test_id in (row.get("target_id") for trace in report.traceability.values()
                    for row in trace.get("targets", {}).values() if row.get("target_kind") == "TEST_CASE"):
        if test_id:
            case = index.test_case(test_id)
            if case["execution_ids"]:
                execution = index.execution(case["execution_ids"][0])
                assert execution["status"] == "RESOLVED"
                assert execution["result"]["status"] == "RESOLVED"
                assert execution["result"]["evidence"]
                assert all(ref["status"] == "RESOLVED" for ref in execution["result"]["evidence"])
                if execution.get("observation_evidence"):
                    assert execution["observation_evidence"]["status"] == "RESOLVED"
                    observation = index.observation(execution["record"]["observation_evidence_id"])
                    assert observation["status"] == "RESOLVED"


def test_codegen_traceability_exposes_generated_artifact_hashes(tmp_path: Path) -> None:
    workspace = tmp_path / "trace-codegen"
    report = run_full_verification(FIXTURE, workspace, run_id="trace-codegen", options=PipelineOptions(
        specification_paths=(FIXTURE / "specification.json",), static_analyzers=(), run_memory=False,
        run_coverage=False, generate_c_model=True, execution_timeout=3, build_timeout=15))
    manifest = json.loads((workspace / "trace-codegen" / "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
    index = TraceabilityIndex(report, run_root=workspace / "trace-codegen", manifest=manifest)
    generated = [row for row in manifest["evidence"] if row.get("metadata", {}).get("artifact_class") == "GENERATED_ARTIFACT"]
    assert generated
    assert all(index.evidence_link(row["id"])["status"] == "RESOLVED" for row in generated)
    assert all(len(row["hash"]) == 64 for row in generated)
