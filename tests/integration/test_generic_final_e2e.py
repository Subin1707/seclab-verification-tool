from __future__ import annotations

import hashlib
import json
from pathlib import Path

from seclab.cli import main
from seclab.pipeline import TraceabilityIndex


ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "examples" / "generic-final-e2e"
STAGES = {"SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN", "BUILD", "STATIC",
          "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT"}


def test_generic_project_runs_full_cli_pipeline_with_integrity_and_traceability(tmp_path, capsys):
    workspace = tmp_path / "runs"
    run_id = "generic-final-e2e"
    exit_code = main(["verify", "--project", str(PROJECT), "--spec",
        str(PROJECT / "specification.json"), "--config", str(PROJECT / "pipeline-config.json"),
        "--workspace", str(workspace), "--run-id", run_id])
    assert exit_code == 0
    assert f"Run {run_id}:" in capsys.readouterr().out

    run_root = workspace / run_id
    report = json.loads((run_root / "evidence" / "report" / "pipeline-report.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_root / "evidence" / "manifest" / "run-manifest.json").read_text(encoding="utf-8"))
    summaries = {row["stage_id"]: row for row in report["stage_summaries"]}
    assert set(summaries) >= STAGES
    assert all(row.get("status") for row in summaries.values())

    assert report["results"]
    assert all(result["evidence_ids"] for result in report["results"])
    for item in manifest["evidence"]:
        artifact = (run_root / item["path"]).resolve(strict=True)
        assert artifact.is_relative_to(run_root.resolve())
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == item["hash"]
        assert len(item["hash"]) == 64

    assert all(not row["changed_during_run"] and row["before_sha256"] == row["after_sha256"]
               for row in report["metadata"]["source_integrity"])
    generated = [item for item in manifest["evidence"]
                 if item.get("metadata", {}).get("artifact_role") == "GENERATED_ARTIFACT"]
    assert generated
    generated_scoped_results = [item for item in report["results"]
        if item.get("metadata", {}).get("artifact_scope") == "GENERATED_ARTIFACT"]
    assert any(item.get("stage") == "STATIC_ANALYSIS" for item in generated_scoped_results)
    assert any(item.get("stage") == "MEMORY_ANALYSIS" for item in generated_scoped_results)
    assert summaries["STATIC"]["metadata"]["generated_model_files"]
    assert summaries["MEMORY"]["metadata"]["generated_model_files"]
    source_map_ref = next(item for item in manifest["evidence"] if item["path"].endswith("source-map.json"))
    source_map = json.loads((run_root / source_map_ref["path"]).read_text(encoding="utf-8"))
    assert source_map

    fuzz_campaigns = [item for item in manifest["evidence"]
                      if item["path"].startswith("evidence/fuzz-campaigns/") and item["path"].endswith("-manifest.json")]
    assert fuzz_campaigns
    observations = [item for item in manifest["evidence"]
                    if item["path"].startswith("evidence/observations/")]
    assert observations
    observed = next(json.loads((run_root / item["path"]).read_text(encoding="utf-8"))
                    for item in observations
                    if "exit_code" in json.loads((run_root / item["path"]).read_text(encoding="utf-8")))
    assert "exit_code" in observed and "stdout" in observed and "crashed" in observed

    specification_model = json.loads((run_root / "evidence" / "model" / "kripke.json").read_text(encoding="utf-8"))
    assert specification_model["model_hash"] == summaries["MODEL"]["metadata"]["model_hash"]
    assert {item["id"] for item in specification_model["states"]} == {"READY", "PROCESSING", "DONE", "FAULT"}
    assert not (run_root / "evidence" / "model" / "source-model-provenance.json").exists()

    traceability = TraceabilityIndex(report, run_root=run_root, manifest=manifest)
    function_trace = traceability.source_function("FUNC-MODEL-STEP")
    assert function_trace["status"] == "RESOLVED"
    assert function_trace["mapping_status"] == "UNRESOLVED"
    assert not function_trace["state_ids"] and not function_trace["transition_ids"]
    assert traceability.test_case("TEST-EXEC-THREE")["execution_ids"]
    assert report["metadata"]["traceability_integrity"]["valid"]

    assert not {"overall_verdict", "overall_status", "overall_safety_verdict"} & report.keys()
    assert "single_project_load" in report["metadata"]["workflow"]
    assert "single_specification_load" in report["metadata"]["workflow"]
