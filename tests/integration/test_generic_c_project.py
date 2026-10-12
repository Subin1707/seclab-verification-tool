from __future__ import annotations

import json
import hashlib
from pathlib import Path

from seclab.pipeline import PipelineOptions, run_full_verification


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples" / "generic-c-project"


def test_generic_c_project_runs_without_external_system(tmp_path: Path) -> None:
    workspace = tmp_path / "evidence"
    report = run_full_verification(
        FIXTURE,
        workspace,
        options=PipelineOptions(
            specification_paths=(FIXTURE / "specification.json",),
            static_analyzers=(),
            run_memory=False,
            run_coverage=False,
            execution_timeout=3,
            build_timeout=15,
        ),
        run_id="generic-c-independent",
    )

    statuses = {item["stage_id"]: item["status"] for item in report.stage_summaries}
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert statuses["SPECIFICATION"] == "COMPLETED"
    assert statuses["MODEL"] == "COMPLETED"
    assert statuses["CTL"] == "COMPLETED"
    assert statuses["SMT"] == "COMPLETED"
    assert statuses["DYNAMIC"] == "COMPLETED"
    assert statuses["SOURCE"] == "COMPLETED"
    assert statuses["STATIC"] == "SKIPPED"
    assert stages["STATIC"]["reason"] == "No static analyzers were configured."
    assert statuses["BMC"] == "SKIPPED"
    assert stages["BMC"]["reason"] == "The specification declares no BMC properties."
    assert statuses["MEMORY"] == "SKIPPED"
    assert stages["MEMORY"]["reason"] == "Memory analysis was disabled."
    assert statuses["COVERAGE"] == "SKIPPED"
    assert stages["COVERAGE"]["reason"] == "Coverage measurement was disabled."
    assert statuses["FUZZING"] == "SKIPPED"
    assert stages["FUZZING"]["reason"] == "No fuzz configuration was provided."
    assert statuses["REPORT"] == "COMPLETED"
    assert report.specification_info["id"] == "generic-counter-project"
    assert any(item["project_relative_path"] == "src/counter.c"
               for item in report.metadata["source_inventory"]["files"])
    assert any(result.technique in {"CTL", "SMT"} for result in report.results)

    manifest_path = workspace / report.run_id / report.evidence_manifest["path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_root = workspace / report.run_id
    evidence_by_id = {item["id"]: item for item in manifest["evidence"]}
    evidence_ids = set(evidence_by_id)
    assert evidence_ids
    assert manifest["project"]["path"] == str(FIXTURE.resolve())
    assert str((FIXTURE / "specification.json").resolve()) in manifest["input_artifacts"]
    assert all((run_root / item["path"]).is_file()
               and hashlib.sha256((run_root / item["path"]).read_bytes()).hexdigest() == item["hash"]
               for item in evidence_by_id.values())
    assert all(set(result.evidence_ids) <= evidence_ids for result in report.results)
    assert all(set(stage["evidence_ids"]) <= evidence_ids
               for stage in report.stage_summaries if stage["stage_id"] != "REPORT")
    dynamic_evidence = set(stages["DYNAMIC"]["evidence_ids"])
    dynamic_results = {result.id for result in report.results if result.stage == "DYNAMIC_TEST"}
    assert dynamic_results


def test_codegen_stage_records_generated_artifacts_and_scoped_status(tmp_path: Path) -> None:
    workspace = tmp_path / "codegen-evidence"
    report = run_full_verification(FIXTURE, workspace,
        options=PipelineOptions(specification_paths=(FIXTURE / "specification.json",),
            static_analyzers=(), run_memory=False, run_coverage=False,
            generate_c_model=True, execution_timeout=3, build_timeout=15),
        run_id="generic-codegen")
    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["CODEGEN"]["status"] in {"COMPLETED", "FAILED"}
    assert "compiler_runs" not in stages["CODEGEN"]["metadata"]
    runs = stages["BUILD"]["metadata"]["compiler_runs"]
    assert runs
    assert all("status" in row and "exit_code" in row and "stdout" in row and "stderr" in row for row in runs)
    artifacts = report.metadata["artifact_classes"]
    assert artifacts["GENERATED_ARTIFACT"]
    assert artifacts["PRODUCTION_SOURCE"]
    assert sum(report.status_counts.values()) == len(report.results)
    assert "overall_verdict" not in report.to_dict()
    assert "overall_status" not in report.to_dict()
    assert any(result.requirement_id == "REQ-COUNTER-INCREMENT"
               and result.stage == "DYNAMIC_TEST" and result.status.value == "PASS"
               for result in report.results)


def test_generic_memory_project_runs_without_optional_integrations(tmp_path: Path) -> None:
    fixture = ROOT / "examples" / "generic-c-memory-project"
    report = run_full_verification(
        fixture,
        tmp_path / "memory-evidence",
        options=PipelineOptions(
            specification_paths=(fixture / "specification.json",),
            static_analyzers=(),
            run_coverage=False,
            execution_timeout=3,
            build_timeout=15,
        ),
        stage_ids=("DYNAMIC", "MEMORY"),
        run_id="generic-memory-independent",
    )
    statuses = {item["stage_id"]: item["status"] for item in report.stage_summaries}
    assert statuses["SPECIFICATION"] == "COMPLETED"
    assert statuses["SOURCE"] == "COMPLETED"
    assert statuses["DYNAMIC"] == "COMPLETED"
    assert statuses["MEMORY"] == "COMPLETED"
    assert report.traceability["REQ-SEQUENCE-SUM"]["results"]
    assert any(result.requirement_id == "REQ-SEQUENCE-SUM"
               and result.stage == "DYNAMIC_TEST" and result.status.value == "PASS"
               for result in report.results)
