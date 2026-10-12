"""Generic pipeline validation across independent project shapes.

All rows use the same loader/validator/normalizer sequence and the same
``run_full_verification`` API. Project differences are fixture data only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from seclab.cli import _load_config
from seclab.pipeline import PipelineOptions, run_full_verification
from seclab.specification import load_specification, normalize_specification, validate_specification


ROOT = Path(__file__).resolve().parents[2]
PROJECT_SHAPES = (
    pytest.param("generic-c-project", 2, 1, 2, 2, id="simple-c"),
    pytest.param("generic-c-memory-project", 2, 1, 1, 0, id="memory-safety-c"),
    pytest.param("generic-multifile-cpp-project", 2, 3, 3, 1, id="multi-file-cpp"),
    pytest.param("generic-dynamic-project", 1, 2, 1, 0, id="multiple-functions"),
    pytest.param("generic-full-pipeline-project", 1, 1, 3, 3, id="multiple-requirements-properties"),
)


@pytest.mark.parametrize("project_name,min_sources,min_functions,min_requirements,min_properties", PROJECT_SHAPES)
def test_one_generic_pipeline_handles_independent_project_shapes(
    tmp_path: Path, project_name: str, min_sources: int, min_functions: int,
    min_requirements: int, min_properties: int,
) -> None:
    project = ROOT / "examples" / project_name
    specification_path = project / "specification.json"

    loaded = load_specification(specification_path)
    validate_specification(loaded)
    specification = normalize_specification(loaded)
    assert specification.id
    assert len(specification.requirements) >= min_requirements
    assert len(specification.functions) >= min_functions
    assert len(specification.properties) >= min_properties

    config = _load_config(project / "pipeline-config.json")
    config["specification_paths"] = (specification_path,)
    config["static_analyzers"] = ("compiler",)
    config["analysis_timeout"] = 15.0
    config["build_timeout"] = 15.0
    options = PipelineOptions(**config)
    workspace = tmp_path / "runs"
    report = run_full_verification(project, workspace, options=options, run_id=project_name)

    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert stages["SPECIFICATION"]["status"] == "COMPLETED"
    assert stages["SOURCE"]["status"] == "COMPLETED"
    assert stages["REPORT"]["status"] == "COMPLETED"
    assert all(item["status"] in {"COMPLETED", "SKIPPED", "FAILED"} for item in stages.values())
    assert all(item["reason"] for item in stages.values() if item["status"] == "SKIPPED")

    run_root = workspace / report.run_id
    manifest_path = run_root / report.evidence_manifest["path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    evidence = {item["id"]: item for item in manifest["evidence"]}
    source_files = report.metadata["source_inventory"]["files"]
    assert len(source_files) >= min_sources
    assert evidence
    assert all(
        (run_root / item["path"]).is_file()
        and hashlib.sha256((run_root / item["path"]).read_bytes()).hexdigest() == item["hash"]
        for item in evidence.values()
    )

    result_ids = {item.id for item in report.results}
    assert all(set(item.evidence_ids) <= evidence.keys() for item in report.results)
    for requirement in report.traceability.values():
        assert set(requirement["results"]) <= result_ids
        assert set(requirement["evidence_ids"]) <= evidence.keys()
        for target in requirement["targets"].values():
            assert set(target["results"]) <= result_ids
            assert set(target["evidence_ids"]) <= evidence.keys()

    source_integrity = report.metadata["source_integrity"]
    assert source_integrity
    assert all(item["before_sha256"] == item["after_sha256"]
               and item["changed_during_run"] is False for item in source_integrity)
    result_statuses = {item.status.value for item in report.results}
    assert result_statuses <= {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "TOOL_ERROR",
                              "SPEC_ERROR", "BUILD_ERROR"}
    assert sum(report.status_counts.values()) == len(report.results)
    serialized = report.to_dict()
    assert "overall_verdict" not in serialized and "overall_status" not in serialized
    assert manifest["project"]["path"] == str(project.resolve())

