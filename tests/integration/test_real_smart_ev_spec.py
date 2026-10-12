"""Integration contract for the real assignment Smart EV specification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from seclab.pipeline import PipelineOptions, run_full_verification
from seclab.integrations.registry import load_adapted_specification
from seclab.results import VerificationStatus
from seclab.source import SourceLoader
from seclab.specification import load_specification, normalize_specification, validate_specification


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _top_level_exclusions(project: Path) -> tuple[str, ...]:
    return tuple(item.name for item in project.iterdir()
                 if item.is_dir() and item.name not in {"src", ".git"})


def test_real_smart_ev_specification_pipeline_structure(tmp_path: Path) -> None:
    configured_spec = os.environ.get("SECLAB_REAL_SMART_EV_SPEC")
    if not configured_spec:
        pytest.skip("Set SECLAB_REAL_SMART_EV_SPEC to opt into the external Smart-EV integration test.")
    source = Path(configured_spec)
    if not source.is_file():
        pytest.skip("Configured external Smart-EV specification is not available.")

    original_hash = _hash(source)
    original_bytes = source.read_bytes()
    original = json.loads(original_bytes)
    assert isinstance(original, dict)
    assert load_specification(source).documents[0].data == original

    # Record the raw-format incompatibility; the adapter must not conceal it.
    from seclab.specification import SpecificationError
    with pytest.raises(SpecificationError, match="Missing required properties: 'id', 'schema_version'"):
        validate_specification(load_specification(source))

    adapted, adapter_info = load_adapted_specification(source)
    assert adapter_info["adapter"] == "Smart-EV Adapter"
    validate_specification(adapted)
    specification = normalize_specification(adapted)
    assert len(specification.requirements) == 11
    assert len(specification.states) == 28
    assert len(specification.transitions) == 47
    assert sum(prop.logic == "CTL" for prop in specification.properties) == 16
    assert sum(bool(prop.metadata.get("satisfiability_check")) for prop in specification.properties) == 12

    project = source.parent.parent.resolve()
    discovered = SourceLoader(exclude=_top_level_exclusions(project)).load_source_tree(project)
    production_sources = tuple(item for item in discovered
                               if item.relative_path.startswith("src/") and item.extension == ".c")
    assert production_sources

    options = PipelineOptions(
        loaded_specification=adapted,
        source_files=production_sources,
        analysis_timeout=30,
        execution_timeout=2,
        build_timeout=60,
        solver_timeout=5,
        metadata={"workflow": "real-smart-ev-teacher-e2e-v4", "adapter_version": "1",
                  "specification_provenance": adapter_info,
                  "original_specification": str(source.resolve()), "original_sha256": original_hash},
    )
    workspace = tmp_path / "pipeline-workspace"
    report = run_full_verification(project, workspace, options=options, run_id="real-smart-ev-e2e-v4")

    stages = {item["stage_id"]: item for item in report.stage_summaries}
    assert {"SPECIFICATION", "MODEL", "CTL", "BMC", "SOURCE", "STATIC", "MEMORY", "SMT",
            "DYNAMIC", "COVERAGE", "FUZZING", "REPORT"} <= stages.keys()
    assert stages["SPECIFICATION"]["status"] == "COMPLETED"
    assert stages["MODEL"]["metadata"]["state_count"] == 28
    assert stages["MODEL"]["metadata"]["transition_count"] == 47
    assert stages["CTL"]["metadata"]["properties_checked"] == 16
    assert stages["BMC"]["status"] == "SKIPPED"
    assert stages["BMC"]["reason"] == "The specification declares no BMC properties."
    assert stages["SMT"]["metadata"]["properties_checked"] == 12
    assert stages["REPORT"]["status"] == "COMPLETED"

    valid_statuses = {status.value for status in VerificationStatus}
    results_by_id = {result.id: result for result in report.results}
    assert report.results
    for result in report.results:
        assert result.status.value in valid_statuses
        assert result.evidence_ids

    run_root = workspace / report.run_id
    manifest_path = (run_root / report.evidence_manifest["path"]).resolve()
    assert manifest_path.is_relative_to(run_root.resolve())
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    normalized_evidence = json.loads((run_root / "evidence" / "pipeline" / "specification.json").read_text(
        encoding="utf-8"))
    assert normalized_evidence["ORIGINAL_SPECIFICATION"]["sha256"] == original_hash
    assert normalized_evidence["NORMALIZED_SPECIFICATION"]["id"] == specification.id
    evidence_by_id = {item["id"]: item for item in manifest["evidence"]}
    assert set(evidence_by_id)
    for result in report.results:
        assert set(result.evidence_ids) <= evidence_by_id.keys()
    for evidence in evidence_by_id.values():
        artifact_path = (run_root / evidence["path"]).resolve()
        assert artifact_path.is_relative_to(run_root.resolve())
        assert artifact_path.is_file()
        assert _hash(artifact_path) == evidence["hash"]

    result_ids = set(results_by_id)
    for row in report.traceability.values():
        assert set(row.get("results", ())) <= result_ids
        for target in row.get("targets", {}).values():
            assert set(target.get("results", ())) <= result_ids
            assert set(target.get("evidence_ids", ())) <= evidence_by_id.keys()

    integrity = report.metadata["source_integrity"]
    assert integrity
    assert all(not item["changed_during_run"] and item["before_sha256"] == item["after_sha256"]
               for item in integrity)
    assert _hash(source) == original_hash
    assert "overall_verdict" not in report.to_dict()
    assert "overall_status" not in report.to_dict()
