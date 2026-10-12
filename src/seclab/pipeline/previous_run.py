"""Read-only reopening and integrity validation for persisted verification runs."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from seclab.evidence import RunManifest

from .report import PipelineReport


def load_previous_run(workspace: str | Path, run_id: str) -> PipelineReport:
    """Load a completed report without invoking any verification stage."""
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", run_id) or run_id in {".", ".."}:
        raise ValueError("run_id must be a safe 1-100 character path component")
    root = Path(workspace).expanduser().resolve(strict=True)
    run_root = (root / run_id).resolve(strict=True)
    if not run_root.is_relative_to(root) or not run_root.is_dir():
        raise ValueError("Run directory escapes the selected workspace or is not a directory")
    manifest_path = run_root / "evidence" / "manifest" / "run-manifest.json"
    report_path = run_root / "evidence" / "report" / "pipeline-report.json"
    integrity_path = run_root / "evidence" / "manifest" / "run-integrity.json"
    manifest_data = _read_confined_json(manifest_path, run_root)
    integrity = _read_confined_json(integrity_path, run_root)
    manifest = RunManifest.from_dict(manifest_data)
    if manifest.run_id != run_id or integrity.get("run_id") != run_id:
        raise ValueError("Persisted run identifiers do not match the requested run")
    _verify_file(run_root, manifest_path, integrity.get("manifest", {}))
    report_record = integrity.get("report", {})
    _verify_file(run_root, report_path, report_record)
    evidence_by_path = {item.path: item for item in manifest.evidence}
    if report_record.get("path") not in evidence_by_path:
        raise ValueError("Run manifest does not reference the persisted report")
    for evidence in manifest.evidence:
        target = (run_root / evidence.path)
        _verify_file(run_root, target, {"sha256": evidence.hash, "size_bytes": evidence.size_bytes})
        if evidence.run_id != run_id or not evidence.checker:
            raise ValueError(f"Evidence {evidence.id} is missing run/checker attribution")
        provenance = evidence.metadata.get("provenance")
        if not isinstance(provenance, dict) and not hasattr(provenance, "items"):
            raise ValueError(f"Evidence {evidence.id} is missing reproducibility provenance")
        required_provenance = {"run_id", "source_sha256", "source_set_sha256",
                               "specification_input_sha256", "tool_versions",
                               "configuration_sha256", "reproducibility_id", "status"}
        if not required_provenance <= set(provenance):
            raise ValueError(f"Evidence {evidence.id} has incomplete reproducibility provenance")
        if provenance["run_id"] != run_id or not provenance["configuration_sha256"]:
            raise ValueError(f"Evidence {evidence.id} has mismatched run/configuration provenance")
    _validate_stage_execution_evidence(run_root, manifest)
    data = _read_confined_json(report_path, run_root)
    report = PipelineReport.from_dict(data)
    if report.run_id != run_id:
        raise ValueError("Persisted report run_id does not match the requested run")
    if "overall_verdict" in data or "overall_status" in data:
        raise ValueError("Persisted verification report contains a forbidden project-level verdict")
    return report


def _validate_stage_execution_evidence(run_root: Path, manifest: RunManifest) -> None:
    evidence_by_id = {item.id: item for item in manifest.evidence}
    for record in manifest.metadata.get("stage_records", ()):
        stage_id = record.get("stage_id")
        evidence_id = record.get("metadata", {}).get("execution_evidence_id")
        evidence = evidence_by_id.get(evidence_id)
        if not stage_id or evidence is None:
            raise ValueError(f"Stage {stage_id or 'UNKNOWN'} has no resolvable execution evidence")
        payload = _read_confined_json(run_root / evidence.path, run_root)
        required = {"run_id", "stage_id", "status", "source_sha256", "source_set_sha256",
                    "specification_input_sha256", "configuration_sha256", "tool_versions"}
        if not required <= set(payload):
            raise ValueError(f"Stage {stage_id} execution evidence is missing provenance fields")
        if payload["run_id"] != manifest.run_id or payload["stage_id"] != stage_id:
            raise ValueError(f"Stage {stage_id} execution evidence identity mismatch")
        if payload["status"] != record.get("status"):
            raise ValueError(f"Stage {stage_id} execution evidence status mismatch")
        if payload["configuration_sha256"] != record.get("metadata", {}).get("configuration_sha256"):
            raise ValueError(f"Stage {stage_id} execution evidence configuration mismatch")


def _read_confined_json(path: Path, root: Path) -> dict:
    selected = path.resolve(strict=True)
    if not selected.is_relative_to(root.resolve()) or not selected.is_file():
        raise ValueError("Persisted run file is missing or escapes the run workspace")
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Persisted JSON file is not an object: {path.name}")
    return value


def _verify_file(root: Path, path: Path, record: dict) -> None:
    selected = path.resolve(strict=True)
    if not selected.is_relative_to(root.resolve()) or not selected.is_file():
        raise ValueError(f"Persisted artifact escapes run workspace: {path}")
    if record.get("path") and (root / record["path"]).resolve(strict=True) != selected:
        raise ValueError(f"Persisted artifact path does not match integrity record: {path}")
    payload = selected.read_bytes()
    actual_hash = hashlib.sha256(payload).hexdigest()
    if actual_hash != record.get("sha256") or len(payload) != record.get("size_bytes"):
        raise ValueError(f"Persisted artifact integrity mismatch: {path}")
