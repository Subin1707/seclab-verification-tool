"""Persist command and environment records through the shared ArtifactStore."""

from __future__ import annotations

import uuid
from typing import Any

from seclab.evidence import ArtifactStore, Evidence, EvidenceType

from .command_runner import CommandResult
from .environment import EnvironmentSnapshot


def store_command_evidence(store: ArtifactStore, result: CommandResult, *, stage: str = "execution",
                           prefix: str | None = None) -> tuple[Evidence, ...]:
    prefix = prefix or f"command-{uuid.uuid4().hex}"
    base = {
        "argv": list(result.argv), "cwd": result.cwd, "exit_code": result.exit_code,
        "duration_ms": result.duration_ms, "timed_out": result.timed_out,
        "started_at": result.started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": result.finished_at.isoformat().replace("+00:00", "Z"),
        "allowed_exit_codes": list(result.allowed_exit_codes), "executable_path": result.executable_path,
        "execution_error": result.execution_error,
        "completed": result.completed, "termination": result.termination_info,
        "environment_override_keys": list(result.environment_keys),
    }
    stdout = store.write_text(stage, f"{prefix}-stdout.txt", result.stdout, evidence_type=EvidenceType.LOG, source="command-runner")
    stderr = store.write_text(stage, f"{prefix}-stderr.txt", result.stderr, evidence_type=EvidenceType.LOG, source="command-runner")
    base["stdout_evidence"] = {"id": stdout.id, "path": stdout.path, "sha256": stdout.hash}
    base["stderr_evidence"] = {"id": stderr.id, "path": stderr.path, "sha256": stderr.hash}
    command = store.write_json(stage, f"{prefix}-metadata.json", base, evidence_type=EvidenceType.TEST_RESULT, source="command-runner")
    return command, stdout, stderr


def store_environment_evidence(store: ArtifactStore, snapshot: EnvironmentSnapshot, *, filename: str | None = None) -> Evidence:
    filename = filename or f"snapshot-{uuid.uuid4().hex}.json"
    return store.write_json("environment", filename, snapshot.to_dict(),
                            evidence_type=EvidenceType.ENVIRONMENT, source="environment-snapshot")
