"""Workspace-confined, content-hashed artifact storage."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Mapping

from .errors import EvidenceError, EvidenceErrorCode
from .evidence import Evidence, EvidenceType


class ArtifactStore:
    def __init__(
        self, workspace_root: str | Path, *, clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None, run_id: str | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.evidence_root = self.workspace_root / "evidence"
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        # Evidence IDs are stable for the same run, stage, relative artifact
        # path and payload. Distinct payloads/paths stay distinct.
        self._id_factory = id_factory
        self.run_id = run_id

    def write_text(self, stage: str, filename: str, content: str, *, evidence_type: EvidenceType = EvidenceType.LOG,
                   source: str = "verification-tool", requirement_id: str | None = None,
                   property_id: str | None = None, metadata: Mapping[str, Any] | None = None,
                   checker: str | None = None, run_id: str | None = None) -> Evidence:
        if not isinstance(content, str):
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_SERIALIZATION_ERROR, "Text artifact content must be str.")
        return self._write(stage, filename, content.encode("utf-8"), evidence_type, source,
                           requirement_id, property_id, metadata, checker, run_id)

    def write_bytes(self, stage: str, filename: str, content: bytes, *, evidence_type: EvidenceType = EvidenceType.LOG,
                    source: str = "verification-tool", requirement_id: str | None = None,
                    property_id: str | None = None, metadata: Mapping[str, Any] | None = None,
                    checker: str | None = None, run_id: str | None = None) -> Evidence:
        if not isinstance(content, bytes):
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_SERIALIZATION_ERROR, "Binary artifact content must be bytes.")
        return self._write(stage, filename, content, evidence_type, source, requirement_id, property_id, metadata,
                           checker, run_id)

    def write_json(self, stage: str, filename: str, content: Any, *, evidence_type: EvidenceType = EvidenceType.TEST_RESULT,
                   source: str = "verification-tool", requirement_id: str | None = None,
                   property_id: str | None = None, metadata: Mapping[str, Any] | None = None,
                   checker: str | None = None, run_id: str | None = None) -> Evidence:
        try:
            encoded = json.dumps(content, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_SERIALIZATION_ERROR, f"Cannot serialize JSON artifact: {exc}") from exc
        return self._write(stage, filename, encoded, evidence_type, source, requirement_id, property_id, metadata,
                           checker, run_id)

    def copy_file(self, stage: str, filename: str, source_path: str | Path, *,
                  evidence_type: EvidenceType = EvidenceType.LOG, source: str = "external-file",
                  requirement_id: str | None = None, property_id: str | None = None,
                  metadata: Mapping[str, Any] | None = None, checker: str | None = None,
                  run_id: str | None = None) -> Evidence:
        try:
            payload = Path(source_path).read_bytes()
        except OSError as exc:
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_WRITE_ERROR, f"Cannot read source artifact: {exc}") from exc
        return self._write(stage, filename, payload, evidence_type, source, requirement_id, property_id, metadata,
                           checker, run_id)

    def _write(self, stage: str, filename: str, payload: bytes, evidence_type: EvidenceType, source: str,
               requirement_id: str | None, property_id: str | None, metadata: Mapping[str, Any] | None,
               checker: str | None, run_id: str | None) -> Evidence:
        if not _safe_component(stage) or not _safe_filename(filename):
            raise EvidenceError(EvidenceErrorCode.INVALID_ARTIFACT_PATH, "Stage and filename must be safe path components.")
        target = self.evidence_root / stage / filename
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            root_resolved = self.evidence_root.resolve()
            target_resolved = target.resolve(strict=False)
            if not target_resolved.is_relative_to(root_resolved) or not target_resolved.is_relative_to(self.workspace_root):
                raise EvidenceError(EvidenceErrorCode.INVALID_ARTIFACT_PATH, "Artifact path resolves outside the workspace evidence directory.")
            # Exclusive creation prevents overwrites and follows no pre-existing file symlink.
            with target.open("xb") as stream:
                written_resolved = target.resolve(strict=True)
                if not written_resolved.is_relative_to(root_resolved) or not written_resolved.is_relative_to(self.workspace_root):
                    raise EvidenceError(EvidenceErrorCode.INVALID_ARTIFACT_PATH, "Artifact path changed outside the evidence directory during write.")
                stream.write(payload)
        except EvidenceError:
            raise
        except FileExistsError as exc:
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_ALREADY_EXISTS, f"Artifact '{stage}/{filename}' already exists.") from exc
        except OSError as exc:
            raise EvidenceError(EvidenceErrorCode.ARTIFACT_WRITE_ERROR, f"Cannot write artifact: {exc}") from exc
        digest = hashlib.sha256(payload).hexdigest()
        evidence_id = (self._id_factory() if self._id_factory is not None else
                       "ev-" + hashlib.sha256("\0".join((self.run_id or "", stage, filename, digest)).encode("utf-8")).hexdigest()[:32])
        return Evidence(
            id=evidence_id, type=evidence_type, stage=stage, source=source,
            path=PurePosixPath("evidence", stage, filename).as_posix(), timestamp=self._clock(), hash=digest,
            requirement_id=requirement_id, property_id=property_id, metadata=metadata or {},
            size_bytes=len(payload), checker=checker or (metadata or {}).get("checker") or source,
            run_id=run_id or self.run_id,
        )


def _safe_component(value: str) -> bool:
    return isinstance(value, str) and bool(value) and value not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", value) is not None


def _safe_filename(value: str) -> bool:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        return False
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
        return False
    return Path(value).name == value and "/" not in value and "\\" not in value and "\x00" not in value
