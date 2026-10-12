"""Portable run manifest joining semantic results and evidence metadata."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from seclab.results import VerificationResult, VerificationStatus

from .errors import EvidenceError, EvidenceErrorCode
from .evidence import Evidence


@dataclass(frozen=True, slots=True)
class RunManifest:
    run_id: str
    project: Mapping[str, Any]
    started_at: datetime
    results: tuple[VerificationResult, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    finished_at: datetime | None = None
    environment: Mapping[str, Any] = field(default_factory=dict)
    tool_versions: Mapping[str, str] = field(default_factory=dict)
    input_artifacts: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, "run_id must be a non-empty string.")
        object.__setattr__(self, "started_at", _utc(self.started_at, "started_at"))
        if self.finished_at is not None:
            object.__setattr__(self, "finished_at", _utc(self.finished_at, "finished_at"))
        object.__setattr__(self, "project", _freeze(self.project))
        object.__setattr__(self, "environment", _freeze(self.environment))
        object.__setattr__(self, "tool_versions", _freeze(self.tool_versions))
        object.__setattr__(self, "metadata", _freeze(self.metadata))
        object.__setattr__(self, "results", tuple(sorted(self.results, key=lambda item: item.id)))
        object.__setattr__(self, "evidence", tuple(sorted(self.evidence, key=lambda item: (item.stage, item.path, item.id))))
        object.__setattr__(self, "input_artifacts", tuple(sorted(self.input_artifacts)))
        _unique((item.id for item in self.results), "result")
        evidence_ids = tuple(item.id for item in self.evidence)
        _unique(evidence_ids, "evidence")
        available = set(evidence_ids)
        missing = sorted({ref for result in self.results for ref in result.evidence_ids if ref not in available})
        if missing:
            raise EvidenceError(EvidenceErrorCode.MISSING_EVIDENCE_REFERENCE, f"Result references missing evidence IDs: {', '.join(missing)}.")

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in VerificationStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return {"total": len(self.results), **counts}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "project": _thaw(self.project),
            "started_at": _timestamp(self.started_at),
            "finished_at": _timestamp(self.finished_at) if self.finished_at else None,
            "environment": _thaw(self.environment),
            "tool_versions": _thaw(self.tool_versions),
            "input_artifacts": list(self.input_artifacts),
            "results": [item.to_dict() for item in self.results],
            "evidence": [item.to_dict() for item in self.evidence],
            "summary": self.summary(),
            "metadata": _thaw(self.metadata),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RunManifest:
        try:
            return cls(
                run_id=data["run_id"], project=data["project"], started_at=_parse_time(data["started_at"]),
                finished_at=_parse_time(data["finished_at"]) if data.get("finished_at") else None,
                environment=data.get("environment", {}), tool_versions=data.get("tool_versions", {}),
                input_artifacts=tuple(data.get("input_artifacts", ())),
                results=tuple(VerificationResult.from_dict(item) for item in data.get("results", ())),
                evidence=tuple(Evidence.from_dict(item) for item in data.get("evidence", ())),
                metadata=data.get("metadata", {}),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, f"Cannot deserialize manifest: {exc}") from exc


def _utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, f"{field_name} must be timezone-aware.")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _unique(values: Any, label: str) -> None:
    values = tuple(values)
    if len(values) != len(set(values)):
        raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, f"Manifest has duplicate {label} IDs.")


def _freeze(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, "Manifest numbers must be finite.")
        return value
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise EvidenceError(EvidenceErrorCode.MANIFEST_SERIALIZATION_ERROR, f"Manifest contains non-JSON value {type(value).__name__}.")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
