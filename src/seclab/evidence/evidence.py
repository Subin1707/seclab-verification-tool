"""Immutable metadata describing a stored verification artifact."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from .errors import EvidenceError, EvidenceErrorCode


class EvidenceType(StrEnum):
    LOG = "LOG"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    WITNESS = "WITNESS"
    TEST_RESULT = "TEST_RESULT"
    SANITIZER_REPORT = "SANITIZER_REPORT"
    STATIC_ANALYSIS_REPORT = "STATIC_ANALYSIS_REPORT"
    COVERAGE_REPORT = "COVERAGE_REPORT"
    FUZZ_INPUT = "FUZZ_INPUT"
    CRASH = "CRASH"
    MODEL = "MODEL"
    SPECIFICATION = "SPECIFICATION"
    ENVIRONMENT = "ENVIRONMENT"


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    type: EvidenceType
    stage: str
    source: str
    path: str
    timestamp: datetime
    hash: str
    requirement_id: str | None = None
    property_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    size_bytes: int | None = None
    checker: str | None = None
    run_id: str | None = None

    def __post_init__(self) -> None:
        for key in ("id", "stage", "source", "path"):
            value = getattr(self, key)
            if not isinstance(value, str) or not value.strip():
                raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, f"{key} must be a non-empty string.")
        try:
            object.__setattr__(self, "type", EvidenceType(self.type))
        except ValueError as exc:
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, f"Unknown evidence type {self.type!r}.") from exc
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, "timestamp must be a timezone-aware datetime.")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
        if not isinstance(self.hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", self.hash):
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, "hash must be a 64-character SHA-256 hex digest.")
        object.__setattr__(self, "hash", self.hash.lower())
        if self.size_bytes is not None and (not isinstance(self.size_bytes, int) or self.size_bytes < 0):
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, "size_bytes must be a non-negative integer.")
        for key in ("checker", "run_id"):
            value = getattr(self, key)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, f"{key} must be a non-empty string when provided.")
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    @property
    def sha256(self) -> str:
        return self.hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "type": self.type.value, "stage": self.stage, "source": self.source,
            "path": self.path, "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "hash": self.hash, "requirement_id": self.requirement_id, "property_id": self.property_id,
            "metadata": _thaw(self.metadata), "size_bytes": self.size_bytes,
            "checker": self.checker, "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Evidence:
        try:
            timestamp = datetime.fromisoformat(str(data["timestamp"]).replace("Z", "+00:00"))
            return cls(
                id=data["id"], type=data["type"], stage=data["stage"], source=data["source"],
                path=data["path"], timestamp=timestamp, hash=data["hash"],
                requirement_id=data.get("requirement_id"), property_id=data.get("property_id"),
                metadata=data.get("metadata", {}), size_bytes=data.get("size_bytes"),
                checker=data.get("checker"), run_id=data.get("run_id"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, f"Cannot deserialize Evidence: {exc}") from exc


def _freeze(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, "Metadata numbers must be finite.")
        return value
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, f"Metadata contains non-JSON value {type(value).__name__}.")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
