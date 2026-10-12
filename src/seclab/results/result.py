"""Immutable, JSON-serializable semantic verification result."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ResultError, ResultErrorCode
from .status import VerificationStatus


@dataclass(frozen=True, slots=True)
class VerificationResult:
    id: str
    stage: str
    technique: str
    status: VerificationStatus
    reason_code: str
    message: str
    requirement_id: str | None = None
    property_id: str | None = None
    source: str | None = None
    scope: str | None = None
    evidence_ids: tuple[str, ...] = ()
    counterexample: Any = None
    duration_ms: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("id", "stage", "technique", "reason_code", "message"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ResultError(ResultErrorCode.INVALID_RESULT, f"{field_name} must be a non-empty string.")
        try:
            normalized_status = VerificationStatus(self.status)
        except ValueError as exc:
            raise ResultError(ResultErrorCode.INVALID_RESULT, f"Unknown verification status {self.status!r}.") from exc
        if self.duration_ms is not None and (
            not isinstance(self.duration_ms, (int, float))
            or isinstance(self.duration_ms, bool)
            or not math.isfinite(self.duration_ms)
            or self.duration_ms < 0
        ):
            raise ResultError(ResultErrorCode.INVALID_RESULT, "duration_ms must be a finite non-negative number.")
        if any(not isinstance(item, str) or not item for item in self.evidence_ids):
            raise ResultError(ResultErrorCode.INVALID_RESULT, "evidence_ids must contain non-empty strings.")
        object.__setattr__(self, "status", normalized_status)
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "counterexample", _freeze_json(self.counterexample))
        object.__setattr__(self, "metadata", _freeze_json(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stage": self.stage,
            "technique": self.technique,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "message": self.message,
            "requirement_id": self.requirement_id,
            "property_id": self.property_id,
            "source": self.source,
            "scope": self.scope,
            "evidence_ids": list(self.evidence_ids),
            "counterexample": _thaw_json(self.counterexample),
            "duration_ms": self.duration_ms,
            "metadata": _thaw_json(self.metadata),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationResult:
        try:
            return cls(
                id=data["id"],
                stage=data["stage"],
                technique=data["technique"],
                status=VerificationStatus(data["status"]),
                reason_code=data["reason_code"],
                message=data["message"],
                requirement_id=data.get("requirement_id"),
                property_id=data.get("property_id"),
                source=data.get("source"),
                scope=data.get("scope"),
                evidence_ids=tuple(data.get("evidence_ids", ())),
                counterexample=data.get("counterexample"),
                duration_ms=data.get("duration_ms"),
                metadata=data.get("metadata", {}),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResultError(
                ResultErrorCode.RESULT_SERIALIZATION_ERROR,
                f"Cannot deserialize VerificationResult: {exc}",
            ) from exc


def _freeze_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ResultError(ResultErrorCode.INVALID_RESULT, "JSON numeric values must be finite.")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ResultError(ResultErrorCode.INVALID_RESULT, "JSON object keys must be strings.")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    raise ResultError(
        ResultErrorCode.INVALID_RESULT,
        f"Value of type {type(value).__name__} is not JSON serializable.",
    )


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value
