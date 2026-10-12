"""Normalized, JSON-safe static analyzer findings."""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    tool: str
    file: str
    line: int | None
    severity: Severity
    category: str
    message: str
    column: int | None = None
    rule_id: str | None = None
    cwe: str | None = None
    raw_evidence: str | None = None
    function: str | None = None
    confidence: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("id", "tool", "file", "category", "message"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "severity", Severity(self.severity))
        for name in ("line", "column"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise ValueError(f"{name} must be a positive integer or None")
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "tool": self.tool, "file": self.file, "line": self.line,
                "column": self.column, "severity": self.severity.value, "category": self.category,
                "message": self.message, "rule_id": self.rule_id, "cwe": self.cwe,
                "raw_evidence": self.raw_evidence, "function": self.function,
                "confidence": self.confidence, "metadata": _thaw(self.metadata)}

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        return cls(**{key: data.get(key) for key in (
            "id", "tool", "file", "line", "severity", "category", "message", "column", "rule_id",
            "cwe", "raw_evidence", "function", "confidence",
        ) if key in data}, metadata=data.get("metadata", {}))


def make_finding(*, tool: str, file: str, line: int | None, severity: str | Severity,
                 category: str, message: str, column: int | None = None, rule_id: str | None = None,
                 cwe: str | None = None, raw_evidence: str | None = None,
                 metadata: Mapping[str, Any] | None = None, finding_id: str | None = None) -> Finding:
    original = str(severity)
    normalized = _normalize_severity(original)
    merged = dict(metadata or {})
    merged.setdefault("original_severity", original)
    return Finding(finding_id or str(uuid.uuid4()), tool, file or "<unknown>", line, normalized,
                   category or "unknown", message or "Analyzer reported a finding without a message.",
                   column, rule_id, _normalize_cwe(cwe), raw_evidence, metadata=merged)


def _normalize_severity(value: str) -> Severity:
    normalized = value.strip().upper()
    try:
        return Severity(normalized)
    except ValueError:
        # Tool categories such as warning/error/style describe diagnostic kind,
        # not calibrated security impact; retain them separately as category.
        return Severity.UNKNOWN


def _normalize_cwe(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    raw = str(value).strip().upper()
    if raw.startswith("CWE-") and raw[4:].isdigit():
        return raw
    if raw.isdigit():
        return f"CWE-{raw}"
    return None


def _freeze(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Finding metadata numbers must be finite")
        return value
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise ValueError(f"Finding metadata contains non-JSON value {type(value).__name__}")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
