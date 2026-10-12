"""Normalized runtime sanitizer findings."""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class MemoryFinding:
    id: str
    tool: str
    kind: str
    message: str
    file: str | None = None
    line: int | None = None
    function: str | None = None
    address: str | None = None
    allocation_site: str | None = None
    failure_site: str | None = None
    stack_trace: tuple[str, ...] = ()
    raw_evidence: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key in ("id", "tool", "kind", "message"):
            if not isinstance(getattr(self, key), str) or not getattr(self, key).strip():
                raise ValueError(f"{key} must be a non-empty string")
        if not isinstance(self.stack_trace, (list, tuple)) or any(not isinstance(item, str) for item in self.stack_trace):
            raise ValueError("stack_trace must be a sequence of strings")
        if self.line is not None and (not isinstance(self.line, int) or isinstance(self.line, bool) or self.line < 1):
            raise ValueError("line must be a positive integer or None")
        object.__setattr__(self, "stack_trace", tuple(self.stack_trace))
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "tool": self.tool, "kind": self.kind, "message": self.message,
                "file": self.file, "line": self.line, "function": self.function, "address": self.address,
                "allocation_site": self.allocation_site, "failure_site": self.failure_site,
                "stack_trace": list(self.stack_trace), "raw_evidence": self.raw_evidence,
                "metadata": _thaw(self.metadata)}

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MemoryFinding:
        return cls(**dict(data))


def make_memory_finding(*, tool: str, kind: str, message: str, file: str | None = None,
                        line: int | None = None, function: str | None = None, address: str | None = None,
                        allocation_site: str | None = None, failure_site: str | None = None,
                        stack_trace: tuple[str, ...] = (), raw_evidence: str | None = None,
                        metadata: Mapping[str, Any] | None = None) -> MemoryFinding:
    return MemoryFinding(str(uuid.uuid4()), tool, kind, message, file, line, function, address,
                         allocation_site, failure_site, stack_trace, raw_evidence, metadata or {})


def _freeze(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Memory finding metadata numbers must be finite")
        return value
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    raise ValueError(f"Memory finding metadata contains non-JSON value {type(value).__name__}")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping): return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple): return [_thaw(item) for item in value]
    return value
