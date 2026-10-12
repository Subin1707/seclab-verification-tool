"""Stable structured model and counterexample representation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ModelAssignment:
    variable: str
    value: bool | int | float | str
    type: str

    def to_dict(self) -> dict[str, Any]:
        return {"variable": self.variable, "type": self.type, "value": self.value}


@dataclass(frozen=True, slots=True)
class Counterexample:
    assignments: tuple[ModelAssignment, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"format": "seclab-smt-counterexample-v1", "assignments": [entry.to_dict() for entry in self.assignments]}
