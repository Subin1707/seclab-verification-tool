"""Stable Python data contract for SecLab specification input.

This module contains data only. Parsing, validation, normalization and checking
belong in their respective layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

Scalar = str | int | float | bool | None
RequirementType = Literal["safety", "liveness", "functional", "security", "performance", "other"]
Priority = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Logic = Literal["CTL", "SMT", "BMC"]


@dataclass(frozen=True, slots=True)
class Domain:
    """Finite or bounded values permitted for a variable."""

    type: Literal["boolean", "integer", "number", "string"] | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    values: tuple[Scalar, ...] = ()
    enum: tuple[Scalar, ...] = ()


@dataclass(frozen=True, slots=True)
class Requirement:
    id: str
    description: str
    type: RequirementType | None = None
    priority: Priority | None = None
    constraint_ids: tuple[str, ...] = ()
    property_ids: tuple[str, ...] = ()
    function_ids: tuple[str, ...] = ()
    test_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Variable:
    id: str
    domain: Domain
    initial: Scalar = None
    description: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Constraint:
    id: str
    expression: str
    requirement_ids: tuple[str, ...] = ()
    kind: Literal["invariant", "initial", "transition", "assumption", "other"] | None = None
    description: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StateSpec:
    id: str
    initial: bool = False
    values: Mapping[str, Scalar] = field(default_factory=dict)
    labels: tuple[str, ...] = ()
    description: str | None = None
    machine_id: str | None = None


@dataclass(frozen=True, slots=True)
class TransitionSpec:
    id: str
    source: str
    target: str
    guard: str | None = None
    action: str | None = None
    label: str | None = None
    machine_id: str | None = None


@dataclass(frozen=True, slots=True)
class StateMachineSpec:
    id: str
    initial_state: str | None = None
    description: str | None = None
    states: tuple["StateSpec", ...] = ()
    transitions: tuple["TransitionSpec", ...] = ()


@dataclass(frozen=True, slots=True)
class PropertySpec:
    id: str
    logic: Logic
    formula: str
    requirement_ids: tuple[str, ...] = ()
    description: str | None = None
    bound: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FunctionSpec:
    id: str
    name: str
    file: str | None = None
    language: str | None = None
    requirement_ids: tuple[str, ...] = ()
    description: str | None = None


@dataclass(frozen=True, slots=True)
class TestSpec:
    id: str
    function_id: str | None = None
    requirement_ids: tuple[str, ...] = ()
    kind: Literal["unit", "integration", "system", "boundary", "fuzz", "other"] | None = None
    input: Mapping[str, Any] = field(default_factory=dict)
    expected: Any = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class Specification:
    """Canonical aggregate input; omitted collections normalize to empty tuples."""

    schema_version: Literal["1.0", "2.0"]
    id: str
    name: str
    description: str | None = None
    initial_state: str | None = None
    requirements: tuple[Requirement, ...] = ()
    variables: tuple[Variable, ...] = ()
    constraints: tuple[Constraint, ...] = ()
    states: tuple[StateSpec, ...] = ()
    transitions: tuple[TransitionSpec, ...] = ()
    properties: tuple[PropertySpec, ...] = ()
    functions: tuple[FunctionSpec, ...] = ()
    tests: tuple[TestSpec, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    project: Mapping[str, Any] = field(default_factory=dict)
    state_machines: tuple[StateMachineSpec, ...] = ()
    coverage: Mapping[str, Any] = field(default_factory=dict)
    fuzzing: Mapping[str, Any] = field(default_factory=dict)
