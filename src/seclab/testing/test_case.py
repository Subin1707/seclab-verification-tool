"""Immutable, JSON-safe dynamic test case and expected behavior models."""

from __future__ import annotations

import json
import math
import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .errors import TestError, TestErrorCode


class TestCategory(StrEnum):
    __test__ = False
    NORMAL = "NORMAL"
    BOUNDARY = "BOUNDARY"
    NEGATIVE = "NEGATIVE"
    INVALID = "INVALID"
    REGRESSION = "REGRESSION"


class TestTargetKind(StrEnum):
    __test__ = False
    FUNCTION = "FUNCTION"
    EXECUTABLE = "EXECUTABLE"
    ABSTRACT = "ABSTRACT"


class OracleType(StrEnum):
    EXIT_CODE_EQUALS = "EXIT_CODE_EQUALS"
    STDOUT_EQUALS = "STDOUT_EQUALS"
    STDOUT_CONTAINS = "STDOUT_CONTAINS"
    STDERR_EQUALS = "STDERR_EQUALS"
    STDERR_CONTAINS = "STDERR_CONTAINS"
    RETURN_VALUE_EQUALS = "RETURN_VALUE_EQUALS"
    NO_CRASH = "NO_CRASH"
    STRUCTURED_OUTPUT_EQUALS = "STRUCTURED_OUTPUT_EQUALS"
    MEMORY_FINDING_PRESENT = "MEMORY_FINDING_PRESENT"


@dataclass(frozen=True, slots=True)
class OracleExpectation:
    oracle_type: OracleType
    expected: Any = None

    def __post_init__(self) -> None:
        try:
            kind = OracleType(self.oracle_type)
        except ValueError as exc:
            raise TestError(TestErrorCode.UNSUPPORTED_EXPECTATION, f"Unsupported oracle type {self.oracle_type!r}.") from exc
        if kind is OracleType.EXIT_CODE_EQUALS:
            if isinstance(self.expected, bool) or not isinstance(self.expected, int):
                raise TestError(TestErrorCode.INVALID_TEST_CASE, "EXIT_CODE_EQUALS expects an integer.")
        elif kind in {OracleType.STDOUT_EQUALS, OracleType.STDOUT_CONTAINS, OracleType.STDERR_EQUALS, OracleType.STDERR_CONTAINS}:
            if not isinstance(self.expected, str):
                raise TestError(TestErrorCode.INVALID_TEST_CASE, f"{kind.value} expects text.")
        elif kind is OracleType.STRUCTURED_OUTPUT_EQUALS:
            _validate_json(self.expected)
        elif kind is OracleType.MEMORY_FINDING_PRESENT:
            if type(self.expected) is not bool:
                raise TestError(TestErrorCode.INVALID_TEST_CASE, "MEMORY_FINDING_PRESENT expects a boolean." )
        elif kind is OracleType.NO_CRASH and self.expected not in {None, True}:
            raise TestError(TestErrorCode.INVALID_TEST_CASE, "NO_CRASH does not accept a false expected value.")
        else:
            _validate_json(self.expected)
        object.__setattr__(self, "oracle_type", kind)

    def to_dict(self) -> dict[str, Any]:
        return {"oracle_type": self.oracle_type.value, "expected": self.expected}


@dataclass(frozen=True, slots=True)
class ExpectedBehavior:
    checks: tuple[OracleExpectation, ...] = ()

    def __post_init__(self) -> None:
        checks = tuple(item if isinstance(item, OracleExpectation) else OracleExpectation(**item) for item in self.checks)
        object.__setattr__(self, "checks", checks)

    @property
    def has_oracle(self) -> bool:
        return bool(self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"checks": [item.to_dict() for item in self.checks]}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | ExpectedBehavior | None) -> ExpectedBehavior | None:
        if value is None or isinstance(value, ExpectedBehavior):
            return value
        aliases: tuple[tuple[str, OracleType], ...] = (
            ("expected_exit_code", OracleType.EXIT_CODE_EQUALS), ("exit_code", OracleType.EXIT_CODE_EQUALS),
            ("expected_stdout", OracleType.STDOUT_EQUALS), ("stdout", OracleType.STDOUT_EQUALS),
            ("stdout_contains", OracleType.STDOUT_CONTAINS),
            ("expected_stderr", OracleType.STDERR_EQUALS), ("stderr", OracleType.STDERR_EQUALS),
            ("stderr_contains", OracleType.STDERR_CONTAINS),
            ("expected_return_value", OracleType.RETURN_VALUE_EQUALS), ("return_value", OracleType.RETURN_VALUE_EQUALS),
            ("no_crash", OracleType.NO_CRASH),
            ("structured_output", OracleType.STRUCTURED_OUTPUT_EQUALS),
            ("memory_finding", OracleType.MEMORY_FINDING_PRESENT),
        )
        checks: list[OracleExpectation] = []
        consumed: set[str] = set()
        for key, kind in aliases:
            if key in value:
                raw = value[key]
                consumed.add(key)
                if kind is OracleType.NO_CRASH:
                    if raw is True:
                        checks.append(OracleExpectation(kind, True))
                else:
                    checks.append(OracleExpectation(kind, raw))
        unknown = set(value) - consumed - {"checks"}
        if unknown:
            raise TestError(TestErrorCode.UNSUPPORTED_EXPECTATION, f"Unknown expected behavior fields: {', '.join(sorted(unknown))}.")
        if "checks" in value:
            for item in value["checks"]:
                if not isinstance(item, Mapping) or "oracle_type" not in item:
                    raise TestError(TestErrorCode.INVALID_TEST_CASE, "Each expected check requires oracle_type and expected.")
                checks.append(OracleExpectation(item["oracle_type"], item.get("expected")))
        return cls(tuple(checks))


@dataclass(frozen=True, slots=True)
class TestCase:
    __test__ = False
    id: str
    name: str
    target: str
    inputs: Mapping[str, Any] = field(default_factory=dict)
    expected: ExpectedBehavior | Mapping[str, Any] | None = None
    category: TestCategory = TestCategory.NORMAL
    target_kind: TestTargetKind = TestTargetKind.FUNCTION
    requirement_id: str | None = None
    property_id: str | None = None
    description: str | None = None
    preconditions: tuple[str, ...] = ()
    timeout_seconds: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key in ("id", "name", "target"):
            value = getattr(self, key)
            if not isinstance(value, str) or not value.strip():
                raise TestError(TestErrorCode.INVALID_TEST_CASE, f"{key} must be non-empty text.")
        try:
            object.__setattr__(self, "category", TestCategory(self.category))
            object.__setattr__(self, "target_kind", TestTargetKind(self.target_kind))
        except ValueError as exc:
            raise TestError(TestErrorCode.INVALID_TEST_CASE, str(exc)) from exc
        if not isinstance(self.inputs, Mapping) or any(not isinstance(key, str) for key in self.inputs):
            raise TestError(TestErrorCode.INVALID_TEST_CASE, "inputs must be a mapping with string keys.")
        _validate_input_data(self.inputs)
        object.__setattr__(self, "inputs", _freeze(self.inputs))
        object.__setattr__(self, "expected", ExpectedBehavior.from_mapping(self.expected))
        if self.timeout_seconds is not None and (
            isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0
        ):
            raise TestError(TestErrorCode.INVALID_TEST_CASE, "timeout_seconds must be a finite positive number.")
        if any(not isinstance(item, str) or not item for item in self.preconditions):
            raise TestError(TestErrorCode.INVALID_TEST_CASE, "preconditions must contain non-empty strings.")
        _validate_json(self.metadata)
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "target": self.target,
            "target_kind": self.target_kind.value, "inputs": _input_json_safe(self.inputs),
            "expected": self.expected.to_dict() if self.expected else None,
            "category": self.category.value, "requirement_id": self.requirement_id,
            "property_id": self.property_id, "description": self.description,
            "preconditions": list(self.preconditions), "timeout_seconds": self.timeout_seconds,
            "metadata": _thaw(self.metadata),
        }


def _validate_json(value: Any) -> None:
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TestError(TestErrorCode.INVALID_TEST_CASE, f"Value is not finite JSON data: {exc}") from exc


def _validate_input_data(value: Any) -> None:
    try:
        json.dumps(_input_json_safe(value), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TestError(TestErrorCode.INVALID_TEST_CASE, f"Value is not valid test input data: {exc}") from exc


def _input_json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$bytes_base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        return {key: _input_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_input_json_safe(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value
