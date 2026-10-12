"""Explicit, data-only expected-versus-observed behavior checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .test_case import ExpectedBehavior, OracleType


@dataclass(frozen=True, slots=True)
class ObservedBehavior:
    exit_code: int | None
    stdout: str
    stderr: str
    returned_value: Any = None
    return_value_available: bool = False
    crashed: bool | None = None
    timed_out: bool = False
    structured_output: Any = None
    structured_output_available: bool = False
    memory_findings: tuple[dict[str, Any], ...] = ()
    memory_analysis_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code, "stdout": self.stdout, "stderr": self.stderr,
            "returned_value": self.returned_value if self.return_value_available else None,
            "return_value_available": self.return_value_available,
            "crashed": self.crashed, "timed_out": self.timed_out,
            "structured_output": self.structured_output if self.structured_output_available else None,
            "structured_output_available": self.structured_output_available,
            "memory_findings": list(self.memory_findings),
            "memory_analysis_available": self.memory_analysis_available,
        }


@dataclass(frozen=True, slots=True)
class OracleCheckResult:
    oracle_type: OracleType
    expected: Any
    actual: Any
    satisfied: bool | None
    evaluated: bool
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"oracle_type": self.oracle_type.value, "expected": self.expected, "actual": self.actual,
                "satisfied": self.satisfied, "evaluated": self.evaluated, "message": self.message}


@dataclass(frozen=True, slots=True)
class OracleEvaluation:
    checks: tuple[OracleCheckResult, ...]

    @property
    def evaluated(self) -> bool:
        return any(check.evaluated for check in self.checks)

    @property
    def satisfied(self) -> bool | None:
        if any(check.evaluated and check.satisfied is False for check in self.checks):
            return False
        if self.checks and all(check.evaluated and check.satisfied is True for check in self.checks):
            return True
        return None

    def to_dict(self) -> dict[str, Any]:
        return {"checks": [check.to_dict() for check in self.checks], "evaluated": self.evaluated,
                "satisfied": self.satisfied}


class Oracle:
    """Compares observations with explicit supported expectations only."""

    def evaluate(self, expected: ExpectedBehavior | None, observed: ObservedBehavior | None) -> OracleEvaluation:
        if expected is None or not expected.checks:
            return OracleEvaluation(())
        results = tuple(self._evaluate_one(item.oracle_type, item.expected, observed) for item in expected.checks)
        return OracleEvaluation(results)

    @staticmethod
    def _evaluate_one(kind: OracleType, expected: Any, observed: ObservedBehavior | None) -> OracleCheckResult:
        if observed is None:
            return OracleCheckResult(kind, expected, None, None, False, "No process observation is available.")
        if observed.timed_out:
            return OracleCheckResult(kind, expected, None, None, False, "Execution timed out; this oracle was not evaluated.")
        if observed.crashed is True and kind not in {OracleType.NO_CRASH, OracleType.MEMORY_FINDING_PRESENT}:
            return OracleCheckResult(kind, expected, None, None, False,
                                     "Process terminated abnormally; this oracle was not evaluated.")
        if kind is OracleType.EXIT_CODE_EQUALS:
            actual, available = observed.exit_code, observed.exit_code is not None
            satisfied = actual == expected if available else None
        elif kind is OracleType.STDOUT_EQUALS:
            actual, available = observed.stdout, True
            satisfied = actual == expected
        elif kind is OracleType.STDOUT_CONTAINS:
            actual, available = observed.stdout, True
            satisfied = expected in actual
        elif kind is OracleType.STDERR_EQUALS:
            actual, available = observed.stderr, True
            satisfied = actual == expected
        elif kind is OracleType.STDERR_CONTAINS:
            actual, available = observed.stderr, True
            satisfied = expected in actual
        elif kind is OracleType.RETURN_VALUE_EQUALS:
            actual, available = observed.returned_value, observed.return_value_available
            satisfied = _equal_values(actual, expected) if available else None
        elif kind is OracleType.NO_CRASH:
            actual, available = observed.crashed, observed.crashed is not None
            satisfied = not actual if available else None
        elif kind is OracleType.STRUCTURED_OUTPUT_EQUALS:
            actual, available = observed.structured_output, observed.structured_output_available
            satisfied = _equal_values(actual, expected) if available else None
        elif kind is OracleType.MEMORY_FINDING_PRESENT:
            actual = bool(observed.memory_findings)
            available = observed.memory_analysis_available
            satisfied = actual == expected if available else None
        else:  # StrEnum additions require an explicit implementation.
            return OracleCheckResult(kind, expected, None, None, False, "Oracle type is not implemented.")
        message = "Expected behavior observed." if satisfied is True else "Expected behavior was not observed." if satisfied is False else "Required observation is unavailable."
        return OracleCheckResult(kind, expected, actual, satisfied, available, message)


def _equal_values(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    return type(actual) is type(expected) and actual == expected
