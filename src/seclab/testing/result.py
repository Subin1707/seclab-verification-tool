"""Raw test observations and batch summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from seclab.execution.command_runner import CommandResult
from seclab.execution.compiler import BuildResult
from seclab.results.result import VerificationResult

from .oracle import ObservedBehavior, OracleEvaluation


@dataclass(frozen=True, slots=True)
class TestExecutionResult:
    test_case_id: str
    executed: bool
    observed: ObservedBehavior | None
    oracle_evaluation: OracleEvaluation
    verification_result: VerificationResult
    command_result: CommandResult | None = None
    build_result: BuildResult | None = None
    duration_ms: float | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str | None = None
    test_case_evidence_id: str | None = None
    observation_evidence_id: str | None = None
    execution_evidence_ids: tuple[str, ...] = ()
    execution_id: str = ""

    @property
    def result(self) -> VerificationResult:
        return self.verification_result

    @property
    def passed(self) -> bool | None:
        return {"PASS": True, "FAIL": False}.get(self.verification_result.status.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_case_id": self.test_case_id, "executed": self.executed,
            "execution_id": self.execution_id,
            "observed": self.observed.to_dict() if self.observed else None,
            "oracle_evaluation": self.oracle_evaluation.to_dict(),
            "verification_result": self.verification_result.to_dict(),
            "duration_ms": self.duration_ms, "evidence_ids": list(self.evidence_ids), "reason": self.reason,
            "test_case_evidence_id": self.test_case_evidence_id,
            "observation_evidence_id": self.observation_evidence_id,
            "execution_evidence_ids": list(self.execution_evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class TestSuiteResult:
    executions: tuple[TestExecutionResult, ...]

    def summary(self) -> dict[str, int]:
        counts = {"total": len(self.executions), "PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0,
                  "NOT_RUN": 0, "TOOL_ERROR": 0, "SPEC_ERROR": 0, "BUILD_ERROR": 0}
        for execution in self.executions:
            counts[execution.verification_result.status.value] += 1
        return counts
