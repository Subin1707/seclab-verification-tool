"""Honest constraint-guided generation prototype; no implicit source tracing."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from seclab.formal.smt import QueryIntent, SMTVerifier, SolverOutcome
from seclab.specification.schema import Domain, Specification, Variable


@dataclass(frozen=True, slots=True)
class BranchConstraint:
    variable: str
    operator: str
    value: int | float
    current_path_operator: str

    def alternate_expression(self) -> str:
        allowed = {"<", "<=", ">", ">=", "==", "!="}
        if self.operator not in allowed or self.current_path_operator not in allowed:
            raise ValueError("unsupported branch operator")
        return f"{self.variable} {self.operator} {self.value}"


@dataclass(frozen=True, slots=True)
class ConcolicResult:
    supported: bool
    reason_code: str
    input_values: dict[str, Any] | None = None
    solver_outcome: str | None = None
    capability_status: str = "PROTOTYPE"
    limitation: str = "Caller-supplied constraint only; source branch tracing and concrete path replay are not implemented."


class ConcolicGenerator:
    """Solves caller-supplied branch constraints with existing SMT; caller must provide instrumentation."""
    capability_status = "PROTOTYPE"

    def __init__(self, verifier: SMTVerifier | None = None) -> None:
        self.verifier = verifier or SMTVerifier()

    def solve_alternate(self, constraint: BranchConstraint, *, minimum: int = -1000000,
                        maximum: int = 1000000) -> ConcolicResult:
        if constraint.operator == constraint.current_path_operator:
            return ConcolicResult(False, "CONCOLIC_TARGET_UNSUPPORTED")
        spec = Specification(schema_version="1.0", id="concolic-path", name="Concolic path constraint",
                             variables=(Variable(constraint.variable, Domain(type="integer", minimum=minimum, maximum=maximum)),))
        check = self.verifier.check(spec, constraint.alternate_expression(), query_intent=QueryIntent.SATISFIABILITY)
        if check.solver_outcome is not SolverOutcome.SAT or check.backend_result.model is None:
            return ConcolicResult(True, "CONCOLIC_NO_SOLUTION", solver_outcome=check.solver_outcome.value)
        assignment = check.backend_result.model.assignments[0]
        return ConcolicResult(True, "CONCOLIC_CANDIDATE", {assignment.variable: assignment.value}, check.solver_outcome.value)
