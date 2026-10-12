"""Production Z3 backend and semantic adapter for SMT queries."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Protocol

from seclab.specification.schema import Specification

from .ast import Binary, Expr, Literal, Unary, Variable
from .counterexample import Counterexample, ModelAssignment
from .encoder import EncodedQuery, QueryIntent, SMTEncoder
from .errors import SMTError, SMTErrorCode
from .evaluator import validate_model
from .validator import ValueType


class SolverOutcome(StrEnum):
    SAT = "SAT"
    UNSAT = "UNSAT"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class BackendResult:
    outcome: SolverOutcome
    model: Counterexample | None = None
    raw_output: str = ""
    reason: str | None = None
    backend: str = "unknown"
    version: str | None = None


class SolverBackend(Protocol):
    def solve(self, query: EncodedQuery, specification: Specification | None = None, *, timeout_seconds: float | None = None) -> BackendResult: ...


class Z3SolverBackend:
    """Z3 through the declared z3-solver Python package; no shell parsing."""

    name = "z3-python"

    def solve(self, query: EncodedQuery, specification: Specification | None = None, *, timeout_seconds: float | None = None) -> BackendResult:
        try:
            import z3
        except ImportError:
            return BackendResult(SolverOutcome.ERROR, raw_output="", reason="SOLVER_NOT_FOUND", backend=self.name)
        started = time.monotonic()
        try:
            variables, solver = self._build(z3, query, timeout_seconds)
            for _, constraint in query.constraints:
                solver.add(self._compile(z3, constraint, variables))
            solver.add(self._compile(z3, query.query_expression, variables))
            outcome = solver.check()
            elapsed = time.monotonic() - started
            if outcome == z3.sat:
                model = solver.model()
                cex = _counterexample(z3, model, variables, dict(query.variable_types))
                return BackendResult(SolverOutcome.SAT, cex, str(model), backend=self.name, version=z3.get_version_string())
            if outcome == z3.unsat:
                return BackendResult(SolverOutcome.UNSAT, raw_output="unsat", backend=self.name, version=z3.get_version_string())
            why = solver.reason_unknown()
            timed_out = "timeout" in why.lower() or timeout_seconds is not None and (
                "canceled" in why.lower() or elapsed >= timeout_seconds * 0.95
            )
            return BackendResult(SolverOutcome.UNKNOWN, raw_output=why, reason="SOLVER_TIMEOUT" if timed_out else "SOLVER_UNKNOWN", backend=self.name, version=z3.get_version_string())
        except SMTError:
            raise
        except Exception as exc:  # backend/API failures are infrastructure errors
            return BackendResult(SolverOutcome.ERROR, raw_output=f"{type(exc).__name__}: {exc}", reason="SOLVER_ERROR", backend=self.name)

    def _build(self, z3: Any, query: EncodedQuery, timeout_seconds: float | None) -> tuple[dict[str, Any], Any]:
        solver = z3.Solver()
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise SMTError(SMTErrorCode.SOLVER_TIMEOUT, "timeout_seconds must be positive.")
            solver.set(timeout=max(1, int(timeout_seconds * 1000)))
        sorts = {
            ValueType.BOOL: z3.BoolSort,
            ValueType.INT: z3.IntSort,
            ValueType.REAL: z3.RealSort,
            ValueType.STRING: z3.StringSort,
        }
        symbols = dict(query.variable_mapping)
        kinds = dict(query.variable_types)
        variables = {name: z3.Const(symbols[name], sorts[kind]()) for name, kind in query.variable_types}
        finite: dict[str, list[Any]] = {}
        for name, op, value in query.domain_constraints:
            variable = variables[name]
            if op == ">=":
                solver.add(variable >= self._literal(z3, value, kinds[name]))
            elif op == "<=":
                solver.add(variable <= self._literal(z3, value, kinds[name]))
            else:
                finite.setdefault(name, []).append(variable == self._literal(z3, value, kinds[name]))
        for choices in finite.values():
            solver.add(z3.Or(*choices))
        return variables, solver

    def _compile(self, z3: Any, expr: Expr, variables: dict[str, Any]) -> Any:
        if isinstance(expr, Literal):
            return self._literal(z3, expr.value, None)
        if isinstance(expr, Variable):
            return variables[expr.name]
        if isinstance(expr, Unary):
            value = self._compile(z3, expr.operand, variables)
            return z3.Not(value) if expr.op == "!" else -value
        if isinstance(expr, Binary):
            left, right = self._compile(z3, expr.left, variables), self._compile(z3, expr.right, variables)
            return {
                "&&": lambda: z3.And(left, right), "||": lambda: z3.Or(left, right), "->": lambda: z3.Implies(left, right),
                "==": lambda: left == right, "!=": lambda: left != right, "<": lambda: left < right,
                "<=": lambda: left <= right, ">": lambda: left > right, ">=": lambda: left >= right,
                "+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right,
            }[expr.op]()
        raise TypeError(f"Unsupported AST node {type(expr).__name__}.")

    @staticmethod
    def _literal(z3: Any, value: Any, expected: ValueType | None) -> Any:
        if isinstance(value, bool):
            return z3.BoolVal(value)
        if isinstance(value, int):
            return z3.RealVal(value) if expected is ValueType.REAL else z3.IntVal(value)
        if isinstance(value, float):
            return z3.RealVal(str(value))
        if isinstance(value, str):
            return z3.StringVal(value)
        raise TypeError(f"Unsupported literal {value!r}.")


@dataclass(frozen=True, slots=True)
class SMTCheck:
    solver_outcome: SolverOutcome
    query_intent: QueryIntent
    result: Any
    query: EncodedQuery
    backend_result: BackendResult
    duration_ms: float
    evidence: tuple[Any, ...] = ()


class SMTVerifier:
    def __init__(self, backend: SolverBackend | None = None, encoder: SMTEncoder | None = None) -> None:
        self.backend = backend or Z3SolverBackend()
        self.encoder = encoder or SMTEncoder()

    def check(
        self,
        specification: Specification,
        property_expression: str,
        *,
        query_intent: QueryIntent = QueryIntent.VIOLATION_SEARCH,
        property_id: str | None = None,
        requirement_id: str | None = None,
        timeout_seconds: float | None = None,
        artifact_store: Any | None = None,
    ) -> SMTCheck:
        from seclab.results.classifier import ClassificationInput, RawOutcome, ResultClassifier

        started = time.monotonic()
        query = self.encoder.encode(specification, property_expression, query_intent=query_intent)
        backend_result = self.backend.solve(query, specification, timeout_seconds=timeout_seconds)
        duration_ms = (time.monotonic() - started) * 1000
        if backend_result.outcome is SolverOutcome.SAT:
            valid, validation_error = validate_model(query, backend_result.model)
            if not valid:
                backend_result = replace(backend_result, outcome=SolverOutcome.ERROR,
                                         reason="SOLVER_INVALID_MODEL",
                                         raw_output=(backend_result.raw_output + "\n" + (validation_error or "Invalid model.")))
        evidence: list[Any] = []
        if artifact_store is not None:
            evidence.extend(_store_evidence(artifact_store, query, backend_result, duration_ms, property_id, requirement_id))
        evidence_ids = tuple(item.id for item in evidence)
        model = backend_result.model.to_dict() if backend_result.model is not None else None
        outcome_map = {
            SolverOutcome.SAT: RawOutcome.PROPERTY_VIOLATED if query.query_intent is QueryIntent.VIOLATION_SEARCH else RawOutcome.UNKNOWN,
            SolverOutcome.UNSAT: RawOutcome.PROPERTY_SATISFIED if query.query_intent is QueryIntent.VIOLATION_SEARCH else RawOutcome.UNKNOWN,
            SolverOutcome.UNKNOWN: RawOutcome.TIMEOUT if backend_result.reason == "SOLVER_TIMEOUT" else RawOutcome.UNKNOWN,
            SolverOutcome.ERROR: RawOutcome.TOOL_FAILED,
        }
        reason = {
            (SolverOutcome.SAT, QueryIntent.VIOLATION_SEARCH): ("PROPERTY_VIOLATED", "A satisfying assignment violates the property."),
            (SolverOutcome.UNSAT, QueryIntent.VIOLATION_SEARCH): ("NO_VIOLATION_IN_SMT_SCOPE", "No violation exists in the encoded SMT scope."),
        }.get((backend_result.outcome, query.query_intent))
        if reason is None and backend_result.outcome is SolverOutcome.UNKNOWN:
            reason = (backend_result.reason or "SOLVER_UNKNOWN", "The solver did not determine the query result.")
        if reason is None and backend_result.outcome is SolverOutcome.ERROR:
            reason = (backend_result.reason or "SOLVER_ERROR", "The solver backend failed.")
        if reason is None:
            reason = ("QUERY_INTENT_UNCLASSIFIED", "Solver result is not a property verdict for this query intent.")
        classified = ResultClassifier().classify(ClassificationInput(
            outcome=outcome_map[backend_result.outcome], stage="FORMAL", technique="SMT",
            reason_code=reason[0], message=reason[1], requirement_id=requirement_id, property_id=property_id,
            source=backend_result.backend, scope="One valuation over declared variable domains satisfying every specification constraint.",
            evidence_ids=evidence_ids, counterexample=model if backend_result.outcome is SolverOutcome.SAT and query.query_intent is QueryIntent.VIOLATION_SEARCH else None,
            duration_ms=duration_ms,
            metadata={"solver_outcome": backend_result.outcome.value, "query_intent": query.query_intent.value,
                      "backend": backend_result.backend, "backend_version": backend_result.version, "solver_reason": backend_result.reason,
                      "evidence": [{"id": item.id, "path": item.path, "sha256": item.hash} for item in evidence]},
        ))
        return SMTCheck(backend_result.outcome, query.query_intent, classified, query, backend_result, duration_ms, tuple(evidence))


def _counterexample(z3: Any, model: Any, variables: dict[str, Any], types: dict[str, ValueType]) -> Counterexample:
    assignments: list[ModelAssignment] = []
    for name in sorted(variables):
        value = model.eval(variables[name], model_completion=True)
        kind = types[name]
        if kind is ValueType.BOOL:
            converted: bool | int | float | str = z3.is_true(value)
        elif kind is ValueType.INT:
            converted = value.as_long()
        elif kind is ValueType.REAL:
            if z3.is_rational_value(value):
                rational = value.as_fraction()
                converted = float(rational) if rational.denominator == 1 else f"{rational.numerator}/{rational.denominator}"
            else:
                converted = value.as_decimal(20).removesuffix("?")
        else:
            converted = value.as_string()
        assignments.append(ModelAssignment(name, converted, kind.value))
    return Counterexample(tuple(assignments))


def _store_evidence(store: Any, query: EncodedQuery, result: BackendResult, duration_ms: float,
                    property_id: str | None, requirement_id: str | None) -> list[Any]:
    import uuid

    from seclab.evidence.evidence import EvidenceType

    token = uuid.uuid4().hex
    query_artifact = store.write_json("smt", f"query-{token}.json", query.to_dict(), evidence_type=EvidenceType.SPECIFICATION,
                                     property_id=property_id, requirement_id=requirement_id,
                                     metadata={"query_intent": query.query_intent.value})
    outcome_data = {"solver_outcome": result.outcome.value, "reason": result.reason, "backend": result.backend,
                    "backend_version": result.version, "query_intent": query.query_intent.value,
                    "duration_ms": duration_ms,
                    "model": result.model.to_dict() if result.model else None,
                    "query_evidence_id": query_artifact.id, "query_sha256": query_artifact.hash}
    outcome_artifact = store.write_json("smt", f"outcome-{token}.json", outcome_data, evidence_type=EvidenceType.TEST_RESULT,
                                        property_id=property_id, requirement_id=requirement_id,
                                        metadata={"query_evidence_id": query_artifact.id, "query_sha256": query_artifact.hash,
                                                  "backend": result.backend, "backend_version": result.version,
                                                  "solver_outcome": result.outcome.value, "duration_ms": duration_ms})
    raw_artifact = store.write_text("smt", f"solver-{token}.txt", result.raw_output or result.outcome.value,
                                    evidence_type=EvidenceType.LOG, property_id=property_id,
                                    requirement_id=requirement_id,
                                    metadata={"backend": result.backend, "backend_version": result.version,
                                              "solver_outcome": result.outcome.value})
    artifacts = [query_artifact, outcome_artifact, raw_artifact]
    if result.outcome is SolverOutcome.SAT and result.model is not None:
        model_evidence_type = (
            EvidenceType.COUNTEREXAMPLE if query.query_intent is QueryIntent.VIOLATION_SEARCH else EvidenceType.WITNESS
        )
        artifacts.append(store.write_json("smt", f"model-{token}.json", result.model.to_dict(),
                                          evidence_type=model_evidence_type, property_id=property_id,
                                          requirement_id=requirement_id,
                                          metadata={"query_sha256": query_artifact.hash, "outcome_sha256": outcome_artifact.hash}))
    return artifacts
