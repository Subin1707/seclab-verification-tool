"""SMT-backed bounded bad-state reachability for finite Kripke models."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from seclab.evidence.evidence import EvidenceType
from seclab.formal.smt.counterexample import Counterexample
from seclab.formal.smt.encoder import EncodedQuery
from seclab.formal.smt.solver import BackendResult, SolverBackend, SolverOutcome, Z3SolverBackend
from seclab.model.kripke import KripkeStructure
from seclab.results.classifier import ClassificationInput, RawOutcome, ResultClassifier
from seclab.results.result import VerificationResult

from .completeness import CompletenessAnalysis, analyze_completeness
from .encoder import BMCEncodedQuery, BMCEncoder, BMCQueryMode
from .errors import BMCError, BMCErrorCode
from .trace import BMCTrace, decode_trace


@dataclass(frozen=True, slots=True)
class BMCCheckResult:
    solver_outcome: SolverOutcome
    query_mode: BMCQueryMode
    requested_bound: int
    checked_bound: int
    completeness_threshold: int
    complete: bool
    trace: BMCTrace | None
    duration_ms: float
    verification_result: VerificationResult
    completeness: CompletenessAnalysis
    evidence: tuple[Any, ...] = ()
    attempts: tuple[tuple[int, SolverOutcome], ...] = ()

    @property
    def result(self) -> VerificationResult:
        return self.verification_result

    @property
    def query_intent(self) -> str:
        return "BOUNDED_BAD_STATE_REACHABILITY"

    @property
    def limitations(self) -> tuple[str, ...]:
        return (
            "Explicit canonical Kripke graph only; source-program execution semantics are not encoded.",
            "No C program or temporal execution semantics are encoded.",
        )


class BMCChecker:
    def __init__(
        self,
        backend: SolverBackend | None = None,
        encoder: BMCEncoder | None = None,
        classifier: ResultClassifier | None = None,
    ) -> None:
        self.backend = backend or Z3SolverBackend()
        self.encoder = encoder or BMCEncoder()
        self.classifier = classifier or ResultClassifier()

    def check_at_bound(
        self,
        model: KripkeStructure,
        bound: int,
        bad_proposition: str,
        *,
        timeout_seconds: float | None = None,
        artifact_store: Any | None = None,
        property_id: str | None = None,
        requirement_id: str | None = None,
    ) -> BMCCheckResult:
        """Check a path with exactly `bound` transitions for any bad prefix state."""
        query = self.encoder.encode(model, bound, bad_proposition, query_mode=BMCQueryMode.EXACT_BOUND)
        completeness = analyze_completeness(model)
        return self._run(
            model, query, query_mode=BMCQueryMode.EXACT_BOUND, requested_bound=bound,
            checked_bound=bound, completeness=completeness, timeout_seconds=timeout_seconds,
            artifact_store=artifact_store, property_id=property_id, requirement_id=requirement_id,
        )

    def check_up_to_bound(
        self,
        model: KripkeStructure,
        bound: int,
        bad_proposition: str,
        *,
        timeout_seconds: float | None = None,
        artifact_store: Any | None = None,
        property_id: str | None = None,
        requirement_id: str | None = None,
    ) -> BMCCheckResult:
        """Search depth 0..bound; stop at the first SAT result (shortest depth)."""
        # Validate before completeness so invalid bounds/propositions cannot be
        # hidden by an unrelated model-shape error.
        if isinstance(bound, bool) or not isinstance(bound, int) or bound < 0:
            raise BMCError(BMCErrorCode.INVALID_BMC_BOUND, "bound must be a non-negative integer number of transition steps.")
        self.encoder.encode(model, 0, bad_proposition, query_mode=BMCQueryMode.UP_TO_BOUND)
        completeness = analyze_completeness(model)
        maximum_depth = min(bound, completeness.threshold)
        all_evidence: list[Any] = []
        attempts: list[tuple[int, SolverOutcome]] = []
        total_started = time.monotonic()
        last: BMCCheckResult | None = None
        for depth in range(maximum_depth + 1):
            query = self.encoder.encode(model, depth, bad_proposition, query_mode=BMCQueryMode.EXACT_BOUND)
            last = self._run(
                model, query, query_mode=BMCQueryMode.UP_TO_BOUND, requested_bound=bound,
                checked_bound=depth, completeness=completeness, timeout_seconds=timeout_seconds,
                artifact_store=artifact_store, property_id=property_id, requirement_id=requirement_id,
            )
            all_evidence.extend(last.evidence)
            attempts.append((depth, last.solver_outcome))
            if last.solver_outcome is not SolverOutcome.UNSAT:
                return self._with_aggregate(
                    last, query_mode=BMCQueryMode.UP_TO_BOUND, requested_bound=bound,
                    checked_bound=depth, duration_ms=(time.monotonic() - total_started) * 1000,
                    evidence=tuple(all_evidence), attempts=tuple(attempts),
                )

        assert last is not None  # maximum_depth is at least zero for a valid finite model.
        complete = bound >= completeness.threshold
        raw = ClassificationInput(
            outcome=RawOutcome.PROPERTY_SATISFIED if complete else RawOutcome.UNKNOWN,
            stage="FORMAL", technique="BMC",
            reason_code="NO_REACHABLE_VIOLATION" if complete else "NO_COUNTEREXAMPLE_WITHIN_BOUND",
            message=(
                "No bad state is reachable in the finite explicit Kripke model; the checked bound reached the reachability completeness threshold."
                if complete else "No bounded counterexample was found within the checked bound; completeness has not been reached."
            ),
            property_id=property_id, requirement_id=requirement_id, source=last.result.source,
            scope=_scope(bound, completeness.threshold, complete),
            evidence_ids=tuple(item.id for item in all_evidence),
            duration_ms=(time.monotonic() - total_started) * 1000,
            metadata={
                "solver_outcome": SolverOutcome.UNSAT.value, "query_mode": BMCQueryMode.UP_TO_BOUND.value,
                "requested_bound": bound, "checked_bound": maximum_depth,
                "completeness_threshold": completeness.threshold, "complete": complete,
                "attempts": [{"depth": depth, "solver_outcome": outcome.value} for depth, outcome in attempts],
                "evidence": _evidence_refs(all_evidence),
            },
        )
        result = self.classifier.classify(raw)
        return BMCCheckResult(
            SolverOutcome.UNSAT, BMCQueryMode.UP_TO_BOUND, bound, maximum_depth,
            completeness.threshold, complete, None, (time.monotonic() - total_started) * 1000,
            result, completeness, tuple(all_evidence), tuple(attempts),
        )

    def _run(
        self,
        model: KripkeStructure,
        query: BMCEncodedQuery,
        *,
        query_mode: BMCQueryMode,
        requested_bound: int,
        checked_bound: int,
        completeness: CompletenessAnalysis,
        timeout_seconds: float | None,
        artifact_store: Any | None,
        property_id: str | None,
        requirement_id: str | None,
    ) -> BMCCheckResult:
        started = time.monotonic()
        backend_result = self.backend.solve(query.solver_query, None, timeout_seconds=timeout_seconds)
        duration = (time.monotonic() - started) * 1000
        evidence: list[Any] = []
        if artifact_store is not None:
            evidence.extend(_store_attempt(artifact_store, query, backend_result, duration, property_id, requirement_id))
            search_complete = checked_bound >= completeness.threshold
            evidence.append(_store_completeness(artifact_store, completeness, requested_bound, checked_bound,
                                                search_complete, property_id, requirement_id))
        trace: BMCTrace | None = None
        if backend_result.outcome is SolverOutcome.SAT:
            try:
                state_ids = _decode_state_ids(backend_result.model, query)
                trace = decode_trace(model, state_ids, query.bad_proposition, query.bound)
            except BMCError as exc:
                raw = ClassificationInput(
                    outcome=RawOutcome.TOOL_FAILED, stage="FORMAL", technique="BMC",
                    reason_code="BMC_TRACE_VALIDATION_ERROR", message=str(exc),
                    property_id=property_id, requirement_id=requirement_id, source=backend_result.backend,
                    scope=(
                        f"The bounded SMT query returned SAT through depth {checked_bound}, but its model did not decode to a validated Kripke trace."
                    ),
                    evidence_ids=tuple(item.id for item in evidence), duration_ms=duration,
                    metadata={"solver_outcome": backend_result.outcome.value, "error_code": exc.code.value,
                              "query_mode": query_mode.value, "checked_bound": checked_bound,
                              "completeness_threshold": completeness.threshold,
                              "complete": checked_bound >= completeness.threshold,
                              "evidence": _evidence_refs(evidence)},
                )
                result = self.classifier.classify(raw)
                return BMCCheckResult(backend_result.outcome, query_mode, requested_bound, checked_bound,
                                      completeness.threshold, checked_bound >= completeness.threshold,
                                      None, duration, result, completeness,
                                      tuple(evidence), ((query.bound, backend_result.outcome),))

        complete = checked_bound >= completeness.threshold
        if backend_result.outcome is SolverOutcome.SAT:
            outcome, reason_code, message = RawOutcome.PROPERTY_VIOLATED, "BOUNDED_COUNTEREXAMPLE_FOUND", "A bad state is reachable within the encoded bounded path."
        elif backend_result.outcome is SolverOutcome.UNSAT:
            outcome = RawOutcome.PROPERTY_SATISFIED if complete else RawOutcome.UNKNOWN
            reason_code = "NO_REACHABLE_VIOLATION" if complete else "NO_COUNTEREXAMPLE_WITHIN_BOUND"
            message = (
                "No bad state is reachable in the finite explicit Kripke model; the checked bound reached the reachability completeness threshold."
                if complete else "No bounded counterexample was found within the checked bound; completeness has not been reached."
            )
        elif backend_result.outcome is SolverOutcome.UNKNOWN:
            outcome = RawOutcome.TIMEOUT if backend_result.reason == "SOLVER_TIMEOUT" else RawOutcome.UNKNOWN
            reason_code = "BMC_SOLVER_TIMEOUT" if outcome is RawOutcome.TIMEOUT else "BMC_SOLVER_UNKNOWN"
            message = "The SMT solver did not decide the bounded reachability query."
        else:
            outcome, reason_code, message = RawOutcome.TOOL_FAILED, backend_result.reason or "BMC_SOLVER_ERROR", "The SMT backend failed during bounded reachability checking."
        if backend_result.outcome is SolverOutcome.SAT and artifact_store is not None and trace is not None:
            evidence.append(_store_trace(artifact_store, trace, property_id, requirement_id))
        raw = ClassificationInput(
            outcome=outcome, stage="FORMAL", technique="BMC", reason_code=reason_code,
            message=message, property_id=property_id, requirement_id=requirement_id,
            source=backend_result.backend,
            scope=_scope(requested_bound, completeness.threshold, complete, backend_result.outcome),
            evidence_ids=tuple(item.id for item in evidence),
            counterexample=trace.to_dict() if trace is not None else None, duration_ms=duration,
            metadata={"solver_outcome": backend_result.outcome.value, "query_mode": query_mode.value,
                      "requested_bound": requested_bound, "checked_bound": checked_bound,
                      "completeness_threshold": completeness.threshold, "complete": complete,
                      "solver_reason": backend_result.reason, "backend": backend_result.backend,
                      "backend_version": backend_result.version, "evidence": _evidence_refs(evidence)},
        )
        result = self.classifier.classify(raw)
        return BMCCheckResult(backend_result.outcome, query_mode, requested_bound, checked_bound,
                              completeness.threshold, complete, trace, duration, result, completeness,
                              tuple(evidence), ((query.bound, backend_result.outcome),))

    @staticmethod
    def _with_aggregate(
        check: BMCCheckResult,
        *,
        query_mode: BMCQueryMode,
        requested_bound: int,
        checked_bound: int,
        duration_ms: float,
        evidence: tuple[Any, ...],
        attempts: tuple[tuple[int, SolverOutcome], ...],
    ) -> BMCCheckResult:
        result = check.result
        result = VerificationResult(
            id=result.id, stage=result.stage, technique=result.technique, status=result.status,
            reason_code=result.reason_code, message=result.message, requirement_id=result.requirement_id,
            property_id=result.property_id, source=result.source, scope=result.scope,
            evidence_ids=tuple(item.id for item in evidence), counterexample=result.counterexample,
            duration_ms=duration_ms,
            metadata={**result.to_dict()["metadata"], "requested_bound": requested_bound,
                      "checked_bound": checked_bound,
                      "attempts": [{"depth": depth, "solver_outcome": outcome.value} for depth, outcome in attempts],
                      "evidence": _evidence_refs(evidence)},
        )
        return BMCCheckResult(check.solver_outcome, query_mode, requested_bound, checked_bound,
                              check.completeness_threshold, check.complete, check.trace, duration_ms,
                              result, check.completeness, evidence, attempts)


def _decode_state_ids(model: Counterexample | None, query: BMCEncodedQuery) -> tuple[str, ...]:
    if model is None:
        raise BMCError(BMCErrorCode.SOLVER_MODEL_MISSING, "SAT outcome has no structured state-variable model.")
    assignment = {item.variable: item.value for item in model.assignments}
    indices = {index: state_id for state_id, index in query.state_mapping}
    output: list[str] = []
    for step in range(query.bound + 1):
        value = assignment.get(f"state_{step}")
        if isinstance(value, bool) or not isinstance(value, int) or value not in indices:
            raise BMCError(BMCErrorCode.INVALID_TRACE, f"Solver returned an invalid state index at step {step}.")
        output.append(indices[value])
    return tuple(output)


def _store_attempt(store: Any, query: BMCEncodedQuery, result: BackendResult, duration_ms: float,
                   property_id: str | None, requirement_id: str | None) -> list[Any]:
    token = uuid.uuid4().hex
    query_evidence = store.write_json("bmc", f"query-{query.bound}-{token}.json", query.to_dict(),
                                      evidence_type=EvidenceType.MODEL, property_id=property_id,
                                      requirement_id=requirement_id,
                                      metadata={"bound": query.bound, "query_mode": query.query_mode.value})
    outcome_evidence = store.write_json(
        "bmc", f"outcome-{query.bound}-{token}.json",
        {"solver_outcome": result.outcome.value, "reason": result.reason, "backend": result.backend,
         "backend_version": result.version, "duration_ms": duration_ms,
         "model": result.model.to_dict() if result.model else None,
         "query_evidence_id": query_evidence.id, "query_sha256": query_evidence.hash},
        evidence_type=EvidenceType.TEST_RESULT, property_id=property_id, requirement_id=requirement_id,
        metadata={"query_evidence_id": query_evidence.id, "query_sha256": query_evidence.hash,
                  "backend": result.backend, "backend_version": result.version,
                  "solver_outcome": result.outcome.value, "duration_ms": duration_ms},
    )
    raw_evidence = store.write_text("bmc", f"solver-{query.bound}-{token}.txt", result.raw_output or result.outcome.value,
                                   evidence_type=EvidenceType.LOG, property_id=property_id,
                                   requirement_id=requirement_id,
                                   metadata={"backend": result.backend, "backend_version": result.version,
                                             "solver_outcome": result.outcome.value})
    return [query_evidence, outcome_evidence, raw_evidence]


def _store_trace(store: Any, trace: BMCTrace, property_id: str | None, requirement_id: str | None) -> Any:
    token = uuid.uuid4().hex
    return store.write_json("bmc", f"counterexample-{trace.bound}-{token}.json", trace.to_dict(),
                            evidence_type=EvidenceType.COUNTEREXAMPLE, property_id=property_id,
                            requirement_id=requirement_id,
                            metadata={"bound": trace.bound, "violating_step": trace.violating_step})


def _store_completeness(store: Any, analysis: CompletenessAnalysis, requested: int, checked: int,
                        complete: bool, property_id: str | None, requirement_id: str | None) -> Any:
    token = uuid.uuid4().hex
    data = {**analysis.to_dict(), "requested_bound": requested, "checked_bound": checked, "complete": complete}
    return store.write_json("bmc", f"completeness-{token}.json", data, evidence_type=EvidenceType.TEST_RESULT,
                            property_id=property_id, requirement_id=requirement_id,
                            metadata={"threshold": analysis.threshold, "complete": complete})


def _evidence_refs(evidence: list[Any]) -> list[dict[str, str]]:
    return [{"id": item.id, "path": item.path, "sha256": item.hash} for item in evidence]


def _scope(requested_bound: int, threshold: int, complete: bool,
           outcome: SolverOutcome | None = None) -> str:
    if outcome is SolverOutcome.SAT:
        return f"The solver found a bad-state path within {requested_bound} transition steps in the finite explicit Kripke model."
    if outcome in {SolverOutcome.UNKNOWN, SolverOutcome.ERROR}:
        return f"The solver did not establish bounded bad-state reachability through {requested_bound} steps; structural completeness threshold is {threshold}."
    if complete:
        return "Bad-state reachability in the finite explicit Kripke model; the checked bound reached the graph reachability completeness threshold."
    return f"Bad-state reachability through at most {requested_bound} transition steps in the finite explicit Kripke model; completeness threshold is {threshold}."
