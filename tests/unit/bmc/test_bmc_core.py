from __future__ import annotations

import pytest

from seclab.formal.bmc import (
    BMCChecker, BMCEncoder, BMCError, BMCErrorCode, BMCQueryMode,
    analyze_completeness, decode_trace,
)
from seclab.formal.smt import BackendResult, SolverOutcome
from seclab.model import KripkeStructure, State, Transition
from seclab.results import VerificationStatus


def linear(*, bad: bool = True) -> KripkeStructure:
    states = (
        State("S0", {"n": 0}, {"safe"}),
        State("S1", {"n": 1}, {"safe"}),
        State("S2", {"n": 2}, {"error" if bad else "safe"}),
    )
    return KripkeStructure(states, ("S0",), (
        Transition("S0", "S1", id="T01"), Transition("S1", "S2", id="T12"),
        Transition("S2", "S2", id="T22"),
    ))


def test_encoder_builds_deterministic_state_transition_and_bad_state_formula() -> None:
    model = linear()
    query = BMCEncoder().encode(model, 2, "error")
    assert query.state_mapping == (("S0", 0), ("S1", 1), ("S2", 2))
    assert query.solver_query.variable_types == (("state_0", "integer"), ("state_1", "integer"), ("state_2", "integer"))
    assert len(query.solver_query.constraints) == 3  # one initial + two transitions
    assert len(query.solver_query.domain_constraints) == 6
    data = query.to_dict()
    assert data["bound"] == 2
    assert data["bound_semantics"].startswith("number of transition steps")
    assert data["transition_pairs"][-1] == {"source": "S2", "target": "S2"}
    assert "canonical model" in data["guard_action_semantics"]
    assert data["model_hash"] == model.model_hash
    assert "one valuation" not in data["solver_query"]["scope"]
    assert any(item["transition_id"] == "T01" for item in data["transition_metadata"])


def test_completeness_is_max_shortest_distance_and_ignores_unreachable_states() -> None:
    model = KripkeStructure(
        (State("A", labels={"safe"}), State("B", labels={"safe"}), State("C", labels={"safe"}), State("Z", labels={"error"})),
        ("A",), (Transition("A", "B"), Transition("B", "C"), Transition("C", "B")),
    )
    analysis = analyze_completeness(model)
    assert analysis.distances == (("A", 0), ("B", 1), ("C", 2))
    assert analysis.reachable_state_ids == ("A", "B", "C")
    assert analysis.threshold == 2


def test_completeness_handles_branching_cycles_and_multiple_initials() -> None:
    model = KripkeStructure(
        tuple(State(name) for name in ("A", "B", "C", "D", "Z")),
        ("A", "D"),
        (Transition("A", "B"), Transition("A", "C"), Transition("B", "A"), Transition("C", "D")),
    )
    analysis = analyze_completeness(model)
    assert analysis.distances == (("A", 0), ("B", 1), ("C", 1), ("D", 0))
    assert analysis.threshold == 1


def test_deadlock_totalization_is_query_local_and_trace_records_virtual_loop() -> None:
    model = KripkeStructure((State("dead", labels={"error"}),), ("dead",), ())
    assert model.transitions == ()  # source graph is not mutated
    query = BMCEncoder().encode(model, 1, "error")
    assert query.transition_pairs == (("dead", "dead"),)
    result = BMCChecker().check_at_bound(model, 1, "error")
    assert result.solver_outcome is SolverOutcome.SAT
    assert result.result.status is VerificationStatus.FAIL
    assert result.trace is not None
    assert result.trace.transitions[0].virtual_deadlock
    assert result.trace.to_dict()["states"][0]["values"] == {}


def test_bound_zero_detects_bad_initial_state_with_one_state_trace() -> None:
    model = KripkeStructure((State("BAD", labels={"error"}),), ("BAD",), ())
    result = BMCChecker().check_up_to_bound(model, 0, "error")
    assert result.solver_outcome is SolverOutcome.SAT
    assert result.result.status is VerificationStatus.FAIL
    assert result.trace is not None
    assert result.trace.bound == 0 and len(result.trace.states) == 1
    assert result.trace.violating_step == 0


@pytest.mark.parametrize("bound", [-1, True, 1.5])
def test_invalid_bounds_are_rejected(bound) -> None:
    with pytest.raises(BMCError) as caught:
        BMCChecker().check_up_to_bound(linear(), bound, "error")
    assert caught.value.code is BMCErrorCode.INVALID_BMC_BOUND


def test_unknown_label_empty_model_and_bad_trace_are_rejected() -> None:
    with pytest.raises(BMCError) as unknown:
        BMCChecker().check_up_to_bound(linear(), 1, "missing")
    assert unknown.value.code is BMCErrorCode.UNKNOWN_PROPOSITION
    with pytest.raises(BMCError) as empty:
        BMCChecker().check_up_to_bound(KripkeStructure((), (), ()), 0, "missing")
    assert empty.value.code is BMCErrorCode.EMPTY_MODEL
    with pytest.raises(BMCError) as invalid_trace:
        decode_trace(linear(), ("S0", "S2"), "error", 1)
    assert invalid_trace.value.code is BMCErrorCode.INVALID_TRACE


class _UnknownBackend:
    def solve(self, query, specification=None, *, timeout_seconds=None):
        return BackendResult(SolverOutcome.UNKNOWN, raw_output="incomplete", reason="SOLVER_UNKNOWN", backend="unit-backend")


class _FixedBackend:
    def __init__(self, result: BackendResult) -> None:
        self.result = result

    def solve(self, query, specification=None, *, timeout_seconds=None):
        return self.result


def test_unknown_solver_outcome_is_inconclusive() -> None:
    single_state_model = KripkeStructure((State("S", labels={"error"}),), ("S",), ())
    result = BMCChecker(backend=_UnknownBackend()).check_up_to_bound(single_state_model, 0, "error")
    assert result.solver_outcome is SolverOutcome.UNKNOWN
    assert result.result.status is VerificationStatus.INCONCLUSIVE
    assert result.result.reason_code == "BMC_SOLVER_UNKNOWN"
    assert result.complete  # threshold coverage does not turn UNKNOWN into PASS


def test_timeout_solver_error_and_missing_model_classification() -> None:
    model = linear()
    timeout = BMCChecker(backend=_FixedBackend(BackendResult(
        SolverOutcome.UNKNOWN, reason="SOLVER_TIMEOUT", backend="unit-backend",
    ))).check_up_to_bound(model, 2, "error")
    assert timeout.result.status is VerificationStatus.INCONCLUSIVE
    assert timeout.result.reason_code == "BMC_SOLVER_TIMEOUT"
    solver_error = BMCChecker(backend=_FixedBackend(BackendResult(
        SolverOutcome.ERROR, reason="SOLVER_ERROR", backend="unit-backend",
    ))).check_up_to_bound(model, 2, "error")
    assert solver_error.result.status is VerificationStatus.TOOL_ERROR
    no_model = BMCChecker(backend=_FixedBackend(BackendResult(
        SolverOutcome.SAT, raw_output="sat", backend="unit-backend",
    ))).check_up_to_bound(model, 2, "error")
    assert no_model.solver_outcome is SolverOutcome.SAT
    assert no_model.result.status is VerificationStatus.TOOL_ERROR
    assert no_model.result.reason_code == "BMC_TRACE_VALIDATION_ERROR"
