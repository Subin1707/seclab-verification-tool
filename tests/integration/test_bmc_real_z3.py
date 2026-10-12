from __future__ import annotations

import hashlib

import pytest

from seclab.evidence import ArtifactStore
from seclab.formal.bmc import BMCChecker
from seclab.formal.ctl import check as ctl_check, parse_ctl
from seclab.formal.smt import SolverOutcome
from seclab.model import KripkeStructure, State, Transition
from seclab.results import VerificationStatus


def _linear(*, error_at_end: bool) -> KripkeStructure:
    states = [
        State("S0", {"value": 0}, {"safe"}),
        State("S1", {"value": 1}, {"safe"}),
        State("S2", {"value": 2}, {"error"} if error_at_end else {"safe"}),
    ]
    if not error_at_end:
        states.append(State("UNREACHABLE", labels={"error"}))
    transitions = (Transition("S0", "S1", id="T01"), Transition("S1", "S2", id="T12"), Transition("S2", "S2", id="T22"))
    return KripkeStructure(tuple(states), ("S0",), transitions)


def test_real_z3_finds_shortest_bounded_trace_and_persists_evidence(tmp_path) -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    model = _linear(error_at_end=True)
    store = ArtifactStore(tmp_path)
    checker = BMCChecker()

    at_zero = checker.check_up_to_bound(model, 0, "error")
    at_one = checker.check_up_to_bound(model, 1, "error")
    found = checker.check_up_to_bound(model, 4, "error", artifact_store=store, property_id="P-error")

    assert at_zero.solver_outcome is SolverOutcome.UNSAT and not at_zero.complete
    assert at_one.solver_outcome is SolverOutcome.UNSAT and not at_one.complete
    assert found.solver_outcome is SolverOutcome.SAT
    assert found.result.status is VerificationStatus.FAIL
    assert found.result.reason_code == "BOUNDED_COUNTEREXAMPLE_FOUND"
    assert found.checked_bound == 2
    assert found.complete  # structural threshold reached; SAT still means FAIL
    assert found.trace is not None and found.trace.violating_step == 2
    assert [step.state_id for step in found.trace.states] == ["S0", "S1", "S2"]
    assert found.trace.states[-1].to_dict()["values"] == {"value": 2}
    assert found.trace.transitions[1].transition_id == "T12"
    assert any(item.type.value == "COUNTEREXAMPLE" for item in found.evidence)
    for item in found.evidence:
        assert hashlib.sha256((tmp_path / item.path).read_bytes()).hexdigest() == item.hash
    assert {entry["id"] for entry in found.result.metadata["evidence"]} == set(found.result.evidence_ids)


def test_real_z3_incomplete_unsat_is_inconclusive_and_complete_unsat_passes(tmp_path) -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    model = _linear(error_at_end=False)
    checker = BMCChecker()
    incomplete_zero = checker.check_up_to_bound(model, 0, "error")
    incomplete = checker.check_up_to_bound(model, 1, "error", artifact_store=ArtifactStore(tmp_path))
    complete = checker.check_up_to_bound(model, 8, "error", artifact_store=ArtifactStore(tmp_path))

    assert incomplete_zero.result.status is VerificationStatus.INCONCLUSIVE
    assert incomplete.solver_outcome is SolverOutcome.UNSAT
    assert incomplete.result.status is VerificationStatus.INCONCLUSIVE
    assert incomplete.result.reason_code == "NO_COUNTEREXAMPLE_WITHIN_BOUND"
    assert incomplete.completeness_threshold == 2 and not incomplete.complete
    assert complete.solver_outcome is SolverOutcome.UNSAT
    assert complete.result.status is VerificationStatus.PASS
    assert complete.result.reason_code == "NO_REACHABLE_VIOLATION"
    assert complete.checked_bound == 2 and complete.complete
    assert any(item.path.startswith("evidence/bmc/completeness-") for item in complete.evidence)
    exact_complete = BMCChecker().check_at_bound(model, 2, "error")
    assert exact_complete.result.status is VerificationStatus.PASS
    assert exact_complete.complete


def test_bad_initial_state_is_sat_at_zero_with_no_edges() -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    model = KripkeStructure((State("ERROR", labels={"error"}),), ("ERROR",), ())
    result = BMCChecker().check_up_to_bound(model, 0, "error")
    assert result.result.status is VerificationStatus.FAIL
    assert result.trace is not None and result.trace.bound == 0
    assert len(result.trace.states) == 1 and result.trace.transitions == ()


def test_bmc_and_ctl_agree_on_safe_and_violating_complete_graphs() -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    checker = BMCChecker()
    violating_model = _linear(error_at_end=True)
    safe_model = _linear(error_at_end=False)

    ctl_violating = ctl_check(violating_model, parse_ctl("AG(!error)"))
    bmc_violating = checker.check_up_to_bound(violating_model, 2, "error")
    ctl_safe = ctl_check(safe_model, parse_ctl("AG(!error)"))
    bmc_safe = checker.check_up_to_bound(safe_model, 2, "error")

    assert not ctl_violating.satisfied and bmc_violating.result.status is VerificationStatus.FAIL
    assert ctl_safe.satisfied and bmc_safe.result.status is VerificationStatus.PASS


def test_real_z3_supports_multiple_initial_and_branching_paths() -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    model = KripkeStructure(
        (State("I0", labels={"safe"}), State("I1", labels={"safe"}), State("OK", labels={"safe"}), State("BAD", labels={"error"})),
        ("I0", "I1"),
        (Transition("I0", "OK"), Transition("I1", "BAD"), Transition("OK", "OK"), Transition("BAD", "BAD")),
    )
    result = BMCChecker().check_up_to_bound(model, 4, "error")
    assert result.result.status is VerificationStatus.FAIL
    assert result.checked_bound == 1
    assert result.trace is not None
    assert [step.state_id for step in result.trace.states] == ["I1", "BAD"]


def test_real_z3_terminates_on_cycle_and_finds_exit_to_bad_state() -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    model = KripkeStructure(
        (State("A", labels={"safe"}), State("B", labels={"safe"}), State("ERR", labels={"error"})),
        ("A",),
        (Transition("A", "B"), Transition("B", "A"), Transition("B", "ERR"), Transition("ERR", "ERR")),
    )
    result = BMCChecker().check_up_to_bound(model, 20, "error")
    assert result.result.status is VerificationStatus.FAIL
    assert result.checked_bound == 2
    assert result.trace is not None
    assert [step.state_id for step in result.trace.states] == ["A", "B", "ERR"]
