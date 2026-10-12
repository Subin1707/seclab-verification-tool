from __future__ import annotations

import pytest

from seclab.formal.ctl.ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, Implies, Not, Or,
)
from seclab.formal.ctl.errors import CTLError, CTLErrorCode
from seclab.formal.ctl.model_checker import check, sat, validate_counterexample
from seclab.results import VerificationStatus, classify_ctl_result
from seclab.formal.ctl.parser import parse_ctl
from seclab.model import KripkeStructure, State, Transition


@pytest.fixture
def branching_model() -> KripkeStructure:
    states = (
        State("S0", labels={"start", "safe"}),
        State("S1", labels={"running", "safe"}),
        State("S2", labels={"done", "safe"}),
        State("S3", labels={"error"}),
    )
    transitions = (
        Transition("S0", "S1"),
        Transition("S1", "S2"),
        Transition("S1", "S3"),
        Transition("S2", "S2"),
        Transition("S3", "S3"),
    )
    return KripkeStructure(states, ("S0",), transitions)


def _ids(states: set[State]) -> set[str]:
    return {state.id for state in states}


def test_atom_and_boolean_operators(branching_model: KripkeStructure) -> None:
    assert _ids(sat(branching_model, Atom("start"))) == {"S0"}
    assert _ids(sat(branching_model, Not(Atom("error")))) == {"S0", "S1", "S2"}
    assert _ids(sat(branching_model, And(Atom("safe"), Atom("running")))) == {"S1"}
    assert _ids(sat(branching_model, Or(Atom("done"), Atom("error")))) == {"S2", "S3"}
    assert _ids(sat(branching_model, Implies(Atom("error"), Atom("done")))) == {"S0", "S1", "S2"}
    assert _ids(sat(branching_model, BoolConstant(True))) == {"S0", "S1", "S2", "S3"}
    assert sat(branching_model, BoolConstant(False)) == set()


def test_ex_and_ax(branching_model: KripkeStructure) -> None:
    assert _ids(sat(branching_model, EX(Atom("done")))) == {"S1", "S2"}
    assert _ids(sat(branching_model, AX(Atom("safe")))) == {"S0", "S2"}


def test_ef_af(branching_model: KripkeStructure) -> None:
    assert _ids(sat(branching_model, EF(Atom("done")))) == {"S0", "S1", "S2"}
    assert _ids(sat(branching_model, AF(Atom("done")))) == {"S2"}


def test_eg_ag(branching_model: KripkeStructure) -> None:
    assert _ids(sat(branching_model, EG(Atom("safe")))) == {"S0", "S1", "S2"}
    assert _ids(sat(branching_model, AG(Atom("safe")))) == {"S2"}


def test_eu_and_au_on_branching_model(branching_model: KripkeStructure) -> None:
    assert _ids(sat(branching_model, EU(Atom("safe"), Atom("done")))) == {"S0", "S1", "S2"}
    assert _ids(sat(branching_model, AU(Atom("safe"), Atom("done")))) == {"S2"}


def test_fixed_points_terminate_on_a_cycle_without_goal() -> None:
    model = KripkeStructure(
        (State("C0", labels={"safe"}), State("C1", labels={"safe"}), State("C2", labels={"done"})),
        ("C0",),
        (Transition("C0", "C1"), Transition("C1", "C0"), Transition("C2", "C2")),
    )

    assert _ids(sat(model, EF(Atom("done")))) == {"C2"}
    assert _ids(sat(model, AF(Atom("done")))) == {"C2"}
    assert _ids(sat(model, EG(Atom("safe")))) == {"C0", "C1"}
    assert _ids(sat(model, EU(Atom("safe"), Atom("done")))) == {"C2"}
    assert _ids(sat(model, AU(Atom("safe"), Atom("done")))) == {"C2"}
    assert model.get_state("C0") not in sat(model, EF(Atom("done")))


def test_virtual_self_loops_define_deadlock_temporal_semantics() -> None:
    deadlocks = KripkeStructure(
        (State("D0", labels={"p"}), State("D1", labels={"q"})),
        ("D0", "D1"),
        (),
    )

    for expression in ("EX p", "AX p", "EF p", "AF p", "EG p", "AG p"):
        assert deadlocks.get_state("D0") in sat(deadlocks, parse_ctl(expression))
    for expression in ("EX p", "AX p", "EF p", "AF p"):
        assert deadlocks.get_state("D1") not in sat(deadlocks, parse_ctl(expression))
    assert deadlocks.get_state("D1") in sat(deadlocks, parse_ctl("EG q"))
    assert deadlocks.get_state("D1") in sat(deadlocks, parse_ctl("AG q"))


def test_unreachable_states_are_still_in_sat_sets(branching_model: KripkeStructure) -> None:
    assert branching_model.get_state("S3") in sat(branching_model, Atom("error"))
    assert branching_model.get_state("S3") in sat(branching_model, EF(Atom("error")))


def test_check_requires_all_initial_states_to_satisfy() -> None:
    model = KripkeStructure(
        (State("A", labels={"safe"}), State("B", labels={"error"})),
        ("A", "B"),
        (),
    )

    result = check(model, Atom("safe"))

    assert not result.satisfied
    assert result.initial_states == (model.get_state("A"), model.get_state("B"))
    multi_initial_violation = check(model, "AG(safe)")
    assert multi_initial_violation.counterexample_validated
    assert validate_counterexample(model, multi_initial_violation)
    multi_initial_ax = check(model, "AX(safe)")
    assert not multi_initial_ax.satisfied
    assert multi_initial_ax.counterexample_validated
    assert validate_counterexample(model, multi_initial_ax)


def test_empty_initial_set_is_a_model_check_error() -> None:
    model = KripkeStructure((), (), ())

    with pytest.raises(CTLError) as raised:
        check(model, Atom("p"))

    assert raised.value.code is CTLErrorCode.NO_INITIAL_STATE


def test_ag_failure_returns_deterministic_counterexample(branching_model: KripkeStructure) -> None:
    result = check(branching_model, "AG(safe)")

    assert not result.satisfied
    assert tuple(state.id for state in result.counterexample or ()) == ("S0", "S1", "S3")
    assert result.counterexample_validated
    assert validate_counterexample(branching_model, result)


def test_ef_success_returns_deterministic_witness(branching_model: KripkeStructure) -> None:
    result = check(branching_model, "EF(done)")

    assert result.satisfied
    assert tuple(state.id for state in result.witness or ()) == ("S0", "S1", "S2")


def test_ex_success_returns_satisfying_successor_witness() -> None:
    model = KripkeStructure(
        (State("S0", labels={"start"}), State("A", labels={"done"}), State("B", labels={"error"})),
        ("S0",),
        (Transition("S0", "B"), Transition("S0", "A")),
    )

    result = check(model, "EX(done)")

    assert result.satisfied
    assert tuple(state.id for state in result.witness or ()) == ("S0", "A")


def test_ax_failure_returns_violating_successor_counterexample() -> None:
    model = KripkeStructure(
        (State("S0", labels={"start"}), State("A", labels={"safe"}), State("B", labels={"error"})),
        ("S0",),
        (Transition("S0", "B"), Transition("S0", "A")),
    )

    result = check(model, "AX(safe)")

    assert not result.satisfied
    assert tuple(state.id for state in result.counterexample or ()) == ("S0", "B")
    assert result.counterexample_validated


def test_ctl_counterexample_validator_rejects_corrupt_traces_and_missing_paths() -> None:
    from dataclasses import replace
    from seclab.results import VerificationStatus, classify_ctl_result

    model = KripkeStructure(
        (State("I", labels={"safe"}), State("B", labels={"bad"}),
         State("OTHER", labels={"bad"}), State("SAFE", labels={"safe"})),
        ("I",), (Transition("I", "B"), Transition("I", "SAFE")),
    )
    good = check(model, "AG(safe)")
    assert validate_counterexample(model, good)
    variants = (
        replace(good, counterexample=(State("I", labels={"safe"}), State("missing", labels={"bad"}))),
        replace(good, counterexample=(model.get_state("I"), model.get_state("OTHER"))),
        replace(good, counterexample=(model.get_state("B"),)),
        replace(good, counterexample=(model.get_state("I"), model.get_state("SAFE"))),
        replace(good, counterexample=None),
    )
    for invalid in variants:
        assert not validate_counterexample(model, invalid)
        assert classify_ctl_result(invalid).status is VerificationStatus.TOOL_ERROR
    assert classify_ctl_result(good).status is VerificationStatus.FAIL


def test_false_ctl_result_without_path_shaped_certificate_has_recomputable_observation() -> None:
    from seclab.results import VerificationStatus, classify_ctl_result

    model = KripkeStructure((State("I"), State("B"), State("UNREACHABLE", labels={"p"})), ("I",),
                            (Transition("I", "B"), Transition("B", "B")))
    result = check(model, "AF(p)")
    assert not result.satisfied
    assert result.counterexample is None
    assert result.counterexample_validated
    assert validate_counterexample(model, result)
    assert classify_ctl_result(result).status is VerificationStatus.FAIL


@pytest.mark.parametrize("formula", ["EF(p)", "AF(p)", "EG(p)", "AG(p)",
                                     "E[p U q]", "A[p U q]", "EX(p)", "AX(p)", "p && q"])
def test_false_ctl_operators_return_validated_model_observations(formula: str) -> None:
    model = KripkeStructure((State("I", labels={"p"}), State("D"), State("Q", labels={"q"})), ("I",),
                            (Transition("I", "D"), Transition("D", "D")))
    result = check(model, formula)
    if result.satisfied:
        return
    assert result.counterexample_validated
    assert validate_counterexample(model, result)
    assert classify_ctl_result(result).status is VerificationStatus.FAIL


def test_syntax_and_unknown_atoms_are_not_verification_failures(branching_model: KripkeStructure) -> None:
    with pytest.raises(CTLError) as syntax:
        check(branching_model, "AG(")
    assert syntax.value.code is CTLErrorCode.CTL_SYNTAX_ERROR
    with pytest.raises(CTLError) as unknown:
        check(branching_model, "AG(missing)")
    assert unknown.value.code is CTLErrorCode.UNKNOWN_ATOM
