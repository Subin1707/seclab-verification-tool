from __future__ import annotations

from dataclasses import replace

import pytest

from seclab.model import (
    KripkeStructure,
    ModelError,
    ModelErrorCode,
    State,
    Transition,
    deadlock_states,
    generate_kripke_structure,
    reachable_states,
    to_dict,
    to_dot,
    to_json,
    unreachable_states,
)
from seclab.specification.schema import Specification, StateSpec, TransitionSpec


@pytest.fixture
def small_specification() -> Specification:
    return Specification(
        schema_version="1.0",
        id="generic-machine",
        name="Generic machine",
        initial_state="IDLE",
        states=(
            StateSpec("IDLE", values={"active": False}, labels=("idle",)),
            StateSpec("RUNNING", values={"active": True}, labels=("active",)),
            StateSpec("STOPPED", values={"active": False}, labels=("stopped",)),
            StateSpec("UNUSED", values={"active": False}),
        ),
        transitions=(
            TransitionSpec("START", "IDLE", "RUNNING", guard="ready == true", action="start"),
            TransitionSpec("STOP", "RUNNING", "STOPPED", label="stop"),
        ),
    )


def test_state_creation_retains_values_and_labels() -> None:
    state = State("S0", {"authenticated": True, "charging": False}, {"authenticated", "not_charging"})

    assert state.id == "S0"
    assert dict(state.values) == {"authenticated": True, "charging": False}
    assert state.labels == frozenset({"authenticated", "not_charging"})
    with pytest.raises(TypeError):
        state.values["charging"] = True  # type: ignore[index]


def test_state_equality_and_hash_ignore_mapping_order() -> None:
    left = State("S0", {"a": 1, "b": False}, {"p", "q"})
    right = State("S0", {"b": False, "a": 1}, {"q", "p"})

    assert left == right
    assert hash(left) == hash(right)
    assert len({left, right}) == 1


def test_state_equality_preserves_scalar_type() -> None:
    assert State("S0", {"v": 1}) != State("S0", {"v": 1.0})
    assert State("S0", {"v": 0.0}) != State("S0", {"v": -0.0})


def test_transition_retains_raw_guard_and_action() -> None:
    transition = Transition("IDLE", "RUNNING", guard="ready == true", action="start", id="T-1")

    assert transition.source == "IDLE"
    assert transition.target == "RUNNING"
    assert transition.guard == "ready == true"
    assert transition.action == "start"
    assert transition.label is None
    assert hash(transition) == hash(Transition("IDLE", "RUNNING", guard="ready == true", action="start", id="T-1"))


def test_generator_builds_kripke_from_normalized_model(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert {state.id for state in model.states} == {"IDLE", "RUNNING", "STOPPED", "UNUSED"}
    assert {state.id for state in model.initial_states} == {"IDLE"}
    assert len(model.transitions) == 2
    assert model.transitions[0].guard == "ready == true"


def test_initial_state_is_resolved(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert model.initial_states == (model.get_state("IDLE"),)
    assert model.state_exists("IDLE")
    assert model.labels("IDLE") == frozenset({"idle"})


def test_successors_are_deterministic(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert tuple(state.id for state in model.successors("IDLE")) == ("RUNNING",)
    assert model.successors("STOPPED") == ()


def test_predecessors_are_deterministic(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert tuple(state.id for state in model.predecessors("RUNNING")) == ("IDLE",)
    assert tuple(state.id for state in model.predecessors("IDLE")) == ()


def test_reachability_returns_initial_bfs_closure(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert tuple(state.id for state in reachable_states(model)) == ("IDLE", "RUNNING", "STOPPED")


def test_unreachable_states_are_reported(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert tuple(state.id for state in unreachable_states(model)) == ("UNUSED",)


def test_deadlock_detection_is_structural_and_includes_unreachable(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)

    assert tuple(state.id for state in deadlock_states(model)) == ("STOPPED", "UNUSED")


@pytest.mark.parametrize(
    ("source", "target"),
    [("MISSING", "RUNNING"), ("IDLE", "MISSING")],
)
def test_invalid_transition_endpoint_is_rejected(source: str, target: str) -> None:
    with pytest.raises(ModelError) as raised:
        KripkeStructure((State("IDLE"),), ("IDLE",), (Transition(source, target),))

    assert raised.value.category == "MODEL_ERROR"
    assert raised.value.code is ModelErrorCode.INVALID_TRANSITION


def test_invalid_initial_state_is_rejected_by_kripke_invariant() -> None:
    with pytest.raises(ModelError) as raised:
        KripkeStructure((State("IDLE"),), ("MISSING",), ())

    assert raised.value.code is ModelErrorCode.INVALID_INITIAL_STATE


def test_duplicate_state_keys_are_rejected() -> None:
    with pytest.raises(ModelError) as raised:
        KripkeStructure((State("S0"), State("S0", {"v": 1})), (), ())

    assert raised.value.code is ModelErrorCode.DUPLICATE_STATE_ID


def test_graph_exports_are_deterministic(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)
    permuted = KripkeStructure(
        reversed(model.states),
        reversed(model.initial_states),
        reversed(model.transitions),
    )

    assert to_dict(model) == to_dict(permuted)
    assert to_json(model) == to_json(permuted)
    assert to_dot(model) == to_dot(permuted)
    assert to_dict(model)["initial_states"] == ["IDLE"]
    assert '"IDLE" -> "RUNNING"' in to_dot(model)
    assert to_dict(model)["states"][-1]["labels"] == []


def test_state_limit_fails_instead_of_truncating(small_specification: Specification) -> None:
    with pytest.raises(ModelError) as raised:
        generate_kripke_structure(small_specification, max_states=3)

    assert raised.value.code is ModelErrorCode.STATE_LIMIT_EXCEEDED


def test_explicit_states_without_initial_are_not_guessed(small_specification: Specification) -> None:
    no_initial = replace(
        small_specification,
        initial_state=None,
        states=tuple(replace(state, initial=False) for state in small_specification.states),
    )

    with pytest.raises(ModelError) as raised:
        generate_kripke_structure(no_initial)

    assert raised.value.code is ModelErrorCode.MISSING_INITIAL_STATE


def test_state_initial_flag_is_used_when_root_selector_is_absent(
    small_specification: Specification,
) -> None:
    flagged = replace(
        small_specification,
        initial_state=None,
        states=tuple(
            replace(state, initial=state.id == "RUNNING")
            for state in small_specification.states
        ),
    )

    model = generate_kripke_structure(flagged)

    assert tuple(state.id for state in model.initial_states) == ("RUNNING",)


def test_specification_without_explicit_states_produces_documented_empty_model() -> None:
    specification = Specification(schema_version="1.0", id="variables-only", name="Variables only")

    model = generate_kripke_structure(specification)

    assert model.states == ()
    assert model.initial_states == ()
    assert reachable_states(model) == ()
    assert unreachable_states(model) == ()
    assert deadlock_states(model) == ()


def test_invalid_root_initial_id_is_rejected_by_generator(small_specification: Specification) -> None:
    invalid = replace(small_specification, initial_state="MISSING")

    with pytest.raises(ModelError) as raised:
        generate_kripke_structure(invalid)

    assert raised.value.code is ModelErrorCode.INVALID_INITIAL_STATE


def test_model_has_canonical_hash_statistics_and_traceable_ids(small_specification: Specification) -> None:
    model = generate_kripke_structure(small_specification)
    exported = to_dict(model)
    assert model.model_hash == generate_kripke_structure(small_specification).model_hash
    assert len(model.model_hash) == 64
    assert model.state_ids == ("IDLE", "RUNNING", "STOPPED", "UNUSED")
    assert model.transition_ids == ("START", "STOP")
    assert dict(model.statistics) == {"state_count": 4, "transition_count": 2,
        "initial_state_count": 1, "reachable_state_count": 3,
        "unreachable_state_count": 1, "deadlock_state_count": 2}
    assert exported["model_hash"] == model.model_hash
    assert exported["unreachable_state_ids"] == ["UNUSED"]
    assert exported["deadlock_state_ids"] == ["STOPPED", "UNUSED"]
    assert exported["traceability"]["transition_ids"] == ["START", "STOP"]
    assert exported["state_variables"] == ["active"]


def test_guard_evaluation_filters_disabled_edges_and_action_checks_target() -> None:
    spec = Specification(schema_version="1.0", id="guarded", name="Guarded",
        states=(StateSpec("S0", initial=True, values={"enabled": False, "count": 0}),
                StateSpec("S1", values={"enabled": True, "count": 1})),
        transitions=(TransitionSpec("DISABLED", "S0", "S1", guard="enabled == true"),))
    assert generate_kripke_structure(spec).transitions == ()
    enabled = replace(spec, states=(replace(spec.states[0], values={"enabled": True, "count": 0}), spec.states[1]),
        transitions=(TransitionSpec("STEP", "S0", "S1", guard="enabled", action="count = count + 1"),))
    model = generate_kripke_structure(enabled)
    assert tuple(edge.id for edge in model.transitions) == ("STEP",)
    assert model.transitions[0].guard_status == "EVALUATED_TRUE"


def test_bad_guard_and_inconsistent_assignment_action_are_rejected() -> None:
    from seclab.specification.schema import StateSpec, TransitionSpec
    guard_spec = Specification(schema_version="1.0", id="bad-guard", name="Bad guard",
        states=(StateSpec("S0", initial=True), StateSpec("S1")),
        transitions=(TransitionSpec("T1", "S0", "S1", guard="enabled &&"),))
    with pytest.raises(ModelError) as guard_error:
        generate_kripke_structure(guard_spec)
    assert guard_error.value.code is ModelErrorCode.INVALID_GUARD

    unresolved = replace(guard_spec,
        transitions=(TransitionSpec("T2", "S0", "S1", guard="external_condition"),))
    unresolved_model = generate_kripke_structure(unresolved)
    assert len(unresolved_model.transitions) == 1
    assert unresolved_model.transitions[0].guard_status == "UNRESOLVED_VARIABLES"

    action_spec = Specification(schema_version="1.0", id="bad-action", name="Bad action",
        states=(StateSpec("S0", initial=True, values={"x": 0}), StateSpec("S1", values={"x": 4})),
        transitions=(TransitionSpec("T1", "S0", "S1", action="x = x + 1"),))
    with pytest.raises(ModelError) as action_error:
        generate_kripke_structure(action_spec)
    assert action_error.value.code is ModelErrorCode.INVALID_ACTION


def test_unidentified_transitions_receive_deterministic_ids() -> None:
    states = (State("A"), State("B"))
    edges = (Transition("A", "B", label="go"),)
    left = KripkeStructure(states, ("A",), edges)
    right = KripkeStructure(reversed(states), ("A",), reversed(edges))
    assert left.transition_ids == right.transition_ids
    assert left.model_hash == right.model_hash
    assert left.transition_ids[0].startswith("TR-")


def test_kripke_supports_multiple_initial_states_and_empty_optional_model() -> None:
    multi = KripkeStructure((State("A"), State("B")), ("B", "A"), ())
    assert tuple(state.id for state in multi.initial_states) == ("A", "B")
    assert dict(multi.statistics)["deadlock_state_count"] == 2
    empty = KripkeStructure((), (), ())
    assert len(empty.model_hash) == 64
    assert dict(empty.statistics)["state_count"] == 0


def test_large_explicit_model_is_not_truncated() -> None:
    count = 1500
    states = tuple(State(f"S{index:04d}", {"step": index}) for index in range(count))
    transitions = tuple(Transition(states[index].id, states[index + 1].id,
                                   id=f"T{index:04d}") for index in range(count - 1))
    model = KripkeStructure(states, (states[0].id,), transitions)
    assert dict(model.statistics)["reachable_state_count"] == count
    assert dict(model.statistics)["deadlock_state_count"] == 1


def test_single_branching_and_cyclic_models_are_constructed_from_specification() -> None:
    single = Specification(schema_version="1.0", id="single", name="Single",
        states=(StateSpec("ONLY", initial=True, labels=("ready",)),))
    one = generate_kripke_structure(single)
    assert one.state_ids == ("ONLY",) and tuple(s.id for s in deadlock_states(one)) == ("ONLY",)

    graph = Specification(schema_version="1.0", id="branch-cycle", name="Branch cycle",
        states=(StateSpec("A", initial=True), StateSpec("B"), StateSpec("C")),
        transitions=(TransitionSpec("AB", "A", "B"), TransitionSpec("AC", "A", "C"),
                     TransitionSpec("CB", "C", "B"), TransitionSpec("BC", "B", "C")))
    model = generate_kripke_structure(graph)
    assert {state.id for state in model.successors("A")} == {"B", "C"}
    assert model.successors("B") == (model.get_state("C"),)
    assert reachable_states(model) == model.states


def test_duplicate_transition_ids_are_rejected() -> None:
    with pytest.raises(ModelError) as raised:
        KripkeStructure((State("A"), State("B")), ("A",),
            (Transition("A", "B", id="SAME"), Transition("B", "A", id="SAME")))
    assert raised.value.code is ModelErrorCode.DUPLICATE_TRANSITION_ID
