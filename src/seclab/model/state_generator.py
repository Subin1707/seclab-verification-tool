"""Build a Kripke structure from the explicit state machine in a specification."""

from __future__ import annotations

from seclab.specification.schema import Specification

from .errors import ModelError, ModelErrorCode
from .kripke import KripkeStructure
from .state import State
from .transition import Transition


def generate_kripke_structure(
    specification: Specification,
    *,
    max_states: int | None = None,
) -> KripkeStructure:
    """Convert explicitly declared states and edges; never invent states/edges."""
    if max_states is not None and max_states < 0:
        raise ValueError("max_states must be non-negative or None")
    state_specs = specification.states
    if max_states is not None and len(state_specs) > max_states:
        raise ModelError(
            ModelErrorCode.STATE_LIMIT_EXCEEDED,
            f"Specification declares {len(state_specs)} states, exceeding max_states={max_states}.",
        )

    states = tuple(
        State(state.id, state.values, frozenset(state.labels))
        for state in state_specs
    )
    states_by_id = {state.id: state for state in states}
    if len(states_by_id) != len(states):
        raise ModelError(ModelErrorCode.DUPLICATE_STATE_ID, "Specification declares duplicate state IDs.")

    if not states:
        if specification.initial_state is not None:
            raise ModelError(
                ModelErrorCode.INVALID_INITIAL_STATE,
                f"Initial state '{specification.initial_state}' is declared but the specification has no states.",
            )
        return KripkeStructure((), (), _transitions(specification, states_by_id))

    flagged_initials = {item.id for item in state_specs if item.initial}
    selected_id = specification.initial_state
    if selected_id is not None:
        if selected_id not in states_by_id:
            raise ModelError(
                ModelErrorCode.INVALID_INITIAL_STATE,
                f"Initial state '{selected_id}' is not declared.",
            )
        if flagged_initials and flagged_initials != {selected_id}:
            raise ModelError(
                ModelErrorCode.INVALID_INITIAL_STATE,
                "Root initial_state conflicts with state initial flags.",
            )
        initial_ids = {selected_id}
    else:
        if not flagged_initials:
            raise ModelError(
                ModelErrorCode.MISSING_INITIAL_STATE,
                "Explicit states have no initial marker; no state was selected implicitly.",
            )
        if len(flagged_initials) > 1:
            raise ModelError(ModelErrorCode.MULTIPLE_INITIAL_STATES, "More than one state is marked initial.")
        initial_ids = flagged_initials

    transitions = _transitions(specification, states_by_id)
    return KripkeStructure(states, (states_by_id[state_id] for state_id in initial_ids), transitions)


def generate_state_space(
    specification: Specification,
    *,
    max_states: int | None = None,
) -> KripkeStructure:
    """Alias emphasizing the generated state-space result."""
    return generate_kripke_structure(specification, max_states=max_states)


def _transitions(specification: Specification, states_by_id: dict[str, State]) -> tuple[Transition, ...]:
    transitions: list[Transition] = []
    for edge in specification.transitions:
        source, target = states_by_id.get(edge.source), states_by_id.get(edge.target)
        if source is None or target is None:
            raise ModelError(ModelErrorCode.INVALID_TRANSITION,
                             f"Transition '{edge.id}' has an undeclared endpoint.")
        if edge.guard:
            try:
                from seclab.formal.smt import evaluate_expression, parse_expression
                from seclab.formal.smt.ast import Binary, Unary, Variable
                expression = parse_expression(edge.guard)
            except Exception as exc:
                raise ModelError(ModelErrorCode.INVALID_GUARD,
                                 f"Transition '{edge.id}' guard is invalid: {exc}") from exc
            variables = _expression_variables(expression, Binary, Unary, Variable)
            if variables <= source.values.keys():
                try:
                    enabled = evaluate_expression(expression, source.values)
                except Exception as exc:
                    raise ModelError(ModelErrorCode.INVALID_GUARD,
                                     f"Transition '{edge.id}' guard could not be evaluated: {exc}") from exc
                if not isinstance(enabled, bool):
                    raise ModelError(ModelErrorCode.INVALID_GUARD,
                                     f"Transition '{edge.id}' guard must evaluate to boolean.")
                if not enabled:
                    continue
                guard_status = "EVALUATED_TRUE"
            else:
                # Legacy state machines often carry symbolic guard text without
                # a matching state valuation. Keep that edge conservatively and
                # expose that the guard was retained but not evaluated.
                guard_status = "UNRESOLVED_VARIABLES"
        else:
            guard_status = "UNSPECIFIED"
        if edge.action:
            _validate_assignment_action(edge.id, edge.action, source, target)
        transitions.append(Transition(source=edge.source, target=edge.target, label=edge.label,
            guard=edge.guard, action=edge.action, id=edge.id, guard_status=guard_status))
    return tuple(transitions)


def _validate_assignment_action(transition_id: str, action: str, source: State, target: State) -> None:
    """Validate the supported ``variable = expression`` action against its target state."""
    import re
    match = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9_.:-]*)\s*=(?!=)\s*(.+?)\s*", action)
    if match is None:
        return  # Other action text is retained as descriptive metadata.
    variable, expression = match.groups()
    try:
        from seclab.formal.smt import evaluate_expression, parse_expression
        value = evaluate_expression(parse_expression(expression), source.values)
    except Exception as exc:
        raise ModelError(ModelErrorCode.INVALID_ACTION,
                         f"Transition '{transition_id}' action could not be evaluated: {exc}") from exc
    if variable not in target.values or target.values[variable] != value:
        raise ModelError(ModelErrorCode.INVALID_ACTION,
                         f"Transition '{transition_id}' action assigns {variable!r}={value!r}, "
                         "which does not match the explicit target state valuation.")


def _expression_variables(expression, binary_type, unary_type, variable_type) -> set[str]:
    if isinstance(expression, variable_type):
        return {expression.name}
    if isinstance(expression, binary_type):
        return (_expression_variables(expression.left, binary_type, unary_type, variable_type)
                | _expression_variables(expression.right, binary_type, unary_type, variable_type))
    if isinstance(expression, unary_type):
        return _expression_variables(expression.operand, binary_type, unary_type, variable_type)
    return set()
