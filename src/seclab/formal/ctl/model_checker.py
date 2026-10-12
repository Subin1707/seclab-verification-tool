"""Finite-state CTL model checking with set-based fixed-point algorithms."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import replace

from seclab.model.kripke import KripkeStructure
from seclab.model.state import State

from .ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, CTLFormula,
    Implies, Not, Or,
)
from .errors import CTLError, CTLErrorCode
from .parser import parse_ctl
from .result import CTLCheckResult
from .validator import validate_ctl_formula


def sat(model: KripkeStructure, formula: CTLFormula) -> set[State]:
    """Return the states satisfying a validated CTL AST."""
    validate_ctl_formula(formula, model)
    return _sat(model, formula)


def check(model: KripkeStructure, formula: str | CTLFormula) -> CTLCheckResult:
    """Check a formula at every initial state and return deterministic evidence."""
    formula_text = formula if isinstance(formula, str) else None
    parsed = parse_ctl(formula) if isinstance(formula, str) else formula
    if not model.initial_states:
        raise CTLError(
            CTLErrorCode.NO_INITIAL_STATE,
            "CTL checking requires at least one initial state.",
        )
    validate_ctl_formula(parsed, model)

    satisfying = frozenset(_sat(model, parsed))
    initial_states = model.initial_states
    holds = all(state in satisfying for state in initial_states)
    witness: tuple[State, ...] | None = None
    counterexample: tuple[State, ...] | None = None

    if isinstance(parsed, EF) and holds:
        witness = _find_path(model, initial_states[0], _sat(model, parsed.child))
    elif isinstance(parsed, AG) and not holds:
        bad_states = set(model.states) - _sat(model, parsed.child)
        failing_initial = next(state for state in initial_states if state not in satisfying)
        counterexample = _find_path(model, failing_initial, bad_states)
    elif isinstance(parsed, EX) and holds:
        child_states = _sat(model, parsed.child)
        start = initial_states[0]
        target = next(
            (state for state in _semantic_successors(model, start) if state in child_states),
            None,
        )
        if target is not None:
            witness = (start, target)
    elif isinstance(parsed, AX) and not holds:
        child_states = _sat(model, parsed.child)
        failing_initial = next(state for state in initial_states if state not in satisfying)
        violating = next(
            (state for state in _semantic_successors(model, failing_initial) if state not in child_states),
            None,
        )
        if violating is not None:
            counterexample = (failing_initial, violating)

    result = CTLCheckResult(
        formula=parsed,
        formula_text=formula_text,
        satisfied=holds,
        satisfying_states=satisfying,
        initial_states=initial_states,
        witness=witness,
        counterexample=counterexample,
        model=model,
    )
    if not holds and validate_counterexample(model, result):
        result = replace(result, counterexample_validated=True)
    return result


def validate_counterexample(model: KripkeStructure, result: CTLCheckResult) -> bool:
    """Independently validate a false CTL observation and any emitted path.

    Path-shaped AG/AX counterexamples are checked edge by edge. Other formulas
    are certified by recomputing their satisfying-state set with the separate
    reference semantics and checking every initial state's observed result.
    The canonical model and formula therefore remain sufficient to reproduce
    the observation even when no compact path certificate exists.
    """
    if result.satisfied or result.counterexample is None:
        if result.satisfied or result.model is not model or result.initial_states != model.initial_states:
            return False
        # AG and AX admit compact path counterexamples. Require the path for
        # those operators; fixed-point observations for other operators are
        # independently reproducible from the canonical model and AST.
        if isinstance(result.formula, (AG, AX)):
            return False
        independently_satisfied = _independent_sat(model, result.formula)
        return (frozenset(independently_satisfied) == result.satisfying_states
                and any(state not in independently_satisfied for state in model.initial_states))
    formula = result.formula
    trace = result.counterexample
    if not trace or trace[0] not in model.initial_states:
        return False
    if any(not model.state_exists(state) for state in trace):
        return False
    if any(right not in _semantic_successors(model, left)
           for left, right in zip(trace, trace[1:])):
        return False
    # Recompute the satisfaction set from the AST rather than trusting result
    # fields; this also validates the terminal violation label/condition.
    if isinstance(formula, AG):
        independently_satisfied = _independent_sat(model, formula)
        if all(state in independently_satisfied for state in model.initial_states):
            return False
        return trace[-1] not in _independent_sat(model, formula.child)
    if isinstance(formula, AX):
        independently_satisfied = _independent_sat(model, formula)
        if all(state in independently_satisfied for state in model.initial_states):
            return False
        return len(trace) == 2 and trace[1] not in _independent_sat(model, formula.child)
    return False


def _independent_sat(model: KripkeStructure, formula: CTLFormula) -> set[State]:
    """Small reference semantics for certificate checking, separate from _sat."""
    states = set(model.states)
    successors = {state: set(_semantic_successors(model, state)) for state in states}
    if isinstance(formula, Atom):
        return {state for state in states if formula.name in model.labels(state)}
    if isinstance(formula, BoolConstant):
        return states if formula.value else set()
    if isinstance(formula, Not):
        return states - _independent_sat(model, formula.child)
    if isinstance(formula, And):
        return _independent_sat(model, formula.left) & _independent_sat(model, formula.right)
    if isinstance(formula, Or):
        return _independent_sat(model, formula.left) | _independent_sat(model, formula.right)
    if isinstance(formula, Implies):
        return (states - _independent_sat(model, formula.left)) | _independent_sat(model, formula.right)
    if isinstance(formula, (EX, AX)):
        child = _independent_sat(model, formula.child)
        predicate = any if isinstance(formula, EX) else all
        return {state for state in states if predicate(nxt in child for nxt in successors[state])}
    if isinstance(formula, (EF, AF)):
        child = _independent_sat(model, formula.child)
        existential = isinstance(formula, EF)
        result = set(child)
        while True:
            prior = set(result)
            result |= {state for state in states if (any if existential else all)(
                nxt in prior for nxt in successors[state])}
            if result == prior:
                return result
    if isinstance(formula, (EG, AG)):
        child = _independent_sat(model, formula.child)
        if isinstance(formula, AG):
            return states - _independent_sat(model, EF(Not(formula.child)))
        result = set(child)
        while True:
            prior = set(result)
            result &= {state for state in states if any(nxt in prior for nxt in successors[state])}
            if result == prior:
                return result
    if isinstance(formula, (EU, AU)):
        left, right = _independent_sat(model, formula.left), _independent_sat(model, formula.right)
        existential = isinstance(formula, EU)
        result = set(right)
        while True:
            prior = set(result)
            result |= {state for state in states if state in left and (any if existential else all)(
                nxt in prior for nxt in successors[state])}
            if result == prior:
                return result
    raise TypeError(f"Unsupported CTL AST node: {type(formula).__name__}")


def _sat(model: KripkeStructure, formula: CTLFormula) -> set[State]:
    all_states = set(model.states)
    if isinstance(formula, Atom):
        return {state for state in model.states if formula.name in model.labels(state)}
    if isinstance(formula, BoolConstant):
        return all_states if formula.value else set()
    if isinstance(formula, Not):
        return all_states - _sat(model, formula.child)
    if isinstance(formula, And):
        return _sat(model, formula.left) & _sat(model, formula.right)
    if isinstance(formula, Or):
        return _sat(model, formula.left) | _sat(model, formula.right)
    if isinstance(formula, Implies):
        return (all_states - _sat(model, formula.left)) | _sat(model, formula.right)
    if isinstance(formula, EX):
        return _pre_exists(model, _sat(model, formula.child))
    if isinstance(formula, AX):
        return _pre_all(model, _sat(model, formula.child))
    if isinstance(formula, EF):
        return _least_fixed_point(_sat(model, formula.child), lambda current: current | _pre_exists(model, current))
    if isinstance(formula, AF):
        return _least_fixed_point(_sat(model, formula.child), lambda current: current | _pre_all(model, current))
    if isinstance(formula, EG):
        return _greatest_fixed_point(
            _sat(model, formula.child),
            lambda current: current & _pre_exists(model, current),
        )
    if isinstance(formula, AG):
        return all_states - _sat(model, EF(Not(formula.child)))
    if isinstance(formula, EU):
        left = _sat(model, formula.left)
        right = _sat(model, formula.right)
        return _least_fixed_point(right, lambda current: current | (left & _pre_exists(model, current)))
    if isinstance(formula, AU):
        left = _sat(model, formula.left)
        right = _sat(model, formula.right)
        return _least_fixed_point(right, lambda current: current | (left & _pre_all(model, current)))
    raise CTLError(
        CTLErrorCode.MODEL_CHECK_ERROR,
        f"Unsupported CTL AST node '{type(formula).__name__}'.",
    )


def _least_fixed_point(
    seed: set[State],
    step: Callable[[set[State]], set[State]],
) -> set[State]:
    current = set(seed)
    while True:
        updated = step(current)
        if updated == current:
            return current
        current = updated


def _greatest_fixed_point(
    seed: set[State],
    step: Callable[[set[State]], set[State]],
) -> set[State]:
    current = set(seed)
    while True:
        updated = step(current)
        if updated == current:
            return current
        current = updated


def _pre_exists(model: KripkeStructure, target: set[State]) -> set[State]:
    return {
        state
        for state in model.states
        if any(successor in target for successor in _semantic_successors(model, state))
    }


def _pre_all(model: KripkeStructure, target: set[State]) -> set[State]:
    return {
        state
        for state in model.states
        if all(successor in target for successor in _semantic_successors(model, state))
    }


def _semantic_successors(model: KripkeStructure, state: State) -> tuple[State, ...]:
    """Use a virtual self-loop for a deadlock, without modifying the Kripke graph."""
    successors = model.successors(state)
    return successors if successors else (state,)


def _find_path(
    model: KripkeStructure,
    start: State,
    goals: Iterable[State],
) -> tuple[State, ...] | None:
    goal_set = set(goals)
    queue = deque((start,))
    predecessor: dict[str, str | None] = {start.id: None}
    found: str | None = None
    while queue:
        state = queue.popleft()
        if state in goal_set:
            found = state.id
            break
        for successor in _semantic_successors(model, state):
            if successor.id not in predecessor:
                predecessor[successor.id] = state.id
                queue.append(successor)
    if found is None:
        return None
    path_ids: list[str] = []
    current: str | None = found
    while current is not None:
        path_ids.append(current)
        current = predecessor[current]
    path_ids.reverse()
    return tuple(model.get_state(state_id) for state_id in path_ids)
