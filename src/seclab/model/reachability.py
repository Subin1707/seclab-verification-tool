"""Domain-independent graph analysis over a Kripke structure."""

from __future__ import annotations

from collections import deque

from .kripke import KripkeStructure
from .state import State


def reachable_states(model: KripkeStructure) -> tuple[State, ...]:
    """Return states reachable from any initial state in deterministic BFS order."""
    visited: set[str] = set()
    ordered_ids: list[str] = []
    queue = deque(state.id for state in model.initial_states)
    while queue:
        state_id = queue.popleft()
        if state_id in visited:
            continue
        visited.add(state_id)
        ordered_ids.append(state_id)
        for successor in model.successors(state_id):
            if successor.id not in visited:
                queue.append(successor.id)
    return tuple(model.get_state(state_id) for state_id in ordered_ids)


def unreachable_states(model: KripkeStructure) -> tuple[State, ...]:
    """Return model states omitted from the initial-state reachable set, ID-sorted."""
    reachable_ids = {state.id for state in reachable_states(model)}
    return tuple(state for state in model.states if state.id not in reachable_ids)


def deadlock_states(model: KripkeStructure) -> tuple[State, ...]:
    """Return every state with no outgoing edge, including unreachable states."""
    return tuple(state for state in model.states if not model.successors(state))
