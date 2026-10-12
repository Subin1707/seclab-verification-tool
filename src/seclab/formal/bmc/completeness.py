"""Reachability completeness analysis for finite explicit Kripke models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from seclab.model.kripke import KripkeStructure

from .errors import BMCError, BMCErrorCode


@dataclass(frozen=True, slots=True)
class CompletenessAnalysis:
    initial_state_ids: tuple[str, ...]
    reachable_state_ids: tuple[str, ...]
    distances: tuple[tuple[str, int], ...]
    threshold: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": "maximum_shortest_path_distance_from_any_initial_state",
            "initial_state_ids": list(self.initial_state_ids),
            "reachable_state_ids": list(self.reachable_state_ids),
            "shortest_distances": [{"state_id": state_id, "distance": distance} for state_id, distance in self.distances],
            "threshold": self.threshold,
            "scope": "Completeness for bad-state reachability in this finite explicit graph only.",
        }


def analyze_completeness(model: KripkeStructure) -> CompletenessAnalysis:
    """Return max shortest distance for every reachable state, from all initials."""
    if not model.states:
        raise BMCError(BMCErrorCode.EMPTY_MODEL, "BMC requires a non-empty explicit state graph.")
    if not model.initial_states:
        raise BMCError(BMCErrorCode.NO_INITIAL_STATE, "BMC requires at least one initial state.")

    distances = {state.id: 0 for state in model.initial_states}
    queue = [state.id for state in model.initial_states]
    cursor = 0
    while cursor < len(queue):
        state_id = queue[cursor]
        cursor += 1
        for successor in model.successors(state_id):
            if successor.id not in distances:
                distances[successor.id] = distances[state_id] + 1
                queue.append(successor.id)
    ordered = tuple(sorted(distances.items()))
    return CompletenessAnalysis(
        initial_state_ids=tuple(state.id for state in model.initial_states),
        reachable_state_ids=tuple(state_id for state_id, _ in ordered),
        distances=ordered,
        threshold=max(distances.values(), default=0),
    )
