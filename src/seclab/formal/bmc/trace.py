"""Decoded, human-readable bounded execution traces."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from seclab.model.kripke import KripkeStructure
from seclab.model.state import State
from seclab.model.transition import Transition

from .errors import BMCError, BMCErrorCode


@dataclass(frozen=True, slots=True)
class TraceStep:
    step: int
    state_id: str
    labels: tuple[str, ...]
    values: tuple[tuple[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "state_id": self.state_id, "labels": list(self.labels), "values": dict(self.values)}


@dataclass(frozen=True, slots=True)
class TraceTransition:
    step: int
    source: str
    target: str
    transition_id: str | None
    label: str | None
    guard: str | None
    action: str | None
    guard_status: str = "UNSPECIFIED"
    virtual_deadlock: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step, "source": self.source, "target": self.target,
            "transition_id": self.transition_id, "label": self.label, "guard": self.guard,
            "action": self.action, "guard_status": self.guard_status,
            "virtual_deadlock": self.virtual_deadlock,
        }


@dataclass(frozen=True, slots=True)
class BMCTrace:
    bound: int
    bad_proposition: str
    states: tuple[TraceStep, ...]
    transitions: tuple[TraceTransition, ...]
    violating_step: int

    @property
    def violating_state(self) -> str:
        return self.states[self.violating_step].state_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "seclab-bmc-trace-v1", "bound": self.bound,
            "bad_proposition": self.bad_proposition, "violating_step": self.violating_step,
            "violating_state": self.violating_state,
            "states": [state.to_dict() for state in self.states],
            "transitions": [transition.to_dict() for transition in self.transitions],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)


def decode_trace(model: KripkeStructure, state_ids: tuple[str, ...], bad_proposition: str, bound: int) -> BMCTrace:
    if len(state_ids) != bound + 1:
        raise BMCError(BMCErrorCode.INVALID_TRACE, "Decoded trace length must equal bound + 1 states.")
    if not state_ids or state_ids[0] not in {state.id for state in model.initial_states}:
        raise BMCError(BMCErrorCode.INVALID_TRACE, "Decoded trace does not start at an initial state.")
    steps: list[TraceStep] = []
    for index, state_id in enumerate(state_ids):
        if not model.state_exists(state_id):
            raise BMCError(BMCErrorCode.INVALID_TRACE, f"Decoded trace refers to unknown state {state_id!r}.")
        state = model.get_state(state_id)
        steps.append(_trace_step(index, state))
    edges: list[TraceTransition] = []
    for index, (source_id, target_id) in enumerate(zip(state_ids, state_ids[1:])):
        candidates = [edge for edge in model.transitions if edge.source == source_id and edge.target == target_id]
        if candidates:
            edge = min(candidates, key=Transition.sort_key)
            edges.append(TraceTransition(index, source_id, target_id, edge.id, edge.label, edge.guard,
                                         edge.action, edge.guard_status))
        elif source_id == target_id and not model.successors(source_id):
            edges.append(TraceTransition(index, source_id, target_id, None, None, None, None, virtual_deadlock=True))
        else:
            raise BMCError(BMCErrorCode.INVALID_TRACE, f"Trace contains non-model transition {source_id!r} -> {target_id!r}.")
    violations = [step.step for step in steps if bad_proposition in step.labels]
    if not violations:
        raise BMCError(BMCErrorCode.INVALID_TRACE, "Decoded trace does not satisfy the bad-state proposition.")
    return BMCTrace(bound, bad_proposition, tuple(steps), tuple(edges), violations[0])


def _trace_step(index: int, state: State) -> TraceStep:
    return TraceStep(index, state.id, tuple(sorted(state.labels)), tuple(sorted(state.values.items())))
