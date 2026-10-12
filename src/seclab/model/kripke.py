"""Validated finite Kripke structure K = (S, S0, R, L)."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Iterable, Mapping

from .errors import ModelError, ModelErrorCode
from .state import State
from .transition import Transition


@dataclass(frozen=True, slots=True, init=False)
class KripkeStructure:
    """Finite state set, initial subset, edge relation and state labeling."""

    _states: tuple[State, ...] = field(repr=False)
    _initial_states: tuple[State, ...] = field(repr=False)
    _transitions: tuple[Transition, ...] = field(repr=False)
    _states_by_id: Mapping[str, State] = field(repr=False)
    _successor_ids: Mapping[str, tuple[str, ...]] = field(repr=False)
    _predecessor_ids: Mapping[str, tuple[str, ...]] = field(repr=False)
    _model_hash: str = field(repr=False)

    def __init__(
        self,
        states: Iterable[State],
        initial_states: Iterable[State | str],
        transitions: Iterable[Transition],
    ) -> None:
        state_list = tuple(states)
        by_id: dict[str, State] = {}
        for state in state_list:
            if not isinstance(state, State):
                raise ModelError(ModelErrorCode.MODEL_INVARIANT_ERROR, "Every model state must be a State instance.")
            if state.id in by_id:
                raise ModelError(ModelErrorCode.DUPLICATE_STATE_ID, f"State ID '{state.id}' is ambiguous.")
            by_id[state.id] = state
        ordered_states = tuple(by_id[state_id] for state_id in sorted(by_id))

        initials: dict[str, State] = {}
        for initial in initial_states:
            state_id = initial.id if isinstance(initial, State) else initial
            known = by_id.get(state_id)
            if known is None or isinstance(initial, State) and known != initial:
                raise ModelError(
                    ModelErrorCode.INVALID_INITIAL_STATE,
                    f"Initial state '{state_id}' is not a member of the model state set.",
                )
            initials[state_id] = known
        if ordered_states and not initials:
            raise ModelError(
                ModelErrorCode.MISSING_INITIAL_STATE,
                "A non-empty Kripke structure must contain at least one initial state.",
            )

        transition_list = _assign_transition_ids(tuple(transitions))
        transition_ids: set[str] = set()
        successor_ids: dict[str, set[str]] = {state.id: set() for state in ordered_states}
        predecessor_ids: dict[str, set[str]] = {state.id: set() for state in ordered_states}
        for transition in transition_list:
            if not isinstance(transition, Transition):
                raise ModelError(ModelErrorCode.MODEL_INVARIANT_ERROR, "Every edge must be a Transition instance.")
            if transition.id in transition_ids:
                raise ModelError(ModelErrorCode.DUPLICATE_TRANSITION_ID,
                                 f"Transition ID '{transition.id}' is ambiguous.")
            transition_ids.add(transition.id or "")
            if transition.source not in by_id:
                raise ModelError(
                    ModelErrorCode.INVALID_TRANSITION,
                    f"Transition '{transition.id or '?'}' has unknown source state '{transition.source}'.",
                )
            if transition.target not in by_id:
                raise ModelError(
                    ModelErrorCode.INVALID_TRANSITION,
                    f"Transition '{transition.id or '?'}' has unknown target state '{transition.target}'.",
                )
            successor_ids[transition.source].add(transition.target)
            predecessor_ids[transition.target].add(transition.source)

        object.__setattr__(self, "_states", ordered_states)
        object.__setattr__(self, "_initial_states", tuple(initials[key] for key in sorted(initials)))
        object.__setattr__(self, "_transitions", tuple(sorted(transition_list, key=Transition.sort_key)))
        object.__setattr__(self, "_states_by_id", MappingProxyType(by_id))
        object.__setattr__(self, "_successor_ids", MappingProxyType({key: tuple(sorted(value)) for key, value in successor_ids.items()}))
        object.__setattr__(self, "_predecessor_ids", MappingProxyType({key: tuple(sorted(value)) for key, value in predecessor_ids.items()}))
        canonical = _canonical_model(ordered_states, tuple(initials[key] for key in sorted(initials)),
                                     tuple(sorted(transition_list, key=Transition.sort_key)))
        object.__setattr__(self, "_model_hash", hashlib.sha256(canonical.encode("utf-8")).hexdigest())

    @property
    def states(self) -> tuple[State, ...]:
        return self._states

    @property
    def initial_states(self) -> tuple[State, ...]:
        return self._initial_states

    @property
    def transitions(self) -> tuple[Transition, ...]:
        return self._transitions

    @property
    def model_hash(self) -> str:
        return self._model_hash

    @property
    def state_ids(self) -> tuple[str, ...]:
        """Stable IDs suitable for traceability and reporting."""
        return tuple(state.id for state in self._states)

    @property
    def transition_ids(self) -> tuple[str, ...]:
        return tuple(edge.id or "" for edge in self._transitions)

    @property
    def statistics(self) -> Mapping[str, int]:
        from .reachability import deadlock_states, reachable_states, unreachable_states
        return MappingProxyType({
            "state_count": len(self._states), "transition_count": len(self._transitions),
            "initial_state_count": len(self._initial_states),
            "reachable_state_count": len(reachable_states(self)),
            "unreachable_state_count": len(unreachable_states(self)),
            "deadlock_state_count": len(deadlock_states(self)),
        })

    def validate(self) -> None:
        """Recheck graph invariants for API consumers loading/receiving a model."""
        if any(edge.source not in self._states_by_id or edge.target not in self._states_by_id
               for edge in self._transitions):
            raise ModelError(ModelErrorCode.MODEL_INVARIANT_ERROR,
                             "A transition endpoint is not present in the model.")
        if self._states and not self._initial_states:
            raise ModelError(ModelErrorCode.MISSING_INITIAL_STATE,
                             "A non-empty Kripke structure must contain an initial state.")

    def state_exists(self, state: State | str) -> bool:
        state_id = state.id if isinstance(state, State) else state
        known = self._states_by_id.get(state_id)
        return known is not None and (not isinstance(state, State) or known == state)

    def has_state(self, state: State | str) -> bool:
        return self.state_exists(state)

    def get_state(self, state: State | str) -> State:
        state_id = state.id if isinstance(state, State) else state
        known = self._states_by_id.get(state_id)
        if known is None or isinstance(state, State) and known != state:
            raise ModelError(ModelErrorCode.UNKNOWN_STATE, f"State '{state_id}' is not in this Kripke structure.")
        return known

    def successors(self, state: State | str) -> tuple[State, ...]:
        known = self.get_state(state)
        return tuple(self._states_by_id[state_id] for state_id in self._successor_ids[known.id])

    def predecessors(self, state: State | str) -> tuple[State, ...]:
        known = self.get_state(state)
        return tuple(self._states_by_id[state_id] for state_id in self._predecessor_ids[known.id])

    def labels(self, state: State | str) -> frozenset[str]:
        return self.get_state(state).labels


def _assign_transition_ids(transitions: tuple[Transition, ...]) -> tuple[Transition, ...]:
    from dataclasses import replace
    import hashlib
    groups: dict[str, list[Transition]] = {}
    for edge in transitions:
        if edge.id is not None:
            groups.setdefault(edge.id, []).append(edge)
            continue
        material = json.dumps([edge.source, edge.target, edge.label, edge.guard, edge.action],
                              ensure_ascii=False, separators=(",", ":"))
        base = "TR-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        groups.setdefault(base, []).append(edge)
    assigned: list[Transition] = []
    for identity in sorted(groups):
        group = sorted(groups[identity], key=Transition.sort_key)
        for index, edge in enumerate(group):
            if edge.id is not None:
                assigned.append(edge)
            else:
                suffix = f"-{index + 1}" if len(group) > 1 else ""
                assigned.append(replace(edge, id=identity + suffix))
    return tuple(assigned)


def _canonical_model(states: tuple[State, ...], initials: tuple[State, ...],
                     transitions: tuple[Transition, ...]) -> str:
    data = {
        "states": [{"id": state.id, "values": dict(state.values), "labels": sorted(state.labels)}
                   for state in states],
        "initial_states": [state.id for state in initials],
        "transitions": [{"id": edge.id, "source": edge.source, "target": edge.target,
                         "label": edge.label, "guard": edge.guard, "action": edge.action,
                         "guard_status": edge.guard_status}
                        for edge in transitions],
    }
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
