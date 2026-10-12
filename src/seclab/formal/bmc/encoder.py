"""Bounded unrolling of an explicit finite Kripke graph into SMT ASTs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from seclab.formal.smt.ast import Binary, Expr, Literal, Unary, Variable
from seclab.formal.smt.encoder import EncodedQuery, QueryIntent
from seclab.formal.smt.validator import ValueType
from seclab.model.kripke import KripkeStructure

from .errors import BMCError, BMCErrorCode


class BMCQueryMode(StrEnum):
    EXACT_BOUND = "EXACT_BOUND"
    UP_TO_BOUND = "UP_TO_BOUND"


@dataclass(frozen=True, slots=True)
class BMCEncodedQuery:
    solver_query: EncodedQuery
    bound: int
    bad_proposition: str
    state_mapping: tuple[tuple[str, int], ...]
    query_mode: BMCQueryMode
    initial_state_ids: tuple[str, ...]
    transition_pairs: tuple[tuple[str, str], ...]
    virtual_deadlock_state_ids: tuple[str, ...]
    model_states: tuple[tuple[str, tuple[str, ...], tuple[tuple[str, Any], ...]], ...]
    transition_metadata: tuple[tuple[str | None, str, str, str | None, str | None, str | None, str], ...]
    model_hash: str

    def to_dict(self) -> dict[str, Any]:
        solver_data = self.solver_query.to_dict()
        solver_data["scope"] = "Finite explicit Kripke path with encoded initial state, transition relation, and bad-label reachability; no source-program semantics."
        solver_data["format"] = "seclab-bmc-solver-query-v1"
        return {
            "format": "seclab-bmc-query-v1",
            "model_hash": self.model_hash,
            "query_mode": self.query_mode.value,
            "bound_semantics": "number of transition steps; the path has bound + 1 states",
            "bound": self.bound,
            "bad_proposition": self.bad_proposition,
            "state_mapping": [{"state_id": state_id, "index": index} for state_id, index in self.state_mapping],
            "initial_state_ids": list(self.initial_state_ids),
            "transition_pairs": [{"source": source, "target": target} for source, target in self.transition_pairs],
            "states": [
                {"state_id": state_id, "labels": list(labels), "values": dict(values)}
                for state_id, labels, values in self.model_states
            ],
            "transition_metadata": [
                {"transition_id": transition_id, "source": source, "target": target,
                 "label": label, "guard": guard, "action": action,
                 "guard_status": guard_status}
                for transition_id, source, target, label, guard, action, guard_status in self.transition_metadata
            ],
            "virtual_deadlock_state_ids": list(self.virtual_deadlock_state_ids),
            "guard_action_semantics": "effective transitions come from the canonical model; evaluated guards and assignment actions are recorded with their model status",
            "solver_query": solver_data,
        }


class BMCEncoder:
    def encode(
        self,
        model: KripkeStructure,
        bound: int,
        bad_proposition: str,
        *,
        query_mode: BMCQueryMode = BMCQueryMode.EXACT_BOUND,
    ) -> BMCEncodedQuery:
        _validate_model_and_input(model, bound, bad_proposition)
        mode = BMCQueryMode(query_mode)
        states = model.states  # KripkeStructure guarantees state-ID order.
        mapping = tuple((state.id, index) for index, state in enumerate(states))
        indices = dict(mapping)
        variables = tuple((f"state_{step}", ValueType.INT) for step in range(bound + 1))
        symbol_mapping = tuple((name, f"v{index}") for index, (name, _) in enumerate(variables))
        state_vars = tuple(Variable(name) for name, _ in variables)
        domain_constraints = tuple(
            entry
            for name, _ in variables
            for entry in ((name, ">=", 0), (name, "<=", len(states) - 1))
        )

        initial = _or(tuple(_eq(state_vars[0], Literal(indices[state.id])) for state in model.initial_states))
        assumptions: list[tuple[str, Expr]] = [("initial", initial)]
        kinds: list[tuple[str, str | None]] = [("initial", "initial")]
        transitions = _semantic_transition_pairs(model)
        for step in range(bound):
            relation = _or(tuple(
                _and((
                    _eq(state_vars[step], Literal(indices[source])),
                    _eq(state_vars[step + 1], Literal(indices[target])),
                ))
                for source, target in transitions
            ))
            assumptions.append((f"transition-{step}", relation))
            kinds.append((f"transition-{step}", "transition"))

        bad_indices = tuple(index for state_id, index in mapping if bad_proposition in model.labels(state_id))
        violation = _or(tuple(
            _eq(state_vars[step], Literal(index))
            for step in range(bound + 1)
            for index in bad_indices
        ))
        property_expr = Unary("!", violation)
        solver_query = EncodedQuery(
            specification_id=f"kripke-bmc-{_stable_model_key(model)}",
            query_intent=QueryIntent.VIOLATION_SEARCH,
            variable_types=variables,
            variable_mapping=symbol_mapping,
            domain_constraints=domain_constraints,
            constraints=tuple(assumptions),
            constraint_kinds=tuple(kinds),
            property_expression=property_expr,
            query_expression=violation,
            property_source=f"No state through depth {bound} has label {bad_proposition!r}.",
        )
        return BMCEncodedQuery(
            solver_query=solver_query,
            bound=bound,
            bad_proposition=bad_proposition,
            state_mapping=mapping,
            query_mode=mode,
            initial_state_ids=tuple(state.id for state in model.initial_states),
            transition_pairs=transitions,
            virtual_deadlock_state_ids=tuple(state.id for state in states if not model.successors(state)),
            model_states=tuple((state.id, tuple(sorted(state.labels)), tuple(sorted(state.values.items()))) for state in states),
            transition_metadata=tuple(
                (edge.id, edge.source, edge.target, edge.label, edge.guard, edge.action, edge.guard_status)
                for edge in model.transitions
            ),
            model_hash=model.model_hash,
        )


def _validate_model_and_input(model: KripkeStructure, bound: int, bad_proposition: str) -> None:
    if isinstance(bound, bool) or not isinstance(bound, int) or bound < 0:
        raise BMCError(BMCErrorCode.INVALID_BMC_BOUND, "bound must be a non-negative integer number of transition steps.")
    if not model.states:
        raise BMCError(BMCErrorCode.EMPTY_MODEL, "BMC requires a non-empty explicit state graph.")
    if not model.initial_states:
        raise BMCError(BMCErrorCode.NO_INITIAL_STATE, "BMC requires at least one initial state.")
    if not isinstance(bad_proposition, str) or not bad_proposition:
        raise BMCError(BMCErrorCode.UNKNOWN_PROPOSITION, "bad_proposition must name an explicit state label.")
    vocabulary = {label for state in model.states for label in state.labels}
    if bad_proposition not in vocabulary:
        raise BMCError(BMCErrorCode.UNKNOWN_PROPOSITION, f"Unknown state label {bad_proposition!r}.")


def _semantic_transition_pairs(model: KripkeStructure) -> tuple[tuple[str, str], ...]:
    pairs = {(transition.source, transition.target) for transition in model.transitions}
    pairs.update((state.id, state.id) for state in model.states if not model.successors(state))
    return tuple(sorted(pairs))


def _eq(left: Expr, right: Expr) -> Expr:
    return Binary("==", left, right)


def _and(expressions: tuple[Expr, ...]) -> Expr:
    if not expressions:
        return Literal(True)
    result = expressions[0]
    for expression in expressions[1:]:
        result = Binary("&&", result, expression)
    return result


def _or(expressions: tuple[Expr, ...]) -> Expr:
    if not expressions:
        return Literal(False)
    result = expressions[0]
    for expression in expressions[1:]:
        result = Binary("||", result, expression)
    return result


def _stable_model_key(model: KripkeStructure) -> str:
    # Only deterministic content identifiers; state IDs and labels are emitted in query metadata.
    import hashlib
    from seclab.model.graph_exporter import to_json

    return hashlib.sha256(to_json(model).encode("utf-8")).hexdigest()[:16]
