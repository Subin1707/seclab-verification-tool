"""Stable structured and DOT exports for Kripke structures."""

from __future__ import annotations

import json

from .kripke import KripkeStructure


def to_dict(model: KripkeStructure) -> dict[str, object]:
    """Return a deterministic, JSON-compatible model representation."""
    model.validate()
    initial_ids = {state.id for state in model.initial_states}
    from .reachability import deadlock_states, reachable_states, unreachable_states
    reachable = reachable_states(model)
    unreachable = unreachable_states(model)
    deadlocks = deadlock_states(model)
    return {
        "states": [
            {
                "id": state.id,
                "values": dict(state.values),
                "labels": sorted(state.labels),
                "initial": state.id in initial_ids,
            }
            for state in model.states
        ],
        "initial_states": [state.id for state in model.initial_states],
        "transitions": [
            {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "label": edge.label,
                "guard": edge.guard,
                "action": edge.action,
                "guard_status": edge.guard_status,
            }
            for edge in model.transitions
        ],
        "state_variables": sorted({name for state in model.states for name in state.values}),
        "model_hash": model.model_hash,
        "statistics": dict(model.statistics),
        "reachable_state_ids": [state.id for state in reachable],
        "unreachable_state_ids": [state.id for state in unreachable],
        "deadlock_state_ids": [state.id for state in deadlocks],
        "traceability": {"state_ids": list(model.state_ids),
                         "transition_ids": list(model.transition_ids)},
    }


def to_json(model: KripkeStructure, *, indent: int | None = 2) -> str:
    """Serialize the structured representation with stable key and list order."""
    return json.dumps(to_dict(model), ensure_ascii=False, indent=indent, sort_keys=True)


def to_dot(model: KripkeStructure) -> str:
    """Export a Graphviz DOT string without requiring the Graphviz package."""
    initial_ids = {state.id for state in model.initial_states}
    lines = ["digraph Kripke {", "  rankdir=LR;"]
    for state in model.states:
        label = state.id
        if state.labels:
            label += "\n" + ", ".join(sorted(state.labels))
        shape = "doublecircle" if state.id in initial_ids else "circle"
        lines.append(f"  {_quote(state.id)} [shape={shape}, label={_quote(label)}];")
    for edge in model.transitions:
        edge_label = edge.label
        details = [value for value in (edge.guard, edge.action) if value]
        if details:
            suffix = "; ".join(details)
            edge_label = f"{edge_label}: {suffix}" if edge_label else suffix
        attributes = f" [label={_quote(edge_label)}]" if edge_label else ""
        lines.append(f"  {_quote(edge.source)} -> {_quote(edge.target)}{attributes};")
    lines.append("}")
    return "\n".join(lines)


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'
