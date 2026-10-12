from __future__ import annotations

import json
from pathlib import Path

from seclab.model import (
    deadlock_states,
    generate_kripke_structure,
    reachable_states,
    unreachable_states,
)
from seclab.specification import load_specification, normalize_specification


def test_json_specification_flows_through_kripke_and_reachability(tmp_path: Path) -> None:
    document = {
        "schema_version": "1.0",
        "id": "workflow-sample",
        "name": "Workflow sample",
        "initial_state": "IDLE",
        "states": [
            {"id": "IDLE", "labels": ["waiting"]},
            {"id": "RUNNING", "labels": ["active"]},
            {"id": "STOPPED", "labels": ["done"]},
            {"id": "UNUSED", "labels": ["unused"]},
        ],
        "transitions": [
            {"id": "T-START", "source": "IDLE", "target": "RUNNING", "guard": "ready"},
            {"id": "T-STOP", "source": "RUNNING", "target": "STOPPED"},
        ],
    }
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    loaded = load_specification(path)
    normalized = normalize_specification(loaded)
    model = generate_kripke_structure(normalized)

    assert tuple(state.id for state in reachable_states(model)) == ("IDLE", "RUNNING", "STOPPED")
    assert tuple(state.id for state in unreachable_states(model)) == ("UNUSED",)
    assert tuple(state.id for state in deadlock_states(model)) == ("STOPPED", "UNUSED")
