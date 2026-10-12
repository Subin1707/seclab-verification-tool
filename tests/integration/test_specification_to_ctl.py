from __future__ import annotations

import json
from pathlib import Path

from seclab.formal.ctl import check, parse_ctl, validate_ctl_formula
from seclab.model import generate_kripke_structure
from seclab.specification import load_specification, normalize_specification


def test_json_to_specification_to_kripke_to_ctl(tmp_path: Path) -> None:
    document = {
        "schema_version": "1.0",
        "id": "generic-safety-example",
        "name": "Generic safety example",
        "initial_state": "NORMAL",
        "states": [
            {"id": "NORMAL", "labels": ["safe"]},
            {"id": "ERROR", "labels": ["error"]},
        ],
        "transitions": [
            {"id": "T-FAIL", "source": "NORMAL", "target": "ERROR"},
            {"id": "T-RECOVER", "source": "ERROR", "target": "NORMAL"},
        ],
        "properties": [
            {"id": "P-SAFE", "logic": "CTL", "formula": "AG(!error)"}
        ],
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    normalized = normalize_specification(load_specification(path))
    model = generate_kripke_structure(normalized)
    formula = parse_ctl(normalized.properties[0].formula)
    validate_ctl_formula(formula, model)
    result = check(model, formula)

    assert not result.satisfied
    assert tuple(state.id for state in result.counterexample or ()) == ("NORMAL", "ERROR")
