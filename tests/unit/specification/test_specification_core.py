"""Contract, loader, validator and normalizer tests using generic fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from seclab.specification import (
    SpecificationError,
    SpecificationErrorCode,
    load_specification,
    normalize_specification,
    validate_specification,
)


COMBINED: dict[str, Any] = {
    "schema_version": "1.0",
    "id": "sample-control",
    "name": "Sample control",
    "initial_state": "IDLE",
    "requirements": [
        {"id": "REQ-001", "description": "Can start", "type": "functional",
         "constraint_ids": ["CON-001"], "property_ids": ["PROP-001"]},
        {"id": "REQ-002", "description": "Can stop", "type": "safety"},
    ],
    "variables": [
        {"id": "running", "domain": {"type": "boolean"}, "initial": False},
        {"id": "mode", "domain": {"enum": ["idle", "active"]}, "initial": "idle"},
    ],
    "constraints": [
        {"id": "CON-001", "expression": "running == true", "requirement_ids": ["REQ-001"]}
    ],
    "states": [
        {"id": "IDLE", "values": {"running": False}, "labels": ["idle"]},
        {"id": "RUNNING", "values": {"running": True}, "labels": ["active", "running"]},
        {"id": "STOPPED", "values": {"running": False}, "labels": ["stopped"]},
    ],
    "transitions": [
        {"id": "TR-START", "source": "IDLE", "target": "RUNNING", "action": "start"},
        {"id": "TR-STOP", "source": "RUNNING", "target": "STOPPED", "action": "stop"},
    ],
    "properties": [
        {"id": "PROP-001", "logic": "CTL", "formula": "AG(running || idle)",
         "requirement_ids": ["REQ-001"]}
    ],
    "functions": [
        {"id": "FN-START", "name": "start", "requirement_ids": ["REQ-001"]},
        {"id": "FN-STOP", "name": "stop", "requirement_ids": ["REQ-002"]},
    ],
    "tests": [
        {"id": "TEST-START", "function_id": "FN-START", "requirement_ids": ["REQ-001"],
         "kind": "unit", "input": {"enabled": True}, "expected": True}
    ],
}


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _split_data() -> list[dict[str, Any]]:
    fragments: list[dict[str, Any]] = []
    for key in ("requirements", "variables", "constraints", "states", "transitions", "properties", "functions", "tests"):
        fragments.append({
            "schema_version": COMBINED["schema_version"], "id": COMBINED["id"],
            "name": COMBINED["name"], "initial_state": COMBINED["initial_state"],
            key: COMBINED[key],
        })
    return fragments


def test_valid_combined_spec_loads_validates_and_normalizes(tmp_path: Path) -> None:
    path = _write_json(tmp_path / "combined.json", COMBINED)
    loaded = load_specification(path)
    validate_specification(loaded)
    normalized = normalize_specification(loaded)

    assert normalized.id == "sample-control"
    assert [item.id for item in normalized.requirements] == ["REQ-001", "REQ-002"]
    assert len(normalized.states) == 3
    assert normalized.initial_state == "IDLE"
    assert normalized.states[0].initial is True
    variables = {item.id: item for item in normalized.variables}
    assert variables["mode"].domain.values == ("idle", "active")


def test_valid_split_spec_normalizes_and_is_semantically_equivalent(tmp_path: Path) -> None:
    paths = [_write_json(tmp_path / f"part-{index}.json", data) for index, data in enumerate(_split_data())]
    loaded = load_specification(reversed(paths))
    validate_specification(loaded)
    split_normalized = normalize_specification(loaded)
    combined_normalized = normalize_specification(
        load_specification(_write_json(tmp_path / "combined.json", COMBINED))
    )

    assert split_normalized == combined_normalized


def test_invalid_json_has_spec_error_code(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text('{"schema_version": "1.0"', encoding="utf-8")
    with pytest.raises(SpecificationError) as raised:
        load_specification(path)
    assert raised.value.category == "SPEC_ERROR"
    assert raised.value.code is SpecificationErrorCode.INVALID_JSON


def test_missing_file_has_specific_error(tmp_path: Path) -> None:
    with pytest.raises(SpecificationError) as raised:
        load_specification(tmp_path / "missing.json")
    assert raised.value.code is SpecificationErrorCode.FILE_NOT_FOUND


def test_schema_error_is_not_verification_fail(tmp_path: Path) -> None:
    invalid = {"schema_version": "1.0", "id": "incomplete"}
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "bad.json", invalid)))
    assert raised.value.category == "SPEC_ERROR"
    assert raised.value.code is SpecificationErrorCode.SCHEMA_VALIDATION_FAILED


def test_missing_entity_id_error_includes_exact_json_path(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["properties"][0].pop("id")
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "missing-id.json", invalid)))

    assert raised.value.location == "properties.0"
    assert "Missing required property 'id'" in raised.value.message


def test_duplicate_id_is_rejected(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["requirements"].append(dict(invalid["requirements"][0]))
    with pytest.raises(SpecificationError) as raised:
        normalize_specification(load_specification(_write_json(tmp_path / "duplicate.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.DUPLICATE_ID


def test_unknown_transition_state_reference_is_rejected(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["transitions"][0]["target"] = "MISSING"
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "unknown.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.UNKNOWN_REFERENCE


def test_unknown_initial_state_is_rejected(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["initial_state"] = "MISSING"
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "unknown-initial.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.UNKNOWN_INITIAL_STATE


def test_missing_initial_marker_is_rejected_for_explicit_state_machine(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid.pop("initial_state")
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "no-initial.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.MISSING_INITIAL_STATE


def test_conflicting_split_entity_definitions_are_not_overwritten(tmp_path: Path) -> None:
    first = {"schema_version": "1.0", "id": "sample-control", "name": "Sample control",
             "requirements": [{"id": "REQ-001", "description": "Original"}]}
    second = {"schema_version": "1.0", "id": "sample-control", "name": "Sample control",
              "requirements": [{"id": "REQ-001", "description": "Changed"}]}
    paths = [
        _write_json(tmp_path / "a.json", first),
        _write_json(tmp_path / "b.json", second),
    ]
    with pytest.raises(SpecificationError) as raised:
        normalize_specification(load_specification(paths))
    assert raised.value.code is SpecificationErrorCode.CONFLICTING_DEFINITION


def test_unknown_ctl_atom_is_rejected(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["properties"][0]["formula"] = "AG(undeclared_atom)"
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "unknown-atom.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.UNKNOWN_ATOM


def test_ctl_formula_syntax_error_is_rejected_by_spec_validator(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["properties"][0]["formula"] = "AG("
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "invalid-ctl.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.INVALID_CTL_FORMULA


def test_variable_name_alone_does_not_define_ctl_atom(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["properties"][0]["formula"] = "AG(running)"
    invalid["states"][1]["labels"].remove("running")
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "variable-as-atom.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.UNKNOWN_ATOM


def test_generic_v2_examples_load_validate_and_normalize() -> None:
    root = Path(__file__).resolve().parents[3]
    examples = (
        root / "examples/generic-c-project/specification-v2.json",
        root / "examples/generic-cpp-project/specification-v2.json",
        root / "examples/generic-state-machine-project/specification-v2.json",
    )
    normalized = []
    for path in examples:
        loaded = load_specification(path)
        validate_specification(loaded)
        normalized.append(normalize_specification(loaded))
    assert [item.schema_version for item in normalized] == ["2.0"] * 3
    assert [item.project["languages"] for item in normalized] == [["C"], ["C++"], []]
    assert len(normalized[2].state_machines) == 1
    assert normalized[2].state_machines[0].initial_state == "STOPPED_CLOSED"


def test_normalization_is_deterministic_for_input_order(tmp_path: Path) -> None:
    first = _write_json(tmp_path / "a.json", {"schema_version": "2.0", "id": "multi", "name": "Multi",
        "requirements": [{"id": "REQ-A", "description": "A"}]})
    second = _write_json(tmp_path / "b.json", {"schema_version": "2.0", "id": "multi", "name": "Multi",
        "requirements": [{"id": "REQ-B", "description": "B"}]})
    assert normalize_specification(load_specification([first, second])) == normalize_specification(
        load_specification([second, first]))


def test_named_state_machine_requires_explicit_initial_state(tmp_path: Path) -> None:
    invalid = {"schema_version": "2.0", "id": "machine", "name": "Machine", "state_machines": [
        {"id": "MACHINE-A", "states": [{"id": "OFF"}], "transitions": []}]}
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "no-machine-initial.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.MISSING_INITIAL_STATE


def test_state_values_must_match_declared_variable_domain(tmp_path: Path) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    invalid["states"][0]["values"]["running"] = "yes"
    with pytest.raises(SpecificationError) as raised:
        validate_specification(load_specification(_write_json(tmp_path / "wrong-state-value.json", invalid)))
    assert raised.value.code is SpecificationErrorCode.INVALID_DOMAIN


def test_validated_specification_is_reusable_and_carries_input_hashes(tmp_path: Path) -> None:
    path = _write_json(tmp_path / "hashable.json", COMBINED)
    loaded = load_specification(path)
    validated = validate_specification(loaded)
    normalized = normalize_specification(validated)

    assert validated.validation_result == "VALID"
    assert validated.diagnostics == ()
    assert validated.input_hashes[0]["sha256"] == loaded.documents[0].sha256
    assert normalized == normalize_specification(loaded)


@pytest.mark.parametrize("mutate", [
    lambda data: data.update(name=42),
    lambda data: data.update(requirements="not-an-array"),
    lambda data: data["tests"].append({"id": "BAD-TEST", "function_id": "missing"}),
    lambda data: data["properties"].append({"id": "BAD-SMT", "logic": "SMT", "formula": "missing > 1"}),
    lambda data: data["properties"].append({"id": "BAD-BMC", "logic": "BMC", "formula": "bad"}),
])
def test_invalid_types_references_and_property_requirements_are_rejected(tmp_path: Path, mutate) -> None:
    invalid = json.loads(json.dumps(COMBINED))
    mutate(invalid)
    with pytest.raises(SpecificationError):
        validate_specification(load_specification(_write_json(tmp_path / "invalid.json", invalid)))


def test_empty_optional_sections_and_generic_extension_metadata_are_preserved(tmp_path: Path) -> None:
    data = {"schema_version": "2.0", "id": "empty", "name": "Empty",
            "requirements": [], "variables": [], "constraints": [], "states": [],
            "transitions": [], "properties": [], "functions": [], "tests": [],
            "metadata": {"traceability": {"owner": "team-a"}, "code_generation": {"enabled": False}},
            "project": {"kind": "generic", "build": {"system": "custom"}},
            "coverage": {}, "fuzzing": {"enabled": False}}
    normalized = normalize_specification(load_specification(_write_json(tmp_path / "empty.json", data)))
    assert not normalized.requirements and not normalized.properties and not normalized.tests
    assert normalized.metadata["traceability"] == {"owner": "team-a"}
    assert normalized.metadata["code_generation"] == {"enabled": False}
    assert normalized.project["build"]["system"] == "custom"


def test_missing_required_fields_and_unknown_forbidden_fields_are_actionable(tmp_path: Path) -> None:
    missing = {"schema_version": "1.0", "id": "missing-name"}
    with pytest.raises(SpecificationError, match="Missing required property 'name'"):
        validate_specification(load_specification(_write_json(tmp_path / "missing.json", missing)))
    forbidden = {"schema_version": "1.0", "id": "future", "name": "Future", "unexpected": True}
    with pytest.raises(SpecificationError):
        validate_specification(load_specification(_write_json(tmp_path / "forbidden.json", forbidden)))
