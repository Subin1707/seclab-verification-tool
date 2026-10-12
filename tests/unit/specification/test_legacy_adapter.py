from __future__ import annotations

import hashlib
import json

import pytest

from seclab.specification import (SpecificationError, adapt_legacy_specification,
    is_legacy_teacher_specification, load_compatible_specification, normalize_specification,
    validate_specification)


def _raw():
    return {
        "name": "Legacy Demo",
        "description": "state machine fixture",
        "requirements": [{"id": "REQ-SAFE", "text": "Remain safe", "category": "safety"}],
        "state_machine": {"states": ["READY", "DONE"], "initial": ["READY"],
            "labeling": {"READY": ["safe"], "DONE": ["done"]},
            "transitions": [["READY", "DONE"]]},
        "safety_properties": ["AG(safe)"],
        "functions": [{"name": "operation", "bug": {"kind": "probe"}}],
        "test_cases": [{"id": "CH4-NARRATIVE", "steps": ["expect safe"]}],
        "flows": {"opaque": {"custom": True}},
    }


def test_legacy_adapter_is_content_detected_deterministic_and_non_mutating(tmp_path):
    path = tmp_path / "renamed.json"
    raw = _raw()
    original = json.dumps(raw, ensure_ascii=False, sort_keys=True).encode()
    path.write_bytes(original)
    loaded1, info1, raw1 = load_compatible_specification(path)
    loaded2, info2, raw2 = load_compatible_specification(path)
    assert is_legacy_teacher_specification(raw)
    assert loaded1.documents[0].data == loaded2.documents[0].data
    assert info1["canonical_sha256"] == info2["canonical_sha256"]
    assert loaded1.documents[0].data["id"] == "Legacy-Demo"
    assert loaded1.documents[0].data["schema_version"] in {"1.0", "2.0"}
    assert raw1 == raw2 == (raw,)
    assert path.read_bytes() == original
    assert info1["original_sha256"] == hashlib.sha256(original).hexdigest()


def test_legacy_adapter_output_passes_canonical_validation_and_preserves_unmapped_data(tmp_path):
    path = tmp_path / "legacy.json"
    raw = _raw()
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded, info, _ = load_compatible_specification(path)
    validated = validate_specification(loaded)
    spec = normalize_specification(validated)
    assert validated.validation_result == "VALID"
    assert info["schema_version"] == spec.schema_version
    assert len(spec.states) == 2 and len(spec.transitions) == 1
    assert len(spec.properties) == 1
    provenance = spec.metadata["source_provenance"]
    assert provenance["original_document"] == raw
    assert provenance["unmapped_fields"]["flows"] == raw["flows"]
    assert provenance["function_classification"]["FN-operation"]["production_source"] is False
    assert spec.tests == ()


def test_legacy_adapter_preserves_declared_violation_labeled_states_and_edges(tmp_path):
    raw = _raw()
    raw["state_machine"] = {
        "states": ["READY", "unreachable_req_safe_violation"],
        "initial": ["READY"],
        "labeling": {
            "READY": ["safe"],
            "unreachable_req_safe_violation": ["req_safe_violation", "unreachable_violation_witness"],
        },
        "transitions": [["READY", "READY"], ["unreachable_req_safe_violation", "unreachable_req_safe_violation"]],
    }
    loaded = adapt_legacy_specification(raw, tmp_path / "legacy.json", json.dumps(raw).encode())
    spec = normalize_specification(validate_specification(loaded))

    assert [state.id for state in spec.states] == raw["state_machine"]["states"]
    assert [(edge.source, edge.target) for edge in spec.transitions] == [tuple(edge) for edge in raw["state_machine"]["transitions"]]
    assert spec.states[1].labels == ("req_safe_violation", "unreachable_violation_witness")


def test_legacy_adapter_emits_generic_source_generation_metadata_without_changing_contract(tmp_path):
    raw = _raw()
    raw["functions"] = [{"name": "copy_value", "language": "python", "kind": "divide",
                         "params": ["source"], "buffer_size": 12, "bug": "buffer-overflow"}]
    raw_bytes = json.dumps(raw, ensure_ascii=False, sort_keys=True).encode()
    loaded = adapt_legacy_specification(raw, tmp_path / "legacy.json", raw_bytes)
    spec = normalize_specification(validate_specification(loaded))
    projection = spec.metadata["source_provenance"]["source_generation"]
    assert projection["source_document_sha256"] == hashlib.sha256(raw_bytes).hexdigest()
    assert projection["functions"] == [{
        "function_id": "FN-copy_value", "name": "copy_value", "language": "python",
        "kind": "divide", "parameters": ["source"], "requirement_ids": [],
        "source_location": None, "probe_class": "BUG_INJECTED_PROBE", "production_source": False,
        "buffer_size": 12, "bug": "buffer-overflow",
    }]
    assert spec.functions[0].language == "python"
    assert "source_generation" not in raw


def test_invalid_legacy_shape_has_field_specific_migration_diagnostic(tmp_path):
    raw = _raw()
    del raw["state_machine"]["transitions"]
    with pytest.raises(SpecificationError, match="LEGACY_MIGRATION_FAILED.*state_machine.transitions"):
        adapt_legacy_specification(raw, tmp_path / "legacy.json", b"{}")


def test_canonical_specification_bypasses_legacy_adapter(tmp_path):
    path = tmp_path / "canonical.json"
    path.write_text(json.dumps({"schema_version": "1.0", "id": "native", "name": "Native"}),
                    encoding="utf-8")
    loaded, info, raw = load_compatible_specification(path)
    assert info["adapter"] is None
    assert loaded.documents[0].data == raw[0]
