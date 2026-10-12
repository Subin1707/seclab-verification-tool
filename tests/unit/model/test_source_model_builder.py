from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from seclab.evidence import ArtifactStore
from seclab.formal.ctl.model_checker import check
from seclab.model import SourceModelBuilder, reachable_states, unreachable_states


FIXTURES = Path(__file__).resolve().parents[3] / "examples" / "source-model"
pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="clang parser is required for source model tests")


def build(name: str, tmp_path: Path, **kwargs):
    return SourceModelBuilder(**kwargs).build(FIXTURES / name, source_root=FIXTURES,
        artifact_store=ArtifactStore(tmp_path / "artifacts"))


def test_linear_assignments_create_source_mapped_state_path(tmp_path: Path) -> None:
    result = build("linear.c", tmp_path)
    assert result.status == "SUPPORTED"
    assert result.model is not None
    assert len(result.model.initial_states) == 1
    assert len(result.model.states) >= 3
    assert any("value =" in (edge.action or "") for edge in result.model.transitions)
    assert len(reachable_states(result.model)) == len(result.model.states)
    assert result.source_to_states and result.source_to_transitions
    assert all(location.line > 0 for location in result.source_locations.values())
    assert result.source_hashes["linear.c"]
    assert result.evidence_ids and all(item for item in result.evidence_ids)


def test_if_else_uses_finite_parameter_domain_and_preserves_both_branches(tmp_path: Path) -> None:
    result = build("if_else.c", tmp_path, parameter_domains={"choose.input": (-1, 1)})
    assert result.status == "SUPPORTED"
    assert result.model is not None
    guards = {edge.guard for edge in result.model.transitions if edge.label == "branch"}
    assert any("input" in str(guard) for guard in guards)
    assert len({item["property_id"] for item in result.property_mappings}) == 1
    assert len(result.model.initial_states) == 2
    assert {state.values["$return"] for state in result.model.states if "$return" in state.values} == {0, 1}
    labels = {label for state in result.model.states for label in state.labels}
    assert result.property_mappings[0]["true_label"] in labels
    assert result.property_mappings[0]["false_label"] in labels


def test_multiple_branches_create_distinct_branch_mappings(tmp_path: Path) -> None:
    result = build("multiple_branches.c", tmp_path,
                   parameter_domains={"classify.input": (-1, 0, 2)})
    assert result.model is not None
    assert len(result.property_mappings) == 2
    assert all(item["status"] == "EVALUATED" for item in result.property_mappings)
    assert len([edge for edge in result.model.transitions if edge.label == "branch"]) >= 4


def test_loop_is_bounded_and_bound_exhaustion_is_inconclusive(tmp_path: Path) -> None:
    complete = build("bounded_loop.c", tmp_path, loop_bound=3)
    assert complete.status == "SUPPORTED"
    assert complete.model is not None
    assert any(state.values.get("result") == 2 for state in complete.model.states)
    bounded = build("bounded_loop.c", tmp_path, loop_bound=1)
    assert bounded.status == "INCONCLUSIVE"
    assert any("loop bound 1 reached" in warning.casefold() for warning in bounded.warnings)


def test_invalid_syntax_is_reported_as_unsupported_without_model(tmp_path: Path) -> None:
    result = build("invalid_syntax.c", tmp_path)
    assert result.status == "UNSUPPORTED"
    assert result.model is None
    assert "syntax" in result.unsupported_constructs[0]["construct"].lower()
    assert result.unsupported_constructs[0].get("diagnostic")
    assert result.evidence_ids and set(result.evidence_hashes) == set(result.evidence_ids)


def test_constant_false_branch_is_absent_and_branch_mapping_is_retained(tmp_path: Path) -> None:
    result = build("unreachable_branch.c", tmp_path)
    assert result.model is not None
    assert len(result.model.states) < 5
    assert len(result.property_mappings) == 1
    assert result.property_mappings[0]["status"] == "EVALUATED"
    assert len(unreachable_states(result.model)) == 0
    assert any("Unreachable under declared initial values" in warning for warning in result.warnings)


def test_multiple_functions_require_an_explicit_entry_function(tmp_path: Path) -> None:
    result = build("multiple_functions.c", tmp_path)
    assert result.status == "UNSUPPORTED"
    assert result.model is None
    assert result.unsupported_constructs[0]["construct"] == "function entry point"


def test_missing_parameter_domain_is_not_guessed(tmp_path: Path) -> None:
    result = build("if_else.c", tmp_path)
    assert result.status == "UNSUPPORTED"
    assert result.model is None
    assert "Finite initial domain" in result.unsupported_constructs[0]["reason"]


def test_source_model_can_be_checked_by_existing_ctl_core(tmp_path: Path) -> None:
    result = build("unreachable_branch.c", tmp_path)
    assert result.model is not None
    checked = check(result.model, "EF(return)")
    assert checked.satisfied is True


def test_multiple_function_entry_is_not_guessed(tmp_path: Path) -> None:
    result = build("multiple_functions.c", tmp_path)
    assert result.status == "UNSUPPORTED"
    assert result.model is None
    assert result.unsupported_constructs[0]["construct"] == "function entry point"
