from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from seclab.formal.ctl import check
from seclab.model import (KripkeStructure, ModelError, State, Transition,
    deadlock_states, generate_kripke_structure, reachable_states, to_dict,
    unreachable_states)
from seclab.specification import load_specification, normalize_specification


def _build(tmp_path: Path, states, transitions, initial="A"):
    transitions = [({"id": f"T{index}", **edge}) for index, edge in enumerate(transitions)]
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"schema_version": "1.0", "id": "generic-fixture",
        "name": "Generic fixture", "initial_state": initial, "states": states,
        "transitions": transitions}), encoding="utf-8")
    return generate_kripke_structure(normalize_specification(load_specification(path)))


def test_linear_branch_deadlock_unreachable_cycle_and_large_models(tmp_path):
    linear = _build(tmp_path, [{"id": x} for x in "ABC"],
        [{"id": "AB", "source": "A", "target": "B"}, {"id": "BC", "source": "B", "target": "C"}])
    assert [state.id for state in reachable_states(linear)] == list("ABC")
    branching = _build(tmp_path, [{"id": x} for x in "ABCD"],
        [{"source": "A", "target": "B"}, {"source": "A", "target": "C"}, {"source": "B", "target": "D"}])
    assert {state.id for state in reachable_states(branching)} == set("ABCD")
    deadlock = _build(tmp_path, [{"id": "A"}], [])
    assert [state.id for state in deadlock_states(deadlock)] == ["A"]
    unreachable = _build(tmp_path, [{"id": x} for x in "ABX"], [{"source": "A", "target": "B"}])
    assert [state.id for state in unreachable_states(unreachable)] == ["X"]
    cycle = _build(tmp_path, [{"id": x} for x in "ABC"],
        [{"source": "A", "target": "B"}, {"source": "B", "target": "C"}, {"source": "C", "target": "A"}])
    assert len(reachable_states(cycle)) == 3
    large = _build(tmp_path, [{"id": f"S{i:03}"} for i in range(120)],
        [{"source": f"S{i:03}", "target": f"S{i + 1:03}"} for i in range(119)], initial="S000")
    assert len(large.states) == 120 and len(large.transitions) == 119


def test_invalid_transition_is_rejected_and_hash_is_deterministic(tmp_path):
    with pytest.raises(Exception):
        _build(tmp_path, [{"id": "A"}], [{"source": "A", "target": "MISSING"}])
    first = _build(tmp_path, [{"id": "A", "labels": ["ready"]}, {"id": "B", "labels": ["done"]}],
        [{"source": "A", "target": "B", "action": "advance"}])
    second = _build(tmp_path, [{"id": "B", "labels": ["done"]}, {"id": "A", "labels": ["ready"]}],
        [{"source": "A", "target": "B", "action": "advance"}])
    assert first.model_hash == second.model_hash
    assert to_dict(first) == to_dict(second)


def test_ctl_is_evaluated_on_built_model_with_real_counterexample(tmp_path):
    model = _build(tmp_path, [{"id": "A", "labels": ["safe"]}, {"id": "B", "labels": ["bad"]}],
        [{"source": "A", "target": "B"}, {"source": "B", "target": "B"}])
    passed = check(model, "EF(bad)")
    failed = check(model, "AG(safe)")
    assert passed.satisfied
    assert not failed.satisfied
    assert tuple(item.id for item in failed.counterexample or ()) == ("A", "B")


def test_accuracy_comparator_compares_independent_model_structure():
    from seclab.benchmark import BenchmarkCase, BenchmarkObservation, compare_benchmark

    case = BenchmarkCase("MODEL-3", "three-node explicit graph", None, None, "model-builder",
        "PASS", None, None, ("MODEL_JSON",), None, "Model",
        scenario={"states": ["A", "B", "C"], "edges": [["A", "B"], ["B", "C"]],
                  "initial": "A", "reachable": ["A", "B", "C"], "deadlocks": ["C"]})
    actual = _build(Path(tempfile.mkdtemp()),
        [{"id": x} for x in "ABC"], [{"source": "A", "target": "B"}, {"source": "B", "target": "C"}])
    truth = case.scenario
    observed_graph = {"states": sorted(state.id for state in actual.states),
        "edges": sorted([[edge.source, edge.target] for edge in actual.transitions]),
        "initial": actual.initial_states[0].id,
        "reachable": sorted(state.id for state in reachable_states(actual)),
        "deadlocks": sorted(state.id for state in deadlock_states(actual))}
    assert observed_graph == {"states": list(truth["states"]),
        "edges": [list(edge) for edge in truth["edges"]], "initial": truth["initial"],
        "reachable": list(truth["reachable"]), "deadlocks": list(truth["deadlocks"])}
    report = compare_benchmark((case,), (BenchmarkObservation("MODEL-3", "model-builder", "PASS",
        evidence=("MODEL_JSON",), evidence_payloads=({"content": observed_graph},)),))
    assert not report.false_positives and not report.false_negatives
