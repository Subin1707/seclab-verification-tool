from __future__ import annotations

import json

import pytest

from seclab.evidence import ArtifactStore
from seclab.formal.smt import SMTVerifier, SolverOutcome
from seclab.results import VerificationStatus
from seclab.specification import load_specification, normalize_specification


def _load(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "id": "generic-smt",
        "name": "Generic SMT example",
        "variables": [{"id": "x", "domain": {"type": "integer", "minimum": 0, "maximum": 10}}],
        "constraints": [{"id": "C-nonnegative", "expression": "x >= 0"}],
    }), encoding="utf-8")
    return normalize_specification(load_specification(path))


def test_normalized_json_to_real_solver_pass_and_fail(tmp_path) -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    specification = _load(tmp_path)
    verifier = SMTVerifier()
    passed = verifier.check(specification, "x <= 10", artifact_store=ArtifactStore(tmp_path))
    failed = verifier.check(specification, "x <= 5", artifact_store=ArtifactStore(tmp_path), property_id="P-x")

    assert passed.solver_outcome is SolverOutcome.UNSAT
    assert passed.result.status is VerificationStatus.PASS
    assert failed.solver_outcome is SolverOutcome.SAT
    assert failed.result.status is VerificationStatus.FAIL
    values = {item["variable"]: item["value"] for item in failed.result.counterexample["assignments"]}
    assert values["x"] in range(6, 11)
    assert any(evidence.type.value == "COUNTEREXAMPLE" for evidence in failed.evidence)
