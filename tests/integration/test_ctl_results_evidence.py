from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone

from seclab.evidence import ArtifactStore, EvidenceType, RunManifest
from seclab.formal.ctl import check, parse_ctl
from seclab.model import KripkeStructure, State, Transition
from seclab.results import VerificationStatus, classify_ctl_result


FIXED_TIME = datetime(2026, 1, 2, tzinfo=timezone.utc)


def model() -> KripkeStructure:
    states = [State("S0", labels={"safe"}), State("S1", labels={"safe"}),
              State("S2", labels={"done", "safe"}), State("S3", labels={"unsafe"})]
    transitions = [Transition("S0", "S1"), Transition("S1", "S2"), Transition("S1", "S3"),
                   Transition("S2", "S2"), Transition("S3", "S3")]
    return KripkeStructure(states, ["S0"], transitions)


def test_ctl_fail_and_pass_flow_into_artifacts_and_manifest(tmp_path) -> None:
    store = ArtifactStore(tmp_path, clock=lambda: FIXED_TIME, id_factory=iter(("counterexample", "witness")).__next__)
    kripke = model()
    failed_ctl = check(kripke, parse_ctl("AG(safe)"))
    fail_path = [state.id for state in failed_ctl.counterexample or ()]
    assert fail_path == ["S0", "S1", "S3"]
    failed = classify_ctl_result(failed_ctl, result_id="r-fail", property_id="P-safe")
    counterexample = store.write_json(
        "formal_ctl", "ag-safe-counterexample.json",
        {"formula": "AG(safe)", "initial_state": "S0", "path": fail_path, "violating_state": fail_path[-1]},
        evidence_type=EvidenceType.COUNTEREXAMPLE, property_id="P-safe",
    )
    failed = replace(failed, evidence_ids=(counterexample.id,))

    passed_ctl = check(kripke, parse_ctl("EF(done)"))
    witness_path = [state.id for state in passed_ctl.witness or ()]
    assert witness_path == ["S0", "S1", "S2"]
    passed = classify_ctl_result(passed_ctl, result_id="r-pass", property_id="P-done")
    witness = store.write_json(
        "formal_ctl", "ef-done-witness.json",
        {"formula": "EF(done)", "initial_state": "S0", "path": witness_path},
        evidence_type=EvidenceType.WITNESS, property_id="P-done",
    )
    passed = replace(passed, evidence_ids=(witness.id,))

    manifest = RunManifest(
        "run-1", {"name": "generic finite model"}, FIXED_TIME, results=(failed, passed),
        evidence=(counterexample, witness), finished_at=FIXED_TIME,
    )
    encoded_manifest = json.loads(manifest.to_json())
    assert [item["status"] for item in encoded_manifest["results"]] == ["FAIL", "PASS"]
    assert failed.status is VerificationStatus.FAIL and passed.status is VerificationStatus.PASS
    for item in manifest.evidence:
        assert hashlib.sha256((tmp_path / item.path).read_bytes()).hexdigest() == item.hash
