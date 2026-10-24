from types import SimpleNamespace

from seclab.formal.ctl import model_checker
from seclab.model import KripkeStructure, State, Transition
from seclab.pipeline.stages import _ctl_negative_control


def test_ctl_negative_control_detects_separately_injected_reachable_violation():
    initial = State("SAFE", labels={"safe"})
    witness = State("unreachable_req_auth_01_violation", labels={"req_auth_01_violation"})
    baseline = KripkeStructure((initial, witness), (initial,), (
        Transition("SAFE", "SAFE", id="SAFE-LOOP"),
        Transition(witness.id, witness.id, id="WITNESS-LOOP"),
    ))
    prop = SimpleNamespace(id="REQ-AUTH-01", formula="AG(!req_auth_01_violation)")

    assert model_checker.check(baseline, prop.formula).satisfied
    baseline_hash = baseline.model_hash
    record = _ctl_negative_control(baseline, prop, baseline_holds=True)

    assert record["status"] == "DETECTED"
    assert record["counterexample_validated"] is True
    assert record["counterexample"] == ["SAFE", witness.id]
    assert record["mutation"]["source"] == "SAFE"
    assert record["mutation"]["target"] == witness.id
    assert record["baseline_model_hash"] == baseline_hash
    assert baseline.model_hash == baseline_hash
    assert model_checker.check(baseline, prop.formula).satisfied
