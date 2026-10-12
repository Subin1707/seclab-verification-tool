from __future__ import annotations

import json

import pytest

from seclab.results import (
    ClassificationInput, RawOutcome, ResultClassifier, ResultCollector, ResultError,
    VerificationResult, VerificationStatus,
)


def result(result_id: str = "r1", status: VerificationStatus = VerificationStatus.PASS) -> VerificationResult:
    return VerificationResult(result_id, "TEST", "UNIT", status, "OK", "done", scope="one test")


def test_statuses_and_result_json_roundtrip_are_canonical() -> None:
    assert [status.value for status in VerificationStatus] == [
        "PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "TOOL_ERROR", "SPEC_ERROR", "BUILD_ERROR"
    ]
    item = VerificationResult("r", "FORMAL", "CTL", "FAIL", "PROPERTY_VIOLATED", "bad",
                              counterexample={"path": ["s0", "s1"]}, metadata={"depth": 2})
    assert VerificationResult.from_dict(json.loads(item.to_json())) == item
    assert item.to_dict()["counterexample"] == {"path": ["s0", "s1"]}


def test_result_metadata_is_deeply_immutable() -> None:
    item = result()
    with pytest.raises(TypeError):
        item.metadata["new"] = "x"


def test_classifier_keeps_unknown_raw_outcome_inconclusive() -> None:
    item = ResultClassifier(lambda: "fixed").classify(ClassificationInput(
        outcome=RawOutcome.UNKNOWN, stage="FUZZ", technique="FUZZER"
    ))
    assert item.id == "fixed"
    assert item.status is VerificationStatus.INCONCLUSIVE
    assert item.reason_code == "UNKNOWN_OUTCOME"


def test_collector_filters_summarizes_and_rejects_duplicate_atomically() -> None:
    collector = ResultCollector()
    collector.add(result())
    with pytest.raises(ResultError):
        collector.extend([result("r2"), result("r1")])
    assert [item.id for item in collector.all()] == ["r1"]
    assert collector.by_status(VerificationStatus.PASS)[0].id == "r1"
    assert collector.summary() == {"total": 1, "PASS": 1, "FAIL": 0, "INCONCLUSIVE": 0,
                                   "NOT_RUN": 0, "TOOL_ERROR": 0, "SPEC_ERROR": 0, "BUILD_ERROR": 0}
