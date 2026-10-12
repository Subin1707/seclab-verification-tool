from __future__ import annotations

import json

from seclab.benchmark.catalog import CASES
from seclab.benchmark.production import execute_case
from seclab.benchmark.runner import run_benchmark, verify_evidence_artifact


def test_run_artifacts_resolve_hash_and_trace_case_chain(tmp_path) -> None:
    selected = tuple(case for case in CASES if case.case_id in {"CTL-001", "BMC-001"})
    report = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="trace-run")
    assert not report.mismatches
    manifest = json.loads((tmp_path / "trace-run" / "evidence" / "run" / "manifest.json").read_text())
    assert set(manifest["cases"]) == {case.case_id for case in selected}
    for case_id, chain in manifest["cases"].items():
        references = chain["evidence_references"]
        assert {"fixture.json", "ground-truth.json", "observation.json"} <= {
            path.rsplit("/", 1)[-1] for path in (ref["path"] for ref in references)
        }
        assert chain["comparison_evidence"]["path"].endswith("comparison.json")
        assert all(verify_evidence_artifact(tmp_path / "trace-run", ref) for ref in references)
        assert verify_evidence_artifact(tmp_path / "trace-run", chain["comparison_evidence"])
        observation = next(row["actual_case"] for row in report.expected_vs_actual if row["case_id"] == case_id)
        assert observation["evidence_payloads"]


def test_integrity_verification_detects_corruption(tmp_path) -> None:
    case = next(case for case in CASES if case.case_id == "CTL-001")
    run_benchmark((case,), execute_case, workspace=tmp_path, execution_id="corrupt-run")
    manifest = json.loads((tmp_path / "corrupt-run" / "evidence" / "run" / "manifest.json").read_text())
    ref = next(item for item in manifest["cases"]["CTL-001"]["evidence_references"]
               if item["path"].endswith("fixture.json"))
    assert verify_evidence_artifact(tmp_path / "corrupt-run", ref)
    (tmp_path / "corrupt-run" / ref["path"]).write_text("tampered", encoding="utf-8")
    assert not verify_evidence_artifact(tmp_path / "corrupt-run", ref)


def test_deterministic_formal_subset_has_same_classification_and_payload(tmp_path) -> None:
    selected = tuple(case for case in CASES if case.case_id in {"CTL-010", "SMT-010", "BMC-006"})
    first = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="det-a")
    second = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="det-b")
    first_rows = {row["case_id"]: row for row in first.expected_vs_actual}
    second_rows = {row["case_id"]: row for row in second.expected_vs_actual}
    for case_id in first_rows:
        assert first_rows[case_id]["mismatch_classification"] == second_rows[case_id]["mismatch_classification"]
        assert first_rows[case_id]["actual_status"] == second_rows[case_id]["actual_status"]
        assert first_rows[case_id]["actual_case"]["evidence_payloads"] == second_rows[case_id]["actual_case"]["evidence_payloads"]


def test_environment_and_nonbinary_cases_are_not_binary_scored(tmp_path) -> None:
    selected = tuple(case for case in CASES if case.case_id in {"CTL-003", "COV-001", "MEM-006"})
    report = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="scope-run")
    assert all(row["mismatch_classification"] not in {"TRUE_POSITIVE", "TRUE_NEGATIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE"}
               for row in report.expected_vs_actual)


def test_task6b_representative_case_reruns_preserve_classification(tmp_path) -> None:
    selected = tuple(case for case in CASES if case.case_id in {
        "CTL-001", "BMC-001", "SMT-001", "STATIC-001", "DYN-001", "COV-005",
    })
    first = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="task6b-rep-a")
    second = run_benchmark(selected, execute_case, workspace=tmp_path, execution_id="task6b-rep-b")
    first_rows = {row["case_id"]: row for row in first.expected_vs_actual}
    second_rows = {row["case_id"]: row for row in second.expected_vs_actual}
    for case_id in first_rows:
        assert first_rows[case_id]["actual_status"] == second_rows[case_id]["actual_status"]
        assert first_rows[case_id]["actual_finding"] == second_rows[case_id]["actual_finding"]
        assert first_rows[case_id]["mismatch_classification"] == second_rows[case_id]["mismatch_classification"]
        for run_id in ("task6b-rep-a", "task6b-rep-b"):
            manifest = json.loads((tmp_path / run_id / "evidence" / "run" / "manifest.json").read_text())
            references = manifest["cases"][case_id]["evidence_references"]
            assert references
            assert all(verify_evidence_artifact(tmp_path / run_id, ref) for ref in references)
            observation = next(ref for ref in references if ref["path"].endswith("observation.json"))
            assert len(observation["hash"]) == 64
