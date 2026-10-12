from __future__ import annotations

from seclab.benchmark.catalog import CASES
from seclab.benchmark.models import BenchmarkCase, BenchmarkObservation, compare_benchmark
from seclab.benchmark.production import execute_case
from seclab.benchmark.runner import run_benchmark
from seclab.benchmark.report import render_markdown


def test_ground_truth_catalog_covers_requested_categories_and_has_required_fields() -> None:
    categories = {case.category for case in CASES}
    assert categories == {"CTL", "BMC", "SMT", "Static", "Memory", "Dynamic", "Coverage", "Fuzzing"}
    assert len({case.benchmark_id for case in CASES}) == len(CASES)
    assert len(CASES) >= 60
    for case in CASES:
        assert case.description and case.expected_checker and case.expected_status
        assert case.category and case.expected_evidence


def test_catalog_has_required_positive_negative_and_nonbinary_fixture_scenarios() -> None:
    cases = {case.case_id: case for case in CASES}
    expected = {
        "CTL-001": "PASS", "CTL-002": "FAIL",
        "BMC-001": "FAIL", "BMC-008": "PASS", "BMC-002": "INCONCLUSIVE",
        "SMT-001": "FAIL", "SMT-002": "PASS", "SMT-003": "INCONCLUSIVE", "SMT-005": "SPEC_ERROR",
        "STATIC-001": "INCONCLUSIVE", "STATIC-002": "INCONCLUSIVE",
        "DYN-001": "PASS", "DYN-002": "FAIL", "DYN-004": "INCONCLUSIVE", "DYN-007": "FAIL",
        "MEM-001": "FAIL", "MEM-002": "FAIL", "MEM-003": "FAIL", "MEM-004": "FAIL",
        "MEM-005": "PASS", "MEM-006": "ENVIRONMENT_LIMITED",
        "FUZZ-001": "FAIL", "FUZZ-002": "INCONCLUSIVE", "FUZZ-003": "INCONCLUSIVE",
    }
    assert all(cases[case_id].expected_status == status for case_id, status in expected.items())
    assert cases["DYN-006"].expected_status == "UNSUPPORTED"
    assert cases["STATIC-004"].expected_status == "TOOL_ERROR"
    assert cases["DYN-003"].expected_status == "BUILD_ERROR"


def test_production_formal_dynamic_and_coverage_adapters_match_ground_truth() -> None:
    selected = tuple(case for case in CASES if case.category in {"CTL", "BMC", "SMT", "Static", "Dynamic", "Coverage", "Fuzzing"})
    report = run_benchmark(selected, execute_case)
    assert report.benchmark_count == len(selected)
    # IDs that the checker itself does not emit remain unknown observations;
    # they are not copied from expected_property to make the comparator green.
    assert all(row["actual_property"] is None or row["actual_property"] == row["expected_property"]
               for row in report.expected_vs_actual if row["case_id"] != "COV-005")
    assert not report.false_positives
    assert not report.false_negatives
    assert "BMC-002" in report.inconclusive
    assert "DYN-004" in report.inconclusive or "DYN-004" in report.tool_errors
    assert "FUZZ-002" in report.inconclusive


def test_bmc_catalog_has_distinct_reachable_unreachable_and_insufficient_bound_cases() -> None:
    by_id = {case.case_id: case for case in CASES if case.category == "BMC"}
    assert by_id["BMC-001"].expected_status == "FAIL"
    assert by_id["BMC-008"].expected_status == "PASS"
    assert by_id["BMC-008"].scenario["model"] == "safe-linear"
    assert by_id["BMC-002"].expected_status == "INCONCLUSIVE"
    actual = execute_case(by_id["BMC-008"])
    assert actual.actual_status == "PASS"
    assert actual.actual_finding == "NONE"
    payload = actual.evidence_payloads[0]["content"]
    assert any(state["id"] == "UNREACHABLE_BAD" for state in payload["model"]["states"])
    assert all(edge["source"] != "UNREACHABLE_BAD" for edge in payload["model"]["transitions"])


def test_dynamic_crash_and_fuzz_crash_use_real_process_execution() -> None:
    dynamic_crash = execute_case(next(case for case in CASES if case.case_id == "DYN-007"))
    assert dynamic_crash.actual_status == "FAIL"
    assert dynamic_crash.actual_finding == "ABNORMAL_TERMINATION"
    dynamic_payload = dynamic_crash.evidence_payloads[0]["content"]
    assert dynamic_payload["observed"]["crashed"] is True
    assert dynamic_payload["oracle_evaluation"]["checks"][0]["actual"] is True

    dynamic = execute_case(next(case for case in CASES if case.case_id == "DYN-005"))
    assert dynamic.actual_status in {"INCONCLUSIVE", "BUILD_ERROR"}
    assert dynamic.actual_finding in {"MEMORY_FINDING:HEAP_BUFFER_OVERFLOW", "NONE", "SANITIZER_UNAVAILABLE", "BUILD_FAILED"}
    if dynamic.actual_status == "BUILD_ERROR":
        assert dynamic.actual_finding == "BUILD_FAILED"
        assert dynamic.evidence_payloads[0]["content"]["build_result"] is not None
    else:
        assert dynamic.evidence_payloads[0]["content"]["command_result"] is not None
        observed = dynamic.evidence_payloads[0]["content"]["observed"]
    if dynamic.actual_finding == "MEMORY_FINDING:HEAP_BUFFER_OVERFLOW":
        assert observed["memory_findings"]
    elif dynamic.actual_finding == "SANITIZER_UNAVAILABLE":
        assert not observed["memory_analysis_available"]

    fuzz = execute_case(next(case for case in CASES if case.case_id == "FUZZ-001"))
    campaign = fuzz.evidence_payloads[0]["content"]["campaign"]
    assert fuzz.actual_finding in {"ABNORMAL_TERMINATION", "NONE"}
    assert (campaign["crashes"] >= 1) == (fuzz.actual_finding == "ABNORMAL_TERMINATION")
    if fuzz.actual_finding == "ABNORMAL_TERMINATION":
        assert campaign["failures"]


def test_scorer_distinguishes_false_positive_false_negative_and_unsupported() -> None:
    cases = (
        BenchmarkCase("CLEAN", "clean", None, None, "checker", "PASS", "NONE", None,
                      ("result",), None, "test"),
        BenchmarkCase("VULN", "vulnerable", "source", None, "checker", "FAIL", "BUG", None,
                      ("finding",), None, "test"),
    )
    observations = (
        BenchmarkObservation("CLEAN", "checker", "FAIL", "BUG", evidence=("result",)),
        BenchmarkObservation("VULN", "checker", "PASS", "NONE", evidence=("finding",)),
    )
    report = compare_benchmark(cases, observations)
    assert report.false_positives == ("CLEAN",)
    assert report.false_negatives == ("VULN",)
    unsupported = BenchmarkObservation("VULN", "checker", "UNSUPPORTED", unsupported_reason="adapter unavailable")
    report = compare_benchmark(cases, (observations[0], unsupported))
    assert report.unsupported == ("VULN",)
    assert report.false_negatives == ()


def test_report_metrics_are_checker_local_and_exclude_nonbinary_expected_cases() -> None:
    cases = (
        BenchmarkCase("PASS", "pass", None, None, "one", "PASS", "NONE", None,
                      ("result",), None, "test"),
        BenchmarkCase("FAIL", "fail", None, None, "one", "FAIL", "BUG", None,
                      ("finding",), None, "test"),
        BenchmarkCase("INC", "inconclusive", None, None, "two", "INCONCLUSIVE", "NONE", None,
                      ("record",), None, "test"),
    )
    observed = (
        BenchmarkObservation("PASS", "one", "PASS", "NONE", evidence=("result",)),
        BenchmarkObservation("FAIL", "one", "FAIL", "BUG", evidence=("finding",)),
        BenchmarkObservation("INC", "two", "INCONCLUSIVE", "NONE", evidence=("record",)),
    )
    report = compare_benchmark(cases, observed)
    assert report.checker_metrics["one"]["true_positive"] == 1
    assert report.checker_metrics["one"]["true_negative"] == 1
    assert report.checker_metrics["two"]["inconclusive_rate"] == 1.0


def test_expected_ground_truth_is_independent_of_actual_observation() -> None:
    case = next(case for case in CASES if case.case_id == "CTL-001")
    expected = case.to_dict()
    report = compare_benchmark((case,), (BenchmarkObservation(
        case.case_id, case.checker, "FAIL", "unexpected", evidence=("counterexample",)),))
    assert case.to_dict() == expected
    row = report.expected_vs_actual[0]
    assert row["expected_status"] == expected["expected_status"]
    assert row["actual_status"] == "FAIL"
    assert row["mismatch_classification"] == "FALSE_POSITIVE"


def test_metrics_have_checker_local_rates_and_ignore_inconclusive_for_confusion_counts() -> None:
    cases = (
        BenchmarkCase("TP", "vulnerable found", None, None, "static", "FAIL", "BUG", None, ("finding",), None, "Static"),
        BenchmarkCase("TN", "clean", None, None, "static", "PASS", "NONE", None, ("result",), None, "Static"),
        BenchmarkCase("FP", "clean flagged", None, None, "static", "PASS", "NONE", None, ("result",), None, "Static"),
        BenchmarkCase("FN", "bug missed", None, None, "static", "FAIL", "BUG", None, ("finding",), None, "Static"),
        BenchmarkCase("INC", "limited", None, None, "static", "FAIL", "BUG", None, ("finding",), None, "Static"),
    )
    statuses = ("FAIL", "PASS", "FAIL", "PASS", "INCONCLUSIVE")
    observations = tuple(BenchmarkObservation(
        case.case_id, "static", status,
        "BUG" if case.case_id in {"TP", "FP"} else None if case.case_id == "INC" else "NONE",
        evidence=case.expected_evidence,
    ) for case, status in zip(cases, statuses))
    metrics = compare_benchmark(cases, observations).checker_metrics["static"]
    assert (metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]) == (1, 1, 1, 1)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["specificity"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["inconclusive"] == 1
    assert metrics["inconclusive_rate"] == 0.2


def test_environment_limitations_are_not_scored_as_false_positive_or_negative() -> None:
    case = BenchmarkCase("ENV", "sanitizer unavailable", "int main(void) { return 0; }", None,
                         "memory", "FAIL", "OVERFLOW", None, ("sanitizer_report",),
                         "Sanitizer may not be installed", "Memory")
    observation = BenchmarkObservation("ENV", "memory", "ENVIRONMENT_LIMITED",
                                       unsupported_reason="sanitizer runtime not installed")
    report = compare_benchmark((case,), (observation,))
    row = report.expected_vs_actual[0]
    metrics = report.checker_metrics["memory"]
    assert row["mismatch_classification"] == "ENVIRONMENT_LIMITED"
    assert report.false_positives == report.false_negatives == ()
    assert metrics["TP"] == metrics["TN"] == metrics["FP"] == metrics["FN"] == 0
    assert metrics["environment_limited_rate"] == 1.0


def test_coverage_and_report_do_not_create_project_verdict_or_score() -> None:
    case = next(case for case in CASES if case.category == "Coverage")
    report = compare_benchmark((case,), (BenchmarkObservation(
        case.case_id, case.checker, case.expected_status, case.expected_finding,
        evidence=case.expected_evidence),))
    payload = report.to_dict()
    markdown = render_markdown(payload)
    assert "project_accuracy" not in payload
    assert "overall_verdict" not in payload
    assert payload["metric_scope"] == "FIXTURE_LEVEL_ONLY"
    assert all(row["metric_scope"] == "FIXTURE_LEVEL_ONLY" for row in payload["expected_vs_actual"])
    assert "fixture-level only" in markdown.lower()
    assert "No cross-checker accuracy score or project verdict is computed." in markdown
    assert "Coverage cases measure execution coverage and are not safety PASS/FAIL results." in markdown


def test_catalog_integrity_hashes_and_ground_truth_provenance_are_reproducible() -> None:
    import hashlib
    import json
    from pathlib import Path

    for case in CASES:
        payload = case.to_dict()
        fixture = json.dumps(case.input, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ground_truth = payload["ground_truth"]
        encoded_gt = json.dumps(ground_truth, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        assert payload["fixture_sha256"] == hashlib.sha256(fixture).hexdigest()
        assert payload["ground_truth_sha256"] == hashlib.sha256(encoded_gt).hexdigest()
        assert payload["ground_truth_catalog_sha256"] == hashlib.sha256(
            Path(__file__).parents[2].joinpath("src/seclab/benchmark/catalog.py").read_bytes()).hexdigest()
        assert case.ground_truth_source and case.creation_method and case.independent_validation


def test_inconclusive_tool_error_build_error_skipped_and_environment_are_distinct() -> None:
    case = BenchmarkCase("POS", "known defect", None, None, "checker", "FAIL", "BUG", None,
                         ("finding",), None, "test")
    observations = tuple(BenchmarkObservation("POS", "checker", status, "BUG", evidence=("finding",))
                         for status in ("INCONCLUSIVE", "TOOL_ERROR", "BUILD_ERROR", "SKIPPED", "ENVIRONMENT_LIMITED"))
    reports = tuple(compare_benchmark((case,), (item,)) for item in observations)
    assert [report.expected_vs_actual[0]["mismatch_classification"] for report in reports] == [
        "INCONCLUSIVE", "TOOL_ERROR", "BUILD_ERROR", "SKIPPED", "ENVIRONMENT_LIMITED"]
    assert all(not report.false_negatives for report in reports)


def test_metrics_require_both_ground_truth_classes_and_include_accuracy() -> None:
    positive = BenchmarkCase("P", "positive", None, None, "one", "FAIL", "BUG", None,
                             ("finding",), None, "test")
    negative = BenchmarkCase("N", "negative", None, None, "one", "PASS", "NONE", None,
                             ("result",), None, "test")
    observed = (BenchmarkObservation("P", "one", "FAIL", "BUG", evidence=("finding",)),
                BenchmarkObservation("N", "one", "PASS", "NONE", evidence=("result",)))
    metrics = compare_benchmark((positive, negative), observed).checker_metrics["one"]
    assert metrics["metrics_ready"] is True
    assert metrics["accuracy"] == 1.0


def test_formal_benchmark_observations_are_deterministic() -> None:
    from seclab.benchmark.runner import run_benchmark

    selected = tuple(case for case in CASES if case.case_id in {"CTL-010", "SMT-010", "BMC-006"})
    first = run_benchmark(selected, execute_case).to_dict()
    second = run_benchmark(selected, execute_case).to_dict()
    assert first == second


def test_expected_field_mutations_do_not_change_dynamic_or_static_observations() -> None:
    from dataclasses import replace

    for case_id in ("DYN-001", "DYN-007", "STATIC-003"):
        case = next(case for case in CASES if case.case_id == case_id)
        changed = replace(case, expected_status="FAIL" if case.expected_status != "FAIL" else "INCONCLUSIVE",
                          expected_finding="MUTATED_EXPECTATION", expected_property="MUTATED_PROPERTY",
                          expected_evidence=("mutated-evidence",))
        before, after = execute_case(case), execute_case(changed)
        assert (before.actual_checker, before.actual_status, before.actual_finding,
                before.actual_property, before.evidence) == (
                after.actual_checker, after.actual_status, after.actual_finding,
                after.actual_property, after.evidence)
        if case_id in {"DYN-001", "DYN-007"}:
            left = before.evidence_payloads[0]["content"]
            right = after.evidence_payloads[0]["content"]
            assert left["observed"] == right["observed"]
            assert left["oracle_evaluation"] == right["oracle_evaluation"]


def test_cov005_executes_real_testcase_and_measures_coverage_independently() -> None:
    case = next(case for case in CASES if case.case_id == "COV-005")
    observation = execute_case(case)
    assert observation.actual_status == "INCONCLUSIVE"
    assert observation.actual_finding == "ORACLE_VIOLATION"
    assert "oracle-evaluation" in observation.evidence
    payload = observation.evidence_payloads[0]["content"]
    assert payload["execution"]["observed"]["returned_value"] == 1
    assert payload["execution"]["oracle_evaluation"]["satisfied"] is False
    assert payload["coverage_report"]["line_metrics"]["total_lines"] > 0
    assert observation.actual_property.endswith("%")


def test_benchmark_manifest_labels_ground_truth_observation_and_comparison(tmp_path) -> None:
    import json
    from pathlib import Path

    case = next(case for case in CASES if case.case_id == "CTL-001")
    run_benchmark((case,), execute_case, workspace=tmp_path, execution_id="evidence-labels")
    run_root = Path(tmp_path) / "evidence-labels" / "evidence"
    refs = json.loads((run_root / "run" / "manifest.json").read_text())[
        "cases"][case.case_id]["evidence_references"]
    by_path = {item["path"]: item["metadata"]["classification"] for item in refs}
    assert any(value == "FIXTURE" for value in by_path.values())
    assert any(value == "GROUND_TRUTH" for value in by_path.values())
    assert any(value == "CHECKER_OBSERVATION" for value in by_path.values())
    comparison = json.loads((run_root / "CTL-001" / "comparison.json").read_text())
    # Comparison classification is carried on its own manifest reference.
    manifest_data = json.loads((run_root / "run" / "manifest.json").read_text())
    comparison_ref = manifest_data["cases"][case.case_id]["comparison_evidence"]
    assert comparison_ref["metadata"]["classification"] == "COMPARISON"
    assert comparison["matched"] is True
