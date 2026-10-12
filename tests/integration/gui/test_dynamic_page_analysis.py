"""Presentation tests for scoped dynamic and coverage analysis."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from seclab.gui.pages.dynamic_page import DynamicPage
from seclab.results import VerificationResult, VerificationStatus


@pytest.fixture(scope="module")
def application():
    return QApplication.instance() or QApplication([])


def test_skipped_stages_explain_absence_of_observation_and_measurement(application):
    page = DynamicPage()
    report = SimpleNamespace(run_id="run-skipped", results=(), stage_summaries=(
        {"stage_id": "DYNAMIC", "status": "SKIPPED", "reason": "The specification contains no test cases."},
        {"stage_id": "COVERAGE", "status": "SKIPPED", "reason": "Coverage requires explicit tests."},
    ))
    page.show_report(report)
    assert "no test cases" in page.summary.text().lower()
    assert "chưa có số đo coverage" in page.summary.text().lower()
    assert page.tests.table.rowCount() == 1
    assert page.coverage.table.rowCount() == 1
    assert "requires explicit tests" in page.coverage.table.item(0, 6).text().lower()
    page.close()


def test_renders_scoped_results_real_observation_and_coverage_metrics(application):
    result = VerificationResult(
        id="result-1", stage="DYNAMIC_TEST", technique="DYNAMIC", status=VerificationStatus.FAIL,
        reason_code="ORACLE_VIOLATION", message="Expected behavior was not observed.", scope="testcase:tc-1",
        evidence_ids=("ev-case", "ev-observation", "ev-execution"), duration_ms=12.5,
        metadata={"test_case_id": "tc-1", "function": "step", "input": {"args": {"x": 3}},
                  "build_status": "BUILT", "executed": True, "oracle": {"return_value": 7},
                  "observation": {"return_value": 6, "stdout": "observed output", "exit_code": 0},
                  "execution_id": "exec-1",
                  "observation_evidence_id": "ev-observation"},
    )
    report = SimpleNamespace(run_id="run-real-data", results=(result,), metadata={"execution_index": {
        "exec-1": {"executed": True, "observation": {"return_value": 6, "stdout": "observed output", "exit_code": 0},
                    "observation_evidence_id": "ev-observation", "evidence_ids": ["ev-case", "ev-observation"]}}}, stage_summaries=(
        {"stage_id": "DYNAMIC", "status": "COMPLETED", "metadata": {"test_count": 1, "executed_count": 1}},
        {"stage_id": "COVERAGE", "status": "COMPLETED", "output": {
            "backend": "fixture-backend",
            "line_metrics": {"covered_lines": 4, "total_lines": 5, "percentage": 80.0,
                             "files": [{"file": "src/demo.c", "covered_lines": 4, "total_lines": 5, "percentage": 80.0}]},
            "branch_metrics": {"covered_branches": 1, "total_branches": 2, "percentage": 50.0, "files": []},
            "limitations": ["fixture scope"],
        }},
    ))
    page = DynamicPage()
    page.show_report(report)
    assert "FAIL" in page.summary.text()
    assert "line 4/5" in page.summary.text()
    assert page.tests.table.rowCount() == 1
    assert "FAIL" in page.tests.table.item(0, 10).text()
    assert "return=6" in page.tests.table.item(0, 7).text()
    assert "returned_value" in page.tests.table.item(0, 9).text()
    assert page.tests.table.item(0, 1).text() == "step"
    assert page.tests.table.columnCount() == 14
    assert all(page.tests.table.item(0, column).text().lower() != "null"
               for column in range(page.tests.table.columnCount()))
    assert page.coverage.table.rowCount() == 3
    # The result object retained actual observation independently from the oracle.
    assert page._result_by_row[0].metadata["observation"]["return_value"] == 6
    page.close()
