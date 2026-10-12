from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from seclab.config import ToolInfo, Toolchain
from seclab.coverage import CoverageRunner
from seclab.results import VerificationStatus
from seclab.testing import TestCase


def test_real_gcov_suite_aggregates_both_function_branches_and_keeps_oracle_failure(tmp_path: Path) -> None:
    if not (shutil.which("gcc") and shutil.which("gcov")):
        pytest.skip("gcc and gcov are required for the gcov integration.")
    source_dir = tmp_path / "sut sources"
    source_dir.mkdir()
    source = source_dir / "branch fixture.c"
    source.write_text("int classify(int x) {\n  if (x > 0) return 1;\n  else return -1;\n}\n", encoding="utf-8")
    cases = (
        TestCase("positive", "positive", "classify", {"x": 5}, {"return_value": 1}),
        TestCase("negative", "negative wrong oracle", "classify", {"x": -5}, {"return_value": 99}),
    )
    workspace = tmp_path / "coverage workspace"
    toolchain = Toolchain(["gcc", "gcov"])
    runner = CoverageRunner(workspace, toolchain)
    run = runner.run(cases, source_files=[source], backend="gcov")
    assert run.report is not None, run.errors
    assert run.report.backend == "gcov"
    assert run.report.line_metrics.total_lines > 0
    assert run.report.branch_metrics.total_branches > 0
    assert run.report.function_metrics is not None
    assert run.report.function_metrics.total_functions > 0
    assert run.report.function_metrics.covered_functions == run.report.function_metrics.total_functions
    assert len(run.report.measurement_sha256) == 64
    assert run.report.branch_metrics.covered_branches == run.report.branch_metrics.total_branches
    assert run.report.tests_executed == 2
    assert run.report.partial is False
    assert run.test_results[1].verification_result.status is VerificationStatus.FAIL
    assert run.report.evidence_ids
    integrity_path = next((workspace / "evidence" / "coverage-integrity").glob("*-report-integrity.json"))
    integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
    report_path = workspace / integrity["path"]
    assert hashlib.sha256(report_path.read_bytes()).hexdigest() == integrity["sha256"]
    assert json.loads(report_path.read_text(encoding="utf-8"))["measurement_sha256"] == run.report.measurement_sha256
    single = runner.run(cases[:1], source_files=[source], backend="gcov")
    assert single.report is not None
    assert single.report.branch_metrics.covered_branches < single.report.branch_metrics.total_branches
    assert all(str(path).startswith(str(workspace / "coverage")) for path in (workspace / "coverage").rglob("*.gcno"))
    assert not list(source_dir.glob("*.gcda")) and not list(source_dir.glob("*.gcno"))


def test_explicit_llvm_missing_tool_does_not_fallback(tmp_path: Path) -> None:
    class MissingCoverageTools(Toolchain):
        def get(self, name: str) -> ToolInfo:
            capabilities = self.TOOL_CAPABILITIES.get(name, ())
            return ToolInfo(name, False, None, None, tuple(capabilities))

    toolchain = MissingCoverageTools([])
    source = tmp_path / "x.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    result = CoverageRunner(tmp_path / "work", toolchain).run(
        [TestCase("noop", "noop", "main", {}, {"exit_code": 0}, target_kind="EXECUTABLE")],
        source_files=[source], backend="llvm")
    assert result.report is None
    assert result.verification_result is not None
    assert result.verification_result.status is VerificationStatus.TOOL_ERROR


def test_instrumented_compiler_failure_is_build_error_not_coverage_failure_verdict(tmp_path: Path) -> None:
    if not (shutil.which("gcc") and shutil.which("gcov")):
        pytest.skip("gcc and gcov are required for the instrumented-build test.")
    source = tmp_path / "incompatible.c"
    source.write_text("int main(void) { return missing_symbol(); }\n", encoding="utf-8")
    case = TestCase("broken-build", "broken build", "app", {}, {"exit_code": 0}, target_kind="EXECUTABLE")
    result = CoverageRunner(tmp_path / "workspace", Toolchain(["gcc", "gcov"])).run(
        (case,), source_files=(source,), backend="gcov")
    assert result.report is None
    assert result.verification_result is not None
    assert result.verification_result.status is VerificationStatus.BUILD_ERROR
    assert result.verification_result.reason_code == "COVERAGE_BUILD_FAILED"


def test_real_llvm_coverage_integration_when_tools_are_available(tmp_path: Path) -> None:
    names = ("clang", "llvm-cov", "llvm-profdata")
    if not all(shutil.which(name) for name in names):
        pytest.skip("clang, llvm-cov and llvm-profdata are required for LLVM integration.")
    source_dir = tmp_path / "llvm sut"
    source_dir.mkdir()
    source = source_dir / "branch.c"
    source.write_text("int classify(int x) {\n  if (x > 0) return 1;\n  else return -1;\n}\n", encoding="utf-8")
    cases = (TestCase("positive", "positive", "classify", {"x": 2}, {"return_value": 1}),
             TestCase("negative", "negative", "classify", {"x": -2}, {"return_value": -1}))
    result = CoverageRunner(tmp_path / "llvm workspace", Toolchain(list(names))).run(
        cases, source_files=[source], backend="llvm")
    assert result.report is not None, result.errors
    assert result.report.backend == "llvm"
    assert result.report.line_metrics.total_lines > 0
    assert result.report.branch_metrics.total_branches > 0
    assert result.report.branch_metrics.covered_branches == result.report.branch_metrics.total_branches
    assert result.report.function_metrics is not None and result.report.function_metrics.covered_functions > 0
    assert result.report.partial is False


def test_timeout_marks_suite_partial_while_preserving_other_coverage(tmp_path: Path) -> None:
    if not (shutil.which("gcc") and shutil.which("gcov")):
        pytest.skip("gcc and gcov are required for the partial-run integration.")
    source = tmp_path / "partial.c"
    source.write_text("#include <stdio.h>\nint main(int argc, char **argv) {\n if (argc > 1) { volatile unsigned long i; for (i=0; i<10000000000UL; ++i) {} }\n puts(\"ok\");\n return 0;\n}\n", encoding="utf-8")
    cases = (TestCase("normal", "normal", "partial", {"argv": []}, {"stdout": "ok\n"}, target_kind="EXECUTABLE"),
             TestCase("timeout", "timeout", "partial", {"argv": ["slow"]}, {"exit_code": 0},
                      target_kind="EXECUTABLE", timeout_seconds=0.05))
    result = CoverageRunner(tmp_path / "partial workspace", Toolchain(["gcc", "gcov"])).run(
        cases, source_files=[source], backend="gcov")
    assert result.report is not None, result.errors
    assert result.report.partial is True
    assert result.report.tests_executed == 2
    assert result.report.line_metrics.total_lines > 0
