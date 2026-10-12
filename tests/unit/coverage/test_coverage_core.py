from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from seclab.coverage import (BranchCoverage, CoverageDelta, CoverageReport, CoverageSnapshot, FileLineCoverage,
    LineCoverage, aggregate_branch_coverage, aggregate_function_coverage, aggregate_line_coverage,
    parse_gcov_function_summary, parse_gcov_json, parse_gcov_text, parse_llvm_export)
from seclab.coverage.errors import CoverageError


def test_gcov_text_lines_branches_non_executable_and_multiple_files() -> None:
    text = """        -:    0:Source:src/a.c
        1:    1:int f(int x) {
        1:    2:  if (x) return 1;
branch  0 taken 1
branch  1 never executed
    #####:    3:  return 0;
        -:    4:}
        -:    0:Source:src/b.c
        1:    1:int g(void) { return 3; }
"""
    parsed = parse_gcov_text(text)
    assert parsed.lines == {"src/a.c": {1: 1, 2: 1, 3: 0}, "src/b.c": {1: 1}}
    assert list(parsed.branches.values()) == [True, False]


def test_gcov_json_malformed_records_are_diagnostics() -> None:
    parsed = parse_gcov_json(json.dumps({"files": [{"file": "a.c", "lines": [
        {"line_number": 2, "count": 1, "branches": [{"count": 1}]}, {"line_number": "bad", "count": 0}
    ]}]}))
    assert parsed.lines == {"a.c": {2: 1}}
    assert parsed.branches["a.c|2||0"] is True
    assert parsed.diagnostics


def test_llvm_parser_segments_branch_outcomes_and_malformed_records() -> None:
    parsed = parse_llvm_export(json.dumps({"data": [{"files": [{"filename": "src/a.c",
        "segments": [[1, 1, 3, True, True, False], [2, 1, 0, True, True, False], [3, 1, 9]],
        "branches": [[2, 4, 0, 1, 0, 0]]}]}]}))
    assert parsed.lines == {"src/a.c": {1: 3, 2: 0}}
    assert sorted(parsed.branches.values()) == [False, True]
    assert parsed.diagnostics


def test_function_coverage_parsers_and_aggregation() -> None:
    llvm = parse_llvm_export(json.dumps({"data": [{"files": [{"filename": "a.c", "segments": [], "branches": []}],
        "functions": [{"name": "called", "count": 2, "filenames": ["a.c"]},
                      {"name": "missed", "count": 0, "filenames": ["a.c"]}]}]}))
    assert llvm.functions == {"a.c|called": 2, "a.c|missed": 0}
    gcov = parse_gcov_function_summary("Function 'called'\nLines executed:100.00% of 2\n"
                                       "Function 'missed'\nLines executed:0.00% of 2\n", "a.c")
    assert gcov.functions == {"a.c|called": 1, "a.c|missed": 0}
    metrics = aggregate_function_coverage({"a.c|called": 3, "a.c|missed": 0})
    assert (metrics.covered_functions, metrics.total_functions, metrics.percentage) == (1, 2, 50)
    assert aggregate_function_coverage({}).percentage is None


def test_metrics_zero_totals_and_union_delta() -> None:
    lines = aggregate_line_coverage({"a.c": {1: 1, 2: 0}, "b.c": {5: 2}})
    assert (lines.covered_lines, lines.total_lines, lines.percentage) == (2, 3, pytest.approx(200 / 3))
    empty = LineCoverage(0, 0, (FileLineCoverage("empty.c", 0, 0),))
    assert empty.percentage is None
    branches = aggregate_branch_coverage({"a.c|1|0": True, "a.c|1|1": False}, "arcs")
    assert branches.percentage == 50
    delta = CoverageDelta.between(CoverageSnapshot(frozenset({("a.c", 1)}), frozenset()),
                                  CoverageSnapshot(frozenset({("a.c", 1), ("a.c", 2)}), frozenset({"b.c|1|0"})))
    assert delta.new_lines == (("a.c", 2),)
    assert delta.new_branches == ("b.c|1|0",)


def test_report_serialization_is_deterministic_and_backend_named() -> None:
    report = CoverageReport("gcov", ("z.c", "a.c"), aggregate_line_coverage({"z.c": {4: 1}}),
        aggregate_branch_coverage({"z.c|4|1": True}, "gcov arcs"), 1, ("T1",), True, False,
        limitations=("measurement only",))
    assert report.to_json() == report.to_json()
    assert report.to_dict()["source_files"] == ["z.c", "a.c"]
    assert report.to_dict()["line_metrics"]["files"][0]["file"] == "z.c"


def test_measurement_hash_ignores_random_evidence_references() -> None:
    args = ("gcov", ("a.c",), aggregate_line_coverage({"a.c": {1: 1}}),
            aggregate_branch_coverage({}, "arcs"), 1, ("T1",), True, False)
    first = CoverageReport(*args, evidence_ids=("random-a",))
    second = CoverageReport(*args, evidence_ids=("random-b",))
    assert first.measurement_sha256 == second.measurement_sha256
    assert first.to_dict()["measurement_sha256"] == first.measurement_sha256


def test_bad_root_json_is_coverage_error() -> None:
    with pytest.raises(CoverageError):
        parse_llvm_export("not-json")


def test_coverage_setup_error_is_inconclusive_with_hashed_diagnostic(tmp_path) -> None:
    import hashlib

    from seclab.config import Toolchain
    from seclab.coverage import CoverageRunner
    from seclab.results import VerificationStatus

    measured = CoverageRunner(tmp_path, Toolchain([])).run((), source_files=())
    result = measured.verification_result
    assert result is not None and result.status is VerificationStatus.INCONCLUSIVE
    assert len(result.evidence_ids) == 1
    ref = result.metadata["evidence"][0]
    artifact = tmp_path / ref["path"]
    assert artifact.is_file()
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == ref["sha256"]


def test_gcov_missing_counter_and_notes_are_measurement_data_missing(tmp_path) -> None:
    from seclab.config import Toolchain
    from seclab.coverage import GcovBackend
    from seclab.evidence import ArtifactStore
    from seclab.execution.process_runner import ProcessRunner

    source = tmp_path / "source.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    backend = GcovBackend(Toolchain([]), ProcessRunner(), ArtifactStore(tmp_path), tmp_path)
    object_dir = tmp_path / "objects"
    object_dir.mkdir()
    raw = tmp_path / "raw"
    raw.mkdir()
    no_data = backend.collect(tmp_path / "app.exe", (source,), object_dir, raw, "no-gcda")
    assert no_data.error_code == "COVERAGE_DATA_MISSING"
    (object_dir / "unit-0-source.gcda").write_bytes(b"counter")
    no_notes = backend.collect(tmp_path / "app.exe", (source,), object_dir, raw, "no-gcno")
    assert no_notes.error_code == "COVERAGE_DATA_MISSING"


def test_gcov_short_path_is_requested_for_long_windows_paths(monkeypatch) -> None:
    import ctypes
    from pathlib import Path

    from seclab.coverage.gcov_backend import _short_path

    class ShortPathFunction:
        def __call__(self, path, buffer, _size):
            buffer.value = "C:\\SHORT"
            return len(buffer.value)

    function = ShortPathFunction()
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(kernel32=SimpleNamespace(GetShortPathNameW=function)), raising=False)
    long_path = Path("C:/" + "longsegment" * 25 + "/file.gcno")
    assert str(_short_path(long_path)) == "C:\\SHORT\\file.gcno"
