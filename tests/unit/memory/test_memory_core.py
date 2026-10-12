from __future__ import annotations

import json
import sys

from seclab.memory import (
    LeakChecker, MemoryFinding, StructAnalyzer, parse_asan_output, parse_ubsan_output,
)
from seclab.results import VerificationStatus
from seclab.static_analysis import AnalysisContext
from seclab.config import Toolchain
from seclab.evidence import ArtifactStore
from seclab.execution import CommandRunner


def test_memory_finding_json_roundtrip_with_optional_fields() -> None:
    item = MemoryFinding("m", "AddressSanitizer", "HEAP_BUFFER_OVERFLOW", "overflow",
                         file="C:/work tree/a.c", line=9, address="0x123", stack_trace=("#0 main",),
                         metadata={"size": 4})
    assert MemoryFinding.from_dict(json.loads(item.to_json())) == item


def test_asan_parser_recognizes_buffer_uaf_double_free_and_unknown() -> None:
    samples = {
        "heap-buffer-overflow": "ERROR: AddressSanitizer: heap-buffer-overflow on address 0xabc\n    #0 0x1 in main C:/work tree/a.c:9\n",
        "stack-buffer-overflow": "ERROR: AddressSanitizer: stack-buffer-overflow on address 0xabc\n",
        "heap-use-after-free": "ERROR: AddressSanitizer: heap-use-after-free on address 0xabc\n",
        "double-free": "ERROR: AddressSanitizer: attempting double-free on 0xabc\n",
        "invalid-free": "ERROR: AddressSanitizer: attempting free on address 0xabc which was not malloc()-ed\n",
        "global-buffer-overflow": "ERROR: AddressSanitizer: global-buffer-overflow on address 0xabc\n",
    }
    expected_kinds = {"heap-buffer-overflow": "HEAP_BUFFER_OVERFLOW", "stack-buffer-overflow": "STACK_BUFFER_OVERFLOW",
                      "heap-use-after-free": "HEAP_USE_AFTER_FREE", "double-free": "DOUBLE_FREE",
                      "invalid-free": "INVALID_FREE", "global-buffer-overflow": "GLOBAL_BUFFER_OVERFLOW"}
    for expected, output in samples.items():
        assert parse_asan_output(output)[0].kind == expected_kinds[expected]
    parsed = parse_asan_output(samples["heap-buffer-overflow"], raw_evidence="ev")[0]
    assert parsed.file == "C:/work tree/a.c" and parsed.line == 9
    assert parsed.raw_evidence == "ev"
    assert parse_asan_output("program crashed with access violation") == ()


def test_leak_report_is_parsed_but_unknown_text_is_not_invented() -> None:
    leak = parse_asan_output("ERROR: LeakSanitizer: detected memory leaks\nDirect leak of 8 byte(s)")
    assert leak[0].kind == "MEMORY_LEAK"
    assert parse_asan_output("AddressSanitizer: random unsupported report") == ()


def test_ubsan_parser_recognizes_required_runtime_errors_and_paths() -> None:
    output = """C:\\work tree\\math.c:14:7: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented
src/shift.c:4:3: runtime error: shift exponent 99 is too large for 32-bit type 'int'
src/div.c:5:9: runtime error: division by zero
src/align.c:7:2: runtime error: misaligned address 0x123
src/other.c:8:1: runtime error: unknown kind
runtime error: unknown behavior without source location
"""
    findings = parse_ubsan_output(output)
    assert [item.kind for item in findings] == ["SIGNED_INTEGER_OVERFLOW", "INVALID_SHIFT", "DIVISION_BY_ZERO",
                                                "ALIGNMENT_VIOLATION", "UNDEFINED_BEHAVIOR", "UNDEFINED_BEHAVIOR"]
    assert findings[0].file == "C:/work tree/math.c" and findings[0].line == 14
    assert parse_ubsan_output("not a sanitizer report") == ()


def test_leak_checker_unavailable_platform_is_inconclusive(tmp_path, monkeypatch) -> None:
    root = tmp_path / "src"; root.mkdir()
    workspace = tmp_path / "workspace"; workspace.mkdir()
    context = AnalysisContext(root, workspace, Toolchain([]), CommandRunner(), ArtifactStore(workspace))
    monkeypatch.setattr("seclab.memory.leak_checker.sys.platform", "win32")
    result = LeakChecker().run((), context, "C")
    assert not result.supported
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert result.verification_result.reason_code == "LEAK_DETECTION_UNAVAILABLE"


def test_struct_analyzer_reports_limitations_instead_of_guessing() -> None:
    result = StructAnalyzer().analyze(())
    assert not result.supported and not result.layouts
    assert "compiler-backed" in result.limitations[0]


def test_ubsan_parser_preserves_multiple_independent_findings() -> None:
    findings = parse_ubsan_output(
        "a.c:3:4: runtime error: division by zero\n"
        "b.c:8:2: runtime error: signed integer overflow: 1 + 2 cannot be represented",
        raw_evidence="raw-1")
    assert [item.kind for item in findings] == ["DIVISION_BY_ZERO", "SIGNED_INTEGER_OVERFLOW"]
    assert all(item.raw_evidence == "raw-1" for item in findings)


def test_missing_sanitizer_compiler_is_environment_limited_with_evidence(tmp_path, monkeypatch) -> None:
    from seclab.memory import ASanRunner
    from seclab.source import SourceLoader
    from seclab.execution import BuildResult

    root = tmp_path / "src"
    root.mkdir()
    (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = AnalysisContext(root, workspace, Toolchain([]), CommandRunner(), ArtifactStore(workspace))
    monkeypatch.setattr("seclab.memory.sanitizer.Compiler.build",
        lambda *_args, **_kwargs: BuildResult(False, None, None, None, (), "C", "COMPILER_NOT_FOUND"))
    run = ASanRunner().run(SourceLoader().load_source_tree(root), context, "C")
    assert not run.supported
    assert run.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert run.verification_result.reason_code == "COMPILER_NOT_FOUND"
    assert run.verification_result.metadata["capability_status"] == "ENVIRONMENT_LIMITED"
    assert run.evidence
    assert all((workspace / item.path).is_file() for item in run.evidence)
