from __future__ import annotations

import hashlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore
from seclab.execution import CommandRunner
from seclab.execution import BuildResult, CommandResult
from seclab.config import ToolInfo
from seclab.memory import ASanRunner, LeakChecker, UBSanRunner
from seclab.results import VerificationStatus
from seclab.source import LanguageDetector, SourceLoader
from seclab.static_analysis import (AnalysisContext, ClangStaticAnalyzerRunner, ClangTidyRunner,
    CompilerDiagnosticsRunner, CppcheckRunner)


def setup_project(tmp_path: Path, name: str, source: str):
    workspace = tmp_path / "workspace"
    project = workspace / name
    project.mkdir(parents=True)
    source_file = project / "case file.c"
    source_file.write_text(source, encoding="utf-8")
    sources = SourceLoader().load_source_tree(project)
    tools = Toolchain(version_timeout=1)
    context = AnalysisContext(project, workspace, tools, CommandRunner(), ArtifactStore(workspace), timeout=15)
    return workspace, source_file, sources, tools, context


def assert_evidence_hashes(workspace: Path, evidence) -> None:
    for item in evidence:
        path = workspace / item.path
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item.hash


def test_cppcheck_real_tool_invocation_and_evidence(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "cppcheck-sut", "int main(void) { int *p = 0; return *p; }\n")
    if not tools.get("cppcheck").installed:
        pytest.skip("cppcheck is not installed")
    original = source.read_bytes()
    result = CppcheckRunner().analyze(sources, context)
    assert result.executed and result.command_result is not None
    assert result.command_result.executable_path
    assert result.reason_code in {"NO_STATIC_FINDINGS", "STATIC_FINDINGS_DETECTED"}
    assert result.findings, "the null-pointer fixture should produce at least one Cppcheck finding"
    if result.findings:
        raw_ids = {item.id for item in result.evidence}
        assert all(item.raw_evidence in raw_ids for item in result.findings)
        assert result.to_verification_result().status is VerificationStatus.INCONCLUSIVE
    assert_evidence_hashes(workspace, result.evidence)
    assert result.to_verification_result().status is VerificationStatus.INCONCLUSIVE
    assert source.read_bytes() == original


def test_compiler_diagnostics_use_existing_toolchain_and_do_not_build(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "compiler-sut", "int main(void) { int unused = 3; return 0; }\n")
    if tools.compiler_for("C") is None:
        pytest.skip("No C compiler is installed")
    original = source.read_bytes()
    result = CompilerDiagnosticsRunner().analyze(sources, context)
    assert result.executed and result.command_result is not None
    assert result.command_result.succeeded
    assert result.findings
    assert all(item.category in {"warning", "error", "note"} for item in result.findings)
    assert_evidence_hashes(workspace, result.evidence)
    assert source.read_bytes() == original
    assert not (workspace / "build").exists()


def test_clang_tidy_integration_is_explicit_and_evidence_backed(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "clang-tidy-sut", "int main(void) { int unused = 1; return unused - 1; }\n")
    if not tools.get("clang-tidy").installed:
        pytest.skip("clang-tidy is not installed")
    original = source.read_bytes()
    result = ClangTidyRunner().analyze(sources, context)
    assert result.executed and result.command_result is not None
    assert result.successful
    assert result.evidence
    assert_evidence_hashes(workspace, result.evidence)
    assert source.read_bytes() == original
    assert "compile_commands.json" in " ".join(result.limitations) or (source.parent / "compile_commands.json").exists()


def test_clang_static_analyzer_runs_separately_from_clang_tidy(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "clang-static-sut", "int main(void) { int *p = 0; return *p; }\n")
    if not tools.get("clang").installed:
        pytest.skip("Clang Static Analyzer requires clang")
    result = ClangStaticAnalyzerRunner().analyze(sources, context)
    assert result.executed and result.command_result is not None
    assert result.successful
    assert result.reason_code in {"STATIC_FINDINGS_DETECTED", "NO_STATIC_FINDINGS"}
    assert result.findings
    assert all(item.raw_evidence in {ref.id for ref in result.evidence} for item in result.findings)
    assert_evidence_hashes(workspace, result.evidence)


def test_asan_heap_violation_is_scoped_fail_when_runtime_supported(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "asan-sut", "#include <stdlib.h>\nint main(void) { volatile char *p = (char*)malloc(1); p[2] = 1; free((void*)p); return 0; }\n")
    if tools.compiler_for("C") is None:
        pytest.skip("No C compiler is installed")
    original = source.read_bytes()
    result = ASanRunner().run(sources, context, LanguageDetector().detect(sources).language)
    if not result.supported:
        assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
        assert result.verification_result.reason_code == "SANITIZER_UNAVAILABLE"
        pytest.skip("AddressSanitizer instrumentation is unsupported by available compiler/runtime")
    assert result.build_result and result.build_result.success
    assert result.findings and result.findings[0].kind == "HEAP_BUFFER_OVERFLOW"
    assert result.verification_result.status is VerificationStatus.FAIL
    assert result.verification_result.reason_code == "MEMORY_SAFETY_VIOLATION"
    assert "execution/input only" in result.verification_result.scope
    assert_evidence_hashes(workspace, result.evidence)
    assert source.read_bytes() == original


def test_ubsan_signed_overflow_is_scoped_fail_when_runtime_supported(tmp_path: Path) -> None:
    workspace, source, sources, tools, context = setup_project(
        tmp_path, "ubsan-sut", "#include <limits.h>\nint main(void) { volatile int x = INT_MAX; return x + 1; }\n")
    if tools.compiler_for("C") is None:
        pytest.skip("No C compiler is installed")
    result = UBSanRunner().run(sources, context, LanguageDetector().detect(sources).language)
    if not result.supported:
        pytest.skip("UndefinedBehaviorSanitizer instrumentation is unsupported")
    assert result.build_result and result.build_result.success
    assert any(item.kind == "SIGNED_INTEGER_OVERFLOW" for item in result.findings)
    assert result.verification_result.status is VerificationStatus.FAIL
    assert result.verification_result.reason_code == "UNDEFINED_BEHAVIOR_DETECTED"
    assert_evidence_hashes(workspace, result.evidence)


def test_clean_asan_run_is_only_a_scoped_execution_pass_when_supported(tmp_path: Path) -> None:
    workspace, _, sources, tools, context = setup_project(
        tmp_path, "asan-clean-sut", "#include <stdlib.h>\nint main(void) { char *p = malloc(4); if (!p) return 2; p[0] = 1; free(p); return 0; }\n")
    if tools.compiler_for("C") is None:
        pytest.skip("No C compiler is installed")
    result = ASanRunner().run(sources, context, "C")
    if not result.supported:
        assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
        assert result.verification_result.reason_code == "SANITIZER_UNAVAILABLE"
        pytest.skip("AddressSanitizer instrumentation is unsupported by available compiler/runtime")
    assert not result.findings
    assert result.verification_result.status is VerificationStatus.PASS
    assert "not a global memory-safety proof" in result.verification_result.scope
    assert_evidence_hashes(workspace, result.evidence)


def test_clean_ubsan_run_is_only_a_scoped_execution_pass_when_supported(tmp_path: Path) -> None:
    workspace, _, sources, tools, context = setup_project(
        tmp_path, "ubsan-clean-sut", "int main(void) { volatile int value = 7; return value - 7; }\n")
    if tools.compiler_for("C") is None:
        pytest.skip("No C compiler is installed")
    result = UBSanRunner().run(sources, context, "C")
    if not result.supported:
        pytest.skip("UndefinedBehaviorSanitizer instrumentation is unsupported")
    assert not result.findings
    assert result.verification_result.status is VerificationStatus.PASS
    assert "not a global memory-safety proof" in result.verification_result.scope
    assert_evidence_hashes(workspace, result.evidence)


def test_leak_check_reports_unavailable_platform_without_claiming_pass(tmp_path: Path) -> None:
    code = "#include <stdlib.h>\nint main(void) { volatile void *p = malloc(32); return p == 0; }\n" if sys.platform.startswith("linux") else "int main(void) { return 0; }\n"
    workspace, _, sources, _, context = setup_project(tmp_path, "leak-sut", code)
    result = LeakChecker().run(sources, context, "C")
    if sys.platform.startswith("linux"):
        if not result.supported:
            pytest.skip("LeakSanitizer is unsupported by the available compiler/runtime")
        assert result.sanitizer == "LeakSanitizer"
        assert any(item.kind == "MEMORY_LEAK" for item in result.findings)
        assert result.verification_result.status is VerificationStatus.FAIL
        assert result.verification_result.reason_code == "LEAK_DETECTED"
        assert_evidence_hashes(workspace, result.evidence)
        return
    assert not result.supported
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert result.verification_result.reason_code == "LEAK_DETECTION_UNAVAILABLE"


def test_instrumented_build_failure_is_not_a_vulnerability(tmp_path: Path, monkeypatch) -> None:
    from seclab.memory import ASanRunner

    _, _, sources, _, context = setup_project(tmp_path, "asan-build-failure", "int main(void) { return 0; }\n")
    failed = BuildResult(False, None, None, None, (), "C", "COMPILATION_FAILED")
    monkeypatch.setattr("seclab.memory.sanitizer.Compiler.build", lambda *_args, **_kwargs: failed)
    run = ASanRunner().run(sources, context, "C")
    assert run.verification_result.status is VerificationStatus.BUILD_ERROR
    assert run.verification_result.reason_code == "SANITIZER_BUILD_FAILED"
    assert not run.findings
    assert run.evidence
    assert_evidence_hashes(context.workspace_root, run.evidence)


def test_sanitizer_runtime_unavailable_is_environment_limited(tmp_path: Path, monkeypatch) -> None:
    from seclab.execution import ProcessRunner
    from seclab.memory import ASanRunner

    _, _, sources, _, context = setup_project(tmp_path, "asan-runtime-missing", "int main(void) { return 0; }\n")
    binary = context.workspace_root / "fake-sanitized-binary"
    binary.write_bytes(b"test-placeholder")
    compiler = ToolInfo("clang", True, "clang", "clang version test", ("compile_c",))
    built = BuildResult(True, None, binary, compiler, tuple(item.relative_path for item in sources), "C")
    monkeypatch.setattr("seclab.memory.sanitizer.Compiler.build", lambda *_args, **_kwargs: built)
    now = datetime.now(timezone.utc)
    process = CommandResult((str(binary),), str(context.workspace_root), 1, "",
        "failed to load sanitizer runtime", 1.0, False, now, now, (0,))
    monkeypatch.setattr(ProcessRunner, "run", lambda *_args, **_kwargs: process)
    run = ASanRunner().run(sources, context, "C")
    assert not run.supported
    assert run.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert run.verification_result.reason_code == "SANITIZER_UNAVAILABLE"
    assert run.verification_result.metadata["capability_status"] == "ENVIRONMENT_LIMITED"
    assert not run.findings
    assert_evidence_hashes(context.workspace_root, run.evidence)
