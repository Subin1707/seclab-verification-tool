from __future__ import annotations

import shutil
import hashlib
import json
import threading
from pathlib import Path

import pytest

from seclab.config import Toolchain
from seclab.coverage import CoverageRunner
from seclab.fuzzing import FuzzConfig, FuzzEngine, FuzzInput, FuzzStrategy, InputKind, InputOrigin
from seclab.results import VerificationStatus
from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType, TestCase, TestRunner


def _toolchain() -> Toolchain:
    return Toolchain([name for name in ("gcc", "gcov") if shutil.which(name)])


def test_fuzz_campaign_that_cannot_start_persists_diagnostic_evidence(tmp_path: Path) -> None:
    import hashlib

    runner = TestRunner(tmp_path, Toolchain([]))
    template = TestCase("template", "missing seed", "program", {}, target_kind="EXECUTABLE")
    result = FuzzEngine(tmp_path, runner).run(template,
        FuzzConfig(FuzzStrategy.MUTATION, 2, 1.0, 37, 16), seeds=())
    verification = result.verification_result
    assert verification.status is VerificationStatus.INCONCLUSIVE
    assert len(verification.evidence_ids) == 1
    evidence = verification.metadata["evidence"][0]
    artifact = tmp_path / evidence["path"]
    assert artifact.is_file()
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == evidence["sha256"]


def test_blackbox_real_executable_oracle_failure_is_scoped_and_reproducible(tmp_path: Path) -> None:
    source = tmp_path / "stdin.c"
    source.write_text("#include <stdio.h>\nint main(void) { int x=0; if (scanf(\"%d\", &x)!=1) return 2; printf(\"%d\\n\", x==42); return 0; }\n")
    executable = tmp_path / "sut.exe"
    toolchain = _toolchain()
    build_workspace = tmp_path / "build-work"
    build_workspace.mkdir()
    build = TestRunner(tmp_path, toolchain).compiler.build([source], "C", output_directory=build_workspace,
                                                              isolated_output=True, output_name="sut")
    assert build.success
    template = TestCase("fuzz", "oracle", "stdin-main", {"stdin": ""},
        ExpectedBehavior((OracleExpectation(OracleType.STDOUT_EQUALS, "0\n"),)), target_kind="EXECUTABLE")
    seed = FuzzInput("boundary-42", "42\n", InputKind.TEXT, InputOrigin.BOUNDARY)
    signatures = []
    for label in ("a", "b"):
        workspace = tmp_path / label
        runner = TestRunner(workspace, toolchain)
        result = FuzzEngine(workspace, runner).run(template,
            FuzzConfig(FuzzStrategy.BOUNDARY, 1, 1, 99, 16), seeds=(seed,), executable=build.binary_path,
            no_crash_is_failure=False)
        assert result.iterations_executed == 1
        assert result.verification_result.status is VerificationStatus.FAIL
        assert result.oracle_failures == 1
        reference = result.execution_evidence[0]
        observation_path = workspace / reference["path"]
        assert hashlib.sha256(observation_path.read_bytes()).hexdigest() == reference["sha256"]
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        assert observation["input"]["data"] == "42\n"
        assert observation["input_sha256"] == reference["input_sha256"]
        assert observation["executed"] is True
        assert observation["command"]["argv"]
        assert observation["command"]["exit_code"] == 0
        assert observation["expected_oracle"]
        assert observation["observation"]
        signatures.append(tuple(item.signature.key for item in result.failures))
    assert signatures[0] == signatures[1]


def test_real_coverage_guided_retains_input_with_new_entities(tmp_path: Path) -> None:
    if not shutil.which("gcc"):
        pytest.skip("gcc and gcov are required")
    source = tmp_path / "branch.c"
    source.write_text("#include <stdio.h>\n#include <stdlib.h>\nint main(int argc, char **argv) { int x=argc>1 ? atoi(argv[1]) : 0; if (x>=0) { puts(\"nonnegative\"); if (x==1) puts(\"one\"); } else puts(\"negative\"); return 0; }\n")
    workspace = tmp_path / "workspace"
    tools = _toolchain()
    test_runner = TestRunner(workspace, tools)
    coverage = CoverageRunner(workspace, tools, test_runner=test_runner)
    seed = FuzzInput("seed", "0\n", InputKind.TEXT, InputOrigin.SEED)
    result = FuzzEngine(workspace, test_runner, coverage_runner=coverage).run(
        TestCase("template", "coverage", "main", {"argv": ["0"]}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.COVERAGE_GUIDED, 10, 2, 4, 16, minimize_failures=False),
        seeds=(FuzzInput("seed", 0, InputKind.SCALARS, InputOrigin.SEED),), source_files=(source,), backend="gcov")
    assert result.iterations_executed >= 1
    assert result.coverage_end
    assert result.corpus_size > 1
    assert result.coverage_delta
    assert result.verification_result.metadata["source_integrity_unchanged"] is True
    assert result.verification_result.status in {VerificationStatus.INCONCLUSIVE, VerificationStatus.TOOL_ERROR}


def test_no_seed_without_failure_is_inconclusive_not_pass(tmp_path: Path) -> None:
    if not shutil.which("python"):
        pytest.skip("python executable not found")
    from seclab.config import Toolchain
    workspace = tmp_path / "workspace"
    runner = TestRunner(workspace, Toolchain([]))
    result = FuzzEngine(workspace, runner).run(
        TestCase("t", "no-op", "noop", {"argv": []}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.BLACKBOX, 2, 1, 5, 8), executable=shutil.which("python"))
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_timeout_is_a_finding_but_not_a_crash(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runner = TestRunner(workspace, Toolchain([]))
    result = FuzzEngine(workspace, runner).run(
        TestCase("t", "timeout", "python", {"argv": ["-c", "import time; time.sleep(2)"]},
                 target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.MUTATION, 1, 0.05, 3, 16, minimize_failures=False),
        seeds=(FuzzInput("seed", b"x", InputKind.BYTES, InputOrigin.SEED),),
        executable=shutil.which("python"))
    assert result.timeouts == 1
    assert result.crashes == 0
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_real_crash_input_produces_scoped_no_crash_failure_and_evidence(tmp_path: Path) -> None:
    if not shutil.which("gcc") and not shutil.which("clang"):
        pytest.skip("gcc or clang is required")
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "crash.c"
    source.write_text("#ifdef _WIN32\n#include <windows.h>\n#else\n#include <signal.h>\n#endif\n#include <stdio.h>\n#include <string.h>\nint main(void) { char input[32]={0}; if (!fgets(input,sizeof(input),stdin)) return 0; if (strstr(input,\"crash\")) {\n#ifdef _WIN32\nSetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS); RaiseException(0xC0000005,EXCEPTION_NONCONTINUABLE,0,0);\n#else\nraise(SIGABRT);\n#endif\n} return 0; }\n")
    workspace = tmp_path / "workspace"
    tools = _toolchain()
    compiler_name = "gcc" if shutil.which("gcc") else "clang"
    build = TestRunner(workspace, tools).compiler.build(
        [source], "C", compiler=compiler_name, output_directory=workspace / "build", output_name="crash-target")
    assert build.success, build.command_result.stderr if build.command_result else build.error_code
    runner = TestRunner(workspace, tools)
    result = FuzzEngine(workspace, runner).run(
        TestCase("crash-template", "no crash", "crash-target", {"argv": []},
            ExpectedBehavior((OracleExpectation(OracleType.NO_CRASH, True),)), target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.MUTATION, 1, 3, 123, 32, minimize_failures=True,
                   max_minimization_executions=12),
        seeds=(FuzzInput("crash-seed", b"XcrashY\n", InputKind.BYTES, InputOrigin.SEED),),
        executable=build.binary_path, source_files=(source,), no_crash_is_failure=True)
    assert result.crashes == 1
    assert result.verification_result.status is VerificationStatus.FAIL
    assert result.verification_result.reason_code == "FUZZ_FAILURE_FOUND"
    assert result.failures[0].classification == "CRASH"
    assert result.failures[0].minimized_input is not None
    assert len(result.failures[0].minimized_input.data) < len(result.failures[0].input.data)
    assert result.failures[0].signature.kind == "ABNORMAL_TERMINATION"
    assert result.failures[0].evidence_ids
    assert result.source_integrity_unchanged
    assert result.source_hashes_before == result.source_hashes_after
    evidence_records = result.verification_result.metadata["evidence"]
    assert evidence_records
    for reference in evidence_records:
        assert hashlib.sha256((workspace / reference["path"]).read_bytes()).hexdigest() == reference["sha256"]


def test_random_seed_manifest_progress_cancellation_and_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runner = TestRunner(workspace, Toolchain([]))
    template = TestCase("t", "blackbox", "python", {"argv": ["-c", "pass"]}, target_kind="EXECUTABLE")
    cancel = threading.Event()
    progress = []

    def notify(event):
        progress.append(dict(event))
        if event["event"] == "case_completed":
            cancel.set()

    result = FuzzEngine(workspace, runner).run(template,
        FuzzConfig(FuzzStrategy.BLACKBOX, 8, 1, None, 8, minimize_failures=False),
        executable=shutil.which("python"), cancel_event=cancel, progress_callback=notify)
    assert result.iterations_executed == 1
    assert result.stop_reason == "CANCELLED"
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
    manifest = next((workspace / "evidence" / "fuzz-campaigns").glob("*-manifest.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["random_seed"] == result.seed
    assert payload["bounded_campaign"] is True
    assert progress[0]["event"] == "campaign_started"
    assert progress[-1]["completed"] == 1


def test_deterministic_seed_replays_same_generated_inputs(tmp_path: Path) -> None:
    observed = []

    class RecordingRunner:
        def __init__(self, runner):
            self.runner = runner
            self.artifact_store = runner.artifact_store

        def run_many(self, cases, **kwargs):
            case = tuple(cases)[0]
            observed.append(dict(case.inputs))
            return self.runner.run_many((case,), **kwargs)

    for name in ("first", "second"):
        workspace = tmp_path / name
        runner = TestRunner(workspace, Toolchain([]))
        FuzzEngine(workspace, RecordingRunner(runner)).run(
            TestCase("t", "blackbox", "python", {"argv": ["-c", "pass"]}, target_kind="EXECUTABLE"),
            FuzzConfig(FuzzStrategy.BLACKBOX, 3, 1, 431, 12, minimize_failures=False),
            executable=shutil.which("python"))
    assert observed[:3] == observed[3:]


def test_deterministic_mutation_replays_same_inputs_and_operators(tmp_path: Path) -> None:
    runs = []

    class RecordingRunner:
        def __init__(self, runner, record):
            self.runner, self.artifact_store, self.record = runner, runner.artifact_store, record

        def run_many(self, cases, **kwargs):
            case = tuple(cases)[0]
            self.record.append((dict(case.inputs), case.metadata.get("fuzz_input_origin")))
            return self.runner.run_many((case,), **kwargs)

    for name in ("mutation-a", "mutation-b"):
        observed = []
        runs.append(observed)
        workspace = tmp_path / name
        runner = TestRunner(workspace, Toolchain([]))
        FuzzEngine(workspace, RecordingRunner(runner, observed)).run(
            TestCase("t", "mutation", "python", {"argv": ["-c", "pass"]}, target_kind="EXECUTABLE"),
            FuzzConfig(FuzzStrategy.MUTATION, 4, 1, 1881, 16, minimize_failures=False),
            seeds=(FuzzInput("seed", b"input", InputKind.BYTES, InputOrigin.SEED),),
            executable=shutil.which("python"))
    assert runs[0] == runs[1]
    assert len(runs[0]) == 4


def test_configured_corpus_loads_and_is_retained_with_manifest(tmp_path: Path) -> None:
    corpus = tmp_path / "seed corpus"
    corpus.mkdir()
    (corpus / "first.bin").write_bytes(b"seed-one")
    (corpus / "nested").mkdir()
    (corpus / "nested" / "second.bin").write_bytes(b"seed-two")
    workspace = tmp_path / "workspace"
    result = FuzzEngine(workspace, TestRunner(workspace, Toolchain([]))).run(
        TestCase("t", "corpus", "python", {"argv": ["-c", "pass"]}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.MUTATION, 1, 1, 5, 16, minimize_failures=False,
                   corpus_directory=str(corpus)), executable=shutil.which("python"))
    manifest = next((workspace / "evidence" / "fuzz-campaigns").glob("*-manifest.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    expected_ids = set()
    for name, data in (("first.bin", b"seed-one"), ("nested/second.bin", b"seed-two")):
        expected_ids.add("corpus-" + hashlib.sha256(name.encode() + bytes([0]) + data).hexdigest()[:16])
    assert {item["id"] for item in payload["seed_inputs"]} == expected_ids
    assert len(list((workspace / "evidence" / "fuzz-corpus").glob("*.bin"))) == 2
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_coverage_guided_can_fall_back_to_blackbox(tmp_path: Path) -> None:
    source = tmp_path / "arbitrary.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    result = FuzzEngine(workspace, TestRunner(workspace, Toolchain([]))).run(
        TestCase("t", "fallback", "python", {"argv": ["-c", "pass"]}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.COVERAGE_GUIDED, 2, 1, 77, 8, minimize_failures=False,
                   fallback_to_blackbox=True),
        seeds=(FuzzInput("seed", b"seed", InputKind.BYTES, InputOrigin.SEED),),
        source_files=(source,), executable=shutil.which("python"))
    assert result.iterations_executed == 2
    assert result.verification_result.metadata["effective_strategy"] == "BLACKBOX"
    assert result.verification_result.metadata["coverage_fallback_used"] is True
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_unavailable_fuzz_target_is_reported_without_false_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    result = FuzzEngine(workspace, TestRunner(workspace, Toolchain([]))).run(
        TestCase("t", "missing", "missing", {"argv": []}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.BLACKBOX, 3, 1, 4, 8, minimize_failures=False), executable=tmp_path / "absent.exe")
    assert result.iterations_executed == 0
    assert result.stop_reason == "TARGET_UNAVAILABLE"
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_fuzz_build_failure_is_distinct_from_campaign_finding(tmp_path: Path) -> None:
    if not shutil.which("gcc"):
        pytest.skip("gcc is required for the fuzz target build test.")
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "broken.c"
    source.write_text("int main(void) { return missing_symbol(); }\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    result = FuzzEngine(workspace, TestRunner(workspace, _toolchain())).run(
        TestCase("t", "broken target", "main", {"argv": []}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.BLACKBOX, 3, 1, 4, 8, minimize_failures=False), source_files=(source,))
    assert result.iterations_executed == 0
    assert result.stop_reason == "BUILD_ERROR"
    assert result.verification_result.status is VerificationStatus.BUILD_ERROR
    assert result.verification_result.reason_code == "FUZZ_TARGET_BUILD_FAILED"


def test_fuzz_runner_exception_is_tool_error_with_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    runner = TestRunner(workspace, Toolchain([]))

    def fail(*_args, **_kwargs):
        raise RuntimeError("target adapter failed")

    runner.run_one = fail
    result = FuzzEngine(workspace, runner).run(
        TestCase("t", "runner error", "python", {"argv": []}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.BLACKBOX, 2, 1, 4, 8, minimize_failures=False), executable=shutil.which("python"))
    assert result.iterations_executed == 0
    assert result.verification_result.status is VerificationStatus.TOOL_ERROR
    assert result.evidence_ids


def test_execution_and_input_budgets_are_enforced_without_persisting_every_candidate_output(tmp_path: Path) -> None:
    workspace = tmp_path / "budgeted"
    runner = TestRunner(workspace, Toolchain([]))
    result = FuzzEngine(workspace, runner).run(
        TestCase("t-budget", "budget", "python", {"argv": ["-c", "print('observed')"]},
                 target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.MUTATION, 8, 1, 14, 8, minimize_failures=False,
                   max_executions=2, max_input_count=2),
        seeds=(FuzzInput("stable-seed", b"x", InputKind.BYTES, InputOrigin.SEED),),
        executable=shutil.which("python"))
    assert result.iterations_executed == 2
    assert result.stop_reason == "EXECUTION_LIMIT"
    evidence_root = workspace / "evidence"
    outputs = list((evidence_root / "test-execution").glob("*-stdout.txt"))
    assert not outputs
    observations = list((evidence_root / "fuzz-executions").glob("*-observation.json"))
    assert len(observations) == 2
    assert all(json.loads(path.read_text(encoding="utf-8"))["output_persisted"] is False
               for path in observations)
    manifest = next((evidence_root / "fuzz-campaigns").glob("*-manifest.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["max_executions"] == 2
    assert payload["max_input_count"] == 2
    assert payload["source_hashes"] == {}
    assert len(payload["configuration_sha256"]) == 64
    assert payload["reproducibility_config"]["random_seed"] == 14
    assert list((evidence_root / "fuzz-corpus").glob("*-corpus-index.json"))


def test_concolic_campaign_is_explicitly_unsupported_by_fuzz_engine(tmp_path: Path) -> None:
    result = FuzzEngine(tmp_path, TestRunner(tmp_path, Toolchain([]))).run(
        TestCase("t", "concolic", "program", {"argv": []}, target_kind="EXECUTABLE"),
        FuzzConfig(FuzzStrategy.CONCOLIC, 1, 1, 5, 8), executable=shutil.which("python"))
    assert result.iterations_executed == 0
    assert result.stop_reason == "CONCOLIC_TARGET_UNSUPPORTED"
    assert result.verification_result.metadata["concolic_capability"] == "UNSUPPORTED"
