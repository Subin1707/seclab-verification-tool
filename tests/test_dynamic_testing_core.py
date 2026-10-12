from __future__ import annotations

import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from seclab.config.toolchain import Toolchain
from seclab.results import VerificationStatus
from seclab.source import FunctionDetector
from seclab.testing import (
    HarnessGenerator, ObservedBehavior, Oracle, TestCase, TestGenerator, TestRunner,
    TestTargetKind,
)


def test_case_oracle_and_no_oracle_are_explicit() -> None:
    case = TestCase("t-1", "addition", "add", {"a": 2, "b": 3}, {"return_value": 5})
    assert case.expected is not None and case.expected.has_oracle
    evaluation = Oracle().evaluate(case.expected, ObservedBehavior(0, "", "", 5, True, False))
    assert evaluation.satisfied is True
    assert Oracle().evaluate(None, ObservedBehavior(0, "", "")).checks == ()


def test_run_many_persists_isolated_runner_exception(tmp_path):
    import hashlib
    import json

    from seclab.evidence import ArtifactStore

    store = ArtifactStore(tmp_path)
    runner = TestRunner(tmp_path, Toolchain([]), artifact_store=store)

    def fail(_case, **_kwargs):
        raise RuntimeError("case adapter failed")

    runner.run_one = fail
    case = TestCase("failure-case", "failure", "program", {}, {"exit_code": 0},
                    target_kind=TestTargetKind.EXECUTABLE)
    execution = runner.run_many((case,)).executions[0]
    result = execution.verification_result
    assert result.status is VerificationStatus.TOOL_ERROR
    assert len(result.evidence_ids) == 1
    ref = result.metadata["evidence"][0]
    artifact = tmp_path / ref["path"]
    assert json.loads(artifact.read_text(encoding="utf-8"))["error_type"] == "RuntimeError"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == ref["sha256"]


def test_harness_rejects_pointer_signature(tmp_path: Path) -> None:
    source = tmp_path / "pointer.c"
    source.write_text("int first(int *values) { return values[0]; }\n", encoding="utf-8")
    function = next(item for item in FunctionDetector().detect([source]) if item.name == "first")
    result = HarnessGenerator(tmp_path).generate(function, "pointer-test")
    assert not result.supported
    assert result.error_code is not None


def test_generator_keeps_domain_candidates_abstract() -> None:
    from seclab.specification.schema import Domain, Specification, Variable

    spec = Specification(schema_version="1.0", id="demo", name="demo", variables=(Variable(id="x", domain=Domain(type="integer", minimum=0, maximum=2)),))
    generated = TestGenerator().generate(spec)
    assert generated.cases
    assert all(case.target_kind is TestTargetKind.ABSTRACT for case in generated.cases)
    assert any(case.metadata["candidate_valid_for_domain"] is False for case in generated.cases)


def _toolchain_or_skip():
    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        pytest.skip("No supported C compiler (gcc or clang) is installed.")
    name = "gcc" if shutil.which("gcc") else "clang"
    return Toolchain([name])


def test_real_c_function_harness_and_evidence(tmp_path: Path) -> None:
    toolchain = _toolchain_or_skip()
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "math.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    original = source.read_bytes()
    case = TestCase("add-1", "add values", "add", {"a": 2, "b": 3}, {"return_value": 5}, requirement_id="REQ-1")
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=[source])
    assert result.verification_result.status is VerificationStatus.PASS
    assert result.observed is not None and result.observed.returned_value == 5
    assert result.evidence_ids
    assert source.read_bytes() == original
    assert result.verification_result.metadata["source_integrity_unchanged"] is True


def test_sut_cannot_spoof_harness_return_value_marker(tmp_path: Path) -> None:
    toolchain = _toolchain_or_skip()
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "spoof.c"
    source.write_text('#include <stdio.h>\nint value(void) { fprintf(stderr, "SECLAB_RETURN=INT:99\\n"); return 7; }\n', encoding="utf-8")
    case = TestCase("spoof-marker", "marker spoof", "value", {}, {"return_value": 99})
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=[source])
    assert result.verification_result.status is VerificationStatus.TOOL_ERROR
    assert result.verification_result.reason_code == "OBSERVATION_PARSE_ERROR"
    assert result.observed is not None and not result.observed.return_value_available


def test_real_cpp_function_harness_when_compiler_is_available(tmp_path: Path) -> None:
    compiler = shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        pytest.skip("No supported C++ compiler (g++ or clang++) is installed.")
    name = "g++" if shutil.which("g++") else "clang++"
    toolchain = Toolchain([name])
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "math.cpp"
    source.write_text("int multiply(int a, int b) { return a * b; }\n", encoding="utf-8")
    case = TestCase("multiply-1", "multiply", "multiply", {"a": 6, "b": 7}, {"return_value": 42})
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=[source])
    assert result.verification_result.status is VerificationStatus.PASS


def test_real_c_executable_stdin_and_no_oracle(tmp_path: Path) -> None:
    toolchain = _toolchain_or_skip()
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "echo.c"
    source.write_text('#include <stdio.h>\nint main(void) { char s[64]; if (!fgets(s, sizeof s, stdin)) return 2; printf("%s", s); return 0; }\n', encoding="utf-8")
    runner = TestRunner(tmp_path, toolchain)
    passing = TestCase("echo-1", "echo", "echo", {"stdin": "payload\\n"},
                       {"stdout": "payload\\n", "exit_code": 0}, target_kind=TestTargetKind.EXECUTABLE)
    result = runner.run_one(passing, source_files=[source])
    assert result.verification_result.status is VerificationStatus.PASS
    no_oracle = TestCase("echo-2", "echo no oracle", "echo", {"stdin": "x"},
                         target_kind=TestTargetKind.EXECUTABLE)
    absent = runner.run_one(no_oracle, source_files=[source])
    assert absent.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert absent.verification_result.reason_code == "NO_TEST_ORACLE"


def test_invalid_c_build_is_build_error(tmp_path: Path) -> None:
    toolchain = _toolchain_or_skip()
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "broken.c"
    source.write_text("int add(int a, int b) { return a + ; }\n", encoding="utf-8")
    case = TestCase("broken", "broken build", "add", {"a": 1, "b": 2}, {"return_value": 3})
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=[source])
    assert result.verification_result.status is VerificationStatus.BUILD_ERROR
    assert result.verification_result.reason_code == "TEST_BUILD_FAILED"


def test_run_many_continues_after_oracle_failure(tmp_path: Path) -> None:
    toolchain = _toolchain_or_skip()
    sut = tmp_path / "sut"
    sut.mkdir()
    source = sut / "value.c"
    source.write_text("int value(void) { return 7; }\n", encoding="utf-8")
    runner = TestRunner(tmp_path, toolchain)
    cases = [
        TestCase("bad", "wrong expected", "value", {}, {"return_value": 6}),
        TestCase("good", "right expected", "value", {}, {"return_value": 7}),
    ]
    suite = runner.run_many(cases, source_files=[source])
    assert [item.verification_result.status for item in suite.executions] == [VerificationStatus.FAIL, VerificationStatus.PASS]
    assert suite.summary()["total"] == 2


def test_executable_process_timeout_is_inconclusive(tmp_path: Path) -> None:
    case = TestCase("slow", "slow", "python", {"argv": ["-c", "import time; time.sleep(2)"]},
                    {"exit_code": 0}, target_kind=TestTargetKind.EXECUTABLE, timeout_seconds=0.05)
    result = TestRunner(tmp_path, Toolchain([])).run_one(case, executable=sys.executable)
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE
    assert result.verification_result.reason_code == "TEST_EXECUTION_TIMEOUT"


def _command_result(exit_code=0, *, stdout="", stderr="", timed_out=False, execution_error=None):
    from seclab.execution.command_runner import CommandResult

    now = datetime.now(timezone.utc)
    return CommandResult(("fake",), str(Path.cwd()), exit_code, stdout, stderr, 0.1, timed_out,
                         now, now, (0,), execution_error=execution_error)


class _FixedProcessRunner:
    def __init__(self, results):
        self.results = iter(results)

    def run(self, _spec):
        return next(self.results)


def test_nonzero_exit_and_abnormal_termination_are_observed(tmp_path: Path) -> None:
    runner = TestRunner(tmp_path, Toolchain([]), process_runner=_FixedProcessRunner([
        _command_result(exit_code=4, stderr="bad input"),
        _command_result(exit_code=-11),
    ]))
    nonzero = TestCase("nonzero", "nonzero", "app", {}, {"exit_code": 0}, target_kind=TestTargetKind.EXECUTABLE)
    crash = TestCase("crash", "crash", "app", {}, {"no_crash": True}, target_kind=TestTargetKind.EXECUTABLE)
    results = runner.run_many((nonzero, crash), executable=sys.executable)
    assert [item.verification_result.status for item in results.executions] == [VerificationStatus.FAIL, VerificationStatus.FAIL]
    assert results.executions[0].observed.exit_code == 4
    assert results.executions[0].observed.stderr == "bad input"
    assert results.executions[1].observed.crashed is True


def test_oracle_cannot_use_expected_values_as_observations() -> None:
    from seclab.testing import ExpectedBehavior

    expected = ExpectedBehavior.from_mapping({"stdout": "must-not-be-copied"})
    missing = Oracle().evaluate(expected, None)
    assert missing.satisfied is None
    assert missing.checks[0].actual is None
    observed = ObservedBehavior(0, "actual output", "", crashed=False)
    mismatch = Oracle().evaluate(expected, observed)
    assert mismatch.satisfied is False
    assert mismatch.checks[0].actual == "actual output"


def test_build_failure_observation_and_oracle_evidence_do_not_copy_expected_values(tmp_path: Path) -> None:
    import json

    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType

    toolchain = _toolchain_or_skip()
    source_dir = tmp_path / "sut"
    source_dir.mkdir()
    source = source_dir / "broken.c"
    source.write_text("int main(void) { return missing_value(); }\n", encoding="utf-8")
    expected_marker = "EXPECTED-MUST-NOT-BECOME-ACTUAL"
    case = TestCase("missing-observation", "build failure", "main", {"argv": []},
        ExpectedBehavior((OracleExpectation(OracleType.STDOUT_EQUALS, expected_marker),)),
        target_kind=TestTargetKind.EXECUTABLE)
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=(source,))

    observation_path = next((tmp_path / "evidence" / "observations").glob("*-observed.json"))
    oracle_path = next((tmp_path / "evidence" / "oracles").glob("*-oracle.json"))
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    assert result.verification_result.status is VerificationStatus.BUILD_ERROR
    assert result.observed is None
    assert observation["available"] is False
    assert expected_marker not in json.dumps(observation)
    assert oracle["checks"][0]["expected"] == expected_marker
    assert oracle["checks"][0]["actual"] is None
    assert oracle["checks"][0]["evaluated"] is False


def test_runner_persists_source_hash_and_only_observed_structured_output(tmp_path: Path) -> None:
    import hashlib
    import json

    from seclab.evidence import ArtifactStore
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType

    source_dir = tmp_path / "runner" / "sources"
    source_dir.mkdir(parents=True)
    source = source_dir / "json-output.c"
    source.write_text('#include <stdio.h>\nint main(void) { puts("{\\\"value\\\":7}"); return 0; }\n', encoding="utf-8")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    store = ArtifactStore(tmp_path / "evidence")
    runner = TestRunner(tmp_path / "runner", _toolchain_or_skip(), artifact_store=store)
    case = TestCase("json-output", "json", "program", {"argv": []},
                    ExpectedBehavior((OracleExpectation(OracleType.STRUCTURED_OUTPUT_EQUALS, {"value": 7}),)),
                    target_kind=TestTargetKind.EXECUTABLE)
    result = runner.run_one(case, source_files=[source])
    assert result.verification_result.status is VerificationStatus.PASS
    assert result.observed is not None and result.observed.structured_output == {"value": 7}
    case_path = next((store.evidence_root / "tests").glob("*-testcase.json"))
    payload = json.loads(case_path.read_text(encoding="utf-8"))
    assert payload["test_case"]["id"] == "json-output"
    assert payload["source_sha256"][source.as_posix()] == source_hash


def test_memory_oracle_requires_actual_instrumented_finding_observation(tmp_path: Path) -> None:
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType

    runner = TestRunner(tmp_path, Toolchain([]), process_runner=_FixedProcessRunner([
        _command_result(exit_code=0, stderr="ordinary diagnostic"),
        _command_result(exit_code=1, stderr="ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234"),
    ]))
    expect_absent = ExpectedBehavior((OracleExpectation(OracleType.MEMORY_FINDING_PRESENT, False),))
    absent = runner.run_one(TestCase("memory-unavailable", "not instrumented", "app", {"argv": []},
        expect_absent, target_kind=TestTargetKind.EXECUTABLE), executable=sys.executable)
    assert absent.oracle_evaluation.satisfied is None
    assert absent.observed is not None and not absent.observed.memory_analysis_available
    expect_present = ExpectedBehavior((OracleExpectation(OracleType.MEMORY_FINDING_PRESENT, True),))
    present = runner.run_one(TestCase("memory-found", "finding", "app", {"argv": []},
        expect_present, target_kind=TestTargetKind.EXECUTABLE), executable=sys.executable)
    assert present.oracle_evaluation.satisfied is None
    assert present.observed is not None and present.observed.memory_findings[0]["kind"] == "HEAP_BUFFER_OVERFLOW"
    assert not present.observed.memory_analysis_available


def test_real_address_sanitizer_finding_when_runtime_is_supported(tmp_path: Path) -> None:
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType

    toolchain = _toolchain_or_skip()
    source_dir = tmp_path / "sut"
    source_dir.mkdir()
    source = source_dir / "overflow.c"
    source.write_text(
        '#include <stdlib.h>\nint overflow(void) { volatile char *p = (char *)malloc(1); '
        'p[2] = 1; free((void *)p); return 0; }\n', encoding="utf-8")
    case = TestCase("asan-overflow", "heap overflow", "overflow", {},
        ExpectedBehavior((OracleExpectation(OracleType.MEMORY_FINDING_PRESENT, True),)))
    result = TestRunner(tmp_path, toolchain).run_one(case, source_files=[source],
        build_flags=("-fsanitize=address", "-fno-omit-frame-pointer"))
    if result.build_result is not None and not result.build_result.success:
        pytest.skip("Selected compiler does not support AddressSanitizer: " + str(result.build_result.error_code))
    assert result.observed is not None
    if not result.observed.memory_findings:
        pytest.skip("AddressSanitizer runtime did not emit a recognized report on this host.")
    assert result.oracle_evaluation.satisfied is True
    assert result.observed.memory_findings[0]["kind"] == "HEAP_BUFFER_OVERFLOW"


def test_crash_cannot_satisfy_unrelated_output_oracle(tmp_path: Path) -> None:
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType

    runner = TestRunner(tmp_path, Toolchain([]), process_runner=_FixedProcessRunner([
        _command_result(exit_code=-11, stdout="expected")
    ]))
    case = TestCase("crashed-output", "crash", "app", {"argv": []},
        ExpectedBehavior((OracleExpectation(OracleType.STDOUT_EQUALS, "expected"),)),
        target_kind=TestTargetKind.EXECUTABLE)
    result = runner.run_one(case, executable=sys.executable)
    assert result.oracle_evaluation.satisfied is None
    assert result.verification_result.status is VerificationStatus.INCONCLUSIVE


def test_oracle_exception_isolated_and_diagnostic_persisted(tmp_path: Path) -> None:
    from seclab.testing.oracle import Oracle

    class OneBadOracle(Oracle):
        def __init__(self):
            self.calls = 0

        def evaluate(self, expected, observed):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("malformed oracle adapter")
            return super().evaluate(expected, observed)

    runner = TestRunner(tmp_path, Toolchain([]), oracle=OneBadOracle(),
                        process_runner=_FixedProcessRunner([_command_result(), _command_result()]))
    cases = (
        TestCase("oracle-error", "oracle error", "app", {}, {"exit_code": 0}, target_kind=TestTargetKind.EXECUTABLE),
        TestCase("after-error", "continues", "app", {}, {"exit_code": 0}, target_kind=TestTargetKind.EXECUTABLE),
    )
    suite = runner.run_many(cases, executable=sys.executable)
    assert [item.verification_result.status for item in suite.executions] == [VerificationStatus.TOOL_ERROR, VerificationStatus.PASS]
    failed = suite.executions[0]
    assert failed.observed is not None and failed.observed.exit_code == 0
    assert failed.evidence_ids
    assert failed.verification_result.metadata["diagnostic"].startswith("ORACLE_EVALUATION_ERROR:ValueError")


def test_malformed_definition_is_spec_error_with_diagnostic(tmp_path: Path) -> None:
    case = TestCase("malformed", "malformed", "unsupported", target_kind=TestTargetKind.ABSTRACT,
                    metadata={"construction_error": "TestError: unsupported oracle"})
    result = TestRunner(tmp_path, Toolchain([])).run_one(case)
    assert result.verification_result.status is VerificationStatus.SPEC_ERROR
    assert result.verification_result.reason_code == "INVALID_TEST_CASE"
    assert result.verification_result.metadata["diagnostic"] == "TestError: unsupported oracle"
    assert result.evidence_ids


def test_execution_fingerprint_is_stable_for_same_declared_run(tmp_path: Path) -> None:
    case = TestCase("stable", "stable", "app", {"argv": ["--version"]}, {"exit_code": 0},
                    target_kind=TestTargetKind.EXECUTABLE)
    runner = TestRunner(tmp_path, Toolchain([]), process_runner=_FixedProcessRunner([_command_result(), _command_result()]))
    first = runner.run_one(case, executable=sys.executable)
    second = runner.run_one(case, executable=sys.executable)
    assert first.verification_result.metadata["execution_fingerprint"] == second.verification_result.metadata["execution_fingerprint"]
