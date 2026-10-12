"""Dynamic test orchestration using shared build, process, evidence, and result APIs."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from seclab.config.toolchain import Toolchain
from seclab.evidence import ArtifactStore, EvidenceType
from seclab.execution.compiler import BuildResult, Compiler
from seclab.execution.evidence import store_command_evidence
from seclab.execution.process_runner import ProcessRunner, ProcessSpec
from seclab.results.classifier import ClassificationInput, RawOutcome, ResultClassifier
from seclab.source import FunctionDetector, Language, SourceFile
from seclab.memory import parse_asan_output, parse_ubsan_output

from .errors import TestError, TestErrorCode
from .harness_generator import HarnessGenerator
from .oracle import ObservedBehavior, Oracle, OracleEvaluation
from .result import TestExecutionResult, TestSuiteResult
from .test_case import OracleType, TestCase, TestTargetKind


class TestRunner:
    __test__ = False
    def __init__(self, workspace_root: str | Path, toolchain: Toolchain, *,
                 compiler: Compiler | None = None, process_runner: ProcessRunner | None = None,
                 artifact_store: ArtifactStore | None = None, harness_generator: HarnessGenerator | None = None,
                 oracle: Oracle | None = None, classifier: ResultClassifier | None = None,
                 build_timeout: float = 60.0) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.artifact_store = artifact_store or ArtifactStore(self.workspace_root)
        self.compiler = compiler or Compiler(self.workspace_root, toolchain, artifact_store=self.artifact_store, timeout=build_timeout)
        self.process_runner = process_runner or ProcessRunner()
        self.harness_generator = harness_generator or HarnessGenerator(self.workspace_root)
        self.oracle = oracle or Oracle()
        self.classifier = classifier or ResultClassifier()

    def run_one(self, test_case: TestCase, *, source_files: Iterable[SourceFile | str | Path] = (),
                language: Language | str | None = None, executable: str | Path | None = None,
                build_flags: Iterable[str] = (), process_env: dict[str, str] | None = None,
                compiler_name: str | None = None, separate_compilation: bool = False,
                isolated_build_output: bool = False, build_directory: str | Path | None = None,
                persist_process_output: bool = True) -> TestExecutionResult:
        started = time.monotonic()
        run_id = uuid.uuid4().hex
        build_flags = tuple(build_flags)
        process_env = dict(process_env or {})
        evidence = []
        sources = tuple(source_files)
        before, initial_error = _hash_sources(sources)
        if persist_process_output:
            case_ref = self.artifact_store.write_json("tests", f"{run_id}-testcase.json",
                {"test_case": test_case.to_dict(), "source_sha256": before},
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id, property_id=test_case.property_id,
                metadata={"artifact_kind": "test-case", "source_sha256": before})
            evidence.append(case_ref)
        else:
            case_ref = None
        build_result: BuildResult | None = None
        command_result = None
        target_executable: Path | None = Path(executable).resolve() if executable is not None else None
        args: tuple[str, ...] = ()
        stdin: str | bytes | None = None
        reason: str | None = None
        executed = False
        observation: ObservedBehavior | None = None

        try:
            construction_error = test_case.metadata.get("construction_error")
            if construction_error:
                reason = "INVALID_TEST_CASE"
            elif initial_error:
                reason = "SOURCE_INTEGRITY_CHECK_FAILED"
            elif test_case.target_kind is TestTargetKind.ABSTRACT:
                reason = "ABSTRACT_TEST_CANDIDATE"
            elif test_case.target_kind is TestTargetKind.FUNCTION:
                if not sources:
                    reason = "FUNCTION_SOURCE_REQUIRED"
                else:
                    functions = [item for item in FunctionDetector().detect(sources) if item.name == test_case.target]
                    if len(functions) != 1:
                        reason = "FUNCTION_NOT_FOUND" if not functions else "AMBIGUOUS_FUNCTION"
                    else:
                        function = functions[0]
                        generated = self.harness_generator.generate(function, test_case.id)
                        if not generated.supported:
                            reason = (generated.error_code.value if generated.error_code else "HARNESS_UNSUPPORTED_SIGNATURE")
                        else:
                            assert generated.source_path and generated.source
                            harness_ref = self.artifact_store.copy_file("harness", f"{run_id}-{generated.source_path.name}", generated.source_path,
                                evidence_type=EvidenceType.LOG, requirement_id=test_case.requirement_id,
                                property_id=test_case.property_id, metadata={"generated": True, "function": test_case.target})
                            evidence.append(harness_ref)
                            args = _function_arguments(test_case, generated.argument_names)
                            language = function.language
                            build_result = self.compiler.build((*sources, generated.source_path), language,
                                compiler=compiler_name, flags=build_flags, output_directory=self._build_directory(run_id, build_directory),
                                output_name="sut", separate_compilation=separate_compilation,
                                isolated_output=isolated_build_output)
                            evidence.extend(build_result.build_evidence)
                            if build_result.success:
                                target_executable = build_result.binary_path
                            else:
                                reason = build_result.error_code or "BUILD_FAILED"
            elif test_case.target_kind is TestTargetKind.EXECUTABLE:
                if target_executable is None and sources:
                    selected_language = language or _language_from_sources(sources)
                    if selected_language is None:
                        reason = "EXECUTABLE_LANGUAGE_REQUIRED"
                    else:
                        build_result = self.compiler.build(sources, selected_language,
                            compiler=compiler_name, flags=build_flags, output_directory=self._build_directory(run_id, build_directory),
                            output_name="sut", separate_compilation=separate_compilation,
                            isolated_output=isolated_build_output)
                        evidence.extend(build_result.build_evidence)
                        if build_result.success:
                            target_executable = build_result.binary_path
                        else:
                            reason = build_result.error_code or "BUILD_FAILED"
                elif target_executable is None:
                    reason = "EXECUTABLE_REQUIRED"
                if reason is None:
                    args, stdin = _executable_inputs(test_case)
            else:
                reason = "UNSUPPORTED_TEST_TARGET_KIND"

            if reason is None and target_executable is not None:
                command_result = self.process_runner.run(ProcessSpec(
                    executable=target_executable, args=args, cwd=self.workspace_root,
                    stdin=stdin, timeout=test_case.timeout_seconds, env=process_env,
                ))
                executed = command_result.execution_error is None
                if persist_process_output:
                    command_evidence, stdout_evidence, stderr_evidence = store_command_evidence(
                        self.artifact_store, command_result, stage="test-execution", prefix=run_id)
                    for item in (command_evidence, stdout_evidence, stderr_evidence):
                        if item is not None:
                            evidence.append(item)
                if test_case.target_kind is TestTargetKind.FUNCTION:
                    marker_value, clean_stderr, marker_error = _extract_return_marker(command_result.stderr)
                else:
                    marker_value, clean_stderr, marker_error = None, command_result.stderr, False
                # On POSIX, a negative return code is the signal number reported by Popen.
                crashed = _did_crash(command_result.exit_code, command_result.execution_error)
                structured_output, structured_output_available = _parse_json_output(command_result.stdout)
                memory_findings = (*parse_asan_output(command_result.stderr), *parse_ubsan_output(command_result.stderr))
                observation = ObservedBehavior(
                    exit_code=command_result.exit_code, stdout=command_result.stdout, stderr=clean_stderr,
                    returned_value=marker_value[1] if marker_value else None,
                    return_value_available=marker_value is not None, crashed=crashed,
                    timed_out=command_result.timed_out,
                    structured_output=structured_output,
                    structured_output_available=structured_output_available,
                    memory_findings=tuple(item.to_dict() for item in memory_findings),
                    memory_analysis_available=(build_result is not None and build_result.success
                                               and _memory_analysis_requested(build_flags)),
                )
                if marker_error:
                    reason = "OBSERVATION_PARSE_ERROR"
                elif crashed and not any(check.oracle_type in {OracleType.NO_CRASH, OracleType.MEMORY_FINDING_PRESENT}
                                         for check in (test_case.expected.checks if test_case.expected else ())):
                    reason = "PROCESS_CRASH_UNASSERTED"
            elif reason is None:
                reason = "EXECUTABLE_UNAVAILABLE"
        except TestError as exc:
            reason = exc.code.value
        except (OSError, ValueError) as exc:
            reason = f"TEST_EXECUTION_ERROR:{type(exc).__name__}:{exc}"

        after, final_error = _hash_sources(sources)
        integrity = {"before": before, "after": after, "unchanged": before == after and not initial_error and not final_error,
                     "initial_error": initial_error, "final_error": final_error}
        if persist_process_output:
            integrity_ref = self.artifact_store.write_json("integrity", f"{run_id}-source-integrity.json", integrity,
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id, property_id=test_case.property_id)
            evidence.append(integrity_ref)

        if not integrity["unchanged"]:
            reason = "SOURCE_INTEGRITY_CHANGED"
        try:
            evaluation = self.oracle.evaluate(test_case.expected, observation)
        except Exception as exc:
            # Oracle adapters are isolated per case just like process execution. Preserve
            # the process observation and a diagnostic instead of losing the whole suite.
            reason = f"ORACLE_EVALUATION_ERROR:{type(exc).__name__}:{exc}"
            evaluation = OracleEvaluation(())
        observed_data = observation.to_dict() if observation else {"available": False, "reason": reason}
        oracle_data = evaluation.to_dict()
        if not persist_process_output and observation is not None:
            observed_data = {**observed_data, "stdout": None, "stderr": None,
                             "stdout_sha256": hashlib.sha256(observation.stdout.encode("utf-8")).hexdigest(),
                             "stderr_sha256": hashlib.sha256(observation.stderr.encode("utf-8")).hexdigest(),
                             "output_persisted": False}
            oracle_data = {**oracle_data, "checks": [
                {**item.to_dict(), "actual": "<redacted>" if item.oracle_type.value in
                 {"STDOUT_EQUALS", "STDOUT_CONTAINS", "STDERR_EQUALS", "STDERR_CONTAINS"} else item.actual}
                for item in evaluation.checks], "output_persisted": False}
        if persist_process_output:
            observed_ref = self.artifact_store.write_json("observations", f"{run_id}-observed.json",
                observed_data,
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id, property_id=test_case.property_id)
            oracle_ref = self.artifact_store.write_json("oracles", f"{run_id}-oracle.json", oracle_data,
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id, property_id=test_case.property_id)
            evidence.extend((observed_ref, oracle_ref))
        else:
            observed_ref = oracle_ref = None

        outcome, code, message = _classification(reason, command_result, build_result, evaluation)
        if test_case.metadata.get("construction_error"):
            outcome, code, message = (RawOutcome.INVALID_SPEC, "INVALID_TEST_CASE",
                f"Test definition is invalid: {test_case.metadata['construction_error']}")
        duration_ms = max(0.0, (time.monotonic() - started) * 1000.0)
        source_label = ",".join(_source_label(item) for item in sources) or (str(executable) if executable else None)
        result = self.classifier.classify(ClassificationInput(
            outcome=outcome, stage="DYNAMIC_TEST", technique="TEST_ORACLE", reason_code=code,
            message=message, requirement_id=test_case.requirement_id, property_id=test_case.property_id,
            source=source_label, scope="Observed execution of one explicit test case and its declared oracle.",
            evidence_ids=tuple(item.id for item in evidence), duration_ms=duration_ms,
            counterexample={"test_case_id": test_case.id, "inputs": test_case.to_dict()["inputs"]} if outcome is RawOutcome.PROPERTY_VIOLATED else None,
            metadata={"test_case_id": test_case.id, "target": test_case.target,
                      "source_integrity_unchanged": integrity["unchanged"], "reason": reason,
                      "source_sha256": before,
                      "execution_fingerprint": _execution_fingerprint(test_case, before, test_case.timeout_seconds,
                          args, stdin, build_flags, process_env, executable=executable, compiler_name=compiler_name),
                      "run_id": run_id,
                      "diagnostic": (test_case.metadata.get("construction_error") or reason)
                          if outcome in {RawOutcome.INVALID_SPEC, RawOutcome.TOOL_FAILED, RawOutcome.BUILD_FAILED} else None,
                      "oracle": oracle_data, "evidence": [{"id": item.id, "path": item.path, "hash": item.hash} for item in evidence]},
        ))
        execution_id = "exec-" + hashlib.sha256((test_case.id + "\0" + str(result.metadata.get("execution_fingerprint", ""))).encode("utf-8")).hexdigest()[:32]
        if persist_process_output:
            result_payload = self.artifact_store.write_json("results", f"{run_id}-verification-result.json", result.to_dict(),
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id,
                property_id=test_case.property_id)
            evidence.append(result_payload)
        raw = TestExecutionResult(test_case_id=test_case.id, execution_id=execution_id, executed=executed,
            observed=observation, oracle_evaluation=evaluation, verification_result=result,
            command_result=command_result, build_result=build_result, duration_ms=duration_ms,
            evidence_ids=tuple(item.id for item in evidence), reason=reason,
            test_case_evidence_id=case_ref.id if case_ref else None,
            observation_evidence_id=observed_ref.id if observed_ref else None,
            execution_evidence_ids=tuple(item.id for item in evidence
                if item.stage == "test-execution" or item.stage == "build"))
        if persist_process_output:
            execution_payload = self.artifact_store.write_json("executions", f"{run_id}-{execution_id}.json", raw.to_dict(),
                evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id,
                property_id=test_case.property_id, metadata={"execution_id": execution_id,
                    "test_case_id": test_case.id, "result_id": result.id,
                    "observation_evidence_id": observed_ref.id if observed_ref else None})
        else:
            execution_payload = None
        raw = TestExecutionResult(test_case_id=raw.test_case_id, execution_id=execution_id,
            executed=raw.executed, observed=raw.observed, oracle_evaluation=raw.oracle_evaluation,
            verification_result=raw.verification_result, command_result=raw.command_result,
            build_result=raw.build_result, duration_ms=raw.duration_ms,
            evidence_ids=tuple((*raw.evidence_ids, *((execution_payload.id,) if execution_payload else ()))), reason=raw.reason,
            test_case_evidence_id=raw.test_case_evidence_id,
            observation_evidence_id=raw.observation_evidence_id,
            execution_evidence_ids=raw.execution_evidence_ids)
        return raw

    def run_many(self, cases: Iterable[TestCase], **kwargs: Any) -> TestSuiteResult:
        executions = []
        for test_case in cases:
            try:
                executions.append(self.run_one(test_case, **kwargs))
            except Exception as exc:  # Keep independently failing test cases isolated.
                reason = f"TEST_RUNNER_ERROR:{type(exc).__name__}:{exc}"
                failure_id = uuid.uuid4().hex
                failure_evidence = self.artifact_store.write_json("test-errors", f"{failure_id}-runner-error.json", {
                    "test_case": test_case.to_dict(), "error_type": type(exc).__name__, "message": str(exc),
                }, evidence_type=EvidenceType.LOG, requirement_id=test_case.requirement_id,
                   property_id=test_case.property_id, metadata={"test_case_id": test_case.id})
                result = self.classifier.classify(ClassificationInput(
                    outcome=RawOutcome.TOOL_FAILED, stage="DYNAMIC_TEST", technique="TEST_ORACLE",
                    reason_code="TEST_RUNNER_ERROR", message=reason,
                    requirement_id=test_case.requirement_id, property_id=test_case.property_id,
                    evidence_ids=(failure_evidence.id,),
                    metadata={"test_case_id": test_case.id, "error_type": type(exc).__name__,
                              "evidence": [{"id": failure_evidence.id, "path": failure_evidence.path,
                                            "sha256": failure_evidence.hash}]},
                ))
                self.artifact_store.write_json("results", f"{failure_id}-verification-result.json", result.to_dict(),
                    evidence_type=EvidenceType.TEST_RESULT, requirement_id=test_case.requirement_id,
                    property_id=test_case.property_id)
                execution_id = "exec-" + hashlib.sha256((test_case.id + "\0" + failure_id).encode()).hexdigest()[:32]
                executions.append(TestExecutionResult(test_case_id=test_case.id, execution_id=execution_id,
                    executed=False, observed=None, oracle_evaluation=OracleEvaluation(()),
                    verification_result=result, evidence_ids=(failure_evidence.id,), reason=reason))
        return TestSuiteResult(tuple(executions))

    def _build_directory(self, run_id: str, base_directory: str | Path | None = None) -> Path:
        path = (Path(base_directory).resolve() if base_directory is not None else self.workspace_root / "build" / "test-runs") / run_id
        path.mkdir(parents=True, exist_ok=False)
        return path


def _function_arguments(case: TestCase, names: tuple[str, ...]) -> tuple[str, ...]:
    if set(case.inputs) != set(names):
        raise TestError(TestErrorCode.HARNESS_UNSUPPORTED_INPUT,
                        f"Function inputs must name exactly these parameters: {', '.join(names)}.")
    args = []
    for name in names:
        value = case.inputs[name]
        if isinstance(value, bool):
            args.append("1" if value else "0")
        elif isinstance(value, int):
            args.append(str(value))
        elif isinstance(value, float) and math.isfinite(value):
            args.append(repr(value))
        else:
            raise TestError(TestErrorCode.HARNESS_UNSUPPORTED_INPUT, f"Function parameter {name!r} requires a finite scalar input.")
    return tuple(args)


def _executable_inputs(case: TestCase) -> tuple[tuple[str, ...], str | bytes | None]:
    unknown = set(case.inputs) - {"argv", "stdin"}
    if unknown:
        raise TestError(TestErrorCode.INVALID_TEST_CASE, f"Executable inputs only support argv and stdin, got {sorted(unknown)}.")
    argv = case.inputs.get("argv", ())
    stdin = case.inputs.get("stdin")
    if not isinstance(argv, (tuple, list)) or any(not isinstance(item, str) for item in argv):
        raise TestError(TestErrorCode.INVALID_TEST_CASE, "Executable argv must be a list of strings.")
    if stdin is not None and not isinstance(stdin, (str, bytes)):
        raise TestError(TestErrorCode.INVALID_TEST_CASE, "Executable stdin must be text or bytes.")
    return tuple(argv), stdin


def _hash_sources(sources: tuple[SourceFile | str | Path, ...]) -> tuple[dict[str, str], str | None]:
    result = {}
    for source in sources:
        path = Path(source.path if isinstance(source, SourceFile) else source)
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                return result, f"Not a regular source file: {resolved}"
            result[_source_label(source)] = hashlib.sha256(resolved.read_bytes()).hexdigest()
        except OSError as exc:
            return result, f"Cannot hash source {_source_label(source)}: {exc}"
    return result, None


def _source_label(source: SourceFile | str | Path) -> str:
    return source.relative_path if isinstance(source, SourceFile) else Path(source).as_posix()


def _execution_fingerprint(test_case: TestCase, source_hashes: dict[str, str], timeout: float | None,
                           args: tuple[str, ...], stdin: str | bytes | None,
                           build_flags: Iterable[str], process_env: dict[str, str] | None, *,
                           executable: str | Path | None = None, compiler_name: str | None = None) -> str:
    """Stable digest of the declared case and execution inputs (excludes run-specific timing/IDs)."""
    stdin_value = ({"bytes_sha256": hashlib.sha256(stdin).hexdigest()} if isinstance(stdin, bytes) else stdin)
    executable_path = Path(executable).resolve() if executable is not None else None
    executable_hash = hashlib.sha256(executable_path.read_bytes()).hexdigest() if executable_path and executable_path.is_file() else None
    payload = {"test_case": test_case.to_dict(), "source_sha256": source_hashes, "timeout_seconds": timeout,
               "argv": list(args), "stdin": stdin_value, "build_flags": list(build_flags),
               "environment": dict(sorted((process_env or {}).items())), "executable": str(executable_path) if executable_path else None,
               "executable_sha256": executable_hash, "compiler": compiler_name}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _language_from_sources(sources: tuple[SourceFile | str | Path, ...]) -> Language | None:
    extensions = {Path(item.path if isinstance(item, SourceFile) else item).suffix.lower() for item in sources}
    if extensions <= {".c"}:
        return Language.C
    if extensions and extensions <= {".cc", ".cpp", ".cxx"}:
        return Language.CPP
    return None


def _parse_json_output(stdout: str) -> tuple[Any, bool]:
    try:
        return json.loads(stdout), True
    except (json.JSONDecodeError, TypeError):
        return None, False


def _memory_analysis_requested(flags: Iterable[str]) -> bool:
    values = tuple(str(item).lower() for item in flags)
    joined = " ".join(values)
    return "-fsanitize=address" in joined or "-fsanitize=undefined" in joined or "-fsanitize=leak" in joined


def _extract_return_marker(stderr: str) -> tuple[tuple[str, Any] | None, str, bool]:
    marker = re.compile(r"^SECLAB_RETURN=(VOID|INT|UINT|BOOL|REAL):(.*)$")
    found = []
    clean = []
    invalid = False
    for line in stderr.splitlines():
        if line.startswith("SECLAB_RETURN="):
            match = marker.fullmatch(line)
            if not match:
                invalid = True
            else:
                kind, raw = match.groups()
                try:
                    value = (None if kind == "VOID" else raw == "1" if kind == "BOOL"
                             else int(raw) if kind in {"INT", "UINT"} else float(raw))
                    if kind == "REAL" and not math.isfinite(value):
                        raise ValueError("non-finite return")
                    found.append((kind, value))
                except ValueError:
                    invalid = True
        else:
            clean.append(line)
    if len(found) != 1:
        return None, "\n".join(clean) + ("\n" if stderr.endswith("\n") and clean else ""), invalid or bool(found)
    return found[0], "\n".join(clean) + ("\n" if stderr.endswith("\n") and clean else ""), invalid


def _did_crash(exit_code: int | None, execution_error: str | None) -> bool | None:
    if exit_code is None or execution_error:
        return None
    if exit_code < 0:
        return True
    return (exit_code & 0xFFFFFFFF) in {0xC0000005, 0xC000001D, 0xC0000094, 0xC00000FD, 0xC0000409, 0xC0000374, 0xC000008C}


def _classification(reason: str | None, command: Any, build: BuildResult | None,
                    evaluation: OracleEvaluation) -> tuple[RawOutcome, str, str]:
    if reason == "INVALID_TEST_CASE":
        return RawOutcome.INVALID_SPEC, "INVALID_TEST_CASE", "Test definition or oracle is invalid."
    if reason and reason.startswith("ORACLE_EVALUATION_ERROR:"):
        return RawOutcome.TOOL_FAILED, "ORACLE_EVALUATION_ERROR", "Oracle evaluation failed; process observation was retained."
    if command is not None and command.timed_out:
        return RawOutcome.TIMEOUT, "TEST_EXECUTION_TIMEOUT", "Test process timed out before the oracle could conclude."
    if reason == "SOURCE_INTEGRITY_CHANGED":
        return RawOutcome.TOOL_FAILED, "SOURCE_INTEGRITY_CHANGED", "SUT source bytes changed during test execution."
    if reason == "OBSERVATION_PARSE_ERROR":
        return RawOutcome.TOOL_FAILED, reason, "Harness return observation could not be parsed uniquely."
    if reason == "PROCESS_CRASH_UNASSERTED":
        return RawOutcome.UNKNOWN, reason, "The process terminated abnormally without an explicit no-crash oracle."
    if build is not None and not build.success:
        if build.error_code == "COMPILATION_FAILED":
            return RawOutcome.BUILD_FAILED, "TEST_BUILD_FAILED", "The SUT and generated harness did not compile."
        return RawOutcome.TOOL_FAILED, build.error_code or "TEST_BUILD_ERROR", "The build tool was unavailable or failed to execute."
    if command is not None and command.execution_error:
        return RawOutcome.TOOL_FAILED, "TEST_EXECUTION_ERROR", "The process runner could not execute the test target."
    if evaluation.satisfied is False:
        return RawOutcome.PROPERTY_VIOLATED, "TEST_ORACLE_VIOLATED", "Observed behavior violated at least one declared oracle check."
    if evaluation.satisfied is True:
        return RawOutcome.PROPERTY_SATISFIED, "TEST_ORACLE_SATISFIED", "All declared oracle checks were satisfied by this execution."
    if reason:
        return RawOutcome.UNKNOWN, reason, f"Test produced no conclusive execution verdict: {reason}."
    if not evaluation.checks:
        return RawOutcome.UNKNOWN, "NO_TEST_ORACLE", "Execution completed without an explicit expected behavior oracle."
    return RawOutcome.UNKNOWN, "OBSERVATION_UNAVAILABLE", "The declared oracle could not be evaluated from available observations."
