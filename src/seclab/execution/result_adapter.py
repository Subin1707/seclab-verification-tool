"""Map build/process infrastructure outcomes into shared semantic results."""

from __future__ import annotations

from collections.abc import Sequence

from seclab.results import ClassificationInput, RawOutcome, ResultClassifier, VerificationResult

from .compiler import BuildResult
from .command_runner import CommandResult


def classify_build_result(build: BuildResult, *, classifier: ResultClassifier | None = None,
                          result_id: str | None = None, evidence_ids: Sequence[str] = ()) -> VerificationResult:
    if build.success:
        outcome, reason, message = RawOutcome.UNKNOWN, "BUILD_COMPLETED", "Compilation completed; no verification property was evaluated."
    elif build.error_code == "COMMAND_TIMEOUT":
        outcome, reason, message = RawOutcome.TIMEOUT, "COMMAND_TIMEOUT", "The compiler exceeded its build timeout."
    elif build.error_code == "COMPILER_NOT_FOUND":
        outcome, reason, message = RawOutcome.TOOL_FAILED, "COMPILER_NOT_FOUND", "No suitable compiler is installed."
    elif build.error_code == "COMPILATION_FAILED":
        outcome, reason, message = RawOutcome.BUILD_FAILED, "COMPILATION_FAILED", "Compilation failed; no property verdict was produced."
    else:
        outcome, reason, message = RawOutcome.TOOL_FAILED, "COMMAND_EXECUTION_ERROR", "The compiler command could not be executed."
    raw = ClassificationInput(outcome, "BUILD", "COMPILER", message, reason,
                              scope="Build infrastructure only; compilation does not establish a verification property.",
                              evidence_ids=tuple(evidence_ids),
                              duration_ms=build.command_result.duration_ms if build.command_result else None,
                              metadata={"language": build.language, "source_files": list(build.source_files),
                                        "compiler": build.compiler.name if build.compiler else None})
    return (classifier or ResultClassifier()).classify(raw, result_id=result_id)


def classify_execution_result(command: CommandResult, *, classifier: ResultClassifier | None = None,
                              result_id: str | None = None, evidence_ids: Sequence[str] = ()) -> VerificationResult:
    if command.timed_out:
        outcome, reason, message = RawOutcome.TIMEOUT, "EXECUTION_TIMEOUT", "The process exceeded its execution timeout."
    elif command.execution_error:
        reason = "EXECUTABLE_NOT_FOUND" if command.executable_path is None else "COMMAND_EXECUTION_ERROR"
        outcome, message = RawOutcome.TOOL_FAILED, "The process could not be started."
    else:
        outcome, reason, message = RawOutcome.UNKNOWN, "EXECUTION_COMPLETED", "The process ran; no verification property was evaluated."
    raw = ClassificationInput(outcome, "EXECUTION", "PROCESS", message, reason,
                              scope="Process execution only; no verification property was evaluated, so exit status is not a verdict.",
                              evidence_ids=tuple(evidence_ids),
                              duration_ms=command.duration_ms,
                              metadata={"exit_code": command.exit_code, "timed_out": command.timed_out})
    return (classifier or ResultClassifier()).classify(raw, result_id=result_id)
