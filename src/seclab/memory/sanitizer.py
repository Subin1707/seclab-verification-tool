"""Common build/run/evidence lifecycle for runtime sanitizers."""

from __future__ import annotations

import uuid
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence

from seclab.evidence import Evidence, EvidenceType
from seclab.execution import (
    BuildResult, CommandResult, Compiler, ProcessRunner, ProcessSpec,
    store_command_evidence,
)
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier, VerificationResult
from seclab.source import Language, SourceFile
from seclab.static_analysis.analyzer import AnalysisContext

from .memory_finding import MemoryFinding


@dataclass(frozen=True, slots=True)
class SanitizerRunResult:
    sanitizer: str
    build_result: BuildResult | None
    execution_result: CommandResult | None
    findings: tuple[MemoryFinding, ...]
    evidence: tuple[Evidence, ...]
    supported: bool
    limitations: tuple[str, ...]
    verification_result: VerificationResult


class Sanitizer:
    name = "sanitizer"
    flags: tuple[str, ...] = ()
    parser: Callable[..., tuple[MemoryFinding, ...]]
    violation_reason = "MEMORY_SAFETY_VIOLATION"
    stage = "SANITIZER"

    def run(self, source_collection: Sequence[SourceFile], context: AnalysisContext, language: Language | str, *,
            args: Sequence[str] = (), stdin: str | bytes | None = None, timeout: float | None = None,
            env: Mapping[str, str] | None = None, compiler: str | None = None,
            result_id: str | None = None) -> SanitizerRunResult:
        limitations: list[str] = []
        evidence: list[Evidence] = []
        compiler_component = Compiler(context.workspace_root, context.toolchain,
                                      command_runner=context.command_runner, artifact_store=context.artifact_store,
                                      timeout=context.timeout)
        selected = compiler
        if selected is None:
            # Prefer Clang where available; both sanitizer families are compiler instrumentation.
            lang = getattr(language, "value", language)
            candidate = "clang" if lang == "C" else "clang++"
            if context.toolchain.get(candidate).installed:
                selected = candidate
        build = compiler_component.build(
            source_collection, language, compiler=selected, flags=(*self.flags, *context.flags),
            output_name=f"{self.name.lower()}-{uuid.uuid4().hex}",
        )
        evidence.extend(build.build_evidence)
        if build.success and build.command_result and _instrumentation_ignored(build.command_result.stderr):
            result = self._result(
                RawOutcome.UNKNOWN, "SANITIZER_UNAVAILABLE",
                f"{self.name} compile flag was ignored; the executable was not run as an instrumented binary.",
                evidence, result_id, None,
                scope=f"{self.name} instrumentation could not be established for the supplied source build.",
                metadata={"compiler_stderr": build.command_result.stderr,
                          "capability_status": "UNSUPPORTED", "environment_limited": True},
            )
            return SanitizerRunResult(self.name, build, None, (), tuple(evidence), False,
                                      ("The compiler reported that sanitizer instrumentation flags were ignored.",), result)
        if not build.success:
            command_stderr = build.command_result.stderr.lower() if build.command_result else ""
            unsupported_markers = ("unsupported option", "unrecognized command-line option", "unknown argument",
                                   "unsupported argument", "cannot find -lasan", "sanitizer is not supported")
            unsupported = any(marker in command_stderr for marker in unsupported_markers)
            if unsupported:
                supported = False
                outcome, reason = RawOutcome.UNKNOWN, "SANITIZER_UNAVAILABLE"
                message = f"{self.name} instrumentation is unavailable in the selected compiler environment."
                limitations.append(build.command_result.stderr if build.command_result and build.command_result.stderr else message)
            elif build.error_code == "COMPILER_NOT_FOUND":
                supported = False
                outcome, reason, message = RawOutcome.UNKNOWN, "COMPILER_NOT_FOUND", "No suitable compiler is installed."
            elif build.error_code == "COMMAND_TIMEOUT":
                supported = True
                outcome, reason, message = RawOutcome.TIMEOUT, "SANITIZER_BUILD_TIMEOUT", "Instrumented compilation timed out."
            else:
                supported = True
                outcome, reason, message = RawOutcome.BUILD_FAILED, "SANITIZER_BUILD_FAILED", "Instrumented compilation failed."
            if not evidence:
                evidence.append(context.artifact_store.write_json("sanitizer",
                    f"{self.name.lower()}-build-capability-{uuid.uuid4().hex}.json",
                    {"sanitizer": self.name, "build_success": False, "build_error": build.error_code,
                     "supported": supported, "reason_code": reason},
                    evidence_type=EvidenceType.ENVIRONMENT if not supported else EvidenceType.LOG,
                    source=self.name))
            result = self._result(outcome, reason, message, evidence, result_id, None,
                                  scope=f"{self.name} instrumentation build for the supplied sources; no runtime property verdict was produced.",
                                  metadata={"build_error": build.error_code,
                                            "capability_status": ("ENVIRONMENT_LIMITED" if not supported else
                                                                   "AVAILABLE"),
                                            "environment_limited": not supported})
            return SanitizerRunResult(self.name, build, None, (), tuple(evidence), supported,
                                      tuple(limitations), result)

        assert build.binary_path is not None
        process = ProcessRunner(context.command_runner).run(ProcessSpec(
            build.binary_path, tuple(args), cwd=context.workspace_root, stdin=stdin,
            timeout=timeout or context.timeout, env=dict(env or {}),
        ))
        prefix = f"{self.name.lower()}-{uuid.uuid4().hex}"
        evidence.extend(store_command_evidence(context.artifact_store, process, stage="sanitizer", prefix=prefix))
        raw_text = process.stdout + ("\n" + process.stderr if process.stderr else "")
        raw_artifact = context.artifact_store.write_text(
            "sanitizer", f"{prefix}-raw.txt", raw_text,
            evidence_type=EvidenceType.SANITIZER_REPORT, source=self.name,
        )
        evidence.append(raw_artifact)
        findings = self.parser(raw_text, raw_evidence=raw_artifact.id)
        if self.name == "LeakSanitizer":
            findings = tuple(replace(item, tool="LeakSanitizer") if item.kind == "MEMORY_LEAK" else item
                             for item in findings)
        normalized_artifact = context.artifact_store.write_json(
            "sanitizer", f"{prefix}-findings.json",
            {"sanitizer": self.name, "findings": [item.to_dict() for item in findings]},
            evidence_type=EvidenceType.SANITIZER_REPORT, source=self.name,
        )
        evidence.append(normalized_artifact)

        runtime_unavailable = _runtime_unavailable(process.exit_code, process.stderr)
        if runtime_unavailable:
            supported = False
            outcome, reason = RawOutcome.UNKNOWN, "SANITIZER_UNAVAILABLE"
            message = f"{self.name} runtime could not be loaded on this platform."
            limitations.append("Instrumentation compiled, but its runtime dependency was unavailable during execution.")
        elif findings:
            supported = True
            outcome = RawOutcome.PROPERTY_VIOLATED
            reason = "LEAK_DETECTED" if any(item.kind == "MEMORY_LEAK" for item in findings) else self.violation_reason
            message = f"{self.name} reported {len(findings)} runtime violation(s) for this execution."
        elif process.timed_out:
            supported = True
            outcome, reason, message = RawOutcome.TIMEOUT, "SANITIZER_EXECUTION_TIMEOUT", "Instrumented execution timed out."
        elif process.execution_error:
            supported = True
            outcome, reason, message = RawOutcome.TOOL_FAILED, "EXECUTABLE_NOT_FOUND", "Instrumented executable could not be started."
        elif process.exit_code in process.allowed_exit_codes:
            supported = True
            outcome, reason = RawOutcome.PROPERTY_SATISFIED, "NO_SANITIZER_VIOLATION_OBSERVED"
            message = f"No {self.name} violation was observed in this execution."
        else:
            supported = True
            outcome, reason = RawOutcome.UNKNOWN, "SANITIZER_RUN_FAILED"
            message = "The instrumented process exited unsuccessfully without a recognized sanitizer report."
            limitations.append("A crash or non-zero exit without a recognized report is not classified as a memory defect.")
        result = self._result(
            outcome, reason, message, evidence, result_id, process.duration_ms,
            scope=f"{self.name} observations for binary {build.binary_path.name} and this execution/input only; this is not a global memory-safety proof.",
            metadata={"finding_ids": [item.id for item in findings], "exit_code": process.exit_code,
                      "timed_out": process.timed_out,
                      "capability_status": "ENVIRONMENT_LIMITED" if not supported else "AVAILABLE",
                      "environment_limited": not supported},
        )
        return SanitizerRunResult(self.name, build, process, findings, tuple(evidence), supported,
                                  tuple(limitations), result)

    def _result(self, outcome: RawOutcome, reason: str, message: str, evidence: Sequence[Evidence],
                result_id: str | None, duration_ms: float | None, *, scope: str,
                metadata: Mapping[str, object]) -> VerificationResult:
        return (ResultClassifier().classify(ClassificationInput(
            outcome, self.stage, self.name.upper(), message, reason, scope=scope,
            evidence_ids=tuple(item.id for item in evidence), duration_ms=duration_ms, metadata=metadata,
        ), result_id=result_id))


def _runtime_unavailable(exit_code: int | None, stderr: str) -> bool:
    if os.name == "nt" and exit_code == 0xC0000135:  # STATUS_DLL_NOT_FOUND
        return True
    lowered = stderr.lower()
    return any(token in lowered for token in (
        "unable to load addresssanitizer", "failed to load sanitizer runtime",
        "libclang_rt.asan" + "-" + "dynamic" + ".dll was not found",
        "cannot find the sanitizer runtime",
    ))


def _instrumentation_ignored(stderr: str) -> bool:
    lowered = stderr.lower()
    return "-fsanitize" in lowered and any(token in lowered for token in (
        "argument unused", "unsupported option", "ignoring unsupported", "not supported",
    ))
