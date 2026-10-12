"""Common static-analysis interface and shared evidence/result adaptation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol, Sequence

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore, Evidence, EvidenceType
from seclab.execution import CommandResult, CommandRunner, store_command_evidence
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier, VerificationResult
from seclab.source import SourceFile

from .finding import Finding


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    source_root: Path
    workspace_root: Path
    toolchain: Toolchain
    command_runner: CommandRunner
    artifact_store: ArtifactStore
    timeout: float = 120.0
    flags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    tool: str
    executed: bool
    findings: tuple[Finding, ...] = ()
    command_result: CommandResult | None = None
    evidence: tuple[Evidence, ...] = ()
    limitations: tuple[str, ...] = ()
    successful: bool = False
    reason_code: str = "STATIC_ANALYSIS_FAILED"
    scope: str = ""
    command_results: tuple[CommandResult, ...] = ()

    def to_verification_result(self, *, result_id: str | None = None,
                                classifier: ResultClassifier | None = None) -> VerificationResult:
        if self.reason_code.endswith("TIMEOUT"):
            outcome = RawOutcome.TIMEOUT
        elif (self.reason_code.endswith("_NOT_FOUND")
              or self.reason_code.endswith("_UNAVAILABLE")
              or self.reason_code in {"NO_SOURCE_FILES", "NO_COMPILER_AVAILABLE"}):
            outcome = RawOutcome.UNKNOWN
        elif not self.executed:
            outcome = RawOutcome.TOOL_FAILED
        elif not self.successful:
            outcome = RawOutcome.TOOL_FAILED
        else:
            # Static findings are analyzer reports, not automatically confirmed violations.
            outcome = RawOutcome.UNKNOWN
        reason = self.reason_code
        message = (f"{len(self.findings)} finding(s) reported by {self.tool}; these are not confirmed property violations."
                   if self.findings else f"{self.tool} reported no findings for this configuration and source collection.")
        raw = ClassificationInput(
            outcome=outcome, stage="STATIC_ANALYSIS", technique=self.tool.upper(), reason_code=reason,
            message=message, scope=self.scope or f"Analysis limited to {self.tool} configuration and collected source files.",
            evidence_ids=tuple(item.id for item in self.evidence),
            duration_ms=(sum(item.duration_ms for item in self.command_results) if self.command_results else
                         self.command_result.duration_ms if self.command_result else None),
            metadata={"finding_ids": [item.id for item in self.findings], "limitations": list(self.limitations),
                      "capability_status": ("AVAILABLE" if self.executed else
                          "ENVIRONMENT_LIMITED" if outcome is RawOutcome.UNKNOWN else "ERROR"),
                      "scan_status": "FINDINGS_REPORTED" if self.findings else
                          "NO_FINDINGS_IN_SCOPE" if self.successful else "SCAN_INCOMPLETE"},
        )
        return (classifier or ResultClassifier()).classify(raw, result_id=result_id)


class StaticAnalyzer(Protocol):
    tool_name: str

    def analyze(self, source_collection: Sequence[SourceFile], context: AnalysisContext) -> AnalysisResult: ...


def normalized_tool_path(raw_path: str | None, context: AnalysisContext,
                         sources: Sequence[SourceFile]) -> tuple[str, str | None]:
    if not raw_path:
        return "<unknown>", None
    raw = raw_path.strip().strip('"')
    candidate = Path(raw)
    try:
        resolved = candidate.resolve(strict=False) if candidate.is_absolute() else (context.source_root / candidate).resolve(strict=False)
        if resolved.is_relative_to(context.source_root.resolve()):
            return resolved.relative_to(context.source_root.resolve()).as_posix(), raw
    except (OSError, RuntimeError):
        pass
    # Match analyzer output against collected relative paths, including Windows separators.
    normalized = raw.replace("\\", "/")
    for source in sources:
        rel = source.relative_path.replace("\\", "/")
        if normalized == rel or normalized.endswith("/" + rel):
            return rel, raw
    return normalized, raw


def persist_analysis(context: AnalysisContext, *, tool: str, command: CommandResult,
                     raw_output: str, findings: Sequence[Finding], stage: str = "static_analysis",
                     limitations: Sequence[str] = ()) -> tuple[tuple[Finding, ...], tuple[Evidence, ...]]:
    evidence, raw = persist_command_output(context, tool=tool, command=command, raw_output=raw_output, stage=stage)
    findings_with_raw = tuple(replace(item, raw_evidence=raw.id) for item in findings)
    normalized = persist_findings(context, tool=tool, findings=findings_with_raw, stage=stage, limitations=limitations)
    return findings_with_raw, (*evidence, normalized)


def persist_command_output(context: AnalysisContext, *, tool: str, command: CommandResult,
                           raw_output: str, stage: str) -> tuple[tuple[Evidence, ...], Evidence]:
    prefix = f"{tool}-{uuid.uuid4().hex}"
    evidence = list(store_command_evidence(context.artifact_store, command, stage=stage, prefix=prefix))
    raw = context.artifact_store.write_text(stage, f"{prefix}-raw.txt", raw_output,
                                            evidence_type=EvidenceType.STATIC_ANALYSIS_REPORT,
                                            source=tool)
    evidence.append(raw)
    return tuple(evidence), raw


def persist_findings(context: AnalysisContext, *, tool: str, findings: Sequence[Finding],
                     stage: str, limitations: Sequence[str] = ()) -> Evidence:
    return context.artifact_store.write_json(
        stage, f"{tool}-{uuid.uuid4().hex}-findings.json",
        {"tool": tool, "findings": [item.to_dict() for item in findings], "limitations": list(limitations)},
        source=tool,
    )


def persist_environment_limitation(context: AnalysisContext, *, tool: str, reason_code: str,
                                  message: str, details: dict[str, object] | None = None) -> Evidence:
    """Persist capability absence as evidence without turning it into a finding."""
    import uuid

    return context.artifact_store.write_json(
        "static_analysis", f"{tool}-{uuid.uuid4().hex}-capability.json",
        {"tool": tool, "reason_code": reason_code, "message": message,
         "capability_status": "ENVIRONMENT_LIMITED", "details": details or {}},
        evidence_type=EvidenceType.ENVIRONMENT, source=tool,
    )
