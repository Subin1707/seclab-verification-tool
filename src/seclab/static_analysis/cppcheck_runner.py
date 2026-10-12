"""Cppcheck XML runner using the shared toolchain, command runner and evidence store."""

from __future__ import annotations

from collections.abc import Sequence

from seclab.evidence import Evidence
from seclab.execution import CommandSpec
from seclab.source import SourceFile

from .analyzer import (AnalysisContext, AnalysisResult, persist_command_output, persist_environment_limitation,
                       persist_findings)
from .cwe_mapper import CWEMapper
from .finding import Finding
from .parsers import parse_cppcheck_xml


class CppcheckRunner:
    tool_name = "cppcheck"

    def analyze(self, source_collection: Sequence[SourceFile], context: AnalysisContext) -> AnalysisResult:
        tool = context.toolchain.get("cppcheck")
        scope = "Cppcheck reports for the collected C/C++ files under the requested enable configuration; reports are not confirmed vulnerabilities."
        if not tool.installed or not tool.path:
            evidence = persist_environment_limitation(context, tool=self.tool_name, reason_code="CPPCHECK_NOT_FOUND",
                message="Cppcheck executable was not found.", details=tool.to_dict())
            return AnalysisResult(self.tool_name, False, evidence=(evidence,), successful=False,
                                  reason_code="CPPCHECK_NOT_FOUND", scope=scope,
                                  limitations=("Cppcheck is unavailable in the current environment.",))
        if not source_collection:
            return AnalysisResult(self.tool_name, False, successful=False, reason_code="NO_SOURCE_FILES", scope=scope,
                                  limitations=("No C/C++ source files were supplied.",))
        argv = (tool.path, "--xml", "--xml-version=2", "--enable=warning,style,performance,portability,information",
                *(str(item.path) for item in source_collection))
        command = context.command_runner.run(CommandSpec(argv, cwd=context.workspace_root, timeout=context.timeout))
        raw = command.stderr if command.stderr.strip() else command.stdout
        command_evidence, raw_evidence = persist_command_output(
            context, tool=self.tool_name, command=command, raw_output=raw, stage="static_analysis")
        parsed = parse_cppcheck_xml(raw, context=context, sources=source_collection, raw_evidence=raw_evidence.id)
        mapped = tuple(CWEMapper().apply(item) for item in parsed)
        findings = mapped
        normalized_evidence = persist_findings(context, tool=self.tool_name, findings=findings, stage="static_analysis")
        evidence = command_evidence + (normalized_evidence,)
        succeeded = command.succeeded
        reason = "STATIC_FINDINGS_DETECTED" if findings else "NO_STATIC_FINDINGS"
        if command.timed_out:
            reason = "STATIC_ANALYSIS_TIMEOUT"
        elif command.execution_error or not command.succeeded:
            reason = "STATIC_ANALYSIS_FAILED"
        return AnalysisResult(self.tool_name, command.execution_error is None, findings, command, evidence, (),
                              succeeded, reason, scope, (command,))
