"""Compiler diagnostics runner; does not build or emit an executable."""

from __future__ import annotations

from collections.abc import Sequence

from seclab.execution import CommandSpec
from seclab.source import SourceFile

from .analyzer import (AnalysisContext, AnalysisResult, persist_command_output, persist_environment_limitation,
                       persist_findings)
from .cwe_mapper import CWEMapper
from .finding import Finding
from .parsers import parse_compiler_diagnostics


class CompilerDiagnosticsRunner:
    tool_name = "compiler-diagnostics"

    def analyze(self, source_collection: Sequence[SourceFile], context: AnalysisContext) -> AnalysisResult:
        translation_units = [item for item in source_collection if item.extension in {".c", ".cc", ".cpp", ".cxx"}]
        if not translation_units:
            return AnalysisResult(self.tool_name, False, successful=False, reason_code="NO_SOURCE_FILES",
                                  scope="No C/C++ translation units were available for compiler diagnostics.")
        grouped = {"C": [item for item in translation_units if item.extension == ".c"],
                   "C++": [item for item in translation_units if item.extension in {".cc", ".cpp", ".cxx"}]}
        findings: list[Finding] = []
        evidence = []
        commands = []
        limitations: list[str] = []
        all_succeeded = True
        mapper = CWEMapper()
        for language, files in grouped.items():
            if not files:
                continue
            tool = context.toolchain.compiler_for(language)
            if tool is None or not tool.path:
                all_succeeded = False
                limitations.append(f"No compiler available for {language} diagnostics.")
                continue
            standard = "-std=c11" if language == "C" else "-std=c++17"
            argv = (tool.path, standard, "-Wall", "-Wextra", "-Wpedantic", "-fsyntax-only",
                    *context.flags, *(str(item.path) for item in files))
            command = context.command_runner.run(CommandSpec(argv, cwd=context.workspace_root, timeout=context.timeout))
            commands.append(command)
            raw = command.stderr + ("\n" + command.stdout if command.stdout else "")
            command_evidence, raw_evidence = persist_command_output(
                context, tool=self.tool_name, command=command, raw_output=raw, stage="static_analysis")
            evidence.extend(command_evidence)
            parsed = parse_compiler_diagnostics(raw, context=context, sources=files, tool=tool.name,
                                                raw_evidence=raw_evidence.id)
            findings.extend(mapper.apply(item) for item in parsed)
            if command.execution_error or command.timed_out or not command.succeeded:
                all_succeeded = False
        if limitations:
            evidence.append(persist_environment_limitation(context, tool=self.tool_name,
                reason_code="COMPILER_NOT_FOUND", message="No compiler was available for one or more source groups.",
                details={"limitations": limitations}))
        normalized = persist_findings(context, tool=self.tool_name, findings=findings, stage="static_analysis",
                                      limitations=limitations)
        evidence.append(normalized)
        timed_out = any(item.timed_out for item in commands)
        reason = ("STATIC_ANALYSIS_TIMEOUT" if timed_out else
                  "STATIC_ANALYSIS_FAILED" if any(not item.succeeded for item in commands) else
                  "COMPILER_NOT_FOUND" if limitations else
                  "STATIC_FINDINGS_DETECTED" if findings else "NO_STATIC_FINDINGS")
        scope = "Compiler warning/error diagnostics for collected translation units with -Wall -Wextra -Wpedantic and syntax-only mode; diagnostics are not security verdicts."
        return AnalysisResult(self.tool_name, any(item.execution_error is None for item in commands), tuple(findings), commands[-1] if commands else None,
                              tuple(evidence), tuple(limitations), all_succeeded, reason, scope, tuple(commands))


CompilerRunner = CompilerDiagnosticsRunner
