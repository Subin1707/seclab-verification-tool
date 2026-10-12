"""Clang-Tidy runner (distinct from Clang Static Analyzer as a standalone tool)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from seclab.execution import CommandSpec
from seclab.source import SourceFile

from .analyzer import (AnalysisContext, AnalysisResult, persist_command_output, persist_environment_limitation,
                       persist_findings)
from .cwe_mapper import CWEMapper
from .finding import Finding
from .parsers import parse_clang_tidy_diagnostics


class ClangTidyRunner:
    tool_name = "clang-tidy"

    def analyze(self, source_collection: Sequence[SourceFile], context: AnalysisContext) -> AnalysisResult:
        units = [item for item in source_collection if item.extension in {".c", ".cc", ".cpp", ".cxx"}]
        tool = context.toolchain.get("clang-tidy")
        scope = "Clang-Tidy checks for collected translation units; analyzer diagnostics are reports, not confirmed property violations."
        if not tool.installed or not tool.path:
            evidence = persist_environment_limitation(context, tool=self.tool_name,
                reason_code="CLANG_TIDY_NOT_FOUND", message="Clang-Tidy executable was not found.",
                details=tool.to_dict())
            return AnalysisResult(self.tool_name, False, evidence=(evidence,), successful=False,
                reason_code="CLANG_TIDY_NOT_FOUND", scope=scope,
                limitations=("Clang-Tidy is unavailable in the current environment.",))
        if not units:
            return AnalysisResult(self.tool_name, False, successful=False, reason_code="NO_SOURCE_FILES", scope=scope)

        database = context.source_root / "compile_commands.json"
        has_database = database.is_file()
        groups = [units] if has_database else [group for group in (
            [item for item in units if item.extension == ".c"],
            [item for item in units if item.extension in {".cc", ".cpp", ".cxx"}],
        ) if group]
        limitations = () if has_database else ("No compile_commands.json exists; analysis uses limited default compile flags.",)
        commands = []
        findings: list[Finding] = []
        evidence = []
        for group in groups:
            args = [tool.path, "-checks=clang-analyzer-*,bugprone-*,performance-*,portability-*"]
            if has_database:
                args.extend(("-p", str(context.source_root)))
            args.extend(str(item.path) for item in group)
            if not has_database:
                args.append("--")
                if group[0].extension == ".c":
                    args.extend(("-x", "c", "-std=c11"))
                else:
                    args.append("-std=c++17")
                args.extend(context.flags)
            command = context.command_runner.run(CommandSpec(tuple(args), cwd=context.workspace_root, timeout=context.timeout))
            commands.append(command)
            raw = command.stdout + ("\n" + command.stderr if command.stderr else "")
            command_evidence, raw_evidence = persist_command_output(
                context, tool=self.tool_name, command=command, raw_output=raw, stage="static_analysis")
            evidence.extend(command_evidence)
            parsed = parse_clang_tidy_diagnostics(raw, context=context, sources=group, raw_evidence=raw_evidence.id)
            findings.extend(CWEMapper().apply(item) for item in parsed)
        normalized = persist_findings(context, tool=self.tool_name, findings=findings,
                                      stage="static_analysis", limitations=limitations)
        evidence.append(normalized)
        successful = all(command.succeeded for command in commands)
        timed_out = any(command.timed_out for command in commands)
        reason = ("STATIC_ANALYSIS_TIMEOUT" if timed_out else "STATIC_ANALYSIS_FAILED" if not successful else
                  "STATIC_FINDINGS_DETECTED" if findings else "NO_STATIC_FINDINGS")
        return AnalysisResult(self.tool_name, any(command.execution_error is None for command in commands),
                              tuple(findings), commands[-1] if commands else None, tuple(evidence), limitations,
                              successful, reason, scope, tuple(commands))


class ClangStaticAnalyzerRunner:
    """Run Clang's built-in Static Analyzer on C and C++ translation units."""

    tool_name = "clang-static-analyzer"

    def analyze(self, source_collection: Sequence[SourceFile], context: AnalysisContext) -> AnalysisResult:
        units = [item for item in source_collection if item.extension in {".c", ".cc", ".cpp", ".cxx"}]
        scope = "Clang Static Analyzer path-sensitive reports for collected C/C++ translation units using clang --analyze; reports are not confirmed property violations."
        if not units:
            return AnalysisResult(self.tool_name, False, successful=False, reason_code="NO_SOURCE_FILES",
                                  scope=scope, limitations=("No C/C++ translation units were supplied.",))
        groups = [("C", [item for item in units if item.extension == ".c"]),
                  ("C++", [item for item in units if item.extension in {".cc", ".cpp", ".cxx"}])]
        commands = []
        findings: list[Finding] = []
        evidence = []
        limitations: list[str] = []
        for language, files in groups:
            if not files:
                continue
            compiler = context.toolchain.get("clang" if language == "C" else "clang++")
            if compiler is None or not compiler.path:
                limitations.append(f"No Clang compiler is available for {language} static analysis.")
                continue
            argv = (compiler.path, "--analyze", "-Xanalyzer", "-analyzer-output=text",
                    "-std=c11" if language == "C" else "-std=c++17", *context.flags,
                    *(str(item.path) for item in files))
            command = context.command_runner.run(CommandSpec(argv, cwd=context.workspace_root,
                                                              timeout=context.timeout))
            commands.append(command)
            raw = command.stdout + ("\n" + command.stderr if command.stderr else "")
            command_evidence, raw_evidence = persist_command_output(
                context, tool=self.tool_name, command=command, raw_output=raw, stage="static_analysis")
            evidence.extend(command_evidence)
            findings.extend(CWEMapper().apply(item) for item in parse_clang_tidy_diagnostics(
                raw, context=context, sources=files, raw_evidence=raw_evidence.id,
                tool=self.tool_name))
        successful = bool(commands) and all(command.succeeded for command in commands)
        if limitations:
            evidence.append(persist_environment_limitation(context, tool=self.tool_name,
                reason_code="CLANG_COMPILER_NOT_FOUND", message="One or more language groups could not be analyzed.",
                details={"limitations": limitations}))
        findings_ref = persist_findings(context, tool=self.tool_name, findings=findings,
                                        stage="static_analysis", limitations=limitations)
        evidence.append(findings_ref)
        timed_out = any(command.timed_out for command in commands)
        reason = ("STATIC_ANALYSIS_TIMEOUT" if timed_out else
                  "STATIC_ANALYSIS_FAILED" if commands and not successful else
                  "CLANG_COMPILER_NOT_FOUND" if limitations or not commands else
                  "STATIC_FINDINGS_DETECTED" if findings else "NO_STATIC_FINDINGS")
        return AnalysisResult(self.tool_name, bool(commands), tuple(findings),
            commands[-1] if commands else None, tuple(evidence), tuple(limitations),
            successful, reason, scope, tuple(commands))
