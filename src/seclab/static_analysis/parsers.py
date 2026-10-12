"""Defensive parsers for machine-readable and compiler diagnostic output."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence

from seclab.source import SourceFile

from .analyzer import AnalysisContext, normalized_tool_path
from .finding import Finding, Severity, make_finding


IdFactory = Callable[[], str]


def parse_cppcheck_xml(output: str, *, context: AnalysisContext | None = None,
                       sources: Sequence[SourceFile] = (), raw_evidence: str | None = None,
                       id_factory: IdFactory | None = None) -> tuple[Finding, ...]:
    if not output or not output.strip():
        return ()
    try:
        root = ET.fromstring(output)
    except (ET.ParseError, ValueError):
        return ()
    make_id = id_factory or _uuid
    findings: list[Finding] = []
    for error in root.findall(".//error"):
        rule = error.get("id")
        severity = error.get("severity", "unknown")
        message = error.get("msg") or error.get("verbose") or "Cppcheck reported a finding without a message."
        location = next(iter(error.findall("location")), None)
        raw_path = location.get("file") if location is not None else None
        line = _positive_int(location.get("line")) if location is not None else None
        if context is not None:
            filename, raw_file = normalized_tool_path(raw_path, context, sources)
        else:
            filename, raw_file = _normalize_slashes(raw_path) or "<unknown>", raw_path
        cwe = error.get("cwe")
        extra = {"original_severity": severity}
        if error.get("verbose") and error.get("verbose") != message:
            extra["verbose"] = error.get("verbose")
        if error.get("inconclusive"):
            extra["inconclusive"] = error.get("inconclusive")
        if raw_file and raw_file != filename:
            extra["raw_file_path"] = raw_file
        findings.append(make_finding(
            finding_id=make_id(), tool="cppcheck", file=filename, line=line,
            severity=Severity.UNKNOWN, category=severity, message=message,
            rule_id=rule, cwe=cwe, raw_evidence=raw_evidence, metadata=extra,
        ))
    return tuple(findings)


_GCC_DIAGNOSTIC = re.compile(r"^(.*?):(\d+):(\d+):\s*(fatal error|error|warning|note):\s*(.*)$")
_GCC_DIAGNOSTIC_NO_COLUMN = re.compile(r"^(.*?):(\d+):\s*(fatal error|error|warning|note):\s*(.*)$")


def parse_compiler_diagnostics(output: str, *, context: AnalysisContext | None = None,
                               sources: Sequence[SourceFile] = (), tool: str = "compiler",
                               raw_evidence: str | None = None, id_factory: IdFactory | None = None) -> tuple[Finding, ...]:
    make_id = id_factory or _uuid
    findings: list[Finding] = []
    for line_text in output.splitlines():
        match = _GCC_DIAGNOSTIC.match(line_text) or _GCC_DIAGNOSTIC_NO_COLUMN.match(line_text)
        if not match:
            continue
        if len(match.groups()) == 5:
            raw_path, line_num, column, severity, message = match.groups()
        else:
            raw_path, line_num, severity, message = match.groups()
            column = None
        if context is not None:
            filename, raw_file = normalized_tool_path(raw_path, context, sources)
        else:
            filename, raw_file = _normalize_slashes(raw_path), raw_path
        findings.append(make_finding(
            finding_id=make_id(), tool=tool, file=filename or "<unknown>", line=int(line_num),
            column=int(column) if column else None, severity=Severity.UNKNOWN,
            category=severity, message=message, raw_evidence=raw_evidence,
            metadata={"original_severity": severity, **({"raw_file_path": raw_file} if raw_file != filename else {})},
        ))
    return tuple(findings)


_TIDY_DIAGNOSTIC = re.compile(r"^(.*?):(\d+):(\d+):\s*(warning|error|note):\s*(.*?)(?:\s+\[([^\]]+)\])?$")


def parse_clang_tidy_diagnostics(output: str, *, context: AnalysisContext | None = None,
                                 sources: Sequence[SourceFile] = (), raw_evidence: str | None = None,
                                 id_factory: IdFactory | None = None,
                                 tool: str = "clang-tidy") -> tuple[Finding, ...]:
    make_id = id_factory or _uuid
    findings: list[Finding] = []
    for line_text in output.splitlines():
        match = _TIDY_DIAGNOSTIC.match(line_text)
        if not match:
            continue
        raw_path, line_num, column, category, message, rule = match.groups()
        if context is not None:
            filename, raw_file = normalized_tool_path(raw_path, context, sources)
        else:
            filename, raw_file = _normalize_slashes(raw_path), raw_path
        findings.append(make_finding(
            finding_id=make_id(), tool=tool, file=filename or "<unknown>", line=int(line_num),
            column=int(column), severity=Severity.UNKNOWN, category=category, message=message,
            rule_id=rule, raw_evidence=raw_evidence,
            metadata={"original_severity": category, **({"raw_file_path": raw_file} if raw_file != filename else {})},
        ))
    return tuple(findings)


def _positive_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        number = int(value)
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


def _normalize_slashes(value: str | None) -> str | None:
    return value.replace("\\", "/") if value else None


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())
