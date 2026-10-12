from __future__ import annotations

import json
from pathlib import Path

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore
from seclab.execution import CommandRunner
from seclab.source import SourceLoader
from seclab.static_analysis import (
    AnalysisContext, AnalysisResult, CWEMapper, Finding, Severity, make_finding,
    parse_clang_tidy_diagnostics, parse_compiler_diagnostics, parse_cppcheck_xml,
)
from seclab.results import VerificationStatus


def context(tmp_path: Path) -> AnalysisContext:
    root = tmp_path / "sut source"
    root.mkdir(exist_ok=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return AnalysisContext(root, workspace, Toolchain([]), CommandRunner(), ArtifactStore(workspace))


def test_finding_serialization_and_severity_preserve_original_category() -> None:
    finding = make_finding(tool="cppcheck", file="src/a.c", line=7, column=3,
                           severity="warning", category="warning", message="possible issue",
                           rule_id="known-rule", cwe="476", finding_id="f1")
    assert finding.severity is Severity.UNKNOWN
    assert finding.category == "warning"
    assert finding.metadata["original_severity"] == "warning"
    assert Finding.from_dict(json.loads(finding.to_json())) == finding
    assert finding.cwe == "CWE-476"


def test_finding_canonical_severities_are_retained() -> None:
    finding = make_finding(tool="x", file="a.c", line=None, severity="HIGH", category="security",
                           message="reported", finding_id="high")
    assert finding.severity is Severity.HIGH
    assert finding.line is None


def test_cppcheck_xml_parser_handles_multiple_locations_cwe_and_missing_location(tmp_path: Path) -> None:
    ctx = context(tmp_path)
    sources = (tmp_path / "sut source" / "one.c")
    sources.write_text("int x;\n", encoding="utf-8")
    collection = SourceLoader().load_source_tree(ctx.source_root)
    xml = '''<?xml version="1.0"?>
<results><errors>
 <error id="nullPointer" severity="warning" msg="possible null dereference" cwe="476">
  <location file="one.c" line="1" column="3"/>
 </error>
 <error id="styleIssue" severity="style" msg="style report"/>
</errors></results>'''
    findings = parse_cppcheck_xml(xml, context=ctx, sources=collection, id_factory=iter(("a", "b")).__next__)
    assert len(findings) == 2
    assert findings[0].file == "one.c" and findings[0].line == 1
    assert findings[0].cwe == "CWE-476"
    assert findings[1].file == "<unknown>" and findings[1].line is None
    assert parse_cppcheck_xml("<broken") == ()
    assert parse_cppcheck_xml("") == ()


def test_compiler_diagnostic_parser_handles_drive_colons_spaces_and_unknown_lines(tmp_path: Path) -> None:
    ctx = context(tmp_path)
    output = """C:\\Users\\A User\\project\\main file.c:12:4: warning: unused value [-Wunused-value]
this line is not a compiler diagnostic
/workspace/src/a.c:3: error: bad token
"""
    findings = parse_compiler_diagnostics(output, context=ctx, tool="gcc",
                                          id_factory=iter(("w", "e")).__next__)
    assert len(findings) == 2
    assert findings[0].line == 12 and findings[0].column == 4
    assert findings[0].file == "C:/Users/A User/project/main file.c"
    assert findings[0].category == "warning"
    assert findings[1].line == 3 and findings[1].column is None


def test_clang_tidy_parser_keeps_rule_and_normalizes_windows_path() -> None:
    output = r"C:\work tree\source.c:8:5: warning: dereference of null pointer [clang-analyzer-core.NullDereference]"
    findings = parse_clang_tidy_diagnostics(output, id_factory=lambda: "tidy")
    assert len(findings) == 1
    assert findings[0].file == "C:/work tree/source.c"
    assert findings[0].rule_id == "clang-analyzer-core.NullDereference"
    assert CWEMapper().apply(findings[0]).cwe == "CWE-476"


def test_cwe_mapping_is_conservative_and_keeps_direct_tool_cwe() -> None:
    mapper = CWEMapper()
    direct = make_finding(tool="cppcheck", file="a.c", line=1, severity="warning", category="warning",
                          message="nonsensical", cwe="476", finding_id="direct")
    vague = make_finding(tool="cppcheck", file="a.c", line=1, severity="warning", category="warning",
                         message="memory problem might happen", finding_id="vague")
    mapped = make_finding(tool="clang-tidy", file="a.c", line=1, severity="warning", category="warning",
                          message="null dereference", rule_id="clang-analyzer-core.NullDereference", finding_id="rule")
    assert mapper.map(direct).source == "tool"
    assert mapper.map(vague) is None
    assert mapper.apply(vague).cwe is None
    assert mapper.apply(mapped).cwe == "CWE-476"


def test_static_analysis_result_never_claims_global_pass_or_failure() -> None:
    clean = AnalysisResult("cppcheck", True, successful=True, reason_code="NO_STATIC_FINDINGS",
                           scope="cppcheck configuration X only")
    reported = AnalysisResult("cppcheck", True,
                              findings=(make_finding(tool="cppcheck", file="a.c", line=1, severity="warning",
                                                     category="warning", message="report", finding_id="f"),),
                              successful=True, reason_code="STATIC_FINDINGS_DETECTED")
    assert clean.to_verification_result().status is VerificationStatus.INCONCLUSIVE
    assert reported.to_verification_result().status is VerificationStatus.INCONCLUSIVE
    assert clean.to_verification_result().reason_code == "NO_STATIC_FINDINGS"
    assert reported.to_verification_result().reason_code == "STATIC_FINDINGS_DETECTED"


def test_missing_static_tool_is_inconclusive_and_explicitly_environment_limited() -> None:
    missing = AnalysisResult("cppcheck", False, successful=False, reason_code="CPPCHECK_NOT_FOUND",
                             limitations=("cppcheck is not installed",))
    result = missing.to_verification_result()
    assert result.status is VerificationStatus.INCONCLUSIVE
    assert result.reason_code == "CPPCHECK_NOT_FOUND"
    assert result.metadata["capability_status"] == "ENVIRONMENT_LIMITED"


def test_clang_static_rule_mapping_is_conservative() -> None:
    specific = make_finding(tool="clang-static-analyzer", file="a.c", line=2, severity="warning",
                            category="warning", message="null dereference",
                            rule_id="core.NullDereference", finding_id="null")
    unknown = make_finding(tool="clang-static-analyzer", file="a.c", line=3, severity="warning",
                           category="warning", message="unknown report", rule_id="unknown.Check",
                           finding_id="unknown")
    assert CWEMapper().apply(specific).cwe == "CWE-476"
    assert CWEMapper().apply(unknown).cwe is None
