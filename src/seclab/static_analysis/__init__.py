"""Static analysis runners and normalized finding models."""

from .analyzer import AnalysisContext, AnalysisResult, StaticAnalyzer
from .clang_runner import ClangStaticAnalyzerRunner, ClangTidyRunner
from .compiler_runner import CompilerDiagnosticsRunner, CompilerRunner
from .cppcheck_runner import CppcheckRunner
from .cwe_mapper import CWEMapper, CWEMapping
from .finding import Finding, Severity, make_finding
from .parsers import parse_clang_tidy_diagnostics, parse_compiler_diagnostics, parse_cppcheck_xml

__all__ = ["AnalysisContext", "AnalysisResult", "ClangStaticAnalyzerRunner", "ClangTidyRunner",
           "CompilerDiagnosticsRunner", "CompilerRunner", "CppcheckRunner", "CWEMapper", "CWEMapping",
           "Finding", "Severity", "StaticAnalyzer", "make_finding", "parse_clang_tidy_diagnostics",
           "parse_compiler_diagnostics", "parse_cppcheck_xml"]
