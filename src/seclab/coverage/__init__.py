"""Coverage measurement core; reports are not property verification results."""

from .backend import BackendCollection, CoverageBackend
from .coverage_report import (BranchCoverage, CoverageDelta, CoverageReport, CoverageSnapshot,
                              FileBranchCoverage, FileFunctionCoverage, FileLineCoverage, FunctionCoverage,
                              LineCoverage, aggregate_branch_coverage, aggregate_function_coverage,
                              aggregate_line_coverage)
from .coverage_runner import CoverageRunResult, CoverageRunner
from .errors import CoverageError, CoverageErrorCode
from .gcov_backend import GcovBackend
from .llvm_backend import LlvmCovBackend
from .parser import ParsedCoverage, parse_gcov_function_summary, parse_gcov_json, parse_gcov_text, parse_llvm_export

__all__ = [
    "BackendCollection", "BranchCoverage", "CoverageBackend", "CoverageDelta", "CoverageError",
    "CoverageErrorCode", "CoverageReport", "CoverageRunResult", "CoverageRunner", "CoverageSnapshot",
    "FileBranchCoverage", "FileFunctionCoverage", "FileLineCoverage", "FunctionCoverage", "GcovBackend",
    "LineCoverage", "LlvmCovBackend", "ParsedCoverage", "aggregate_branch_coverage",
    "aggregate_function_coverage", "aggregate_line_coverage", "parse_gcov_function_summary",
    "parse_gcov_json", "parse_gcov_text", "parse_llvm_export",
]
