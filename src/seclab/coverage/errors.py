"""Coverage measurement errors, distinct from SUT property failures."""

from enum import StrEnum


class CoverageErrorCode(StrEnum):
    COVERAGE_TOOL_NOT_FOUND = "COVERAGE_TOOL_NOT_FOUND"
    COVERAGE_BUILD_FAILED = "COVERAGE_BUILD_FAILED"
    COVERAGE_EXECUTION_FAILED = "COVERAGE_EXECUTION_FAILED"
    COVERAGE_DATA_MISSING = "COVERAGE_DATA_MISSING"
    COVERAGE_PARSE_ERROR = "COVERAGE_PARSE_ERROR"
    COVERAGE_UNSUPPORTED_BACKEND = "COVERAGE_UNSUPPORTED_BACKEND"
    COVERAGE_PARTIAL = "COVERAGE_PARTIAL"


class CoverageError(Exception):
    def __init__(self, code: CoverageErrorCode, message: str) -> None:
        self.code = CoverageErrorCode(code)
        self.message = message
        super().__init__(f"{self.code.value}: {message}")
