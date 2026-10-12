"""Structured specification and loader errors."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path


class SpecificationErrorCode(StrEnum):
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    INVALID_JSON = "INVALID_JSON"
    FILE_READ_ERROR = "FILE_READ_ERROR"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    INVALID_DOMAIN = "INVALID_DOMAIN"
    DUPLICATE_ID = "DUPLICATE_ID"
    DUPLICATE_NAME = "DUPLICATE_NAME"
    UNKNOWN_REFERENCE = "UNKNOWN_REFERENCE"
    UNKNOWN_INITIAL_STATE = "UNKNOWN_INITIAL_STATE"
    MISSING_INITIAL_STATE = "MISSING_INITIAL_STATE"
    MULTIPLE_INITIAL_STATES = "MULTIPLE_INITIAL_STATES"
    UNKNOWN_ATOM = "UNKNOWN_ATOM"
    INVALID_CTL_FORMULA = "INVALID_CTL_FORMULA"
    CONFLICTING_DEFINITION = "CONFLICTING_DEFINITION"
    VALIDATOR_UNAVAILABLE = "VALIDATOR_UNAVAILABLE"
    LEGACY_MIGRATION_FAILED = "LEGACY_MIGRATION_FAILED"


class SpecificationError(Exception):
    """A specification input error; never a verification FAIL result."""

    category = "SPEC_ERROR"

    def __init__(
        self,
        code: SpecificationErrorCode,
        message: str,
        *,
        source: Path | None = None,
        location: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.source = source
        self.location = location
        details = f"{code}: {message}"
        if source is not None:
            details += f" [{source}]"
        if location:
            details += f" at {location}"
        super().__init__(details)


class SpecificationToolError(Exception):
    """A core dependency/configuration problem that prevents validation."""

    category = "TOOL_ERROR"

    def __init__(self, code: SpecificationErrorCode, message: str, *, source: Path | None = None) -> None:
        self.code = code
        self.message = message
        self.source = source
        details = f"{code}: {message}"
        if source is not None:
            details += f" [{source}]"
        super().__init__(details)
