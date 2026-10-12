"""Canonical semantic statuses shared by verification techniques."""

from enum import StrEnum


class VerificationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    TOOL_ERROR = "TOOL_ERROR"
    SPEC_ERROR = "SPEC_ERROR"
    BUILD_ERROR = "BUILD_ERROR"
