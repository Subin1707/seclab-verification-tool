"""Structured test and harness input errors."""

from __future__ import annotations

from enum import StrEnum


class TestErrorCode(StrEnum):
    INVALID_TEST_CASE = "INVALID_TEST_CASE"
    UNSUPPORTED_EXPECTATION = "UNSUPPORTED_EXPECTATION"
    HARNESS_UNSUPPORTED_SIGNATURE = "HARNESS_UNSUPPORTED_SIGNATURE"
    HARNESS_UNSUPPORTED_INPUT = "HARNESS_UNSUPPORTED_INPUT"
    HARNESS_GENERATION_ERROR = "HARNESS_GENERATION_ERROR"
    HARNESS_PATH_CONFLICT = "HARNESS_PATH_CONFLICT"
    OBSERVATION_PARSE_ERROR = "OBSERVATION_PARSE_ERROR"


class TestError(Exception):
    category = "TEST_INPUT_ERROR"

    def __init__(self, code: TestErrorCode, message: str) -> None:
        self.code = TestErrorCode(code)
        self.message = message
        super().__init__(f"{self.code.value}: {message}")
