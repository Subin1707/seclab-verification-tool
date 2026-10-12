"""Controlled command and build execution errors."""

from enum import StrEnum


class ExecutionErrorCode(StrEnum):
    EXECUTABLE_NOT_FOUND = "EXECUTABLE_NOT_FOUND"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    COMMAND_EXECUTION_ERROR = "COMMAND_EXECUTION_ERROR"
    COMPILER_NOT_FOUND = "COMPILER_NOT_FOUND"
    COMPILATION_FAILED = "COMPILATION_FAILED"
    INVALID_OUTPUT_PATH = "INVALID_OUTPUT_PATH"


class ExecutionError(Exception):
    category = "EXECUTION_ERROR"

    def __init__(self, code: ExecutionErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
