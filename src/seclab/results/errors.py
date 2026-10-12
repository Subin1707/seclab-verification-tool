"""Result contract errors."""

from enum import StrEnum


class ResultErrorCode(StrEnum):
    DUPLICATE_RESULT_ID = "DUPLICATE_RESULT_ID"
    INVALID_RESULT = "INVALID_RESULT"
    RESULT_SERIALIZATION_ERROR = "RESULT_SERIALIZATION_ERROR"


class ResultError(Exception):
    category = "RESULT_ERROR"

    def __init__(self, code: ResultErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
