"""Source discovery and inspection errors."""

from enum import StrEnum


class SourceErrorCode(StrEnum):
    SOURCE_ROOT_NOT_FOUND = "SOURCE_ROOT_NOT_FOUND"
    SOURCE_ACCESS_ERROR = "SOURCE_ACCESS_ERROR"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"
    INVALID_SOURCE_PATH = "INVALID_SOURCE_PATH"


class SourceError(Exception):
    category = "SOURCE_ERROR"

    def __init__(self, code: SourceErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
