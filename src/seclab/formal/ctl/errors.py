"""Structured CTL syntax, semantic and model-checking errors."""

from __future__ import annotations

from enum import StrEnum


class CTLErrorCode(StrEnum):
    CTL_SYNTAX_ERROR = "CTL_SYNTAX_ERROR"
    UNKNOWN_ATOM = "UNKNOWN_ATOM"
    NO_INITIAL_STATE = "NO_INITIAL_STATE"
    MODEL_CHECK_ERROR = "MODEL_CHECK_ERROR"


class CTLError(Exception):
    """A formula input or CTL evaluation error, never a verification result."""

    category = "CTL_ERROR"

    def __init__(
        self,
        code: CTLErrorCode,
        message: str,
        *,
        position: int | None = None,
        token: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.position = position
        self.token = token
        self.line = line
        self.column = column
        details = f"{code}: {message}"
        if position is not None:
            details += f" (line {line}, column {column}, position {position})"
        if token is not None:
            details += f" [token {token!r}]"
        super().__init__(details)
