"""Structured SMT input and solving errors."""

from __future__ import annotations

from enum import StrEnum


class SMTErrorCode(StrEnum):
    CONSTRAINT_SYNTAX_ERROR = "CONSTRAINT_SYNTAX_ERROR"
    UNKNOWN_VARIABLE = "UNKNOWN_VARIABLE"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    UNSUPPORTED_DOMAIN_TYPE = "UNSUPPORTED_DOMAIN_TYPE"
    UNSUPPORTED_OPERATOR = "UNSUPPORTED_OPERATOR"
    PROPERTY_NOT_BOOLEAN = "PROPERTY_NOT_BOOLEAN"
    SMT_ENCODING_ERROR = "SMT_ENCODING_ERROR"
    SOLVER_NOT_FOUND = "SOLVER_NOT_FOUND"
    SOLVER_TIMEOUT = "SOLVER_TIMEOUT"
    SOLVER_UNKNOWN = "SOLVER_UNKNOWN"
    SOLVER_ERROR = "SOLVER_ERROR"


class SMTError(Exception):
    """An invalid expression/domain or solver infrastructure error."""

    category = "SMT_ERROR"

    def __init__(self, code: SMTErrorCode, message: str, *, position: int | None = None) -> None:
        self.code = SMTErrorCode(code)
        self.message = message
        self.position = position
        suffix = f" at position {position}" if position is not None else ""
        super().__init__(f"{self.code.value}: {message}{suffix}")
