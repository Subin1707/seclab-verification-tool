"""Structured input and trace errors for bounded model checking."""

from __future__ import annotations

from enum import StrEnum


class BMCErrorCode(StrEnum):
    INVALID_BMC_BOUND = "INVALID_BMC_BOUND"
    EMPTY_MODEL = "EMPTY_MODEL"
    NO_INITIAL_STATE = "NO_INITIAL_STATE"
    UNKNOWN_PROPOSITION = "UNKNOWN_PROPOSITION"
    INVALID_TRACE = "INVALID_TRACE"
    SOLVER_MODEL_MISSING = "SOLVER_MODEL_MISSING"


class BMCError(Exception):
    category = "BMC_INPUT_ERROR"

    def __init__(self, code: BMCErrorCode, message: str) -> None:
        self.code = BMCErrorCode(code)
        self.message = message
        super().__init__(f"{self.code.value}: {message}")
