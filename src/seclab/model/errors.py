"""Model construction and invariant errors."""

from __future__ import annotations

from enum import StrEnum


class ModelErrorCode(StrEnum):
    INVALID_STATE = "INVALID_STATE"
    DUPLICATE_STATE_ID = "DUPLICATE_STATE_ID"
    DUPLICATE_TRANSITION_ID = "DUPLICATE_TRANSITION_ID"
    UNKNOWN_STATE = "UNKNOWN_STATE"
    INVALID_INITIAL_STATE = "INVALID_INITIAL_STATE"
    MISSING_INITIAL_STATE = "MISSING_INITIAL_STATE"
    MULTIPLE_INITIAL_STATES = "MULTIPLE_INITIAL_STATES"
    INVALID_TRANSITION = "INVALID_TRANSITION"
    STATE_LIMIT_EXCEEDED = "STATE_LIMIT_EXCEEDED"
    MODEL_INVARIANT_ERROR = "MODEL_INVARIANT_ERROR"
    INVALID_GUARD = "INVALID_GUARD"
    INVALID_ACTION = "INVALID_ACTION"


class ModelError(Exception):
    """A model construction problem, distinct from a property violation."""

    category = "MODEL_ERROR"

    def __init__(self, code: ModelErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
