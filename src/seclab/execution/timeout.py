"""Timeout normalization helpers."""

from __future__ import annotations

import math

from .errors import ExecutionError, ExecutionErrorCode


def validate_timeout(timeout: float | None) -> float | None:
    if timeout is None:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "timeout must be a finite positive number of seconds.")
    return float(timeout)
