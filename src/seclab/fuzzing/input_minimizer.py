"""Bounded delta-debugging reducer that accepts only the same failure signature."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import FailureSignature, FuzzInput, InputKind


@dataclass(frozen=True, slots=True)
class MinimizationResult:
    input: FuzzInput
    executions: int
    minimized: bool
    error: str | None = None


class InputMinimizer:
    def minimize(self, original: FuzzInput, expected: FailureSignature,
                 check: Callable[[FuzzInput], FailureSignature | None], *, max_executions: int = 64,
                 should_stop: Callable[[], bool] | None = None) -> MinimizationResult:
        if max_executions <= 0:
            return MinimizationResult(original, 0, False, "INPUT_MINIMIZATION_FAILED: execution budget is zero")
        if original.kind is InputKind.BYTES:
            current = original.data
        elif original.kind is InputKind.TEXT:
            current = original.data
        else:
            return MinimizationResult(original, 0, False, "structured scalar minimization is unsupported")
        attempts, changed = 0, False
        granularity = 2
        while current and attempts < max_executions:
            if should_stop is not None and should_stop():
                return MinimizationResult(original, attempts, False, "TIME_BUDGET_EXHAUSTED")
            chunk = max(1, (len(current) + granularity - 1) // granularity)
            reduced = False
            for start in range(0, len(current), chunk):
                if should_stop is not None and should_stop():
                    return MinimizationResult(original, attempts, False, "TIME_BUDGET_EXHAUSTED")
                candidate_data = current[:start] + current[start + chunk:]
                candidate = FuzzInput(f"{original.id}-min-{attempts:04d}", candidate_data, original.kind,
                                      original.origin, original.parent_id, original.generation,
                                      {**dict(original.metadata), "minimizing": True})
                attempts += 1
                try:
                    signature = check(candidate)
                except Exception as exc:
                    return MinimizationResult(original, attempts, False, f"INPUT_MINIMIZATION_FAILED: {type(exc).__name__}")
                if signature == expected:
                    current, changed, granularity = candidate_data, True, max(2, granularity - 1)
                    reduced = True
                    break
                if attempts >= max_executions:
                    break
            if not reduced:
                if granularity >= len(current):
                    break
                granularity = min(len(current), granularity * 2)
        if not changed:
            return MinimizationResult(original, attempts, False)
        minimized = FuzzInput(f"{original.id}-minimized", current, original.kind, original.origin,
                              original.parent_id, original.generation, {**dict(original.metadata), "minimized": True})
        return MinimizationResult(minimized, attempts, True)
