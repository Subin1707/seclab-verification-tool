"""Deterministic collection, filtering and status aggregation."""

from __future__ import annotations

from collections.abc import Iterable

from .errors import ResultError, ResultErrorCode
from .result import VerificationResult
from .status import VerificationStatus


class ResultCollector:
    def __init__(self) -> None:
        self._results: dict[str, VerificationResult] = {}

    def add(self, result: VerificationResult) -> None:
        if result.id in self._results:
            raise ResultError(ResultErrorCode.DUPLICATE_RESULT_ID, f"Result ID '{result.id}' already exists.")
        self._results[result.id] = result

    def extend(self, results: Iterable[VerificationResult]) -> None:
        batch = tuple(results)
        batch_ids = [result.id for result in batch]
        if len(set(batch_ids)) != len(batch_ids):
            duplicate = next(result_id for index, result_id in enumerate(batch_ids) if result_id in batch_ids[:index])
            raise ResultError(ResultErrorCode.DUPLICATE_RESULT_ID, f"Result ID '{duplicate}' occurs more than once.")
        duplicate_existing = next((item for item in batch_ids if item in self._results), None)
        if duplicate_existing is not None:
            raise ResultError(
                ResultErrorCode.DUPLICATE_RESULT_ID,
                f"Result ID '{duplicate_existing}' already exists.",
            )
        for result in batch:
            self._results[result.id] = result

    def all(self) -> tuple[VerificationResult, ...]:
        return tuple(self._results.values())

    def by_status(self, status: VerificationStatus) -> tuple[VerificationResult, ...]:
        selected = VerificationStatus(status)
        return tuple(result for result in self._results.values() if result.status is selected)

    def by_stage(self, stage: str) -> tuple[VerificationResult, ...]:
        return tuple(result for result in self._results.values() if result.stage == stage)

    def by_requirement(self, requirement_id: str) -> tuple[VerificationResult, ...]:
        return tuple(result for result in self._results.values() if result.requirement_id == requirement_id)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in VerificationStatus}
        for result in self._results.values():
            counts[result.status.value] += 1
        return {"total": len(self._results), **counts}
