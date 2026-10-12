"""Duplicate-safe evidence collection and filtering."""

from collections.abc import Iterable

from .errors import EvidenceError, EvidenceErrorCode
from .evidence import Evidence, EvidenceType


class EvidenceCollector:
    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    def add(self, evidence: Evidence) -> None:
        if evidence.id in self._items:
            raise EvidenceError(EvidenceErrorCode.DUPLICATE_EVIDENCE_ID, f"Evidence ID '{evidence.id}' already exists.")
        self._items[evidence.id] = evidence

    def extend(self, items: Iterable[Evidence]) -> None:
        batch = tuple(items)
        ids = [item.id for item in batch]
        if len(ids) != len(set(ids)) or any(item_id in self._items for item_id in ids):
            raise EvidenceError(EvidenceErrorCode.DUPLICATE_EVIDENCE_ID, "Evidence batch contains a duplicate ID.")
        self._items.update((item.id, item) for item in batch)

    def all(self) -> tuple[Evidence, ...]:
        return tuple(self._items.values())

    def replace_all(self, items: Iterable[Evidence]) -> None:
        """Replace metadata-enriched records while preserving duplicate-ID checks."""
        batch = tuple(items)
        ids = [item.id for item in batch]
        if len(ids) != len(set(ids)):
            raise EvidenceError(EvidenceErrorCode.DUPLICATE_EVIDENCE_ID,
                                "Replacement evidence batch contains duplicate IDs.")
        if set(ids) != set(self._items):
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE,
                                "Replacement evidence IDs must match the collected evidence IDs.")
        self._items = {item.id: item for item in batch}

    def by_stage(self, stage: str) -> tuple[Evidence, ...]:
        return tuple(item for item in self._items.values() if item.stage == stage)

    def by_requirement(self, requirement_id: str) -> tuple[Evidence, ...]:
        return tuple(item for item in self._items.values() if item.requirement_id == requirement_id)

    def by_type(self, evidence_type: EvidenceType) -> tuple[Evidence, ...]:
        selected = EvidenceType(evidence_type)
        return tuple(item for item in self._items.values() if item.type is selected)
