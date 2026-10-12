"""Deterministic hash-deduplicated fuzz corpus."""
from __future__ import annotations

from .models import CorpusEntry, FuzzInput


class Corpus:
    def __init__(self, seeds: tuple[FuzzInput, ...] | list[FuzzInput] = ()) -> None:
        self._entries: dict[str, CorpusEntry] = {}
        for item in seeds:
            self.add(item, retention_reason="seed")

    def add(self, item: FuzzInput, *, coverage_signature: tuple[str, ...] = (),
            discovered_at_iteration: int = 0, parent_id: str | None = None,
            retention_reason: str = "interesting", failure_signature=None) -> bool:
        digest = item.content_hash
        if digest in self._entries:
            return False
        self._entries[digest] = CorpusEntry(item, tuple(sorted(set(coverage_signature))), discovered_at_iteration,
                                            parent_id or item.parent_id, retention_reason, failure_signature)
        return True

    @property
    def entries(self) -> tuple[CorpusEntry, ...]:
        return tuple(sorted(self._entries.values(), key=lambda entry: (
            entry.discovered_at_iteration, entry.input.content_hash, entry.input.id)))

    @property
    def inputs(self) -> tuple[FuzzInput, ...]:
        return tuple(entry.input for entry in self.entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.entries)
