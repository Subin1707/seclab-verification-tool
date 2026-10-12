"""A directed state-machine edge; guard and action remain uninterpreted text."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, eq=False)
class Transition:
    source: str
    target: str
    label: str | None = None
    guard: str | None = None
    action: str | None = None
    id: str | None = None
    guard_status: str = "UNSPECIFIED"

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.source,
            self.target,
            _optional_key(self.id),
            _optional_key(self.label),
            _optional_key(self.guard),
            _optional_key(self.action),
            self.guard_status,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Transition):
            return NotImplemented
        return self.sort_key() == other.sort_key()

    def __hash__(self) -> int:
        encoded = json.dumps(self.sort_key(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        digest = hashlib.blake2b(encoded, digest_size=8).digest()
        value = int.from_bytes(digest, byteorder="big", signed=True)
        return -2 if value == -1 else value


def _optional_key(value: str | None) -> tuple[bool, str]:
    return value is not None, value or ""
