"""Immutable Kripke state with order-independent values and stable hashing."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from seclab.specification.schema import Scalar

from .errors import ModelError, ModelErrorCode


@dataclass(frozen=True, slots=True, eq=False, init=False)
class State:
    """A state identified by an ID, scalar valuation and AP label set."""

    id: str
    _value_items: tuple[tuple[str, Scalar], ...] = field(repr=False)
    labels: frozenset[str]

    def __init__(
        self,
        id: str,
        values: Mapping[str, Scalar] | None = None,
        labels: frozenset[str] | set[str] | tuple[str, ...] = frozenset(),
    ) -> None:
        if not isinstance(id, str) or not id:
            raise ModelError(ModelErrorCode.INVALID_STATE, "State ID must be a non-empty string.")
        normalized_values: list[tuple[str, Scalar]] = []
        for key, value in (values or {}).items():
            if not isinstance(key, str) or not key:
                raise ModelError(ModelErrorCode.INVALID_STATE, "State value names must be non-empty strings.")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ModelError(
                    ModelErrorCode.INVALID_STATE,
                    f"State value '{key}' must be a JSON scalar, got {type(value).__name__}.",
                )
            if isinstance(value, float) and not math.isfinite(value):
                raise ModelError(ModelErrorCode.INVALID_STATE, f"State value '{key}' must be finite.")
            normalized_values.append((key, value))
        normalized_labels = frozenset(labels)
        if any(not isinstance(label, str) or not label for label in normalized_labels):
            raise ModelError(ModelErrorCode.INVALID_STATE, "State labels must be non-empty strings.")
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "_value_items", tuple(sorted(normalized_values)))
        object.__setattr__(self, "labels", normalized_labels)

    @property
    def values(self) -> Mapping[str, Scalar]:
        """Read-only valuation mapping, returned in key-sorted order."""
        return MappingProxyType(dict(self._value_items))

    def _canonical(self) -> str:
        body = {
            "id": self.id,
            "values": [[key, _typed_scalar(value)] for key, value in self._value_items],
            "labels": sorted(self.labels),
        }
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, State):
            return NotImplemented
        return self._canonical() == other._canonical()

    def __hash__(self) -> int:
        digest = hashlib.blake2b(self._canonical().encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, byteorder="big", signed=True)
        return -2 if value == -1 else value

    def evaluate(self, proposition: str) -> bool:
        """Evaluate an atomic proposition using explicit labels only."""
        if not isinstance(proposition, str) or not proposition:
            raise ModelError(ModelErrorCode.INVALID_STATE, "Proposition name must be non-empty text.")
        return proposition in self.labels


def _typed_scalar(value: Scalar) -> list[str]:
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", "true" if value else "false"]
    if isinstance(value, int):
        return ["integer", str(value)]
    if isinstance(value, float):
        return ["number", value.hex()]
    return ["string", value]
