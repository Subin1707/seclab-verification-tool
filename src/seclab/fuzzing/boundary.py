"""Bounded black-box boundary values derived from declared input domains."""
from __future__ import annotations

from typing import Iterable

from seclab.specification.schema import Domain, Specification

from .models import FuzzInput, InputKind, InputOrigin


def boundary_values(domain: Domain) -> tuple[object, ...]:
    candidates: list[object] = []
    if domain.values:
        candidates.extend(domain.values)
    elif domain.type == "boolean":
        candidates.extend((False, True))
    elif domain.type in {"integer", "number"}:
        lo, hi = domain.minimum, domain.maximum
        if lo is not None:
            candidates.extend((lo - 1, lo, lo + 1))
        candidates.append(0 if lo is None or lo <= 0 <= (hi if hi is not None else 0) else lo)
        if hi is not None:
            candidates.extend((hi - 1, hi, hi + 1))
    elif domain.type == "string":
        candidates.extend(("", "a", "A" * 8, "\x00", "'\"\\"))
    unique: list[object] = []
    seen: set[str] = set()
    for value in candidates:
        key = repr((type(value).__name__, value))
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return tuple(unique)


class BoundaryGenerator:
    def __init__(self, specification: Specification, *, max_input_size: int = 4096) -> None:
        self.specification, self.max_input_size = specification, max_input_size

    def generate(self) -> tuple[FuzzInput, ...]:
        inputs: list[FuzzInput] = []
        for variable in sorted(self.specification.variables, key=lambda item: item.id):
            for index, value in enumerate(boundary_values(variable.domain)):
                item = FuzzInput(f"boundary-{variable.id}-{index:04d}", {variable.id: value}, InputKind.SCALARS,
                                 InputOrigin.BOUNDARY, metadata={"variable": variable.id, "boundary_index": index})
                if item.size <= self.max_input_size:
                    inputs.append(item)
        return tuple(inputs)

    def __iter__(self) -> Iterable[FuzzInput]:
        return iter(self.generate())
