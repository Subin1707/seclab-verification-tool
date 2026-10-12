"""Bounded input mutation operators (never program/source mutation)."""
from __future__ import annotations

import random
from dataclasses import replace
from typing import Any

from .models import FuzzInput, InputKind, InputOrigin


class InputMutator:
    def __init__(self, rng: random.Random, *, max_input_size: int, max_mutations_per_input: int = 8) -> None:
        self.rng, self.max_input_size, self.max_mutations_per_input = rng, max_input_size, max_mutations_per_input

    def mutate(self, parent: FuzzInput, iteration: int) -> FuzzInput:
        if parent.kind is InputKind.BYTES:
            data, operator = self._bytes(parent.data)
        elif parent.kind is InputKind.TEXT:
            data, operator = self._text(parent.data)
        else:
            data, operator = self._scalar(parent.data)
        child = replace(parent, id=f"mutation-{iteration:08d}", data=data, origin=InputOrigin.MUTATION,
                        parent_id=parent.id, generation=parent.generation + 1,
                        metadata={**dict(parent.metadata), "mutation_operator": operator})
        if child.size > self.max_input_size:
            return replace(parent, id=f"mutation-{iteration:08d}", origin=InputOrigin.MUTATION,
                           parent_id=parent.id, generation=parent.generation + 1,
                           metadata={**dict(parent.metadata), "mutation_operator": "size-cap-noop"})
        return child

    def _bytes(self, original: bytes) -> tuple[bytes, str]:
        data = bytearray(original)
        ops = ["bit-flip", "byte-flip", "insert-byte", "delete-byte", "duplicate-chunk", "replace-chunk"]
        op = self.rng.choice(ops)
        if op == "bit-flip" and data:
            i = self.rng.randrange(len(data)); data[i] ^= 1 << self.rng.randrange(8)
        elif op == "byte-flip" and data:
            data[self.rng.randrange(len(data))] ^= 0xFF
        elif op == "insert-byte" and len(data) < self.max_input_size:
            data.insert(self.rng.randrange(len(data) + 1), self.rng.randrange(256))
        elif op == "delete-byte" and data:
            del data[self.rng.randrange(len(data))]
        elif op == "duplicate-chunk" and data and len(data) < self.max_input_size:
            start = self.rng.randrange(len(data)); chunk = data[start:start + max(1, len(data) // 2)]
            data.extend(chunk[:self.max_input_size-len(data)])
        elif op == "replace-chunk" and data:
            data[self.rng.randrange(len(data))] = self.rng.randrange(256)
        else:
            op = "empty-safe-noop"
        return bytes(data[:self.max_input_size]), op

    def _text(self, original: str) -> tuple[str, str]:
        data = list(original)
        op = self.rng.choice(("insert-text", "delete-text", "replace-text", "duplicate-text"))
        if op == "insert-text" and len("".join(data).encode("utf-8")) < self.max_input_size:
            data.insert(self.rng.randrange(len(data) + 1), self.rng.choice("a0\n!"))
        elif op == "delete-text" and data:
            del data[self.rng.randrange(len(data))]
        elif op == "replace-text" and data:
            data[self.rng.randrange(len(data))] = self.rng.choice("a0\n!")
        elif op == "duplicate-text" and data:
            start = self.rng.randrange(len(data)); data.extend(data[start:start + max(1, len(data)//2)])
        else:
            op = "empty-safe-noop"
        output = "".join(data)
        while len(output.encode("utf-8")) > self.max_input_size:
            output = output[:-1]
        return output, op

    def _scalar(self, value: Any) -> tuple[Any, str]:
        op = self.rng.choice(("scalar-plus-minus-one", "scalar-boundary", "scalar-sign-change"))
        if isinstance(value, bool):
            return not value, "scalar-boundary"
        if isinstance(value, (int, float)):
            if op == "scalar-sign-change": return -value, op
            return value + self.rng.choice((-1, 1)), op
        if isinstance(value, str):
            return value + self.rng.choice(("", "0", "!")), "scalar-text-append"
        if isinstance(value, dict) and value:
            output = dict(value)
            key = sorted(output)[self.rng.randrange(len(output))]
            output[key], actual = self._scalar(output[key])
            return output, actual
        if isinstance(value, list) and value:
            output = list(value)
            index = self.rng.randrange(len(output))
            output[index], actual = self._scalar(output[index])
            return output, actual
        return {"value": 0}, "scalar-seed-value"
