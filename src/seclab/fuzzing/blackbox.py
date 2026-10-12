"""Black-box random input generation without code or coverage inspection."""
from __future__ import annotations

import random
import string

from .models import FuzzInput, InputKind, InputOrigin


class BlackBoxFuzzer:
    def __init__(self, rng: random.Random, *, max_input_size: int, alphabet: str | None = None,
                 scalar_names: tuple[str, ...] = ()) -> None:
        self.rng, self.max_input_size = rng, max_input_size
        self.alphabet = alphabet or (string.ascii_letters + string.digits + " \t\n")
        self.scalar_names = tuple(sorted(scalar_names))

    def generate(self, iteration: int) -> FuzzInput:
        kind = self.rng.choice((InputKind.BYTES, InputKind.TEXT, InputKind.SCALARS))
        if kind is InputKind.BYTES:
            size = self.rng.randint(0, self.max_input_size)
            data = bytes(self.rng.getrandbits(8) for _ in range(size))
        elif kind is InputKind.TEXT:
            size = self.rng.randint(0, min(self.max_input_size, 256))
            data = "".join(self.rng.choice(self.alphabet) for _ in range(size))
        else:
            value = self.rng.choice((0, 1, -1, self.rng.randint(-1000, 1000), True, False))
            data = {name: value for name in self.scalar_names} if self.scalar_names else value
        return FuzzInput(f"blackbox-{iteration:08d}", data, kind, InputOrigin.BLACKBOX,
                         metadata={"generator": "black-box-random"})
