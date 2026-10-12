"""Bounded grammar expansion for structured fuzz inputs."""
from __future__ import annotations

import json
import random
import re
from collections.abc import Mapping
from typing import Any

from .models import FuzzInput, InputKind, InputOrigin

_SYMBOL = re.compile(r"<[^<>]+>")


class GrammarFuzzer:
    """Expand a JSON mapping of nonterminal names to alternative strings.

    Recursive grammars are bounded by depth and output bytes. A generated JSON
    object becomes SCALARS for function targets; other outputs remain TEXT.
    """

    def __init__(self, rng: random.Random, start: str, rules: Mapping[str, Any], *,
                 max_input_size: int, max_depth: int = 16) -> None:
        self.rng, self.start, self.rules = rng, start, dict(rules)
        self.max_input_size, self.max_depth = max_input_size, max_depth
        if start not in self.rules:
            raise ValueError(f"grammar start rule {start!r} is missing")
        for name, alternatives in self.rules.items():
            if not isinstance(name, str) or not _SYMBOL.fullmatch(name):
                raise ValueError(f"invalid grammar rule name: {name!r}")
            if isinstance(alternatives, str):
                alternatives = [alternatives]
            if not isinstance(alternatives, (list, tuple)) or not alternatives or any(not isinstance(x, str) for x in alternatives):
                raise ValueError(f"grammar rule {name!r} must contain one or more string alternatives")
            self.rules[name] = tuple(alternatives)
        referenced = {symbol for value in self.rules.values() for text in value for symbol in _SYMBOL.findall(text)}
        unknown = referenced - self.rules.keys()
        if unknown:
            raise ValueError("undefined grammar rule(s): " + ", ".join(sorted(unknown)))

    def generate(self, iteration: int, *, structured: bool = False,
                 required_fields: tuple[str, ...] = ()) -> FuzzInput:
        text = self._expand(self.start, 0)
        if len(text.encode("utf-8")) > self.max_input_size:
            raise ValueError("grammar output exceeds max_input_size")
        kind, data = InputKind.TEXT, text
        if structured:
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"function grammar output must be valid JSON: {exc.msg}") from exc
            if not isinstance(value, dict):
                raise ValueError("function grammar output must be a JSON object keyed by function input names")
            missing = set(required_fields) - value.keys()
            if missing:
                raise ValueError("function grammar is missing input field(s): " + ", ".join(sorted(missing)))
            kind, data = InputKind.SCALARS, value
        return FuzzInput(f"grammar-{iteration:08d}", data, kind, InputOrigin.GRAMMAR,
                         metadata={"generator": "grammar", "start": self.start})

    def _expand(self, symbol: str, depth: int) -> str:
        if depth >= self.max_depth:
            alternatives = [item for item in self.rules[symbol] if not _SYMBOL.search(item)]
            if not alternatives:
                raise ValueError(f"recursive grammar exceeded maximum depth at {symbol}")
            return self.rng.choice(alternatives)
        choice = self.rng.choice(self.rules[symbol])
        output = _SYMBOL.sub(lambda match: self._expand(match.group(), depth + 1), choice)
        if len(output.encode("utf-8")) > self.max_input_size:
            raise ValueError("grammar expansion exceeds max_input_size")
        return output
