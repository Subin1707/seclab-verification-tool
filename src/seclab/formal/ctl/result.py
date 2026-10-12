"""Structured CTL model-checking result and evidence paths."""

from __future__ import annotations

from dataclasses import dataclass, field

from seclab.model.state import State
from seclab.model.kripke import KripkeStructure

from .ast import CTLFormula


@dataclass(frozen=True, slots=True)
class CTLCheckResult:
    formula: CTLFormula
    formula_text: str | None
    satisfied: bool
    satisfying_states: frozenset[State]
    initial_states: tuple[State, ...]
    witness: tuple[State, ...] | None = None
    counterexample: tuple[State, ...] | None = None
    counterexample_validated: bool = False
    model: KripkeStructure | None = field(default=None, repr=False, compare=False)

    @property
    def initial_satisfied(self) -> bool:
        """Whether every initial state satisfies the formula."""
        return self.satisfied
