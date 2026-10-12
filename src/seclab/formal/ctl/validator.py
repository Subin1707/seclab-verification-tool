"""CTL atom validation against an explicit Kripke labeling vocabulary."""

from __future__ import annotations

from collections.abc import Iterable

from seclab.model.kripke import KripkeStructure

from .ast import CTLFormula, atomic_propositions
from .errors import CTLError, CTLErrorCode


def validate_ctl_formula(
    formula: CTLFormula,
    model_or_atoms: KripkeStructure | Iterable[str],
) -> None:
    """Raise UNKNOWN_ATOM for propositions absent from explicit labels."""
    if isinstance(model_or_atoms, KripkeStructure):
        vocabulary = frozenset(
            label
            for state in model_or_atoms.states
            for label in model_or_atoms.labels(state)
        )
    else:
        vocabulary = frozenset(model_or_atoms)
    unknown = sorted(atomic_propositions(formula) - vocabulary)
    if unknown:
        atom = unknown[0]
        raise CTLError(
            CTLErrorCode.UNKNOWN_ATOM,
            f"Atomic proposition '{atom}' is not present in the labeling vocabulary.",
            token=atom,
        )
