"""CTL parsing, semantic validation and finite-state model checking."""

from typing import Any

from .ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, CTLFormula,
    Implies, Not, Or, atomic_propositions,
)
from .errors import CTLError, CTLErrorCode
from .parser import parse_ctl


def __getattr__(name: str) -> Any:
    """Load model-dependent APIs lazily so spec parsing stays model-independent."""
    if name in {"check", "sat"}:
        from .model_checker import check, sat

        return {"check": check, "sat": sat}[name]
    if name == "CTLCheckResult":
        from .result import CTLCheckResult

        return CTLCheckResult
    if name == "validate_ctl_formula":
        from .validator import validate_ctl_formula

        return validate_ctl_formula
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "AF", "AG", "AX", "AU", "EF", "EG", "EU", "EX", "And", "Atom",
    "BoolConstant", "CTLCheckResult", "CTLError", "CTLErrorCode", "CTLFormula",
    "Implies", "Not", "Or", "atomic_propositions", "check", "parse_ctl", "sat",
    "validate_ctl_formula",
]
