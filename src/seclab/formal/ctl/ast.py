"""Immutable abstract syntax tree for the supported CTL fragment."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Atom:
    name: str


@dataclass(frozen=True, slots=True)
class BoolConstant:
    value: bool


@dataclass(frozen=True, slots=True)
class Not:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class And:
    left: CTLFormula
    right: CTLFormula


@dataclass(frozen=True, slots=True)
class Or:
    left: CTLFormula
    right: CTLFormula


@dataclass(frozen=True, slots=True)
class Implies:
    left: CTLFormula
    right: CTLFormula


@dataclass(frozen=True, slots=True)
class EX:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class AX:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class EF:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class AF:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class EG:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class AG:
    child: CTLFormula


@dataclass(frozen=True, slots=True)
class EU:
    left: CTLFormula
    right: CTLFormula


@dataclass(frozen=True, slots=True)
class AU:
    left: CTLFormula
    right: CTLFormula


CTLFormula = Atom | BoolConstant | Not | And | Or | Implies | EX | AX | EF | AF | EG | AG | EU | AU


def atomic_propositions(formula: CTLFormula) -> frozenset[str]:
    """Return exactly the proposition names present in an AST."""
    if isinstance(formula, Atom):
        return frozenset((formula.name,))
    if isinstance(formula, BoolConstant):
        return frozenset()
    if isinstance(formula, (Not, EX, AX, EF, AF, EG, AG)):
        return atomic_propositions(formula.child)
    if isinstance(formula, (And, Or, Implies, EU, AU)):
        return atomic_propositions(formula.left) | atomic_propositions(formula.right)
    raise TypeError(f"Unsupported CTL AST node: {type(formula).__name__}")
