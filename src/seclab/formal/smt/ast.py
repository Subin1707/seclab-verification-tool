"""Solver-independent syntax tree for the SMT expression subset."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class Literal:
    value: bool | int | float | str


@dataclass(frozen=True, slots=True)
class Variable:
    name: str


@dataclass(frozen=True, slots=True)
class Unary:
    op: str
    operand: Expr


@dataclass(frozen=True, slots=True)
class Binary:
    op: str
    left: Expr
    right: Expr


Expr: TypeAlias = Literal | Variable | Unary | Binary
