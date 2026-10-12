from __future__ import annotations

import pytest

from seclab.formal.ctl.ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, Implies, Not, Or,
)
from seclab.formal.ctl.errors import CTLError, CTLErrorCode
from seclab.formal.ctl.parser import parse_ctl


@pytest.mark.parametrize("operator, node", [
    ("EX", EX), ("AX", AX), ("EF", EF), ("AF", AF), ("EG", EG), ("AG", AG),
])
def test_unary_temporal_operators(operator: str, node: type) -> None:
    assert parse_ctl(f"{operator} p") == node(Atom("p"))


def test_atom_and_boolean_constant() -> None:
    assert parse_ctl("p") == Atom("p")
    assert parse_ctl("true") == BoolConstant(True)
    assert parse_ctl("false") == BoolConstant(False)


def test_not_and_parentheses() -> None:
    assert parse_ctl("!(p)") == Not(Atom("p"))


def test_boolean_binary_operators() -> None:
    assert parse_ctl("p && q") == And(Atom("p"), Atom("q"))
    assert parse_ctl("p || q") == Or(Atom("p"), Atom("q"))
    assert parse_ctl("p -> q") == Implies(Atom("p"), Atom("q"))


def test_until_operators() -> None:
    assert parse_ctl("E[p U q]") == EU(Atom("p"), Atom("q"))
    assert parse_ctl("A[p U q]") == AU(Atom("p"), Atom("q"))


def test_nested_temporal_and_boolean_formula() -> None:
    assert parse_ctl("AG(p -> EF(q))") == AG(Implies(Atom("p"), EF(Atom("q"))))
    assert parse_ctl("AG(!(p && q))") == AG(Not(And(Atom("p"), Atom("q"))))


def test_boolean_operator_precedence() -> None:
    assert parse_ctl("p || q && r") == Or(Atom("p"), And(Atom("q"), Atom("r")))


def test_implication_is_right_associative() -> None:
    assert parse_ctl("p -> q -> r") == Implies(Atom("p"), Implies(Atom("q"), Atom("r")))


def test_whitespace_is_ignored_and_ast_is_hashable() -> None:
    first = parse_ctl("  AG ( p  ->  EF ( q ) ) ")
    second = parse_ctl("AG(p->EF(q))")

    assert first == second
    assert hash(first) == hash(second)


@pytest.mark.parametrize("formula", [
    "AG(",
    "AG()",
    "&& p",
    "p q",
    "E[p q]",
    "E[p U]",
    "A[U q]",
    "p &&",
    "UNKNOWN(p)",
    "G(p)",
    "F(p)",
    "X(p)",
    "(p",
    "p)",
    "p @ q",
])
def test_invalid_formula_reports_structured_syntax_error(formula: str) -> None:
    with pytest.raises(CTLError) as raised:
        parse_ctl(formula)

    assert raised.value.category == "CTL_ERROR"
    assert raised.value.code is CTLErrorCode.CTL_SYNTAX_ERROR
    assert raised.value.position is not None
    assert raised.value.line is not None
    assert raised.value.column is not None


def test_syntax_error_identifies_line_column_and_token() -> None:
    with pytest.raises(CTLError) as raised:
        parse_ctl("p &&\n)")

    assert raised.value.line == 2
    assert raised.value.column == 1
    assert raised.value.token == ")"
