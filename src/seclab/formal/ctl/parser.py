"""Tokenizer and recursive-descent parser for CTL formulas."""

from __future__ import annotations

from dataclasses import dataclass

from .ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, CTLFormula,
    Implies, Not, Or,
)
from .errors import CTLError, CTLErrorCode

_TEMPORAL_UNARY = {
    "EX": EX,
    "AX": AX,
    "EF": EF,
    "AF": AF,
    "EG": EG,
    "AG": AG,
}


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    position: int


def parse_ctl(formula: str) -> CTLFormula:
    """Parse one complete CTL formula, rejecting all unconsumed input."""
    if not isinstance(formula, str):
        raise TypeError("CTL formula must be a string")
    return _Parser(formula).parse()


class _Parser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.tokens = _tokenize(source)
        self.index = 0

    def parse(self) -> CTLFormula:
        if self._peek().kind == "EOF":
            self._fail("Formula is empty.", self._peek())
        formula = self._parse_implication()
        if self._peek().kind != "EOF":
            self._fail("Unexpected trailing input after a complete formula.", self._peek())
        return formula

    def _parse_implication(self) -> CTLFormula:
        left = self._parse_or()
        if self._accept("IMPLIES") is not None:
            # Conventional implication associates to the right.
            return Implies(left, self._parse_implication())
        return left

    def _parse_or(self) -> CTLFormula:
        expression = self._parse_and()
        while self._accept("OR") is not None:
            expression = Or(expression, self._parse_and())
        return expression

    def _parse_and(self) -> CTLFormula:
        expression = self._parse_unary()
        while self._accept("AND") is not None:
            expression = And(expression, self._parse_unary())
        return expression

    def _parse_unary(self) -> CTLFormula:
        if self._accept("NOT") is not None:
            return Not(self._parse_unary())
        token = self._peek()
        if token.kind == "TEMPORAL":
            self._advance()
            return _TEMPORAL_UNARY[token.value](self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> CTLFormula:
        token = self._peek()
        if token.kind == "LPAREN":
            self._advance()
            expression = self._parse_implication()
            self._expect("RPAREN", "Expected ')' to close this expression.")
            return expression
        if token.kind == "IDENT":
            self._advance()
            if token.value in {"E", "A"} and self._peek().kind == "LBRACKET":
                return self._parse_until(token.value)
            if token.value == "true":
                return BoolConstant(True)
            if token.value == "false":
                return BoolConstant(False)
            return Atom(token.value)
        self._fail("Expected an atom, parenthesized formula, or CTL operator.", token)

    def _parse_until(self, quantifier: str) -> CTLFormula:
        self._expect("LBRACKET", "Expected '[' after path quantifier.")
        left = self._parse_implication()
        self._expect("UNTIL", "Expected 'U' between the operands of a path-until formula.")
        right = self._parse_implication()
        self._expect("RBRACKET", "Expected ']' after the path-until formula.")
        return EU(left, right) if quantifier == "E" else AU(left, right)

    def _peek(self) -> _Token:
        return self.tokens[self.index]

    def _advance(self) -> _Token:
        token = self._peek()
        self.index += 1
        return token

    def _accept(self, kind: str) -> _Token | None:
        if self._peek().kind == kind:
            return self._advance()
        return None

    def _expect(self, kind: str, message: str) -> _Token:
        token = self._peek()
        if token.kind != kind:
            self._fail(message, token)
        return self._advance()

    def _fail(self, message: str, token: _Token) -> None:
        line = self.source.count("\n", 0, token.position) + 1
        last_newline = self.source.rfind("\n", 0, token.position)
        column = token.position - last_newline
        display = "end of input" if token.kind == "EOF" else token.value
        raise CTLError(
            CTLErrorCode.CTL_SYNTAX_ERROR,
            message,
            position=token.position,
            token=display,
            line=line,
            column=column,
        )


def _tokenize(source: str) -> tuple[_Token, ...]:
    tokens: list[_Token] = []
    index = 0
    fixed = (
        ("&&", "AND"),
        ("||", "OR"),
        ("->", "IMPLIES"),
    )
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        matched = False
        for spelling, kind in fixed:
            if source.startswith(spelling, index):
                tokens.append(_Token(kind, spelling, index))
                index += len(spelling)
                matched = True
                break
        if matched:
            continue
        single = {
            "!": "NOT",
            "(": "LPAREN",
            ")": "RPAREN",
            "[": "LBRACKET",
            "]": "RBRACKET",
        }.get(char)
        if single is not None:
            tokens.append(_Token(single, char, index))
            index += 1
            continue
        if _is_ascii_letter(char):
            start = index
            index += 1
            while (
                index < len(source)
                and _is_identifier_char(source[index])
                and not source.startswith("->", index)
            ):
                index += 1
            value = source[start:index]
            if value in _TEMPORAL_UNARY:
                kind = "TEMPORAL"
            elif value == "U":
                kind = "UNTIL"
            else:
                kind = "IDENT"
            tokens.append(_Token(kind, value, start))
            continue
        bad = _Token("INVALID", char, index)
        line = source.count("\n", 0, index) + 1
        last_newline = source.rfind("\n", 0, index)
        raise CTLError(
            CTLErrorCode.CTL_SYNTAX_ERROR,
            f"Invalid character {char!r}.",
            position=index,
            token=char,
            line=line,
            column=index - last_newline,
        )
    tokens.append(_Token("EOF", "", len(source)))
    return tuple(tokens)


def _is_ascii_letter(char: str) -> bool:
    return "a" <= char <= "z" or "A" <= char <= "Z"


def _is_identifier_char(char: str) -> bool:
    return _is_ascii_letter(char) or "0" <= char <= "9" or char in "_.:-"
