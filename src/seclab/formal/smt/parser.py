"""A small, non-evaluating parser for Specification v1 SMT expressions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ast import Binary, Expr, Literal, Unary, Variable
from .errors import SMTError, SMTErrorCode

_TOKEN = re.compile(
    r"(?P<WS>\s+)|(?P<REAL>(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+)"
    r"|(?P<INT>[0-9]+)|(?P<STRING>\"(?:[^\"\\]|\\[\"\\nrt])*\")"
    r"|(?P<OP>==|!=|<=|>=|&&|\|\||->|[()!+*/<>-])"
    r"|(?P<ID>[A-Za-z][A-Za-z0-9_.:-]*(?:-[A-Za-z0-9_.:-]+)*)"
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    text: str
    position: int


def parse_expression(text: str) -> Expr:
    if not isinstance(text, str):
        raise SMTError(SMTErrorCode.CONSTRAINT_SYNTAX_ERROR, "Expression must be text.")
    return _Parser(text).parse()


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens: list[_Token] = []
        offset = 0
        while offset < len(text):
            match = _TOKEN.match(text, offset)
            if match is None:
                raise SMTError(SMTErrorCode.CONSTRAINT_SYNTAX_ERROR, f"Unexpected character {text[offset]!r}.", position=offset)
            kind = match.lastgroup or ""
            if kind != "WS":
                self.tokens.append(_Token(kind, match.group(), offset))
            offset = match.end()
        self.tokens.append(_Token("EOF", "", len(text)))
        self.index = 0

    def parse(self) -> Expr:
        if self.peek().kind == "EOF":
            self.fail("Expression is empty.")
        result = self.implication()
        if self.peek().kind != "EOF":
            self.fail(f"Unexpected token {self.peek().text!r}.")
        return result

    def implication(self) -> Expr:
        left = self.disjunction()
        if self.accept("->"):
            return Binary("->", left, self.implication())
        return left

    def disjunction(self) -> Expr:
        result = self.conjunction()
        while self.accept("||"):
            result = Binary("||", result, self.conjunction())
        return result

    def conjunction(self) -> Expr:
        result = self.comparison()
        while self.accept("&&"):
            result = Binary("&&", result, self.comparison())
        return result

    def comparison(self) -> Expr:
        result = self.additive()
        if self.peek().text in {"==", "!=", "<", "<=", ">", ">="}:
            op = self.take().text
            result = Binary(op, result, self.additive())
            if self.peek().text in {"==", "!=", "<", "<=", ">", ">="}:
                self.fail("Chained comparisons are not supported; combine comparisons with &&.")
        return result

    def additive(self) -> Expr:
        result = self.multiplicative()
        while self.peek().text in {"+", "-"}:
            op = self.take().text
            result = Binary(op, result, self.multiplicative())
        return result

    def multiplicative(self) -> Expr:
        result = self.unary()
        while self.peek().text in {"*", "/"}:
            op = self.take().text
            result = Binary(op, result, self.unary())
        return result

    def unary(self) -> Expr:
        if self.peek().text in {"!", "-"}:
            return Unary(self.take().text, self.unary())
        return self.atom()

    def atom(self) -> Expr:
        token = self.peek()
        if token.text == "(":
            self.take()
            value = self.implication()
            self.expect(")")
            return value
        if token.kind == "INT":
            self.take()
            return Literal(int(token.text))
        if token.kind == "REAL":
            self.take()
            return Literal(float(token.text))
        if token.kind == "STRING":
            self.take()
            # Decode only the explicit string escapes accepted by the grammar.
            value = token.text[1:-1]
            value = re.sub(r"\\([\"\\nrt])", lambda m: {"\\n": "\n", "\\r": "\r", "\\t": "\t", "\\\\": "\\", '\\"': '"'}[m.group()], value)
            return Literal(value)
        if token.kind == "ID":
            self.take()
            if token.text in {"true", "false"}:
                return Literal(token.text == "true")
            return Variable(token.text)
        self.fail(f"Expected a literal, variable, or parenthesized expression; found {token.text!r}.")
        raise AssertionError("unreachable")

    def peek(self) -> _Token:
        return self.tokens[self.index]

    def take(self) -> _Token:
        value = self.peek()
        self.index += 1
        return value

    def accept(self, text: str) -> bool:
        if self.peek().text == text:
            self.take()
            return True
        return False

    def expect(self, text: str) -> None:
        if not self.accept(text):
            self.fail(f"Expected {text!r}; found {self.peek().text!r}.")

    def fail(self, message: str) -> None:
        raise SMTError(SMTErrorCode.CONSTRAINT_SYNTAX_ERROR, message, position=self.peek().position)
