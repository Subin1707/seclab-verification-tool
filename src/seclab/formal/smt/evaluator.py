"""Safe solver independent evaluator for the supported SMT AST subset."""

from __future__ import annotations

from fractions import Fraction
import math
from typing import Any, Mapping

from .ast import Binary, Expr, Literal, Unary, Variable
from .counterexample import Counterexample
from .encoder import EncodedQuery
from .validator import ValueType


def validate_model(query: EncodedQuery, model: Counterexample | None) -> tuple[bool, str | None]:
    """Reconstruct and validate a backend valuation without eval/exec."""
    if model is None:
        return False, "SAT result did not include a model."
    declared = dict(query.variable_types)
    valuation: dict[str, Any] = {}
    for assignment in model.assignments:
        if assignment.variable in valuation or assignment.variable not in declared:
            return False, f"Unexpected or duplicate model variable {assignment.variable!r}."
        expected = declared[assignment.variable]
        if assignment.type != expected.value:
            return False, f"Model type mismatch for {assignment.variable!r}."
        try:
            valuation[assignment.variable] = _coerce(assignment.value, expected)
        except (TypeError, ValueError, ZeroDivisionError) as exc:
            return False, f"Invalid model value for {assignment.variable!r}: {exc}"
    if set(valuation) != set(declared):
        return False, "Model does not assign every declared variable."
    try:
        finite_domains: dict[str, list[Any]] = {}
        for name, op, bound in query.domain_constraints:
            value = valuation[name]
            if op == "in":
                finite_domains.setdefault(name, []).append(_coerce(bound, declared[name]))
            elif op == ">=" and not value >= _coerce(bound, declared[name]):
                return False, f"Model violates lower bound for {name!r}."
            elif op == "<=" and not value <= _coerce(bound, declared[name]):
                return False, f"Model violates upper bound for {name!r}."
        if any(valuation[name] not in choices for name, choices in finite_domains.items()):
            return False, "Model violates a finite variable domain."
        for _, constraint in query.constraints:
            if _evaluate(constraint, valuation) is not True:
                return False, "Model does not satisfy every specification constraint."
        if _evaluate(query.query_expression, valuation) is not True:
            return False, "Model does not satisfy the encoded query expression."
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
        return False, f"Model query evaluation failed: {exc}"
    return True, None


def _coerce(value: Any, kind: ValueType) -> Any:
    if kind is ValueType.BOOL:
        if not isinstance(value, bool):
            raise TypeError("expected boolean")
        return value
    if kind is ValueType.INT:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("expected integer")
        return value
    if kind is ValueType.REAL:
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise TypeError("expected real number")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("real number must be finite")
        return Fraction(str(value))
    if kind is ValueType.STRING:
        if not isinstance(value, str):
            raise TypeError("expected string")
        return value
    raise TypeError(f"unsupported value type {kind!r}")


def _evaluate(expression: Expr, valuation: Mapping[str, Any]) -> Any:
    if isinstance(expression, Literal):
        if isinstance(expression.value, float):
            return Fraction(str(expression.value))
        return expression.value
    if isinstance(expression, Variable):
        return valuation[expression.name]
    if isinstance(expression, Unary):
        value = _evaluate(expression.operand, valuation)
        if expression.op == "!":
            if not isinstance(value, bool):
                raise TypeError("logical negation requires boolean")
            return not value
        if expression.op == "-":
            return -value
        raise ValueError(f"unsupported unary operator {expression.op!r}")
    if isinstance(expression, Binary):
        left, right = _evaluate(expression.left, valuation), _evaluate(expression.right, valuation)
        operations = {
            "&&": lambda: _boolean(left) and _boolean(right),
            "||": lambda: _boolean(left) or _boolean(right),
            "->": lambda: not _boolean(left) or _boolean(right),
            "==": lambda: left == right,
            "!=": lambda: left != right,
            "<": lambda: left < right,
            "<=": lambda: left <= right,
            ">": lambda: left > right,
            ">=": lambda: left >= right,
            "+": lambda: left + right,
            "-": lambda: left - right,
            "*": lambda: left * right,
        }
        try:
            return operations[expression.op]()
        except KeyError as exc:
            raise ValueError(f"unsupported binary operator {expression.op!r}") from exc
    raise TypeError(f"unsupported AST node {type(expression).__name__}")


def evaluate_expression(expression: Expr, valuation: Mapping[str, Any]) -> Any:
    """Evaluate a parsed supported SMT expression without Python eval/exec."""
    return _evaluate(expression, valuation)


def _boolean(value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError("boolean operator requires booleans")
    return value
