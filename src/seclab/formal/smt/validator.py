"""Type checking and domain interpretation for SMT expressions."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Mapping

from seclab.specification.schema import Domain, Specification

from .ast import Binary, Expr, Literal, Unary, Variable
from .errors import SMTError, SMTErrorCode


class ValueType(StrEnum):
    BOOL = "boolean"
    INT = "integer"
    REAL = "number"
    STRING = "string"


def domain_type(domain: Domain, variable_id: str) -> ValueType:
    if domain.type is not None:
        try:
            value_type = ValueType(domain.type)
        except ValueError as exc:
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Variable {variable_id!r} has unsupported domain type {domain.type!r}.") from exc
    elif domain.values:
        kinds = {_literal_type(value) for value in domain.values}
        if len(kinds) != 1 or None in kinds:
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Variable {variable_id!r} has a finite domain with mixed or unsupported value types.")
        value_type = next(iter(kinds))
    else:
        raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Variable {variable_id!r} has no explicit type or finite values from which to infer one.")
    if value_type is ValueType.BOOL and (domain.minimum is not None or domain.maximum is not None):
        raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Boolean variable {variable_id!r} cannot have numeric bounds.")
    if value_type is ValueType.STRING and (domain.minimum is not None or domain.maximum is not None):
        raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"String variable {variable_id!r} cannot have numeric bounds.")
    for bound in (domain.minimum, domain.maximum):
        if bound is not None and (isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(bound)):
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Variable {variable_id!r} has a non-finite or non-numeric bound.")
        if value_type is ValueType.INT and bound is not None and not isinstance(bound, int):
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Integer variable {variable_id!r} must use integer bounds.")
    if domain.minimum is not None and domain.maximum is not None and domain.minimum > domain.maximum:
        raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Variable {variable_id!r} has minimum greater than maximum.")
    for value in domain.values:
        if not _value_matches_type(value, value_type):
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Finite value {value!r} does not match variable {variable_id!r} type {value_type.value}.")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if domain.minimum is not None and value < domain.minimum or domain.maximum is not None and value > domain.maximum:
                raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Finite value {value!r} lies outside bounds for {variable_id!r}.")
    return value_type


def type_environment(specification: Specification) -> dict[str, ValueType]:
    output: dict[str, ValueType] = {}
    for variable in specification.variables:
        if variable.id in output:
            raise SMTError(SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE, f"Duplicate variable {variable.id!r}.")
        output[variable.id] = domain_type(variable.domain, variable.id)
    return output


def infer_type(expression: Expr, environment: Mapping[str, ValueType]) -> ValueType:
    if isinstance(expression, Literal):
        kind = _literal_type(expression.value)
        if kind is None:
            raise SMTError(SMTErrorCode.TYPE_MISMATCH, f"Unsupported literal {expression.value!r}.")
        return kind
    if isinstance(expression, Variable):
        try:
            return environment[expression.name]
        except KeyError as exc:
            raise SMTError(SMTErrorCode.UNKNOWN_VARIABLE, f"Expression references unknown variable {expression.name!r}.") from exc
    if isinstance(expression, Unary):
        kind = infer_type(expression.operand, environment)
        if expression.op == "!":
            _require(kind is ValueType.BOOL, "Logical ! requires a boolean operand.")
            return ValueType.BOOL
        if expression.op == "-":
            _require(kind in {ValueType.INT, ValueType.REAL}, "Unary - requires a numeric operand.")
            return kind
        raise SMTError(SMTErrorCode.UNSUPPORTED_OPERATOR, f"Unsupported unary operator {expression.op!r}.")
    if isinstance(expression, Binary):
        left = infer_type(expression.left, environment)
        right = infer_type(expression.right, environment)
        if expression.op in {"&&", "||", "->"}:
            _require(left is right is ValueType.BOOL, f"Operator {expression.op} requires boolean operands.")
            return ValueType.BOOL
        if expression.op in {"==", "!="}:
            _require(left is right or left in {ValueType.INT, ValueType.REAL} and right in {ValueType.INT, ValueType.REAL}, "Equality operands must have compatible types.")
            return ValueType.BOOL
        if expression.op in {"<", "<=", ">", ">="}:
            _require(left in {ValueType.INT, ValueType.REAL} and right in {ValueType.INT, ValueType.REAL}, "Ordering comparisons require numeric operands.")
            return ValueType.BOOL
        if expression.op in {"+", "-", "*"}:
            _require(left in {ValueType.INT, ValueType.REAL} and right in {ValueType.INT, ValueType.REAL}, f"Arithmetic {expression.op} requires numeric operands.")
            return ValueType.INT if left is right is ValueType.INT else ValueType.REAL
        if expression.op == "/":
            raise SMTError(SMTErrorCode.UNSUPPORTED_OPERATOR, "Division is not supported in SMT Core v1.")
        raise SMTError(SMTErrorCode.UNSUPPORTED_OPERATOR, f"Unsupported binary operator {expression.op!r}.")
    raise SMTError(SMTErrorCode.TYPE_MISMATCH, f"Unknown AST node {type(expression).__name__}.")


def _literal_type(value: object) -> ValueType | None:
    if isinstance(value, bool):
        return ValueType.BOOL
    if isinstance(value, int):
        return ValueType.INT
    if isinstance(value, float) and math.isfinite(value):
        return ValueType.REAL
    if isinstance(value, str):
        return ValueType.STRING
    return None


def _value_matches_type(value: object, expected: ValueType) -> bool:
    actual = _literal_type(value)
    return actual is expected or expected is ValueType.REAL and actual is ValueType.INT


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SMTError(SMTErrorCode.TYPE_MISMATCH, message)
