"""Solver-neutral, deterministic SMT query representation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from seclab.specification.schema import Specification

from .ast import Binary, Expr, Literal, Unary, Variable
from .errors import SMTError, SMTErrorCode
from .parser import parse_expression
from .validator import ValueType, infer_type, type_environment


class QueryIntent(StrEnum):
    VIOLATION_SEARCH = "VIOLATION_SEARCH"
    SATISFIABILITY = "SATISFIABILITY"


@dataclass(frozen=True, slots=True)
class EncodedQuery:
    specification_id: str
    query_intent: QueryIntent
    variable_types: tuple[tuple[str, ValueType], ...]
    variable_mapping: tuple[tuple[str, str], ...]
    domain_constraints: tuple[tuple[str, str, Any], ...]
    constraints: tuple[tuple[str, Expr], ...]
    constraint_kinds: tuple[tuple[str, str | None], ...]
    property_expression: Expr
    query_expression: Expr
    property_source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "seclab-smt-query-v1",
            "specification_id": self.specification_id,
            "query_intent": self.query_intent.value,
            "variables": [{"id": name, "type": kind.value} for name, kind in self.variable_types],
            "declarations": [
                {"symbol": symbol, "sort": kind.value}
                for (name, kind), (_, symbol) in zip(self.variable_types, self.variable_mapping)
            ],
            "variable_mapping": [{"id": name, "symbol": symbol} for name, symbol in self.variable_mapping],
            "domain_constraints": [
                {"variable": name, "operator": op, "value": _json_value(value)}
                for name, op, value in self.domain_constraints
            ],
            "assumptions": [
                {"id": constraint_id, "kind": kind, "ast": _expr_dict(expr)}
                for (constraint_id, expr), (_, kind) in zip(self.constraints, self.constraint_kinds)
            ],
            "property_source": self.property_source,
            "property_ast": _expr_dict(self.property_expression),
            "query_ast": _expr_dict(self.query_expression),
            "scope": "One valuation satisfying all specification constraints and the query; no transition or temporal semantics are inferred.",
        }


class SMTEncoder:
    def encode(
        self,
        specification: Specification,
        property_expression: str,
        *,
        query_intent: QueryIntent = QueryIntent.VIOLATION_SEARCH,
    ) -> EncodedQuery:
        intent = QueryIntent(query_intent)
        environment = type_environment(specification)
        constraints = tuple((item.id, parse_expression(item.expression)) for item in specification.constraints)
        domains: list[tuple[str, str, Any]] = []
        for variable in sorted(specification.variables, key=lambda item: item.id):
            domain = variable.domain
            if domain.minimum is not None:
                domains.append((variable.id, ">=", domain.minimum))
            if domain.maximum is not None:
                domains.append((variable.id, "<=", domain.maximum))
            for value in domain.values:
                domains.append((variable.id, "in", value))
        prop = parse_expression(property_expression)
        for constraint_id, expr in constraints:
            kind = infer_type(expr, environment)
            if kind is not ValueType.BOOL:
                raise SMTError(SMTErrorCode.TYPE_MISMATCH, f"Constraint {constraint_id!r} must be boolean.")
        if infer_type(prop, environment) is not ValueType.BOOL:
            raise SMTError(SMTErrorCode.PROPERTY_NOT_BOOLEAN, "Property expression must be boolean.")
        query = Unary("!", prop) if intent is QueryIntent.VIOLATION_SEARCH else prop
        return EncodedQuery(
            specification_id=specification.id,
            query_intent=intent,
            variable_types=tuple(sorted(environment.items())),
            variable_mapping=tuple((name, f"v{index}") for index, (name, _) in enumerate(sorted(environment.items()))),
            domain_constraints=tuple(domains),
            constraints=constraints,
            constraint_kinds=tuple((item.id, item.kind) for item in specification.constraints),
            property_expression=prop,
            query_expression=query,
            property_source=property_expression,
        )


def _expr_dict(expr: Expr) -> dict[str, Any]:
    if isinstance(expr, Literal):
        return {"op": "LITERAL", "value": expr.value, "type": "boolean" if isinstance(expr.value, bool) else "integer" if isinstance(expr.value, int) else "number" if isinstance(expr.value, float) else "string"}
    if isinstance(expr, Variable):
        return {"op": "VARIABLE", "name": expr.name}
    if isinstance(expr, Unary):
        return {"op": expr.op, "operand": _expr_dict(expr.operand)}
    if isinstance(expr, Binary):
        return {"op": expr.op, "left": _expr_dict(expr.left), "right": _expr_dict(expr.right)}
    raise TypeError(f"Unsupported AST node {type(expr).__name__}.")


def _json_value(value: Any) -> Any:
    if isinstance(value, float):
        return {"decimal": repr(value)}
    return value
