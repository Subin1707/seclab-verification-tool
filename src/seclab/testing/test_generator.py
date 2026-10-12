"""Deterministic abstract test candidates from Specification v1 domains."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any

from seclab.specification.schema import Domain, Specification, Variable

from .test_case import ExpectedBehavior, TestCase, TestCategory, TestTargetKind


@dataclass(frozen=True, slots=True)
class TestGenerationResult:
    cases: tuple[TestCase, ...]
    unsupported_variables: tuple[str, ...] = ()


class TestGenerator:
    def generate(
        self,
        specification: Specification,
        *,
        requirement_id: str | None = None,
        property_id: str | None = None,
    ) -> TestGenerationResult:
        variables = tuple(sorted(specification.variables, key=lambda item: item.id))
        representatives: dict[str, Any] = {}
        unsupported: list[str] = []
        for variable in variables:
            representative = _representative(variable)
            if representative is _UNSUPPORTED:
                unsupported.append(variable.id)
            else:
                representatives[variable.id] = representative
        cases: list[TestCase] = []
        for variable in variables:
            if variable.id not in representatives:
                continue
            candidates = _candidates(variable, representatives[variable.id])
            seen: set[tuple[type, Any]] = set()
            for label, value, category in candidates:
                key = (type(value), value)
                if key in seen:
                    continue
                seen.add(key)
                inputs = dict(representatives)
                inputs[variable.id] = value
                case_id = _case_id(specification.id, variable.id, label, value)
                cases.append(TestCase(
                    id=case_id, name=f"{specification.name}: {variable.id} {label}",
                    target=specification.id, inputs=inputs, expected=ExpectedBehavior(),
                    category=category, target_kind=TestTargetKind.ABSTRACT,
                    requirement_id=requirement_id, property_id=property_id,
                    description="Abstract domain candidate; no automatic C parameter mapping is inferred.",
                    metadata={"specification_id": specification.id, "variable_id": variable.id,
                              "candidate_label": label, "candidate_valid_for_domain": _in_domain(value, variable.domain)},
                ))
        return TestGenerationResult(tuple(cases), tuple(unsupported))


_UNSUPPORTED = object()


def _representative(variable: Variable) -> Any:
    domain = variable.domain
    kind = _domain_kind(domain)
    if domain.values:
        return domain.values[0]
    if kind == "boolean":
        return False
    if kind == "integer":
        if domain.minimum is not None and domain.maximum is not None:
            return (int(domain.minimum) + int(domain.maximum)) // 2
        if domain.minimum is not None:
            return int(domain.minimum)
        if domain.maximum is not None:
            return int(domain.maximum)
        return 0
    if kind == "number":
        if domain.minimum is not None and domain.maximum is not None:
            value = float(domain.minimum) / 2.0 + float(domain.maximum) / 2.0
            return value if math.isfinite(value) else _UNSUPPORTED
        if domain.minimum is not None:
            return float(domain.minimum)
        if domain.maximum is not None:
            return float(domain.maximum)
        return 0.0
    if kind == "string":
        return ""
    return _UNSUPPORTED


def _candidates(variable: Variable, representative: Any) -> list[tuple[str, Any, TestCategory]]:
    domain = variable.domain
    kind = _domain_kind(domain)
    if domain.values:
        return [(f"finite-{index}", value, TestCategory.NORMAL) for index, value in enumerate(domain.values)]
    if kind == "boolean":
        return [("false", False, TestCategory.NORMAL), ("true", True, TestCategory.NORMAL)]
    if kind == "string":
        return [("representative-empty", representative, TestCategory.NORMAL)]
    if kind == "integer":
        candidates: list[tuple[str, Any, TestCategory]] = []
        lower, upper = domain.minimum, domain.maximum
        if lower is not None:
            candidates.extend((("below-min", int(lower) - 1, TestCategory.INVALID),
                               ("min", int(lower), TestCategory.BOUNDARY),
                               ("min-plus-one", int(lower) + 1, TestCategory.BOUNDARY)))
        candidates.append(("representative", representative, TestCategory.NORMAL))
        if upper is not None:
            candidates.extend((("max-minus-one", int(upper) - 1, TestCategory.BOUNDARY),
                               ("max", int(upper), TestCategory.BOUNDARY),
                               ("above-max", int(upper) + 1, TestCategory.INVALID)))
        return candidates
    if kind == "number":
        candidates = []
        lower, upper = domain.minimum, domain.maximum
        if lower is not None:
            candidates.append(("min", float(lower), TestCategory.BOUNDARY))
        candidates.append(("midpoint" if lower is not None and upper is not None else "representative",
                           representative, TestCategory.NORMAL))
        if upper is not None:
            candidates.append(("max", float(upper), TestCategory.BOUNDARY))
        return candidates
    return []


def _domain_kind(domain: Domain) -> str | None:
    if domain.type is not None:
        return domain.type
    if domain.values:
        first = domain.values[0]
        if isinstance(first, bool):
            return "boolean" if all(isinstance(item, bool) for item in domain.values) else None
        if isinstance(first, int):
            return "integer" if all(type(item) is int for item in domain.values) else None
        if isinstance(first, float):
            return "number" if all(type(item) in {int, float} and not isinstance(item, bool) for item in domain.values) else None
        if isinstance(first, str):
            return "string" if all(isinstance(item, str) for item in domain.values) else None
    return None


def _in_domain(value: Any, domain: Domain) -> bool:
    if domain.values and not any(type(value) is type(item) and value == item for item in domain.values):
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (domain.minimum is None or value >= domain.minimum) and (domain.maximum is None or value <= domain.maximum)
    return True


def _case_id(specification_id: str, variable_id: str, label: str, value: Any) -> str:
    digest = hashlib.sha256(f"{type(value).__name__}:{value!r}".encode("utf-8")).hexdigest()[:8]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{specification_id}-{variable_id}-{label}").strip("-._") or "test"
    if not stem[0].isalpha():
        stem = f"T-{stem}"
    return f"{stem}-{digest}"
