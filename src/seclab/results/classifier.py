"""Translate normalized engine outcomes into semantic verification results."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Mapping

from seclab.formal.ctl.ast import (
    AF, AG, AX, AU, EF, EG, EU, EX, And, Atom, BoolConstant, Implies, Not, Or,
)
from seclab.formal.ctl.errors import CTLError, CTLErrorCode
from seclab.formal.ctl.result import CTLCheckResult

from .result import VerificationResult
from .status import VerificationStatus


class RawOutcome(StrEnum):
    PROPERTY_SATISFIED = "PROPERTY_SATISFIED"
    PROPERTY_VIOLATED = "PROPERTY_VIOLATED"
    INVALID_SPEC = "INVALID_SPEC"
    BUILD_FAILED = "BUILD_FAILED"
    TOOL_FAILED = "TOOL_FAILED"
    TIMEOUT = "TIMEOUT"
    NOT_RUN = "NOT_RUN"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ClassificationInput:
    outcome: RawOutcome
    stage: str
    technique: str
    message: str | None = None
    reason_code: str | None = None
    requirement_id: str | None = None
    property_id: str | None = None
    source: str | None = None
    scope: str | None = None
    evidence_ids: tuple[str, ...] = ()
    counterexample: Any = None
    duration_ms: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


_CLASSIFICATIONS: dict[RawOutcome, tuple[VerificationStatus, str, str]] = {
    RawOutcome.PROPERTY_SATISFIED: (
        VerificationStatus.PASS, "PROPERTY_SATISFIED", "The checked property is satisfied in the stated scope.",
    ),
    RawOutcome.PROPERTY_VIOLATED: (
        VerificationStatus.FAIL, "PROPERTY_VIOLATED", "The checked property is violated in the stated scope.",
    ),
    RawOutcome.INVALID_SPEC: (
        VerificationStatus.SPEC_ERROR, "INVALID_SPECIFICATION", "The input specification is invalid.",
    ),
    RawOutcome.BUILD_FAILED: (
        VerificationStatus.BUILD_ERROR, "BUILD_FAILED", "The SUT or verification harness could not be built.",
    ),
    RawOutcome.TOOL_FAILED: (
        VerificationStatus.TOOL_ERROR, "TOOL_FAILED", "A verification tool or infrastructure operation failed.",
    ),
    RawOutcome.TIMEOUT: (
        VerificationStatus.INCONCLUSIVE, "TIMEOUT", "The technique timed out before reaching a conclusion.",
    ),
    RawOutcome.NOT_RUN: (
        VerificationStatus.NOT_RUN, "NOT_RUN", "The verification check was not run.",
    ),
    RawOutcome.UNKNOWN: (
        VerificationStatus.INCONCLUSIVE, "UNKNOWN_OUTCOME", "The engine did not produce a conclusive outcome.",
    ),
}


class ResultClassifier:
    def __init__(self, id_factory: Callable[[], str] | None = None) -> None:
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))

    def classify(
        self,
        raw: ClassificationInput,
        *,
        result_id: str | None = None,
    ) -> VerificationResult:
        status, default_reason, default_message = _CLASSIFICATIONS[RawOutcome(raw.outcome)]
        return VerificationResult(
            id=result_id or self._id_factory(),
            stage=raw.stage,
            technique=raw.technique,
            status=status,
            reason_code=raw.reason_code or default_reason,
            message=raw.message or default_message,
            requirement_id=raw.requirement_id,
            property_id=raw.property_id,
            source=raw.source,
            scope=raw.scope,
            evidence_ids=raw.evidence_ids,
            counterexample=raw.counterexample,
            duration_ms=raw.duration_ms,
            metadata=raw.metadata,
        )


def classify_ctl_result(
    result: CTLCheckResult,
    *,
    result_id: str | None = None,
    classifier: ResultClassifier | None = None,
    stage: str = "FORMAL",
    technique: str = "CTL",
    requirement_id: str | None = None,
    property_id: str | None = None,
    source: str | None = None,
    scope: str = (
        "Canonical finite Kripke structure supplied to CTL; only guards evaluated by the model builder affect its transition relation."
    ),
    evidence_ids: tuple[str, ...] = (),
    duration_ms: float | None = None,
) -> VerificationResult:
    """Adapt a completed CTL result without changing the CTL engine contract."""
    from seclab.formal.ctl.model_checker import validate_counterexample

    if not result.satisfied and (result.model is None or not result.counterexample_validated
                                 or not validate_counterexample(result.model, result)):
        raw = ClassificationInput(
            outcome=RawOutcome.TOOL_FAILED, stage=stage, technique=technique,
            reason_code="CTL_OBSERVATION_INVALID",
            message="CTL reported a violation without a validated model observation.",
            requirement_id=requirement_id, property_id=property_id, source=source,
            scope=scope, duration_ms=duration_ms,
            metadata={"formula_text": result.formula_text,
                      "initial_state_ids": [state.id for state in result.initial_states]},
        )
        return (classifier or ResultClassifier()).classify(raw, result_id=result_id)
    outcome = RawOutcome.PROPERTY_SATISFIED if result.satisfied else RawOutcome.PROPERTY_VIOLATED
    ast_payload = _formula_to_dict(result.formula)
    raw = ClassificationInput(
        outcome=outcome,
        stage=stage,
        technique=technique,
        reason_code="PROPERTY_SATISFIED" if result.satisfied else "PROPERTY_VIOLATED",
        message=(
            "CTL property holds at every initial state."
            if result.satisfied
            else "CTL property does not hold at every initial state."
        ),
        requirement_id=requirement_id,
        property_id=property_id,
        source=source,
        scope=scope,
        evidence_ids=evidence_ids,
        duration_ms=duration_ms,
        metadata={
            "formula_text": result.formula_text,
            "formula_ast": ast_payload,
            "counterexample_validated": (not result.satisfied and result.counterexample is not None),
            "initial_state_ids": [state.id for state in result.initial_states],
            "model_hash": result.model.model_hash if result.model is not None else None,
            "satisfying_state_ids": sorted(state.id for state in result.satisfying_states),
            "violating_initial_state_ids": sorted(state.id for state in result.initial_states
                                                   if state not in result.satisfying_states),
        },
    )
    return (classifier or ResultClassifier()).classify(raw, result_id=result_id)


def classify_ctl_error(
    error: CTLError,
    *,
    result_id: str | None = None,
    classifier: ResultClassifier | None = None,
    stage: str = "FORMAL",
    technique: str = "CTL",
    property_id: str | None = None,
    source: str | None = None,
) -> VerificationResult:
    """Map CTL input errors separately from inconclusive/model-tool errors."""
    if error.code is CTLErrorCode.CTL_SYNTAX_ERROR:
        outcome, reason = RawOutcome.INVALID_SPEC, "INVALID_CTL_FORMULA"
    elif error.code is CTLErrorCode.UNKNOWN_ATOM:
        outcome, reason = RawOutcome.INVALID_SPEC, "UNKNOWN_ATOM"
    elif error.code is CTLErrorCode.NO_INITIAL_STATE:
        outcome, reason = RawOutcome.UNKNOWN, "NO_INITIAL_STATE"
    else:
        outcome, reason = RawOutcome.TOOL_FAILED, "MODEL_CHECK_ERROR"
    raw = ClassificationInput(
        outcome=outcome,
        stage=stage,
        technique=technique,
        reason_code=reason,
        message=error.message,
        property_id=property_id,
        source=source,
        scope="CTL formula evaluation could not produce a property verdict.",
        metadata={"error_code": error.code.value},
    )
    return (classifier or ResultClassifier()).classify(raw, result_id=result_id)


def _formula_to_dict(formula: Any) -> dict[str, Any]:
    if isinstance(formula, Atom):
        return {"op": "ATOM", "name": formula.name}
    if isinstance(formula, BoolConstant):
        return {"op": "BOOL", "value": formula.value}
    if isinstance(formula, Not):
        return {"op": "NOT", "child": _formula_to_dict(formula.child)}
    unary_names = {EX: "EX", AX: "AX", EF: "EF", AF: "AF", EG: "EG", AG: "AG"}
    if type(formula) in unary_names:
        return {"op": unary_names[type(formula)], "child": _formula_to_dict(formula.child)}
    binary_names = {And: "AND", Or: "OR", Implies: "IMPLIES", EU: "EU", AU: "AU"}
    if type(formula) in binary_names:
        return {
            "op": binary_names[type(formula)],
            "left": _formula_to_dict(formula.left),
            "right": _formula_to_dict(formula.right),
        }
    raise TypeError(f"Unsupported CTL AST node: {type(formula).__name__}")
