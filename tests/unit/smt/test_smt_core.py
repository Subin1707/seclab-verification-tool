from __future__ import annotations

import hashlib

import pytest

from seclab.evidence import ArtifactStore
from seclab.formal.smt import (
    BackendResult, Binary, Counterexample, Literal, ModelAssignment, QueryIntent, SMTEncoder, SMTError,
    SMTErrorCode, SMTVerifier, SolverOutcome, Unary,
    parse_expression, validate_model,
)
from seclab.specification.schema import Constraint, Domain, Specification, Variable
from seclab.results import VerificationStatus


def spec(*, domain: Domain | None = None, constraint: str = "x >= 0") -> Specification:
    return Specification(
        schema_version="1.0", id="generic", name="Generic",
        variables=(Variable("x", domain or Domain(type="integer", minimum=0, maximum=10)),),
        constraints=(Constraint("C1", constraint),),
    )


@pytest.mark.parametrize("text", [
    "x < 10", "x <= 10", "x == 10", "x != 10", "x >= 0 && x <= 100",
    "x + 1 < y", "!(x > 10)", "a -> b", "(x < 10) || flag",
    "((x + 1) * 2) >= 4", "true && !(false)", "sensor-main == 1", "x - y > 0",
])
def test_parser_accepts_supported_grammar(text: str) -> None:
    assert parse_expression(text)


@pytest.mark.parametrize("text", ["x <<< 5", "x <", "(x < 5", "x < 5 trailing", ""])
def test_parser_reports_structured_syntax_error(text: str) -> None:
    with pytest.raises(SMTError) as caught:
        parse_expression(text)
    assert caught.value.code is SMTErrorCode.CONSTRAINT_SYNTAX_ERROR


def test_parser_preserves_precedence_and_right_associative_implication() -> None:
    expr = parse_expression("a || b && !c -> d -> e")
    assert isinstance(expr, Binary) and expr.op == "->"
    assert isinstance(expr.right, Binary) and expr.right.op == "->"
    assert isinstance(expr.left, Binary) and expr.left.op == "||"
    assert isinstance(expr.left.right, Binary) and expr.left.right.op == "&&"


def test_encoder_checks_references_types_and_property_boolean() -> None:
    encoder = SMTEncoder()
    query = encoder.encode(spec(), "x + 1 < 5")
    assert query.query_intent is QueryIntent.VIOLATION_SEARCH
    assert query.query_expression == Unary("!", query.property_expression)
    with pytest.raises(SMTError) as unknown:
        encoder.encode(spec(), "missing > 10")
    assert unknown.value.code is SMTErrorCode.UNKNOWN_VARIABLE
    with pytest.raises(SMTError) as bad_type:
        encoder.encode(spec(), "x && true")
    assert bad_type.value.code is SMTErrorCode.TYPE_MISMATCH
    with pytest.raises(SMTError) as non_boolean:
        encoder.encode(spec(), "x + 1")
    assert non_boolean.value.code is SMTErrorCode.PROPERTY_NOT_BOOLEAN


def test_numeric_domains_are_materialized_in_deterministic_query() -> None:
    specification = Specification(
        schema_version="1.0", id="domains", name="Domains",
        variables=(
            Variable("real", Domain(type="number", minimum=0.5, maximum=4.0)),
            Variable("flag", Domain(type="boolean")),
            Variable("mode", Domain(values=("off", "on"))),
        ),
    )
    first = SMTEncoder().encode(specification, "flag || real > 1")
    second = SMTEncoder().encode(specification, "flag || real > 1")
    assert first.to_dict() == second.to_dict()
    assert first.variable_mapping == (("flag", "v0"), ("mode", "v1"), ("real", "v2"))
    assert first.domain_constraints == (("mode", "in", "off"), ("mode", "in", "on"), ("real", ">=", 0.5), ("real", "<=", 4.0))
    assert first.to_dict()["domain_constraints"][2]["value"] == {"decimal": "0.5"}


def test_division_and_unsupported_domains_are_rejected_explicitly() -> None:
    with pytest.raises(SMTError) as division:
        SMTEncoder().encode(spec(), "x / 2 > 1")
    assert division.value.code is SMTErrorCode.UNSUPPORTED_OPERATOR
    with pytest.raises(SMTError) as missing_type:
        SMTEncoder().encode(spec(domain=Domain()), "true")
    assert missing_type.value.code is SMTErrorCode.UNSUPPORTED_DOMAIN_TYPE


class _FixedBackend:
    name = "unit-test-backend"

    def __init__(self, outcome: SolverOutcome) -> None:
        self.outcome = outcome
        self.called = False

    def solve(self, query, specification, *, timeout_seconds=None):
        self.called = True
        reason = "SOLVER_UNKNOWN" if self.outcome is SolverOutcome.UNKNOWN else "SOLVER_ERROR" if self.outcome is SolverOutcome.ERROR else None
        return BackendResult(self.outcome, reason=reason)


def test_invalid_constraint_never_calls_backend_or_becomes_fail() -> None:
    backend = _FixedBackend(SolverOutcome.SAT)
    verifier = SMTVerifier(backend)
    with pytest.raises(SMTError) as caught:
        verifier.check(spec(constraint="x <<< 5"), "x <= 10")
    assert caught.value.code is SMTErrorCode.CONSTRAINT_SYNTAX_ERROR
    assert not backend.called


def test_solver_outcome_classification_is_intent_sensitive() -> None:
    violation_sat = SMTVerifier(_FixedBackend(SolverOutcome.SAT)).check(spec(), "x <= 5")
    assert violation_sat.result.status is VerificationStatus.TOOL_ERROR  # SAT violation must provide a model.
    unknown = SMTVerifier(_FixedBackend(SolverOutcome.UNKNOWN)).check(spec(), "x <= 5")
    assert unknown.result.status is VerificationStatus.INCONCLUSIVE
    assert unknown.result.reason_code == "SOLVER_UNKNOWN"
    # Set the fake result's explicit timeout reason to exercise timeout mapping.
    timeout_backend = _FixedBackend(SolverOutcome.UNKNOWN)
    timeout_backend.solve = lambda query, specification, *, timeout_seconds=None: BackendResult(  # type: ignore[method-assign]
        SolverOutcome.UNKNOWN, reason="SOLVER_TIMEOUT",
    )
    timed_out = SMTVerifier(timeout_backend).check(spec(), "x <= 5")
    assert timed_out.result.status is VerificationStatus.INCONCLUSIVE
    assert timed_out.result.reason_code == "SOLVER_TIMEOUT"
    error = SMTVerifier(_FixedBackend(SolverOutcome.ERROR)).check(spec(), "x <= 5")
    assert error.result.status is VerificationStatus.TOOL_ERROR
    satisfiable = SMTVerifier(_FixedBackend(SolverOutcome.SAT)).check(
        spec(), "x <= 5", query_intent=QueryIntent.SATISFIABILITY,
    )
    assert satisfiable.result.status is VerificationStatus.TOOL_ERROR  # SAT without a valid valuation is rejected for either intent.


def test_independent_model_validation_checks_query_domains_and_types() -> None:
    encoded = SMTEncoder().encode(spec(), "x <= 5")
    valid_violation = Counterexample((ModelAssignment("x", 6, "integer"),))
    valid_property_sat = Counterexample((ModelAssignment("x", 5, "integer"),))
    corrupted = Counterexample((ModelAssignment("x", 5, "integer"),))
    wrong_type = Counterexample((ModelAssignment("x", True, "integer"),))
    out_of_bounds = Counterexample((ModelAssignment("x", 11, "integer"),))
    assert validate_model(encoded, valid_violation) == (True, None)
    assert not validate_model(encoded, corrupted)[0]
    assert not validate_model(encoded, wrong_type)[0]
    assert not validate_model(encoded, out_of_bounds)[0]
    satisfiability = SMTEncoder().encode(spec(), "x <= 5", query_intent=QueryIntent.SATISFIABILITY)
    assert validate_model(satisfiability, valid_property_sat) == (True, None)


def test_real_and_boolean_models_are_reconstructed_safely() -> None:
    specification = Specification("1.0", "typed", "Typed", variables=(
        Variable("ratio", Domain(type="number", minimum=0.5, maximum=2.5)),
        Variable("flag", Domain(type="boolean")),
    ))
    query = SMTEncoder().encode(specification, "flag && ratio > 1.0", query_intent=QueryIntent.SATISFIABILITY)
    assert validate_model(query, Counterexample((
        ModelAssignment("flag", True, "boolean"), ModelAssignment("ratio", "3/2", "number"),
    ))) == (True, None)
    assert not validate_model(query, Counterexample((
        ModelAssignment("flag", "true", "boolean"), ModelAssignment("ratio", 1.5, "number"),
    )))[0]


def test_smt_verifier_rejects_backend_sat_with_corrupt_model_without_retry() -> None:
    class CorruptBackend:
        def __init__(self):
            self.calls = 0

        def solve(self, query, specification=None, *, timeout_seconds=None):
            self.calls += 1
            return BackendResult(SolverOutcome.SAT,
                Counterexample((ModelAssignment("x", 5, "integer"),)), backend="corrupt")

    backend = CorruptBackend()
    check = SMTVerifier(backend).check(spec(), "x <= 5")
    assert backend.calls == 1
    assert check.solver_outcome is SolverOutcome.ERROR
    assert check.result.status is VerificationStatus.TOOL_ERROR
    assert check.result.reason_code == "SOLVER_INVALID_MODEL"
    assert check.backend_result.model.assignments[0].value == 5


def test_model_evaluator_rejects_unsupported_operator_without_execution() -> None:
    from dataclasses import replace

    query = SMTEncoder().encode(spec(), "x <= 5")
    unsupported = replace(query, query_expression=Binary("/", Literal(1), Literal(0)))
    assert not validate_model(unsupported, Counterexample((ModelAssignment("x", 6, "integer"),)))[0]


def test_real_backend_violation_emits_hashed_counterexample_evidence(tmp_path) -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    store = ArtifactStore(tmp_path)
    check = SMTVerifier().check(spec(), "x <= 5", property_id="P1", artifact_store=store)
    assert check.solver_outcome is SolverOutcome.SAT
    assert check.result.status is VerificationStatus.FAIL
    assert check.result.reason_code == "PROPERTY_VIOLATED"
    assert check.result.counterexample["assignments"]
    assert len(check.evidence) == 4
    for evidence in check.evidence:
        assert hashlib.sha256((tmp_path / evidence.path).read_bytes()).hexdigest() == evidence.hash
    assert set(check.result.evidence_ids) == {item.id for item in check.evidence}


def test_real_backend_unsat_is_scoped_pass_with_evidence(tmp_path) -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    check = SMTVerifier().check(spec(), "x <= 10", artifact_store=ArtifactStore(tmp_path))
    assert check.solver_outcome is SolverOutcome.UNSAT
    assert check.result.status is VerificationStatus.PASS
    assert check.result.reason_code == "NO_VIOLATION_IN_SMT_SCOPE"
    assert "one valuation" in check.result.scope.lower()
    assert len(check.evidence) == 3
    assert all(item.hash for item in check.evidence)


def test_real_bool_real_string_and_finite_domains_are_supported() -> None:
    pytest.importorskip("z3", reason="the declared production z3-solver backend is unavailable")
    specification = Specification(
        schema_version="1.0", id="typed", name="Typed domains",
        variables=(
            Variable("flag", Domain(type="boolean")),
            Variable("ratio", Domain(type="number", minimum=0.5, maximum=2.5)),
            Variable("mode", Domain(type="string", values=("off", "on"))),
        ),
    )
    check = SMTVerifier().check(
        specification, 'flag && ratio > 1.0 && mode == "on"',
        query_intent=QueryIntent.SATISFIABILITY,
    )
    assert check.solver_outcome is SolverOutcome.SAT
    assert check.result.status is VerificationStatus.INCONCLUSIVE  # satisfiability intent is not a property verdict
    model = {item["variable"]: item["value"] for item in check.backend_result.model.to_dict()["assignments"]}
    assert model["flag"] is True and model["mode"] == "on" and float(model["ratio"]) > 1.0
