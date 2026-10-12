from __future__ import annotations

import random

from seclab.fuzzing import (BranchConstraint, ConcolicGenerator, Corpus, CrashAnalyzer, FuzzInput,
                            InputKind, InputMinimizer, InputMutator, InputOrigin, boundary_values)
from seclab.specification.schema import Domain


def fuzz_input(data: bytes, name: str = "seed") -> FuzzInput:
    return FuzzInput(name, data, InputKind.BYTES, InputOrigin.SEED)


def test_corpus_deduplicates_content_and_orders_deterministically() -> None:
    corpus = Corpus((fuzz_input(b"a", "z"), fuzz_input(b"a", "other"), fuzz_input(b"b", "a")))
    assert len(corpus) == 2
    assert [entry.input.content_hash for entry in corpus.entries] == sorted(entry.input.content_hash for entry in corpus.entries)


def test_mutation_is_reproducible_bounded_and_safe_for_empty_input() -> None:
    parent = fuzz_input(b"")
    a = InputMutator(random.Random(7), max_input_size=8).mutate(parent, 1)
    b = InputMutator(random.Random(7), max_input_size=8).mutate(parent, 1)
    assert a.data == b.data
    assert a.size <= 8
    assert a.metadata["mutation_operator"]


def test_boundary_values_deduplicate_integer_edges_and_boolean() -> None:
    values = boundary_values(Domain(type="integer", minimum=0, maximum=2))
    assert values == (-1, 0, 1, 2, 3)
    assert boundary_values(Domain(type="boolean")) == (False, True)


def test_minimizer_preserves_identical_signature_and_bounds_attempts() -> None:
    signature = __import__("seclab.fuzzing", fromlist=["FailureSignature"]).FailureSignature("CRASH", exit_code=-6)
    result = InputMinimizer().minimize(fuzz_input(b"prefix-TRIGGER-suffix"), signature,
        lambda item: signature if b"TRIGGER" in item.data else None, max_executions=40)
    assert result.minimized
    assert result.input.data == b"TRIGGER"
    assert result.executions <= 40


def test_minimizer_stops_when_campaign_time_budget_expires() -> None:
    signature = __import__("seclab.fuzzing", fromlist=["FailureSignature"]).FailureSignature("CRASH")
    result = InputMinimizer().minimize(fuzz_input(b"long-input"), signature,
        lambda _item: None, max_executions=40, should_stop=lambda: True)
    assert result.executions == 0
    assert result.error == "TIME_BUDGET_EXHAUSTED"


def test_concolic_solver_generates_candidate_for_explicit_alternate_path() -> None:
    result = ConcolicGenerator().solve_alternate(BranchConstraint("x", ">", 10, "<="))
    assert result.supported
    assert result.reason_code == "CONCOLIC_CANDIDATE"
    assert result.input_values["x"] > 10


def test_nonzero_is_not_assumed_crash():
    from types import SimpleNamespace
    cmd = SimpleNamespace(exit_code=1, timed_out=False, allowed_exit_codes=(0,), stderr="")
    result = SimpleNamespace(command_result=cmd, observed=SimpleNamespace(stderr="", crashed=False),
                             executed=True, oracle_evaluation=SimpleNamespace(satisfied=None, checks=()))
    assert CrashAnalyzer().analyze(result).classification == "NONZERO_EXIT"


def test_abnormal_termination_is_distinct_and_signature_is_stable():
    from types import SimpleNamespace
    cmd = SimpleNamespace(exit_code=-6, timed_out=False, allowed_exit_codes=(0,), stderr="")
    check = SimpleNamespace(oracle_type=__import__("seclab.testing", fromlist=["OracleType"]).OracleType.NO_CRASH,
                            evaluated=True, satisfied=False)
    result = SimpleNamespace(command_result=cmd,
        observed=SimpleNamespace(stderr="", crashed=True), executed=True,
        oracle_evaluation=SimpleNamespace(satisfied=False, checks=(check,)))
    analysis = CrashAnalyzer().analyze(result)
    assert analysis.classification == "CRASH"
    assert analysis.signature.kind == "ABNORMAL_TERMINATION"
    assert analysis.finding
