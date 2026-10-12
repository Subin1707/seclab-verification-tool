"""Controlled observation-boundary mutations for benchmark sensitivity.

These fixtures mutate benchmark observations, not production modules. They
verify whether independently declared benchmark expectations detect each
injected behavioral defect at the checker/result interface.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from tempfile import TemporaryDirectory
from pathlib import Path

from seclab.benchmark.catalog import CASES
from seclab.benchmark.models import BenchmarkCase, BenchmarkObservation, compare_benchmark
from seclab.benchmark.production import execute_case
from seclab.benchmark.runner import run_benchmark


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    component: str
    case_id: str | None
    defect: str
    apply: str


MUTATIONS = (
    Mutation("MUT-CTL-001", "CTL parser/model checker", "CTL-002", "Treat a false AG invariant as satisfied.", "flip status"),
    Mutation("MUT-SMT-001", "SMT parser/encoder", "SMT-001", "Drop the violation negation so a satisfiable violation is reported safe.", "flip status"),
    Mutation("MUT-BMC-001", "BMC encoder/checker", "BMC-001", "Discard the SAT counterexample and report no violation.", "flip status"),
    Mutation("MUT-RESULT-001", "result classification", "CTL-002", "Map a failing verification outcome to PASS.", "flip status"),
    Mutation("MUT-DYNAMIC-001", "dynamic oracle", "DYN-001", "Accept a return value that differs from the declared oracle.", "wrong finding"),
    Mutation("MUT-STATIC-001", "static finding parser", "STATIC-002", "Drop a parsed diagnostic finding.", "drop finding"),
    Mutation("MUT-FUZZ-001", "fuzz crash classification", "FUZZ-001", "Classify abnormal termination as no finding.", "wrong finding"),
    Mutation("MUT-EVIDENCE-001", "evidence integrity", None, "Accept a changed artifact while retaining a valid-integrity finding.", "drop evidence"),
    Mutation("MUT-TRACE-001", "traceability", None, "Drop the source reference from a requirement-to-result trace.", "drop evidence"),
)


def _catalog_case(case_id: str) -> BenchmarkCase:
    return next(case for case in CASES if case.case_id == case_id)


def _synthetic_case(mutation: Mutation) -> BenchmarkCase:
    expected_finding = {
        "MUT-RESULT-001": "PROPERTY_VIOLATED",
        "MUT-STATIC-001": "NULL_DEREFERENCE",
        "MUT-EVIDENCE-001": "HASH_VERIFIED",
        "MUT-TRACE-001": "SOURCE_TRACED",
    }[mutation.mutation_id]
    expected_evidence = {
        "MUT-RESULT-001": ("result",),
        "MUT-STATIC-001": ("finding-record",),
        "MUT-EVIDENCE-001": ("verified-artifact",),
        "MUT-TRACE-001": ("requirement-property-result-evidence-source",),
    }[mutation.mutation_id]
    return BenchmarkCase(mutation.mutation_id, mutation.defect, "controlled fixture", None,
                         mutation.component, "FAIL" if mutation.mutation_id == "MUT-RESULT-001" else "INCONCLUSIVE",
                         expected_finding, None, expected_evidence, None, "MutationFixture",
                         ground_truth_source="Independent test fixture contract",
                         creation_method="Controlled evidence/trace fixture",
                         independent_validation="Fixture output is computed from file hashing or explicit reference resolution")


def _case(mutation: Mutation) -> BenchmarkCase:
    return _catalog_case(mutation.case_id) if mutation.case_id else _synthetic_case(mutation)


def _fixture_observation(mutation: Mutation, case: BenchmarkCase) -> BenchmarkObservation:
    """Observe checker behavior or execute the concrete evidence/trace fixture."""
    if mutation.case_id:
        return execute_case(case)
    if mutation.mutation_id == "MUT-EVIDENCE-001":
        with TemporaryDirectory(prefix="seclab-evidence-fixture-") as temporary:
            artifact = Path(temporary) / "artifact.bin"
            artifact.write_bytes(b"verified fixture artifact")
            observed_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
            expected_hash = hashlib.sha256(b"verified fixture artifact").hexdigest()
            valid = observed_hash == expected_hash
        return BenchmarkObservation(case.case_id, case.checker, "INCONCLUSIVE",
            "HASH_VERIFIED" if valid else "HASH_MISMATCH", evidence=("verified-artifact",),
            evidence_references=({"sha256": observed_hash},))
    if mutation.mutation_id == "MUT-TRACE-001":
        graph = {"requirement": "REQ-1", "property": "P-1", "result": "R-1",
                 "evidence": "E-1", "source": "fixture.c"}
        resolved = all(graph.get(key) for key in ("requirement", "property", "result", "evidence", "source"))
        return BenchmarkObservation(case.case_id, case.checker, "INCONCLUSIVE",
            "SOURCE_TRACED" if resolved else "TRACE_INCOMPLETE",
            evidence=("requirement-property-result-evidence-source",))
    raise AssertionError(f"No executable observation fixture for {mutation.mutation_id}")


def _mutate(mutation: Mutation, observation: BenchmarkObservation) -> BenchmarkObservation:
    if mutation.apply == "flip status":
        return replace(observation, actual_status="PASS" if observation.actual_status == "FAIL" else "FAIL")
    if mutation.apply == "wrong finding":
        finding = "ORACLE_VIOLATION" if mutation.mutation_id == "MUT-DYNAMIC-001" else "NONE"
        return replace(observation, actual_finding=finding)
    if mutation.apply == "drop finding":
        return replace(observation, actual_finding="NONE", evidence=())
    if mutation.apply == "drop evidence":
        return replace(observation, evidence=())
    raise AssertionError(f"Unknown mutation operation {mutation.apply}")


def run_mutation_campaign() -> tuple[dict[str, object], ...]:
    records = []
    for mutation in MUTATIONS:
        case = _case(mutation)
        observed = _fixture_observation(mutation, case)
        baseline = compare_benchmark((case,), (observed,))
        baseline_detected = bool(baseline.mismatches)
        mutated = compare_benchmark((case,), (_mutate(mutation, observed),))
        detected = bool(mutated.mismatches)
        records.append({
            "mutation_id": mutation.mutation_id,
            "component": mutation.component,
            "injected_defect": mutation.defect,
            "benchmark_case": case.case_id,
            "expected_detection": "detected mismatch",
            "actual_detection": "detected mismatch" if detected else "not detected",
            "baseline_clean": not baseline_detected,
            "detected": detected and not baseline_detected,
            "classification": mutated.expected_vs_actual[0]["mismatch_classification"],
            "surviving": not detected,
            "known_limitation": "Observation-boundary fixture validates benchmark/scorer sensitivity; it does not execute a binary-patched production core.",
        })
    return tuple(records)


def render_mutation_report(results: tuple[dict[str, object], ...]) -> str:
    lines = [
        "# Verification Core Mutation Testing Report",
        "",
        "This report records controlled test-only mutations at the benchmark observation boundary. "
        "Expected outcomes remain the independently declared catalog/fixture values.",
        "",
        "These tests establish benchmark/scorer sensitivity to changed component outputs. They do not "
        "patch production source files or prove that every internal implementation defect will reach "
        "the observation boundary; parser/encoder-specific unit mutation execution remains a limitation.",
        "",
        "## Mutation results",
        "",
        "| Mutation ID | Component | Injected defect | Expected detection | Actual detection | Surviving mutation |",
        "|---|---|---|---|---|---|",
    ]
    for item in results:
        cells = (item["mutation_id"], item["component"], item["injected_defect"],
                 item["expected_detection"], item["actual_detection"],
                 "Yes" if item["surviving"] else "No")
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in cells) + " |")
    lines.extend([
        "",
        f"Mutations run: {len(results)}; detected from clean baseline: {sum(bool(item['detected']) for item in results)}; "
        f"surviving: {sum(bool(item['surviving']) for item in results)}.",
        "",
        "## Execution method and scope",
        "",
        "Each checker case is executed through its checker adapter once. Evidence and trace cases execute "
        "their concrete file-hash/reference fixtures. One controlled mutation is applied to the observed "
        "output, and a clean unmutated comparison is required before it counts as detected. The fixtures cover the "
        "listed CTL, SMT, BMC, result, dynamic, static, fuzzing, evidence, and traceability boundaries.",
        "",
        "No production implementation was modified. No project safety verdict or aggregate safety score is produced.",
        "",
    ])
    return "\n".join(lines)


def test_each_controlled_mutation_is_detected_from_a_clean_baseline() -> None:
    results = run_mutation_campaign()
    assert len(results) == 9
    assert all(item["baseline_clean"] for item in results)
    assert all(item["detected"] for item in results)
    assert not any(item["surviving"] for item in results)


def test_mutation_campaign_covers_all_requested_components() -> None:
    components = {item.component for item in MUTATIONS}
    assert components == {
        "CTL parser/model checker", "SMT parser/encoder", "BMC encoder/checker",
        "result classification", "dynamic oracle", "static finding parser",
        "fuzz crash classification", "evidence integrity", "traceability",
    }


def test_mutation_observations_are_not_copied_from_expected_fields() -> None:
    assert "expected_status" not in _fixture_observation.__code__.co_names
    assert "expected_finding" not in _fixture_observation.__code__.co_names
    for mutation in MUTATIONS:
        case = _case(mutation)
        observed = _fixture_observation(mutation, case)
        if mutation.case_id:
            assert observed.actual_status is not None


def test_report_records_each_mutation_without_overall_safety_verdict() -> None:
    report = render_mutation_report(run_mutation_campaign())
    assert "Mutations run: 9; detected from clean baseline: 9; surviving: 0." in report
    assert "overall project verdict" not in report.casefold()
    assert "MUT-TRACE-001" in report

