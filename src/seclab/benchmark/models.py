"""Ground-truth records and per-checker benchmark scoring."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Any, Iterable, Mapping
from pathlib import Path


PASS_FAIL = frozenset({"PASS", "FAIL"})
NON_BINARY = frozenset({"INCONCLUSIVE", "UNSUPPORTED", "TOOL_ERROR", "SPEC_ERROR", "BUILD_ERROR",
                        "SKIPPED", "ENVIRONMENT_LIMITED"})
MISMATCH_CLASSIFICATIONS = frozenset({
    "TRUE_POSITIVE", "TRUE_NEGATIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE",
    "INCONCLUSIVE", "UNSUPPORTED", "ENVIRONMENT_LIMITED", "TOOL_ERROR", "BUILD_ERROR",
    "SKIPPED", "SPECIFICATION_ERROR",
})


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """An independently authored ground-truth case.

    ``expected_*`` values are catalog inputs and are never derived from an
    observation. The older field names remain available for compatibility.
    """

    benchmark_id: str
    description: str
    source: str | None
    specification: Mapping[str, Any] | None
    expected_checker: str
    expected_status: str
    expected_finding: str | None
    expected_property: str | None
    expected_evidence: tuple[str, ...]
    known_limitation: str | None
    category: str
    scenario: Mapping[str, Any] = field(default_factory=dict)
    ground_truth_source: str = "Manually verified synthetic fixture semantics"
    creation_method: str = "Synthetic fixture with declared behavior"
    independent_validation: str = "Manual semantic derivation; checker output is not used"

    def __post_init__(self) -> None:
        if not self.benchmark_id or not self.description or not self.expected_checker or not self.category:
            raise ValueError("case_id, description, checker and category are required")
        allowed = PASS_FAIL | NON_BINARY
        if self.expected_status not in allowed:
            raise ValueError(f"Unsupported expected status {self.expected_status!r}")
        if self.expected_status == "PASS" and self.expected_finding not in (None, "NONE"):
            raise ValueError("A passing case cannot expect a finding")
        if self.category.casefold() == "coverage" and self.expected_status in PASS_FAIL:
            raise ValueError("Coverage is measurement-only and cannot have PASS/FAIL ground truth")
        object.__setattr__(self, "specification", _freeze(self.specification) if self.specification is not None else None)
        object.__setattr__(self, "scenario", _freeze(self.scenario))
        object.__setattr__(self, "expected_evidence", tuple(self.expected_evidence))
        if not self.ground_truth_source.strip() or not self.creation_method.strip() or not self.independent_validation.strip():
            raise ValueError("ground-truth provenance fields are required")

    @property
    def case_id(self) -> str:
        return self.benchmark_id

    @property
    def checker(self) -> str:
        return self.expected_checker

    @property
    def input(self) -> Mapping[str, Any]:
        """Serializable checker input declared by the catalog."""
        return {
            "source": self.source,
            "specification": _thaw(self.specification),
            "parameters": _thaw(self.scenario),
        }

    @property
    def expected_evidence_type(self) -> tuple[str, ...]:
        return self.expected_evidence

    @property
    def known_environment_limitation(self) -> str | None:
        return self.known_limitation

    def to_dict(self) -> dict[str, Any]:
        fixture_sha256 = _sha256(self.input)
        ground_truth = {
            "case_id": self.case_id,
            "fixture_sha256": fixture_sha256,
            "status": self.expected_status,
            "finding": self.expected_finding,
            "property": self.expected_property,
            "evidence": list(self.expected_evidence),
            "source": self.ground_truth_source,
            "creation_method": self.creation_method,
            "independent_validation": self.independent_validation,
        }
        catalog_path = Path(__file__).with_name("catalog.py")
        catalog_sha256 = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
        return {
            "case_id": self.case_id,
            "checker": self.checker,
            "description": self.description,
            "input": self.input,
            "expected_status": self.expected_status,
            "expected_finding": self.expected_finding,
            "expected_evidence_type": list(self.expected_evidence_type),
            "known_environment_limitation": self.known_environment_limitation,
            "expected_property": self.expected_property,
            "category": self.category,
            "fixture_sha256": fixture_sha256,
            "ground_truth": ground_truth,
            "ground_truth_sha256": _sha256(ground_truth),
            "ground_truth_catalog_sha256": catalog_sha256,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkObservation:
    """One actual checker observation. It never supplies or edits ground truth."""

    benchmark_id: str
    actual_checker: str | None
    actual_status: str | None
    actual_finding: str | None = None
    actual_property: str | None = None
    evidence: tuple[str, ...] = ()
    unsupported_reason: str | None = None
    error: str | None = None
    evidence_references: tuple[Mapping[str, Any], ...] = ()
    evidence_payloads: tuple[Mapping[str, Any], ...] = ()

    @property
    def case_id(self) -> str:
        return self.benchmark_id

    @property
    def actual_evidence(self) -> tuple[str, ...]:
        return self.evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "actual_checker": self.actual_checker,
            "actual_status": self.actual_status,
            "actual_finding": self.actual_finding,
            "actual_property": self.actual_property,
            "actual_evidence": list(self.actual_evidence),
            "unsupported_reason": self.unsupported_reason,
            "error": self.error,
            "evidence_references": [_thaw(item) for item in self.evidence_references],
            "evidence_payloads": [_json_safe(_thaw(item)) for item in self.evidence_payloads],
        }


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    benchmark_count: int
    expected_vs_actual: tuple[Mapping[str, Any], ...]
    mismatches: tuple[str, ...]
    false_positives: tuple[str, ...]
    false_negatives: tuple[str, ...]
    inconclusive: tuple[str, ...]
    unsupported: tuple[str, ...]
    checker_metrics: Mapping[str, Mapping[str, int | float | None]] = field(default_factory=dict)
    tool_errors: tuple[str, ...] = ()
    build_errors: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    environment_limited: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_count": self.benchmark_count,
            "metric_scope": "FIXTURE_LEVEL_ONLY",
            "accuracy_claim": "Observed behavior on catalog fixtures only; not a general checker accuracy estimate.",
            "expected_vs_actual": [_thaw(row) for row in self.expected_vs_actual],
            "mismatches": list(self.mismatches),
            "false_positives": list(self.false_positives),
            "false_negatives": list(self.false_negatives),
            "inconclusive": list(self.inconclusive),
            "unsupported": list(self.unsupported),
            "tool_errors": list(self.tool_errors),
            "build_errors": list(self.build_errors),
            "skipped": list(self.skipped),
            "environment_limited": list(self.environment_limited),
            "checker_metrics": {checker: dict(metrics) for checker, metrics in self.checker_metrics.items()},
        }


def compare_benchmark(cases: Iterable[BenchmarkCase], observations: Iterable[BenchmarkObservation]) -> BenchmarkReport:
    """Compare observations with fixed expected outcomes and score per checker only."""
    cases = tuple(cases)
    observations = tuple(observations)
    case_map = {case.case_id: case for case in cases}
    observation_map = {item.case_id: item for item in observations}
    if len(case_map) != len(cases) or len(observation_map) != len(observations):
        raise ValueError("Duplicate benchmark IDs")
    if set(case_map) != set(observation_map):
        missing = sorted(set(case_map) - set(observation_map))
        extra = sorted(set(observation_map) - set(case_map))
        raise ValueError(f"Observation IDs differ from case IDs; missing={missing}, extra={extra}")

    rows: list[dict[str, Any]] = []
    mismatches: list[str] = []
    false_positives: list[str] = []
    false_negatives: list[str] = []
    inconclusive: list[str] = []
    unsupported: list[str] = []
    tool_errors: list[str] = []
    build_errors: list[str] = []
    skipped: list[str] = []
    environment_limited: list[str] = []
    counters: dict[str, dict[str, int]] = {}

    for case_id in sorted(case_map):
        case, actual = case_map[case_id], observation_map[case_id]
        status_match = actual.actual_status == case.expected_status
        checker_match = actual.actual_checker == case.expected_checker
        finding_match = case.expected_finding is None or actual.actual_finding == case.expected_finding
        # An adapter that did not observe a property identity reports None. That
        # is unavailable metadata, not evidence that the checker used a different
        # property; retain the null for audit without penalizing the observation.
        property_match = (case.expected_property is None or actual.actual_property is None
                          or actual.actual_property == case.expected_property)
        evidence_match = set(case.expected_evidence_type) <= set(actual.actual_evidence)
        matched = status_match and checker_match and finding_match and property_match and evidence_match
        classification = _classify(case, actual)
        if classification not in MISMATCH_CLASSIFICATIONS:
            raise AssertionError(f"Invalid benchmark classification {classification!r}")
        if not matched:
            mismatches.append(case_id)

        if actual.actual_status == "INCONCLUSIVE" or classification == "INCONCLUSIVE":
            inconclusive.append(case_id)
        if classification == "FALSE_POSITIVE":
            false_positives.append(case_id)
        elif classification == "FALSE_NEGATIVE":
            false_negatives.append(case_id)
        elif classification in {"UNSUPPORTED", "ENVIRONMENT_LIMITATION"}:
            unsupported.append(case_id)
        elif classification == "ENVIRONMENT_LIMITED":
            environment_limited.append(case_id)
        elif classification == "TOOL_ERROR":
            tool_errors.append(case_id)
        elif classification == "BUILD_ERROR":
            build_errors.append(case_id)
        elif classification == "SKIPPED":
            skipped.append(case_id)

        metric = counters.setdefault(case.checker, {
            "cases": 0, "TP": 0, "TN": 0, "FP": 0, "FN": 0,
            "inconclusive": 0, "unsupported": 0, "environment_limited": 0,
            "tool_errors": 0, "build_errors": 0, "cases_skipped": 0,
        })
        metric["cases"] += 1
        if classification in {"TRUE_POSITIVE", "TRUE_NEGATIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE"}:
            metric[{"TRUE_POSITIVE": "TP", "TRUE_NEGATIVE": "TN",
                    "FALSE_POSITIVE": "FP", "FALSE_NEGATIVE": "FN"}[classification]] += 1
        elif classification == "INCONCLUSIVE":
            metric["inconclusive"] += 1
        elif classification in {"UNSUPPORTED", "ENVIRONMENT_LIMITED", "ENVIRONMENT_LIMITATION"}:
            metric["environment_limited" if classification in {"ENVIRONMENT_LIMITED", "ENVIRONMENT_LIMITATION"} else "unsupported"] += 1
        elif classification == "TOOL_ERROR":
            metric["tool_errors"] += 1
        elif classification == "BUILD_ERROR":
            metric["build_errors"] += 1
        elif classification == "SKIPPED":
            metric["cases_skipped"] += 1
        if actual.actual_status == "INCONCLUSIVE" and classification != "INCONCLUSIVE":
            # Static analyzers expose a finding signal while their scoped safety
            # result remains INCONCLUSIVE. Preserve both facts independently.
            metric["inconclusive"] += 1

        rows.append({
            **case.to_dict(),
            "benchmark_id": case.case_id,
            "metric_scope": "FIXTURE_LEVEL_ONLY",
            "expected_checker": case.checker,
            "expected_property": case.expected_property,
            "expected_evidence": list(case.expected_evidence_type),
            "known_limitation": case.known_environment_limitation,
            "actual_case": actual.to_dict(),
            "actual_checker": actual.actual_checker,
            "actual_status": actual.actual_status,
            "actual_finding": actual.actual_finding,
            "actual_property": actual.actual_property,
            "actual_evidence": list(actual.actual_evidence),
            "mismatch_classification": classification,
            "mismatch_cause": _mismatch_cause(case, actual, status_match, checker_match,
                                                finding_match, property_match, evidence_match),
            "expected": {"checker": case.checker, "status": case.expected_status,
                         "finding": case.expected_finding, "property": case.expected_property,
                         "evidence": list(case.expected_evidence_type),
                         "fixture_sha256": case.to_dict()["fixture_sha256"],
                         "ground_truth_sha256": case.to_dict()["ground_truth_sha256"],
                         "ground_truth_source": case.ground_truth_source,
                         "creation_method": case.creation_method,
                         "independent_validation": case.independent_validation},
            "actual": {"checker": actual.actual_checker, "status": actual.actual_status,
                       "finding": actual.actual_finding, "property": actual.actual_property,
                       "evidence": list(actual.actual_evidence),
                       "evidence_references": [_thaw(item) for item in actual.evidence_references],
                       "unsupported_reason": actual.unsupported_reason, "error": actual.error},
            "matched": matched,
        })

    metrics: dict[str, dict[str, int | float | None]] = {}
    for checker, counts in sorted(counters.items()):
        tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
        conclusive_positive = tp + fp
        conclusive_negative = tn + fn
        conclusive = tp + tn + fp + fn
        total = counts["cases"]
        catalog_positive = sum(case.checker == checker and _expected_detection(case) is True for case in cases)
        catalog_negative = sum(case.checker == checker and _expected_detection(case) is False for case in cases)
        metric_ready = (tp + fn) > 0 and (tn + fp) > 0
        metrics[checker] = {
            **counts,
            "true_positive": tp, "true_negative": tn,
            "false_positive": fp, "false_negative": fn,
            "accuracy": _ratio(tp + tn, conclusive) if metric_ready else None,
            "metrics_ready": metric_ready,
            "catalog_has_both_classes": catalog_positive > 0 and catalog_negative > 0,
            "ground_truth_positive_cases": catalog_positive,
            "ground_truth_negative_cases": catalog_negative,
            "precision": _ratio(tp, conclusive_positive) if metric_ready else None,
            "recall": _ratio(tp, tp + fn) if metric_ready else None,
            "specificity": _ratio(tn, tn + fp) if metric_ready else None,
            "false_positive_rate": _ratio(fp, tn + fp) if metric_ready else None,
            "false_negative_rate": _ratio(fn, tp + fn) if metric_ready else None,
            "inconclusive_rate": _ratio(counts["inconclusive"], total),
            "unsupported_rate": _ratio(counts["unsupported"], total),
            "environment_limited_rate": _ratio(counts["environment_limited"], total),
            "tool_error_rate": _ratio(counts["tool_errors"], total),
            "build_error_rate": _ratio(counts["build_errors"], total),
            "skipped_rate": _ratio(counts["cases_skipped"], total),
            "conclusive_rate": _ratio(conclusive, total),
        }

    return BenchmarkReport(len(rows), tuple(rows), tuple(mismatches), tuple(false_positives),
                           tuple(false_negatives), tuple(inconclusive), tuple(unsupported), metrics,
                           tuple(tool_errors), tuple(build_errors), tuple(skipped), tuple(environment_limited))


def _classify(case: BenchmarkCase, actual: BenchmarkObservation) -> str:
    status = actual.actual_status
    if status == "ENVIRONMENT_LIMITED":
        return "ENVIRONMENT_LIMITED"
    if status == "SKIPPED":
        return "SKIPPED"
    if status == "TOOL_ERROR":
        return "TOOL_ERROR"
    if status == "BUILD_ERROR":
        return "BUILD_ERROR"
    if status == "UNSUPPORTED":
        return "UNSUPPORTED"
    if status == "INCONCLUSIVE" and case.category.casefold() == "static":
        expected_positive = _expected_detection(case)
        actual_positive = _actual_detection(actual)
        if expected_positive is not None and actual_positive is not None:
            if expected_positive and actual_positive: return "TRUE_POSITIVE"
            if not expected_positive and not actual_positive: return "TRUE_NEGATIVE"
            if not expected_positive and actual_positive: return "FALSE_POSITIVE"
            return "FALSE_NEGATIVE"
        return "INCONCLUSIVE"
    if status == "INCONCLUSIVE" or status is None:
        return "INCONCLUSIVE"
    if status == "SPEC_ERROR" or case.expected_status == "SPEC_ERROR":
        return "SPECIFICATION_ERROR"
    # Coverage is a measurement only. A coverage adapter reporting PASS/FAIL is
    # a contract error, not a safety true/false observation.
    if case.category.casefold() == "coverage":
        return "SPECIFICATION_ERROR"
    if case.expected_status not in PASS_FAIL or status not in PASS_FAIL:
        return "UNSUPPORTED"
    expected_positive = _expected_detection(case)
    actual_positive = _actual_detection(actual)
    if expected_positive is None or actual_positive is None:
        return "INCONCLUSIVE"
    if expected_positive and actual_positive:
        return "TRUE_POSITIVE"
    if not expected_positive and not actual_positive:
        return "TRUE_NEGATIVE"
    if not expected_positive and actual_positive:
        return "FALSE_POSITIVE"
    return "FALSE_NEGATIVE"


def _expected_detection(case: BenchmarkCase) -> bool | None:
    if case.category.casefold() == "coverage":
        return None
    if case.expected_status == "PASS":
        return False
    if case.expected_status == "FAIL":
        return True
    if case.category.casefold() == "static" and case.expected_finding is not None:
        return case.expected_finding not in {"NONE", "NO_FINDING"}
    return None


def _actual_detection(actual: BenchmarkObservation) -> bool | None:
    if actual.actual_finding is None:
        return None
    return actual.actual_finding not in {"NONE", "NO_FINDING"}


def _mismatch_cause(case: BenchmarkCase, actual: BenchmarkObservation, status_match: bool,
                    checker_match: bool, finding_match: bool, property_match: bool,
                    evidence_match: bool) -> str | None:
    if status_match and checker_match and finding_match and property_match and evidence_match:
        return None
    return _classify(case, actual)


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _sha256(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "value"):
        return _json_safe(value.value)
    if hasattr(value, "to_dict"):
        return _json_safe(value.to_dict())
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import fields
        return {field.name: _json_safe(getattr(value, field.name)) for field in fields(value)}
    return str(value)
