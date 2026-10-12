"""Evidence-linked checker cross-check matrix with no aggregate verdict."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Iterable


class CrossCheckStatus(StrEnum):
    LINKED = "LINKED"
    CONSISTENT = "CONSISTENT"
    INCONSISTENCY = "INCONSISTENCY"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    UNRESOLVED = "UNRESOLVED"


def json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_safe(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return json_safe(value.to_dict())
    if isinstance(value, StrEnum):
        return value.value
    return value


def build_cross_check_matrix(ctx: Any) -> dict[str, Any]:
    """Build links only from declared IDs, source hashes, or explicit comparison keys."""
    artifacts = {item.id: item for item in ctx.artifact_store.all()}
    results = tuple(ctx.result_collector.all())
    properties = {item.id: item for item in getattr(ctx.specification, "properties", ())}
    cases = {item.id: item for item in getattr(ctx, "test_cases", ())}
    formal = [item for item in results if item.technique.upper() in {"CTL", "BMC", "SMT"}]
    dynamic = [item for item in results if item.stage.upper() == "DYNAMIC_TEST"]
    model = getattr(ctx, "kripke", None)
    inventory = getattr(ctx, "source_metadata", {}) or {}
    source_hashes = {item.get("project_relative_path"): item.get("sha256")
                     for item in inventory.get("files", ()) if item.get("project_relative_path")}
    state_map = {}
    transition_map = {}

    relation_rows: list[dict[str, Any]] = []

    def relation(name: str, source: str, target: str, status: CrossCheckStatus,
                 mappings: list[dict[str, Any]], *, evidence_ids: Iterable[str] = (),
                 note: str = "") -> None:
        ids = tuple(dict.fromkeys(evidence_ids))
        relation_rows.append({"id": name, "from": source, "to": target, "status": status.value,
            "mappings": mappings, "evidence_ids": list(ids),
            "evidence": [_evidence_ref(artifacts[item]) for item in ids if item in artifacts],
            "note": note})

    model_evidence = [item.id for item in artifacts.values() if item.stage == "model"]
    relation("SPECIFICATION_MODEL", "SPECIFICATION", "MODEL",
        CrossCheckStatus.LINKED if ctx.specification is not None and model is not None else CrossCheckStatus.UNRESOLVED,
        ([{"specification_id": ctx.specification.id, "model_hash": model.model_hash,
           "state_ids": list(model.state_ids), "transition_ids": list(model.transition_ids)}]
         if ctx.specification is not None and model is not None else []), evidence_ids=model_evidence,
        note="Declared specification graph is linked to its canonical model; this does not claim source equivalence.")

    function_links = list(inventory.get("function_links", ()))
    matched_functions = [item for item in function_links if item.get("match_status") == "MATCHED"]
    relation("SPECIFICATION_SOURCE", "SPECIFICATION", "SOURCE",
        CrossCheckStatus.LINKED if matched_functions else CrossCheckStatus.UNRESOLVED,
        [{"function_id": item.get("function_id"), "source_id": item.get("source_id"),
          "path": item.get("source_relative_path"), "requirement_ids": item.get("requirement_ids", [])}
         for item in matched_functions],
        evidence_ids=[item.id for item in artifacts.values() if item.stage == "source"],
        note="Only uniquely matched declared functions are linked.")

    state_links = [{"source_id": key, "state_ids": list(value)} for key, value in state_map.items()]
    transition_links = [{"source_id": key, "transition_ids": list(value)} for key, value in transition_map.items()]
    relation("MODEL_SOURCE", "MODEL", "SOURCE",
        CrossCheckStatus.LINKED if state_links or transition_links else CrossCheckStatus.UNRESOLVED,
        state_links + transition_links,
        evidence_ids=[item.id for item in artifacts.values() if item.stage in {"model", "source"}],
        note="Verification models are derived from Specification states and transitions, never project source.")

    dynamic_source_mappings: list[dict[str, Any]] = []
    dynamic_source_conflicts: list[dict[str, Any]] = []
    dynamic_source_evidence: list[str] = []
    executions = {item.execution_id: item for item in getattr(ctx, "dynamic_results", ())}
    for result in dynamic:
        execution = executions.get(result.metadata.get("execution_id"))
        if execution is None or not execution.executed or execution.observed is None:
            continue
        actual_hashes = dict(result.metadata.get("source_sha256", {}))
        if not actual_hashes:
            continue
        compared = []
        for path, digest in actual_hashes.items():
            normalized = str(path).replace("\\", "/")
            source_digest = source_hashes.get(normalized)
            if source_digest is not None:
                compared.append({"path": normalized, "source_sha256": source_digest,
                                 "dynamic_sha256": digest})
                if source_digest != digest:
                    dynamic_source_conflicts.append({"result_id": result.id, **compared[-1]})
        if compared:
            dynamic_source_mappings.append({"result_id": result.id, "test_case_id": result.metadata.get("test_case_id"),
                                            "files": compared,
                                            "source_integrity_unchanged": result.metadata.get("source_integrity_unchanged")})
            dynamic_source_evidence.extend(result.evidence_ids)
    dynamic_source_status = (CrossCheckStatus.INCONSISTENCY if dynamic_source_conflicts or any(
        item.get("source_integrity_unchanged") is False for item in dynamic_source_mappings) else
        CrossCheckStatus.LINKED if dynamic_source_mappings else CrossCheckStatus.UNRESOLVED)
    relation("SOURCE_DYNAMIC", "SOURCE", "DYNAMIC", dynamic_source_status,
        [{"runs": dynamic_source_mappings, "conflicts": dynamic_source_conflicts}],
        evidence_ids=dynamic_source_evidence + [item.id for item in artifacts.values() if item.stage == "source"],
        note="Source hash equality links a testcase execution to the discovered source snapshot.")

    spec_tests = {item.id: item for item in getattr(ctx.specification, "tests", ())}
    spec_dynamic = []
    for case_id, case in cases.items():
        test_spec = spec_tests.get(case_id)
        reqs = tuple(getattr(test_spec, "requirement_ids", ())) if test_spec else tuple(case.metadata.get("requirement_ids", ()))
        if test_spec or reqs or case.property_id:
            spec_dynamic.append({"test_case_id": case_id, "property_id": case.property_id,
                                 "requirement_ids": list(reqs),
                                 "specification_test_id": test_spec.id if test_spec else None})
    relation("SPECIFICATION_DYNAMIC", "SPECIFICATION", "DYNAMIC",
        CrossCheckStatus.LINKED if spec_dynamic else CrossCheckStatus.UNRESOLVED, spec_dynamic,
        evidence_ids=[item.id for item in artifacts.values() if item.stage in {"tests", "observations", "executions"}],
        note="Only matching declared testcase IDs, requirement IDs, or explicit property IDs are linked.")

    spec_formal = [{"property_id": item.property_id, "result_id": item.id, "technique": item.technique,
                    "status": item.status.value}
                   for item in formal if item.property_id in properties]
    relation("SPECIFICATION_FORMAL", "SPECIFICATION", "FORMAL",
        CrossCheckStatus.LINKED if spec_formal else CrossCheckStatus.UNRESOLVED, spec_formal,
        evidence_ids=[item for row in spec_formal for item in next(
            (result.evidence_ids for result in formal if result.id == row["result_id"]), ())],
        note="Formal results link by declared property ID; each technique retains its own verdict and scope.")

    model_formal = [{"result_id": item.id, "technique": item.technique,
                     "result_model_hash": item.metadata.get("model_hash"),
                     "canonical_model_hash": model.model_hash if model is not None else None,
                     "comparable": item.technique.upper() in {"CTL", "BMC"}}
                    for item in formal if item.technique.upper() in {"CTL", "BMC", "SMT"}]
    relation("MODEL_FORMAL", "MODEL", "FORMAL",
        (CrossCheckStatus.LINKED if any(row["comparable"] and row["result_model_hash"] == row["canonical_model_hash"]
                                       for row in model_formal) else
         CrossCheckStatus.NOT_COMPARABLE if any(row["technique"].upper() == "SMT" for row in model_formal)
         else CrossCheckStatus.UNRESOLVED), model_formal,
        evidence_ids=[item for result in formal for item in result.evidence_ids],
        note="CTL/BMC results are model-scoped; SMT checks a valuation and is not treated as a Kripke-model check.")

    explicit_pairs, conflicts = _explicit_dynamic_formal_comparisons(dynamic, cases, formal, properties)
    dynamic_formal_status = (CrossCheckStatus.INCONSISTENCY if conflicts else
        CrossCheckStatus.CONSISTENT if explicit_pairs and all(item["comparison"] == "AGREE" for item in explicit_pairs) else
        CrossCheckStatus.NOT_COMPARABLE if explicit_pairs else CrossCheckStatus.UNRESOLVED)
    relation("DYNAMIC_FORMAL", "DYNAMIC", "FORMAL", dynamic_formal_status,
        [{"comparisons": explicit_pairs, "conflicts": conflicts}],
        evidence_ids=[item for row in explicit_pairs + conflicts for item in row.get("evidence_ids", ())],
        note="Verdicts are compared only when both sides declare the same cross_check_key for the same claim.")

    checker_records = [_checker_record(result, artifacts, ctx) for result in results]
    fuzz_campaigns = [item.to_dict() for item in getattr(ctx, "fuzz_results", ())]
    coverage = getattr(ctx, "coverage_report", None)
    measurements = []
    if coverage is not None:
        measurements.append({"id": "COVERAGE", "kind": "COVERAGE_MEASUREMENT",
            "measurement_only": True, "measurement_sha256": coverage.measurement_sha256,
            "backend": coverage.backend, "complete": coverage.complete, "partial": coverage.partial,
            "tests_executed": coverage.tests_executed, "test_case_ids": list(coverage.test_case_ids),
            "source_files": list(coverage.source_files), "line_metrics": coverage.line_metrics.to_dict(),
            "branch_metrics": coverage.branch_metrics.to_dict(),
            "evidence_ids": list(coverage.evidence_ids),
            "evidence": [_evidence_ref(artifacts[item]) for item in coverage.evidence_ids if item in artifacts]})
    return {"format": "seclab-cross-check-matrix-v1", "run_id": ctx.run_id,
        "aggregation": "NONE",
        "layers": {"SPECIFICATION": bool(ctx.specification is not None), "MODEL": bool(model is not None),
                   "SOURCE": bool(inventory.get("files")), "DYNAMIC": bool(dynamic), "FORMAL": bool(formal)},
        "relations": relation_rows,
        "inconsistencies": [row for row in relation_rows if row["status"] == CrossCheckStatus.INCONSISTENCY.value],
        "checker_records": checker_records, "measurements": measurements,
        "bounded_campaigns": fuzz_campaigns}


def _explicit_dynamic_formal_comparisons(dynamic: list[Any], cases: dict[str, Any], formal: list[Any],
                                         properties: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    comparisons: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for dynamic_result in dynamic:
        case = cases.get(dynamic_result.metadata.get("test_case_id"))
        if case is None:
            continue
        key = case.metadata.get("cross_check_key")
        if not isinstance(key, str) or not key:
            continue
        for formal_result in formal:
            prop = properties.get(formal_result.property_id)
            if prop is None or prop.metadata.get("cross_check_key") != key:
                continue
            left, right = dynamic_result.status.value, formal_result.status.value
            conclusive = left in {"PASS", "FAIL"} and right in {"PASS", "FAIL"}
            row = {"cross_check_key": key, "property_id": formal_result.property_id,
                   "test_case_id": case.id, "dynamic_result_id": dynamic_result.id,
                   "formal_result_id": formal_result.id,
                   "dynamic_status": left, "formal_status": right,
                   "comparison": ("AGREE" if left == right else "CONTRADICT") if conclusive else "INCONCLUSIVE",
                   "evidence_ids": list(dict.fromkeys((*dynamic_result.evidence_ids, *formal_result.evidence_ids)))}
            comparisons.append(row)
            if row["comparison"] == "CONTRADICT":
                conflicts.append(row)
    return comparisons, conflicts


def _checker_record(result: Any, artifacts: dict[str, Any], ctx: Any) -> dict[str, Any]:
    evidence = [_evidence_ref(artifacts[item]) for item in result.evidence_ids if item in artifacts]
    details: dict[str, Any] = {}
    metadata = dict(result.metadata)
    if result.technique.upper() == "CTL":
        validated = metadata.get("counterexample_validated")
        details["counterexample_validation"] = "VALIDATED" if validated else "NOT_PRESENT" if validated is False else "UNAVAILABLE"
    elif result.technique.upper() == "BMC":
        details = {key: metadata.get(key) for key in ("checked_bound", "requested_bound", "completeness_threshold", "complete", "solver_outcome") if key in metadata}
        details["trace_validation"] = "ENFORCED_BY_BMC_CHECKER" if result.counterexample is not None else "NO_TRACE"
    elif result.technique.upper() == "SMT":
        details = {"query_hashes": sorted({str(item.get("query_sha256")) for item in evidence
                                            if item.get("query_sha256")}),
                   "constraint_ids": [item.id for item in getattr(ctx.specification, "constraints", ())],
                   "model_validation": "FAILED" if result.reason_code == "SOLVER_INVALID_MODEL" else "SOLVER_RESULT_VALIDATED_OR_NO_MODEL"}
    elif result.stage.upper() == "STATIC_ANALYSIS":
        details = {"finding_ids": list(metadata.get("finding_ids", ())), "source": result.source,
                   "source_hashes": _pipeline_source_hashes(ctx)}
    elif result.stage.upper() in {"MEMORY_ANALYSIS", "SANITIZER"}:
        details = {"runtime_scope": result.scope, "finding_ids": list(metadata.get("finding_ids", ())),
                   "capability_status": metadata.get("capability_status")}
    elif result.stage.upper() == "DYNAMIC_TEST":
        execution = next((item for item in getattr(ctx, "dynamic_results", ())
                          if item.execution_id == metadata.get("execution_id")), None)
        details = {"test_case_id": metadata.get("test_case_id"),
                   "execution_id": metadata.get("execution_id"),
                   "observation_evidence_id": metadata.get("observation_evidence_id"),
                   "executed": bool(execution and execution.executed),
                   "observation": execution.observed.to_dict() if execution and execution.observed else None,
                   "source_hashes": metadata.get("source_sha256", {})}
    elif result.stage.upper() == "COVERAGE":
        details = {"measurement_only": True, "scope": result.scope}
    elif result.stage.upper() == "FUZZING":
        details = {"bounded_campaign": True, "scope": result.scope,
                   "budget": {key: metadata.get(key) for key in ("iterations_requested", "executions_requested",
                       "input_count_requested", "duration_seconds", "stop_reason") if key in metadata}}
    return {"result_id": result.id, "stage": result.stage, "checker": result.technique,
            "status": result.status.value, "reason_code": result.reason_code, "scope": result.scope,
            "property_id": result.property_id, "requirement_id": result.requirement_id,
            "evidence_ids": list(result.evidence_ids), "evidence": evidence, "checker_contract": details}


def _pipeline_source_hashes(ctx: Any) -> dict[str, str]:
    return {item.get("project_relative_path"): item.get("sha256")
            for item in (getattr(ctx, "source_metadata", {}) or {}).get("files", ())
            if item.get("project_relative_path") and item.get("sha256")}


def _evidence_ref(item: Any) -> dict[str, Any]:
    return {"id": item.id, "stage": item.stage, "path": item.path, "sha256": item.hash,
            **{key: value for key, value in dict(item.metadata).items()
               if key in {"query_sha256", "query_evidence_id", "finding_ids", "artifact_class"}}}
