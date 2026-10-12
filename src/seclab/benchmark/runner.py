"""Benchmark execution, evidence retention, and scoring entry points."""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import uuid
from typing import Callable, Iterable, Mapping, Any

from seclab.evidence import ArtifactStore, Evidence, EvidenceType

from .models import BenchmarkCase, BenchmarkObservation, BenchmarkReport, compare_benchmark

Executor = Callable[[BenchmarkCase], BenchmarkObservation]


def verify_evidence_artifact(workspace_root: str | Path, reference: Evidence | Mapping[str, Any]) -> bool:
    """Return whether an ArtifactStore reference resolves safely and matches SHA-256."""
    evidence = reference if isinstance(reference, Evidence) else Evidence.from_dict(reference)
    root = Path(workspace_root).resolve()
    relative = PurePosixPath(evidence.path)
    if relative.is_absolute() or ".." in relative.parts or PureWindowsPath(evidence.path).is_absolute():
        return False
    path = (root / Path(*relative.parts)).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == evidence.hash


def run_benchmark(cases: Iterable[BenchmarkCase], executor: Executor, *,
                  workspace: str | Path | None = None, execution_id: str | None = None,
                  run_metadata: Mapping[str, Any] | None = None) -> BenchmarkReport:
    case_list = tuple(cases)
    run_id = execution_id or str(uuid.uuid4())
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise ValueError("execution_id must be a safe path component")
    run_root = Path(workspace).resolve() / run_id if workspace is not None else None
    store = ArtifactStore(run_root) if run_root is not None else None
    observations = []
    case_references: dict[str, dict[str, Any]] = {}
    for case in case_list:
        refs: list[dict[str, Any]] = []
        if store:
            declaration = case.to_dict()
            refs.append(_record(store.write_json(f"{case.case_id}", "fixture.json", declaration["input"],
                evidence_type=EvidenceType.SPECIFICATION, source="benchmark-catalog",
                metadata={"case_id": case.case_id, "fixture_sha256": declaration["fixture_sha256"],
                          "classification": "FIXTURE"})))
            refs.append(_record(store.write_json(f"{case.case_id}", "ground-truth.json", declaration["ground_truth"],
                evidence_type=EvidenceType.TEST_RESULT, source="independent-ground-truth",
                metadata={"case_id": case.case_id, "ground_truth_sha256": declaration["ground_truth_sha256"],
                          "classification": "GROUND_TRUTH"})))
        try:
            observation = executor(case)
            if observation.benchmark_id != case.benchmark_id:
                raise ValueError("executor returned an observation for a different benchmark ID")
        except Exception as exc:
            observation = BenchmarkObservation(case.benchmark_id, None, "TOOL_ERROR",
                                               error=f"{type(exc).__name__}: {exc}")
        if store:
            for index, payload in enumerate(observation.evidence_payloads):
                name = str(payload.get("name", f"checker-evidence-{index + 1}"))
                safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip(".-") or f"evidence-{index + 1}"
                kind = str(payload.get("kind", "normalized"))
                content = _json_safe(payload.get("content"))
                if kind == "raw" and isinstance(content, str):
                    evidence = store.write_text(case.case_id, f"{safe_name}.txt", content,
                        evidence_type=EvidenceType.LOG, source=str(payload.get("source", observation.actual_checker or "checker")),
                        metadata={"case_id": case.case_id, "execution_id": run_id, "evidence_name": name,
                                  "classification": "CHECKER_OBSERVATION"})
                else:
                    evidence = store.write_json(case.case_id, f"{safe_name}.json", content,
                        evidence_type=_evidence_type(payload.get("type")),
                        source=str(payload.get("source", observation.actual_checker or "checker")),
                        metadata={"case_id": case.case_id, "execution_id": run_id, "evidence_name": name,
                                  "classification": "CHECKER_OBSERVATION"})
                refs.append(_record(evidence))
            normalized = store.write_json(case.case_id, "observation.json", _json_safe(observation.to_dict()),
                evidence_type=EvidenceType.TEST_RESULT, source="benchmark-runner",
                metadata={"case_id": case.case_id, "execution_id": run_id,
                          "classification": "CHECKER_OBSERVATION"})
            refs.append(_record(normalized))
            integrity_errors = [ref["path"] for ref in refs if not verify_evidence_artifact(run_root, ref)]
            if integrity_errors:
                observation = BenchmarkObservation(case.case_id, observation.actual_checker, "TOOL_ERROR",
                    error="EVIDENCE_INTEGRITY_FAILURE: " + ", ".join(integrity_errors),
                    evidence_references=tuple(refs))
            else:
                observation = _with_refs(observation, refs)
        observations.append(_with_refs(observation, refs) if store is None else observation)
        case_references[case.case_id] = {"execution_id": run_id, "evidence_references": refs}
    report = compare_benchmark(case_list, observations)
    if store:
        final_references: list[dict[str, Any]] = []
        for row in report.expected_vs_actual:
            case_id = str(row["case_id"])
            ref = store.write_json(case_id, "comparison.json", {
                "case_id": case_id, "execution_id": run_id,
                "classification": row["mismatch_classification"], "matched": row["matched"],
                "mismatch_cause": row["mismatch_cause"], "expected": row["expected"], "actual": row["actual"],
            }, evidence_type=EvidenceType.TEST_RESULT, source="benchmark-comparator",
               metadata={"case_id": case_id, "execution_id": run_id,
                         "classification": "COMPARISON"})
            comparison_ref = _record(ref)
            case_references[case_id]["comparison_evidence"] = comparison_ref
            final_references.extend(case_references[case_id]["evidence_references"])
            final_references.append(comparison_ref)
        # Report manifest makes case -> fixture/truth -> observation -> comparison traceable.
        manifest = store.write_json("run", "manifest.json", {
            "execution_id": run_id, "run_metadata": dict(run_metadata or {}),
            "cases": case_references,
        }, evidence_type=EvidenceType.ENVIRONMENT, source="benchmark-runner",
           metadata={"execution_id": run_id})
        final_references.append(_record(manifest))
        invalid = [ref["path"] for ref in final_references if not verify_evidence_artifact(run_root, ref)]
        if invalid:
            raise RuntimeError("EVIDENCE_INTEGRITY_FAILURE: " + ", ".join(invalid))
    return report


def _evidence_type(value: Any) -> EvidenceType:
    try:
        return EvidenceType(str(value))
    except ValueError:
        return EvidenceType.TEST_RESULT


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
        return {item.name: _json_safe(getattr(value, item.name)) for item in fields(value)}
    return str(value)


def _record(evidence: Evidence) -> dict[str, Any]:
    return evidence.to_dict()


def _with_refs(observation: BenchmarkObservation, refs: list[dict[str, Any]]) -> BenchmarkObservation:
    return BenchmarkObservation(observation.benchmark_id, observation.actual_checker, observation.actual_status,
        observation.actual_finding, observation.actual_property, observation.evidence,
        observation.unsupported_reason, observation.error, tuple(refs), observation.evidence_payloads)


def load_executor(reference: str) -> Executor:
    """Load ``package.module:callable`` executor for local checker adapters."""
    module_name, separator, attribute = reference.partition(":")
    if not separator:
        raise ValueError("executor must use package.module:callable syntax")
    executor = getattr(importlib.import_module(module_name), attribute)
    if not callable(executor):
        raise TypeError(f"{reference} is not callable")
    return executor
