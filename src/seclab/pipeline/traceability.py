"""Read-only query and integrity API for a single verification report/run."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping


class TraceabilityIndex:
    """Index only links explicitly present in report, manifest, and evidence metadata."""

    def __init__(self, report: Any, *, run_root: str | Path | None = None,
                 manifest: Mapping[str, Any] | Any | None = None) -> None:
        self.report = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        self.run_root = Path(run_root).resolve() if run_root is not None else None
        self.manifest = (manifest.to_dict() if hasattr(manifest, "to_dict") else dict(manifest)
                         if manifest is not None else {})
        self.run_id = self.report.get("run_id")
        self.trace = self.report.get("traceability", {})
        self._result_rows = tuple(self.report.get("results", ()))
        self._result_rows_by_id = _index_rows(self._result_rows)
        self.results = {key: rows[0] for key, rows in self._result_rows_by_id.items() if len(rows) == 1}
        evidence_rows = self.manifest.get("evidence", ())
        if not evidence_rows:
            evidence_rows = self.report.get("metadata", {}).get("evidence", ())
        self._evidence_rows = tuple(evidence_rows)
        self._evidence_rows_by_id = _index_rows(self._evidence_rows)
        self.evidence = {key: rows[0] for key, rows in self._evidence_rows_by_id.items() if len(rows) == 1}

    def requirement(self, requirement_id: str) -> dict[str, Any]:
        row = self.trace.get(requirement_id)
        if row is None:
            return {"id": requirement_id, "status": "UNRESOLVED", "reason": "Requirement is not indexed."}
        result_ids = tuple(row.get("results", ()))
        evidence_ids = tuple(row.get("evidence_ids", ()))
        return {"id": requirement_id, "status": "RESOLVED", "record": row,
                "results": [self._result_link(item) for item in result_ids],
                "evidence": [self.evidence_link(item) for item in evidence_ids]}

    def source_function(self, function_id: str) -> dict[str, Any]:
        inventory = self.report.get("metadata", {}).get("source_inventory", {})
        links = inventory.get("function_links", ())
        matched = [row for row in links if row.get("function_id") == function_id]
        state_map = {}
        transition_map = {}
        locations = {}
        source_paths = {row.get("source_relative_path") for row in matched}
        mapping_keys = set(state_map) | set(transition_map)
        related_keys = [key for key in mapping_keys
                        if any(path and (key == path or key.startswith(path.rstrip("/\\") + ":"))
                               for path in source_paths)]
        states = sorted({state for key in related_keys for state in state_map.get(key, ())})
        transitions = sorted({edge for key in related_keys for edge in transition_map.get(key, ())})
        exists = bool(matched) or bool(related_keys)
        for row in matched:
            if row.get("match_status") != "MATCHED":
                return {"id": function_id, "status": "UNRESOLVED", "function_links": matched,
                        "state_ids": [], "transition_ids": [], "mapping_status": "UNRESOLVED",
                        "reason": row.get("match_status")}
        return {"id": function_id, "status": "RESOLVED" if exists else "UNRESOLVED",
                "function_links": matched, "state_ids": states, "transition_ids": transitions,
                "mapping_status": "RESOLVED" if states or transitions else "UNRESOLVED"}

    def model_state(self, state_id: str) -> dict[str, Any]:
        model_evidence = [row for row in self._evidence_rows if row.get("type") == "MODEL" and
                          row.get("stage") == "model"]
        found = False
        for row in model_evidence:
            data = self._read_evidence_json(row)
            if data and any(item.get("id") == state_id for item in data.get("states", ())):
                found = True
                break
        property_links = self.report.get("metadata", {}).get("property_model_links", {})
        relevant_properties = {prop_id for prop_id, row in property_links.items()
                               if state_id in row.get("state_ids", ())}
        result_rows = []
        for result in self.results.values():
            observation = result.get("counterexample") or {}
            path = observation.get("path", ()) if isinstance(observation, dict) else ()
            candidate_ids = [item.get("id") for item in path if isinstance(item, dict)]
            if (state_id in candidate_ids or state_id in result.get("metadata", {}).get("state_ids", ())):
                result_rows.append(self._result_link(result["id"]))
        for prop_id in relevant_properties:
            links = property_links[prop_id]
            if state_id in links.get("state_ids", ()):
                for result in self.results.values():
                    if result.get("property_id") == prop_id and self._result_link(result["id"]) not in result_rows:
                        result_rows.append(self._result_link(result["id"]))
        return {"id": state_id, "status": "RESOLVED" if found else "UNRESOLVED",
                "results": result_rows, "result_mapping_status": "RESOLVED" if result_rows else "UNRESOLVED"}

    def specification_property(self, property_id: str) -> dict[str, Any]:
        declared_properties = {item.get("id") for item in self.report.get("metadata", {}).get("specification", {}).get("properties", ())}
        declared = set(self.report.get("metadata", {}).get("property_test_cases", {}).get(property_id, ()))
        cases = [row for row in self._evidence_rows if row.get("stage") == "tests" and
                 row.get("metadata", {}).get("artifact_kind") == "test-case"]
        related = []
        for row in cases:
            data = self._read_evidence_json(row)
            if data and data.get("property_id") == property_id:
                related.append({"id": data.get("id"), "evidence_id": row.get("id")})
        related.extend({"id": item, "evidence_id": None} for item in sorted(declared)
                       if item not in {row["id"] for row in related})
        exists = bool(related)
        return {"id": property_id, "status": "RESOLVED" if exists else "UNRESOLVED",
                "declared": property_id in declared_properties or any(row.get("property_id") == property_id for row in self.results.values()),
                "test_cases": related,
                "mapping_status": "RESOLVED" if exists else "UNRESOLVED"}

    def test_case(self, test_case_id: str) -> dict[str, Any]:
        executions = []
        for requirement in self.trace.values():
            for target in requirement.get("targets", {}).values():
                execution = target.get("execution")
                if execution and execution.get("test_case_id") == test_case_id:
                    executions.append(execution)
        results = [self._result_link(row["id"]) for row in self.results.values()
                   if row.get("metadata", {}).get("test_case_id") == test_case_id]
        evidence_ids = {ref for row in executions for ref in row.get("evidence_ids", ())}
        evidence = [row for row in self._evidence_rows if row.get("id") in evidence_ids or
                    row.get("metadata", {}).get("test_case_id") == test_case_id]
        case_refs = [row for row in self._evidence_rows if row.get("stage") == "tests" and
                     row.get("metadata", {}).get("artifact_kind") == "test-case" and
                     (lambda data: bool(data and data.get("id") == test_case_id))(self._read_evidence_json(row))]
        return {"id": test_case_id, "status": "RESOLVED" if case_refs or executions else "UNRESOLVED",
                "execution_ids": [row["id"] for row in executions], "executions": executions,
                "execution_results": results, "evidence": [self.evidence_link(item["id"]) for item in evidence]}

    def execution(self, execution_id: str) -> dict[str, Any]:
        execution = self.report.get("metadata", {}).get("execution_index", {}).get(execution_id)
        if execution:
            result_id = execution.get("result_id") or next(iter(execution.get("result_ids", ())), None)
            return {"id": execution_id, "status": "RESOLVED", "record": execution,
                    "observation": execution.get("observation"),
                    "observation_evidence": self.evidence_link(execution["observation_evidence_id"])
                        if execution.get("observation_evidence_id") else None,
                    "result": self.result(result_id) if result_id else None}
        for requirement in self.trace.values():
            for target in requirement.get("targets", {}).values():
                execution = target.get("execution")
                if execution and execution.get("id") == execution_id:
                    return {"id": execution_id, "status": "RESOLVED", "record": execution,
                            "observation": execution.get("observation"),
                            "observation_evidence": self.evidence_link(execution["observation_evidence_id"])
                                if execution.get("observation_evidence_id") else None,
                            "result": self.result(execution["result_id"]) if execution.get("result_id") else None}
        return {"id": execution_id, "status": "UNRESOLVED", "reason": "Execution ID is not indexed as evidence."}

    def observation(self, observation_id: str) -> dict[str, Any]:
        row = self.evidence.get(observation_id)
        if row is None or row.get("stage") != "observations":
            return {"id": observation_id, "status": "UNRESOLVED"}
        return {"id": observation_id, "status": "RESOLVED", "data": self._read_evidence_json(row),
                "evidence": self.evidence_link(observation_id)}

    def result(self, result_id: str) -> dict[str, Any]:
        if len(self._result_rows_by_id.get(result_id, ())) > 1:
            return {"id": result_id, "status": "BROKEN", "reason": "Result ID is duplicated.",
                    "candidate_count": len(self._result_rows_by_id[result_id])}
        if result_id not in self.results:
            return {"id": result_id, "status": "UNRESOLVED"}
        result = self.results[result_id]
        return {"id": result_id, "status": "RESOLVED", "record": result,
                "evidence": [self.evidence_link(item) for item in result.get("evidence_ids", ())]}

    def evidence_link(self, evidence_id: str) -> dict[str, Any]:
        if len(self._evidence_rows_by_id.get(evidence_id, ())) > 1:
            return {"id": evidence_id, "status": "BROKEN", "reason": "Evidence ID is duplicated.",
                    "candidate_count": len(self._evidence_rows_by_id[evidence_id])}
        row = self.evidence.get(evidence_id)
        if row is None:
            return {"id": evidence_id, "status": "BROKEN", "reason": "Evidence ID is missing from manifest."}
        status = "RESOLVED"
        error = None
        if self.run_root is not None:
            try:
                path = (self.run_root / row["path"]).resolve(strict=True)
                if not path.is_relative_to(self.run_root) or not path.is_file():
                    raise ValueError("path escapes run root or is not a regular file")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != row.get("hash"):
                    raise ValueError("SHA-256 mismatch")
            except (OSError, ValueError, KeyError) as exc:
                status, error = "BROKEN", str(exc)
        return {"id": evidence_id, "status": status, "record": row, "reason": error}

    def integrity(self) -> dict[str, Any]:
        duplicate_ids = []
        collections = [("result", self.report.get("results", ())), ("evidence", self._evidence_rows)]
        for collection, label in ((self.report.get("metadata", {}).get("source_inventory", {}).get("files", ()), "source"),
                                  (self.report.get("metadata", {}).get("source_inventory", {}).get("functions", ()), "function"),
                                  (self.report.get("metadata", {}).get("property_model_links", {}).keys(), "property")):
            ids = [row.get("source_id") if label == "source" else row.get("function_id") if label == "function" else row
                   for row in collection]
            duplicate_ids.extend({"kind": label, "id": key, "count": count}
                                 for key, count in Counter(item for item in ids if item).items() if count > 1)
        for label, rows in collections:
            counts = Counter(row.get("id") for row in rows if row.get("id"))
            duplicate_ids.extend({"kind": label, "id": key, "count": count}
                                 for key, count in counts.items() if count > 1)
        broken_results = [{"result_id": result.get("id"), "evidence_id": evidence_id}
                          for result in self._result_rows
                          for evidence_id in result.get("evidence_ids", ())
                          if self.evidence_link(evidence_id)["status"] != "RESOLVED"]
        linked = {ref for result in self.results.values() for ref in result.get("evidence_ids", ())}
        for stage in self.report.get("stage_summaries", ()):
            linked.update(stage.get("evidence_ids", ()))
            linked.update(stage.get("output_refs", ()))
        orphan_evidence = sorted(item for item in self.evidence if item not in linked and
                                 self.evidence[item].get("stage") not in {"manifest", "report"})
        artifact_checks = [self.evidence_link(item) for item in self._evidence_rows_by_id]
        broken_artifacts = [item for item in artifact_checks if item["status"] == "BROKEN"]
        broken_mappings = []
        for requirement_id, row in self.trace.items():
            for result_id in row.get("results", ()):
                if self.result(result_id)["status"] != "RESOLVED":
                    broken_mappings.append({"kind": "requirement_result", "owner_id": requirement_id,
                                            "target_id": result_id})
            for evidence_id in row.get("evidence_ids", ()):
                if self.evidence_link(evidence_id)["status"] != "RESOLVED":
                    broken_mappings.append({"kind": "requirement_evidence", "owner_id": requirement_id,
                                            "target_id": evidence_id})
        for execution_id, execution in self.report.get("metadata", {}).get("execution_index", {}).items():
            for result_id in execution.get("result_ids", ()):
                if self.result(result_id)["status"] != "RESOLVED":
                    broken_mappings.append({"kind": "execution_result", "owner_id": execution_id,
                                            "target_id": result_id})
            for evidence_id in execution.get("evidence_ids", ()):
                if self.evidence_link(evidence_id)["status"] != "RESOLVED":
                    broken_mappings.append({"kind": "execution_evidence", "owner_id": execution_id,
                                            "target_id": evidence_id})
        unresolved = [{"kind": "requirement", "id": key} for key, row in self.trace.items()
                      if row.get("status") == "NOT_CHECKED"]
        return {"valid": not duplicate_ids and not broken_results and not orphan_evidence and not broken_artifacts and not broken_mappings,
                "duplicate_ids": duplicate_ids, "broken_result_references": broken_results,
                "orphan_evidence_ids": orphan_evidence, "broken_artifacts": broken_artifacts,
                "broken_mappings": broken_mappings,
                "unresolved": unresolved}

    def _result_link(self, result_id: str) -> dict[str, Any]:
        return self.result(result_id)

    def _read_evidence_json(self, row: Mapping[str, Any]) -> dict[str, Any] | None:
        if self.run_root is None:
            return None
        try:
            path = (self.run_root / row["path"]).resolve(strict=True)
            if not path.is_relative_to(self.run_root):
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError, KeyError):
            return None


def _index_rows(rows: Any) -> dict[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        if isinstance(row, Mapping) and row.get("id"):
            grouped[str(row["id"])].append(row)
    return {key: tuple(value) for key, value in grouped.items()}
