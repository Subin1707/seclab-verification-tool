from __future__ import annotations

from copy import deepcopy

from seclab.pipeline import TraceabilityIndex


def _report() -> dict:
    return {"run_id": "run", "traceability": {"REQ-1": {"requirement_id": "REQ-1", "status": "CHECKED",
        "results": ["R1"], "evidence_ids": ["E1"], "targets": {}}},
        "results": [{"id": "R1", "evidence_ids": ["E1"], "property_id": "P1", "metadata": {}}],
        "stage_summaries": [{"evidence_ids": [], "output_refs": []}], "metadata": {}}


def _evidence() -> list[dict]:
    return [{"id": "E1", "stage": "test", "path": "evidence/test/a.json", "hash": "0" * 64,
             "size_bytes": 1, "type": "TEST_RESULT", "metadata": {}}]


def test_trace_queries_keep_missing_edges_unresolved_or_broken() -> None:
    index = TraceabilityIndex(_report(), manifest={"evidence": _evidence()})
    assert index.requirement("REQ-1")["status"] == "RESOLVED"
    assert index.requirement("MISSING")["status"] == "UNRESOLVED"
    assert index.result("MISSING")["status"] == "UNRESOLVED"
    assert index.evidence_link("MISSING")["status"] == "BROKEN"


def test_integrity_detects_broken_result_reference_orphan_and_duplicate_ids() -> None:
    report = _report()
    report["results"].append(deepcopy(report["results"][0]))
    report["results"][0]["evidence_ids"].append("MISSING-EVIDENCE")
    manifest = {"evidence": _evidence() + [_evidence()[0], {"id": "ORPHAN", "stage": "other",
        "path": "evidence/other/orphan", "hash": "1" * 64, "size_bytes": 2, "type": "LOG", "metadata": {}}]}
    audit = TraceabilityIndex(report, manifest=manifest).integrity()
    assert not audit["valid"]
    assert {item["evidence_id"] for item in audit["broken_result_references"]} == {
        "E1", "MISSING-EVIDENCE"}
    assert audit["orphan_evidence_ids"] == ["ORPHAN"]
    assert {row["kind"] for row in audit["duplicate_ids"]} == {"result", "evidence"}


def test_evidence_link_detects_missing_modified_and_wrong_hash(tmp_path) -> None:
    report = _report()
    entry = _evidence()[0]
    root = tmp_path / "run"
    artifact = root / entry["path"]
    artifact.parent.mkdir(parents=True)
    artifact.write_text("x", encoding="utf-8")
    entry["hash"] = "f" * 64
    index = TraceabilityIndex(report, run_root=root, manifest={"evidence": [entry]})
    assert index.evidence_link("E1")["status"] == "BROKEN"
    artifact.unlink()
    assert index.evidence_link("E1")["status"] == "BROKEN"


def test_duplicate_ids_are_ambiguous_and_never_select_an_arbitrary_record() -> None:
    evidence = _evidence()[0]
    evidence2 = {**evidence, "path": "evidence/test/other.json", "hash": "1" * 64}
    report = _report()
    report["results"].append({**report["results"][0], "message": "different record"})
    index = TraceabilityIndex(report, manifest={"evidence": [evidence, evidence2]})
    assert index.result("R1")["status"] == "BROKEN"
    assert index.evidence_link("E1")["status"] == "BROKEN"
    audit = index.integrity()
    assert {item["kind"] for item in audit["duplicate_ids"]} == {"result", "evidence"}
    assert not audit["valid"]


def test_source_function_does_not_resolve_model_mapping_from_source_lines() -> None:
    report = _report()
    report["metadata"] = {"source_inventory": {
        "function_links": [{"function_id": "FUNC-1", "match_status": "MATCHED",
                            "source_relative_path": "src/step.c"}],
        "source_model": {"source_locations": {"NODE-1": {"file": "src/step.c", "line": 4}},
                         "source_to_states": {"src/step.c:4": ["STATE-1"]},
                         "source_to_transitions": {"src/step.c:4": ["TRANSITION-1"]}},
    }}
    mapping = TraceabilityIndex(report).source_function("FUNC-1")
    assert mapping["status"] == "RESOLVED"
    assert mapping["mapping_status"] == "UNRESOLVED"
    assert mapping["state_ids"] == []
    assert mapping["transition_ids"] == []


def test_integrity_reports_broken_requirement_and_execution_mappings() -> None:
    report = _report()
    report["traceability"]["REQ-1"]["evidence_ids"].append("MISSING-TRACE-EVIDENCE")
    report["metadata"] = {"execution_index": {"EXEC-1": {
        "result_ids": ["MISSING-RESULT"], "evidence_ids": ["MISSING-EXEC-EVIDENCE"]}}}
    audit = TraceabilityIndex(report, manifest={"evidence": _evidence()}).integrity()
    assert not audit["valid"]
    assert {(item["kind"], item["target_id"]) for item in audit["broken_mappings"]} == {
        ("requirement_evidence", "MISSING-TRACE-EVIDENCE"),
        ("execution_result", "MISSING-RESULT"),
        ("execution_evidence", "MISSING-EXEC-EVIDENCE"),
    }
