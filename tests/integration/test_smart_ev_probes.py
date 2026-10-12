from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from seclab.integrations.smart_ev_probes import load_probe_manifest, run_smart_ev_probes


PROBE_ROOT = Path(__file__).resolve().parents[2] / "examples" / "smart-ev-probes"
EXPECTED_NAMES = {"buffer_overflow", "memory_leak", "double_free", "use_after_free"}


def test_probe_manifest_rejects_production_scope(tmp_path: Path) -> None:
    copied = tmp_path / "probes"
    shutil.copytree(PROBE_ROOT, copied)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probes"][0]["scope"] = "PRODUCTION_SOURCE"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid production/probe scope"):
        load_probe_manifest(copied)


def test_smart_ev_probe_suite_uses_supported_tools_and_records_evidence(tmp_path: Path) -> None:
    root, manifest = load_probe_manifest(PROBE_ROOT)
    assert root == PROBE_ROOT.resolve()
    assert {item["name"] for item in manifest["probes"]} == EXPECTED_NAMES
    assert all(item["scope"] in {"TOOL_CAPABILITY_EVIDENCE", "BUG_INJECTED_PROBE"}
               for item in manifest["probes"])
    assert all(item["scope"] != "PRODUCTION_SOURCE" for item in manifest["probes"])

    original_hashes = {
        item["source_file"]: hashlib.sha256((root / item["source_file"]).read_bytes()).hexdigest()
        for item in manifest["probes"]
    }
    workspace = tmp_path / "probe-run"
    report = run_smart_ev_probes(root, workspace, timeout=20.0)

    assert report["production_source_affected"] == 0
    assert report["production_vulnerability_claim"] is False
    assert len(report["probes"]) == 4
    assert {item["name"] for item in report["probes"]} == EXPECTED_NAMES
    assert all(item["scope"] != "PRODUCTION_SOURCE" and item["production_source"] is False
               for item in report["probes"])

    toolchain = report["environment"]["tools"]
    compiler_available = any(toolchain[name]["installed"] for name in ("gcc", "clang"))
    for probe in report["probes"]:
        integrity = probe["observed"]["source_integrity"]
        assert integrity["equal"] is True
        assert integrity["sha256_before"] == original_hashes[
            next(entry["source_file"] for entry in manifest["probes"] if entry["name"] == probe["name"])
        ]
        assert integrity["sha256_after"] == integrity["sha256_before"]

        compile_record = next(item for item in probe["observed"]["tools"] if item["tool"] == "compiler")
        if compiler_available:
            assert compile_record["observed"]["success"] is True
            assert compile_record["observed"]["command"]["argv"]

        for tool_record in probe["observed"]["tools"]:
            assert "expected" in tool_record and "observed" in tool_record
            for evidence_id in tool_record.get("evidence_ids", []):
                assert evidence_id
            if tool_record["tool"] == "compiler-diagnostics":
                assert tool_record["observed"]["executed"] is compiler_available
            elif tool_record["tool"] in {"cppcheck", "clang-tidy"}:
                assert tool_record["observed"]["executed"] is toolchain[tool_record["tool"]]["installed"]
            if tool_record["tool"] in {"compiler-diagnostics", "cppcheck", "clang-tidy"} and tool_record["observed"]["executed"]:
                assert tool_record["observed"]["commands"]
                assert all(command["argv"] for command in tool_record["observed"]["commands"])
            elif tool_record["tool"] in {"AddressSanitizer", "UndefinedBehaviorSanitizer"} and compiler_available:
                observed = tool_record["observed"]
                assert observed["verification_result"]["status"] in {
                    "PASS", "FAIL", "INCONCLUSIVE", "TOOL_ERROR", "BUILD_ERROR"
                }
                if observed["build_succeeded"] is False:
                    assert observed["verification_result"]["status"] == "BUILD_ERROR"

    evidence = report["evidence"]
    assert evidence
    evidence_by_id = {item["id"]: item for item in evidence}
    for item in evidence:
        artifact = workspace / item["path"]
        assert artifact.is_file()
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == item["hash"]

    for probe in report["probes"]:
        assert any(evidence_by_id[item_id]["path"].endswith(f"{probe['probe_id']}.c")
                   for item_id in probe["evidence_ids"])
        assert any(evidence_by_id[item_id]["path"].endswith(f"{probe['probe_id']}.json")
                   for item_id in probe["evidence_ids"])
        assert probe["result"]["status"] in {"FAIL", "INCONCLUSIVE", "TOOL_ERROR", "BUILD_ERROR"}

    run_manifest = json.loads((workspace / "run-manifest.json").read_text(encoding="utf-8"))
    assert run_manifest["scope"] == "TOOL_CAPABILITY_EVIDENCE"
    assert run_manifest["production_source_affected"] == 0
    assert (workspace / "probe-report.json").is_file()
    assert original_hashes == {
        item["source_file"]: hashlib.sha256((root / item["source_file"]).read_bytes()).hexdigest()
        for item in manifest["probes"]
    }
