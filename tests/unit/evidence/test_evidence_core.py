from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from seclab.evidence import ArtifactStore, Evidence, EvidenceCollector, EvidenceError, EvidenceType, RunManifest
from seclab.results import VerificationResult, VerificationStatus


FIXED_TIME = datetime(2026, 1, 2, tzinfo=timezone.utc)


def test_store_text_json_and_copy_hash_exact_bytes(tmp_path) -> None:
    store = ArtifactStore(tmp_path, clock=lambda: FIXED_TIME, id_factory=iter(("e1", "e2", "e3")).__next__)
    text = store.write_text("tests", "hello.txt", "hello")
    assert text.hash == hashlib.sha256(b"hello").hexdigest()
    assert (tmp_path / text.path).read_bytes() == b"hello"
    json_item = store.write_json("tests", "data.json", {"b": 1, "a": "é"})
    assert json.loads((tmp_path / json_item.path).read_text(encoding="utf-8")) == {"a": "é", "b": 1}
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x00\xff")
    copied = store.copy_file("tests", "copy.bin", source)
    assert (tmp_path / copied.path).read_bytes() == b"\x00\xff"
    assert copied.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert text.size_bytes == len(b"hello")
    assert text.checker == "verification-tool"
    assert text.run_id is None


@pytest.mark.parametrize("filename", ["../escape", "..\\escape", "C:\\outside", "/outside", "folder/file"])
def test_store_rejects_unsafe_filename(tmp_path, filename: str) -> None:
    with pytest.raises(EvidenceError):
        ArtifactStore(tmp_path).write_text("stage", filename, "x")


def test_store_prevents_overwrite_and_evidence_collection_rejects_duplicates(tmp_path) -> None:
    store = ArtifactStore(tmp_path, clock=lambda: FIXED_TIME, id_factory=lambda: "ev")
    first = store.write_text("stage", "x.txt", "first")
    with pytest.raises(EvidenceError):
        store.write_text("stage", "x.txt", "second")
    collector = EvidenceCollector()
    collector.add(first)
    with pytest.raises(EvidenceError):
        collector.add(first)


def test_default_evidence_ids_are_stable_for_same_run_path_and_content(tmp_path) -> None:
    first = ArtifactStore(tmp_path / "one", run_id="run-1").write_text("stage", "x.txt", "same")
    same = ArtifactStore(tmp_path / "two", run_id="run-1").write_text("stage", "x.txt", "same")
    changed = ArtifactStore(tmp_path / "three", run_id="run-1").write_text("stage", "x.txt", "other")
    other_run = ArtifactStore(tmp_path / "four", run_id="run-2").write_text("stage", "x.txt", "same")
    assert first.id == same.id
    assert len({first.id, changed.id, other_run.id}) == 3


def test_manifest_roundtrip_summary_and_reference_validation() -> None:
    evidence = Evidence("ev", EvidenceType.LOG, "TEST", "unit", "evidence/test/log.txt", FIXED_TIME,
                        hashlib.sha256(b"x").hexdigest())
    result = VerificationResult("r", "TEST", "UNIT", VerificationStatus.PASS, "OK", "ok", evidence_ids=("ev",))
    manifest = RunManifest("run", {"id": "demo"}, FIXED_TIME, results=(result,), evidence=(evidence,))
    encoded = manifest.to_json()
    decoded = RunManifest.from_dict(json.loads(encoded))
    assert decoded.to_dict() == manifest.to_dict()
    assert decoded.evidence[0].size_bytes is None  # legacy manifests remain readable
    assert manifest.summary()["PASS"] == 1
    with pytest.raises(EvidenceError):
        RunManifest("bad", {}, FIXED_TIME, results=(
            VerificationResult("r2", "T", "X", "FAIL", "BAD", "bad", evidence_ids=("missing",)),
        ))


def test_manifest_serialization_uses_canonical_result_and_evidence_order() -> None:
    evidence_a = Evidence("ev-a", EvidenceType.LOG, "Z", "unit", "evidence/z/a", FIXED_TIME,
                          hashlib.sha256(b"a").hexdigest(), size_bytes=1, checker="unit", run_id="run")
    evidence_b = Evidence("ev-b", EvidenceType.LOG, "A", "unit", "evidence/a/b", FIXED_TIME,
                          hashlib.sha256(b"b").hexdigest(), size_bytes=1, checker="unit", run_id="run")
    result_a = VerificationResult("r-a", "T", "X", VerificationStatus.PASS, "OK", "ok")
    result_b = VerificationResult("r-b", "T", "X", VerificationStatus.FAIL, "BAD", "bad")
    first = RunManifest("run", {}, FIXED_TIME, results=(result_b, result_a), evidence=(evidence_a, evidence_b))
    second = RunManifest("run", {}, FIXED_TIME, results=(result_a, result_b), evidence=(evidence_b, evidence_a))
    assert first.to_json() == second.to_json()
