from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from seclab.evidence import ArtifactStore
from seclab.model import SourceModelBuilder
from seclab.pipeline import PipelineOptions, run_full_verification
from seclab.source import SourceLoader


pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="clang parser is required")
FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "examples" / "source-model"


def test_discovered_fixture_builds_traceable_model_and_hash_verified_evidence(tmp_path: Path) -> None:
    discovered = SourceLoader().load_source_tree(FIXTURE_ROOT)
    selected = next(item for item in discovered if item.path.name == "if_else.c")
    store = ArtifactStore(tmp_path / "run", run_id="source-model-run")
    result = SourceModelBuilder(parameter_domains={"choose.input": (-2, 2)}).build(
        (selected,), source_root=FIXTURE_ROOT, artifact_store=store)

    assert result.model is not None
    assert result.model.model_hash
    assert result.status == "SUPPORTED"
    assert result.source_hashes[selected.relative_path] == hashlib.sha256(selected.path.read_bytes()).hexdigest()
    assert result.source_to_states and result.source_to_transitions and result.property_mappings
    artifacts = tuple((store.evidence_root / "source-model").glob("*"))
    assert len(result.evidence_ids) == len(artifacts) == 2
    assert set(result.evidence_hashes) == set(result.evidence_ids)
    ast_path = next(item for item in artifacts if item.name.endswith(".ast.json"))
    report_path = next(item for item in artifacts if item.name.startswith("model-build-"))
    assert hashlib.sha256(ast_path.read_bytes()).hexdigest() == result.evidence_hashes[result.evidence_ids[0]]
    assert hashlib.sha256(report_path.read_bytes()).hexdigest() == result.evidence_hashes[result.evidence_ids[1]]
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["model_hash"] == result.model.model_hash
    assert payload["source_hashes"] == dict(result.source_hashes)
    assert payload["evidence_hashes"][result.evidence_ids[0]] == result.evidence_hashes[result.evidence_ids[0]]


def test_unsupported_construct_is_not_accepted_as_a_partial_model(tmp_path: Path) -> None:
    project = tmp_path / "generic-project"
    project.mkdir()
    (project / "unsupported.c").write_text(
        "int helper(void) { return 1; }\nint entry(void) { return helper(); }\n", encoding="utf-8")
    sources = SourceLoader().load_source_tree(project)
    result = SourceModelBuilder().build(sources, source_root=project)
    assert result.status == "UNSUPPORTED"
    assert result.model is None
    assert result.unsupported_constructs
    assert "CallExpr" in str(result.unsupported_constructs)


def _source_pipeline_project(root: Path, *, loop: bool = False) -> Path:
    project = root / "project"
    project.mkdir()
    if loop:
        source = "int run(void) { int i = 0; while (i < 4) { i++; } return i; }\n"
        function = "run"
    else:
        source = "int run(void) { int value = 1; if (value > 0) return 1; else return 0; }\n"
        function = "run"
    (project / "main.c").write_text(source, encoding="utf-8")
    specification = {
        "schema_version": "1.0", "id": "source-derived-generic", "name": "Source-derived generic",
        "properties": [{"id": "PROP-SOURCE", "logic": "CTL", "formula": "EF(true)"}],
        "functions": [{"id": "FUNC-RUN", "name": function, "file": "main.c"}],
    }
    (project / "specification.json").write_text(json.dumps(specification), encoding="utf-8")
    return project


def test_pipeline_never_substitutes_project_source_for_missing_specification_model(tmp_path: Path) -> None:
    project = _source_pipeline_project(tmp_path)
    report = run_full_verification(project, tmp_path / "runs", options=PipelineOptions(
        specification_paths=(project / "specification.json",), static_analyzers=(),
        run_memory=False, run_coverage=False), run_id="source-derived")
    stages = {row["stage_id"]: row for row in report.stage_summaries}
    assert stages["SOURCE"]["status"] == "COMPLETED"
    assert stages["MODEL"]["status"] == "SKIPPED"
    assert stages["CTL"]["status"] == "SKIPPED"
    assert not (tmp_path / "runs/source-derived/evidence/model/source-model-provenance.json").exists()


def test_source_model_options_are_not_needed_or_used_by_verification_pipeline(tmp_path: Path) -> None:
    project = _source_pipeline_project(tmp_path, loop=True)
    report = run_full_verification(project, tmp_path / "runs", options=PipelineOptions(
        specification_paths=(project / "specification.json",), static_analyzers=(),
        run_memory=False, run_coverage=False),
        run_id="source-incomplete")
    stages = {row["stage_id"]: row for row in report.stage_summaries}
    assert stages["MODEL"]["status"] == "SKIPPED"
    assert stages["CTL"]["status"] == "SKIPPED"
    assert "property_model_links" not in report.metadata or "PROP-SOURCE" not in report.metadata["property_model_links"]
