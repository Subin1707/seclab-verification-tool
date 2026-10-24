"""Single verification-run context shared by every pipeline stage."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from seclab.evidence import ArtifactStore, Evidence, EvidenceCollector
from seclab.results import ResultCollector, VerificationResult


EvidenceStore = EvidenceCollector


class TraceabilityStore(dict[str, dict[str, Any]]):
    """Mutable trace graph owned by one VerificationContext."""


class TrackedArtifactStore(ArtifactStore):
    """ArtifactStore adapter that exposes artifacts emitted by existing cores."""
    def __init__(self, workspace_root: str | Path, run_id: str) -> None:
        super().__init__(workspace_root, run_id=run_id)
        self._items: dict[str, Evidence] = {}

    def _track(self, item: Evidence) -> Evidence:
        self._items[item.id] = item
        return item

    def write_json(self, *args: Any, **kwargs: Any) -> Evidence:
        return self._track(super().write_json(*args, **kwargs))

    def write_text(self, *args: Any, **kwargs: Any) -> Evidence:
        return self._track(super().write_text(*args, **kwargs))

    def write_bytes(self, *args: Any, **kwargs: Any) -> Evidence:
        return self._track(super().write_bytes(*args, **kwargs))

    def copy_file(self, *args: Any, **kwargs: Any) -> Evidence:
        return self._track(super().copy_file(*args, **kwargs))

    def all(self) -> tuple[Evidence, ...]:
        return tuple(self._items.values())

    def ids(self) -> frozenset[str]:
        return frozenset(self._items)


@dataclass(frozen=True, slots=True)
class ProjectContext:
    root: Path
    source_files: tuple[Any, ...]
    source_metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SpecificationContext:
    loaded: Any
    validated: Any
    normalized: Any


@dataclass(frozen=True, slots=True)
class ModelContext:
    model: Any


@dataclass(frozen=True, slots=True)
class GeneratedSourceContext:
    root: Path | None
    result: Any


@dataclass(slots=True)
class VerificationContext:
    """All inputs and accumulated outputs for one verification run.

    The orchestrator creates exactly one instance after resolving the project,
    workspace, run identifier, and configuration. Stages enrich this same
    object with the loaded/validated/normalized specification and model; they
    must not construct replacement contexts or ask callers to reload inputs.
    """
    run_id: str
    project: Path
    workspace: Path
    started_at: datetime
    artifact_store: TrackedArtifactStore
    toolchain: Any
    source_metadata: dict[str, Any] = field(default_factory=dict)
    loaded_specification: Any = None
    validated_specification: Any = None
    specification: Any = None
    kripke: Any = None
    codegen_result: Any = None
    generated_c_root: Path | None = None
    generated_model_executable: Path | None = None
    generated_model_fuzz_executable: Path | None = None
    generated_model_test_cases: tuple[Any, ...] = ()
    generated_model_test_results: tuple[Any, ...] = ()
    language: Any = None
    source_files: tuple[Any, ...] = ()
    test_cases: tuple[Any, ...] = ()
    dynamic_results: tuple[Any, ...] = ()
    coverage_report: Any = None
    fuzz_results: tuple[Any, ...] = ()
    outputs: dict[str, Any] = field(default_factory=dict)
    stage_records: dict[str, Any] = field(default_factory=dict)
    result_collector: ResultCollector = field(default_factory=ResultCollector)
    result_ids: set[str] = field(default_factory=set)
    evidence_collector: EvidenceStore = field(default_factory=EvidenceStore)
    traceability: TraceabilityStore = field(default_factory=TraceabilityStore)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    options: Any = None
    progress_callback: Any = None
    manifest: Any = None
    command_runner: Any = None
    test_runner: Any = None
    coverage_runner: Any = None
    source_hashes: dict[str, str | None] = field(default_factory=dict)
    specification_input_hashes: dict[str, str | None] = field(default_factory=dict)
    finished_at: datetime | None = None

    def add_results(self, results: tuple[VerificationResult, ...] | list[VerificationResult]) -> None:
        for result in results:
            if result.id not in self.result_ids:
                self.result_collector.add(result)
                self.result_ids.add(result.id)
            if result.requirement_id:
                row = self.traceability.setdefault(result.requirement_id, {
                    "requirement_id": result.requirement_id, "checker_refs": [], "results": [],
                    "evidence_ids": [], "stages": [], "targets": {}})
                if result.id not in row["results"]:
                    row["results"].append(result.id)
                row["evidence_ids"].extend(item for item in result.evidence_ids if item not in row["evidence_ids"])
                stage_id = _trace_stage_id(result.stage, result.technique)
                if stage_id and stage_id not in row["stages"]:
                    row["stages"].append(stage_id)
                target_id = result.property_id or result.metadata.get("test_case_id")
                if target_id:
                    target_kind = "TEST_CASE" if result.metadata.get("test_case_id") == target_id else "PROPERTY"
                    target = row["targets"].setdefault(target_id, {
                        "target_id": target_id, "target_kind": target_kind, "stage_id": stage_id,
                        "results": [], "evidence_ids": [], "statuses": [], "status": "NOT_CHECKED"})
                    if stage_id:
                        target["stage_id"] = stage_id
                    if result.id not in target["results"]:
                        target["results"].append(result.id)
                    target["evidence_ids"].extend(item for item in result.evidence_ids
                                                  if item not in target["evidence_ids"])
                    if result.status.value not in target["statuses"]:
                        target["statuses"].append(result.status.value)
                    target["status"] = "CHECKED"

    def add_evidence(self, items: tuple[Evidence, ...] | list[Evidence]) -> None:
        known = {item.id for item in self.evidence_collector.all()}
        for item in items:
            if item.id not in known:
                self.evidence_collector.add(item)
                known.add(item.id)

    def flush_artifacts(self) -> None:
        self.add_evidence(self.artifact_store.all())

    @property
    def elapsed_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return max(0.0, (end - self.started_at).total_seconds())

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    @property
    def project_context(self) -> ProjectContext:
        return ProjectContext(self.project, self.source_files, self.source_metadata)

    @property
    def specification_context(self) -> SpecificationContext:
        return SpecificationContext(self.loaded_specification, self.validated_specification, self.specification)

    @property
    def model_context(self) -> ModelContext:
        return ModelContext(self.kripke)

    @property
    def generated_source_context(self) -> GeneratedSourceContext:
        return GeneratedSourceContext(self.generated_c_root, self.codegen_result)


def _trace_stage_id(stage: str, technique: str) -> str | None:
    technique = technique.upper()
    if technique in {"CTL", "BMC", "SMT"}:
        return technique
    stage = stage.upper()
    return {"STATIC_ANALYSIS": "STATIC", "SANITIZER": "MEMORY", "MEMORY_ANALYSIS": "MEMORY",
            "DYNAMIC_TEST": "DYNAMIC", "COVERAGE": "COVERAGE", "FUZZING": "FUZZING"}.get(stage)


# Backwards-compatible public names for the single per-run context contract.
PipelineContext = VerificationContext
RunContext = VerificationContext
