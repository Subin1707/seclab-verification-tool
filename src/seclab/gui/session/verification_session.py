"""GUI-owned context shared by project, pipeline, results, and evidence views."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any


class SessionState(str, Enum):
    NO_PROJECT = "NO_PROJECT"
    PROJECT_LOADED = "PROJECT_LOADED"
    SPECIFICATION_LOADED = "SPECIFICATION_LOADED"
    VALIDATED = "VALIDATED"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


@dataclass
class VerificationSession:
    """Presentation context only; verification execution remains in PipelineOrchestrator."""

    workspace: Path | None = None
    project_path: Path | None = None
    specification_path: Path | None = None
    loaded_specification: Any = None
    raw_specification: Any = None
    canonical_specification: Any = None
    normalized_specification: Any = None
    specification_format: str | None = None
    adapter_name: str | None = None
    original_spec_hash: str | None = None
    canonical_spec_hash: str | None = None
    schema_version: str | None = None
    validation_result: str | None = None
    run_id: str | None = None
    source_files: tuple[str, ...] = ()
    requirements: tuple[Any, ...] = ()
    model: Any = None
    selected_stages: tuple[str, ...] = ()
    stage_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    workflow_steps: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: tuple[dict[str, Any], ...] = ()
    traceability: dict[str, Any] = field(default_factory=dict)
    report: Any = None
    specification_info: dict[str, Any] = field(default_factory=dict)
    state: SessionState = SessionState.NO_PROJECT
    error: str | None = None
    validation_checks: dict[str, bool] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.project_path is not None and self.specification_path is not None \
            and self.normalized_specification is not None and self.state in {
                SessionState.READY, SessionState.COMPLETED, SessionState.PARTIAL, SessionState.ERROR}

    @property
    def current_run(self) -> Any:
        return self.report

    def open_project(self, path: str | Path, source_files: tuple[str, ...] = ()) -> None:
        self.project_path = Path(path).expanduser().resolve()
        self.specification_path = None
        self.normalized_specification = None
        self.loaded_specification = None
        self.raw_specification = None
        self.canonical_specification = None
        self.specification_format = None
        self.adapter_name = None
        self.original_spec_hash = None
        self.canonical_spec_hash = None
        self.schema_version = None
        self.validation_result = None
        self.source_files = tuple(source_files)
        self.requirements = ()
        self.model = None
        self.run_id = None
        self.selected_stages = ()
        self.stage_results.clear()
        self.evidence = ()
        self.traceability.clear()
        self.report = None
        self.specification_info.clear()
        self.error = None
        self.validation_checks = {"project": True, "specification": False, "json": False,
                                  "schema": False, "semantic": False, "sources": bool(source_files)}
        self.state = SessionState.PROJECT_LOADED

    def select_specification(self, path: str | Path) -> None:
        if self.project_path is None:
            raise ValueError("Open a project before selecting a specification")
        self.specification_path = Path(path).expanduser().resolve()
        self.normalized_specification = None
        self.loaded_specification = None
        self.raw_specification = None
        self.canonical_specification = None
        self.specification_format = None
        self.adapter_name = None
        self.original_spec_hash = None
        self.canonical_spec_hash = None
        self.schema_version = None
        self.validation_result = None
        self.requirements = ()
        self.report = None
        self.run_id = None
        self.stage_results.clear()
        self.evidence = ()
        self.traceability.clear()
        self.error = None
        self.validation_checks = {"project": self.project_path.is_dir(), "specification": True,
                                  "json": False, "schema": False, "semantic": False,
                                  "sources": bool(self.source_files)}
        self.state = SessionState.SPECIFICATION_LOADED

    def set_validated_specification(self, specification: Any, *, loaded: Any = None,
                                    adapter_info: dict[str, Any] | None = None) -> None:
        self.normalized_specification = specification
        self.loaded_specification = loaded
        adapter_info = adapter_info or {}
        self.specification_format = adapter_info.get("format", "Generic Specification")
        self.adapter_name = adapter_info.get("adapter")
        self.original_spec_hash = adapter_info.get("original_sha256")
        documents = tuple(getattr(loaded, "documents", ()))
        self.canonical_specification = documents[0].data if len(documents) == 1 else None
        self.raw_specification = adapter_info.get("raw_specification")
        self.canonical_spec_hash = adapter_info.get("canonical_sha256")
        if self.canonical_spec_hash is None and self.canonical_specification is not None:
            canonical_bytes = json.dumps(self.canonical_specification, ensure_ascii=False,
                sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            self.canonical_spec_hash = hashlib.sha256(canonical_bytes).hexdigest()
        self.schema_version = str(getattr(specification, "schema_version", "")) or None
        self.validation_result = "VALID"
        self.requirements = tuple(getattr(specification, "requirements", ()))
        self.specification_info = {"id": getattr(specification, "id", ""),
                                   "name": getattr(specification, "name", ""),
                                   "requirements": len(self.requirements),
                                   "properties": len(getattr(specification, "properties", ())),
                                   "schema_version": self.schema_version,
                                   "source_specification_path": str(self.specification_path or ""),
                                   "source_sha256": self.original_spec_hash,
                                   "canonical_sha256": self.canonical_spec_hash,
                                   "validation_result": self.validation_result,
                                   "format": self.specification_format,
                                   "adapter": self.adapter_name}
        self.state = SessionState.READY
        self.validation_checks.update({"project": bool(self.project_path and self.project_path.is_dir()),
                                       "specification": bool(self.specification_path and self.specification_path.is_file()),
                                       "json": True, "schema": True, "semantic": True,
                                       "sources": bool(self.source_files)})
        self.error = None

    def begin_run(self, stages: tuple[str, ...] = ()) -> None:
        if not self.ready:
            raise ValueError("Project and valid specification are required before verification")
        self.state = SessionState.RUNNING
        self.selected_stages = stages
        self.run_id = None
        self.stage_results.clear()
        self.evidence = ()
        self.traceability.clear()
        self.report = None
        self.error = None

    def reset_workflow(self) -> None:
        """Start GUI bookkeeping for a fresh continuous workflow in this session."""
        self.workflow_steps.clear()

    def workflow_step(self, step_id: str) -> dict[str, Any]:
        return dict(self.workflow_steps.get(step_id, {"stage_id": step_id, "status": "NOT_RUN"}))

    def update_stage(self, record: dict[str, Any]) -> None:
        stage_id = str(record.get("stage_id", "UNKNOWN"))
        self.stage_results[stage_id] = dict(record)

    def update_workflow_step(self, record: dict[str, Any]) -> None:
        step_id = str(record.get("stage_id", "UNKNOWN"))
        self.workflow_steps[step_id] = dict(record)

    def complete_run(self, report: Any, evidence: tuple[dict[str, Any], ...] = ()) -> None:
        self.report = report
        self.run_id = report.run_id
        self.evidence = tuple(evidence)
        self.traceability = dict(report.traceability)
        self.stage_results = {str(item.get("stage_id", "")): dict(item)
                              for item in report.stage_summaries}
        self.specification_info = dict(report.specification_info)
        failed = _is_partial(report)
        self.state = SessionState.PARTIAL if failed else SessionState.COMPLETED

    def open_saved_run(self, report: Any, workspace: str | Path) -> None:
        self.report = report
        self.run_id = report.run_id
        self.workspace = Path(workspace).expanduser().resolve()
        project = report.metadata.get("project")
        if project:
            self.project_path = Path(project).expanduser()
        self.specification_path = None
        self.normalized_specification = None
        self.specification_info = dict(report.specification_info)
        self.stage_results = {str(item.get("stage_id", "")): dict(item)
                              for item in report.stage_summaries}
        self.evidence = ()
        self.traceability = dict(report.traceability)
        self.requirements = ()
        self.source_files = tuple(item.get("project_relative_path", item) if isinstance(item, dict)
                                  else str(item) for item in report.metadata.get("source_inventory", {}).get("files", ()))
        self.state = SessionState.PARTIAL if _is_partial(report) else SessionState.COMPLETED
        self.validation_checks = {"project": bool(self.project_path), "specification": False,
                                  "json": False, "schema": False, "semantic": False,
                                  "sources": bool(self.source_files)}

    def fail(self, message: str) -> None:
        self.error = message
        if self.state in {SessionState.SPECIFICATION_LOADED, SessionState.PROJECT_LOADED}:
            self.validation_checks.update({"json": False, "schema": False, "semantic": False})
        self.state = SessionState.ERROR


def _is_partial(report: Any) -> bool:
    return (bool(getattr(report, "metadata", {}).get("cancelled"))
            or any(item.get("status") == "FAILED" for item in report.stage_summaries)
            or any(report.status_counts.get(status, 0) for status in ("TOOL_ERROR", "BUILD_ERROR")))
