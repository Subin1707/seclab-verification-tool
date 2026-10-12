"""Adapter to existing pipeline and workspace manifest/report APIs."""
from __future__ import annotations

import json
import hashlib
from threading import Event
from dataclasses import replace
from collections.abc import Callable
from pathlib import Path
from typing import Any

from seclab.evidence import RunManifest
from seclab.pipeline import PipelineOptions, load_previous_run, run_full_verification
from seclab.pipeline.report import PipelineReport


class VerificationController:
    def __init__(self, project_controller: Any) -> None:
        self.project_controller = project_controller
        self.workspace: Path | None = None
        self.report: PipelineReport | None = None
        self.last_error: dict[str, str] | None = None
        self.logs: list[dict[str, str]] = []

    def verify_specification(self) -> Any:
        self._log("SPECIFICATION", "INFO", "Validating and normalizing selected specification")
        return self.project_controller.normalize()

    def run_full(self, workspace: str | Path, *, options: PipelineOptions | None = None,
                 run_id: str | None = None,
                 cancellation_event: Event | None = None,
                 progress_callback: Callable[[dict[str, Any]], None] | None = None) -> PipelineReport:
        project = self.project_controller.project_path
        if project is None:
            raise ValueError("Open a project first")
        spec_path = self.project_controller.specification_path
        selected = self._session_options(options, spec_path)
        if not self.project_controller.verify_original_unchanged():
            raise RuntimeError("Original specification SHA-256 changed after adaptation; pipeline was not started.")
        self.workspace = Path(workspace).expanduser().resolve()
        self._log("PIPELINE", "INFO", "Full verification started")
        self.report = run_full_verification(project, self.workspace, options=selected, run_id=run_id,
                                            cancellation_event=cancellation_event,
                                            progress_callback=progress_callback)
        if not self.project_controller.verify_original_unchanged():
            raise RuntimeError("Original specification SHA-256 changed during verification.")
        self._log("PIPELINE", "INFO", "Full verification report is ready")
        for stage in self.report.stage_summaries:
            self._log(str(stage["stage_id"]), str(stage["status"]), str(stage.get("reason") or "Stage finished"))
        return self.report

    def run_stages(self, workspace: str | Path, stages: tuple[str, ...], *,
                   options: PipelineOptions | None = None,
                   cancellation_event: Event | None = None,
                   progress_callback: Callable[[dict[str, Any]], None] | None = None) -> PipelineReport:
        project = self.project_controller.project_path
        if project is None:
            raise ValueError("Open a project first")
        spec_path = self.project_controller.specification_path
        selected = self._session_options(options, spec_path)
        if not self.project_controller.verify_original_unchanged():
            raise RuntimeError("Original specification SHA-256 changed after adaptation; pipeline was not started.")
        self.workspace = Path(workspace).expanduser().resolve()
        self._log("PIPELINE", "INFO", f"Requested stages: {', '.join(stages)}")
        self.report = run_full_verification(project, self.workspace, options=selected, stage_ids=stages,
                                            cancellation_event=cancellation_event,
                                            progress_callback=progress_callback)
        if not self.project_controller.verify_original_unchanged():
            raise RuntimeError("Original specification SHA-256 changed during verification.")
        self._log("PIPELINE", "INFO", "Selected stage report is ready")
        for stage in self.report.stage_summaries:
            self._log(str(stage["stage_id"]), str(stage["status"]), str(stage.get("reason") or "Stage finished"))
        return self.report

    def load_run_history(self) -> tuple[dict[str, Any], ...]:
        if self.workspace is None or not self.workspace.exists():
            return ()
        records = []
        for manifest_path in sorted(self.workspace.glob("*/evidence/manifest/run-manifest.json"),
                                    key=lambda path: path.stat().st_mtime, reverse=True):
            try:
                workspace_root = self.workspace.resolve()
                run_root = manifest_path.parents[2].resolve(strict=True)
                selected_manifest = manifest_path.resolve(strict=True)
                if not run_root.is_relative_to(workspace_root) or not selected_manifest.is_relative_to(run_root):
                    continue
                manifest = RunManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
                report_path = run_root / "evidence" / "report" / "pipeline-report.json"
                selected_report = report_path.resolve(strict=True) if report_path.is_file() else None
                if selected_report is not None and not selected_report.is_relative_to(run_root):
                    continue
                report_data = json.loads(selected_report.read_text(encoding="utf-8")) if selected_report else {}
                stage_statuses = manifest.metadata.get("stage_statuses", {})
                if not stage_statuses:
                    stage_statuses = {item.get("stage_id", ""): item.get("status", "")
                                      for item in manifest.metadata.get("stage_records", ())}
                spec_info = report_data.get("specification_info", {})
                project = manifest.project
                records.append({"run_id": manifest.run_id, "date": manifest.started_at.isoformat(),
                    "timestamp": manifest.started_at.isoformat(),
                    "project": project.get("name") or project.get("path", ""),
                    "project_path": project.get("path", ""),
                    "specification": spec_info.get("id") or spec_info.get("name", ""),
                    "stage_statuses": dict(stage_statuses),
                    "stage_count": len(stage_statuses),
                    "result_count": len(report_data.get("results", ())),
                    "evidence_count": len(manifest.evidence),
                    "completion_state": ("COMPLETED" if manifest.finished_at else "INCOMPLETE"),
                    "workspace": str(run_root),
                    "duration": (manifest.finished_at - manifest.started_at).total_seconds()
                                if manifest.finished_at else None,
                    "manifest": str(manifest_path), "report": str(report_path),
                    "run_root": str(run_root)})
            except Exception:
                continue
        return tuple(records)

    def load_report(self, path: str | Path) -> PipelineReport:
        selected = Path(path).expanduser().resolve(strict=True)
        if self.workspace is not None and not selected.is_relative_to(self.workspace.resolve()):
            raise ValueError("Pipeline report path escapes the selected run workspace")
        self.report = PipelineReport.from_dict(json.loads(selected.read_text(encoding="utf-8")))
        return self.report

    def reopen_run(self, workspace: str | Path, run_id: str) -> PipelineReport:
        """Open and integrity-check a persisted run without starting verification."""
        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        self.report = load_previous_run(self.workspace, run_id)
        self._log("PIPELINE", "INFO", f"Loaded persisted run {run_id} without rerunning verification")
        return self.report

    def read_accuracy_report(self, path: str | Path) -> str:
        """Read a user-selected Markdown/JSON benchmark report for display."""
        selected = Path(path).expanduser().resolve(strict=True)
        if selected.suffix.casefold() not in {".md", ".json"}:
            raise ValueError("Accuracy reports must be Markdown or JSON files")
        if selected.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Accuracy report is larger than the 4 MiB display limit")
        return selected.read_text(encoding="utf-8")

    def read_evidence_metadata(self, evidence_id: str) -> dict[str, Any]:
        if self.report is None or self.workspace is None:
            raise ValueError("No run report is loaded")
        workspace_root = self.workspace.resolve()
        run_root = (workspace_root / self.report.run_id).resolve()
        if not run_root.is_relative_to(workspace_root):
            raise ValueError("Run path escapes the selected workspace")
        manifest_path = (run_root / "evidence" / "manifest" / "run-manifest.json").resolve(strict=True)
        if not manifest_path.is_relative_to(run_root):
            raise ValueError("Run manifest path escapes the run workspace")
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        item = next((entry for entry in data.get("evidence", ()) if entry.get("id") == evidence_id), None)
        if item is None:
            raise KeyError(f"Evidence ID {evidence_id} was not found in the run manifest")
        return dict(item)

    def read_evidence(self, evidence_id: str) -> tuple[dict[str, Any], Path]:
        return self.read_evidence_metadata(evidence_id), self.evidence_path(evidence_id)

    def verify_evidence(self, evidence_id: str) -> dict[str, Any]:
        """Verify a manifest artifact without changing it; report corruption as data."""
        try:
            metadata = self.read_evidence_metadata(evidence_id)
        except KeyError as exc:
            return {"evidence_id": evidence_id, "status": "MISSING", "path": "",
                    "expected_sha256": "", "actual_sha256": "", "error": str(exc)}
        except (OSError, ValueError) as exc:
            return {"evidence_id": evidence_id, "status": "INTEGRITY_ERROR", "path": "",
                    "expected_sha256": "", "actual_sha256": "", "error": str(exc)}
        try:
            path = self.evidence_path(evidence_id)
            payload = path.read_bytes()
            return {"evidence_id": evidence_id, "status": "VERIFIED", "path": str(path),
                    "expected_sha256": metadata.get("hash", ""),
                    "actual_sha256": hashlib.sha256(payload).hexdigest(),
                    "expected_size_bytes": metadata.get("size_bytes"),
                    "actual_size_bytes": len(payload), "error": ""}
        except FileNotFoundError as exc:
            return {"evidence_id": evidence_id, "status": "MISSING", "path": metadata.get("path", ""),
                    "expected_sha256": metadata.get("hash", ""), "actual_sha256": "", "error": str(exc)}
        except (OSError, ValueError) as exc:
            return {"evidence_id": evidence_id, "status": "INTEGRITY_ERROR", "path": metadata.get("path", ""),
                    "expected_sha256": metadata.get("hash", ""), "actual_sha256": "", "error": str(exc)}

    def evidence_path(self, evidence_id: str) -> Path:
        if self.report is None or self.workspace is None:
            raise ValueError("No run report is loaded")
        run_root = self.workspace / self.report.run_id
        item = self.read_evidence_metadata(evidence_id)
        target = (run_root / item["path"]).resolve(strict=True)
        if not target.is_relative_to(run_root.resolve()):
            raise ValueError("Evidence path escapes the run workspace")
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_hash != item.get("hash"):
            raise ValueError("Evidence SHA-256 does not match the run manifest")
        if item.get("size_bytes") is None or target.stat().st_size != item.get("size_bytes"):
            raise ValueError("Evidence size does not match the run manifest")
        return target

    def _log(self, stage: str, level: str, message: str) -> None:
        from datetime import datetime, timezone
        self.logs.append({"timestamp": datetime.now(timezone.utc).isoformat(), "stage": stage,
                          "level": level, "message": message})

    def _session_options(self, options: PipelineOptions | None, spec_path: Path | None) -> PipelineOptions:
        selected = options or PipelineOptions(specification_paths=(spec_path,) if spec_path else ())
        if spec_path is not None and self.project_controller.specification is None:
            self.project_controller.normalize()
        if self.project_controller.validated_specification is not None and self.project_controller.specification is not None:
            selected = replace(selected,
                specification_paths=(spec_path,) if spec_path else selected.specification_paths,
                loaded_specification=self.project_controller.loaded,
                validated_specification=self.project_controller.validated_specification,
                normalized_specification=self.project_controller.specification)
        info = self.project_controller.specification_info or {}
        if info.get("adapter"):
            metadata = dict(selected.metadata)
            metadata["specification_provenance"] = dict(info)
            selected = replace(selected, metadata=metadata)
        return selected
