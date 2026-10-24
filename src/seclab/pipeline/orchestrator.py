"""Deterministic, failure-isolated stage orchestration for full verification."""
from __future__ import annotations

import uuid
import hashlib
import json
from threading import Event
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from seclab.evidence import EvidenceType, RunManifest
from seclab.execution import CommandRunner, capture_environment
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier, VerificationStatus

from .context import VerificationContext, TrackedArtifactStore
from .options import PipelineOptions
from .report import PipelineReport
from .stage import FunctionalStage, Stage, StageOutput, StageRecord, StageSkipped, StageStatus
from .stages import PipelineStages


STAGE_ORDER = ("SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN", "BUILD", "STATIC", "MEMORY",
               "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT")
OPTIONAL_STAGE_INPUTS = {
    "STATIC": ("SOURCE", "CODEGEN"),
    "MEMORY": ("SOURCE", "CODEGEN"),
    "DYNAMIC": ("SOURCE", "BUILD"),
    "COVERAGE": ("SOURCE", "CODEGEN", "BUILD"),
    "FUZZING": ("SOURCE", "CODEGEN", "BUILD"),
}


class PipelineOrchestrator:
    def __init__(self, stages: Iterable[Stage], *, options: PipelineOptions | None = None) -> None:
        self.options = options or PipelineOptions()
        self.stages = tuple(stages)
        self._by_id = {stage.stage_id: stage for stage in self.stages}
        if len(self._by_id) != len(self.stages):
            raise ValueError("Stage IDs must be unique.")
        self._validate_graph()

    def _validate_graph(self) -> None:
        for stage in self.stages:
            unknown = set(stage.dependencies) - self._by_id.keys()
            if unknown:
                raise ValueError(f"Stage {stage.stage_id} has unknown dependencies: {sorted(unknown)}")
        seen: set[str] = set()
        for stage_id in self._ordered_ids():
            if stage_id in seen:
                raise ValueError("Stage dependency graph contains a cycle.")
            seen.add(stage_id)
        if len(seen) != len(self.stages):
            raise ValueError("Stage dependency graph contains a cycle.")

    def _ordered_ids(self) -> tuple[str, ...]:
        pending = list(self.stages)
        ordered: list[str] = []
        while pending:
            ready = [item for item in pending if set(item.dependencies) <= set(ordered)]
            if not ready:
                raise ValueError("Stage dependency graph contains a cycle.")
            ready.sort(key=lambda item: (STAGE_ORDER.index(item.stage_id) if item.stage_id in STAGE_ORDER else 999,
                                         item.stage_id))
            # Select one ready stage at a time so a preferred dependent stage can
            # precede an unrelated stage while retaining dependency correctness.
            ordered.append(ready[0].stage_id)
            pending = [item for item in pending if item.stage_id != ready[0].stage_id]
        return tuple(ordered)

    @classmethod
    def full(cls, options: PipelineOptions | None = None) -> "PipelineOrchestrator":
        from .stages import PipelineStages as S
        entries = [
            ("SPECIFICATION", "Specification", S.specification, ()),
            ("MODEL", "Kripke Model", S.model, ("SPECIFICATION",)),
            ("CTL", "CTL Verification", S.ctl, ("SPECIFICATION", "MODEL")),
            ("BMC", "Bounded Model Checking", S.bmc, ("SPECIFICATION", "MODEL")),
            ("SMT", "SMT Verification", S.smt, ("SPECIFICATION",)),
            ("SOURCE", "Source Discovery", S.source, ()),
            ("CODEGEN", "Specification C Generation", S.codegen, ("SPECIFICATION",)),
            ("BUILD", "Generated Model Build", S.build, ("CODEGEN",)),
            ("STATIC", "Static Analysis", S.static, ()),
            ("MEMORY", "Memory Analysis", S.memory, ()),
            ("DYNAMIC", "Dynamic Tests", S.dynamic, ("SPECIFICATION",)),
            ("COVERAGE", "Coverage Measurement", S.coverage, ("DYNAMIC",)),
            # Coverage feedback is strategy-dependent and is checked by the fuzzing
            # adapter. It is not a hard prerequisite for black-box campaigns.
            # Fuzzing can create no-crash templates from detected source functions,
            # so optional specification/dynamic stages must not block this stage.
            ("FUZZING", "Fuzzing", S.fuzzing, ()),
            # Cross-checking inspects available independent outputs and must still
            # run when an optional checker is skipped or environment-limited.
            ("CROSS_CHECK", "Cross-check Matrix", S.cross_check, ()),
            ("REPORT", "Report Assembly", lambda _ctx, _opts: StageOutput(),
             ("SPECIFICATION", "MODEL", "SOURCE", "CTL", "BMC", "SMT", "CODEGEN", "BUILD", "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK")),
        ]
        report_entry = entries.pop()
        entries.append(report_entry)
        stages = tuple(FunctionalStage(stage_id, name,
            # Stage configuration is read from the per-run context. Do not let
            # a closure retain a second, potentially divergent configuration.
            lambda ctx, fn=fn: fn(ctx, ctx.options or PipelineOptions()), dependencies)
            for stage_id, name, fn, dependencies in entries)
        return cls(stages, options=options)

    def run(self, project: str | Path, workspace: str | Path, *, run_id: str | None = None,
            stage_ids: Iterable[str] | None = None,
            cancellation_event: Event | None = None,
            progress_callback: Callable[[dict[str, Any]], None] | None = None) -> PipelineReport:
        project_path = Path(project).expanduser().resolve(strict=True)
        workspace_root = Path(workspace).expanduser().resolve()
        workspace_root.mkdir(parents=True, exist_ok=True)
        workspace_root = workspace_root.resolve(strict=True)
        if not project_path.is_dir():
            raise ValueError("project must be an existing directory")
        if workspace_root == project_path or workspace_root.is_relative_to(project_path):
            raise ValueError("Pipeline workspace must be outside the source project directory.")
        run_id = _safe_run_id(run_id or uuid.uuid4().hex)
        run_root = workspace_root / run_id
        run_root.mkdir(parents=True, exist_ok=False)
        now = datetime.now(timezone.utc)
        tools = CommandRunner()
        from seclab.config import Toolchain
        toolchain = Toolchain(self.options.toolchain_tools, command_runner=tools)
        ctx = VerificationContext(run_id, project_path, run_root, now, TrackedArtifactStore(run_root, run_id), toolchain,
                              options=self.options, command_runner=tools, progress_callback=progress_callback)
        _prime_specification_hashes(ctx)
        selected = self._select_stages(stage_ids)
        for stage_id in self._ordered_ids():
            stage = self._by_id[stage_id]
            ctx.stage_records[stage_id] = StageRecord(stage_id, stage.name)
            ctx.stage_records[stage_id].selected = stage_id in selected
            if stage_id not in selected:
                ctx.stage_records[stage_id].status = StageStatus.SKIPPED
                ctx.stage_records[stage_id].reason = "Stage was not selected for this run."
        for stage_id in selected:
            stage = self._by_id[stage_id]
            record = ctx.stage_records[stage_id]
            if cancellation_event is not None and cancellation_event.is_set() and stage_id not in {"REPORT", "CROSS_CHECK"}:
                record.status = StageStatus.SKIPPED
                record.reason = "Run cancelled before this stage started."
                timestamp = datetime.now(timezone.utc).isoformat()
                record.started_at = record.finished_at = timestamp
                _notify_progress(progress_callback, record, run_id=run_id)
                continue
            record.input_refs = _stage_input_refs(stage_id, stage.dependencies, ctx, self.options)
            blocked = ([] if stage_id in {"REPORT", "CROSS_CHECK"} else
                       [dep for dep in stage.dependencies
                        if stage_id != "SOURCE" or dep in selected
                        if ctx.stage_records[dep].status in
                        {StageStatus.FAILED, StageStatus.SKIPPED}
                        ])
            if blocked:
                record.status = StageStatus.SKIPPED
                record.reason = f"Required input stages did not complete: {', '.join(blocked)}."
                timestamp = datetime.now(timezone.utc).isoformat()
                record.started_at = record.finished_at = timestamp
                _notify_progress(progress_callback, record, run_id=run_id)
                continue
            record.status = StageStatus.RUNNING
            record.started_at = datetime.now(timezone.utc).isoformat()
            _notify_progress(progress_callback, record, run_id=run_id)
            started = ctx.monotonic()
            artifact_ids_before = ctx.artifact_store.ids()
            progress_results: tuple[Any, ...] = ()
            progress_evidence: tuple[Any, ...] = ()
            try:
                output = stage.execute(ctx)
                if not isinstance(output, StageOutput):
                    raise TypeError(f"Stage {stage_id} returned {type(output).__name__}, expected StageOutput")
                progress_results = tuple(output.results)
                ctx.add_results(output.results)
                ctx.add_evidence(output.evidence)
                ctx.flush_artifacts()
                if stage_id == "SOURCE":
                    _cache_source_hashes(ctx)
                created_artifact_ids = tuple(ctx.artifact_store.ids() - artifact_ids_before)
                progress_evidence = tuple(item for item in ctx.artifact_store.all()
                                          if item.id in set(created_artifact_ids))
                record.output_refs = created_artifact_ids
                if output.value is not None and output.value.__class__.__name__ == "FuzzCampaignResult":
                    for result in output.results:
                        record.result_ids = tuple((*record.result_ids, result.id))
                ctx.limitations.extend(item for item in output.limitations if item not in ctx.limitations)
                record.output = _stage_summary(output.value)
                record.result_ids = tuple(item.id for item in output.results)
                record.evidence_ids = tuple(dict.fromkeys((
                    *created_artifact_ids, *(item.id for item in output.evidence))))
                record.metadata.update(output.metadata)
                record.reason = output.value.reason if isinstance(output.value, StageSkipped) else None
                record.status = StageStatus.SKIPPED if record.reason else StageStatus.COMPLETED
                if output.value is not None and output.value.__class__.__name__ == "FuzzCampaignResult":
                    record.status = StageStatus.COMPLETED
                if output.metadata.get("stage_status") == "FAILED":
                    record.status = StageStatus.FAILED
                    record.reason = output.metadata.get("error")
                    record.error_type = "StageInputError"
            except Exception as exc:
                record.status = StageStatus.FAILED
                record.error_type = type(exc).__name__
                record.reason = str(exc)
                try:
                    ref = ctx.artifact_store.write_json("pipeline-errors", f"{stage_id.lower()}-error.json",
                        {"stage_id": stage_id, "error_type": type(exc).__name__, "message": str(exc)},
                        evidence_type=EvidenceType.LOG)
                    result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                        stage=stage_id, technique="PIPELINE_STAGE", reason_code="STAGE_FAILED",
                        message=f"{stage.name} stage failed: {exc}", evidence_ids=(ref.id,),
                        metadata={"error_type": type(exc).__name__}))
                    ctx.add_evidence((ref,)); ctx.add_results((result,))
                    ctx.flush_artifacts()
                    stage_artifacts = tuple(ctx.artifact_store.ids() - artifact_ids_before)
                    progress_results = (result,)
                    progress_evidence = tuple(item for item in ctx.artifact_store.all()
                                              if item.id in set(stage_artifacts))
                    record.result_ids = (result.id,)
                    record.evidence_ids = tuple(dict.fromkeys((*stage_artifacts, ref.id)))
                    record.output_refs = record.evidence_ids
                except Exception as artifact_error:
                    ctx.limitations.append(f"Could not persist failure evidence for {stage_id}: {artifact_error}")
            finally:
                record.duration_ms = max(0.0, (ctx.monotonic() - started) * 1000.0)
                record.finished_at = datetime.now(timezone.utc).isoformat()
                _notify_progress(progress_callback, record, progress_results, progress_evidence, run_id)
        for record in ctx.stage_records.values():
            if record.stage_id == "REPORT":
                record.output_refs = ("path:evidence/manifest/run-manifest.json",
                                      "path:evidence/report/pipeline-report.json")
            try:
                _record_stage_execution(ctx, record)
            except Exception as artifact_error:
                ctx.limitations.append(f"Could not persist stage execution evidence for {record.stage_id}: {artifact_error}")
        ctx.finished_at = datetime.now(timezone.utc)
        if cancellation_event is not None and cancellation_event.is_set():
            ctx.metadata["cancelled"] = True
            ctx.limitations.append("Run cancellation was requested; the active stage was allowed to finish and remaining stages were skipped.")
        for req_id, row in ctx.traceability.items():
            statuses = [result.status.value for result in ctx.result_collector.all() if result.requirement_id == req_id]
            row["status"] = "CHECKED" if statuses else "NOT_CHECKED"
        ctx.metadata["workflow"] = {
            "stage_order": [record.stage_id for record in ctx.stage_records.values()],
            "stage_statuses": {key: value.status.value for key, value in ctx.stage_records.items()},
            "single_project_load": True,
            "single_specification_load": True,
        }
        if ctx.options is not None and ctx.options.metadata.get("workflow_chapter"):
            ctx.metadata["workflow"]["workflow_chapter"] = ctx.options.metadata["workflow_chapter"]
        return self._assemble_report(ctx)

    def _select_stages(self, requested: Iterable[str] | None) -> tuple[str, ...]:
        if requested is None:
            return self._ordered_ids()
        targets = set(requested)
        unknown = targets - self._by_id.keys()
        if unknown:
            raise ValueError(f"Unknown pipeline stage(s): {', '.join(sorted(unknown))}")
        required = set(targets)
        pending = list(targets)
        while pending:
            current = pending.pop()
            if current == "REPORT":
                continue
            for dependency in self._by_id[current].dependencies:
                if dependency not in required:
                    required.add(dependency)
                    pending.append(dependency)
            for optional_input in OPTIONAL_STAGE_INPUTS.get(current, ()):
                if optional_input not in required:
                    required.add(optional_input)
                    pending.append(optional_input)
        # Report is always assembled from the selected run; its full-stage dependency
        # list is informational and does not force unrequested stages to execute.
        if "REPORT" in self._by_id:
            required.add("REPORT")
        if "CROSS_CHECK" in self._by_id and (requested is None or any(item != "REPORT" for item in targets)):
            required.add("CROSS_CHECK")
        return tuple(item for item in self._ordered_ids() if item in required)

    def _assemble_report(self, ctx: VerificationContext) -> PipelineReport:
        assert ctx.finished_at is not None
        source_integrity, integrity_ref = _record_source_integrity(ctx)
        ctx.flush_artifacts()
        _enrich_evidence_provenance(ctx)
        artifact_integrity = _verify_artifact_hashes(ctx)
        invalid_artifacts = [item for item in artifact_integrity if not item["valid"]]
        broken_refs = _broken_evidence_references(ctx)
        duplicate_ids = _duplicate_trace_ids(ctx)
        if invalid_artifacts or broken_refs or duplicate_ids:
            integrity_ref_error = ctx.artifact_store.write_json("report", "artifact-integrity-errors.json",
                {"run_id": ctx.run_id, "artifacts": invalid_artifacts,
                 "broken_evidence_references": broken_refs,
                 "duplicate_ids": duplicate_ids}, evidence_type=EvidenceType.LOG)
            result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                stage="REPORT", technique="ARTIFACT_INTEGRITY", reason_code="ARTIFACT_HASH_MISMATCH",
                message=(f"{len(invalid_artifacts)} run artifact(s) failed integrity checks; "
                         f"{len(broken_refs)} result evidence reference(s) and {len(duplicate_ids)} duplicate ID(s) do not resolve."),
                evidence_ids=(integrity_ref_error.id,),
                metadata={"invalid_artifact_ids": [item["artifact_id"] for item in invalid_artifacts],
                          "broken_evidence_references": broken_refs, "duplicate_ids": duplicate_ids}))
            ctx.add_evidence((integrity_ref_error,)); ctx.add_results((result,)); ctx.flush_artifacts()
            _enrich_evidence_provenance(ctx)
            ctx.limitations.append("Run artifact integrity or evidence-reference checks failed; see artifact-integrity-errors.json.")
            artifact_integrity = _verify_artifact_hashes(ctx)
            report_stage_record = ctx.stage_records.get("REPORT")
            if report_stage_record is not None:
                report_stage_record.result_ids = (result.id,)
                report_stage_record.evidence_ids = (integrity_ref_error.id,)
                report_stage_record.output_refs = (integrity_ref_error.id,)
        results = _detach_unresolved_evidence(ctx)
        evidence = ctx.evidence_collector.all()
        evidence_by_id = {item.id: item for item in evidence}
        source_hashes = {item["path"]: item["before_sha256"] for item in source_integrity
                         if item.get("before_sha256")}
        result_traceability = {}
        for result in results:
            stage_id = _stage_for_result(result)
            stage = ctx.stage_records.get(stage_id)
            applicable_source_hashes = (source_hashes if result.stage.upper() in {
                "STATIC_ANALYSIS", "SANITIZER", "MEMORY_ANALYSIS", "DYNAMIC_TEST", "COVERAGE", "FUZZING"
            } else {})
            result_traceability[result.id] = {
                "run_id": ctx.run_id, "checker": result.technique, "stage_id": stage_id,
                "scope": result.scope, "source_hashes": applicable_source_hashes,
                "input_refs": list(stage.input_refs) if stage else [],
                "evidence": [evidence_by_id[item].to_dict() for item in result.evidence_ids
                             if item in evidence_by_id],
                "unresolved_evidence_ids": list(result.metadata.get("unresolved_evidence_ids", ()))
                    + [item for item in result.evidence_ids if item not in evidence_by_id],
            }
        source_inventory = _source_lineage_report(ctx, results, source_integrity,
                                                  integrity_ref.id if integrity_ref else None)
        tool_versions = {item.name: item.version for item in ctx.toolchain.all() if item.version}
        report_provenance = _run_provenance(ctx, "COMPLETED")
        report_stage = ctx.stage_records.get("REPORT")
        if report_stage is not None:
            report_stage.output_refs = ("path:evidence/manifest/run-manifest.json",
                                        "path:evidence/report/pipeline-report.json")
        _complete_stage_reasons(ctx)
        counts = {status.value: 0 for status in VerificationStatus}
        for result in results:
            counts[result.status.value] += 1
        report = PipelineReport(ctx.run_id, ctx.started_at, ctx.finished_at, ctx.elapsed_seconds,
            {"id": ctx.specification.id, "name": ctx.specification.name,
             "requirements": len(ctx.specification.requirements), "properties": len(ctx.specification.properties)}
             if ctx.specification else {},
            tuple({**record.to_dict(), "output": _stage_summary(record.output)}
                  for record in ctx.stage_records.values()), results, counts,
            {"path": "evidence/manifest/run-manifest.json", "evidence_count": len(evidence) + 1,
             "result_count": len(results)},
            {key: dict(value) for key, value in ctx.traceability.items()}, tuple(ctx.limitations),
            {"project": str(ctx.project), "workspace": str(ctx.workspace), "source_inventory": source_inventory,
             "source_integrity": source_integrity, "workflow": dict(ctx.metadata.get("workflow", {})),
             "property_model_links": dict(ctx.metadata.get("property_model_links", {})),
             "property_test_cases": dict(ctx.metadata.get("property_test_cases", {})),
             "execution_index": dict(ctx.metadata.get("execution_index", {})),
             "cross_check_matrix": ctx.metadata.get("cross_check_matrix", {}),
             "cross_check_matrix_evidence_id": ctx.metadata.get("cross_check_matrix_evidence_id"),
             "specification": _plain_data(ctx.specification) if ctx.specification is not None else {},
             "artifact_classes": _report_artifact_classes(ctx.evidence_collector.all()),
             "generated_artifacts": [{"artifact_class": artifact_class, "evidence_ids": [item.id for item in ctx.evidence_collector.all()
                                  if item.metadata.get("artifact_class") == artifact_class or
                                     artifact_class == "GENERATED_SOURCE" and item.metadata.get("artifact_role") == "GENERATED_ARTIFACT"]}
                                  for artifact_class in ("GENERATED_ARTIFACT", "GENERATED_SOURCE", "TEST_HARNESS", "FUZZ_HARNESS")],
             "artifact_integrity": artifact_integrity,
             "reproducibility": report_provenance,
             "traceability_integrity": {**_verify_traceability(ctx, results, evidence),
                 "duplicate_ids": duplicate_ids,
                 "valid": _verify_traceability(ctx, results, evidence)["valid"] and not duplicate_ids},
             "cancelled": bool(ctx.metadata.get("cancelled")),
             "gui_run_configuration": dict(self.options.metadata.get("gui_run_configuration", {}))})
        report_ref = ctx.artifact_store.write_json("report", "pipeline-report.json", report.to_dict(),
            evidence_type=EvidenceType.LOG, checker="REPORT", run_id=ctx.run_id,
            metadata={"status": "COMPLETED", "provenance": report_provenance, **report_provenance})
        ctx.add_evidence((report_ref,)); ctx.flush_artifacts()
        if report_stage is not None:
            report_stage.evidence_ids = tuple(dict.fromkeys((*report_stage.evidence_ids, report_ref.id)))
        final_evidence = ctx.evidence_collector.all()
        manifest = RunManifest(run_id=ctx.run_id,
            project={"path": str(ctx.project), "name": ctx.project.name}, started_at=ctx.started_at,
            finished_at=ctx.finished_at, results=results, evidence=final_evidence,
            environment=capture_environment(ctx.toolchain.summary()).to_dict(), tool_versions=tool_versions,
            input_artifacts=[str(path) for path in self.options.specification_paths],
            metadata={"stage_statuses": {key: value.status.value for key, value in ctx.stage_records.items()},
                      "stage_records": [record.to_dict() for record in ctx.stage_records.values()],
                      "workflow": dict(ctx.metadata.get("workflow", {})),
                      "reproducibility": report_provenance,
                      "source_integrity_evidence_id": integrity_ref.id if integrity_ref else None,
                      "artifact_classes": _report_artifact_classes(final_evidence),
                      "generated_artifacts": [{"artifact_class": artifact_class, "evidence_ids": [item.id for item in final_evidence
                                           if item.metadata.get("artifact_class") == artifact_class or
                                              artifact_class == "GENERATED_SOURCE" and item.metadata.get("artifact_role") == "GENERATED_ARTIFACT"]}
                                           for artifact_class in ("GENERATED_ARTIFACT", "GENERATED_SOURCE", "TEST_HARNESS", "FUZZ_HARNESS")],
                      "result_traceability": result_traceability})
        ctx.manifest = manifest
        manifest_ref = ctx.artifact_store.write_json("manifest", "run-manifest.json", manifest.to_dict(),
            evidence_type=EvidenceType.ENVIRONMENT, checker="MANIFEST", run_id=ctx.run_id,
            metadata={"status": "COMPLETED", "provenance": report_provenance, **report_provenance})
        ctx.add_evidence((manifest_ref,)); ctx.flush_artifacts()
        integrity_record = {"schema_version": "1.0", "run_id": ctx.run_id,
            "manifest_evidence": {"id": manifest_ref.id, "type": manifest_ref.type.value,
                "path": manifest_ref.path, "sha256": manifest_ref.hash,
                "source_sha256": report_provenance["source_sha256"], "run_id": ctx.run_id,
                "timestamp": manifest_ref.timestamp.isoformat(),
                "tool_versions": report_provenance["tool_versions"],
                "configuration_sha256": report_provenance["configuration_sha256"],
                "status": "COMPLETED"},
            "report": {"path": report_ref.path, "sha256": report_ref.hash,
                       "size_bytes": report_ref.size_bytes},
            "manifest": {"path": manifest_ref.path, "sha256": manifest_ref.hash,
                         "size_bytes": manifest_ref.size_bytes}}
        (ctx.workspace / "evidence" / "manifest" / "run-integrity.json").write_text(
            __import__("json").dumps(integrity_record, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8")
        final_integrity = _verify_artifact_hashes(ctx)
        final_artifact_ids = {report_ref.id, manifest_ref.id}
        if any(not item["valid"] for item in final_integrity
               if item["artifact_id"] in final_artifact_ids):
            raise RuntimeError("Final report/manifest artifact integrity check failed.")
        _verify_report_manifest_hashes(ctx, report_ref, manifest_ref)
        return report


def _verify_artifact_hashes(ctx: VerificationContext) -> list[dict[str, Any]]:
    import hashlib

    verified = []
    for evidence in ctx.evidence_collector.all():
        try:
            unresolved = ctx.workspace / evidence.path
            if unresolved.is_symlink() and not unresolved.resolve(strict=False).is_relative_to(ctx.workspace.resolve()):
                raise ValueError("artifact path resolves outside the run workspace")
            unresolved = unresolved.resolve(strict=False)
            if not unresolved.is_relative_to(ctx.workspace.resolve()):
                raise ValueError("artifact path resolves outside the run workspace")
            artifact = unresolved.resolve(strict=True)
            if not artifact.is_relative_to(ctx.workspace.resolve()) or not artifact.is_file():
                raise ValueError("artifact path is outside the run workspace or is not a file")
            payload = artifact.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            size_matches = evidence.size_bytes is not None and len(payload) == evidence.size_bytes
            hash_matches = digest == evidence.hash
            valid = hash_matches and size_matches and evidence.run_id == ctx.run_id and bool(evidence.checker)
            errors = []
            if not hash_matches:
                errors.append("SHA-256 differs from evidence metadata")
            if not size_matches:
                errors.append("artifact size is missing or differs from evidence metadata")
            if evidence.run_id != ctx.run_id:
                errors.append("evidence run_id does not match current run")
            if not evidence.checker:
                errors.append("evidence checker is missing")
            error = "; ".join(errors) or None
        except (OSError, ValueError) as exc:
            digest, valid, error = None, False, f"{type(exc).__name__}: {exc}"
        verified.append({"artifact_id": evidence.id, "type": evidence.type.value,
                         "stage": evidence.stage, "checker": evidence.checker,
                         "run_id": evidence.run_id, "path": evidence.path,
                         "expected_size_bytes": evidence.size_bytes,
                         "actual_size_bytes": len(payload) if digest is not None else None,
                         "expected_sha256": evidence.hash, "actual_sha256": digest,
                         "valid": valid, "error": error})
    return verified


def _cache_source_hashes(ctx: VerificationContext) -> None:
    """Cache source digests discovered by SOURCE for all later provenance records."""
    for item in _provenance_sources(ctx):
        path = Path(item.path if hasattr(item, "path") else item)
        relative = getattr(item, "relative_path", path.name)
        digest = getattr(item, "sha256", None)
        if digest is None:
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                digest = None
        ctx.source_hashes[str(relative)] = digest


def _prime_specification_hashes(ctx: VerificationContext) -> None:
    """Hash specification inputs once; stage execution records reuse these digests."""
    for specification_path in getattr(ctx.options, "specification_paths", ()):
        path = Path(specification_path)
        try:
            ctx.specification_input_hashes[str(path.name)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            ctx.specification_input_hashes[str(path.name)] = None


def _broken_evidence_references(ctx: VerificationContext) -> list[dict[str, str]]:
    known = {item.id for item in ctx.evidence_collector.all()}
    return [{"result_id": result.id, "evidence_id": evidence_id}
            for result in ctx.result_collector.all() for evidence_id in result.evidence_ids
            if evidence_id not in known]


def _duplicate_trace_ids(ctx: VerificationContext) -> list[dict[str, Any]]:
    from collections import Counter
    results = [item.id for item in ctx.result_collector.all()]
    evidence = [item.id for item in ctx.evidence_collector.all()]
    duplicates = []
    for kind, values in (("result", results), ("evidence", evidence)):
        duplicates.extend({"kind": kind, "id": identifier, "count": count}
                          for identifier, count in Counter(values).items() if count > 1)
    return duplicates


def _detach_unresolved_evidence(ctx: VerificationContext) -> tuple[Any, ...]:
    """Keep malformed links auditable while preserving a resolvable manifest graph."""
    from dataclasses import replace

    known = {item.id for item in ctx.evidence_collector.all()}
    output = []
    for result in ctx.result_collector.all():
        missing = tuple(item for item in result.evidence_ids if item not in known)
        if missing:
            result = replace(result, evidence_ids=tuple(item for item in result.evidence_ids if item in known),
                             metadata={**dict(result.metadata), "unresolved_evidence_ids": list(missing)})
        output.append(result)
    return tuple(output)


def _verify_traceability(ctx: VerificationContext, results: tuple[Any, ...], evidence: tuple[Any, ...]) -> dict[str, Any]:
    result_ids = {item.id for item in results}
    evidence_ids = {item.id for item in evidence}
    broken = []
    for requirement_id, row in ctx.traceability.items():
        for result_id in row.get("results", ()):
            if result_id not in result_ids:
                broken.append({"requirement_id": requirement_id, "reference_type": "result",
                               "reference_id": result_id})
        known_property_ids = {item.id for item in ctx.specification.properties} if ctx.specification is not None else set()
        known_test_ids = {item.id for item in ctx.specification.tests} if ctx.specification is not None else set()
        for property_id in row.get("checker_refs", ()):
            if property_id not in known_property_ids | known_test_ids:
                broken.append({"requirement_id": requirement_id, "reference_type": "property",
                               "reference_id": property_id})
        for evidence_id in row.get("evidence_ids", ()):
            if evidence_id not in evidence_ids:
                broken.append({"requirement_id": requirement_id, "reference_type": "evidence",
                               "reference_id": evidence_id})
        model = row.get("model")
        if model and model.get("evidence_id") not in evidence_ids:
            broken.append({"requirement_id": requirement_id, "reference_type": "model_evidence",
                           "reference_id": model.get("evidence_id")})
        targets = row.get("targets", {})
        for target_id, target in targets.items():
            for result_id in target.get("results", ()):
                if result_id not in result_ids:
                    broken.append({"requirement_id": requirement_id, "target_id": target_id,
                                   "reference_type": "target_result", "reference_id": result_id})
            for evidence_id in target.get("evidence_ids", ()):
                if evidence_id not in evidence_ids:
                    broken.append({"requirement_id": requirement_id, "target_id": target_id,
                                   "reference_type": "target_evidence", "reference_id": evidence_id})
            execution = target.get("execution", {})
            if execution:
                result_id = execution.get("result_id")
                if result_id not in result_ids:
                    broken.append({"requirement_id": requirement_id, "target_id": target_id,
                                   "reference_type": "execution_result", "reference_id": result_id})
                for evidence_id in (execution.get("test_case_evidence_id"), execution.get("observation_evidence_id")):
                    if evidence_id and evidence_id not in evidence_ids:
                        broken.append({"requirement_id": requirement_id, "target_id": target_id,
                                       "reference_type": "execution_evidence", "reference_id": evidence_id})
    result_ref_ids = {ref for result in results for ref in result.evidence_ids}
    stage_ref_ids = {ref for record in ctx.stage_records.values()
                     for ref in (*record.output_refs, *record.evidence_ids)}
    orphans = [item.id for item in evidence if item.id not in result_ref_ids and item.id not in stage_ref_ids
               and item.stage not in {"report", "manifest"}]
    return {"valid": not broken and not orphans, "broken_references": broken,
            "orphan_evidence_ids": sorted(orphans)}


def _complete_stage_reasons(ctx: VerificationContext) -> None:
    for record in ctx.stage_records.values():
        if record.status == StageStatus.COMPLETED and not record.reason:
            record.reason = "Stage completed successfully."
        elif record.status == StageStatus.FAILED and not record.reason:
            record.reason = record.error_type or "Stage failed; see linked diagnostic evidence."
        elif record.status == StageStatus.SKIPPED and not record.reason:
            record.reason = "Stage skipped; required inputs or configuration were unavailable."


def _verify_report_manifest_hashes(ctx: VerificationContext, report_ref: Any, manifest_ref: Any) -> None:
    import hashlib

    expected = {report_ref.path: report_ref.hash, manifest_ref.path: manifest_ref.hash}
    for relative, digest in expected.items():
        path = (ctx.workspace / relative).resolve(strict=True)
        if not path.is_relative_to(ctx.workspace.resolve()) or not path.is_file():
            raise RuntimeError(f"Final integrity artifact escaped workspace: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Final integrity hash mismatch: {relative}")


def _safe_run_id(value: str) -> str:
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) or value in {".", ".."}:
        raise ValueError("run_id must be a safe 1-100 character path component")
    return value


def _notify_progress(callback: Callable[[dict[str, Any]], None] | None, record: StageRecord,
                     results: tuple[Any, ...] = (), evidence: tuple[Any, ...] = (),
                     run_id: str | None = None) -> None:
    if callback is not None:
        try:
            payload = record.to_dict()
            if run_id is not None:
                payload["run_id"] = run_id
            if results or evidence:
                payload["stage_results"] = [item.to_dict() for item in results]
                payload["stage_evidence"] = [item.to_dict() for item in evidence]
            callback(payload)
        except Exception:
            # UI progress is observational and must not change verification behavior.
            pass


def _stage_input_refs(stage_id: str, dependencies: tuple[str, ...], ctx: VerificationContext,
                      options: PipelineOptions) -> tuple[str, ...]:
    references: list[str] = []
    if stage_id == "CROSS_CHECK":
        for record in ctx.stage_records.values():
            if record.stage_id not in {"CROSS_CHECK", "REPORT"}:
                references.extend(record.output_refs)
                references.extend(record.result_ids)
    if stage_id == "SPECIFICATION":
        references.extend(str(Path(path).expanduser().resolve()) for path in options.specification_paths)
    if stage_id == "SOURCE":
        references.append(str(ctx.project))
    for dependency in dependencies:
        record = ctx.stage_records.get(dependency)
        if record is None:
            continue
        references.extend(record.output_refs)
        references.extend(record.result_ids)
    return tuple(dict.fromkeys(references))


def _record_source_integrity(ctx: VerificationContext) -> tuple[list[dict[str, Any]], Any | None]:
    import hashlib

    records = []
    for source in ctx.source_files:
        try:
            current_hash = hashlib.sha256(Path(source.path).read_bytes()).hexdigest()
            error = None
        except OSError as exc:
            current_hash, error = None, f"{type(exc).__name__}: {exc}"
        records.append({"source_id": "SRC-" + hashlib.sha256(source.relative_path.encode("utf-8")).hexdigest()[:16],
                        "path": source.relative_path, "before_sha256": source.sha256,
                        "after_sha256": current_hash, "changed_during_run": current_hash != source.sha256,
                        "error": error})
    if not records:
        return records, None
    payload = {"run_id": ctx.run_id, "sources": records,
               "all_unchanged": all(not item["changed_during_run"] and not item["error"] for item in records)}
    ref = ctx.artifact_store.write_json("source", "source-integrity.json", payload,
                                        evidence_type=EvidenceType.ENVIRONMENT)
    ctx.add_evidence((ref,))
    source_stage = ctx.stage_records.get("SOURCE")
    if source_stage is not None:
        source_stage.output_refs = tuple(dict.fromkeys((*source_stage.output_refs, ref.id)))
        source_stage.evidence_ids = tuple(dict.fromkeys((*source_stage.evidence_ids, ref.id)))
        source_stage.metadata["integrity_evidence_id"] = ref.id
    report_stage = ctx.stage_records.get("REPORT")
    if report_stage is not None:
        report_stage.input_refs = tuple(dict.fromkeys((*report_stage.input_refs, ref.id)))
    if any(item["changed_during_run"] or item["error"] for item in records):
        ctx.limitations.append("One or more source files changed or could not be hashed during the run; see source-integrity evidence.")
        result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
            stage="SOURCE", technique="SOURCE_INTEGRITY", reason_code="SOURCE_HASH_MISMATCH",
            message="One or more source files changed or could not be hashed during the run.",
            evidence_ids=(ref.id,), metadata={"changed_source_ids": [item["source_id"] for item in records
                if item["changed_during_run"] or item["error"]]}))
        ctx.add_results((result,))
        source_stage = ctx.stage_records.get("SOURCE")
        if source_stage is not None:
            source_stage.result_ids = tuple(dict.fromkeys((*source_stage.result_ids, result.id)))
            source_stage.evidence_ids = tuple(dict.fromkeys((*source_stage.evidence_ids, ref.id)))
    return records, ref


def _source_lineage_report(ctx: VerificationContext, results: tuple[Any, ...],
                           integrity: list[dict[str, Any]], integrity_evidence_id: str | None) -> dict[str, Any]:
    before_by_id = {item.get("source_id"): item for item in ctx.source_metadata.get("files", ())}
    integrity_by_id = {item["source_id"]: item for item in integrity}
    rows = []
    for source_id, original in before_by_id.items():
        hashes = integrity_by_id.get(source_id, {})
        function_ids = tuple(original.get("function_ids", ()))
        analysis_refs = []
        for result in results:
            result_stage = result.stage.upper()
            applies = result_stage in {"STATIC_ANALYSIS", "SANITIZER", "MEMORY_ANALYSIS", "COVERAGE", "FUZZING"}
            if result_stage == "DYNAMIC_TEST":
                applies = result.metadata.get("function_id") in function_ids
            if applies:
                analysis_refs.append({"stage_id": _stage_for_result(result), "result_id": result.id,
                                      "status": result.status.value, "evidence_ids": list(result.evidence_ids),
                                      "scope": "SOURCE_SET" if result_stage != "DYNAMIC_TEST" else "FUNCTION"})
        inventory_id = original.get("source_inventory_evidence_id")
        rows.append({**original, "after_sha256": hashes.get("after_sha256"),
                     "changed_during_run": hashes.get("changed_during_run", False),
                     "integrity_error": hashes.get("error"),
                     "source_inventory_evidence_id": inventory_id,
                     "source_integrity_evidence_id": integrity_evidence_id,
                     "analysis_results": analysis_refs,
                     "artifact_class": "PRODUCTION_SOURCE"})
    return {**ctx.source_metadata, "files": rows,
            "generated_artifacts": [{"artifact_class": artifact_class, "evidence_ids": [item.id for item in ctx.evidence_collector.all()
                                    if item.metadata.get("artifact_class") == artifact_class or
                                       artifact_class == "GENERATED_SOURCE" and item.metadata.get("artifact_role") == "GENERATED_ARTIFACT"]}
                                    for artifact_class in ("GENERATED_ARTIFACT", "GENERATED_SOURCE", "TEST_HARNESS", "FUZZ_HARNESS")]
                                   + [{"artifact_class": "TEST_HARNESS", "evidence_ids": [item.id for item in ctx.evidence_collector.all()
                                    if item.stage == "harness" and item.metadata.get("generated")]},
                                   ]}


def _stage_for_result(result: Any) -> str:
    technique = result.technique.upper()
    if technique in {"CTL", "BMC", "SMT"}:
        return technique
    return {"STATIC_ANALYSIS": "STATIC", "SANITIZER": "MEMORY", "MEMORY_ANALYSIS": "MEMORY",
            "DYNAMIC_TEST": "DYNAMIC", "COVERAGE": "COVERAGE", "FUZZING": "FUZZING"}.get(
                result.stage.upper(), result.stage.upper())


def _artifact_classes(evidence: tuple[Any, ...]) -> dict[str, list[str]]:
    classes: dict[str, list[str]] = {"PRODUCTION_SOURCE": [], "GENERATED_ARTIFACT": [], "GENERATED_SOURCE": [],
                                    "TEST_HARNESS": [], "FUZZ_HARNESS": []}
    for item in evidence:
        artifact_class = item.metadata.get("artifact_class")
        if artifact_class in classes:
            classes[artifact_class].append(item.id)
        if item.metadata.get("artifact_role") == "GENERATED_ARTIFACT":
            classes["GENERATED_ARTIFACT"].append(item.id)
        elif item.stage == "harness" and item.metadata.get("generated"):
            classes["TEST_HARNESS"].append(item.id)
        elif item.stage == "source" and item.path in {
            "evidence/source/source-inventory.json", "evidence/source/source-lineage.json"
        }:
            classes["PRODUCTION_SOURCE"].append(item.id)
    return classes


def _report_artifact_classes(evidence: tuple[Any, ...]) -> dict[str, list[str]]:
    """Include the legacy generated-source alias beside explicit artifact class."""
    classes = _artifact_classes(evidence)
    classes["GENERATED_SOURCE"] = list(dict.fromkeys((*classes["GENERATED_SOURCE"], *classes["GENERATED_ARTIFACT"])))
    return classes


def _run_provenance(ctx: VerificationContext, status: str) -> dict[str, Any]:
    source_hashes = {}
    for item in _provenance_sources(ctx):
        relative = str(getattr(item, "relative_path", Path(getattr(item, "path", item)).name))
        digest = getattr(item, "sha256", None)
        if digest is None:
            try:
                digest = hashlib.sha256(Path(getattr(item, "path", item)).read_bytes()).hexdigest()
            except OSError:
                digest = None
        source_hashes[relative] = digest
    specification_inputs = {}
    for value in getattr(ctx.options, "specification_paths", ()):
        path = Path(value)
        try:
            specification_inputs[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            specification_inputs[path.name] = None
    config = _plain_data(ctx.options) if ctx.options is not None else {}
    if isinstance(config, dict):
        for key in ("metadata", "loaded_specification", "validated_specification",
                    "normalized_specification", "source_files", "test_cases"):
            config.pop(key, None)
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
    tool_versions = {item.name: item.version for item in ctx.toolchain.all() if item.version}
    normalized_spec_hash = None
    if ctx.specification is not None:
        normalized = json.dumps(_plain_data(ctx.specification), sort_keys=True, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
        normalized_spec_hash = hashlib.sha256(normalized).hexdigest()
    reproducibility_input = {"source_sha256": source_hashes,
        "specification_input_sha256": specification_inputs,
        "specification_sha256": normalized_spec_hash,
        "configuration_sha256": config_hash, "tool_versions": tool_versions}
    reproducibility_id = "RP-" + hashlib.sha256(json.dumps(reproducibility_input, sort_keys=True,
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()[:32]
    return {"run_id": ctx.run_id, "source_sha256": source_hashes,
            "source_set_sha256": hashlib.sha256(json.dumps(source_hashes, sort_keys=True,
                ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "specification_input_sha256": specification_inputs,
            "specification_sha256": normalized_spec_hash,
            "tool_versions": tool_versions,
            "configuration_sha256": config_hash, "configuration": config,
            "reproducibility_id": reproducibility_id, "status": status}


def _evidence_stage_status(ctx: VerificationContext, evidence: Any) -> str:
    stage_id = str(evidence.metadata.get("stage_id") or evidence.stage).upper().replace("-", "_")
    aliases = {"SPECIFICATION": "SPECIFICATION", "SOURCE": "SOURCE", "MODEL": "MODEL",
        "CODEGEN": "CODEGEN", "CTL": "CTL", "BMC": "BMC", "SMT": "SMT", "STATIC": "STATIC",
        "STATIC_ANALYSIS": "STATIC", "MEMORY": "MEMORY", "SANITIZER": "MEMORY",
        "DYNAMIC": "DYNAMIC", "DYNAMIC_TEST": "DYNAMIC", "COVERAGE": "COVERAGE",
        "FUZZING": "FUZZING", "CROSS_CHECK": "CROSS_CHECK", "REPORT": "REPORT"}
    stage_id = aliases.get(stage_id, stage_id)
    record = ctx.stage_records.get(stage_id)
    return record.status.value if record is not None else str(evidence.metadata.get("status", "RECORDED"))


def _provenance_sources(ctx: VerificationContext) -> tuple[Any, ...]:
    return tuple(ctx.source_files)


def _enrich_evidence_provenance(ctx: VerificationContext) -> None:
    from dataclasses import replace
    enriched = []
    for item in ctx.evidence_collector.all():
        stage_id = str(item.metadata.get("stage_id") or item.stage).upper().replace("-", "_")
        provenance = _run_provenance(ctx, _evidence_stage_status(ctx, item))
        metadata = {**dict(item.metadata), "provenance": provenance,
                    "source_sha256": provenance["source_sha256"],
                    "configuration_sha256": provenance["configuration_sha256"],
                    "tool_versions": provenance["tool_versions"],
                    "status": provenance["status"]}
        enriched.append(replace(item, metadata=metadata, run_id=ctx.run_id,
                                checker=item.checker or stage_id or "UNKNOWN"))
    ctx.evidence_collector.replace_all(enriched)


def _record_stage_execution(ctx: VerificationContext, record: StageRecord) -> None:
    """Persist common provenance for every attempted or lifecycle-skipped stage."""
    source_hashes = dict(ctx.source_hashes)
    specification_hash = None
    if ctx.specification is not None:
        try:
            encoded_spec = json.dumps(_plain_data(ctx.specification), ensure_ascii=False,
                                     sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            specification_hash = hashlib.sha256(encoded_spec).hexdigest()
        except (TypeError, ValueError):
            specification_hash = None
    specification_input_hashes = dict(ctx.specification_input_hashes)
    options = ctx.options
    configuration = _plain_data(options) if options is not None else {}
    # Preserve reproducible knobs while leaving runtime timestamps in the
    # evidence envelope rather than in this configuration fingerprint.
    reproducibility = {key: value for key, value in configuration.items()
                       if key not in {"metadata", "loaded_specification", "validated_specification",
                                      "normalized_specification", "source_files", "test_cases"}}
    payload = {"schema_version": "1.0", "run_id": ctx.run_id, "stage_id": record.stage_id,
        "status": record.status.value, "reason": record.reason, "error_type": record.error_type,
        "source_sha256": source_hashes,
        "source_set_sha256": hashlib.sha256(json.dumps(source_hashes, sort_keys=True,
            ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest(),
        "specification_sha256": specification_hash,
        "specification_input_sha256": specification_input_hashes,
        "configuration": reproducibility,
        "configuration_sha256": hashlib.sha256(json.dumps(reproducibility, sort_keys=True,
            ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest(),
        "tool_versions": {item.name: item.version for item in ctx.toolchain.all() if item.version},
        "toolchain": ctx.toolchain.summary(), "started_at": record.started_at,
        "finished_at": record.finished_at, "duration_ms": record.duration_ms,
        "result_ids": list(record.result_ids), "input_refs": list(record.input_refs),
        "output_refs": list(record.output_refs)}
    ref = ctx.artifact_store.write_json("stage-executions", f"{record.stage_id.lower()}-execution.json",
        payload, evidence_type=EvidenceType.ENVIRONMENT, source="pipeline-orchestrator",
        checker=record.stage_id, run_id=ctx.run_id,
        metadata={"stage_id": record.stage_id, "status": record.status.value,
                  "source_sha256": source_hashes, "source_set_sha256": payload["source_set_sha256"],
                  "specification_sha256": specification_hash,
                  "specification_input_sha256": specification_input_hashes,
                  "configuration_sha256": payload["configuration_sha256"],
                  "tool_versions": payload["tool_versions"]})
    ctx.add_evidence((ref,))
    record.evidence_ids = tuple(dict.fromkeys((*record.evidence_ids, ref.id)))
    record.output_refs = tuple(dict.fromkeys((*record.output_refs, ref.id)))
    record.metadata.update({"execution_evidence_id": ref.id, "source_sha256": source_hashes,
                            "source_set_sha256": payload["source_set_sha256"],
                            "specification_sha256": specification_hash,
                            "specification_input_sha256": specification_input_hashes,
                            "configuration_sha256": payload["configuration_sha256"]})


def _stage_summary(value: Any) -> Any:
    if isinstance(value, StageSkipped):
        return {"skipped_reason": value.reason}
    if value is None or isinstance(value, (str, int, float, bool, dict, list)):
        return value
    serializer = getattr(value, "to_dict", None)
    if callable(serializer):
        return serializer()
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import fields
        return {item.name: _stage_summary(getattr(value, item.name)) for item in fields(value)}
    return None


def _plain_data(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _plain_data(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_plain_data(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, (str, int, float, bool)):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {name: _plain_data(getattr(value, name)) for name in value.__dataclass_fields__}
    return str(value)
