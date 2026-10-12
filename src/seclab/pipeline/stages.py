"""Adapters from existing SecLab cores to the pipeline lifecycle."""
from __future__ import annotations

import json
import hashlib
import re
import sys
import time
from dataclasses import fields, is_dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any

from seclab.evidence import EvidenceType
from seclab.formal.ctl import model_checker
from seclab.model import deadlock_states, generate_kripke_structure, graph_exporter, reachable_states, unreachable_states
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier
from seclab.results.classifier import classify_ctl_error, classify_ctl_result
from seclab.source import FunctionDetector, LanguageDetector, SourceLoader
from seclab.specification import SpecificationError, load_specification, normalize_specification, validate_specification
from seclab.testing import ExpectedBehavior, TestCase, TestCategory, TestTargetKind

from .stage import StageOutput, StageSkipped


class _FuzzCoverageAdapter:
    """Shorten per-iteration coverage directory names for bounded path platforms."""
    def __init__(self, runner: Any) -> None:
        self._runner = runner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runner, name)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        run_id = kwargs.get("run_id")
        if run_id:
            kwargs["run_id"] = "fz-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8]
        return self._runner.run(*args, **kwargs)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _properties(spec: Any, logic: str) -> tuple[Any, ...]:
    return tuple(item for item in spec.properties if item.logic.upper() == logic)


class PipelineStages:
    """Stage implementations. Core checkers retain ownership of verdict semantics."""

    @staticmethod
    def _formal_model(ctx: Any) -> tuple[Any | None, str | None]:
        """Return only the model built from the normalized specification."""
        if ctx.specification is not None and ctx.specification.states and ctx.kripke is not None:
            return ctx.kripke, None
        return None, "The normalized specification does not declare an explicit state machine."

    @staticmethod
    def _model_unavailable(ctx: Any, logic: str, reason: str | None) -> StageOutput:
        spec = ctx.specification
        if spec is None:
            return StageOutput(value=StageSkipped("A valid specification is required."))
        properties = _properties(spec, logic)
        if not properties:
            return StageOutput(value=StageSkipped(f"The specification declares no {logic} properties."))
        ref = ctx.artifact_store.write_json(logic.lower(), "model-unavailable.json", {
            "status": "MODEL_UNAVAILABLE", "logic": logic,
            "specification_id": spec.id, "reason": reason or "A complete model is unavailable.",
            "model_status": "NOT_DECLARED"}, evidence_type=EvidenceType.MODEL,
            source="formal-model-gate", metadata={"stage_id": logic, "model_status": "NOT_DECLARED"})
        results = []
        for prop in properties:
            result = ResultClassifier().classify(ClassificationInput(
                outcome=RawOutcome.UNKNOWN,
                stage="FORMAL" if logic == "CTL" else "BOUNDED_MODEL_CHECKING", technique=logic,
                property_id=prop.id, reason_code="MODEL_UNAVAILABLE",
                message=reason or "A complete model is unavailable.", evidence_ids=(ref.id,), metadata={
                    "model_status": "NOT_DECLARED"}))
            results.extend(_link_result(result, prop.id, prop.requirement_ids))
        return StageOutput(results=tuple(results), evidence=(ref,), metadata={"properties_checked": 0,
            "model_status": "NOT_DECLARED", "reason": reason})

    @staticmethod
    def specification(ctx: Any, options: Any) -> StageOutput:
        paths = options.specification_paths
        if options.loaded_specification is None and not paths:
            return StageOutput(value=StageSkipped("No specification paths were configured."))
        loaded = options.loaded_specification
        compatibility: dict[str, Any] = {}
        try:
            if options.validated_specification is not None and options.normalized_specification is not None:
                validated = options.validated_specification
                loaded = validated.loaded
                spec = options.normalized_specification
            else:
                if loaded is None:
                    if len(paths) == 1 and Path(paths[0]).suffix.casefold() == ".xlsx":
                        from seclab.integrations.xlsx_adapter import load_teacher_xlsx
                        loaded, compatibility, _raw_document = load_teacher_xlsx(paths[0])
                    else:
                        if any(Path(path).suffix.casefold() == ".xlsx" for path in paths):
                            raise ValueError("Không thể gộp XLSX với các tệp đặc tả khác; hãy chọn riêng một workbook.")
                        from seclab.specification.legacy_adapter import load_compatible_specification
                        loaded, compatibility, _raw_documents = load_compatible_specification(paths)
                else:
                    compatibility = {}
                validated = validate_specification(loaded, schema_path=options.schema_path)
                spec = normalize_specification(validated)
        except Exception as exc:
            error_data = {"error_type": type(exc).__name__, "message": str(exc),
                          "result": "INVALID", "diagnostics": [{
                              "code": getattr(getattr(exc, "code", None), "value", getattr(exc, "code", "SPECIFICATION_ERROR")),
                              "message": getattr(exc, "message", str(exc)),
                              "source": str(getattr(exc, "source", "") or ""),
                              "location": str(getattr(exc, "location", "") or ""),
                          }]}
            if loaded is not None:
                error_data["input_hashes"] = [{"source": str(item.source), "sha256": item.sha256}
                                              for item in loaded.documents]
            else:
                input_hashes = []
                for path in paths:
                    try:
                        resolved = Path(path).expanduser().resolve(strict=True)
                        input_hashes.append({"source": str(resolved),
                                             "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()})
                    except OSError:
                        input_hashes.append({"source": str(path), "sha256": "UNAVAILABLE"})
                error_data["input_hashes"] = input_hashes
            ref = ctx.artifact_store.write_json("pipeline", "specification-error.json",
                error_data, evidence_type=EvidenceType.LOG)
            ctx.add_evidence((ref,))
            result = ResultClassifier().classify(ClassificationInput(
                outcome=RawOutcome.INVALID_SPEC, stage="SPECIFICATION", technique="SPECIFICATION_VALIDATOR",
                reason_code="INVALID_SPECIFICATION", message=str(exc), evidence_ids=(ref.id,),
                metadata={"error_type": type(exc).__name__}))
            ctx.add_results((result,))
            return StageOutput(results=(result,), evidence=(ref,), metadata={"stage_status": "FAILED", "error": str(exc)})
        ctx.loaded_specification, ctx.validated_specification, ctx.specification = loaded, validated, spec
        normalized_payload = _jsonable(spec)
        normalized_hash = hashlib.sha256(json.dumps(normalized_payload, ensure_ascii=False,
            sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        input_ref = ctx.artifact_store.write_json("pipeline", "specification-input-hashes.json",
            {"documents": list(validated.input_hashes)}, evidence_type=EvidenceType.SPECIFICATION)
        validation_ref = ctx.artifact_store.write_json("pipeline", "specification-validation.json",
            {"result": validated.validation_result, "diagnostics": list(validated.diagnostics),
             "input_hashes": list(validated.input_hashes), "normalized_sha256": normalized_hash},
            evidence_type=EvidenceType.LOG)
        payload = {"loaded": _jsonable(loaded), "normalized": _jsonable(spec)}
        payload["normalized_sha256"] = normalized_hash
        provenance = spec.metadata.get("source_provenance", {})
        if provenance:
            payload["ORIGINAL_SPECIFICATION"] = {
                "source_path": provenance.get("source_path"),
                "sha256": provenance.get("source_sha256"),
                "format": provenance.get("format"),
                "document": provenance.get("original_document"),
            }
            payload["NORMALIZED_SPECIFICATION"] = _jsonable(spec)
        ref = ctx.artifact_store.write_json("pipeline", "specification.json", payload,
                                            evidence_type=EvidenceType.SPECIFICATION)
        ctx.add_evidence((input_ref, validation_ref, ref))
        requirements = {}
        for req in spec.requirements:
            requirements[req.id] = {"requirement_id": req.id, "description": req.description,
                                    "checker_refs": [], "targets": {}, "sources": [], "stages": [],
                                    "results": [], "evidence_ids": [], "status": "NOT_CHECKED"}
        ctx.traceability.update(requirements)
        for prop in spec.properties:
            for req_id in prop.requirement_ids:
                row = ctx.traceability.get(req_id)
                if row is not None and prop.id not in row["checker_refs"]:
                    row["checker_refs"].append(prop.id)
                    row["targets"][prop.id] = {"target_id": prop.id, "target_kind": "PROPERTY",
                        "logic": prop.logic, "stage_id": prop.logic, "results": [], "evidence_ids": [],
                        "statuses": [], "status": "NOT_CHECKED"}
        tests_by_id = {test.id: test for test in spec.tests}
        for test in spec.tests:
            for req_id in test.requirement_ids:
                row = ctx.traceability.get(req_id)
                if row is not None and test.id not in row["checker_refs"]:
                    row["checker_refs"].append(test.id)
                    row["targets"][test.id] = {"target_id": test.id, "target_kind": "TEST_CASE",
                        "function_id": test.function_id, "stage_id": "DYNAMIC", "results": [],
                        "evidence_ids": [], "statuses": [], "status": "NOT_CHECKED",
                        "property_id": test.metadata.get("property_id") if hasattr(test, "metadata") else None}
        for target in spec.metadata.get("unexecutable_targets", ()):
            target_id = target["target_id"]
            for req_id in target.get("requirement_ids", ()):
                row = ctx.traceability.get(req_id)
                if row is None:
                    continue
                if target_id not in row["checker_refs"]:
                    row["checker_refs"].append(target_id)
                row["targets"][target_id] = {
                    "target_id": target_id,
                    "target_kind": target["target_kind"],
                    "stage_id": target["stage_id"],
                    "results": [],
                    "evidence_ids": [],
                    "statuses": [],
                    "status": target["status"],
                    "reason": target["reason"],
                }
        return StageOutput(value=spec, evidence=(input_ref, validation_ref, ref), metadata={
            "specification_id": spec.id, "input_hashes": list(validated.input_hashes),
            "normalized_sha256": normalized_hash, "validation_result": validated.validation_result,
            "compatibility": compatibility or
                (options.metadata.get("specification_provenance", {}) if options.metadata else {}),
            "validation_diagnostics": list(validated.diagnostics),
            "requirements": len(spec.requirements), "properties": len(spec.properties), "tests": len(spec.tests)})

    @staticmethod
    def model(ctx: Any, options: Any) -> StageOutput:
        spec = ctx.specification
        if spec is None or not spec.states:
            reason = "A specification with explicit states is required."
            unsupported = ctx.artifact_store.write_json("model", "model-unsupported.json", {
                "status": "MODEL_UNSUPPORTED", "specification_id": getattr(spec, "id", None),
                "reason": reason, "source_specification_paths": [str(item.source)
                    for item in getattr(getattr(ctx, "loaded_specification", None), "documents", ())],
            }, evidence_type=EvidenceType.MODEL, source="model-builder",
                metadata={"stage_id": "MODEL", "status": "MODEL_UNSUPPORTED"})
            return StageOutput(value=StageSkipped(reason), evidence=(unsupported,),
                               metadata={"model_status": "MODEL_UNSUPPORTED", "reason": reason})
        started = time.monotonic()
        model = generate_kripke_structure(spec, max_states=options.max_states)
        ctx.kripke = model
        model.validate()
        reach = reachable_states(model)
        deadlocks, unreachable = deadlock_states(model), unreachable_states(model)
        normalized = _jsonable(spec)
        specification_hash = hashlib.sha256(json.dumps(normalized, ensure_ascii=False,
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        documents = getattr(getattr(ctx, "loaded_specification", None), "documents", ())
        source_paths = [str(item.source) for item in documents]
        input_hashes = [{"source": str(item.source), "sha256": item.sha256} for item in documents]
        model_id = "MODEL-" + hashlib.sha256((spec.id + "\0" + specification_hash + "\0" + model.model_hash)
            .encode("utf-8")).hexdigest()[:24]
        model_data = {**graph_exporter.to_dict(model),
                      "model_id": model_id, "specification_id": spec.id,
                      "specification_hash": specification_hash,
                      "source_specification_paths": source_paths,
                      "source_specification_hashes": input_hashes,
                      "construction_metadata": {"method": "explicit-specification-state-machine",
                          "version": "1.0", "configuration": {"max_states": options.max_states}},
                      "reachable_state_ids": [state.id for state in reach],
                      "unreachable_state_ids": [state.id for state in unreachable],
                      "deadlock_state_ids": [state.id for state in deadlocks]}
        statistics = dict(model.statistics)
        statistics["proposition_count"] = len({label for state in model.states for label in state.labels})
        validation = {"status": "PASS", "valid": True, "model_id": model_id,
            "model_hash": model.model_hash, "specification_hash": specification_hash,
            "statistics": statistics, "initial_states": [state.id for state in model.initial_states],
            "reachable_state_ids": [state.id for state in reach],
            "unreachable_state_ids": [state.id for state in unreachable],
            "deadlock_state_ids": [state.id for state in deadlocks],
            "transition_references_valid": True, "initial_states_exist": True}
        summary = {"status": "BUILT", "model_id": model_id, "model_hash": model.model_hash,
            "specification_id": spec.id, "specification_hash": specification_hash,
            "source_specification_paths": source_paths, "source_specification_hashes": input_hashes,
            "initial_states": validation["initial_states"], "atomic_propositions": sorted(
                {label for state in model.states for label in state.labels}),
            "construction_metadata": model_data["construction_metadata"], "statistics": statistics}
        graph_text = graph_exporter.to_dot(model)
        refs = (
            ctx.artifact_store.write_json("model", "kripke.json", model_data,
                evidence_type=EvidenceType.MODEL, source="model-builder",
                metadata={"model_id": model_id, "model_hash": model.model_hash,
                          "specification_id": spec.id, "specification_hash": specification_hash,
                          "source_specification_paths": source_paths}),
            ctx.artifact_store.write_json("model", "model-summary.json", summary,
                evidence_type=EvidenceType.MODEL, source="model-builder",
                metadata={"model_id": model_id, "specification_hash": specification_hash}),
            ctx.artifact_store.write_json("model", "model-validation.json", validation,
                evidence_type=EvidenceType.MODEL, source="model-validator",
                metadata={"model_id": model_id, "specification_hash": specification_hash}),
            ctx.artifact_store.write_text("model", "model-graph.dot", graph_text,
                evidence_type=EvidenceType.MODEL, source="model-graph-exporter",
                metadata={"model_id": model_id, "model_hash": model.model_hash,
                          "specification_hash": specification_hash}),
        )
        ref = refs[0]
        for row in ctx.traceability.values():
            row["model"] = {"model_hash": model.model_hash, "evidence_id": ref.id,
                            "state_ids": list(model.state_ids),
                            "transition_ids": list(model.transition_ids)}
        return StageOutput(model, evidence=refs, metadata={"model_id": model_id,
            "model_hash": model.model_hash, "specification_hash": specification_hash,
            "source_specification_paths": source_paths,
            "construction_duration_ms": (time.monotonic() - started) * 1000,
            "validation_status": "PASS", "statistics": statistics, "state_ids": list(model.state_ids),
            "transition_ids": list(model.transition_ids),
            "state_count": len(model.states), "transition_count": len(model.transitions), "initial_state_ids": [s.id for s in model.initial_states],
            "reachable_state_count": len(reach), "unreachable_state_ids": [state.id for state in unreachable],
            "deadlock_state_ids": [state.id for state in deadlocks]})

    @staticmethod
    def codegen(ctx: Any, options: Any) -> StageOutput:
        if ctx.specification is None:
            return StageOutput(value=StageSkipped("A normalized specification is required."))
        model_stage = getattr(ctx, "stage_records", {}).get("MODEL")
        if model_stage is not None and model_stage.status.value == "FAILED":
            return StageOutput(value=StageSkipped("Model generation failed; no C model can be generated."))
        from seclab.codegen import CGenerator
        from seclab.model import KripkeStructure
        from seclab.execution import CommandSpec

        output_root = ctx.workspace / "generated"
        # An empty explicit model keeps no-machine specifications applicable to
        # C model-runtime generation without inventing a state or transition.
        model = ctx.kripke if ctx.kripke is not None else KripkeStructure((), (), ())
        include_fuzz = options.generate_c_fuzz_harness or options.fuzz_config is not None
        generated = CGenerator().generate(ctx.specification, model, output_root,
            include_fuzz=include_fuzz, validate_specification_match=True,
            source_specification_paths=tuple(str(item.source) for item in
                getattr(getattr(ctx, "loaded_specification", None), "documents", ())),
            source_specification_hashes=tuple({"source": str(item.source), "sha256": item.sha256}
                for item in getattr(getattr(ctx, "loaded_specification", None), "documents", ())),
            run_id=ctx.run_id)
        # Function bodies are not generated without executable behavior in
        # the normalized Specification contract.
        ctx.codegen_result = generated
        ctx.generated_c_root = output_root
        evidence: list[Any] = []
        for item in generated.manifest["files"]:
            relative = item["path"]
            ref = ctx.artifact_store.copy_file(
                "codegen", "artifact-" + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16] + Path(relative).suffix,
                output_root / relative, evidence_type=EvidenceType.MODEL,
                metadata={"artifact_class": item["artifact_class"],
                          "artifact_role": "GENERATED_ARTIFACT" if item["artifact_class"] == "GENERATED_SOURCE" else item["artifact_class"],
                          "generated": item.get("generated", False),
                          "source_kind": item.get("source_kind"),
                          "production_source": item.get("production_source", False),
                          "generated_path": relative,
                          "sha256": item["sha256"], "generator_version": generated.manifest["generator_version"],
                          "specification_id": generated.manifest["specification_id"],
                          "specification_hash": generated.manifest["specification_hash"],
                          "model_id": generated.manifest["model_id"],
                          "requirement_ids": generated.manifest["requirement_ids"]})
            evidence.append(ref)
        manifest_ref = ctx.artifact_store.write_json("codegen", "manifest.json", generated.manifest,
            evidence_type=EvidenceType.MODEL, metadata={"artifact_class": "GENERATION_METADATA",
                "specification_id": generated.manifest["specification_id"],
                "specification_hash": generated.manifest["specification_hash"],
                "model_id": generated.manifest["model_id"]})
        source_map_ref = ctx.artifact_store.write_json("codegen", "source-map.json", generated.source_map,
            evidence_type=EvidenceType.MODEL, metadata={"artifact_class": "GENERATION_METADATA",
                "specification_id": generated.manifest["specification_id"],
                "specification_hash": generated.manifest["specification_hash"],
                "model_id": generated.manifest["model_id"]})
        requirements_map_ref = ctx.artifact_store.copy_file("codegen", "requirements-map.json",
            output_root / "requirements-map.json", evidence_type=EvidenceType.MODEL,
            metadata={"artifact_class": "GENERATION_METADATA", "specification_id": generated.manifest["specification_id"],
                "specification_hash": generated.manifest["specification_hash"],
                "model_id": generated.manifest["model_id"]})
        generation_ref = ctx.artifact_store.write_json("codegen", "generation-metadata.json",
            generated.generation_metadata or {}, evidence_type=EvidenceType.MODEL,
            metadata={"artifact_class": "GENERATION_METADATA",
                "specification_id": generated.manifest["specification_id"],
                "specification_hash": generated.manifest["specification_hash"],
                "model_id": generated.manifest["model_id"]})
        evidence.extend((manifest_ref, source_map_ref, requirements_map_ref, generation_ref))

        limitations = tuple(generated.manifest["limitations"]) + (
            "FunctionSpec declares no executable behavior contract; application C/Python functions cannot be generated from names or prose.",)
        return StageOutput(value=generated.to_dict(), evidence=tuple(evidence),
            metadata={"generated_root": str(output_root), "generator_version": generated.manifest["generator_version"],
                      "model_hash": generated.manifest["model_hash"], "model_id": generated.manifest["model_id"],
                      "specification_hash": generated.manifest["specification_hash"],
                      "generated_files": generated.manifest["files"],
                      "source_map_evidence_id": source_map_ref.id, "manifest_evidence_id": manifest_ref.id,
                      "requirements_map_evidence_id": requirements_map_ref.id,
                      "generation_metadata_evidence_id": generation_ref.id,
                      "limitations": list(limitations)})

    @staticmethod
    def build(ctx: Any, options: Any) -> StageOutput:
        if ctx.codegen_result is None or ctx.generated_c_root is None:
            return StageOutput(value=StageSkipped("Generated C artifacts are unavailable."))
        from seclab.execution import CommandSpec
        generated = ctx.codegen_result
        output_root = ctx.generated_c_root
        evidence = []
        compiler_runs = []
        build_dir = output_root / "build"
        build_dir.mkdir(parents=True, exist_ok=True)
        for compiler in ("gcc", "clang"):
            executable = build_dir / (f"model-test-{compiler}.exe" if __import__("os").name == "nt"
                                      else f"model-test-{compiler}")
            compile_result = ctx.command_runner.run(CommandSpec(
                argv=(compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                      "-I", str(output_root / "include"), str(output_root / "source" / "model.c"),
                      str(output_root / "tests" / "model_test.c"), "-o", str(executable)),
                cwd=output_root, timeout=options.build_timeout))
            row = {"compiler": compiler, "available": compile_result.executable_path is not None,
                   "argv": list(compile_result.argv), "exit_code": compile_result.exit_code,
                   "stdout": compile_result.stdout, "stderr": compile_result.stderr,
                   "timed_out": compile_result.timed_out, "execution_error": compile_result.execution_error,
                   "duration_ms": compile_result.duration_ms,
                   "status": ("TOOL_ERROR" if not compile_result.executable_path or compile_result.execution_error
                              else "BUILD_ERROR" if compile_result.timed_out or compile_result.exit_code != 0
                              else "COMPLETED")}
            if compile_result.succeeded and executable.is_file():
                row["artifact"] = str(executable)
                row["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
            compiler_runs.append(row)
            log_ref = ctx.artifact_store.write_json("build", f"compiler-{compiler}.json", row,
                evidence_type=EvidenceType.LOG, metadata={"artifact_class": "BUILD_COMMAND_LOG",
                    "compiler": compiler, "specification_id": generated.manifest["specification_id"],
                    "specification_hash": generated.manifest["specification_hash"],
                    "model_id": generated.manifest["model_id"]})
            row["evidence_id"] = log_ref.id
            evidence.append(log_ref)
        fuzz_compiler_runs = []
        fuzz_driver = output_root / "fuzz" / "model_fuzz_driver.c"
        fuzz_harness = output_root / "fuzz" / "model_fuzz.c"
        if fuzz_driver.is_file() and fuzz_harness.is_file():
            for compiler in ("gcc", "clang"):
                fuzz_executable = build_dir / (f"model-fuzz-{compiler}.exe" if __import__("os").name == "nt"
                                               else f"model-fuzz-{compiler}")
                compile_result = ctx.command_runner.run(CommandSpec(
                    argv=(compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
                          str(output_root / "source" / "model.c"), str(fuzz_harness), str(fuzz_driver),
                          "-o", str(fuzz_executable)), cwd=output_root, timeout=options.build_timeout))
                row = {"compiler": compiler, "available": compile_result.executable_path is not None,
                    "argv": list(compile_result.argv), "exit_code": compile_result.exit_code,
                    "stdout": compile_result.stdout, "stderr": compile_result.stderr,
                    "timed_out": compile_result.timed_out, "execution_error": compile_result.execution_error,
                    "duration_ms": compile_result.duration_ms,
                    "status": ("TOOL_ERROR" if not compile_result.executable_path or compile_result.execution_error
                               else "BUILD_ERROR" if compile_result.timed_out or compile_result.exit_code != 0
                               else "COMPLETED")}
                if compile_result.succeeded and fuzz_executable.is_file():
                    row["artifact"] = str(fuzz_executable)
                    row["sha256"] = hashlib.sha256(fuzz_executable.read_bytes()).hexdigest()
                fuzz_compiler_runs.append(row)
                log_ref = ctx.artifact_store.write_json("build", f"model-fuzz-{compiler}.json", row,
                    evidence_type=EvidenceType.LOG, metadata={"artifact_class": "FUZZ_HARNESS_BUILD_LOG",
                        "compiler": compiler, "source_kind": "MODEL_GENERATED",
                        "specification_id": generated.manifest["specification_id"],
                        "specification_hash": generated.manifest["specification_hash"],
                        "model_id": generated.manifest["model_id"]})
                row["evidence_id"] = log_ref.id
                evidence.append(log_ref)
            fuzz_executable_row = next((row for row in fuzz_compiler_runs
                if row["status"] == "COMPLETED" and row.get("artifact") and Path(row["artifact"]).is_file()), None)
            if fuzz_executable_row:
                ctx.generated_model_fuzz_executable = Path(fuzz_executable_row["artifact"])
                fuzz_executable_ref = ctx.artifact_store.copy_file("build", ctx.generated_model_fuzz_executable.name,
                    ctx.generated_model_fuzz_executable, evidence_type=EvidenceType.MODEL,
                    metadata={"artifact_class": "GENERATED_FUZZ_EXECUTABLE", "generated": True,
                        "source_kind": "MODEL_GENERATED", "production_source": False,
                        "specification_id": generated.manifest["specification_id"],
                        "specification_hash": generated.manifest["specification_hash"],
                        "model_id": generated.manifest["model_id"], "model_hash": generated.manifest["model_hash"],
                        "compiler": fuzz_executable_row["compiler"]})
                evidence.append(fuzz_executable_ref)
        executable_row = next((row for row in compiler_runs
            if row["status"] == "COMPLETED" and row.get("artifact") and Path(row["artifact"]).is_file()), None)
        if executable_row:
            ctx.generated_model_executable = Path(executable_row["artifact"])
            executable_ref = ctx.artifact_store.copy_file("build", ctx.generated_model_executable.name,
                ctx.generated_model_executable, evidence_type=EvidenceType.MODEL,
                metadata={"artifact_class": "GENERATED_EXECUTABLE", "generated": True,
                    "source_kind": "MODEL_GENERATED", "production_source": False,
                    "specification_id": generated.manifest["specification_id"],
                    "specification_hash": generated.manifest["specification_hash"],
                    "model_id": generated.manifest["model_id"], "model_hash": generated.manifest["model_hash"],
                    "compiler": executable_row["compiler"]})
            evidence.append(executable_ref)
            executable_row["executable_evidence_id"] = executable_ref.id
        python_source = output_root / "python" / "model.py"
        python_model_runs = []
        if python_source.is_file():
            python_result = ctx.command_runner.run(CommandSpec(
                argv=(sys.executable, str(python_source)), cwd=output_root,
                timeout=options.build_timeout))
            python_row = {"interpreter": sys.executable, "artifact": str(python_source),
                "argv": list(python_result.argv), "exit_code": python_result.exit_code,
                "stdout": python_result.stdout, "stderr": python_result.stderr,
                "timed_out": python_result.timed_out, "execution_error": python_result.execution_error,
                "duration_ms": python_result.duration_ms,
                "status": "PASS" if python_result.succeeded else
                    "BUILD_ERROR" if python_result.timed_out or python_result.exit_code not in (None, 0) else "TOOL_ERROR"}
            python_runs_ref = ctx.artifact_store.write_json("build", "python-model-runtime.json",
                python_row, evidence_type=EvidenceType.LOG,
                metadata={"artifact_class": "GENERATED_PYTHON_MODEL_RUN", "generated": True,
                    "source_kind": "MODEL_GENERATED", "production_source": False,
                    "generated_path": "python/model.py", "specification_id": generated.manifest["specification_id"],
                    "specification_hash": generated.manifest["specification_hash"],
                    "model_id": generated.manifest["model_id"], "model_hash": generated.manifest["model_hash"]})
            python_row["evidence_id"] = python_runs_ref.id
            python_model_runs.append(python_row)
            evidence.append(python_runs_ref)
        python_passed = bool(python_model_runs) and python_model_runs[0]["status"] == "PASS"
        status = ("BUILD_ERROR" if any(row["status"] == "BUILD_ERROR" for row in compiler_runs)
                  or any(row["status"] == "BUILD_ERROR" for row in python_model_runs) else
                  "PASS" if executable_row and python_passed else "ENVIRONMENT_LIMITED")
        result_ref = ctx.artifact_store.write_json("build", "build-result.json", {
            "status": status, "scope": "generated-model-project-only", "model_id": generated.manifest["model_id"],
            "specification_id": generated.manifest["specification_id"],
            "specification_hash": generated.manifest["specification_hash"],
            "compiler_runs": compiler_runs, "fuzz_compiler_runs": fuzz_compiler_runs,
            "python_model_runs": python_model_runs}, evidence_type=EvidenceType.TEST_RESULT,
            metadata={"artifact_class": "BUILD_RESULT", "status": status,
                "model_id": generated.manifest["model_id"],
                "specification_hash": generated.manifest["specification_hash"]})
        evidence.append(result_ref)
        return StageOutput(value={"status": status, "compiler_runs": compiler_runs,
                                  "fuzz_compiler_runs": fuzz_compiler_runs,
                                  "python_model_runs": python_model_runs}, evidence=tuple(evidence),
            metadata={"build_status": status, "build_result_evidence_id": result_ref.id,
                "generated_executable": str(ctx.generated_model_executable) if ctx.generated_model_executable else None,
                "generated_fuzz_executable": str(ctx.generated_model_fuzz_executable) if ctx.generated_model_fuzz_executable else None,
                "fuzz_compiler_runs": fuzz_compiler_runs,
                "compiler_runs": compiler_runs, "python_model_runs": python_model_runs,
                "stage_status": "COMPLETED" if executable_row and python_passed else "FAILED",
                **({"error": "Generated model C did not produce an executable."} if not executable_row else {})})

    @staticmethod
    def source(ctx: Any, options: Any) -> StageOutput:
        sources = tuple(options.source_files) if options.source_files is not None else SourceLoader().load_source_tree(ctx.project)
        if not sources:
            return StageOutput(value=StageSkipped("No supported source files were found in the project."))
        for source in sources:
            resolved = Path(source.path).resolve(strict=True)
            if not resolved.is_relative_to(ctx.project):
                raise ValueError(f"Source file is outside the project tree: {source.relative_path}")
            if not resolved.is_file():
                raise ValueError(f"Source file is not a regular file: {source.relative_path}")
        detection = LanguageDetector().detect(sources)
        functions = FunctionDetector().detect(sources)
        ctx.source_files, ctx.language = sources, detection
        discovered_functions = [{"name": item.name, "file": item.file, "line": item.line,
                                 "language": item.language} for item in functions]
        function_links, file_links = _source_function_links(ctx.specification, sources, functions)
        function_ids_by_source: dict[str, list[str]] = {item.relative_path: [] for item in sources}
        requirements_by_source: dict[str, list[str]] = {item.relative_path: [] for item in sources}
        for link in function_links:
            relative = link.get("source_relative_path")
            if relative and link["match_status"] == "MATCHED":
                function_ids_by_source[relative].append(link["function_id"])
                requirements_by_source[relative].extend(
                    req for req in link["requirement_ids"] if req not in requirements_by_source[relative])
        source_rows = [{"source_id": _source_id(item.relative_path),
                        "artifact_class": "PRODUCTION_SOURCE", "artifact_path": str(item.path),
                        "project_relative_path": item.relative_path, "size_bytes": item.size_bytes,
                        "sha256": item.sha256, "before_sha256": item.sha256,
                        "language_hint": item.language_hint,
                        "function_ids": function_ids_by_source[item.relative_path],
                        "requirement_ids": requirements_by_source[item.relative_path]}
                       for item in sources]
        ctx.source_metadata = {"files": source_rows,
                               "language": detection.language.value, "language_reason": detection.reason,
                               "functions": discovered_functions,
                               "function_links": function_links,
                               "source_function_links": file_links}
        ref = ctx.artifact_store.write_json("source", "source-inventory.json", ctx.source_metadata)
        for row in source_rows:
            row["source_inventory_evidence_id"] = ref.id
            for req_id in row["requirement_ids"]:
                trace = ctx.traceability.get(req_id)
                if trace is not None:
                    source_ref = {"source_id": row["source_id"], "function_ids": row["function_ids"],
                                  "path": row["project_relative_path"], "sha256": row["sha256"]}
                    if source_ref not in trace.setdefault("sources", []):
                        trace["sources"].append(source_ref)
        lineage_ref = ctx.artifact_store.write_json("source", "source-lineage.json", {
            "files": source_rows, "functions": function_links,
            "classification": {"provided_source": "PRODUCTION_SOURCE", "generated_harness": "TEST_HARNESS"},
        }, evidence_type=EvidenceType.ENVIRONMENT)
        source_stage_metadata = {"source_count": len(sources), "function_count": len(functions),
            "language": detection.language.value, "lineage_evidence_id": lineage_ref.id,
            "function_links": function_links}
        return StageOutput(sources, evidence=(ref, lineage_ref), metadata=source_stage_metadata)

    @staticmethod
    def ctl(ctx: Any, _options: Any) -> StageOutput:
        model, reason = PipelineStages._formal_model(ctx)
        if model is None:
            return PipelineStages._model_unavailable(ctx, "CTL", reason)
        if ctx.specification is None:
            return StageOutput(value=StageSkipped("A valid specification is required."))
        ctl_properties = _properties(ctx.specification, "CTL")
        if not ctl_properties:
            return StageOutput(value=StageSkipped("The specification declares no CTL properties."))
        results, evidence = [], []
        for prop in ctl_properties:
            ctx.metadata.setdefault("property_model_links", {})[prop.id] = {
                "model_hash": model.model_hash, "state_ids": list(model.state_ids),
                "transition_ids": list(model.transition_ids)}
            started = time.monotonic()
            try:
                checked = model_checker.check(model, prop.formula)
                elapsed_ms = (time.monotonic() - started) * 1000
                proof = {"property_id": prop.id, "formula": prop.formula,
                         "observed_status": "PASS" if checked.satisfied else "FAIL",
                         "satisfied": checked.satisfied,
                         "model_hash": model.model_hash,
                         "model_statistics": dict(model.statistics),
                         "state_ids": list(model.state_ids),
                         "transition_ids": list(model.transition_ids),
                         "initial_state_ids": [s.id for s in checked.initial_states],
                         "satisfying_state_ids": sorted(s.id for s in checked.satisfying_states),
                         "violating_initial_state_ids": sorted(s.id for s in checked.initial_states
                                                               if s not in checked.satisfying_states),
                         "witness": _state_path(checked.witness, model),
                         "counterexample": _state_path(checked.counterexample, model),
                         "counterexample_validated": checked.counterexample_validated,
                         "duration_ms": elapsed_ms}
                ref = ctx.artifact_store.write_json("ctl", f"{_filename(prop.id)}.json", proof,
                    evidence_type=(EvidenceType.COUNTEREXAMPLE if checked.counterexample else
                                   EvidenceType.WITNESS if checked.witness else EvidenceType.MODEL),
                    property_id=prop.id)
                result = classify_ctl_result(checked, property_id=prop.id, evidence_ids=(ref.id,),
                                             duration_ms=elapsed_ms)
            except Exception as exc:
                ref = ctx.artifact_store.write_json("ctl", f"{_filename(prop.id)}-error.json",
                    {"property_id": prop.id, "error_type": type(exc).__name__, "message": str(exc)},
                    evidence_type=EvidenceType.LOG, property_id=prop.id)
                from seclab.formal.ctl.errors import CTLError
                if isinstance(exc, CTLError):
                    result = replace(classify_ctl_error(exc, property_id=prop.id),
                                     evidence_ids=(ref.id,))
                else:
                    result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                        stage="FORMAL", technique="CTL", property_id=prop.id,
                        reason_code="CTL_CHECK_ERROR", message=str(exc), evidence_ids=(ref.id,)))
            evidence.append(ref)
            results.extend(_link_result(result, prop.id, prop.requirement_ids))
            ctx.metadata.setdefault("property_model_links", {})[prop.id] = {
                "model_hash": model.model_hash, "state_ids": list(model.state_ids),
                "transition_ids": list(model.transition_ids)}
        results = _annotate_formal_results(ctx, results,
            {prop.id: {"model_hash": model.model_hash, "formula": prop.formula,
                       "cross_check_key": prop.metadata.get("cross_check_key"),
                       "state_ids": list(model.state_ids),
                       "transition_ids": list(model.transition_ids)} for prop in ctl_properties})
        return StageOutput(results=tuple(results), evidence=tuple(evidence), metadata={"properties_checked": len(ctl_properties)})

    @staticmethod
    def bmc(ctx: Any, options: Any) -> StageOutput:
        model, reason = PipelineStages._formal_model(ctx)
        if model is None:
            return PipelineStages._model_unavailable(ctx, "BMC", reason)
        if ctx.specification is None:
            return StageOutput(value=StageSkipped("A valid specification is required."))
        from seclab.formal.bmc import BMCChecker
        bmc_properties = _properties(ctx.specification, "BMC")
        if not bmc_properties:
            return StageOutput(value=StageSkipped("The specification declares no BMC properties."))
        results, evidence = [], []
        for prop in bmc_properties:
            ctx.metadata.setdefault("property_model_links", {})[prop.id] = {
                "model_hash": model.model_hash, "state_ids": list(model.state_ids),
                "transition_ids": list(model.transition_ids)}
            started = time.monotonic()
            try:
                checked = BMCChecker().check_up_to_bound(model, prop.bound if prop.bound is not None else options.bmc_default_bound,
                    prop.formula, timeout_seconds=options.solver_timeout, artifact_store=ctx.artifact_store,
                    property_id=prop.id, requirement_id=None)
                result = checked.verification_result
                results.extend(_link_result(result, prop.id, prop.requirement_ids))
                ctx.metadata.setdefault("property_model_links", {})[prop.id] = {
                    "model_hash": model.model_hash, "state_ids": list(model.state_ids),
                    "transition_ids": list(model.transition_ids)}
                evidence.extend(checked.evidence)
            except Exception as exc:
                ref = ctx.artifact_store.write_json("bmc", f"{_filename(prop.id)}-error.json",
                    {"property_id": prop.id, "error_type": type(exc).__name__, "message": str(exc)},
                    evidence_type=EvidenceType.LOG, property_id=prop.id)
                from seclab.formal.bmc import BMCError
                invalid_input = isinstance(exc, BMCError) and exc.code.value in {
                    "INVALID_BMC_BOUND", "EMPTY_MODEL", "NO_INITIAL_STATE", "UNKNOWN_PROPOSITION"}
                result = ResultClassifier().classify(ClassificationInput(
                    outcome=RawOutcome.INVALID_SPEC if invalid_input else RawOutcome.TOOL_FAILED,
                    stage="BOUNDED_MODEL_CHECKING", technique="BMC", property_id=prop.id,
                      reason_code=exc.code.value if invalid_input else "BMC_CHECK_ERROR",
                      message=str(exc), evidence_ids=(ref.id,),
                      duration_ms=(time.monotonic() - started) * 1000))
                results.extend(_link_result(result, prop.id, prop.requirement_ids)); evidence.append(ref)
        results = _annotate_formal_results(ctx, results,
            {prop.id: {"model_hash": model.model_hash, "bad_proposition": prop.formula,
                       "cross_check_key": prop.metadata.get("cross_check_key"),
                       "bound": prop.bound, "query_mode": "UP_TO_BOUND"} for prop in bmc_properties})
        return StageOutput(results=tuple(results), evidence=tuple(evidence), metadata={"properties_checked": len(bmc_properties)})

    @staticmethod
    def smt(ctx: Any, options: Any) -> StageOutput:
        if ctx.specification is None:
            return StageOutput(value=StageSkipped("A valid specification is required."))
        smt_properties = _properties(ctx.specification, "SMT")
        if not smt_properties:
            return StageOutput(value=StageSkipped("The specification declares no SMT properties."))
        from seclab.formal.smt import QueryIntent, SMTVerifier
        results, evidence = [], []
        for prop in smt_properties:
            started = time.monotonic()
            try:
                query_intent = QueryIntent(prop.metadata.get("query_intent", QueryIntent.VIOLATION_SEARCH.value))
                checked = SMTVerifier().check(ctx.specification, prop.formula, query_intent=query_intent,
                    property_id=prop.id, requirement_id=None, timeout_seconds=options.solver_timeout,
                    artifact_store=ctx.artifact_store)
                results.extend(_link_result(checked.result, prop.id, prop.requirement_ids))
                evidence.extend(checked.evidence)
            except Exception as exc:
                ref = ctx.artifact_store.write_json("smt", f"{_filename(prop.id)}-error.json",
                    {"property_id": prop.id, "error_type": type(exc).__name__, "message": str(exc)},
                    evidence_type=EvidenceType.LOG, property_id=prop.id)
                from seclab.formal.smt import SMTError
                invalid_input = isinstance(exc, SMTError) and exc.code.value not in {
                    "SOLVER_NOT_FOUND", "SOLVER_TIMEOUT", "SOLVER_UNKNOWN", "SOLVER_ERROR", "SMT_ENCODING_ERROR"}
                result = ResultClassifier().classify(ClassificationInput(
                    outcome=RawOutcome.INVALID_SPEC if invalid_input else RawOutcome.TOOL_FAILED,
                      stage="FORMAL", technique="SMT", property_id=prop.id,
                      reason_code=exc.code.value if invalid_input else "SMT_CHECK_ERROR",
                      message=str(exc), evidence_ids=(ref.id,),
                      duration_ms=(time.monotonic() - started) * 1000))
                results.extend(_link_result(result, prop.id, prop.requirement_ids)); evidence.append(ref)
        results = _annotate_formal_results(ctx, results,
            {prop.id: {"specification_id": ctx.specification.id, "property_expression": prop.formula,
                       "cross_check_key": prop.metadata.get("cross_check_key"),
                       "variable_ids": [item.id for item in ctx.specification.variables],
                       "constraint_ids": [item.id for item in ctx.specification.constraints],
                       "query_intent": prop.metadata.get("query_intent", "VIOLATION_SEARCH")}
             for prop in smt_properties})
        return StageOutput(results=tuple(results), evidence=tuple(evidence), metadata={"properties_checked": len(smt_properties)})
    @staticmethod
    def static(ctx: Any, options: Any) -> StageOutput:
        generated_sources = _generated_model_sources(ctx)
        if not ctx.source_files and not generated_sources:
            return StageOutput(value=StageSkipped("No supported source files were found."))
        if not options.static_analyzers:
            return StageOutput(value=StageSkipped("No static analyzers were configured."))
        from seclab.static_analysis import (AnalysisContext, ClangStaticAnalyzerRunner,
            ClangTidyRunner, CompilerDiagnosticsRunner, CppcheckRunner)
        classes = {"compiler": CompilerDiagnosticsRunner, "cppcheck": CppcheckRunner,
                   "clang-tidy": ClangTidyRunner, "clang-static": ClangStaticAnalyzerRunner}
        # Shared build and process tools keep paths confined to this run workspace.
        from seclab.execution import CommandRunner
        runner = ctx.command_runner or CommandRunner()
        analysis_ctx = AnalysisContext(source_root=ctx.project, workspace_root=ctx.workspace,
            toolchain=ctx.toolchain, command_runner=runner, artifact_store=ctx.artifact_store,
            timeout=options.analysis_timeout, flags=options.static_flags)
        results, evidence = [], []
        capability_tools = {"compiler": ("gcc", "g++", "clang", "clang++"),
                            "cppcheck": ("cppcheck",), "clang-tidy": ("clang-tidy",),
                            "clang-static": ("clang", "clang++")}
        capabilities = {name: [ctx.toolchain.get(tool).to_dict() for tool in capability_tools[name]]
                        for name in options.static_analyzers if name in capability_tools}
        for name in options.static_analyzers:
            if not ctx.source_files:
                break
            cls = classes.get(name)
            if cls is None:
                ref = ctx.artifact_store.write_json("static", f"{_filename(name)}-configuration-error.json",
                    {"analyzer": name, "error": "UNKNOWN_STATIC_ANALYZER",
                     "configured_analyzers": sorted(classes)}, evidence_type=EvidenceType.LOG)
                result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                    stage="STATIC_ANALYSIS", technique=name, reason_code="UNKNOWN_STATIC_ANALYZER",
                    message=f"Unknown static analyzer '{name}'. Supported analyzers: {', '.join(sorted(classes))}.",
                    source=str(ctx.project), evidence_ids=(ref.id,)))
                results.append(result)
                evidence.append(ref)
                continue
            try:
                analyzed = cls().analyze(ctx.source_files, analysis_ctx)
                result = analyzed.to_verification_result()
                evidence.extend(analyzed.evidence)
                result = replace(result, metadata={**dict(result.metadata), "analyzer": name})
                result, result_evidence = _ensure_result_evidence(ctx, result, "static", f"{name}-result.json")
                results.append(result)
                evidence.extend(result_evidence)
            except Exception as exc:
                ref = ctx.artifact_store.write_json("static", f"{name}-error.json",
                    {"error_type": type(exc).__name__, "message": str(exc)}, evidence_type=EvidenceType.LOG)
                result = ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                    stage="STATIC_ANALYSIS", technique=name, reason_code="ANALYZER_ERROR", message=str(exc),
                    source=str(ctx.project), evidence_ids=(ref.id,)))
                results.append(result); evidence.append(ref)
        if generated_sources:
            generated_ctx = AnalysisContext(source_root=ctx.generated_c_root,
                workspace_root=ctx.workspace / "static-generated-model", toolchain=ctx.toolchain,
                command_runner=runner, artifact_store=ctx.artifact_store,
                timeout=options.analysis_timeout, flags=options.static_flags)
            generated_ctx.workspace_root.mkdir(parents=True, exist_ok=True)
            for name in options.static_analyzers:
                cls = classes.get(name)
                if cls is None:
                    continue
                try:
                    analyzed = cls().analyze(generated_sources, generated_ctx)
                    generated_result = analyzed.to_verification_result()
                    evidence.extend(analyzed.evidence)
                    generated_result = replace(generated_result,
                        id=f"{generated_result.id}-GENERATED-MODEL",
                        technique=f"{generated_result.technique}-GENERATED-MODEL",
                        metadata={**dict(generated_result.metadata), "analyzer": name,
                            "artifact_scope": "GENERATED_ARTIFACT",
                            "generated": True, "source_kind": "MODEL_GENERATED",
                            "production_source": False,
                            "generated_source_hashes": {item.relative_path: item.sha256
                                for item in generated_sources},
                            "codegen_manifest_evidence_id": next((item.id for item in ctx.artifact_store.all()
                                if item.stage == "codegen" and item.path.endswith("manifest.json")), None)})
                    generated_result, generated_refs = _ensure_result_evidence(ctx, generated_result,
                        "static", f"{name}-generated-model-result.json")
                    results.append(generated_result)
                    evidence.extend(generated_refs)
                except Exception as exc:
                    ref = ctx.artifact_store.write_json("static", f"{name}-generated-model-error.json",
                        {"error_type": type(exc).__name__, "message": str(exc),
                         "artifact_scope": "GENERATED_ARTIFACT", "generated": True,
                         "source_kind": "MODEL_GENERATED", "production_source": False},
                        evidence_type=EvidenceType.LOG)
                    evidence.append(ref)
                    results.append(ResultClassifier().classify(ClassificationInput(
                        outcome=RawOutcome.TOOL_FAILED, stage="STATIC_ANALYSIS",
                        technique=f"{name}-GENERATED-MODEL", reason_code="ANALYZER_ERROR",
                        message=str(exc), evidence_ids=(ref.id,),
                        metadata={"artifact_scope": "GENERATED_ARTIFACT", "generated": True,
                            "source_kind": "MODEL_GENERATED", "production_source": False})))
        return StageOutput(results=tuple(results), evidence=tuple(evidence), metadata={
            "analyzers": list(options.static_analyzers), "tool_capabilities": capabilities,
            "generated_model_files": [item.relative_path for item in generated_sources],
            "finding_count": sum(len(item.metadata.get("finding_ids", ())) for item in results),
            "environment_limited": [item.technique for item in results
                                    if item.metadata.get("capability_status") == "ENVIRONMENT_LIMITED"]})

    @staticmethod
    def memory(ctx: Any, options: Any) -> StageOutput:
        if not options.run_memory:
            return StageOutput(value=StageSkipped("Memory analysis was disabled."))
        if not ctx.source_files and not _generated_model_runtime_sources(ctx):
            return StageOutput(value=StageSkipped("No supported source files were found."))
        from seclab.memory import ASanRunner, LeakChecker, StructAnalyzer, UBSanRunner
        from seclab.static_analysis import AnalysisContext
        from seclab.execution import CommandRunner
        analysis_context = AnalysisContext(source_root=ctx.project, workspace_root=ctx.workspace / "memory",
            toolchain=ctx.toolchain, command_runner=ctx.command_runner or CommandRunner(),
            artifact_store=ctx.artifact_store, timeout=options.analysis_timeout)
        analysis_context.workspace_root.mkdir(parents=True, exist_ok=True)
        results, evidence, limitations = [], [], []
        sanitizer_capabilities = []
        struct = StructAnalyzer().analyze(ctx.source_files) if ctx.source_files else None
        if struct is not None:
            limitations.extend(struct.limitations)
            struct_ref = ctx.artifact_store.write_json("memory", "struct-analysis.json",
                {"supported": struct.supported, "layouts": list(struct.layouts),
                 "limitations": list(struct.limitations)}, evidence_type=EvidenceType.LOG)
            evidence.append(struct_ref)
        for name, runner_cls in (("asan", ASanRunner), ("ubsan", UBSanRunner), ("leak", LeakChecker)) if ctx.source_files else ():
            try:
                run = runner_cls().run(ctx.source_files, context=analysis_context, language=ctx.language.language)
                limitations.extend(item for item in run.limitations if item not in limitations)
                sanitizer_capabilities.append({"sanitizer": run.sanitizer, "supported": run.supported,
                    "reason_code": run.verification_result.reason_code,
                    "capability_status": run.verification_result.metadata.get("capability_status",
                        "AVAILABLE" if run.supported else "ENVIRONMENT_LIMITED"),
                    "compiler": (run.build_result.compiler.to_dict() if run.build_result and run.build_result.compiler else None),
                    "build_error": run.build_result.error_code if run.build_result else None})
                if run.verification_result is not None:
                    result, result_evidence = _ensure_result_evidence(
                        ctx, run.verification_result, "memory", f"{name}-result.json", run.evidence)
                    results.append(result)
                    evidence.extend(result_evidence)
                else:
                    evidence.extend(run.evidence)
            except Exception as exc:
                ref = ctx.artifact_store.write_json("memory", f"{name}-error.json",
                    {"error_type": type(exc).__name__, "message": str(exc)}, evidence_type=EvidenceType.LOG)
                results.append(ResultClassifier().classify(ClassificationInput(outcome=RawOutcome.TOOL_FAILED,
                    stage="MEMORY_ANALYSIS", technique=name.upper(), reason_code="MEMORY_ANALYZER_ERROR",
                    message=str(exc), evidence_ids=(ref.id,))))
                evidence.append(ref)
        generated_sources = _generated_model_runtime_sources(ctx)
        if generated_sources:
            generated_context = AnalysisContext(source_root=ctx.generated_c_root,
                workspace_root=ctx.workspace / "memory" / "generated-model",
                toolchain=ctx.toolchain, command_runner=ctx.command_runner or CommandRunner(),
                artifact_store=ctx.artifact_store, timeout=options.analysis_timeout)
            generated_context.workspace_root.mkdir(parents=True, exist_ok=True)
            generated_struct = StructAnalyzer().analyze(generated_sources)
            generated_struct_ref = ctx.artifact_store.write_json("memory", "generated-model-struct-analysis.json",
                {"supported": generated_struct.supported, "layouts": list(generated_struct.layouts),
                 "limitations": list(generated_struct.limitations), "artifact_scope": "GENERATED_ARTIFACT",
                 "generated": True, "source_kind": "MODEL_GENERATED", "production_source": False},
                evidence_type=EvidenceType.LOG)
            evidence.append(generated_struct_ref)
            for name, runner_cls in (("asan-generated-model", ASanRunner),
                                     ("ubsan-generated-model", UBSanRunner),
                                     ("leak-generated-model", LeakChecker)):
                try:
                    run = runner_cls().run(generated_sources, context=generated_context,
                                           language=ctx.language.language if ctx.language else "C")
                    limitations.extend(item for item in run.limitations if item not in limitations)
                    if run.verification_result is not None:
                        generated_result = replace(run.verification_result,
                            id=f"{run.verification_result.id}-GENERATED-MODEL",
                            technique=f"{run.verification_result.technique}-GENERATED-MODEL",
                            metadata={**dict(run.verification_result.metadata),
                                "artifact_scope": "GENERATED_ARTIFACT", "generated": True,
                                "source_kind": "MODEL_GENERATED", "production_source": False,
                                "generated_source_hashes": {item.relative_path: item.sha256
                                    for item in generated_sources},
                                "codegen_manifest_evidence_id": next((item.id for item in ctx.artifact_store.all()
                                    if item.stage == "codegen" and item.path.endswith("manifest.json")), None)})
                        generated_result, generated_refs = _ensure_result_evidence(ctx, generated_result,
                            "memory", f"{name}-result.json", run.evidence)
                        results.append(generated_result)
                        evidence.extend(generated_refs)
                    else:
                        evidence.extend(run.evidence)
                except Exception as exc:
                    ref = ctx.artifact_store.write_json("memory", f"{name}-error.json",
                        {"error_type": type(exc).__name__, "message": str(exc),
                         "artifact_scope": "GENERATED_ARTIFACT", "generated": True,
                         "source_kind": "MODEL_GENERATED", "production_source": False},
                        evidence_type=EvidenceType.LOG)
                    evidence.append(ref)
                    results.append(ResultClassifier().classify(ClassificationInput(
                        outcome=RawOutcome.TOOL_FAILED, stage="MEMORY_ANALYSIS", technique=name.upper(),
                        reason_code="MEMORY_ANALYZER_ERROR", message=str(exc), evidence_ids=(ref.id,),
                        metadata={"artifact_scope": "GENERATED_ARTIFACT", "generated": True,
                            "source_kind": "MODEL_GENERATED", "production_source": False})))
        return StageOutput(results=tuple(results), evidence=tuple(evidence), limitations=tuple(limitations),
            metadata={"sanitizer_capabilities": sanitizer_capabilities,
                      "generated_model_files": [item.relative_path for item in generated_sources],
                      "finding_count": sum(len(item.metadata.get("finding_ids", ())) for item in results),
                      "environment_limited": [item.technique for item in results
                          if item.metadata.get("capability_status") == "ENVIRONMENT_LIMITED"]})

    @staticmethod
    def build_tests(ctx: Any, options: Any) -> tuple[TestCase, ...]:
        if ctx.specification is None:
            return ()
        functions = {item.id: item for item in ctx.specification.functions}
        cases = []
        for item in ctx.specification.tests:
            fn = functions.get(item.function_id) if item.function_id else None
            raw_input = dict(item.input)
            target_kind = TestTargetKind.FUNCTION if fn else TestTargetKind.EXECUTABLE
            target = fn.name if fn else str(raw_input.get("target", "program"))
            if fn:
                if "args" in raw_input and isinstance(raw_input["args"], dict):
                    inputs = raw_input["args"]
                else:
                    inputs = {key: value for key, value in raw_input.items() if key not in {"target", "stdin", "argv"}}
                # The generated harness validates argument names; preserve supplied input exactly.
            else:
                inputs = {key: raw_input[key] for key in ("stdin", "argv") if key in raw_input}
            expected = item.expected
            try:
                expected = ExpectedBehavior.from_mapping(expected) if isinstance(expected, dict) else expected
                if isinstance(expected, (str, int, float, bool)):
                    expected = _scalar_expected(expected, raw_input)
                case = TestCase(id=item.id, name=item.description or item.id, target=target, inputs=inputs,
                    expected=expected, category=_test_category(item.kind), target_kind=target_kind,
                    requirement_id=None, timeout_seconds=options.execution_timeout,
                    metadata={"requirement_ids": list(item.requirement_ids), "function_id": item.function_id})
            except Exception as exc:
                # Keep malformed individual cases visible and preserve their diagnostic.
                case = TestCase(id=item.id, name=item.description or item.id, target="unsupported",
                    target_kind=TestTargetKind.ABSTRACT, metadata={"construction_error": f"{type(exc).__name__}: {exc}",
                    "requirement_ids": list(item.requirement_ids)}, timeout_seconds=options.execution_timeout)
            cases.append(case)
            ctx.options.test_case_requirement_ids[item.id] = tuple(item.requirement_ids)
            ctx.options.test_case_function_ids[item.id] = item.function_id
        return tuple(cases)

    @staticmethod
    def dynamic(ctx: Any, options: Any) -> StageOutput:
        from seclab.execution.process_runner import ProcessRunner
        from seclab.testing import TestRunner
        cases = tuple(options.test_cases) if options.test_cases is not None else PipelineStages.build_tests(ctx, options)
        ctx.test_cases = cases
        tr = TestRunner(ctx.workspace / "dynamic", ctx.toolchain, artifact_store=ctx.artifact_store,
                        process_runner=ProcessRunner(), build_timeout=options.build_timeout)
        model_cases = _generated_model_test_cases(ctx, options)
        model_sources = _generated_model_runtime_sources(ctx)
        model_executions = ()
        project_executions = ()
        evidence = []
        if cases and ctx.source_files:
            suite = tr.run_many(cases, source_files=ctx.source_files,
                language=ctx.language.language if ctx.language else None, build_flags=options.build_flags)
            project_executions = suite.executions
        if model_cases and ctx.generated_model_executable and model_sources:
            suite = tr.run_many(model_cases, source_files=model_sources, language="C",
                executable=ctx.generated_model_executable)
            model_executions = suite.executions
            ctx.generated_model_test_cases = model_cases
            ctx.generated_model_test_results = model_executions
            refs_by_id = {item.id: item for item in ctx.artifact_store.all()}
            evidence.extend(refs_by_id[item] for execution in model_executions
                for item in execution.evidence_ids if item in refs_by_id)
        if not project_executions and not model_executions:
            reason = ("Generated model executable is unavailable; no generated-model dynamic observation was made."
                      if ctx.codegen_result is not None else
                      "No executable project tests or generated-model transition tests are configured.")
            return StageOutput(value=StageSkipped(reason), evidence=tuple(evidence), metadata={
                "generated_model_status": "UNSUPPORTED" if ctx.codegen_result is not None else "NOT_REQUESTED",
                "project_test_count": len(cases), "generated_model_test_count": len(model_cases)})
        executions = (*project_executions, *model_executions)
        results = []
        case_by_id = {item.id: item for item in (*cases, *model_cases)}
        for execution in executions:
            raw_result = execution.verification_result
            case = case_by_id.get(execution.test_case_id)
            if case is not None:
                raw_result = replace(raw_result, metadata={**dict(raw_result.metadata),
                    "function_id": case.metadata.get("function_id"), "test_case_id": execution.test_case_id,
                    "source_kind": case.metadata.get("source_kind", "PROJECT_SOURCE"),
                    "generated": case.metadata.get("generated", False),
                    "model_state_ids": list(case.metadata.get("model_state_ids", ())),
                    "model_transition_ids": list(case.metadata.get("model_transition_ids", ())),
                    "execution_id": execution.execution_id,
                    "test_case_evidence_id": execution.test_case_evidence_id,
                    "observation_evidence_id": execution.observation_evidence_id})
            req_ids = ctx.options.test_case_requirement_ids.get(execution.test_case_id,
                (raw_result.requirement_id,) if raw_result.requirement_id else ())
            linked_results = _link_result(raw_result, execution.test_case_id, req_ids)
            results.extend(linked_results)
            test_case = case_by_id.get(execution.test_case_id)
            property_id = test_case.property_id if test_case is not None else None
            execution_row = {"id": execution.execution_id, "test_case_id": execution.test_case_id,
                "result_ids": [item.id for item in linked_results], "executed": execution.executed,
                "observation": execution.observed.to_dict() if execution.observed else None,
                "observation_evidence_id": execution.observation_evidence_id,
                "test_case_evidence_id": execution.test_case_evidence_id,
                "execution_evidence_ids": list(execution.execution_evidence_ids),
                "evidence_ids": list(execution.evidence_ids)}
            ctx.metadata.setdefault("execution_index", {})[execution.execution_id] = execution_row
            if property_id:
                property_links = ctx.metadata.setdefault("property_test_cases", {}).setdefault(property_id, [])
                if execution.test_case_id not in property_links:
                    property_links.append(execution.test_case_id)
            for req_id in req_ids:
                trace = ctx.traceability.get(req_id)
                if trace is None:
                    continue
                target = trace.setdefault("targets", {}).setdefault(execution.test_case_id, {
                    "target_id": execution.test_case_id, "target_kind": "TEST_CASE", "stage_id": "DYNAMIC",
                    "results": [], "evidence_ids": [], "statuses": [], "status": "NOT_CHECKED"})
                target.setdefault("execution_ids", []).append(execution.execution_id)
                if execution.observation_evidence_id:
                    target.setdefault("observation_evidence_ids", []).append(execution.observation_evidence_id)
                target["evidence_ids"].extend(item for item in execution.evidence_ids if item not in target["evidence_ids"])
                target["execution"] = {**execution_row,
                    "result_id": next((item.id for item in linked_results if item.requirement_id == req_id),
                                       linked_results[0].id if linked_results else None)}
            ctx.metadata.setdefault("execution_index", {})[execution.execution_id] = execution_row
        ctx.dynamic_results = executions
        unique_evidence = tuple({item.id: item for item in evidence}.values())
        return StageOutput(executions, tuple(results), evidence=unique_evidence, metadata={
            "test_count": len(cases) + len(model_cases), "project_test_count": len(cases),
            "generated_model_test_count": len(model_cases),
            "generated_model_executed_count": sum(bool(item.executed) for item in model_executions),
            "executed_count": sum(bool(x.executed) for x in executions)})

    @staticmethod
    def coverage(ctx: Any, options: Any) -> StageOutput:
        if not options.run_coverage:
            return StageOutput(value=StageSkipped("Coverage measurement was disabled."))
        generated_scope = bool(ctx.generated_model_test_cases and ctx.generated_model_test_results)
        coverage_cases = ctx.generated_model_test_cases if generated_scope else ctx.test_cases
        coverage_sources = _generated_model_runtime_sources(ctx) if generated_scope else ctx.source_files
        coverage_language = "C" if generated_scope else (ctx.language.language if ctx.language else None)
        coverage_root = ctx.generated_c_root if generated_scope else ctx.project
        if not coverage_sources or not coverage_cases or not ctx.dynamic_results:
            return StageOutput(value=StageSkipped("Coverage requires executable source files and completed dynamic tests."),
                metadata={"target_scope": "MODEL_GENERATED" if generated_scope else "PROJECT_SOURCE",
                          "status": "UNSUPPORTED", "reason_code": "COVERAGE_INPUTS_UNAVAILABLE"})
        from seclab.coverage import CoverageRunner
        from seclab.execution.process_runner import ProcessRunner
        from seclab.testing import TestRunner
        test_runner = TestRunner(ctx.workspace, ctx.toolchain,
                                 artifact_store=ctx.artifact_store, process_runner=ProcessRunner(),
                                 build_timeout=options.build_timeout)
        runner = CoverageRunner(ctx.workspace / "coverage", ctx.toolchain, test_runner=test_runner,
                                process_runner=ProcessRunner(), artifact_store=ctx.artifact_store)
        try:
            measured = runner.run(coverage_cases, source_files=coverage_sources, language=coverage_language,
                backend=options.coverage_backend, source_root=coverage_root,
                run_id=(ctx.run_id + "-model") if generated_scope else ctx.run_id)
            ctx.coverage_report = measured.report
            evidence = tuple(item for item in ctx.artifact_store.all() if item.stage.startswith("coverage"))
            value = measured.report
            if measured.errors:
                ctx.limitations.extend(measured.errors)
            return StageOutput(value=value, results=(measured.verification_result,) if measured.verification_result else (),
                               evidence=evidence, limitations=tuple(measured.errors),
                               metadata={"measurement_only": True, "has_report": measured.report is not None,
                                   "target_scope": "MODEL_GENERATED" if generated_scope else "PROJECT_SOURCE",
                                   "source_hashes": {item.relative_path: item.sha256 for item in coverage_sources}})
        except Exception as exc:
            raise RuntimeError(f"Coverage runner failed: {exc}") from exc

    @staticmethod
    def fuzzing(ctx: Any, options: Any) -> StageOutput:
        config = options.fuzz_config
        if config is None:
            return StageOutput(value=StageSkipped("No fuzz configuration was provided."),
                metadata={"status": "SKIPPED", "reason_code": "FUZZ_CONFIG_MISSING",
                          "fuzz_configured": False,
                          "gui_run_configuration": options.metadata.get("gui_run_configuration", {})})
        generated_scope = bool(ctx.codegen_result and ctx.generated_c_root and _generated_model_runtime_sources(ctx))
        if generated_scope:
            fuzz_sources = _generated_model_fuzz_sources(ctx)
            # Transition testcases exercise the CLI with fixed argv; that CLI does
            # not consume stdin, so running a black-box stdin campaign for every
            # edge only repeats the same transition oracle. DYNAMIC already checks
            # each transition against the canonical structured-output oracle.
            # FUZZING targets the generated API harness, whose byte input actually
            # drives model API lookups and transition operations.
            fuzz_cases = ()
            api_case = _generated_model_api_test_case(ctx, options)
            if api_case is not None:
                fuzz_cases = (api_case,)
        else:
            fuzz_sources = ctx.source_files
            fuzz_cases = ctx.test_cases
            fuzz_cases = _add_discovered_function_templates(fuzz_cases, fuzz_sources, ctx.specification,
                options.execution_timeout)
        if not fuzz_cases or not fuzz_sources:
            return StageOutput(value=StageSkipped("Fuzzing requires a runnable test template and source files."),
                metadata={"target_scope": "MODEL_GENERATED" if generated_scope else "PROJECT_SOURCE",
                          "status": "UNSUPPORTED", "reason_code": "FUZZ_TARGET_UNAVAILABLE",
                          "fuzz_configured": True,
                          "gui_run_configuration": options.metadata.get("gui_run_configuration", {})})
        from seclab.fuzzing import FuzzEngine, FuzzStrategy
        from seclab.fuzzing.models import FuzzInput, InputKind, InputOrigin
        from seclab.testing import TestRunner
        from seclab.coverage import CoverageRunner
        from seclab.execution.process_runner import ProcessRunner
        test_runner = TestRunner(ctx.workspace, ctx.toolchain, artifact_store=ctx.artifact_store,
                                 process_runner=ProcessRunner(), build_timeout=options.build_timeout)
        coverage = None
        if config.strategy is FuzzStrategy.COVERAGE_GUIDED:
            if ctx.stage_records.get("COVERAGE") and ctx.stage_records["COVERAGE"].status.value != "COMPLETED":
                if not config.fallback_to_blackbox:
                    return StageOutput(value=StageSkipped("Coverage-guided fuzzing requires completed coverage measurement."))
            if ctx.coverage_report is None:
                if not config.fallback_to_blackbox:
                    return StageOutput(value=StageSkipped("Coverage-guided fuzzing requires a coverage report."))
            else:
                coverage = _FuzzCoverageAdapter(CoverageRunner(ctx.workspace / "c", ctx.toolchain,
                    test_runner=test_runner, process_runner=ProcessRunner(), artifact_store=ctx.artifact_store))
        engine = FuzzEngine(ctx.workspace / "fuzz", test_runner, coverage_runner=coverage,
                            artifact_store=ctx.artifact_store)
        campaigns = []
        linked_results = []
        all_target_sources: dict[str, Any] = {}
        templates = tuple(fuzz_cases)
        for index, original in enumerate(templates, start=1):
            template = original
            model_api_fuzz = bool(template.metadata.get("model_api_fuzz"))
            model_transition_fuzz = generated_scope and not model_api_fuzz
            if generated_scope and not model_api_fuzz:
                from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType
                states = template.metadata.get("model_state_ids", ())
                transitions = template.metadata.get("model_transition_ids", ())
                template = replace(template,
                    expected=ExpectedBehavior((OracleExpectation(OracleType.NO_CRASH, True),)),
                    metadata={**template.to_dict()["metadata"],
                        "analysis_surface": "MODEL_GENERATED_TRANSITION",
                        "model_state_ids": list(states), "model_transition_ids": list(transitions)})
            target_sources = (_generated_model_fuzz_sources(ctx) if model_api_fuzz else
                              _generated_model_runtime_sources(ctx) if generated_scope else tuple(fuzz_sources))
            target_executable = (ctx.generated_model_fuzz_executable if model_api_fuzz else
                                 ctx.generated_model_executable if generated_scope else None)
            all_target_sources.update({item.relative_path: item for item in target_sources})
            surface = template.metadata.get("analysis_surface", "PROJECT_FUNCTION")
            _notify_fuzz_stage(ctx, {"event": "target_started", "target_index": index,
                "target_count": len(templates), "target": template.target, "test_case_id": template.id,
                "function_id": template.metadata.get("function_id"), "analysis_surface": surface,
                "step": "PREPARE"})
            def report_progress(event: Any, *, item=template, item_index=index) -> None:
                payload = dict(event)
                payload.update({"target_index": item_index, "target_count": len(templates),
                    "target": item.target, "test_case_id": item.id,
                    "function_id": item.metadata.get("function_id"),
                    "analysis_surface": item.metadata.get("analysis_surface", "PROJECT_FUNCTION")})
                payload["step"] = {"campaign_started": "GENERATE", "input_generated": "EXECUTE",
                    "execution_completed": "ORACLE", "case_completed": "CORPUS"}.get(
                        payload.get("event"), "GENERATE")
                _notify_fuzz_stage(ctx, payload)
            target_config = replace(config, target=None, entry_point=None)
            if model_api_fuzz:
                template_seeds = (FuzzInput(f"model-api-{ctx.run_id}", b"\x00\x01\x02\x03",
                    InputKind.BYTES, InputOrigin.SEED, metadata={"model_id": template.metadata.get("model_id")}),)
            else:
                template_seeds = (FuzzInput(f"template-{template.id}", template.to_dict()["inputs"], InputKind.SCALARS,
                    InputOrigin.SEED, metadata={"test_case_id": template.id}),) if template.inputs else ()
            campaign = engine.run(template, target_config, seeds=(*options.fuzz_seeds, *template_seeds),
                specification=ctx.specification, source_files=target_sources,
                language="C" if generated_scope else (ctx.language.language if ctx.language else None),
                executable=target_executable, backend=options.coverage_backend, progress_callback=report_progress)
            campaigns.append(campaign)
            _notify_fuzz_stage(ctx, {"event": "target_finished", "step": "EVIDENCE",
                "target_index": index, "target_count": len(templates), "target": template.target,
                "test_case_id": template.id, "function_id": template.metadata.get("function_id"),
                "requested": campaign.iterations_requested, "executed": campaign.iterations_executed,
                "analysis_surface": surface,
                "findings": len(campaign.failures),
                "corpus_size": campaign.corpus_size, "evidence_count": len(campaign.evidence_ids),
                "stop_reason": campaign.stop_reason,
                "campaign_status": campaign.verification_result.status.value if campaign.verification_result else "UNKNOWN"})
            if campaign.verification_result is not None:
                linked = replace(campaign.verification_result, metadata={
                    **dict(campaign.verification_result.metadata), "test_case_id": template.id,
                    "function_id": template.metadata.get("function_id"),
                    "source_kind": template.metadata.get("source_kind", "PROJECT_SOURCE"),
                    "generated": template.metadata.get("generated", False),
                    "model_state_ids": list(template.metadata.get("model_state_ids", ())),
                    "model_transition_ids": list(template.metadata.get("model_transition_ids", ())),
                    "analysis_surface": surface, "target_index": index, "target_count": len(templates),
                    "model_hash": template.metadata.get("model_hash")})
                requirement_ids = tuple(template.metadata.get("requirement_ids", ()))
                linked_results.extend(tuple(replace(linked, id=f"{linked.id}-{req_index + 1}", requirement_id=req_id)
                    for req_index, req_id in enumerate(requirement_ids)) or (linked,))
        ctx.fuzz_results = tuple(campaigns)
        refs = tuple(item for item in ctx.artifact_store.all() if item.stage.startswith("fuzz"))
        campaign_rows = [{**item.to_dict(), "target": templates[n].target,
            "test_case_id": templates[n].id, "function_id": templates[n].metadata.get("function_id"),
            "analysis_surface": templates[n].metadata.get("analysis_surface",
                "MODEL_GENERATED_TRANSITION" if generated_scope else "PROJECT_FUNCTION"),
            "model_hash": templates[n].metadata.get("model_hash") or
                (ctx.codegen_result.manifest.get("model_hash") if generated_scope and ctx.codegen_result else None),
            "model_state_ids": list(templates[n].metadata.get("model_state_ids", ())),
            "model_transition_ids": list(templates[n].metadata.get("model_transition_ids", ()))}
            for n, item in enumerate(campaigns)]
        output = campaign_rows[0] if len(campaign_rows) == 1 else {"campaigns": campaign_rows}
        _notify_fuzz_stage(ctx, {"event": "fuzz_finished", "step": "EVIDENCE", "target_count": len(templates),
            "completed_targets": len(campaigns), "executed": sum(item.iterations_executed for item in campaigns),
            "requested": sum(item.iterations_requested for item in campaigns),
            "findings": sum(len(item.failures) for item in campaigns),
            "evidence_count": sum(len(item.evidence_ids) for item in campaigns)})
        return StageOutput(output, results=tuple(linked_results), evidence=refs, metadata={"finding_count": sum(len(item.failures) for item in campaigns),
            "executed_count": sum(item.iterations_executed for item in campaigns),
            "campaign_count": len(campaigns), "target_count": len(templates),
            "stop_reason": campaigns[-1].stop_reason if campaigns else "NO_CAMPAIGNS",
            "target_scope": "MODEL_GENERATED" if generated_scope else "PROJECT_SOURCE",
            "target_source_hashes": {name: item.sha256 for name, item in all_target_sources.items()}})
    @staticmethod
    def cross_check(ctx: Any, _options: Any) -> StageOutput:
        from seclab.pipeline.cross_check import CrossCheckStatus, build_cross_check_matrix, json_safe

        matrix = json_safe(build_cross_check_matrix(ctx))
        ref = ctx.artifact_store.write_json("cross-check", "matrix.json", matrix,
            evidence_type=EvidenceType.TEST_RESULT,
            metadata={"artifact_kind": "cross-check-matrix", "aggregation": "NONE"})
        ctx.metadata["cross_check_matrix"] = matrix
        ctx.metadata["cross_check_matrix_evidence_id"] = ref.id
        results = []
        for relation in matrix["inconsistencies"]:
            evidence_ids = tuple(dict.fromkeys((ref.id, *relation.get("evidence_ids", ()))))
            results.append(ResultClassifier().classify(ClassificationInput(
                outcome=RawOutcome.UNKNOWN, stage="CROSS_CHECK", technique="CROSS_CHECK_MATRIX",
                reason_code="CROSS_CHECK_INCONSISTENCY",
                message=f"Cross-check relation {relation['id']} contains contradictory evidence; no checker result was selected.",
                scope=f"Evidence relation {relation['from']} â†” {relation['to']} for this run.",
                evidence_ids=evidence_ids,
                metadata={"relation_id": relation["id"], "relation_status": CrossCheckStatus.INCONSISTENCY.value,
                          "inconsistencies": relation.get("mappings", [])})))
        counts = {status.value: sum(row["status"] == status.value for row in matrix["relations"])
                  for status in CrossCheckStatus}
        return StageOutput(value=matrix, results=tuple(results), evidence=(ref,),
            metadata={"relation_counts": counts, "inconsistency_count": len(matrix["inconsistencies"]),
                      "aggregation": "NONE", "matrix_evidence_id": ref.id})


def _notify_fuzz_stage(ctx: Any, payload: dict[str, Any]) -> None:
    callback = getattr(ctx, "progress_callback", None)
    if callback is not None:
        try:
            callback({"stage_id": "FUZZING", "status": "RUNNING", "progress_event": payload})
        except Exception:
            pass


def _add_discovered_function_templates(cases: Any, sources: Any, specification: Any,
                                      timeout: float) -> tuple[Any, ...]:
    """Give each detected C/C++ function a bounded no-crash fuzz template when none exists."""
    from seclab.testing import (ExpectedBehavior, OracleExpectation, OracleType, TestCase,
                               TestCategory, TestTargetKind)

    prepared = list(cases)
    covered = {item.target for item in prepared if item.target_kind is TestTargetKind.FUNCTION}
    declared = {item.name: item for item in getattr(specification, "functions", ())}
    for index, function in enumerate(FunctionDetector().detect(sources), start=1):
        if function.language not in {"C", "C++"} or function.name in covered:
            continue
        inputs = {}
        for declaration in function.parameters or ():
            if declaration.strip() == "void":
                continue
            match = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*$", declaration)
            if match:
                inputs[match.group(1)] = 0
        function_spec = declared.get(function.name)
        function_id = function_spec.id if function_spec else None
        requirement_ids = tuple(function_spec.requirement_ids) if function_spec else ()
        case_id = f"AUTO-FUZZ-{index}-{function.name}"
        prepared.append(TestCase(id=case_id, name=f"Auto-discovered fuzz target: {function.name}",
            target=function.name, inputs=inputs,
            expected=ExpectedBehavior((OracleExpectation(OracleType.NO_CRASH, True),)),
            category=TestCategory.NORMAL, target_kind=TestTargetKind.FUNCTION,
            requirement_id=requirement_ids[0] if requirement_ids else None, timeout_seconds=timeout,
            metadata={"function_id": function_id, "requirement_ids": list(requirement_ids),
                "source_kind": "AUTO_DISCOVERED", "source_file": function.file,
                "source_line": function.line, "oracle_basis": "bounded no-crash baseline"}))
        covered.add(function.name)
    return tuple(prepared)


def _generated_model_sources(ctx: Any) -> tuple[Any, ...]:
    """Load only generated model artifacts, excluding standalone function fixtures."""
    root = getattr(ctx, "generated_c_root", None)
    if root is None or not Path(root).is_dir():
        return ()
    model_paths = {"source/model.c", "include/model.h"}
    return tuple(item for item in SourceLoader(exclude=()).load_source_tree(root)
                 if item.relative_path in model_paths)


def _generated_model_runtime_sources(ctx: Any) -> tuple[Any, ...]:
    """Source inputs needed to integrity-check the built generated model executable."""
    root = getattr(ctx, "generated_c_root", None)
    if root is None or not Path(root).is_dir():
        return ()
    runtime_paths = {"source/model.c", "tests/model_test.c"}
    return tuple(item for item in SourceLoader(exclude=()).load_source_tree(root)
                 if item.relative_path in runtime_paths)


def _generated_model_fuzz_sources(ctx: Any) -> tuple[Any, ...]:
    """Load the model implementation and the fuzz entrypoint/driver."""
    root = getattr(ctx, "generated_c_root", None)
    if root is None or not Path(root).is_dir():
        return ()
    paths = {"source/model.c", "fuzz/model_fuzz.c", "fuzz/model_fuzz_driver.c"}
    return tuple(item for item in SourceLoader(exclude=()).load_source_tree(root)
                 if item.relative_path in paths)


def _generated_model_api_test_case(ctx: Any, options: Any) -> TestCase | None:
    """Create a byte-driven no-crash target for the generated C model API."""
    sources = _generated_model_fuzz_sources(ctx)
    if not sources or {item.relative_path for item in sources} != {
        "source/model.c", "fuzz/model_fuzz.c", "fuzz/model_fuzz_driver.c"
    }:
        return None
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType, TestCategory

    model = getattr(ctx, "kripke", None)
    state_ids = [item.id for item in model.states] if model is not None else []
    transition_ids = [item.id for item in model.transitions] if model is not None else []
    model_hash = getattr(ctx, "codegen_result", None)
    model_hash = (model_hash.manifest.get("model_hash")
                  if model_hash is not None and isinstance(model_hash.manifest, dict) else None)
    return TestCase(id=f"MODEL-API-{_filename(str(model_hash or ctx.run_id))}",
        name="Generated C model API robustness", target="generated-model-api", inputs={"stdin": ""},
        expected=ExpectedBehavior((OracleExpectation(OracleType.NO_CRASH, True),)),
        category=TestCategory.NORMAL, target_kind=TestTargetKind.EXECUTABLE,
        timeout_seconds=options.execution_timeout,
        metadata={"source_kind": "MODEL_GENERATED", "generated": True, "model_api_fuzz": True,
            "fuzz_stdin": True, "analysis_surface": "MODEL_GENERATED_API", "model_hash": model_hash,
            "model_state_ids": state_ids, "model_transition_ids": transition_ids,
            "oracle_basis": "generated C API invariants and bounded no-crash execution"})


def _generated_model_test_cases(ctx: Any, options: Any) -> tuple[TestCase, ...]:
    """Create transition-level cases whose oracle is the canonical model itself."""
    model = getattr(ctx, "kripke", None)
    if model is None or getattr(ctx, "codegen_result", None) is None:
        return ()
    from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType, TestCategory

    requirement_rows: dict[str, list[str]] = {}
    map_path = Path(ctx.generated_c_root) / "requirements-map.json"
    try:
        payload = json.loads(map_path.read_text(encoding="utf-8"))
        for row in payload.get("requirements", ()):
            for transition_id in row.get("transition_ids", ()):
                requirement_rows.setdefault(transition_id, []).append(row["requirement_id"])
    except (OSError, ValueError, TypeError):
        requirement_rows = {}
    transition_by_state: dict[str, list[Any]] = {state.id: [] for state in model.states}
    for edge in model.transitions:
        transition_by_state[edge.source].append(edge)
    scenarios = [(model.get_state(edge.source), edge) for edge in model.transitions]
    scenarios.extend((state, None) for state in model.initial_states if not transition_by_state[state.id])
    cases = []
    for index, (state, edge) in enumerate(scenarios):
        outgoing = [item.id for item in transition_by_state[state.id]]
        expected_output = {"input_state_id": state.id, "is_initial": state in model.initial_states,
            "transition_id": edge.id if edge else None,
            "result_state_id": edge.target if edge else state.id,
            "outgoing_transition_ids": outgoing}
        transition_id = edge.id if edge else "INITIAL"
        case_id = f"MODEL-{index + 1}-{_filename(transition_id)}"
        req_ids = tuple(sorted(set(requirement_rows.get(edge.id, ()))) if edge else ())
        expectation = ExpectedBehavior((OracleExpectation(OracleType.EXIT_CODE_EQUALS, 0),
            OracleExpectation(OracleType.STRUCTURED_OUTPUT_EQUALS, expected_output)))
        cases.append(TestCase(id=case_id, name=f"Generated model transition {transition_id}",
            target="generated-model", inputs={"argv": [state.id, edge.id] if edge else [state.id]},
            expected=expectation, category=TestCategory.NORMAL, target_kind=TestTargetKind.EXECUTABLE,
            requirement_id=req_ids[0] if req_ids else None, timeout_seconds=options.execution_timeout,
            metadata={"source_kind": "MODEL_GENERATED", "generated": True,
                "model_state_ids": [state.id, edge.target] if edge else [state.id],
                "model_transition_ids": [edge.id] if edge else [],
                "requirement_ids": list(req_ids), "oracle_basis": "canonical Kripke model"}))
        options.test_case_requirement_ids[case_id] = req_ids
        options.test_case_function_ids[case_id] = None
    return tuple(cases)


def _parse_sanitizer_findings(output: str) -> list[dict[str, Any]]:
    """Extract only categories explicitly emitted by ASan/UBSan diagnostics."""
    patterns = (
        ("heap-buffer-overflow", "BUFFER_OVERFLOW", "CWE-122"),
        ("stack-buffer-overflow", "BUFFER_OVERFLOW", "CWE-121"),
        ("global-buffer-overflow", "BUFFER_OVERFLOW", "CWE-122"),
        ("heap-use-after-free", "USE_AFTER_FREE", "CWE-416"),
        ("double-free", "DOUBLE_FREE", "CWE-415"),
        ("attempting double-free", "DOUBLE_FREE", "CWE-415"),
        ("detected memory leaks", "MEMORY_LEAK", "CWE-401"),
        ("runtime error:", "UNDEFINED_BEHAVIOR", None),
    )
    lowered = output.casefold()
    findings = []
    for needle, category, cwe in patterns:
        if needle in lowered:
            line = next((row.strip() for row in output.splitlines() if needle in row.casefold()), needle)
            findings.append({"tool": "AddressSanitizer/UndefinedBehaviorSanitizer",
                "category": category, "message": line, "cwe": cwe,
                "confidence": "TOOL_REPORTED", "raw_output": output})
    return findings


def _source_id(relative_path: str) -> str:
    return "SRC-" + hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:16]


def _filename(value: str) -> str:
    """Return a filesystem-safe, deterministic evidence filename component."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._-")
    return cleaned[:100] or "item"


def _state_path(path: Any, model: Any) -> list[str] | None:
    """Serialize a CTL witness or counterexample as ordered specification state IDs."""
    if path is None:
        return None
    return [state.id for state in path]


def _source_function_links(specification: Any, sources: tuple[Any, ...], detected: tuple[Any, ...]
                           ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if specification is None:
        return [], [{"source_id": _source_id(item.relative_path), "function_ids": [],
                     "requirement_ids": []} for item in sources]
    links: list[dict[str, Any]] = []
    functions_by_file: dict[str, list[str]] = {item.relative_path: [] for item in sources}
    for function in specification.functions:
        candidates = [item for item in detected if item.name == function.name]
        if function.file:
            requested_file = function.file.replace("\\", "/").casefold()
            candidates = [item for item in candidates if item.file.replace("\\", "/").casefold() == requested_file]
        if len(candidates) == 1:
            candidate = candidates[0]
            source = next((item for item in sources if item.relative_path == candidate.file), None)
            status = "MATCHED" if source is not None else "SOURCE_NOT_FOUND"
        else:
            candidate = None
            source = None
            status = "AMBIGUOUS" if candidates else "UNMATCHED"
        record = {"function_id": function.id, "name": function.name, "declared_file": function.file,
                  "requirement_ids": list(function.requirement_ids), "match_status": status,
                  "source_id": _source_id(source.relative_path) if source else None,
                  "source_relative_path": source.relative_path if source else None,
                  "detected_file": candidate.file if candidate else None,
                  "detected_line": candidate.line if candidate else None}
        links.append(record)
        if source is not None:
            functions_by_file[source.relative_path].append(function.id)
    by_id = {item.id: item for item in specification.functions}
    file_links = []
    for source in sources:
        function_ids = functions_by_file[source.relative_path]
        requirement_ids = list(dict.fromkeys(req for function_id in function_ids
                                             for req in by_id[function_id].requirement_ids))
        file_links.append({"source_id": _source_id(source.relative_path), "project_relative_path": source.relative_path,
                           "function_ids": function_ids, "requirement_ids": requirement_ids})
    return links, file_links


def _link_result(result: Any, entity_id: str, requirement_ids: tuple[str, ...]) -> tuple[Any, ...]:
    reqs = tuple(requirement_ids) or (None,)
    property_id = result.property_id or (entity_id if result.stage != "DYNAMIC_TEST" else None)
    return tuple(replace(result, id=f"{result.id}-{index+1}", property_id=property_id,
                         requirement_id=req_id) for index, req_id in enumerate(reqs))


def _annotate_formal_results(ctx: Any, results: list[Any], inputs_by_property: dict[str, dict[str, Any]]) -> list[Any]:
    """Attach the common auditable run envelope without changing result semantics."""
    artifacts = {item.id: item for item in ctx.artifact_store.all()}
    annotated = []
    for result in results:
        refs = [{"id": evidence_id, "path": artifacts[evidence_id].path,
                 "sha256": artifacts[evidence_id].hash}
                for evidence_id in result.evidence_ids if evidence_id in artifacts]
        details = dict(result.metadata)
        declared_inputs = inputs_by_property.get(result.property_id or "", {})
        if declared_inputs.get("model_hash"):
            details.setdefault("model_hash", declared_inputs["model_hash"])
        if declared_inputs.get("cross_check_key"):
            details["cross_check_key"] = declared_inputs["cross_check_key"]
        tool_version = (details.get("backend_version") or details.get("tool_version")
                        or ("native-finite-ctl-v1" if result.technique == "CTL" else None))
        details["formal_run"] = {
            "run_id": ctx.run_id,
            "checker": result.technique,
            "property_id": result.property_id,
            "observed_status": result.status.value,
            "reason_code": result.reason_code,
            "inputs": declared_inputs,
            "artifact_references": refs,
            "evidence_ids": list(result.evidence_ids),
            "timing_ms": result.duration_ms,
            "tool_version": tool_version,
        }
        identity = "|".join((ctx.run_id, result.technique, result.property_id or "",
                             result.requirement_id or "", result.reason_code))
        stable_id = "VR-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        annotated.append(replace(result, id=stable_id, metadata=details))
    return annotated


def _test_category(kind: str | None) -> TestCategory:
    mapping = {"boundary": TestCategory.BOUNDARY, "fuzz": TestCategory.NEGATIVE,
               "integration": TestCategory.NORMAL, "system": TestCategory.NORMAL,
               "unit": TestCategory.NORMAL}
    return mapping.get((kind or "").lower(), TestCategory.NORMAL)


def _ensure_result_evidence(ctx: Any, result: Any, stage: str, filename: str,
                            existing: tuple[Any, ...] = ()) -> tuple[Any, tuple[Any, ...]]:
    """Persist a result record when an adapter has no native evidence artifact."""
    if result.evidence_ids:
        return result, existing
    ref = ctx.artifact_store.write_json(stage, filename, result.to_dict(), evidence_type=EvidenceType.LOG,
                                       metadata={"result_id": result.id, "result_status": result.status.value})
    return replace(result, evidence_ids=(ref.id,)), (*existing, ref)


def _scalar_expected(value: Any, raw_input: dict[str, Any]) -> ExpectedBehavior | None:
    """Normalize the established scalar spec test form to one supported oracle."""
    if isinstance(value, bool):
        return ExpectedBehavior.from_mapping({"return_value": value})
    if isinstance(value, (int, float)):
        return ExpectedBehavior.from_mapping({"return_value": value})
    if isinstance(value, str):
        if "stdin" in raw_input or "argv" in raw_input:
            return ExpectedBehavior.from_mapping({"stdout": value})
        return ExpectedBehavior.from_mapping({"return_value": value})
    return None
