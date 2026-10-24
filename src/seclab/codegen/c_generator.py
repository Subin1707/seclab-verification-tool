"""Deterministic, data-driven C artifacts for explicit finite-state models.

Generated model source represents the canonical Kripke graph. It is classified
as GENERATED_ARTIFACT and is not source code for an external system under test.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from seclab.codegen.ir import CBlock, CFile, CLine, CProgram
from seclab.model import KripkeStructure
from seclab.specification import Specification

GENERATOR_VERSION = "1.4.0"


class CGenerationError(ValueError):
    """A specification/model cannot be represented safely by this generator."""


@dataclass(frozen=True, slots=True)
class CGenerationResult:
    root: Path
    manifest: dict[str, Any]
    source_map: dict[str, Any]
    generation_metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"root": str(self.root), "manifest": self.manifest, "source_map": self.source_map,
                "generation_metadata": self.generation_metadata or {}}


# Public generic contract name; keep the existing result name for compatibility.
GeneratedProject = CGenerationResult


class CGenerator:
    """Write reproducible C model, test, and optional fuzz artifacts."""

    def generate(self, specification: Specification, model: KripkeStructure,
                 output_root: str | Path, *, include_fuzz: bool = False,
                 validate_specification_match: bool = True,
                 source_specification_paths: tuple[str, ...] = (),
                 source_specification_hashes: tuple[dict[str, str], ...] = (),
                 run_id: str | None = None) -> CGenerationResult:
        model.validate()
        if validate_specification_match:
            from seclab.model import generate_kripke_structure
            expected_model = generate_kripke_structure(specification)
            if expected_model.model_hash != model.model_hash:
                raise CGenerationError("The supplied canonical model does not match the normalized specification.")
        root = Path(output_root).expanduser().resolve()
        files, line_maps = _render(specification, model, include_fuzz=include_fuzz)
        specification_payload = _plain_specification(specification)
        specification_hash = hashlib.sha256(_json(specification_payload).encode("utf-8")).hexdigest()
        requirement_ids = sorted({item.id for item in specification.requirements})
        generation_metadata = {"specification_id": specification.id,
            "run_id": run_id,
            "specification_hash": specification_hash,
            "source_specification_paths": list(source_specification_paths),
            "source_specification_hashes": list(source_specification_hashes),
            "model_hash": model.model_hash, "model_id": "MODEL-" + hashlib.sha256(
                (specification.id + "\0" + specification_hash + "\0" + model.model_hash).encode("utf-8")).hexdigest()[:24],
            "requirement_ids": requirement_ids,
            "runtime_contract": {"state_representation": "explicit canonical state index and state valuations",
                "initialization": "first declared initial state in canonical model order",
                "guard_execution": "evaluated guards are compiled; unresolved guards require a runtime callback",
                "action_execution": "a successful step moves to the declared target state, whose valuation is observable; arbitrary action text is not interpreted",
                "automatic_step": "step_next selects the first enabled outgoing transition in canonical model order",
                "model_queries": ["state_by_id", "transition_by_id", "atomic_label", "outgoing_transitions", "initial_states"],
                "model_validation": "runtime checks non-empty models have an initial state, IDs are unique, and transition endpoints are in range",
                "build_project": "CMake C99 static library with a CTest model contract executable",
                "input": "transition selection through runtime API and harness argv",
                "output": "observed state and transition IDs as JSON",
                "not_declared_in_specification": [name for name, declared in (
                    ("runtime_input_schema", bool(specification.variables)),
                    ("runtime_output_schema", bool(specification.metadata.get("outputs")))) if not declared]},
            "generator": "seclab-generic-c", "generator_version": GENERATOR_VERSION,
            "generated_project_root": str(root), "generated_file_count": len(files)}
        file_rows = [{"path": name, "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                      "artifact_class": _artifact_class(name),
                      **({"generated": True, "source_kind": "MODEL_GENERATED",
                          "production_source": False, "specification_id": specification.id,
                          "model_hash": model.model_hash}
                         if name in {"source/model.c", "include/model.h", "tests/model_test.c", "python/model.py"}
                         else {})}
                     for name, content in sorted(files.items())]
        state_requirements: dict[str, set[str]] = {state_id: set() for state_id in model.state_ids}
        transition_requirements: dict[str, set[str]] = {transition_id: set() for transition_id in model.transition_ids}
        for requirement in specification.requirements:
            metadata = requirement.metadata
            if not isinstance(metadata, Mapping):
                continue
            for state_id in metadata.get("state_ids", ()):
                if state_id in state_requirements:
                    state_requirements[state_id].add(requirement.id)
            for transition_id in metadata.get("transition_ids", ()):
                if transition_id in transition_requirements:
                    transition_requirements[transition_id].add(requirement.id)
        source_map = {
            "format_version": 1,
            "generator": "seclab-generic-c",
            "generator_version": GENERATOR_VERSION,
            "specification_id": specification.id,
            "specification_hash": specification_hash,
            "source_specification_paths": list(source_specification_paths),
            "source_specification_hashes": list(source_specification_hashes),
            "requirement_ids": requirement_ids,
            "function_ids": sorted({item.id for item in specification.functions}),
            "function_generation": [],
            "requirements": [{"requirement_id": req_id,
                "generated_locations": [{"path": "source/model.c", "generated_line": 3},
                                        {"path": "include/model.h", "generated_line": 3}]}
                for req_id in requirement_ids],
            "model_id": generation_metadata["model_id"],
            "model_hash": model.model_hash,
            "files": {"source/model.c": {
                "artifact_class": "GENERATED_ARTIFACT",
                "specification_id": specification.id,
                "generated_lines": line_maps["source/model.c"],
                "states": [{"state_id": state.id, "generated_index": i,
                            "source_spec_id": specification.id,
                            "requirement_ids": sorted(state_requirements[state.id]),
                            "source_location": None}
                           for i, state in enumerate(model.states)],
                "transitions": [{"transition_id": edge.id, "source_state_id": edge.source,
                                 "target_state_id": edge.target, "guard": edge.guard,
                                 "source_spec_id": specification.id,
                                 "requirement_ids": sorted(transition_requirements[edge.id]),
                                 "source_location": None,
                                 "guard_status": edge.guard_status, "action": edge.action,
                                 "action_execution": "TARGET_STATE_VALUATION" if edge.action and
                                     _is_simple_assignment_action(edge.action) else
                                     "DESCRIPTIVE_ONLY" if edge.action else "NOT_DECLARED"}
                                for edge in model.transitions],
            }, "include/model.h": {"artifact_class": "GENERATED_ARTIFACT",
                                    "specification_id": specification.id,
                                    "generated_lines": line_maps["include/model.h"]},
                      "tests/model_test.c": {"artifact_class": "TEST_HARNESS",
                                              "specification_id": specification.id,
                                              "generated_lines": line_maps["tests/model_test.c"]},
                      "CMakeLists.txt": {"artifact_class": "BUILD_CONFIGURATION",
                                          "generated_lines": line_maps["CMakeLists.txt"]},
                      "README.md": {"artifact_class": "GENERATION_METADATA",
                                    "generated_lines": line_maps["README.md"]},
                      "python/model.py": {"artifact_class": "GENERATED_ARTIFACT",
                                          "specification_id": specification.id,
                                          "generated_lines": line_maps["python/model.py"],
                                          "states": [{"state_id": state.id, "generated_index": index,
                                                      "source_spec_id": specification.id}
                                                     for index, state in enumerate(model.states)],
                                          "transitions": [{"transition_id": edge.id,
                                                           "source_state_id": edge.source,
                                                           "target_state_id": edge.target,
                                                           "source_spec_id": specification.id}
                                                          for edge in model.transitions]}},
        }
        source_map["test_cases"] = []
        provenance = specification.metadata.get("source_provenance", {})
        source_generation = provenance.get("source_generation", {}) if isinstance(provenance, Mapping) else {}
        generation_rows = source_generation.get("functions", ()) if isinstance(source_generation, Mapping) else ()
        generation_by_id = {str(row.get("function_id", "")): row for row in generation_rows
                            if isinstance(row, Mapping)}
        function_records = []
        for item in sorted(specification.functions, key=lambda row: row.id):
            declared = generation_by_id.get(item.id, {})
            source_location = declared.get("source_location")
            if source_location is None:
                source_location = item.file
            declared_metadata = {key: declared[key] for key in (
                "parameters", "operation", "magic_values", "bug", "buffer_size",
                "allocation_count", "exception_message", "probe_class") if key in declared}
            generation_status = "SOURCE_BOUND_NOT_GENERATED" if item.file else "UNSUPPORTED_NO_EXECUTABLE_CONTRACT"
            # Legacy source-generation fixtures can carry probe declarations in
            # specification provenance. Keep those distinct from real source
            # functions and from model-generated code in the public status field.
            status = "NOT_MODEL_CODE" if declared.get("probe_class") else generation_status
            function_records.append({
                "function_id": item.id, "function_name": item.name, "name": item.name,
                "file": item.file, "source_location": source_location,
                "start_line": None, "end_line": None,
                "language": item.language or declared.get("language") or "UNSPECIFIED",
                "kind": declared.get("kind"), "declared_parameters": list(declared.get("parameters", ())),
                "declared_metadata": declared_metadata,
                "declared_cwe_ids": list(declared.get("cwe_ids", ())),
                "probe_class": declared.get("probe_class"),
                "requirement_ids": list(item.requirement_ids or declared.get("requirement_ids", ())),
                "mapping_status": "DECLARED_ONLY", "specification_id": specification.id,
                "model_state_ids": [], "model_transition_ids": [], "source_kind": None,
                "generated": False, "status": status, "generation_status": generation_status,
                "reason": ("Declared probe metadata is not executable function code; CODEGEN emits model runtimes only."
                           if declared else "Function source is bound to a project file; CODEGEN emits model runtimes only."
                           if item.file else "No typed signature or executable behavior contract is declared."),
                "production_source": False,
            })
        source_map["functions"] = function_records
        requirement_map = _requirement_map(specification, model, (), (), source_map)
        consistency = _model_code_consistency(model, source_map, requirement_map)
        source_map["model_code_consistency"] = consistency
        source_map_text = _json(source_map)
        requirement_map_text = _json(requirement_map)
        _write_tree(root, files)
        _safe_write(root, "source-map.json", source_map_text)
        _safe_write(root, "requirements-map.json", requirement_map_text)
        manifest = {
            "format_version": 1,
            "run_id": run_id,
            "artifact_type": "GENERATED_ARTIFACT",
            "source_classification": "GENERATED_ARTIFACT",
            "generator": "seclab-generic-c",
            "generator_version": GENERATOR_VERSION,
            "specification_id": specification.id,
            "specification_hash": specification_hash,
            "source_specification_paths": list(source_specification_paths),
            "source_specification_hashes": list(source_specification_hashes),
            "requirement_ids": requirement_ids,
            "function_ids": sorted({item.id for item in specification.functions}),
            "functions": source_map["functions"],
            "test_cases": [],
            "model_id": generation_metadata["model_id"],
            "model_hash": model.model_hash,
            "model_code_consistency": consistency,
            "runtime_contract": generation_metadata["runtime_contract"],
            "requirements_map": "requirements-map.json",
            "files": file_rows + [{"path": "source-map.json",
                                   "sha256": hashlib.sha256(source_map_text.encode("utf-8")).hexdigest(),
                                   "artifact_class": "GENERATION_METADATA"},
                                  {"path": "requirements-map.json",
                                   "sha256": hashlib.sha256(requirement_map_text.encode("utf-8")).hexdigest(),
                                   "artifact_class": "GENERATION_METADATA"}],
            "artifact_classes": ["GENERATED_ARTIFACT", "TEST_HARNESS"] + (["FUZZ_HARNESS"] if include_fuzz else []),
            "limitations": sorted(
                {f"Transition {edge.id} uses unresolved guard {edge.guard!r}; runtime guard callback must approve it."
                 for edge in model.transitions if edge.guard_status == "UNRESOLVED_VARIABLES"}
                | {f"Transition {edge.id} action {edge.action!r} is retained as descriptive metadata; only its target state valuation is applied."
                   for edge in model.transitions if edge.action and not _is_simple_assignment_action(edge.action)}
                ),
        }
        _safe_write(root, "manifest.json", _json(manifest))
        return CGenerationResult(root, manifest, source_map, generation_metadata)


def _render(specification: Specification, model: KripkeStructure, *, include_fuzz: bool) -> tuple[dict[str, str], dict[str, list[dict[str, object]]]]:
    _check_supported_model(model)
    states = model.states
    transitions = model.transitions
    requirement_ids = sorted({item.id for item in specification.requirements})
    lines = ["/* GENERATED_ARTIFACT; source_kind=MODEL_GENERATED; production_source=false",
             f" * Specification ID: {_c_comment(specification.id)}",
             f" * Model hash: {model.model_hash} */",
             "/* Generated by seclab-generic-c; class: GENERATED_ARTIFACT.",
             f" * Specification: {_c_comment(specification.id)}",
             f" * Requirement IDs: {_c_comment(', '.join(requirement_ids))}",
             f" * Model hash: {model.model_hash}", " */",
             '#include "../include/model.h"', "", "#include <string.h>", "",
             f"static const size_t generated_state_count = {len(states)}u;",
             f"static const size_t generated_transition_count = {len(transitions)}u;", ""]
    guard_functions: dict[str, str] = {}
    for edge in transitions:
        if edge.guard and edge.guard_status != "UNRESOLVED_VARIABLES":
            function_name, expression = _guard_code(edge.guard, state=model.get_state(edge.source))
            guard_functions[function_name] = f"static int {function_name}(void) {{ return !!({expression}); }}"
    if guard_functions:
        lines.extend(guard_functions[name] for name in sorted(guard_functions))
        lines.append("")
    if not states:
        lines.append("static const seclab_state_t states[1] = {{ 0u, NULL, NULL, NULL, NULL, 0u }};")
    if not transitions:
        lines.append("static const seclab_transition_t transitions[1] = {{ NULL, 0u, 0u, NULL, NULL, NULL, NULL }};")
    for index, state in enumerate(states):
        if state.labels:
            lines.append(f"static const char *const state_labels_{index}[] = {{ " + ", ".join(
                _c_string(label) for label in sorted(state.labels)) + " };")
    if any(state.labels for state in states):
        lines.append("")
    if states:
        lines.append("static const seclab_state_t states[] = {")
        for index, state in enumerate(states):
            label_pointer = f"state_labels_{index}" if state.labels else "NULL"
            lines.append(f"    {{ {index}u, {_c_string(state.id)}, {_c_string(_json(dict(state.values)))}, {_c_string(_json(sorted(state.labels)))}, {label_pointer}, {len(state.labels)}u }},")
        lines += ["};", ""]
    if transitions:
        indexes = {state.id: index for index, state in enumerate(states)}
        lines.append("static const seclab_transition_t transitions[] = {")
        for edge in transitions:
            guard_expr = _guard_code(edge.guard, state=model.get_state(edge.source))[0] if edge.guard_status != "UNRESOLVED_VARIABLES" and edge.guard else None
            lines.append(f"    {{ {_c_string(edge.id or '')}, {indexes[edge.source]}u, {indexes[edge.target]}u, {_c_string(edge.guard or '')}, {_c_string(edge.action or '')}, {_c_string(edge.label or '')}, {guard_expr or 'NULL'} }},")
        lines += ["};", ""]
    lines += ["size_t seclab_state_count(void) { return generated_state_count; }",
              "size_t seclab_transition_count(void) { return generated_transition_count; }",
              "const seclab_state_t *seclab_state_at(size_t index) {",
              "    return index < generated_state_count ? &states[index] : NULL;", "}",
              "const seclab_transition_t *seclab_transition_at(size_t index) {",
              "    return index < generated_transition_count ? &transitions[index] : NULL;", "}",
              "size_t seclab_initial_state_count(void) {",
              "    size_t count = 0u; for (size_t i = 0u; i < generated_state_count; ++i) count += (size_t)seclab_is_initial(i); return count;", "}",
              "int seclab_state_has_label(size_t state_index, const char *label) {",
              "    if (state_index >= generated_state_count || label == NULL) return 0;",
              "    const seclab_state_t *state = &states[state_index];",
              "    for (size_t i = 0u; i < state->label_count; ++i) if (strcmp(state->labels[i], label) == 0) return 1;",
              "    return 0;", "}",
              "int seclab_state_find_label(const char *label, size_t *index_out) {",
              "    if (label == NULL || index_out == NULL) return 0;",
              "    for (size_t i = 0u; i < generated_state_count; ++i) if (seclab_state_has_label(i, label)) { *index_out = i; return 1; }",
              "    return 0;", "}",
              "size_t seclab_outgoing_transition_count(size_t state_index) {",
              "    if (state_index >= generated_state_count) return 0u;",
              "    size_t count = 0u;",
              "    for (size_t i = 0u; i < generated_transition_count; ++i) {",
              "        if (transitions[i].source_index == state_index) ++count;",
              "    }",
              "    return count;", "}",
              "const seclab_transition_t *seclab_outgoing_transition_at(size_t state_index, size_t ordinal) {",
              "    if (state_index >= generated_state_count) return NULL;",
              "    for (size_t i = 0u; i < generated_transition_count; ++i) if (transitions[i].source_index == state_index) { if (ordinal == 0u) return &transitions[i]; --ordinal; }",
              "    return NULL;", "}",
              "int seclab_transition_index(const char *id, size_t *index_out) {",
              "    if (id == NULL || index_out == NULL) return 0;",
              "    for (size_t i = 0u; i < generated_transition_count; ++i) if (strcmp(transitions[i].id, id) == 0) { *index_out = i; return 1; }",
              "    return 0;", "}",
              "int seclab_model_validate(void) {",
              "    if (generated_state_count == 0u) return generated_transition_count == 0u ? 1 : 0;",
              "    if (seclab_initial_state_count() == 0u) return 0;",
              "    for (size_t i = 0u; i < generated_state_count; ++i) {",
              "        const seclab_state_t *s = &states[i]; if (s->id == NULL || s->values_json == NULL || s->labels_json == NULL || s->index != i || (s->label_count != 0u && s->labels == NULL)) return 0;",
              "        for (size_t j = i + 1u; j < generated_state_count; ++j) if (strcmp(s->id, states[j].id) == 0) return 0;",
              "    }",
              "    for (size_t i = 0u; i < generated_transition_count; ++i) {",
              "        const seclab_transition_t *e = &transitions[i]; if (e->id == NULL || e->source_index >= generated_state_count || e->target_index >= generated_state_count) return 0;",
              "        for (size_t j = i + 1u; j < generated_transition_count; ++j) if (strcmp(e->id, transitions[j].id) == 0) return 0;",
              "    } return 1;", "}",
              "int seclab_state_index(const char *id, size_t *index_out) {",
              "    if (id == NULL || index_out == NULL) return 0;",
              "    for (size_t i = 0; i < generated_state_count; ++i) {",
              "        if (strcmp(states[i].id, id) == 0) { *index_out = i; return 1; }",
              "    }", "    return 0;", "}",
              "int seclab_is_initial(size_t index) {",
              "    static const size_t initial_indexes[] = {" + (", ".join(
                  f"{next(i for i, s in enumerate(states) if s.id == initial.id)}u" for initial in model.initial_states
              ) or "0u") + "};",
              "    if (index >= generated_state_count) return 0;",
              "    for (size_t i = 0; i < sizeof(initial_indexes) / sizeof(initial_indexes[0]); ++i)",
              "        if (initial_indexes[i] == index) return 1;",
              "    return 0;", "}",
              "int seclab_transition_enabled(size_t index, seclab_guard_fn guard_fn, void *user_data) {",
              "    if (index >= generated_transition_count) return 0;",
              "    if (transitions[index].guard_expression != NULL) return transitions[index].guard_expression();",
              "    if (transitions[index].guard[0] == '\\0') return 1;",
              "    return guard_fn != NULL && guard_fn(transitions[index].id, transitions[index].guard, user_data) != 0;",
              "}",
              "int seclab_apply_transition(size_t *state_index, size_t transition_index, seclab_guard_fn guard_fn, void *user_data) {",
              "    if (state_index == NULL || transition_index >= generated_transition_count) return 0;",
              "    const seclab_transition_t *edge = &transitions[transition_index];",
              "    if (*state_index != edge->source_index || !seclab_transition_enabled(transition_index, guard_fn, user_data)) return 0;",
              "    *state_index = edge->target_index;",
              "    return 1;",
              "}",
              "int seclab_model_init(size_t *state_index) {",
              "    if (state_index == NULL) return 0;",
              "    for (size_t i = 0u; i < generated_state_count; ++i) {",
              "        if (seclab_is_initial(i)) { *state_index = i; return 1; }",
              "    }",
              "    return 0;",
              "}",
              "int seclab_model_reset(size_t *state_index) { return seclab_model_init(state_index); }",
              "int seclab_model_step(size_t *state_index, size_t transition_index, seclab_guard_fn guard_fn, void *user_data) {",
              "    return seclab_apply_transition(state_index, transition_index, guard_fn, user_data);",
              "}",
              "int seclab_model_step_by_id(size_t *state_index, const char *transition_id, seclab_guard_fn guard_fn, void *user_data) {",
              "    size_t transition_index = 0u; if (!seclab_transition_index(transition_id, &transition_index)) return 0;",
              "    return seclab_model_step(state_index, transition_index, guard_fn, user_data);", "}",
              "int seclab_model_step_next(size_t *state_index, size_t *transition_index_out, seclab_guard_fn guard_fn, void *user_data) {",
              "    if (state_index == NULL || *state_index >= generated_state_count) return 0;",
              "    for (size_t i = 0u; i < generated_transition_count; ++i) {",
              "        if (transitions[i].source_index != *state_index) continue;",
              "        if (seclab_apply_transition(state_index, i, guard_fn, user_data)) {",
              "            if (transition_index_out != NULL) *transition_index_out = i;",
              "            return 1;",
              "        }",
              "    }",
              "    return 0;",
              "}",
              "const seclab_state_t *seclab_model_get_state(size_t state_index) { return seclab_state_at(state_index); }",
              "const seclab_state_t *seclab_model_observe(size_t state_index) { return seclab_model_get_state(state_index); }", ""]
    header = ["/* GENERATED_ARTIFACT; source_kind=MODEL_GENERATED; production_source=false",
              f" * Specification ID: {_c_comment(specification.id)}",
              f" * Model hash: {model.model_hash} */",
              "/* Generated by seclab-generic-c; class: GENERATED_ARTIFACT.",
              f" * Specification: {_c_comment(specification.id)}",
              f" * Requirement IDs: {_c_comment(', '.join(requirement_ids))}",
              f" * Model hash: {model.model_hash}", " */",
              "#ifndef SECLAB_GENERATED_MODEL_H", "#define SECLAB_GENERATED_MODEL_H", "",
              "#include <stddef.h>", "", "typedef struct {", "    size_t index;", "    const char *id;",
              "    const char *values_json;", "    const char *labels_json;", "    const char *const *labels;", "    size_t label_count;", "} seclab_state_t;", "",
              "typedef int (*seclab_guard_fn)(const char *transition_id, const char *guard, void *user_data);",
              "typedef int (*seclab_guard_expression_fn)(void);", "typedef struct {",
              "    const char *id;", "    size_t source_index;", "    size_t target_index;", "    const char *guard;",
              "    const char *action;", "    const char *label;", "    seclab_guard_expression_fn guard_expression;",
              "} seclab_transition_t;", "", "size_t seclab_state_count(void);",
              "size_t seclab_transition_count(void);", "const seclab_state_t *seclab_state_at(size_t index);",
              "const seclab_transition_t *seclab_transition_at(size_t index);",
              "int seclab_state_index(const char *id, size_t *index_out);", "int seclab_is_initial(size_t index);",
              "size_t seclab_initial_state_count(void);",
              "int seclab_state_has_label(size_t state_index, const char *label);",
              "int seclab_state_find_label(const char *label, size_t *index_out);",
              "size_t seclab_outgoing_transition_count(size_t state_index);",
              "const seclab_transition_t *seclab_outgoing_transition_at(size_t state_index, size_t ordinal);",
              "int seclab_transition_index(const char *id, size_t *index_out);",
              "int seclab_model_validate(void);",
              "int seclab_transition_enabled(size_t index, seclab_guard_fn guard_fn, void *user_data);", "",
              "/* Applies a model edge after checking its source state and guard. */",
              "int seclab_apply_transition(size_t *state_index, size_t transition_index, seclab_guard_fn guard_fn, void *user_data);", "",
              "int seclab_model_init(size_t *state_index);",
              "int seclab_model_reset(size_t *state_index);",
              "int seclab_model_step(size_t *state_index, size_t transition_index, seclab_guard_fn guard_fn, void *user_data);",
              "int seclab_model_step_by_id(size_t *state_index, const char *transition_id, seclab_guard_fn guard_fn, void *user_data);",
              "/* Takes the first enabled outgoing model edge and reports its index when requested. */",
              "int seclab_model_step_next(size_t *state_index, size_t *transition_index_out, seclab_guard_fn guard_fn, void *user_data);",
              "const seclab_state_t *seclab_model_get_state(size_t state_index);",
              "const seclab_state_t *seclab_model_observe(size_t state_index);", "",
              "#endif", ""]
    test = ["/* Generated test harness; class: TEST_HARNESS. */", '#include "../include/model.h"',
            "#include <stdio.h>", "#include <string.h>", "",
            "static int validate_model(void) {", f"    if (seclab_state_count() != {len(states)}u) return 1;",
            f"    if (seclab_transition_count() != {len(transitions)}u) return 2;",
            "    if (!seclab_model_validate()) return 7;",
            f"    if (seclab_state_at({len(states)}u) != NULL) return 5;",
            f"    if (seclab_transition_at({len(transitions)}u) != NULL) return 6;"]
    if model.initial_states:
        test += ["    size_t index = 0;",
                 f"    if (!seclab_state_index({_c_string(model.initial_states[0].id)}, &index)) return 3;",
                 "    if (!seclab_is_initial(index)) return 4;"]
    state_indexes = {state.id: index for index, state in enumerate(states)}
    for index, edge in enumerate(transitions):
        test += [f"    const seclab_transition_t *edge_{index} = seclab_transition_at({index}u);",
                 f"    if (strcmp(edge_{index}->id, {_c_string(edge.id or '')}) != 0) return {10 + index};",
                 f"    if (edge_{index}->source_index != {state_indexes[edge.source]}u || edge_{index}->target_index != {state_indexes[edge.target]}u) return {100 + index};"]
        if edge.guard_status == "UNRESOLVED_VARIABLES":
            test.append(f"    if (seclab_transition_enabled({index}u, NULL, NULL)) return {200 + index};")
        else:
            test.append(f"    if (!seclab_transition_enabled({index}u, NULL, NULL)) return {200 + index};")
    test += ["    return 0;", "}", ""]
    test.extend(_model_test_cli().splitlines())
    source_lines = [CLine(line, specification.id, "specification")
                    if line.startswith(" * Specification:") else CLine(line) for line in lines]
    header_lines = [CLine(line, specification.id, "specification")
                    if line.startswith(" * Specification:") else CLine(line) for line in header]
    # Mark the exact generated data rows with canonical model IDs. This keeps
    # the line map tied to the IR node that emitted the row, not a text search.
    for index, state in enumerate(states):
        needle = f"    {{ {index}u, {_c_string(state.id)},"
        for line_index, line in enumerate(source_lines):
            if line.text.startswith(needle):
                source_lines[line_index] = CLine(line.text, state.id, "state")
                break
    for edge in transitions:
        needle = f"    {{ {_c_string(edge.id or '')},"
        for line_index, line in enumerate(source_lines):
            if line.text.startswith(needle):
                source_lines[line_index] = CLine(line.text, edge.id or "", "transition")
                break
    test_lines = [CLine(line) for line in test]
    for index, edge in enumerate(transitions):
        needle = f"    if (strcmp(edge_{index}->id,"
        for line_index, line in enumerate(test_lines):
            if line.text.startswith(needle):
                test_lines[line_index] = CLine(line.text, edge.id or "", "transition")
                break
    program_files = [
        CFile("include/model.h", "GENERATED_ARTIFACT", (CBlock(tuple(header_lines)),)),
        CFile("source/model.c", "GENERATED_ARTIFACT", (CBlock(tuple(source_lines)),)),
        CFile("tests/model_test.c", "TEST_HARNESS", (CBlock(tuple(test_lines)),)),
        CFile("CMakeLists.txt", "BUILD_CONFIGURATION", (CBlock.of(_cmake_project().splitlines()),)),
        CFile("README.md", "GENERATION_METADATA", (CBlock.of(
            _generated_readme(specification, model, include_fuzz).splitlines()),)),
        CFile("python/model.py", "GENERATED_ARTIFACT",
              (CBlock(tuple(_python_model_source(specification, model))),)),
    ]
    if include_fuzz:
        program_files.append(CFile("fuzz/model_fuzz.c", "FUZZ_HARNESS", (CBlock.of(_fuzz_source().split("\n")),)))
        program_files.append(CFile("fuzz/model_fuzz_driver.c", "FUZZ_HARNESS",
            (CBlock.of(_fuzz_driver_source().split("\n")),)))
    return CProgram(tuple(program_files)).render()


def _check_supported_model(model: KripkeStructure) -> None:
    for edge in model.transitions:
        if edge.guard_status == "UNRESOLVED_VARIABLES":
            continue
        if edge.guard:
            _guard_code(edge.guard, state=model.get_state(edge.source))


def _guard_code(expression: str, *, state: Any) -> tuple[str, str]:
    if not expression:
        raise CGenerationError("A non-empty guard expression is required.")
    from seclab.formal.smt import evaluate_expression, parse_expression
    from seclab.formal.smt.ast import Binary, Unary, Variable
    try:
        parsed = parse_expression(expression)
        variables = _variables(parsed, Binary, Unary, Variable)
        if not variables <= state.values.keys():
            raise CGenerationError(f"Guard {expression!r} has unresolved variables for state {state.id!r}.")
        value = evaluate_expression(parsed, state.values)
        if not isinstance(value, bool):
            raise CGenerationError(f"Guard {expression!r} does not evaluate to boolean.")
        # The canonical model already evaluated this guard against the source
        # state and omitted disabled edges. Preserve the guard text on the edge
        # and emit the observed enabled value, rather than re-evaluating it
        # using C integer/string rules that could differ from model semantics.
        canonical_value = "1" if value else "0"
        return f"guard_{hashlib.sha256((expression + chr(0) + canonical_value).encode()).hexdigest()[:12]}", canonical_value
    except CGenerationError:
        raise
    except Exception as exc:
        raise CGenerationError(f"Cannot safely translate guard {expression!r}: {exc}") from exc


def _variables(expression: Any, binary_type: type, unary_type: type, variable_type: type) -> set[str]:
    if isinstance(expression, variable_type): return {expression.name}
    if isinstance(expression, binary_type): return _variables(expression.left, binary_type, unary_type, variable_type) | _variables(expression.right, binary_type, unary_type, variable_type)
    if isinstance(expression, unary_type): return _variables(expression.operand, binary_type, unary_type, variable_type)
    return set()


def _c_string(value: str) -> str:
    chunks = ['"']
    for byte in value.encode("utf-8"):
        if byte == 0x22: chunks.append('\\"')
        elif byte == 0x5C: chunks.append('\\\\')
        elif byte == 0x0A: chunks.append("\\n")
        elif byte == 0x0D: chunks.append("\\r")
        elif byte == 0x09: chunks.append("\\t")
        elif 0x20 <= byte <= 0x7E: chunks.append(chr(byte))
        else: chunks.append(f"\\{byte:03o}")
    chunks.append('"')
    return "".join(chunks)


def _c_comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\r", " ").replace("\n", " ")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _plain_specification(specification: Specification) -> dict[str, Any]:
    from dataclasses import fields, is_dataclass
    def convert(value):
        if is_dataclass(value):
            return {item.name: convert(getattr(value, item.name)) for item in fields(value)}
        if isinstance(value, dict) or hasattr(value, "items"):
            return {str(key): convert(item) for key, item in value.items()}
        if isinstance(value, (tuple, list, set, frozenset)):
            return [convert(item) for item in value]
        return value
    return convert(specification)


def _artifact_class(path: str) -> str:
    if path == "source/generated_test_driver.c": return "TEST_HARNESS"
    if path == "CMakeLists.txt": return "BUILD_CONFIGURATION"
    if path == "README.md": return "GENERATION_METADATA"
    if path.startswith("source/") or path.startswith("include/"): return "GENERATED_ARTIFACT"
    if path.startswith("tests/"): return "TEST_HARNESS"
    if path.startswith("fuzz/"): return "FUZZ_HARNESS"
    if path.startswith("python/"): return "GENERATED_ARTIFACT"
    return "GENERATED_SOURCE"


def _is_simple_assignment_action(action: str) -> bool:
    """True only for assignment syntax validated against an explicit target state."""
    return re.fullmatch(r"\s*[A-Za-z][A-Za-z0-9_.:-]*\s*=(?!=)\s*.+?\s*", action) is not None


def _requirement_map(specification: Specification, model: KripkeStructure,
                     functions: Any, tests: Any,
                     source_map: dict[str, Any]) -> dict[str, Any]:
    """Build traceability only from links explicitly present in the specification."""
    rows = {item.id: {"requirement_id": item.id, "function_ids": [], "test_ids": [],
                      "property_ids": [], "constraint_ids": [], "state_ids": [],
                      "transition_ids": [], "generated_locations": [], "mapping_status": "ORPHAN"}
            for item in specification.requirements}
    for function in functions:
        for req_id in function.get("requirement_ids", ()):
            if req_id in rows: rows[req_id]["function_ids"].append(function["function_id"])
    for test in tests:
        for req_id in test.get("requirement_ids", ()):
            if req_id in rows: rows[req_id]["test_ids"].append(test["test_id"])
    for collection, key in ((specification.properties, "property_ids"),
                            (specification.constraints, "constraint_ids")):
        for entity in collection:
            for req_id in getattr(entity, "requirement_ids", ()):
                if req_id in rows: rows[req_id][key].append(entity.id)
    state_ids, transition_ids = set(model.state_ids), set(model.transition_ids)
    source_requirements = {row["requirement_id"]: row for row in source_map.get("requirements", ())}
    for requirement in specification.requirements:
        row = rows[requirement.id]
        row["function_ids"] = sorted(set(row["function_ids"]) | set(requirement.function_ids))
        row["test_ids"] = sorted(set(row["test_ids"]) | set(requirement.test_ids))
        row["property_ids"] = sorted(set(row["property_ids"]) | set(requirement.property_ids))
        row["constraint_ids"] = sorted(set(row["constraint_ids"]) | set(requirement.constraint_ids))
        metadata = requirement.metadata
        requested_states = set(metadata.get("state_ids", ())) if isinstance(metadata, Mapping) else set()
        requested_transitions = set(metadata.get("transition_ids", ())) if isinstance(metadata, Mapping) else set()
        row["state_ids"] = sorted(requested_states & state_ids)
        row["transition_ids"] = sorted(requested_transitions & transition_ids)
        row["unresolved_state_ids"] = sorted(requested_states - state_ids)
        row["unresolved_transition_ids"] = sorted(requested_transitions - transition_ids)
        row["generated_locations"] = source_requirements.get(requirement.id, {}).get("generated_locations", [])
        linked = any(row[key] for key in ("function_ids", "test_ids", "property_ids", "constraint_ids",
                                          "state_ids", "transition_ids"))
        row["mapping_status"] = "LINKED" if linked else "ORPHAN"
    return {"format_version": 1, "specification_id": specification.id,
            "requirements": [rows[key] for key in sorted(rows)]}


def _model_code_consistency(model: KripkeStructure, source_map: dict[str, Any],
                            requirement_map: dict[str, Any]) -> dict[str, Any]:
    model_data = source_map.get("files", {}).get("source/model.c", {})
    generated_states = {str(item.get("state_id")) for item in model_data.get("states", ())}
    generated_transitions = {str(item.get("transition_id")) for item in model_data.get("transitions", ())}
    model_states, model_transitions = set(model.state_ids), set(model.transition_ids)
    declared = {item.get("requirement_id") for item in source_map.get("requirements", ())}
    mapped = {item.get("requirement_id") for item in requirement_map.get("requirements", ())}
    orphan_functions = sorted(item.get("function_id") for item in source_map.get("functions", ())
                              if not item.get("requirement_ids"))
    return {"status": "PASS" if model_states == generated_states and
            model_transitions == generated_transitions and declared == mapped else "FAIL",
            "model_state_count": len(model_states), "generated_state_count": len(generated_states),
            "model_transition_count": len(model_transitions),
            "generated_transition_count": len(generated_transitions),
            "missing_states": sorted(model_states - generated_states),
            "orphan_states": sorted(generated_states - model_states),
            "missing_transitions": sorted(model_transitions - generated_transitions),
            "orphan_transitions": sorted(generated_transitions - model_transitions),
            "missing_requirements": sorted(declared - mapped), "orphan_functions": orphan_functions,
            "mapping_basis": "generated source-map records; links are specification-declared"}


def _fuzz_source() -> str:
    return "\n".join([
        "/* GENERATED_ARTIFACT; source_kind=MODEL_GENERATED; class: FUZZ_HARNESS. */",
        "#include <stddef.h>", "#include <stdint.h>", "#include <stdlib.h>",
        '#include "../include/model.h"', "",
        "static void check_generated_model(void) {",
        "    if (!seclab_model_validate()) abort();",
        "    size_t state_count = seclab_state_count();",
        "    size_t transition_count = seclab_transition_count();",
        "    if (seclab_state_at(state_count) != NULL || seclab_transition_at(transition_count) != NULL) abort();",
        "    size_t initial = (size_t)-1;",
        "    int has_initial = seclab_model_init(&initial);",
        "    if (has_initial != (seclab_initial_state_count() != 0u)) abort();",
        "    if (has_initial && (!seclab_is_initial(initial) || seclab_model_reset(&initial) == 0)) abort();",
        "    if (has_initial && !seclab_is_initial(initial)) abort();",
        "    if (seclab_model_init(NULL) || seclab_model_reset(NULL)) abort();",
        "    if (seclab_state_index(NULL, &initial) || seclab_state_find_label(NULL, &initial)) abort();",
        "    if (seclab_model_step(NULL, 0u, NULL, NULL) ||",
        "        seclab_model_step_by_id(NULL, NULL, NULL, NULL) ||",
        "        seclab_model_step_next(NULL, NULL, NULL, NULL)) abort();",
        "    for (size_t i = 0u; i < state_count; ++i) {",
        "        const seclab_state_t *state = seclab_state_at(i);",
        "        size_t roundtrip = (size_t)-1;",
        "        if (state == NULL || !seclab_state_index(state->id, &roundtrip) || roundtrip != i) abort();",
        "        for (size_t label = 0u; label < state->label_count; ++label) {",
        "            size_t found = (size_t)-1;",
        "            if (!seclab_state_has_label(i, state->labels[label]) ||",
        "                !seclab_state_find_label(state->labels[label], &found) || found >= state_count) abort();",
        "        }",
        "        size_t outgoing = seclab_outgoing_transition_count(i);",
        "        for (size_t ordinal = 0u; ordinal < outgoing; ++ordinal) {",
        "            const seclab_transition_t *edge = seclab_outgoing_transition_at(i, ordinal);",
        "            if (edge == NULL || edge->source_index != i) abort();",
        "        }",
        "        if (seclab_outgoing_transition_at(i, outgoing) != NULL) abort();",
        "        if (seclab_state_has_label(i, NULL) || seclab_state_has_label(state_count, \"\")) abort();",
        "    }",
        "    for (size_t i = 0u; i < transition_count; ++i) {",
        "        const seclab_transition_t *edge = seclab_transition_at(i);",
        "        size_t roundtrip = (size_t)-1;",
        "        if (edge == NULL || edge->source_index >= state_count || edge->target_index >= state_count ||",
        "            !seclab_transition_index(edge->id, &roundtrip) || roundtrip != i) abort();",
        "        int enabled = seclab_transition_enabled(i, NULL, NULL);",
        "        size_t current = edge->source_index;",
        "        int stepped = seclab_model_step(&current, i, NULL, NULL);",
        "        if (stepped != enabled || current != (enabled ? edge->target_index : edge->source_index)) abort();",
        "        current = edge->source_index;",
        "        stepped = seclab_model_step_by_id(&current, edge->id, NULL, NULL);",
        "        if (stepped != enabled || current != (enabled ? edge->target_index : edge->source_index)) abort();",
        "        current = (edge->source_index + 1u) % state_count;",
        "        size_t unchanged = current;",
        "        if (seclab_apply_transition(&current, i, NULL, NULL) || current != unchanged) abort();",
        "    }",
        "}", "",
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
        "    check_generated_model();",
        "    if (data == NULL) return 0;",
        "    size_t state_count = seclab_state_count();",
        "    size_t transition_count = seclab_transition_count();",
        "    for (size_t i = 0u; i < size; ++i) {",
        "        if (state_count != 0u) {",
        "            size_t state_index = (size_t)data[i] % state_count;",
        "            (void)seclab_model_get_state(state_index);",
        "            (void)seclab_model_observe(state_index);",
        "            (void)seclab_state_has_label(state_index, \"fuzz-label\");",
        "            (void)seclab_outgoing_transition_count(state_index);",
        "        }",
        "        if (transition_count != 0u) {",
        "            size_t transition_index = (size_t)data[i] % transition_count;",
        "            const seclab_transition_t *edge = seclab_transition_at(transition_index);",
        "            size_t state_index = edge->source_index;",
        "            (void)seclab_transition_enabled(transition_index, NULL, NULL);",
        "            (void)seclab_apply_transition(&state_index, transition_index, NULL, NULL);",
        "            state_index = edge->source_index;",
        "            (void)seclab_model_step_next(&state_index, NULL, NULL, NULL);",
        "        }",
        "    }",
        "    return 0;", "}", ""])


def _fuzz_driver_source() -> str:
    return "\n".join([
        "/* Generated bounded stdin driver for the model API fuzz harness. */",
        "#include <stddef.h>", "#include <stdint.h>", "#include <stdio.h>", "",
        "#define SECLAB_FUZZ_STDIN_LIMIT 65536u",
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);", "",
        "int main(void) {",
        "    uint8_t data[SECLAB_FUZZ_STDIN_LIMIT];",
        "    size_t size = fread(data, 1u, sizeof(data), stdin);",
        "    return LLVMFuzzerTestOneInput(data, size);",
        "}", ""])


def _cmake_project() -> str:
    return """cmake_minimum_required(VERSION 3.16)
project(seclab_generated_model C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(seclab_model STATIC source/model.c)
target_include_directories(seclab_model PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(seclab_model_test tests/model_test.c)
target_link_libraries(seclab_model_test PRIVATE seclab_model)

enable_testing()
add_test(NAME generated_model_contract COMMAND seclab_model_test)
"""


def _generated_readme(specification: Specification, model: KripkeStructure,
                      include_fuzz: bool) -> str:
    lines = [f"# Generated model: {specification.name}", "",
        "This project is a C representation of the declared finite-state model. It is not an implementation of application functions.", "",
        f"- Specification: `{specification.id}`", f"- Model SHA-256: `{model.model_hash}`",
        f"- States: {len(model.states)}", f"- Transitions: {len(model.transitions)}",
        f"- Initial states: {len(model.initial_states)}", "", "## Build and run", "", "```sh",
        "cmake -S . -B build", "cmake --build build", "ctest --test-dir build --output-on-failure",
        "./build/seclab_model_test", "```", "", "## Runtime API", "",
        "Include `model.h` and link `seclab_model`. The API supports state and transition lookup, atomic-label queries, outgoing-edge enumeration, initial-state inspection, model validation, and guarded transition stepping.", "",
        "An unresolved guard is enabled only when the caller supplies a callback that approves it. The callback receives the transition ID and guard text. Declared action text is preserved as metadata; arbitrary action code is not executed.", "",
        "The CLI accepts `[state-id [transition-id]]` and prints a JSON observation. The same model API is available in `python/model.py`. Generated artifacts and model harnesses do not establish application safety."]
    if include_fuzz:
        lines.extend(["", "The optional libFuzzer entry point is in `fuzz/model_fuzz.c`."])
    return "\n".join(lines) + "\n"


def _python_model_source(specification: Specification, model: KripkeStructure) -> tuple[CLine, ...]:
    """Render a standalone Python runtime for the same declared Kripke model."""
    state_rows = [{"id": state.id, "values": dict(state.values), "labels": sorted(state.labels),
                   "initial": state in model.initial_states} for state in model.states]
    transition_rows = [{"id": edge.id, "source": edge.source, "target": edge.target,
                        "guard": edge.guard, "action": edge.action, "label": edge.label,
                        "guard_status": edge.guard_status} for edge in model.transitions]
    lines: list[CLine] = [CLine('"""Generated Python runtime for the canonical finite-state model.'),
        CLine('This is model code, not an implementation of declared application functions.'),
        CLine('"""'), CLine("from __future__ import annotations"), CLine("import json"),
        CLine("import sys"), CLine(""), CLine(f"SPECIFICATION_ID = {specification.id!r}"),
        CLine(f"MODEL_HASH = {model.model_hash!r}"), CLine("STATE_ROWS = (")]
    for row in state_rows:
        payload = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        lines.append(CLine(f"    json.loads({payload!r}),", row["id"], "state"))
    lines.extend((CLine(")"), CLine("TRANSITION_ROWS = (")))
    for row in transition_rows:
        payload = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        lines.append(CLine(f"    json.loads({payload!r}),", row["id"], "transition"))
    function_lines = [
        ")", "INITIAL_STATE_IDS = tuple(row['id'] for row in STATE_ROWS if row['initial'])", "",
        "def validate_model() -> bool:",
        "    if not STATE_ROWS:", "        return not TRANSITION_ROWS",
        "    ids = [row['id'] for row in STATE_ROWS]",
        "    if len(ids) != len(set(ids)) or not INITIAL_STATE_IDS:", "        return False",
        "    known = set(ids)",
        "    edge_ids = [row['id'] for row in TRANSITION_ROWS]",
        "    return len(edge_ids) == len(set(edge_ids)) and all(",
        "        row['source'] in known and row['target'] in known for row in TRANSITION_ROWS)", "",
        "def state_by_id(state_id: str) -> dict:",
        "    for row in STATE_ROWS:", "        if row['id'] == state_id:", "            return row",
        "    raise KeyError(f'unknown state id: {state_id}')", "",
        "def transition_by_id(transition_id: str) -> dict:",
        "    for row in TRANSITION_ROWS:", "        if row['id'] == transition_id:", "            return row",
        "    raise KeyError(f'unknown transition id: {transition_id}')", "",
        "def state_has_label(state_id: str, label: str) -> bool:",
        "    return label in state_by_id(state_id)['labels']", "",
        "def states_with_label(label: str) -> tuple[str, ...]:",
        "    return tuple(row['id'] for row in STATE_ROWS if label in row['labels'])", "",
        "def outgoing_transitions(state_id: str) -> tuple[dict, ...]:",
        "    state_by_id(state_id)",
        "    return tuple(row for row in TRANSITION_ROWS if row['source'] == state_id)", "",
        "def transition_enabled(edge: dict, guard=None) -> bool:",
        "    if edge['guard_status'] == 'UNRESOLVED_VARIABLES':",
        "        return guard is not None and bool(guard(edge['id'], edge['guard']))",
        "    return True", "",
        "def step(state_id: str, transition_id: str, guard=None) -> str:",
        "    edge = transition_by_id(transition_id)",
        "    if edge['source'] != state_id:",
        "        raise ValueError('transition does not leave selected state')",
        "    if not transition_enabled(edge, guard):",
        "        raise PermissionError('transition guard is unresolved or denied')",
        "    return edge['target']", "",
        "def observe(state_id: str | None = None, transition_id: str | None = None, guard=None) -> dict:",
        "    if not STATE_ROWS:",
        "        return {'state_count': 0, 'transition_count': 0}",
        "    if state_id is None:",
        "        if not INITIAL_STATE_IDS:",
        "            raise ValueError('model has no initial state')",
        "        state_id = INITIAL_STATE_IDS[0]",
        "    source = state_by_id(state_id)",
        "    result_id = step(state_id, transition_id, guard) if transition_id is not None else state_id",
        "    return {'input_state_id': state_id, 'is_initial': source['initial'],",
        "            'transition_id': transition_id, 'result_state_id': result_id,",
        "            'outgoing_transition_ids': [row['id'] for row in outgoing_transitions(state_id)]}", "",
        "def main(argv=None) -> int:",
        "    args = list(sys.argv[1:] if argv is None else argv)",
        "    if len(args) > 2:",
        "        print('usage: python model.py [state-id [transition-id]]', file=sys.stderr)",
        "        return 64",
        "    if not validate_model():",
        "        print('invalid generated model', file=sys.stderr)",
        "        return 70",
        "    try:",
        "        print(json.dumps(observe(*(args or [None])), ensure_ascii=False, sort_keys=True))",
        "    except (KeyError, ValueError, PermissionError) as exc:",
        "        print(str(exc), file=sys.stderr)",
        "        return 65",
        "    return 0", "", "if __name__ == '__main__':", "    raise SystemExit(main())", "",
    ]
    lines.extend(CLine(line) for line in function_lines)
    return tuple(lines)


def _model_test_cli() -> str:
    """Fixed generic CLI for validating and querying a generated finite model."""
    return r'''static void print_json_string(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    putchar('"');
    while (*cursor != 0u) {
        switch (*cursor) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*cursor < 0x20u) printf("\\u%04x", (unsigned int)*cursor);
            else putchar((int)*cursor);
        }
        ++cursor;
    }
    putchar('"');
}

int main(int argc, char **argv) {
    int validation = validate_model();
    if (validation != 0) return validation;
    if (argc < 1 || argc > 3) {
        fputs("usage: model-test [state-id [transition-id]]\n", stderr);
        return 64;
    }
    size_t state_count = seclab_state_count();
    size_t transition_count = seclab_transition_count();
    if (state_count == 0u) {
        if (argc != 1) { fputs("empty model accepts no state input\n", stderr); return 65; }
        puts("{\"state_count\":0,\"transition_count\":0}");
        return 0;
    }
    size_t source_index = 0u;
    int has_initial = 0;
    for (size_t i = 0u; i < state_count; ++i) {
        if (seclab_is_initial(i)) { source_index = i; has_initial = 1; break; }
    }
    if (argc >= 2 && !seclab_state_index(argv[1], &source_index)) {
        fputs("unknown state id\n", stderr); return 65;
    }
    if (argc == 1 && !has_initial) {
        fputs("model has no initial state\n", stderr); return 66;
    }
    const seclab_transition_t *selected = NULL;
    size_t selected_index = 0u;
    size_t input_state_index = source_index;
    if (argc == 3) {
        for (size_t i = 0u; i < transition_count; ++i) {
            const seclab_transition_t *candidate = seclab_transition_at(i);
            if (strcmp(candidate->id, argv[2]) == 0) { selected = candidate; selected_index = i; break; }
        }
        if (selected == NULL) { fputs("unknown transition id\n", stderr); return 67; }
        if (selected->source_index != source_index) {
            fputs("transition does not leave selected state\n", stderr); return 68;
        }
        if (!seclab_model_step(&source_index, selected_index, NULL, NULL)) {
            fputs("transition guard is unresolved or denied\n", stderr); return 69;
        }
    }
    size_t result_index = source_index;
    const seclab_state_t *source_state = seclab_state_at(input_state_index);
    const seclab_state_t *result_state = seclab_state_at(result_index);
    fputs("{\"input_state_id\":", stdout);
    print_json_string(source_state->id);
    printf(",\"is_initial\":%s,\"transition_id\":",
           seclab_is_initial(input_state_index) ? "true" : "false");
    if (selected == NULL) fputs("null", stdout); else print_json_string(selected->id);
    fputs(",\"result_state_id\":", stdout);
    print_json_string(result_state->id);
    fputs(",\"outgoing_transition_ids\":[", stdout);
    int first = 1;
    for (size_t i = 0u; i < transition_count; ++i) {
        const seclab_transition_t *edge = seclab_transition_at(i);
        if (edge->source_index != input_state_index) continue;
        if (!first) putchar(',');
        print_json_string(edge->id);
        first = 0;
    }
    puts("]}");
    return 0;
}'''


def _write_tree(root: Path, files: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    resolved_root = root.resolve(strict=True)
    for name, content in sorted(files.items()):
        _safe_write(root, name, content, resolved_root=resolved_root)


def _safe_write(root: Path, name: str, content: str, *, resolved_root: Path | None = None) -> None:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or "\\" in name or not pure.parts:
        raise CGenerationError(f"Unsafe generated filename {name!r}.")
    root.mkdir(parents=True, exist_ok=True)
    resolved_root = resolved_root or root.resolve(strict=True)
    target = root.joinpath(*pure.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or not target.resolve(strict=False).is_relative_to(resolved_root):
        raise CGenerationError(f"Generated path {name!r} escapes output root.")
    payload = content.encode("utf-8")
    if target.exists():
        if not target.is_file() or hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(payload).digest():
            raise CGenerationError(f"Generated path {name!r} already exists with different content.")
        return
    target.write_bytes(payload)
