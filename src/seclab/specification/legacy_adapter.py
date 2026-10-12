"""Deterministic migration for the legacy teacher specification format.

The source document remains untouched. Unsupported narrative-only test and
probe declarations are retained as provenance instead of being presented as
executable production code.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .errors import SpecificationError, SpecificationErrorCode
from .loader import LoadedSpecification, SourceDocument, load_specification
from .validator import _DEFAULT_SCHEMA


def is_legacy_teacher_specification(raw: Any) -> bool:
    """Recognize the legacy structure by content, independently of its filename."""
    return (isinstance(raw, Mapping)
            and "schema_version" not in raw
            and isinstance(raw.get("state_machine"), Mapping)
            and isinstance(raw.get("requirements"), list))


def adapt_legacy_specification(raw_spec: Mapping[str, Any], source_path: str | Path,
                               raw_bytes: bytes | None = None) -> LoadedSpecification:
    """Translate a recognized legacy teacher document to canonical JSON in memory.

    The original bytes remain untouched and their SHA-256 stays on the source
    document record. Uninterpretable declarations are retained verbatim in
    provenance; they never become executable tests or observations.
    """
    source = Path(source_path).expanduser().resolve()
    raw = raw_spec
    if not is_legacy_teacher_specification(raw):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "The JSON does not match the supported legacy teacher specification structure.",
            source=source, location="$")
    machine = raw.get("state_machine")
    required_machine_fields = ("states", "initial", "transitions")
    missing_machine = [field for field in required_machine_fields if field not in machine]
    if missing_machine:
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            f"Legacy migration requires state_machine field(s): {', '.join(missing_machine)}.",
            source=source, location="state_machine." + missing_machine[0])
    for field in required_machine_fields:
        if not isinstance(machine[field], list):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                f"Expected an array at state_machine.{field}.", source=source,
                location=f"state_machine.{field}")
    if any(not isinstance(item, str) for item in machine["states"]):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Legacy state IDs must be strings.", source=source, location="state_machine.states")
    if any(not isinstance(item, str) for item in machine["initial"]):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Legacy initial state IDs must be strings.", source=source, location="state_machine.initial")
    if len(machine["initial"]) != 1 or machine["initial"][0] not in machine["states"]:
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Legacy state_machine must identify exactly one initial state declared in states.",
            source=source, location="state_machine.initial")
    if not isinstance(machine.get("labeling", {}), Mapping):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Expected an object at state_machine.labeling.", source=source,
            location="state_machine.labeling")
    if not isinstance(raw.get("safety_properties", []), list):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Expected an array at safety_properties.", source=source, location="safety_properties")
    if any(not isinstance(item, str) for item in raw.get("safety_properties", [])):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Each legacy safety property must be a formula string.", source=source,
            location="safety_properties")
    for collection in ("arithmetic_checks", "functions", "test_cases"):
        if not isinstance(raw.get(collection, []), list):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                f"Expected an array at {collection}.", source=source, location=collection)
    if raw.get("name") is not None and not isinstance(raw["name"], str):
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "Legacy specification name must be a string.", source=source, location="name")
    for index, edge in enumerate(machine["transitions"]):
        if not isinstance(edge, (list, tuple)) or len(edge) != 2 or not all(isinstance(node, str) for node in edge):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                "Each legacy transition must be a two-item [source, target] array.", source=source,
                location=f"state_machine.transitions[{index}]")
    for index, requirement in enumerate(raw["requirements"]):
        if not isinstance(requirement, Mapping) or not isinstance(requirement.get("id"), str):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                "Each legacy requirement must be an object with a string id.", source=source,
                location=f"requirements[{index}].id")
    for index, function in enumerate(raw.get("functions", [])):
        if not isinstance(function, Mapping) or not isinstance(function.get("name"), str):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                "Each legacy function declaration must have a string name; no body will be inferred.",
                source=source, location=f"functions[{index}].name")
    for index, check in enumerate(raw.get("arithmetic_checks", [])):
        if not isinstance(check, Mapping) or not isinstance(check.get("name"), str) \
                or not isinstance(check.get("condition"), str):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                "Each arithmetic check requires string name and condition fields.", source=source,
                location=f"arithmetic_checks[{index}]")
    for index, test_case in enumerate(raw.get("test_cases", [])):
        if not isinstance(test_case, Mapping):
            raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
                "Each narrative test case must be an object; prose is retained, not executed.",
                source=source, location=f"test_cases[{index}]")
    raw_bytes = raw_bytes if raw_bytes is not None else source.read_bytes()
    name_value = raw.get("name") or source.stem or hashlib.sha256(raw_bytes).hexdigest()[:16]
    name = str(name_value)
    id_source = raw.get("id") or name_value or source.stem or hashlib.sha256(raw_bytes).hexdigest()
    normalized_id = _identifier_fragment(str(id_source))
    try:
        schema_data = json.loads(_DEFAULT_SCHEMA.read_text(encoding="utf-8"))
        versions = schema_data["properties"]["schema_version"]["enum"]
        schema_version = sorted(versions, key=lambda item: tuple(int(part) for part in item.split(".")))[0]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            f"Cannot derive canonical schema version from the project Specification schema: {exc}",
            source=source, location="schema_version") from exc
    machine = raw.get("state_machine") or {}
    states = list(machine.get("states") or ())
    initial = list(machine.get("initial") or ())
    labeling = machine.get("labeling") or {}
    state_rows = [
        {"id": state, "initial": state in initial, "labels": list(labeling.get(state, ())) }
        for state in states
    ]
    transitions = [
        {"id": f"T-{index:03d}", "source": pair[0], "target": pair[1]}
        for index, pair in enumerate(machine.get("transitions") or (), start=1)
    ]

    requirements = []
    for item in raw.get("requirements") or ():
        requirement = {
            "id": item["id"],
            "description": item.get("text", item.get("description", item["id"])),
            "property_ids": [],
        }
        category = item.get("category")
        if category is not None:
            requirement["type"] = category
        priority = item.get("priority")
        if priority is not None:
            requirement["priority"] = priority
        requirements.append(requirement)
    requirement_ids = {item["id"] for item in requirements}

    properties = []
    for index, formula in enumerate(raw.get("safety_properties") or (), start=1):
        linked_requirements = _requirement_ids_for_ctl(formula, requirement_ids)
        property_id = f"CTL-P-{index:02d}"
        properties.append({
            "id": property_id,
            "logic": "CTL",
            "formula": formula,
            "requirement_ids": linked_requirements,
            "description": "Adapted from safety_properties in the unchanged teacher document.",
            "metadata": {"teacher_formula_index": index, "teacher_formula": formula},
        })
        for req in requirements:
            if req["id"] in linked_requirements:
                req["property_ids"].append(property_id)

    expected_outcomes, check_requirements = _arithmetic_expectations(
        raw.get("test_cases") or (), {str(check["name"]) for check in raw.get("arithmetic_checks") or ()})
    check_rows = []
    variables: dict[str, dict[str, Any]] = {}
    for check in raw.get("arithmetic_checks") or ():
        check_id = str(check["name"])
        for variable in check.get("int_vars", ()):
            variables.setdefault(variable, {"id": variable, "domain": {"type": "integer"}})
        check_req_ids = list(check_requirements.get(check_id, ()))
        property_id = f"SMT-{check_id}"
        formula = _teacher_expression(check["condition"])
        properties.append({
            "id": property_id,
            "logic": "SMT",
            "formula": formula,
            "requirement_ids": check_req_ids,
            "description": f"Teacher arithmetic satisfiability check: {check_id}.",
            "metadata": {
                "satisfiability_check": {
                    "check_id": check_id,
                    "expected_solver_outcome": expected_outcomes.get(check_id),
                    "teacher_check": deepcopy(check),
                    "bounded_expression": check.get("overflow_expr"),
                    "bounded_expected_outcome": "UNSAT" if check.get("overflow_expr") else None,
                    "bounded_query_kind": "signed_int32_overflow",
                },
                "check_id": check_id,
                "teacher_check": deepcopy(check),
                "expected_solver_outcome": expected_outcomes.get(check_id),
                "query_intent": "SATISFIABILITY",
            },
        })
        check_rows.append({
            **deepcopy(check),
            "property_id": property_id,
            "expression": formula,
            "requirement_ids": check_req_ids,
            "expected_solver_outcome": expected_outcomes.get(check_id),
            "overflow_expected_solver_outcome": "UNSAT" if check.get("overflow_expr") else None,
        })
        for req in requirements:
            if req["id"] in check_req_ids and property_id not in req["property_ids"]:
                req["property_ids"].append(property_id)

    function_rows = []
    function_categories = {}
    source_generation_functions = []
    for function in raw.get("functions") or ():
        function_id = "FN-" + _identifier_fragment(function["name"])
        bug = function.get("bug")
        function_rows.append({
            "id": function_id,
            "name": function["name"],
            **({"file": function["file"]} if function.get("file") else {}),
            **({"language": str(function["language"]).casefold()} if function.get("language") else {}),
            **({"requirement_ids": list(function["requirement_ids"])} if function.get("requirement_ids") else {}),
            "description": "Teacher-declared capability probe; no source file is referenced by the JSON.",
        })
        function_categories[function_id] = {
            "name": function["name"],
            "bug": bug,
            "artifact_class": "BUG_INJECTED_PROBE" if bug else "TOOL_CAPABILITY_EVIDENCE",
            "usage": "PROBE_ONLY",
            "production_source": False,
            "source_reference": None,
        }
        # Preserve only declared, structured generation inputs in a generic
        # internal projection. The JSON contract remains unchanged and no body
        # or source location is invented by the adapter.
        source_generation_functions.append({
            "function_id": function_id,
            "name": function["name"],
            "language": function.get("language"),
            "kind": function.get("kind"),
            "parameters": deepcopy(function.get("params", ())),
            "requirement_ids": list(function.get("requirement_ids", ())),
            "source_location": deepcopy(function.get("source_location")),
            "probe_class": function_categories[function_id]["artifact_class"],
            "production_source": False,
            **{key: deepcopy(function[key]) for key in (
                "buffer_size", "allocation_count", "bug", "operation", "magic_values",
                "exception_message", "cwe_ids") if key in function},
        })

    narrative_targets = []
    for test in raw.get("test_cases") or ():
        test_id = str(test.get("id", ""))
        chapter_match = re.search(r"CH([1-6])", test_id, flags=re.IGNORECASE)
        stage_id = ({"1": "CTL", "2": "STATIC", "3": "SMT", "4": "FUZZING"}.get(chapter_match.group(1))
                    if chapter_match else "REPORT")
        narrative_targets.append({
            "target_id": test_id,
            "requirement_ids": list(test.get("requirement_ids") or ()),
            "stage_id": stage_id,
            "target_kind": "NARRATIVE_TEST_CASE",
            "status": "NOT_APPLICABLE",
            "reason": "The JSON provides prose preconditions/steps/expected text, not executable inputs and an oracle.",
        })

    teacher_metadata = {
        "format": "legacy_teacher_state_machine",
        "original_document_id": raw.get("id"),
        "normalized_specification_id": normalized_id,
        "normalized_id_generated": not bool(raw.get("id")),
        "normalized_id_generation": "sanitized legacy name" if not raw.get("id") else None,
        "normalized_schema_version": schema_version,
        "schema_version_generated": True,
        "schema_version_generation": "adapter target contract",
        "source_path": str(source.resolve()),
        "source_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "original_root_keys": list(raw),
        "original_document": deepcopy(dict(raw)),
        "state_machine_declared_counts": {
            "states": len(states), "transitions": len(transitions),
        },
        "arithmetic_checks": check_rows,
        "function_classification": function_categories,
        "source_generation": {"format_version": 1,
            "source_document_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "functions": source_generation_functions},
        "narrative_test_cases": deepcopy(raw.get("test_cases") or []),
        "unexecutable_targets": narrative_targets,
        "unmapped_fields": {
            "additional_flows": deepcopy(raw.get("additional_flows")),
            "flows": deepcopy(raw.get("flows")),
            "mutual_exclusion": deepcopy(raw.get("mutual_exclusion")),
            "root_states_duplicate_view": deepcopy(raw.get("states")),
            "root_transitions_duplicate_view": deepcopy(raw.get("transitions")),
            "root_initial_duplicate_view": deepcopy(raw.get("initial")),
            "root_labeling_duplicate_view": deepcopy(raw.get("labeling")),
            "source_code_references": [],
            "additional_legacy_fields": {
                key: deepcopy(value) for key, value in raw.items()
                if key not in {"name", "id", "schema_version", "description", "requirements",
                    "state_machine", "states", "transitions", "initial", "labeling",
                    "safety_properties", "arithmetic_checks", "functions", "test_cases",
                    "additional_flows", "flows", "mutual_exclusion"}
            },
        },
        "execution_contract": {
            "narrative_test_cases_executable": False,
            "declared_function_bodies_present": False,
            "fuzzing_targets_executable": False,
        },
    }
    canonical = {
        "schema_version": schema_version,
        "id": normalized_id,
        "name": name,
        "description": raw.get("description", "Adapted legacy teacher specification."),
        "requirements": requirements,
        "variables": sorted(variables.values(), key=lambda item: item["id"]),
        "states": state_rows,
        "transitions": transitions,
        "properties": properties,
        "functions": function_rows,
        "tests": [],
        "metadata": {"external_format": "legacy_teacher_state_machine",
                     "source_provenance": teacher_metadata},
    }
    if len(initial) == 1:
        canonical["initial_state"] = initial[0]
    return LoadedSpecification((SourceDocument(source, canonical,
        hashlib.sha256(raw_bytes).hexdigest()),))


def load_compatible_specification(paths: str | Path | list[str | Path] | tuple[str | Path, ...]):
    """Load native or recognized legacy JSON and return documents plus provenance.

    Legacy migration is deliberately single-document. Mixing legacy source with
    canonical fragments is rejected instead of applying ambiguous merge rules.
    """
    path_list = [paths] if isinstance(paths, (str, Path)) else list(paths)
    if not path_list:
        raise ValueError("At least one specification path must be provided")
    loaded_raw = load_specification(path_list)
    legacy_documents = [doc for doc in loaded_raw.documents if is_legacy_teacher_specification(doc.data)]
    if not legacy_documents:
        return loaded_raw, {"format": "generic", "adapter": None}, tuple(
            doc.data for doc in loaded_raw.documents)
    if len(loaded_raw.documents) != 1:
        first = legacy_documents[0]
        raise SpecificationError(SpecificationErrorCode.LEGACY_MIGRATION_FAILED,
            "A legacy teacher document cannot be merged with canonical specification fragments. Select one legacy document or migrate fragments explicitly.",
            source=first.source, location="$")
    document = legacy_documents[0]
    raw_bytes = document.source.read_bytes()
    migrated = adapt_legacy_specification(document.data, document.source, raw_bytes)
    from .validator import _DEFAULT_SCHEMA
    canonical_hash = hashlib.sha256(json.dumps(migrated.documents[0].data, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
    return migrated, {
        "format": "Legacy teacher specification",
        "adapter": "Legacy Specification Adapter",
        "source_path": str(document.source),
        "original_sha256": document.sha256,
        "canonical_sha256": canonical_hash,
        "schema_version": migrated.documents[0].data["schema_version"],
        "schema_path": str(_DEFAULT_SCHEMA),
        "normalization_status": "IN_MEMORY",
    }, tuple(doc.data for doc in loaded_raw.documents)


def _teacher_expression(expression: str) -> str:
    return re.sub(r"\bor\b", "||", re.sub(r"\band\b", "&&", expression, flags=re.IGNORECASE), flags=re.IGNORECASE)


def _identifier_fragment(value: str) -> str:
    fragment = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-.")
    return fragment if fragment and fragment[0].isalpha() else f"F-{fragment}"


def _requirement_ids_for_ctl(formula: str, available: set[str]) -> list[str]:
    match = re.search(r"req_([a-z0-9_]+)_violation", formula, flags=re.IGNORECASE)
    if not match:
        return []
    slug = match.group(1).replace("_", "-").upper()
    candidate = f"REQ-{slug}"
    return [candidate] if candidate in available else []


def _arithmetic_expectations(test_cases: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
                             check_names: set[str]) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    outcomes: dict[str, str] = {}
    requirements: dict[str, tuple[str, ...]] = {}
    patterns = {name: re.compile(r"\b" + re.escape(name) +
        r"\s*:[^\n]*?->\s*(SAT|UNSAT)\b", flags=re.IGNORECASE) for name in check_names}
    for test in test_cases:
        req_ids = tuple(str(item) for item in test.get("requirement_ids", ()))
        for step in test.get("steps", ()):
            for check_id, pattern in patterns.items():
                match = pattern.search(str(step))
                if match:
                    outcomes[check_id] = match.group(1).upper()
                    requirements[check_id] = req_ids
    return outcomes, requirements
