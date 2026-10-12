"""Merge specification fragments into the canonical Python representation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, TYPE_CHECKING

from .errors import SpecificationError, SpecificationErrorCode
from .loader import LoadedSpecification
if TYPE_CHECKING:
    from .validator import ValidatedSpecification
from .schema import (
    Constraint, Domain, FunctionSpec, PropertySpec, Requirement, Specification,
    StateMachineSpec, StateSpec, TestSpec, TransitionSpec, Variable,
)

_COLLECTIONS = (
    "requirements", "variables", "constraints", "states", "transitions",
    "properties", "functions", "tests", "state_machines",
)


def merge_fragment_data(loaded: LoadedSpecification) -> dict[str, Any]:
    """Merge validated fragment objects, rejecting every repeated definition."""
    if not loaded.documents:
        raise ValueError("At least one loaded specification document is required")

    documents = sorted(loaded.documents, key=lambda item: str(item.source))
    merged: dict[str, Any] = {name: [] for name in _COLLECTIONS}
    definitions: dict[str, dict[str, tuple[dict[str, Any], str]]] = {
        name: {} for name in _COLLECTIONS
    }

    for document in documents:
        data = document.data
        if not isinstance(data, dict):
            # The schema validator normally reports this first. Keep this helper
            # safe when called directly as part of normalization.
            raise SpecificationError(
                SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                "The document root must be a JSON object.",
                source=document.source,
            )
        if "state_machines" in data:
            merged["state_machines"].extend(deepcopy(data["state_machines"]))
            for machine in data["state_machines"]:
                machine_id = machine["id"]
                for state in machine.get("states", ()):
                    state = deepcopy(state)
                    state.setdefault("machine_id", machine_id)
                    _append_definition(merged, definitions, "states", state, document.source)
                for transition in machine.get("transitions", ()):
                    transition = deepcopy(transition)
                    transition.setdefault("machine_id", machine_id)
                    _append_definition(merged, definitions, "transitions", transition, document.source)
        for key in ("schema_version", "id", "name"):
            if key in merged and merged[key] is not None and merged[key] != data.get(key):
                raise SpecificationError(
                    SpecificationErrorCode.CONFLICTING_DEFINITION,
                    f"Fragment value for '{key}' differs from the other specification fragments.",
                    source=document.source,
                    location=key,
                )
            merged[key] = data.get(key)
        for key in ("description", "initial_state", "project", "coverage", "fuzzing"):
            value = data.get(key)
            if value is None or value == {}:
                continue
            if key not in merged or merged[key] in (None, {}):
                merged[key] = deepcopy(value)
            elif isinstance(value, dict) and isinstance(merged[key], dict):
                for child_key, child_value in value.items():
                    if child_key in merged[key] and merged[key][child_key] != child_value:
                        raise SpecificationError(
                            SpecificationErrorCode.CONFLICTING_DEFINITION,
                            f"Fragments provide conflicting values for '{key}.{child_key}'.",
                            source=document.source, location=f"{key}.{child_key}",
                        )
                    merged[key][child_key] = deepcopy(child_value)
            elif merged[key] != value:
                raise SpecificationError(
                    SpecificationErrorCode.CONFLICTING_DEFINITION,
                    f"Fragments provide conflicting values for '{key}'.",
                    source=document.source, location=key,
                )

        metadata = merged.setdefault("metadata", {})
        for key, value in data.get("metadata", {}).items():
            if key in metadata and metadata[key] != value:
                raise SpecificationError(
                    SpecificationErrorCode.CONFLICTING_DEFINITION,
                    f"Fragments provide conflicting metadata value for '{key}'.",
                    source=document.source,
                    location=f"metadata.{key}",
                )
            metadata[key] = deepcopy(value)

        for collection in _COLLECTIONS:
            if collection == "state_machines":
                continue
            for item in data.get(collection, []):
                _append_definition(merged, definitions, collection, item, document.source)

    for collection in _COLLECTIONS:
        merged[collection].sort(key=lambda item: item["id"])
    return merged


def _append_definition(merged: dict[str, Any], definitions: dict[str, Any], collection: str,
                       item: dict[str, Any], source: Any) -> None:
    entity_id = item["id"]
    known = definitions[collection].get(entity_id)
    if known is not None:
        previous, previous_source = known
        if previous != item:
            code = SpecificationErrorCode.CONFLICTING_DEFINITION
            reason = f"Conflicting definitions of {collection[:-1]} '{entity_id}' in {previous_source} and {source}."
        else:
            code = SpecificationErrorCode.DUPLICATE_ID
            reason = f"Duplicate {collection[:-1]} ID '{entity_id}' in {previous_source} and {source}."
        raise SpecificationError(code, reason, source=source, location=f"{collection}[id={entity_id}]")
    definitions[collection][entity_id] = (deepcopy(item), str(source))
    merged[collection].append(deepcopy(item))


def normalize_specification(loaded: LoadedSpecification | "ValidatedSpecification") -> Specification:
    """Convert validated JSON documents to canonical Python records.

    Passing ``ValidatedSpecification`` reuses its validated merge and avoids a
    second schema/semantic validation pass. ``LoadedSpecification`` remains a
    supported compatibility input and is validated here as before.
    """
    from .validator import ValidatedSpecification
    if isinstance(loaded, ValidatedSpecification):
        data = deepcopy(loaded.merged_data)
    else:
        from .validator import validate_specification
        validated = validate_specification(loaded)
        data = deepcopy(validated.merged_data)

    requirements = tuple(Requirement(
        id=item["id"], description=item["description"], type=item.get("type"),
        priority=item.get("priority"), constraint_ids=tuple(item.get("constraint_ids", ())),
        property_ids=tuple(item.get("property_ids", ())),
        function_ids=tuple(item.get("function_ids", ())), test_ids=tuple(item.get("test_ids", ())),
        metadata=deepcopy(item.get("metadata", {})),
    ) for item in data["requirements"])
    variables = tuple(Variable(
        id=item["id"], domain=_domain(item["domain"]), initial=item.get("initial"),
        description=item.get("description"), metadata=deepcopy(item.get("metadata", {})),
    ) for item in data["variables"])
    constraints = tuple(Constraint(
        id=item["id"], expression=item["expression"],
        requirement_ids=tuple(item.get("requirement_ids", ())), kind=item.get("kind"),
        description=item.get("description"), metadata=deepcopy(item.get("metadata", {})),
    ) for item in data["constraints"])
    machines_by_id = {item["id"]: item for item in data["state_machines"]}
    states = tuple(StateSpec(
        id=item["id"], initial=bool(item.get("initial", False) or
            item["id"] == (machines_by_id.get(item.get("machine_id"), {}).get("initial_state")
                           if item.get("machine_id") else data.get("initial_state"))),
        values=deepcopy(item.get("values", {})), labels=tuple(item.get("labels", ())),
        description=item.get("description"), machine_id=item.get("machine_id"),
    ) for item in data["states"])
    transitions = tuple(TransitionSpec(
        id=item["id"], source=item["source"], target=item["target"],
        guard=item.get("guard"), action=item.get("action"), label=item.get("label"),
        machine_id=item.get("machine_id"),
    ) for item in data["transitions"])
    properties = tuple(PropertySpec(
        id=item["id"], logic=item["logic"], formula=item["formula"],
        requirement_ids=tuple(item.get("requirement_ids", ())), description=item.get("description"),
        bound=item.get("bound"), metadata=deepcopy(item.get("metadata", {})),
    ) for item in data["properties"])
    functions = tuple(FunctionSpec(
        id=item["id"], name=item["name"], file=item.get("file"),
        language=item.get("language"),
        requirement_ids=tuple(item.get("requirement_ids", ())), description=item.get("description"),
    ) for item in data["functions"])
    tests = tuple(TestSpec(
        id=item["id"], function_id=item.get("function_id"),
        requirement_ids=tuple(item.get("requirement_ids", ())), kind=item.get("kind"),
        input=deepcopy(item.get("input", {})), expected=deepcopy(item.get("expected")),
        description=item.get("description"),
    ) for item in data["tests"])
    machines = tuple(StateMachineSpec(
        id=item["id"], initial_state=item.get("initial_state"), description=item.get("description"),
        states=tuple(state for state in states if state.machine_id == item["id"]),
        transitions=tuple(edge for edge in transitions if edge.machine_id == item["id"]),
    ) for item in data["state_machines"])

    return Specification(
        schema_version=data["schema_version"], id=data["id"], name=data["name"],
        description=data.get("description"), initial_state=data.get("initial_state"),
        requirements=requirements, variables=variables, constraints=constraints,
        states=states, transitions=transitions, properties=properties,
        functions=functions, tests=tests, metadata=deepcopy(data.get("metadata", {})),
        project=deepcopy(data.get("project", {})), state_machines=machines,
        coverage=deepcopy(data.get("coverage", {})), fuzzing=deepcopy(data.get("fuzzing", {})),
    )


def _domain(raw: dict[str, Any]) -> Domain:
    if "enum" in raw:
        return Domain(values=tuple(raw["enum"]), enum=tuple(raw["enum"]))
    return Domain(type=raw["type"], minimum=raw.get("minimum"), maximum=raw.get("maximum"),
                  values=tuple(raw.get("values", ())))
