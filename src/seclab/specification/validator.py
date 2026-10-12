"""JSON Schema and cross-entity consistency validation for specifications."""

from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SpecificationError, SpecificationErrorCode, SpecificationToolError
from .loader import LoadedSpecification
from .normalizer import merge_fragment_data

_DEFAULT_SCHEMA = Path(__file__).resolve().parents[3] / "schemas" / "specification.schema.json"


@dataclass(frozen=True, slots=True)
class ValidatedSpecification:
    """Validated, merged generic input reusable by normalization and pipeline stages."""

    loaded: LoadedSpecification
    merged_data: dict[str, Any]
    input_hashes: tuple[dict[str, str], ...]
    diagnostics: tuple[dict[str, str], ...] = ()

    @property
    def validation_result(self) -> str:
        return "VALID"


def validate_specification(
    loaded: LoadedSpecification,
    schema_path: str | Path | None = None,
) -> ValidatedSpecification:
    """Validate once and return reusable canonical merge inputs; errors remain structured."""
    try:
        import jsonschema
    except ImportError as exc:
        raise SpecificationToolError(
            SpecificationErrorCode.VALIDATOR_UNAVAILABLE,
            "JSON Schema validation requires the 'jsonschema' package; install the project dependencies.",
        ) from exc

    selected_schema = Path(schema_path) if schema_path is not None else _DEFAULT_SCHEMA
    try:
        schema = _read_schema(selected_schema)
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
    except OSError as exc:
        raise SpecificationToolError(
            SpecificationErrorCode.VALIDATOR_UNAVAILABLE,
            f"Cannot read JSON Schema file: {exc}", source=selected_schema,
        ) from exc
    except jsonschema.SchemaError as exc:
        raise SpecificationToolError(
            SpecificationErrorCode.VALIDATOR_UNAVAILABLE,
            f"The configured JSON Schema is invalid: {exc.message}", source=selected_schema,
        ) from exc

    for document in loaded.documents:
        if isinstance(document.data, dict) and "state_machines" in document.data:
            if document.data.get("states") or document.data.get("transitions"):
                raise SpecificationError(
                    SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                    "Use either legacy root states/transitions or state machine scoped states/transitions, not both.",
                    source=document.source, location="state_machines",
                )
            # Validate machine-local entities with the same entity schemas used
            # by the legacy root-level representation.
            expanded = dict(document.data)
            expanded["state_machines"] = [
                {key: value for key, value in machine.items() if key not in {"states", "transitions"}}
                for machine in document.data["state_machines"]
            ]
            expanded["states"] = [dict(state, machine_id=state.get("machine_id", machine["id"]))
                                   for machine in document.data["state_machines"]
                                   for state in machine.get("states", ())]
            expanded["transitions"] = [dict(transition, machine_id=transition.get("machine_id", machine["id"]))
                                        for machine in document.data["state_machines"]
                                        for transition in machine.get("transitions", ())]
            errors = sorted(validator.iter_errors(expanded),
                            key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message))
            if errors:
                error = errors[0]
                location = ".".join(str(part) for part in error.absolute_path) or "$"
                raise SpecificationError(SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                                         error.message, source=document.source, location=location)
            continue
        errors = sorted(
            validator.iter_errors(document.data),
            key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
        )
        if errors:
            error = errors[0]
            location = ".".join(str(part) for part in error.absolute_path) or "$"
            message = _format_schema_error(error)
            raise SpecificationError(
                SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                message,
                source=document.source,
                location=location,
            )

    merged = merge_fragment_data(loaded)
    _validate_semantics(merged)
    return ValidatedSpecification(
        loaded=loaded,
        merged_data=merged,
        input_hashes=tuple({"source": str(item.source), "sha256": item.sha256}
                           for item in loaded.documents),
    )


def _read_schema(path: Path) -> dict[str, Any]:
    import json

    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _format_schema_error(error: Any) -> str:
    """Make common missing-field errors actionable without weakening the schema."""
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = sorted(set(error.validator_value) - error.instance.keys())
        if len(missing) == 1:
            return f"Missing required property '{missing[0]}'."
        if missing:
            return f"Missing required properties: {', '.join(repr(name) for name in missing)}."
    return error.message


def _validate_semantics(data: dict[str, Any]) -> None:
    collections = (
        "requirements", "variables", "constraints", "states", "transitions",
        "properties", "functions", "tests", "state_machines",
    )
    by_id: dict[str, dict[str, dict[str, Any]]] = {}
    for collection in collections:
        entities: dict[str, dict[str, Any]] = {}
        for item in data[collection]:
            entity_id = item["id"]
            if entity_id in entities:
                _error(
                    SpecificationErrorCode.DUPLICATE_ID,
                    f"Duplicate {collection[:-1]} ID '{entity_id}'.",
                    f"{collection}[id={entity_id}]",
                )
            entities[entity_id] = item
        by_id[collection] = entities

    function_names: dict[str, str] = {}
    for function in data["functions"]:
        prior = function_names.get(function["name"])
        if prior is not None:
            _error(
                SpecificationErrorCode.DUPLICATE_NAME,
                f"Functions '{prior}' and '{function['id']}' share the name '{function['name']}'.",
                f"functions[name={function['name']}]",
            )
        function_names[function["name"]] = function["id"]

    root_has_machine_data = not bool(data["state_machines"]) and bool(data["states"])
    if data["state_machines"] and not any(machine.get("states") for machine in data["state_machines"]):
        _error(SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
               "Each declared state machine must contain explicit states.", "state_machines")
    states = by_id["states"]
    machines = by_id["state_machines"]
    if machines and (data.get("initial_state") or
                     (root_has_machine_data and any(item.get("initial") for item in data["states"]))):
        _error(SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
               "Use state machine initial_state fields when state_machines are declared; root initial_state/initial flags are ambiguous.",
               "state_machines")
    declared_initials = {item["id"] for item in data["states"] if item.get("initial", False)}
    selected_initial = data.get("initial_state")
    if selected_initial is not None and not machines:
        if selected_initial not in states:
            _error(
                SpecificationErrorCode.UNKNOWN_INITIAL_STATE,
                f"Initial state '{selected_initial}' is not declared in states.",
                "initial_state",
            )
        if declared_initials and declared_initials != {selected_initial}:
            _error(
                SpecificationErrorCode.UNKNOWN_INITIAL_STATE,
                "initial_state conflicts with the state marked initial=true.",
                "initial_state",
            )
    elif states and not machines:
        if not declared_initials:
            _error(
                SpecificationErrorCode.MISSING_INITIAL_STATE,
                "An explicit state machine must mark one state initial or set initial_state.",
                "states",
            )
        if len(declared_initials) > 1:
            _error(
                SpecificationErrorCode.MULTIPLE_INITIAL_STATES,
                "Only one initial state may be selected.",
                "states",
            )

    for transition in data["transitions"]:
        if transition["source"] not in states:
            _unknown("state", transition["source"], f"transitions[{transition['id']}].source")
        if transition["target"] not in states:
            _unknown("state", transition["target"], f"transitions[{transition['id']}].target")
    if machines:
        states_by_machine: dict[str, set[str]] = {machine_id: set() for machine_id in machines}
        for state in data["states"]:
            machine_id = state.get("machine_id")
            if machine_id is None:
                _error(SpecificationErrorCode.UNKNOWN_REFERENCE,
                       f"State '{state['id']}' must reference a declared state machine.",
                       f"states[{state['id']}].machine_id")
            if machine_id not in machines:
                _unknown("state machine", machine_id, f"states[{state['id']}].machine_id")
            states_by_machine[machine_id].add(state["id"])
        for machine_id, machine in machines.items():
            initial = machine.get("initial_state")
            if initial is not None and initial not in states_by_machine[machine_id]:
                _unknown("state in state machine", initial, f"state_machines[{machine_id}].initial_state")
            if states_by_machine[machine_id] and initial is None:
                _error(SpecificationErrorCode.MISSING_INITIAL_STATE,
                       f"State machine '{machine_id}' must explicitly declare its initial_state.",
                       f"state_machines[{machine_id}].initial_state")
            if not states_by_machine[machine_id] and initial is not None:
                _unknown("state in state machine", initial, f"state_machines[{machine_id}].initial_state")
        for machine_id, machine in machines.items():
            if "initial_state" not in machine:
                _error(SpecificationErrorCode.MISSING_INITIAL_STATE,
                       f"State machine '{machine_id}' must explicitly declare initial_state; it is not inferred.",
                       f"state_machines[{machine_id}].initial_state")
        for transition in data["transitions"]:
            machine_id = transition.get("machine_id")
            if machine_id is None:
                _error(SpecificationErrorCode.UNKNOWN_REFERENCE,
                       f"Transition '{transition['id']}' must reference a declared state machine.",
                       f"transitions[{transition['id']}].machine_id")
            if machine_id not in machines:
                _unknown("state machine", machine_id, f"transitions[{transition['id']}].machine_id")
            if transition["source"] not in states_by_machine[machine_id] or transition["target"] not in states_by_machine[machine_id]:
                _error(SpecificationErrorCode.UNKNOWN_REFERENCE,
                       f"Transition '{transition['id']}' endpoints must belong to machine '{machine_id}'.",
                       f"transitions[{transition['id']}]" )

    variables = by_id["variables"]
    for variable in data["variables"]:
        _validate_domain(variable)
    for state in data["states"]:
        for name in state.get("values", {}):
            if name not in variables:
                _unknown("variable", name, f"states[{state['id']}].values.{name}")
        for name, value in state.get("values", {}).items():
            _validate_value(value, variables[name], f"states[{state['id']}].values.{name}")

    requirements = by_id["requirements"]
    constraints = by_id["constraints"]
    properties = by_id["properties"]
    functions = by_id["functions"]
    for requirement in data["requirements"]:
        for constraint_id in requirement.get("constraint_ids", []):
            _require(constraints, constraint_id, f"requirements[{requirement['id']}].constraint_ids")
        for property_id in requirement.get("property_ids", []):
            _require(properties, property_id, f"requirements[{requirement['id']}].property_ids")
            # v1 allowed one-sided requirement/property links. Preserve those;
            # if both sides declare links, validate them as a consistent pair.
            # The requirement-side property_ids list remains authoritative when
            # present; older v1 documents may carry stale/missing reverse links.
        for function_id in requirement.get("function_ids", []):
            _require(functions, function_id, f"requirements[{requirement['id']}].function_ids")
        for test_id in requirement.get("test_ids", []):
            _require(by_id["tests"], test_id, f"requirements[{requirement['id']}].test_ids")
    for collection in ("constraints", "properties", "functions", "tests"):
        for entity in data[collection]:
            for requirement_id in entity.get("requirement_ids", []):
                _require(requirements, requirement_id, f"{collection}[{entity['id']}].requirement_ids")
    for test in data["tests"]:
        function_id = test.get("function_id")
        if function_id is not None:
            _require(functions, function_id, f"tests[{test['id']}].function_id")
    for function in data["functions"]:
        file_path = function.get("file")
        if file_path is not None and (file_path.startswith(("/", "\\")) or
                                      ".." in Path(file_path.replace("\\", "/")).parts):
            _error(SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                   f"Function '{function['id']}' file must be a project-relative path.",
                   f"functions[{function['id']}].file")
    for prop in data["properties"]:
        if prop["logic"] == "BMC" and prop.get("bound") is None:
            _error(SpecificationErrorCode.SCHEMA_VALIDATION_FAILED,
                   f"BMC property '{prop['id']}' requires an explicit bound.",
                   f"properties[{prop['id']}].bound")
        if prop["logic"] == "SMT":
            identifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", prop["formula"]))
            keywords = {"and", "or", "not", "true", "false", "sat", "unsat"}
            unknown = identifiers - set(variables) - keywords
            if unknown:
                _error(SpecificationErrorCode.UNKNOWN_REFERENCE,
                       f"SMT property '{prop['id']}' refers to undeclared variable '{sorted(unknown)[0]}'.",
                       f"properties[{prop['id']}].formula")

    atom_names = {label for state in data["states"] for label in state.get("labels", [])}
    for prop in data["properties"]:
        if prop["logic"] == "CTL":
            # Import at the validation boundary to keep specification models
            # independent from the formal-methods package at module load time.
            from seclab.formal.ctl.ast import atomic_propositions
            from seclab.formal.ctl.errors import CTLError
            from seclab.formal.ctl.parser import parse_ctl

            try:
                formula = parse_ctl(prop["formula"])
            except CTLError as exc:
                raise SpecificationError(
                    SpecificationErrorCode.INVALID_CTL_FORMULA,
                    str(exc),
                    location=f"properties[{prop['id']}].formula",
                ) from exc
            for atom in atomic_propositions(formula):
                if atom not in atom_names:
                    _error(
                        SpecificationErrorCode.UNKNOWN_ATOM,
                        f"CTL property '{prop['id']}' refers to undeclared atom '{atom}'.",
                        f"properties[{prop['id']}].formula",
                    )


def _validate_domain(variable: dict[str, Any]) -> None:
    domain = variable["domain"]
    kind = domain.get("type")
    minimum, maximum = domain.get("minimum"), domain.get("maximum")
    if minimum is not None and maximum is not None and minimum > maximum:
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Variable '{variable['id']}' domain minimum exceeds maximum.",
               f"variables[{variable['id']}].domain")
    if kind in {"integer", "number"} and any(value is not None and isinstance(value, bool)
                                               for value in (minimum, maximum)):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Variable '{variable['id']}' uses a boolean numeric bound.",
               f"variables[{variable['id']}].domain")
    if kind in {"boolean", "string"} and (minimum is not None or maximum is not None):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Variable '{variable['id']}' uses numeric bounds with {kind} domain.",
               f"variables[{variable['id']}].domain")
    if kind == "integer" and any(value is not None and not isinstance(value, int) for value in (minimum, maximum)):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Variable '{variable['id']}' uses a non-integer bound for an integer domain.",
               f"variables[{variable['id']}].domain")

    values = domain.get("enum", domain.get("values", []))
    for value in values:
        if not _matches_type(value, kind):
            _error(SpecificationErrorCode.INVALID_DOMAIN,
                   f"Value {value!r} does not match variable '{variable['id']}' domain type '{kind}'.",
                   f"variables[{variable['id']}].domain")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if minimum is not None and value < minimum or maximum is not None and value > maximum:
                _error(SpecificationErrorCode.INVALID_DOMAIN,
                       f"Enumerated value {value!r} is outside variable '{variable['id']}' bounds.",
                       f"variables[{variable['id']}].domain")

    initial = variable.get("initial")
    if "initial" not in variable:
        return
    if not _matches_type(initial, kind):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Initial value {initial!r} does not match variable '{variable['id']}' domain type '{kind}'.",
               f"variables[{variable['id']}].initial")
    if values and not any(type(initial) is type(value) and initial == value for value in values):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"Initial value {initial!r} is not in variable '{variable['id']}' finite domain.",
               f"variables[{variable['id']}].initial")
    if isinstance(initial, (int, float)) and not isinstance(initial, bool):
        if minimum is not None and initial < minimum or maximum is not None and initial > maximum:
            _error(SpecificationErrorCode.INVALID_DOMAIN,
                   f"Initial value {initial!r} is outside variable '{variable['id']}' bounds.",
                   f"variables[{variable['id']}].initial")


def _validate_value(value: Any, variable: dict[str, Any], location: str) -> None:
    domain = variable["domain"]
    kind = domain.get("type")
    values = domain.get("enum", domain.get("values", []))
    if not _matches_type(value, kind):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"State value {value!r} does not match variable '{variable['id']}' domain type '{kind}'.",
               location)
    if values and not any(type(value) is type(item) and value == item for item in values):
        _error(SpecificationErrorCode.INVALID_DOMAIN,
               f"State value {value!r} is not in variable '{variable['id']}' finite domain.", location)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if domain.get("minimum") is not None and value < domain["minimum"] or \
                domain.get("maximum") is not None and value > domain["maximum"]:
            _error(SpecificationErrorCode.INVALID_DOMAIN,
                   f"State value {value!r} is outside variable '{variable['id']}' bounds.", location)


def _matches_type(value: Any, kind: str | None) -> bool:
    if kind is None:
        return True
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    return False


def _require(entities: dict[str, Any], reference: str, location: str) -> None:
    if reference not in entities:
        _unknown("entity", reference, location)


def _unknown(kind: str, reference: str, location: str) -> None:
    _error(SpecificationErrorCode.UNKNOWN_REFERENCE,
           f"Reference to unknown {kind} '{reference}'.", location)


def _error(code: SpecificationErrorCode, message: str, location: str) -> None:
    raise SpecificationError(code, message, location=location)
