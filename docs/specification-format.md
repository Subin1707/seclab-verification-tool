# Specification input contract (v1)

The authoritative JSON contract is [`schemas/specification.schema.json`](../schemas/specification.schema.json).
`src/seclab/specification/schema.py` is its Python data model. JSON Schema checks
shape and primitive types; semantic checks such as duplicate IDs, unresolved
references, domain bounds, initial states and unknown CTL atoms belong to the
validator. A malformed specification is a specification error, not a failed
verification result.

## Required and optional fields

| Object | Required fields | Optional fields |
| --- | --- | --- |
| Specification | `schema_version` (`"1.0"`), `id`, `name` | `description`, `initial_state`, all collections, `metadata` |
| Requirement | `id`, `description` | `type`, `priority`, `constraint_ids`, `property_ids`, `metadata` |
| Variable | `id`, `domain` | `initial`, `description`, `metadata` |
| Constraint | `id`, `expression` | `requirement_ids`, `kind`, `description`, `metadata` |
| State | `id` | `initial`, `values`, `labels`, `description` |
| Transition | `id`, `source`, `target` | `guard`, `action`, `label` |
| Property | `id`, `logic`, `formula` | `requirement_ids`, `description`, `bound` (required when `logic` is `BMC`), `metadata` |
| Function | `id`, `name` | `file`, `requirement_ids`, `description` |
| Test | `id` | `function_id`, `requirement_ids`, `kind`, `input`, `expected`, `description` |

All IDs use letters, digits, `_`, `.`, `:`, or `-`, and start with a letter.
Variables use a typed domain (`boolean`, `integer`, `number`, or `string`),
optionally bounded by `minimum`/`maximum` or enumerated with `values`; an
explicit `{ "enum": [...] }` domain is also supported (both finite forms map to
`Domain.values` internally). Collections default to empty during normalization.
`initial` on a variable is a scalar initial value;
`initial: true` on a state marks an initial state. The optional root
`initial_state` names that same state; when both forms are supplied they must
agree. An explicit state machine must identify exactly one initial state by one
of these forms. Expressions and formulas are
strings interpreted by their relevant later-stage parser, not evaluated while
loading JSON.

## Chapter and pipeline mapping

The source project describes chapters by technical area rather than providing
an authoritative chapter-to-field matrix. This contract therefore records the
stable implementation mapping by pipeline responsibility; final Chapter 1–4
labels should follow the course report:

| Input fields | Internal model | Pipeline consumers |
| --- | --- | --- |
| `states`, `transitions`, variable `domain`/`initial` | `StateSpec`, `TransitionSpec`, `Variable`, `Domain` | State generation, Kripke model, reachability and CTL |
| `constraints` | `Constraint` | Specification validation, SMT encoding and bounded checking |
| `properties` | `PropertySpec` | CTL/SMT/BMC validation and checking |
| `functions` | `FunctionSpec` | Source mapping, static analysis and call graph |
| `tests` | `TestSpec` | Test generation/execution and fuzzing seeds |
| `requirements` and each `requirement_ids` link | `Requirement` and references | Traceability from requirement through result to evidence |

Function declarations may include an optional `language` string for source
traceability. It identifies the declared implementation language; it does not
provide parameter types, function behavior, or an executable body contract.

No field hard-codes Smart EV names or values. The aggregate document is the
canonical representation. The loader reads fragments without merging them;
the validator and normalizer apply the cross-file rules below.

Each split fragment is still a v1 specification object and must repeat the same
`schema_version`, `id`, and `name`. Optional root `description` and
`initial_state` values, and overlapping metadata keys, must agree. Distinct
metadata keys are combined. Entity arrays are merged by collection; repeated
IDs are errors even if the definitions are identical (`DUPLICATE_ID`), and
different definitions under one ID report `CONFLICTING_DEFINITION`. The
normalizer sorts each entity collection by ID, so input file and array order do
not change its output.

## Error classification

Invalid input errors use the `SPEC_ERROR` category. Reason codes include
`FILE_NOT_FOUND`, `FILE_READ_ERROR`, `INVALID_JSON`,
`SCHEMA_VALIDATION_FAILED`, `INVALID_DOMAIN`, `DUPLICATE_ID`, `DUPLICATE_NAME`,
`UNKNOWN_REFERENCE`, `UNKNOWN_INITIAL_STATE`, `MISSING_INITIAL_STATE`,
`MULTIPLE_INITIAL_STATES`, `UNKNOWN_ATOM`, `INVALID_CTL_FORMULA`, and `CONFLICTING_DEFINITION`. A
missing or unusable JSON Schema validator is `TOOL_ERROR` with reason
`VALIDATOR_UNAVAILABLE`. Neither category means the SUT failed verification.

## Minimal example

```json
{
  "schema_version": "1.0",
  "id": "bounded-counter",
  "name": "Bounded counter",
  "requirements": [
    { "id": "REQ-COUNTER-01", "type": "safety", "priority": "HIGH",
      "description": "The counter remains within its declared range.",
      "property_ids": ["PROP-COUNTER-01"] }
  ],
  "variables": [
    { "id": "count", "domain": { "type": "integer", "minimum": 0, "maximum": 100 }, "initial": 0 }
  ],
  "states": [
    { "id": "READY", "initial": true, "labels": ["within_range"] }
  ],
  "properties": [
    { "id": "PROP-COUNTER-01", "logic": "CTL", "formula": "AG(within_range)",
      "requirement_ids": ["REQ-COUNTER-01"] }
  ]
}
```

The formula's atoms must be explicit state labels; variable names do not
automatically become atomic propositions. JSON and CTL syntax validation do not
prove the property.

Recognized legacy teacher documents can be migrated in memory through the
content-based adapter described in [`specification-migration.md`](specification-migration.md).
Native v1/v2 schema validation remains unchanged; migration output must pass
that same schema and semantic validation before it enters a pipeline.
# Specification contract v2 (additive to v1)

The canonical JSON Schema accepts `schema_version` `1.0` and `2.0`. Existing v1
root collections and the singular `initial_state` remain valid. V2 adds optional
generic `project`, `state_machines`, `coverage`, and `fuzzing` fields. A named
state machine owns explicit `states` and `transitions` and must declare its
`initial_state`; the normalizer also exposes these entities through the existing
root `Specification.states` and `Specification.transitions` collections for
current model consumers. V2 does not infer a language, source path, initial state,
test oracle, coverage backend, or fuzz strategy.

`project` can describe project kind, languages, project-relative source roots, and
an extensible build mapping. Requirements may link to constraints, properties,
functions, and tests through IDs. References must resolve; older one-sided v1
requirement/property links remain accepted. Domain values in states and initial
variable values are checked against declared type, finite values, and bounds.
SMT properties must reference declared variables, but their formulas are not
solved during specification validation.

Coverage and fuzzing fields describe configuration only. They do not add runner
behavior or verdicts. Specification validation and normalization produce no
project-level PASS/FAIL.

