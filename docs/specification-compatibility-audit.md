# Specification compatibility audit

Audit date: 2026-10-07. This is a read-only contract and data-shape audit made
before the legacy adapter changes.

## Current canonical contract

The authoritative schema is `schemas/specification.schema.json`; the Python
data contract is `src/seclab/specification/schema.py`. Canonical documents
require `schema_version` (`1.0` or `2.0`), `id`, and `name`. V1 supports
requirements, variables, constraints, root states/transitions, CTL/SMT/BMC
properties, functions, tests, and extensible `metadata`. V2 adds generic
`project`, `state_machines`, `coverage`, and `fuzzing`. Schema validation checks
shape/types; semantic validation checks IDs, references, state-machine
initialization, domains, and supported property consistency. Normalization
creates deterministic typed `Specification` values. No contract change is
proposed by this audit.

## Observed legacy teacher document

The configured file `E:/smart-ev-charging-safety/teacher_specs/smart_ev_teacher_e2e_v4.json`
is readable in this environment. It has no `schema_version` or `id`; its
`name` is `smart_ev_teacher_e2e_v4`. It contains 11 requirements, a nested
`state_machine` with 28 states, 47 transitions and one initial state, a
smaller duplicate root state/edge view (10/19), 16 `safety_properties`, 12
arithmetic checks, 9 function/probe declarations, and 9 narrative test cases.
Additional root fields include `description`, `labeling`, `initial`, `flows`,
`additional_flows`, and `mutual_exclusion`.

## Mapping and preservation

| Legacy data | Canonical destination | Rule / limitation |
| --- | --- | --- |
| `name` | `name`, deterministic `id` fallback | Normalize to contract ID characters; retain original name and ID inputs in provenance. |
| missing `schema_version` | Canonical contract version | Derive from the schema's declared supported versions; do not weaken validation. |
| `requirements` | `Requirement` records | Map declared IDs/text/category/priority; reject malformed rows rather than dropping them. |
| nested `state_machine` | root `states`, `transitions`, `initial_state` | Prefer the full nested graph over duplicate root summary; preserve both raw forms and counts. |
| `safety_properties` | CTL `PropertySpec` | Preserve each formula exactly; map requirement links only when the explicit formula convention yields an existing requirement ID. |
| `arithmetic_checks` | SMT properties/metadata | Translate only known Boolean spelling (`and`/`or`) into the supported expression operators; keep original check and expected solver annotation as teacher provenance, not actual observation. |
| `functions` | function declarations + metadata | Declarations have no source file/body; cannot generate faithful executable function bodies from these names. Mark as probe declarations with no source binding. |
| `test_cases` | provenance metadata/unexecutable targets | Narrative prose lacks executable input/oracle structure; do not turn prose expectations into observations. |
| bugs/vulnerabilities, flows, mutual exclusion, extra fields | full original document under provenance metadata | No canonical executable semantics can be safely inferred; retain verbatim and identify unsupported mapping. |
| `labeling` | state labels | Direct mapping for declared labels. |

The existing optional adapter already retains the full original document and
hash in metadata, but hardcodes the target schema version, assigns a filename
based ID, silently defaults some malformed collections, and is selected only
through an explicit Smart-EV adapter label. It lives in the integrations layer.
The GUI's generic loading path does not automatically dispatch this recognizable
legacy format. The canonical pipeline itself correctly validates normalized
input and constructs a 28-state/47-transition Kripke graph when given the
adapted `LoadedSpecification`.

## Migration rules

1. Detect legacy format from its data shape, independent of basename/path.
2. Preserve raw bytes/hash and input object; never rewrite the source file.
3. Build a canonical v1 document deterministically; obtain supported schema
   versions from the authoritative schema instead of duplicating a version
   literal in the adapter.
4. Reject malformed or semantically ambiguous required data with a
   `LEGACY_MIGRATION_FAILED` diagnostic naming the source field. Do not silently
   discard any nonempty field: map it, preserve it in provenance, or list why it
   has no executable canonical interpretation.
5. Run the unchanged canonical schema and semantic validators, then the normalizer.
6. After normalization, all pipeline stages consume the single typed canonical
   `Specification` and retain both original and canonical hashes/provenance.
7. Keep legacy expected outcomes separate from runtime observations. Do not
   generate fake function bodies or executable tests from narrative declarations.

## Existing model, graph, generation, and project context

The model stage consumes normalized `Specification.states` and
`Specification.transitions`, validates the Kripke structure, writes JSON,
summary, validation and DOT graph evidence, and maps requirements to that model.
The GUI Model page can display and pan/zoom the graph. Code generation consumes
the same normalized specification and model, emits generated model C/header,
manifest and source map, then builds/runs its generated-model consistency
harness. It does not synthesize the nine declared teacher function bodies; this
must remain `UNSUPPORTED` without implementation/source semantics. The GUI
session already retains selected project/spec paths and the normalized object;
the remaining adapter integration must put the raw and canonical inputs in
that same context before pipeline start.

## Acceptance feasibility

The external Smart-EV project and requested JSON are present. The existing
integration report documents a prior real run and input hash, but this audit
does not treat that historical report as a new acceptance run. A fresh real
GUI/CLI run and exact per-stage statuses must be recorded after implementing
automatic legacy dispatch. Static/memory/tool limits must retain their scoped
statuses. Arbitrary generated implementations for declarations without bodies
are not a valid acceptance criterion and must be reported unsupported.

## Implementation and fresh acceptance result

The read-only audit above preceded implementation. The adapter now lives under
Specification Core and is dispatched by the shared GUI/pipeline compatibility
loader based on document content. The source stays unchanged, canonical schema
and semantic validation run normally, and GUI session context retains raw,
canonical and normalized forms with both input hashes.

Fresh CLI run `legacy-teacher-e2e-v4` completed with 15 stage rows and valid
traceability. Model: 28 states/47 transitions, one initial state. Generated
model C/harness build: `PASS`; generated C is separately analyzed by static and
memory adapters with `GENERATED_ARTIFACT` scope. All 155 manifest evidence paths
and hashes were verified; zero source files changed. Fresh offscreen GUI run
also loaded the project/specification once, displayed the 28/47 graph, built the
generated model and produced a report.

Dynamic is `SKIPPED` because the source teacher document supplies no executable
test inputs/oracles; Coverage and Fuzzing consequently remain `SKIPPED`. BMC is
`SKIPPED` because no BMC property is declared. Static/memory checker outcomes
remain their actual `INCONCLUSIVE`, `TOOL_ERROR` and `BUILD_ERROR` values. The
nine declared function/probe names do not have bodies, signatures or source
bindings; no executable function implementations are generated. This is an
explicit information gap, not a migration or pipeline success claim for those
functions.
