# Legacy specification migration

## Data path

```text
immutable raw JSON + SHA-256
        ↓ content-based legacy detection
Legacy Specification Adapter
        ↓ canonical Specification Core JSON
unchanged JSON Schema validation
        ↓ semantic validation
deterministic normalized Specification
        ↓ one retained GUI/pipeline context
```

`seclab.specification.legacy_adapter.load_compatible_specification()` is the
shared loader used by the GUI and pipeline/CLI. The legacy signature requires
an absent `schema_version`, a `state_machine` object and a `requirements`
array. Detection does not use the filename. Native JSON is sent to the existing
loader and validator without migration. Mixing legacy and native fragments is
rejected with `LEGACY_MIGRATION_FAILED` because merge meaning is ambiguous.

The adapter creates a stable canonical ID from an existing ID or the declared
name (then filename/hash fallback), sanitizes it to the existing ID grammar,
and reads the canonical schema version from the authoritative schema enum. It
does not change `schemas/specification.schema.json` or bypass validation.
Malformed legacy machine structures fail with a field-specific migration
diagnostic. Schema and semantic errors retain their existing structured error
codes and source locations.

The source file is never written. `SourceDocument.sha256` and provenance carry
the original file hash. Provenance retains the complete original object,
duplicate root graph views, unexecutable declarations, and unmapped extension
fields. The compatibility loader returns raw, canonical and compatibility
objects separately. The GUI `VerificationSession` retains project path, source
spec path, raw document, canonical document, normalized typed Specification,
ID, schema version, source/canonical hashes, and validation state; the pipeline
receives the already loaded/validated/normalized values from that same session.

## Current legacy mapping

| Source | Canonical mapping | Unsupported meaning retained |
| --- | --- | --- |
| `name` / optional `id` | required canonical `name` and stable `id` | Original values retained in provenance. |
| `state_machine.states`, `.transitions`, `.initial`, `.labeling` | root states, transitions, initial state and labels | Duplicate smaller root graph retained and reported as an unmapped duplicate view. |
| `requirements` | `Requirement` records | Category/priority are only included when present; schema validates values. |
| `safety_properties` | CTL properties | Requirement link is derived only by the established requirement-label naming convention and only when that exact requirement ID exists. |
| `arithmetic_checks` | SMT properties and source check metadata | Teacher expected solver outcome stays an expectation field; runtime solver observation is independently produced. |
| `functions` | declaration records and provenance classification | No source file or function body is provided; no executable implementation is synthesized. Probe/vulnerability declarations are not production source. |
| `test_cases` | narrative provenance and `NOT_APPLICABLE` trace targets | No executable inputs/oracles are inferred from prose. |
| flows, mutual exclusion, duplicate root fields, other extension fields | verbatim original document and explicit unmapped-field provenance | No state/property semantics are guessed. |

## Reproduce

```python
from seclab.specification import load_compatible_specification, validate_specification, normalize_specification

loaded, compatibility, raw_documents = load_compatible_specification("path/to/teacher.json")
validated = validate_specification(loaded)
normalized = normalize_specification(validated)
```

The real teacher document was migrated twice with the same ID and canonical
digest, validated by the canonical schema/semantic validator, and normalized
to ID `smart_ev_teacher_e2e_v4`, schema `1.0`, 28 states and 47 transitions.
