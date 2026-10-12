# Verification accuracy benchmark contract (Task 3C, extended by Task 7)

This document defines the interpretation of benchmark version 1 with the Task 7 accuracy scenarios. It applies to the independently authored cases in `seclab.benchmark.catalog.CASES` and describes fixture-level observations only. It is a synthetic fixture suite, not an externally adjudicated reference corpus.

## Case and provenance contract

Each case has a stable `case_id`, checker/category, declared fixture input, expected status/finding/property/evidence labels, ground-truth source, creation method, independent validation rationale, and any known limitation. Fixture and ground-truth hashes are computed from canonical JSON. Expected outcomes are authored from fixture semantics and are never inferred or edited from checker observations. The catalog source hash is retained with each run.

Catalog provenance is manually/analytically derived from the fixture construction. Its independence means it is not populated from the checker observation; it does not mean independent expert adjudication. Controlled solver/time injection validates classification paths and is excluded from binary accuracy classes. Reported TP/TN/FP/FN values must carry `metric_scope: FIXTURE_LEVEL_ONLY` and must not be described as general checker accuracy.

The observation contract is separate: it records the checker name, status, finding/property, evidence labels, limitations/errors, and retained evidence references. Evidence payloads describe checker output only. They cannot modify expected values.

Adapters leave `actual_property` unavailable when the checker did not emit an independently observed property identity. An unavailable identity is retained as `null` and is not treated as a contradictory identity by the comparator; adapters must not fill it from `expected_property`.

## Status and classification

`PASS` and `FAIL` are the only binary statuses. A positive case means the declared safety defect/property violation exists; a negative case means it does not. A matching positive observation is TP, a matching negative observation is TN, a reported defect on a negative case is FP, and a missed defect on a positive case is FN. Static analyzers retain their checker status as inconclusive while scoring only the independently defined finding-presence signal.

`INCONCLUSIVE`, `UNSUPPORTED`, `ENVIRONMENT_LIMITED`, `TOOL_ERROR`, `BUILD_ERROR`, `SPEC_ERROR`, and `SKIPPED` remain separately reported and are excluded from TP/TN/FP/FN. Coverage is measurement-only and never contributes a safety classification. Metrics are per checker; no combined score or overall project verdict is defined.

Fixture requirements include a BMC unreachable bad state, distinct from both a reachable bad state and a bad state beyond the explored bound. Crash positives are scored only when the real process observation or fuzz campaign reports a crash; a nonzero exit code without crash classification is not upgraded to a crash. Sanitizer build/runtime limitations remain `BUILD_ERROR` or `ENVIRONMENT_LIMITED` according to the observed stage.

## Evidence and reproducibility

Each execution has a unique ID, UTC timestamp, Python/platform/tool summary, and source SHA-256 map. Its evidence workspace contains, per case, the serialized fixture, independent ground truth, raw checker output where available, normalized checker result/query/findings/process or campaign record, the observation, and comparator classification. `Evidence` references use the existing ArtifactStore schema: UUID, type, stage, source, workspace-relative path, timestamp, SHA-256, and metadata. The run manifest links each case to its evidence records and comparison record. The runner verifies every created artifact's safe path and hash before accepting that observation.

Evidence metadata labels the record role as `FIXTURE`, `GROUND_TRUTH`, `CHECKER_OBSERVATION`, or `COMPARISON`; these are metadata values and do not change the serialized Evidence schema.

Rerun one case with:

```powershell
python -m seclab.benchmark --case CTL-001 --workspace t/benchmark-runs
```

Use `--execution-id rerun-ctl-001` to choose a readable run label, `--output` for JSON, and `--markdown` for Markdown. Do not reuse an execution ID in a workspace: ArtifactStore uses exclusive file creation. Validate a stored reference through `verify_evidence_artifact(workspace_root, reference)` or recompute SHA-256 over the referenced bytes. A modified/missing/out-of-workspace artifact fails verification.

To check deterministic behavior, rerun the same selected cases under distinct execution IDs and compare classification, status, and normalized evidence payloads. Timing, generated artifact IDs, and execution timestamps are provenance fields and are not part of that semantic comparison. Fuzz evidence records the fixed campaign seed, requested and executed iteration budget, strategy, failures, coverage, and stop state.

| Trace stage | Persisted record | Integrity / relation |
|---|---|---|
| Catalog → fixture | `fixture.json` | Catalog-derived fixture SHA-256 |
| Independent ground truth | `ground-truth.json` | Ground-truth SHA-256 and provenance |
| Checker execution | Raw logs and normalized query/result records | Per-artifact SHA-256 |
| Observation | `observation.json` | Case ID, status, finding, evidence labels/references |
| Comparison | `comparison.json` | Expected/actual fields and classification |
| Execution provenance | `run/manifest.json` and CLI report | Execution ID, environment, source hashes, case evidence chain |

## Scope limits

Results describe only these cases, tool versions, environment, and declared bounded/fuzz budgets. They do not establish general soundness, completeness, or project-wide verification accuracy. Environment-limited and otherwise nonbinary observations are not relabeled as checker errors or false negatives. Checker implementations and formal semantics are outside this contract.
