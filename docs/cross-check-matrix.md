# Cross-check Matrix v1

The pipeline runs a dedicated `CROSS_CHECK` stage after the configured checker stages. It writes a hashed ArtifactStore matrix and attaches the matrix reference to the pipeline report. It has no dependencies on optional checkers, so it can describe partial runs when a checker is skipped, failed, or limited by the host.

The matrix relates:

- Specification ↔ Model: declared graph to canonical model hash. This does not establish that the model matches source behavior.
- Specification ↔ Source: uniquely matched declared function and requirement links.
- Model ↔ Source: source-derived provenance only when `SourceModelBuilder` output is explicitly available; otherwise `UNRESOLVED`.
- Source ↔ Dynamic: only completed process observations whose testcase source hashes match the discovered source snapshot. Hash mismatch or source mutation is `INCONSISTENCY`.
- Specification ↔ Dynamic and Specification ↔ Formal: explicit test/property/requirement IDs only.
- Model ↔ Formal: CTL/BMC model hashes are linked; SMT is marked not comparable to a Kripke model because its scope is a valuation under specification constraints.
- Dynamic ↔ Formal: statuses are compared only when the test and property both declare the same non-empty `cross_check_key`, which explicitly identifies the same claim. Opposite conclusive statuses produce `INCONSISTENCY`; neither result is preferred or rewritten.

Relation states are `LINKED`, `CONSISTENT`, `INCONSISTENCY`, `NOT_COMPARABLE`, and `UNRESOLVED`. The matrix has `aggregation: NONE` and does not contain an overall-verdict field. It retains checker-specific status, scope, and evidence references for CTL, BMC, SMT, static analysis, memory analysis, dynamic testing, coverage, and fuzzing. Coverage records are measurement-only. Fuzz records retain bounded campaign details. A cross-check inconsistency adds a scoped `CROSS_CHECK_MATRIX` result with `INCONCLUSIVE`; the original checker results remain unchanged.

Coverage reports appear in a separate `measurements` collection with their measurement hash and scope; they do not receive a verification verdict. `cross_check_key` is optional metadata on the existing property metadata and dynamic `TestCase.metadata`; the Specification JSON contract is unchanged. Without that explicit equivalence declaration, differently scoped PASS/FAIL values remain un-compared rather than being treated as contradictory.
