# Generic Verification Test Matrix v1.2

This matrix exercises ten independent projects through the existing generic API: specification loading, model construction, formal properties, source discovery, configured analyses, dynamic tests, evidence and hashes, traceability, manifest, and persisted report. No fixture from `examples/teacher-workflow` or `examples/smart-ev-probes` is used here.

`COMPLETED` means the stage ran and emitted its normal stage output. A stage may complete with a scoped `TOOL_ERROR`, `BUILD_ERROR`, or inconclusive verification result when a checker/backend cannot establish an outcome. `SKIPPED` is reserved for an unconfigured capability or unmet prerequisite and carries a reason. Stage completion and verification status are separate concepts; neither is an overall project verdict.

| Fixture | Language | Specification | Model | CTL | SMT | BMC | Static | Memory | Dynamic | Coverage | Fuzzing | Evidence | Traceability |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `generic-c-project` | C | COMPLETED | COMPLETED | COMPLETED | COMPLETED, no SMT properties | SKIPPED: no BMC properties | SKIPPED: no analyzers configured | SKIPPED: disabled | COMPLETED, PASS oracle | SKIPPED: disabled | SKIPPED: no fuzz config | Hash and manifest references verified | Requirement, checker, result, and evidence references verified |
| `generic-c-memory-project` | C | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | SKIPPED: no properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | COMPLETED; findings remain scoped analyzer results | COMPLETED, PASS oracle | SKIPPED: disabled | SKIPPED: no fuzz config | Hash and manifest references verified | Requirement, result, and evidence references verified |
| `generic-cpp-project` | C++ | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | SKIPPED: no properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | SKIPPED: disabled | COMPLETED, PASS oracle | SKIPPED: disabled | SKIPPED: no fuzz config | Hash and manifest references verified | Requirement, source, result, and evidence references verified |
| `generic-state-machine-project` | C inventory + finite model | COMPLETED | COMPLETED, 3 states | COMPLETED, reachability/safety checks | SKIPPED: no properties | SKIPPED: no BMC properties | SKIPPED: no analyzers configured | SKIPPED: disabled | SKIPPED: no test cases | SKIPPED: disabled | SKIPPED: no fuzz config | CTL proof artifacts hashed and manifested | Model properties linked to requirement results/evidence |
| `generic-smt-project` | C inventory + integer/Boolean constraints | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | COMPLETED, PASS/FAIL/PASS properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | SKIPPED: disabled | SKIPPED: no test cases | SKIPPED: disabled | SKIPPED: no fuzz config | Per-property evidence hashes verified | Each SMT property linked to requirements/results/evidence |
| `generic-bmc-project` | C inventory + finite model | COMPLETED | COMPLETED, 3 states | SKIPPED: no CTL properties | SKIPPED: no SMT properties | COMPLETED: bound 1 INCONCLUSIVE; bound 2 counterexample; complete-depth bound result | SKIPPED: no analyzers configured | SKIPPED: disabled | SKIPPED: no test cases | SKIPPED: disabled | SKIPPED: no fuzz config | Counterexample/completeness evidence hashes verified | Property requirements link to bounded results and evidence |
| `generic-dynamic-project` | C | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | SKIPPED: no properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | SKIPPED: disabled | COMPLETED: PASS oracle, FAIL oracle, INCONCLUSIVE timeout, BUILD_ERROR for executable target | SKIPPED: disabled | SKIPPED: no fuzz config | Per-test build/execution/oracle evidence hashed | All test results linked to `REQ-DYNAMIC` |
| `generic-coverage-project` | C | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | SKIPPED: no properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | SKIPPED: disabled | COMPLETED: one correct oracle and one deliberate oracle FAIL | COMPLETED stage, `BUILD_ERROR` measurement result on this Windows GCC/gcov setup | SKIPPED: no fuzz config | Coverage configuration and source-integrity artifacts hashed; configured SUT set excludes generated harness | Dynamic failure and coverage measurement result linked; coverage is never a safety PASS |
| `generic-fuzz-project` | C | COMPLETED | SKIPPED: no explicit states | SKIPPED: model prerequisite | SKIPPED: no properties | SKIPPED: model prerequisite | SKIPPED: no analyzers configured | SKIPPED: disabled | COMPLETED, smoke oracle | COMPLETED seeded coverage-guided campaign in this environment | Fuzz campaign, corpus, and crash evidence manifested and hashed | Fuzz result linked to declared requirement |
| `generic-full-pipeline-project` | C + finite model | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED with compiler analyzer | COMPLETED; environment-dependent analyzer outcomes retained | COMPLETED, PASS oracle | COMPLETED stage; measurement backend may emit a scoped infrastructure result | COMPLETED bounded black-box campaign | Stage, result, source-integrity, manifest, and report artifacts hashed | Requirement-to-property/test/source/result/evidence paths verified |

## Audit checks

The parameterized integration test runs every fixture separately through `run_full_verification()` using its project-local JSON pipeline config. For every run it verifies:

- Results use the canonical verification statuses; result IDs are unique and status counts reconcile.
- Every skipped stage has a non-empty reason. Stage and result status are kept distinct.
- Every result/stage evidence reference resolves to the run manifest. Each manifested artifact exists and its SHA-256 matches.
- Source inventory entries have matching before/after hashes and report unchanged source bytes.
- Traceability result/evidence references resolve to actual results and manifested artifacts.
- Both the in-memory and persisted pipeline report omit `overall_verdict` and `overall_status`.

`tests/architecture/test_import_boundaries.py` verifies generic modules do not import optional integrations, generic core source has no forbidden Smart-EV markers or absolute external SUT path, and importing/running the generic pipeline remains possible while integration imports are blocked.

## Environment limitations observed

- The Windows GCC/gcov coverage integration for `generic-coverage-project` successfully discovers and records its configured production-source set, but the instrumented harness build fails in this toolchain setup. The pipeline preserves a scoped coverage `BUILD_ERROR`; it does not invent line or branch metrics. Unit/integration coverage-backend tests separately determine whether a given backend is available before asserting measurements.
- Coverage is a measurement only. Its result is not a safety verdict and does not override the intentional dynamic oracle failure.
- Static and memory stages can complete while individual analyzers return tool errors or inconclusive results. Those remain per-technique outcomes.
- BMC completeness is bounded to the explicit finite graph and declared state labels. The matrix reports the actual counterexample/no-counterexample and completeness fields without extrapolating to source-code behavior.

## Definition of Done

- [x] Ten independent generic fixtures exercise distinct language/model/analysis/testing capabilities.
- [x] Fixture integration checks cover results, status semantics, evidence hashes, manifest references, traceability, source integrity, stages, skip reasons, and report serialization.
- [x] No overall project verdict is created.
- [x] Generic import and source-isolation architecture checks remain in place.
- [x] No Smart-EV repository content, adapter, or domain-specific behavior is required by the generic fixture matrix.
- [x] Windows coverage backend limitation is recorded as a scoped build error; no coverage metrics are fabricated.
- [x] Full test suite: 282 passed, 5 skipped, 0 failed (`python -m pytest -q --basetemp=t\q`); compileall passed. This is the canonical baseline recorded in [architecture-freeze.md](architecture-freeze.md).
