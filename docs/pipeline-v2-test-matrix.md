# Pipeline v2 finalization test matrix

Each stage is selectable with `run_full_verification(..., stage_ids=("STAGE",))`. The selected stage and its declared prerequisites run in deterministic order; `REPORT` by itself assembles an empty-scope report and does not implicitly request every checker. A stage that lacks suitable inputs is `SKIPPED` with a reason. Stage lifecycle is separate from checker status. No project-level verdict is generated.

## Stage matrix

| Stage | Declared inputs/dependencies | Focused test coverage | Expected behavior without usable input |
|---|---|---|---|
| SPECIFICATION | Configured specification paths | `test_invalid_spec_failure_is_recorded_without_blocking_source_analysis`; valid-spec integration tests | `SKIPPED` when no path is configured; invalid documents create scoped `INVALID_SPECIFICATION` result and `FAILED` stage |
| SOURCE | Project root and supported source files | `test_missing_source_skips_source_dependent_stages`; generic C project integration | `SKIPPED` with “No supported source files…” |
| MODEL | Valid specification with explicit states | `test_missing_initial_state_fails_spec_and_skips_formal_dependents`; CTL/BMC integration | `SKIPPED` when no valid explicit-state model is available |
| CTL | SPECIFICATION + MODEL, CTL properties | `test_full_pipeline_specification_model_ctl_traceability`; formal integration tests | `SKIPPED` for missing model or no CTL properties |
| BMC | SPECIFICATION + MODEL, BMC properties | formal integration tests and bounded-result assertions | `SKIPPED` for missing model or no BMC properties |
| SMT | SPECIFICATION, SMT properties | formal integration tests and SMT result assertions | `SKIPPED` when no SMT properties exist |
| STATIC | SOURCE, configured analyzers | missing-analyzer and static pipeline tests | `SKIPPED` with reason if no source or analyzers; individual missing tools remain scoped tool results |
| MEMORY | SOURCE, enabled memory analysis | `test_memory_stage_runs_existing_analyzers_and_persists_limitations`; sanitizer integration | `SKIPPED` if disabled or no source; unavailable sanitizers remain scoped unsupported/inconclusive results |
| DYNAMIC | SPECIFICATION + SOURCE and test cases | generic C project integration; build/oracle/timeout test-core coverage | `SKIPPED` if tests or supported source are absent; build and timeout outcomes stay scoped |
| COVERAGE | SOURCE + DYNAMIC, enabled measurement and executed tests | `test_coverage_stage_failure_does_not_block_blackbox_fuzzing`; coverage integration | `SKIPPED` if disabled or inputs absent; partial coverage is a measurement, not PASS |
| FUZZING | SPECIFICATION + SOURCE + DYNAMIC, fuzz configuration | fuzz campaign integration; `test_coverage_stage_failure_does_not_block_blackbox_fuzzing` | `SKIPPED` without configuration/template/source; only coverage-guided strategy requires coverage success |
| REPORT | Results, traceability, evidence, source/artifact integrity | `test_report_stage_can_run_without_expanding_to_full_pipeline`; full report integration | Always assembles the selected run scope; never synthesizes overall PASS/FAIL |

## Cross-stage fault and integrity checks

| Condition | Test | Required observable result |
|---|---|---|
| Invalid specification | `test_invalid_spec_failure_is_recorded_without_blocking_source_analysis` | SPECIFICATION failed with a scoped result; independent SOURCE continues |
| Missing source | `test_missing_source_skips_source_dependent_stages` | SOURCE skipped; source-dependent analyses skip with their own reason |
| Missing tool | `tests/integration/test_coverage_backends.py::test_explicit_llvm_missing_tool_does_not_fallback`; optional analyzer/sanitizer integration tests | Tool-specific result/limitation; no clean PASS is inferred |
| Timeout | Dynamic/fuzz execution tests and bounded solver fixtures | Scoped timeout/inconclusive result; unrelated stage continues |
| Build failure | Dynamic test execution and pipeline stage-result tests | Build error is scoped to the affected test/stage |
| Partial coverage | Coverage aggregation/core tests | Measured percentage retained; no safety verdict |
| Unavailable sanitizer | Memory/sanitizer integration tests | Explicit unsupported/inconclusive limitation |
| No fuzz configuration | Generic C project integration | FUZZING skipped with a non-empty reason |
| Optional-stage failure | `test_coverage_stage_failure_does_not_block_blackbox_fuzzing` | Black-box fuzzing proceeds when coverage fails |
| Source mutation | `test_generic_c_project_runs_without_external_system`, chapter workflow hash checks | Before/after SHA-256 comparison is persisted |
| Artifact tampering | `test_artifact_hash_mismatch_is_a_scoped_report_result` | REPORT records `ARTIFACT_HASH_MISMATCH`; valid artifacts report matching SHA-256 |
| Evidence/trace links | Generic project and chapter workflow integration tests | Requirement → property/test → result → evidence and source lineage IDs resolve in the run workspace |

Run the full regression suite with `python -m pytest -q --basetemp=t\q`.
