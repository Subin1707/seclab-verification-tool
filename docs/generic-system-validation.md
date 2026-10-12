# Generic System Validation v1

## Scope and method

Seven independent, generic projects were run through the existing `seclab verify` CLI on 2026-10-03. Each project has its own source tree, `specification.json`, and `pipeline-config.json`; project-specific inputs are under `examples/`. The fixtures are A `generic-c-project`, B `generic-cpp-project`, C `generic-state-machine-project`, D `generic-c-memory-project`, E `generic-smt-project`, F `generic-dynamic-project`, and G `generic-fuzz-project`.

Expected behavior below is taken from each fixture's source, specification, README, and declared configuration. Actual status is the scoped checker result. `SKIPPED` means the configured pipeline did not have the required input or the capability was disabled; it is not a verification pass. Stage `COMPLETED` only means its adapter ran. No project-level verdict is calculated.

CLI form used for each run:

```powershell
python -m seclab.cli verify --project examples/<fixture> --spec examples/<fixture>/specification.json --config examples/<fixture>/pipeline-config.json --workspace t/gsv/runs --run-id <run-id>
```

CLI invocation exit code was 0 for all seven runs. This reports successful orchestration and report persistence; the checker outcomes are listed separately. GUI was not run: PySide6 is not installed in this environment (`importlib.util.find_spec("PySide6")` returned `None`). No GUI runtime result is claimed.

## Benchmark project ground truth

| Project | Independent source and specification | Expected behavior and known bugs | Expected checker results from fixture ground truth |
|---|---|---|---|
| A — Generic C | `examples/generic-c-project/src/counter.c`; `specification.json` | `counter_increment(value)` returns `value + 1`; no injected bug is declared. | CTL `AG(safe)` holds in the one-state self-loop model; SMT `0 <= counter <= 100` is valid under its declared domain; `TEST-COUNTER-INCREMENT` returns 10 for input 9. Other analyses are disabled or have no declared properties. |
| B — Generic C++ | `examples/generic-cpp-project/src/numeric.cpp`; `specification.json` | `scale_value(value, factor)` multiplies its arguments; no injected bug is declared. | `TEST-SCALE` returns 42 for inputs 6 and 7. No explicit-state model or formal property is declared. |
| C — State machine | `examples/generic-state-machine-project/src/state_machine.c`; explicit states/transitions and CTL properties in `specification.json` | `IDLE → ACTIVE → COMPLETE`, with a `COMPLETE` self-loop. `done` is reachable and `safe` labels every state; no bug is declared. | `EF(done)` and `AG(safe)` both hold. No BMC/SMT property or dynamic test is declared. |
| D — Memory safety | `examples/generic-c-memory-project/src/sequence.c` and `src/main.c`; `specification.json` | `sum_sequence(5)` allocates five integers, writes indices 0–4, sums 1–5, frees the allocation, and returns 15. No known bug is declared. Sanitizer results depend on installed compiler/runtime support. | Dynamic oracle expects 15. Address/undefined behavior/leak checks should assess this source if the configured analyzer/runtime is available; unavailable instrumentation must remain a scoped build error or inconclusive result. |
| E — Arithmetic/constraints | `examples/generic-smt-project/src/integer_model.c`; bounded integer and Boolean declarations in `specification.json` | `value` ranges from 0 to 10, `enabled` is Boolean; no source defect is declared. The property `value <= 5` is intentionally false over the full declared domain. | `PROP-RANGE` and `PROP-BOOLEAN` are valid; `PROP-BOUND` is violated (for example, value 6). Other stages have no applicable declared inputs. |
| F — Dynamic tests | `examples/generic-dynamic-project/src/operations.c`; four explicit tests in `specification.json` | The fixture deliberately includes a mismatching oracle (expected 99 from identity input 4), a missing target causing build failure, and a negative input that loops until timeout. | `TEST-ORACLE-PASS` PASS; `TEST-ORACLE-FAIL` FAIL; `TEST-BUILD-FAIL` BUILD_ERROR; `TEST-TIMEOUT` INCONCLUSIVE. These are expected test outcomes, not claims that the SUT passes. |
| G — Coverage and fuzzing | `examples/generic-fuzz-project/src/guarded.c`; one smoke oracle plus scalar seed 13 and coverage-guided settings | Value 0 satisfies the no-crash smoke oracle. `guarded_operation(13)` deliberately terminates abnormally. The seed is a known crash input by source inspection. | Dynamic smoke PASS. Coverage should measure the configured source/test execution. Fuzzing should replay seed 13 and identify abnormal termination if the backend can preserve coverage feedback for the crashing process. Otherwise report incomplete/tool limitation, never “no finding” or PASS. |

## Project × Checker × Expected × Actual × Status × Evidence

Evidence is rooted at `t/gsv/runs/<run-id>/evidence/`. For a row with no checker result, evidence points to the stage record and its explicit skip reason in `evidence/manifest/run-manifest.json`; a dash means no checker artifact was expected. `COMPLETED`/`SKIPPED` are stage statuses; actual checker statuses appear in parentheses where applicable.

| Project | Checker | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|
| A | Specification | Load, validate, normalize fixture | Loaded and normalized; 2 requirements, 2 properties, 1 test | COMPLETED | `gsv-a/evidence/pipeline/specification.json` |
| A | Model | One `READY` state with self-loop | 1 state, 1 transition; no deadlocks | COMPLETED | `gsv-a/evidence/model/kripke.json` |
| A | CTL | `AG(safe)` true | `PROP-COUNTER-NONNEGATIVE` PASS | COMPLETED | `gsv-a/evidence/ctl/PROP-COUNTER-NONNEGATIVE.json` |
| A | BMC | No BMC property declared | No result | SKIPPED: no BMC properties | `gsv-a/evidence/manifest/run-manifest.json` |
| A | SMT | Counter range valid | `PROP-COUNTER-RANGE` PASS | COMPLETED | Manifested SMT query/result artifacts |
| A | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-a/evidence/manifest/run-manifest.json` |
| A | Memory | Disabled | No result | SKIPPED: disabled | `gsv-a/evidence/manifest/run-manifest.json` |
| A | Dynamic | Increment input 9 yields 10 | `TEST-COUNTER-INCREMENT` PASS | COMPLETED | Manifested test, harness, execution and oracle artifacts |
| A | Coverage | Disabled | No result | SKIPPED: disabled | `gsv-a/evidence/manifest/run-manifest.json` |
| A | Fuzzing | No fuzz configuration | No result | SKIPPED: no fuzz configuration | `gsv-a/evidence/manifest/run-manifest.json` |
| A | Evidence | Every artifact present and hash-valid | 22 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-a/evidence/manifest/run-manifest.json` |
| A | Traceability | Requirements link to targets/results/evidence/source | 2 requirements; references resolve; source hashes unchanged | VERIFIED | `gsv-a/evidence/report/pipeline-report.json` |
| B | Specification | Load, validate, normalize fixture | Loaded and normalized; 1 requirement, 1 test | COMPLETED | `gsv-b/evidence/pipeline/specification.json` |
| B | Model | No explicit model declared | No model | SKIPPED: explicit states required | `gsv-b/evidence/manifest/run-manifest.json` |
| B | CTL | No CTL property/model | No result | SKIPPED: model prerequisite | `gsv-b/evidence/manifest/run-manifest.json` |
| B | BMC | No BMC property/model | No result | SKIPPED: model prerequisite | `gsv-b/evidence/manifest/run-manifest.json` |
| B | SMT | No SMT property | No result | SKIPPED: no SMT properties | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Memory | Disabled | No result | SKIPPED: disabled | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Dynamic | 6 × 7 yields 42 | `TEST-SCALE` PASS | COMPLETED | Manifested test, harness, execution and oracle artifacts |
| B | Coverage | Disabled | No result | SKIPPED: disabled | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Fuzzing | No fuzz configuration | No result | SKIPPED: no fuzz configuration | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Evidence | Every artifact present and hash-valid | 17 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-b/evidence/manifest/run-manifest.json` |
| B | Traceability | Requirement links test/result/evidence/source | 1 requirement; references resolve; source unchanged | VERIFIED | `gsv-b/evidence/report/pipeline-report.json` |
| C | Specification | Load state-machine requirements/properties | Loaded and normalized; 2 requirements, 2 CTL properties | COMPLETED | `gsv-c/evidence/pipeline/specification.json` |
| C | Model | Three states and three transitions | 3 states, 3 transitions, all states reachable | COMPLETED | `gsv-c/evidence/model/kripke.json` |
| C | CTL | `EF(done)` and `AG(safe)` true | Both properties PASS | COMPLETED | `gsv-c/evidence/ctl/PROP-COMPLETE-REACHABLE.json`; `PROP-FAILURE-ABSENT.json` |
| C | BMC | No BMC property | No result | SKIPPED: no BMC properties | `gsv-c/evidence/manifest/run-manifest.json` |
| C | SMT | No SMT property | No result | SKIPPED: no SMT properties | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Memory | Disabled | No result | SKIPPED: disabled | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Dynamic | No tests declared | No result | SKIPPED: no test cases | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Coverage | No dynamic tests | No result | SKIPPED: dynamic prerequisite | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Fuzzing | No dynamic template/config | No result | SKIPPED: dynamic prerequisite/no config | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Evidence | Every artifact present and hash-valid | 8 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-c/evidence/manifest/run-manifest.json` |
| C | Traceability | Both requirements link CTL result/evidence | 2 requirements; result/evidence refs resolve | VERIFIED | `gsv-c/evidence/report/pipeline-report.json` |
| D | Specification | Load function/test requirement | Loaded and normalized; 1 requirement, 1 test | COMPLETED | `gsv-d/evidence/pipeline/specification.json` |
| D | Model | No explicit model | No model | SKIPPED: explicit states required | `gsv-d/evidence/manifest/run-manifest.json` |
| D | CTL | No model/property | No result | SKIPPED: model prerequisite | `gsv-d/evidence/manifest/run-manifest.json` |
| D | BMC | No model/property | No result | SKIPPED: model prerequisite | `gsv-d/evidence/manifest/run-manifest.json` |
| D | SMT | No SMT property | No result | SKIPPED: no SMT properties | `gsv-d/evidence/manifest/run-manifest.json` |
| D | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-d/evidence/manifest/run-manifest.json` |
| D | Memory | Safe sequence code; sanitizer checks where available | ASan BUILD_ERROR; UBSan BUILD_ERROR; leak checker INCONCLUSIVE (unavailable on Windows) | COMPLETED with scoped limitations | Manifested compiler/runtime diagnostics and memory result artifacts |
| D | Dynamic | `sum_sequence(5)` returns 15 | `TEST-SEQUENCE-SUM-5` PASS | COMPLETED | Manifested test, harness, execution and oracle artifacts |
| D | Coverage | Disabled | No result | SKIPPED: disabled | `gsv-d/evidence/manifest/run-manifest.json` |
| D | Fuzzing | No fuzz config | No result | SKIPPED: no fuzz configuration | `gsv-d/evidence/manifest/run-manifest.json` |
| D | Evidence | Every artifact present and hash-valid | 25 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-d/evidence/manifest/run-manifest.json` |
| D | Traceability | `REQ-SEQUENCE-SUM` links dynamic result and source | 1 requirement; refs resolve; source unchanged | VERIFIED | `gsv-d/evidence/report/pipeline-report.json` |
| E | Specification | Load integer/Boolean domains and constraints | Loaded and normalized; 2 requirements, 3 SMT properties | COMPLETED | `gsv-e/evidence/pipeline/specification.json` |
| E | Model | No explicit states | No model | SKIPPED: explicit states required | `gsv-e/evidence/manifest/run-manifest.json` |
| E | CTL | No model/property | No result | SKIPPED: model prerequisite | `gsv-e/evidence/manifest/run-manifest.json` |
| E | BMC | No model/property | No result | SKIPPED: model prerequisite | `gsv-e/evidence/manifest/run-manifest.json` |
| E | SMT | Range and Boolean valid; upper bound false | `PROP-RANGE` PASS; `PROP-BOOLEAN` PASS; `PROP-BOUND` FAIL | COMPLETED | Manifested per-property SMT query/result artifacts |
| E | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Memory | Disabled | No result | SKIPPED: disabled | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Dynamic | No tests declared | No result | SKIPPED: no test cases | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Coverage | No dynamic tests | No result | SKIPPED: dynamic prerequisite | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Fuzzing | No dynamic template/config | No result | SKIPPED: dynamic prerequisite/no config | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Evidence | Every artifact present and hash-valid | 15 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-e/evidence/manifest/run-manifest.json` |
| E | Traceability | Both requirements link to SMT properties/results/evidence | 2 requirements; references resolve | VERIFIED | `gsv-e/evidence/report/pipeline-report.json` |
| F | Specification | Load four explicit dynamic cases | Loaded and normalized; 1 requirement, 4 tests | COMPLETED | `gsv-f/evidence/pipeline/specification.json` |
| F | Model | No explicit states | No model | SKIPPED: explicit states required | `gsv-f/evidence/manifest/run-manifest.json` |
| F | CTL | No model/property | No result | SKIPPED: model prerequisite | `gsv-f/evidence/manifest/run-manifest.json` |
| F | BMC | No model/property | No result | SKIPPED: model prerequisite | `gsv-f/evidence/manifest/run-manifest.json` |
| F | SMT | No SMT property | No result | SKIPPED: no SMT properties | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Memory | Disabled | No result | SKIPPED: disabled | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Dynamic | Expected pass, deliberate oracle mismatch, build failure, timeout | `TEST-ORACLE-PASS` PASS; `TEST-ORACLE-FAIL` FAIL; `TEST-BUILD-FAIL` BUILD_ERROR; `TEST-TIMEOUT` INCONCLUSIVE | COMPLETED | Per-test harness, build, execution, observed-value and oracle artifacts |
| F | Coverage | Disabled | No result | SKIPPED: disabled | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Fuzzing | No fuzz configuration | No result | SKIPPED: no fuzz configuration | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Evidence | Every artifact present and hash-valid | 49 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-f/evidence/manifest/run-manifest.json` |
| F | Traceability | Four test outcomes link to `REQ-DYNAMIC` | 1 requirement; all four result and evidence paths resolve | VERIFIED | `gsv-f/evidence/report/pipeline-report.json` |
| G | Specification | Load smoke test, requirement and function | Loaded and normalized; 1 requirement, 1 test | COMPLETED | `gsv-g/evidence/pipeline/specification.json` |
| G | Model | No explicit states | No model | SKIPPED: explicit states required | `gsv-g/evidence/manifest/run-manifest.json` |
| G | CTL | No model/property | No result | SKIPPED: model prerequisite | `gsv-g/evidence/manifest/run-manifest.json` |
| G | BMC | No model/property | No result | SKIPPED: model prerequisite | `gsv-g/evidence/manifest/run-manifest.json` |
| G | SMT | No SMT property | No result | SKIPPED: no SMT properties | `gsv-g/evidence/manifest/run-manifest.json` |
| G | Static | No analyzer configured | No result | SKIPPED: no analyzers configured | `gsv-g/evidence/manifest/run-manifest.json` |
| G | Memory | Disabled | No result | SKIPPED: disabled | `gsv-g/evidence/manifest/run-manifest.json` |
| G | Dynamic | Smoke input 0 satisfies no-crash oracle | `TEST-GUARDED-SMOKE` PASS | COMPLETED | Manifested test, harness, execution and oracle artifacts |
| G | Coverage | Coverage measurement on configured source/test | Complete gcov report: 3/5 lines = 60%; 1/2 branches = 50%; one test executed | COMPLETED | `gsv-g/evidence/report/pipeline-report.json` stage `COVERAGE`; gcov artifacts in manifest |
| G | Fuzzing | Seed 13 should exercise declared abnormal termination | 0/2 fuzz inputs executed; no crash finding; campaign stopped with `COVERAGE_FEEDBACK_UNAVAILABLE` and `COVERAGE_DATA_MISSING` | TOOL_ERROR, campaign incomplete; no PASS/no-finding claim | `gsv-g/evidence/report/pipeline-report.json` stage `FUZZING`; fuzz campaign artifacts in manifest |
| G | Evidence | Every artifact present and hash-valid | 64 manifest artifacts verified; 0 mismatches | VERIFIED | `gsv-g/evidence/manifest/run-manifest.json` |
| G | Traceability | Requirement links smoke and fuzz results/evidence/source | 1 requirement; result/evidence refs resolve; source unchanged | VERIFIED | `gsv-g/evidence/report/pipeline-report.json` |

## Cross-run integrity checks

- All seven reports contain the full ordered stage set: specification, source, model, CTL, BMC, SMT, static, memory, dynamic, coverage, fuzzing, and report.
- Every skipped stage has a recorded reason.
- Independently recomputed SHA-256 matched every manifest artifact: A 22, B 17, C 8, D 25, E 15, F 49, G 64; no missing or hash-mismatched artifact was found.
- Pipeline artifact integrity records had no invalid hash or error. Every source's before/after hashes matched and every report marked source unchanged.
- Every result evidence ID and requirement-level result/evidence reference resolved to an entry in the run manifest. Requirement traceability was present for each declared requirement.
- Reports and manifests contain scoped results only; no overall project PASS/FAIL was emitted.

## Limitations and observed gaps

- GUI runtime validation was unavailable because PySide6 is absent. CLI and pipeline artifacts were checked; this does not establish GUI operation.
- The Windows memory-toolchain configuration could not build ASan/UBSan instrumented targets; leak detection reports unavailable on this platform. These are not clean-memory findings.
- Fuzz project G did not reach the crashing seed outcome. Its separate smoke input covered only the non-crashing value 0. The coverage measurement completed, but the fuzz engine reports missing gcov feedback after abnormal seed termination and executed zero fuzz iterations. The fixture's declared crash ground truth therefore remains unconfirmed by this run.
- Source/function inventory for state-machine project C is an independent C file; its model properties apply to the explicit specification model, not the C implementation.
- Checker applicability is fixture-driven. Static analysis is unconfigured in these project configs, and BMC has no property in A-G; those cells remain skipped rather than implying a pass.

## Milestone completion criteria

- [x] Seven independent generic project fixtures, each with source, specification, expected behavior, known-bug notes, and checker expectations.
- [x] Every project executed through the generic CLI, with actual stage and scoped checker outcomes recorded.
- [x] Specification, model, CTL, BMC, SMT, static, memory, dynamic, coverage, fuzzing, evidence, and traceability represented in the matrix, including explicit skips.
- [x] Actual artifact hashes, source hashes, result-evidence references, and requirement trace references checked across all runs.
- [x] No expected result inferred from tool silence; incomplete fuzzing and unavailable sanitizers are recorded as limitations.
- [x] No overall project verdict produced; no Smart-EV repository modified.
- [ ] GUI runtime verified (environment does not provide PySide6).
