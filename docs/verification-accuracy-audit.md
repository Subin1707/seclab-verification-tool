# Verification Accuracy Benchmark Audit

Audit date: 2026-10-04  
Repository baseline: 282 passed, 5 skipped, 0 failed; `python -m compileall -q src tests` passed (baseline recorded in [architecture-freeze.md](architecture-freeze.md)).  
Scope: TASK 2 audit only. No checker, core, specification contract, Smart-EV repository, or benchmark implementation was changed.

## 1. Finding

The project has an executable benchmark framework and independently declared expected outcomes for 45 catalog cases. It compares and reports checker-local results, but it does **not** establish broad or general checker accuracy. Some checker categories have only narrow fixtures; static analysis has no binary TP/TN benchmark outcomes; memory analysis could not be exercised on this Windows host; and several requested scenarios are absent. The checked-in [verification-accuracy.md](verification-accuracy.md) is a generated report that does not match the audit run and must not be used as the current environment result.

The benchmark run on this host completed with exit code 1 because six memory observations differed from their catalog expectations: `MEM-001` through `MEM-006` all returned `UNSUPPORTED` due to unavailable sanitizer support. These were classified as environment limitations and excluded from TP/TN/FP/FN counts. The run had 45 cases, no FP/FN, and no conclusive memory observations. This result is not an accuracy percentage.

## 2. Checker inventory

“Evidence” below means the benchmark observation contains an evidence *type label*. It does not mean the benchmark preserves a payload, validates its hash, or verifies evidence content.

| Checker | Benchmark? | Ground truth? | Comparator? | Evidence? | Test? |
|---|---|---|---|---|---|
| CTL | Yes, 8 cases | Yes, catalog-authored expected status/finding/property | Yes, shared comparator | Type labels only; actual checker result/witness payload is not retained in observation | Yes |
| BMC | Yes, 5 cases | Yes, catalog-authored; timeout is controlled backend | Yes | Type labels only; no retained trace/query payload | Yes |
| SMT | Yes, 7 cases | Yes, catalog-authored; UNKNOWN/timeout are controlled backends | Yes | Type labels only; no retained model/query payload | Yes |
| Static analysis | Yes, 4 cases | Declared fixture behavior, but defect outcomes are not independently confirmed; all cases expect non-binary statuses | Yes | Type labels only; analyzer output is not stored in benchmark observation/report | Yes |
| Memory analysis | Yes, 6 cases | Declared safe/defect fixtures | Yes | Type labels only; sanitizer payload is not retained | Catalog exists; full accuracy run does not succeed on this host |
| Dynamic testing | Yes, 5 cases | Independent return-value oracle, malformed source, and controlled timeout/crash outcomes | Yes | Type labels only; process/build/oracle evidence payload is not retained | Yes |
| Fuzzing | Yes, 5 cases | Declared seeded crash/oracle and bounded campaign scenarios | Yes | Type labels only; campaign payload is not retained | Yes |
| Coverage (measurement only) | Yes, 5 cases | Known counters / expected measured ratios | Yes, measurement comparison | Type labels only; no safety classification is allowed | Yes |

Implementation locations: catalog and expected inputs in [catalog.py](../src/seclab/benchmark/catalog.py); case/observation/report models and comparator in [models.py](../src/seclab/benchmark/models.py); execution adapter in [production.py](../src/seclab/benchmark/production.py); orchestration in [runner.py](../src/seclab/benchmark/runner.py); CLI in [__main__.py](../src/seclab/benchmark/__main__.py); tests in [test_accuracy_benchmark.py](../tests/benchmark/test_accuracy_benchmark.py).

## 3. Existing benchmark inventory and data flow

- **Runner:** `run_benchmark(cases, executor)` executes each case, converts raised exceptions into `TOOL_ERROR` observations, and calls `compare_benchmark`. The CLI runs all `CASES`, can write JSON/Markdown, and exits nonzero on any report mismatch.
- **Case model:** `BenchmarkCase` stores source, specification, scenario parameters, checker/category, and expected status/finding/property/evidence type plus a limitation note. The catalog's expected values are literal declarations and are not populated from execution.
- **Actual model:** `BenchmarkObservation` stores actual checker/status/finding/property, evidence type labels, unsupported reason, and error text. It has no structured raw outcome or evidence payload/reference.
- **Comparator:** exact status/checker/finding/property and required evidence-type inclusion determine `matched`. Separately, status alone drives TP/TN/FP/FN. Therefore a status can score as a true positive/negative even when the finding, property, evidence, or checker identity does not match; such a case is listed as a mismatch but still affects confusion counts.
- **Evidence:** observations and report rows contain strings such as `counterexample` or `sanitizer-report`, not artifacts, hashes, or validated payloads. Evidence presence is checked by type subset only.
- **Report:** per-checker confusion counts and rates, mismatch lists, and case-by-case expected/actual rows. No combined score or project verdict is generated. Reports can become stale: checked-in `docs/verification-accuracy.md` has no run timestamp/environment and currently shows all memory metrics as unsupported without enumerating the current six mismatches consistently.
- **Tests:** test catalog shape/count, production adapter behavior for non-memory categories, artificial FP/FN and unsupported examples, metric calculations, expected-vs-actual separation, environment-limit handling, and absence of a project verdict. These prove plumbing/scorer behavior; they do not prove all checkers accurate.

## 4. Ground-truth methodology and leakage audit

Catalog expected fields are separately authored in `catalog.py`; production execution is invoked after catalog construction. A source search found no production assignment of `expected_status` from the checker result and no benchmark runner path that executes a checker to generate catalog expectations. The expected values are independent **declarations**, not independent external proofs: many formal cases use hand-built finite graphs and controlled backend outcomes, and static/memory/fuzz defect truth is based on known fixture intent. Accordingly, claims are limited to these declared fixtures and the adapter paths exercised.

The production adapters use `expected_property` as the property/result identifier passed to APIs, and use case IDs/scenario names to select known controlled inputs. They do not use `expected_status` to compute checker output. The coverage adapter derives the expected ratio from catalog counter parameters and compares it to the aggregation API; this is measurement validation, not safety ground truth.

**Ground-truth leak found in a test-only helper:** [test_mutation_validation.py](../tests/mutation/test_mutation_validation.py) `_reference_observation` constructs its synthetic baseline observation directly from `case.expected_status`, `expected_finding`, `expected_property`, and expected evidence. The file describes this as a deterministic observation-boundary mutation fixture, not a production checker benchmark. It is therefore a deliberate tautological reference for scorer sensitivity and cannot be cited as independent checker evidence. This TASK 2 audit did not change it.

No production benchmark ground-truth leak was found. The observation-boundary test [test_expected_ground_truth_is_independent_of_actual_observation](../tests/benchmark/test_accuracy_benchmark.py) confirms the catalog case remains unchanged after a deliberately mismatching observation, but does not by itself establish fixture truth.

## 5. Classification methodology audit

The comparator labels positive as expected/actual status `FAIL`, negative as `PASS`, and applies TP/TN/FP/FN from those statuses. Expected `INCONCLUSIVE`, `TOOL_ERROR`, `BUILD_ERROR`, and `SPEC_ERROR` cases are not binary-scored. Coverage `PASS`/`FAIL` observations are rejected from safety scoring. There is no overall project verdict.

Limitations against the requested outcome taxonomy:

- `INCONCLUSIVE` stays out of FP/FN counts, which is correct.
- `UNSUPPORTED` is separated from binary outcomes. `ENVIRONMENT_LIMITATION` is inferred from substrings in `unsupported_reason`; this is brittle and may misclassify an unsupported feature or tool defect.
- `TOOL_ERROR` and `BUILD_ERROR` are both mapped to the `INCONCLUSIVE` classification, so the report cannot distinguish those required states. Runner exceptions lose checker identity and become `actual_checker=None`, status `TOOL_ERROR`.
- There is no explicit `TOOL_ERROR` classification or dedicated report list. There is an additional `SPECIFICATION_ERROR` class, which the task did not list but is defensible as a separate input error.
- Expected/actual status match is not required to assign TP/TN/etc. As a result `matched=false` and a `TRUE_POSITIVE`/`TRUE_NEGATIVE` classification can coexist if another field differs.
- Only evidence *type* presence is compared, not evidence content, trace correctness, source association, or artifact integrity.

Thus the non-binary separation is partial: `INCONCLUSIVE` is preserved, but tool errors are collapsed into it, and unsupported/environment distinctions rely on free-text heuristics.

## 6. Per-checker audit and required case coverage

`Present` means an explicitly cataloged case exists; it does not certify checker correctness. Counts are from the actual 45-case catalog.

| Checker | Audit and required cases |
|---|---|
| **CTL (8)** | True property, false property, cycle, deadlock, and multiple initial states (safe and unsafe) are present. **Branching behavior is MISSING**: current catalog graphs do not provide a branch with alternative successor paths. Unknown atom is a specification error. Cases exercise finite explicit graphs, not source-derived semantics. |
| **BMC (5)** | Counterexample within bound, no counterexample below bound, complete safe bound, timeout, and a cyclic safe graph are present. The below-bound case remains `INCONCLUSIVE`; completeness is correctly scoped to the supplied finite graph. **An explicit branching graph case is MISSING.** |
| **SMT (7)** | SAT/violation model, UNSAT/safe bounded domain, unknown backend, timeout, type mismatch, and unsupported division are present. SAT case exercises counterexample evidence. **Unknown variable is MISSING**: `x` is declared in the generated specification for all current expressions. Controlled backends test classification, not solver reliability. |
| **Static (4)** | Clean scan, intended null dereference, compiler warning, and unavailable analyzer are present. All expected statuses are `INCONCLUSIVE` or `TOOL_ERROR`, so there are **no independently scored static TP/TN/FP/FN fixtures**. The expected defect/analyzer behavior is not independently adjudicated. **Syntax error and unsupported construct cases are MISSING.** |
| **Memory (6)** | Intended safe execution, heap overflow, use-after-free, double-free, leak, and unavailable sanitizer are cataloged. On this Windows run, all six observations were `UNSUPPORTED` due to sanitizer/compiler runtime limitations, so **none of safe/overflow/UAF/double-free/leak behavior was verified here**. No independent defect oracle beyond the defect fixtures/analyzer outcome is retained. |
| **Dynamic (5)** | Passing oracle, failing oracle, build error, timeout, and abnormal termination are present. Timeout and abnormal termination are controlled execution-result fixtures; these cases validate classification/oracle wiring, not OS/process backend reliability. |
| **Fuzzing (5)** | Known crash, bounded no-finding, timeout, oracle violation, and coverage expansion are present. No finding remains inconclusive. Crash and timeout observations include controlled runners; coverage expansion depends on available GCC/gcov. The catalog does not test campaign reproducibility across engines/platforms. |
| **Coverage (5; measurement only)** | Zero/partial/full line ratio, branch ratio, and measurement while oracle fails are present. All are `INCONCLUSIVE` measurement observations, never safety PASS/FAIL. This separation is represented in the model guard, comparator, report, and tests. Coverage is excluded as a safety checker. |

## 7. Run observations and environment limitations

Command run: `python -m seclab.benchmark --output t\q\benchmark-audit.json --markdown t\q\benchmark-audit.md`.

- 45 cases executed; exit code 1 due to six expected-vs-actual mismatches.
- `MEM-001`–`MEM-005` expected a sanitizer result, but actual status was `UNSUPPORTED`; `MEM-006` expected its controlled unavailable-path `INCONCLUSIVE`, but actual was also `UNSUPPORTED` because this built-in adapter checks the host compiler/runtime first. All six were classified as environment limitations, not FN.
- No FP/FN were reported. This does not establish high accuracy: static has no binary outcomes and memory has zero conclusive outcomes; several other cases are inconclusive by design.
- BMC, CTL, SMT, dynamic, fuzzing, and coverage outcomes agreed with their declared cases in this run. This validates only these fixtures/adapter executions.
- The report does not capture host/environment metadata, raw logs, or evidence artifacts, reducing reproducibility and reviewability.

## 8. TASK 3 gaps / minimum contract

Do not infer accuracy from unit-test success or these small fixture counts. TASK 3 should address, at minimum:

1. Add the missing cases listed above: CTL branching; BMC branching; SMT unknown variable; static syntax error and unsupported construct. Add controlled, independently specified cases where a missing state is important to the intended checker scope.
2. Make ground-truth basis explicit per case (mathematical finite model/oracle, fixture defect rationale, or controlled environment condition), separate from the checker adapter, and preserve limitations.
3. Use a typed result taxonomy that keeps `TP`, `TN`, `FP`, `FN`, `INCONCLUSIVE`, `UNSUPPORTED`, `ENVIRONMENT_LIMITATION`, and `TOOL_ERROR` distinct. Do not map tool errors to inconclusive or derive environment classification from free text. Keep specification/build outcomes explicit as suitable.
4. Define confusion-matrix scoring from expected and actual finding presence, while preserving status, finding, checker, property, and evidence mismatches as separate dimensions. Never convert non-binary outcomes into FN/FP.
5. Persist evidence references/payload metadata and verify evidence relevant to each case; distinguish an evidence-type label from actual evidence validation.
6. Record run timestamp, platform, tool versions, skip/limitation reasons, and current report provenance; make the generated report reproducible and avoid treating a stale checked-in report as current.
7. Add analyzer defect-free/defect-positive cases with an independent oracle, and run supported sanitizer cases in an environment that can execute them. Report unsupported/environment-limited denominators transparently.

Minimum per-case contract: immutable case ID and input; checker and scope; independent expected finding/status plus ground-truth basis; explicit allowed non-binary outcomes; actual normalized outcome; evidence references and validation requirements; classification result and reason; environment/tool metadata. Reports remain checker-local and must never create a project verdict.

## 9. Final assessment

- **Accuracy benchmark present:** Yes; executable runner, case catalog, adapters, comparator, metrics, JSON/Markdown reports, and benchmark tests exist.
- **Trustworthy broad checker accuracy established:** No. Results are fixture-limited and several categories lack required independent positive/negative coverage.
- **Benchmark with useful supported ground truth:** CTL, BMC, SMT, dynamic, and fuzzing have independently declared controlled scenarios with meaningful but narrow scope. Coverage has useful measurement ground truth only. Static has fixture expectations but no binary accuracy scoring. Memory cannot be assessed on this host.
- **Ground-truth leak:** No production catalog-generation leak found. The mutation test helper intentionally copies expected values into synthetic observations; it is not independent checker evidence.
- **Next work:** the gaps in section 8 belong to TASK 3. No TASK 3, mutation-testing expansion, or GUI work was performed.
- **Final regression:** `python -m pytest -q --basetemp=t\q` — 282 passed, 5 skipped, 0 failed (185.84s); `python -m compileall -q src tests` — passed.

