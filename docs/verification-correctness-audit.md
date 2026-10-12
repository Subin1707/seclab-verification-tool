# Verification Correctness and Trustworthiness Audit

**Audit date:** 2026-10-04  
**Final assessment:** PARTIALLY VERIFIED  
**Scope:** Existing generic checker semantics, benchmark evidence, and result/evidence classification. This audit does not assess GUI runtime (Task 5C remains blocked by unavailable PySide6).

## 1. Baseline and executed audit

Before examining or changing checker code, the required baseline completed:

- `python -m pytest -q --basetemp=t\q` — **298 passed, 5 skipped, 0 failed** (209.22s).
- `python -m compileall -q src tests` — **PASS**.

No checker, benchmark, specification, GUI, or Smart-EV implementation was changed for this audit. The full 58-case benchmark was run with the production adapters and persisted under `t\q\task6-benchmark-workspace\task6-audit`; JSON and Markdown summaries were written under `t\q`. The CLI returned exit code 1 because five expected binary Memory cases were environment-limited. The final regression and compileall are recorded in §18 after the report is complete.

The catalog contains 58 cases: CTL 10, BMC 7, SMT 10, Static 9, Memory 6, Dynamic 6, Coverage 5, Fuzzing 5. A separate benchmark unit test runs the production adapters for the 52 non-Memory cases; the CLI run above exercised all 58 catalog cases.

## 2. Trust model and terms

- **Fixture-scope soundness** means that a conclusive result agrees with the declared semantics for the exact model, formula, source, inputs, tools, and execution scope recorded in that case. Agreement on a small synthetic catalog is not a proof of general checker soundness.
- **Fixture-scope completeness** means that the catalog detects the included known violations and avoids findings on its included clean fixtures. It does not mean all violations in a program/model will be found. Recall is meaningful only for the catalog's positive cases and verified environment.
- **Bounded verification** examines only an encoded finite depth, finite graph, finite domain, or fixed campaign budget. An UNSAT result below a completeness threshold and a fuzz run with no finding are not general proofs.
- **Environment limitation** means the checker could not be evaluated because a required compiler, analyzer, sanitizer, runtime, or backend capability was not established. It is neither a true negative nor a false negative.
- **INCONCLUSIVE** means the check ran or was attempted but did not yield a conclusive property result (for example timeout, UNKNOWN, bounded search below completeness, unasserted abnormal termination, or measurement-only work).
- **TOOL_ERROR** means a required tool/backend or infrastructure operation failed. **BUILD_ERROR** means the subject or generated verification harness did not build. Neither is a property FAIL.
- **UNSUPPORTED** means the requested capability/target is outside the adapter's implemented or available scope. **SKIPPED** means a stage/case was not executed under the applicable lifecycle. In the benchmark report these have distinct categories; the core `VerificationStatus` enum does not contain `UNSUPPORTED`, `ENVIRONMENT_LIMITED`, or `SKIPPED` (stage skip is lifecycle state, while unsupported paths generally use INCONCLUSIVE plus a reason code).
- **PASS/FAIL** are scoped results only. Static no-finding, coverage, and a bounded fuzz run do not become safety PASS. A scoped clean instrumented memory execution can PASS only for that binary/input/runtime execution.

Nothing in this audit supports “100% correct”, “formally verified” for the complete tool, or “production-safe”.

## 3. Per-checker results

### CTL — PARTIALLY VERIFIED

- **What was tested:** Formula parser/validator and fixed-point evaluator tests cover Boolean operators, EX/AX/EF/AF/EG/AG/EU/AU, branching state sets, cycles, deadlocks, multiple initial states, missing atoms, empty initial sets, AG/AX counterexamples, and EF/EX witnesses. The 58-case run exercised all ten CTL cases, including unsafe/safe multi-initial and branching fixtures.
- **Ground truth:** Small explicitly authored Kripke graphs and formulas. Expected values can be derived from labels and edges; provenance is catalog-authored manual reasoning, not independent third-party validation.
- **Observed vs expected:** All ten CTL benchmark rows matched. The run produced 3 binary positives and 6 binary negatives; one input-error case was not binary-scored. The tests independently assert selected state sets and paths.
- **Correctness finding:** The evaluator rejects unknown atoms and empty initial sets rather than converting them to PASS/FAIL. Its documented virtual-self-loop deadlock semantics are exercised. However, `check()` constructs a counterexample only for failed AG and AX, and witnesses only for successful EF and EX. Other formulas can yield a conclusive FAIL without a counterexample path/tree in `CTLCheckResult`; `classify_ctl_result()` also does not include the returned witness/counterexample or satisfying-state set in `VerificationResult` evidence metadata. Thus the Boolean result is exercised on fixture semantics, but the required FAIL-to-valid-counterexample evidence contract is incomplete.
- **Evidence:** Unit tests assert AG/AX counterexample and EF/EX witness paths. Benchmark artifacts preserve model and normalized result payloads. The benchmark observation uses evidence type labels (`counterexample`, `proof-or-result`) rather than checker-issued, typed CTL proof artifacts.
- **Limits:** No independent oracle validates arbitrary/nested CTL proof objects; no generalized proof-tree evidence is emitted for all temporal operators. Finite graph/label/transition semantics are not source-code semantics, and transition guards/actions are metadata only.

### BMC — PARTIALLY VERIFIED

- **What was tested:** Real-Z3 and unit tests cover depth 0/1/k, shortest SAT path, path length of `k+1` states, multiple initial states, branching, cycles, reachable/unreachable states, trace transition validation, timeout/UNKNOWN/error classification, and finite-graph completeness threshold. Seven benchmark cases ran.
- **Ground truth:** Explicit finite Kripke graphs with manually determined shortest bad-state reachability and bounds. Controlled UNKNOWN/timeout backends are classification fixtures, not solver wall-clock tests.
- **Observed vs expected:** All seven cases matched: 3 FAIL counterexamples, 1 complete-bound PASS, and 3 INCONCLUSIVE cases (including incomplete UNSAT and controlled timeout). BMC and CTL agree on selected safe/violating complete graphs.
- **Correctness finding:** The `UP_TO_BOUND` search checks from depth zero and stops at the first SAT trace. `decode_trace()` validates that returned state IDs form a legal graph path and include the bad proposition. UNSAT is PASS only when the checked depth reaches the maximum shortest distance of all reachable graph states; otherwise it is INCONCLUSIVE. The tests support these finite-graph claims.
- **Evidence:** Tests verify query/completeness/counterexample artifacts and SHA-256 for stored BMC evidence. Benchmark observations retain a normalized query/result payload plus labels, not the BMC checker’s temporary ArtifactStore records.
- **Limits:** Completeness is only for bad-state reachability in the supplied explicit finite graph. Transition guards/actions and program behavior are not encoded. Timeout is injected via a controlled backend; live timeout reliability is not measured by the benchmark.

### SMT — PARTIALLY VERIFIED

- **What was tested:** Parser precedence/syntax, supported arithmetic/Boolean operators, unknown variables, type mismatch, Boolean/integer/real/string finite domains, bounds, SAT/UNSAT/UNKNOWN, timeout mapping, missing SAT model, and real Z3 bounded-domain examples. Ten benchmark cases ran.
- **Ground truth:** Manually derived bounded formula/domain cases; actual Z3 is used for production adapter cases except controlled UNKNOWN/timeout.
- **Observed vs expected:** All ten benchmark rows matched. Binary scoring was 2 TP and 3 TN; 2 controlled backend cases were inconclusive and 3 specification-error/unsupported-input cases were non-binary.
- **Correctness finding:** `VIOLATION_SEARCH` encodes constraints and domains together with `¬property`; SAT maps to FAIL only if a model is returned, UNSAT maps to a scope-limited PASS, UNKNOWN/timeout to INCONCLUSIVE, and backend ERROR to TOOL_ERROR. `SATISFIABILITY` intent does not become a property verdict. This is covered by tests.
- **Evidence:** Real-Z3 tests assert model assignments and artifact hashes for selected SAT/UNSAT cases. Query/outcome/model artifacts are stored when an ArtifactStore is passed. The verifier itself does not independently re-evaluate a returned backend model against the encoded query; production relies on Z3’s model contract. Benchmark payloads include normalized query/backend/result objects, not independently replayed proofs.
- **Limits:** PASS means no violating valuation exists in one encoded valuation over declared domains and constraints. It says nothing about transition/time behavior. Real wall-clock timeout behavior and independent model validation are not established by the fixture suite.

### Static analysis — PARTIALLY VERIFIED

- **What was tested:** Cppcheck XML, compiler and Clang-Tidy diagnostic parsing, path/severity/CWE normalization, known source snippets, missing analyzer handling, and real integrations conditional on installed tools. The catalog has six Cppcheck cases, two compiler-diagnostics cases, and one missing-tool case.
- **Ground truth:** Synthetic clean/defective source semantics manually declared in the catalog. Analyzer detection is observed independently by running the analyzer/compiler. The defect labels are not an external adjudication dataset.
- **Observed vs expected:** All nine benchmark rows matched in this environment. The six Cppcheck cases were all semantically INCONCLUSIVE; their separate finding-presence signal yielded 5 TP and 1 TN on these fixtures. The compiler-diagnostics malformed-source case was TOOL_ERROR; the missing analyzer was TOOL_ERROR.
- **Correctness finding:** Clean scans do not become PASS; findings also remain INCONCLUSIVE because they are reports, not confirmed property violations. Missing tools and failed execution do not become safety FAIL. One parser limitation remains: malformed Cppcheck XML returns an empty finding tuple, and a successful command can consequently be reported as “no static findings” (still INCONCLUSIVE, not PASS). The status avoids a false safety PASS, but the reason can imply a clean parse when parsing failed.
- **Evidence:** Real integration tests preserve raw command output/findings, hash evidence, and verify source bytes unchanged. Benchmark adapter payloads include analyzer output and normalized findings, but no per-source source hash is attached to each finding/result.
- **Limits:** Fixture-level detection does not establish analyzer completeness/soundness. Static metric `TP/TN` concerns finding presence, while VerificationResult remains INCONCLUSIVE; benchmark `conclusive_rate` therefore describes its binary finding channel, not conclusive verification statuses. No independent large clean/vulnerable corpus or unsupported-construct coverage was exercised.

### Memory analysis — ENVIRONMENT LIMITED

- **What was tested:** Parser unit tests cover ASan heap/stack/global overflow, use-after-free, double/invalid-free, LeakSanitizer and UBSan signed overflow/shift/division/alignment patterns. Conditional integration tests cover real overflow and signed-overflow fixtures, clean ASan/UBSan runs, and leak detection when supported.
- **Ground truth:** Synthetic C operations with manually known defect/safe intent. The audit host is Windows, where these sanitizer tool/runtime cases are not established.
- **Observed vs expected:** In the full catalog run, `MEM-001`–`MEM-005` returned ENVIRONMENT_LIMITED (sanitizer/runtime unavailable); `MEM-006` matched its explicitly environment-limited expectation. There were 5 expected-vs-actual mismatches, 6 environment-limited rows total, and **zero conclusive Memory observations**. No memory FP/FN was counted.
- **Correctness finding:** A recognized sanitizer report maps to scoped FAIL; completed allowed-exit instrumented execution with no finding maps to scoped PASS; timeout maps to INCONCLUSIVE; tool/runtime unavailable is not a clean PASS; unexplained unsuccessful termination without a recognized report remains UNKNOWN/INCONCLUSIVE. Existing tests exercise these branches conditionally and parsers preserve raw finding kinds.
- **Evidence:** Conditional integration tests verify artifact hashes when sanitizer support exists. The current host benchmark retained environment diagnostic payloads for unsupported cases, not real sanitizer output for defect cases.
- **Limits:** Runtime detection accuracy is unverified on this host. No inference about ASan/UBSan/LeakSanitizer reliability follows from parser fixtures or catalog intent. This category is environment-limited, not a checker pass.

### Dynamic testing — PARTIALLY VERIFIED

- **What was tested:** Independent declared-oracle comparisons against return value/stdout/stderr/exit code/no-crash observations, no-oracle behavior, timeouts, build errors, abnormal termination, unsupported function signatures, and batch continuation after a failed case. Six benchmark cases ran.
- **Ground truth:** A test’s expected behavior is a declarative oracle; observations are produced from program execution/harness return markers or process records, not copied from that expected value. The oracle and implementation are separate inputs, though oracle quality remains an external assumption.
- **Observed vs expected:** Benchmark rows matched: DYN-001 PASS, DYN-002 FAIL, DYN-003 BUILD_ERROR, DYN-004/DYN-005 INCONCLUSIVE, DYN-006 UNSUPPORTED. Confusion count was 1 TP and 1 TN; other rows were non-binary.
- **Correctness finding:** `_classification()` gives timeout, source-integrity failure, observation parse failure, unasserted crash, build failure, and process execution failure precedence over oracle verdicts. A single failed testcase does not prevent `run_many()` from recording subsequent cases. No explicit oracle produces INCONCLUSIVE, not PASS.
- **Evidence:** TestRunner writes testcase, build/command output, observation, oracle evaluation, source-integrity hashes, and a result artifact; tests exercise these interfaces. Benchmark retains a normalized execution payload. `case.expected_property` is passed as property metadata and copied into `actual_property`; this makes property attribution in the benchmark report tautological, although the TP/FP/FN finding classification uses observed status/finding rather than that field.
- **Limits:** Oracle correctness is not established by checker execution. Controlled abnormal-termination cases validate mapping, not OS crash reliability. Test behavior is limited to explicitly supplied input/cases.

### Fuzzing — PARTIALLY VERIFIED

- **What was tested:** Unit/integration tests cover reproducible seeds, oracle failures, crash-vs-timeout distinction, bounded no-finding, coverage feedback, mutation/corpus/minimization helpers, and source integrity. Five benchmark cases ran.
- **Ground truth:** Deterministic target/oracle/seed and budget declarations. Known crash and timeout benchmark paths include controlled process-result fixtures; the known-crash adapter does not rely solely on a live OS crash observation.
- **Observed vs expected:** All five rows matched: crash and oracle-seed cases FAIL under explicit failure oracles; bounded-clean, timeout and coverage-increase cases remain INCONCLUSIVE. Two binary positives, no binary negative fixture; accuracy is N/A.
- **Correctness finding:** The engine classifies crash as a property failure only when the template requires NO_CRASH; timeout and no finding remain INCONCLUSIVE; tool/source/coverage setup failures are not safety outcomes. Failure signatures are deduplicated, raw and minimized inputs can be retained, and iteration/time budgets are explicit.
- **Evidence:** Campaign results retain run parameters, input/failure artifacts, command/output records, oracle observations, and coverage deltas where applicable. Benchmark evidence is normalized campaign payload and typed labels.
- **Limits:** No positive/negative balanced fuzz accuracy denominator. The known-crash benchmark uses a controlled abnormal ProcessRunner outcome, so it validates campaign classification more than real crash detection. Fuzz correctness depends on oracle, seed, strategy, and budget.

### Coverage — MEASUREMENT ONLY

- **What was tested:** Line/branch parsing, malformed records, zero denominator, partial/full percentages, suite aggregation, deltas, generated harness exclusion, source integrity, and preserving measured coverage when an oracle fails.
- **Ground truth:** Four of the five catalog cases use manually declared synthetic counters/ratios; the oracle-failure case stores separate declared expected/actual values. These cases exercise counter aggregation, not a real test execution. Fuzz coverage-guided case separately uses the backend when available.
- **Observed vs expected:** All five measurement rows matched. All five result statuses are INCONCLUSIVE; none contributes safety TP/TN/FP/FN. No coverage PASS/FAIL or project verdict was created.
- **Correctness finding:** Zero denominator yields undefined/N/A; line and branch ratios aggregate separately; source hashes and backend evidence are retained; oracle failure does not discard collected coverage. The catalog’s COV-005 derives its ORACLE_VIOLATION signal by comparing `oracle_expected` and `oracle_actual` values placed in the scenario, rather than running an independent testcase. This validates measurement/report wiring, not independent oracle observation.
- **Evidence:** Unit/integration tests verify real backend outputs and hashes when available; synthetic counter tests check arithmetic. Benchmark retains normalized measurement payloads.
- **Limits:** Coverage is execution measurement only. Backend-specific branch semantics vary; counter fixtures do not establish source instrumentation accuracy. No inference from coverage percentage to safety is valid.

## 4. Result classifier audit

The core classifier maps `PROPERTY_SATISFIED → PASS`, `PROPERTY_VIOLATED → FAIL`, `UNKNOWN/TIMEOUT → INCONCLUSIVE`, `TOOL_FAILED → TOOL_ERROR`, `BUILD_FAILED → BUILD_ERROR`, `INVALID_SPEC → SPEC_ERROR`, and `NOT_RUN → NOT_RUN`. Static results deliberately use UNKNOWN for both clean and finding-present scans. Memory runtime and dynamic test oracles use PASS/FAIL only when their scoped observation/oracle supports it. Fuzz uses UNKNOWN for no finding and timeout. Coverage has no property PASS outcome.

Classifier tests exercise canonical serialization, unknown outcomes, and several tool/build/timeout mappings. The canonical `VerificationStatus` set does not include UNSUPPORTED, ENVIRONMENT_LIMITED, or SKIPPED. Those conditions are represented by a mix of INCONCLUSIVE/SPEC_ERROR/TOOL_ERROR plus reason codes and separate benchmark/stage lifecycle states. This is understandable but not a single normalized end-to-end status vocabulary; consumers must inspect reason code and stage status.

| Input condition | Expected semantic state | Observed handling | Assessment |
|---|---|---|---|
| CTL/BMC/SMT or dynamic property satisfied within declared scope | PASS | PASS | Correct on tested fixtures, scope-limited |
| Valid property counterexample / explicit oracle mismatch | FAIL | FAIL | Correct on tested fixtures; CTL counterexample evidence incomplete for some formula forms |
| Timeout / solver UNKNOWN / incomplete bounded search | INCONCLUSIVE | INCONCLUSIVE | Correct on tested fixtures; controlled timeout cases do not measure live timeout reliability |
| Missing checker/backend infrastructure | TOOL_ERROR or explicit unsupported/environment reason | TOOL_ERROR, UNSUPPORTED, ENVIRONMENT_LIMITED or INCONCLUSIVE by subsystem | No observed false PASS/FAIL; vocabulary differs by subsystem |
| Build failure | BUILD_ERROR | BUILD_ERROR for compile failure; tool execution failures remain TOOL_ERROR | Correct on tested dynamic fixture |
| Malformed specification/formula/type | SPEC_ERROR / CTL error | Structured input error or SPEC_ERROR | Not a property FAIL; tested for CTL/SMT input cases |
| Empty/no-result static scan | INCONCLUSIVE | INCONCLUSIVE | Correct status; malformed Cppcheck output may have misleading no-finding reason |
| No fuzz finding / timeout without property oracle | INCONCLUSIVE | INCONCLUSIVE | Correct on tested cases |
| Coverage measurement | Measurement-only / no property verdict | INCONCLUSIVE measurement envelope | Correct separation |
| Stage not requested/dependency skipped | NOT_RUN or SKIPPED lifecycle | NOT_RUN result or separate SKIPPED stage state | Distinct layers; inspect both |

## 5. Evidence independence and traceability

The full benchmark run manifest has 58 case chains and 292 referenced artifacts: 58 fixtures, 58 ground-truth records, 58 observations, 58 comparisons, and adapter evidence records. I re-resolved each referenced path inside the run workspace and recalculated SHA-256: **292/292 references valid**, no missing/out-of-workspace paths or hash mismatch in this run. The report contains no `overall_verdict`, `overall_status`, `project_pass`, or `project_fail` key.

This validates artifact integrity for this run, not authenticity of ground truth or semantic validity of every payload. Fixture, ground truth, observation and comparison are colocated and hashed by the same runner. Hashes prove bytes have not changed relative to the manifest; they do not prove the ground-truth author was independent. Static/dynamic/memory adapters often persist normalized evidence payloads; checker-native artifacts created inside temporary adapter workspaces are not always retained as directly resolvable references. CTL adapter records model/result data but labels its evidence as `proof-or-result`; for arbitrary CTL failures that is not a validated counterexample. Source fixtures have fixture hashes, while per-result source hash linkage is not universal.

The Task 3B/3C mutation suite reports 9/9 observation-boundary mutations detected from clean baselines. These mutate observations/scorer inputs (and use small concrete hash/reference fixtures for evidence/trace cases); they do not patch and execute mutated production checker binaries. This is useful scorer-sensitivity evidence, not checker implementation mutation coverage.

## 6. Accuracy benchmark review

The 58-case CLI run reported:

- **False positives: 0; false negatives: 0.** This is a count on conclusive scored fixture outcomes, not a general error-rate estimate.
- BMC: 3 TP / 1 TN / 3 inconclusive; SMT: 2 TP / 3 TN / 2 inconclusive; CTL: 3 TP / 6 TN / one non-binary input error.
- Static finding channel: Cppcheck 5 TP / 1 TN, with all six VerificationResults INCONCLUSIVE; compiler diagnostic cases are not balanced (one finding signal and one TOOL_ERROR); missing analyzer is TOOL_ERROR.
- Memory: 0 conclusive cases; five environment-limited mismatches and one expected/actual environment-limited case. No Memory TP/TN/FP/FN was counted.
- Dynamic: 1 TP / 1 TN plus non-binary build, timeout, abnormal, and unsupported cases. Fuzzing: 2 positive cases and no binary negative; accuracy N/A. Coverage is not binary-scored.
- DYN-006 was UNSUPPORTED, not FN. Environment-limited Memory rows were not converted to FN/FP.

Ground truth is catalog-authored synthetic/manual fixture reasoning; provenance strings and hashes are recorded. They do not constitute external certification or independent expert adjudication. Production adapters do not derive expected status from checker status, but there are attribution/data independence gaps: CTL, BMC, SMT, dynamic, and fuzz adapters pass `case.expected_property` as result metadata and expose it as `actual_property`; this makes the property-match dimension tautological. It does not feed the primary TP/FP/FN status/finding classifier, but it can make the broad `matched` field look stronger than independently observed property attribution. In COV-005 the benchmark scenario supplies both `oracle_expected` and `oracle_actual`; the adapter compares those scenario fields instead of executing a testcase oracle. Neither issue was changed because Task 3B/3C benchmark semantics/catalog are frozen for this audit.

Accordingly, existing 100% accuracy fields are only observed fixture-level ratios for the listed conclusive cases. They are not “checker accuracy” guarantees. Inconclusive, unsupported, environment-limited, tool-error, build-error, and skipped cases remain outside binary FP/FN scoring.

## 7. Cross-checks

- **CTL ↔ BMC:** Integration tests compare selected safe and violating complete finite graphs; results agree on these graph fixtures. The two tools do not provide independent ground truth for one another.
- **SMT arithmetic:** Real Z3 tests check selected bounded numeric, Boolean, real and string formulas against explicit expected assignments/statuses; no broad external solver cross-validation was run.
- **Dynamic:** Concrete C executions and explicit return/process oracles are tested; oracle correctness remains assumed.
- **Static/Memory:** Known vulnerable snippets are passed to available analyzers/sanitizers in conditional integration tests. Memory runtime was unavailable for the benchmark cases on this Windows environment.
- **Fuzz:** Seeded concrete oracle and coverage cases exercise campaign plumbing; the known-crash benchmark uses a controlled runner outcome.

## 8. Environment limitations

The host is Windows 11, Python 3.12.5, AMD64 64-bit. The PySide6 GUI runtime remains blocked (Task 5C) and was not part of this audit. Memory benchmark cases were environment-limited because sanitizer instrumentation/runtime support was not established. These facts limit runtime coverage; they are not checker false negatives.

## 9. Known limitations and remaining risks

1. CTL conclusive FAIL is not paired with a general validated counterexample/proof artifact for every formula form; the adapter also omits available path evidence from the normalized VerificationResult.
2. SMT trusts the selected backend’s SAT model and does not independently validate every returned model against the encoded query.
3. Static malformed Cppcheck XML can collapse to an empty finding tuple and a “no findings” reason, although status remains INCONCLUSIVE.
4. Benchmark `actual_property` is copied from expected catalog metadata for several adapters; COV-005 compares scenario-supplied expected/actual values instead of a live testcase oracle.
5. Memory runtime correctness is not verified on this host; there were no conclusive sanitizer observations.
6. Static/fuzz catalog denominators are narrow; fuzzing lacks a binary negative case, and coverage is measurement-only by design.
7. Hash integrity is strong for the audited benchmark artifact set but does not establish ground-truth authenticity or semantic evidence sufficiency.
8. The 9 mutation checks are observation-boundary mutations, not production-source mutation testing.
9. `UNSUPPORTED`, `ENVIRONMENT_LIMITED`, and `SKIPPED` are not members of the core `VerificationStatus` enum; interpretation relies on reason codes and stage/benchmark lifecycle fields.
10. GUI launch/workflow remains unverified due PySide6 absence.

## 10. Recommended next work

1. Add formula-family-specific CTL counterexample/proof structures and require their validation before presenting a conclusive FAIL as evidence-backed.
2. Independently evaluate SAT assignments against encoded SMT constraints/property before classifying them as a violation witness, or explicitly narrow the backend trust boundary.
3. Make analyzer parse failure distinct from a successful no-finding parse while preserving static-result INCONCLUSIVE semantics.
4. Separate checker-observed property identity from catalog expected-property metadata; represent unobserved identity as unavailable rather than echoing the expected field. Keep frozen benchmark compatibility explicit in a separately versioned contract change.
5. Replace the COV-005 scenario comparison with a real testcase observation and independent oracle evaluation in a future benchmark contract revision.
6. Run Memory fixtures in a supported sanitizer environment and retain native raw output/result references.
7. Expand independent positive/negative fixtures where a binary score is intended; keep controlled timeout/error cases outside accuracy denominators.
8. Add production-source mutation execution if implementation mutation resistance is a required claim.
9. Unify status vocabulary or document adapters from subsystem-specific outcomes to core statuses without losing unsupported/environment/skip distinctions.
10. Complete GUI runtime verification separately in an environment with PySide6; no GUI claims are made here.

## 11. Final assessment

- Checker semantics are **partially verified on explicit fixtures**. The audit found no observed false PASS/FAIL caused by timeouts, missing tools, unsupported capability, clean static scans, no-finding fuzz runs, or coverage measurements in the executed benchmark.
- The current evidence does **not** establish broad checker correctness or completeness. CTL evidence coverage, SMT model validation, environment-dependent Memory runtime, benchmark property attribution, and controlled fuzz crash evidence remain material limits.
- The 58-case benchmark had zero FP/FN on scored outcomes, but that does not establish general checker accuracy. Five Memory mismatches were environment-limited and excluded from FP/FN; one Dynamic case remained UNSUPPORTED.
- Benchmark evidence artifact paths/hashes were valid for all 292 references in this run; semantic independence/authenticity is only partially established.
- No overall project verdict was created. No Specification contract, benchmark catalog/comparator semantics, checker code, or Smart-EV repository was modified.

**TASK 6 FINAL STATUS: PARTIALLY VERIFIED.** Checker-specific gaps remain; no blanket correctness claim is made.

## Task 6B addendum — 2026-10-05

This addendum records the follow-up hardening; the Task 6 findings above are historical and are superseded only where this section explicitly closes them.

### Baseline and changes

- Pre-change baseline: `python -m pytest -q --basetemp=t\q` — **298 passed, 5 skipped, 0 failed**; `python -m compileall -q src tests` — **PASS**.
- CTL now independently re-evaluates the supported CTL semantics when validating AG/AX counterexample traces. It checks initial state membership, every graph edge (including the documented virtual deadlock self-loop), and the violating terminal condition. Classification revalidates the trace. A missing/invalid trace, or a false result whose formula needs a tree/lasso certificate not represented by the current result format, maps to TOOL_ERROR and cannot become FAIL.
- SMT now reconstructs backend assignments with strict declared types and uses a safe internal AST evaluator (no `eval`/`exec`) to check finite domains, bounds, all specification constraints, and the encoded query expression. An invalid or missing SAT model is retained as the backend model, classified as `SOLVER_INVALID_MODEL` / TOOL_ERROR, and never repaired or retried. `SolverOutcome` and `VerificationStatus` enums are unchanged; SAT intent remains non-verdict INCONCLUSIVE when its model validates.
- Benchmark formal, dynamic, fuzz, static, and memory adapters no longer copy catalog `expected_property` into observed property metadata or pass it into checker calls. Missing observed property identity remains `null`; the comparator treats it as unavailable metadata rather than a contradictory identity. Expected fields remain solely in ground truth and comparator logic.
- COV-005 now runs its declared function testcase through `CoverageRunner` and `TestRunner`. The oracle compares the observed return value with the fixture's separate testcase oracle. Coverage is taken from actual instrumented execution and remains measurement-only/INCONCLUSIVE even when the testcase oracle fails. The fixture no longer contains `oracle_expected` / `oracle_actual` observation shortcuts; expected status/finding/evidence remain unchanged.
- Benchmark artifact metadata now distinguishes `FIXTURE`, `GROUND_TRUTH`, `CHECKER_OBSERVATION`, and `COMPARISON`. The run metadata records source hashes for the adapters, CTL validator, and SMT evaluator.

### Regression and rerun results

- Added CTL counterexample regressions for valid AG/AX traces, absent certificates, unknown states, illegal transitions, non-initial starts, and a non-violating terminal label. Classifier-level tests ensure malformed/missing certificates are TOOL_ERROR.
- Added SMT model checks for valid SAT valuation, intentionally corrupted valuation, type mismatch, unsupported operator, Boolean and real values, integer bounds, finite domains, and negated-property query semantics. Invalid SAT is not retried.
- Added expectation-mutation tests for Dynamic and Static observations; changed expected status/finding/property/evidence leaves checker status, finding, observed output, and oracle result unchanged.
- Added COV-005 real execution/coverage assertions and evidence classification/hash-resolution checks. Representative reruns cover CTL-001, BMC-001, SMT-001, STATIC-001, DYN-001, and COV-005; status/finding/comparison classification remain stable and every persisted observation hash resolves. Raw evidence hashes can still differ between fresh Dynamic/Static/Coverage executions because process durations, temporary paths, and generated run identifiers are execution-specific; this is recorded rather than normalized away.
- The original Task 6 benchmark result under `t\q\task6-benchmark*` was not modified. The Task 6B run uses a separate execution ID and workspace.
- No expected status/finding/evidence was changed to improve metrics. Property attribution mismatches caused by removing expected-property echo are report mismatches, not FP/FN. Environment-limited Memory cases remain separately classified, and unsupported/inconclusive cases remain non-binary.

### Remaining limits and status

- The CTL result format represents a linear path, not general branching proof trees or lasso certificates. Only AG and AX violations with validated paths can be reported as FAIL by this path; unsupported certificate forms are TOOL_ERROR pending a richer evidence contract.
- This host may not support native sanitizer runtime checks; the five historical Memory cases were environment-limited. No Memory accuracy claim follows.
- COV-001 through COV-004 remain synthetic aggregation fixtures; COV-005 is the actual execution case. Coverage never creates a safety verdict.
- Static no-finding remains INCONCLUSIVE, malformed analyzer-output parsing remains a known limitation from Task 6, and fuzz no-finding remains INCONCLUSIVE. The controlled fuzz crash does not establish operating-system crash detection reliability.
- Fresh-run raw evidence hashes for process-backed cases may vary due execution metadata even where semantic observation and comparison classification are stable.
- This work does not establish general tool correctness or accuracy from passing tests. No overall project verdict, GUI feature, Smart-EV behavior, Specification JSON contract, or expected benchmark outcome was introduced.

### Final Task 6B verification results

- Final `python -m pytest -q --basetemp=t\q` — **308 passed, 5 skipped, 0 failed** (223.85s).
- Final `python -m compileall -q src tests` — **PASS**.
- Full CLI: `python -m seclab.benchmark --output t\q\task6b-final2-benchmark.json --markdown t\q\task6b-final2-benchmark.md --workspace t\q\task6b-final2-workspace --execution-id task6b-final2` — **58 cases**, exit code **1** because six rows did not fully match. This is the actual CLI exit contract, not an overall project verdict.
- Final benchmark: **0 FP, 0 FN**; 22 inconclusive, 1 unsupported, 6 environment-limited, 2 tool errors, 1 build error, 0 skipped. Per-checker scored counts: BMC 3 TP/1 TN; CTL 3 TP/6 TN; SMT 2 TP/3 TN; Cppcheck 5 TP/1 TN; compiler diagnostics 1 TP (no negative class); Dynamic 1 TP/1 TN; Fuzzing 2 TP (no negative class). These small fixture counts and method changes do not establish general accuracy or an accuracy improvement.
- Six mismatches: `MEM-001`–`MEM-005` are ENVIRONMENT_LIMITED on this host, and `COV-005` has expected measurement label 50% versus actual measured line coverage 100%. COV-005 status and oracle finding match; coverage remains INCONCLUSIVE/measurement-only. Expected outcomes were not changed. `MEM-006` remains an expected/observed environment limitation and is not a mismatch.
- The final full benchmark produced **292/292 valid evidence references**, with zero invalid paths/hashes and zero unreferenced evidence files. Role counts are FIXTURE 58, GROUND_TRUTH 58, CHECKER_OBSERVATION 118, COMPARISON 58. The historical Task 6 artifacts were not overwritten; final files are `t\q\task6b-final2-benchmark.{json,md}` and workspace `t\q\task6b-final2-workspace\task6b-final2`.
- Representative reruns: CTL-001, BMC-001 and SMT-001 retained identical observation hashes across two runs. STATIC-001, DYN-001 and COV-005 retained status/finding/classification, while raw observation hashes differed due to temporary paths, timing, and generated execution details. All individual hashes resolved against their manifests.

**TASK 6B FINAL STATUS: PARTIALLY VERIFIED.** The tested paths are hardened, but general checker accuracy is not established; native sanitizer verification remains environment-limited, the CTL result format does not encode general proof trees/lassos, and several catalog measurements remain fixture-scoped.
