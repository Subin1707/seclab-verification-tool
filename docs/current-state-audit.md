# Current State Audit — Generic Verification Workbench

Audit date: 2026-10-06 (Asia/Saigon)  
Scope: read-only audit of the current repository. No source code, schema, fixtures, specifications, or external project were modified. This document is the only intended audit artifact.

## 1. Executive summary

SecLab is a real generic verification workbench foundation. It has a typed specification contract and loader/validator/normalizer; explicit finite-state model construction; implemented CTL, Z3-backed SMT, and bounded model checking cores; source discovery; real compiler/process abstractions; static and memory analyzer adapters; dynamic C test harnesses; coverage backends; a bounded mutation/black-box/coverage-guided fuzzer; a staged pipeline; hashed evidence/manifests; CLI; and a PySide GUI with a single run session and history projections.

Most checker cores are more than stubs, and generic project pipeline integration tests exist. That does not mean the entire desired workflow is complete. The model builder converts state and transition declarations already in the specification; it does not infer a behavioral model from arbitrary source code or derive states from requirements. The optional C generator translates that explicit graph to C and the model is connected to CTL/BMC/SMT pipeline stages, but the full chain is opt-in and supported only for a subset of model expressions. Fuzzing is a genuine bounded execution engine but its configuration is supplied through pipeline options/config and generic project test templates; it has no GUI configuration flow demonstrated by this audit. Static and memory checks depend on external tools, and coverage can return a scoped build/tool error on this Windows toolchain.

The GUI implements a continuous project/specification/session/run flow in code, including worker-thread progress and reopenable runs. A real Qt GUI runtime test is present, but PySide6 availability and this audit's full test completion could not be confirmed from the host run (see validation section); interactive desktop behavior therefore remains environment-limited, not established as passed. Existing docs record earlier full-suite baselines, which are historical and are not substituted for a live result.

**Core model finding:** source-to-model inference is a **CRITICAL MISSING CORE** relative to the requested project-source → model flow. Explicit specification-to-model construction and formal checking of that explicit model do exist.

**Overall assessment:** strong tested cores and a generic staged integration, with P0 gaps in automatic/source-derived model construction and generic configured C harness generation/execution as one first-class workflow; P1 gaps in complete GUI configuration and dependable cross-platform static/memory/coverage integration; P2 gaps in broader parsers, evidence validation and accuracy evidence; P3 usability/documentation work.

## 2. Architecture map

```text
Generic project directory ── SourceLoader / detectors ── source inventory + source hashes
Specification files ── loader ── schema + semantic validator ── normalizer ── Specification
                                                        ├─ declared states/edges ─ model builder ─ Kripke graph
                                                        │                             ├─ CTL core
                                                        │                             ├─ BMC encoder + Z3
                                                        │                             └─ C model generator (optional)
                                                        ├─ SMT properties ─ SMT encoder + Z3
                                                        └─ tests / fuzz config ─ C harness + compiler/process runner
                                                                          ├─ dynamic oracle
                                                                          ├─ coverage backend
                                                                          └─ fuzz campaign
Project sources ── compiler/cppcheck/clang adapters; ASan/UBSan/LSan + structural memory analysis
All stages ── orchestrator/context ─ result classifier + traceability ─ artifact store/hash/manifest
                                                        └─ report JSON/Markdown projection
CLI ────────────────────────────────────────────────────────────────┘
GUI ─ project/spec controllers + VerificationSession ─ worker ─ same pipeline/report APIs
```

Implementation is principally under `src/seclab/{specification,model,formal,source,static_analysis,memory,testing,codegen,execution,coverage,fuzzing,results,evidence,pipeline,benchmark,gui,integrations}`. The tests are split into core unit, integration, pipeline, architecture, GUI/controller, benchmark, mutation, and chapter workflow suites. `schemas/` holds the JSON contract; `examples/` contains independent generic fixtures plus explicitly optional Smart-EV/teacher fixtures; `docs/` contains core contracts and validation reports.

## 3. Capability matrix

Status vocabulary: **Full** = working implementation in the stated scope; **Partial** = real but scoped/configuration or environment limits; **Adapter** = API bridge without independent core behavior; **Mock/fixture** = test-only behavior; **Docs** = documentation only; **Env-limited** = execution depends on unavailable host capability; **Missing** = no implementation found. “Tested” indicates repository tests exist; live-suite status is reported separately below. GUI connection refers to page/projection or invocation support, not proof of interactive runtime.

| Area | Exists / implementation | Executable and tested | GUI | Evidence / traceability | Missing / limitation |
|---|---|---|---|---|---|
| A Project loading | Partial: path controller and source-tree discovery | CLI/pipeline and controller tested | Yes | Project path and source inventory in run | No project import/build-system abstraction; scan is extension based |
| B Specification loading | Full: JSON and fragments, provenance hashes | Unit/integration tests | Yes | Input hash and validation artifacts | External-format loading only through optional adapter |
| C JSON/schema validation | Full: JSON Schema contract | Unit tests | Yes | Diagnostics artifact | Schema evolution is versioned, not arbitrary formats |
| D Semantic validation | Full within current contract | Unit/integration tests | Yes | Structured diagnostic codes/locations | Semantic contract limited to declared entities/formulas |
| E Normalization | Full deterministic canonical dataclasses | Tests for stable ordering | Yes | Normalized specification and digest | Does not infer missing semantics |
| F Requirement extraction | Partial: explicit requirement records and references | Pipeline tests | Yes | Requirement traceability rows | No natural-language requirement extraction |
| G Property extraction | Partial: explicit CTL/SMT/BMC properties | Integration tests | Yes | Property targets/results/evidence | No automatic derivation from prose |
| H Model construction | Partial: generates graph from explicit states/transitions | Unit/integration tests | Yes | Canonical model evidence/hash | **CRITICAL MISSING CORE:** no source-derived or requirements-derived model |
| I Model representation | Full: validated Kripke graph, export, reachability/deadlocks | Unit tests | Yes, graph/data projection | Model hash and model artifact | GUI displays declared graph data; no source/model correspondence inference |
| J CTL parser | Full, supported grammar | Unit tests | Formal page projection | Formula/property evidence | Grammar intentionally bounded |
| K CTL checking | Full over explicit finite graph; witnesses/counterexamples | Unit + pipeline tests | Yes | Per-property proof/result evidence, validated counterexample | No relationship to C behavior without a trustworthy model |
| L SMT translation | Full for supported expression grammar/domains | Unit/integration tests | Formal page | Query artifacts | Some operators/types deliberately unsupported (e.g. division) |
| M SMT/Z3 | Full real Z3 backend; injected backends for controlled tests | Real-Z3 integration tests | Yes | Query, solver result, counterexample | Z3 dependency and supported fragment limit |
| N BMC | Full bounded graph reachability, completeness analysis, traces | Real Z3 integration tests | Yes | Solver query, trace, completeness artifact | Checks explicit finite graph, not arbitrary source behavior |
| O Source discovery | Partial: C/C++ source loader, language/function detection | Unit/integration tests | Yes | Inventory/hash/requirement links | No general project build metadata or broad language support |
| P Source parsing/model | Partial: lexical/function detection, not compiler AST | Unit tests | Yes | Inventory and function records | No full parser or source semantic model |
| Q Static analysis | Partial: compiler diagnostics, cppcheck, clang-tidy, clang analyzer runners/parsers | Unit/integration; external tools may skip | Yes | Raw outputs/findings/results where tools run | Tool availability/configuration; findings are scoped and not proof |
| R Memory analysis | Partial: ASan, UBSan, leak checker and structural analyzer | Unit/integration; environment skips | Yes through memory/static results | Logs, findings, result evidence | Compiler/runtime/platform limits; dynamic-input coverage is narrow |
| S Test-case representation | Full typed cases, oracle checks, target kinds | Unit/integration | Yes via specification/dynamic views | Case includes source hash map; observation/oracle/result evidence are hashed | Finite scalar function arguments; unsupported kinds remain diagnostics |
| T C/Python model generation | Partial real model-to-C/Python generators | Generator/runtime tests | Optional codegen pipeline page/stage | Generated file manifest/source map/hash | Only explicit finite models; not application source synthesis |
| U Generated model build/runtime | Real gcc/clang C build plus generated Python model execution in BUILD | Generator tests and pipeline path | Stage progress/result | Compiler and Python stdout/stderr/exit evidence | Pipeline tries gcc and clang; unavailable compiler is capability data; not a configurable compiler matrix |
| V Generated C execution | Partial generated model test execution | Stage implementation; integration coverage limited | Stage result | Exit/stdout/stderr/timeout artifact | Executes generated graph consistency test, not a generated test suite against SUT |
| W Dynamic testing | Partial/full for supported explicit test cases and harness kinds | Unit/integration with real compiler | Yes | Build/process/oracle/source integrity evidence; actual JSON stdout and recognized sanitizer findings supported | Does not synthesize expected behavior; scalar function harness and executable input constraints; memory absence is unknown without instrumentation |
| X Coverage | Partial real gcov/LLVM runners and parsers | Unit/integration; host-dependent | Yes | Coverage reports and source hashes | Windows GCC/gcov fixture records BUILD_ERROR; no fabricated metrics |
| Y Fuzzing | Partial real bounded black-box/mutation/coverage-guided engine | Unit + real target integration tests | Fuzz page renders results | Campaign, corpus, finding input, reproduction/evidence hashes | Generic target/template/corpus/budget available via API/config; no first-class GUI setup; concolic strategy explicitly unsupported |
| Z Result model | Full status/result classifier and per-checker semantics | Extensive unit/integration | Yes | Canonical results link evidence | No overall project verdict by design |
| AA Evidence storage | Full content-addressed/hashed artifact store | Unit/integration | Yes | Run manifest and artifact refs | Mutable workspace files can later be changed; tampering is detectable on reopen/verify |
| AB SHA-256 integrity | Full for recorded source and artifacts | Tests for tampering | Evidence viewer verifies | Source before/after and artifact hashes/sizes | Hash integrity identifies changes, not trusted provenance or immutable storage |
| AC Manifest | Full run manifest plus pipeline integrity record | Pipeline/reopen tests | History/reopen | Manifest/report cross references | Older benchmark runner manifest is separate from pipeline manifest |
| AD Traceability | Partial-to-full for declared IDs and supported source/function links | Generic matrix tests | Traceability page | Requirement→property/test→result/evidence/source where IDs exist | No semantic correctness guarantee for user-created associations; model linked globally by model hash |
| AE Accuracy benchmark | Partial 58-case synthetic benchmark; checker-local scoring | Benchmark tests and executable adapters | Report file display | Fixture/ground-truth hashes and observation evidence artifacts | Some observations are mathematically computed or controlled; no general checker accuracy claim; limited TP/TN classes |
| AF Reproducibility | Partial: run IDs, tool/environment/source hashes, seeded campaigns | Evidence/reproducibility tests | History view | Manifest/report and stable inputs | External tools and environment may drift; pipeline does not freeze dependencies/tool binaries |
| AG Pipeline orchestration | Full staged orchestrator with dependency closure, progress, cancellation, isolation | Unit/integration and generic multi-project matrix | Used by GUI and CLI | Stage records, results, evidence, report | CODEGEN omitted unless `generate_c_model`; input contracts still rely on configured spec/config |
| AH Failure isolation | Full at stage and per-test/checker boundaries | Pipeline tests | Partial states/progress shown | Failure diagnostic artifact and scoped TOOL_ERROR | Process-level hard crash can terminate host; stage errors do not guarantee every low-level failure is recoverable |
| AI CLI | Full verify/show-run interface; JSON options | CLI/pipeline tests | Not applicable | Run workspace and report | No interactive guided configuration or benchmark subcommand separate from module runner |
| AJ GUI | Partial PySide desktop app, views and controllers | Controller tests; Qt smoke runtime environment-gated | It is the GUI | Report/evidence/history projections | Audit host runtime availability not confirmed; interactive GUI not directly demonstrated |
| AK Continuous GUI workflow | Partial implementation: project, spec normalization, run, worker/progress, one report/session and reopen | Controller and real GUI smoke test defined | Yes in code | Shared Run ID/workspace/report | Runtime not established on current host; settings chiefly checker options, fuzz setup remains limited |
| AL Report | Full structured pipeline report and CLI summaries | Serialization/pipeline tests | Report page | Manifest/report integrity and limitations | Does not create aggregate PASS/FAIL; evidence details distributed among artifacts |
| AM Run history | Partial/full persisted run enumeration and integrity-checked reopen APIs | Controller tests | History page | Manifest-based run IDs and artifact validation | History depends on selected workspace and intact run structure |

### Real-checker end-to-end question

CTL, SMT, and BMC can receive a normalized generic specification with explicit properties and (for CTL/BMC) the declared finite graph, execute real checker logic, persist scoped result/evidence, and reach the pipeline report. Dynamic, static, memory, coverage, and fuzz stages also invoke real local tools/runners when configured and available, with explicit skips/errors. None of these observations makes the checker input a model of arbitrary C automatically. C generation is a separate opt-in model translation, not a general C test synthesis path.

## 4. Core verification audit

* Specification loading, schema/semantic validation, normalized dataclasses and requirement/property/test extraction are real. Extraction is declarative: it converts IDs and records supplied by the user.
* CTL AST/parser/checker support the finite Kripke structure semantics in `formal/ctl`; counterexamples and witnesses are created and CTL counterexamples are validated.
* SMT supports a typed bounded-domain query fragment and calls Z3. Results and query/evidence are integrated into the SMT pipeline stage.
* BMC builds a bounded encoding over the explicit graph and uses the SMT/Z3 backend; it reports incomplete bounds as inconclusive and has completeness checks for supported finite graphs.
* The model, CTL, BMC, and SMT pipeline adapters execute real cores, classify errors, and attach artifacts. Dependency skips are explicit.
* Formal validity is limited by model/property assumptions. There is no source-to-transition extraction, natural-language property extraction, or proof that the supplied specification model matches source behavior.

## 5. Model audit

**Current chain:** source-independent normalized requirement/property/state/transition declarations → `generate_kripke_structure()` copies and validates explicit graph definitions → CTL/BMC consume graph; SMT checks constraints/domains separately. The graph builder evaluates supported guards against explicit valuations and validates assignment actions against explicit targets. It does not enumerate a Cartesian domain, infer a transition relation, inspect C control flow, or build abstract program states automatically.

* Automatically generated from specification? **Only in the narrow conversion sense** of transforming declared states/edges into a canonical graph. Not automatically synthesized from requirements, properties, or source.
* Loaded from pre-created JSON only? Model declarations are part of the specification contract; callers can also construct model objects in API/tests. There is no standalone imported-model-only restriction.
* GUI model review? Model page and explicit graph export/data are wired to report projections. User inspection depends on a completed run's model artifact; pre-run model construction/review is not established as an interactive build preview.
* CTL verification/counterexamples? Yes over the resulting explicit model; checked counterexamples and evidence are emitted.
* Construction errors? Yes, typed model errors for bad/missing/multiple initial states, invalid edges/guards/actions and state limit. Pipeline persists stage error details when construction throws.
* Requirement→property→model→result? Declared property requirements are linked to results/evidence and model hash; requirement rows carry model reference. This is referential traceability, not source/model semantic validation.

**CRITICAL MISSING CORE:** automatically construct a reviewable behavioral model from generic project source or provide a defined generic model-construction input workflow that connects source behavior to formal state variables/transitions. Current explicit model support must not be represented as inferred source verification.

## 6. C generation audit

`CGenerator` emits model headers/source, generated model tests, optional fuzz harness, a file manifest, source map, hashes, and limitations from a normalized spec plus canonical Kripke graph. The pipeline's CODEGEN stage is enabled only with `PipelineOptions.generate_c_model`; it writes generated outputs under the run workspace, copies generated files into evidence storage, builds with gcc and clang when available, captures command output/status/timeouts, and executes successful test binaries. Generated test behavior checks generated model representation/transition consistency.

This is genuine model-to-C generation and real compile/execute integration, but it does **not** generate generic unit tests from arbitrary requirements/properties for the user's implementation, does not infer test inputs/oracles, and is not enabled in an ordinary default run. The supported model/expression subset is limited. `PipelineOptions` exposes a `generate_c_fuzz_harness` flag, but no broad generated-C test suite is implied by that name. Therefore “C code generation exists” = **Partial**; “automatically generate SUT test harness → compile → execute → oracle → evidence for generic specifications” = **incomplete/P0**.

## 7. Fuzzing audit

The fuzzer is a real bounded engine around `TestRunner`, with target/test template, byte/scalar inputs, mutation, deterministic seeds, optional corpus directory, max executions/time/input size, cancellation/progress, timeout/crash/oracle classification, coverage-guided corpus admission, failure deduplication/minimization, source hash before/after checks, campaign/corpus/finding artifacts and replay metadata. It can repeatedly execute real configured targets and keep triggering/minimized inputs. It distinguishes timeout observations from abnormal termination and can reproduce the retained failing input.

Gaps: campaign selection is API/config based; schema fuzzing/project-specific target acquisition is not automatic. A corpus directory can be supplied, or seeds passed to the engine; pipeline config has `fuzz_seeds`/`fuzz_config`. The pipeline derives its template from explicit specification tests; no tests means skipped. Coverage guidance requires a functioning coverage runner or explicit fallback, and concolic strategy returns unsupported. Campaign findings are integrated as result/evidence; GUI has a Fuzzing page for display, but a complete generic GUI configuration/setup flow is not established. No user should infer “no finding” means safe.

## 8. Static, memory, and dynamic audit

| Area | Actual checker and execution | Output / classification / evidence | Environment and GUI |
|---|---|---|---|
| Static | Compiler diagnostics, cppcheck, clang-tidy, clang static analyzer are separately invoked through toolchain/command runner against discovered source files. | Parsers produce finding records and scoped result; missing tools are error/limited states, never assumed clean. Logs/results are retained. | External binaries, compiler flags and languages affect coverage. Static page displays stage results. |
| Memory | Struct analyzer plus real ASan, UBSan and leak-sanitizer build/run adapters. | Sanitizer parsers classify supported reports; build/tool errors remain explicit. Source and run artifacts are retained. | Host compiler/runtime support varies; Linux-only leak support is declared. Memory page/results are projections. |
| Dynamic | `TestRunner` compiles a generated scalar-function harness or configured executable, executes under timeout, captures output/exit/termination, checks an explicit oracle, hashes source before/after. | Build failure, timeout, abnormal termination, unsupported input and oracle violation have distinct outcomes and evidence; per-case failures are isolated. | Generic C/C++ compiler required for source targets. Dynamic page projects tests/results. |

These are implemented checker integrations rather than a single universal static/memory proof. Parsers/tool invocations and result semantics are separate. A stage can complete while one configured technique reports `TOOL_ERROR`, `ENVIRONMENT_LIMITED`, `BUILD_ERROR`, or `INCONCLUSIVE`.

## 9. Pipeline audit

The default orchestrator contains SPECIFICATION, SOURCE, MODEL, CTL, BMC, SMT, STATIC, MEMORY, DYNAMIC, COVERAGE, FUZZING, REPORT. CODEGEN is added conditionally. The orchestrator validates dependency graphs, computes stage dependency closure, records skipped reasons, invokes progress callbacks, supports cancellation between stages, catches stage exceptions into diagnostics/evidence, and assembles one report/run ID/workspace. The report deliberately has no project-level overall verdict.

Main integration limits: spec must be passed through pipeline options/config (GUI controller carries its already-loaded/validated/normalized value to avoid reloading); without an explicit-state spec model/formal stages skip. Dynamic/fuzz need declared test templates. Coverage needs source plus dynamic cases and actual backend data. The CLI supports project/spec/workspace/config/stages and show-run. The GUI reuses these APIs. Results are stage-scoped; a “COMPLETED” stage does not mean checker PASS.

## 10. GUI audit

The PySide application creates a `VerificationSession`, project/spec controllers, stage/config pages and result/model/formal/static/dynamic/fuzz/evidence/traceability/report/history/accuracy views. Selecting a spec normalizes it into the session; the verification controller passes loaded/validated/normalized objects into the pipeline options. `_RunWorker` performs execution off the GUI thread, progress updates stage views, and a shared report/run ID populates pages. Controller supports history discovery and integrity-checked reopen.

GUI tests comprise controller/session tests and a Qt offscreen smoke suite that includes a real generic project through `MainWindow` and the pipeline. However test module imports PySide6 with `importorskip`; recorded release docs state it was absent on that validation host. Since this audit's current live full-suite result is unavailable, no GUI runtime PASS is asserted. Further gaps: run configuration does not present a comprehensive corpus/seed/budget/target workflow; completed report views cannot provide pre-run requirement/model review for an automatically constructed source model that does not exist.

## 11. Accuracy audit

The catalog contains **59** synthetic cases after Task 7. Catalog ground-truth declarations are not populated from observations; each case records fixture, expected values, rationale, and hashes. The production executor dispatches cases into checker adapters; some controlled timeout/backend observations deliberately use injected test backends. Evidence artifacts can preserve fixture/ground truth, normalized observation and checker evidence payload, with per-case comparison/manifest hashes. However “independent ground truth” means manually/analytically derived fixture semantics, not an external benchmark corpus or independent checker oracle.

* **CTL (11 cases):** graph semantics are explicit and analytically checkable; cases include positive and negative formula outcomes, input error and graph shapes. Can produce TP/TN when checker outcomes are conclusive.
* **BMC (8):** explicit graph/bounds provide independent reachability truth, including a bad node unreachable from all initial states (BMC-008). TP/TN possible for conclusive positive/negative cases; bounded no-path remains inconclusive unless completeness threshold applies. One timeout uses an injected backend.
* **SMT (10):** bounded integer formulas/domains are mathematically inspectable; positive/negative conclusive cases support TP/TN. Unknown/timeout and invalid inputs are not accuracy binary cases; controlled backend cases are not live timeout performance tests.
* **Static (9):** finding presence on synthetic clean/defective sources is the scored signal while status remains INCONCLUSIVE. Current cases supply at least one clean and several defects, so presence-signal TP/TN are structurally possible. Compiler diagnostics/syntax and missing-analyzer cases measure classification/availability, not defect-detection accuracy.
* **Memory (6):** includes defect, safe, and explicit unavailable cases. Actual sanitizer truth can only be scored on supported runtimes; environment-limited runs do not become TN/FN. Current host runtime results were not freshly measured in this audit.
* **Dynamic (6):** declared return oracle, build/timeout, sanitizer/memory behavior, and unsupported cases test execution classification; only explicit oracle positive/negative behavior supports relevant binary comparison. Windows may report a native exception exit code without classifying it as a crash; sanitizer build/runtime failures remain non-binary.
* **Coverage (5):** mathematical counter inputs and one combined oracle/coverage case test measurement; coverage must never be scored as safety TP/TN.
* **Fuzzing (5):** deterministic seeds/budgets and fixed target behavior test engine classification; no-finding is inconclusive. The actual crash fixture ran but Windows did not classify its exception exit as a crash, so it must not be counted as detected on this host. Coverage-guided case requires backend/compiler; timeout is a bounded observation.

Only checker types with both ground-truth detection classes and conclusive actual detection observations should receive TP/TN/FP/FN metrics. Static uses a distinct finding-presence signal. Coverage does not have binary accuracy. Environment-limited, unsupported, errors, skips, timeouts/unknowns are separate. Task 7 ran all 59 cases on Windows 11/Python 3.12.5: 0 FP and 0 FN; 17 TP, 13 TN, 13 inconclusive, 1 unsupported, 6 environment-limited, 3 tool errors, 2 build errors, and 0 skipped. Per checker: CTL 3 TP/6 TN; BMC 3 TP/2 TN; SMT 2 TP/3 TN; cppcheck 5 TP/1 TN; compiler diagnostics 1 TP and no negative class; Dynamic 1 TP/1 TN (timeout could not launch and the sanitizer fixture failed to build); Fuzz 2 TP with no negative class (crash seed was executed, but Windows did not classify its exception exit as crash). ASan/leak-sanitizer cases were environment-limited, and coverage remained measurement-only. These are fixture-level counts (`FIXTURE_LEVEL_ONLY`), not general accuracy estimates. Checker output is stored as an observation, not copied into expected ground truth. Evidence can be independently hash-revalidated, but hash-valid evidence alone does not independently validate the checker logic or semantic correctness of the benchmark design.

## 12. Evidence and traceability audit

The artifact store computes SHA-256/size and uses confined relative output paths. Pipeline assembly records source integrity and artifact integrity, resolves/detaches bad evidence references into diagnostics, and includes traceability integrity findings in the report. Manifest construction validates unique IDs and result→evidence references. `load_previous_run()` confines paths, checks run IDs, report/manifest/integrity hashes and every manifested evidence artifact. GUI evidence resolution rechecks path confinement/hash/size before opening. Pipeline stage and formal evidence includes model/property/formula or source/checker details where available.

Known limits: the store is not immutable; later file edits are detected on validation/reopen. Referential traceability does not prove model fidelity. Requirement links rely on identifiers supplied in the spec/function/test mapping. External checker binaries/tool configuration and source revisions can change between runs, although environment/tool versions and hashes are recorded. Audit did not mutate a run or independently probe every historical artifact. Existing benchmark report contract notes that some displayed evidence labels are less rich than pipeline artifacts; this should not be generalized to all adapters.

## 13. Genericity and isolation audit

Generic core architecture tests enforce import boundaries and prohibited markers. Current source search locates explicit Smart-EV adapter/probe code under `src/seclab/integrations/` and `src/seclab/probes/`; names in integrations/tests/examples/docs are legitimate optional or documentation/test cases. No generic pipeline dependency on an external Smart-EV checkout was found in the inspected generic paths. `examples/generic-c-project` and several other independent generic fixtures exercise the generic API without Smart-EV.

A new project can be used without changing tool source **if** it supplies a supported C/C++ tree plus a compatible specification and optional pipeline config; it does not need Smart-EV. It cannot currently obtain source-derived formal verification merely by pointing the tool at arbitrary source: the user must provide formal states/transitions/properties/tests and configure optional analyses. Genericity of input plumbing is present; automatic semantic adaptation is not.

## 14. Prioritized gap list

### P0 — Core blockers

1. **Source/specification-to-model construction:** no generic source-derived transition relation/state model; formal proof currently establishes properties only over declared abstract graph. Design a reviewable model boundary and fidelity assumptions.
2. **Formal capability path for ordinary generic projects:** explicit-model CTL/BMC and domain SMT cores work, but make model assumptions and supported inputs a first-class user workflow; no proof linkage currently ties C behavior to the graph.
3. **Generic test synthesis integration:** current scalar C harness is real for explicit tests, but property/requirement → generated input/oracle → SUT harness is not generally synthesized. Avoid claiming arbitrary “spec to C tests.”
4. **First-class generic pipeline configuration:** fuzzing, codegen, and full run options exist in APIs/config but the continuous user workflow does not automatically supply sensible test/model/campaign configuration. Ensure unsupported work remains explicit.

### P1 — Major workflow requirements

1. Make GUI runtime supported/validated on a documented PySide environment and complete the real workflow for project → spec → pre-run review → one full run → reopen history.
2. Add a GUI/API path for target/template, seed/corpus, budget, strategy and oracle setup, and show unsupported/concolic/coverage fallback clearly.
3. Finish cross-platform compiler/toolchain handling and verify real memory/static/coverage outcomes on declared CI environments; keep Windows gcov limitations explicit.
4. Improve project source parsing/build abstraction beyond lexical function detection for supported languages, without silently altering project files.
5. Ensure generated C artifacts are a useful SUT test path or clearly label them as model-consistency artifacts; expose compiler selection/status without treating unavailable tools as pass.

### P2 — Important quality/reproducibility

1. Extend independent benchmark classes per checker and persist fresh checker-local metrics/evidence; validate ground truth review provenance and avoid accuracy claims on fixture-only subsets.
2. Strengthen requirement→source→model relation checks and source-map validation; make broken trace paths prominent.
3. Capture exact compiler/analyzer flags, binary/tool versions and project/config hashes for every stage; clarify mutable-workspace threat model.
4. Add output parsers/diagnostics for unsupported project formats and unsupported specification constructs.

### P3 — Polish

1. Improve GUI pre-run model/requirement review and report navigation/localized status labels.
2. Consolidate historical validation docs/counts and record a current baseline only after a completed run.
3. Improve operator-facing CLI configuration/help and explain stage skips in plain language.

## 15. Final implementation roadmap

The phases below respect the requested order. They are roadmap only; no phase work starts in this audit.

| Phase | Objective and current state | Missing pieces / likely modules | Dependencies and implementation tasks | Tests required / Definition of Done | Must not change / expected artifacts |
|---|---|---|---|---|---|
| 1 CORE MODEL | Build a reviewable generic behavioral model. Explicit spec graph conversion exists; source inference is missing. | `specification/schema.py`, validator/normalizer, `model/*`, source parser, pipeline MODEL, model GUI page. | Define supported generic source/model input and fidelity boundary; preserve declared graph path; construct variables/states/transitions deterministically; reject ambiguity/limits with diagnostics. | New model construction unit/property tests, generic C fixtures, error/limit tests, pipeline trace test. DoD: new supported generic project produces canonical inspectable model with explicit provenance and no guessed transitions. | Do not weaken schema, invent semantics, bind Smart-EV; output canonical model, mapping/provenance, diagnostics. |
| 2 FORMAL VERIFICATION | Bind CTL/SMT/BMC to canonical model/property contracts. Existing cores and explicit-model pipeline stages are real. | `formal/{ctl,smt,bmc}`, `pipeline/stages.py`, traceability/result serializers. | Specify property applicability and translation limits; pass model/property provenance; retain counterexample validation and bounded semantics. | Real Z3, CTL, BMC tests plus end-to-end generic model test. DoD: declared supported properties execute against canonical model with truthful pass/fail/inconclusive and traceable evidence. | Do not imply source proof absent model relation; outputs query/result/counterexample/completeness artifacts. |
| 3 C CODE GENERATION | Provide generic test generation where supported. Current model-to-C generator is opt-in and narrow. | `codegen/c_generator.py`, `testing/{harness_generator,test_generator}.py`, pipeline CODEGEN/options. | Define accepted property/test forms, safe input mapping, oracle source; make compiler configuration explicit; separate model consistency test from SUT test. | Generated-code golden/compile tests and source isolation; DoD: supported cases generate auditable C with source map and explicit oracle, otherwise unsupported diagnostic. | Do not fabricate expected behavior or modify project; output source, manifest, maps, capability/build records. |
| 4 DYNAMIC EXECUTION | Execute generated and declared tests consistently. Existing runner supports real compile/process/oracle. | `testing/test_runner.py`, `execution/*`, pipeline DYNAMIC. | Connect phase 3 outputs to SUT build/run; preserve timeout/crash/build distinctions and source integrity. | Compiler-backed C/C++ tests, abnormal/timeout/oracle mismatch tests. DoD: every test has declared oracle, captured execution and reproducible result evidence. | Do not equate execution with proof; output build/process/oracle/source-integrity artifacts. |
| 5 FUZZING | Make generic campaigns configurable end to end. Core engine is real and bounded. | `fuzzing/*`, `pipeline/stages.py`, options/CLI/GUI settings. | Define target/template/seeds/corpus/budget/oracle handoff; make fallback visible; preserve replay/minimization/source hashes. | Real target seeded crash, timeout separation, replay, corpus, cancellation and coverage fallback tests. DoD: campaign setup→mutation→execution→finding/reproduction/evidence works for supported target kinds. | Do not call no finding PASS; concolic stays unsupported unless implemented; output campaign manifest/findings/corpus. |
| 6 COVERAGE | Measure supported dynamic/fuzz runs and correlate inputs. Backends exist but are environment-sensitive. | `coverage/*`, execution/compiler configs, pipeline stage. | Clarify production-source set, test vs harness attribution, backend selection and unavailable semantics; enable supported CI toolchains. | Real gcov and LLVM integrations, partial runs, failed build/tool cases. DoD: valid metrics are reproducible and scoped; failures carry no invented metric. | No coverage safety verdict; output raw/backend/report/source hash artifacts. |
| 7 EVIDENCE / TRACEABILITY HARDENING | Make complete chain independently verifiable. Strong hashes/manifest checks already exist. | `evidence/*`, `pipeline/context.py`, `orchestrator.py`, `previous_run.py`, report and benchmark. | Add relation validation requirement→property/model/test→checker→result→evidence→hash→manifest→report; exact tool/config provenance; test traversal attacks and tampering. | Tamper/path-escape/broken-reference/report inconsistency tests. DoD: run reopen validates every recorded link/hash or emits precise failure; no silent drop. | Preserve result semantics and source hashes; output machine-readable trace/integrity summary. |
| 8 GUI CONTINUOUS WORKFLOW | Complete single-session user experience. Controllers/pages and worker exist; runtime not established. | `gui/main_window.py`, controllers/session/pages, run options. | Real Qt runtime; pre-run requirements/model preview; one spec/project/session; campaign controls; progress/results/history. | Offscreen real workflow on supported Qt CI plus manual desktop acceptance. DoD: one load each, one run ID, inspect stages/evidence, reopen run without reload/rerun. | Keep pipeline as source of truth; no mock-only DoD; output GUI workflow screenshots/acceptance record if requested. |
| 9 ACCURACY VALIDATION | Validate engine on justified per-checker ground truth. Current 58-case suite is useful synthetic regression. | `benchmark/{catalog,production,models,runner}.py`, accuracy docs. | Review independent truth, add both classes where meaningful, distinguish controlled injection/environment limitation, revalidate evidence. | Fresh benchmark run on declared tool matrix; meta-tests for no leakage from expected into actual; DoD: only justified checker-local metrics reported, all excluded cases categorized. | No cross-checker score, no generated expected values from output, no Smart-EV benchmark. |

## Task 8 delta — evidence and reproducibility (2026-10-06)

The pipeline now emits a hashed stage-execution evidence envelope for every stage record, including unselected, dependency-skipped, and cancellation-skipped stages. Stage envelopes and evidence metadata bind run/stage ID, lifecycle status, source/specification hashes, canonical configuration hash, reproducibility ID, tool versions, timestamps, and referenced results/artifacts. Common evidence metadata is enriched before report/manifest serialization. The manifest self-hash remains in the adjacent integrity sidecar to avoid recursive hashing.

`load_previous_run()` now rejects evidence without provenance and validates that each stage record resolves to a confined, hash-valid execution envelope with matching run ID, stage ID, status, and configuration fingerprint. Reproducibility IDs cover source hashes, specification inputs/normalized specification, configuration/seeds, and tool versions while excluding run ID/timing/artifact IDs. Report fields remain checker-local/stage-local and contain no overall safety verdict. Focused and full regression results for Task 8 are appended after validation.

Task 8 validation: focused pipeline/evidence regression **40 passed**; final full regression **430 passed, 5 skipped, 2 failed**. Both failures are the existing Windows gcov and LLVM instrumented-test compile failures in `tests/integration/test_coverage_backends.py`; instrumented executables did not compile on this host. `python -m compileall -q src tests` **PASS**. Two persisted SOURCE-selected runs reopened through `load_previous_run()` with the same reproducibility ID `RP-ae08a522276cc4e981886d22776ee8d3`. All 13 stage records resolved to execution evidence, all 18 manifest evidence paths were workspace-confined and SHA-256-valid, and `accuracy.status` was `NOT_RUN` with fixture-level scope. The report contained none of the forbidden overall-verdict keys. Timestamped evidence bytes are not expected to hash identically across runs; stage observations are compared under the shared reproducibility ID.

### Task 7 delta — verification accuracy

- Added BMC-008: a bad state exists in the supplied finite graph but is disconnected from every initial-state path; the real BMC adapter confirms the complete graph reachability result.
- Removed injected abnormal-process runners from the benchmark Dynamic/Fuzz crash paths. The fuzz crash seed now passes through the actual compiled executable and campaign engine; crash classification requires the real observation to report a crash. DYN-005 exercises a real sanitizer build/run and preserves BUILD_ERROR/INCONCLUSIVE where Windows MinGW has no working ASan runtime.
- Benchmark JSON rows and aggregate now declare `metric_scope: FIXTURE_LEVEL_ONLY`; Markdown states this scope next to results. No cross-checker or project-level verdict is added.
- Focused suite: 17 tests pass; full-suite regression and final fresh benchmark/compileall results are recorded in the Task 7 addendum below.

### Task 7 validation results — 2026-10-06

- Accuracy-focused suite: `python -m pytest tests/benchmark/test_accuracy_benchmark.py -q` — **17 passed**.
- Full regression: `python -m pytest -q --basetemp=t/task7-pytest` — **429 passed, 5 skipped, 1 failed**. The one failure is `tests/integration/test_coverage_backends.py::test_real_gcov_suite_aggregates_both_function_branches_and_keeps_oracle_failure`; GCC/gcov’s instrumented test executable did not compile on this Windows toolchain. This is an environment-limited integration failure, not counted as a benchmark checker outcome.
- `python -m compileall -q src tests` — **PASS**.
- Fresh benchmark `t/accuracy-task7-final.json` / `.md`: **59 cases**, `metric_scope=FIXTURE_LEVEL_ONLY`, **17 TP / 13 TN / 0 FP / 0 FN**, 13 inconclusive, 1 unsupported, 6 environment-limited, 3 tool errors, 2 build errors, 0 skipped. Checker-local counts and classifications are in the JSON/Markdown artifacts; the counts do not establish general checker accuracy.
- No Memory cases were conclusive because the selected Windows GCC/MinGW toolchain did not provide sanitizer runtime support (five positive/safe memory scenarios environment-limited; MEM-006 is an expected environment-limit control). DYN-005 sanitizer build returned BUILD_ERROR. DYN-004 process launch returned TOOL_ERROR. FUZZ-001 ran the compiled target and seed without an injected process result; Windows did not expose the target exception as `crashed=True`, so this fixture does not count as a crash detection on this host. FUZZ-004 is an observed oracle TP; no fuzz negative class exists, so no fuzz accuracy rate is calculable.
- Benchmark evidence: **296/296** manifest references resolved and matched their recorded SHA-256.
- BMC-008 confirms an unreachable bad node in a complete supplied finite graph; insufficient bound remains INCONCLUSIVE (BMC-002/BMC-005).
- Report adds explicit per-row and aggregate fixture-level scope. No overall verdict, checker-contract semantics, specification contract, or Smart-EV logic changed.
| 10 FINAL END-TO-END VALIDATION | Establish release evidence across generic projects/platforms. Historical report has stale counts. | tests/integration, architecture tests, CLI/GUI workflows, final docs. | Run full tests/compileall and generic multi-project CLI+GUI; preserve baseline report, skips and tool matrix. | Defined CI commands with captured exit/counts, no unexplained skips, evidence/hash/reopen checks. DoD: reproducible report covers all prior phases, limitations explicit, source project unchanged. | No overall project verdict; output release validation report and reproducible run artifacts. |

## 16. Validation, environment, files inspected, and next task

### Test and compile status

* Discovered **42** Python test files and **329** test functions (count is collection-by-source scan; parametrization increases pytest cases).
* Live command: `.venv\\Scripts\\python.exe -m pytest -q -rs --basetemp=t\\audit-final` — **393 passed, 4 skipped, 1 failed in 249.18s**. The failure is `tests/integration/test_coverage_backends.py::test_real_gcov_suite_aggregates_both_function_branches_and_keeps_oracle_failure`: on this Windows gcc/gcov setup, both instrumented testcases fail compilation, so the test receives no coverage report. This matches the known backend limitation but remains a real failing test.
* Skip reasons: external Smart-EV integration is opt-in; two ASan integration cases report unsupported compiler/runtime; source symlink test cannot create symlinks in this environment. No PySide6 skip appeared in this run, so GUI runtime status should be assessed from collection/environment directly; this audit did not launch an interactive desktop.
* `python -m compileall -q src tests` completed successfully with no error output.
* Prior repo docs report absent PySide6 GUI runtime and Windows gcov instrumentation limitations. Current pytest had no GUI skip, so the previous PySide6 note may refer to a different environment/baseline and is not relied on as a current observed skip.

### Files and directories inspected

Inspected file inventories under `src/seclab/`, `tests/`, `examples/`, `docs/`, `schemas/`, `tools/`, plus `pyproject.toml`; implementation reads included specification contract/loader/validator/normalizer, model generator/graph, CTL/SMT/BMC, source discovery, pipeline stages/orchestrator/options/report/context, C generation, testing runner/harness, fuzz engine/models, static/memory/coverage adapters, results/evidence/manifest/reopen validation, CLI, GUI session/controllers/main window/smoke test, benchmark catalog/models/production/runner/report, and genericity/accuracy/runtime validation docs. Search covered Smart-EV markers and test skip declarations. Full test suite and compileall were also run as recorded above. No external Smart-EV repository was opened or modified.

### Exact next task

Create a design/specification for **Phase 1 CORE MODEL** that defines a generic, explicitly bounded route from a supported source-language representation to reviewable state variables, states, transitions, initial conditions and source provenance, with sound unsupported/ambiguity diagnostics. Keep the existing declared-state specification path backward compatible. Do not start implementation until that design and its acceptance tests are reviewed.

## Audit delta after Phase 1 task work (2026-10-06)

The source-model finding above describes the pre-milestone baseline. `src/seclab/model/source_model.py` now adds a conservative Clang-AST-backed C model builder. It reuses the existing source loader, command runner, artifact store, and canonical Kripke model. It does not alter the Specification contract, explicit specification model builder, or Kripke semantics. Its scope, parameter assumptions, loop-bound behavior, outputs and unsupported cases are documented in `docs/model-core.md`.

The seven requested generic C fixtures are under `examples/source-model/`. Unit and real-fixture integration coverage is in `tests/unit/model/test_source_model_builder.py` and `tests/integration/test_source_model_builder_integration.py`. The focused suite reported **11 passed**; `python -m compileall -q src tests` succeeded. The full regression reported **403 passed, 4 skipped, 2 failed (409 collected outcomes)**. Both failures are real gcov/LLVM coverage integrations whose instrumented builds/executions could not complete on this Windows toolchain; the prior baseline already had a Windows gcov failure. Re-running just those tests reproduced both failures. Pipeline MODEL-stage fallback/integration and GUI pre-run model review remain **NOT IMPLEMENTED**; the builder is currently a callable core API. This is a milestone implementation delta, not a claim that Phase 1 or the final product is complete.

The pre-milestone exact next-task statement above is superseded by this implementation delta. The next implementation task should decide and test how `PipelineStages.model` consumes source-derived results while preserving explicit-model compatibility and preventing CTL/BMC from treating an `INCONCLUSIVE` bounded abstraction as complete.

## Task 1 follow-up — source model formal pipeline (2026-10-07)

`PipelineOptions` now exposes an explicit source-model opt-in (`source_model_target`), finite parameter domains, and a loop bound without adding fields to the Specification JSON contract. The target must match a declared generic `FunctionSpec`; the selected translation unit must contain only that function definition. The source-derived graph and its Clang AST/build evidence remain separate from the declared-specification MODEL graph. CTL/BMC prefer an available explicit graph; otherwise they consume only a `SUPPORTED` opted-in source model. Incomplete or unsupported source models are preserved as evidence and formal properties receive a scoped `INCONCLUSIVE` result without invoking CTL/BMC. Existing explicit-model formal checks do not select or require SOURCE. Full pipeline order places SOURCE before MODEL/formal stages; selecting CTL/BMC pulls SOURCE only when source modeling is explicitly configured. SMT remains specification-scoped.

The standalone builder no longer merges multiple function definitions as independent initial paths. It returns `UNSUPPORTED` with a function-entry ambiguity diagnostic. The seven generic source fixtures remain under `examples/source-model/`: linear assignments, if/else, multiple branch conditions, bounded loop, invalid syntax, constant-unreachable branch, and multiple functions. Source/model builder tests verify structure, branches, mappings, source hashes/evidence, unsupported syntax, and ambiguous multi-function input. Two pipeline integration cases cover (1) opt-in source-derived CTL with no explicit specification states and (2) bounded-loop `INCONCLUSIVE` propagation with no formal model link.

Validation: direct source-model builder tests and pipeline integration/order checks passed (**18 passed** in the final affected set); generic fixture pipeline matrix **10 passed**; multi-project generic pipeline **5 passed**. A broader source/model/CTL/BMC/pipeline group reached **157 passed, 1 skipped, 1 failed** on a stale expected stage-order tuple, which was corrected; the stage-order and affected chapter/source tests then passed (**18 passed**). Verbose full regression collected **450 tests** and stopped at `tests/integration/gui/test_gui_smoke.py::test_real_generic_c_project_runs_through_gui_workflow` after several minutes with active CPU and no output. It had reported CH1/CH3/CH6 workflow failures before the stop; those three exact tests were rerun after fixing source-stage selection and optional chapter metadata and passed. The remaining full suite is **NOT VERIFIED**. `python -m compileall -q src tests` passed after final code/test edits.

Current limitations: C only; Clang is required; only signed integer/void scalar functions and the documented statement/expression subset are modeled. Function calls, global/static storage, pointers, uninitialized locals, unsupported operators/types, multiple candidate entries, and invalid syntax yield `UNSUPPORTED`. Finite integer parameter domains must be supplied; no values are guessed. Loop-bound exhaustion and unresolved branch conditions yield `INCONCLUSIVE`. No source-level property or requirement is inferred, and arbitrary CTL atoms remain subject to the unchanged specification validator. Source-model results are available through the pipeline core API; GUI target/domain/bound configuration is **NOT IMPLEMENTED**. Task 1 follow-up is **PARTIAL**, not a claim of full project-source verification.

Fixture observations from the real Clang run: `linear.c` 3 states/2 transitions; `if_else.c` 4/2 with domains `choose.input={-1,1}`; `multiple_branches.c` 8/5 with `classify.input={-1,0,2}`; `bounded_loop.c` 10/9 with loop bound 3; `unreachable_branch.c` 2/1 and one unreachable warning; `multiple_functions.c` 4/2; `invalid_syntax.c` returned `UNSUPPORTED` and no model. No fixture uses Smart-EV data.

## Audit delta after Task 2 — Generic C code generation (2026-10-06)

`src/seclab/codegen/ir.py` adds typed deterministic C file/block/line IR. `CGenerator` renders the existing canonical model through this IR without changing Specification or Kripke semantics. Generated C/header are marked `GENERATED_ARTIFACT` in generation manifest/source map; compatibility reports retain the legacy `GENERATED_SOURCE` alias. Source map version 1 now includes generated line numbers linked to state and transition IDs. Hashes remain SHA-256 over exact UTF-8 outputs.

`GeneratedArtifactRunner` compiles and executes the generated model self-check using shared `CommandRunner`, and stores source input hashes plus build/execution records with `ArtifactStore`. It separates `BUILD_ERROR`, `TOOL_ERROR`, `TIMEOUT`, `ABNORMAL_TERMINATION`, `COMPLETED`, and `NOT_RUN`, and explicitly scopes these observations to generated artifact execution. The harness checks graph representation only; it does not synthesize an external project oracle or claim production safety. Existing pipeline CODEGEN captures the same separated build/execution status fields and preserves generated artifact classifications.

Generic fixtures in `examples/codegen/` cover a boolean state machine, counter, branching graph, bounded transition graph, and invalid guard. Validation: focused codegen and integration regressions **21 passed**; `python -m compileall -q src tests` succeeded. Full regression: **411 passed, 4 skipped, 3 failed** (418 outcomes); one failure was the legacy generated-source compatibility assertion and was fixed, then its focused regression passed. The remaining two failures are real gcov and LLVM coverage integrations whose instrumented testcase builds fail on this Windows toolchain, matching the preceding audit's platform-limited coverage issue. Codegen Task 2 DoD is **partially met**: deterministic generated files, hashes, model-to-line mappings, four positive fixture compile/execute paths, invalid-guard negative case, pipeline ArtifactStore integration, and missing-compiler classification are covered. Explicit configurable model-selection input/output is accepted by the runner API, but the current generated consistency harness does not consume it or emit runtime output; arbitrary specification-to-program C synthesis and full executable test-vector generation are **NOT IMPLEMENTED**. Runtime abnormal termination and timeout classification are implemented from real command results but lack dedicated executed negative-process fixtures. These are remaining gaps; this delta does not declare the broader code-generation milestone complete.

## Audit delta after Task 3 — End-to-end traceability (2026-10-06)

`seclab.pipeline.TraceabilityIndex` is a read-only query API exported for pipeline/report consumers (including a future GUI). It supports requirement, source-function, model-state, specification-property, test-case, execution, observation, result, and evidence lookups. It reads IDs and relationships from the report, run manifest, source inventory, dynamic execution records, and ArtifactStore metadata; absent links return `UNRESOLVED`, dangling or hash-invalid evidence returns `BROKEN`. Requirement traces preserve checker/property/test links and results/evidence; dynamic execution now has a stable ID derived from test ID and execution fingerprint and explicit testcase/observation/result/evidence edges. Default ArtifactStore evidence IDs are deterministic from run ID, stage, filename and payload hash; callers supplying an ID factory retain that behavior.

Pipeline trace validation now checks property and execution-result/evidence references and duplicate result/evidence IDs. `TraceabilityIndex.integrity()` checks duplicate result/evidence/source/function/property IDs, dangling result evidence, orphan evidence and missing/modified/wrong-hash files when given a run root. Existing manifest/reopen validation remains in force. Added tests cover all requested artifact corruption classes and query unresolved/broken cases.


Validation after final edits: trace/evidence/pipeline focused suite **41 passed**; source-model plus missing/modified/hash/reopen suite **14 passed**; compileall is to be recorded after the final run. Full-suite regression has not yet been run for Task 3. Task 3 DoD is **partially met**, not complete: explicit declared-spec property-to-test mapping is available only when test evidence carries the same property ID or an explicit `TestCase.property_id`; generic Specification JSON tests currently link to requirements but have no property-ID field, so property→test can correctly remain `UNRESOLVED`. `SourceModelBuilder` provenance is not currently wired into the generic pipeline MODEL stage; source-function→model-state/transition queries therefore remain unresolved in ordinary pipeline runs unless source-derived provenance is explicitly supplied. CTL/BMC map each property to the evaluated model state/transition set, while SMT remains specification-variable scoped and does not claim a Kripke-state mapping. Orphan/duplicate/missing/hash integrity findings are queryable and pipeline-reported; comprehensive stage-wide stable IDs for every intermediate artifact are **NOT IMPLEMENTED**. No missing mapping is fabricated.

### Task 3 follow-up — ambiguity and link integrity

`TraceabilityIndex` now groups records by ID before exposing lookup dictionaries. Duplicate result/evidence IDs make direct lookups return `BROKEN` with the candidate count instead of selecting an arbitrary record. Its integrity report now checks requirement→result/evidence and execution→result/evidence references as well as the pre-existing artifact hash, orphan and duplicate checks. Unit tests cover ambiguous duplicate IDs and broken requirement/execution edges. Generic integration coverage asserts real requirement/result/evidence links, a model-state formal result link, resolved observation/result/evidence queries, and generated artifact hashes where code generation is enabled.

Limits remain explicit: ordinary generic source-function→state/transition mappings are unresolved without source-model provenance; specification-property→test-case is unresolved unless an explicit property association is present; SMT does not claim a Kripke-state link; and stable IDs are not yet defined for every intermediate stage artifact. Task 3 therefore remains **PARTIAL**. Follow-up validation: focused traceability + generic C integration **10 passed**; pipeline/generic project regression **48 passed**; `python -m compileall -q src tests` succeeded. Full repository regression was not run for this follow-up.

## Audit delta after Task 4 — Generic fuzzing (2026-10-06)

The existing real `FuzzEngine` remains based on shared `TestRunner` and `CoverageRunner`; this delta adds explicit `max_executions` and `max_input_count` caps alongside iteration, elapsed-time, per-input timeout, byte-size, and separately bounded minimization limits. Remaining campaign time now constrains each execution; minimization stops when the campaign time/cancellation budget is exhausted. The campaign manifest contains the random seed, canonical reproducibility configuration and SHA-256, source hashes, target, oracle, seeds, requested/effective strategy and budgets.

Every candidate input is stored as evidence, process output/command/execution/observation/result evidence is persisted per testcase, per-input analysis records include crash/timeout/oracle signature plus coverage entities/delta, and a final deduplicated corpus index links retained entries to input evidence, parent/generation, retention reason, coverage signature and failure signature. No-finding stays `INCONCLUSIVE`; an oracle/crash/sanitizer finding only has `FAIL` where a matching declared no-crash/oracle scope exists. Concolic target fuzzing is `UNSUPPORTED`; `ConcolicGenerator` is labeled `PROTOTYPE` and only solves caller-provided constraints, without source branch tracing or concrete replay.

Focused fuzz regressions after the changes: **24 passed**, including a rerun of the dynamic execution fingerprint collision test fixed by making per-invocation execution evidence filenames unique while retaining stable execution IDs. Cases include crash, timeout, oracle failure, coverage increase, corpus deduplication, minimization, deterministic input replay, explicit execution/input caps, candidate/output evidence, and concolic unsupported status. `compileall` passed. Full regression reported **419 passed, 4 skipped, 3 failed** before the execution-filename fix: two known Windows gcov/LLVM instrumented-build failures and one duplicate execution-evidence path, which passed on focused rerun afterward. The complete regression has not been rerun after that fix. Task 4 is **partially implemented** pending a full rerun; platform-limited coverage feedback remains explicit and cannot be treated as successful feedback.

## Audit delta after Task 5 — Dynamic testing hardening (2026-10-06)

The runner persists each testcase together with its source hash map, derives parsed structured output only from actual process stdout, and records recognized ASan/UBSan findings parsed from actual process stderr. Scoped oracle checks support structured JSON equality and memory-finding presence. A memory check is conclusive only after a successful source build with an explicit sanitizer flag; a report-like string from an uninstrumented/prebuilt process is recorded but cannot establish a memory-oracle result. Absence is not treated as evidence of safety. Timed-out runs remain unevaluated, and abnormal termination cannot satisfy unrelated output/return checks. Return marker ambiguity is an observation tool error. Existing ArtifactStore IDs/hashes link testcase, observation, oracle, execution, process/build evidence, and result.

Negative coverage checks that absent observations cannot pass by copying expected data, mismatching actual stdout is evaluated against observed text, uninstrumented missing/report-like memory output remains unknown, crash output cannot satisfy an unrelated oracle, SUT attempts to spoof the harness return marker are rejected, and testcase evidence contains source hashes. Focused dynamic/termination/pipeline/generic-C regression before the final memory-provenance tightening: **51 passed**. An optional real ASan fixture was attempted and skipped because the selected Windows compiler reports `COMPILATION_FAILED` for sanitizer instrumentation. Full regression after Task 5: **425 passed, 5 skipped, 2 failed** in 242.56s. `compileall -q src tests` passed. Both failures are the known Windows gcov and LLVM instrumented-coverage builds failing to compile their instrumented testcases. Task 5 remains **partially implemented**; live ASan/UBSan execution is **ENVIRONMENT LIMITED**, and the two coverage backend failures remain open regression issues.

## Audit delta after Task 6 — Unified checker integration and cross-check matrix

The full pipeline now has an independent `CROSS_CHECK` stage and a `seclab-cross-check-matrix-v1` ArtifactStore artifact. It is included in full, checker-selective, and cancelled-run reports without becoming a prerequisite for any checker; report-only runs remain report-only. The report preserves checker-local statuses/scopes and has no aggregate verdict. Matrix links use explicit specification/property/test/function IDs, canonical model hash, testcase source hashes, and evidence IDs/hashes. Source-to-model remains `UNRESOLVED` unless source-derived provenance is supplied.

Matrix relations cover specification↔model, specification↔source, model↔source, source↔dynamic, specification↔dynamic, specification↔formal, model↔formal, and dynamic↔formal. Opposite conclusive PASS/FAIL outcomes become `INCONSISTENCY` only when the property and testcase declare the same explicit `cross_check_key`; the cross-check emits a scoped `INCONCLUSIVE` result and preserves original outcomes. Missing mappings remain unresolved; SMT is marked not comparable to a Kripke graph. Coverage is represented separately as measurement-only. Checker records retain CTL counterexample validation, BMC trace/completeness data, SMT query hashes and constraint IDs, static finding provenance/source hashes, memory runtime scope, actual dynamic observations, and bounded fuzz campaign details.

Pipeline regressions cover full multi-checker execution, traceability, memory scope, coverage measurement-only behavior, BMC completeness, SMT query hashes, explicit contradiction handling, unchanged checker results, partial-stage selection, cancellation, and omission of any overall verdict key. Latest pipeline/chapter/generic-matrix focused regression: **20 passed**; `compileall -q src tests` passed. Final full regression: **426 passed, 5 skipped, 2 failed** in 248.73s. The two failures are the existing Windows gcc/gcov and LLVM instrumented-coverage testcase build failures; no cross-check regression failed. Task 6 is **PARTIAL**: stage integration and contradiction reporting are implemented, but ordinary pipeline runs do not yet invoke `SourceModelBuilder`, so model↔source links remain explicitly unresolved unless provenance is supplied. The broader Windows coverage backend failures remain open environment issues.

## Task 2 follow-up — Generated model executable interface (2026-10-07)

The generated test harness now validates the serialized model before accepting runtime input. Its deterministic CLI accepts an optional state ID and optional outgoing transition ID, validates both against the graph, and emits actual JSON stdout with the input state, initial marker, selected transition, target state, and outgoing transition IDs. Invalid input is written to stderr and exits nonzero. Generated C/header comments and manifest/source-map continue to mark them `GENERATED_ARTIFACT`; the harness is `TEST_HARNESS`.

Source-map entries now also map the specification identifier and generated harness transition checks to generated lines. `GeneratedArtifactRunner` supports separate build/execution timeouts and persists generated C/header/harness, source map, manifest, compile/run stdout and stderr, exit codes and termination data to ArtifactStore with SHA-256 hashes. Invocation-specific evidence filenames prevent collisions when several generated artifacts are run in one evidence store. Compile errors/build timeouts remain `BUILD_ERROR`; unavailable/start failures remain `TOOL_ERROR`; runtime timeout, abnormal nonzero termination, tool error and completion remain distinct. All output and scope identify generated-artifact execution and do not create production safety verdicts.

Generic compile/execute regressions after this change: **21 passed** (unit and fixture integration). Optional pipeline CODEGEN checks: **2 passed**. Cases include deterministic generation/hash, all four positive fixtures, observable JSON output and parameterized state/transition input, source maps, invalid inputs, an actual C compilation failure with stored diagnostics, abnormal process exit, runtime timeout, missing compiler, and ArtifactStore hashes. `python -m compileall -q src tests` is recorded after final edits below. Windows MinGW `abort()` can hang on this host; the exercised portable abnormal-termination case is a real nonzero process exit, so OS signal-level crash execution remains **ENVIRONMENT LIMITED** here. The broad suite was not rerun for this follow-up.

Task 2 remains **PARTIAL**: C generation represents the canonical finite graph and tests/query harness only; it does not synthesize arbitrary application functions or infer requirement oracles from the Specification, and generated output is not automatically treated as production source by downstream project testing.

## Task 4 follow-up — deterministic mutation replay (2026-10-07)

Added an engine-level two-run replay test for `MUTATION`, comparing actual generated testcase inputs for a fixed seed corpus and random seed. This complements the existing black-box replay check and unit-level deterministic mutator test. Focused fuzz suite after this addition: **24 passed** (`tests/unit/fuzzing` and `tests/integration/fuzzing`). `python -m compileall -q src tests` succeeded. The entire repository regression was not rerun. Fuzzing remains **PARTIAL** pending broad regression and reliable coverage backend availability on Windows; concolic target tracing remains **UNSUPPORTED**, with only the explicit-constraint solver prototype available.

## Task 5 follow-up — observation/oracle negative boundary (2026-10-07)

Added a runner/evidence negative test where the C target fails to build while a distinctive expected stdout value is declared. It verifies that the observation artifact says unavailable without containing the expected marker, and the oracle evidence keeps expected separate with `actual: null` and `evaluated: false`. This complements existing negative tests for absent observations, spoofed function-return markers, crashes that cannot satisfy output oracles, and memory findings without successful sanitizer instrumentation. Focused dynamic runner plus source-execution/generic-C integration: **29 passed, 1 skipped**; the skip is environment-gated sanitizer execution. `python -m compileall -q src tests` succeeded. The full repository suite was not rerun.

## Task 6 follow-up — unified engine verification (2026-10-07)

Revalidated the existing staged integration and cross-check matrix against the required checker contracts. Each checker retains its own result and evidence. Matrix contract rows expose CTL counterexample validation; BMC checked/completeness thresholds and trace validation; SMT query hashes, constraints and model-validation status; static finding/source provenance; memory runtime scope; dynamic actual observation; coverage measurement-only status; and bounded fuzz campaign data. Explicit common `cross_check_key` is required before dynamic/formal verdict comparison; a contradictory conclusive pair yields `INCONSISTENCY` plus a separate scoped `INCONCLUSIVE` cross-check result, with original checker results preserved. No project-level verdict is created.

Focused pipeline core + generic verification matrix + multi-project regression: **46 passed**. `python -m compileall -q src tests` succeeded. Full repository regression was not run. Task 6 remains **PARTIAL**: matrix source-model relations are `UNRESOLVED` during ordinary runs unless SourceModelBuilder provenance is present, and known Windows coverage backend failures remain environment-limited. These gaps do not fabricate consistency or coverage results.

## Task 7 follow-up — accuracy catalog and fresh run (2026-10-07)

Corrected the Dynamic catalog label for DYN-005 (it exercises sanitizer-backed memory observation, not a reliable process crash) and added DYN-007, a real subprocess abnormal-termination case. The adapter uses observed POSIX signal termination or Windows access-violation exit status with an explicit no-crash oracle; it does not use catalog expected values to construct the observation. Added catalog tests for each requested scenario class, including BMC unreachable/insufficient bound, SMT unknown/type error, Dynamic crash/timeout, memory defect types/safe, and fuzz crash/no-finding/timeout.

Accuracy tests: **23 passed**. Fresh 60-case benchmark is `t/accuracy-task7-final-20261007.json`; rendered report is `docs/verification-accuracy.md`; evidence workspace and run metadata are in the JSON manifest records (`execution_id=0e785840-4c2a-4f48-bf84-861f322c9c9e`). Counts are fixture-level: **18 TP, 13 TN, 0 FP, 0 FN**. Separate classifications: **14 inconclusive, 1 unsupported, 6 environment-limited, 2 tool errors, 2 build errors, 4 specification errors**. DYN-007 was observed as `crashed=true` and scored TP. All memory sanitizer cases were environment-limited on this Windows MinGW host; coverage remains measurement-only. These counts establish no general checker accuracy, and zero FP/FN here means none occurred in this fixture run. `python -m compileall -q src tests` succeeded; full repository regression was not run.

## Task 8 follow-up — evidence contract checks (2026-10-07)

Extended the per-stage provenance integration test to inspect every manifest Evidence row: stable ID, type, workspace-relative path, SHA-256, timestamp, run ID, checker, stage status, source hash map, tool-version map, full reproducibility configuration and configuration digest. The test resolves every path under the run root and verifies each recorded SHA-256. It now re-runs identical source/options under a different run ID and asserts the reproducibility ID remains equal, then changes only the fuzz seed and asserts the fingerprint changes. Reopen still validates the report/manifest sidecar and all stage execution evidence; report output is checked for forbidden overall-verdict fields.

Focused evidence + pipeline integrity/reproducibility tests: **19 passed** (4 stage/reopen cases and 15 evidence/benchmark-evidence cases). `python -m compileall -q src tests` succeeded. Full repository regression was not rerun. Existing platform limits remain: time-varying process outputs, timestamps and external tool/environment differences can change evidence bytes; reproducibility IDs support comparison and do not promise byte-identical dynamic evidence across runs.

## Task 9 follow-up — continuous GUI workflow (2026-10-07)

Completed the PySide single-session user flow around existing generic APIs. Project and normalized Specification remain in `VerificationSession`; one full-run action forwards configured `PipelineOptions` to the existing pipeline worker, and history reopen loads report/manifest without reloading either input. The GUI settings now expose optional source-model function, finite integer parameter domains and loop bound (passed through existing `SourceModelBuilder`/pipeline options), optional generated C, bounded fuzz configuration, coverage and the independent fixture-level accuracy benchmark. No Specification schema or checker logic changed.

Model review distinguishes a declared Specification graph preview from an explicitly opted-in source-derived model. The latter parses source through `SourceModelBuilder` without executing it and shows status, source hashes and provenance mappings where returned; missing configuration is labeled `UNSUPPORTED`, while parse/domain/entry errors remain visible as diagnostics. Source model construction remains limited to the documented C subset and requires one declared function target plus finite input domains when parameters exist. Pipeline MODEL status remains independently authoritative for the run.

Added a GUI workflow lifecycle list for project/spec load, validation, normalization, source-model construction, review, generation, verification, dynamic, coverage, fuzz, results, evidence, traceability, accuracy, report and run history. Status rows preserve reason, evidence IDs and log context; checker result verdicts remain checker-local. Viewing Accuracy is `UNSUPPORTED` when no benchmark artifact exists. Failed workflow actions open a detail view containing status/reason/evidence/logs. The report continues to omit any aggregate project PASS/FAIL/safety verdict.

GUI/controller/offscreen real-project workflow and generic source-model preview: **36 passed** in a clean GUI run. A broader GUI + pipeline core + multi-project run reported **71 passed, 1 failed** before the domain-key fix; the affected GUI test and controller/session subset then passed **22/22**, and the full suite below passed afterward. Full repository regression: **458 passed, 5 skipped** in 385.30 seconds. `python -m compileall -q src tests` succeeded. PySide6 6.11.2 and Clang were available for these GUI/source-model runs.

Task 9 remains **PARTIAL** against the aspirational full workflow: the run history persists automatically, but opening Accuracy reports outside a run still uses a user file picker; source-derived models support only the audited C subset; and static/memory/coverage/fuzz checker outcomes still depend on configured project templates and host tools. These are shown as scoped unsupported, skipped, inconclusive or environment-limited states instead of project-level PASS/FAIL.

## Task 10 follow-up � Generic verification E2E (2026-10-07)

Added `examples/generic-final-e2e/`, a non-Smart-EV C project with a source-derived branch/state function, executable argument parser, arithmetic, bounded heap allocation/free, dynamic cases with structured stdout oracles, fuzz seed corpus, formal model, and independent accuracy catalog. The same project/specification are retained for one uninterrupted CLI or GUI run. The GUI settings now accept a JSON fuzz seed corpus and source-model target/domains/bound; the GUI run passes these to the existing pipeline without reloading inputs. Generic GUI initialization no longer imports the optional Smart-EV adapter; it is dynamically loaded only for an explicitly selected Smart-EV adapter.

Fixed source-function traceability to resolve source-line mappings from declared source paths and added a regression test. Failed pipeline stages now retain artifacts produced before the exception as linked stage evidence so they cannot become orphan evidence. Added CLI/GUI E2E tests for stage lifecycle rows, scoped results/evidence, manifest hashes and workspace confinement, unchanged source hashes, generated artifact role/source map, real dynamic observations, source-derived model provenance, fuzz campaign, resolved source-function traceability, integrity, one-load workflow, and absence of aggregate verdict fields.

Final focused CLI + GUI E2E and affected regression: **74 passed** in 161.16 seconds. Full repository regression: **464 passed, 5 skipped** in 441.16 seconds. `python -m compileall -q src tests` succeeded. The CLI and offscreen GUI E2E workflows both executed the configured pipeline through report; each final report contains 15 stage rows and has no overall verdict field. CLI run `generic-final-cli-v3` contains 13 result records, all with evidence; 485 stored artifact paths resolve within the run workspace and their SHA-256 hashes match. Source hashes remained unchanged, generated C/header are marked `GENERATED_ARTIFACT` with a source map, model source provenance is `SUPPORTED`, source function mapping resolves (11 states/7 transitions), and traceability integrity is valid. The run includes actual process exit/stdout/structured observations and a four-iteration fuzz campaign. No Smart-EV module is imported by the generic controller path.

Checker outputs remain scoped: CTL/BMC/SMT and the two dynamic cases returned PASS for their declared checks; fuzz returned a scoped failure after two mutated inputs violated the declared exact-output oracle; static findings were INCONCLUSIVE; memory checks were INCONCLUSIVE because sanitizer/leak tooling was unavailable or failed on this Windows host. These are not promoted into an overall project verdict. Task 10 E2E structural DoD is **VERIFIED**; checker conclusions retain those explicit limitations and failures.

## GUI specification format error fix (2026-10-07)

Removed the GUI controller's pre-validation requirement for all three root keys (`schema_version`, `id`, `name`). Native JSON is parsed by the shared Specification loader and validated by the unchanged schema/semantic validator, so incomplete native input reports `SCHEMA_VALIDATION_FAILED` with path/location instead of the misleading �Unsupported specification format� adapter message. Malformed JSON reports the loader's `INVALID_JSON` code and line/column. The optional integration registry now dispatches generic JSON using the native schema-version marker and likewise lets incomplete native documents reach canonical validation; unknown external formats still require an explicitly selected adapter. GUI failure refresh no longer overwrites the useful error detail, and status classification is structured around Specification errors rather than a brittle phrase match. Invalid input can be replaced by a valid spec without reopening the project.

Added controller coverage for missing required fields, invalid schema version, unknown external JSON, and malformed JSON; added offscreen GUI recovery coverage for visible schema diagnostics followed by successful selection of a valid document. Focused controller/adapter/import-boundary/recovery tests: **26 passed, 1 skipped**. GUI and CLI E2E plus GUI regression: **41 passed**. Full regression: **469 passed, 5 skipped** in 490.01 seconds. `python -m compileall -q src tests` succeeded. Specification JSON contract and optional Smart-EV integration behavior remain unchanged.

## Legacy Specification migration + Model/Codegen workflow follow-up (2026-10-07)

### IMPLEMENTED

- Added a Specification Core `legacy_adapter` with content-based legacy teacher format detection, deterministic ID generation, schema-version discovery from the authoritative JSON Schema, field-specific `LEGACY_MIGRATION_FAILED` diagnostics, canonical migration, and shared GUI/pipeline loading. Canonical schema/semantic validation remains unchanged.
- Preserved immutable raw JSON, original hash, canonical JSON/hash, normalized typed Specification and validation state in the retained GUI project session. GUI now passes the exact loaded/validated/normalized values into `PipelineOptions`; CLI/pipeline path loading uses the same adapter.
- Retained the complete original teacher document, duplicate root graph, narrative scenarios, probe/vulnerability declarations, flows and unmapped extension fields in canonical provenance. No function implementation or test oracle is fabricated.
- Added generated-artifact-scoped static and memory analyzer execution on emitted model C/harness in addition to the configured project-source analysis. Generated results carry source hashes and a link to codegen manifest; `production_source=false`.
- Extended C generation metadata with original source specification hashes, explicit Requirement-to-generated-line mapping, and per-function `UNSUPPORTED_NO_IMPLEMENTATION_BODY` mapping when `FunctionSpec` supplies no function implementation. Manifest limitations make this gap visible.
- Documented compatibility audit, migration rules, model graph semantics and limitations, code generation behavior, and continuous workflow.

### VERIFIED

- Fresh CLI acceptance run: `t/legacy-teacher-e2e-runs/legacy-teacher-e2e-final-v5` (`legacy-teacher-e2e-final-v5`). It has 15 stage rows, 50 scoped results, valid traceability, 155 evidence entries with all paths/hashes valid, and no aggregate verdict fields. Original spec SHA-256 stayed `00d6314f32db70e1e8bf1454cfdca02922c126943dbdfae408983a09870f0193`; analyzed source files did not change. Canonical ID `smart_ev_teacher_e2e_v4`, schema `1.0`; model has 28 states, 47 transitions, one initial state. Generated model C source map includes the original specification hash; GCC and Clang both compiled and executed the generated model harness (`CODEGEN` build `PASS`).
- Static and memory analyzers ran on both actual project source and generated model artifacts, each with explicit artifact scope. Their checker records retain actual results including `INCONCLUSIVE`, `TOOL_ERROR`, and `BUILD_ERROR`; generated artifact findings do not claim production source behavior.
- Fresh offscreen GUI acceptance test opened project/spec once and completed the pipeline with the same session context. All expected stage rows were present; model graph counts, codegen build, generated artifact-scoped analysis, evidence/traceability, and no-overall-verdict assertions passed.
- An initial focused run exposed one architecture failure because the moved adapter still recognized the legacy fixture's `gd12_` check-ID prefix. That extraction now uses the declared check IDs generically; affected architecture + adapter + external integration rerun: **8 passed, 1 skipped**. Generated C unit tests: **18 passed**. GUI legacy acceptance: **1 passed**; generic end-to-end regression passed in the full suite.
- Full repository regression: **474 passed, 6 skipped** in 492.63 seconds. `python -m compileall -q src tests` succeeded.

### BLOCKED BY SPECIFICATION CONTENT / ENVIRONMENT

- BMC is `SKIPPED`: no BMC property is declared. Dynamic is `SKIPPED`: the teacher file has nine narrative test cases but no executable input/oracle cases. Coverage and fuzzing are consequently `SKIPPED` with dependency reasons. Accuracy was disabled for the acceptance run.
- The teacher file declares nine function/probe names but provides no implementation bodies, signatures, or source bindings. Faithful generated implementations, function runtime tests, and production-code behavior cannot be inferred from this declaration-only data. They remain `UNSUPPORTED_NO_IMPLEMENTATION_BODY`; no dummy C is created.
- Host analyzers remain scoped: original/generated static results include tool errors/inconclusive findings; ASan/UBSan builds failed and leak support is unavailable. These are not transformed into PASS.

### NOT IMPLEMENTED

- Automatic synthesis of arbitrary function implementations from declaration-only `FunctionSpec`/legacy function names.
- Executable dynamic/fuzz/coverage tests from narrative prose without concrete inputs and independent oracles.
- A fresh manual desktop acceptance on the user's interactive display; GUI verification was a real offscreen PySide runtime acceptance.

## Dynamic Testing and Coverage GUI analysis update (2026-10-07)

- `DynamicPage` now projects per-testcase checker verdicts, execution counts, actual observations from the persisted execution index, oracle expectations, and result/evidence details. Double-clicking a testcase opens its scoped result and linked execution record.
- Dynamic and coverage lifecycle states/reasons are summarized independently. A skipped or unavailable coverage stage is explicitly presented without synthetic metrics.
- Coverage output shows real aggregate line/branch measurements and per-file measurements when available, together with backend and limitations. Coverage remains measurement-only.
- Focused offscreen GUI integration tests cover skipped-stage explanations, real observation display, scoped failure, and aggregate/per-file coverage rendering.

## CODEGEN and Fuzzing GUI workflow update (2026-10-07)

- Added a dedicated CODEGEN navigation page. It projects generated file classes and hashes, source-map entries, compiler/build/execution records, and offers a source preview only after resolving the artifact within the run directory and validating both evidence and generated-manifest SHA-256 values.
- The CODEGEN page action enables the existing generic code-generation option and reruns the pipeline using the current project/specification session. Generated C is explicitly labeled `GENERATED_ARTIFACT`; it is not production source.
- The Fuzzing page now renders skipped reasons even when the run produced no checker result, and shows campaign strategy, seed, bounded execution/corpus/finding metrics, stop reason, source integrity, coverage feedback, and evidence when available.
- The Fuzzing page action enables the existing campaign configuration and reruns the pipeline without reloading the project/specification. If no test template or source target is available, the stage remains skipped with its backend reason.
- Offscreen GUI tests cover disabled/skipped stages, optional-stage run actions, a bounded inconclusive campaign projection, generated artifact preview/hash rejection, and source-map/build projection.
- Function declarations without implementation semantics appear in the CODEGEN Functions table with declared language and `UNSUPPORTED_NO_EXECUTABLE_CONTRACT`; source-bound functions are marked `SOURCE_BOUND_NOT_GENERATED`.

### CODEGEN default source selection correction (2026-10-07)

- The generated manifest is alphabetically ordered, so `include/model.h` preceded `source/model.c`; selecting row 0 displayed the header as the default preview. The GUI now selects `source/model.c` first, then the first `.c` artifact when that canonical path is absent. Other artifacts remain selectable from the artifact list.
- The source is loaded only after manifest/evidence hash validation; its generated path, artifact class, and digest remain available in the artifact list.
- Comparison against the persisted `legacy-teacher-e2e-v4` run confirms the user's header digest `2422aa42d6dd671f96eef0a8b3e20f0dd3ff30a62f5243d454ed8a6bdefd77a2` is the generated `include/model.h`; the same run records source specification hash `00d6314f32db70e1e8bf1454cfdca02922c126943dbdfae408983a09870f0193`, model hash `db6de4038ca3a181f507fe8e78e98132de4871b6b17a61ac30ca358c77ecdd8e`, 28 states, and 47 transitions.
- CODEGEN now emits a Python runtime for the declared Kripke model alongside C, and BUILD runs that Python artifact and stores its observation. Teacher-style C/Python probe bodies are still not generated: legacy probe metadata is not an application function contract.
- Regression verification for this correction is recorded with the implementation change.

## Fuzzing workflow visualization update (2026-10-07)

- The Fuzzing page has separate Process, Coverage, Technique Comparison, and Source Flow/CFG tabs.
- The process diagram branches across Boundary, Black-box, Mutation, Coverage-guided, and Concolic choices. It reports the selected/effective strategy, execution/corpus/finding/evidence counts, coverage feedback, and lifecycle states from the campaign report. Unselected strategies are visibly not run; Concolic remains unsupported because source branch tracing/replay is not implemented.
- Coverage rows are populated only from the Coverage stage measurement and explicitly retain its lifecycle and limitations. Technique comparison keeps stage lifecycle separate from checker-specific result statuses and evidence counts.
- The C flow tab displays source-to-state/transition locations only when source-derived model provenance is present. It labels that bounded abstraction clearly and shows unsupported constructs; it does not claim to render a complete compiler CFG when such data is absent.
- GUI tests cover skipped campaigns, selected versus unselected strategies, unsupported Concolic, inconclusive checker verdicts, measured coverage, source-model mappings, and the diagram's offscreen paint path.

## Specification-declared function source generation follow-up (2026-10-07)

### IMPLEMENTED

- The Specification JSON/schema contract is unchanged. Legacy function rows are
  carried into a separate provenance projection with the original input hash.
- CODEGEN now includes a generic registry for declared C `buffer_copy` and
  `alloc_release` and Python `divide` and `magic_value` semantics. C emission
  uses the existing C IR. Unsupported kinds/metadata are explicit. Outputs are
  deterministic and classified as `GENERATED_ARTIFACT` / `PROBE_ONLY`, with
  `production_source=false`, source maps, function/requirement IDs and hashes.
- C generation harness compiles with discovered gcc/clang and runs only its
  listing mode. Python artifacts are parsed and listing mode is executed. Build
  and process logs are persisted to ArtifactStore. STATIC and MEMORY receive
  generated functions in explicitly generated-probe scope; zero-argument
  memory probes use actual sanitizer/structural tool execution, while missing
  concrete function inputs are explicitly unsupported.
- GUI CODEGEN shows C and Python generated text from resolved, hash-checked
  evidence, per-function support metadata, source map, and build/execution
  records. It can export the selected source artifact.

### VERIFIED

- Focused legacy adapter + generator + generic fixtures + GUI tests: **43
  passed**. Post-cleanup GUI localization and codegen regression: **16 passed**.
- Full repository suite before the final GUI localization cleanup: **492
  passed, 6 skipped, 1 failed**. The one failure was the GUI localization
  source check on the newly replaced CODEGEN page. After cleanup, the directly
  affected localization and page suites passed; a full post-cleanup rerun was
  not performed.
- `python -m compileall -q src tests`: **passed**.

### NOT IMPLEMENTED / ENVIRONMENT LIMITED

- This is registered-semantics generation, not arbitrary function synthesis.
  Unknown kinds or absent/invalid metadata remain `UNSUPPORTED`.
- Generated function probes are not automatically fed into dynamic testing,
  coverage or fuzzing. The current declarations provide no concrete test input
  and independent oracle. These stages continue to use their configured
  project-source inputs; no generated testcase/oracle is invented.
- Sanitizer/leak findings depend on host tools and are reported as observed
  scoped checker results. Declared expected vulnerabilities/CWE mappings are
  metadata only and do not create findings or production-source verdicts.
- The declaration format supplies no reliable binding to a production source
  body; generated source locations are declarations or `UNRESOLVED`.

Overall task status: **PARTIAL**. Core generation, persistence, presentation,
and scoped static/memory integration are implemented. Full dynamic/coverage/
fuzz consumption and a full regression after the last GUI-only fix remain
unverified or not implemented; this audit does not mark the task complete.
