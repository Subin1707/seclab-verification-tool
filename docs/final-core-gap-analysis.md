# Final Core Gap Analysis and Architecture Freeze

Audit date: 2026-10-05  
Repository: `E:\seclab-verification-tool`  
Scope: source, tests, schemas, existing architecture/core/validation documentation, generic CLI/GUI and benchmark surfaces. Generated run directories (`t/`, `.runs/`), caches and packaged metadata were excluded from source inventory. No implementation was changed for this audit.

## Architecture freeze

SecLab is a generic software verification workbench. A user supplies an arbitrary supported project directory, specification fragments, optional generic pipeline settings, and an external toolchain. Current source ingestion is centered on C and C++ translation units and headers; the finite model/formal APIs can also be used independently of source-language support. Smart-EV is an optional external-format adapter and probe fixture only. Its adapters live under `seclab.integrations`; the architecture import-boundary suite checks the generic core does not import integrations or embed Smart-EV markers. No Smart-EV repository was read or modified for this audit.

The core does not produce an aggregate project PASS/FAIL. Checker results are scoped `VerificationResult` records; stage lifecycle is recorded separately. Specification v1/v2 contracts and the current result/evidence/stage contracts are frozen for this task. This document proposes future work only; it does not authorize changing those contracts or checker semantics.

### Current architecture and dependency graph

```text
External project + specification + generic options
             |                         |
        Generic CLI              Optional PySide6 GUI
             |                 project/settings/report controllers
             +-------------------------+
                           |
                Pipeline API / stages
                   /              \
       Specification + Model       Source + Execution
          |       |                   |      |
       CTL/BMC   SMT                Static  Memory  Dynamic
                                                |       |
                                      Results / Coverage
                                                   |
                                             Fuzzing
                           |
             Results + Evidence + Traceability
                           |
                    Pipeline report

Optional boundary: external format adapters and case studies under
seclab.integrations -> generic specification/pipeline APIs (one way only).
Benchmark is an adjacent checker-local evaluation harness; it is not a
project-verdict stage.
```

The intended direction is UI/CLI/adapters → pipeline → generic core. Coverage and fuzzing reuse dynamic test/execution primitives. Results and evidence are shared infrastructure consumed by pipeline/report and benchmark outputs. `tests/architecture/test_import_boundaries.py` is the executable guard for the integration boundary.

### Area classification matrix

`IMPLEMENTED_AND_VERIFIED` means the repository contains substantive implementation and relevant passing unit/integration tests in its latest documented baseline; it does not claim general soundness. `IMPLEMENTED_BUT_INCOMPLETE` marks explicit scope/feature gaps. `PLACEHOLDER` means an API exists but intentionally does not execute the named capability. `ENVIRONMENT_LIMITED` means implementation exists but verification/runtime evidence depends on host tooling. Classification applies to the named area, so one row can mention both a capability limitation and its tested supported path.

| Area | Classification | Existing API / implementation | Audit finding and evidence |
|---|---|---|---|
| Specification | IMPLEMENTED_AND_VERIFIED | `Specification`, `load_specification`, `validate_specification`, `normalize_specification`; schema files under `schemas/` | Typed v1/v2 input models, JSON Schema and semantic validation, fragment loading and deterministic normalization. Unit tests in `tests/unit/specification`; examples and integration pipelines. Contract intentionally unchanged. |
| Model / Kripke | IMPLEMENTED_AND_VERIFIED | `KripkeStructure`, `State`, `Transition`, `generate_kripke_structure`, reachability/export APIs | Explicit finite graph construction, validation, reachability, deadlock handling and deterministic exports. Unit and specification-to-model integration tests. Source code is not generally translated into a model. |
| CTL | IMPLEMENTED_AND_VERIFIED | `parse_ctl`, `validate_ctl_formula`, `sat`, `check` | Supported CTL fragment and finite explicit-state fixed-point checker; selected witness/counterexample forms only. Unit and spec-to-CTL tests. General C/C++ temporal semantics and witnesses for every formula shape are outside current scope. |
| SMT | IMPLEMENTED_AND_VERIFIED | `parse_expression`, `SMTEncoder`, `SMTVerifier`, backend protocol/Z3 | Supported expression/type/domain subset over one valuation, with outcomes/evidence. Unit tests and real Z3 specification pipeline integration. Division is explicitly unsupported; no source or transition semantics. |
| BMC | IMPLEMENTED_AND_VERIFIED | `BMCEncoder`, `BMCChecker`, completeness and trace APIs | Bounded bad-state reachability over supplied explicit finite graphs; validated traces and graph completeness. Unit tests and real-Z3 integration. Not source-C BMC or CBMC. |
| Source loading | IMPLEMENTED_BUT_INCOMPLETE | `SourceLoader`, `LanguageDetector`, `FunctionDetector` | Tested deterministic C/C++ file discovery, hashes and conservative lexical function discovery. No general compiler AST/database ingestion; complex declarations/templates/macros may be omitted. Additional languages are unsupported. |
| C code generation | MISSING | No generic C code-generation package/API found; `testing.HarnessGenerator` generates test harness C, not SUT/model C | No model-to-C or verification-code generation capability identified. Harness generation is covered under dynamic testing and must not be conflated with general code generation. |
| Static analysis | IMPLEMENTED_BUT_INCOMPLETE | `StaticAnalyzer`, `CppcheckRunner`, `CompilerDiagnosticsRunner`, `ClangTidyRunner`, parsers/findings/CWE mapper | Substantive adapters, parsing and evidence, with tests. Clean/findings remain scoped inconclusive. Analyzer-specific coverage and independent false-positive/negative benchmark denominators remain limited. Standalone `ClangStaticAnalyzerRunner` is a placeholder. |
| Memory analysis | ENVIRONMENT_LIMITED | ASan/UBSan runners, parsers, `StructAnalyzer`, `LeakChecker` | Sanitizer path and unsupported cases are implemented and tested, but host runtime/compiler support blocks some outcomes (notably sanitizer benchmark cases on recorded Windows/MinGW environment). `StructAnalyzer` explicitly does not infer layouts. |
| Dynamic testing | IMPLEMENTED_BUT_INCOMPLETE | `TestCase`, oracles, `HarnessGenerator`, `TestRunner`, `TestGenerator` | Build/execute/oracle flow and C/C++ harness path tested. Harness supports a conservative scalar signature subset; unsupported signatures/types remain unsupported. Generated cases derive only supported finite domains and are not a complete test-generation strategy. |
| Coverage | IMPLEMENTED_BUT_INCOMPLETE | `CoverageRunner`, gcov/LLVM backends, parsers/reports | Isolated per-test instrumentation, aggregation and coverage deltas tested. Backend semantics differ and platform/toolchain limitations can yield partial/error outcomes. Measurement only; no safety verdict. |
| Fuzzing | IMPLEMENTED_BUT_INCOMPLETE | `FuzzEngine`, black-box/boundary/mutation/coverage-guided strategies, corpus/minimizer/crash analyzer; explicit `ConcolicGenerator` | Bounded generic input campaigns and evidence tested. Concolic generation solves caller-supplied constraints only; `FuzzEngine` has no instrumentation/branch-trace adapter and labels CONCOLIC unsupported. No finding within budget is inconclusive. |
| Evidence | IMPLEMENTED_AND_VERIFIED | `Evidence`, `ArtifactStore`, `EvidenceCollector`, `RunManifest` | Hashing, path containment, manifest references and pipeline artifact integrity are tested. Evidence meaning depends on the emitting adapter and declared scope. |
| Traceability | IMPLEMENTED_BUT_INCOMPLETE | Pipeline traceability mapping/report and manifest result trace records | Requirement→property/test→result/evidence is implemented and exercised by generic matrix. Source association is available where supported; formal model properties do not automatically establish a link to implementation source. |
| Report | IMPLEMENTED_BUT_INCOMPLETE | `PipelineReport`, JSON persistence, `ReportPage` | Pipeline JSON report and checker-local counts, limitations, stages, traceability and history exist. GUI HTML/PDF exports are disabled; no aggregate project verdict is permitted. |
| Pipeline / orchestration | IMPLEMENTED_AND_VERIFIED | `PipelineOptions`, stage contracts, `PipelineOrchestrator`, `run_full_verification` | Twelve deterministic stages, prerequisite closure, independent-stage progress, skip/failure isolation, source/artifact integrity and report assembly tested. It orchestrates only currently supported source/tool adapters. |
| Accuracy benchmark | IMPLEMENTED_BUT_INCOMPLETE | `BenchmarkCase`, catalog, production adapters, comparator/runner/report/CLI | Checker-local ground-truth comparison and evidence persistence are present; catalog coverage remains fixture-specific and environment-limited. Results do not establish broad checker accuracy. Some historical docs/report totals are stale relative to the current catalog; rerun is required for current numbers. |
| GUI | ENVIRONMENT_LIMITED | Optional PySide6 app, controllers/session, pages/widgets | Controllers and GUI wiring have tests; offscreen runtime smoke depends on PySide6, absent in the previously documented host. GUI project workflow cannot be claimed runtime-verified here. HTML/PDF and cancellation/live per-check progress are absent. |
| CLI | IMPLEMENTED_AND_VERIFIED | `seclab.cli` generic `verify`; `seclab.benchmark` CLI | Project/spec/workspace/stage/config/run ID route into pipeline. Help and generic fixture flows are documented/tested. Exit zero denotes orchestration/report completion, not project correctness. |
| Tests | IMPLEMENTED_BUT_INCOMPLETE | 123 test source files across unit, integration, pipeline, GUI, benchmark, mutation and architecture suites | Broad subsystem and generic multi-project coverage exists. The known canonical baseline is dated 2026-10-04 and predates this audit/current catalog changes; this task reruns the suite. Test success does not prove soundness. GUI/sanitizer/symlink/opt-in integrations can skip by environment. |

### Dependency and audit reference map

| Area | Primary source locations | Primary test locations / docs |
|---|---|---|
| Specification | `src/seclab/specification/`, `schemas/` | `tests/unit/specification/`, `tests/integration/test_specification_to_model.py`, `docs/specification-format.md` |
| Model, CTL, SMT, BMC | `src/seclab/model/`, `src/seclab/formal/{ctl,smt,bmc}/` | `tests/unit/{model,ctl,smt,bmc}/`, `tests/integration/test_{specification_to_ctl,smt_specification_pipeline,bmc_real_z3}.py`; corresponding `docs/*-core.md` |
| Source and C harness generation | `src/seclab/source/`, `src/seclab/testing/harness_generator.py` | `tests/unit/source/`, `tests/integration/test_source_execution_pipeline.py`, `tests/unit/execution/` |
| Static and memory | `src/seclab/static_analysis/`, `src/seclab/memory/` | `tests/unit/{static_analysis,memory}/`, `tests/integration/test_static_memory_integration.py`, `docs/static-memory-core.md` |
| Dynamic, coverage, fuzzing | `src/seclab/testing/`, `src/seclab/coverage/`, `src/seclab/fuzzing/` | `tests/test_dynamic_testing_core.py`, `tests/unit/{coverage,fuzzing}/`, `tests/integration/fuzzing/`, `docs/{dynamic-testing,coverage,fuzzing}-core.md` |
| Results/evidence/traceability/report/pipeline | `src/seclab/{results,evidence,pipeline}/` | `tests/unit/{results,evidence}/`, `tests/pipeline/`, integration generic matrices; `docs/{results-evidence,pipeline-core}.md` |
| Benchmark | `src/seclab/benchmark/` | `tests/benchmark/`, `docs/verification-accuracy-audit.md`, `docs/accuracy-contract.md` |
| GUI / CLI / isolation | `src/seclab/gui/`, `src/seclab/cli.py`, `src/seclab/integrations/` | `tests/gui/`, `tests/integration/gui/`, `tests/architecture/`, `docs/{gui-core,architecture-isolation}.md` |

## Gaps in generic core capability

The entries below identify the current API/implementation, missing behavior and the validation/integration work needed later. “Evidence gap” distinguishes missing product evidence behavior from missing audit evidence. GUI references mean visibility/control integration in the app; CLI means input/output access where applicable.

| Gap and priority | Existing API / implementation | Missing behavior | Missing tests | Missing evidence | Missing GUI / CLI integration | Dependencies |
|---|---|---|---|---|---|---|
| Source-to-model and implementation semantics (P0) | Specification/model constructors; source inventory and lexical function IDs; CTL/BMC over explicit graphs | A justified, generic mapping from supported source constructs to executable/formal models, with explicit unsupported constructs and sound scope | Cross-check generated models against independently defined source behavior, plus unsupported-language/construct fixtures | Model provenance, source-to-model mapping and validation records attached to each result | Surface model provenance/limitations and configuration in GUI/CLI; current model UI can show supplied/generated model only | Parser/compiler frontend, source identity, specification validation, model schema; this is a foundational research/engineering project |
| C code generation (P1, only if required by product roadmap) | C `HarnessGenerator` for supported dynamic test signatures; no general generator | General, safe code generation from model/specification or intermediate representation is absent | Generator golden tests, compile/execute equivalence, malformed/unsupported model cases | Generated-code origin, input/model hash, compiler and build outputs | GUI generation preview/config and CLI output selection do not exist | Stable generic IR/spec contract; do not alter frozen Specification contract without separate version review |
| Source loader/frontend completeness (P1) | C/C++ file and function lexical discovery | Compiler-backed declarations, compile database ingestion, robust preprocessing and configurable additional language backends | Multi-file include/macro/template/function-pointer fixtures across compilers; conservative unsupported diagnostics | Compilation database and parser/frontend version/config provenance | GUI source inventory already exists; expose selected frontend/config; CLI config needs typed validation | External compiler frontend/tool adapters; generic source API compatibility |
| Static analyzer breadth/accuracy (P1) | Existing Cppcheck/compiler/Clang-Tidy adapters and normalized findings | Standalone Clang Static Analyzer driver; broader language/tool coverage and independently calibrated analyzer outcomes | Defect-free/defect-positive independent corpus, syntax/unsupported cases per adapter, parser fuzz tests | Retained raw tool output/finding/source hashes are implemented; missing benchmark-validated semantic confirmation and broader reproducible fixtures | Analyzer/config selection exists in settings/CLI options; expose unsupported capability reason and benchmark results consistently | Tool discovery, compilation databases, parser contracts, benchmark ground truth |
| Memory layout and broader analyzer support (P1) | ASan/UBSan runner/parsers, `StructAnalyzer` unavailable result | Compiler-backed struct layout probes; dependable supported-host sanitizer matrix; broader resource/memory classes | Supported Linux/macOS/Windows compiler CI and clean/defect fixtures, struct packing/alignment/anonymous/nested types | Toolchain capability probes and layout provenance; sanitizer raw artifacts exist but need supported-host CI evidence | GUI currently renders findings/limits; add clear capability and layout view; CLI options/report for layout absent | Compiler ABI, isolated probe build/run, host matrix, evidence schema use (no contract change presumed) |
| Dynamic harness/type support (P1) | Test/oracle APIs, function discovery, C/C++ harness for finite scalar subset | Pointers, arrays, structs, callbacks, complex C++ methods/namespaces/mangling and user harness/plugin extension | Per-type compile/runtime/oracle fixtures and unsupported diagnostic tests | Argument encoding and harness source are retained; need structured type/layout provenance for expanded types | GUI test editor and CLI input currently cover declared cases/settings, not arbitrary harnesses | Compiler-backed function/type metadata, source loader, oracle semantics, isolation |
| Coverage portability and comparability (P1) | gcov and LLVM backend interfaces and normalized reports | Stable cross-backend meaning, broader host/compiler coverage, resilient partial-data reconciliation | Cross-platform backend conformance and corrupted/missing profile cases | Existing raw profile/backend artifacts; add environment capability evidence to reproducible runs | GUI shows selected metrics; add backend-specific definitions/tool diagnostics. CLI supports backend selection | Compiler/toolchain matrices, source identity, dynamic runner |
| Concolic fuzz integration (P2) | `ConcolicGenerator.solve_alternate(BranchConstraint)` using SMT; fuzz engine refuses unsupported CONCOLIC | Instrumented branch trace capture, symbolic path constraints, feedback/replay integration | End-to-end branch flip, infeasible path, multi-variable and source-map tests | Branch trace, constraint, solver query, generated input and replay artifacts | GUI strategy currently can represent but may report unsupported; CLI config needs documented supported-input diagnostics | Instrumentation/compiler, branch/source mapping, SMT; explicit handling of unsupported source constructs |
| Generic GUI runtime/report completeness (P1) | PySide6 pages/controllers, session, JSON report export | Runtime-verified supported environment; HTML/PDF, cancellation, per-check progress are absent | Qt-enabled desktop/offscreen CI and manual workflow; history/path/error cases across OS | GUI export artifact provenance and run/capability state are not implemented for HTML/PDF | Existing GUI lacks HTML/PDF/cancel/per-check controls; CLI provides JSON report through run artifacts | Optional PySide6; pipeline cancellation/progress API would be prerequisite for controls |
| Traceability to implementation source (P1) | Requirement/property/test/result/evidence links; source/function inventory mappings | General proof that implementation source implements the model/property, versus current inventory/coarse source-set association | Source mapping correctness on independent multi-file projects and stale/mutated source cases | Model/source mapping and claim-scope evidence | GUI can display mappings but should expose missing-link state; CLI report already serializes available links | Source frontend, source-to-model gap, stable mapping identifiers |
| Benchmark accuracy and reproducibility (P1) | Catalog-authored cases, production adapters, comparator and evidence artifacts | Broad independent corpus, multi-environment reproducibility, consistent current report generation; old docs must be reconciled | Expand adversarial/metamorphic cases, mutation against production checker implementation, adapter/platform matrix | Current framework retains references/hashes; ensure every report captures run metadata and regenerate checked-in snapshot from same catalog | Benchmark CLI exists; GUI can open a selected report but has no guided benchmark execution | Checker-local truth design, supported toolchains, immutable fixture provenance |

Not classified as a missing capability: the pipeline intentionally has no overall project verdict. No milestone below adds one.

## Exact future implementation order

Each item is a future milestone and requires a separate implementation task. Keep checker semantics and Specification contract frozen unless a dedicated contract/version review authorizes a change.

1. **M1 — Freeze baseline and supported-capability inventory.** Run full pytest/compileall in CI; record exact skipped reasons, tool versions, supported source language/tool matrix and regenerate stale benchmark/validation reports. Preserve generic integration import boundary. Do not change checker outputs.
2. **M2 — Source frontend and provenance design.** Define an internal, versioned implementation IR/provenance mapping that consumes current Specification without modifying it. Select compiler frontend adapters, define unsupported syntax behavior, and validate source hashing/compilation database discovery. Deliver design and independent fixtures before implementation.
3. **M3 — Source-to-model semantics.** Implement only a declared source subset; map constructs to explicit states/transitions with provenance, validate against independent expected models, and report unsupported constructs. Retain finite-model CTL/BMC semantics; do not imply source safety beyond mapped subset.
4. **M4 — Dynamic harness type expansion.** Reuse the frontend metadata to support additional C/C++ value types and optional user harness adapters. Compile/run equivalence and scope diagnostics before exposing new GUI/CLI inputs.
5. **M5 — Analysis capability completion.** Implement standalone static analyzer driver and compiler-backed struct-layout probe; establish multi-OS sanitizer/analyzer CI. Preserve tool/build/environment distinctions and current result contract.
6. **M6 — Coverage/fuzz feedback.** Establish backend-specific metric conformance first, then instrumented branch-trace capture for concolic path flips and replay. Keep coverage measurement-only and bounded fuzz no-finding inconclusive.
7. **M7 — Traceability completion.** Connect requirement→spec/model→source constructs→test/result/evidence only where mappings are validated. Expose missing/partial source links explicitly, without a combined verdict.
8. **M8 — Accuracy benchmark and evidence strengthening.** Expand independent ground truth by checker and platform, test production implementations with mutations/adversarial cases, regenerate benchmark docs from timestamped runs, and maintain per-checker metrics only.
9. **M9 — GUI/CLI parity and runtime validation.** Add supported-capability explanations and new generic inputs, run Qt workflow CI, and implement any requested report export/cancellation only after stable pipeline APIs exist. Keep GUI as a projection of core APIs.

## Definition of Done for future milestones

| Milestone | Definition of Done |
|---|---|
| M1 Baseline | Full pytest and compileall results recorded with interpreter/OS/tool versions and skip reasons; checked-in reports generated from the current catalog/run; generic architecture test passes; no project verdict. |
| M2 Frontend design | Internal IR and provenance documented; frontend/version/license/tool failure policy documented; supported and rejected syntax cataloged; independent expected IR fixtures agreed; Specification JSON and public contract unchanged. |
| M3 Source-to-model | Every accepted construct has semantics and source mapping; independent differential fixtures pass; unsupported constructs produce explicit scoped non-verdict outcomes; CTL/BMC results are attributable to the mapped subset; no source behavior silently omitted. |
| M4 Harness expansion | Each added type has compile/runtime/oracle tests on supported compilers; generated harness and argument encoding are evidenced; unsupported ABI/signature reports remain explicit; original source hash unchanged. |
| M5 Analysis completion | Standalone analyzer executes through shared command/evidence APIs; struct probe reports compiler/ABI/layout provenance; sanitizer and analyzer matrices pass on declared hosts; tool/build/environment outcomes remain distinct. |
| M6 Feedback | gcov/LLVM reports define backend-specific counters and pass fixtures; concolic engine consumes captured trace/constraints and generated inputs replay; infeasible/unsupported/error cases are tested; no finding stays inconclusive. |
| M7 Traceability | Validated source mappings link only the claims they support; stale source or absent mapping is visible; each result/evidence reference resolves and hashes; no implied link or aggregate verdict. |
| M8 Benchmark | Cases have independent provenance and expected outcomes; production output cannot mutate expected data; supported host runs are reproducible with raw evidence and hashes; nonbinary outcomes remain outside TP/TN/FP/FN; metrics remain checker-local. |
| M9 UI/CLI | Generic controls map to existing typed core options; Qt-enabled smoke and documented user workflow pass; CLI help/config/errors are tested; exported reports are reproducible; stage/result semantics remain distinct and there is no project-wide verdict. |

## Risks

1. **Overclaiming source verification:** explicit finite-model proofs and source inventory do not prove the C/C++ implementation conforms to that model. Source-to-model work is foundational and should be scoped narrowly.
2. **Frozen Specification contract pressure:** richer source/type semantics may tempt specification field changes. Treat any such proposal as a separately versioned compatibility decision.
3. **Tool and host variability:** sanitizers, static analyzers, compilers, gcov/LLVM and PySide6 vary by platform/version; unsupported must never silently become a clean result.
4. **False confidence from benchmark metrics:** current catalog cases are controlled and finite; accuracy is fixture-local. Environment-limited denominators and stale reports can distort summaries.
5. **Lexical discovery omissions:** missing functions/includes can lead to incomplete dynamic analysis or source traceability unless limitations are surfaced.
6. **Generated harness trust boundary:** generated test code must remain isolated, attributable, and distinguishable from production source in evidence.
7. **Traceability overstatement:** requirement links to abstract properties are not automatically links to implementation lines or proof of conformance.
8. **GUI environment gap:** controller tests do not establish desktop runtime behavior when PySide6 is unavailable.
9. **Feature-order dependency:** concolic fuzzing, source traceability and model generation depend on reliable source frontend/provenance; implementing them first would encode brittle assumptions.

## Audit commands and baseline

Requested commands for this audit:

```powershell
pytest
python -m compileall -q src tests
```

Results from this audit run are recorded after execution below. The repository’s prior documented baseline in `docs/architecture-freeze.md` was 282 passed, 5 skipped, 0 failed and compileall passed (2026-10-04). It is historical and must not be mistaken for the run on 2026-10-05. Known skip/environment dimensions in the prior record include absent PySide6, opt-in external Smart-EV specification test, sanitizer host support, and symlink availability.

| Check | Result |
|---|---|
| Literal `pytest` command | Could not start: `pytest` is not on this PowerShell PATH. |
| Full suite via repository environment (`.venv\Scripts\python.exe -m pytest`) | Exit 0; **324 passed, 4 skipped, 0 failed** in 311.25s; 328 collected. Skips observed: opt-in real Smart-EV spec (1), two sanitizer cases (2), and source-loader symlink case (1). GUI smoke ran and passed in this environment. |
| `python -m compileall -q src tests` via repository environment | Exit 0. |

The test command used the repository’s existing virtual environment because the requested console entry point was not installed on PATH; no dependencies were installed. The skipped external specification is an opt-in adapter integration test and does not make Smart-EV a core dependency.

## Scope record

This is architecture documentation and audit only. No feature implementation, checker semantics, Specification contract, Smart-EV source, integration behavior, or overall project verdict is changed or created.
