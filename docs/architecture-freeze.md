# SecLab Architecture Freeze — Phase 0

Audit date: 2026-10-04  
Repository: `E:\seclab-verification-tool`  
Environment: Windows 11, Python 3.12.5, pytest 8.4.2. PySide6 is not installed.

This document records the current public architecture and behavioral contracts
to protect before correctness work continues. It is an audit baseline, not a
claim that every checker is correct or that the tool has a project-wide
verification verdict.

## Baseline

Commands run from the repository root:

```powershell
python -m pytest -q --basetemp=t\q
python -m compileall -q src tests
```

| Check | Result |
|---|---|
| Full test suite (`python -m pytest -q --basetemp=t\q`) | Exit 0; 282 passed, 5 skipped, 0 failed in 194.19s |
| Skip-reason confirmation (`python -m pytest -q -rs --basetemp=t\q`) | 282 passed, 5 skipped, 0 failed in 166.87s |
| Compile | Exit 0; `src` and `tests` compiled |
| PySide6 | Not installed; GUI runtime tests are skipped and GUI launch is unverified |
| CLI entry point | `python -m seclab.cli --help` succeeds; generic `verify` subcommand is available |

The five skipped pytest items were:

- GUI smoke module: PySide6 is not installed.
- External Smart-EV specification integration: it requires explicit
  `SECLAB_REAL_SMART_EV_SPEC` opt-in.
- Two sanitizer integration cases: AddressSanitizer instrumentation is
  unsupported by the available compiler/runtime.
- Source-loader symlink case: symlinks are unavailable in this environment.

No test failed. The focused `-rs` confirmation had the same pass/skip counts as
the required quiet run.

## Architecture and dependency direction

```text
External project + specification + optional generic config
                         |
                 CLI / GUI controllers
                         |
                 Pipeline API / stages
                         |
  Specification -> Model -> CTL / BMC / SMT
  Source -> Execution / Static / Memory / Dynamic
                    Dynamic -> Coverage / Fuzzing
                         |
              Results + Evidence + Traceability
                         |
                  Pipeline report
```

The top-level package is `src/seclab`. The principal areas are:

| Area | Responsibility |
|---|---|
| `specification` | JSON loader, v1 input/model contract, schema/semantic validation and deterministic normalization |
| `model` | Explicit finite-state Kripke structures, state generation, reachability and deterministic graph export |
| `formal/ctl` | CTL AST/parser, vocabulary validation, finite model checking and witness/counterexample results |
| `formal/smt` | Expression parser/type checker, deterministic query encoding, solver interface and Z3 backend |
| `formal/bmc` | Bounded bad-state reachability over explicit finite models, traces and completeness analysis |
| `source` | Supported source discovery, C/C++ language identification, hashes and conservative function discovery |
| `execution` | Command/process execution, compilation, timeout/environment capture and result/evidence adapters |
| `static_analysis` | Analyzer adapters, diagnostic parsing, normalized findings and CWE mapping |
| `memory` | Sanitizer execution/parsing, memory findings and structural-analysis limitation reporting |
| `testing` | Declared test cases/oracles, harness generation and dynamic execution |
| `coverage` | gcov/LLVM coverage parsing, measurement, aggregation and deltas |
| `fuzzing` | Bounded input generation/campaigns, crash/oracle analysis, minimization and optional coverage feedback |
| `results` | Shared scoped verification result/status model and raw-outcome classifier |
| `evidence` | Artifact metadata/storage, SHA-256, evidence collection and run manifest |
| `pipeline` | Generic stage dependency graph, orchestration, isolation, traceability and report assembly |
| `benchmark` | Static expected-ground-truth catalog, production adapters, expected/actual comparison and per-checker metrics |
| `cli` | Generic project/specification/config/stage input to the pipeline API |
| `gui` | Optional PySide6 projection/controller layer over project, pipeline and report APIs |
| `integrations` | Optional external-format adapters and standalone integration fixtures; not imported by generic cores |
| `workflows` | Higher-level generic workflow presets layered on core and pipeline APIs |

The intended dependency direction is adapter/UI to pipeline to core APIs.
Generic areas are checked by `tests/architecture/test_import_boundaries.py`
for integration imports and known Smart-EV domain markers. Smart-EV format
translation and opt-in probes are in `src/seclab/integrations/`; the project
is not a dependency of the generic CLI or pipeline.

## Public API surface

These package exports are the current supported Python entry points. Internal
helpers outside these exports are not frozen as public API.

| Package | Public entry points |
|---|---|
| `seclab.specification` | `load_specification`, `validate_specification`, `normalize_specification`, `LoadedSpecification`, `Specification` and specification entity/error models |
| `seclab.model` | `KripkeStructure`, `State`, `Transition`, `generate_kripke_structure`, `generate_state_space`, reachability/deadlock helpers and graph serializers |
| `seclab.formal.ctl` | `parse_ctl`, CTL AST/operators, `validate_ctl_formula`, `sat`, `check`, `CTLCheckResult` |
| `seclab.formal.smt` | `parse_expression`, `SMTEncoder`, encoded query/types/errors, `SMTVerifier`, solver protocol/backend/outcomes and counterexamples |
| `seclab.formal.bmc` | `BMCChecker`, `BMCEncoder`, completeness analysis, trace decoding and BMC result/query/error models |
| `seclab.source` / `seclab.execution` | Source loader/detectors; `Compiler`, `CommandRunner`, `ProcessRunner`, command/process specs/results, environment and result adapters |
| `seclab.results` | `VerificationStatus`, `VerificationResult`, `ResultClassifier`, `RawOutcome`, `ClassificationInput`, `ResultCollector` |
| `seclab.evidence` | `Evidence`, `EvidenceType`, `ArtifactStore`, `EvidenceCollector`, `RunManifest` |
| `seclab.static_analysis` / `seclab.memory` | Analyzer runners, parsers, normalized findings, sanitizer runners and memory analysis results |
| `seclab.testing` | `TestCase`, oracle declarations/evaluation, `TestRunner`, `HarnessGenerator` and execution results |
| `seclab.coverage` / `seclab.fuzzing` | Coverage backends/runner/reports; `FuzzConfig`, `FuzzEngine`, campaign results and `CrashAnalyzer` |
| `seclab.pipeline` | `PipelineOptions`, `PipelineOrchestrator`, `run_full_verification`, stage contracts and `PipelineReport` |
| `seclab.benchmark` | `BenchmarkCase`, `BenchmarkObservation`, `BenchmarkReport`, `compare_benchmark` |
| CLI / GUI | `seclab.cli.main`; optional script `seclab-workbench` starts the PySide6 application |

Canonical integrated call:

```python
from seclab.pipeline import PipelineOptions, run_full_verification

report = run_full_verification(
    project="path/to/project",
    workspace="path/outside/project",
    options=PipelineOptions(specification_paths=("path/to/specification.json",)),
    stage_ids=("CTL",),  # omit to select FULL
)
```

`run_full_verification` is the common pipeline API used by CLI, GUI controller,
and generic integration fixtures. Selecting stages includes prerequisite
stages; unselected stages remain `NOT_STARTED`, while selected stages with
missing applicable inputs can be `SKIPPED` with a reason.

## Frozen contracts

### Specification input and normalized model

The authoritative JSON schema is `schemas/specification.schema.json`; Python
models are in `src/seclab/specification/schema.py`. The contract represents
project metadata, requirements, variables/domains, constraints, states and
transitions, properties, functions, tests and state machines. Loading parses
documents, validation checks shape and semantics, and normalization merges
fragments deterministically. Do not silently infer absent states, properties,
requirements, test oracles, domains, or expected outcomes.

### Result semantics

Canonical `VerificationStatus` values are:

`PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_RUN`, `TOOL_ERROR`, `SPEC_ERROR`, and
`BUILD_ERROR`.

Each `VerificationResult` is scoped and carries a stage/technique, reason code,
message, optional requirement/property/source identifiers, evidence IDs, and
optional counterexample/metadata. A raw solver SAT/UNSAT value, process exit
code, successful build, empty static scan, coverage percentage, or finding-free
bounded fuzz run is not by itself a project verdict. Invalid input, tool/build
failure and incomplete checking must remain distinct from property PASS/FAIL.

Pipeline lifecycle is a separate contract: `NOT_STARTED`, `RUNNING`,
`COMPLETED`, `SKIPPED`, or `FAILED`. Each stage record includes start/finish,
duration, reason/error type, dependency/input/output references, result IDs and
evidence IDs. `COMPLETED` means the stage adapter returned; scoped checker
results may still be `INCONCLUSIVE`, `TOOL_ERROR`, or `BUILD_ERROR`.

### Evidence and manifest

`Evidence` contains `id`, enum `type`, `stage`, `source`, workspace-relative
`path`, timezone-aware timestamp, SHA-256 `hash`, optional requirement/property
IDs and JSON metadata. The current evidence types are `LOG`, `COUNTEREXAMPLE`,
`WITNESS`, `TEST_RESULT`, `SANITIZER_REPORT`, `STATIC_ANALYSIS_REPORT`,
`COVERAGE_REPORT`, `FUZZ_INPUT`, `CRASH`, `MODEL`, `SPECIFICATION`, and
`ENVIRONMENT`.

`RunManifest` currently serializes `schema_version: "1.0"`, run/project/time,
environment/tool versions, input artifact references, result/evidence arrays,
summary counts and metadata. It rejects duplicate result/evidence IDs and
results whose evidence IDs are absent. ArtifactStore disallows unsafe path
components, exclusive-writes artifact files, and records SHA-256. The pipeline
confines the workspace outside the project, checks source before/after hashes,
and verifies generated artifact hashes before report assembly.

### Pipeline stages and dependencies

Stable deterministic stage order:

`SPECIFICATION → SOURCE → MODEL → CTL → BMC → SMT → STATIC → MEMORY → DYNAMIC → COVERAGE → FUZZING → REPORT`

Declared dependencies in `PipelineOrchestrator.full`:

| Stage | Required stage inputs |
|---|---|
| SPECIFICATION | none |
| SOURCE | none |
| MODEL | SPECIFICATION |
| CTL | SPECIFICATION, MODEL |
| BMC | SPECIFICATION, MODEL |
| SMT | SPECIFICATION |
| STATIC | SOURCE |
| MEMORY | SOURCE |
| DYNAMIC | SPECIFICATION, SOURCE |
| COVERAGE | SOURCE, DYNAMIC |
| FUZZING | SPECIFICATION, SOURCE, DYNAMIC; coverage feedback is strategy-dependent |
| REPORT | assembles the current run's available stage data |

No overall project `PASS`/`FAIL`, `overall_status`, score, grade, or verdict is
part of `PipelineReport` or `RunManifest`.

## Existing correctness/accuracy test coverage

The suite includes core unit tests, production integration tests, pipeline
integration, accuracy benchmark cases, and observation-boundary mutation tests.
Benchmark ground truth is catalog-authored and separate from actual observations.

| Checker/core | Current accuracy evidence | Remaining correctness limit |
|---|---|---|
| Specification | Loader/validator/normalizer semantic and deterministic tests; generic examples | Contract extensions require backward-compatibility review; absence is not inferred |
| Model | State/transition invariants, initial states, deadlocks, reachability, deterministic exports and model-pipeline tests | Explicit finite-state model only; source-to-model semantics are not generally inferred |
| CTL | Parser/validator/model-checker tests for temporal operators, fixed points, cycles, deadlocks, branching, multiple initial states and witnesses/counterexamples; catalog cases `CTL-001`–`CTL-009` | Finite explicit Kripke semantics; no general C/C++ model extraction claim |
| BMC | Encoder/checker tests and real Z3 tests for counterexamples, bounds/completeness, cycles, branching and multiple initial states; catalog cases `BMC-001`–`BMC-005` | Completeness is scoped to the supported supplied finite model/query; solver/tool errors are not property outcomes |
| SMT | Grammar/type/domain/encoding tests and real backend SAT/UNSAT/evidence tests; catalog cases `SMT-001`–`SMT-007` | Supported expression/domain subset only; no transition/temporal semantics inferred |
| Static | Normalized finding/parser unit tests and optional compiler/Cppcheck/clang-tidy integration tests; catalog cases `STATIC-001`–`STATIC-004` | A clean scan is scoped/inconclusive; finding meaning depends on analyzer and parser; standalone Clang Static Analyzer adapter is unavailable |
| Memory | ASan/UBSan/LeakSanitizer parsers, runner integration and explicit unavailable-platform paths; catalog cases `MEM-001`–`MEM-006` | Runtime instrumentation is host-dependent; `StructAnalyzer` records a limitation rather than inferring memory layouts |
| Dynamic | Oracle type/equality tests, build/timeout/crash and real process tests; catalog cases `DYN-001`–`DYN-005` | Results only cover executed inputs and declared oracle; unsupported harness signatures remain unsupported |
| Coverage | Parser/aggregation/backend/partial-run tests; catalog cases `COV-001`–`COV-005` | Measurement only; backend/build partials must not imply safety |
| Fuzzing | Deterministic generators, bounded campaigns, timeout/crash/oracle and coverage feedback tests; catalog cases `FUZZ-001`–`FUZZ-005` | No finding within budget is inconclusive; campaign quality depends on seeds, budget and available feedback |
| Result classifier | Unit tests for unknown outcomes and execution/build distinction; benchmark scorer tests | Accuracy benchmark labels mismatches from observations; broader production classifier mutation testing remains absent |
| Evidence/traceability | Hash/path/manifest/reference integrity tests, pipeline and GUI controller checks | The Phase 1 mutation fixtures mutate observations at the benchmark boundary and do not mutate production core implementations |

Accuracy artifacts are in `docs/verification-accuracy.md`; controlled mutation
test scope and its limitation are in `docs/verification-core-mutation-testing.md`.
The accuracy suite has 45 cases across eight checker categories. Current
documented Windows execution has sanitizer environment limitations; consult
the accuracy report for its exact per-checker counts and mismatches. Metrics
are per checker and do not form a combined score.

## GUI and CLI contracts

The CLI supports `verify --project`, repeatable `--spec`, `--workspace`,
repeatable `--stage`, `--config`, and `--run-id`. JSON config maps to generic
`PipelineOptions`. CLI return success indicates orchestration/report completion,
not that every property passed.

The GUI is an optional PySide6 client. Project/spec controllers call the
specification APIs; the verification controller calls the pipeline and reads
reports/manifests/evidence. A `QThread` worker keeps runs off the UI thread.
The GUI projects stage/result status, evidence, traceability, source integrity,
limitations, accuracy reports and history. It has no separate verification
algorithm or overall project verdict. In this audit environment PySide6 is
absent, so controller tests can pass while GUI runtime/smoke behavior remains
unverified.

## Stable areas, allowed extension and protected changes

### Stable areas to preserve

- Generic core imports must not depend on `seclab.integrations` or any SUT.
- Specification v1 field meanings and serialized compatibility.
- The result statuses above, and the distinction between result status and
  stage lifecycle.
- Evidence and manifest references, hashes, path confinement and workspace
  layout under `workspace/<run_id>/`.
- The twelve stage IDs, deterministic order and declared dependency graph.
- Explicit scope/limitation semantics; coverage is measurement-only.
- No project-wide verdict, aggregate safety score or inferred missing input.

### Allowed without changing frozen contracts

- Add independent generic fixtures and more ground-truth accuracy cases.
- Improve tests, docs, output formatting and adapters that consume existing
  specification/result/evidence contracts.
- Add optional SUT integrations under `src/seclab/integrations/` while keeping
  them out of generic imports and test prerequisites.
- Add checker implementation support only with explicit scoped outcomes,
  evidence and independent correctness tests in a later phase.

### Changes requiring explicit contract/version review

- Renaming/removing specification, result, evidence, manifest, stage or public
  API fields/enums; changing serialization or status semantics.
- Inferring absent project/specification facts or treating execution/tool
  success as verification PASS.
- Changing stage ordering/dependencies, evidence location/hash semantics, or
  source integrity behavior.
- Adding a global project verdict, ranking or combined accuracy score.
- Adding any SUT-specific path, requirement, function, checker branch or JSON
  field to a generic core.

## Phase 0 exit record

- Repository source, tests, examples and existing architecture/core/validation
  documentation were audited at the package/test/public-export level.
- Canonical baseline: **282 passed, 5 skipped, 0 failed**; exact skip reasons
  are listed above. Historical test counts in older milestone documents are
  labeled as historical and superseded by this run.
- `python -m compileall -q src tests`: exit 0.
- No source code, checker, specification contract, Smart-EV repository, or GUI
  behavior was modified in this phase; this document is the Phase 0 artifact.
- This document freezes the architecture; it does not certify checker accuracy.

Proceed to Phase 1 only when requested. Phase 1 should address correctness gaps
with independent expected outcomes before expanding GUI or feature scope.
