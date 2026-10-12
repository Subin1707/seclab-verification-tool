# Final Release Validation v1.0

Validation date: 2026-10-04  
Environment: Windows 11, Python 3.12.5, pytest 8.4.2.  
Scope: checks against the tool's release Definition of Done. This report contains no verdict for any project under verification.

## DoD status by criterion

| Area | Criterion | Status | Evidence / limitation |
|---|---|---|---|
| Architecture | Generic core; no Smart-EV dependency | PASS | `tests/architecture/test_import_boundaries.py` checks imports and domain markers. Smart-EV format/probe code is confined to `src/seclab/integrations/`. |
| Architecture | No hard-coded project paths | PASS | Architecture boundary test checks external-SUT paths; source search found Smart-EV-specific references only under integrations. Generic CLI accepts project/specification paths as inputs. |
| Specification | Schema and model contract | PASS | JSON Schema and typed specification model are present; specification core suite exercises schema and model validation. |
| Specification | Semantic validator | PASS | Tests cover duplicate IDs, references, state-machine initial states, domains, CTL atoms/formulas and SMT variable references. |
| Specification | Deterministic normalization | PASS | Loader sorts fragment paths; normalizer sorts entity definitions. `test_normalization_is_deterministic_for_input_order` and generic v2 examples pass. |
| Formal | Model | PASS | Model unit/integration tests cover graph construction, reachability, deadlocks, deterministic exports and multiple initial states. |
| Formal | CTL | PASS | CTL parser, validator, model-checker, result/evidence and specification-pipeline tests are present and passed in full suite. |
| Formal | BMC | PASS | Real Z3 integration tests cover SAT traces, completeness threshold, incomplete bounds, cycles and multiple initial states. |
| Formal | SMT | PASS | Parser, type/domain validation, query encoding, real solver outcomes and evidence tests are present and passed. |
| Code analysis | Source | PASS | Source discovery/language/function tests and source-to-execution integration tests passed. |
| Code analysis | Static | PASS WITH TOOL LIMITS | Static core and optional analyzer integrations are tested; tool availability is handled by scoped unsupported/inconclusive results. |
| Code analysis | Memory | LIMITED | Memory/sanitizer tests passed as tests, but this Windows toolchain cannot establish ASan/UBSan/LeakSanitizer outcomes for the affected benchmark cases; see Accuracy. This is not evidence of clean memory behavior. |
| Testing | Dynamic | PASS | Oracle pass/fail, build error, timeout and abnormal termination cases have unit/integration coverage. |
| Testing | Coverage | PASS WITH BACKEND LIMITS | gcov/LLVM backends and partial runs are tested. Backend availability and failed instrumentation remain explicit limitations. |
| Testing | Fuzzing | PASS WITH BACKEND LIMITS | Black-box and coverage-guided tests cover crash, oracle, timeout, no-finding and coverage delta. Windows generic fuzz fixture G stopped before executing its abnormal seed because coverage data was unavailable (`docs/generic-system-validation.md`). |
| Pipeline | Stage isolation | PASS | Invalid specification and controlled stage failures are tested; dependent stages skip while independent SOURCE work continues. |
| Pipeline | Deterministic ordering | PASS | `test_pipeline_stage_order_is_stable` checks all twelve stages in fixed order. |
| Pipeline | Skip semantics | PASS | Missing inputs/configuration produce `SKIPPED` stage records with reasons; pipeline tests cover missing spec/source/properties. |
| Pipeline | Failure isolation | PASS | Optional coverage failure does not prevent black-box fuzzing; controlled stage failure remains scoped. |
| Evidence | Artifact hashes | PASS | Pipeline verifies hashes and confines artifact paths; tampering is tested as a scoped report result. Generic integration matrix verifies each manifested artifact. |
| Evidence | Source hashes | PASS | Before/after source hashes and mutation checks are exercised by generic pipeline/workflow integration tests. |
| Evidence | Workspace confinement | PASS | ArtifactStore path validation, pipeline workspace exclusion, controller evidence resolution and integration tests verify run-root confinement. |
| Traceability | Requirement → Property/Test → Result → Evidence → Source | PASS WITH OPTIONAL SOURCE LINK LIMIT | Pipeline report builds requirement targets and links result/evidence/source where a property or test has a supported source association. State-machine project C's CTL properties apply to its explicit specification model; its C file is inventory input only (`docs/generic-system-validation.md`). |
| GUI | Launch and interactive workflow | NOT VERIFIED | PySide6 is absent (`importlib.util.find_spec("PySide6")` is `None`); `tests/integration/gui/test_gui_smoke.py` skips. No GUI launch or interactive desktop workflow is claimed. |
| GUI | Project/spec selection, validation, stage selection and run controller | PASS AT CONTROLLER LEVEL | `tests/gui/test_gui_controllers.py` exercises project/spec selection, load/validate/normalize, stage forwarding and run settings. GUI runtime integration is unverified without PySide6. |
| GUI | Results, evidence, traceability, report and history projections | PASS AT CONTROLLER/SMOKE-TEST LEVEL | Controller suite and offscreen smoke assertions cover result filtering, evidence opening/hash check, traceability/source, report and history views; Qt smoke is skipped in this environment. |
| Accuracy | Benchmark suite and expected-vs-actual output | LIMITED | 45 benchmark cases executed. Report artifact: `t/final-accuracy-report.json`; the CLI exits 1 because six memory cases mismatch in this Windows environment. |
| Accuracy | False positives / false negatives | PASS FOR CONCLUSIVE BENCHMARK CASES | 0 false positives and 0 false negatives recorded. No combined accuracy score or checker ranking is used. |
| Accuracy | Inconclusive / unsupported and limitations | LIMITED, EXPLICIT | 18 inconclusive cases; 6 unsupported cases. All 6 mismatches are `ENVIRONMENT_LIMITATION` for ASan/LeakSanitizer availability. They are not counted as false negatives. Per-checker metrics remain separate. |
| CLI | Help | PASS | `python -m seclab.cli --help` and `python -m seclab.cli verify --help` display project/spec, workspace, stage, config and run-id options. |
| CLI | Verify / stage selection / config | PASS | Seven independent generic projects were run through generic CLI with project specification/config and stable run IDs; controller and pipeline tests exercise stage selection/prerequisites. See `docs/generic-system-validation.md`. |
| Documentation | Architecture, schemas, cores, pipeline, GUI, benchmark and validation docs | PASS WITH KNOWN LIMITS DOCUMENTED | Existing core documentation plus `generic-system-validation.md`, `verification-accuracy.md` and this report record scope and environment limits. |

## Accuracy benchmark summary

The benchmark CLI produced a 45-case expected-versus-actual report at `t/final-accuracy-report.json` and exited 1 because the actual memory outcomes differed from the requested defect ground truth on this host. Results:

- False positives: 0.
- False negatives: 0.
- Inconclusive cases: 18.
- Unsupported cases: 6.
- Mismatches: `MEM-001` through `MEM-006`, all classified `ENVIRONMENT_LIMITATION` because the available Windows compiler/runtime could not establish ASan or leak-sanitizer behavior.

Checker-local metrics: CTL 8 cases (TP 2, TN 5); BMC 5 (TP 1, TN 1, 3 inconclusive); SMT 7 (TP 1, TN 2, 2 inconclusive); dynamic 5 (TP 1, TN 1, 2 inconclusive); fuzzing 5 (TP 2, 3 inconclusive); static analysis 4 (3 inconclusive); coverage 5 (5 inconclusive); ASan 5 unsupported; LeakSanitizer 1 unsupported. Metrics do not combine checker types.

## Required commands

`python -m pytest -q --basetemp=t\q`

**Current canonical baseline:** exit code 0; **282 passed, 5 skipped, 0 failed in 194.19s** for the exact required command. A follow-up `-rs` run confirmed the same counts. Skip reasons: PySide6 unavailable (GUI smoke module), external Smart-EV specification integration not opted in, two ASan cases unsupported by the available compiler/runtime, and symlinks unavailable for one source-loader test. See [architecture-freeze.md](architecture-freeze.md) for the canonical baseline and architecture record. The original 268-test count from this report's earlier validation run is superseded.

`python -m compileall -q src tests`

**Result:** exit code 0.

## Changes and scope

No checker, specification contract, pipeline, GUI, or project fixture code was changed during this release audit. Only this validation report was added. No Smart-EV repository was modified. No project-level overall verdict was created.
