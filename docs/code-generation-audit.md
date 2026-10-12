# Generic Specification-to-C Generation Audit

## End-to-end architecture audit (2026-10-08)

This audit matrix records the implementation found before the refactor in this
work session. The normalized `Specification` object is the
pipeline's canonical intermediate representation; no separate semantic IR
currently exists.

| Component | Current behavior | Correct | Incorrect / gap | Required change |
|---|---|---|---|---|
| Specification contract | `Specification` contains requirements, finite variables/constraints, explicit states/transitions, formulas, function declarations with optional language, and test inputs/oracles. | Validation/normalization precedes model and code generation; declared function language is retained for traceability. | `FunctionSpec` still has no typed signature, operation/body AST, input/output contract, or function execution semantics. | Keep unsupported application-function synthesis explicit; only add it through a declared, validated contract. |
| Formal model | `generate_kripke_structure()` copies declared state IDs, values, labels and initial state; transitions are checked against declared endpoints, guards and assignments. | No Smart-EV or source-derived state invention is used by the pipeline. | State/transition provenance and requirement links are not first-class fields in `KripkeStructure`; statically false guards are omitted from the enabled relation. | Preserve specification IDs and provenance in exported model/evidence mappings; distinguish declared edges from enabled edges. |
| C/Python model generator | `CGenerator` emits matching C99 and Python runtimes for the validated Kripke model, CLI/test harness, CMake project, usage README, maps and manifest. | Both model runtimes carry the same specification/model hashes and state/transition data; Python artifacts are verified by BUILD. | It does not emit `FunctionSpec` application implementations. Guard callbacks may be unresolved; arbitrary action text is not executed. | Add application functions only after the specification declares a validated executable contract. |
| Build | CODEGEN generated, compiled with gcc/clang when available, and executed its model harness inside one stage. | Real compiler commands and executable observations were recorded. | Generation and build were coupled; diagnostics were not a standalone BUILD stage. | Separated CODEGEN and BUILD while preserving artifact hashes and stage evidence. |
| Static analysis | Runs configured analyzers on project sources and, when generated, model C/header sources. | Analyzer output comes from actual tools and carries generated/project scope. | Generated application functions do not exist; user project code remains a separate target and is not Specification-generated. | Make target scope and limitations explicit; pass generated artifacts only through the generated scope. |
| Dynamic testing | Executes declared test cases against project sources; transition cases execute the generated model binary when C generation is enabled. | TestRunner records actual process observations and evidence. | `FunctionSpec` cases target project implementations; the generated model harness cannot implement arbitrary declared functions. | Gate unsupported targets as explicit unsupported/environment-limited; do not substitute model runs for function behavior. |
| Memory | Runs ASan/UBSan/leak tools on project sources and generated model runtime sources. | Sanitizer outcomes are tool observations. | Generated model C has no application memory behavior to verify. | Keep checker scope visible; do not treat harness capability as application memory assurance. |
| CTL/BMC/SMT | CTL/BMC use the explicit Specification-derived model; SMT checks declared formulas and variables/constraints. | The generic model builder does not create violation states; legacy adapters preserve the declared graph and labels. | A source specification can itself declare unreachable violation-labeled states; their presence does not make them real witnesses or justify a safety conclusion. SMT is a valuation/property check, not execution of generated C. | Preserve the declared graph exactly and report reachability/provenance; never synthesize or silently filter states based on their names or labels. |
| Fuzzing/coverage | Có thể kiểm tra các testcase thực thi của mô hình sau khi chạy dynamic; nếu không thì dùng mục tiêu mã nguồn/test của dự án đã cấu hình. | Mỗi lỗi được ghi kèm kết quả oracle, quan sát lúc chạy có cấu trúc, chi tiết sanitizer và phần đầu stdout/stderr có giới hạn. Khi mở báo cáo, GUI làm nổi bật lỗi đầu tiên cùng mục tiêu, chẩn đoán/vị trí và đầu vào tái hiện. Khi chọn chiến dịch, người dùng xem được giá trị kỳ vọng/thực tế, stack trace, trạng thái tiến trình, đầu vào đã rút gọn, mã bằng chứng và giải thích cơ chế lỗi cùng giới hạn của bằng chứng. Sơ đồ tiến trình thể hiện vòng lặp corpus → đầu vào và cập nhật lượt hiện tại trực tiếp. Khi không tìm thấy lỗi, giao diện nêu phạm vi, số lượt đã chạy, kết quả các bộ kiểm tra và lý do dừng; kết quả được ghi rõ là chưa kết luận, không phải bằng chứng an toàn. | Fuzzing trên mô hình sinh kiểm tra bộ chuyển đổi đồ thị, không kiểm tra hành vi hàm ứng dụng đã khai báo; chỉ hiển thị vị trí mã nguồn nếu bộ phân tích báo cáo vị trí đó. Loại lỗi sanitizer cho biết cơ chế được phát hiện, nhưng để kết luận nguyên nhân chính xác ở mã nguồn cần dòng được báo cáo và code xung quanh. | Nêu rõ phạm vi mục tiêu, hiển thị bằng chứng lỗi cụ thể trước log chiến dịch, giải thích cơ chế lỗi mà không suy diễn nguyên nhân mã nguồn, thể hiện vòng lặp và không suy luận độ an toàn ứng dụng từ chiến dịch trên bộ chuyển đổi mô hình. |
| Evidence/traceability | Artifacts have hashes; requirements connect to properties/tests and generated source maps. | Result and evidence integrity is checked. | Function-to-model links are unresolved by design; state/transition source provenance is incomplete. | Add direct Specification IDs and requirement links to state/transition/source-map records. |
| Benchmark | Benchmark package owns catalogs, ground truth and comparison. | Benchmark execution is now outside pipeline orchestration and report assembly. | Benchmark report viewing remains an independent user-selected GUI reader. | Keep any future benchmark runner separate from verification inputs, stages, and results. |
| Smart-EV | Adapters/probes live under `seclab.integrations`. | Generic model/codegen does not import Smart-EV behavior. | Legacy detection can route Smart-EV-format documents through an integration adapter; probe module is not nested under a `smart_ev` package. | Keep adapter opt-in at ingestion boundary and move/retain all domain behavior under integrations. |
| GUI | GUI loads and validates the Specification and delegates execution. | No generated input needs to be reloaded between stages. | GUI no longer previews/builds a model before the run; stage-result projection and some page detail still have limited application semantics. | Keep GUI orchestration-only and show stage artifacts from the run report. |

### Generator audit answers

1. The generated functions are model APIs (`seclab_state_count`, state/transition lookup, initialization, guard dispatch, and transition application) in `source/model.c`. No application function body is generated from `FunctionSpec`.
2. Generic model API implementations are generator templates. Smart-EV probe implementations are confined to `integrations/smart_ev_probes.py`; registered declaration probes are under `integrations/probes` and must not be treated as production code.
3. The Specification currently has no `FunctionSpec.kind`, signature, behavior or operation field. Function kind is therefore not consumed by the normalized contract/generic generator. Model state/transition kind is determined by the normalized declarations.
4. Requirement-to-function associations are carried as declared IDs/source metadata; they do not cause function bodies to be emitted. Requirement-to-property/test links can drive result traceability.
5. State IDs, values, labels, initials, transition IDs/endpoints, guards, actions and labels are represented in the model/C tables. Guards are compiled only when evaluable from the source state's declared valuation; otherwise a runtime callback is required. Arbitrary action text is descriptive; supported assignments are checked against the declared target valuation.

### Audit limitations and root causes

- The requested `validate_token(token: string)` implementation cannot be derived from the current `FunctionSpec` contract. It supplies no parameter type, condition AST, accept/reject semantics, or output representation. Guessing these from a function name, requirement prose, expected CWE, or test expected value would fabricate behavior.
- The existing C project is a model interpreter/observer. Its executable tests validate the generated model representation against that same canonical graph; they do not prove that an application implementation satisfies requirements.
- Static/memory analysis of generated model C is valid but has limited application semantics. Project-source analyses remain separately scoped observations.
- Benchmark isolation is currently violated by the ACCURACY pipeline stage and is a concrete root cause to fix.
- GUI localization source currently contains mojibake markers; this is a product defect and also explains the localization failures in the latest full pytest run.

### Implementation delta and milestone status (2026-10-08)

The changes made after the audit are deliberately scoped to semantics the
current contract actually declares:

- Removed the benchmark Accuracy stage, result aggregation, run option, and
  report field from the verification pipeline. Benchmark code and the
  independently selected read-only report viewer remain separate.
- Made CODEGEN an unconditional full-run stage and separated compiler
  invocation into BUILD. BUILD records compiler commands, exit codes, output,
  executable hash and build evidence. DYNAMIC consumes the built executable for
  generated model transition tests.
- A specification without a state machine gets an empty generated model
  artifact; no state or transition is invented. A failed model stage prevents
  model C generation.
- Added `source_spec_id`, declared `requirement_ids`, and an explicit null
  `source_location` to generated state and transition map entries. The current
  input schema has no source-location field.
- Removed probe-only/tool-capability/bug-injection placeholder artifact classes
  from pipeline metadata. Static and memory analysis may still analyze
  separately scoped project sources and generated model sources.
- GUI Verify now calls the orchestrator without constructing a model preview or
  waiting for model review. The GUI localization catalog and fuzzing page
  strings were repaired; canonical backend IDs are unchanged.

| Milestone | Status | Evidence / remaining boundary |
|---|---|---|
| M1 Specification → normalized IR | Existing | Validation artifacts and normalized hash are produced. |
| M2 IR → formal model | Implemented for declared state machines | Explicit state/transition graph; no invented graph elements. |
| M3 IR → generated C | Partial | Model runtime and harness are generated; declared application functions are not. |
| M4 Build generated C | Implemented | Independent BUILD stage compiles and stores executable evidence. |
| M5 Static verification | Partial | Real analyzers consume project sources and generated model C; no generated application function exists. |
| M6 Dynamic verification | Partial | Real observations are recorded; generated-model tests exercise the model adapter, while declared app tests still target project source. |
| M7 Memory verification | Partial | Sanitizers build/run scoped project or generated model sources; this is not application-function memory verification. |
| M8 BMC/SMT/CTL | Implemented within declared inputs | Formal checks consume declared model/formulas; they do not execute generated application C. |
| M9 Fuzzing/Coverage | Partial | Bounded target observations exist; current generated target is the model adapter, not an application implementation. |
| M10 Evidence + traceability | Partial | Hashes and requirement links exist; there is no end-to-end application-function chain. |
| M11 Single-run orchestration | Implemented | One `VerificationContext`; codegen and build have separate stages. |
| M12 GUI integration | Partial | One-click orchestration works; application-function detail is unavailable from the schema. |
| M13 End-to-end verification | BLOCKED | The current `FunctionSpec` has no typed signature, operation/behavior AST, or output contract. |

Post-refactor verification: `python -m pytest -q` completed with **507 passed,
6 skipped**; `python -m compileall -q src tests` completed successfully. Architecture
boundary tests verify the generic core has no benchmark/probe artifact imports or
Smart-EV-specific generator symbols. These results validate the implemented model
pipeline and its boundaries; they do not clear the FunctionSpec contract blocker.

### Contract blocker

The requested generic safe/unsafe application C acceptance cases cannot be
implemented from this repository's current `FunctionSpec` contract (`id`,
`name`, optional `file`, requirement IDs, and description). It cannot express
`bounded_copy`, `unbounded_copy`, allocation lifecycle, or another typed
operation. Generating those bodies from expected outcomes, CWE metadata, free
text, or test oracles would violate the task's Specification-only and
no-synthetic-behavior constraints. The refactor therefore does not claim the
full Specification → application function → executable verification chain.
Completing M3/M6/M7/M9/M10/M12/M13 requires an explicit user-approved schema
contract for executable function semantics; the task explicitly directs us to
stop at this contract conflict rather than silently invent it.

## Function-source generation follow-up (2026-10-07)

### IMPLEMENTED

- Kept the normalized Specification JSON/schema contract unchanged. The legacy
  adapter now preserves the original specification hash and exposes explicitly
  declared function generation metadata as a separate provenance projection.
- Added a generic `FunctionSourceGenerator` dispatched by declared
  `(language, kind)` pairs. It uses the existing C IR for C source, validates
  identifiers, arity, bounds and conflicting metadata, and reports unsupported
  rows instead of guessing. It currently supports generic C `buffer_copy` and
  `alloc_release` probes plus Python `divide` and `magic_value` probes.
- Generated outputs carry `GENERATED_ARTIFACT` / `PROBE_ONLY` markings,
  `production_source=false`, stable function/requirement references, declared
  source location (or an explicit unresolved value), expected vulnerability
  metadata (not a finding), deterministic source maps and SHA-256 manifest
  entries. C and Python entry-point harnesses validate input shape and expose
  actual output; listing harness entries does not invoke probe functions.
- CODEGEN now compiles generated C function sources with available gcc/clang
  and parses/runs Python entry-point listing, saving command output, status and
  source hashes as ArtifactStore evidence. STATIC and MEMORY analyze generated
  functions under `GENERATED_FUNCTION_PROBES` / `GENERATED_FUNCTION_PROBE`
  scope. Memory probes are invoked only where the declared signature requires
  no arguments; parameterized functions without concrete declared test input
  are recorded unsupported.
- The GUI presents C and Python source from hash-resolved evidence, function
  declarations/status, generated files, source maps and build/execution logs;
  export uses the selected evidence content. Generic C fixtures cover copying,
  allocation/release and Python branching.

### VERIFIED

- Focused Specification, CGenerator, source-generation fixtures and GUI
  projection suite: **43 passed**. A post-fix localization + GUI codegen rerun:
  **16 passed**.
- Full repository regression before the final GUI text cleanup: **492 passed,
  6 skipped, 1 failed**. The single failure was the new GUI file's mojibake
  marker; after removing it the directly affected localization and GUI tests
  passed. The entire suite was not rerun after this cleanup.
- `python -m compileall -q src tests`: **passed**.

### NOT IMPLEMENTED / LIMITATIONS

- Function bodies are generated only for the explicit registered generic
  `(language, kind)` semantics above. Unknown constructs, invalid metadata,
  arbitrary C/Python bodies and absent declarations remain `UNSUPPORTED`; this
  is not general source synthesis.
- Dynamic testing, coverage and fuzzing are not automatically invoked on these
  generated function probes. The current legacy metadata has no concrete
  executable inputs and independent oracles for those functions. No such
  inputs/oracles are fabricated. Existing project-source test stages remain
  separately scoped and configured.
- ASan/UBSan/LeakChecker behavior remains tool/platform dependent. Checker
  outputs are actual analyzer observations, not expected-vulnerability labels;
  the latter are explicitly metadata only. Generated findings never imply a
  production-source safety verdict.
- Generic function source provenance is a declared location when present; the
  declaration-only legacy format does not establish a mapping to actual
  production function bodies.

## Existing architecture and implemented behavior

- The stable normalized contract is `Specification` in
  `seclab.specification.schema`. It currently exposes requirement IDs and
  mappings, finite variable domains and initial values, constraints, explicit
  state/state-machine declarations, transitions with guard/action/label,
  property formulas, function IDs/names/files, and test inputs/expected values.
  The loader hashes source JSON; the normalizer validates and merges root and
  machine-scoped state declarations. The contract does not define C types,
  function signatures/implementations, executable transition semantics,
  or scenario-to-function execution mappings sufficient for general synthesis.
- `seclab.codegen.CGenerator` already writes deterministic `include/model.h`,
  `source/model.c`, `tests/model_test.c`, optional fuzz harness, a source map,
  and a manifest for a supplied `KripkeStructure`. It checks generated paths,
  avoids overwriting differing content, records hashes and classifies artifacts.
  Its generated C represents graph data and lookup APIs; it does not synthesize
  arbitrary application functions from `FunctionSpec` or `Constraint` text.
- The existing C harness validates generated graph access/count/initial/edge
  data. It is not generated from specification `TestSpec` expected values.
- `PipelineStages.codegen` is enabled only by `generate_c_model`. It writes to
  the run workspace's `generated/`, copies generation outputs into evidence,
  then tries gcc and clang and executes the graph harness after a successful
  build. Compiler outcomes are written as JSON. Build failures currently mark
  CODEGEN failed, although a missing compiler is partially distinguished in
  the per-compiler record.
- CODEGEN depends on SPECIFICATION and MODEL, but SOURCE and downstream checkers
  scan the project source tree. Generated C is not automatically passed through
  STATIC, MEMORY, DYNAMIC, COVERAGE, FUZZING, or BMC. The existing optional C
  fuzz harness is generated, but fuzz orchestration targets project sources.
- `PipelineContext` retains normalized specification, canonical model,
  generated root/result, run workspace, stage outputs and evidence during one
  run. `VerificationSession` retains project/specification and completed run
  summary in the GUI, but not a reusable in-progress generated project object
  across separate stage invocations. The GUI has a dedicated code generation
  page and Settings has an opt-in generate C model option. After a run, the C
  source tab is selected and populated from hash-verified run evidence; it does
  not present a generated workspace path as the source content.
- ArtifactStore provides SHA-256, workspace containment, exclusive artifact
  creation and manifest collection. Traceability already links requirement
  rows to model and generated evidence, while the C source map maps model state
  and transition IDs to generated source lines. Requirement/function IDs and
  specification hash are not yet embedded in generated source map/manifest.
- Tests cover deterministic model C generation, build/run with available
  compilers, unsafe path handling, source maps, manifests and generic model
  integration. The general accuracy catalog does not include semantic C
  generator cases with expected function/signature/source-map structure.

## Specification fields usable without contract changes

The generic generator can truthfully serialize finite values, explicit state
IDs/labels, initial-state membership, transition IDs/endpoints, labels, actions
and guards from the model. Requirement IDs can be carried as provenance where
the existing mapping declares them. Function names/files and test inputs can be
reported as declarations, but not turned into executable implementations or
tests unless the specification supplies a supported, explicit semantics
contract. No such general implementation contract is present today.

## Output and build integration

Existing output format is a standalone C project tree with `include/`,
`source/`, `tests/`, optional `fuzz/`, `source-map.json`, and `manifest.json`.
The pipeline owns its run-scoped workspace and ArtifactStore. gcc/clang are
invoked through `CommandRunner` with C99 and warnings-as-errors. The generated
harness is executed only from that workspace. Downstream checkers currently
consume project sources independently.

## Gaps and implementation scope

1. Add specification hash, source paths/hashes, requirement links, model ID,
   generator version and generation metadata to the existing output artifacts.
2. Make generated project creation unique and fail closed on reuse with
   different input; retain workspace containment and manifest entries.
3. Persist separate generation metadata and build logs/results with scoped
   statuses so unavailable compilers/build errors do not become application
   verification FAIL results.
4. Add generic independent structure benchmark fixtures and tests for build
   result distinctions, source-map provenance, evidence and workspace safety.
5. Keep the code-generation GUI projection connected to the existing single
   project/specification/session. It exposes that output represents the model
   graph rather than inventing application code/tests.
6. Keep downstream generated-source checker handoff and arbitrary function
   synthesis marked as limitations until the contract defines safe semantics.

## Limitations

There is not enough specification semantics to synthesize arbitrary C function
bodies or infer executable expected behavior. The safe current capability is
generic C serialization of an explicit finite state model plus a structural
test harness. Generated-source reuse by downstream project-source checkers and
full scenario harness generation require further integration and must not be
claimed complete by this audit.

