# Teacher-compatible six-chapter workflow mapping

This document describes an **independent implementation of the intended verification workflow represented by the teacher application**. It does not claim to reproduce the teacher application's implementation or undocumented behavior. The project contains no separate teacher manual/application workflow description; therefore this mapping follows the chapter boundaries stated in the accepted milestone brief.

## 1. Workflow abstraction

The backend adapts an input specification and user-provided source into existing SecLab APIs. Chapter calls select stable pipeline stage targets; the orchestrator computes their required dependency closure. Checker, model, parser, solver, execution, and result semantics remain owned by the existing cores.

```python
from pathlib import Path
from seclab.pipeline import PipelineOptions
from seclab.workflows.teacher import WorkflowChapter, run_chapter_verification

report = run_chapter_verification(
    WorkflowChapter.CH6,
    project=Path("examples/teacher-workflow/project"),
    workspace=Path("artifacts"),
    options=PipelineOptions(specification_paths=(Path("examples/teacher-workflow/specification.json"),)),
)
```

`run_full_verification` remains available. The chapter adapter is additive and calls it; chapter-specific or full execution uses the same pipeline implementation.

## 2. Six-chapter mapping

| Chapter | Sidebar/API chapter | Stage targets | Principal inputs and outputs |
|---|---|---|---|
| Ch1 | Specification / Model / Formal | Specification, Model, CTL, BMC | JSON states/transitions/properties → normalized specification, Kripke export, reachability/deadlocks, scoped CTL/BMC results and witnesses/counterexamples |
| Ch2 | Source & Static | Specification, Source, Static, Memory | JSON function references and provided source → function/source links, source hashes, analyzer/sanitizer results and evidence |
| Ch3 | SMT | Specification, SMT | Existing SMT properties and supported finite/bounded domains → encoded violation query, solver outcome, `VerificationResult`, and query/model evidence |
| Ch4 | Dynamic & Coverage | Specification, Source, Dynamic, Coverage | Declared tests → testcase/harness/build/execution/oracle observations; coverage is a measurement with evidence |
| Ch5 | Fuzzing | Specification, Source, Dynamic, Fuzzing | Declared test template, seed/configuration → bounded campaign results, corpus/finding artifacts. Coverage is selected only when the strategy is coverage-guided |
| Ch6 | Full Verification | All pipeline stages | Full ordered run → independent stage records, results, evidence manifest, traceability, source-integrity record, and report |

The fixture in `examples/teacher-workflow/` provides one safe self-looping model, CTL/BMC/SMT properties, one C `add` function, and one oracle-backed test with stable requirement/property/test IDs.

## 3. Actual Ch6 stage order and dependencies

The full run order is:

`SPECIFICATION → MODEL → CTL → BMC → SOURCE → STATIC → MEMORY → SMT → DYNAMIC → COVERAGE → FUZZING → REPORT`.

The scheduler chooses one topologically ready stage at a time using this stable preference order. A dependency failure or skip explicitly skips only dependent stages; independent work can proceed. Examples:

- CTL/BMC require successful specification and model inputs.
- Static/memory require source discovery, but do not require a specification.
- SMT requires a valid specification, not a source build.
- Coverage requires completed dynamic execution and source files. If coverage fails, dynamic results remain available.
- Black-box fuzzing does not hard-depend on coverage. Coverage-guided fuzzing selects the coverage target and is skipped with an explicit reason if feedback is unavailable.
- Missing Z3/tool support is reported by the SMT adapter/core and does not turn other chapter results into success or failure.

## 4. Stage lifecycle and report identity

Each report contains one stage record per pipeline stage. Selected stages have `RUNNING` followed by `COMPLETED`, `FAILED`, or `SKIPPED`; unselected stages in chapter reports remain `NOT_STARTED`. Records retain stable stage ID/name, UTC start/end times, duration, input references, output references, result IDs, evidence IDs, error type/message, and skip reason where applicable. A checker result status is separate from lifecycle status.

## 5. Result semantics

The report is a collection of scoped backend results. It has no overall project verdict, safety label, or aggregate pass percentage. In particular:

- CTL/BMC use their existing classifiers; incomplete BMC bounds remain scoped/inconclusive as classified by BMC Core.
- SMT solver outcome (`SAT`, `UNSAT`, `UNKNOWN`) remains in query/result metadata and is distinct from `VerificationStatus`. For violation-search queries the existing SMT adapter classifies SAT as a found violation and UNSAT as no violating valuation in the supported scope; timeout/unknown and tool failures retain existing classifications.
- Static clean scans remain inconclusive; analyzer/tool failures retain tool-error classifications.
- Memory observations retain existing sanitizer classifications and limitations. A StructAnalyzer limitation is not a memory pass/fail.
- Dynamic results follow the declared oracle; exit code zero alone does not imply verification pass.
- Coverage is measurement/evidence only.
- Fuzzing preserves campaign-core outcomes; absence of findings in a bounded campaign is not proof of safety. Crashes are not automatically memory-safety findings.

There is no distinct `arithmetic_checks` field in Specification Core v1. Ch3 adapts existing `logic: "SMT"` properties and their formulas. Adding a separate arithmetic-check schema would be a separate specification-contract change and is not inferred here.

## 6. Source and generated-artifact provenance

The source adapter records deterministic `SRC-...` IDs, production-source classification, project-relative and resolved paths, SHA-256 before the run, function IDs matched by declared file/name, related requirement IDs, and source-inventory evidence. A final `source-integrity.json` records the after hash and whether each source changed during the run. Source lineage associates applicable source-set or function-scoped results with result/evidence IDs and scope.

The current project does not generate production implementation code from specifications. Source is user-provided production input. Generated test harness evidence is classified `TEST_HARNESS`. Tool capability/version information is kept in the run environment/manifest. This implementation creates no `BUG_INJECTED_PROBE` or `PROBE_ONLY` source artifacts; empty classifications are recorded as such, not inferred from a real source file.

Project source files are input references outside the run workspace. All pipeline-generated artifacts, harnesses, logs, evidence, and reports are confined below `workspace/<run_id>/`; the manifest keeps source input paths/hashes so their provenance is auditable.

## 7. Traceability

Requirement rows use IDs from the specification and retain checker refs, target records, stage IDs, source/function links, result IDs, and evidence IDs. Property and test targets begin `NOT_CHECKED`; a real backend result links the target to its actual stage, result, and evidence. Requirements with no result remain `NOT_CHECKED`. No IDs or results are synthesized to fill gaps.

## 8. Evidence semantics

Existing cores write normalized specifications, model exports, CTL proof/counterexample files, BMC/SMT queries and results, static tool output/findings, memory observations, dynamic testcase/harness/build/execution/oracle artifacts, coverage reports, fuzz campaign artifacts, source lineage/integrity, run manifest, and pipeline report as supported by the current adapters. Result references point to evidence IDs; the manifest records artifact paths and hashes. Artifact paths are confined to the run workspace.

## 9. Known differences and limitations

- No teacher implementation code or additional teacher chapter document is present in this repository; this is a mapping to the brief, not a claim of behavioral identity.
- No production source-code generator or separate arithmetic-check contract exists in the current specification core.
- Function discovery is the existing conservative lexical C/C++ detector. Ambiguous/unmatched function declarations are recorded instead of guessed.
- Static/memory analyzers run on the discovered source set; their results are source-set-scoped unless a specific dynamic testcase links a function.
- Struct layout inference, some static-analysis drivers, sanitizers, coverage tools, Z3, and fuzz feedback retain their documented tool/platform capability limits. Unsupported stages are skipped/failed or return scoped tool outcomes; unrelated stages continue.
- Coverage-guided fuzzing requires coverage. Other fuzz modes do not.
- Concolic execution remains prototype/limited as documented in Fuzzing Core.
- GUI runtime remains a separate milestone dependency; this backend mapping adds no GUI feature and does not claim the Qt desktop workflow was run.
