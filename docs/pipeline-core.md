# Pipeline Integration Core v1

`seclab.pipeline` coordinates existing specification, model, formal, source, analysis,
testing, coverage, fuzzing, and evidence components. It is an orchestration layer;
checker contracts and `VerificationStatus` meanings remain owned by their existing cores.
Workflow-specific stage groupings are integrations layered on top of this generic API;
the six-chapter teacher workflow is documented in
[teacher-workflow-mapping.md](teacher-workflow-mapping.md).

## Run

```python
from pathlib import Path
from seclab.pipeline import PipelineOptions, run_full_verification

report = run_full_verification(
    project=Path("path/to/source"),
    workspace=Path("path/to/artifacts"),
    options=PipelineOptions(specification_paths=(Path("spec.json"),)),
)
```

The workspace must be outside the project tree. Each invocation creates
`workspace/<run_id>/`; all generated artifacts, builds, reports, and evidence stay in
that run directory. Source discovery hashes supported C/C++ files and analysis runners
are given the source root read-only. No initial state is inferred by the pipeline.

## Stage order and inputs

Each run report contains one record per known stage. Stages are independently recorded as `NOT_STARTED`, `RUNNING`, `COMPLETED`, `SKIPPED`,
or `FAILED`. A checker result such as `PASS`, `FAIL`, or `INCONCLUSIVE` does not control
stage execution. The stages are specification, model, source, CTL, BMC, SMT, static,
memory, dynamic, coverage, fuzzing, and report. Dependencies describe required inputs;
for example, source analysis can proceed when specification loading failed, while CTL
requires both a normalized specification and its explicit-state Kripke model.
Stage records include UTC start/end, duration, input/output references, result/evidence
references, and explicit skip/error information. Unselected stages in chapter runs remain
`NOT_STARTED`.

Static findings stay inconclusive unless the analyzer core classifies infrastructure
failure. Coverage is reported as a measurement and has no safety verdict. Fuzzing is
optional; coverage-guided strategy requires coverage feedback. A campaign with no
finding does not establish safety.

The integrated memory stage invokes the existing StructAnalyzer and records its
support boundary as a limitation; its current implementation does not infer layouts.
Likewise, the available Clang Static Analyzer runner reports that its standalone
driver contract is not implemented. These remain explicit tool limitations in their
results and do not become safety passes.

## Outputs

`evidence/manifest/run-manifest.json` carries stage statuses, tool/environment details,
all collected `VerificationResult` records, and evidence metadata. `evidence/report/pipeline-report.json`
contains run timing, specification summary, stage summaries, status counts, traceability,
limitations, and manifest reference. The report intentionally has no overall project
PASS/FAIL field. Requirement traceability links requirement IDs to property/test IDs,
result IDs, and evidence IDs; requirements without a result remain `NOT_CHECKED`.

Stages execute in deterministic dependency order: specification, source discovery,
model, CTL, BMC, SMT, static analysis, memory analysis, dynamic tests, coverage,
fuzzing, then report assembly. A selected stage runs with its declared prerequisite
closure; selecting REPORT alone assembles an empty-scope report. The scheduler chooses
one topologically ready stage at a time to preserve this order. A source inventory with
no supported source files is itself `SKIPPED` with a reason. Coverage is strategy-dependent for fuzzing: a coverage
failure does not hard-block black-box fuzzing; coverage-guided fuzzing records a skip
when feedback is unavailable.

## Verified example and limits

The integration test suite exercises a real JSON specification, explicit Kripke graph,
CTL, Z3 BMC/SMT, compiler diagnostics, dynamic harness execution, gcov coverage, and a
coverage-guided fuzz campaign. Harnesses, executables, gcov files, logs, and reports are
created below `workspace/<run_id>/`; the source tree is SHA-256 checked by dynamic and
fuzz execution adapters.

Source inventory records stable source IDs, source/function/requirement mappings, and
pre-run SHA-256. Final source-integrity evidence compares hashes after the run. The
report verifies every tracked artifact's SHA-256 against its evidence reference; hash
mismatches create a scoped `ARTIFACT_INTEGRITY` result. Source
lineage in the report links source-set or function-scoped analysis results to their
result and evidence IDs. Project source is a user input reference; generated artifacts
remain under the run workspace. Generated test harnesses are identified as
`TEST_HARNESS`; production source is never labeled as an injected probe.

Available limitations come from the existing cores: `StructAnalyzer` currently records
that it cannot infer layouts; the standalone Clang Static Analyzer runner is an
explicit unavailable placeholder; LeakSanitizer declares platform support boundaries;
and unsupported test signatures or missing compiler/coverage/fuzz feedback produce
their existing inconclusive or tool/build errors. Those outcomes are retained as
limitations and never converted into a safety pass.
