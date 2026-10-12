# Generic Multi-Project Validation

This validation runs five independent, non-Smart-EV projects through the same
`run_full_verification` API. Each selected specification is loaded, validated,
normalized, and then supplied to the pipeline. Static compiler diagnostics are
configured uniformly for all five projects; other optional stages follow each
project's generic `pipeline-config.json` and available inputs.

## Project shapes

| Project | Shape checked |
|---|---|
| `generic-c-project` | Simple C; two requirements, two properties, dynamic test |
| `generic-c-memory-project` | C memory/sanitizer analysis and dynamic test |
| `generic-multifile-cpp-project` | Two C++ translation units, three functions/tests, three requirements, CTL model |
| `generic-dynamic-project` | Multiple C functions and mixed dynamic outcomes |
| `generic-full-pipeline-project` | Multiple requirements/properties and configured verification stages |

## Pipeline stage lifecycle

`COMPLETED` and `SKIPPED` below are pipeline lifecycle states. A completed
stage can contain an individual checker result of `INCONCLUSIVE`, `TOOL_ERROR`,
or `BUILD_ERROR`; the pipeline preserves those scoped results without changing
the stage lifecycle or producing a project-level verdict.

| Project | SPECIFICATION | SOURCE | MODEL | CTL | BMC | SMT | STATIC | MEMORY | DYNAMIC | COVERAGE | FUZZING | REPORT |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Generic C | COMPLETED | COMPLETED | COMPLETED | COMPLETED | SKIPPED | COMPLETED | COMPLETED | SKIPPED | COMPLETED | SKIPPED | SKIPPED | COMPLETED |
| Memory C | COMPLETED | COMPLETED | SKIPPED | SKIPPED | SKIPPED | SKIPPED | COMPLETED | COMPLETED | COMPLETED | SKIPPED | SKIPPED | COMPLETED |
| Multi-file C++ | COMPLETED | COMPLETED | COMPLETED | COMPLETED | SKIPPED | SKIPPED | COMPLETED | SKIPPED | COMPLETED | SKIPPED | SKIPPED | COMPLETED |
| Multiple functions | COMPLETED | COMPLETED | SKIPPED | SKIPPED | SKIPPED | SKIPPED | COMPLETED | SKIPPED | COMPLETED | SKIPPED | SKIPPED | COMPLETED |
| Multiple requirements/properties | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED | COMPLETED |

No pipeline stage lifecycle was `FAILED` in these runs.

## Individual checker/result statuses

| Project | Observed result statuses and scopes |
|---|---|
| Generic C | CTL `PASS`; SMT `PASS`; static diagnostics `INCONCLUSIVE` (no static findings is scoped, not a safety proof); dynamic oracle `PASS` |
| Memory C | Static diagnostics `INCONCLUSIVE`; ASan and UBSan `BUILD_ERROR`; Leak Checker `INCONCLUSIVE` (unavailable); dynamic oracle `PASS` |
| Multi-file C++ | CTL `PASS`; static diagnostics `INCONCLUSIVE`; all three dynamic oracles `PASS` |
| Multiple functions | Static diagnostics `INCONCLUSIVE`; dynamic outcomes include `PASS`, `FAIL`, `INCONCLUSIVE` (timeout), and `BUILD_ERROR` |
| Multiple requirements/properties | CTL `PASS`; BMC `TOOL_ERROR`; SMT `PASS`; static diagnostics `INCONCLUSIVE`; ASan/UBSan `BUILD_ERROR`; Leak Checker `INCONCLUSIVE`; dynamic oracle `PASS`; Coverage `BUILD_ERROR`; Fuzzing `FAIL` (finding reported) |

The sanitizer and coverage build limitations reflect the current host/toolchain.
BMC's `TOOL_ERROR` is retained as a scoped result. These statuses are not
converted into project verdicts.

## Evidence and traceability checks

All five runs verified that:

- specification, source, and report stages completed;
- each evidence artifact existed under its run workspace and its SHA-256 matched the manifest;
- result evidence references and stage evidence references resolved to manifest entries;
- requirement and target traceability result/evidence references resolved to report/manifest entries;
- source integrity records had matching before/after SHA-256 values and `changed_during_run=false`;
- serialized reports contained no `overall_verdict` or `overall_status`.

## Automated integration test

`tests/integration/test_generic_multi_project_validation.py` parameterizes the
five project shapes through a single test body and pipeline API. The validation
run passed all five cases in the current environment.
