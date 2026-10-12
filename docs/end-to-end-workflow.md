# Continuous Specification-to-verification workflow

## One project/specification context

The GUI's `VerificationSession` retains project path, selected source
specification path, immutable raw JSON, in-memory canonical JSON, normalized
Specification, source/canonical SHA-256 hashes, schema version and validation
result. Legacy migration occurs at selection/load time. Validation and
normalization happen before the session becomes ready. The exact loaded,
validated and normalized values are passed into `PipelineOptions` when a run
starts; the Specification stage does not reload them from disk. CLI runs use
the same content-based compatibility loader in the Specification stage.

## Stage dependencies and artifacts

The orchestrator builds explicit dependency edges: Specification → Model →
CTL/BMC/Codegen; Specification → SMT; Source → Static/Memory/Dynamic; Dynamic →
Coverage; Source/Dynamic → Fuzzing; all selected checker stages → Cross-check
and Report. Stages consume shared typed context populated by upstream stages
and persist their outputs through ArtifactStore. A missing required input is
reported in that stage's reason/status; it is not guessed or fabricated.

Evidence includes the raw input hash, canonical/normalized representation,
model and graph files, generated C/header, generated build/run logs and result,
static/memory/dynamic/coverage/fuzz evidence where those stages have supported
inputs, traceability links, and report/manifest. The GUI Evidence page can open
generated C artifacts as well as verify their manifest hashes. Model and
generated artifacts remain classified separately from production source.

## Real legacy acceptance run

Command used:

```powershell
python -m seclab.cli verify `
  --project E:\smart-ev-charging-safety `
  --spec E:\smart-ev-charging-safety\teacher_specs\smart_ev_teacher_e2e_v4.json `
  --config t/legacy-teacher-e2e-config.json `
  --workspace t/legacy-teacher-e2e-runs `
  --run-id legacy-teacher-e2e-v3
```

The fresh CLI run has 15 stage records and 43 scoped results. Specification,
Source, Model, CTL, SMT, Codegen, Static, Memory, Cross-check and Report stages
completed. BMC is skipped because no BMC property exists. Dynamic is skipped
because the specification has no executable test cases. Coverage and Fuzzing
are consequently skipped with the missing Dynamic dependency stated. Accuracy
was disabled in run config. Model is 28 states/47 transitions; generated model
C built/executed (`CODEGEN` build status `PASS`). Traceability integrity is
valid; all 127 evidence artifacts resolve and hash correctly; no analyzed
source changed during the run.

Static checker records include `INCONCLUSIVE` findings and `TOOL_ERROR` results;
ASan/UBSan have `BUILD_ERROR`, and leak checking is `INCONCLUSIVE` on the host.
These remain scoped. No dynamic or fuzz result is claimed without executable
tests/targets. No aggregate project PASS/FAIL/safety verdict is produced.

The offscreen PySide GUI acceptance test opened the same project and legacy
specification once, retained session context, rendered the 28/47 graph, ran
the configured pipeline and verified model/codegen evidence and report
traceability. This is an offscreen GUI runtime test, not a claim of manual
desktop acceptance on every platform.
