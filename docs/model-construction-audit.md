# Generic Model Construction Audit

## Scope and findings

The repository already has a domain-independent finite Kripke core. The audit
covered the specification schema, loader/validator/normalizer, model core,
CTL parser/checker, pipeline stages and orchestrator, artifact storage and
traceability, the GUI model page, benchmark catalog, and related tests.

## Existing model and active behavior

- `Specification` is the canonical normalized input. Its contract already
  supports root `states` and `transitions`, `initial_state`, state-level
  `initial`, `values`, and `labels`, transition `source`, `target`, `guard`,
  `action`, `label`, plus nested `state_machines`. Normalization flattens
  nested machines into those root collections and keeps machine IDs.
- `generate_kripke_structure` copies explicit states and transitions. It
  applies guards only where the existing SMT expression evaluator can resolve
  them from the source state's values. It does not infer a state space from
  variable domains. Invalid endpoints, missing/conflicting initial states,
  invalid guards, or inconsistent assignment actions are rejected.
- `KripkeStructure` is immutable, sorts its states and edges, validates
  references and initial membership, and computes a stable SHA-256 structural
  hash. Missing transition IDs receive content-derived IDs.
- Reachability, unreachable-state detection, and structural deadlock detection
  are implemented. JSON and DOT exporters expose graph data, hash, statistics,
  labels, initial states and reachability sets.
- The CTL parser and checker support EX, AX, EF, AF, EG, AG, EU and AU, plus
  Boolean operators. `PipelineStages.ctl` evaluates declared CTL properties
  against `ctx.kripke`, records property/model links, and persists witness or
  counterexample observations when available. The checker uses virtual
  self-loops for temporal semantics at deadlocks without changing graph data.
- The pipeline orders SPECIFICATION → MODEL → CTL and BMC. MODEL failure or
  skip blocks dependent checks with a recorded dependency reason; unrelated
  stages can continue. ArtifactStore hashes artifacts with SHA-256, validates
  evidence paths remain within the workspace, and the pipeline includes
  artifacts in its manifest and requirement traceability.

## Current gaps

- The model stage skips explicitly when there are no declared states. The skip
  reason exists, but there is no dedicated model validation or unsupported
  result artifact.
- A successful model run currently writes only `evidence/model/kripke.json`.
  That artifact has graph statistics and hash but omits specification ID/hash,
  source specification path, construction method/version, and a distinct
  validation report. There is no separate summary or DOT artifact.
- The GUI preview is assembled from normalized states/transitions and the
  result page renders records in a table. It does not draw a graph, distinguish
  reachable/unreachable/deadlock styling, or provide model-specific build,
  validate, display, and export actions. It has project/specification selection
  elsewhere in the workbench, not on the model page.
- The generic accuracy benchmark catalog covers CTL and other verification
  areas, but has no model-builder graph-comparison fixture benchmark or model
  TP/TN/FP/FN report.
- Existing generic model tests cover core construction, reachability, export,
  invalid models, and JSON-to-model-to-CTL. The architecture test prevents
  generic areas from importing integrations, but does not isolate a model-only
  test invocation from Smart-EV packages.

## Existing CTL input and evidence

CTL properties come from normalized `properties` entries with `logic: CTL` and
their `formula` text; formulas are parsed and checked by the existing CTL core.
Per-property evidence records formula, observed status, model hash, statistics,
state/transition IDs, satisfying/violating initial states, and any validated
witness/counterexample. Unsupported path forms are represented by a
recomputable model observation instead of a fabricated path.

## GUI and benchmark

`ModelPage` currently consumes MODEL stage summaries or a preview and presents
state/transition rows, initial states, reachability and deadlock rows. The
benchmark ground truth lives in `src/seclab/benchmark/catalog.py` and the common
runner compares checker observations independently from expected values; no
model-construction-specific catalog/runner is present at audit time.

## Evidence and traceability

ArtifactStore writes JSON under the run evidence directory, computes SHA-256,
and enforces workspace containment. Pipeline manifests and reports list those
artifacts. Requirements receive a model hash and evidence reference, while CTL
properties receive model links in pipeline metadata. The model artifact needs
stronger specification provenance and richer graph/validation artifact
references to satisfy the requested contract.

## Implementation gaps to address

1. Add deterministic model provenance and separate summary, JSON, validation,
   and graph evidence through the existing model generator/exporter and
   ArtifactStore; preserve current specification contract.
2. Make the GUI render the real serialized graph with pan/zoom/fit/reset and
   clear state classifications; expose export using existing graph formats.
3. Add generic graph fixtures and independent structure comparison coverage,
   including deterministic IDs/hashes, reachability, deadlock, invalid
   transitions, CTL linkage, and Smart-EV import isolation.
4. Document actual limitations, including uninterpreted unresolved guards and
   absent graph rendering when the GUI runtime is unavailable.
