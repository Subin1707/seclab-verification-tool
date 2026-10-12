# Generic C code generation

`seclab.codegen.CGenerator` emits a deterministic C representation of a normalized `Specification` and its canonical `KripkeStructure`. It has no Smart-EV imports or domain-specific fields. Its small typed IR (`CProgram`, `CFile`, `CBlock`, `CLine`) renders files in sorted path order; each line can carry the model element that produced it. Callers choose an output directory; the generator creates:

```text
generated/
  source/model.c
  include/model.h
  tests/model_test.c
  fuzz/model_fuzz.c       # when requested
  manifest.json
  source-map.json
```

`source/model.c` exposes indexed states/transitions, initial-state lookup, ID lookup, and transition guard evaluation. State values and labels are emitted as escaped JSON strings. Known guards are consistent with the canonical model: model construction has already evaluated these guards and excluded disabled edges, so each retained guard is emitted as its canonical enabled value while the original expression remains attached to the transition record. An unresolved guard is retained as text and is rejected unless the caller supplies a runtime callback. Actions and labels remain transition metadata because the canonical graph does not define action execution semantics.

Generated C and its header are classified `GENERATED_ARTIFACT`; the executable self-check is `TEST_HARNESS`, and the optional fuzz entry point is `FUZZ_HARNESS`. The test executable validates the emitted graph, then accepts `[state-id [transition-id]]`; omitted input selects the first initial state. It validates IDs and transition source membership and emits JSON with the input state, initial marker, outgoing transition IDs, selected transition and resulting state. Invalid input writes a diagnostic to stderr and exits nonzero. Generated model code is not production source and a completed self-check is not a production safety verdict. IDs are stored as escaped strings and never interpolated into paths or C identifiers. Generated paths are fixed and checked for traversal and symlink escapes. Re-running generation with the same model produces identical file contents and hashes. `source-map.json` includes generated C line numbers mapped to specification ID, state IDs and transition IDs, including the generated harness transition checks.

`GeneratedArtifactRunner` compiles the generated model and self-check with a configured compiler and runs the executable through the shared `CommandRunner`. Build and execution timeouts are configurable separately. It persists every generated input, source map, manifest, compiler output, stdout/stderr, exit status and termination metadata through `ArtifactStore` with SHA-256 evidence. Compile failure or build timeout is `BUILD_ERROR`; unavailable/failed-to-start tools are `TOOL_ERROR`. Runtime outcomes remain separate: `TIMEOUT`, `ABNORMAL_TERMINATION`, `TOOL_ERROR`, or `COMPLETED`. A nonzero harness exit is an observed generated-artifact failure, not a property or production safety verdict. `input_args` configures the state/transition query; the harness does not invent an external application oracle.

Pipeline generation is opt-in with `PipelineOptions(generate_c_model=True)`. `generate_c_fuzz_harness=True` includes the libFuzzer-compatible entry point. The pipeline records generated files, manifest, source map, GCC/Clang compile and execution logs as evidence; unavailable compilers are recorded as unavailable/`TOOL_ERROR`. Other verification stages continue to analyze provided production source unless explicitly built to consume generated model artifacts in a future change. Generic JSON model fixtures for a boolean machine, counter, branching graph, bounded transition system and invalid guard are in `examples/codegen/`.
