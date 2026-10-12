# Coverage Core v1

Coverage is a measurement and evidence stage. **100% coverage does not prove absence of defects.** A coverage report does not create a safety/security PASS, and it is deliberately separate from the functional `VerificationResult` produced for each testcase.

## Architecture and backends

`CoverageRunner` reuses `TestCase`, the existing `TestRunner`, `Compiler`, `ProcessRunner`, `ArtifactStore`, `Toolchain`, and shared result classifier. It enables backend instrumentation through the small `TestRunner.run_one` options for compiler flags, process environment, compiler selection, separate compilation, and an isolated build directory.

- GCC/gcov uses `--coverage`, isolated object files, gcov line listings and gcov branch arcs. The backend parses gcov's own line and branch records. JSON gcov output is not required, so GCC 8 installations remain usable.
- Clang/LLVM uses `-fprofile-instr-generate -fcoverage-mapping`, `LLVM_PROFILE_FILE`, `llvm-profdata merge`, and `llvm-cov export` JSON. LLVM segment regions and true/false branch outcomes are parsed separately.
- `auto` selects an installed compiler/backend pair. Explicit `gcov` or `llvm` selection never silently falls back. LLVM requires `llvm-profdata`, `llvm-cov`, and the matching Clang compiler.

Gcov branch metrics count backend-reported control-flow arcs. LLVM metrics count exported true/false outcomes. Those totals have backend-specific semantics and must not be compared as if identical.

## Isolation, filtering, and aggregation

Each testcase gets a fresh instrumented build under `coverage/<run>/build` and raw/profile output under `coverage/<run>/raw`. That is the reset strategy: no old `.gcda` or `.profraw` files participate in a new run. The original SUT files are hashed before and after the suite and are not edited. Builds use separate compilation so object/profile notes stay in the isolated coverage build tree.

Only explicitly supplied SUT source files are included in normalized report metrics. Coverage from the generated dynamic-test harness, system headers, runtime libraries, and other files exported by a backend is filtered out by canonical source path. Source labels are relative to `SourceFile.relative_path`, an explicit source root, or the common source parent.

The suite aggregates the union of executable source lines and backend branch identities. It does not add testcase percentages. Per-file and suite percentages use executable entities reported by that backend; a zero denominator produces `null` (`None` in Python). Lines with no executable count are excluded. `CoverageSnapshot` and `CoverageDelta` expose new covered lines and branches for future consumers.

## Partial runs and test outcomes

A testcase whose functional oracle fails still runs through coverage collection. Timeout, crash, execution error, missing per-test data, build failure, or collection diagnostics make the suite incomplete/partial; usable data from other tests remains reportable. A nonzero exit can still be a complete execution when the process finishes and the oracle allows it. If a process produced no usable backend data, the run returns a shared `INCONCLUSIVE` or `TOOL_ERROR` result with a coverage-specific reason such as `COVERAGE_DATA_MISSING`. These infrastructure outcomes do not mean the SUT is vulnerable.

## Evidence and report

`CoverageReport` serializes backend, SUT file list, normalized line and branch metrics, testcase IDs/count, completeness/partial flags, tool version, limitations, evidence IDs, and generated harness paths. Evidence stores coverage configuration, shared testcase/execution evidence, compiler/tool commands and logs, raw gcov/profile files, backend export/listing files, source integrity hashes, and normalized report JSON. Raw backend outputs are never interpreted by the other backend's parser.

Threshold checks, fuzzing, per-test reports, and safety conclusions are outside v1.
