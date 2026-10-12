# Static and Memory Analysis Core v1

## Static analyzer interface

`StaticAnalyzer.analyze(source_collection, context)` returns an `AnalysisResult` containing tool identity, whether it ran, normalized findings, command result(s), evidence references, success state, reason code, scope, and limitations. The context reuses the existing `Toolchain`, `CommandRunner`, `ArtifactStore`, workspace and source roots. No second subprocess, status, evidence, or compiler system is introduced.

Supported static entry points in this milestone are:

- `CppcheckRunner`: invokes Cppcheck with XML v2 and warning/style/performance/portability/information categories.
- `CompilerDiagnosticsRunner`: uses the existing GCC/Clang toolchain in syntax-only mode with `-Wall -Wextra -Wpedantic`; it does not build an executable.
- `ClangTidyRunner`: invokes Clang-Tidy checks. If `compile_commands.json` is absent it uses limited default language flags and records that limitation. `ClangStaticAnalyzerRunner` is an explicit unavailable result; Clang-Tidy is not represented as the standalone Static Analyzer.

Raw command metadata, stdout, stderr, raw XML/diagnostics and normalized findings are stored through the existing `ArtifactStore`. Findings refer to the raw output Evidence ID. The command metadata also carries stdout/stderr artifact references. Files use unique evidence names under `evidence/static_analysis/`.

## Normalized Finding and severity

`Finding` includes `id`, `tool`, `file`, `line`, `column`, `severity`, `category`, `message`, `rule_id`, `cwe`, `raw_evidence`, optional function/confidence, and metadata. It is immutable and JSON serializable. Paths are normalized to source-root-relative POSIX paths when safely resolvable; the original path is retained in metadata when normalization changes it.

Severity values are `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, and `UNKNOWN`. A tool category such as `warning`, `error`, `style`, or `performance` is retained in `category` and `metadata.original_severity`; it is not converted into a security severity. Parser failures and unknown output produce no synthetic findings, while the original tool output remains evidence.

`CWEMapper` preserves CWE supplied by the analyzer and has a small exact rule map for Clang's explicit null-dereference checker. It does not infer CWE from vague message words or invent CVEs.

## Static result semantics

Static analyzer reports are not confirmed runtime or property violations. A successful analyzer result with findings maps to shared `INCONCLUSIVE / STATIC_FINDINGS_DETECTED`; a successful run with no findings maps to `INCONCLUSIVE / NO_STATIC_FINDINGS`. Missing tools map to `TOOL_ERROR` with tool-specific reason codes. Timeouts are inconclusive and failed invocations are tool errors. Scope states which tool/configuration/source collection was checked. No result claims that the whole project is safe or vulnerable.

## Sanitizer architecture and findings

`Sanitizer` reuses `Compiler`, `Toolchain`, `ProcessRunner`/`CommandRunner`, `ArtifactStore`, and the shared `VerificationResult`. ASan uses `-fsanitize=address -fno-omit-frame-pointer`; UBSan uses `-fsanitize=undefined`. Instrumented binaries and evidence are stored under the workspace build/evidence roots. Original SUT files are only read and hashed; sanitizer flags apply to compiler invocations. A successful compile alone does not establish sanitizer support: ignored flags and missing runtime dependencies produce `INCONCLUSIVE / SANITIZER_UNAVAILABLE` without running or passing an uninstrumented binary.

`MemoryFinding` records ID, tool, kind, message, optional source location/function/address/allocation/failure sites, stack frames, raw evidence reference, and JSON metadata. ASan parsing recognizes common buffer overflows, use-after-free, double/invalid free, and leak reports. UBSan parsing recognizes signed overflow, invalid shifts, division by zero, alignment faults, and explicit runtime-error reports. Unknown crash text does not create a memory finding.

Observed ASan/UBSan findings map to `FAIL` scoped to the instrumented binary and this run/input. A clean completed run may map to `PASS / NO_SANITIZER_VIOLATION_OBSERVED`, with scope explicitly limited to that execution and not a global proof. Timeouts are inconclusive. An unexplained crash/nonzero exit without a recognized report is inconclusive and is not labeled a memory bug. Instrumentation/runtime unavailability is inconclusive; a missing compiler is a tool error; a real instrumented source build failure is a build error.

`LeakChecker` uses ASan leak detection only on Linux, forces `ASAN_OPTIONS=detect_leaks=1` in the child environment, and reports unavailable elsewhere as `INCONCLUSIVE / LEAK_DETECTION_UNAVAILABLE`. It does not infer leak support from ASan compilation alone. On Linux, a detected leak is `FAIL / LEAK_DETECTED` for that run.

## Struct layout and limitations

`StructAnalyzer` deliberately reports unsupported with an explicit limitation. Reliable `sizeof`, alignment, padding, and field offsets require a compiler-backed type selection/probe contract; this milestone does not guess from regex or block the analysis core on a partial C parser.

Analyzer checks depend on the available tool version, flags, source collection, platform, and compilation context. Clang-Tidy's limited mode is not equivalent to a project compilation database. Sanitizer runtime support differs by compiler/platform; this core records actual build/run evidence and does not infer support from flags alone. No SMT, BMC, fuzzing, coverage, mutation testing, GUI, or full verification pipeline is implemented.
