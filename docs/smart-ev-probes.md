# Smart-EV Probe Capability Report

## 1. Why these probes are separate

The real Smart-EV source audit found that the teacher JSON declares vulnerability names and metadata, but supplies no executable probe bodies. This area provides four intentionally defective, minimal C programs solely to exercise existing analysis tools. The files are not copied from or linked as replacements for production code.

Run the suite with:

```powershell
python tools/run_smart_ev_probes.py
```

The runner creates a unique workspace under `.runs/smart-ev-probes/`. Its coordinator only loads probe inputs/metadata and invokes existing compiler, static-analysis, and sanitizer APIs; it does not implement another analyzer.

## 2. Evidence scopes

| Classification | Meaning in this project |
|---|---|
| `PRODUCTION_SOURCE` | Real Smart-EV implementation under `E:\smart-ev-charging-safety\src`. No probe has this scope. |
| `BUG_INJECTED_PROBE` | Standalone source intentionally contains the declared defect. All four manifest entries use this scope. |
| `TOOL_CAPABILITY_EVIDENCE` | The run as a whole measures what the verification tools report on those probes. |

The run records `production_source_affected=0` and `production_vulnerability_claim=false`. Probe findings are never added to the Smart-EV production source inventory or production requirement verdicts.

## 3. Four vulnerability classes

| Probe | Injected operation |
|---|---|
| `buffer_overflow` | Writes at index 8 to an 8-byte heap buffer. |
| `memory_leak` | Allocates 64 bytes in a returned helper frame and never frees them. |
| `double_free` | Frees the same allocation twice. |
| `use_after_free` | Writes to an allocation after freeing it. |

All manifest entries set `expected_cwe: null`. The existing `CWEMapper` does not map the Clang-Tidy array-bound rule to a CWE or map `MemoryFinding` kinds to CWEs. CWE values are retained only when supplied by an analyzer or produced by an existing mapper rule; the probe runner does not add class-to-CWE mappings.

## 4. Tools used

The run invoked the existing `Compiler`, `CompilerDiagnosticsRunner`, `CppcheckRunner`, `ClangTidyRunner`, `ASanRunner`, `UBSanRunner`, and `LeakChecker`. It recorded toolchain paths/versions and actual command lines. Static findings retain each tool's raw output, normalized finding, rule ID, and any analyzer-provided/mapper-produced CWE.

## 5. Actual observations

Environment: Windows 11, Python 3.12.5; GCC 8.1.0, Clang 22.1.7, Cppcheck 2.21.0, and Clang-Tidy detected. All four ordinary C compilation commands succeeded.

| Probe | Static observations | Runtime observations | Scoped final result |
|---|---|---|---|
| `buffer_overflow` | Clang-Tidy reported `clang-analyzer-security.ArrayBound`: “Out of bound access to memory after the end of the heap area”. No CWE was attached. Cppcheck emitted its checker inventory line but no vulnerability diagnostic. Compiler diagnostics were clean. | ASan instrumentation compiled, but the runtime could not load. UBSan ran without a recognized finding. Leak detection unavailable on Windows. | `INCONCLUSIVE`; `STATIC_FINDINGS_REPORTED`. Static output is evidence, not a verified property verdict. |
| `memory_leak` | Cppcheck reported `memleak`, tool-supplied CWE-401. Clang-Tidy reported `clang-analyzer-unix.Malloc`: “Potential leak of memory pointed to by 'buffer'”; it also emitted a separate `memset` warning. | ASan runtime unavailable; UBSan ran without a recognized finding; LeakSanitizer unavailable on Windows. | `INCONCLUSIVE`; `STATIC_FINDINGS_REPORTED`. |
| `double_free` | Cppcheck reported `doubleFree`, tool-supplied CWE-415. Clang-Tidy reported `clang-analyzer-unix.Malloc`: “Attempt to release already released memory”. | ASan runtime unavailable. UBSan execution ended unsuccessfully without a recognized sanitizer report; core semantics leave it inconclusive. LeakSanitizer unavailable. | `INCONCLUSIVE`; `STATIC_FINDINGS_REPORTED`. |
| `use_after_free` | Cppcheck reported `deallocuse`, tool-supplied CWE-416. Clang-Tidy reported `clang-analyzer-unix.Malloc`: “Use of memory after it is released”. | ASan runtime unavailable; UBSan ran without a recognized finding; LeakSanitizer unavailable on Windows. | `INCONCLUSIVE`; `STATIC_FINDINGS_REPORTED`. |

Compiler diagnostics reported no warnings for these sources. The suite does not treat UBSan's clean scoped run as proof about memory safety. For double-free, its unrecognized abnormal termination is not relabeled as a memory finding.

## 6. Windows limitations

ASan builds completed, but execution reported that its runtime dependency could not be loaded; the existing runner returned `INCONCLUSIVE / SANITIZER_UNAVAILABLE`. `LeakChecker` explicitly declares leak detection unsupported on Windows and returned `INCONCLUSIVE / LEAK_DETECTION_UNAVAILABLE`. Sanitizer behavior was not changed to force a pass. Static analysis still ran and produced the findings above.

## 7. Evidence structure

The concrete run is at:

`.runs/smart-ev-probes/run-1790966699569455800/`

The [probe report](</E:/seclab-verification-tool/.runs/smart-ev-probes/run-1790966699569455800/probe-report.json>) and [run manifest](</E:/seclab-verification-tool/.runs/smart-ev-probes/run-1790966699569455800/run-manifest.json>) link to 167 hashed artifacts. The evidence includes:

- A copy of the manifest and each manifest entry.
- Each source file as consumed, with its hash and probe scope.
- Toolchain/environment snapshot.
- Compiler invocation, result, stdout/stderr, and build evidence.
- Each analyzer invocation/result, raw output, normalized findings, CWE mapping (if any), and evidence IDs.
- Sanitizer build/runtime commands, outputs, normalized findings, and existing `VerificationResult` objects.
- Before/after source-integrity records and final per-probe scoped results.

All evidence artifacts, compiler outputs, executables, and reports are inside the run workspace. The source files themselves remain in `examples/smart-ev-probes/` and are not modified by the runner.

## 8. Source integrity

For the recorded run, SHA-256 before and after matched for every source:

| Probe file | SHA-256 before = after |
|---|---|
| `buffer_overflow.c` | `3244c52618494e1989cb363a7477f5476a1ad3988549b24b8ea4e51254034700` |
| `memory_leak.c` | `788237cca376d6595a2c91923e036b6b1a0b1e78fff488090d5a7d864ac96884` |
| `double_free.c` | `50a88fb1b1f0aa1a77ed9f43df7cbddab5c39ad8fbb6696b125a5578d050bbdf` |
| `use_after_free.c` | `9e65f5f71b857011fdc993e12c546b474d6f7516e53b944c8956fc24722e6864` |

The runner checks hashes after compilation and each analyzer/sanitizer invocation. A changed hash marks `SOURCE_MUTATED` and stops further probe execution.

## 9. Why probe findings are not production vulnerabilities

The programs are intentionally defective and live under an examples-only root. They are passed individually to the tools, and every result's scope names `BUG_INJECTED_PROBE`; the run scope is `TOOL_CAPABILITY_EVIDENCE`. No source mapping or requirement link to the production Smart-EV project is created. A tool finding demonstrates only what that tool reported for that probe, configuration, and environment. It does not establish that production Smart-EV source contains the same defect.

## 10. Test status

The integration tests validate manifest rejection of production scope, all four probe declarations and files, compilation when a compiler is installed, analyzer invocation when each tool is installed, evidence file hashes, source integrity, and production/probe separation. They do not assert that every analyzer must detect every defect. Historical milestone run: `python -m pytest -q` completed with **238 passed, 4 skipped**; `python -m compileall -q src tests` passed. This historical count is superseded by the current canonical baseline in [architecture-freeze.md](architecture-freeze.md): **282 passed, 5 skipped, 0 failed**.
