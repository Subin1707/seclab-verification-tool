# Source and Execution Core v1

## Source discovery

`SourceLoader` accepts any existing source root; the project does not need a `src/` folder. It discovers `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hh`, `.hpp`, and `.hxx` files and returns immutable `SourceFile` metadata: resolved path, root-relative POSIX path, extension, language hint, byte size, and SHA-256 over the exact file bytes. Results are sorted deterministically. Files are never modified. Files containing NUL bytes are treated as binary and ignored.

Default excluded directories are `.git`, `.workspace`, `build`, and `dist`; callers can replace include and exclude glob patterns. Symlinks are not followed by default. If following is enabled, resolved targets outside the selected source root are ignored. Traversal and access failures are reported as source errors.

`LanguageDetector` uses translation unit extensions as evidence: `.c` indicates C; `.cc`, `.cpp`, or `.cxx` indicates C++; both means `MIXED_C_CPP`. Headers alone produce `UNKNOWN`, as do empty source collections. A nonempty collection containing no recognized C/C++ translation unit produces `UNSUPPORTED`.

`FunctionDetector` masks comments, strings, character literals, and preprocessor directives, then scans brace depth and conservatively parses declaration-like signatures immediately preceding top-level function bodies. It ignores prototypes and control keywords. It is not a compiler frontend: complex declarators, macros, templates, overload resolution, nested namespace/class methods, and some function-pointer forms may be omitted or have partial return/parameter metadata. It favors false negatives over treating arbitrary calls as definitions.

## Toolchain and command execution

`Toolchain` discovers `gcc`, `g++`, `clang`, `clang++`, `cppcheck`, `clang-tidy`, `z3`, `cbmc`, `gcov`, and `llvm-cov` independently. Each `ToolInfo` includes name, installation state, path, best-effort version, and capabilities. Version probes use `CommandRunner`, have a timeout, and combine stdout/stderr; missing or misbehaving tools remain informational and do not crash discovery.

`CommandRunner` accepts a structured argument vector, working directory, child environment overrides, stdin, timeout, and allowed exit codes. It always invokes subprocesses with `shell=False`; shell metacharacters in arguments remain ordinary argument characters. It captures stdout/stderr as bytes and decodes UTF-8 with replacement, so malformed output cannot break collection. The environment is copied for the child and the process-wide `os.environ` is not changed. On timeout, it kills the process (and on Windows attempts a process-tree termination) and captures remaining output. `ProcessRunner` is a SUT-oriented wrapper over the same primitive.

## Compilation and result semantics

`Compiler` selects `gcc` then `clang` for C, or `g++` then `clang++` for C++, through `Toolchain`. It compiles translation units (headers are not passed as translation units), defaults to configurable `-std=c11` or `-std=c++17`, accepts caller flags and include directories, and applies a build timeout. The executable is written under `<workspace>/build` by default or to a validated directory inside the workspace, outside the inferred source roots. It does not add sanitizer or optimization flags.

`BuildResult` records success, command result, binary path, compiler identity, source paths, language, an error code, and build evidence. A missing compiler maps to shared `TOOL_ERROR / COMPILER_NOT_FOUND`; failed compilation maps to `BUILD_ERROR / COMPILATION_FAILED`. A successful build is infrastructure progress, not a property verdict.

Execution timeout maps to `INCONCLUSIVE / EXECUTION_TIMEOUT`; an unstartable executable maps to `TOOL_ERROR`. Normal process completion, including exit code zero, maps to `INCONCLUSIVE / EXECUTION_COMPLETED` with scope stating that no verification property was evaluated. The core never maps process exit zero to `PASS`.

## Environment and evidence

`EnvironmentSnapshot` contains OS, platform description, architecture, Python version, and an optional caller-provided toolchain summary. It does not collect hostname, username, home path, or environment variables.

Command/build artifacts are written through the existing `ArtifactStore` under `evidence/execution/` or `evidence/build/`. Each command record contains argv, cwd, exit code, duration, timeout, timestamps, executable identity, and references to separate stdout and stderr artifacts. Environment snapshots use `evidence/environment/`. The store computes SHA-256 over artifact bytes. Child environment values are never dumped into evidence.

## Limitations

This milestone supplies infrastructure only. It does not implement static analyzers, sanitizers, coverage, fuzzing, model checkers for source code, or a complete verification pipeline. Mixed C/C++ collections are detected but must be split or configured by a later build orchestration layer. Function discovery is lexical and incomplete by design; build diagnostics and runtime behavior do not establish security properties.
