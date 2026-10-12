# Dynamic Testing Core v1

The dynamic testing package runs explicit test cases against a C/C++ function or executable. It reuses the shared `Compiler`, `ProcessRunner`, `ArtifactStore`, and `VerificationResult` classifier. It does not perform coverage-guided exploration, fuzzing, or formal verification.

## Test cases and expected behavior

`TestCase` carries a stable caller-provided ID, target, structured inputs, category, requirement/property links, timeout, and expected behavior. `ExpectedBehavior` is independent from execution and can contain checks for `exit_code`, `stdout`, `stdout_contains`, `stderr`, `stderr_contains`, `return_value`, `no_crash`, parsed JSON `structured_output`, and `memory_finding` presence. Each check is compared as data; predicates and executable expressions are not accepted. JSON is parsed from the process's actual stdout. Memory checks are conclusive only when the runner successfully built source with an explicit supported sanitizer flag; a signature from an uninstrumented/prebuilt process is recorded as output but cannot establish a memory-oracle result.

Function inputs map exact C parameter names to finite JSON scalar numbers or booleans. Executable inputs use `{"argv": ["..."], "stdin": "..."}`. Arguments are passed without a shell. A completed process with no declared oracle is `INCONCLUSIVE/NO_TEST_ORACLE`, never a pass.

## Function harness limits

The generic harness supports simple, unmangled C function names, named scalar integer, bool, float, and double parameters, and scalar or void returns. Pointer/reference/array/function-pointer, aggregate, variadic, unnamed, overloaded C++, and unsupported declarations are rejected with a structured unsupported-signature result. The detector is lexical, so ambiguous discovery also requires caller resolution; no signature is guessed.

Harness inputs travel through argv and are parsed/range-checked in generated C. Input values are not interpolated into source. A return marker is written to stderr and removed from the user's observed stderr; ambiguous or malformed markers are a tool observation error, so SUT output cannot silently substitute a different returned value. Ordinary SUT stdout/stderr remain observations. Oracle checks are not evaluated after timeout, and unrelated checks are not evaluated after abnormal termination. SUT files are hashed before and after execution and are never rewritten by the runner.

## Domain candidates and evidence

`TestGenerator` deterministically emits abstract candidates for supported integer, real, boolean, finite-value, and string domains. Integer bounds include adjacent invalid values; real domains use endpoints and midpoint. Candidates remain `ABSTRACT` because specification variable IDs are not assumed to correspond to function parameters. Unsupported domains are reported instead of fabricated.

Each run records the test case and its source hash map, generated harness when applicable, compiler command/output, process command/stdout/stderr, raw observation (including structured output and recognized memory findings), oracle evaluation, and shared verification result in `ArtifactStore`. Artifacts carry content hashes and IDs. `run_many` isolates failures and continues with subsequent cases. A `PASS` or `FAIL` applies only to the explicit oracle checks for that execution; it says nothing about coverage or untested behavior. Expected values are only persisted in the testcase/oracle record and are never used to populate observations.
