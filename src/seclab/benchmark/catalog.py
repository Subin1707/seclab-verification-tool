"""Generic accuracy cases spanning current checker APIs and known limits."""
from __future__ import annotations

from .models import BenchmarkCase


def _case(case_id: str, category: str, description: str, checker: str, status: str,
          finding: str | None = None, prop: str | None = None, evidence: tuple[str, ...] = (),
          limitation: str | None = None, source: str | None = None,
          spec: dict | None = None, **scenario: object) -> BenchmarkCase:
    provenance = {
        "CTL": ("Manually verified finite-state transition system", "Manual label/transition construction",
                "Temporal property evaluated from the declared graph semantics"),
        "BMC": ("Mathematically derived finite-state reachability fixture", "Manual graph and bound construction",
                "Reachable bad-state depth is derived from explicit transitions"),
        "SMT": ("Mathematically derived bounded integer/Boolean formula", "Manual formula and finite-domain construction",
                "Satisfiability follows by evaluating the declared bounded formula"),
        "Static": ("Manually verified source semantics", "Synthetic clean or defective C fixture",
                   "Expected defect presence is derived from source operations, independent of analyzer output"),
        "Memory": ("Known synthetic memory-safety defect or safe allocation fixture", "Synthetic C program",
                   "Expected behavior follows allocation, access, and deallocation operations"),
        "Dynamic": ("Declared return-value oracle or controlled process condition", "Synthetic C/Python fixture",
                    "Expected return is declared independently; build/timeout/crash conditions are controlled"),
        "Fuzzing": ("Known deterministic seed behavior or bounded campaign condition", "Synthetic target and fixed seed/budget",
                    "Expected crash/oracle behavior is declared from target branch and seed bytes"),
        "Coverage": ("Mathematically derived counters", "Synthetic line/branch counter input",
                     "Expected ratio is computed from declared covered and total counts"),
    }
    gt_source, creation, validation = provenance.get(category, ("Manual fixture review", "Synthetic fixture",
        "Independent fixture-level reasoning; checker output is not used"))
    return BenchmarkCase(case_id, description, source, spec, checker, status, finding, prop,
                         evidence, limitation, category, scenario, gt_source, creation, validation)


CASES = (
    # CTL: truth, input errors, graph shape and temporal scope.
    _case("CTL-001", "CTL", "True invariant over a self-loop", "CTL", "PASS", "NONE", "P-SAFE", ("proof-or-result",), None, "int main(void){return 0;}", formula="AG(safe)", model="safe-loop"),
    _case("CTL-002", "CTL", "False invariant has a counterexample", "CTL", "FAIL", "PROPERTY_VIOLATED", "P-UNSAFE", ("counterexample",), None, "int main(void){return 0;}", formula="AG(safe)", model="unsafe-path"),
    _case("CTL-003", "CTL", "Unknown proposition is a specification error", "CTL", "SPEC_ERROR", "UNKNOWN_ATOM", "P-UNKNOWN", ("diagnostic",), "Input labels are explicit; no label inference.", formula="AG(missing)", model="safe-loop"),
    _case("CTL-004", "CTL", "Multiple initial states are all checked", "CTL", "FAIL", "PROPERTY_VIOLATED", "P-MULTI", ("counterexample",), None, formula="AG(safe)", model="two-initial-one-unsafe"),
    _case("CTL-005", "CTL", "Deadlock uses query-local self-loop semantics", "CTL", "PASS", "NONE", "P-DEADLOCK", ("proof-or-result",), "Virtual self-loop does not modify source graph.", formula="AG(safe)", model="safe-deadlock"),
    _case("CTL-006", "CTL", "Cycle supports greatest fixed point", "CTL", "PASS", "NONE", "P-CYCLE", ("proof-or-result",), None, formula="EG(active)", model="active-cycle"),
    _case("BMC-005", "BMC", "Bounded search finds no path before the bad state", "BMC", "INCONCLUSIVE", "NONE_WITHIN_BOUND", "P-BOUNDED", ("solver-query", "completeness"), "A larger bound is needed to reach the bad state.", formula="bad", model="bad-at-depth-3", bound=1),
    _case("CTL-008", "CTL", "Unbounded eventuality holds on a finite graph", "CTL", "PASS", "NONE", "P-UNBOUNDED", ("proof-or-result",), None, formula="AF(done)", model="eventually-done"),
    _case("CTL-009", "CTL", "Multiple initial states satisfying property pass", "CTL", "PASS", "NONE", "P-MULTI-SAFE", ("proof-or-result",), None, formula="AG(safe)", model="two-initial-safe"),
    _case("CTL-010", "CTL", "AG rejects one unsafe branch among safe successors", "CTL", "FAIL", "PROPERTY_VIOLATED", "P-BRANCH", ("counterexample",), None, formula="AG(safe)", model="branching-one-unsafe"),
    _case("CTL-011", "CTL", "Nested temporal operators hold on every branch", "CTL", "PASS", "NONE", "P-NESTED", ("proof-or-result",), None, formula="AG(AF(done))", model="branching-eventually-done"),
    # BMC.
    _case("BMC-001", "BMC", "SAT path contains a reachable bad state", "BMC", "FAIL", "COUNTEREXAMPLE", "P-BAD", ("trace", "solver-query"), None, formula="bad", model="bad-at-depth-1", bound=2),
    _case("BMC-002", "BMC", "UNSAT below completeness threshold stays inconclusive", "BMC", "INCONCLUSIVE", "NONE_WITHIN_BOUND", "P-DEEP", ("solver-query", "completeness"), None, formula="bad", model="bad-at-depth-3", bound=1),
    _case("BMC-003", "BMC", "UNSAT at completeness threshold proves bounded graph property", "BMC", "PASS", "NONE", "P-SAFE", ("solver-query", "completeness"), "Complete only for bad-state reachability in the supplied finite graph.", formula="bad", model="safe-linear", bound=3),
    _case("BMC-004", "BMC", "Injected backend timeout is inconclusive", "BMC", "INCONCLUSIVE", "SOLVER_TIMEOUT", "P-TIMEOUT", ("solver-query",), "Controlled backend fixture; not a wall-clock performance test.", formula="bad", model="linear", bound=2),
    _case("BMC-006", "BMC", "Bad state at depth zero is immediately reachable", "BMC", "FAIL", "COUNTEREXAMPLE", "P-DEPTH-0", ("trace", "solver-query"), None, formula="bad", model="bad-at-depth-0", bound=0),
    _case("BMC-007", "BMC", "One branch reaches a bad state within the bound", "BMC", "FAIL", "COUNTEREXAMPLE", "P-BRANCH", ("trace", "solver-query"), None, formula="bad", model="branching-one-unsafe", bound=1),
    _case("BMC-008", "BMC", "Bad state exists but is unreachable from every initial state", "BMC", "PASS", "NONE", "P-UNREACHABLE", ("solver-query", "completeness"), "Complete for bad-state reachability in this finite graph.", formula="bad", model="safe-linear", bound=3),
    # SMT.
    _case("SMT-001", "SMT", "Satisfiable violation query returns model", "SMT", "FAIL", "PROPERTY_VIOLATED", "P-SAT", ("solver-query", "counterexample"), None, formula="x <= 5", domain="0..10"),
    _case("SMT-002", "SMT", "No violating valuation in bounded domain", "SMT", "PASS", "NONE", "P-UNSAT", ("solver-query",), "Scoped to declared finite/bounded variable domains.", formula="x <= 10", domain="0..10"),
    _case("SMT-003", "SMT", "Backend UNKNOWN remains inconclusive", "SMT", "INCONCLUSIVE", "UNKNOWN", "P-UNKNOWN", ("solver-query",), "Controlled backend fixture.", formula="x <= 5", domain="0..10"),
    _case("SMT-004", "SMT", "Solver timeout remains inconclusive", "SMT", "INCONCLUSIVE", "TIMEOUT", "P-TIMEOUT", ("solver-query",), "Controlled backend fixture.", formula="x <= 5", domain="0..10"),
    _case("SMT-005", "SMT", "Boolean/integer type mismatch is rejected", "SMT", "SPEC_ERROR", "TYPE_MISMATCH", "P-TYPE", ("diagnostic",), None, formula="x && true", domain="integer"),
    _case("SMT-006", "SMT", "Division operator is explicitly unsupported", "SMT", "SPEC_ERROR", "UNSUPPORTED_OPERATOR", "P-OP", ("diagnostic",), "Current SMT expression grammar omits division.", formula="x / 2 > 1", domain="integer"),
    _case("SMT-007", "SMT", "Domain bounds constrain solver model", "SMT", "PASS", "NONE", "P-DOMAIN", ("solver-query", "domain-constraints"), None, formula="x <= 10", domain="0..10"),
    _case("SMT-008", "SMT", "Unknown variable is rejected without inventing a domain", "SMT", "SPEC_ERROR", "UNKNOWN_VARIABLE", "P-UNKNOWN-VAR", ("diagnostic",), None, formula="missing > 0", domain="x:0..10"),
    _case("SMT-009", "SMT", "Violation query outside the declared lower domain is UNSAT", "SMT", "PASS", "NONE", "P-DOMAIN-LOW", ("solver-query",), None, formula="x >= 0", domain="0..10"),
    _case("SMT-010", "SMT", "Boundary valuation at declared maximum remains satisfiable", "SMT", "FAIL", "PROPERTY_VIOLATED", "P-BOUNDARY", ("solver-query", "counterexample"), None, formula="x == 10", domain="0..10"),
    # Static analysis.
    _case("STATIC-001", "Static", "Known clean function produces no analyzer finding", "cppcheck", "INCONCLUSIVE", "NONE", None, ("raw-analyzer-output",), "No scan is a global safety proof.", "int value(void){return 3;}", analyzer="cppcheck"),
    _case("STATIC-002", "Static", "Known null dereference is reported where analyzer is available", "cppcheck", "INCONCLUSIVE", "FINDING_PRESENT", None, ("raw-analyzer-output", "finding-record"), "Static findings remain scoped to the analyzer and fixture.", "int f(void){int *p=0;return *p;}", analyzer="cppcheck"),
    _case("STATIC-003", "Static", "Compiler warning is retained as diagnostic finding", "compiler-diagnostics", "INCONCLUSIVE", "FINDING_PRESENT", None, ("compiler-output", "finding-record"), "Compiler and warning flags affect diagnostics.", "int main(void){int unused=3;return 0;}", analyzer="compiler"),
    _case("STATIC-004", "Static", "Missing analyzer reports tool error, never clean", "missing-analyzer", "TOOL_ERROR", "ANALYZER_UNAVAILABLE", None, ("diagnostic",), "Tool availability is environment-dependent.", "int main(void){return 0;}", analyzer="nonexistent-analyzer"),
    _case("STATIC-005", "Static", "Known stack buffer write exceeds the declared array", "cppcheck", "INCONCLUSIVE", "FINDING_PRESENT", None, ("raw-analyzer-output", "finding-record"), None, "int f(void){char a[4]={0};a[8]=1;return a[0];}", analyzer="cppcheck"),
    _case("STATIC-006", "Static", "Known allocation is not released before return", "cppcheck", "INCONCLUSIVE", "FINDING_PRESENT", None, ("raw-analyzer-output", "finding-record"), None, "#include <stdlib.h>\nint f(void){void*p=malloc(16);return p==0;}", analyzer="cppcheck"),
    _case("STATIC-007", "Static", "Known pointer is read after it is freed", "cppcheck", "INCONCLUSIVE", "FINDING_PRESENT", None, ("raw-analyzer-output", "finding-record"), None, "#include <stdlib.h>\nint f(void){volatile int x;int*p=malloc(sizeof(int));if(!p)return 0;free(p);x=*p;return x;}", analyzer="cppcheck"),
    _case("STATIC-008", "Static", "Known pointer is freed twice", "cppcheck", "INCONCLUSIVE", "FINDING_PRESENT", None, ("raw-analyzer-output", "finding-record"), None, "#include <stdlib.h>\nint f(void){void*p=malloc(8);if(!p)return 0;free(p);free(p);return 0;}", analyzer="cppcheck"),
    _case("STATIC-009", "Static", "Syntax error is retained as a compiler/tool error", "compiler-diagnostics", "TOOL_ERROR", "FINDING_PRESENT", None, ("compiler-output", "finding-record"), "Syntax diagnostics are not memory defect findings.", "int broken(void){return ( ;}", analyzer="compiler"),
    # Memory analysis.
    _case("MEM-001", "Memory", "Heap buffer overflow is detected by ASan where supported", "asan", "FAIL", "HEAP_BUFFER_OVERFLOW", None, ("sanitizer-report",), "Compiler/runtime support is platform-dependent.", "#include <stdlib.h>\nint main(void){volatile char*p=malloc(1);p[2]=1;free((void*)p);}", sanitizer="asan"),
    _case("MEM-002", "Memory", "Use after free is detected by ASan where supported", "asan", "FAIL", "USE_AFTER_FREE", None, ("sanitizer-report",), "Compiler/runtime support is platform-dependent.", "#include <stdlib.h>\nint main(void){char*p=malloc(4);free(p);return p[0];}", sanitizer="asan"),
    _case("MEM-003", "Memory", "Double free is detected by ASan where supported", "asan", "FAIL", "DOUBLE_FREE", None, ("sanitizer-report",), "Compiler/runtime support is platform-dependent.", "#include <stdlib.h>\nint main(void){void*p=malloc(4);free(p);free(p);}", sanitizer="asan"),
    _case("MEM-004", "Memory", "Memory leak is detected by LeakSanitizer where supported", "leak-sanitizer", "FAIL", "MEMORY_LEAK", None, ("sanitizer-report",), "LeakSanitizer currently declares Linux support only.", "#include <stdlib.h>\nint main(void){volatile void*p=malloc(32);return p==0;}", sanitizer="leak"),
    _case("MEM-005", "Memory", "Clean execution is scoped PASS, not global safety", "asan", "PASS", "NONE", None, ("execution-record",), "Only this execution/input is checked.", "#include <stdlib.h>\nint main(void){void*p=malloc(4);free(p);}", sanitizer="asan"),
    _case("MEM-006", "Memory", "Unavailable sanitizer is explicitly environment limited", "asan", "ENVIRONMENT_LIMITED", "SANITIZER_UNAVAILABLE", None, ("diagnostic",), "Controlled empty-toolchain fixture; no negative finding is inferred.", "int main(void){return 0;}", sanitizer="asan", toolchain="empty"),
    # Dynamic execution.
    _case("DYN-001", "Dynamic", "Oracle matches observed return value", "dynamic-test", "PASS", "NONE", "T-RETURN", ("test-case", "observation", "oracle-evaluation"), None, "int answer(void){return 42;}", input={"args": {}}, expected={"return_value": 42}),
    _case("DYN-002", "Dynamic", "Oracle mismatch is a scoped failure", "dynamic-test", "FAIL", "ORACLE_VIOLATION", "T-ORACLE", ("observation", "oracle-evaluation"), None, "int answer(void){return 42;}", input={"args": {}}, expected={"return_value": 41}),
    _case("DYN-003", "Dynamic", "Build failure remains BUILD_ERROR", "dynamic-test", "BUILD_ERROR", "BUILD_FAILED", "T-BUILD", ("build-log", "oracle-evaluation"), None, "int broken(void){return ( ;}", input={"args": {}}, expected={"return_value": 1}),
    _case("DYN-004", "Dynamic", "Process timeout remains inconclusive", "dynamic-test", "INCONCLUSIVE", "TIMEOUT", "T-TIMEOUT", ("process-record",), "Timeout is bounded to this execution.", None, target="python-sleep", timeout=0.05),
    _case("DYN-005", "Dynamic", "Sanitizer-backed memory finding remains unavailable without instrumentation", "dynamic-test", "INCONCLUSIVE", "SANITIZER_UNAVAILABLE", "T-MEMORY", ("process-record", "oracle-evaluation"), "Windows may not provide a compatible sanitizer runtime.", "#include <stdlib.h>\nint main(void){volatile char*p=malloc(1);p[2]=1;free((void*)p);return 0;}", target="abnormal-executable", sanitizer="asan"),
    _case("DYN-006", "Dynamic", "Unsupported non-scalar function input remains unsupported", "dynamic-test", "UNSUPPORTED", "HARNESS_UNSUPPORTED_INPUT", "T-UNSUPPORTED", ("test-case", "diagnostic"), "The harness accepts finite scalar arguments only.", "int echo(int value){return value;}", target="unsupported-input", input={"args": {"value": "not-a-scalar"}}, expected={"return_value": 0}),
    _case("DYN-007", "Dynamic", "A real subprocess abnormal termination violates an explicit no-crash oracle", "dynamic-test", "FAIL", "ABNORMAL_TERMINATION", "T-CRASH-PROCESS", ("process-record", "observation", "oracle-evaluation"), "Uses POSIX SIGSEGV or the Windows access-violation exit status; only the observed subprocess termination is scored.", None, target="python-crash"),
    # Coverage measurements.
    _case("COV-001", "Coverage", "Zero covered executable lines reports zero percent", "coverage", "INCONCLUSIVE", "NONE", "0%", ("coverage-report",), "Coverage has no property verdict.", coverage={"covered": 0, "total": 4}),
    _case("COV-002", "Coverage", "Partial line coverage reports the measured ratio", "coverage", "INCONCLUSIVE", "NONE", "50%", ("coverage-report",), "Backend semantics are retained.", coverage={"covered": 2, "total": 4}),
    _case("COV-003", "Coverage", "Full line coverage reports 100 percent only", "coverage", "INCONCLUSIVE", "NONE", "100%", ("coverage-report",), "Coverage does not imply correctness.", coverage={"covered": 4, "total": 4}),
    _case("COV-004", "Coverage", "Branch arcs are measured independently", "coverage", "INCONCLUSIVE", "NONE", "50%", ("coverage-report",), "Branch/arc semantics vary by backend.", coverage={"branches_covered": 1, "branches_total": 2}),
    _case("COV-005", "Coverage", "Coverage is retained when testcase oracle fails", "coverage", "INCONCLUSIVE", "ORACLE_VIOLATION", "50%", ("coverage-report", "oracle-evaluation"), "Coverage measurement and oracle verdict are independent.", "int f(int x){if(x)return 1;return 0;}", coverage={"covered": 1, "total": 2}, test_case={"target": "f", "arguments": {"x": 1}, "oracle": {"return_value": 7}}),
    # Fuzz campaign scope and stopping conditions.
    _case("FUZZ-001", "Fuzzing", "Seed reproduces known process crash", "fuzzing", "FAIL", "ABNORMAL_TERMINATION", "T-CRASH", ("campaign-report", "failure-input"), "Controlled process-result fixture; host OS crash handling is not under test.", "int main(void){return 0;}", strategy="known-crash"),
    _case("FUZZ-002", "Fuzzing", "Bounded campaign without failure is inconclusive", "fuzzing", "INCONCLUSIVE", "NO_FINDING_WITHIN_BUDGET", "T-NO-FINDING", ("campaign-report",), "No finding is not evidence of safety.", "int f(int x){return x+1;}", strategy="bounded-clean"),
    _case("FUZZ-003", "Fuzzing", "Per-input timeout is recorded as campaign observation", "fuzzing", "INCONCLUSIVE", "TIMEOUT", "T-TIMEOUT", ("campaign-report", "timeout-record"), "Bounded timeout is not a semantic verdict.", None, strategy="timeout"),
    _case("FUZZ-004", "Fuzzing", "Oracle violation is distinguished from crash", "fuzzing", "FAIL", "ORACLE_VIOLATION", "T-ORACLE", ("campaign-report", "oracle-evaluation"), "Oracle quality bounds this result.", "int f(int x){return x;}", strategy="oracle-seed"),
    _case("FUZZ-005", "Fuzzing", "Coverage-guided campaign records new coverage", "fuzzing", "INCONCLUSIVE", "COVERAGE_INCREASE", "T-COVERAGE", ("campaign-report", "coverage-delta"), "Requires gcov/LLVM backend and compiler support.", "int f(int x){if(x>0)return 1;return 0;}", strategy="coverage-guided"),
)
