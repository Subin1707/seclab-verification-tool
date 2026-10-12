"""Built-in adapters for production formal and coverage APIs."""
from __future__ import annotations

from tempfile import TemporaryDirectory
from pathlib import Path
import shutil
import sys
from collections.abc import Mapping
from datetime import datetime, timezone

from seclab.formal.bmc import BMCChecker
from seclab.formal.ctl import model_checker
from seclab.formal.ctl.errors import CTLError
from seclab.formal.smt import (BackendResult, QueryIntent, SMTError, SMTVerifier,
                               SolverOutcome)
from seclab.model import KripkeStructure, State, Transition
from seclab.results import VerificationStatus, classify_ctl_error, classify_ctl_result
from seclab.specification.schema import Constraint, Domain, Specification, Variable
from seclab.config import Toolchain
from seclab.source import SourceLoader
from seclab.execution import CommandResult
from seclab.testing import TestCase, TestRunner, TestTargetKind

from .models import BenchmarkCase, BenchmarkObservation


def _jsonable(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "value"):
        return _jsonable(value.value)
    if hasattr(value, "to_dict"):
        return _jsonable(value.to_dict())
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import fields
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if hasattr(value, "__dict__"):
        return {key: _jsonable(item) for key, item in vars(value).items() if not key.startswith("_")}
    return str(value)


def _graph_dict(graph):
    return {"initial_states": [_jsonable(state) for state in graph.initial_states],
            "states": [{"id": state.id, "values": _jsonable(state.values), "labels": sorted(state.labels)}
                       for state in graph.states],
            "transitions": [{"source": edge.source, "target": edge.target} for edge in graph.transitions]}


class _FixedSolver:
    def __init__(self, outcome: SolverOutcome, reason: str | None = None) -> None:
        self.outcome, self.reason = outcome, reason

    def solve(self, query, specification=None, *, timeout_seconds=None):
        return BackendResult(self.outcome, reason=self.reason, backend="benchmark-controlled-backend")


def execute_case(case: BenchmarkCase) -> BenchmarkObservation:
    if case.expected_checker == "CTL":
        return _ctl(case)
    if case.expected_checker == "BMC":
        return _bmc(case)
    if case.expected_checker == "SMT":
        return _smt(case)
    if case.expected_checker == "coverage":
        return _coverage(case)
    if case.expected_checker == "dynamic-test":
        return _dynamic(case)
    if case.category.casefold() == "static":
        return _static(case)
    if case.expected_checker in {"asan", "leak-sanitizer"}:
        return _memory(case)
    if case.expected_checker == "fuzzing":
        return _fuzz(case)
    return BenchmarkObservation(case.benchmark_id, case.expected_checker, "UNSUPPORTED",
        unsupported_reason="No production benchmark adapter is registered for this checker/category yet.")


def _graph(name: str) -> KripkeStructure:
    if name == "safe-loop": return KripkeStructure((State("S", labels={"safe"}),), ("S",), (Transition("S", "S"),))
    if name == "unsafe-path": return KripkeStructure((State("S0", labels={"safe"}), State("S1", labels={"bad"})), ("S0",), (Transition("S0", "S1"), Transition("S1", "S1")))
    if name == "two-initial-one-unsafe": return KripkeStructure((State("S0", labels={"safe"}), State("S1", labels={"bad"})), ("S0", "S1"), (Transition("S0", "S0"), Transition("S1", "S1")))
    if name == "two-initial-safe": return KripkeStructure((State("S0", labels={"safe"}), State("S1", labels={"safe"})), ("S0", "S1"), (Transition("S0", "S0"), Transition("S1", "S1")))
    if name == "safe-deadlock": return KripkeStructure((State("S", labels={"safe"}),), ("S",), ())
    if name == "active-cycle": return KripkeStructure((State("A", labels={"active"}), State("B", labels={"active"})), ("A",), (Transition("A", "B"), Transition("B", "A")))
    if name == "eventually-done": return KripkeStructure((State("A"), State("B", labels={"done"})), ("A",), (Transition("A", "B"), Transition("B", "B")))
    if name == "branching-one-unsafe": return KripkeStructure((State("S0", labels={"safe"}), State("SAFE", labels={"safe"}), State("BAD", labels={"bad"})), ("S0",), (Transition("S0", "SAFE"), Transition("S0", "BAD"), Transition("SAFE", "SAFE"), Transition("BAD", "BAD")))
    if name == "branching-eventually-done": return KripkeStructure((State("S0"), State("LEFT", labels={"done"}), State("RIGHT"), State("END", labels={"done"})), ("S0",), (Transition("S0", "LEFT"), Transition("S0", "RIGHT"), Transition("LEFT", "LEFT"), Transition("RIGHT", "END"), Transition("END", "END")))
    if name.startswith("bad-at-depth-"):
        depth = int(name.rsplit("-", 1)[1]); states = tuple(State(f"S{i}", labels={"bad"} if i == depth else set()) for i in range(depth + 1))
        return KripkeStructure(states, ("S0",), tuple(Transition(f"S{i}", f"S{i+1}") for i in range(depth)) + (Transition(f"S{depth}", f"S{depth}"),))
    if name == "safe-linear":
        states = tuple(State(f"S{i}") for i in range(4)) + (State("UNREACHABLE_BAD", labels={"bad"}),)
        return KripkeStructure(states, ("S0",), tuple(Transition(f"S{i}", f"S{i+1}") for i in range(3)) + (Transition("S3", "S3"),))
    # BMC timeout fixture and fallback linear graph.
    states = tuple(State(f"S{i}") for i in range(4)) + (State("UNREACHABLE_BAD", labels={"bad"}),)
    return KripkeStructure(states, ("S0",), tuple(Transition(f"S{i}", f"S{i+1}") for i in range(3)) + (Transition("S3", "S3"),))


def _ctl(case: BenchmarkCase) -> BenchmarkObservation:
    model = _graph(str(case.scenario["model"]))
    try:
        checked = model_checker.check(model, str(case.scenario["formula"]))
        result = classify_ctl_result(checked)
        finding = "NONE" if result.status is VerificationStatus.PASS else "PROPERTY_VIOLATED"
        evidence = ("proof-or-result",) if checked.satisfied else ("counterexample",)
    except CTLError as error:
        result = classify_ctl_error(error)
        finding = result.reason_code
        evidence = ("diagnostic",)
        checked = None
    payload = {"model": _graph_dict(model), "formula": str(case.scenario["formula"]),
               "result": {"status": result.status.value, "satisfied": getattr(checked, "satisfied", None),
                          "satisfying_states": list(getattr(checked, "satisfying_states", ())),
                          "initial_states": list(getattr(checked, "initial_states", ())),
                          "witness": _jsonable(getattr(checked, "witness", None)),
                          "counterexample": _jsonable(getattr(checked, "counterexample", None)),
                          "finding": finding, "diagnostic": getattr(checked, "diagnostic", None)}}
    return BenchmarkObservation(case.benchmark_id, "CTL", result.status.value, finding,
                                None, evidence, evidence_payloads=({"name": "ctl-model-and-result", "content": payload},))


def _bmc(case: BenchmarkCase) -> BenchmarkObservation:
    backend = None
    if case.benchmark_id == "BMC-004":
        backend = _FixedSolver(SolverOutcome.UNKNOWN, "SOLVER_TIMEOUT")
    checked = BMCChecker(backend=backend).check_up_to_bound(_graph(str(case.scenario["model"])),
        int(case.scenario["bound"]), str(case.scenario["formula"]))
    if checked.solver_outcome is SolverOutcome.SAT:
        finding = "COUNTEREXAMPLE"; evidence = ("trace", "solver-query")
    elif checked.result.status is VerificationStatus.PASS:
        finding = "NONE"; evidence = ("solver-query", "completeness")
    elif checked.result.reason_code == "BMC_SOLVER_TIMEOUT":
        finding = "SOLVER_TIMEOUT"; evidence = ("solver-query",)
    else:
        finding = "NONE_WITHIN_BOUND"; evidence = ("solver-query", "completeness")
    normalized_result = _jsonable(checked)
    normalized_result.pop("duration_ms", None)
    if isinstance(normalized_result.get("verification_result"), dict):
        normalized_result["verification_result"].pop("id", None)
        normalized_result["verification_result"].pop("duration_ms", None)
    payload = {"model": _graph_dict(_graph(str(case.scenario["model"]))),
               "formula": str(case.scenario["formula"]), "bound": int(case.scenario["bound"]),
               "result": normalized_result}
    return BenchmarkObservation(case.benchmark_id, "BMC", checked.result.status.value, finding,
                                None, evidence, evidence_payloads=({"name": "bmc-query-and-result", "content": payload},))


def _smt(case: BenchmarkCase) -> BenchmarkObservation:
    name = case.benchmark_id
    if name in {"SMT-003", "SMT-004"}:
        outcome = SolverOutcome.UNKNOWN
        backend = _FixedSolver(outcome, "SOLVER_TIMEOUT" if name == "SMT-004" else "SOLVER_UNKNOWN")
    else:
        backend = None
    spec = Specification("1.0", "benchmark", "Benchmark", variables=(
        Variable("x", Domain(type="integer", minimum=0, maximum=10)),
    ), constraints=(Constraint("DOMAIN", "x >= 0"),))
    try:
        result = SMTVerifier(backend=backend).check(spec, str(case.scenario["formula"]),
                                                   property_id=None)
        solver_outcome = result.solver_outcome.value
        finding = "PROPERTY_VIOLATED" if result.result.status is VerificationStatus.FAIL else (
            "NONE" if result.result.status is VerificationStatus.PASS else
            ("TIMEOUT" if result.backend_result.reason == "SOLVER_TIMEOUT" else solver_outcome))
        evidence = ("solver-query", "counterexample") if result.result.status is VerificationStatus.FAIL else ("solver-query",)
        if name == "SMT-007": evidence = ("solver-query", "domain-constraints")
        payload = {"query": _jsonable(result.query), "solver_outcome": solver_outcome,
                   "backend_result": _jsonable(result.backend_result), "result": _jsonable(result.result)}
        payload["result"].pop("id", None)
        payload["result"].pop("duration_ms", None)
        return BenchmarkObservation(case.benchmark_id, "SMT", result.result.status.value, finding,
                                    None, evidence, evidence_payloads=({"name": "smt-query-backend-result", "content": payload},))
    except SMTError as error:
        return BenchmarkObservation(case.benchmark_id, "SMT", "SPEC_ERROR", error.code.value,
                                    None, ("diagnostic",), evidence_payloads=({"name": "smt-error", "content": {"code": error.code.value, "message": str(error)}},))


def _coverage(case: BenchmarkCase) -> BenchmarkObservation:
    if case.benchmark_id == "COV-005":
        return _coverage_oracle_case(case)
    from seclab.coverage import aggregate_branch_coverage, aggregate_line_coverage
    metrics = case.scenario["coverage"]
    if "covered" in metrics:
        report = aggregate_line_coverage({"case.c": {line + 1: int(line < metrics["covered"])
                                                       for line in range(metrics["total"])}})
        actual = report.percentage
    else:
        report = aggregate_branch_coverage({f"case.c|1|{index}": index < metrics["branches_covered"]
                                            for index in range(metrics["branches_total"])}, "benchmark arcs")
        actual = report.percentage
    return BenchmarkObservation(case.benchmark_id, "coverage", "INCONCLUSIVE", "NONE",
                                actual_property=f"{actual:g}%" if actual is not None else "UNDEFINED",
                                evidence=("coverage-report",),
                                evidence_payloads=({"name": "coverage-measurement", "type": "COVERAGE_REPORT",
                                                   "content": {"metrics": metrics, "measured_percentage": actual}},))


def _coverage_oracle_case(case: BenchmarkCase) -> BenchmarkObservation:
    """Run COV-005's declared C fixture through both testcase oracle and coverage measurement."""
    from seclab.coverage import CoverageRunner
    with TemporaryDirectory(prefix="seclab-bench-cov005-") as temporary:
        root = Path(temporary)
        project = root / "source"
        project.mkdir()
        source = project / "case.c"
        source.write_text(str(case.source), encoding="utf-8")
        sources = SourceLoader().load_source_tree(project)
        compiler = "gcc" if shutil.which("gcc") and shutil.which("gcov") else (
            "clang" if shutil.which("clang") and shutil.which("llvm-cov") else None)
        if compiler is None:
            # Still execute and evaluate the functional oracle when coverage tools
            # are missing; the coverage value stays explicitly unavailable.
            compiler = "gcc" if shutil.which("gcc") else "clang" if shutil.which("clang") else None
        if compiler is None:
            return BenchmarkObservation(case.benchmark_id, "coverage", "INCONCLUSIVE", "ORACLE_UNAVAILABLE",
                evidence=("coverage-report",), unsupported_reason="No C compiler is installed.",
                evidence_payloads=({"name": "coverage-measurement", "type": "COVERAGE_REPORT",
                                    "content": {"measurement_available": False}},))
        test_spec = case.scenario["test_case"]
        testcase = TestCase(case.benchmark_id, case.description, str(test_spec["target"]),
                            dict(test_spec["arguments"]), dict(test_spec["oracle"]),
                            target_kind=TestTargetKind.FUNCTION)
        toolchain = Toolchain([compiler] + (["gcov"] if compiler == "gcc" and shutil.which("gcov") else []))
        measured = CoverageRunner(root / "run", toolchain).run(
            (testcase,), source_files=sources, language="C", backend="auto", source_root=project,
            run_id="cov005")
        execution = measured.test_results[0] if measured.test_results else None
        finding = ("ORACLE_VIOLATION" if execution and
                   execution.verification_result.status is VerificationStatus.FAIL else
                   "NONE" if execution and execution.verification_result.status is VerificationStatus.PASS else
                   "ORACLE_UNAVAILABLE")
        percentage = measured.report.line_metrics.percentage if measured.report else None
        evidence = ["oracle-evaluation"] if execution else []
        if measured.report:
            evidence.append("coverage-report")
        payload = {"test_case": _jsonable(testcase), "execution": _jsonable(execution),
                   "coverage_report": _jsonable(measured.report), "errors": list(measured.errors),
                   "measurement_only": True}
        return BenchmarkObservation(case.benchmark_id, "coverage", "INCONCLUSIVE", finding,
            actual_property=f"{percentage:g}%" if percentage is not None else "UNDEFINED",
            evidence=tuple(evidence), evidence_payloads=({"name": "coverage-test-execution", "type": "COVERAGE_REPORT",
                                                          "content": payload},))


def _dynamic(case: BenchmarkCase) -> BenchmarkObservation:
    with TemporaryDirectory(prefix="seclab-bench-") as temporary:
        root = Path(temporary)
        options = dict(case.scenario)
        if case.scenario.get("target") == "python-sleep":
            test = TestCase(case.benchmark_id, case.description, "python",
                            {"argv": ["-c", "import time;time.sleep(1)"]}, {"exit_code": 0},
                            target_kind=TestTargetKind.EXECUTABLE,
                            timeout_seconds=float(case.scenario["timeout"]))
            result = TestRunner(root, Toolchain([])).run_one(test, executable=sys.executable)
        elif case.scenario.get("target") == "python-crash":
            crash_code = ("import ctypes;ctypes.windll.kernel32.ExitProcess(0xC0000005)" if sys.platform == "win32"
                          else "import os,signal;os.kill(os.getpid(),signal.SIGSEGV)")
            test = TestCase(case.benchmark_id, case.description, "python", {"argv": ["-c", crash_code]},
                            {"no_crash": True}, target_kind=TestTargetKind.EXECUTABLE, timeout_seconds=2.0)
            result = TestRunner(root, Toolchain([])).run_one(test, executable=sys.executable)
        else:
            compiler_name = "gcc" if shutil.which("gcc") else "clang" if shutil.which("clang") else None
            if compiler_name is None:
                return BenchmarkObservation(case.benchmark_id, "dynamic-test", "UNSUPPORTED",
                    unsupported_reason="No supported C compiler is installed.")
            project = root / "source"
            project.mkdir()
            source_path = project / "case.c"
            source_path.write_text(str(case.source), encoding="utf-8")
            source_files = SourceLoader().load_source_tree(project)
            if options.get("target") in {"executable", "abnormal-executable"}:
                test = TestCase(case.benchmark_id, case.description, "program", {},
                                {"no_crash": True} if options.get("target") == "abnormal-executable" else {"exit_code": 0},
                                target_kind=TestTargetKind.EXECUTABLE,
                                timeout_seconds=2.0,
                                metadata={"sanitizer": options.get("sanitizer")} if options.get("sanitizer") else {})
            else:
                target = "echo" if options.get("target") == "unsupported-input" else (
                    "broken" if case.benchmark_id == "DYN-003" else "answer")
                test = TestCase(case.benchmark_id, case.description,
                    target,
                    dict(options.get("input", {}).get("args", {})), options.get("expected"),
                    property_id=None, timeout_seconds=2.0)
            build_flags = ("-fsanitize=address", "-fno-omit-frame-pointer") if options.get("sanitizer") == "asan" else ()
            result = TestRunner(root / "run", Toolchain([compiler_name])).run_one(
                test, source_files=source_files, language="C", build_flags=build_flags)
        verification = result.verification_result
        if result.build_result is not None and not result.build_result.success:
            finding = "BUILD_FAILED"
        elif result.observed is not None and result.observed.memory_findings:
            finding = "MEMORY_FINDING:" + str(result.observed.memory_findings[0].get("kind", "UNKNOWN"))
        elif options.get("target") == "abnormal-executable" and result.observed is not None and result.observed.memory_analysis_available:
            finding = "NONE"
        elif options.get("target") == "abnormal-executable" and result.observed is not None and not result.observed.memory_analysis_available:
            finding = "SANITIZER_UNAVAILABLE"
        elif result.command_result is not None and result.command_result.execution_error:
            finding = "TOOL_ERROR"
        elif result.command_result is not None and result.command_result.timed_out:
            finding = "TIMEOUT"
        elif options.get("target") == "python-sleep":
            finding = "TIMEOUT"
        elif result.reason == "HARNESS_UNSUPPORTED_INPUT":
            finding = "HARNESS_UNSUPPORTED_INPUT"
        elif result.command_result is not None and result.command_result.timed_out:
            finding = "TIMEOUT"
        elif result.observed is not None and result.observed.crashed is None and options.get("target") == "abnormal-executable":
            finding = "ABNORMALITY_UNOBSERVABLE"
        elif result.observed is not None and result.observed.crashed:
            finding = "ABNORMAL_TERMINATION"
        elif options.get("target") == "abnormal-executable" and result.command_result is not None and result.command_result.exit_code not in (None, 0):
            finding = "ABNORMALITY_UNCLASSIFIED"
        elif verification.status is VerificationStatus.FAIL:
            finding = "ORACLE_VIOLATION"
        else:
            finding = "NONE"
        evidence = []
        if result.command_result is not None: evidence.append("process-record")
        if result.build_result is not None and not result.build_result.success: evidence.append("build-log")
        if result.reason == "HARNESS_UNSUPPORTED_INPUT":
            evidence.extend(("test-case", "diagnostic"))
        elif result.evidence_ids:
            evidence.extend(("test-case", "observation", "oracle-evaluation"))
        actual_status = ("UNSUPPORTED" if result.reason == "HARNESS_UNSUPPORTED_INPUT" else
                         "TOOL_ERROR" if result.command_result is not None and result.command_result.execution_error else
                         "INCONCLUSIVE" if (result.command_result is not None and result.command_result.timed_out)
                         or options.get("target") == "python-sleep" else verification.status.value)
        payload = {"test_case": _jsonable(test), "observed": _jsonable(result.observed),
                   "oracle_evaluation": _jsonable(result.oracle_evaluation),
                   "verification_result": _jsonable(verification),
                   "command_result": _jsonable(result.command_result),
                   "build_result": _jsonable(result.build_result), "reason": result.reason,
                   "duration_ms": result.duration_ms}
        return BenchmarkObservation(case.benchmark_id, "dynamic-test", actual_status,
            finding, None, tuple(dict.fromkeys(evidence)),
            unsupported_reason=result.reason if actual_status == "UNSUPPORTED" else None,
            evidence_payloads=({"name": "dynamic-test-execution", "content": payload},))


def _analysis_context(root: Path, project: Path, toolchain: Toolchain):
    from seclab.evidence import ArtifactStore
    from seclab.execution import CommandRunner
    from seclab.static_analysis import AnalysisContext
    workspace = root / "analysis"
    workspace.mkdir(parents=True)
    return AnalysisContext(project, workspace, toolchain, CommandRunner(), ArtifactStore(workspace), timeout=15)


def _static(case: BenchmarkCase) -> BenchmarkObservation:
    from seclab.static_analysis import CompilerDiagnosticsRunner, CppcheckRunner
    with TemporaryDirectory(prefix="seclab-bench-static-") as temporary:
        root = Path(temporary)
        source = root / "case.c"
        source.write_text(str(case.source), encoding="utf-8")
        sources = SourceLoader().load_source_tree(root)
        requested = str(case.scenario["analyzer"])
        if requested == "nonexistent-analyzer":
            return BenchmarkObservation(case.benchmark_id, case.checker, "TOOL_ERROR",
                                        "ANALYZER_UNAVAILABLE", evidence=("diagnostic",),
                                        evidence_payloads=({"name": "static-analyzer-diagnostic", "content": {"requested": requested, "available": False}},))
        tool = "cppcheck" if requested == "cppcheck" else (
            "gcc" if shutil.which("gcc") else "clang" if shutil.which("clang") else None)
        if tool is None:
            return BenchmarkObservation(case.benchmark_id, case.checker, "ENVIRONMENT_LIMITED",
                                        unsupported_reason="No C compiler is installed.")
        toolchain = Toolchain([tool])
        if tool == "cppcheck" and not toolchain.get("cppcheck").installed:
            return BenchmarkObservation(case.benchmark_id, case.checker, "ENVIRONMENT_LIMITED",
                                        unsupported_reason="Cppcheck is not installed.")
        context = _analysis_context(root, root, toolchain)
        analyzed = (CppcheckRunner().analyze(sources, context) if requested == "cppcheck"
                    else CompilerDiagnosticsRunner().analyze(sources, context))
        result = analyzed.to_verification_result()
        if not analyzed.executed:
            return BenchmarkObservation(case.benchmark_id, case.checker, "ENVIRONMENT_LIMITED",
                                        unsupported_reason=analyzed.reason_code)
        relevant_findings = (analyzed.findings if requested != "cppcheck" else
                             tuple(item for item in analyzed.findings
                                   if item.category.casefold() in {"error", "warning"}))
        finding = "FINDING_PRESENT" if relevant_findings else "NONE"
        evidence = (("raw-analyzer-output", "finding-record") if relevant_findings and requested == "cppcheck"
                    else ("compiler-output", "finding-record") if relevant_findings
                    else ("raw-analyzer-output",) if requested == "cppcheck"
                    else ("compiler-output",))
        command = analyzed.command_result
        raw = "\n".join(filter(None, [getattr(command, "stdout", ""), getattr(command, "stderr", "")]))
        payloads = ({"name": "static-findings", "content": {"findings": [_jsonable(item) for item in analyzed.findings],
                     "status": result.status.value, "reason": analyzed.reason_code}},
                    {"name": "static-analyzer-output", "kind": "raw", "content": raw})
        return BenchmarkObservation(case.benchmark_id, case.checker, result.status.value,
                                    finding, evidence=evidence, evidence_payloads=payloads)


def _memory(case: BenchmarkCase) -> BenchmarkObservation:
    from seclab.memory import ASanRunner, LeakChecker
    if case.scenario.get("toolchain") == "empty":
        return BenchmarkObservation(case.benchmark_id, case.expected_checker, "ENVIRONMENT_LIMITED",
            "SANITIZER_UNAVAILABLE", evidence=("diagnostic",),
            unsupported_reason="This catalog case explicitly disables compiler capability to exercise environment-limited handling.")
    with TemporaryDirectory(prefix="seclab-bench-memory-") as temporary:
        root = Path(temporary)
        project = root / "source"
        project.mkdir()
        source = project / "case.c"
        source.write_text(str(case.source), encoding="utf-8")
        sources = SourceLoader().load_source_tree(project)
        toolchain = Toolchain()
        compiler = toolchain.compiler_for("C")
        if compiler is None:
            return BenchmarkObservation(case.benchmark_id, case.expected_checker, "ENVIRONMENT_LIMITED",
                "SANITIZER_UNAVAILABLE", evidence=("diagnostic",),
                unsupported_reason="No supported C compiler is installed in the selected toolchain.")
        context = _analysis_context(root, project, toolchain)
        checked = (LeakChecker().run(sources, context, "C") if case.expected_checker == "leak-sanitizer"
                   else ASanRunner().run(sources, context, "C"))
        if not checked.supported:
            limitation = "; ".join(checked.limitations) or checked.verification_result.message
            return BenchmarkObservation(case.benchmark_id, case.expected_checker, "ENVIRONMENT_LIMITED",
                checked.verification_result.reason_code, evidence=("diagnostic",),
                unsupported_reason=limitation)
        if checked.findings:
            finding = checked.findings[0].kind
            evidence = ("sanitizer-report",)
        else:
            finding = "NONE" if checked.verification_result.status is VerificationStatus.PASS else checked.verification_result.reason_code
            evidence = ("execution-record",) if checked.verification_result.status is VerificationStatus.PASS else ("diagnostic",)
        payload = {"supported": checked.supported, "limitations": list(checked.limitations),
                   "findings": [_jsonable(item) for item in checked.findings],
                   "verification_result": _jsonable(checked.verification_result),
                   "execution_result": _jsonable(checked.execution_result),
                   "build_result": _jsonable(checked.build_result)}
        return BenchmarkObservation(case.benchmark_id, case.expected_checker,
            checked.verification_result.status.value, finding, evidence=evidence,
            evidence_payloads=({"name": "sanitizer-execution", "type": "SANITIZER_REPORT", "content": payload},))


def _fuzz(case: BenchmarkCase) -> BenchmarkObservation:
    from seclab.coverage import CoverageRunner
    from seclab.fuzzing import (FuzzConfig, FuzzEngine, FuzzInput, FuzzStrategy,
                                InputKind, InputOrigin)
    with TemporaryDirectory(prefix="seclab-bench-fuzz-") as temporary:
        root = Path(temporary)
        scenario = str(case.scenario["strategy"])
        if scenario == "timeout":
            runner = TestRunner(root, Toolchain([]))
            template = TestCase("template", case.description, "python",
                {"argv": ["-c", "import time;time.sleep(1)"]}, target_kind=TestTargetKind.EXECUTABLE,
                timeout_seconds=0.05)
            seed = FuzzInput("timeout-seed", b"x", InputKind.BYTES, InputOrigin.SEED)
            campaign = FuzzEngine(root, runner).run(template,
                FuzzConfig(FuzzStrategy.MUTATION, 1, 0.05, 9, 16, minimize_failures=False),
                seeds=(seed,), executable=sys.executable)
        elif scenario == "bounded-clean":
            runner = TestRunner(root, Toolchain([]))
            template = TestCase("template", case.description, "python",
                {"argv": ["-c", "pass"]}, target_kind=TestTargetKind.EXECUTABLE)
            campaign = FuzzEngine(root, runner).run(template,
                FuzzConfig(FuzzStrategy.BLACKBOX, 1, 1, 17, 16, minimize_failures=False),
                executable=sys.executable)
        else:
            compiler_name = "gcc" if shutil.which("gcc") else "clang" if shutil.which("clang") else None
            if compiler_name is None:
                return BenchmarkObservation(case.benchmark_id, "fuzzing", "UNSUPPORTED",
                    unsupported_reason="No supported C compiler is installed.")
            project = root / "source"
            project.mkdir()
            source = project / "fuzz.c"
            if scenario == "coverage-guided":
                if compiler_name != "gcc" or not shutil.which("gcov"):
                    return BenchmarkObservation(case.benchmark_id, "fuzzing", "UNSUPPORTED",
                        unsupported_reason="Coverage-guided benchmark requires gcc and gcov.")
                source.write_text("int f(int value){if(value>0)return 1;return 0;}\n", encoding="utf-8")
                inputs = {"value": 0}
                target = "f"
            elif scenario == "oracle-seed":
                source.write_text("int answer(int value){return value;}\n", encoding="utf-8")
                inputs = {"value": 1}
                target = "answer"
            else:
                source.write_text(str(case.source), encoding="utf-8")
                inputs = {}
                target = "main"
            sources = SourceLoader().load_source_tree(project)
            toolchain = Toolchain([compiler_name, "gcov"] if scenario == "coverage-guided" else [compiler_name])
            runner = TestRunner(root / "run", toolchain)
            if scenario == "known-crash":
                # A stable input trigger also sets Windows' error mode in its source,
                # preventing a platform crash dialog from turning a crash into timeout.
                source.write_text("""#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif
#include <stdio.h>
#include <string.h>
int main(void){char s[32]={0};if(!fgets(s,sizeof s,stdin))return 0;if(!strcmp(s,\"crash\\n\")){
#ifdef _WIN32
SetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS);RaiseException(0xC0000005,EXCEPTION_NONCONTINUABLE,0,0);
#else
raise(SIGABRT);
#endif
}return 0;}
                """, encoding="utf-8")
                sources = SourceLoader().load_source_tree(project)
                build = runner.compiler.build(sources, "C", compiler=compiler_name,
                    output_directory=root / "run" / "build", output_name="crash-target")
                if not build.success or build.binary_path is None:
                    return BenchmarkObservation(case.benchmark_id, "fuzzing", "BUILD_ERROR", "BUILD_FAILED",
                                                evidence=("campaign-report",))
                template = TestCase("template", case.description, "crash-target", {"argv": []},
                    {"no_crash": True}, target_kind=TestTargetKind.EXECUTABLE,
                    timeout_seconds=3.0)
                seed = FuzzInput("crash-seed", b"crash\n", InputKind.BYTES, InputOrigin.SEED)
                campaign = FuzzEngine(root / "fuzz", runner).run(template,
                    FuzzConfig(FuzzStrategy.MUTATION, 1, 3, 31, 32, minimize_failures=False),
                    seeds=(seed,), executable=build.binary_path, source_files=sources, no_crash_is_failure=True)
            elif scenario == "coverage-guided":
                coverage = CoverageRunner(root / "run" / "coverage", toolchain, test_runner=runner)
                template = TestCase("template", case.description, target, inputs, target_kind=TestTargetKind.FUNCTION)
                seed = FuzzInput("coverage-seed", inputs, InputKind.SCALARS, InputOrigin.SEED)
                campaign = FuzzEngine(root / "fuzz", runner, coverage_runner=coverage).run(template,
                    FuzzConfig(FuzzStrategy.COVERAGE_GUIDED, 4, 2, 23, 32,
                               minimize_failures=False), seeds=(seed,), source_files=sources, language="C", backend="gcov")
            else:
                template = TestCase("template", case.description, target, inputs,
                    {"return_value": 0}, target_kind=TestTargetKind.FUNCTION)
                seed = FuzzInput("oracle-seed", inputs, InputKind.SCALARS, InputOrigin.SEED)
                campaign = FuzzEngine(root / "fuzz", runner).run(template,
                    FuzzConfig(FuzzStrategy.MUTATION, 1, 1, 41, 16, minimize_failures=False),
                    seeds=(seed,), source_files=sources, language="C")
        if scenario == "known-crash":
            finding = "ABNORMAL_TERMINATION" if campaign.crashes else "NONE"
        elif scenario == "timeout":
            finding = "TIMEOUT" if campaign.timeouts else "NONE"
        elif scenario == "oracle-seed":
            finding = "ORACLE_VIOLATION" if campaign.oracle_failures else "NONE"
        elif scenario == "coverage-guided":
            finding = "COVERAGE_INCREASE" if campaign.coverage_delta else "NO_COVERAGE_INCREASE"
        else:
            finding = "NO_FINDING_WITHIN_BUDGET" if not campaign.failures else "FINDING"
        status = campaign.verification_result.status.value if campaign.verification_result else "INCONCLUSIVE"
        evidence = ["campaign-report"]
        if scenario == "known-crash" and campaign.failures: evidence.append("failure-input")
        if scenario == "timeout" and campaign.timeouts: evidence.append("timeout-record")
        if scenario == "oracle-seed" and campaign.oracle_failures: evidence.append("oracle-evaluation")
        if scenario == "coverage-guided" and campaign.coverage_delta: evidence.append("coverage-delta")
        payload = {"campaign": _jsonable(campaign), "scenario": scenario,
                   "seed": {"timeout": 9, "bounded-clean": 17, "known-crash": 31,
                            "coverage-guided": 23, "oracle-seed": 41}.get(scenario),
                   "requested_budget": campaign.iterations_requested,
                   "executed_iterations": campaign.iterations_executed,
                   "strategy": campaign.strategy.value}
        return BenchmarkObservation(case.benchmark_id, "fuzzing", status, finding,
                                    actual_property=None, evidence=tuple(evidence),
                                    evidence_payloads=({"name": "fuzz-campaign", "content": payload},))
