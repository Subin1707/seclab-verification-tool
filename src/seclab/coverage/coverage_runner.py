"""Coverage orchestration over the existing dynamic TestRunner."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Iterable

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore, EvidenceType
from seclab.execution.process_runner import ProcessRunner
from seclab.results.classifier import ClassificationInput, RawOutcome, ResultClassifier
from seclab.results.result import VerificationResult
from seclab.source import Language, SourceFile
from seclab.testing import TestCase, TestExecutionResult, TestRunner

from .backend import CoverageBackend
from .coverage_report import (CoverageDelta, CoverageReport, CoverageSnapshot,
                              aggregate_branch_coverage, aggregate_function_coverage, aggregate_line_coverage)
from .gcov_backend import GcovBackend
from .llvm_backend import LlvmCovBackend


class CoverageRunResult:
    """Measurement report stays separate from VerificationResult verdicts."""
    def __init__(self, report: CoverageReport | None, test_results: tuple[TestExecutionResult, ...],
                 evidence_ids: tuple[str, ...], verification_result: VerificationResult | None = None,
                 errors: tuple[str, ...] = ()) -> None:
        self.report, self.test_results, self.evidence_ids = report, test_results, evidence_ids
        self.verification_result, self.errors = verification_result, errors


class CoverageRunner:
    def __init__(self, workspace_root: str | Path, toolchain: Toolchain, *,
                 test_runner: TestRunner | None = None, process_runner: ProcessRunner | None = None,
                 artifact_store: ArtifactStore | None = None, classifier: ResultClassifier | None = None) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.coverage_root = self.workspace_root / "coverage"
        self.coverage_root.mkdir(parents=True, exist_ok=True)
        self.toolchain = toolchain
        self.artifact_store = artifact_store or ArtifactStore(self.workspace_root)
        self.process_runner = process_runner or ProcessRunner()
        self.test_runner = test_runner or TestRunner(self.workspace_root, toolchain, artifact_store=self.artifact_store,
                                                     process_runner=self.process_runner)
        self.classifier = classifier or ResultClassifier()

    def run(self, cases: Iterable[TestCase], *, source_files: Iterable[SourceFile | str | Path],
            language: Language | str | None = None, backend: str = "auto", source_root: str | Path | None = None,
            run_id: str | None = None, persist_process_output: bool = True) -> CoverageRunResult:
        suite = tuple(cases)
        sources = tuple(source_files)
        try:
            normalized_sources = _unique_sources(sources)
        except OSError as exc:
            return self._error_result("COVERAGE_EXECUTION_FAILED", f"Cannot read source set: {exc}", (), ())
        source_paths = tuple(path for _, path in normalized_sources)
        if not suite:
            return self._error_result("COVERAGE_DATA_MISSING", "Coverage suite has no test cases.", (), ())
        lang = _select_language(source_paths, language)
        if lang is None:
            return self._error_result("COVERAGE_UNSUPPORTED_BACKEND", "Coverage requires one unambiguous C or C++ language suite.", (), ())
        extensions = {path.suffix.lower() for path in source_paths if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}}
        expected_extensions = {".c"} if lang is Language.C else {".cc", ".cpp", ".cxx"}
        if not extensions or not extensions <= expected_extensions:
            return self._error_result("COVERAGE_UNSUPPORTED_BACKEND", "Source files mix languages or contain no translation unit.", (), ())
        run_id = _safe_run_id(run_id or uuid.uuid4().hex)
        run_root = self.coverage_root / run_id
        build_root, raw_root, report_root = run_root / "build", run_root / "raw", run_root / "reports"
        for path in (build_root, raw_root, report_root):
            path.mkdir(parents=True, exist_ok=False)
        chosen = self._select_backend(backend, lang)
        if isinstance(chosen, CoverageRunResult):
            return chosen
        source_index, source_error = _hash_sources(sources)
        if source_error:
            return self._error_result("COVERAGE_EXECUTION_FAILED", source_error, (), ())
        labels = _source_labels(normalized_sources, Path(source_root).resolve() if source_root else None)
        translation_units = tuple(path for path in source_paths if path.suffix.lower() in
                                  ({".c"} if lang is Language.C else {".cc", ".cpp", ".cxx"}))
        config_evidence = self.artifact_store.write_json("coverage-config", f"{run_id}-config.json", {
            "backend": chosen.name, "language": lang.value, "instrumentation_flags": list(chosen.instrumentation_flags()),
            "source_files": list(labels), "test_case_ids": [case.id for case in suite],
            "source_hashes_before": source_index, "workspace": str(run_root),
            "profile_reset": "fresh isolated build/profile path per testcase",
            "runtime_profile": "LLVM_PROFILE_FILE per testcase" if chosen.name == "llvm" else "gcda beside isolated gcno object files",
        }, evidence_type=EvidenceType.ENVIRONMENT, source="coverage-runner")
        evidence = [config_evidence]
        test_results: list[TestExecutionResult] = []
        line_hits: dict[str, dict[int, int]] = {}
        branch_hits: dict[str, bool] = {}
        function_counts: dict[str, int] = {}
        errors: list[str] = []
        collection_errors: list[str] = []
        generated_harnesses: set[str] = set()
        complete = True
        any_measurement = False
        source_map = {_canonical(path): labels[index] for index, (_, path) in enumerate(normalized_sources)}

        for index, case in enumerate(suite):
            token = f"{run_id}-case-{index:04d}-{hashlib.sha256(case.id.encode()).hexdigest()[:10]}"
            case_raw = raw_root / token
            case_raw.mkdir(parents=True)
            harness_root = self.workspace_root / "harness"
            harnesses_before = set(harness_root.glob("harness-*")) if harness_root.exists() else set()
            result = self.test_runner.run_many((case,), source_files=sources, language=lang,
                build_flags=chosen.instrumentation_flags(), process_env=chosen.process_environment(case_raw, token),
                compiler_name=chosen.compiler_name(lang), separate_compilation=True, isolated_build_output=True,
                build_directory=build_root / token, persist_process_output=persist_process_output).executions[0]
            test_results.append(result)
            evidence.extend(_new_evidence_from_result(result, self.artifact_store))
            harnesses_after = set(harness_root.glob("harness-*")) if harness_root.exists() else set()
            generated_harnesses.update(path.relative_to(self.workspace_root).as_posix()
                                       for path in harnesses_after - harnesses_before)
            if case.target_kind.value == "FUNCTION":
                digest = hashlib.sha256(f"{case.id}\0{case.target}".encode()).hexdigest()[:16]
                extension = ".cpp" if lang is Language.CPP else ".c"
                expected_harness = harness_root / f"harness-{digest}{extension}"
                if expected_harness.is_file():
                    generated_harnesses.add(expected_harness.relative_to(self.workspace_root).as_posix())
            if result.command_result is None or not result.executed:
                complete = False
                errors.append(f"{case.id}: testcase did not execute ({result.reason or result.verification_result.reason_code})")
                continue
            if result.command_result.timed_out:
                complete = False
                errors.append(f"{case.id}: execution timed out; any collected data is partial")
            if result.reason == "PROCESS_CRASH_UNASSERTED":
                complete = False
                errors.append(f"{case.id}: process crash; collected data is partial")
            if result.command_result.execution_error:
                complete = False
                errors.append(f"{case.id}: execution error")
            binary = result.build_result.binary_path if result.build_result else None
            if binary is None:
                complete = False
                errors.append(f"{case.id}: instrumented build output is unavailable")
                continue
            object_directory = binary.parent
            collection = chosen.collect(binary, translation_units, object_directory, case_raw, token)
            evidence.extend(_resolve_evidence_ids(self.artifact_store, collection.evidence_ids))
            if collection.error_code:
                complete = False
                collection_errors.append(collection.error_code)
                errors.append(f"{case.id}: {collection.error_code}: {collection.message or ''}".strip())
                continue
            if collection.parsed is None:
                complete = False
                continue
            any_measurement = True
            for path, records in collection.parsed.lines.items():
                label = source_map.get(_canonical(Path(path)))
                if label is None:
                    continue
                output = line_hits.setdefault(label, {})
                for line, count in records.items():
                    output[line] = output.get(line, 0) + count
            for entity, covered in collection.parsed.branches.items():
                raw_path, separator, suffix = entity.partition("|")
                label = source_map.get(_canonical(Path(raw_path)))
                if label is not None:
                    key = f"{label}|{suffix}" if separator else label
                    branch_hits[key] = branch_hits.get(key, False) or covered
            for entity, count in (collection.parsed.functions or {}).items():
                raw_path, separator, name = entity.partition("|")
                label = source_map.get(_canonical(Path(raw_path)))
                if label is not None:
                    key = f"{label}|{name}" if separator else f"{label}|{entity}"
                    function_counts[key] = function_counts.get(key, 0) + count
            if collection.parsed.diagnostics:
                errors.extend(f"{case.id}: {item}" for item in collection.parsed.diagnostics)
                complete = False

        after_hashes, after_error = _hash_sources(sources)
        integrity = {"before": source_index, "after": after_hashes, "unchanged": source_index == after_hashes and not after_error,
                     "after_error": after_error}
        integrity_ref = self.artifact_store.write_json("coverage-integrity", f"{run_id}-source-integrity.json", integrity,
            evidence_type=EvidenceType.ENVIRONMENT, source="coverage-runner")
        evidence.append(integrity_ref)
        if not integrity["unchanged"]:
            complete = False
            errors.append("SUT source hashes changed during coverage run")
        if not any_measurement:
            has_build_failure = any(item.build_result is not None and not item.build_result.success for item in test_results)
            code = ("COVERAGE_BUILD_FAILED" if has_build_failure else collection_errors[0]
                    if collection_errors else "COVERAGE_DATA_MISSING")
            message = "; ".join(errors) or "No backend coverage records were collected."
            return self._error_result(code, message, tuple(test_results), tuple(item.id for item in evidence))

        line_metrics = aggregate_line_coverage(line_hits)
        branch_metrics = aggregate_branch_coverage(branch_hits, chosen.semantics)
        function_metrics = aggregate_function_coverage(function_counts) if function_counts else None
        limitations = list(errors)
        if function_metrics is None:
            limitations.append("The selected coverage backend did not emit function coverage records.")
        partial = not complete or len(test_results) < len(suite) or any(not item.executed for item in test_results)
        report = CoverageReport(chosen.name, tuple(sorted(set(labels))), line_metrics, branch_metrics,
            sum(item.executed for item in test_results), tuple(case.id for case in suite), complete and not partial,
            partial, chosen.tool_version, tuple(limitations), tuple(item.id for item in evidence),
            tuple(sorted(generated_harnesses)), function_metrics)
        report_ref = self.artifact_store.write_json("coverage-reports", f"{run_id}-coverage-report.json", report.to_dict(),
            evidence_type=EvidenceType.COVERAGE_REPORT, source=chosen.name,
            metadata={"measurement_only": True, "complete": report.complete, "partial": report.partial})
        evidence.append(report_ref)
        report_path = self.artifact_store.workspace_root / report_ref.path
        report_integrity = self.artifact_store.write_json("coverage-integrity", f"{run_id}-report-integrity.json", {
            "artifact_id": report_ref.id, "path": report_ref.path,
            "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "measurement_sha256": report.measurement_sha256, "measurement_only": True,
        }, evidence_type=EvidenceType.COVERAGE_REPORT, source="coverage-runner")
        evidence.append(report_integrity)
        # Include the normalized report artifact reference in the returned measurement envelope.
        report = CoverageReport(report.backend, report.source_files, report.line_metrics, report.branch_metrics,
            report.tests_executed, report.test_case_ids, report.complete, report.partial, report.tool_version,
            report.limitations, tuple(item.id for item in evidence), report.generated_harness_files,
            report.function_metrics, report.measurement_sha256)
        return CoverageRunResult(report, tuple(test_results), tuple(item.id for item in evidence))

    def snapshot(self, report: CoverageReport) -> CoverageSnapshot:
        lines = frozenset((path, line) for path, records in report.line_metrics.counts.items()
                          for line, count in records.items() if count > 0)
        branches = frozenset(entity for entity, hit in report.branch_metrics.hits.items() if hit)
        return CoverageSnapshot(lines, branches)

    def delta(self, before: CoverageReport, after: CoverageReport) -> CoverageDelta:
        return CoverageDelta.between(self.snapshot(before), self.snapshot(after))

    def _select_backend(self, requested: str, language: Language) -> CoverageBackend | CoverageRunResult:
        gcov = GcovBackend(self.toolchain, self.process_runner, self.artifact_store, self.workspace_root)
        llvm = LlvmCovBackend(self.toolchain, self.process_runner, self.artifact_store, self.workspace_root)
        if requested not in {"auto", "gcov", "llvm"}:
            return self._error_result("COVERAGE_UNSUPPORTED_BACKEND", f"Unknown backend {requested!r}.", (), ())
        if requested == "gcov":
            selected = gcov if gcov.available(language) else None
        elif requested == "llvm":
            selected = llvm if llvm.available(language) else None
        else:
            compiler = self.toolchain.compiler_for(language.value)
            if compiler and compiler.name in {"gcc", "g++"} and gcov.available(language):
                selected = gcov
            elif compiler and compiler.name in {"clang", "clang++"} and llvm.available(language):
                selected = llvm
            elif gcov.available(language):
                selected = gcov
            elif llvm.available(language):
                selected = llvm
            else:
                selected = None
        if selected is None:
            return self._error_result("COVERAGE_TOOL_NOT_FOUND",
                f"Requested coverage backend {requested!r} is unavailable for {language.value}; no fallback was applied.", (), ())
        return selected

    def _error_result(self, code: str, message: str, tests: tuple[TestExecutionResult, ...],
                      evidence_ids: tuple[str, ...]) -> CoverageRunResult:
        diagnostic = self.artifact_store.write_json("coverage-errors", f"{uuid.uuid4().hex}-measurement-error.json", {
            "code": code, "message": message, "measurement_only": True,
            "test_case_ids": [item.test_case_id for item in tests],
        }, evidence_type=EvidenceType.LOG, source="coverage-runner",
           metadata={"reason_code": code, "measurement_only": True})
        evidence_ids = tuple(dict.fromkeys((*evidence_ids, diagnostic.id)))
        outcome = (RawOutcome.UNKNOWN if code == "COVERAGE_DATA_MISSING" else
                   RawOutcome.BUILD_FAILED if code == "COVERAGE_BUILD_FAILED" else RawOutcome.TOOL_FAILED)
        result = self.classifier.classify(ClassificationInput(outcome, "COVERAGE", "COVERAGE_MEASUREMENT",
            reason_code=code, message=message, scope="Coverage infrastructure/measurement only; no SUT safety verdict." ,
            evidence_ids=evidence_ids,
            metadata={"measurement_only": True,
                      "evidence": [{"id": diagnostic.id, "path": diagnostic.path, "sha256": diagnostic.hash}]}))
        return CoverageRunResult(None, tests, evidence_ids, result, (message,))


def _unique_sources(sources):
    items = {}
    for item in sources:
        path = Path(item.path if isinstance(item, SourceFile) else item).resolve(strict=True)
        items[_canonical(path)] = (item.relative_path if isinstance(item, SourceFile) else None, path)
    return tuple(items[key] for key in sorted(items))


def _select_language(paths, language):
    if language is not None:
        try:
            return Language(language)
        except ValueError:
            return None
    extensions = {path.suffix.lower() for path in paths if path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}}
    if extensions and extensions <= {".c"}:
        return Language.C
    if extensions and extensions <= {".cc", ".cpp", ".cxx"}:
        return Language.CPP
    return None


def _source_labels(normalized_sources, root):
    paths = [path for _, path in normalized_sources]
    if root is None:
        try:
            root = Path(os.path.commonpath([str(path.parent) for path in paths])).resolve()
        except ValueError:
            root = paths[0].parent
    labels = []
    for relative, path in normalized_sources:
        label = Path(relative).as_posix() if relative else path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
        labels.append(_normalize_label(label))
    return tuple(labels)


def _normalize_label(value):
    value = value.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def _canonical(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))


def _hash_sources(sources):
    result = {}
    for item in sources:
        path = Path(item.path if isinstance(item, SourceFile) else item)
        try:
            result[item.relative_path if isinstance(item, SourceFile) else path.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            return result, str(exc)
    return result, None


def _safe_run_id(value):
    if not value or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value):
        raise ValueError("run_id must be a safe workspace path component")
    if value in {".", ".."}:
        raise ValueError("invalid run_id")
    return value


def _resolve_evidence_ids(store, evidence_ids):
    # Backend evidence has already been persisted; IDs remain stable references but the store API
    # intentionally does not expose a mutable evidence registry.
    return tuple(_EvidenceRef(item) for item in evidence_ids)


class _EvidenceRef:
    def __init__(self, evidence_id):
        self.id = evidence_id


def _new_evidence_from_result(result, store):
    # TestRunner stores these artifacts itself and returns their IDs in its shared result.
    # This adapter keeps suite evidence references without manufacturing another evidence store.
    return tuple(_EvidenceRef(item) for item in result.evidence_ids)
