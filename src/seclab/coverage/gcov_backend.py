"""GCC/gcov backend. gcov arc counters are not LLVM branch regions."""

from __future__ import annotations

import re
from pathlib import Path

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore, EvidenceType
from seclab.execution.evidence import store_command_evidence
from seclab.execution.process_runner import ProcessRunner, ProcessSpec
from seclab.source import Language

from .backend import BackendCollection
from .parser import ParsedCoverage, parse_gcov_function_summary, parse_gcov_text


class GcovBackend:
    name = "gcov"
    semantics = "GCC gcov control-flow arcs; branch totals follow gcov JSON and are not directly comparable to LLVM."

    def __init__(self, toolchain: Toolchain, runner: ProcessRunner, store: ArtifactStore, workspace: Path) -> None:
        self.toolchain, self.runner, self.store, self.workspace = toolchain, runner, store, workspace
        self.gcov = toolchain.get("gcov")
        self.tool_version = self.gcov.version

    def available(self, language: Language) -> bool:
        compiler = self.toolchain.get("gcc" if language is Language.C else "g++")
        return bool(compiler.installed and self.gcov.installed)

    def compiler_name(self, language: Language) -> str:
        return "gcc" if language is Language.C else "g++"

    def instrumentation_flags(self) -> tuple[str, ...]:
        return ("--coverage",)

    def process_environment(self, raw_directory: Path, case_id: str) -> dict[str, str]:
        raw_directory.mkdir(parents=True, exist_ok=True)
        # Each testcase has a fresh object directory, so gcda counters are isolated there.
        return {}

    def collect(self, binary: Path, source_paths: tuple[Path, ...], object_directory: Path,
                raw_directory: Path, testcase_id: str) -> BackendCollection:
        if not tuple(object_directory.glob("*.gcda")):
            return BackendCollection(None, (), "COVERAGE_DATA_MISSING", "No gcda counter file was written by this testcase")
        report_directory = raw_directory / "gcov-report"
        report_directory.mkdir(parents=True, exist_ok=True)
        evidences = []
        lines: dict[str, dict[int, int]] = {}
        branches: dict[str, bool] = {}
        functions: dict[str, int] = {}
        diagnostics: list[str] = []
        try:
            for index, source in enumerate(source_paths):
                source_report_dir = report_directory / f"source-{index:04d}"
                source_report_dir.mkdir()
                safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", source.stem).strip("._-") or "source"
                note_files = sorted(object_directory.glob(f"unit-*-{safe_stem}.gcno"))
                if not note_files:
                    return BackendCollection(None, tuple(item.id for item in evidences),
                        "COVERAGE_DATA_MISSING", f"No gcno notes found for source {source.name}")
                if len(note_files) != 1:
                    return BackendCollection(None, tuple(item.id for item in evidences),
                        "COVERAGE_PARSE_ERROR", f"Cannot uniquely map source {source.name} to gcov notes")
                command = self.runner.run(ProcessSpec(executable=self.gcov.path or "gcov",
                    args=("-f", "-b", "-c", "-o", str(_short_path(note_files[0])), str(_short_path(source))),
                    cwd=source_report_dir, timeout=30))
                evidences.extend(store_command_evidence(self.store, command, stage="coverage-tools",
                    prefix=f"gcov-{testcase_id}-{index}"))
                if command.timed_out or command.execution_error or command.exit_code != 0:
                    return BackendCollection(None, tuple(item.id for item in evidences), "COVERAGE_EXECUTION_FAILED",
                        command.execution_error or command.stderr or "gcov failed")
                report_files = sorted(source_report_dir.glob("*.gcov"))
                if not report_files:
                    return BackendCollection(None, tuple(item.id for item in evidences), "COVERAGE_DATA_MISSING",
                        "gcov completed but did not emit line coverage data")
                for path in report_files:
                    parsed = parse_gcov_text(path.read_bytes())
                    _merge(lines, parsed.lines)
                    branches.update(parsed.branches)
                    diagnostics.extend(parsed.diagnostics)
                    evidences.append(self.store.copy_file("coverage-raw", f"{testcase_id}-{index}-{path.name}", path,
                        evidence_type=EvidenceType.COVERAGE_REPORT, source="gcov"))
                function_summary = parse_gcov_function_summary(command.stdout, str(source))
                functions.update(function_summary.functions or {})
        except (OSError, ValueError) as exc:
            return BackendCollection(None, tuple(item.id for item in evidences), "COVERAGE_PARSE_ERROR", str(exc))
        _copy_profile_artifacts(self.store, object_directory, raw_directory, testcase_id, evidences)
        return BackendCollection(ParsedCoverage(lines, branches, tuple(diagnostics), functions), tuple(item.id for item in evidences))


def _merge(target: dict[str, dict[int, int]], incoming: dict[str, dict[int, int]]) -> None:
    for path, records in incoming.items():
        output = target.setdefault(path, {})
        for line, count in records.items():
            output[line] = output.get(line, 0) + count


def _short_path(path: Path) -> Path:
    if " " not in str(path) and len(str(path)) < 240:
        return path
    try:
        import ctypes
        from ctypes import wintypes
        function = ctypes.windll.kernel32.GetShortPathNameW
        function.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        function.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(str(path.parent), buffer, len(buffer))
        if length and length < len(buffer) and buffer.value:
            return Path(buffer.value) / path.name
    except (AttributeError, OSError):
        pass
    return path


def _copy_profile_artifacts(store, object_directory, raw_directory, testcase_id, evidences):
    copied = set()
    for root in (object_directory, raw_directory):
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".gcda", ".gcno"}:
                continue
            resolved = str(path.resolve())
            if resolved in copied:
                continue
            copied.add(resolved)
            evidences.append(store.copy_file("coverage-raw", f"{testcase_id}-{path.name}", path,
                evidence_type=EvidenceType.COVERAGE_REPORT, source="gcov-profile"))
