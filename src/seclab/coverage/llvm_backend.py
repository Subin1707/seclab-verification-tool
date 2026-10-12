"""Clang source-based coverage backend using llvm-profdata and llvm-cov export."""

from __future__ import annotations

from pathlib import Path

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore, EvidenceType
from seclab.execution.evidence import store_command_evidence
from seclab.execution.process_runner import ProcessRunner, ProcessSpec
from seclab.source import Language

from .backend import BackendCollection
from .parser import parse_llvm_export


class LlvmCovBackend:
    name = "llvm"
    semantics = "LLVM source regions and true/false branch outcomes from llvm-cov export; not equivalent to gcov arcs."

    def __init__(self, toolchain: Toolchain, runner: ProcessRunner, store: ArtifactStore, workspace: Path) -> None:
        self.toolchain, self.runner, self.store, self.workspace = toolchain, runner, store, workspace
        self.llvm_cov, self.profdata = toolchain.get("llvm-cov"), toolchain.get("llvm-profdata")
        self.tool_version = self.llvm_cov.version

    def available(self, language: Language) -> bool:
        name = "clang" if language is Language.C else "clang++"
        return all((self.toolchain.get(name).installed, self.llvm_cov.installed, self.profdata.installed))

    def compiler_name(self, language: Language) -> str:
        return "clang" if language is Language.C else "clang++"

    def instrumentation_flags(self) -> tuple[str, ...]:
        return ("-fprofile-instr-generate", "-fcoverage-mapping")

    def process_environment(self, raw_directory: Path, case_id: str) -> dict[str, str]:
        raw_directory.mkdir(parents=True, exist_ok=True)
        return {"LLVM_PROFILE_FILE": str(_short_path(raw_directory / f"{case_id}.profraw").resolve())}

    def collect(self, binary: Path, source_paths: tuple[Path, ...], object_directory: Path,
                raw_directory: Path, testcase_id: str) -> BackendCollection:
        raw_profile = _short_path(raw_directory / f"{testcase_id}.profraw")
        if not raw_profile.is_file():
            return BackendCollection(None, (), "COVERAGE_DATA_MISSING", "LLVM runtime did not create a .profraw file")
        merged = _short_path(raw_directory / f"{testcase_id}.profdata")
        merge = self.runner.run(ProcessSpec(executable=self.profdata.path or "llvm-profdata",
            args=("merge", "-sparse", str(raw_profile), "-o", str(merged)), cwd=raw_directory, timeout=30))
        evidence = list(store_command_evidence(self.store, merge, stage="coverage-tools", prefix=f"profdata-{testcase_id}"))
        if not merge.succeeded or not merged.is_file():
            return BackendCollection(None, tuple(item.id for item in evidence), "COVERAGE_EXECUTION_FAILED",
                                     merge.execution_error or merge.stderr or "llvm-profdata merge failed")
        export = self.runner.run(ProcessSpec(executable=self.llvm_cov.path or "llvm-cov",
            args=("export", str(binary), f"-instr-profile={merged}"), cwd=raw_directory, timeout=30))
        evidence.extend(store_command_evidence(self.store, export, stage="coverage-tools", prefix=f"llvm-cov-{testcase_id}"))
        if not export.succeeded:
            return BackendCollection(None, tuple(item.id for item in evidence), "COVERAGE_EXECUTION_FAILED",
                                     export.execution_error or export.stderr or "llvm-cov export failed")
        try:
            parsed = parse_llvm_export(export.stdout)
        except Exception as exc:
            return BackendCollection(None, tuple(item.id for item in evidence), "COVERAGE_PARSE_ERROR", str(exc))
        evidence.append(self.store.write_text("coverage-raw", f"{testcase_id}-llvm-export.json", export.stdout,
            evidence_type=EvidenceType.COVERAGE_REPORT, source="llvm-cov"))
        for path in (raw_profile, merged):
            if path.is_file():
                evidence.append(self.store.copy_file("coverage-raw", f"{testcase_id}-{path.name}", path,
                    evidence_type=EvidenceType.COVERAGE_REPORT, source="llvm-profile"))
        return BackendCollection(parsed, tuple(item.id for item in evidence))


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
