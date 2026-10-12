"""Coverage backend protocol and backend-neutral collection payload."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from seclab.source import Language

from .parser import ParsedCoverage


@dataclass(frozen=True, slots=True)
class BackendCollection:
    parsed: ParsedCoverage | None
    evidence_ids: tuple[str, ...] = ()
    error_code: str | None = None
    message: str | None = None


class CoverageBackend(Protocol):
    name: str
    tool_version: str | None
    semantics: str

    def available(self, language: Language) -> bool: ...
    def compiler_name(self, language: Language) -> str: ...
    def instrumentation_flags(self) -> tuple[str, ...]: ...
    def process_environment(self, raw_directory: Path, case_id: str) -> dict[str, str]: ...
    def collect(self, binary: Path, source_paths: tuple[Path, ...], object_directory: Path,
                raw_directory: Path, testcase_id: str) -> BackendCollection: ...
