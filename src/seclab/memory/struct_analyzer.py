"""Explicit limitation for struct layout until a compiler-backed probe API exists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from seclab.source import SourceFile


@dataclass(frozen=True, slots=True)
class StructAnalysisResult:
    supported: bool
    layouts: tuple[dict[str, object], ...]
    limitations: tuple[str, ...]


class StructAnalyzer:
    def analyze(self, source_collection: Sequence[SourceFile]) -> StructAnalysisResult:
        return StructAnalysisResult(
            False, (),
            ("Struct layout is not inferred by regex. A trustworthy implementation needs compiler-backed type selection and a probe build/run contract.",),
        )
