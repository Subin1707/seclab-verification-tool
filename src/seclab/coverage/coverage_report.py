"""Normalized, measurement-only coverage report models."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Mapping


def _percentage(covered: int, total: int) -> float | None:
    return covered / total * 100.0 if total else None


@dataclass(frozen=True, slots=True)
class FileLineCoverage:
    file: str
    covered_lines: int
    total_lines: int
    counts: Mapping[int, int] = field(default_factory=dict)

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_lines, self.total_lines)

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "covered_lines": self.covered_lines, "total_lines": self.total_lines,
                "percentage": self.percentage, "execution_counts": {str(k): v for k, v in sorted(self.counts.items())}}


@dataclass(frozen=True, slots=True)
class LineCoverage:
    covered_lines: int
    total_lines: int
    files: tuple[FileLineCoverage, ...] = ()
    counts: Mapping[str, Mapping[int, int]] = field(default_factory=dict)

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_lines, self.total_lines)

    def to_dict(self) -> dict[str, Any]:
        return {"covered_lines": self.covered_lines, "total_lines": self.total_lines,
                "percentage": self.percentage, "files": [item.to_dict() for item in sorted(self.files, key=lambda x: x.file)]}


@dataclass(frozen=True, slots=True)
class FileBranchCoverage:
    file: str
    covered_branches: int
    total_branches: int

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_branches, self.total_branches)

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "covered_branches": self.covered_branches,
                "total_branches": self.total_branches, "percentage": self.percentage}


@dataclass(frozen=True, slots=True)
class BranchCoverage:
    covered_branches: int
    total_branches: int
    files: tuple[FileBranchCoverage, ...] = ()
    hits: Mapping[str, bool] = field(default_factory=dict)
    semantics: str = "Backend-defined branch/arc semantics; metrics are not directly comparable across backends."

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_branches, self.total_branches)

    def to_dict(self) -> dict[str, Any]:
        return {"covered_branches": self.covered_branches, "total_branches": self.total_branches,
                "percentage": self.percentage, "files": [item.to_dict() for item in sorted(self.files, key=lambda x: x.file)],
                "semantics": self.semantics, "hits": dict(sorted(self.hits.items()))}


@dataclass(frozen=True, slots=True)
class FileFunctionCoverage:
    file: str
    covered_functions: int
    total_functions: int
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_functions, self.total_functions)

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "covered_functions": self.covered_functions,
                "total_functions": self.total_functions, "percentage": self.percentage,
                "execution_counts": dict(sorted(self.counts.items()))}


@dataclass(frozen=True, slots=True)
class FunctionCoverage:
    covered_functions: int
    total_functions: int
    files: tuple[FileFunctionCoverage, ...] = ()
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def percentage(self) -> float | None:
        return _percentage(self.covered_functions, self.total_functions)

    def to_dict(self) -> dict[str, Any]:
        return {"covered_functions": self.covered_functions, "total_functions": self.total_functions,
                "percentage": self.percentage, "files": [item.to_dict() for item in sorted(self.files, key=lambda x: x.file)]}


@dataclass(frozen=True, slots=True)
class CoverageReport:
    backend: str
    source_files: tuple[str, ...]
    line_metrics: LineCoverage
    branch_metrics: BranchCoverage
    tests_executed: int
    test_case_ids: tuple[str, ...]
    complete: bool
    partial: bool
    tool_version: str | None = None
    limitations: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    generated_harness_files: tuple[str, ...] = ()
    function_metrics: FunctionCoverage | None = None
    measurement_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.measurement_sha256 is None:
            payload = json.dumps(self._measurement_dict(), ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False)
            object.__setattr__(self, "measurement_sha256", hashlib.sha256(payload.encode("utf-8")).hexdigest())

    def _measurement_dict(self) -> dict[str, Any]:
        return {"backend": self.backend, "source_files": sorted(self.source_files),
                "line_metrics": self.line_metrics.to_dict(), "branch_metrics": self.branch_metrics.to_dict(),
                "function_metrics": self.function_metrics.to_dict() if self.function_metrics else None,
                "tests_executed": self.tests_executed, "test_case_ids": list(self.test_case_ids),
                "complete": self.complete, "partial": self.partial, "tool_version": self.tool_version,
                "limitations": list(self.limitations), "generated_harness_files": sorted(self.generated_harness_files)}

    def to_dict(self) -> dict[str, Any]:
        return {"backend": self.backend, "source_files": list(self.source_files),
                "line_metrics": self.line_metrics.to_dict(), "branch_metrics": self.branch_metrics.to_dict(),
                "function_metrics": self.function_metrics.to_dict() if self.function_metrics else None,
                "measurement_sha256": self.measurement_sha256,
                "tests_executed": self.tests_executed, "test_case_ids": list(self.test_case_ids),
                "complete": self.complete, "partial": self.partial, "tool_version": self.tool_version,
                "limitations": list(self.limitations), "evidence_ids": list(self.evidence_ids),
                "generated_harness_files": list(self.generated_harness_files)}

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent, allow_nan=False)


@dataclass(frozen=True, slots=True)
class CoverageSnapshot:
    lines: frozenset[tuple[str, int]]
    branches: frozenset[str]


@dataclass(frozen=True, slots=True)
class CoverageDelta:
    new_lines: tuple[tuple[str, int], ...]
    new_branches: tuple[str, ...]

    @classmethod
    def between(cls, before: CoverageSnapshot, after: CoverageSnapshot) -> CoverageDelta:
        return cls(tuple(sorted(after.lines - before.lines)), tuple(sorted(after.branches - before.branches)))


def aggregate_line_coverage(records: Mapping[str, Mapping[int, int]]) -> LineCoverage:
    files = tuple(FileLineCoverage(path, sum(count > 0 for count in lines.values()), len(lines), dict(lines))
                  for path, lines in sorted(records.items()))
    return LineCoverage(sum(item.covered_lines for item in files), sum(item.total_lines for item in files), files,
                        {path: dict(sorted(lines.items())) for path, lines in sorted(records.items())})


def aggregate_branch_coverage(hits: Mapping[str, bool], semantics: str) -> BranchCoverage:
    per_file: dict[str, list[bool]] = {}
    for entity, covered in hits.items():
        path = entity.split("|", 1)[0]
        per_file.setdefault(path, []).append(bool(covered))
    files = tuple(FileBranchCoverage(path, sum(values), len(values)) for path, values in sorted(per_file.items()))
    return BranchCoverage(sum(hits.values()), len(hits), files, dict(sorted(hits.items())), semantics)


def aggregate_function_coverage(counts: Mapping[str, int]) -> FunctionCoverage:
    per_file: dict[str, dict[str, int]] = {}
    for entity, count in counts.items():
        path, separator, name = entity.partition("|")
        if not separator:
            path, name = entity, entity
        per_file.setdefault(path, {})[name] = max(0, int(count))
    files = tuple(FileFunctionCoverage(path, sum(count > 0 for count in items.values()), len(items), dict(items))
                  for path, items in sorted(per_file.items()))
    return FunctionCoverage(sum(item.covered_functions for item in files), sum(item.total_functions for item in files),
                            files, dict(sorted(counts.items())))
