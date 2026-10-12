"""Entity-based coverage feedback helpers over the shared coverage models."""
from __future__ import annotations

from seclab.coverage import CoverageDelta, CoverageRunner, CoverageSnapshot


class CoverageGuidedFuzzer:
    def __init__(self, runner: CoverageRunner) -> None:
        self.runner = runner

    def snapshot(self, report) -> CoverageSnapshot:
        return self.runner.snapshot(report)

    def delta(self, before: CoverageSnapshot, after: CoverageSnapshot) -> CoverageDelta:
        return CoverageDelta.between(before, after)

    @staticmethod
    def signature(snapshot: CoverageSnapshot) -> tuple[str, ...]:
        return tuple(sorted([f"line:{path}:{line}" for path, line in snapshot.lines] +
                            [f"branch:{item}" for item in snapshot.branches]))
