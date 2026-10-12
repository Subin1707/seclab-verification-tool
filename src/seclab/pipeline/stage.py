"""Shared stage lifecycle separate from checker VerificationStatus."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from seclab.evidence import Evidence
from seclab.results import VerificationResult


class StageStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class StageOutput:
    value: Any = None
    results: tuple[VerificationResult, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StageSkipped:
    """Explicitly skipped stage with an actionable missing-input reason."""
    reason: str


@dataclass(slots=True)
class StageRecord:
    stage_id: str
    name: str
    status: StageStatus = StageStatus.NOT_STARTED
    output: Any = None
    result_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: float = 0.0
    reason: str | None = None
    error_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    input_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()
    selected: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"stage_id": self.stage_id, "stage_name": self.name, "name": self.name,
                "status": self.status.value,
                "result_ids": list(self.result_ids), "evidence_ids": list(self.evidence_ids),
                "input_refs": list(self.input_refs), "output_refs": list(self.output_refs),
                "start_time": self.started_at, "end_time": self.finished_at,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "duration_ms": self.duration_ms, "reason": self.reason,
                "error_type": self.error_type, "metadata": dict(self.metadata),
                "output": self.output, "selected": self.selected}


class Stage(Protocol):
    stage_id: str
    name: str
    dependencies: tuple[str, ...]

    def execute(self, context: Any) -> StageOutput: ...


@dataclass(frozen=True, slots=True)
class FunctionalStage:
    stage_id: str
    name: str
    execute_fn: Any
    dependencies: tuple[str, ...] = ()

    def execute(self, context: Any) -> StageOutput:
        return self.execute_fn(context)
