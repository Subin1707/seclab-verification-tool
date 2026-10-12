"""Pipeline report and requirement traceability without an overall verdict."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from seclab.results import VerificationResult


@dataclass(frozen=True, slots=True)
class PipelineReport:
    run_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    specification_info: Mapping[str, Any]
    stage_summaries: tuple[Mapping[str, Any], ...]
    results: tuple[VerificationResult, ...]
    status_counts: Mapping[str, int]
    evidence_manifest: Mapping[str, Any]
    traceability: Mapping[str, Any]
    limitations: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(), "duration_seconds": self.duration_seconds,
                "specification_info": dict(self.specification_info),
                "stage_summaries": [dict(item) for item in self.stage_summaries],
                "results": [item.to_dict() for item in self.results],
                "status_counts": dict(self.status_counts), "evidence_manifest": dict(self.evidence_manifest),
                "traceability": {key: dict(value) for key, value in self.traceability.items()},
                "limitations": list(self.limitations),
                "metadata": dict(self.metadata)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PipelineReport":
        from datetime import datetime
        from seclab.results import VerificationResult
        return cls(run_id=data["run_id"], start_time=datetime.fromisoformat(data["start_time"]),
            end_time=datetime.fromisoformat(data["end_time"]), duration_seconds=data["duration_seconds"],
            specification_info=data.get("specification_info", {}),
            stage_summaries=tuple(data.get("stage_summaries", ())),
            results=tuple(VerificationResult.from_dict(item) for item in data.get("results", ())),
            status_counts=data.get("status_counts", {}), evidence_manifest=data.get("evidence_manifest", {}),
            traceability=data.get("traceability", {}), limitations=tuple(data.get("limitations", ())),
            metadata=data.get("metadata", {}))
