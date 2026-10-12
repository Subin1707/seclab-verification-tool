"""Public entry point for a complete integrated verification run."""
from __future__ import annotations

from pathlib import Path
from threading import Event
from typing import Any, Callable, Iterable

from .options import PipelineOptions
from .orchestrator import PipelineOrchestrator
from .report import PipelineReport


def run_full_verification(project: str | Path, workspace: str | Path, *,
                          options: PipelineOptions | None = None,
                          run_id: str | None = None,
                          stage_ids: Iterable[str] | None = None,
                          cancellation_event: Event | None = None,
                          progress_callback: Callable[[dict[str, Any]], None] | None = None) -> PipelineReport:
    """Run all configured stages and return a report with no project-level verdict."""
    return PipelineOrchestrator.full(options).run(project, workspace, run_id=run_id, stage_ids=stage_ids,
                                                  cancellation_event=cancellation_event,
                                                  progress_callback=progress_callback)
