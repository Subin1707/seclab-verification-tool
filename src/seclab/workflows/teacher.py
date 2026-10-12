"""Six-chapter adapter for the teacher workflow example.

This workflow-specific API is intentionally separate from ``seclab.pipeline``.
It selects generic pipeline stages but does not add checker behavior.
"""
from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterable

from seclab.pipeline import PipelineOptions, PipelineReport, run_full_verification


class WorkflowChapter(StrEnum):
    CH1 = "CH1"
    CH2 = "CH2"
    CH3 = "CH3"
    CH4 = "CH4"
    CH5 = "CH5"
    CH6 = "CH6"


CHAPTER_STAGE_TARGETS: dict[WorkflowChapter, tuple[str, ...] | None] = {
    WorkflowChapter.CH1: ("CTL", "BMC"),
    WorkflowChapter.CH2: ("SPECIFICATION", "SOURCE", "STATIC", "MEMORY"),
    WorkflowChapter.CH3: ("SMT",),
    WorkflowChapter.CH4: ("SPECIFICATION", "SOURCE", "DYNAMIC", "COVERAGE"),
    WorkflowChapter.CH5: ("SPECIFICATION", "SOURCE", "DYNAMIC", "FUZZING"),
    WorkflowChapter.CH6: None,
}


def run_chapter_verification(chapter: WorkflowChapter | str, project: str | Path,
                             workspace: str | Path, *, options: PipelineOptions | None = None,
                             run_id: str | None = None,
                             progress_callback: Callable[[dict[str, Any]], None] | None = None
                             ) -> PipelineReport:
    """Run a chapter's stage targets through the generic pipeline."""
    try:
        selected_chapter = WorkflowChapter(str(chapter).upper())
    except ValueError as exc:
        raise ValueError(f"Unknown workflow chapter {chapter!r}; expected CH1 through CH6.") from exc
    selected_options = options or PipelineOptions()
    targets = CHAPTER_STAGE_TARGETS[selected_chapter]
    stage_ids: Iterable[str] | None = targets
    if selected_chapter is WorkflowChapter.CH5 and selected_options.fuzz_config is not None:
        from seclab.fuzzing import FuzzStrategy
        if selected_options.fuzz_config.strategy is FuzzStrategy.COVERAGE_GUIDED:
            stage_ids = (*targets, "COVERAGE")
    selected_options = replace(selected_options, metadata={
        **selected_options.metadata, "workflow_chapter": selected_chapter.value,
    })
    return run_full_verification(project, workspace, options=selected_options, run_id=run_id,
                                 stage_ids=stage_ids, progress_callback=progress_callback)
