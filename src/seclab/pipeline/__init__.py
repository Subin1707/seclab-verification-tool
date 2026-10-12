"""Pipeline integration core: per-run orchestration, lifecycle, and report."""

from .context import (EvidenceStore, GeneratedSourceContext, ModelContext, PipelineContext, ProjectContext,
                      RunContext, SpecificationContext, TraceabilityStore, TrackedArtifactStore,
                      VerificationContext)
from .cross_check import CrossCheckStatus, build_cross_check_matrix
from .full_verification import run_full_verification
from .options import PipelineOptions
from .orchestrator import PipelineOrchestrator
from .previous_run import load_previous_run
from .report import PipelineReport
from .teacher_report import render_teacher_report
from .stage import FunctionalStage, Stage, StageOutput, StageRecord, StageSkipped, StageStatus
from .traceability import TraceabilityIndex

__all__ = ["EvidenceStore", "FunctionalStage", "GeneratedSourceContext", "ModelContext", "PipelineContext",
           "ProjectContext", "RunContext", "SpecificationContext", "TraceabilityStore", "PipelineOptions", "PipelineOrchestrator",
           "PipelineReport", "Stage", "StageOutput", "StageRecord", "StageSkipped", "StageStatus",
           "TrackedArtifactStore", "TraceabilityIndex", "CrossCheckStatus", "build_cross_check_matrix",
           "VerificationContext", "load_previous_run", "run_full_verification", "render_teacher_report"]
