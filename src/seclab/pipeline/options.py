"""Configuration for the integrated full-verification run."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from seclab.fuzzing import FuzzConfig, FuzzInput
from seclab.source import SourceFile
from seclab.testing import TestCase


@dataclass(frozen=True, slots=True)
class PipelineOptions:
    specification_paths: tuple[Path, ...] = ()
    loaded_specification: Any = None
    validated_specification: Any = None
    normalized_specification: Any = None
    schema_path: Path | None = None
    static_analyzers: tuple[str, ...] = ("compiler", "cppcheck", "clang-tidy", "clang-static")
    run_memory: bool = True
    run_coverage: bool = True
    fuzz_config: FuzzConfig | None = None
    fuzz_seeds: tuple[FuzzInput, ...] = ()
    coverage_backend: str = "auto"
    analysis_timeout: float = 60.0
    execution_timeout: float = 5.0
    build_timeout: float = 60.0
    solver_timeout: float | None = 10.0
    bmc_default_bound: int = 10
    max_states: int | None = 10000
    # Accepted for config compatibility; CODEGEN is always part of the full run.
    generate_c_model: bool = True
    generate_c_fuzz_harness: bool = False
    build_flags: tuple[str, ...] = ()
    toolchain_tools: tuple[str, ...] | None = None
    static_flags: tuple[str, ...] = ()
    source_files: tuple[SourceFile, ...] | None = None
    test_cases: tuple[TestCase, ...] | None = None
    test_case_requirement_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)
    test_case_function_ids: dict[str, str | None] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.analysis_timeout <= 0 or self.execution_timeout <= 0 or self.build_timeout <= 0:
            raise ValueError("pipeline timeouts must be positive")
        if self.solver_timeout is not None and self.solver_timeout <= 0:
            raise ValueError("solver_timeout must be positive or None")
        if self.bmc_default_bound < 0 or self.max_states is not None and self.max_states < 0:
            raise ValueError("BMC bound and max_states must be non-negative")
        allowed_analyzers = {"compiler", "cppcheck", "clang-tidy", "clang-static"}
        unknown = set(self.static_analyzers) - allowed_analyzers
        if unknown:
            raise ValueError(f"Unsupported static analyzer(s): {', '.join(sorted(unknown))}")
