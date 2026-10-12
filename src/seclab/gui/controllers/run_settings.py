"""GUI run settings translated to the existing generic PipelineOptions API."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from seclab.fuzzing import FuzzConfig, FuzzInput, FuzzStrategy
from seclab.pipeline import PipelineOptions


@dataclass(frozen=True, slots=True)
class GuiRunSettings:
    static_analyzers: tuple[str, ...] = ("compiler", "cppcheck", "clang-tidy", "clang-static")
    toolchain_tools: tuple[str, ...] | None = None
    run_memory: bool = True
    run_coverage: bool = True
    coverage_backend: str = "auto"
    analysis_timeout: float = 60.0
    execution_timeout: float = 5.0
    build_timeout: float = 60.0
    fuzz_enabled: bool = True
    fuzz_strategy: str = "BLACKBOX"
    fuzz_iterations: int = 100
    fuzz_timeout: float = 2.0
    fuzz_seed: int = 1
    fuzz_max_input_size: int = 4096
    fuzz_seeds: tuple[FuzzInput, ...] = ()
    fuzz_grammar_start: str = "<start>"
    fuzz_grammar_rules: dict[str, object] | None = None

    def to_pipeline_options(self, specification_path: str | Path | None = None) -> PipelineOptions:
        fuzz = FuzzConfig(FuzzStrategy(self.fuzz_strategy), self.fuzz_iterations, self.fuzz_timeout,
                          self.fuzz_seed, self.fuzz_max_input_size, grammar_start=self.fuzz_grammar_start,
                          grammar_rules=self.fuzz_grammar_rules or {}) if self.fuzz_enabled else None
        return PipelineOptions(
            specification_paths=(Path(specification_path),) if specification_path else (),
            static_analyzers=self.static_analyzers, toolchain_tools=self.toolchain_tools,
            run_memory=self.run_memory, run_coverage=self.run_coverage,
            coverage_backend=self.coverage_backend, analysis_timeout=self.analysis_timeout,
            execution_timeout=self.execution_timeout, build_timeout=self.build_timeout,
            fuzz_config=fuzz,
            fuzz_seeds=self.fuzz_seeds,
        )


def parse_tool_list(value: str) -> tuple[str, ...] | None:
    """Parse optional comma/space separated tool names; blank means auto-discovery."""
    names = tuple(dict.fromkeys(item for item in value.replace(",", " ").split() if item))
    return names or None
