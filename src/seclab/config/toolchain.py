"""Best-effort discovery of supported verification tool executables."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True, slots=True)
class ToolInfo:
    name: str
    installed: bool
    path: str | None
    version: str | None
    capabilities: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "installed": self.installed, "path": self.path,
                "version": self.version, "capabilities": list(self.capabilities)}


class Toolchain:
    TOOL_CAPABILITIES = {
        "gcc": ("compile_c",), "g++": ("compile_cpp",), "clang": ("compile_c",),
        "clang++": ("compile_cpp",), "cppcheck": ("static_analysis",),
        "clang-tidy": ("static_analysis",), "z3": ("smt_solving",), "cbmc": ("bounded_model_checking",),
        "gcov": ("coverage",), "llvm-cov": ("coverage",), "llvm-profdata": ("coverage_profile_merge",),
    }
    VERSION_ARGS = {
        "gcc": ("--version",), "g++": ("--version",), "clang": ("--version",),
        "clang++": ("--version",), "cppcheck": ("--version",), "clang-tidy": ("--version",),
        "z3": ("--version",), "cbmc": ("--version",), "gcov": ("--version",),
        "llvm-cov": ("--version",), "llvm-profdata": ("--version",),
    }

    def __init__(self, tools: Iterable[str] | None = None, *, command_runner: CommandRunner | None = None,
                 version_timeout: float = 2.0) -> None:
        if command_runner is None:
            from seclab.execution.command_runner import CommandRunner
            command_runner = CommandRunner()
        self.command_runner = command_runner
        self.version_timeout = version_timeout
        self._tools = {name: self._discover(name) for name in (tools or self.TOOL_CAPABILITIES)}

    def _discover(self, name: str) -> ToolInfo:
        from seclab.execution.command_runner import CommandSpec
        path = shutil.which(name)
        capabilities = self.TOOL_CAPABILITIES.get(name, ())
        if path is None:
            return ToolInfo(name, False, None, None, tuple(capabilities))
        version = None
        try:
            result = self.command_runner.run(CommandSpec((path, *self.VERSION_ARGS.get(name, ("--version",))), timeout=self.version_timeout,
                                                          allowed_exit_codes=frozenset({0, 1})))
            output = (result.stdout + "\n" + result.stderr).strip()
            if output and not result.timed_out and not result.execution_error:
                version = re.sub(r"\s+", " ", output.splitlines()[0])[:300]
        except Exception:
            # Discovery is informational; a broken version probe does not make the app unusable.
            version = None
        return ToolInfo(name, True, path, version, tuple(capabilities))

    def get(self, name: str) -> ToolInfo:
        if name not in self._tools:
            self._tools[name] = self._discover(name)
        return self._tools[name]

    def all(self) -> tuple[ToolInfo, ...]:
        return tuple(self._tools.values())

    def compiler_for(self, language: str) -> ToolInfo | None:
        normalized = getattr(language, "value", language)
        candidates = ("gcc", "clang") if normalized == "C" else ("g++", "clang++") if normalized == "C++" else ()
        return next((info for name in candidates if (info := self.get(name)).installed), None)

    def summary(self) -> dict[str, dict[str, object]]:
        return {item.name: item.to_dict() for item in self.all()}
