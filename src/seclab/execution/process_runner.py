"""SUT-oriented execution wrapper over CommandRunner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .command_runner import CommandResult, CommandRunner, CommandSpec


@dataclass(frozen=True, slots=True)
class ProcessSpec:
    executable: str | Path
    args: tuple[str, ...] | Sequence[str] = ()
    cwd: Path | str | None = None
    stdin: str | bytes | None = None
    timeout: float | None = None
    env: Mapping[str, str] = field(default_factory=dict)


class ProcessRunner:
    def __init__(self, command_runner: CommandRunner | None = None) -> None:
        self.command_runner = command_runner or CommandRunner()

    def run(self, process: ProcessSpec) -> CommandResult:
        return self.command_runner.run(CommandSpec(
            argv=(str(process.executable), *tuple(process.args)), cwd=process.cwd, env=process.env,
            stdin=process.stdin, timeout=process.timeout,
        ))
