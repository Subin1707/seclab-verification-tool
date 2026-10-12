"""Structured subprocess primitive. All commands execute without a shell."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .errors import ExecutionError, ExecutionErrorCode
from .timeout import validate_timeout


@dataclass(frozen=True, slots=True)
class CommandSpec:
    argv: tuple[str, ...] | Sequence[str]
    cwd: Path | str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    timeout: float | None = None
    stdin: str | bytes | None = None
    allowed_exit_codes: frozenset[int] = frozenset({0})

    def __post_init__(self) -> None:
        argv = tuple(self.argv)
        if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "argv must be a non-empty sequence of strings without NUL bytes.")
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in self.env.items()):
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "Environment overrides must map strings to strings.")
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "timeout", validate_timeout(self.timeout))
        codes = frozenset(self.allowed_exit_codes)
        if not codes or any(not isinstance(code, int) or isinstance(code, bool) for code in codes):
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "allowed_exit_codes must contain integer exit codes.")
        object.__setattr__(self, "allowed_exit_codes", codes)


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    cwd: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    allowed_exit_codes: tuple[int, ...]
    executable_path: str | None = None
    execution_error: str | None = None
    environment_keys: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.execution_error is None and self.exit_code in self.allowed_exit_codes

    @property
    def completed(self) -> bool:
        """Whether the target process ended before its runtime budget expired."""
        return not self.timed_out and self.execution_error is None and self.exit_code is not None

    @property
    def termination_info(self) -> dict[str, int | str | None]:
        if self.timed_out:
            return {"kind": "TIMEOUT", "return_code": self.exit_code, "signal": None}
        if self.execution_error is not None:
            return {"kind": "EXECUTION_ERROR", "return_code": self.exit_code, "signal": None}
        if self.exit_code is None:
            return {"kind": "UNKNOWN", "return_code": None, "signal": None}
        if os.name != "nt" and self.exit_code < 0:
            return {"kind": "SIGNAL", "return_code": self.exit_code, "signal": -self.exit_code}
        # On Windows, Popen exposes the process exit status but does not tell
        # whether it came from ExitProcess or an unhandled structured exception.
        return {"kind": "EXIT_CODE", "return_code": self.exit_code, "signal": None}


class CommandRunner:
    def run(self, spec: CommandSpec) -> CommandResult:
        started_wall = datetime.now(timezone.utc)
        started = time.monotonic()
        cwd = Path(spec.cwd or Path.cwd()).resolve()
        executable = shutil.which(spec.argv[0], path=spec.env.get("PATH", os.environ.get("PATH")))
        child_env = os.environ.copy()
        child_env.update(spec.env)
        timed_out = False
        execution_error = None
        exit_code: int | None = None
        stdout = stderr = ""
        try:
            proc = subprocess.Popen(
                list(spec.argv), cwd=cwd, env=child_env, stdin=subprocess.PIPE if spec.stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=(os.name != "nt"),
            )
            try:
                out_bytes, err_bytes = proc.communicate(_stdin_bytes(spec.stdin), timeout=spec.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_tree(proc)
                out_bytes, err_bytes = proc.communicate()
            exit_code = proc.returncode
            stdout = out_bytes.decode("utf-8", errors="replace")
            stderr = err_bytes.decode("utf-8", errors="replace")
        except FileNotFoundError as exc:
            execution_error = str(exc)
        except OSError as exc:
            execution_error = str(exc)
        finished = datetime.now(timezone.utc)
        return CommandResult(
            argv=tuple(spec.argv), cwd=str(cwd), exit_code=exit_code, stdout=stdout, stderr=stderr,
            duration_ms=(time.monotonic() - started) * 1000, timed_out=timed_out,
            started_at=started_wall, finished_at=finished, allowed_exit_codes=tuple(sorted(spec.allowed_exit_codes)),
            executable_path=executable, execution_error=execution_error,
            environment_keys=tuple(sorted(spec.env)),
        )


def _stdin_bytes(value: str | bytes | None) -> bytes | None:
    return value.encode("utf-8") if isinstance(value, str) else value


def _terminate_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"], check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False, timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                proc.kill()
            if proc.poll() is None:
                proc.kill()
        else:
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        proc.kill()
