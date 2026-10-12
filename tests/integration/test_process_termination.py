from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from seclab.config import Toolchain
from seclab.execution import Compiler, ProcessRunner, ProcessSpec
from seclab.testing import ExpectedBehavior, OracleExpectation, OracleType, TestCase, TestRunner


_FIXTURE = r'''#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif
#include <string.h>
int main(int argc, char **argv) {
  if (argc < 2) return 9;
  if (!strcmp(argv[1], "zero")) return 0;
  if (!strcmp(argv[1], "nonzero")) return 1;
  if (!strcmp(argv[1], "crash")) {
#ifdef _WIN32
    /* Suppress the interactive WER error dialog while preserving the OS exception exit status. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    RaiseException(0xC0000005, EXCEPTION_NONCONTINUABLE, 0, 0);
#else
    raise(SIGABRT);
#endif
    return 2;
  }
  if (!strcmp(argv[1], "sleep")) {
#ifdef _WIN32
    Sleep(5000);
#else
    sleep(5);
#endif
  }
  return 0;
}
'''


@pytest.fixture(scope="module")
def process_fixture(tmp_path_factory):
    compiler_name = "gcc" if shutil.which("gcc") else "clang" if shutil.which("clang") else None
    if not compiler_name:
        pytest.skip("gcc or clang is required for process termination integration")
    root = tmp_path_factory.mktemp("process-termination")
    source_dir = root / "input"
    source_dir.mkdir()
    source = source_dir / "process_fixture.c"
    source.write_text(_FIXTURE, encoding="utf-8")
    workspace = root / "workspace"
    workspace.mkdir()
    build = Compiler(workspace, Toolchain([compiler_name])).build(
        [source], "C", output_directory=workspace / "build", output_name="process-fixture")
    assert build.success, build.command_result.stderr if build.command_result else build.error_code
    return root, source, workspace, build.binary_path


def test_real_process_completion_exit_code_crash_and_timeout(process_fixture):
    _, _, _, executable = process_fixture
    runner = ProcessRunner()
    normal = runner.run(ProcessSpec(executable, ("zero",), timeout=2))
    nonzero = runner.run(ProcessSpec(executable, ("nonzero",), timeout=2))
    crash = runner.run(ProcessSpec(executable, ("crash",), timeout=2))
    timeout = runner.run(ProcessSpec(executable, ("sleep",), timeout=0.1))

    assert normal.completed and not normal.timed_out and normal.exit_code == 0
    assert nonzero.completed and not nonzero.timed_out and nonzero.exit_code == 1
    assert crash.completed and not crash.timed_out and crash.exit_code not in {None, 0}
    assert timeout.timed_out and not timeout.completed


def test_real_abnormal_termination_reaches_no_crash_oracle(process_fixture):
    _, _, workspace, executable = process_fixture
    runner = TestRunner(workspace, Toolchain(["gcc"] if shutil.which("gcc") else ["clang"]))
    case = TestCase("crash", "abnormal termination", "process-fixture", {"argv": ["crash"]},
        ExpectedBehavior((OracleExpectation(OracleType.NO_CRASH, True),)), target_kind="EXECUTABLE", timeout_seconds=3)
    result = runner.run_one(case, executable=executable)
    assert result.executed
    assert result.command_result is not None
    assert result.command_result.completed
    assert not result.command_result.timed_out
    assert result.observed is not None and result.observed.crashed is True
    assert result.oracle_evaluation.satisfied is False
