from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

import pytest

from seclab.execution import (
    CommandRunner, CommandSpec, EnvironmentSnapshot, ExecutionError, ProcessRunner, ProcessSpec,
    capture_environment, classify_execution_result, store_command_evidence,
)
from seclab.evidence import ArtifactStore
from seclab.results import VerificationStatus


def py(*args: str) -> tuple[str, ...]:
    return (sys.executable, "-c", *args)


def test_command_runner_captures_streams_exit_stdin_unicode_and_cwd(tmp_path) -> None:
    runner = CommandRunner()
    result = runner.run(CommandSpec(py("import sys; sys.stdout.buffer.write((sys.stdin.read() + ' ✓\\n').encode('utf-8')); print('err', file=sys.stderr)"),
                                    cwd=tmp_path, stdin="hello", timeout=3))
    assert result.succeeded
    assert "hello ✓" in result.stdout
    assert result.stderr.strip() == "err"
    assert result.cwd == str(tmp_path.resolve())

    failed = runner.run(CommandSpec(py("raise SystemExit(7)")))
    assert failed.exit_code == 7 and not failed.succeeded


def test_command_runner_uses_argv_without_shell_interpretation(tmp_path) -> None:
    argument = "hello;echo hacked && $HOME"
    result = CommandRunner().run(CommandSpec(py("import json,sys; print(json.dumps(sys.argv[1:]))", argument)))
    assert json.loads(result.stdout) == [argument]


def test_timeout_terminates_child_process_and_classifies_as_inconclusive() -> None:
    start = time.monotonic()
    result = CommandRunner().run(CommandSpec(py("import time; time.sleep(5)"), timeout=0.2))
    assert result.timed_out
    assert time.monotonic() - start < 3
    semantic = classify_execution_result(result)
    assert semantic.status is VerificationStatus.INCONCLUSIVE
    assert semantic.reason_code == "EXECUTION_TIMEOUT"


def test_command_environment_is_child_only_and_process_runner_reuses_command_runner(monkeypatch) -> None:
    key = "SECLAB_TEST_CHILD_ENV"
    monkeypatch.delenv(key, raising=False)
    result = CommandRunner().run(CommandSpec(py("import os; print(os.environ['SECLAB_TEST_CHILD_ENV'])"), env={key: "child"}))
    assert result.stdout.strip() == "child"
    assert key not in os.environ
    wrapper = ProcessRunner()
    wrapped = wrapper.run(ProcessSpec(sys.executable, ("-c", "print('sut')"), timeout=2))
    assert wrapped.stdout.strip() == "sut"


def test_execution_exit_zero_never_claims_property_pass(tmp_path) -> None:
    command = CommandRunner().run(CommandSpec(py("print('ran')")))
    result = classify_execution_result(command)
    assert result.status is VerificationStatus.INCONCLUSIVE
    assert result.reason_code == "EXECUTION_COMPLETED"
    assert "no verification property" in result.scope


def test_command_evidence_and_environment_snapshot_are_serializable(tmp_path) -> None:
    runner_result = CommandRunner().run(CommandSpec(py("print('ok')")))
    store = ArtifactStore(tmp_path)
    evidence = store_command_evidence(store, runner_result)
    assert len(evidence) == 3
    assert all((tmp_path / item.path).exists() for item in evidence)
    snapshot = capture_environment()
    assert set(("os", "architecture", "python_version", "toolchain")).issubset(snapshot.to_dict())
    json.dumps(snapshot.to_dict())


def test_toolinfo_shape_and_discovery_is_tolerant_of_missing_tools(monkeypatch) -> None:
    from seclab.config import Toolchain
    monkeypatch.setattr("seclab.config.toolchain.shutil.which", lambda name: None)
    tools = Toolchain(["definitely-not-a-real-tool"])
    info = tools.get("definitely-not-a-real-tool")
    assert info.installed is False and info.path is None and info.version is None
    assert set(info.to_dict()) == {"name", "installed", "path", "version", "capabilities"}


def test_tool_version_timeout_does_not_crash_discovery(monkeypatch) -> None:
    from seclab.config import Toolchain
    from seclab.execution import CommandResult

    class TimedOutRunner:
        def run(self, spec):
            now = datetime.now(timezone.utc)
            return CommandResult(tuple(spec.argv), str(os.getcwd()), None, "partial", "", 10.0, True,
                                 now, now, tuple(spec.allowed_exit_codes), str(sys.executable))

    monkeypatch.setattr("seclab.config.toolchain.shutil.which", lambda name: sys.executable)
    info = Toolchain(["fake-tool"], command_runner=TimedOutRunner()).get("fake-tool")
    assert info.installed is True
    assert info.version is None


def test_missing_process_executable_is_tool_error() -> None:
    result = CommandRunner().run(CommandSpec(("seclab-definitely-missing-executable-xyz",)))
    assert result.execution_error
    assert classify_execution_result(result).status is VerificationStatus.TOOL_ERROR
    assert classify_execution_result(result).reason_code == "EXECUTABLE_NOT_FOUND"


def test_build_and_process_integration_generic_c_project(tmp_path) -> None:
    from seclab.config import Toolchain
    from seclab.execution import Compiler, classify_build_result
    from seclab.source import Language, SourceLoader

    workspace = tmp_path / "workspace"
    project = workspace / "sut-source"
    project.mkdir(parents=True)
    (project / "main file.c").write_text('#include <stdio.h>\nint main(void) { puts("hello build"); return 0; }\n', encoding="utf-8")
    sources = SourceLoader().load_source_tree(project)
    toolchain = Toolchain(["gcc", "clang"], version_timeout=2)
    compiler = Compiler(workspace, toolchain)
    if toolchain.compiler_for("C") is None:
        pytest.skip("No supported C compiler is installed")
    built = compiler.build(sources, Language.C)
    assert built.success
    assert built.binary_path and built.binary_path.is_file()
    assert built.binary_path.parent == workspace / "build"
    assert len(built.build_evidence) == 3
    assert all((workspace / item.path).exists() for item in built.build_evidence)
    command_evidence = json.loads((workspace / built.build_evidence[0].path).read_text(encoding="utf-8"))
    assert command_evidence["stdout_evidence"]["id"] == built.build_evidence[1].id
    assert command_evidence["stderr_evidence"]["id"] == built.build_evidence[2].id
    run = ProcessRunner().run(ProcessSpec(built.binary_path, timeout=2))
    assert run.stdout.strip() == "hello build"
    assert classify_build_result(built).status is VerificationStatus.INCONCLUSIVE
    assert classify_execution_result(run).status is VerificationStatus.INCONCLUSIVE


def test_compile_failure_is_build_error_and_output_cannot_be_inside_source_tree(tmp_path) -> None:
    from seclab.config import Toolchain
    from seclab.execution import Compiler, classify_build_result
    from seclab.source import Language, SourceLoader

    workspace = tmp_path / "workspace"
    project = workspace / "sut-source"
    project.mkdir(parents=True)
    (project / "bad.c").write_text("int main( { invalid", encoding="utf-8")
    sources = SourceLoader().load_source_tree(project)
    toolchain = Toolchain(["gcc", "clang"], version_timeout=2)
    if toolchain.compiler_for("C") is None:
        pytest.skip("No supported C compiler is installed")
    compiler = Compiler(workspace, toolchain)
    with pytest.raises(ExecutionError):
        compiler.build(sources, Language.C, output_directory=project / "build")
    failed = compiler.build(sources, Language.C)
    assert not failed.success
    assert failed.error_code == "COMPILATION_FAILED"
    assert classify_build_result(failed).status is VerificationStatus.BUILD_ERROR
