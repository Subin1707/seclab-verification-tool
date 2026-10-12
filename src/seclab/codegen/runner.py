"""Compile and execute generated model artifacts with scoped outcomes/evidence."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from seclab.evidence import ArtifactStore, Evidence, EvidenceType
from seclab.execution import CommandRunner, CommandSpec


@dataclass(frozen=True, slots=True)
class GeneratedRunResult:
    build_status: str
    execution_status: str
    executable: Path | None
    stdout: str
    stderr: str
    exit_code: int | None
    evidence: tuple[Evidence, ...]
    scope: str = "Generated artifact execution only; no production-source or safety verdict."


class GeneratedArtifactRunner:
    def __init__(self, workspace_root: str | Path, *, command_runner: CommandRunner | None = None,
                 artifact_store: ArtifactStore | None = None) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.command_runner = command_runner or CommandRunner()
        self.artifact_store = artifact_store or ArtifactStore(self.workspace_root)

    def compile_and_run(self, generated_root: str | Path, *, compiler: str = "cc",
                        timeout: float = 30.0, build_timeout: float | None = None,
                        execution_timeout: float | None = None,
                        input_args: tuple[str, ...] = ()) -> GeneratedRunResult:
        root = Path(generated_root).resolve(strict=True)
        source = root / "source/model.c"
        harness = root / "tests/model_test.c"
        header = root / "include/model.h"
        for path in (source, harness, header):
            if not path.is_file() or not path.resolve().is_relative_to(root):
                raise ValueError(f"Generated input is missing or escapes artifact root: {path.name}")
        executable = root / ("model-test.exe" if os.name == "nt" else "model-test")
        if executable.exists():
            raise FileExistsError(f"Refusing to overwrite generated executable: {executable}")
        input_files = [source, harness, header]
        for relative in ("source-map.json", "manifest.json"):
            candidate = root / relative
            if candidate.is_file() and candidate.resolve().is_relative_to(root):
                input_files.append(candidate)
        source_hashes = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in input_files}
        evidence: list[Evidence] = []
        invocation_id = uuid.uuid4().hex[:12]
        for relative, digest in sorted(source_hashes.items()):
            artifact_class = ("TEST_HARNESS" if relative.startswith("tests/") else
                              "GENERATION_METADATA" if relative in {"source-map.json", "manifest.json"} else
                              "GENERATED_ARTIFACT")
            evidence.append(self.artifact_store.copy_file(
                "codegen", "input-" + invocation_id + "-" + digest[:16] + Path(relative).suffix, root / relative,
                evidence_type=EvidenceType.MODEL,
                metadata={"artifact_class": artifact_class, "generated_path": relative,
                          "sha256": digest}))
        compile_result = self.command_runner.run(CommandSpec(
            argv=(compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-I", str(header.parent),
                  str(source), str(harness), "-o", str(executable)), cwd=root,
            timeout=timeout if build_timeout is None else build_timeout))
        evidence.extend(self._store_command("generated-build-" + invocation_id, "BUILD", compile_result))
        if compile_result.timed_out:
            return GeneratedRunResult("BUILD_ERROR", "NOT_RUN", None, compile_result.stdout,
                                      compile_result.stderr, compile_result.exit_code, tuple(evidence))
        if compile_result.execution_error:
            status = "TOOL_ERROR" if compile_result.executable_path is None else "TOOL_ERROR"
            return GeneratedRunResult(status, "NOT_RUN", None, compile_result.stdout,
                                      compile_result.stderr, compile_result.exit_code, tuple(evidence))
        if not compile_result.succeeded:
            return GeneratedRunResult("BUILD_ERROR", "NOT_RUN", None, compile_result.stdout,
                                      compile_result.stderr, compile_result.exit_code, tuple(evidence))
        if not executable.is_file():
            return GeneratedRunResult("TOOL_ERROR", "NOT_RUN", None, compile_result.stdout,
                                      "Compiler reported success but executable is absent.", None, tuple(evidence))
        run_result = self.command_runner.run(CommandSpec(argv=(str(executable), *input_args), cwd=root,
            timeout=timeout if execution_timeout is None else execution_timeout))
        evidence.extend(self._store_command("generated-execution-" + invocation_id, "EXECUTION", run_result))
        if run_result.timed_out:
            status = "TIMEOUT"
        elif run_result.execution_error:
            status = "TOOL_ERROR"
        elif run_result.succeeded:
            status = "COMPLETED"
        else:
            status = "ABNORMAL_TERMINATION"
        return GeneratedRunResult("COMPLETED", status, executable if executable.is_file() else None,
                                  run_result.stdout, run_result.stderr, run_result.exit_code, tuple(evidence))

    def _store_command(self, prefix: str, kind: str, result: Any) -> tuple[Evidence, ...]:
        base = {"scope": "generated artifact only", "kind": kind, "argv": list(result.argv),
                "cwd": result.cwd, "exit_code": result.exit_code, "stdout": result.stdout,
                "stderr": result.stderr, "timed_out": result.timed_out,
                "execution_error": result.execution_error, "duration_ms": result.duration_ms,
                "termination": result.termination_info}
        row = self.artifact_store.write_json("codegen", prefix + ".json", base,
            evidence_type=EvidenceType.TEST_RESULT,
            metadata={"artifact_class": "GENERATED_EXECUTION_EVIDENCE", "scope": base["scope"], "kind": kind})
        return (row,)
