"""Generic, isolated-output compiler orchestration."""

from __future__ import annotations

import uuid
import os
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Iterable

from seclab.config.toolchain import ToolInfo, Toolchain
from seclab.evidence import ArtifactStore, Evidence
from seclab.source import Language, SourceFile

from .command_runner import CommandResult, CommandRunner, CommandSpec
from .errors import ExecutionError, ExecutionErrorCode
from .evidence import store_command_evidence


@dataclass(frozen=True, slots=True)
class BuildResult:
    success: bool
    command_result: CommandResult | None
    binary_path: Path | None
    compiler: ToolInfo | None
    source_files: tuple[str, ...]
    language: str
    error_code: str | None = None
    build_evidence: tuple[Evidence, ...] = ()


class Compiler:
    def __init__(self, workspace_root: str | Path, toolchain: Toolchain, *,
                 command_runner: CommandRunner | None = None, artifact_store: ArtifactStore | None = None,
                 timeout: float = 60.0) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.toolchain = toolchain
        self.command_runner = command_runner or CommandRunner()
        self.artifact_store = artifact_store or ArtifactStore(self.workspace_root)
        self.timeout = timeout

    def build(self, source_files: Iterable[SourceFile | str | Path], language: Language | str, *,
              compiler: str | ToolInfo | None = None,
              flags: Iterable[str] = (), include_dirs: Iterable[str | Path] = (),
              output_directory: str | Path | None = None, output_name: str = "sut",
              separate_compilation: bool = False, isolated_output: bool = False) -> BuildResult:
        lang = getattr(language, "value", language)
        files = tuple(source_files)
        if not files or lang not in {"C", "C++"}:
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "Build requires source files and language C or C++.")
        units = tuple(item for item in files if Path(item.path if isinstance(item, SourceFile) else item).suffix.lower() in
                      ({".c"} if lang == "C" else {".cc", ".cpp", ".cxx"}))
        if not units:
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, f"No {lang} translation units were supplied.")
        paths = tuple(Path(item.path if isinstance(item, SourceFile) else item).resolve() for item in units)
        if any(not path.is_file() for path in paths):
            raise ExecutionError(ExecutionErrorCode.COMMAND_EXECUTION_ERROR, "Every compiler input must be an existing regular file.")
        if not output_name or Path(output_name).name != output_name or output_name in {".", ".."}:
            raise ExecutionError(ExecutionErrorCode.INVALID_OUTPUT_PATH, "output_name must be a filename component.")
        output_dir = Path(output_directory).resolve() if output_directory else (self.workspace_root / "build").resolve()
        inferred_roots = []
        for item, path in zip(units, paths):
            if isinstance(item, SourceFile):
                depth = len(PurePosixPath(item.relative_path).parts) - 1
                inferred_roots.append(path.parents[depth])
            else:
                inferred_roots.append(path.parent)
        if not output_dir.is_relative_to(self.workspace_root) or (not isolated_output and any(
            output_dir == root or output_dir.is_relative_to(root) for root in inferred_roots
        )):
            raise ExecutionError(ExecutionErrorCode.INVALID_OUTPUT_PATH, "Build output directory must be inside workspace and outside source files.")
        selected_compiler = self.toolchain.compiler_for(lang) if compiler is None else (
            compiler if isinstance(compiler, ToolInfo) else self.toolchain.get(compiler)
        )
        if selected_compiler is None or not selected_compiler.installed:
            return BuildResult(False, None, None, None, tuple(str(path) for path in paths), lang, "COMPILER_NOT_FOUND")
        required_capability = "compile_c" if lang == "C" else "compile_cpp"
        if required_capability not in selected_compiler.capabilities:
            raise ExecutionError(ExecutionErrorCode.COMPILER_NOT_FOUND,
                                 f"Compiler '{selected_compiler.name}' does not advertise {required_capability}.")
        output_dir.mkdir(parents=True, exist_ok=True)
        binary = output_dir / (output_name + ".exe" if os.name == "nt" and not output_name.lower().endswith(".exe") else output_name)
        binary_command_path = _compiler_output_path(binary) if separate_compilation else binary
        if binary_command_path.exists():
            raise ExecutionError(ExecutionErrorCode.INVALID_OUTPUT_PATH, f"Build output '{binary}' already exists; refusing to overwrite it.")
        standard = "-std=c11" if lang == "C" else "-std=c++17"
        argv = [selected_compiler.path or selected_compiler.name, standard, *(str(flag) for flag in flags)]
        for include_dir in include_dirs:
            argv.extend(("-I", str(Path(include_dir).resolve())))
        build_evidence = []
        if separate_compilation:
            objects = []
            for index, path in enumerate(paths):
                obj = output_dir / f"unit-{index}-{_safe_stem(path.stem)}.o"
                object_command_path = _compiler_output_path(obj)
                compile_argv = [*argv, "-c", str(path), "-o", str(object_command_path)]
                command = self.command_runner.run(CommandSpec(tuple(compile_argv), cwd=self.workspace_root, timeout=self.timeout))
                build_evidence.extend(store_command_evidence(self.artifact_store, command, stage="build",
                                                             prefix=f"build-{uuid.uuid4().hex}"))
                if not command.succeeded or not object_command_path.is_file():
                    error_code = "COMMAND_TIMEOUT" if command.timed_out else "COMPILATION_FAILED" if command.execution_error is None else "COMMAND_EXECUTION_ERROR"
                    return BuildResult(False, command, None, selected_compiler, tuple(str(path) for path in paths),
                                       lang, error_code, tuple(build_evidence))
                objects.append(obj)
            link_argv = [selected_compiler.path or selected_compiler.name,
                         *(str(_compiler_output_path(item)) for item in objects),
                         *(str(flag) for flag in flags), "-o", str(binary_command_path)]
            command = self.command_runner.run(CommandSpec(tuple(link_argv), cwd=self.workspace_root, timeout=self.timeout))
            build_evidence.extend(store_command_evidence(self.artifact_store, command, stage="build",
                                                         prefix=f"build-{uuid.uuid4().hex}"))
        else:
            argv.extend(str(path) for path in paths)
            argv.extend(("-o", str(binary)))
            command = self.command_runner.run(CommandSpec(tuple(argv), cwd=self.workspace_root, timeout=self.timeout))
            build_evidence.extend(store_command_evidence(self.artifact_store, command, stage="build",
                                                         prefix=f"build-{uuid.uuid4().hex}"))
        success = command.succeeded and binary_command_path.is_file()
        error_code = None if success else (
            "COMMAND_TIMEOUT" if command.timed_out else
            "COMPILATION_FAILED" if command.execution_error is None else "COMMAND_EXECUTION_ERROR"
        )
        return BuildResult(success, command, binary_command_path if binary_command_path.exists() else None, selected_compiler,
                           tuple(str(path) for path in paths), lang, error_code,
                           tuple(build_evidence))


def _safe_stem(value: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "source"


def _compiler_output_path(path: Path) -> Path:
    """Use a Windows short parent alias for GCC's gcno writer when paths contain spaces."""
    if os.name != "nt" or " " not in str(path.parent):
        return path
    try:
        import ctypes
        from ctypes import wintypes
        function = ctypes.windll.kernel32.GetShortPathNameW
        function.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        function.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(str(path.parent), buffer, len(buffer))
        if length and length < len(buffer) and buffer.value:
            return Path(buffer.value) / path.name
    except (AttributeError, OSError):
        pass
    return path
