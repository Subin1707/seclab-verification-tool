"""Controlled compilation and process execution primitives."""

from .command_runner import CommandResult, CommandRunner, CommandSpec
from .compiler import BuildResult, Compiler
from .environment import EnvironmentSnapshot, capture_environment
from .errors import ExecutionError, ExecutionErrorCode
from .evidence import store_command_evidence, store_environment_evidence
from .process_runner import ProcessRunner, ProcessSpec
from .result_adapter import classify_build_result, classify_execution_result

__all__ = ["BuildResult", "CommandResult", "CommandRunner", "CommandSpec", "Compiler", "EnvironmentSnapshot",
           "ExecutionError", "ExecutionErrorCode", "ProcessRunner", "ProcessSpec", "capture_environment",
           "classify_build_result", "classify_execution_result", "store_command_evidence", "store_environment_evidence"]
