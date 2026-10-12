"""Conservative crash, sanitizer, timeout, and oracle classification."""
from __future__ import annotations

import re

from seclab.testing import TestExecutionResult

from .models import CrashAnalysis, FailureSignature


_SANITIZERS = (("AddressSanitizer", re.compile(r"AddressSanitizer: (?:ERROR: )?([A-Za-z0-9_-]+)")),
               ("UndefinedBehaviorSanitizer", re.compile(r"runtime error: ([^\n]+)")),
               ("MemorySanitizer", re.compile(r"MemorySanitizer: ([^\n]+)")) )


class CrashAnalyzer:
    def analyze(self, result: TestExecutionResult, *, no_crash_is_failure: bool = False) -> CrashAnalysis:
        command = result.command_result
        observed = result.observed
        stderr = (observed.stderr if observed else "") + (command.stderr if command else "")
        for name, pattern in _SANITIZERS:
            match = pattern.search(stderr)
            if match:
                signature = FailureSignature("SANITIZER", sanitizer=f"{name}:{match.group(1).strip()[:100]}")
                return CrashAnalysis("SANITIZER", signature, True)
        if command is None or not result.executed:
            return CrashAnalysis("NOT_EXECUTED")
        if command.timed_out:
            return CrashAnalysis("TIMEOUT", FailureSignature("TIMEOUT"), True)
        code = command.exit_code
        if observed and observed.crashed is True:
            signature = FailureSignature("ABNORMAL_TERMINATION", exit_code=code, signal=(-code if code is not None and code < 0 else None))
            return CrashAnalysis("CRASH", signature, True)
        if result.oracle_evaluation.satisfied is False:
            failed = next((item for item in result.oracle_evaluation.checks if item.evaluated and item.satisfied is False), None)
            oracle_id = failed.oracle_type.value if failed else "ORACLE"
            return CrashAnalysis("ORACLE_FAILURE", FailureSignature("ORACLE_FAILURE", oracle_id=oracle_id), True)
        if result.oracle_evaluation.satisfied is True:
            return CrashAnalysis("NORMAL_EXIT")
        if code not in {0, None}:
            allowed = command.allowed_exit_codes
            if code in allowed:
                return CrashAnalysis("NORMAL_EXIT")
            # A nonzero status alone is not an abnormal process termination.
            if no_crash_is_failure:
                return CrashAnalysis("UNEXPECTED_EXIT", FailureSignature("UNEXPECTED_EXIT", exit_code=code), True)
            return CrashAnalysis("NONZERO_EXIT")
        return CrashAnalysis("NORMAL_EXIT")
