"""Leak detection with an explicit platform support boundary."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from seclab.results import ClassificationInput, RawOutcome, ResultClassifier
from seclab.source import Language, SourceFile
from seclab.static_analysis.analyzer import AnalysisContext

from .asan_runner import ASanRunner
from .sanitizer import SanitizerRunResult


class LeakChecker:
    """Uses LeakSanitizer through ASan only on Linux, where this runtime is supported."""

    def run(self, source_collection: Sequence[SourceFile], context: AnalysisContext, language: Language | str,
            *, result_id: str | None = None, **options: object) -> SanitizerRunResult:
        if not sys.platform.startswith("linux"):
            diagnostic = context.artifact_store.write_json("sanitizer", "leak-detection-unavailable.json", {
                "sanitizer": "LeakSanitizer", "supported": False, "platform": sys.platform,
                "reason_code": "LEAK_DETECTION_UNAVAILABLE",
            })
            result = ResultClassifier().classify(ClassificationInput(
                RawOutcome.UNKNOWN, "SANITIZER", "LEAK_CHECKER",
                "Leak detection is unavailable on this platform.", "LEAK_DETECTION_UNAVAILABLE",
                scope="Leak detection was not run because this platform's support was not established.",
                evidence_ids=(diagnostic.id,),
                metadata={"capability_status": "ENVIRONMENT_LIMITED", "environment_limited": True},
            ), result_id=result_id)
            return SanitizerRunResult("LeakSanitizer", None, None, (), (diagnostic,), False,
                                      (f"LeakSanitizer is not declared supported on {sys.platform}.",), result)
        env = dict(options.pop("env", {}) or {})
        env["ASAN_OPTIONS"] = _append_option(env.get("ASAN_OPTIONS", ""), "detect_leaks=1")
        runner = ASanRunner()
        runner.name = "LeakSanitizer"
        result = runner.run(source_collection, context, language, env=env, result_id=result_id, **options)
        if not result.supported and result.verification_result.reason_code == "SANITIZER_UNAVAILABLE":
            from dataclasses import replace
            verification = replace(result.verification_result, reason_code="LEAK_DETECTION_UNAVAILABLE",
                                  message="LeakSanitizer instrumentation or runtime is unavailable.")
            return replace(result, verification_result=verification,
                           limitations=(*result.limitations, "Leak detection could not be established by the installed toolchain."))
        return result


def _append_option(existing: str, option: str) -> str:
    parts = [item for item in existing.split(":") if item]
    key = option.split("=", 1)[0]
    parts = [item for item in parts if item.split("=", 1)[0] != key]
    parts.append(option)
    return ":".join(parts)
