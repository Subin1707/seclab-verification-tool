"""Shared semantic results and classification."""

from .classifier import (
    ClassificationInput, RawOutcome, ResultClassifier, classify_ctl_error,
    classify_ctl_result,
)
from .errors import ResultError, ResultErrorCode
from .result import VerificationResult
from .result_collector import ResultCollector
from .status import VerificationStatus

__all__ = [
    "ClassificationInput", "RawOutcome", "ResultClassifier", "ResultCollector",
    "ResultError", "ResultErrorCode", "VerificationResult", "VerificationStatus",
    "classify_ctl_error", "classify_ctl_result",
]
