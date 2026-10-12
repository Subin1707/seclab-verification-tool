"""SMT-backed BMC over finite explicit Kripke structures."""

from .checker import BMCCheckResult, BMCChecker
from .completeness import CompletenessAnalysis, analyze_completeness
from .encoder import BMCEncodedQuery, BMCEncoder, BMCQueryMode
from .errors import BMCError, BMCErrorCode
from .trace import BMCTrace, TraceStep, TraceTransition, decode_trace

__all__ = [
    "BMCCheckResult", "BMCChecker", "BMCEncodedQuery", "BMCEncoder", "BMCError", "BMCErrorCode",
    "BMCQueryMode", "BMCTrace", "CompletenessAnalysis", "TraceStep", "TraceTransition",
    "analyze_completeness", "decode_trace",
]
