"""UndefinedBehaviorSanitizer build and runtime report adapter."""

from .parsers import parse_ubsan_output
from .sanitizer import Sanitizer


class UBSanRunner(Sanitizer):
    name = "UndefinedBehaviorSanitizer"
    flags = ("-g", "-fsanitize=undefined")
    parser = staticmethod(parse_ubsan_output)
    violation_reason = "UNDEFINED_BEHAVIOR_DETECTED"


UndefinedBehaviorSanitizerRunner = UBSanRunner
