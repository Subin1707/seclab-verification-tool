"""AddressSanitizer build and runtime report adapter."""

from .parsers import parse_asan_output
from .sanitizer import Sanitizer


class ASanRunner(Sanitizer):
    name = "AddressSanitizer"
    flags = ("-g", "-fsanitize=address", "-fno-omit-frame-pointer")
    parser = staticmethod(parse_asan_output)
    violation_reason = "MEMORY_SAFETY_VIOLATION"


AddressSanitizerRunner = ASanRunner
