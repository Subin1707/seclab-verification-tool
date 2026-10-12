"""Recognize only known sanitizer report signatures; unknown text yields no finding."""

from __future__ import annotations

import re
from collections.abc import Callable

from .memory_finding import MemoryFinding, make_memory_finding


_ASAN_PATTERNS = (
    ("heap-buffer-overflow", "HEAP_BUFFER_OVERFLOW"),
    ("stack-buffer-overflow", "STACK_BUFFER_OVERFLOW"),
    ("global-buffer-overflow", "GLOBAL_BUFFER_OVERFLOW"),
    ("heap-use-after-free", "HEAP_USE_AFTER_FREE"),
    ("stack-use-after-return", "STACK_USE_AFTER_RETURN"),
    ("double-free", "DOUBLE_FREE"),
    ("attempting double-free", "DOUBLE_FREE"),
    ("bad-free", "INVALID_FREE"),
    ("attempting free on address", "INVALID_FREE"),
    ("alloc-dealloc-mismatch", "ALLOC_DEALLOC_MISMATCH"),
    ("use-after-poison", "USE_AFTER_POISON"),
    ("container-overflow", "CONTAINER_OVERFLOW"),
    ("stack-overflow", "STACK_OVERFLOW"),
    ("detected memory leaks", "MEMORY_LEAK"),
)
_UBSAN_PATTERNS = (
    ("signed integer overflow", "SIGNED_INTEGER_OVERFLOW"),
    ("division by zero", "DIVISION_BY_ZERO"),
    ("shift exponent", "INVALID_SHIFT"),
    ("shift base", "INVALID_SHIFT"),
    ("misaligned address", "ALIGNMENT_VIOLATION"),
    ("insufficient space for an object", "OUT_OF_BOUNDS_ACCESS"),
    ("index .* out of bounds", "OUT_OF_BOUNDS_ACCESS"),
    ("runtime error:", "UNDEFINED_BEHAVIOR"),
)
_UB_LOCATION = re.compile(r"^(.*?):(\d+):(\d+):\s*runtime error:\s*(.*)$")
_ASAN_LOCATION = re.compile(r"#\d+\s+.*?\s+in\s+([^\s]+).*?(?:\s|^)(.*?):(\d+)(?::\d+)?(?:\s|$)")
_ADDRESS = re.compile(r"(?:on address|address)\s+(0x[0-9a-fA-F]+)")


def parse_asan_output(output: str, *, raw_evidence: str | None = None,
                      id_factory: Callable[[], str] | None = None) -> tuple[MemoryFinding, ...]:
    lower = output.lower()
    recognized = [(token, kind) for token, kind in _ASAN_PATTERNS if token in lower]
    if not recognized:
        return ()
    token, kind = recognized[0]
    first = next((line.strip() for line in output.splitlines() if token in line.lower()), token)
    function = file = None
    line_no = None
    frames: list[str] = []
    for line in output.splitlines():
        if line.lstrip().startswith("#"):
            frames.append(line.strip())
            loc = _ASAN_LOCATION.search(line)
            if loc and file is None:
                function, file, line_no = loc.group(1), loc.group(2), int(loc.group(3))
    address_match = _ADDRESS.search(output)
    finding = make_memory_finding(tool="AddressSanitizer", kind=kind, message=first,
                                  file=_normalize_path(file), line=line_no, function=function,
                                  address=address_match.group(1) if address_match else None,
                                  failure_site=f"{file}:{line_no}" if file and line_no else None,
                                  stack_trace=tuple(frames), raw_evidence=raw_evidence,
                                  metadata={"report_signature": token})
    if id_factory:
        from dataclasses import replace
        finding = replace(finding, id=id_factory())
    return (finding,)


def parse_ubsan_output(output: str, *, raw_evidence: str | None = None,
                       id_factory: Callable[[], str] | None = None) -> tuple[MemoryFinding, ...]:
    findings: list[MemoryFinding] = []
    for line in output.splitlines():
        if "runtime error:" not in line.lower():
            continue
        match = _UB_LOCATION.match(line.strip())
        message = match.group(4) if match else line.strip()
        lower = message.lower()
        kind = next((mapped for token, mapped in _UBSAN_PATTERNS if token in lower), "UNDEFINED_BEHAVIOR")
        item = make_memory_finding(
            tool="UndefinedBehaviorSanitizer", kind=kind, message=message,
            file=_normalize_path(match.group(1)) if match else None,
            line=int(match.group(2)) if match else None,
            failure_site=(f"{match.group(1)}:{match.group(2)}" if match else None),
            raw_evidence=raw_evidence, metadata={"report_signature": "runtime error"},
        )
        if id_factory:
            from dataclasses import replace
            item = replace(item, id=id_factory())
        findings.append(item)
    return tuple(findings)


def _normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("\\", "/")
    if len(normalized) > 1 and normalized[1] == ":":
        normalized = normalized[0].upper() + normalized[1:]
    return normalized
