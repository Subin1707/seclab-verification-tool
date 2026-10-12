"""Conservative lexical discovery of top-level C/C++ function definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .source_loader import SourceFile


@dataclass(frozen=True, slots=True)
class FunctionInfo:
    name: str
    file: str
    line: int
    return_type: str | None
    parameters: tuple[str, ...] | None
    language: str


_CONTROL = {"if", "for", "while", "switch", "catch", "sizeof", "alignof", "decltype", "return"}
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


class FunctionDetector:
    def detect(self, sources: Iterable[SourceFile | str | Path]) -> tuple[FunctionInfo, ...]:
        found: list[FunctionInfo] = []
        for source in sources:
            path = source.path if isinstance(source, SourceFile) else Path(source)
            display = source.relative_path if isinstance(source, SourceFile) else path.as_posix()
            extension = path.suffix.lower()
            language = "C" if extension == ".c" else "C++" if extension in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"} else "UNKNOWN"
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found.extend(_scan_functions(text, display, language))
        return tuple(sorted(found, key=lambda item: (item.file, item.line, item.name)))


def detect_functions(sources: Iterable[SourceFile | str | Path]) -> tuple[FunctionInfo, ...]:
    return FunctionDetector().detect(sources)


def _mask_comments_and_literals(text: str) -> str:
    chars = list(text)
    # Preprocessor directives and macros are not function definitions. Mask whole
    # logical directive lines, including backslash continuations.
    offset = 0
    continued_directive = False
    for line in text.splitlines(keepends=True):
        is_directive = line.lstrip().startswith("#") or continued_directive
        if is_directive:
            for pos in range(offset, offset + len(line)):
                if chars[pos] != "\n":
                    chars[pos] = " "
        continued_directive = is_directive and line.rstrip("\r\n").rstrip().endswith("\\")
        offset += len(line)
    i, n, state = 0, len(chars), "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/": state = "line_comment"; chars[i] = chars[i + 1] = " "; i += 2; continue
            if c == "/" and nxt == "*": state = "block_comment"; chars[i] = chars[i + 1] = " "; i += 2; continue
            if c == '"': state = "string"; chars[i] = " "; i += 1; continue
            if c == "'": state = "char"; chars[i] = " "; i += 1; continue
        elif state == "line_comment":
            if c == "\n": state = "code"
            else: chars[i] = " "
        elif state == "block_comment":
            if c == "*" and nxt == "/": chars[i] = chars[i + 1] = " "; i += 2; state = "code"; continue
            if c != "\n": chars[i] = " "
        else:
            if c == "\\" and i + 1 < n:
                if c != "\n": chars[i] = " "
                if text[i + 1] != "\n": chars[i + 1] = " "
                i += 2; continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"): state = "code"
            if c != "\n": chars[i] = " "
        i += 1
    return "".join(chars)


def _scan_functions(text: str, filename: str, language: str) -> list[FunctionInfo]:
    code = _mask_comments_and_literals(text)
    results: list[FunctionInfo] = []
    depth = 0
    segment_start = 0
    paren_depth = bracket_depth = 0
    i = 0
    while i < len(code):
        c = code[i]
        if c == "(": paren_depth += 1
        elif c == ")": paren_depth = max(0, paren_depth - 1)
        elif c == "[": bracket_depth += 1
        elif c == "]": bracket_depth = max(0, bracket_depth - 1)
        elif c == "{" and depth == 0:
            signature = code[segment_start:i].strip()
            parsed = _parse_signature(signature)
            if parsed:
                name, return_type, parameters = parsed
                signature_offset = next((pos for pos in range(segment_start, i) if not code[pos].isspace()), segment_start)
                line = text.count("\n", 0, signature_offset) + 1
                results.append(FunctionInfo(name, filename, line, return_type, parameters, language))
            depth = 1
        elif c == "{" and depth > 0:
            depth += 1
        elif c == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                segment_start = i + 1
        elif c == ";" and depth == 0:
            segment_start = i + 1
        i += 1
    return results


def _parse_signature(signature: str) -> tuple[str, str | None, tuple[str, ...] | None] | None:
    value = re.sub(r"(?m)^\s*#.*$", " ", signature).strip()
    if not value or value.startswith(("extern \"C\"", "namespace ", "class ", "struct ", "union ", "enum ", "template", "using ")):
        return None
    close = value.rfind(")")
    if close < 0:
        return None
    level = 0
    open_pos = -1
    for pos in range(close, -1, -1):
        if value[pos] == ")": level += 1
        elif value[pos] == "(":
            level -= 1
            if level == 0: open_pos = pos; break
    if open_pos < 0:
        return None
    prefix = value[:open_pos].rstrip()
    match = _IDENT.search(prefix[::-1])
    if not match:
        return None
    end = len(prefix) - match.start()
    start = end - match.end()
    name = prefix[start:end]
    if name in _CONTROL or not _IDENT.fullmatch(name):
        return None
    # Exclude member calls / expressions where the declarator has no plausible type.
    return_type = prefix[:start].strip()
    if not return_type or return_type.endswith((".", "->", "return", "new", "delete", "=")):
        return None
    if "=" in return_type or "?" in return_type:
        return None
    params_text = value[open_pos + 1:close].strip()
    if not params_text or params_text == "void":
        parameters: tuple[str, ...] = ()
    else:
        parts = _split_parameters(params_text)
        if parts is None:
            parameters = None
        else:
            parameters = tuple(parts)
    return name, return_type, parameters


def _split_parameters(value: str) -> list[str] | None:
    parts: list[str] = []
    start = depth_angle = depth_paren = depth_bracket = 0
    for i, char in enumerate(value):
        if char == "<": depth_angle += 1
        elif char == ">": depth_angle = max(0, depth_angle - 1)
        elif char == "(": depth_paren += 1
        elif char == ")": depth_paren -= 1
        elif char == "[": depth_bracket += 1
        elif char == "]": depth_bracket -= 1
        elif char == "," and depth_angle == depth_paren == depth_bracket == 0:
            parts.append(value[start:i].strip()); start = i + 1
    parts.append(value[start:].strip())
    return parts if all(parts) else None
