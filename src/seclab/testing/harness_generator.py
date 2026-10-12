"""Generate a small, data-driven C/C++ wrapper for supported scalar functions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from seclab.source.function_detector import FunctionInfo

from .errors import TestErrorCode


@dataclass(frozen=True, slots=True)
class HarnessResult:
    supported: bool
    source_path: Path | None
    source: str | None
    error_code: TestErrorCode | None = None
    message: str | None = None
    argument_names: tuple[str, ...] = ()


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INT_TYPES = {
    "char": ("signed", "CHAR_MIN", "CHAR_MAX"), "signed char": ("signed", "SCHAR_MIN", "SCHAR_MAX"),
    "unsigned char": ("unsigned", "0", "UCHAR_MAX"), "short": ("signed", "SHRT_MIN", "SHRT_MAX"),
    "short int": ("signed", "SHRT_MIN", "SHRT_MAX"), "signed short": ("signed", "SHRT_MIN", "SHRT_MAX"),
    "signed short int": ("signed", "SHRT_MIN", "SHRT_MAX"), "unsigned short": ("unsigned", "0", "USHRT_MAX"),
    "unsigned short int": ("unsigned", "0", "USHRT_MAX"), "int": ("signed", "INT_MIN", "INT_MAX"),
    "signed": ("signed", "INT_MIN", "INT_MAX"), "signed int": ("signed", "INT_MIN", "INT_MAX"),
    "unsigned": ("unsigned", "0", "UINT_MAX"), "unsigned int": ("unsigned", "0", "UINT_MAX"),
    "long": ("signed", "LONG_MIN", "LONG_MAX"), "long int": ("signed", "LONG_MIN", "LONG_MAX"),
    "signed long": ("signed", "LONG_MIN", "LONG_MAX"), "signed long int": ("signed", "LONG_MIN", "LONG_MAX"),
    "unsigned long": ("unsigned", "0", "ULONG_MAX"), "unsigned long int": ("unsigned", "0", "ULONG_MAX"),
    "long long": ("signed", "LLONG_MIN", "LLONG_MAX"), "long long int": ("signed", "LLONG_MIN", "LLONG_MAX"),
    "signed long long": ("signed", "LLONG_MIN", "LLONG_MAX"), "signed long long int": ("signed", "LLONG_MIN", "LLONG_MAX"),
    "unsigned long long": ("unsigned", "0", "ULLONG_MAX"), "unsigned long long int": ("unsigned", "0", "ULLONG_MAX"),
}


class HarnessGenerator:
    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).resolve()

    def generate(self, function: FunctionInfo, test_case_id: str) -> HarnessResult:
        def unsupported(code: TestErrorCode, message: str) -> HarnessResult:
            return HarnessResult(False, None, None, code, message)

        if function.language not in {"C", "C++"}:
            return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE, "Only C and C++ functions are supported.")
        if not _IDENT.fullmatch(function.name):
            return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE, "Function must have a simple, unmangled identifier.")
        if function.parameters is None or function.return_type is None:
            return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE, "Function signature could not be parsed safely.")
        parsed_params: list[tuple[str, str]] = []
        for declaration in function.parameters:
            parsed = _parse_parameter(declaration)
            if parsed is None:
                return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE,
                                   f"Unsupported scalar parameter declaration: {declaration!r}.")
            parsed_params.append(parsed)
        names = [name for _, name in parsed_params]
        if len(set(names)) != len(names):
            return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE, "Function parameter names must be unique.")
        return_info = _parse_return(function.return_type)
        if return_info is None:
            return unsupported(TestErrorCode.HARNESS_UNSUPPORTED_SIGNATURE,
                               f"Unsupported scalar return type: {function.return_type!r}.")
        code = _render(function.name, parsed_params, return_info)
        digest = hashlib.sha256(f"{test_case_id}\0{function.name}".encode()).hexdigest()[:16]
        directory = self.workspace_root / "harness"
        directory.mkdir(parents=True, exist_ok=True)
        extension = ".cpp" if function.language == "C++" else ".c"
        path = directory / f"harness-{digest}{extension}"
        if path.is_symlink() or not path.resolve().is_relative_to(self.workspace_root):
            return unsupported(TestErrorCode.HARNESS_PATH_CONFLICT, "Harness path escapes workspace.")
        try:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(code)
        except FileExistsError:
            try:
                if path.read_text(encoding="utf-8") != code:
                    return unsupported(TestErrorCode.HARNESS_PATH_CONFLICT, "Generated harness path already contains different content.")
            except OSError as exc:
                return unsupported(TestErrorCode.HARNESS_PATH_CONFLICT, f"Cannot verify existing harness: {exc}")
        except OSError as exc:
            return unsupported(TestErrorCode.HARNESS_PATH_CONFLICT, f"Cannot create harness source: {exc}")
        return HarnessResult(True, path, code, argument_names=tuple(names))


def _normalize_type(value: str) -> str:
    value = re.sub(r"\b(const|volatile|restrict|register|static|extern|inline)\b", " ", value)
    return " ".join(value.split())


def _parse_parameter(declaration: str) -> tuple[str, str] | None:
    if any(char in declaration for char in "*&[]()=,") or "..." in declaration:
        return None
    match = re.fullmatch(r"\s*(.*?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*", declaration)
    if not match:
        return None
    ctype, name = _normalize_type(match.group(1)), match.group(2)
    if ctype not in _INT_TYPES and ctype not in {"bool", "_Bool", "float", "double"}:
        return None
    return ctype, name


def _parse_return(declaration: str) -> tuple[str, str] | None:
    ctype = _normalize_type(declaration)
    if ctype == "void":
        return "void", "void"
    if ctype in _INT_TYPES:
        return ctype, _INT_TYPES[ctype][0]
    if ctype in {"bool", "_Bool"}:
        return ctype, "bool"
    if ctype in {"float", "double"}:
        return ctype, "real"
    return None


def _render(name: str, params: list[tuple[str, str]], returned: tuple[str, str]) -> str:
    lines = ["#include <errno.h>", "#include <float.h>", "#include <limits.h>", "#include <math.h>",
             "#include <stdbool.h>", "#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>", ""]
    signature = ", ".join(f"{ctype} {param}" for ctype, param in params) or "void"
    lines += [f"extern {returned[0]} {name}({signature});", "",
              "static int parse_signed(const char *s, long long lo, long long hi, long long *out) {",
              "  char *end = NULL; errno = 0; long long v = strtoll(s, &end, 10);",
              "  if (errno || end == s || *end || v < lo || v > hi) return 0; *out = v; return 1;", "}",
              "static int parse_unsigned(const char *s, unsigned long long hi, unsigned long long *out) {",
              "  if (*s == '-') return 0; char *end = NULL; errno = 0; unsigned long long v = strtoull(s, &end, 10);",
              "  if (errno || end == s || *end || v > hi) return 0; *out = v; return 1;", "}",
              "static int parse_real(const char *s, double lo, double hi, double *out) {",
              "  char *end = NULL; errno = 0; double v = strtod(s, &end);",
              "  if (errno || end == s || *end || !isfinite(v) || v < lo || v > hi) return 0; *out = v; return 1;", "}",
              "int main(int argc, char **argv) {", f"  if (argc != {len(params) + 1}) return 64;"]
    call_args: list[str] = []
    for index, (ctype, param) in enumerate(params, 1):
        lines.append(f"  {ctype} {param};")
        if ctype in _INT_TYPES:
            kind, lo, hi = _INT_TYPES[ctype]
            if kind == "signed":
                lines.append(f"  long long raw_{index}; if (!parse_signed(argv[{index}], (long long)({lo}), (long long)({hi}), &raw_{index})) return 65;")
            else:
                lines.append(f"  unsigned long long raw_{index}; if (!parse_unsigned(argv[{index}], (unsigned long long)({hi}), &raw_{index})) return 65;")
        elif ctype in {"bool", "_Bool"}:
            lines.append(f"  if (!strcmp(argv[{index}], \"0\")) {param} = 0; else if (!strcmp(argv[{index}], \"1\")) {param} = 1; else return 65;")
        else:
            upper = "FLT_MAX" if ctype == "float" else "DBL_MAX"
            lines.append(f"  double raw_{index}; if (!parse_real(argv[{index}], -(double){upper}, (double){upper}, &raw_{index})) return 65;")
        if ctype in _INT_TYPES:
            lines.append(f"  {param} = ({ctype})raw_{index};")
        elif ctype in {"float", "double"}:
            lines.append(f"  {param} = ({ctype})raw_{index};")
        call_args.append(param)
    call = f"{name}({', '.join(call_args)})"
    ctype, kind = returned
    if kind == "void":
        lines += [f"  {call};", "  fputs(\"SECLAB_RETURN=VOID:\\n\", stderr);"]
    elif kind == "signed":
        lines += [f"  {ctype} result = {call};", "  fprintf(stderr, \"SECLAB_RETURN=INT:%lld\\n\", (long long)result);"]
    elif kind == "unsigned":
        lines += [f"  {ctype} result = {call};", "  fprintf(stderr, \"SECLAB_RETURN=UINT:%llu\\n\", (unsigned long long)result);"]
    elif kind == "bool":
        lines += [f"  {ctype} result = {call};", "  fprintf(stderr, \"SECLAB_RETURN=BOOL:%d\\n\", result ? 1 : 0);"]
    else:
        lines += [f"  {ctype} result = {call};", "  fprintf(stderr, \"SECLAB_RETURN=REAL:%.17g\\n\", (double)result);"]
    lines += ["  return 0;", "}", ""]
    return "\n".join(lines)
