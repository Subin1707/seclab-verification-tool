"""Generate probe-only function sources from explicit, normalized function metadata.

This is an opt-in capability generator. It never reads names to select semantics;
implementations are dispatched by the declared (language, kind) pair.
"""
from __future__ import annotations

import keyword
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from seclab.codegen.ir import CBlock, CFile, CLine, CProgram


@dataclass(frozen=True, slots=True)
class FunctionSourceArtifacts:
    files: Mapping[str, str]
    line_maps: Mapping[str, list[dict[str, object]]]
    functions: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()
    test_cases: tuple[dict[str, Any], ...] = ()


class FunctionSourceGenerator:
    """Generate only semantics described by a registered language/kind handler."""

    def generate(self, records: Sequence[Mapping[str, Any]], *, test_cases: Sequence[Any] = ()) -> FunctionSourceArtifacts:
        functions: list[dict[str, Any]] = []
        c_rows: list[tuple[Mapping[str, Any], list[str]]] = []
        py_rows: list[tuple[Mapping[str, Any], list[str]]] = []
        warnings: list[str] = []
        for raw in sorted(records, key=lambda item: str(item.get("function_id", item.get("id", "")))):
            row = dict(raw)
            try:
                name = str(row.get("name", ""))
                language = str(row.get("language", "")).casefold()
                kind = str(row.get("kind", "")).casefold()
                params = _parameters(row)
                if language == "c":
                    _c_identifier(name, role="function")
                    for param in params:
                        _c_identifier(param, role="parameter")
                    body = _c_handler(kind)(row, params)
                    c_rows.append((row, body))
                elif language == "python":
                    _python_identifier(name, role="function")
                    for param in params:
                        _python_identifier(param, role="parameter")
                    body = _python_handler(kind)(row, params)
                    py_rows.append((row, body))
                else:
                    raise UnsupportedFunctionSource(f"Unsupported source language: {language or 'missing'}")
                functions.append(_function_row(row, "GENERATED", None))
            except (UnsupportedFunctionSource, ValueError, TypeError) as exc:
                message = str(exc)
                functions.append(_function_row(row, "UNSUPPORTED", message))
                warnings.append(f"{row.get('function_id', row.get('name', 'unknown'))}: {message}")

        files: dict[str, str] = {}
        line_maps: dict[str, list[dict[str, object]]] = {}
        c_cases: tuple[dict[str, Any], ...] = ()
        skipped_cases: tuple[dict[str, Any], ...] = ()
        if c_rows:
            c_cases, skipped_cases = _resolve_c_test_cases(c_rows, test_cases)
            c_files, c_maps = _render_c(c_rows, c_cases)
            files.update(c_files)
            line_maps.update(c_maps)
        elif test_cases:
            skipped_cases = tuple({"test_id": str(_get(item, "id", "")),
                "status": "UNSUPPORTED", "reason": "No generated C function target is declared."}
                for item in test_cases)
        if py_rows:
            py_files, py_maps = _render_python(py_rows)
            files.update(py_files)
            line_maps.update(py_maps)
        return FunctionSourceArtifacts(files, line_maps, tuple(functions), tuple(warnings),
            tuple((*c_cases, *skipped_cases)))


class UnsupportedFunctionSource(ValueError):
    """A declared function cannot be rendered by the registered generator."""


def _c_handler(kind: str) -> Callable[[Mapping[str, Any], tuple[str, ...]], list[str]]:
    return {"buffer_copy": _c_buffer_copy, "alloc_release": _c_alloc_release}.get(
        kind, _unsupported_kind("C", kind))


def _python_handler(kind: str) -> Callable[[Mapping[str, Any], tuple[str, ...]], list[str]]:
    return {"divide": _python_divide, "magic_value": _python_magic_value}.get(
        kind, _unsupported_kind("Python", kind))


def _unsupported_kind(language: str, kind: str):
    def fail(_row: Mapping[str, Any], _params: tuple[str, ...]) -> list[str]:
        raise UnsupportedFunctionSource(f"Unsupported {language} function kind: {kind or 'missing'}")
    return fail


def _c_buffer_copy(row: Mapping[str, Any], params: tuple[str, ...]) -> list[str]:
    if len(params) != 1:
        raise UnsupportedFunctionSource("buffer_copy requires exactly one declared source parameter")
    size = _positive_size(row)
    bug = _bug(row)
    operation = str(row.get("operation", "")).casefold()
    if bug not in {None, "buffer-overflow"}:
        raise UnsupportedFunctionSource(f"Unsupported buffer_copy vulnerability tag: {bug}")
    if operation and operation not in {"strncpy", "strcpy", "snprintf", "sprintf"}:
        raise UnsupportedFunctionSource(f"Unsupported buffer_copy operation: {operation}")
    if bug == "buffer-overflow" and operation in {"strncpy", "snprintf"}:
        raise UnsupportedFunctionSource("Declared buffer overflow conflicts with an explicitly bounded operation")
    if bug is None and operation in {"strcpy", "sprintf"}:
        raise UnsupportedFunctionSource("Unsafe copy operation requires an explicit vulnerability declaration")
    source = params[0]
    unsafe = bug == "buffer-overflow" or operation in {"strcpy", "sprintf"}
    if operation in {"snprintf", "sprintf"}:
        call = f'    {operation}(buffer, ' + ("" if operation == "sprintf" else "sizeof(buffer), ") + f'"%s", {source});'
    elif unsafe:
        call = f"    strcpy(buffer, {source});"
    else:
        call = (f"    strncpy(buffer, {source}, sizeof(buffer) - 1u);",
                "    buffer[sizeof(buffer) - 1u] = '\\0';")
    rows = [f"void {row['name']}(const char *{source}) {{", f"    char buffer[{size}];",
            *([call] if isinstance(call, str) else list(call)), '    printf("%s\\n", buffer);', "}"]
    return rows


def _c_alloc_release(row: Mapping[str, Any], params: tuple[str, ...]) -> list[str]:
    if params:
        raise UnsupportedFunctionSource("alloc_release currently requires no declared parameters")
    count = _positive_size(row)
    bug = _bug(row)
    if bug not in {None, "memory-leak", "double-free", "use-after-free"}:
        raise UnsupportedFunctionSource(f"Unsupported alloc_release vulnerability tag: {bug}")
    rows = [f"void {row['name']}(void) {{", f"    int *buf = malloc(sizeof(int) * {count}u);",
            "    if (buf == NULL) return;", "    buf[0] = 0;"]
    if bug == "memory-leak":
        rows.append("    /* Intentional probe behavior: allocation is not released. */")
    elif bug == "double-free":
        rows += ["    free(buf);", "    free(buf); /* Intentional double-free probe. */"]
    elif bug == "use-after-free":
        rows += ["    free(buf);", "    buf[0] = 1; /* Intentional use-after-free probe. */"]
    else:
        rows.append("    free(buf);")
    rows.append("}")
    return rows


def _python_divide(_row: Mapping[str, Any], params: tuple[str, ...]) -> list[str]:
    if len(params) != 2:
        raise UnsupportedFunctionSource("divide requires exactly two declared parameters")
    return [f"def {_row['name']}({', '.join(params)}):", f"    return {params[0]} // {params[1]}"]


def _python_magic_value(row: Mapping[str, Any], params: tuple[str, ...]) -> list[str]:
    if len(params) != 2:
        raise UnsupportedFunctionSource("magic_value requires exactly two declared parameters")
    values = row.get("magic_values")
    if (not isinstance(values, (tuple, list)) or len(values) != 2
            or any(isinstance(value, bool) or not isinstance(value, (int, float, str)) for value in values)):
        raise UnsupportedFunctionSource("magic_value requires two declared scalar magic_values")
    first, second = (repr(value) for value in values)
    message = repr(str(row.get("exception_message", "magic value reached")))
    return [f"def {row['name']}({', '.join(params)}):", f"    if {params[0]} == {first}:",
            f"        if {params[1]} == {second}:", f"            raise ValueError({message})",
            f"    return {params[0]} + {params[1]}"]


def _render_c(rows: Sequence[tuple[Mapping[str, Any], list[str]]], test_cases=()):
    includes = CBlock.of(("/* GENERATED_ARTIFACT · PROBE_ONLY · production_source=false */",
        "#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>", ""))
    function_blocks = []
    header_lines = [CLine("/* GENERATED_ARTIFACT · PROBE_ONLY · production_source=false */"),
                    CLine("#ifndef SECLAB_GENERATED_FUNCTIONS_H"), CLine("#define SECLAB_GENERATED_FUNCTIONS_H"), ""]
    for row, body in rows:
        fid = str(row.get("function_id", row.get("id", row["name"])))
        class_name = str(row.get("probe_class", "TOOL_CAPABILITY_EVIDENCE"))
        vulnerability = row.get("expected_vulnerability", row.get("bug"))
        cwe = _expected_cwe(row)
        comments = [CLine("/*", fid, "function"),
            CLine(" * Generated by SecLab generic function generator; GENERATED_ARTIFACT.", fid, "function"),
            CLine(f" * Function ID: {_comment(fid)}; probe class: {_comment(class_name)}; production_source=false.", fid, "function"),
            CLine(f" * Requirement IDs: {_comment(', '.join(str(item) for item in row.get('requirement_ids', ())) or 'none')}.", fid, "function"),
            CLine(f" * Source location: {_comment(str(row.get('source_location') or 'not declared'))}.", fid, "function"),
            CLine(f" * Kind: {_comment(str(row.get('kind', '')))}; expected vulnerability: {_comment(str(vulnerability or 'none'))}.", fid, "function"),
            CLine(f" * Expected CWE mapping (not a checker finding): {_comment(', '.join(cwe) or 'unmapped')}.", fid, "function"),
            CLine(" */", fid, "function")]
        function_blocks.append(CBlock(tuple(comments + [CLine(line, fid, "function") for line in body] + [CLine("")])))
        params = tuple(row.get("parameters", row.get("params", ())))
        signature = (f"void {row['name']}(const char *{params[0]});" if str(row.get("kind")) == "buffer_copy"
                     else f"void {row['name']}(void);")
        header_lines.append(CLine(signature, fid, "function"))
    header_lines.extend([CLine(""), CLine("#endif")])
    c_program = CProgram((CFile("source/generated_functions.c", "GENERATED_ARTIFACT", (includes, *function_blocks)),
        CFile("include/generated_functions.h", "GENERATED_ARTIFACT", (CBlock.of(header_lines),)),
        CFile("include/generated_api.h", "GENERATED_ARTIFACT", (CBlock.of(header_lines),))))
    files, maps = c_program.render()
    files["source/generated_functions.c"] += "\n"
    files["include/generated_functions.h"] += "\n"
    files["include/generated_api.h"] += "\n"
    harness = _c_harness(rows)
    files["tests/generated_functions_main.c"] = harness
    # Stable generic name for downstream test, sanitizer, coverage and fuzz
    # adapters. Keep the historical filename as a compatibility artifact.
    files["tests/generated_harness.c"] = harness
    maps["tests/generated_functions_main.c"] = [
        {"generated_line": index, "element_id": str(row.get("function_id", row.get("id", row["name"]))),
         "element_kind": "function_dispatch"} for index, (row, _) in enumerate(rows, start=14)]
    maps["tests/generated_harness.c"] = list(maps["tests/generated_functions_main.c"])
    test_driver = _c_test_driver(rows, test_cases)
    files["source/generated_test_driver.c"] = test_driver
    driver_lines = test_driver.splitlines()
    driver_map = []
    for item in test_cases:
        marker = _c_literal(item["test_id"])
        start = next((index for index, line in enumerate(driver_lines, start=1)
                      if f'strcmp(argv[1], "{marker}")' in line), None)
        end = next((index for index, line in enumerate(driver_lines, start=1)
                    if f'TEST_COMPLETED:{marker}' in line), None)
        if start is not None:
            driver_map.append({"generated_line": start, "element_id": item["test_id"],
                "element_kind": "test_case_start"})
        if end is not None:
            driver_map.append({"generated_line": end, "element_id": item["test_id"],
                "element_kind": "test_case_end"})
    maps["source/generated_test_driver.c"] = driver_map
    return files, maps


def _c_harness(rows: Sequence[tuple[Mapping[str, Any], list[str]]], test_cases=()) -> str:
    lines = ["/* GENERATED_ARTIFACT · TEST_HARNESS · PROBE_ONLY · production_source=false */",
        '#include "../include/generated_functions.h"', "#include <stdio.h>", "#include <string.h>", "",
        "int main(int argc, char **argv) {", "    if (argc == 2 && strcmp(argv[1], \"--list\") == 0) {"]
    lines += [f'        puts("{row["name"]}");' for row, _ in rows]
    lines += ["        return 0;", "    }", "    if (argc < 2) {", '        fputs("function name required\\n", stderr);', "        return 64;", "    }"]
    for row, _ in rows:
        name = str(row["name"])
        params = tuple(row.get("parameters", row.get("params", ())))
        if str(row.get("kind")) == "buffer_copy":
            lines += [f'    if (strcmp(argv[1], "{name}") == 0) {{',
                '        if (argc != 3) { fputs("one string argument required\\n", stderr); return 64; }',
                f"        {name}(argv[2]);"]
        else:
            lines += [f'    if (strcmp(argv[1], "{name}") == 0) {{',
                      '        if (argc != 2) { fputs("no arguments accepted\\n", stderr); return 64; }',
                      f"        {name}();"]
        lines += [f'        printf("{{\\\"function\\\":\\\"{name}\\\",\\\"invoked\\\":true}}\\n");',
                  "        return 0;", "    }"]
    lines += ['    fputs("unknown function\\n", stderr);', "    return 64;", "}", ""]
    return "\n".join(lines)


def _c_test_driver(rows: Sequence[tuple[Mapping[str, Any], list[str]]], test_cases=()) -> str:
    """Render a driver whose runnable cases come only from normalized tests."""
    lines = ['/* GENERATED_ARTIFACT · TEST_HARNESS · PROBE_ONLY · production_source=false */',
        '#include "../include/generated_api.h"', "#include <stdio.h>", "#include <string.h>", "",
        "int main(int argc, char **argv) {", "    if (argc == 2 && strcmp(argv[1], \"--list-tests\") == 0) {"]
    lines.extend(f'        puts("{_c_literal(item["test_id"])}");' for item in test_cases)
    lines.extend(["        return 0;", "    }", "    if (argc < 2) {",
        '        fputs("test ID required\\n", stderr);', "        return 64;", "    }"])
    for item in test_cases:
        function = item["function"]
        name = str(function["name"])
        params = tuple(function.get("parameters", function.get("params", ())))
        test_id = _c_literal(item["test_id"])
        lines.append(f'    if (strcmp(argv[1], "{test_id}") == 0) {{')
        if params:
            lines.extend(['        if (argc != 3) { fputs("one string argument required\\n", stderr); return 64; }',
                          f"        {name}(argv[2]);"])
        else:
            lines.extend(['        if (argc != 2) { fputs("no arguments accepted\\n", stderr); return 64; }',
                          f"        {name}();"])
        lines.extend([f'        puts("TEST_COMPLETED:{test_id}");', "        return 0;", "    }"])
    lines.extend(['    fputs("unknown test ID\\n", stderr);', "    return 64;", "}", ""])
    return "\n".join(lines)


def _render_python(rows: Sequence[tuple[Mapping[str, Any], list[str]]]):
    lines = ["# GENERATED_ARTIFACT · PROBE_ONLY · production_source=false", ""]
    mapping: list[dict[str, object]] = []
    for row, body in rows:
        start = len(lines) + 1
        fid = str(row.get("function_id", row.get("id", row["name"])))
        lines.extend([f"# Function ID: {fid}; kind: {row.get('kind')}; expected vulnerability: "
                      f"{row.get('expected_vulnerability', row.get('bug')) or 'none'}; production_source=false"])
        lines.extend(body)
        end = len(lines)
        mapping.append({"function_id": fid, "function_name": row["name"],
                        "start_line": start + 1, "end_line": end, "element_kind": "function"})
        lines.append("")
    main_lines = ["# GENERATED_ARTIFACT · TEST_HARNESS · PROBE_ONLY · production_source=false",
        "import json", "import sys", "from generated_functions import ("]
    main_lines.extend(f"    {row['name']}," for row, _ in rows)
    main_lines += [")", "", "FUNCTIONS = {"]
    main_lines.extend(f"    {row['name']!r}: {row['name']}," for row, _ in rows)
    main_lines += ["}", "", "def main(argv=None):", "    argv = list(sys.argv[1:] if argv is None else argv)",
        "    if argv == ['--list']:", "        print(json.dumps(sorted(FUNCTIONS)))", "        return 0",
        "    if len(argv) != 2:", "        print('expected function name and JSON argument array', file=sys.stderr)",
        "        return 64", "    function = FUNCTIONS.get(argv[0])", "    if function is None:",
        "        print('unknown function', file=sys.stderr)", "        return 64", "    try:",
        "        arguments = json.loads(argv[1])", "        if not isinstance(arguments, list):",
        "            raise ValueError('input must be a JSON array')", "        result = function(*arguments)",
        "    except Exception as exc:",
        "        print(json.dumps({'exception_type': type(exc).__name__, 'message': str(exc)}), file=sys.stderr)",
        "        return 1", "    print(json.dumps({'return_value': result}, sort_keys=True))", "    return 0", "",
        "if __name__ == '__main__':", "    raise SystemExit(main())", ""]
    return {"python/generated_functions.py": "\n".join(lines).rstrip() + "\n",
        "python/generated_functions_main.py": "\n".join(main_lines)}, {
        "python/generated_functions.py": mapping,
        "python/generated_functions_main.py": [
            {"generated_line": index, "element_id": str(row.get("function_id", row.get("id", row["name"]))),
             "element_kind": "function_dispatch"} for index, (row, _) in enumerate(rows, start=1)]}


def _function_row(row: Mapping[str, Any], status: str, reason: str | None) -> dict[str, Any]:
    cwe = _expected_cwe(row)
    bug = row.get("expected_vulnerability", row.get("bug"))
    params = tuple(row.get("parameters", row.get("params", ())))
    parameter_specs = [{"name": name,
        "type": "const char *" if str(row.get("language", "")).casefold() == "c"
            and str(row.get("kind", "")).casefold() == "buffer_copy" else "int *"}
        for name in params]
    return {"function_id": str(row.get("function_id", row.get("id", ""))),
        "name": str(row.get("name", "")), "language": str(row.get("language", "")).casefold(),
        "kind": str(row.get("kind", "")), "status": status, "reason": reason,
        "return_type": "void" if str(row.get("language", "")).casefold() == "c" else None,
        "parameter_specs": parameter_specs,
        "body_specification": {"kind": str(row.get("kind", "")), "supported": status == "GENERATED"},
        "generated_path": (("source/generated_functions.c" if str(row.get("language", "")).casefold() == "c"
                            else "python/generated_functions.py" if str(row.get("language", "")).casefold() == "python" else None)
                           if status == "GENERATED" else None),
        "probe_class": row.get("probe_class", "TOOL_CAPABILITY_EVIDENCE"),
        "source_class": "GENERATED_ARTIFACT", "artifact_class": "GENERATED_ARTIFACT", "production_source": False,
        "generated": True,
        "source_kind": "BUG_INJECTED_PROBE" if bug else "TOOL_CAPABILITY_EVIDENCE",
        "requirement_ids": sorted(set(str(value) for value in row.get("requirement_ids", ()))),
        "mapping_status": ("DECLARED" if row.get("requirement_ids") else "NOT_DECLARED"),
        "parameters": list(row.get("parameters", row.get("params", ()))),
        "declared_metadata": {key: row[key] for key in (
            "buffer_size", "allocation_count", "bug", "operation", "magic_values", "cwe_ids") if key in row},
        "source_location": row.get("source_location"), "expected_vulnerability": bug,
        "expected_cwe_ids": cwe, "expected_cwe": cwe[0] if len(cwe) == 1 else None,
        "cwe_mapping_basis": "declared probe kind/vulnerability; not a checker finding" if cwe else None}


def _expected_cwe(row: Mapping[str, Any]) -> list[str]:
    declared = row.get("cwe_ids", ())
    if isinstance(declared, (tuple, list)) and all(
            isinstance(item, str) and re.fullmatch(r"CWE-[0-9]+", item) for item in declared):
        if declared:
            return sorted(set(declared))
    language, kind, bug = (str(row.get("language", "")).casefold(),
        str(row.get("kind", "")).casefold(), _bug(row))
    mapping = {("c", "buffer_copy", "buffer-overflow"): "CWE-121",
        ("c", "alloc_release", "memory-leak"): "CWE-401",
        ("c", "alloc_release", "double-free"): "CWE-415",
        ("c", "alloc_release", "use-after-free"): "CWE-416",
        ("python", "divide", None): "CWE-369",
        ("python", "magic_value", None): "CWE-798"}
    value = mapping.get((language, kind, bug))
    return [value] if value else []


def _bug(row: Mapping[str, Any]) -> str | None:
    value = row.get("expected_vulnerability", row.get("bug"))
    return None if value in (None, "", False) else str(value).casefold()


def _resolve_c_test_cases(rows, test_cases: Sequence[Any]):
    functions = {str(row.get("function_id", row.get("id", ""))): row for row, _body in rows}
    runnable: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for test in test_cases:
        test_id = str(_get(test, "id", ""))
        function_id = str(_get(test, "function_id", "") or "")
        function = functions.get(function_id)
        if not test_id or function is None:
            skipped.append({"test_id": test_id, "function_id": function_id,
                "status": "UNSUPPORTED", "reason": "Test case does not target a generated C function."})
            continue
        input_data = _get(test, "input", {})
        input_data = dict(input_data) if isinstance(input_data, Mapping) else {}
        raw_args = input_data.get("args", input_data.get("arguments", ()))
        params = tuple(function.get("parameters", function.get("params", ())))
        if isinstance(raw_args, Mapping):
            values = tuple(raw_args[name] for name in params) if set(raw_args) == set(params) else ()
        elif isinstance(raw_args, (tuple, list)):
            values = tuple(raw_args)
        else:
            values = (raw_args,) if raw_args != () else ()
        if len(params) == 0 and len(values) == 0 and function.get("kind") == "alloc_release":
            runnable.append({"test_id": test_id, "function_id": function_id,
                "function": function, "arguments": [], "expected": _get(test, "expected", None),
                "status": "GENERATED",
                "requirement_ids": list(_get(test, "requirement_ids", ()))})
        elif (len(params) == 1 and function.get("kind") == "buffer_copy" and len(values) == 1
              and isinstance(values[0], str)):
            runnable.append({"test_id": test_id, "function_id": function_id,
                "function": function, "arguments": [values[0]], "expected": _get(test, "expected", None),
                "status": "GENERATED",
                "requirement_ids": list(_get(test, "requirement_ids", ()))})
        else:
            skipped.append({"test_id": test_id, "function_id": function_id,
                "status": "UNSUPPORTED", "reason": f"Thiếu test input tương thích cho function {function_id}."})
    return tuple(runnable), tuple(skipped)


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _c_literal(value: Any) -> str:
    text = str(value)
    if any(ord(char) < 0x20 for char in text):
        raise UnsupportedFunctionSource("Test IDs and function names cannot contain control characters")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _positive_size(row: Mapping[str, Any]) -> int:
    value = row.get("buffer_size", row.get("allocation_count"))
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_000_000:
        raise UnsupportedFunctionSource("A positive bounded buffer_size/allocation_count is required")
    return value


def _parameters(row: Mapping[str, Any]) -> tuple[str, ...]:
    values = row.get("parameters", row.get("params", ()))
    if not isinstance(values, (tuple, list)) or any(not isinstance(item, str) for item in values):
        raise UnsupportedFunctionSource("Function parameters must be a list of identifiers")
    return tuple(values)


def _c_identifier(value: str, *, role: str) -> None:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) or value in _C_KEYWORDS:
        raise UnsupportedFunctionSource(f"Invalid C {role} identifier: {value!r}")


def _python_identifier(value: str, *, role: str) -> None:
    if not value.isidentifier() or keyword.iskeyword(value):
        raise UnsupportedFunctionSource(f"Invalid Python {role} identifier: {value!r}")


def _comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\r", " ").replace("\n", " ")


_C_KEYWORDS = frozenset("auto break case char const continue default do double else enum extern float for goto if int long register return short signed sizeof static struct switch typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local".split())
