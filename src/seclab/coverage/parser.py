"""Backend-specific parsers; malformed records are diagnosed without fabricated metrics."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import CoverageError, CoverageErrorCode


@dataclass(frozen=True, slots=True)
class ParsedCoverage:
    lines: dict[str, dict[int, int]]
    branches: dict[str, bool]
    diagnostics: tuple[str, ...] = ()
    functions: dict[str, int] | None = None


def parse_gcov_json(payload: str | bytes) -> ParsedCoverage:
    """Parse gcov --json-format output. Branches are gcov arcs, not LLVM regions."""
    data = _load_json(payload)
    files = data.get("files")
    if not isinstance(files, list):
        raise CoverageError(CoverageErrorCode.COVERAGE_PARSE_ERROR, "gcov JSON must contain a files array.")
    lines: dict[str, dict[int, int]] = {}
    branches: dict[str, bool] = {}
    functions: dict[str, int] = {}
    diagnostics: list[str] = []
    for file_index, item in enumerate(files):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            diagnostics.append(f"gcov files[{file_index}] has no file path")
            continue
        path = item["file"]
        records = item.get("lines", [])
        if not isinstance(records, list):
            diagnostics.append(f"gcov {path}: lines is not an array")
            continue
        line_map = lines.setdefault(path, {})
        for index, record in enumerate(records):
            if not isinstance(record, dict) or not _integer(record.get("line_number")) or not _integer(record.get("count")):
                diagnostics.append(f"gcov {path}: malformed line record {index}")
                continue
            line_map[record["line_number"]] = max(0, record["count"])
            arcs = record.get("branches", [])
            if not isinstance(arcs, list):
                diagnostics.append(f"gcov {path}:{record['line_number']}: malformed branches array")
                continue
            for arc_index, arc in enumerate(arcs):
                if not isinstance(arc, dict) or not _integer(arc.get("count")):
                    diagnostics.append(f"gcov {path}:{record['line_number']}: malformed branch {arc_index}")
                    continue
                branch_id = arc.get("branch_id", arc_index)
                block_id = arc.get("source_block_id", "")
                key = f"{path}|{record['line_number']}|{block_id}|{branch_id}"
                branches[key] = arc["count"] > 0
        records = item.get("functions", [])
        if not isinstance(records, list):
            diagnostics.append(f"gcov {path}: functions is not an array")
        else:
            for index, function in enumerate(records):
                if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                    diagnostics.append(f"gcov {path}: malformed function record {index}")
                    continue
                count = function.get("execution_count", function.get("count"))
                if not _integer(count):
                    diagnostics.append(f"gcov {path}: malformed function count {index}")
                    continue
                functions[f"{path}|{function['name']}"] = max(0, count)
    return ParsedCoverage(lines, branches, tuple(diagnostics), functions)


def parse_llvm_export(payload: str | bytes) -> ParsedCoverage:
    """Parse llvm-cov export JSON. Branch outcomes use LLVM's true/false counts."""
    data = _load_json(payload)
    datasets = data.get("data")
    if not isinstance(datasets, list):
        raise CoverageError(CoverageErrorCode.COVERAGE_PARSE_ERROR, "llvm-cov JSON must contain a data array.")
    lines: dict[str, dict[int, int]] = {}
    branches: dict[str, bool] = {}
    functions: dict[str, int] = {}
    diagnostics: list[str] = []
    for dataset_index, dataset in enumerate(datasets):
        files = dataset.get("files") if isinstance(dataset, dict) else None
        if not isinstance(files, list):
            diagnostics.append(f"llvm data[{dataset_index}] has no files array")
            continue
        for file_index, item in enumerate(files):
            if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
                diagnostics.append(f"llvm data[{dataset_index}].files[{file_index}] has no filename")
                continue
            path = item["filename"]
            line_map = lines.setdefault(path, {})
            segments = item.get("segments", [])
            if not isinstance(segments, list):
                diagnostics.append(f"llvm {path}: segments is not an array")
                segments = []
            for index, segment in enumerate(segments):
                if (not isinstance(segment, list) or len(segment) < 6 or not _integer(segment[0])
                        or not _integer(segment[2]) or not isinstance(segment[3], bool)
                        or not isinstance(segment[4], bool) or not isinstance(segment[5], bool)):
                    diagnostics.append(f"llvm {path}: malformed segment {index}")
                    continue
                line, count, has_count, region_entry, gap = segment[0], segment[2], segment[3], segment[4], segment[5]
                if region_entry and has_count and not gap:
                    line_map[line] = max(line_map.get(line, 0), count)
            records = item.get("branches", [])
            if not isinstance(records, list):
                diagnostics.append(f"llvm {path}: branches is not an array")
                records = []
            for index, branch in enumerate(records):
                if not isinstance(branch, list) or len(branch) < 5 or not _integer(branch[0]) or not _integer(branch[1]) or not _integer(branch[2]) or not _integer(branch[3]) or not _integer(branch[4]):
                    diagnostics.append(f"llvm {path}: malformed branch {index}")
                    continue
                line, column, true_count, false_count = branch[0], branch[1], branch[3], branch[4]
                key = f"{path}|{line}|{column}|{index}"
                branches[key + "|true"] = true_count > 0
                branches[key + "|false"] = false_count > 0
        function_records = dataset.get("functions", [])
        if not isinstance(function_records, list):
            diagnostics.append(f"llvm data[{dataset_index}]: functions is not an array")
            continue
        for index, function in enumerate(function_records):
            if not isinstance(function, dict) or not isinstance(function.get("name"), str) or not _integer(function.get("count")):
                diagnostics.append(f"llvm data[{dataset_index}]: malformed function record {index}")
                continue
            filenames = function.get("filenames", [])
            if not isinstance(filenames, list) or not filenames or any(not isinstance(name, str) for name in filenames):
                diagnostics.append(f"llvm data[{dataset_index}]: function {function['name']!r} has invalid filenames")
                continue
            for filename in filenames:
                functions[f"{filename}|{function['name']}"] = max(0, function["count"])
    return ParsedCoverage(lines, branches, tuple(diagnostics), functions)


def parse_gcov_text(payload: str | bytes) -> ParsedCoverage:
    """Parse gcov's documented line/branch listing for older GCC versions."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    lines: dict[str, dict[int, int]] = {}
    branches: dict[str, bool] = {}
    functions: dict[str, int] = {}
    diagnostics: list[str] = []
    current_file = ""
    current_line: int | None = None
    line_pattern = re.compile(r"^\s*([0-9]+\*?|#+|=+|-):\s*(\d+):")
    branch_pattern = re.compile(r"^\s*branch\s+(\d+)\s+(.*)$")
    for index, record in enumerate(payload.splitlines()):
        if record.startswith("        -:    0:Source:") or re.match(r"^\s*-:\s*0:Source:", record):
            current_file = record.split("Source:", 1)[1].strip()
            lines.setdefault(current_file, {})
            continue
        match = line_pattern.match(record)
        if match:
            raw_count, raw_line = match.groups()
            current_line = int(raw_line)
            if raw_count != "-":
                count_match = re.match(r"\d+", raw_count)
                count = int(count_match.group()) if count_match else 0
                lines.setdefault(current_file, {})[current_line] = count
            continue
        branch = branch_pattern.match(record)
        if branch:
            if not current_file or current_line is None:
                diagnostics.append(f"gcov text: branch record {index} has no preceding source line")
                continue
            branch_index, details = branch.groups()
            taken = re.search(r"\btaken\s+(\d+)", details)
            never = "never executed" in details.lower()
            if taken is None and not never:
                percent = re.search(r"\btaken\s+(\d+(?:\.\d+)?)%", details)
                if percent is None:
                    diagnostics.append(f"gcov text {current_file}:{current_line}: malformed branch record {index}")
                    continue
                covered = float(percent.group(1)) > 0
            else:
                covered = taken is not None and int(taken.group(1)) > 0
            branches[f"{current_file}|{current_line}|{branch_index}"] = covered
    return ParsedCoverage(lines, branches, tuple(diagnostics), functions)


def parse_gcov_function_summary(payload: str | bytes, source_path: str) -> ParsedCoverage:
    """Parse gcov -f summary output, recording whether each function executed."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    functions: dict[str, int] = {}
    current: str | None = None
    for line in payload.splitlines():
        found = re.match(r"^Function ['\"](.+?)['\"]$", line.strip())
        if found:
            current = found.group(1)
            continue
        summary = re.match(r"^Lines executed:([0-9]+(?:\.[0-9]+)?)%", line.strip())
        if current is not None and summary:
            functions[f"{source_path}|{current}"] = int(float(summary.group(1)) > 0)
            current = None
    return ParsedCoverage({}, {}, (), functions)


def _load_json(payload: str | bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise CoverageError(CoverageErrorCode.COVERAGE_PARSE_ERROR, f"Invalid coverage JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CoverageError(CoverageErrorCode.COVERAGE_PARSE_ERROR, "Coverage JSON root must be an object.")
    return value


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
