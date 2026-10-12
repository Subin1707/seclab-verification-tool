"""Read one or more UTF-8 JSON specification documents from disk."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import SpecificationError, SpecificationErrorCode


@dataclass(frozen=True, slots=True)
class SourceDocument:
    """Parsed document paired with the path it came from."""

    source: Path
    data: Any
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class LoadedSpecification:
    """Raw input documents; merging and validation happen in later layers."""

    documents: tuple[SourceDocument, ...]


def load_specification(paths: str | Path | Iterable[str | Path]) -> LoadedSpecification:
    """Load a combined specification or a deterministically ordered fragment set."""
    if isinstance(paths, (str, Path)):
        path_list = [Path(paths)]
    else:
        path_list = [Path(path) for path in paths]
    if not path_list:
        raise ValueError("At least one specification path must be provided")

    # Sorting makes multi-file diagnostics and merge behavior independent of the
    # caller's iterable order. Relative paths are retained for actionable errors.
    ordered_paths = sorted(path_list, key=lambda path: str(path))
    documents: list[SourceDocument] = []
    for path in ordered_paths:
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except FileNotFoundError as exc:
            raise SpecificationError(
                SpecificationErrorCode.FILE_NOT_FOUND,
                "Specification file does not exist.",
                source=path,
            ) from exc
        except IsADirectoryError as exc:
            raise SpecificationError(
                SpecificationErrorCode.FILE_NOT_FOUND,
                "Specification path is a directory, not a file.",
                source=path,
            ) from exc
        except OSError as exc:
            raise SpecificationError(
                SpecificationErrorCode.FILE_READ_ERROR,
                f"Cannot read specification file: {exc}",
                source=path,
            ) from exc
        except UnicodeDecodeError as exc:
            raise SpecificationError(
                SpecificationErrorCode.INVALID_JSON,
                f"File is not valid UTF-8: {exc}",
                source=path,
            ) from exc

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecificationError(
                SpecificationErrorCode.INVALID_JSON,
                f"Invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno}).",
                source=path,
                location=f"line {exc.lineno}, column {exc.colno}",
            ) from exc
        documents.append(SourceDocument(path, data, hashlib.sha256(raw).hexdigest()))
    return LoadedSpecification(tuple(documents))
