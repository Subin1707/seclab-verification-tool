"""Deterministic, read-only discovery and hashing of C/C++ source files."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .errors import SourceError, SourceErrorCode

SUPPORTED_EXTENSIONS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"})


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: Path
    relative_path: str
    extension: str
    language_hint: str
    size_bytes: int
    sha256: str


class SourceLoader:
    def __init__(self, *, include: Iterable[str] | None = None,
                 exclude: Iterable[str] = (".git", ".workspace", "build", "dist", "evidence",
                     ".runtime", ".runs", "runs", "generated", ".generated", ".venv", "venv",
                     "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                     ".tmp*"),
                 follow_symlinks: bool = False) -> None:
        self.include = tuple(include) if include is not None else ("**/*", "*")
        self.exclude = tuple(exclude)
        self.follow_symlinks = follow_symlinks

    def load_source_tree(self, source_root: str | Path) -> tuple[SourceFile, ...]:
        root = Path(source_root).expanduser()
        if not root.exists() or not root.is_dir():
            raise SourceError(SourceErrorCode.SOURCE_ROOT_NOT_FOUND, f"Source root '{root}' does not exist or is not a directory.")
        try:
            root = root.resolve(strict=True)
        except OSError as exc:
            raise SourceError(SourceErrorCode.SOURCE_ACCESS_ERROR, f"Cannot resolve source root: {exc}") from exc
        found: list[SourceFile] = []
        visited_directories: set[Path] = set()
        def on_walk_error(error: OSError) -> None:
            raise SourceError(SourceErrorCode.SOURCE_ACCESS_ERROR, f"Cannot traverse source tree: {error}") from error

        for current, dirs, files in os.walk(root, followlinks=self.follow_symlinks, onerror=on_walk_error):
            current_path = Path(current)
            try:
                resolved_current = current_path.resolve(strict=True)
            except (OSError, RuntimeError):
                dirs[:] = []
                continue
            if not resolved_current.is_relative_to(root) or resolved_current in visited_directories:
                dirs[:] = []
                continue
            visited_directories.add(resolved_current)
            kept_dirs = []
            for dirname in sorted(dirs):
                candidate = current_path / dirname
                relative = candidate.relative_to(root).as_posix()
                if self._excluded(relative, dirname):
                    continue
                if candidate.is_symlink():
                    if not self.follow_symlinks:
                        continue
                    try:
                        resolved = candidate.resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    if not resolved.is_relative_to(root):
                        continue
                kept_dirs.append(dirname)
            dirs[:] = kept_dirs
            for filename in sorted(files):
                candidate = current_path / filename
                relative = candidate.relative_to(root).as_posix()
                if self._excluded(relative, filename) or not self._included(relative):
                    continue
                if candidate.suffix.lower() not in SUPPORTED_EXTENSIONS:
                    continue
                if candidate.is_symlink():
                    if not self.follow_symlinks:
                        continue
                    try:
                        resolved = candidate.resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    if not resolved.is_relative_to(root):
                        continue
                try:
                    resolved = candidate.resolve(strict=True)
                    if not resolved.is_relative_to(root) or not resolved.is_file():
                        continue
                    content = resolved.read_bytes()
                except (OSError, RuntimeError) as exc:
                    raise SourceError(SourceErrorCode.SOURCE_ACCESS_ERROR, f"Cannot read source '{relative}': {exc}") from exc
                if b"\x00" in content:
                    continue
                found.append(SourceFile(
                    path=resolved, relative_path=relative, extension=candidate.suffix.lower(),
                    language_hint=_language_hint(candidate.suffix.lower()), size_bytes=len(content),
                    sha256=hashlib.sha256(content).hexdigest(),
                ))
        return tuple(sorted(found, key=lambda item: item.relative_path.casefold()))

    def _included(self, relative: str) -> bool:
        from pathlib import PurePosixPath
        path = PurePosixPath(relative)
        return any(path.match(pattern) for pattern in self.include)

    def _excluded(self, relative: str, basename: str) -> bool:
        from pathlib import PurePosixPath
        path = PurePosixPath(relative)
        return any(path.match(pattern) or basename == pattern or path.match(f"**/{pattern}/**")
                   for pattern in self.exclude)


def load_source_tree(source_root: str | Path, **options: object) -> tuple[SourceFile, ...]:
    return SourceLoader(**options).load_source_tree(source_root)


def _language_hint(extension: str) -> str:
    return "C" if extension == ".c" else "C++" if extension in {".cc", ".cpp", ".cxx"} else "HEADER"
