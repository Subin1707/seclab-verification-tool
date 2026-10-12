"""Small deterministic C intermediate representation used by code generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class CLine:
    text: str = ""
    element_id: str | None = None
    element_kind: str | None = None


@dataclass(frozen=True, slots=True)
class CBlock:
    lines: tuple[CLine, ...]

    @classmethod
    def of(cls, lines: Iterable[CLine | str]) -> "CBlock":
        return cls(tuple(item if isinstance(item, CLine) else CLine(item) for item in lines))


@dataclass(frozen=True, slots=True)
class CFile:
    path: str
    artifact_class: str
    blocks: tuple[CBlock, ...]


@dataclass(frozen=True, slots=True)
class CProgram:
    files: tuple[CFile, ...]

    def render(self) -> tuple[dict[str, str], dict[str, list[dict[str, object]]]]:
        """Render files and deterministic generated-line to source-element maps."""
        rendered: dict[str, str] = {}
        maps: dict[str, list[dict[str, object]]] = {}
        for file in sorted(self.files, key=lambda item: item.path):
            lines: list[str] = []
            mapping: list[dict[str, object]] = []
            for block in file.blocks:
                for line in block.lines:
                    lines.append(line.text)
                    if line.element_id is not None:
                        mapping.append({"generated_line": len(lines), "element_id": line.element_id,
                                        "element_kind": line.element_kind or "model"})
            rendered[file.path] = "\n".join(lines)
            maps[file.path] = mapping
        return rendered, maps
