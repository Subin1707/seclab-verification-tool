"""Project and specification file operations; no verification rules live here."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from seclab.specification import LoadedSpecification, ValidatedSpecification, normalize_specification, validate_specification
import hashlib


@dataclass
class ProjectController:
    project_path: Path | None = None
    specification_path: Path | None = None
    loaded: LoadedSpecification | None = None
    specification: Any = None
    validated_specification: ValidatedSpecification | None = None
    specification_info: dict[str, Any] | None = None
    adapter: str | None = None
    raw_specification: Any = None

    def open_project(self, path: str | Path) -> Path:
        selected = Path(path).expanduser().resolve(strict=True)
        if not selected.is_dir():
            raise ValueError("Project path must be a directory")
        self.project_path = selected
        self.specification_path = None
        self.loaded = None
        self.specification = None
        self.validated_specification = None
        self.specification_info = None
        self.raw_specification = None
        self.adapter = None
        return selected

    def select_specification(self, path: str | Path) -> Path:
        selected = Path(path).expanduser().resolve(strict=True)
        if not selected.is_file():
            raise ValueError("Specification path must be a file")
        self.specification_path = selected
        self.loaded = None
        self.specification = None
        self.validated_specification = None
        self.specification_info = None
        self.raw_specification = None
        # Native Specification Core input is the default. Optional adapters must
        # be selected explicitly by an integration-aware caller after selection.
        self.adapter = None
        return selected

    def load(self) -> LoadedSpecification:
        if self.specification_path is None:
            raise ValueError("Select a specification file first")
        if self.specification_path.suffix.casefold() == ".xlsx":
            from seclab.integrations.xlsx_adapter import load_teacher_xlsx
            self.loaded, self.specification_info, self.raw_specification = load_teacher_xlsx(
                self.specification_path)
        elif self.adapter is None:
            from seclab.specification.legacy_adapter import load_compatible_specification
            self.loaded, self.specification_info, raw_documents = load_compatible_specification(
                self.specification_path)
            self.raw_specification = raw_documents[0] if len(raw_documents) == 1 else raw_documents
        elif self.adapter == "smart-ev-teacher":
            from seclab.integrations.registry import load_adapted_specification
            self.loaded, self.specification_info = load_adapted_specification(self.specification_path)
            self.raw_specification = json.loads(self.specification_path.read_text(encoding="utf-8"))
        else:
            raise ValueError(f"Unsupported explicit specification adapter: {self.adapter}")
        if self.specification_info.get("original_sha256") is None and self.loaded.documents:
            self.specification_info["original_sha256"] = self.loaded.documents[0].sha256
        return self.loaded

    def validate(self) -> LoadedSpecification:
        loaded = self.loaded or self.load()
        self.validated_specification = validate_specification(loaded)
        return loaded

    def normalize(self) -> Any:
        self.validate()
        assert self.validated_specification is not None
        self.specification = normalize_specification(self.validated_specification)
        return self.specification

    def verify_original_unchanged(self) -> bool:
        info = self.specification_info or {}
        expected = info.get("original_sha256")
        if expected is None:
            return True
        actual = hashlib.sha256(self.specification_path.read_bytes()).hexdigest()
        return actual == expected

    def preview(self) -> str:
        if self.specification_path is None:
            return ""
        if self.loaded is not None and self.loaded.documents:
            return json.dumps(self.loaded.documents[0].data, ensure_ascii=False, indent=2)
        return json.dumps(json.loads(self.specification_path.read_text(encoding="utf-8")),
                          ensure_ascii=False, indent=2)
