"""Shared non-editable result and evidence inspection widgets."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QPlainTextEdit, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)


class ReadOnlyTable(QTableWidget):
    def __init__(self, headers: tuple[str, ...], parent=None) -> None:
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.horizontalHeader().setStretchLastSection(True)

    def set_records(self, records: list[tuple[Any, ...]] | tuple[tuple[Any, ...], ...]) -> None:
        self.setUpdatesEnabled(False)
        try:
            self.setRowCount(len(records))
            self._populate_records(records, 0)
        finally:
            self.setUpdatesEnabled(True)
            self.viewport().update()

    def append_records(self, records: list[tuple[Any, ...]] | tuple[tuple[Any, ...], ...]) -> None:
        if not records:
            return
        self.setUpdatesEnabled(False)
        try:
            first_row = self.rowCount()
            self.setRowCount(first_row + len(records))
            self._populate_records(records, first_row)
        finally:
            self.setUpdatesEnabled(True)
            self.viewport().update()

    def _populate_records(self, records: list[tuple[Any, ...]] | tuple[tuple[Any, ...], ...],
                          first_row: int) -> None:
        for offset, values in enumerate(records):
            for column, value in enumerate(values):
                display = _display(value)
                item = QTableWidgetItem(display)
                item.setToolTip(display)
                self.setItem(first_row + offset, column, item)


class DetailDialog(QDialog):
    def __init__(self, title: str, payload: Any, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        viewer = QPlainTextEdit(self)
        viewer.setReadOnly(True)
        viewer.setPlainText(_display(payload))
        layout.addWidget(viewer)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("Đóng")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class EvidenceViewer(DetailDialog):
    """Read-only viewer; opens text/JSON only from a validated run artifact path."""
    def __init__(self, evidence: Any, path: Path | None, parent=None) -> None:
        payload: dict[str, Any] = {
            "evidence_id": evidence.get("id", ""), "type": evidence.get("type", ""),
            "path": evidence.get("path", ""), "sha256": evidence.get("hash", ""),
            "size_bytes": evidence.get("size_bytes", ""), "stage": evidence.get("stage", ""),
            "checker": evidence.get("checker", ""), "run_id": evidence.get("run_id", ""),
            "source": evidence.get("source", ""), "created_time": evidence.get("timestamp", ""),
            "metadata": evidence.get("metadata", {}),
        }
        if path is not None:
            payload["content"] = path.read_text(encoding="utf-8", errors="replace") if path.suffix.lower() in {".txt", ".json", ".log", ".gcov", ".c", ".h"} else "Binary evidence; metadata only."
            payload["size_bytes"] = path.stat().st_size
        super().__init__(f"Bằng chứng kiểm chứng (Evidence) · {evidence.get('id', '')}", payload, parent)


def _display(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)
    except (TypeError, ValueError):
        return str(value)
