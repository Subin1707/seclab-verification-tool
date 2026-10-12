from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from seclab.gui.main_window import MainWindow


def test_invalid_native_specification_shows_schema_diagnostic_and_recovers(tmp_path: Path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    project = tmp_path / "project"
    project.mkdir()
    bad = project / "incomplete.json"
    bad.write_text(json.dumps({"schema_version": "1.0", "id": "incomplete"}), encoding="utf-8")
    good = project / "valid.json"
    good.write_text(json.dumps({
        "schema_version": "1.0", "id": "valid", "name": "Valid",
        "states": [{"id": "S0", "initial": True}], "initial_state": "S0",
    }), encoding="utf-8")
    errors: list[str] = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args: errors.append(str(args[-1])))
    window = MainWindow()
    try:
        window.project_controller.open_project(project)
        window.session.open_project(project)
        window._set_specification(str(bad))
        app.processEvents()
        assert errors
        assert "SCHEMA_VALIDATION_FAILED" in errors[-1]
        assert "Missing required property 'name'" in errors[-1]
        assert "Unsupported specification format" not in errors[-1]
        assert "SCHEMA_VALIDATION_FAILED" in window.specification.errors.toPlainText()
        assert "at $" in window.specification.errors.toPlainText()
        assert not window.session.ready

        window._set_specification(str(good))
        app.processEvents()
        assert window.session.ready
        assert window.session.normalized_specification.id == "valid"
        assert window.project_controller.project_path == project.resolve()
    finally:
        window.close()
        app.processEvents()
