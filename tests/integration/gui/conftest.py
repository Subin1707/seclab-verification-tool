from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_gui_run_workspace(tmp_path, monkeypatch):
    """Keep GUI tests independent from the user's persistent run history."""
    monkeypatch.setenv("SECLAB_WORKSPACE", str(tmp_path / "gui-run-workspace"))
