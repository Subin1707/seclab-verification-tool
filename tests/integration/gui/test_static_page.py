from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from seclab.gui.pages.static_page import StaticPage
from seclab.results import VerificationResult, VerificationStatus


@pytest.fixture(scope="module")
def application():
    return QApplication.instance() or QApplication([])


def test_static_page_never_renders_null_cwe_and_keeps_tool_cwe(application):
    result = VerificationResult(id="static-1", stage="STATIC_ANALYSIS", technique="compiler",
        status=VerificationStatus.INCONCLUSIVE, reason_code="STATIC_ANALYSIS_FAILED",
        message="Compiler diagnostics were reported.", evidence_ids=("ev-findings",),
        metadata={"analyzer": "compiler", "finding_ids": ["f1", "f2"]})
    report = SimpleNamespace(results=(result,), limitations=(), stage_summaries=())
    page = StaticPage()
    page._evidence_cache = {"ev-findings": (
        {"id": "f1", "severity": "UNKNOWN", "cwe": None, "file": "src/a.c", "line": 1,
         "message": "fatal error: missing header"},
        {"id": "f2", "severity": "HIGH", "cwe": "CWE-476", "file": "src/b.c", "line": 8,
         "message": "possible null dereference"},
    )}
    page.show_report(report)
    assert page.static_table.table.rowCount() == 2
    assert page.static_table.table.item(0, 5).text() == "Unclassified (tool provided no CWE)"
    assert page.static_table.table.item(0, 5).text().lower() != "null"
    assert page.static_table.table.item(1, 5).text() == "CWE-476"
    page.close()
