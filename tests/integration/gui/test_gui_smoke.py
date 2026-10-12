"""Offscreen Qt construction/navigation smoke; not a manual desktop workflow."""
from __future__ import annotations

import os
import json
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtTest import QSignalSpy
from PySide6.QtCore import QThread

from seclab.gui.main_window import MainWindow
from seclab.gui.main_window import _RunWorker
from seclab.gui.pages.report_page import ReportPage
from seclab.gui.pages.sections import AccuracyPage
from seclab.gui.pages.source_page import SourcePage
from seclab.results import VerificationResult, VerificationStatus
from seclab.pipeline import PipelineOptions


@pytest.fixture(scope="module")
def application():
    instance = QApplication.instance() or QApplication([])
    yield instance


def test_qapplication_main_window_sidebar_and_controller_initialization(application):
    window = MainWindow()
    try:
        window.show()
        application.processEvents()
        assert window.isVisible()
        assert window.project_controller.project_path is None
        assert window.verification_controller.project_controller is window.project_controller
        assert window.navigation.count() == len(window.PAGE_NAMES)
        assert window.navigation.count() == 18
        assert window.navigation.currentItem().text() == "Dự án"
        assert window.requirements.requirements.columnCount() == 7
        assert window.stages.items.count() == 14
        assert not window.project_start.isEnabled()
        assert window.model.graph_view.scene() is window.model.graph_scene
        assert window.model.export_button.text() == "Xuất mô hình"
        assert not window.dashboard.start_verification.isEnabled()
        assert window.settings_page.settings().to_pipeline_options().specification_paths == ()
        options = window.settings_page.settings().to_pipeline_options()
        assert not hasattr(options, "run_accuracy")
        assert not hasattr(options, "source_model_target")
        assert window.session.workflow_step("BUILD_SPECIFICATION_MODEL")["status"] == "NOT_RUN"
        assert "không tạo kết luận" in window.report_page.description.text()
        assert window.report_page.open_accuracy_report.text() == "Mở báo cáo bộ đánh giá (Benchmark) / độ chính xác"
        assert "Bộ đánh giá (Benchmark) / Độ chính xác" in [window.report_page.tabs.tabText(i)
                                           for i in range(window.report_page.tabs.count())]
        for index, name in enumerate(window.PAGE_NAMES):
            window.navigation.setCurrentRow(index)
            application.processEvents()
            assert window.pages.currentWidget() is window._navigation_widgets[index]
            assert window.navigation.currentItem().text() == name
        assert window.report_page.accuracy_disclaimer.isVisible() or window.report_page.accuracy_tab.isHidden()
    finally:
        window.close()
        application.processEvents()


def test_accuracy_page_shows_fixture_metrics_from_json_and_markdown(application):
    page = AccuracyPage()
    try:
        page.show_report(SimpleNamespace())
        assert page.table.rowCount() == 1
        assert page.table.item(0, 0).text() == "UNSUPPORTED"
        report = {"benchmark_count": 2, "checker_metrics": {
            "CTL": {"TP": 1, "TN": 1, "FP": 0, "FN": 0, "accuracy": 1.0,
                    "precision": 1.0, "recall": 1.0, "metrics_ready": True}}}
        page.show_accuracy_report("benchmark.json", json.dumps(report))
        assert page.table.rowCount() == 1
        assert page.table.item(0, 0).text() == "CTL"
        assert "benchmark_count" not in page.table.item(0, 1).text()
        assert "2 fixture" in page.description.text()

        markdown = "| Checker | TP | TN | FP | FN | Accuracy | Precision | Recall |\n|---|---:|---:|---:|---:|---:|---:|---:|\n| CTL | 1 | 1 | 0 | 0 | 100% | 100% | 100% |"
        page.show_accuracy_report("benchmark.md", markdown)
        assert page.table.rowCount() == 1
        assert "100%" in page.table.item(0, 1).text()
    finally:
        page.close()


def test_accuracy_page_renders_executed_benchmark_results(application):
    page = AccuracyPage()
    try:
        page.set_benchmark_running()
        assert not page.run_button.isEnabled()
        page.show_benchmark_result({"benchmark_count": 2, "mismatches": ["CASE-2"],
            "checker_metrics": {"CTL": {"TP": 1, "TN": 0, "FP": 0, "FN": 0,
                "accuracy": None, "metrics_ready": False}},
            "expected_vs_actual": [{"case_id": "CASE-1"}, {"case_id": "CASE-2"}]},
            "benchmark-report.json")
        assert page.run_button.isEnabled()
        assert page.table.rowCount() == 1
        assert page.table.item(0, 0).text() == "CTL"
        assert "2 fixture" in page.description.text()
        assert "1 sai khác" in page.description.text()
    finally:
        page.close()


def test_model_page_renders_exportable_real_graph_data(application, tmp_path, monkeypatch):
    from seclab.gui.pages.model_page import ModelPage

    page = ModelPage()
    model = {"model_id": "MODEL-test", "model_hash": "hash", "specification_hash": "spec-hash",
        "states": [{"id": "A", "labels": ["ready"], "initial": True},
                   {"id": "B", "labels": ["done"], "initial": False}],
        "transitions": [{"id": "T", "source": "A", "target": "B", "action": "advance"}],
        "initial_states": ["A"], "reachable_state_ids": ["A", "B"],
        "unreachable_state_ids": [], "deadlock_state_ids": ["B"],
        "statistics": {"reachable_state_count": 2, "unreachable_state_count": 0,
                       "deadlock_state_count": 1}}
    now = datetime.now(timezone.utc)
    report = SimpleNamespace(stage_summaries=({"stage_id": "MODEL", "status": "COMPLETED",
                                               "output": model},))
    page.show_report(report, model)
    assert len(page.graph_scene.items()) >= 4
    assert "MODEL-test" in page.description.text()
    target = tmp_path / "model.json"
    monkeypatch.setattr("seclab.gui.pages.model_page.QFileDialog.getSaveFileName",
                        lambda *args: (str(target), "JSON model (*.json)"))
    page.export_model()
    exported = json.loads(target.read_text(encoding="utf-8"))
    assert exported["model_id"] == "MODEL-test"
    assert exported["specification_hash"] == "spec-hash"
    page.close()


def test_model_page_expands_long_state_labels_inside_their_nodes(application):
    from PySide6.QtWidgets import QGraphicsPathItem, QGraphicsTextItem
    from seclab.gui.pages.model_page import ModelPage

    page = ModelPage()
    state_id = "unreachable_req_auth_01_violation"
    labels = ["req_auth_01_violation", "smart_ev_v2", "unreachable_violation_witness"]
    page.show_specification_preview({
        "states": [{"id": "root", "labels": [], "initial": True},
                   {"id": state_id, "labels": labels, "initial": False}],
        "transitions": [], "initial_states": ["root"],
        "reachable_state_ids": ["root"], "unreachable_state_ids": [state_id],
        "deadlock_state_ids": [],
    })

    node = next(item for item in page.graph_scene.items()
                if isinstance(item, QGraphicsPathItem) and item.toolTip().startswith(state_id + "\n"))
    node_rect = node.sceneBoundingRect()
    text_items = [item for item in page.graph_scene.items()
                  if isinstance(item, QGraphicsTextItem) and item.toolTip().startswith(state_id + "\n")]
    assert len(text_items) == 2
    for item in text_items:
        text_rect = item.sceneBoundingRect()
        assert node_rect.contains(text_rect)
    assert node_rect.height() > 100
    assert all(label in node.toolTip() for label in labels)
    assert any(isinstance(item, QGraphicsTextItem) and "CHƯA TỚI" in item.toPlainText()
               for item in page.graph_scene.items())
    page.close()


def test_report_filters_evidence_traceability_history_and_source_projection(application):
    page = ReportPage()
    now = datetime.now(timezone.utc)
    results = (
        VerificationResult("R-PASS", "FORMAL", "CTL", VerificationStatus.PASS, "PROVED", "holds",
            property_id="P-1", evidence_ids=("EV-1",), metadata={"severity": "LOW"}),
        VerificationResult("R-FAIL", "DYNAMIC_TEST", "TEST_ORACLE", VerificationStatus.FAIL,
            "ORACLE_MISMATCH", "oracle mismatch", evidence_ids=("EV-2",),
            metadata={"test_case_id": "T-2", "severity": "HIGH"}),
    )
    report = SimpleNamespace(
        run_id="run-gui", duration_seconds=1.25, start_time=now, end_time=now,
        specification_info={"id": "generic-spec"}, status_counts={"PASS": 1, "FAIL": 1},
        evidence_manifest={"path": "evidence/manifest/run-manifest.json"}, results=results,
        stage_summaries=({"stage_id": "CTL", "status": "COMPLETED", "finished_at": now.isoformat()},
                         {"stage_id": "DYNAMIC", "status": "COMPLETED", "finished_at": now.isoformat()}),
        traceability={"REQ-1": {"targets": {"T-2": {"status": "CHECKED", "results": ["R-FAIL"],
            "evidence_ids": ["EV-2"]}}}}, limitations=("bounded fixture",),
        metadata={"source_inventory": {"files": ({"source_id": "SRC-1", "project_relative_path": "src/a.c",
            "before_sha256": "a" * 64, "after_sha256": "a" * 64, "changed_during_run": False,
            "function_ids": ["F-1"], "requirement_ids": ["REQ-1"], "analysis_results": []},),
            "functions": ({"name": "check", "file": "src/a.c"},)},
            "source_integrity": ({"changed_during_run": False},)},
    )
    page.show_report(report)
    assert results[0].status is VerificationStatus.PASS
    assert results[1].status is VerificationStatus.FAIL
    page.set_accuracy_report("verification-accuracy.md", "# Accuracy\nPer-checker metrics")
    assert "Per-checker metrics" in page.accuracy_report.toPlainText()
    page.stage_filter.setCurrentText("DYNAMIC")
    page.status_filter.setCurrentIndex(page.status_filter.findData("FAIL"))
    assert page.results_table.rowCount() == 1
    assert page.results_table.item(0, 2).text() == "T-2"
    assert page.results_table.item(0, 3).text() == "KHÔNG ĐẠT (FAIL)"
    assert page.results_table.item(0, 4).text() == "HIGH"
    assert page.results_table.item(0, 5).text() == now.isoformat()
    assert page.results_table.item(0, 6).text() == "1"
    page.set_evidence(({"id": "EV-2", "type": "LOG", "path": "evidence/test/log.txt",
        "hash": "b" * 64, "source": "test-runner", "created_at": now.isoformat(), "size_bytes": 12},))
    assert page.evidence_table.item(0, 0).text() == "EV-2"
    assert page.evidence_table.item(0, 2).text() == "test-runner"
    assert page.evidence_table.item(0, 5).text() == "b" * 64
    assert results[1].evidence_ids == ("EV-2",)
    opened = QSignalSpy(page.evidenceActivated)
    page.evidence_table.selectRow(0)
    page.open_evidence.click()
    assert opened.count() == 1 and opened.at(0)[0] == "EV-2"
    assert page.trace_table.item(0, 0).text() == "REQ-1"
    assert page.trace_table.item(0, 1).text() == "T-2"
    assert "src/a.c" in page.trace_table.item(0, 4).text()
    page.set_history(({"run_id": "run-gui", "timestamp": now.isoformat(), "project": "generic",
        "specification": "generic-spec", "stage_statuses": {"CTL": "COMPLETED"}},))
    assert page.history_table.columnCount() == 7
    assert page.history_table.item(0, 0).text() == "run-gui"
    assert "CTL" in page.history_table.item(0, 4).text()
    source = SourcePage()
    source.show_report(report)
    assert source.table.item(0, 0).text() == "src/a.c"
    assert source.table.item(0, 3).text().endswith('UNCHANGED)')
    assert source.table.item(0, 4).text() == "check"
    page.close()


def test_traceability_marks_broken_references(application):
    page = ReportPage()
    now = datetime.now(timezone.utc)
    report = SimpleNamespace(run_id="run-broken", duration_seconds=0, start_time=now, end_time=now,
        specification_info={}, status_counts={}, evidence_manifest={}, results=(), stage_summaries=(),
        traceability={"REQ-X": {"targets": {"P-X": {"status": "CHECKED", "results": ["missing-result"],
            "evidence_ids": ["missing-evidence"]}}}}, limitations=(), metadata={})
    page.show_report(report)
    assert "BROKEN LINK" in page.trace_table.item(0, 2).text()
    page.close()


def test_pipeline_worker_runs_off_gui_thread(application, tmp_path):
    observed = {}
    expected_report = object()

    class Controller:
        def run_full(self, _workspace, *, options, cancellation_event, progress_callback):
            observed["thread_id"] = threading.get_ident()
            progress_callback({"stage_id": "CTL", "status": "COMPLETED"})
            return expected_report

    thread = QThread()
    worker = _RunWorker(Controller(), tmp_path, None, PipelineOptions(), threading.Event())
    worker.moveToThread(thread)
    returned = []
    worker.succeeded.connect(returned.append)
    worker.finished.connect(thread.quit)
    worker.finished.connect(worker.deleteLater)
    thread.started.connect(worker.run)
    gui_thread_id = threading.get_ident()
    thread.start()
    deadline = time.monotonic() + 5
    while thread.isRunning() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)
    thread.wait(1000)
    application.processEvents()
    assert not thread.isRunning()
    assert observed["thread_id"] != gui_thread_id
    assert returned == [expected_report]


def test_real_generic_c_project_runs_through_gui_workflow(application, tmp_path):
    project = tmp_path / "generic-c-project"
    project.mkdir()
    (project / "calculator.c").write_text(
        "int add(int left, int right) { return left + right; }\n", encoding="utf-8")
    specification = tmp_path / "generic-spec.json"
    specification.write_text(json.dumps({
        "schema_version": "1.0", "id": "GUI-GENERIC", "name": "Generic GUI smoke",
        "initial_state": "READY", "states": [{"id": "READY", "labels": ["safe"]}],
        "requirements": [{"id": "REQ-ADD", "description": "Addition returns the sum."}],
        "properties": [{"id": "PROP-SAFE", "logic": "CTL", "formula": "AG(safe)"}],
        "functions": [{"id": "FUNC-ADD", "name": "add"}],
        "tests": [{"id": "TEST-ADD", "function_id": "FUNC-ADD", "requirement_ids": ["REQ-ADD"],
                   "input": {"args": {"left": 20, "right": 22}},
                   "expected": {"return_value": 42}}],
    }), encoding="utf-8")
    window = MainWindow()
    try:
        window.project_controller.open_project(project)
        window.session.open_project(project)
        window._workspace = tmp_path / "runs"
        window.session.workspace = window._workspace
        window.settings_page.analyzers.setText("")
        window.settings_page.memory.setChecked(False)
        window.settings_page.coverage.setChecked(False)
        window._set_specification(str(specification))
        assert window.session.ready
        assert window.session.workflow_step("LOAD_SPECIFICATION")["status"] == "COMPLETED"
        assert window.session.workflow_step("VALIDATE")["status"] == "COMPLETED"
        assert window.session.workflow_step("NORMALIZE")["status"] == "COMPLETED"
        # The production UI requests an explicit model review; acknowledge it in
        # this offscreen integration test without bypassing its real workflow.
        original_question = QMessageBox.question
        QMessageBox.question = staticmethod(lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
        try:
            window._run_full()
        finally:
            QMessageBox.question = original_question
        deadline = time.monotonic() + 90
        while window._thread is not None and time.monotonic() < deadline:
            application.processEvents()
            time.sleep(0.01)
        application.processEvents()
        assert window._thread is None, "GUI verification worker did not finish within 90 seconds"
        report = window.session.report
        assert report is not None
        assert next(item for item in report.results if item.property_id == "PROP-SAFE").status.value == "PASS"
        assert next(item for item in report.results
                    if item.metadata.get("test_case_id") == "TEST-ADD").status.value == "PASS"
        assert window.evidence_page.table.rowCount() > 0
        assert window.results_page.table.rowCount() >= 2
        assert window.traceability_page.table.rowCount() > 0
        assert "overall_verdict" not in report.to_dict() and "overall_status" not in report.to_dict()
        assert window.session.workflow_step("VIEW_REPORT")["status"] == "COMPLETED"
        assert window.session.workflow_step("SAVE_RUN_HISTORY")["status"] == "COMPLETED"
        assert window.session.workflow_step("VIEW_ACCURACY")["status"] == "NOT_RUN"
        run_root = tmp_path / "runs" / report.run_id
        assert (run_root / "evidence/report/pipeline-report.json").is_file()
        assert (run_root / "evidence/manifest/run-manifest.json").is_file()
        evidence_id = window.session.evidence[0]["id"]
        window.verification_controller.report = report
        window.verification_controller.workspace = tmp_path / "runs"
        assert window.verification_controller.verify_evidence(evidence_id)["status"] == "VERIFIED"
    finally:
        window.close()
        application.processEvents()


def test_gui_model_preview_uses_only_specification_states(application, tmp_path):
    project = tmp_path / "source-model-project"
    project.mkdir()
    (project / "target.c").write_text("int step(int value) { int next = value + 1; return next; }\n", encoding="utf-8")
    specification = tmp_path / "source-model-spec.json"
    specification.write_text(json.dumps({
        "schema_version": "1.0", "id": "GUI-SOURCE-MODEL", "name": "Source model GUI",
        "functions": [{"id": "FUNC-STEP", "name": "step", "file": "target.c"}],
    }), encoding="utf-8")
    window = MainWindow()
    try:
        window.project_controller.open_project(project)
        window.session.open_project(project)
        window._workspace = tmp_path / "runs"
        window.session.workspace = window._workspace
        window._set_specification(str(specification))
        window._build_review_model()
        assert window.session.model["preview_status"] == "NOT_APPLICABLE"
        assert window.session.model["states"] == ()
        assert "no state-machine elements" in window.session.model["reason"]
        assert window.session.workflow_step("BUILD_SPECIFICATION_MODEL")["status"] == "NOT_APPLICABLE"
    finally:
        window.close()
        application.processEvents()

