from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from seclab.gui.main_window import MainWindow
from seclab.pipeline import TraceabilityIndex


ROOT = Path(__file__).resolve().parents[3]
PROJECT = ROOT / "examples" / "generic-final-e2e"
STAGES = {"SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN", "BUILD", "STATIC",
          "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "CROSS_CHECK", "REPORT"}


def test_generic_project_runs_full_gui_workflow_without_reloading_inputs(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    project = PROJECT.resolve()
    workspace = tmp_path / "runs"
    try:
        window.project_controller.open_project(project)
        window.session.open_project(project)
        window._workspace = workspace
        window.session.workspace = workspace
        window.settings_page.analyzers.setText("compiler, cppcheck, clang-tidy, clang-static")
        window.settings_page.memory.setChecked(True)
        window.settings_page.coverage.setChecked(True)
        window.settings_page.coverage_backend.setCurrentIndex(
            window.settings_page.coverage_backend.findData("auto"))
        assert not hasattr(window.settings_page, "generate_c_model")
        window.settings_page.fuzz_enabled.setChecked(True)
        window.settings_page.fuzz_strategy.setCurrentIndex(window.settings_page.fuzz_strategy.findData("BLACKBOX"))
        window.settings_page.fuzz_iterations.setValue(4)
        window.settings_page.fuzz_timeout.setValue(2)
        window.settings_page.fuzz_seed.setValue(20261007)
        window.settings_page.fuzz_input_size.setValue(64)
        window.settings_page.fuzz_seeds.setPlainText(json.dumps([
            {"id": "seed-zero", "data": {"argv": ["0"]}, "kind": "SCALARS", "origin": "SEED"},
            {"id": "seed-three", "data": {"argv": ["3"]}, "kind": "SCALARS", "origin": "SEED"},
        ]))
        window._set_specification(str(PROJECT / "specification.json"))
        assert window.session.ready
        assert window.project_controller.project_path == project
        assert window.project_controller.specification_path == (PROJECT / "specification.json").resolve()

        window._run_full()
        assert window._thread is not None, f"GUI worker did not start; logs={window.log_view.toPlainText()}"

        deadline = time.monotonic() + 180
        while window._thread is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()
        assert window._thread is None, "Full GUI pipeline did not finish within three minutes"
        report = window.session.report
        assert report is not None
        assert window.project_controller.project_path == project
        assert window.project_controller.specification_path == (PROJECT / "specification.json").resolve()
        summaries = {row["stage_id"]: row for row in report.stage_summaries}
        assert set(summaries) >= STAGES
        assert all(row.get("status") for row in summaries.values())

        run_root = workspace / report.run_id
        manifest = json.loads((run_root / "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
        raw_report = json.loads((run_root / "evidence/report/pipeline-report.json").read_text(encoding="utf-8"))
        assert all(result.evidence_ids for result in report.results)
        for item in manifest["evidence"]:
            artifact = (run_root / item["path"]).resolve(strict=True)
            assert artifact.is_relative_to(run_root.resolve())
            assert hashlib.sha256(artifact.read_bytes()).hexdigest() == item["hash"]
        assert all(not item["changed_during_run"] for item in raw_report["metadata"]["source_integrity"])
        assert any(item.get("metadata", {}).get("artifact_role") == "GENERATED_ARTIFACT"
                   for item in manifest["evidence"])
        assert any(item["path"].endswith("source-map.json") for item in manifest["evidence"])
        assert any(item["path"].startswith("evidence/fuzz-campaigns/") for item in manifest["evidence"])
        assert any(item["path"].startswith("evidence/observations/") for item in manifest["evidence"])
        assert summaries["MODEL"]["metadata"]["validation_status"] == "PASS"
        assert set(summaries["MODEL"]["metadata"]["state_ids"]) == {
            "READY", "PROCESSING", "DONE", "FAULT"}

        index = TraceabilityIndex(report, run_root=run_root, manifest=manifest)
        function = index.source_function("FUNC-MODEL-STEP")
        assert function["mapping_status"] == "UNRESOLVED"
        assert not function["state_ids"] and not function["transition_ids"]
        assert raw_report["metadata"]["traceability_integrity"]["valid"]
        assert not {"overall_verdict", "overall_status", "overall_safety_verdict"} & raw_report.keys()
    finally:
        window.close()
        app.processEvents()
