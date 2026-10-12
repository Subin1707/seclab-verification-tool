from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox

from seclab.gui.main_window import MainWindow


def test_real_legacy_specification_runs_through_gui_without_reloading(tmp_path, monkeypatch):
    specification_path = os.environ.get("SECLAB_LEGACY_TEACHER_SPEC")
    if not specification_path:
        pytest.skip("Set SECLAB_LEGACY_TEACHER_SPEC to the external legacy teacher JSON for acceptance.")
    spec_path = Path(specification_path).resolve(strict=True)
    project = spec_path.parent.parent.resolve(strict=True)
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    errors = []
    monkeypatch.setattr(QMessageBox, "critical", lambda *args: errors.append(str(args[-1])))
    try:
        window.project_controller.open_project(project)
        window.session.open_project(project)
        window._workspace = tmp_path / "runs"
        window.session.workspace = window._workspace
        assert not hasattr(window.settings_page, "generate_c_model")
        window.settings_page.analyzers.setText("compiler, cppcheck")
        window.settings_page.memory.setChecked(True)
        window.settings_page.coverage.setChecked(True)
        source_hash = hashlib.sha256(spec_path.read_bytes()).hexdigest()

        window._set_specification(str(spec_path))
        app.processEvents()
        assert not errors, errors
        assert window.session.ready
        assert window.session.schema_version == "1.0"
        assert window.session.original_spec_hash == source_hash
        assert window.session.normalized_specification.id == "smart_ev_teacher_e2e_v4"
        assert window.session.specification_info["validation_result"] == "VALID"
        assert window.session.specification_info["source_sha256"] == source_hash
        assert window.session.specification_info["canonical_sha256"] == window.project_controller.specification_info["canonical_sha256"]
        assert len(window.session.normalized_specification.states) == 28
        assert len(window.session.normalized_specification.transitions) == 47
        assert window.session.raw_specification == window.project_controller.raw_specification
        assert window.project_controller.verify_original_unchanged()

        window._build_review_model()
        assert len(window.session.model["states"]) == 28
        assert len(window.session.model["transitions"]) == 47
        window._specification_reviewed = True
        window._start_run(None)
        deadline = time.monotonic() + 360
        while window._thread is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()
        assert window._thread is None, "GUI verification run exceeded six minutes"
        assert window.session.report is not None, window.session.error
        assert window.project_controller.project_path == project
        assert window.project_controller.specification_path == spec_path
        report = window.session.report
        stages = {item["stage_id"]: item for item in report.stage_summaries}
        assert {"SPECIFICATION", "SOURCE", "MODEL", "CTL", "BMC", "SMT", "CODEGEN",
                "STATIC", "MEMORY", "DYNAMIC", "COVERAGE", "FUZZING", "REPORT"} <= stages.keys()
        assert stages["SPECIFICATION"]["status"] == "COMPLETED"
        assert stages["MODEL"]["metadata"]["state_count"] == 28
        assert stages["MODEL"]["metadata"]["transition_count"] == 47
        assert stages["CODEGEN"]["metadata"]["build_status"] == "PASS"
        assert stages["DYNAMIC"]["status"] == "SKIPPED"
        assert "no test cases" in stages["DYNAMIC"]["reason"].lower()
        assert stages["COVERAGE"]["status"] == "SKIPPED"
        assert stages["FUZZING"]["status"] == "SKIPPED"
        raw_report = json.loads((window._workspace / report.run_id /
            "evidence/report/pipeline-report.json").read_text(encoding="utf-8"))
        assert raw_report["metadata"]["traceability_integrity"]["valid"]
        assert not {"overall_verdict", "overall_status", "overall_safety_verdict"} & raw_report.keys()
        assert hashlib.sha256(spec_path.read_bytes()).hexdigest() == source_hash
        manifest = json.loads((window._workspace / report.run_id /
            "evidence/manifest/run-manifest.json").read_text(encoding="utf-8"))
        assert any(row["path"].endswith("kripke.json") for row in manifest["evidence"])
        assert any(row["path"].endswith("source-map.json") for row in manifest["evidence"])
        build_ref = next(row for row in manifest["evidence"] if row["path"].endswith("build-result.json"))
        build_data = json.loads((window._workspace / report.run_id / build_ref["path"]).read_text(encoding="utf-8"))
        assert build_data["status"] == "PASS"
        assert all(row["build_status"] == "COMPLETED" and row["execution_status"] == "COMPLETED"
                   for row in build_data["compiler_runs"])
        assert any(row.get("metadata", {}).get("artifact_scope") == "GENERATED_ARTIFACT"
                   for row in report.to_dict()["results"])
    finally:
        window.close()
        app.processEvents()
