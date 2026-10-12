from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "seclab"
GENERIC_AREAS = (
    "specification", "model", "formal", "source", "static_analysis", "memory", "testing",
    "fuzzing", "coverage", "execution", "results", "evidence", "pipeline",
)
FORBIDDEN_DOMAIN_MARKERS = re.compile(
    r"smart.?ev|smart_ev_teacher|smart-ev-charging-safety|ev_parse_remote_cmd|"
    r"ev_alloc_session_record|ev_release_port_context|ev_resume_charging_after_fault|"
    r"REQ-(?:SOC|TEMP|PORT|CHG|EMG)-|gd12_",
    re.IGNORECASE,
)


def test_generic_areas_do_not_import_or_encode_optional_sut_logic() -> None:
    files = [path for area in GENERIC_AREAS for path in (PACKAGE / area).rglob("*.py")]
    assert files
    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            else:
                continue
            assert all(not name.startswith("seclab.integrations") for name in imported), path
        assert FORBIDDEN_DOMAIN_MARKERS.search(source) is None, path


def test_core_source_has_no_absolute_external_sut_path() -> None:
    for path in PACKAGE.rglob("*.py"):
        if "integrations" in path.relative_to(PACKAGE).parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "E:\\smart-ev-charging-safety" not in source.casefold(), path


def test_generic_pipeline_imports_with_optional_integrations_blocked() -> None:
    code = """import importlib.abc, sys
class BlockIntegrations(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'seclab.integrations' or fullname.startswith('seclab.integrations.'):
            raise AssertionError('generic import reached optional integration: ' + fullname)
sys.meta_path.insert(0, BlockIntegrations())
from seclab.pipeline import PipelineOptions, run_full_verification
assert not any(name == 'seclab.integrations' or name.startswith('seclab.integrations.') for name in sys.modules)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=environment,
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr


def test_generic_gui_controller_imports_with_optional_integrations_blocked() -> None:
    code = """import importlib.abc, sys
class BlockIntegrations(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'seclab.integrations' or fullname.startswith('seclab.integrations.'):
            raise AssertionError('generic GUI import reached optional integration: ' + fullname)
sys.meta_path.insert(0, BlockIntegrations())
from seclab.gui.controllers import ProjectController
assert ProjectController().adapter is None
assert not any(name == 'seclab.integrations' or name.startswith('seclab.integrations.') for name in sys.modules)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=environment,
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
