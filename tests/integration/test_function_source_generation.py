from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from seclab.codegen import CGenerator
from seclab.benchmark import FunctionSourceGenerator
from seclab.model import generate_kripke_structure
from seclab.specification import adapt_legacy_specification, normalize_specification, validate_specification


FIXTURES = Path(__file__).resolve().parents[2] / "examples" / "source-generation"


def _specification(path: Path):
    raw_bytes = path.read_bytes()
    raw = json.loads(raw_bytes)
    loaded = adapt_legacy_specification(raw, path, raw_bytes)
    return normalize_specification(validate_specification(loaded))


@pytest.mark.parametrize("fixture", ["buffer_copy.json", "memory.json", "python_branch.json"])
def test_generic_source_generation_fixtures_have_manifest_hashes_and_trace_maps(tmp_path, fixture):
    specification = _specification(FIXTURES / fixture)
    first = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "first")
    second = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "second")
    first_hashes = {item["path"]: item["sha256"] for item in first.manifest["files"]}
    second_hashes = {item["path"]: item["sha256"] for item in second.manifest["files"]}
    assert first_hashes == second_hashes
    assert first.manifest["specification_hash"] == first.generation_metadata["specification_hash"]
    assert all(item["status"] == "NOT_MODEL_CODE" for item in first.manifest["functions"])
    assert not (first.root / "source/generated_functions.c").exists()
    for path, digest in first_hashes.items():
        if path == "source-map.json":
            actual = hashlib.sha256((first.root / path).read_bytes()).hexdigest()
        else:
            actual = hashlib.sha256((first.root / path).read_bytes()).hexdigest()
        assert actual == digest
    assert any(item.get("generated_lines") for item in first.source_map["files"].values())
    assert all(item["production_source"] is False for item in first.manifest["functions"])


def test_model_generator_never_reads_probe_provenance(tmp_path):
    specification = _specification(FIXTURES / "buffer_copy.json")
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "model")
    model_paths = [item["path"] for item in generated.manifest["files"]]
    assert "source/generated_functions.c" not in model_paths
    assert not (generated.root / "source/generated_functions.c").exists()
    for relative in ("source/model.c", "include/model.h", "tests/model_test.c"):
        content = (generated.root / relative).read_text(encoding="utf-8")
        for forbidden in ("PROBE_ONLY", "BUG_INJECTED_PROBE", "TOOL_CAPABILITY_EVIDENCE",
                          "expected vulnerability", "Expected CWE mapping"):
            assert forbidden not in content
    probe_records = specification.metadata["source_provenance"]["source_generation"]["functions"]
    probes = FunctionSourceGenerator().generate(probe_records)
    assert "source/generated_functions.c" in probes.files
    assert "PROBE_ONLY" in probes.files["source/generated_functions.c"]


def test_generated_c_function_header_harness_and_source_mapping_are_explicit(tmp_path):
    specification = _specification(FIXTURES / "buffer_copy.json")
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"])
    assert "include/generated_functions.h" in generated.files
    assert "tests/generated_harness.c" in generated.files
    c_source = generated.files["source/generated_functions.c"]
    assert "int main(" not in c_source
    assert "copy_bounded" in generated.files["include/generated_functions.h"]
    function_map = generated.functions
    assert len(function_map) == 2
    assert all(item["generated_path"] == "source/generated_functions.c" for item in function_map)


def test_normalized_c_test_case_builds_and_executes_generated_test_driver(tmp_path):
    compiler = shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("No clang or gcc compiler is installed")
    from seclab.specification.schema import TestSpec

    specification = _specification(FIXTURES / "buffer_copy.json")
    specification = replace(specification, tests=(TestSpec(id="TC-COPY-01",
        function_id="FN-copy_bounded", kind="unit", input={"args": {"source": "from-spec"}}),))
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"],
        test_cases=specification.tests)
    case = next(item for item in generated.test_cases if item["test_id"] == "TC-COPY-01")
    assert case["status"] == "GENERATED"
    assert "TC-COPY-01" in generated.files["source/generated_test_driver.c"]
    probe_root = tmp_path / "gen" / "probes"
    for path, content in generated.files.items():
        target = probe_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    executable = probe_root / ("generated_app.exe" if sys.platform == "win32" else "generated_app")
    build = subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra", "-I",
        str(probe_root / "include"), str(probe_root / "source/generated_functions.c"),
        str(probe_root / "source/generated_test_driver.c"), "-o", str(executable)],
        cwd=probe_root, capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(executable), "TC-COPY-01", "from-spec"], cwd=probe_root,
        capture_output=True, text=True, timeout=5)
    assert run.returncode == 0
    assert "from-spec" in run.stdout
    assert "TEST_COMPLETED:TC-COPY-01" in run.stdout


def test_codegen_pipeline_does_not_promote_legacy_function_probe_declarations(tmp_path):
    from types import SimpleNamespace
    from seclab.config import Toolchain
    from seclab.execution import CommandRunner
    from seclab.evidence import ArtifactStore
    from seclab.pipeline.stages import PipelineStages
    from seclab.specification.schema import TestSpec

    if not (shutil.which("clang") or shutil.which("gcc")):
        pytest.skip("No clang or gcc compiler is installed")
    specification = _specification(FIXTURES / "buffer_copy.json")
    specification = replace(specification, tests=(TestSpec(id="TC-COPY-PIPELINE",
        function_id="FN-copy_bounded", kind="unit", input={"args": {"source": "pipeline-input"}}),))
    run_root = tmp_path / "run"
    run_root.mkdir()
    context = SimpleNamespace(run_id="pipeline-test", workspace=run_root,
        specification=specification, kripke=generate_kripke_structure(specification),
        loaded_specification=None, artifact_store=ArtifactStore(run_root, run_id="pipeline-test"),
        command_runner=CommandRunner(), toolchain=Toolchain(command_runner=CommandRunner()))
    options = SimpleNamespace(generate_c_fuzz_harness=False, build_timeout=30, execution_timeout=5)
    output = PipelineStages.codegen(context, options)
    assert "function_build_status" not in output.metadata
    assert "function_build_runs" not in output.metadata
    assert not (run_root / "generated" / "source" / "generated_functions.c").exists()
    assert "no executable behavior contract" in output.metadata["limitations"][0]
    assert (run_root / "generated" / "source" / "model.c").is_file()


def test_generic_c_source_preserves_declared_safe_and_vulnerable_copy_behavior(tmp_path):
    specification = _specification(FIXTURES / "buffer_copy.json")
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"])
    source = generated.files["source/generated_functions.c"]
    assert "strncpy(buffer, source, sizeof(buffer) - 1u);" in source
    assert "buffer[sizeof(buffer) - 1u] = '\\0';" in source
    assert "strcpy(buffer, source);" in source
    assert "ev_" not in source
    overflow = next(item for item in generated.functions
                    if item["name"] == "copy_declared_overflow")
    assert overflow["expected_vulnerability"] == "buffer-overflow"
    assert overflow["expected_cwe_ids"] == ["CWE-121"]
    assert overflow["cwe_mapping_basis"].endswith("not a checker finding")


def test_generic_memory_and_python_sources_keep_probe_semantics(tmp_path):
    memory = _specification(FIXTURES / "memory.json")
    c_generated = FunctionSourceGenerator().generate(
        memory.metadata["source_provenance"]["source_generation"]["functions"])
    c_source = c_generated.files["source/generated_functions.c"]
    assert "Intentional probe behavior: allocation is not released" in c_source
    assert "free(buf); /* Intentional double-free probe. */" in c_source
    assert "buf[0] = 1; /* Intentional use-after-free probe. */" in c_source

    python = _specification(FIXTURES / "python_branch.json")
    py_generated = FunctionSourceGenerator().generate(
        python.metadata["source_provenance"]["source_generation"]["functions"])
    py_source = py_generated.files["python/generated_functions.py"]
    assert "return numerator // denominator" in py_source
    assert "if first == 17:" in py_source and "if second == 29:" in py_source
    assert "raise ValueError('magic value reached')" in py_source


def test_generated_c_harness_compiles_lists_and_executes_safe_function(tmp_path):
    compiler = shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    specification = _specification(FIXTURES / "buffer_copy.json")
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"])
    probe_root = tmp_path / "probes"
    for path, content in generated.files.items():
        target = probe_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    executable = probe_root / ("functions.exe" if sys.platform == "win32" else "functions")
    build = subprocess.run([compiler, "-std=c99", "-Wall", "-Wextra",
        str(probe_root / "source/generated_functions.c"),
        str(probe_root / "tests/generated_functions_main.c"), "-o", str(executable)],
        cwd=probe_root, capture_output=True, text=True, timeout=30)
    assert build.returncode == 0, build.stderr
    listed = subprocess.run([str(executable), "--list"], cwd=probe_root,
        capture_output=True, text=True, timeout=5)
    assert listed.returncode == 0
    assert listed.stdout.splitlines() == ["copy_bounded", "copy_declared_overflow"]
    executed = subprocess.run([str(executable), "copy_bounded", "actual-input"], cwd=probe_root,
        capture_output=True, text=True, timeout=5)
    assert executed.returncode == 0
    assert "actual-input" in executed.stdout
    assert '"invoked":true' in executed.stdout


def test_generated_python_harness_executes_and_records_real_exception(tmp_path):
    specification = _specification(FIXTURES / "python_branch.json")
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"])
    probe_root = tmp_path / "probes"
    for path, content in generated.files.items():
        target = probe_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    main = probe_root / "python/generated_functions_main.py"
    listed = subprocess.run([sys.executable, str(main), "--list"], cwd=probe_root,
        capture_output=True, text=True, timeout=5)
    assert listed.returncode == 0
    assert json.loads(listed.stdout) == ["ratio", "unlock_gate"]
    raised = subprocess.run([sys.executable, str(main), "unlock_gate", "[17,29]"], cwd=probe_root,
        capture_output=True, text=True, timeout=5)
    assert raised.returncode == 1
    assert json.loads(raised.stderr)["exception_type"] == "ValueError"


def test_pipeline_python_probe_declarations_do_not_enter_codegen(tmp_path):
    from seclab.pipeline import PipelineOptions, run_full_verification

    project = tmp_path / "project"
    project.mkdir()
    fixture = FIXTURES / "python_branch.json"
    report = run_full_verification(project, tmp_path / "workspace", run_id="python-codegen",
        options=PipelineOptions(specification_paths=(fixture,), static_analyzers=(),
            run_memory=False, run_coverage=False, generate_c_model=True))
    stage = next(item for item in report.stage_summaries if item["stage_id"] == "CODEGEN")
    assert stage["status"] == "COMPLETED"
    assert "function_build_status" not in stage["metadata"]
    assert "function_build_runs" not in stage["metadata"]
    generated = tmp_path / "workspace/python-codegen/generated"
    assert not (generated / "source/generated_functions.c").exists()
    assert not {"PROBE", "PROBE_ONLY", "BUG_INJECTED_PROBE"} & set(report.metadata["artifact_classes"])


def test_unknown_kind_is_explicitly_unsupported_and_not_emitted(tmp_path):
    raw = {"id": "unsupported-kind", "name": "Unsupported kind", "requirements": [],
        "state_machine": {"states": ["READY"], "initial": ["READY"], "transitions": []},
        "functions": [{"name": "mystery", "language": "c", "kind": "unknown", "params": []}]}
    raw_bytes = json.dumps(raw, sort_keys=True).encode()
    loaded = adapt_legacy_specification(raw, tmp_path / "input.json", raw_bytes)
    specification = normalize_specification(validate_specification(loaded))
    generated = FunctionSourceGenerator().generate(
        specification.metadata["source_provenance"]["source_generation"]["functions"])
    function = generated.functions[0]
    assert function["status"] == "UNSUPPORTED"
    assert "Unsupported C function kind" in function["reason"]
    assert not generated.files
