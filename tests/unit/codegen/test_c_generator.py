from __future__ import annotations

from dataclasses import replace
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from seclab.codegen import CGenerationError, CGenerator, GeneratedArtifactRunner
from seclab.model import generate_kripke_structure
from seclab.model.errors import ModelError
from seclab.specification import FunctionSpec, Requirement, Specification
from seclab.specification.schema import StateSpec, TransitionSpec


@pytest.fixture
def specification() -> Specification:
    return Specification(schema_version="1.0", id="generic-machine", name="Generic machine",
        states=(StateSpec("OFF state", initial=True, values={"enabled": True}, labels=("off",)),
                StateSpec("ON", values={"enabled": True}, labels=("on",))),
        transitions=(TransitionSpec("turn-on", "OFF state", "ON", guard="enabled == true",
                                    action="enabled = true", label='switch "on"'),))


def test_generator_writes_deterministic_manifest_mapping_and_artifact_classes(tmp_path: Path,
                                                                               specification: Specification) -> None:
    model = generate_kripke_structure(specification)
    first = CGenerator().generate(specification, model, tmp_path / "generated", include_fuzz=True)
    hashes = {item["path"]: item["sha256"] for item in first.manifest["files"]}
    second = CGenerator().generate(specification, model, tmp_path / "generated", include_fuzz=True)
    assert first.manifest == second.manifest
    assert first.source_map == second.source_map
    assert first.generation_metadata == second.generation_metadata
    assert first.manifest["specification_hash"] == first.generation_metadata["specification_hash"]
    assert first.manifest["model_id"] == first.generation_metadata["model_id"]
    assert first.manifest["requirement_ids"] == []
    assert "Specification: generic-machine" in (first.root / "source/model.c").read_text()
    assert hashes == {item["path"]: item["sha256"] for item in second.manifest["files"]}
    assert (tmp_path / "generated/source/model.c").is_file()
    assert (tmp_path / "generated/include/model.h").is_file()
    assert (tmp_path / "generated/tests/model_test.c").is_file()
    assert (tmp_path / "generated/fuzz/model_fuzz.c").is_file()
    model_source = (tmp_path / "generated/source/model.c").read_text(encoding="utf-8")
    assert "source_kind=MODEL_GENERATED" in model_source
    assert "PROBE_ONLY" not in model_source
    assert "BUG_INJECTED_PROBE" not in model_source
    assert "TOOL_CAPABILITY_EVIDENCE" not in model_source
    assert json.loads((tmp_path / "generated/manifest.json").read_text()) == first.manifest
    assert first.source_map["files"]["source/model.c"]["states"][0]["state_id"] == "OFF state"
    assert {item["artifact_class"] for item in first.manifest["files"]} == {
        "GENERATED_ARTIFACT", "TEST_HARNESS", "FUZZ_HARNESS", "GENERATION_METADATA",
        "BUILD_CONFIGURATION"}
    assert "add_library(seclab_model STATIC source/model.c)" in (first.root / "CMakeLists.txt").read_text()
    assert "callback" in (first.root / "README.md").read_text()
    mapped = first.source_map["files"]["source/model.c"]["generated_lines"]
    assert any(row["element_kind"] == "state" and row["element_id"] == "OFF state" for row in mapped)
    assert any(row["element_kind"] == "transition" and row["element_id"] == "turn-on" for row in mapped)


def test_function_declarations_are_traceable_but_never_fabricated_as_c_bodies(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="declared", name="Declared",
        requirements=(Requirement(id="REQ-1", description="A declared requirement"),),
        functions=(FunctionSpec(id="FN-DECLARED", name="declared_function"),),
        states=(StateSpec("S0", initial=True, labels=("safe",)),))
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path,
        source_specification_paths=("legacy.json",),
        source_specification_hashes=({"source": "legacy.json", "sha256": "a" * 64},))
    source = (tmp_path / "source/model.c").read_text(encoding="utf-8")
    assert "declared_function(" not in source
    assert generated.source_map["requirements"] == [{"requirement_id": "REQ-1",
        "generated_locations": [{"path": "source/model.c", "generated_line": 3},
                                {"path": "include/model.h", "generated_line": 3}]}]
    assert generated.source_map["function_generation"] == []
    assert generated.manifest["functions"][0]["status"] == "UNSUPPORTED_NO_EXECUTABLE_CONTRACT"
    assert not any(path.startswith("source/generated_functions") for path in
                   (item["path"] for item in generated.manifest["files"]))
    assert generated.manifest["source_specification_hashes"] == [{"source": "legacy.json", "sha256": "a" * 64}]


def test_function_manifest_preserves_declared_legacy_metadata_and_cwe(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="declared-meta", name="Declared metadata",
        functions=(FunctionSpec(id="FN-copy", name="copy_value", language="c",
                                requirement_ids=("REQ-COPY",)),),
        metadata={"source_provenance": {"source_generation": {"functions": [{
            "function_id": "FN-copy", "name": "copy_value", "language": "c",
            "kind": "copy", "parameters": ["source", "destination"],
            "requirement_ids": ["REQ-COPY"], "source_location": "src/copy.c",
            "cwe_ids": ["CWE-120"], "bug": "buffer-overflow", "buffer_size": 16,
        }]}}})
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "out")
    function = generated.manifest["functions"][0]
    assert function["kind"] == "copy"
    assert function["language"] == "c"
    assert function["declared_parameters"] == ["source", "destination"]
    assert function["declared_cwe_ids"] == ["CWE-120"]
    assert function["source_location"] == "src/copy.c"
    assert function["requirement_ids"] == ["REQ-COPY"]
    assert function["declared_metadata"] == {"parameters": ["source", "destination"],
        "bug": "buffer-overflow", "buffer_size": 16}
    assert function["status"] == "UNSUPPORTED_NO_EXECUTABLE_CONTRACT"


def test_source_tree_changes_do_not_affect_specification_generated_artifacts(tmp_path: Path,
                                                                            specification: Specification) -> None:
    model = generate_kripke_structure(specification)
    source_root = tmp_path / "project"
    source_root.mkdir()
    source_file = source_root / "application.c"
    source_file.write_text("int value(void) { return 1; }\n", encoding="utf-8")
    first = CGenerator().generate(specification, model, tmp_path / "first")
    source_file.write_text("int value(void) { return 999; }\n", encoding="utf-8")
    second = CGenerator().generate(specification, model, tmp_path / "second")
    assert {item["path"]: item["sha256"] for item in first.manifest["files"]} == {
        item["path"]: item["sha256"] for item in second.manifest["files"]}


def test_requirement_map_preserves_declared_links_and_reports_orphans(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="mapped", name="Mapped",
        requirements=(Requirement(id="REQ-LINKED", description="Linked", function_ids=("FN-1",),
                                  metadata={"state_ids": ["S0"], "transition_ids": ["T1"]}),
                      Requirement(id="REQ-ORPHAN", description="No declared links")),
        functions=(FunctionSpec(id="FN-1", name="linked", requirement_ids=("REQ-LINKED",)),),
        states=(StateSpec("S0", initial=True), StateSpec("S1")),
        transitions=(TransitionSpec("T1", "S0", "S1"),))
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "out")
    requirement_map = json.loads((tmp_path / "out/requirements-map.json").read_text(encoding="utf-8"))
    linked, orphan = requirement_map["requirements"]
    assert linked["requirement_id"] == "REQ-LINKED"
    assert linked["function_ids"] == ["FN-1"]
    assert linked["state_ids"] == ["S0"]
    assert linked["transition_ids"] == ["T1"]
    assert linked["mapping_status"] == "LINKED"
    mapped_state = generated.source_map["files"]["source/model.c"]["states"][0]
    mapped_transition = generated.source_map["files"]["source/model.c"]["transitions"][0]
    assert mapped_state["source_spec_id"] == "mapped"
    assert mapped_state["requirement_ids"] == ["REQ-LINKED"]
    assert mapped_state["source_location"] is None
    assert mapped_transition["source_spec_id"] == "mapped"
    assert mapped_transition["requirement_ids"] == ["REQ-LINKED"]
    assert orphan["requirement_id"] == "REQ-ORPHAN"
    assert orphan["mapping_status"] == "ORPHAN"
    assert generated.manifest["model_code_consistency"]["status"] == "PASS"
    assert generated.manifest["model_code_consistency"]["orphan_functions"] == []


def test_specification_change_changes_model_and_generated_c_hashes(tmp_path: Path) -> None:
    first = Specification(schema_version="1.0", id="negative-case", name="Negative case",
        requirements=(Requirement("REQ-1", "Move between declared states", metadata={
            "state_ids": ["SAFE", "ERROR"], "transition_ids": ["T-1"]}),),
        states=(StateSpec("SAFE", initial=True, labels=("safe",)), StateSpec("ERROR", labels=("error",))),
        transitions=(TransitionSpec("T-1", "SAFE", "ERROR"),))
    changed = replace(first, states=(first.states[0], StateSpec("ERROR", labels=("terminal",))))
    first_model = generate_kripke_structure(first)
    changed_model = generate_kripke_structure(changed)
    first_generated = CGenerator().generate(first, first_model, tmp_path / "first")
    changed_generated = CGenerator().generate(changed, changed_model, tmp_path / "changed")
    first_files = {item["path"]: item["sha256"] for item in first_generated.manifest["files"]}
    changed_files = {item["path"]: item["sha256"] for item in changed_generated.manifest["files"]}
    assert first_model.model_hash != changed_model.model_hash
    assert first_files["source/model.c"] != changed_files["source/model.c"]


def test_empty_state_machine_does_not_invent_model_states(tmp_path: Path) -> None:
    from seclab.model import KripkeStructure

    specification = Specification(schema_version="1.0", id="no-machine", name="No machine")
    model = KripkeStructure((), (), ())
    generated = CGenerator().generate(specification, model, tmp_path / "empty")
    graph = generated.source_map["files"]["source/model.c"]
    assert graph["states"] == []
    assert graph["transitions"] == []
    assert generated.source_map["model_code_consistency"]["model_state_count"] == 0
    assert generated.source_map["model_code_consistency"]["model_transition_count"] == 0


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_generated_model_compiles_and_executes_with_available_compilers(
    tmp_path: Path, specification: Specification, compiler: str
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        pytest.skip(f"{compiler} is not installed")
    output = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), output)
    executable = tmp_path / ("model-test.exe" if compiler == "gcc" else "model-test-clang.exe")
    compiled = subprocess.run([compiler_path, "-std=c99", "-Wall", "-Wextra", "-Werror",
        "-I", str(output / "include"), str(output / "source/model.c"),
        str(output / "tests/model_test.c"), "-o", str(executable)],
        capture_output=True, text=True, check=False)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False)
    assert executed.returncode == 0, executed.stdout + executed.stderr


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_generated_runtime_api_queries_labels_edges_and_guarded_steps(
    tmp_path: Path, compiler: str,
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        pytest.skip(f"{compiler} is not installed")
    specification = Specification(schema_version="1.0", id="runtime-api", name="Runtime API",
        states=(StateSpec("READY", initial=True, labels=("ready", 'quote"tag')),
                StateSpec("DONE", labels=("done",))),
        transitions=(TransitionSpec("advance", "READY", "DONE", guard="external_ok"),))
    output = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), output)
    harness = tmp_path / "api_test.c"
    harness.write_text('''#include "model.h"
#include <stddef.h>
static int approve(const char *id, const char *guard, void *data) {
    (void)data; return id != NULL && guard != NULL;
}
int main(void) {
    size_t state = 99u, found = 99u, ready = 99u, done = 99u;
    if (!seclab_model_validate() || seclab_initial_state_count() != 1u) return 1;
    if (!seclab_model_init(&state) || !seclab_state_index("READY", &ready) || state != ready) return 2;
    if (!seclab_state_has_label(state, "ready") || !seclab_state_has_label(state, "quote\\\"tag")) return 3;
    if (!seclab_state_find_label("done", &found) || !seclab_state_index("DONE", &done) || found != done) return 4;
    if (seclab_outgoing_transition_count(state) != 1u || seclab_outgoing_transition_at(state, 1u) != NULL) return 5;
    if (seclab_transition_enabled(0u, NULL, NULL)) return 6;
    if (!seclab_model_step_by_id(&state, "advance", approve, NULL) || state != done) return 7;
    if (!seclab_state_has_label(state, "done") || seclab_model_step_by_id(&state, "missing", approve, NULL)) return 8;
    return 0;
}
''', encoding="utf-8")
    executable = tmp_path / "api-test.exe"
    compiled = subprocess.run([compiler_path, "-std=c99", "-Wall", "-Wextra", "-Werror",
        "-I", str(output / "include"), str(output / "source/model.c"), str(harness),
        "-o", str(executable)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True)
    assert executed.returncode == 0, executed.stdout + executed.stderr


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_generated_model_automatically_executes_declared_state_transition(
    tmp_path: Path, compiler: str,
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        pytest.skip(f"{compiler} is not installed")
    specification = Specification(schema_version="1.0", id="state-step", name="State step",
        states=(StateSpec("WAIT", initial=True, values={"count": 0}, labels=("waiting",)),
                StateSpec("DONE", values={"count": 1}, labels=("complete",))),
        transitions=(TransitionSpec("increment", "WAIT", "DONE", guard="count == 0",
                                    action="count = count + 1"),))
    output = tmp_path / "generated"
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), output)
    harness = tmp_path / "step_test.c"
    harness.write_text('''#include "model.h"
#include <string.h>
int main(void) {
    size_t state = 99u, transition = 99u;
    if (!seclab_model_init(&state)) return 1;
    if (!seclab_model_step_next(&state, &transition, NULL, NULL)) return 2;
    if (strcmp(seclab_state_at(state)->id, "DONE") != 0) return 3;
    if (strcmp(seclab_transition_at(transition)->id, "increment") != 0) return 4;
    if (strcmp(seclab_state_at(state)->values_json, "{\\"count\\":1}") != 0) return 5;
    if (seclab_model_step_next(&state, &transition, NULL, NULL)) return 6;
    return 0;
}
''', encoding="utf-8")
    executable = tmp_path / "step-test.exe"
    compiled = subprocess.run([compiler_path, "-std=c99", "-Wall", "-Wextra", "-Werror",
        "-I", str(output / "include"), str(output / "source/model.c"), str(harness),
        "-o", str(executable)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True)
    assert executed.returncode == 0, executed.stdout + executed.stderr
    assert generated.manifest["runtime_contract"]["automatic_step"].startswith("step_next selects")


def test_generated_python_model_is_executable_and_matches_canonical_model(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="python-runtime", name="Python runtime",
        states=(StateSpec("READY", initial=True, values={"count": 1}, labels=("ready", 'quote"tag')),
                StateSpec("DONE", values={"count": 2}, labels=("done",))),
        transitions=(TransitionSpec("advance", "READY", "DONE", guard="external_ok"),))
    model = generate_kripke_structure(specification)
    generated = CGenerator().generate(specification, model, tmp_path / "generated")
    source = generated.root / "python/model.py"
    assert source.is_file()
    assert generated.manifest["model_hash"] in source.read_text(encoding="utf-8")
    state_map = generated.source_map["files"]["python/model.py"]["states"]
    assert {item["state_id"] for item in state_map} == set(model.state_ids)
    assert generated.source_map["files"]["python/model.py"]["transitions"][0]["transition_id"] == "advance"

    api_harness = tmp_path / "python_api_test.py"
    api_harness.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(source.parent)!r})\n"
        "import model\n"
        "assert model.validate_model()\n"
        "assert model.state_has_label('READY', 'quote\\\"tag')\n"
        "assert model.states_with_label('done') == ('DONE',)\n"
        "assert [edge['id'] for edge in model.outgoing_transitions('READY')] == ['advance']\n"
        "try:\n    model.step('READY', 'advance')\n"
        "except PermissionError:\n    pass\n"
        "else:\n    raise AssertionError('unresolved guard was accepted without callback')\n"
        "assert model.step('READY', 'advance', lambda _id, _guard: True) == 'DONE'\n",
        encoding="utf-8")
    checked = subprocess.run([sys.executable, str(api_harness)], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stdout + checked.stderr

    executed = subprocess.run([sys.executable, str(source)], capture_output=True, text=True)
    assert executed.returncode == 0, executed.stdout + executed.stderr
    assert json.loads(executed.stdout) == {
        "input_state_id": "READY", "is_initial": True, "transition_id": None,
        "result_state_id": "READY", "outgoing_transition_ids": ["advance"]}


def test_unresolved_guards_are_rejected_by_default_but_preserved_for_callback(
    tmp_path: Path,
) -> None:
    specification = Specification(schema_version="1.0", id="unresolved", name="Unresolved",
        states=(StateSpec("S0", initial=True), StateSpec("S1")),
        transitions=(TransitionSpec("T1", "S0", "S1", guard="external_ready"),))
    result = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "generated")
    source = (result.root / "source/model.c").read_text()
    assert "guard_fn != NULL" in source
    assert result.manifest["limitations"]


def test_empty_model_generates_compilable_source(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="empty", name="Empty")
    result = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "generated")
    assert result.manifest["model_hash"] == generate_kripke_structure(specification).model_hash


@pytest.mark.parametrize("compiler", ["gcc", "clang"])
def test_empty_model_compiles_and_runs(tmp_path: Path, compiler: str) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        pytest.skip(f"{compiler} is not installed")
    specification = Specification(schema_version="1.0", id="empty", name="Empty")
    output = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), output)
    executable = tmp_path / "empty-model.exe"
    compile_result = subprocess.run([compiler_path, "-std=c99", "-Wall", "-Wextra", "-Werror",
        "-I", str(output / "include"), str(output / "source/model.c"),
        str(output / "tests/model_test.c"), "-o", str(executable)], capture_output=True, text=True)
    assert compile_result.returncode == 0, compile_result.stdout + compile_result.stderr
    execute_result = subprocess.run([str(executable)], capture_output=True, text=True)
    assert execute_result.returncode == 0, execute_result.stdout + execute_result.stderr


def test_malicious_paths_are_not_derived_from_specification_ids(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="../../outside", name="Path safe",
        states=(StateSpec("../state", initial=True),))
    result = CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "generated")
    assert result.root == (tmp_path / "generated").resolve()
    assert not (tmp_path / "outside").exists()


def test_unsupported_generated_filename_is_rejected(tmp_path: Path) -> None:
    from seclab.codegen.c_generator import _safe_write

    with pytest.raises(CGenerationError, match="Unsafe generated filename"):
        _safe_write(tmp_path, "../outside.c", "bad")


def test_runner_records_hashed_artifacts_and_observable_execution(tmp_path: Path, specification: Specification) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    root = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), root)
    result = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler=compiler)
    assert result.build_status == "COMPLETED"
    assert result.execution_status == "COMPLETED"
    assert result.exit_code == 0
    observation = json.loads(result.stdout)
    assert observation["input_state_id"] == "OFF state"
    assert observation["is_initial"] is True
    assert observation["result_state_id"] == "OFF state"
    assert observation["outgoing_transition_ids"] == ["turn-on"]
    assert result.scope.startswith("Generated artifact execution only")
    assert len(result.evidence) >= 7
    for evidence in result.evidence:
        stored = tmp_path / evidence.path
        assert stored.is_file()
        import hashlib
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == evidence.hash
    input_metadata = [item.metadata for item in result.evidence if item.metadata.get("generated_path")]
    assert {item["generated_path"] for item in input_metadata} >= {
        "source-map.json", "manifest.json", "source/model.c", "include/model.h", "tests/model_test.c"}


def test_runner_accepts_state_and_transition_inputs_and_reports_resulting_state(
    tmp_path: Path, specification: Specification,
) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    root = tmp_path / "generated"
    generated = CGenerator().generate(specification, generate_kripke_structure(specification), root)
    run = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler=compiler,
        input_args=("OFF state", "turn-on"))
    assert run.build_status == "COMPLETED"
    assert run.execution_status == "COMPLETED"
    assert json.loads(run.stdout) == {"input_state_id": "OFF state", "is_initial": True,
        "transition_id": "turn-on", "result_state_id": "ON", "outgoing_transition_ids": ["turn-on"]}
    c_map = generated.source_map["files"]["source/model.c"]["generated_lines"]
    h_map = generated.source_map["files"]["tests/model_test.c"]["generated_lines"]
    assert any(row["element_kind"] == "specification" and row["element_id"] == specification.id for row in c_map)
    assert any(row["element_kind"] == "transition" and row["element_id"] == "turn-on" for row in h_map)


def test_generic_model_guard_action_compile_and_observed_execution(tmp_path: Path) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    specification = Specification(schema_version="1.0", id="generic-counter", name="Generic counter",
        states=(StateSpec("IDLE", initial=True, values={"request": 1, "counter": 0}),
                StateSpec("ACTIVE", values={"request": 0, "counter": 1}),
                StateSpec("STOPPED", values={"request": 0, "counter": 1})),
        transitions=(TransitionSpec("start", "IDLE", "ACTIVE", guard="request == 1",
                                    action="counter = counter + 1"),
                     TransitionSpec("stop", "ACTIVE", "STOPPED", guard="request == 0")))
    model = generate_kripke_structure(specification)
    output = tmp_path / "generated-model"
    generated = CGenerator().generate(specification, model, output)
    assert len(model.states) == 3
    assert len(model.transitions) == 2
    c_source = (output / "source/model.c").read_text(encoding="utf-8")
    assert "STATE_IDLE" not in c_source  # IDs remain model data, not hard-coded enums.
    assert "request == 1" in c_source
    runner = GeneratedArtifactRunner(tmp_path)
    result = runner.compile_and_run(output, compiler=compiler, input_args=("IDLE", "start"))
    assert result.build_status == "COMPLETED"
    assert result.execution_status == "COMPLETED"
    observed = json.loads(result.stdout)
    assert observed["input_state_id"] == "IDLE"
    assert observed["transition_id"] == "start"
    assert observed["result_state_id"] == "ACTIVE"
    assert generated.manifest["model_code_consistency"]["status"] == "PASS"


def test_runner_invalid_input_is_observed_with_failure_evidence(tmp_path: Path, specification: Specification) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    root = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), root)
    result = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler=compiler,
        input_args=("missing-state",))
    assert result.build_status == "COMPLETED"
    assert result.execution_status == "ABNORMAL_TERMINATION"
    assert "unknown state id" in result.stderr
    assert any(item.metadata.get("kind") == "EXECUTION" for item in result.evidence)


def test_runner_persists_real_generated_compile_failure(tmp_path: Path, specification: Specification) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    root = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), root)
    harness = root / "tests/model_test.c"
    harness.write_text(harness.read_text(encoding="utf-8") + "\nthis is not valid C;\n", encoding="utf-8")
    result = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler=compiler)
    assert result.build_status == "BUILD_ERROR"
    assert result.execution_status == "NOT_RUN"
    build_evidence = next(item for item in result.evidence if item.metadata.get("kind") == "BUILD")
    payload = json.loads((tmp_path / build_evidence.path).read_text(encoding="utf-8"))
    assert payload["exit_code"] != 0
    assert payload["stderr"]


def test_runner_distinguishes_runtime_abnormal_exit_and_timeout(tmp_path: Path, specification: Specification) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    root = tmp_path / "crash-generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), root)
    (root / "tests/model_test.c").write_text(
        "int main(void) { return 42; }\n", encoding="utf-8")
    crashed = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler=compiler)
    assert crashed.build_status == "COMPLETED"
    assert crashed.execution_status == "ABNORMAL_TERMINATION"
    assert any(item.metadata.get("kind") == "EXECUTION" for item in crashed.evidence)

    timeout_root = tmp_path / "timeout-generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), timeout_root)
    (timeout_root / "tests/model_test.c").write_text(
        "int main(void) { volatile unsigned long counter = 0ul; for (;;) ++counter; }\n",
        encoding="utf-8")
    timed_out = GeneratedArtifactRunner(tmp_path).compile_and_run(timeout_root, compiler=compiler,
        execution_timeout=0.2)
    assert timed_out.build_status == "COMPLETED"
    assert timed_out.execution_status == "TIMEOUT"
    assert any(item.metadata.get("kind") == "EXECUTION" for item in timed_out.evidence)


def test_runner_keeps_missing_compiler_as_tool_error(tmp_path: Path, specification: Specification) -> None:
    root = tmp_path / "generated"
    CGenerator().generate(specification, generate_kripke_structure(specification), root)
    result = GeneratedArtifactRunner(tmp_path).compile_and_run(root, compiler="missing-seclab-cc")
    assert result.build_status == "TOOL_ERROR"
    assert result.execution_status == "NOT_RUN"


def test_invalid_guard_is_rejected_without_generated_output(tmp_path: Path) -> None:
    specification = Specification(schema_version="1.0", id="invalid", name="Invalid",
        states=(StateSpec("S0", initial=True, values={"ready": True}), StateSpec("S1")),
        transitions=(TransitionSpec("bad", "S0", "S1", guard="ready &&"),))
    with pytest.raises(ModelError, match="guard is invalid"):
        CGenerator().generate(specification, generate_kripke_structure(specification), tmp_path / "generated")
    assert not (tmp_path / "generated/source/model.c").exists()
