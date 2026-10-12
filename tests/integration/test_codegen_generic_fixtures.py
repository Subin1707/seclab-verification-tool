from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from seclab.codegen import CGenerationError, CGenerator, GeneratedArtifactRunner
from seclab.model import generate_kripke_structure
from seclab.model.errors import ModelError
from seclab.specification import load_specification, normalize_specification, validate_specification


FIXTURES = Path(__file__).resolve().parents[2] / "examples" / "codegen"


@pytest.mark.parametrize("fixture", ["boolean_state_machine", "counter", "branching_function", "bounded_transition_system"])
def test_generic_codegen_fixtures_generate_compile_execute_and_map(tmp_path: Path, fixture: str) -> None:
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler is installed")
    loaded = load_specification(FIXTURES / f"{fixture}.json")
    normalized = normalize_specification(validate_specification(loaded))
    model = generate_kripke_structure(normalized)
    result = CGenerator().generate(normalized, model, tmp_path / fixture)
    mapped = result.source_map["files"]["source/model.c"]["generated_lines"]
    assert all(1 <= row["generated_line"] <= len((result.root / "source/model.c").read_text().splitlines())
               for row in mapped)
    assert {row["element_kind"] for row in mapped} >= {"state", "transition"}
    run = GeneratedArtifactRunner(tmp_path).compile_and_run(result.root, compiler=compiler)
    assert run.build_status == "COMPLETED"
    assert run.execution_status == "COMPLETED"
    assert run.exit_code == 0


def test_invalid_fixture_is_diagnosed_without_silent_codegen(tmp_path: Path) -> None:
    loaded = load_specification(FIXTURES / "invalid_generation.json")
    normalized = normalize_specification(validate_specification(loaded))
    with pytest.raises(ModelError, match="guard is invalid"):
        CGenerator().generate(normalized, generate_kripke_structure(normalized), tmp_path / "invalid")
    assert not (tmp_path / "invalid/source/model.c").exists()
