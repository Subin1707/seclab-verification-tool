from __future__ import annotations

import hashlib
import json

import pytest

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore
from seclab.execution import (
    Compiler, ProcessRunner, ProcessSpec, capture_environment, classify_build_result,
    classify_execution_result, store_command_evidence, store_environment_evidence,
)
from seclab.results import VerificationStatus
from seclab.source import LanguageDetector, SourceLoader


def test_generic_c_source_build_execution_and_evidence_pipeline(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "input-sut"
    project.mkdir(parents=True)
    source_path = project / "main ; safe.c"
    source_path.write_text('#include <stdio.h>\nint main(void) { puts("pipeline-ready"); return 0; }\n', encoding="utf-8")

    sources = SourceLoader().load_source_tree(project)
    assert len(sources) == 1
    assert sources[0].sha256 == hashlib.sha256(source_path.read_bytes()).hexdigest()
    detection = LanguageDetector().detect(sources)
    assert detection.language.value == "C"

    toolchain = Toolchain(["gcc", "clang"], version_timeout=2)
    if toolchain.compiler_for("C") is None:
        pytest.skip("No supported C compiler is installed")
    store = ArtifactStore(workspace)
    build = Compiler(workspace, toolchain, artifact_store=store).build(sources, detection.language)
    assert build.success and build.binary_path is not None
    assert build.binary_path.is_relative_to(workspace)
    build_result = classify_build_result(build, evidence_ids=[item.id for item in build.build_evidence])
    assert build_result.status is VerificationStatus.INCONCLUSIVE

    process = ProcessRunner().run(ProcessSpec(build.binary_path, timeout=3))
    assert process.succeeded
    assert process.stdout.strip() == "pipeline-ready"
    process_evidence = store_command_evidence(store, process)
    execution_result = classify_execution_result(process, evidence_ids=[item.id for item in process_evidence])
    assert execution_result.status is VerificationStatus.INCONCLUSIVE
    assert execution_result.reason_code == "EXECUTION_COMPLETED"
    assert execution_result.status is not VerificationStatus.PASS

    environment_evidence = store_environment_evidence(store, capture_environment(toolchain.summary()))
    for evidence in (*build.build_evidence, *process_evidence, environment_evidence):
        artifact_bytes = (workspace / evidence.path).read_bytes()
        assert hashlib.sha256(artifact_bytes).hexdigest() == evidence.hash
    command_json = json.loads((workspace / process_evidence[0].path).read_text(encoding="utf-8"))
    assert command_json["stdout_evidence"]["id"] == process_evidence[1].id
