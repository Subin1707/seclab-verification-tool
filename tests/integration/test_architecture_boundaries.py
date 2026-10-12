from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_verification_core_does_not_import_benchmark_or_probe_artifacts() -> None:
    core = ROOT / "src" / "seclab"
    verifier_dirs = ("pipeline", "testing", "static_analysis", "memory", "fuzzing", "formal", "codegen")
    forbidden_imports = ("seclab.benchmark", "integrations.probes")
    forbidden_artifact_ids = ("BUG_INJECTED_PROBE", "PROBE_ONLY", "TOOL_CAPABILITY_EVIDENCE")
    for name in verifier_dirs:
        for path in (core / name).rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            assert not any(item in source for item in forbidden_imports), path
            assert not any(item in source for item in forbidden_artifact_ids), path


def test_generic_core_has_no_smart_ev_specific_generator_symbols() -> None:
    core = ROOT / "src" / "seclab"
    generic_dirs = ("pipeline", "codegen", "testing", "static_analysis", "memory", "formal")
    forbidden = ("ev_parse_remote_cmd", "ev_alloc_session_record", "ev_release_port_context",
                 "ev_resume_charging_after_fault", "smart_ev")
    for name in generic_dirs:
        for path in (core / name).rglob("*.py"):
            source = path.read_text(encoding="utf-8").casefold()
            assert not any(symbol.casefold() in source for symbol in forbidden), path
