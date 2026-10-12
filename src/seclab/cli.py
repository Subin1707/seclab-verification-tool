"""Command line entry point for generic project verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from seclab.fuzzing import FuzzConfig, FuzzInput
from seclab.pipeline import PipelineOptions, load_previous_run, run_full_verification


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="seclab", description="Verify an external software project.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="run verification for a project and optional specification")
    verify.add_argument("--project", required=True, type=Path, help="path to the system under test")
    verify.add_argument("--spec", action="append", default=[], type=Path,
                        help="specification input (may be supplied more than once)")
    verify.add_argument("--workspace", type=Path,
                        help="evidence workspace (default: a sibling directory outside the project)")
    verify.add_argument("--stage", action="append", dest="stages",
                        help="run a stage and its prerequisites; may be supplied more than once")
    verify.add_argument("--config", type=Path, help="JSON file with generic pipeline options")
    verify.add_argument("--run-id", help="optional stable run identifier")
    show = subparsers.add_parser("show-run", help="reopen a persisted run without rerunning verification")
    show.add_argument("--workspace", required=True, type=Path, help="parent run workspace")
    show.add_argument("--run-id", required=True, help="persisted run identifier")
    args = parser.parse_args(argv)

    if args.command == "show-run":
        report = load_previous_run(args.workspace, args.run_id)
        print(f"Run {report.run_id}: {report.status_counts}")
        return 0

    project = args.project.expanduser().resolve(strict=True)
    workspace = args.workspace or (project.parent / f"{project.name}-seclab-runs")
    config = _load_config(args.config) if args.config else {}
    config["specification_paths"] = tuple(args.spec)
    report = run_full_verification(project, workspace,
                                   options=PipelineOptions(**config), run_id=args.run_id,
                                   stage_ids=args.stages)
    print(f"Run {report.run_id}: {report.status_counts}")
    print(f"Evidence: {Path(report.evidence_manifest['path'])}")
    return 0


def _load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Pipeline config must be a JSON object.")
    allowed = {"static_analyzers", "run_memory", "run_coverage", "coverage_backend",
               "analysis_timeout", "execution_timeout", "build_timeout", "solver_timeout",
               "bmc_default_bound", "max_states", "build_flags", "toolchain_tools", "static_flags",
               "fuzz_config", "fuzz_seeds", "generate_c_model", "generate_c_fuzz_harness"}
    unknown = set(data) - allowed
    if unknown:
        raise ValueError(f"Unsupported pipeline config key(s): {', '.join(sorted(unknown))}")
    for key in ("static_analyzers", "build_flags", "toolchain_tools", "static_flags"):
        if key in data and data[key] is not None:
            if not isinstance(data[key], list):
                raise ValueError(f"Pipeline config key '{key}' must be a JSON array.")
            data[key] = tuple(data[key])
    if "fuzz_config" in data and data["fuzz_config"] is not None:
        if not isinstance(data["fuzz_config"], dict):
            raise ValueError("Pipeline config key 'fuzz_config' must be a JSON object.")
        data["fuzz_config"] = FuzzConfig(**data["fuzz_config"])
    if "fuzz_seeds" in data:
        if not isinstance(data["fuzz_seeds"], list):
            raise ValueError("Pipeline config key 'fuzz_seeds' must be a JSON array.")
        data["fuzz_seeds"] = tuple(FuzzInput(**item) for item in data["fuzz_seeds"])
    return data


if __name__ == "__main__":
    raise SystemExit(main())
