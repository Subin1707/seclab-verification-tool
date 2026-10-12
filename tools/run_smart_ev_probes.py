from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from seclab.integrations.smart_ev_probes import run_smart_ev_probes


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated Smart-EV tool-capability probes.")
    parser.add_argument("--probe-root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "examples" / "smart-ev-probes")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    workspace = args.workspace or (Path(__file__).resolve().parents[1] / ".runs" / "smart-ev-probes" /
                                   f"run-{time.time_ns()}")
    report = run_smart_ev_probes(args.probe_root, workspace, timeout=args.timeout)
    print(json.dumps({"workspace": str(workspace.resolve()),
                      "report": str(workspace.resolve() / "probe-report.json"),
                      "probe_observations": {item["name"]: item["observed"]["capability_observation"]
                                             for item in report["probes"]}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
