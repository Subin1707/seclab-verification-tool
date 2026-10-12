"""Minimal, JSON-serializable host environment snapshot."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    os: str
    platform: str
    architecture: str
    python_version: str
    toolchain: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"os": self.os, "platform": self.platform, "architecture": self.architecture,
                "python_version": self.python_version, "toolchain": dict(self.toolchain)}


def capture_environment(toolchain: Mapping[str, Any] | None = None) -> EnvironmentSnapshot:
    return EnvironmentSnapshot(platform.system(), platform.platform(), platform.machine(), sys.version.split()[0], dict(toolchain or {}))
