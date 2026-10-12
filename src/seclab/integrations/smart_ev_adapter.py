"""Compatibility shim for the historical optional integration API."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from seclab.specification.legacy_adapter import adapt_legacy_specification
from seclab.specification import LoadedSpecification


def adapt_smart_ev_document(source: Path, raw: Mapping[str, Any], raw_bytes: bytes) -> LoadedSpecification:
    """Keep the old import name while delegating migration to Specification Core."""
    return adapt_legacy_specification(raw, source, raw_bytes)
