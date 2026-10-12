"""Registry boundary for optional external specification adapters."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from seclab.specification import LoadedSpecification, load_specification
from seclab.specification.legacy_adapter import adapt_legacy_specification, is_legacy_teacher_specification


def load_adapted_specification(path: str | Path) -> tuple[LoadedSpecification, dict[str, Any]]:
    """Load native specifications directly or dispatch known external formats."""
    source = Path(path).expanduser().resolve(strict=True)
    raw_bytes = source.read_bytes()
    try:
        raw = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return load_specification(source), {"format": "generic", "adapter": None}
    if is_legacy_teacher_specification(raw):
        loaded = adapt_legacy_specification(raw, source, raw_bytes)
        provenance = loaded.documents[0].data["metadata"]["source_provenance"]
        return loaded, {"format": "Smart-EV Teacher Specification", "adapter": "Smart-EV Adapter",
                        "original_sha256": provenance["source_sha256"],
                        "source_format": provenance["format"],
                        "original_id": raw.get("id"),
                        "normalized_id": loaded.documents[0].data["id"],
                        "normalization_status": "IN_MEMORY"}
    # The registry is the explicit adapter boundary. Native JSON, including
    # incomplete documents, should reach the canonical loader/validator so it
    # can return precise parse/schema diagnostics rather than an ambiguous
    # format-dispatch error.
    if isinstance(raw, dict) and "schema_version" in raw:
        return load_specification(source), {"format": "generic", "adapter": None}
    raise ValueError(
        "Unsupported specification format. Chọn JSON Specification chuẩn hoặc cài adapter tương thích. "
        "The file was not passed to the generic schema validator."
    )


def _is_smart_ev_teacher_document(raw: Any) -> bool:
    """Deprecated private alias retained for existing plugin integrations."""
    return is_legacy_teacher_specification(raw)
