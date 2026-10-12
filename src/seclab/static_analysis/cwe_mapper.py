"""Conservative mapping from trusted analyzer rule IDs to CWE identifiers."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .finding import Finding


@dataclass(frozen=True, slots=True)
class CWEMapping:
    cwe_id: str
    source: str
    confidence: str
    reason: str


_RULE_MAP: dict[tuple[str, str], CWEMapping] = {
    ("clang-tidy", "clang-analyzer-core.NullDereference"): CWEMapping(
        "CWE-476", "rule_id", "high", "The specific Clang Static Analyzer null-dereference check maps directly to CWE-476."
    ),
    ("clang-static-analyzer", "core.NullDereference"): CWEMapping(
        "CWE-476", "rule_id", "high", "The specific Clang Static Analyzer null-dereference check maps directly to CWE-476."
    ),
}


class CWEMapper:
    def map(self, finding: Finding) -> CWEMapping | None:
        if finding.cwe:
            return CWEMapping(finding.cwe, "tool", "tool-provided", "The analyzer supplied an explicit CWE identifier.")
        if finding.rule_id:
            return _RULE_MAP.get((finding.tool.lower(), finding.rule_id))
        return None

    def apply(self, finding: Finding) -> Finding:
        mapping = self.map(finding)
        if mapping is None or finding.cwe:
            return finding
        metadata = dict(finding.metadata)
        metadata["cwe_mapping"] = {"source": mapping.source, "confidence": mapping.confidence,
                                   "reason": mapping.reason}
        return replace(finding, cwe=mapping.cwe_id, confidence=mapping.confidence, metadata=metadata)
