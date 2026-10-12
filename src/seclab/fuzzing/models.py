"""Structured input, strategy, and budget models for bounded fuzz campaigns."""
from __future__ import annotations

import hashlib
import json
import math
import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping


class InputKind(StrEnum):
    BYTES = "BYTES"
    TEXT = "TEXT"
    SCALARS = "SCALARS"


class InputOrigin(StrEnum):
    SEED = "SEED"
    BLACKBOX = "BLACKBOX"
    BOUNDARY = "BOUNDARY"
    MUTATION = "MUTATION"
    COVERAGE_GUIDED = "COVERAGE_GUIDED"
    GRAMMAR = "GRAMMAR"
    CONCOLIC = "CONCOLIC"


class FuzzStrategy(StrEnum):
    BLACKBOX = "BLACKBOX"
    BOUNDARY = "BOUNDARY"
    MUTATION = "MUTATION"
    COVERAGE_GUIDED = "COVERAGE_GUIDED"
    GRAMMAR = "GRAMMAR"
    CONCOLIC = "CONCOLIC"


def _canonical(value: Any) -> bytes:
    if isinstance(value, bytes):
        return b"bytes\0" + value
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class FuzzInput:
    id: str
    data: bytes | str | Mapping[str, Any] | int | float | bool
    kind: InputKind
    origin: InputOrigin
    parent_id: str | None = None
    generation: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", InputKind(self.kind))
        object.__setattr__(self, "origin", InputOrigin(self.origin))
        if self.kind is InputKind.BYTES and not isinstance(self.data, bytes):
            raise TypeError("BYTES input requires bytes")
        if self.kind is InputKind.TEXT and not isinstance(self.data, str):
            raise TypeError("TEXT input requires str")
        if self.kind is InputKind.SCALARS and not isinstance(self.data, (Mapping, int, float, bool)):
            raise TypeError("SCALARS input requires a scalar or mapping")
        if isinstance(self.data, float) and not math.isfinite(self.data):
            raise ValueError("Fuzz input numbers must be finite")
        if self.generation < 0:
            raise ValueError("generation must be non-negative")
        json.dumps(dict(self.metadata), sort_keys=True, allow_nan=False)

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.kind.value.encode() + b"\0" + _canonical(self.data)).hexdigest()

    @property
    def size(self) -> int:
        if self.kind is InputKind.BYTES:
            return len(self.data)
        if self.kind is InputKind.TEXT:
            return len(self.data.encode("utf-8"))
        return len(_canonical(self.data))

    def to_dict(self, *, include_data: bool = True) -> dict[str, Any]:
        if isinstance(self.data, bytes):
            data: Any = {"base64": __import__("base64").b64encode(self.data).decode("ascii")} if include_data else None
        else:
            data = self.data if include_data else None
        return {"id": self.id, "kind": self.kind.value, "data": data, "origin": self.origin.value,
                "parent_id": self.parent_id, "generation": self.generation, "metadata": dict(self.metadata),
                "content_hash": self.content_hash, "size_bytes": self.size}


@dataclass(frozen=True, slots=True)
class FuzzConfig:
    strategy: FuzzStrategy
    max_iterations: int
    timeout_per_input: float
    random_seed: int | None
    max_input_size: int
    max_mutations_per_input: int = 8
    max_seconds: float | None = None
    stop_on_first_failure: bool = False
    minimize_failures: bool = True
    max_minimization_executions: int = 64
    target: str | None = None
    entry_point: str | None = None
    harness: str = "auto"
    corpus_directory: str | Path | None = None
    fallback_to_blackbox: bool = False
    max_executions: int | None = None
    max_input_count: int | None = None
    grammar_start: str = "<start>"
    grammar_rules: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "strategy", FuzzStrategy(self.strategy))
        if self.random_seed is None:
            object.__setattr__(self, "random_seed", secrets.randbits(64))
        elif isinstance(self.random_seed, bool) or not isinstance(self.random_seed, int):
            raise ValueError("random_seed must be an integer or None")
        if self.target and self.entry_point and self.target != self.entry_point:
            raise ValueError("target and entry_point must identify the same entry when both are set")
        if self.harness not in {"auto", "function", "executable"}:
            raise ValueError("harness must be 'auto', 'function', or 'executable'")
        if self.corpus_directory is not None:
            object.__setattr__(self, "corpus_directory", str(self.corpus_directory))
        object.__setattr__(self, "grammar_rules", dict(self.grammar_rules))
        if self.strategy is FuzzStrategy.GRAMMAR:
            if not self.grammar_start or self.grammar_start not in self.grammar_rules:
                raise ValueError("grammar_start must name a rule in grammar_rules")
        if (isinstance(self.max_iterations, bool) or not isinstance(self.max_iterations, int) or self.max_iterations <= 0
                or isinstance(self.timeout_per_input, bool) or not isinstance(self.timeout_per_input, (int, float))
                or not math.isfinite(self.timeout_per_input) or self.timeout_per_input <= 0
                or isinstance(self.max_input_size, bool) or not isinstance(self.max_input_size, int) or self.max_input_size <= 0):
            raise ValueError("iteration, timeout, and input-size budgets must be positive")
        if self.max_mutations_per_input <= 0 or self.max_minimization_executions < 0:
            raise ValueError("mutation budget must be positive and minimization budget non-negative")
        if self.max_seconds is not None and (isinstance(self.max_seconds, bool)
                or not isinstance(self.max_seconds, (int, float)) or not math.isfinite(self.max_seconds)
                or self.max_seconds <= 0):
            raise ValueError("max_seconds must be finite and positive")
        for name in ("max_executions", "max_input_count"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise ValueError(f"{name} must be a positive integer when provided")


@dataclass(frozen=True, slots=True)
class FailureSignature:
    kind: str
    exit_code: int | None = None
    signal: int | None = None
    sanitizer: str | None = None
    oracle_id: str | None = None
    detail: str | None = None

    @property
    def key(self) -> str:
        return hashlib.sha256(json.dumps({"kind": self.kind, "exit_code": self.exit_code, "signal": self.signal,
            "sanitizer": self.sanitizer, "oracle_id": self.oracle_id, "detail": self.detail},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "exit_code": self.exit_code, "signal": self.signal,
                "sanitizer": self.sanitizer, "oracle_id": self.oracle_id, "detail": self.detail, "key": self.key}


@dataclass(frozen=True, slots=True)
class CrashAnalysis:
    classification: str
    signature: FailureSignature | None = None
    finding: bool = False


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    input: FuzzInput
    coverage_signature: tuple[str, ...] = ()
    discovered_at_iteration: int = 0
    parent_id: str | None = None
    retention_reason: str = "seed"
    failure_signature: FailureSignature | None = None


@dataclass(frozen=True, slots=True)
class FuzzFinding:
    input: FuzzInput
    signature: FailureSignature
    classification: str
    minimized_input: FuzzInput | None = None
    verification_result: Any = None
    evidence_ids: tuple[str, ...] = ()
    minimization_executions: int = 0
    minimized: bool = False
    minimization_error: str | None = None
    oracle_evaluation: Mapping[str, Any] = field(default_factory=dict)
    observation: Mapping[str, Any] | None = None
    command_diagnostic: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"input": self.input.to_dict(), "signature": self.signature.to_dict(),
                "classification": self.classification,
                "minimized_input": self.minimized_input.to_dict() if self.minimized_input else None,
                "minimization_executions": self.minimization_executions,
                "minimized": self.minimized, "minimization_error": self.minimization_error,
                "verification_result": self.verification_result.to_dict() if self.verification_result else None,
                "oracle_evaluation": dict(self.oracle_evaluation),
                "observation": dict(self.observation) if self.observation else None,
                "command_diagnostic": dict(self.command_diagnostic),
                "evidence_ids": list(self.evidence_ids)}


@dataclass(frozen=True, slots=True)
class FuzzCampaignResult:
    strategy: FuzzStrategy
    seed: int
    iterations_requested: int
    iterations_executed: int
    unique_inputs: int
    corpus_size: int
    failures: tuple[FuzzFinding, ...]
    crashes: int
    timeouts: int
    oracle_failures: int
    coverage_start: tuple[str, ...] = ()
    coverage_end: tuple[str, ...] = ()
    coverage_delta: tuple[str, ...] = ()
    duration_seconds: float = 0.0
    stop_reason: str = "ITERATION_LIMIT"
    verification_result: Any = None
    evidence_ids: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    source_hashes_before: Mapping[str, str] = field(default_factory=dict)
    source_hashes_after: Mapping[str, str] = field(default_factory=dict)
    source_integrity_unchanged: bool = True
    executions_requested: int = 0
    input_count_requested: int = 0
    execution_evidence: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"strategy": self.strategy.value, "seed": self.seed,
                "iterations_requested": self.iterations_requested, "iterations_executed": self.iterations_executed,
                "unique_inputs": self.unique_inputs, "corpus_size": self.corpus_size,
                "failures": [item.to_dict() for item in self.failures], "crashes": self.crashes,
                "timeouts": self.timeouts, "oracle_failures": self.oracle_failures,
                "coverage_start": list(self.coverage_start), "coverage_end": list(self.coverage_end),
                "coverage_delta": list(self.coverage_delta), "duration_seconds": self.duration_seconds,
                "stop_reason": self.stop_reason,
                "verification_result": self.verification_result.to_dict() if self.verification_result else None,
                "evidence_ids": list(self.evidence_ids), "errors": list(self.errors),
                "source_hashes_before": dict(sorted(self.source_hashes_before.items())),
                "source_hashes_after": dict(sorted(self.source_hashes_after.items())),
                "source_integrity_unchanged": self.source_integrity_unchanged,
                "executions_requested": self.executions_requested,
                "input_count_requested": self.input_count_requested,
                "execution_evidence": [dict(item) for item in self.execution_evidence]}
