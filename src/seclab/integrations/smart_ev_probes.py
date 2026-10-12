"""Optional orchestration for the standalone Smart-EV capability fixture."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from seclab.config import Toolchain
from seclab.evidence import ArtifactStore, Evidence, EvidenceType
from seclab.execution import CommandRunner, Compiler, capture_environment
from seclab.memory import ASanRunner, LeakChecker, UBSanRunner
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier
from seclab.source import SourceFile, SourceLoader
from seclab.static_analysis import (
    AnalysisContext,
    ClangTidyRunner,
    CompilerDiagnosticsRunner,
    CppcheckRunner,
    CWEMapper,
)


_EXPECTED_PROBES = {
    "buffer_overflow",
    "memory_leak",
    "double_free",
    "use_after_free",
}
_ALLOWED_SCOPES = {"TOOL_CAPABILITY_EVIDENCE", "BUG_INJECTED_PROBE"}
_RUNTIME_ISSUES = {
    "buffer_overflow": {"HEAP_BUFFER_OVERFLOW", "STACK_BUFFER_OVERFLOW", "GLOBAL_BUFFER_OVERFLOW"},
    "memory_leak": {"MEMORY_LEAK"},
    "double_free": {"DOUBLE_FREE"},
    "use_after_free": {"HEAP_USE_AFTER_FREE", "STACK_USE_AFTER_RETURN"},
}
_ANALYZERS = (
    ("compiler-diagnostics", CompilerDiagnosticsRunner),
    ("cppcheck", CppcheckRunner),
    ("clang-tidy", ClangTidyRunner),
)
_SANITIZERS = (
    ("AddressSanitizer", ASanRunner),
    ("UndefinedBehaviorSanitizer", UBSanRunner),
    ("LeakSanitizer", LeakChecker),
)


def load_probe_manifest(probe_root: str | Path) -> tuple[Path, dict[str, Any]]:
    """Load and strictly validate the four standalone probe declarations."""
    root = Path(probe_root).resolve(strict=True)
    manifest_path = root / "manifest.json"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("Probe manifest must be an object with schema_version=1.")
    if raw.get("evidence_class") != "TOOL_CAPABILITY_EVIDENCE":
        raise ValueError("Probe manifest must declare TOOL_CAPABILITY_EVIDENCE.")
    if raw.get("production_source_included") is not False:
        raise ValueError("Probe manifest must explicitly exclude production source.")
    entries = raw.get("probes")
    if not isinstance(entries, list) or len(entries) != 4:
        raise ValueError("Probe manifest must contain exactly four entries.")
    if {item.get("name") for item in entries if isinstance(item, dict)} != _EXPECTED_PROBES:
        raise ValueError("Probe manifest must declare exactly the four required probe names.")

    seen_ids: set[str] = set()
    for item in entries:
        required = {"probe_id", "name", "category", "language", "source_file", "expected_issue",
                    "expected_cwe", "expected_tools", "scope"}
        if not isinstance(item, dict) or not required <= item.keys():
            raise ValueError("Every probe entry must provide all required metadata fields.")
        if not item["probe_id"] or item["probe_id"] in seen_ids:
            raise ValueError("Probe IDs must be non-empty and unique.")
        seen_ids.add(item["probe_id"])
        if item["scope"] not in _ALLOWED_SCOPES or item["scope"] == "PRODUCTION_SOURCE":
            raise ValueError(f"Invalid production/probe scope for {item['name']}.")
        if item["language"] != "C" or item["category"] != item["name"]:
            raise ValueError(f"Unexpected language/category for {item['name']}.")
        if item["expected_cwe"] is not None and not _has_cwe_mapping(item["expected_cwe"]):
            raise ValueError(f"No existing CWEMapper mapping supports {item['expected_cwe']}.")
        relative = PurePosixPath(str(item["source_file"]))
        if (relative.is_absolute() or len(relative.parts) != 1 or relative.name in {"", ".", ".."}
                or "\\" in str(item["source_file"])):
            raise ValueError(f"Probe source must be a filename directly under the probe area: {item['source_file']!r}.")
        source = (root / relative.name).resolve(strict=True)
        if not source.is_relative_to(root) or not source.is_file() or source.suffix.lower() != ".c":
            raise ValueError(f"Probe source is missing, outside the probe area, or not C: {item['source_file']}.")
        if not isinstance(item["expected_tools"], list) or not item["expected_tools"]:
            raise ValueError(f"expected_tools must be a non-empty list for {item['name']}.")
    return root, raw


def run_smart_ev_probes(probe_root: str | Path, workspace_root: str | Path, *, timeout: float = 20.0) -> dict[str, Any]:
    """Run each probe independently and persist all generated evidence in workspace_root."""
    root, manifest = load_probe_manifest(probe_root)
    workspace = Path(workspace_root).resolve()
    if workspace == root or workspace.is_relative_to(root) or root.is_relative_to(workspace):
        raise ValueError("Probe source area and run workspace must be separate trees.")
    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise ValueError(f"Run workspace must be empty: {workspace}")
    temporary = workspace / "temporary"
    temporary.mkdir()
    previous_temp = {key: os.environ.get(key) for key in ("TMP", "TEMP", "TMPDIR")}
    for key in previous_temp:
        os.environ[key] = str(temporary)
    try:
        return _run_smart_ev_probes_in_workspace(root, workspace, manifest, timeout)
    finally:
        for key, value in previous_temp.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run_smart_ev_probes_in_workspace(root: Path, workspace: Path, manifest: dict[str, Any],
                                      timeout: float) -> dict[str, Any]:
    store = ArtifactStore(workspace)
    command_runner = CommandRunner()
    toolchain = Toolchain(tools=("gcc", "clang", "cppcheck", "clang-tidy"),
                          command_runner=command_runner, version_timeout=1.0)
    evidence: list[Evidence] = []
    environment_info = {**capture_environment(toolchain.summary()).to_dict(), "tools": toolchain.summary(),
                        "production_source_included": False,
                        "scope": "BUG_INJECTED_PROBE / TOOL_CAPABILITY_EVIDENCE"}
    evidence.append(store.write_json("probe_run", "toolchain.json", environment_info,
                                     evidence_type=EvidenceType.ENVIRONMENT,
                                     source="probe-capability-runner"))
    evidence.append(store.copy_file("probe_manifest", "manifest.json", root / "manifest.json",
                                    evidence_type=EvidenceType.SPECIFICATION,
                                    source="smart-ev-probe-manifest"))

    source_rows: dict[str, SourceFile] = {}
    source_hashes: dict[str, str] = {}
    for source in SourceLoader().load_source_tree(root):
        source_rows[source.relative_path] = source
        source_hashes[source.relative_path] = _sha256(source.path.read_bytes())
    if len(source_rows) != 4:
        raise ValueError(f"Expected exactly four C source files in probe area; found {len(source_rows)}.")

    probe_reports: list[dict[str, Any]] = []
    stopped_for_mutation = False
    for entry in manifest["probes"]:
        source = source_rows[entry["source_file"]]
        source_bytes = source.path.read_bytes()
        source_before = _sha256(source_bytes)
        expected_hash = source_hashes[source.relative_path]
        if source_before != expected_hash:
            stopped_for_mutation = True
            probe_reports.append(_not_run_after_mutation(entry, expected_hash, source_before))
            break

        probe_evidence: list[Evidence] = []
        source_artifact = store.write_bytes(
            "probe_sources", f"{entry['probe_id']}.c", source_bytes,
            evidence_type=EvidenceType.LOG, source="bug-injected-probe-source",
            metadata={"probe_id": entry["probe_id"], "scope": entry["scope"], "sha256": source_before,
                      "production_source": False},
        )
        manifest_artifact = store.write_json("probe_manifest", f"{entry['probe_id']}.json", entry,
                                              evidence_type=EvidenceType.SPECIFICATION,
                                              source="smart-ev-probe-manifest-entry")
        probe_evidence.extend((source_artifact, manifest_artifact))
        evidence.extend((source_artifact, manifest_artifact))

        runner_records: list[dict[str, Any]] = []
        compile_root = workspace / "tool_work" / entry["probe_id"] / "compile"
        compile_root.mkdir(parents=True, exist_ok=True)
        compiler_component = Compiler(compile_root, toolchain, command_runner=command_runner,
                                      artifact_store=store, timeout=timeout)
        build = compiler_component.build(
            (source,), "C", flags=("-Wall", "-Wextra", "-Wpedantic"), output_name="probe-program",
        )
        probe_evidence.extend(build.build_evidence)
        compiler_record = _build_record(build)
        compiler_evidence = store.write_json("probe_results", f"{entry['probe_id']}-compile.json",
                                              compiler_record, evidence_type=EvidenceType.TEST_RESULT,
                                              source="compiler")
        probe_evidence.append(compiler_evidence)
        runner_records.append({"tool": "compiler", "expected": "compile successfully where supported",
                               "observed": compiler_record, "evidence_ids": [item.id for item in build.build_evidence] + [compiler_evidence.id]})
        source_mutated = _sha256(source.path.read_bytes()) != source_before

        mapper = CWEMapper()
        for tool_name, runner_type in _ANALYZERS:
            if source_mutated:
                break
            context = _analysis_context(root, workspace, entry["probe_id"], tool_name, toolchain,
                                        command_runner, store, timeout)
            tool_evidence: tuple[Evidence, ...] = ()
            try:
                analysis = runner_type().analyze((source,), context)
                findings = [item.to_dict() for item in analysis.findings]
                mappings = [asdict(mapping) if mapping else None for mapping in
                            (mapper.map(item) for item in analysis.findings)]
                verification = analysis.to_verification_result().to_dict()
                command_rows = [_command_record(command) for command in analysis.command_results]
                record = {
                    "tool": tool_name,
                    "expected": {"issue": entry["expected_issue"], "cwe": entry["expected_cwe"]},
                    "observed": {"executed": analysis.executed, "successful": analysis.successful,
                                 "reason_code": analysis.reason_code, "findings": findings,
                                 "cwe_mappings": mappings, "verification_result": verification,
                                 "limitations": list(analysis.limitations), "commands": command_rows,
                                 "raw_output": _commands_raw_output(analysis.command_results)},
                }
                tool_evidence = analysis.evidence
                evidence.extend(tool_evidence)
                probe_evidence.extend(tool_evidence)
            except Exception as exc:
                record = {"tool": tool_name,
                          "expected": {"issue": entry["expected_issue"], "cwe": entry["expected_cwe"]},
                          "observed": {"executed": False, "successful": False, "result": "TOOL_ERROR",
                                       "error_type": type(exc).__name__, "error": str(exc), "findings": [],
                                       "cwe_mappings": [], "commands": [], "raw_output": ""}}
            source_mutated = _sha256(source.path.read_bytes()) != source_before
            artifact = store.write_json("probe_results", f"{entry['probe_id']}-{_file_token(tool_name)}.json",
                                        record, evidence_type=EvidenceType.STATIC_ANALYSIS_REPORT, source=tool_name)
            evidence.append(artifact)
            probe_evidence.append(artifact)
            record["evidence_ids"] = [artifact.id, *[item.id for item in tool_evidence]]
            runner_records.append(record)
            if source_mutated:
                break

        memory_observations: list[dict[str, Any]] = []
        for tool_name, runner_type in _SANITIZERS:
            if source_mutated:
                break
            context = _analysis_context(root, workspace, entry["probe_id"], tool_name, toolchain,
                                        command_runner, store, timeout)
            tool_evidence = ()
            try:
                run = runner_type().run((source,), context, "C", timeout=timeout)
                findings = [item.to_dict() for item in run.findings]
                command_rows = []
                if run.build_result and run.build_result.command_result:
                    command_rows.append({"phase": "build", **_command_record(run.build_result.command_result)})
                if run.execution_result:
                    command_rows.append({"phase": "runtime", **_command_record(run.execution_result)})
                memory_kind_to_issue = {kind: issue for issue, kinds in _RUNTIME_ISSUES.items() for kind in kinds}
                observed_issues = sorted({memory_kind_to_issue[item.kind] for item in run.findings
                                          if item.kind in memory_kind_to_issue})
                record = {
                    "tool": tool_name,
                    "expected": {"issue": entry["expected_issue"], "category": entry["category"],
                                 "cwe": entry["expected_cwe"]},
                    "observed": {"supported": run.supported, "findings": findings,
                                 "issue_categories": observed_issues,
                                 "expected_issue_observed": entry["category"] in observed_issues,
                                 "cwe_mappings": [None for _ in run.findings],
                                 "cwe_mapping_note": "Existing CWEMapper maps static Finding records only; no mapping is inferred for MemoryFinding.",
                                 "verification_result": run.verification_result.to_dict(),
                                 "limitations": list(run.limitations), "commands": command_rows,
                                 "build_error": run.build_result.error_code if run.build_result else None,
                                 "build_succeeded": run.build_result.success if run.build_result else None,
                                 "raw_output": _runtime_raw_output(run)},
                }
                tool_evidence = run.evidence
                evidence.extend(tool_evidence)
                probe_evidence.extend(tool_evidence)
            except Exception as exc:
                record = {"tool": tool_name,
                          "expected": {"issue": entry["expected_issue"], "category": entry["category"],
                                       "cwe": entry["expected_cwe"]},
                          "observed": {"supported": False, "findings": [], "issue_categories": [],
                                       "expected_issue_observed": False, "cwe_mappings": [],
                                       "result": "TOOL_ERROR", "error_type": type(exc).__name__,
                                       "error": str(exc), "limitations": ["Runner raised an exception."],
                                       "commands": [], "raw_output": ""}}
            source_mutated = _sha256(source.path.read_bytes()) != source_before
            artifact = store.write_json("probe_results", f"{entry['probe_id']}-{_file_token(tool_name)}.json",
                                        record, evidence_type=EvidenceType.SANITIZER_REPORT, source=tool_name)
            evidence.append(artifact)
            probe_evidence.append(artifact)
            record["evidence_ids"] = [artifact.id, *[item.id for item in tool_evidence]]
            runner_records.append(record)
            memory_observations.append(record)
            if source_mutated:
                break

        source_after = _sha256(source.path.read_bytes())
        source_intact = source_before == source_after == expected_hash
        integrity = {"probe_id": entry["probe_id"], "source_file": entry["source_file"],
                     "sha256_before": source_before, "sha256_after": source_after,
                     "sha256_manifest_baseline": expected_hash, "equal": source_intact}
        integrity_artifact = store.write_json("probe_integrity", f"{entry['probe_id']}-source-integrity.json",
                                              integrity, evidence_type=EvidenceType.TEST_RESULT,
                                              source="probe-source-integrity")
        probe_evidence.append(integrity_artifact)
        evidence.append(integrity_artifact)

        matching = [item for item in memory_observations
                    if item.get("observed", {}).get("expected_issue_observed") is True]
        runtime_results = [item.get("observed", {}).get("verification_result", {}) for item in memory_observations]
        runtime_supported = any(item.get("observed", {}).get("supported") is True for item in memory_observations)
        any_tool_executed = any(item.get("observed", {}).get("executed") is True for item in runner_records)
        if not source_intact:
            stopped_for_mutation = True
            capability_observation = "SOURCE_MUTATED"
            result = _probe_result(entry, probe_evidence, RawOutcome.TOOL_FAILED, "SOURCE_MUTATED",
                                   "Probe source hash changed during execution; remaining probes were stopped.", integrity)
        elif matching:
            capability_observation = "OBSERVED"
            result = _probe_result(entry, probe_evidence, RawOutcome.PROPERTY_VIOLATED,
                                   "EXPECTED_ISSUE_OBSERVED", "A runtime analyzer reported the expected issue class in this probe scope.",
                                   {**integrity, "observed_tools": [item["tool"] for item in matching]})
        elif not runtime_supported and not any_tool_executed:
            capability_observation = "INCONCLUSIVE"
            result = _probe_result(entry, probe_evidence, RawOutcome.TOOL_FAILED, "NO_SUPPORTED_TOOL_EXECUTED",
                                   "No supported analyzer or sanitizer could be executed for this probe.", integrity)
        else:
            static_findings_reported = any(
                item.get("tool") in {"compiler-diagnostics", "cppcheck", "clang-tidy"}
                and any(finding.get("rule_id") or finding.get("category") in {"warning", "error"}
                        for finding in item.get("observed", {}).get("findings", []))
                for item in runner_records
            )
            capability_observation = "STATIC_FINDINGS_REPORTED" if static_findings_reported else "NOT_OBSERVED"
            reason = "STATIC_FINDINGS_REPORTED" if static_findings_reported else "EXPECTED_ISSUE_NOT_OBSERVED"
            message = ("Static analyzer diagnostics were observed; they remain scoped inconclusive evidence, and no runtime finding confirmed the expected class."
                       if static_findings_reported else
                       "No static finding or runtime sanitizer report confirmed the expected issue class in this run.")
            result = _probe_result(entry, probe_evidence, RawOutcome.UNKNOWN, reason, message,
                                   {**integrity, "static_findings_present": static_findings_reported,
                                    "runtime_results": runtime_results})
        final_artifact = store.write_json("probe_results", f"{entry['probe_id']}-final-result.json",
                                          result.to_dict(), evidence_type=EvidenceType.TEST_RESULT,
                                          source="probe-scoped-result")
        evidence.append(final_artifact)
        result_evidence = [*probe_evidence, final_artifact]
        probe_reports.append({
            "probe_id": entry["probe_id"], "name": entry["name"], "category": entry["category"],
            "scope": entry["scope"], "production_source": False,
            "expected": {"issue": entry["expected_issue"], "cwe": entry["expected_cwe"],
                         "tools": entry["expected_tools"]},
            "observed": {"capability_observation": capability_observation,
                         "finding_count": sum(len(item.get("observed", {}).get("findings", [])) for item in runner_records),
                         "tools": runner_records, "source_integrity": integrity},
            "result": result.to_dict(), "evidence_ids": [item.id for item in result_evidence],
        })
        if stopped_for_mutation:
            break

    if stopped_for_mutation:
        for entry in manifest["probes"][len(probe_reports):]:
            probe_reports.append(_not_run_after_mutation(entry, source_hashes.get(entry["source_file"]), None))

    report = {
        "report_type": "SMART_EV_PROBE_CAPABILITY_REPORT",
        "run_id": workspace.name,
        "scope": "TOOL_CAPABILITY_EVIDENCE",
        "production_source_affected": 0,
        "production_vulnerability_claim": False,
        "manifest_sha256": _sha256((root / "manifest.json").read_bytes()),
        "probe_root": str(root),
        "workspace": str(workspace),
        "environment": environment_info,
        "source_integrity": [item["observed"].get("source_integrity") for item in probe_reports
                              if item.get("observed", {}).get("source_integrity")],
        "probes": probe_reports,
    }
    report_artifact = store.write_json("probe_run", "capability-report.json", report,
                                       evidence_type=EvidenceType.TEST_RESULT,
                                       source="probe-capability-runner")
    evidence.append(report_artifact)
    report["report_evidence_id"] = report_artifact.id
    report["evidence"] = [item.to_dict() for item in evidence]
    (workspace / "probe-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run_manifest = {
        "run_id": workspace.name,
        "scope": "TOOL_CAPABILITY_EVIDENCE",
        "production_source_affected": 0,
        "production_vulnerability_claim": False,
        "evidence": [item.to_dict() for item in evidence],
    }
    (workspace / "run-manifest.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def _analysis_context(root: Path, workspace: Path, probe_id: str, tool: str, toolchain: Toolchain,
                      command_runner: CommandRunner, store: ArtifactStore, timeout: float) -> AnalysisContext:
    work = workspace / "tool_work" / probe_id / _file_token(tool)
    work.mkdir(parents=True, exist_ok=True)
    return AnalysisContext(root, work, toolchain, command_runner, store, timeout=timeout)


def _build_record(build: Any) -> dict[str, Any]:
    command = build.command_result
    return {
        "success": build.success, "error_code": build.error_code, "language": build.language,
        "compiler": build.compiler.to_dict() if build.compiler else None,
        "source_files": list(build.source_files), "binary_path": str(build.binary_path) if build.binary_path else None,
        "command": _command_record(command) if command else None,
        "build_evidence_ids": [item.id for item in build.build_evidence],
    }


def _command_record(command: Any) -> dict[str, Any]:
    return {
        "argv": list(command.argv), "cwd": command.cwd, "exit_code": command.exit_code,
        "succeeded": command.succeeded, "timed_out": command.timed_out,
        "execution_error": command.execution_error, "executable_path": command.executable_path,
        "duration_ms": command.duration_ms, "stdout": command.stdout, "stderr": command.stderr,
    }


def _commands_raw_output(commands: Any) -> str:
    return "\n".join((f"$ {' '.join(item.argv)}\n{item.stdout}\n{item.stderr}").rstrip()
                     for item in commands)


def _runtime_raw_output(run: Any) -> str:
    output = []
    if run.build_result and run.build_result.command_result:
        command = run.build_result.command_result
        output.append(f"$ {' '.join(command.argv)}\n{command.stdout}\n{command.stderr}")
    if run.execution_result:
        command = run.execution_result
        output.append(f"$ {' '.join(command.argv)}\n{command.stdout}\n{command.stderr}")
    return "\n".join(output).rstrip()


def _probe_result(entry: Mapping[str, Any], evidence: list[Evidence], outcome: RawOutcome,
                  reason: str, message: str, metadata: Mapping[str, Any]):
    return ResultClassifier().classify(ClassificationInput(
        outcome=outcome, stage="PROBE_CAPABILITY", technique="EXISTING_ANALYZERS",
        reason_code=reason, message=message,
        scope=f"{entry['scope']} only for {entry['name']}; no production-source claim is made.",
        evidence_ids=tuple(item.id for item in evidence),
        metadata={"probe_id": entry["probe_id"], "category": entry["category"],
                  "expected_cwe": entry["expected_cwe"], **dict(metadata)},
    ))


def _not_run_after_mutation(entry: Mapping[str, Any], baseline: str | None, current: str | None) -> dict[str, Any]:
    return {"probe_id": entry["probe_id"], "name": entry["name"], "category": entry["category"],
            "scope": entry["scope"], "production_source": False,
            "expected": {"issue": entry["expected_issue"], "cwe": entry["expected_cwe"],
                         "tools": entry["expected_tools"]},
            "observed": {"capability_observation": "NOT_RUN_SOURCE_MUTATED",
                         "source_integrity": {"sha256_before": baseline, "sha256_after": current,
                                               "equal": baseline is not None and baseline == current},
                         "tools": []},
            "result": None, "evidence_ids": []}


def _has_cwe_mapping(value: str) -> bool:
    """Manifest expectations only accept CWE IDs present in the existing trusted mapper."""
    mapper = CWEMapper()
    for tool, rule in (("clang-tidy", "clang-analyzer-core.NullDereference"),
                       ("clang-static-analyzer", "core.NullDereference")):
        from seclab.static_analysis import make_finding
        sample = make_finding(tool=tool, file="probe.c", line=1, severity="warning",
                              category="expected", message="mapping validation", rule_id=rule)
        mapping = mapper.map(sample)
        if mapping and mapping.cwe_id == value:
            return True
    return False


def _file_token(value: str) -> str:
    return "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
