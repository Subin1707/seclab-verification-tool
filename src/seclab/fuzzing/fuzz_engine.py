"""Deterministic bounded fuzz campaign orchestration over shared runners."""
from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from seclab.coverage import CoverageRunner, CoverageSnapshot
from seclab.evidence import ArtifactStore, EvidenceType
from seclab.results import ClassificationInput, RawOutcome, ResultClassifier, VerificationStatus
from seclab.source import Language, SourceFile
from seclab.testing import ExpectedBehavior, TestCase, TestCategory, TestExecutionResult, TestRunner, TestTargetKind

from .blackbox import BlackBoxFuzzer
from .boundary import BoundaryGenerator
from .corpus import Corpus
from .coverage_guided import CoverageGuidedFuzzer
from .grammar import GrammarFuzzer
from .crash_analyzer import CrashAnalyzer
from .input_minimizer import InputMinimizer
from .models import (FailureSignature, FuzzCampaignResult, FuzzConfig, FuzzFinding,
                     FuzzInput, FuzzStrategy, InputKind, InputOrigin)
from .mutation import InputMutator


class FuzzEngine:
    def __init__(self, workspace_root: str | Path, test_runner: TestRunner, *,
                 coverage_runner: CoverageRunner | None = None, artifact_store: ArtifactStore | None = None,
                 classifier: ResultClassifier | None = None) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.test_runner = test_runner
        self.coverage_runner = coverage_runner
        self.artifact_store = artifact_store or test_runner.artifact_store
        self.classifier = classifier or ResultClassifier()

    def run(self, template: TestCase, config: FuzzConfig, *, seeds: Iterable[FuzzInput] = (),
            specification=None, source_files: Iterable[SourceFile | str | Path] = (),
            language: Language | str | None = None, executable: str | Path | None = None,
            backend: str = "auto", no_crash_is_failure: bool | None = None,
            progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
            cancel_event: Any = None) -> FuzzCampaignResult:
        started = time.monotonic()
        campaign_id = uuid.uuid4().hex[:12]
        source_tuple, seed_inputs = tuple(source_files), tuple(seeds)
        template = _configured_template(template, config)
        try:
            seed_inputs = (*seed_inputs, *_load_corpus(config.corpus_directory))
        except OSError as exc:
            return self._unsupported(template, config, "FUZZ_CORPUS_READ_ERROR", str(exc), started)
        source_before, source_error = _source_hashes(source_tuple)
        if source_error:
            return self._unsupported(template, config, "FUZZ_SOURCE_INTEGRITY_ERROR", source_error, started)
        execution_budget = config.max_executions or config.max_iterations
        input_budget = config.max_input_count or config.max_iterations
        strategy = config.strategy
        fallback_used = False
        if strategy is FuzzStrategy.CONCOLIC:
            return self._unsupported(template, config, "CONCOLIC_TARGET_UNSUPPORTED",
                "FuzzEngine does not implement target branch tracing. ConcolicGenerator is a prototype for caller-supplied constraints only.", started)
        if strategy is FuzzStrategy.COVERAGE_GUIDED and (self.coverage_runner is None or not source_tuple):
            if config.fallback_to_blackbox:
                strategy = FuzzStrategy.BLACKBOX
                fallback_used = True
            else:
                return self._unsupported(template, config, "COVERAGE_FEEDBACK_UNAVAILABLE",
                    "Coverage-guided strategy requires source files and CoverageRunner.", started)
        if strategy in {FuzzStrategy.MUTATION, FuzzStrategy.COVERAGE_GUIDED} and not seed_inputs:
            if strategy is FuzzStrategy.COVERAGE_GUIDED and config.fallback_to_blackbox:
                strategy = FuzzStrategy.BLACKBOX
                fallback_used = True
            else:
                return self._unsupported(template, config, "EMPTY_SEED_CORPUS", "Mutation strategies require at least one seed.", started)
        rng = random.Random(config.random_seed)
        scalar_names = tuple(template.inputs) if template.target_kind is TestTargetKind.FUNCTION else ()
        blackbox = BlackBoxFuzzer(rng, max_input_size=config.max_input_size, scalar_names=scalar_names)
        grammar = None
        if strategy is FuzzStrategy.GRAMMAR:
            try:
                grammar = GrammarFuzzer(rng, config.grammar_start, config.grammar_rules,
                                        max_input_size=config.max_input_size)
            except (TypeError, ValueError) as exc:
                return self._unsupported(template, config, "INVALID_FUZZ_GRAMMAR", str(exc), started)
        mutator = InputMutator(rng, max_input_size=config.max_input_size,
                               max_mutations_per_input=config.max_mutations_per_input)
        corpus = Corpus(seed_inputs)
        coverage_fuzzer = CoverageGuidedFuzzer(self.coverage_runner) if self.coverage_runner else None
        known_coverage = CoverageSnapshot(frozenset(), frozenset())
        failures: list[FuzzFinding] = []
        seen_failures: set[str] = set()
        seen_inputs: set[str] = set()
        all_evidence: list[str] = []
        artifact_refs = []
        input_evidence_by_hash: dict[str, str] = {}
        errors: list[str] = []
        observation_evidence_limit = 256
        observation_evidence_written = 0
        execution_evidence: list[dict[str, Any]] = []
        # Keep seed corpus inputs for reproducibility; generated candidates are
        # retained only when they add coverage or reproduce a finding.
        for index, seed in enumerate(corpus.inputs):
            seed_ref = self.artifact_store.write_bytes("fuzz-corpus", f"{campaign_id}-seed-{index:06d}.bin",
                _input_bytes(seed), evidence_type=EvidenceType.LOG, source="fuzz-engine",
                requirement_id=template.requirement_id, property_id=template.property_id,
                metadata={"input_id": seed.id, "sha256": seed.content_hash, "origin": seed.origin.value})
            all_evidence.append(seed_ref.id)
            artifact_refs.append(seed_ref)
            input_evidence_by_hash[seed.content_hash] = seed_ref.id
        reproducibility_config = {"requested_strategy": config.strategy.value, "effective_strategy": strategy.value,
            "random_seed": config.random_seed, "max_iterations": config.max_iterations,
            "max_executions": execution_budget, "max_input_count": input_budget,
            "max_seconds": config.max_seconds, "timeout_per_input": config.timeout_per_input,
            "max_input_size": config.max_input_size, "max_mutations_per_input": config.max_mutations_per_input,
            "grammar_start": config.grammar_start, "grammar_rules": dict(config.grammar_rules),
            "stop_on_first_failure": config.stop_on_first_failure, "minimize_failures": config.minimize_failures,
            "max_minimization_executions": config.max_minimization_executions,
            "target": template.target, "target_kind": template.target_kind.value,
            "entry_point": config.entry_point or config.target or template.target,
            "harness": config.harness, "source_hashes": source_before}
        configuration_sha256 = hashlib.sha256(json.dumps(reproducibility_config, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        manifest = self.artifact_store.write_json("fuzz-campaigns", f"{campaign_id}-manifest.json", {
            "campaign_id": campaign_id, "target": template.target, "target_kind": template.target_kind.value,
            "entry_point": config.entry_point or config.target or template.target,
            "harness": config.harness, "requested_strategy": config.strategy.value,
            "effective_strategy": strategy.value, "random_seed": config.random_seed,
            "seed_inputs": [{"id": item.id, "sha256": item.content_hash, "origin": item.origin.value}
                            for item in corpus.inputs],
            "oracle": template.expected.to_dict() if template.expected else None,
            "max_iterations": config.max_iterations, "max_executions": execution_budget,
            "max_input_count": input_budget, "max_seconds": config.max_seconds,
            "timeout_per_input": config.timeout_per_input, "max_input_size": config.max_input_size,
            "max_mutations_per_input": config.max_mutations_per_input,
            "grammar_start": config.grammar_start, "grammar_rules": dict(config.grammar_rules),
            "stop_on_first_failure": config.stop_on_first_failure,
            "minimize_failures": config.minimize_failures,
            "max_minimization_executions": config.max_minimization_executions,
            "corpus_directory": config.corpus_directory,
            "source_hashes": source_before, "reproducibility_config": reproducibility_config,
            "configuration_sha256": configuration_sha256,
            "coverage_backend": backend if strategy is FuzzStrategy.COVERAGE_GUIDED else None,
            "bounded_campaign": True, "measurement_only": True,
        }, evidence_type=EvidenceType.TEST_RESULT, source="fuzz-engine",
            requirement_id=template.requirement_id, property_id=template.property_id,
            metadata={"campaign_id": campaign_id, "strategy": strategy.value, "random_seed": config.random_seed,
                      "source_hashes": source_before, "configuration_sha256": configuration_sha256})
        all_evidence.append(manifest.id)
        artifact_refs.append(manifest)
        progress_error = _notify_fuzz_progress(progress_callback, {"event": "campaign_started", "campaign_id": campaign_id,
            "requested": config.max_iterations, "completed": 0, "strategy": strategy.value,
            "random_seed": config.random_seed})
        if progress_error:
            errors.append(progress_error)
        crashes = timeouts = oracle_failures = executed = 0
        input_count = 0
        stop_reason = "ITERATION_LIMIT"
        queue = list(corpus.inputs)
        analyzer = CrashAnalyzer()
        minimizer = InputMinimizer()
        build_error = unavailable_target = False
        tool_error = bool(progress_error)
        for iteration in range(config.max_iterations):
            if _is_cancelled(cancel_event):
                stop_reason = "CANCELLED"; break
            if config.max_seconds is not None and time.monotonic() - started >= config.max_seconds:
                stop_reason = "TIME_LIMIT"; break
            if executed >= execution_budget:
                stop_reason = "EXECUTION_LIMIT"; break
            if input_count >= input_budget:
                stop_reason = "INPUT_LIMIT"; break
            if iteration < len(queue):
                candidate = queue[iteration]
            elif strategy is FuzzStrategy.BLACKBOX:
                candidate = blackbox.generate(iteration)
            elif strategy is FuzzStrategy.GRAMMAR:
                try:
                    candidate = grammar.generate(iteration,
                        structured=template.target_kind is TestTargetKind.FUNCTION,
                        required_fields=tuple(template.inputs) if template.target_kind is TestTargetKind.FUNCTION else ())
                except ValueError as exc:
                    errors.append(f"INVALID_FUZZ_GRAMMAR: {exc}")
                    stop_reason = "INVALID_FUZZ_GRAMMAR"; tool_error = True; break
            elif strategy is FuzzStrategy.BOUNDARY:
                boundaries = BoundaryGenerator(specification, max_input_size=config.max_input_size).generate() if specification else ()
                candidate = boundaries[(iteration-len(queue)) % len(boundaries)] if boundaries else blackbox.generate(iteration)
                if not boundaries:
                    candidate = replace(candidate, origin=InputOrigin.BOUNDARY,
                                        metadata={"generator": "boundary-fallback-no-domain"})
            elif strategy in {FuzzStrategy.MUTATION, FuzzStrategy.COVERAGE_GUIDED}:
                parents = corpus.inputs
                parent = parents[rng.randrange(len(parents))]
                candidate = mutator.mutate(parent, iteration)
                if strategy is FuzzStrategy.COVERAGE_GUIDED:
                    candidate = replace(candidate, origin=InputOrigin.COVERAGE_GUIDED,
                                         metadata={**dict(candidate.metadata), "generator": "coverage-guided-mutation"})
            else:
                errors.append("CONCOLIC_TARGET_UNSUPPORTED: use ConcolicGenerator.solve_alternate with an explicit instrumented branch constraint")
                stop_reason = "CONCOLIC_TARGET_UNSUPPORTED"; break
            if candidate.kind in {InputKind.BYTES, InputKind.TEXT} and candidate.size > config.max_input_size:
                errors.append(f"input {candidate.id} exceeds max_input_size")
                continue
            input_count += 1
            seen_inputs.add(candidate.content_hash)
            timeout = _remaining_timeout(config, started)
            if timeout is not None and timeout <= 0:
                stop_reason = "TIME_LIMIT"; break
            case = _test_case(template, candidate, timeout)
            _notify_fuzz_progress(progress_callback, {"event": "input_generated", "campaign_id": campaign_id,
                "requested": config.max_iterations, "completed": iteration, "input_id": candidate.id})
            coverage_before_iteration = known_coverage
            coverage_run = None
            if strategy is FuzzStrategy.COVERAGE_GUIDED:
                try:
                    coverage_run = self.coverage_runner.run((case,), source_files=source_tuple, language=language,
                        backend=backend, run_id=f"fuzz-{campaign_id}-{iteration:06d}", persist_process_output=False)
                except Exception as exc:
                    errors.append(f"coverage feedback failed: {type(exc).__name__}: {exc}")
                if coverage_run is None or coverage_run.report is None or not coverage_run.test_results:
                    if config.fallback_to_blackbox:
                        if coverage_run is None:
                            fallback_reason = "coverage adapter raised an exception"
                        elif coverage_run.errors:
                            fallback_reason = "; ".join(coverage_run.errors)
                        elif coverage_run.verification_result is not None:
                            fallback_reason = coverage_run.verification_result.reason_code
                        else:
                            fallback_reason = "coverage report unavailable"
                        fallback_ref = self.artifact_store.write_json("fuzz-campaigns",
                            f"{campaign_id}-{iteration:06d}-coverage-fallback.json", {
                                "campaign_id": campaign_id, "iteration": iteration,
                                "from_strategy": strategy.value, "to_strategy": FuzzStrategy.BLACKBOX.value,
                                "reason": fallback_reason, "bounded_campaign": True,
                            }, evidence_type=EvidenceType.ENVIRONMENT, source="fuzz-engine",
                            requirement_id=template.requirement_id, property_id=template.property_id,
                            metadata={"campaign_id": campaign_id, "iteration": iteration})
                        all_evidence.append(fallback_ref.id)
                        artifact_refs.append(fallback_ref)
                        strategy = FuzzStrategy.BLACKBOX
                        fallback_used = True
                        if coverage_run is not None:
                            all_evidence.extend(coverage_run.evidence_ids)
                        test_result = self.test_runner.run_many((case,), source_files=source_tuple, language=language,
                            executable=executable, persist_process_output=False).executions[0]
                        all_evidence.extend(test_result.evidence_ids)
                        artifact_refs.extend(_result_evidence(test_result))
                    else:
                        if coverage_run is not None:
                            errors.extend(coverage_run.errors or (coverage_run.verification_result.reason_code if coverage_run.verification_result else "coverage failed",))
                        stop_reason = "COVERAGE_FEEDBACK_UNAVAILABLE"; tool_error = True; break
                else:
                    test_result = coverage_run.test_results[0]
                    artifact_refs.extend(_result_evidence(test_result))
                    snap = self.coverage_runner.snapshot(coverage_run.report)
                    delta = self.coverage_runner.delta(_report_from_snapshot(known_coverage, coverage_run.report), coverage_run.report)
                    current_coverage = CoverageSnapshot(known_coverage.lines | snap.lines, known_coverage.branches | snap.branches)
                    covsig = coverage_fuzzer.signature(snap)
                    if delta.new_lines or delta.new_branches:
                        corpus.add(candidate, coverage_signature=covsig, discovered_at_iteration=iteration,
                                   parent_id=candidate.parent_id, retention_reason="new coverage entities")
                        ref = self.artifact_store.write_bytes("fuzz-inputs", f"{campaign_id}-{iteration:06d}-coverage.bin",
                            _input_bytes(candidate), evidence_type=EvidenceType.LOG, source="fuzz-engine",
                            requirement_id=template.requirement_id, property_id=template.property_id,
                            metadata={"input_id": candidate.id, "sha256": candidate.content_hash,
                                      "coverage_signature": list(covsig), "retention_reason": "new coverage entities"})
                        all_evidence.append(ref.id)
                        artifact_refs.append(ref)
                    known_coverage = current_coverage
                    all_evidence.extend(coverage_run.evidence_ids)
            else:
                test_result = self.test_runner.run_many((case,), source_files=source_tuple, language=language,
                    executable=executable, persist_process_output=False).executions[0]
                all_evidence.extend(test_result.evidence_ids)
                artifact_refs.extend(_result_evidence(test_result))
            executed += int(test_result.executed)
            _notify_fuzz_progress(progress_callback, {"event": "execution_completed", "campaign_id": campaign_id,
                "requested": config.max_iterations, "completed": iteration + 1, "executed": executed,
                "unique_inputs": len(seen_inputs), "failures": len(failures)})
            if not test_result.executed or test_result.verification_result.status in {
                    VerificationStatus.BUILD_ERROR, VerificationStatus.TOOL_ERROR, VerificationStatus.SPEC_ERROR}:
                errors.append(test_result.reason or test_result.verification_result.reason_code)
                build_error = test_result.verification_result.status is VerificationStatus.BUILD_ERROR
                missing_target = bool(test_result.command_result and test_result.command_result.execution_error
                    and any(marker in test_result.command_result.execution_error.lower()
                            for marker in ("no such file", "not found", "winerror 2", "cannot find the file")))
                tool_error = test_result.verification_result.status is VerificationStatus.TOOL_ERROR and not missing_target
                unavailable_target = missing_target or (not build_error and not tool_error)
                stop_reason = "BUILD_ERROR" if build_error else "TOOL_ERROR" if tool_error else "TARGET_UNAVAILABLE"
                if progress_callback:
                    _notify_fuzz_progress(progress_callback, {"event": "case_completed", "campaign_id": campaign_id,
                        "requested": config.max_iterations, "completed": iteration + 1, "executed": executed,
                        "stop_reason": stop_reason})
                break
            analysis = analyzer.analyze(test_result, no_crash_is_failure=(no_crash_is_failure if no_crash_is_failure is not None else _requires_no_crash(template)))
            iteration_coverage = tuple(sorted(
                [f"line:{path}:{line}" for path, line in known_coverage.lines] +
                [f"branch:{branch}" for branch in known_coverage.branches]))
            prior_iteration_coverage = set(
                [f"line:{path}:{line}" for path, line in coverage_before_iteration.lines] +
                [f"branch:{branch}" for branch in coverage_before_iteration.branches])
            if observation_evidence_written < observation_evidence_limit:
                command_result = test_result.command_result
                command_observation = None
                if command_result is not None:
                    command_observation = {
                        "argv": list(command_result.argv), "exit_code": command_result.exit_code,
                        "duration_ms": command_result.duration_ms, "timed_out": command_result.timed_out,
                        "execution_error": command_result.execution_error,
                        "stdout_sha256": hashlib.sha256(command_result.stdout.encode("utf-8", errors="replace")).hexdigest(),
                        "stderr_sha256": hashlib.sha256(command_result.stderr.encode("utf-8", errors="replace")).hexdigest(),
                        "stdout_preview": command_result.stdout[:4096], "stderr_preview": command_result.stderr[:4096],
                        "stdout_truncated": len(command_result.stdout) > 4096,
                        "stderr_truncated": len(command_result.stderr) > 4096,
                    }
                observation_record = self.artifact_store.write_json("fuzz-executions",
                f"{campaign_id}-{iteration:06d}-observation.json", {
                    "campaign_id": campaign_id, "iteration": iteration, "input_id": candidate.id,
                    "input_sha256": candidate.content_hash, "execution_id": test_result.execution_id,
                    "source_hashes": source_before,
                    "input": candidate.to_dict(include_data=True),
                    "test_case_id": case.id, "target": case.target, "target_kind": case.target_kind.value,
                    "test_case_inputs": _evidence_value(case.inputs),
                    "expected_oracle": case.expected.to_dict() if case.expected else None,
                    "executed": bool(test_result.executed),
                    "result_id": test_result.verification_result.id,
                    "result_status": test_result.verification_result.status.value,
                    "result_reason_code": test_result.verification_result.reason_code,
                    "result_message": test_result.verification_result.message,
                    "observation_evidence_id": test_result.observation_evidence_id,
                    "command": command_observation,
                    "classification": analysis.classification,
                    "failure_signature": analysis.signature.to_dict() if analysis.signature else None,
                    "coverage_entities": list(iteration_coverage),
                    "coverage_delta": sorted(set(iteration_coverage) - prior_iteration_coverage),
                    "evidence_ids": list(test_result.evidence_ids),
                    "observation": (test_result.observed.to_dict() if test_result.observed is not None else None),
                    "output_persisted": False,
                }, evidence_type=EvidenceType.TEST_RESULT, source="fuzz-engine",
                requirement_id=template.requirement_id, property_id=template.property_id,
                metadata={"campaign_id": campaign_id, "iteration": iteration, "input_id": candidate.id,
                          "execution_id": test_result.execution_id, "result_id": test_result.verification_result.id,
                          "sample_limit": observation_evidence_limit})
                all_evidence.append(observation_record.id)
                artifact_refs.append(observation_record)
                execution_evidence.append({"evidence_id": observation_record.id,
                    "path": observation_record.path, "sha256": observation_record.hash,
                    "iteration": iteration + 1, "input_id": candidate.id,
                    "input_sha256": candidate.content_hash, "classification": analysis.classification,
                    "result_status": test_result.verification_result.status.value,
                    "executed": bool(test_result.executed)})
                observation_evidence_written += 1
            if analysis.classification == "CRASH": crashes += 1
            if analysis.classification == "TIMEOUT": timeouts += 1
            if analysis.classification == "ORACLE_FAILURE": oracle_failures += 1
            if analysis.finding and analysis.signature:
                if analysis.signature.key not in seen_failures:
                    seen_failures.add(analysis.signature.key)
                    raw = test_result.command_result
                    evidence = list(test_result.evidence_ids)
                    if raw is not None:
                        command = self.artifact_store.write_json("fuzz-findings", f"{campaign_id}-{iteration:06d}-command.json", {
                            "argv": list(raw.argv), "exit_code": raw.exit_code, "timed_out": raw.timed_out,
                            "execution_error": raw.execution_error, "duration_ms": raw.duration_ms},
                            evidence_type=EvidenceType.LOG, metadata={"signature": analysis.signature.key})
                        out = self.artifact_store.write_text("fuzz-findings", f"{campaign_id}-{iteration:06d}-stdout.txt", raw.stdout,
                            evidence_type=EvidenceType.LOG, metadata={"signature": analysis.signature.key})
                        err = self.artifact_store.write_text("fuzz-findings", f"{campaign_id}-{iteration:06d}-stderr.txt", raw.stderr,
                            evidence_type=EvidenceType.LOG, metadata={"signature": analysis.signature.key})
                        evidence.extend((command.id, out.id, err.id))
                        artifact_refs.extend((command, out, err))
                    raw_input = self.artifact_store.write_bytes("fuzz-inputs", f"{campaign_id}-{iteration:06d}.bin",
                        _input_bytes(candidate), evidence_type=EvidenceType.LOG, source="fuzz-engine",
                        requirement_id=template.requirement_id, property_id=template.property_id,
                        metadata={"input_id": candidate.id, "sha256": candidate.content_hash,
                                  "origin": candidate.origin.value})
                    evidence.append(raw_input.id)
                    artifact_refs.append(raw_input)
                    input_evidence_by_hash[candidate.content_hash] = raw_input.id
                    all_evidence.extend(evidence)
                    minimized = None
                    minimization_executions = 0
                    minimization_completed = False
                    minimization_error = None
                    if config.minimize_failures and config.max_minimization_executions:
                        def check(probe: FuzzInput):
                            if config.max_seconds is not None and time.monotonic() - started >= config.max_seconds:
                                return None
                            probe_case = _test_case(template, probe, _remaining_timeout(config, started) or config.timeout_per_input)
                            probe_result = self.test_runner.run_many((probe_case,), source_files=source_tuple,
                                language=language, executable=executable, persist_process_output=False).executions[0]
                            all_evidence.extend(probe_result.evidence_ids)
                            artifact_refs.extend(_result_evidence(probe_result))
                            return analyzer.analyze(probe_result, no_crash_is_failure=(no_crash_is_failure if no_crash_is_failure is not None else _requires_no_crash(template))).signature
                        reduction = minimizer.minimize(candidate, analysis.signature, check,
                            max_executions=config.max_minimization_executions,
                            should_stop=lambda: _is_cancelled(cancel_event) or
                                config.max_seconds is not None and time.monotonic() - started >= config.max_seconds)
                        minimized = reduction.input if reduction.minimized else None
                        minimization_executions = reduction.executions
                        minimization_completed = reduction.minimized
                        minimization_error = reduction.error
                        if minimization_error == "TIME_BUDGET_EXHAUSTED":
                            stop_reason = "CANCELLED" if _is_cancelled(cancel_event) else "TIME_LIMIT"
                        if minimized is not candidate and minimized.content_hash != candidate.content_hash:
                            min_ref = self.artifact_store.write_bytes("fuzz-inputs", f"{campaign_id}-{iteration:06d}-minimized.bin",
                                _input_bytes(minimized), evidence_type=EvidenceType.LOG, source="fuzz-engine",
                                requirement_id=template.requirement_id, property_id=template.property_id,
                                metadata={"input_id": minimized.id, "sha256": minimized.content_hash})
                            all_evidence.append(min_ref.id)
                            artifact_refs.append(min_ref)
                    command_diagnostic = {}
                    if raw is not None:
                        command_diagnostic = {
                            "argv": list(raw.argv), "exit_code": raw.exit_code,
                            "timed_out": raw.timed_out, "execution_error": raw.execution_error,
                            "duration_ms": raw.duration_ms,
                            "stdout_preview": raw.stdout[:4096], "stderr_preview": raw.stderr[:4096],
                            "stdout_truncated": len(raw.stdout) > 4096,
                            "stderr_truncated": len(raw.stderr) > 4096,
                        }
                    observation = test_result.observed.to_dict() if test_result.observed else None
                    if observation is not None:
                        # The command previews below are bounded; don't duplicate unbounded process output.
                        observation.pop("stdout", None)
                        observation.pop("stderr", None)
                    failures.append(FuzzFinding(candidate, analysis.signature, analysis.classification, minimized,
                        test_result.verification_result, tuple(evidence), minimization_executions,
                        minimization_completed, minimization_error,
                        oracle_evaluation=test_result.oracle_evaluation.to_dict(),
                        observation=observation,
                        command_diagnostic=command_diagnostic))
                    corpus.add(candidate, coverage_signature=(), discovered_at_iteration=iteration,
                               retention_reason=f"failure:{analysis.classification}", failure_signature=analysis.signature)
                    if config.stop_on_first_failure:
                        stop_reason = "FIRST_FAILURE"
            progress_error = _notify_fuzz_progress(progress_callback, {"event": "case_completed", "campaign_id": campaign_id,
                "requested": config.max_iterations, "completed": iteration + 1, "executed": executed,
                "unique_inputs": len(seen_inputs), "failures": len(failures), "stop_reason": stop_reason})
            if progress_error:
                errors.append(progress_error)
                tool_error = True
            if stop_reason == "FIRST_FAILURE":
                break
        source_after, after_error = _source_hashes(source_tuple)
        integrity_ok = not after_error and source_before == source_after
        if not integrity_ok:
            errors.append("SOURCE_INTEGRITY_CHANGED")
            tool_error = True
        end_signature = tuple(sorted([f"line:{path}:{line}" for path, line in known_coverage.lines] +
                                     [f"branch:{item}" for item in known_coverage.branches]))
        corpus_ref = self.artifact_store.write_json("fuzz-corpus", f"{campaign_id}-corpus-index.json", {
            "campaign_id": campaign_id,
            "entries": [{"input_id": item.input.id, "content_sha256": item.input.content_hash,
                         "kind": item.input.kind.value, "origin": item.input.origin.value,
                         "parent_id": item.parent_id, "generation": item.input.generation,
                         "retention_reason": item.retention_reason,
                         "coverage_signature": list(item.coverage_signature),
                         "failure_signature": item.failure_signature.to_dict() if item.failure_signature else None,
                         "input_evidence_id": input_evidence_by_hash.get(item.input.content_hash)}
                        for item in corpus.entries],
            "deduplication": "typed-payload-sha256", "entry_count": len(corpus),
        }, evidence_type=EvidenceType.TEST_RESULT, source="fuzz-engine",
           requirement_id=template.requirement_id, property_id=template.property_id,
           metadata={"campaign_id": campaign_id, "artifact_kind": "fuzz-corpus-index"})
        all_evidence.append(corpus_ref.id)
        artifact_refs.append(corpus_ref)
        start_sig: tuple[str, ...] = ()
        delta_sig = tuple(sorted(set(end_signature) - set(start_sig)))
        decisive_failures = [item for item in failures if item.classification in {"ORACLE_FAILURE", "SANITIZER"}
                             or item.classification == "CRASH" and _requires_no_crash(template)]
        if decisive_failures:
            status, reason = RawOutcome.PROPERTY_VIOLATED, "FUZZ_FAILURE_FOUND"
            msg = f"Fuzz campaign found {len(decisive_failures)} scoped failure(s)."
        elif build_error:
            status, reason = RawOutcome.BUILD_FAILED, "FUZZ_TARGET_BUILD_FAILED"
            msg = "; ".join(errors) or "Fuzz target could not be built."
        elif tool_error:
            status, reason = RawOutcome.TOOL_FAILED, "FUZZ_CAMPAIGN_INCOMPLETE"
            msg = "; ".join(errors) or stop_reason
        elif unavailable_target:
            status, reason = RawOutcome.UNKNOWN, "FUZZ_TARGET_UNAVAILABLE"
            msg = "; ".join(errors) or "Fuzz target was unavailable."
        elif errors and strategy is not FuzzStrategy.BLACKBOX:
            status, reason = RawOutcome.TOOL_FAILED, "FUZZ_CAMPAIGN_INCOMPLETE"
            msg = "; ".join(errors)
        elif failures:
            status, reason = RawOutcome.UNKNOWN, "FUZZ_CAMPAIGN_INCONCLUSIVE"
            msg = "Timeout or unasserted abnormal termination was observed; it does not establish a scoped safety violation."
        else:
            status, reason = RawOutcome.UNKNOWN, "NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET"
            msg = "No failure found within this bounded fuzz campaign; this does not establish absence of defects."
        verification = self.classifier.classify(ClassificationInput(status, "FUZZING", config.strategy.value,
            reason_code=reason, message=msg, requirement_id=template.requirement_id,
            property_id=template.property_id, source=template.target,
            scope=f"{executed} fuzz testcase execution(s), random seed {config.random_seed}.",
            evidence_ids=tuple(dict.fromkeys(all_evidence)), duration_ms=(time.monotonic()-started)*1000,
            counterexample=failures[0].input.to_dict() if failures else None,
            metadata={"source_integrity_unchanged": integrity_ok, "stop_reason": stop_reason,
                      "coverage_feedback": strategy is FuzzStrategy.COVERAGE_GUIDED,
                      "coverage_fallback_used": fallback_used,
                      "requested_strategy": config.strategy.value, "effective_strategy": strategy.value,
                      "campaign_id": campaign_id, "random_seed": config.random_seed,
                      "max_iterations": config.max_iterations, "max_executions": execution_budget,
                      "observation_evidence_limit": observation_evidence_limit,
                      "observation_evidence_written": observation_evidence_written,
                      "max_input_count": input_budget, "inputs_considered": input_count,
                      "executions_completed": executed, "max_seconds": config.max_seconds,
                      "timeout_per_input": config.timeout_per_input,
                      "source_hashes_before": source_before, "source_hashes_after": source_after,
                      "evidence": [_evidence_record(item) for item in artifact_refs]}))
        summary = FuzzCampaignResult(config.strategy, config.random_seed, config.max_iterations, executed,
            len(seen_inputs), len(corpus), tuple(failures), crashes, timeouts, oracle_failures, start_sig,
            end_signature, delta_sig, time.monotonic()-started, stop_reason, verification,
            tuple(dict.fromkeys(all_evidence)), tuple(errors), source_before, source_after, integrity_ok,
            execution_budget, input_budget, tuple(execution_evidence))
        summary_ref = self.artifact_store.write_json("fuzz-campaigns", f"{campaign_id}-summary.json", summary.to_dict(),
            evidence_type=EvidenceType.TEST_RESULT, requirement_id=template.requirement_id,
            property_id=template.property_id, metadata={"strategy": config.strategy.value,
                "random_seed": config.random_seed, "iteration_budget": config.max_iterations,
                "source_integrity_unchanged": integrity_ok})
        verification = replace(summary.verification_result,
            evidence_ids=tuple(dict.fromkeys((*summary.verification_result.evidence_ids, summary_ref.id))),
            metadata={**dict(summary.verification_result.metadata),
                      "evidence": [*summary.verification_result.metadata.get("evidence", ()),
                                   {"id": summary_ref.id, "path": summary_ref.path, "sha256": summary_ref.hash}]})
        return replace(summary, evidence_ids=summary.evidence_ids + (summary_ref.id,),
                       verification_result=verification)

    def _unsupported(self, template: TestCase, config: FuzzConfig, code: str, message: str, started: float) -> FuzzCampaignResult:
        diagnostic = self.artifact_store.write_json("fuzz-campaigns", f"{uuid.uuid4().hex}-not-started.json", {
            "test_case_id": template.id, "target": template.target,
            "reason_code": code, "message": message,
            "strategy": config.strategy.value, "random_seed": config.random_seed,
            "iteration_budget": config.max_iterations, "timeout_per_input": config.timeout_per_input,
            "max_input_size": config.max_input_size,
        }, evidence_type=EvidenceType.ENVIRONMENT, source="fuzz-engine",
           requirement_id=template.requirement_id, property_id=template.property_id,
           metadata={"strategy": config.strategy.value, "random_seed": config.random_seed,
                     "iteration_budget": config.max_iterations, "reason_code": code})
        result = self.classifier.classify(ClassificationInput(RawOutcome.UNKNOWN, "FUZZING", config.strategy.value,
            reason_code=code, message=message, requirement_id=template.requirement_id, property_id=template.property_id,
            scope="Campaign could not start within its declared capabilities.",
            evidence_ids=(diagnostic.id,), metadata={"random_seed": config.random_seed,
                "iteration_budget": config.max_iterations,
                "execution_budget": config.max_executions or config.max_iterations,
                "input_count_budget": config.max_input_count or config.max_iterations,
                "evidence": [{"id": diagnostic.id, "path": diagnostic.path, "sha256": diagnostic.hash}]}))
        return FuzzCampaignResult(config.strategy, config.random_seed, config.max_iterations, 0, 0, 0, (), 0, 0, 0,
                                  duration_seconds=time.monotonic()-started, stop_reason=code,
                                  verification_result=replace(result, metadata={**dict(result.metadata),
                                      "concolic_capability": "UNSUPPORTED" if config.strategy is FuzzStrategy.CONCOLIC else None}),
                                  evidence_ids=(diagnostic.id,), errors=(message,),
                                  executions_requested=config.max_executions or config.max_iterations,
                                  input_count_requested=config.max_input_count or config.max_iterations)


def _test_case(template: TestCase, fuzz_input: FuzzInput, timeout: float) -> TestCase:
    if template.metadata.get("fuzz_stdin"):
        if isinstance(fuzz_input.data, Mapping) and set(fuzz_input.data) <= {"argv", "stdin"}:
            inputs = dict(fuzz_input.data)
            inputs.setdefault("argv", list(template.inputs.get("argv", ())))
        elif fuzz_input.kind is InputKind.BYTES or fuzz_input.kind is InputKind.TEXT:
            inputs = {"argv": list(template.inputs.get("argv", ())), "stdin": fuzz_input.data}
        else:
            inputs = {"argv": list(template.inputs.get("argv", ())), "stdin": str(fuzz_input.data)}
    elif fuzz_input.kind is InputKind.BYTES:
        inputs = {"argv": list(template.inputs.get("argv", ())), "stdin": fuzz_input.data}
    elif fuzz_input.kind is InputKind.TEXT:
        inputs = {"argv": list(template.inputs.get("argv", ())), "stdin": fuzz_input.data}
    elif isinstance(fuzz_input.data, Mapping) and template.target_kind is TestTargetKind.EXECUTABLE:
        if set(fuzz_input.data) <= {"argv", "stdin"}:
            inputs = dict(fuzz_input.data)
        else:
            inputs = {"stdin": json.dumps(fuzz_input.data, sort_keys=True, ensure_ascii=False)}
    elif template.target_kind is TestTargetKind.FUNCTION and isinstance(fuzz_input.data, Mapping):
        inputs = dict(fuzz_input.data)
    elif template.target_kind is TestTargetKind.FUNCTION and template.inputs and isinstance(fuzz_input.data, (int, float, bool)):
        inputs = {name: fuzz_input.data for name in template.inputs}
    elif template.target_kind is TestTargetKind.EXECUTABLE:
        inputs = {"argv": [str(fuzz_input.data)]}
    else:
        inputs = {"value": fuzz_input.data}
    return replace(template, id=f"fuzz-{fuzz_input.id}", name=f"Fuzz {fuzz_input.id}", inputs=inputs,
                   category=TestCategory.NEGATIVE, timeout_seconds=timeout,
                   metadata={**template.to_dict()["metadata"], "fuzz_input_hash": fuzz_input.content_hash,
                             "fuzz_input_origin": fuzz_input.origin.value})


def _configured_template(template: TestCase, config: FuzzConfig) -> TestCase:
    target = config.entry_point or config.target or template.target
    target_kind = template.target_kind
    if config.harness == "function":
        target_kind = TestTargetKind.FUNCTION
    elif config.harness == "executable":
        target_kind = TestTargetKind.EXECUTABLE
    return replace(template, target=target, target_kind=target_kind, metadata=template.to_dict()["metadata"])


def _load_corpus(directory: str | None) -> tuple[FuzzInput, ...]:
    if not directory:
        return ()
    root = Path(directory).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise OSError(f"Corpus path is not a directory: {root}")
    entries = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise OSError(f"Corpus entry resolves outside the corpus directory: {path}")
        content = resolved.read_bytes()
        identity = hashlib.sha256(path.relative_to(root).as_posix().encode() + b"\0" + content).hexdigest()[:16]
        entries.append(FuzzInput(f"corpus-{identity}", content, InputKind.BYTES, InputOrigin.SEED,
                                 metadata={"corpus_path": path.relative_to(root).as_posix()}))
    return tuple(entries)


def _remaining_timeout(config: FuzzConfig, started: float) -> float | None:
    if config.max_seconds is None:
        return config.timeout_per_input
    return min(config.timeout_per_input, max(0.0, config.max_seconds - (time.monotonic() - started)))


def _is_cancelled(event: Any) -> bool:
    if event is None:
        return False
    return bool(event() if callable(event) else event.is_set())


def _notify_fuzz_progress(callback: Callable[[Mapping[str, Any]], None] | None,
                          event: Mapping[str, Any]) -> str | None:
    if callback is None:
        return None
    try:
        callback(dict(event))
    except Exception as exc:
        return f"FUZZ_PROGRESS_CALLBACK_ERROR:{type(exc).__name__}:{exc}"
    return None


def _result_evidence(result: TestExecutionResult) -> tuple[dict[str, Any], ...]:
    references = result.verification_result.metadata.get("evidence", ())
    return tuple(dict(item) for item in references if isinstance(item, Mapping) and
                 {"id", "path", "sha256"} <= set(item))


def _evidence_record(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return {"id": item["id"], "path": item["path"], "sha256": item["sha256"]}
    return {"id": item.id, "path": item.path, "sha256": item.hash}


def _input_bytes(item: FuzzInput) -> bytes:
    if isinstance(item.data, bytes): return item.data
    if isinstance(item.data, str): return item.data.encode("utf-8")
    return json.dumps(item.data, sort_keys=True, ensure_ascii=False).encode("utf-8")


def _evidence_value(value: Any) -> Any:
    """Make actual testcase inputs JSON-safe without losing binary payloads."""
    if isinstance(value, bytes):
        return {"base64": __import__("base64").b64encode(value).decode("ascii"),
                "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}
    if isinstance(value, Mapping):
        return {str(key): _evidence_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_evidence_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _requires_no_crash(case: TestCase) -> bool:
    return bool(case.expected and any(check.oracle_type.value == "NO_CRASH" for check in case.expected.checks))


def _source_hashes(sources: tuple[SourceFile | str | Path, ...]) -> tuple[dict[str, str], str | None]:
    output = {}
    try:
        for source in sources:
            path = Path(source.path if isinstance(source, SourceFile) else source).resolve(strict=True)
            output[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return output, str(exc)
    return output, None


def _report_from_snapshot(snapshot: CoverageSnapshot, report):
    """Aggregate entity-only snapshot into an ephemeral report for shared CoverageDelta API."""
    from seclab.coverage import CoverageReport, LineCoverage, BranchCoverage
    line_counts: dict[str, dict[int, int]] = {}
    for path, line in snapshot.lines: line_counts.setdefault(path, {})[line] = 1
    branch_hits = {item: True for item in snapshot.branches}
    line_metrics = replace(report.line_metrics, counts=line_counts,
        covered_lines=len(snapshot.lines), total_lines=len(snapshot.lines))
    branch_metrics = replace(report.branch_metrics, hits=branch_hits,
        covered_branches=len(snapshot.branches), total_branches=len(snapshot.branches))
    return replace(report, line_metrics=line_metrics, branch_metrics=branch_metrics,
                   complete=True, partial=False, limitations=())
