"""Human-readable, checker-local benchmark reports."""
from __future__ import annotations

import json
from typing import Any, Mapping


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render case ground truth, observations, and per-checker metrics."""
    run = report.get("run_metadata", {})
    lines = [
        "# Verification Accuracy Benchmark",
        "",
        f"Cases: {report.get('benchmark_count', 0)}",
        "",
        "**Scope: fixture-level observations only. These counts are not general checker accuracy estimates.**",
        "",
        "## Methodology and reproducibility",
        "",
        "Each case carries a catalog-authored expected result and provenance. The runner invokes the selected checker adapter, records its observation, and compares it with that independent declaration. Ground-truth expectations are never populated from checker output. Binary finding detection is scored separately from the verification status; inconclusive, unsupported, environment-limited, tool-error, build-error, and skipped outcomes are not converted into negative detections. TP/TN/FP/FN counts are fixture-level only.",
        "Coverage cases measure execution coverage and are not safety PASS/FAIL results. Metrics are per checker/analyzer; there is no project verdict.",
        "",
        "Reproduce with `python -m seclab.benchmark --output t\\benchmark-report.json --markdown docs\\verification-accuracy.md`.",
        f"Run started UTC: `{run.get('started_utc', 'not recorded')}`; platform: `{run.get('platform', 'not recorded')}`; Python: `{run.get('python', 'not recorded')}`.",
        f"Tool versions: `{_json(run.get('tools', {}))}`",
        "",
        "## Metrics by checker",
        "",
        "| Checker | TP | TN | FP | FN | Accuracy | Precision | Recall | Specificity | FPR | FNR | Inconclusive | Unsupported | Environment limited | Tool errors | Build errors | Skipped |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    metrics = report.get("checker_metrics", {})
    measurable = [f"{checker} ({values.get('TP', 0) + values.get('TN', 0) + values.get('FP', 0) + values.get('FN', 0)} conclusive binary cases)"
                  for checker, values in sorted(metrics.items()) if values.get("metrics_ready")]
    not_measurable = [checker for checker, values in sorted(metrics.items()) if not values.get("metrics_ready")]
    for checker, values in sorted(metrics.items()):
        lines.append("| " + " | ".join((
            _cell(checker), str(values.get("TP", 0)), str(values.get("TN", 0)),
            str(values.get("FP", 0)), str(values.get("FN", 0)),
            *(_percent(values.get(key)) for key in (
                "accuracy", "precision", "recall", "specificity", "false_positive_rate",
                "false_negative_rate", "inconclusive_rate", "unsupported_rate",
                "environment_limited_rate", "tool_error_rate", "build_error_rate", "skipped_rate")),
        )) + " |")
    lines.extend(["", "## Case results", ""])
    for row in report.get("expected_vs_actual", []):
        ground_truth = row.get("ground_truth", {})
        lines.extend([
            f"### {row.get('case_id', row.get('benchmark_id', 'unknown'))} — {_cell(row.get('checker', row.get('expected_checker', '')))}",
            "",
            f"- Description: {row.get('description', '')}",
            f"- Input: `{_json(row.get('input', {}))}`",
            f"- Expected: status `{row.get('expected_status')}`, finding `{row.get('expected_finding')}`, evidence type `{_json(row.get('expected_evidence_type', row.get('expected_evidence', [])))}`",
            f"- Ground-truth provenance: {ground_truth.get('source', 'not recorded')}; method: {ground_truth.get('creation_method', 'not recorded')}; independent validation: {ground_truth.get('independent_validation', 'not recorded')}",
            f"- Integrity: fixture SHA-256 `{row.get('fixture_sha256', 'not recorded')}`; ground-truth SHA-256 `{row.get('ground_truth_sha256', 'not recorded')}`; catalog SHA-256 `{row.get('ground_truth_catalog_sha256', 'not recorded')}`",
            f"- Known environment limitation: {row.get('known_environment_limitation', row.get('known_limitation')) or 'None recorded'}",
            f"- Actual: status `{row.get('actual_status')}`, finding `{row.get('actual_finding')}`, evidence `{_json(row.get('actual_evidence', []))}`",
            f"- Actual outcome detail: {_json(row.get('actual', {}))}",
            f"- Mismatch classification: **{row.get('mismatch_classification', 'UNSUPPORTED')}**",
            "",
        ])
    lines.extend([
        "## Classification totals",
        "",
        f"- Mismatches: {len(report.get('mismatches', []))}",
        f"- False positives: {len(report.get('false_positives', []))}",
        f"- False negatives: {len(report.get('false_negatives', []))}",
        f"- Inconclusive: {len(report.get('inconclusive', []))}",
        f"- Unsupported: {len(report.get('unsupported', []))}",
        f"- Environment-limited: {len(report.get('environment_limited', []))}",
        f"- Tool errors: {len(report.get('tool_errors', []))}",
        f"- Build errors: {len(report.get('build_errors', []))}",
        f"- Skipped: {len(report.get('skipped', []))}",
        "- CLI exit behavior: exits 1 when any expected/actual field differs. Environment-limited mismatches remain visible but are excluded from TP/TN/FP/FN.",
        "",
        "No cross-checker accuracy score or project verdict is computed.",
        "",
        "## Known limitations",
        "",
        "Ground truth is independently authored from fixture semantics, but is not an externally adjudicated reference corpus. Controlled timeout/unknown injections test classification paths rather than checker accuracy. Memory cases may be environment-limited. Static TP/TN counts score finding presence even though the static verification status remains INCONCLUSIVE.",
        "Results establish behavior only on the listed fixtures and recorded environment. They do not establish general soundness or completeness. Static analyzer positives are scoped to known synthetic defects, memory results depend on sanitizer runtime availability, and bounded/fuzzing cases do not establish behavior outside their declared bound or campaign budget. Adapters currently retain evidence type labels, not checker artifact payloads; fixture and ground-truth inputs are hashed, but actual checker evidence cannot yet be independently revalidated from this report.",
        "",
        "## Conclusion",
        "",
        f"Binary metrics were calculable for: {', '.join(measurable) if measurable else 'none'}. Metrics were not calculable for: {', '.join(not_measurable) if not_measurable else 'none'} because both ground-truth classes were not observed conclusively.",
        "These fixture-level measurements are limited to the stated samples. Environment-limited, inconclusive, skipped, tool-error, and build-error cases do not count as false negatives or true negatives.",
        "",
    ])
    return "\n".join(lines)


def _percent(value: Any) -> str:
    return "N/A" if value is None else f"{value:.1%}"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")
