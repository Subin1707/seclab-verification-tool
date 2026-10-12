# Verification Accuracy Benchmark v1

This benchmark scores individual checker observations against explicit ground truth. It does not produce a project-level verdict. A clean run with no detected defect is not treated as a proof of correctness: bounded searches, fuzzing without a finding, coverage measurements, and unavailable checkers retain their own `INCONCLUSIVE` or `UNSUPPORTED` outcomes.

Run the complete catalog with:

```powershell
python -m seclab.benchmark --output t\benchmark-report.json
```

The catalog records a stable benchmark ID, scenario, checker, expected status, finding, property, evidence, known limitation, and category for each case. The report includes expected-versus-actual rows, mismatches, false positives and negatives, inconclusive cases, and unsupported cases. False positives and negatives are scored only when the actual observation is conclusive; an unsupported checker is not counted as a false negative.

The v1 catalog contains CTL, BMC, SMT, static-analysis, memory-safety, dynamic-test, coverage, and fuzzing cases. Production adapters invoke the corresponding package APIs where practical. Some outcomes are intentionally controlled fixtures: solver timeout/unknown outcomes, selected process timeout/abnormal termination, and coverage percentages with known counters. These exercise result classification and reporting deterministically; they do not measure solver reliability or establish analyzer soundness. Memory sanitizer cases depend on host compiler/runtime support and are reported unsupported when unavailable.

The benchmark’s expected evidence identifies the evidence class required from the checker (for example, a counterexample trace, process record, sanitizer report, or coverage delta); matching a class does not assert that two evidence payloads are byte-identical.
