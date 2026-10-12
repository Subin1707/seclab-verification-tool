# Verification Core Mutation Testing Report

This report records controlled test-only mutations at the benchmark observation boundary. Expected outcomes remain the independently declared catalog/fixture values.

These tests establish benchmark/scorer sensitivity to changed component outputs. They do not patch production source files or prove that every internal implementation defect will reach the observation boundary; parser/encoder-specific unit mutation execution remains a limitation.

## Mutation results

| Mutation ID | Component | Injected defect | Expected detection | Actual detection | Surviving mutation |
|---|---|---|---|---|---|
| MUT-CTL-001 | CTL parser/model checker | Treat a false AG invariant as satisfied. | detected mismatch | detected mismatch | No |
| MUT-SMT-001 | SMT parser/encoder | Drop the violation negation so a satisfiable violation is reported safe. | detected mismatch | detected mismatch | No |
| MUT-BMC-001 | BMC encoder/checker | Discard the SAT counterexample and report no violation. | detected mismatch | detected mismatch | No |
| MUT-RESULT-001 | result classification | Map a failing verification outcome to PASS. | detected mismatch | detected mismatch | No |
| MUT-DYNAMIC-001 | dynamic oracle | Accept a return value that differs from the declared oracle. | detected mismatch | detected mismatch | No |
| MUT-STATIC-001 | static finding parser | Drop a parsed diagnostic finding. | detected mismatch | detected mismatch | No |
| MUT-FUZZ-001 | fuzz crash classification | Classify abnormal termination as no finding. | detected mismatch | detected mismatch | No |
| MUT-EVIDENCE-001 | evidence integrity | Accept a changed artifact while retaining a valid-integrity finding. | detected mismatch | detected mismatch | No |
| MUT-TRACE-001 | traceability | Drop the source reference from a requirement-to-result trace. | detected mismatch | detected mismatch | No |

Mutations run: 9; detected from clean baseline: 9; surviving: 0.

## Execution method and scope

Each case is run through the benchmark runner twice: first with a deterministic test-only reference observation, then with one controlled mutation applied to that observation. A clean baseline is required before a mutation counts as detected. The mutation fixtures cover the listed CTL, SMT, BMC, result, dynamic, static, fuzzing, evidence, and traceability boundaries.

No production implementation was modified. No project safety verdict or aggregate safety score is produced.
