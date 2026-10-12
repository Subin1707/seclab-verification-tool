# Real Smart-EV Source / Probe Traceability Audit

Audit date: 2026-10-03  
Teacher document: `E:\smart-ev-charging-safety\teacher_specs\smart_ev_teacher_e2e_v4.json`  
Teacher JSON SHA-256: `00d6314f32db70e1e8bf1454cfdca02922c126943dbdfae408983a09870f0193`

This audit treats the JSON and its instructions as evidence to inspect. It does not generate or modify Smart-EV source. Exact-name searches covered source-like files throughout the Smart-EV project (`.c/.h/.cpp/.hpp/.cc/.cxx/.py`), including production, verification, tests, fixtures, teacher application, and toolkit folders. Duplicate `dist`, VCS/cache directories, and binary files were excluded. Structural inspection focused on the production C tree and relevant fixture/formal trees.

## 1. Real source roots

The real project root is `E:\smart-ev-charging-safety`. The main production implementation is under `src/` (87 C/header files inventoried; the prior pipeline run analyzed 36 C translation units). Other code-bearing roots include:

| Root | Contents and audit treatment |
|---|---|
| `src/` | Production Smart-EV C implementation (vehicle, station, charging, auth, communication, database, safety, simulation, monitoring, core, logging, utils). |
| `tests/` | C integration/unit fixtures and Python tests/harnesses; not production implementation. |
| `static_analysis/vulnerable/`, `static_analysis/fixed/` | Separate vulnerable/fixed C demonstrations, not the nine named probes. |
| `formal/` | Formal model and BMC examples, not the nine named probes. |
| `verification/` | Python verification/build scripts. `gd123_build_v4_spec.py` declares metadata and writes JSON; its `functions[]` entries contain no executable function bodies. |
| `teacher_app/` | Teacher application Python source and extracted data; exact probe definitions were not found. |
| `teacher_specs/` | JSON specifications and experiments; the v4 JSON is the only source for these nine declarations. |
| `bin/` | Generated/build/test code, separate from production `src/`; exact probe definitions were not found. |
| `softsec-toolkit/softsec-toolkit/` | Teaching toolkit examples, separate from the Smart-EV production tree; no exact probe definitions found. |
| `bridge/`, `scripts/`, `tools/`, `spec_generator/` | Python application, utilities, and specification tooling; no exact probe definitions found. |

The v4 JSON has no per-function file/source reference. The builder’s internal `_doc` comments mention analogous Smart-EV paths for some scenarios, but those comments are stripped before JSON output and are not function-to-file mappings.

## 2. Nine probe inventory

The JSON provides a `name`, language/kind, selected parameters, and selected metadata. It does **not** provide a function ID, return type, function body/code, source file/reference, formal category field, or declared expected behavior field. The `bug` and `magic_values` fields below are copied as-is. Expected CWE values come only from the narrative test cases, not the function records.

| Name (JSON `name`) | Language / kind | Expected CWE in narrative | Source ref / category / behavior / return / body | Parameters and metadata |
|---|---|---|---|---|
| `ev_copy_vehicle_id` | C / `buffer_copy` | None declared | Absent; no body or return type | `src_id`; `buffer_size=20`; `bug=null` |
| `ev_copy_auth_token` | C / `buffer_copy` | None declared | Absent; no body or return type | `raw_token`; `buffer_size=32`; `bug=null` |
| `ev_parse_remote_cmd` | C / `buffer_copy` | CWE-121 (test narrative) | Absent; no body or return type | `cmd_payload`; `buffer_size=16`; `bug=buffer-overflow` |
| `ev_alloc_session_record` | C / `alloc_release` | CWE-401 (test narrative) | Absent; no body or return type | no parameters; `buffer_size=64`; `bug=memory-leak` |
| `ev_release_port_context` | C / `alloc_release` | CWE-415 (test narrative) | Absent; no body or return type | no parameters; `buffer_size=32`; `bug=double-free` |
| `ev_resume_charging_after_fault` | C / `alloc_release` | CWE-416 (test narrative) | Absent; no body or return type | no parameters; `buffer_size=48`; `bug=use-after-free` |
| `ev_charging_power_ratio` | Python / `divide` | CWE-369 (test narrative) | Absent; no body or return type | `energy_delivered_wh`, `session_time_seconds` |
| `ev_token_validation_ratio` | Python / `divide` | CWE-369 (test narrative) | Absent; no body or return type | `tokens_issued`, `tokens_active` |
| `ev_firmware_unlock_gate` | Python / `magic_value` | CWE-798 or CWE-327 (test narrative) | Absent; no body or return type | `unlock_code_a`, `unlock_code_b`; `magic_values=[4721,9033]` |

## 3. Exact search results

All nine function definitions are **NOT_FOUND** in the searched Smart-EV source files. There is no file, line, signature, or source hash to report for any named function.

| Probe | Definition search |
|---|---|
| `ev_copy_vehicle_id` | NOT_FOUND |
| `ev_copy_auth_token` | NOT_FOUND |
| `ev_parse_remote_cmd` | NOT_FOUND |
| `ev_alloc_session_record` | NOT_FOUND |
| `ev_release_port_context` | NOT_FOUND |
| `ev_resume_charging_after_fault` | NOT_FOUND |
| `ev_charging_power_ratio` | NOT_FOUND |
| `ev_token_validation_ratio` | NOT_FOUND |
| `ev_firmware_unlock_gate` | NOT_FOUND |

Name occurrences in code are declaration/test prose in `teacher_specs/smart_ev_teacher_e2e_v4.json` and `verification/gd123_build_v4_spec.py`; no executable definitions occur there. The builder’s Ch2 test steps explicitly say “Generate C from …”, which confirms the entries describe intended generated capability artifacts rather than checked-in definitions. Its Python probe names similarly occur in expected-test/report text, not as Python function definitions.

## 4. Structural search results

No alias, renamed definition, wrapper, macro, static definition, C++ method/member, function pointer, conditional definition, embedded source body, or generated source definition matching any of the nine names was found. No matching implementation was found in `teacher_app`, `tests`, `static_analysis`, `formal`, `bin`, or the toolkit tree.

There are semantically adjacent production routines and separate vulnerability examples; these do not establish identity or equivalence with a named probe:

| Area | Evidence | Audit interpretation |
|---|---|---|
| Vehicle-ID copy | `src/vehicle/xe_dien.c` uses bounded `strncpy` into the vehicle ID field. | Production implementation; no `ev_copy_vehicle_id` alias or function boundary. |
| Token handling | `src/auth/token.c` validates pointers and writes a token with `snprintf`; `src/auth/xac_thuc.c` handles authentication. | Production auth routines; not `ev_copy_auth_token`. |
| Remote command parsing | `src/communication/dieu_khien_tu_xa.c` has command handling and bounded extraction; `src/communication/message.c` uses a length-checked field-copy helper with `memcpy`. | Production command/message implementation; no named probe. The `_doc` text in the spec builder’s source comment describes a scenario mapping, not a source definition. |
| Vulnerable buffer examples | `static_analysis/vulnerable/loi_id_xe.c` and `loi_phan_tich_thong_diep.c`, paired with `static_analysis/fixed/sua_*.c`. | Separate teaching/static-analysis fixtures with different function names, not the named probes and not production source. |
| Charging/session behavior | `src/charging/phien_sac.c`, `src/charging/dieu_khien_sac.c`, and `src/database/phien_sac_repository.c`. | Production session logic uses caller-owned records/database operations; no named allocation/free probe was found. |
| Divide/magic-value probes | Python source exists in bridge, tools, scripts, verification, tests, and toolkit roots. | No definitions of the three named Python probes or embedded bodies found. |

## 5. Function detector limitations

`SourceLoader` supports C/C++ source/header extensions (`.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hh`, `.hpp`, `.hxx`) and does not load Python files. `FunctionDetector` is a conservative lexical scanner for top-level C/C++ function definitions. It does not represent Python probes, and its lexical approach can have general limitations around non-top-level/member constructs.

Those limits do not explain the current nine misses: a full-project exact-name search found no C/C++ definition for the six C declarations and no Python definition for the three Python declarations. There is therefore no existing function that was missed by the detector and no specific `FUNCTION_DETECTOR_LIMITATION`, `SOURCE_DISCOVERY_LIMITATION`, or `LANGUAGE_DETECTION_LIMITATION` to assign as the cause. The actual reason is `SPECIFICATION_REFERENCE_MISSING`: names and probe metadata exist, but no code/body/source reference does. This is consistent with the spec’s own capability-probe language. No mapping logic or source discovery defect is demonstrated.

## 6. Probe classification

| Probe(s) | Classification | Explicit evidence |
|---|---|---|
| `ev_copy_vehicle_id`, `ev_copy_auth_token` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Ch2 safe-codegen preconditions call them tool-capability artifacts and say they are not production authentication implementations. |
| `ev_parse_remote_cmd`, `ev_alloc_session_record`, `ev_release_port_context`, `ev_resume_charging_after_fault` | `BUG_INJECTED_PROBE` / `PROBE_ONLY` | Ch2 unsafe-codegen preconditions explicitly call them bug-injected tool-capability artifacts, list their bug patterns, and exclude production implementation status. |
| `ev_charging_power_ratio`, `ev_token_validation_ratio` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Ch4 divide-fuzz preconditions explicitly call them tool-capability artifacts and distinguish Python integer probes from production float arithmetic. |
| `ev_firmware_unlock_gate` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Ch4 concolic narrative declares magic values and describes a probe; no source body is provided. |

None is evidenced as `PRODUCTION_SOURCE` or `TEST_HARNESS`. `UNKNOWN` is unnecessary because the JSON explicitly identifies Ch2/Ch4 as capability probes and probe-only artifacts. No fake source was created.

## 7. Production-source mapping

None of the nine declarations maps to production source. Production functions that perform related domain operations are present, but the JSON supplies no source references and no stable semantic mapping key. The report’s source inventory of 36 analyzed C translation units is consistent with the production `src/` scope; the separate static-analysis fixtures and generated/toolkit code are not production mappings.

Decision under Ch2 options:

- **D. Probe source does not exist** for the nine named executable functions in the checked-in Smart-EV project.
- The JSON declares probe metadata and describes code generation, but contains no function body/code field. Separate vulnerability demos exist under `static_analysis/`, but they are different fixtures, not source for these names.

The adapter currently retains the declarations as probe metadata and does not create executable `Specification.functions` entries for them. There is no production mapping miss to repair and no integration-layer defect established by this audit.

## 8. Ch4 test audit

All nine raw `test_cases` have only `id`, `requirement_ids`, `title`, `priority`, prose `preconditions`, prose `steps`, and prose `expected_result`. None supplies a machine-structured executable input, output, oracle, source file, or harness. The Dynamic Testing Core therefore cannot execute these narratives as dynamic tests. Ch1/Ch3 semantics did run through their respective CTL/SMT stages; that is partial pipeline coverage, not Dynamic Testing Core execution.

| Test case | Executable inputs / expected output / oracle / target / source / harness | Current pipeline basis | Classification |
|---|---|---|---|
| `GD12-TC-CH1-CTL-16` | Narrative assertions only; no dynamic inputs, target function, source ref, or harness. | State machine and CTL properties exist and were checked. | `PARTIALLY_RUNNABLE` |
| `GD12-TC-CH2-SAFE-CODEGEN` | No function bodies, inputs, source refs, or codegen harness; expected findings are prose. | No generated probe code; production static-analysis stage ran on production sources only. | `NON_RUNNABLE` |
| `GD12-TC-CH2-UNSAFE-CODEGEN` | No function bodies, inputs, source refs, or codegen harness; expected CWEs are prose. | No generated probe code. | `NON_RUNNABLE` |
| `GD12-TC-CH3-SOC-CONTRACT` | Formulas/expected outcomes appear in separate arithmetic declarations and prose; no dynamic target/harness. | Five corresponding SMT checks ran. | `PARTIALLY_RUNNABLE` |
| `GD12-TC-CH3-TEMP-CONTRACT` | Formulas/expected outcomes appear in arithmetic declarations and prose; no dynamic target/harness. | Four corresponding SMT checks ran. | `PARTIALLY_RUNNABLE` |
| `GD12-TC-CH3-POWER-CONTRACT` | Formulas/expected outcomes appear in arithmetic declarations and prose; no dynamic target/harness. | Three corresponding SMT checks ran. | `PARTIALLY_RUNNABLE` |
| `GD12-TC-CH4-FUZZ-DIVIDE` | No Python bodies, fuzz inputs/seeds, source refs, harness, or executable oracle. | No Dynamic Core target supplied; Ch4 skipped. | `NON_RUNNABLE` |
| `GD12-TC-CH4-CONCOLIC-MAGIC` | Magic values are stated, but no function body, branch/source, input harness, or executable oracle is supplied. | No Dynamic Core target supplied; Ch4 skipped. | `NON_RUNNABLE` |
| `GD12-TC-E2E-TRACEABILITY` | Expected links are prose; no runnable end-to-end test/harness. | Underlying Ch1/Ch3 results and requirement links exist; Ch2/Ch4 capability artifacts do not. | `PARTIALLY_RUNNABLE` |

The adapter records all nine as `NARRATIVE_TEST_CASE` with `NOT_APPLICABLE` execution status because their preconditions/steps/expected values are not executable test objects.

## 9. Ch5 fuzz audit

The raw v4 JSON has no Ch5 fuzz configuration and declares no fuzz target object, seed, corpus, mutation strategy, time/iteration budget, structured oracle, expected crash, or coverage target. Ch4 prose mentions black-box/concolic fuzz operations, but provides no runnable targets or campaign configuration. **`FUZZING_CONFIGURATION_ABSENT`.** No campaign or synthetic input was created.

## 10. Ch3 overflow verification

Reviewed the existing `gd12_charging_rate_positive_time` evidence from:

`.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/`

Trace:

1. **Original check:** the unchanged teacher JSON declares `int_vars=["energy_wh","time_seconds"]`, condition `energy_wh >= 0 and time_seconds > 0 and energy_wh <= 79200`, and `overflow_expr="energy_wh + time_seconds"`. The JSON has no upper bound on `time_seconds`.
2. **Normalized expression:** the in-memory adapter converts the condition to `energy_wh >= 0 && time_seconds > 0 && energy_wh <= 79200`. No bounds are added to either variable.
3. **SMT AST/query:** the overflow query is the normalized condition conjoined with the signed-int32 overflow predicate over the declared `overflow_expr`: `(energy_wh + time_seconds) > 2147483647 || (energy_wh + time_seconds) < -2147483648`. The query artifact has empty `assumptions` and `domain_constraints`; its variable declarations are integers. Query SHA-256: `849bf478acb1fd1fa6bd75fc9cbc1bb58dbae89f32188d1d33d783ad3773a3b2`.
4. **Z3 model:** `energy_wh=0`, `time_seconds=2147483648` (other declared integers are zero). This satisfies the original condition and makes the sum exceed `INT32_MAX`.
5. **Evidence:** result is `FAIL`, `solver_outcome=SAT`, expected outcome `UNSAT`, property `SMT-gd12_charging_rate_positive_time-OVERFLOW`. Query/model/outcome evidence is linked in the report; model SHA-256: `1eb12334fd71aa8c696782572841f49c1512957bcdfed8506b84564848de31d2`.

The adapter does add the standard signed-int32 overflow predicate for an explicitly declared `overflow_expr`; it does not add a fabricated production-domain constraint. The counterexample follows from the real JSON condition, because positive time is unbounded there. The narrative test says overflow should be impossible “within production bounds”, but those time bounds are not included in the arithmetic check. Thus the SAT/FAIL is genuine for the declared formula, while the narrative `UNSAT` expectation is unsupported by the current constraint. This does not establish that a production charging-rate implementation overflows; the check is an integer capability/formal abstraction, not a direct execution of production code. The result remains unchanged.

## 11. Recommended next implementation step

Do not change source discovery or function detection for these nine names. The next milestone should obtain an authoritative source-to-requirement mapping and executable artifacts from the Smart-EV owner:

1. If the intended Ch2/Ch4 targets are capability probes, provide their separately generated source/body and runnable harness inputs as probe-only artifacts with their own source hashes and result scope; keep them out of production SUT evidence.
2. If a Ch2 declaration is intended to map to production, add an explicit source file/symbol reference and verify its semantics before mapping it.
3. Resolve the charging-rate overflow expectation by supplying the authoritative maximum `time_seconds` bound in the specification/check or revising the stated expected outcome. Do not infer or insert the missing bound in the adapter.

No code changes are recommended by this audit. No detector/core edits, fake functions, test inputs, or fuzz campaigns were made.
