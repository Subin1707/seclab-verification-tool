# Real Smart EV specification integration

## Validation and immutable input

The input used for this run is `E:\smart-ev-charging-safety\teacher_specs\smart_ev_teacher_e2e_v4.json` (39,745 bytes). Its SHA-256 was `00d6314f32db70e1e8bf1454cfdca02922c126943dbdfae408983a09870f0193` before and after the run; it was not edited.

The existing loader parses the original JSON successfully. The unadapted v1 schema check fails with the exact first error `SCHEMA_VALIDATION_FAILED: 'id' is a required property ... at $`; the document also lacks `schema_version`, uses teacher-specific root keys, and stores its state machine and checks in a different shape. Raw semantic validation and raw normalization therefore do not run past that schema failure. The adapter keeps the original document and hash in specification evidence, maps the teacher format in memory, then runs the existing schema validator, semantic validator, and normalizer on that mapped document. Those three adapted-input operations pass. No fields were added to or removed from the source JSON.

The adapter maps `name` to the canonical specification ID, maps `state_machine` to canonical states/transitions, keeps all original formula/check/test data in provenance metadata, and turns each declared `int_vars` name into an integer variable. It does not turn prose test instructions into executable tests or create function bodies. Boolean words `and`/`or` are translated to the existing expression grammar's `&&`/`||` for SMT queries.

## 1. Real JSON structure

| Field | Observed content |
|---|---|
| `schema_version`, `id` | Not present in the original file |
| Project name | `smart_ev_teacher_e2e_v4`; no separate project ID |
| Requirements | 11 safety requirements: `REQ-AUTH-01/02`, `REQ-SOC-01/02`, `REQ-TEMP-01`, `REQ-PORT-01/02/03`, `REQ-CHG-01/02`, `REQ-EMG-01` |
| `state_machine` | 28 states, 47 transitions, 28 label sets, initial state `DISCONNECTED` |
| Root `states` / `transitions` | Also present as a smaller view: 10 states and 19 transitions; the adapter uses the full `state_machine` object |
| `safety_properties` | 16 CTL formulas: 11 `AG(!req_*_violation)`, four `EF(...)`, one `AF(safe)` |
| Functions | 6 C declarations (2 safe examples, 4 bug-injected examples) and 3 Python declarations (2 divide probes, 1 magic-value probe) |
| Variables/domains | No top-level variable/domain declarations. Checks list integer variables and put relevant bounds into each condition |
| Arithmetic | 12 `arithmetic_checks`, including three `overflow_expr` probes |
| Test cases | 9 narrative cases with prose preconditions/steps/expected-result text; no executable input/oracle structure |
| Code references | No `file`, `source_files`, or source-code mapping fields on the function declarations. Narrative Ch3 preconditions refer to `src/core/hang_so.h` for constants |
| Expected findings | No top-level expected-findings list. Narrative cases state expected probe CWEs and solver outcomes |

The independent source scan used 36 C translation units below `src/`. The pipeline discovered 123 functions, but all nine JSON function names were unmatched. This confirms the JSON functions are capability-probe declarations, not linked production implementations.

## 2. Ch1 — formal model

The full `state_machine` declares 28 states and 47 transitions, which the adapter and model builder preserve exactly. It includes 11 declared unreachable states whose IDs and labels contain violation/witness wording. These are source declarations, not generated witness states; their reachability is not evidence that the system can enter them. All 16 declared CTL formulas returned `PASS` in this finite model, meaning those formulas hold over the declared graph and initial state only. Each result has an individual CTL evidence artifact containing the formula, satisfaction result, and witness/counterexample fields. EF witness paths are in their corresponding evidence; the AG/AF checks have no counterexample in this run.

The model result is scoped to the encoded Kripke graph. The eleven violation states are explicitly unreachable from `DISCONNECTED`, so the eleven AG results establish the model's reachability property, not a proof about compiled production code. `AF(safe)` also passes because `safe` labels the initial/normal states; it does not establish that charging remains safe forever or that every fault recovers.

BMC is **SKIPPED**: the real JSON declares no BMC property, bound, or trace target. The stage is not counted as a successful verification.

## 3. Ch2 — source, compiler, static and memory analysis

The JSON declares these function names but supplies no source locations or bodies:

| Function | Classification from source JSON | Source/hash | Result for declared function |
|---|---|---|---|
| `ev_copy_vehicle_id` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Not supplied | `UNSUPPORTED`; no generated code to compile/analyze |
| `ev_copy_auth_token` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Not supplied | `UNSUPPORTED`; no generated code to compile/analyze |
| `ev_parse_remote_cmd` | `BUG_INJECTED_PROBE` / `PROBE_ONLY`; buffer-overflow | Not supplied | `UNSUPPORTED`; CWE-121 expectation not exercised |
| `ev_alloc_session_record` | `BUG_INJECTED_PROBE` / `PROBE_ONLY`; memory leak | Not supplied | `UNSUPPORTED`; CWE-401 expectation not exercised |
| `ev_release_port_context` | `BUG_INJECTED_PROBE` / `PROBE_ONLY`; double free | Not supplied | `UNSUPPORTED`; CWE-415 expectation not exercised |
| `ev_resume_charging_after_fault` | `BUG_INJECTED_PROBE` / `PROBE_ONLY`; use after free | Not supplied | `UNSUPPORTED`; CWE-416 expectation not exercised |
| `ev_charging_power_ratio` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Not supplied | `UNSUPPORTED`; no Python probe source to fuzz |
| `ev_token_validation_ratio` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Not supplied | `UNSUPPORTED`; no Python probe source to fuzz |
| `ev_firmware_unlock_gate` | `TOOL_CAPABILITY_EVIDENCE` / `PROBE_ONLY` | Not supplied | `UNSUPPORTED`; no Python probe source/concolic target |

The existing static and memory adapters did run on the 36 production C translation units. Their outcomes are **source-set observations**, not results for the nine named probe functions and not automatic production defect verdicts:

- Compiler diagnostics: 20 findings, `TOOL_ERROR` (`STATIC_ANALYSIS_FAILED`).
- Cppcheck: 17 findings, `INCONCLUSIVE` (`STATIC_FINDINGS_DETECTED`).
- Clang-tidy: 172 findings, `TOOL_ERROR` (`STATIC_ANALYSIS_FAILED`).
- Clang Static Analyzer: `TOOL_ERROR` / unavailable; no standalone driver is implemented in this integration.
- AddressSanitizer and UndefinedBehaviorSanitizer: `BUILD_ERROR`; the C build cannot resolve project headers such as `hang_so.h` and `xe_dien.h` because this run has no project include-directory/build configuration.
- Leak detection: `INCONCLUSIVE`; the runner does not support LeakSanitizer on Windows.

No probe CWE finding is claimed. The source and findings remain separated from `BUG_INJECTED_PROBE` declarations in the specification provenance.

## 4. Ch3 — arithmetic checks

All twelve conditions were checked with the installed Z3 Python backend. Every raw condition outcome matched the expectation explicitly described by a Ch3 narrative step: ten `SAT` and two `UNSAT` (the table below lists each, with requirement-linked result rows repeated where the same check maps to two requirements). These are satisfiability observations, not project-level verdicts.

The adapter also evaluated each declared `overflow_expr` under its condition against signed int32 bounds. The SOC update and five-port sum overflow queries were `UNSAT`. `gd12_charging_rate_positive_time` was `SAT` for overflow: its condition bounds `energy_wh` but only requires `time_seconds > 0`, with no upper bound. Z3 produced `energy_wh=0`, `time_seconds=2147483648`. This contradicts the narrative assertion that overflow is impossible at production scale; the JSON needs a justified maximum time bound before that claim is established. The raw `SAT` is retained and the overflow expectation is classified `FAIL`.

## 5. Ch4 — declared test cases

The three Ch4 narratives describe two Python divide-by-zero probes and one concolic magic-value probe, but their function declarations contain no code, file, executable input, or runnable oracle. The normalized specification therefore has zero executable tests. `DYNAMIC`, `COVERAGE`, and `FUZZING` are `SKIPPED`; no build, execution, coverage, or fuzz campaign result is claimed. The CWE-369 and CWE-798/CWE-327 statements remain expected probe findings, not observed findings. The other six test cases are likewise retained as narrative provenance; Chapter 1 and Chapter 3 checks were executed directly from their declared model/formula/check sections.

## 6. Ch5 — fuzzing

There is no dedicated Ch5 fuzz configuration, target body, seed, mutation strategy, or budget. Ch4 mentions capability probes, but without executable source those are not runnable targets. No fuzz requirement was invented. The pipeline stage is `SKIPPED` because no runnable dynamic test target exists; there are no campaign crashes/findings/coverage feedback artifacts.

## 7. Ch6 — full real pipeline

The full run used the real JSON plus its in-memory adapter and the actual project C sources. It ran specification/model/CTL/source/static/memory/SMT/report; BMC was skipped because no BMC property is declared; dynamic/coverage/fuzzing were skipped because the JSON has no executable tests/probe code. The report contains no overall verdict field.

Run artifacts:

- [Pipeline report](../.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/report/pipeline-report.json)
- [Run manifest](../.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/manifest/run-manifest.json)
- [Specification evidence](../.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/pipeline/specification.json)
- [Source inventory and function lineage](../.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/source/source-lineage.json)
- [Source integrity](../.runs/smart-ev-v4-final/workspace/smart-ev-teacher-e2e-v4/evidence/source/source-integrity.json)

The manifest lists 102 evidence artifacts. All listed files exist within the run root, have SHA-256 values matching their contents, and every one of the 49 verification results references evidence IDs present in the manifest. All 36 analyzed C source hashes match before/after. The original specification hash also matches before/after. All 11 requirements have at least one executed linked CTL result; SMT-linked requirements also have check/result/evidence chains. Narrative-only targets are marked `NOT_APPLICABLE`, with the missing executable/oracle reason retained.

## 8. Result classification

The table lists each result object from the pipeline report, including separate requirement-linked copies of arithmetic results. `PASS`/`FAIL` for arithmetic means only that the raw solver outcome matched/missed the expectation stated in the teacher test text. It is not a project verdict. SAT models and CTL witness/counterexample details are stored in the referenced evidence artifacts.

| Chapter | ID | Type | Target | Status | Raw outcome | Evidence IDs | Notes |
|---|---|---|---|---|---|---|---|
| Ch1 | CTL-P-01 | CTL | AG(!req_auth_01_violation) | PASS | PROPERTY_SATISFIED | 58d518bc-25bb-4485-9db2-9a32df32c00c | Requirement REQ-AUTH-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-02 | CTL | AG(!req_auth_02_violation) | PASS | PROPERTY_SATISFIED | 37bf1e88-8631-4f46-9a51-43255cbb454f | Requirement REQ-AUTH-02; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-03 | CTL | AG(!req_soc_01_violation) | PASS | PROPERTY_SATISFIED | 0be7d703-40b2-42f5-beb9-5c0be71b58c8 | Requirement REQ-SOC-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-04 | CTL | AG(!req_soc_02_violation) | PASS | PROPERTY_SATISFIED | bf1713a7-cdd3-489f-ad5c-0904424ba0a7 | Requirement REQ-SOC-02; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-05 | CTL | AG(!req_temp_01_violation) | PASS | PROPERTY_SATISFIED | eb7dffb0-bc77-4834-8354-7c2f93867d2c | Requirement REQ-TEMP-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-06 | CTL | AG(!req_port_01_violation) | PASS | PROPERTY_SATISFIED | aea1940a-9956-4ab7-9ff9-2654236b7227 | Requirement REQ-PORT-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-07 | CTL | AG(!req_port_02_violation) | PASS | PROPERTY_SATISFIED | b5631d0a-a321-41a2-90d9-05168cc137b1 | Requirement REQ-PORT-02; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-08 | CTL | AG(!req_port_03_violation) | PASS | PROPERTY_SATISFIED | 909a5162-d83e-4d7c-b1d0-dab4f2a5ca54 | Requirement REQ-PORT-03; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-09 | CTL | AG(!req_chg_01_violation) | PASS | PROPERTY_SATISFIED | 89c9c273-c075-4b54-9e0b-44e43eef1ca0 | Requirement REQ-CHG-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-10 | CTL | AG(!req_chg_02_violation) | PASS | PROPERTY_SATISFIED | 9a6d2c26-e314-4407-9c0d-d1214b108418 | Requirement REQ-CHG-02; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-11 | CTL | AG(!req_emg_01_violation) | PASS | PROPERTY_SATISFIED | 4db7fa78-1715-43ed-af79-5eb2f6302366 | Requirement REQ-EMG-01; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-12 | CTL | EF(charging) | PASS | PROPERTY_SATISFIED | 31e17184-391e-4b9f-8640-63e44ecab435 | Requirement none; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-13 | CTL | EF(start_blocked) | PASS | PROPERTY_SATISFIED | 6405af72-44b0-4b76-b0ea-3617d95cac00 | Requirement none; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-14 | CTL | EF(stopped) | PASS | PROPERTY_SATISFIED | 24ec61e6-4d47-43b2-84ae-412f0d321a76 | Requirement none; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-15 | CTL | EF(recovered) | PASS | PROPERTY_SATISFIED | 27f06ddf-659c-4a54-97e0-bf75b9216902 | Requirement none; witness/counterexample fields in CTL evidence. |
| Ch1 | CTL-P-16 | CTL | AF(safe) | PASS | PROPERTY_SATISFIED | cddf9c09-7384-487f-8341-7e80f8dbcf5a | Requirement none; witness/counterexample fields in CTL evidence. |
| Ch2 | 1f14ccd0-a45b-40cc-b60e-c7802d0e6052 | Static COMPILER-DIAGNOSTICS | 36 production C translation units under src/ | TOOL_ERROR | STATIC_ANALYSIS_FAILED | 1bd1734f-2e62-4ae2-a9d4-f59d10ee03f4, 0e47e982-4664-4fbc-8fc8-c9c925852c39, 8ff0594a-409c-4e4f-b416-bf475fe907e4, 9dbf0b76-4aad-4d0c-837a-da9dec6d7356, 1d59dfd2-0691-43ec-a8de-4eb9d17e2714 | Finding IDs: 20; review diagnostics in artifacts before treating them as defects. |
| Ch2 | 36417ef8-0d4e-4857-a3c5-1062ff94b892 | Static CLANG-TIDY | 36 production C translation units under src/ | TOOL_ERROR | STATIC_ANALYSIS_FAILED | 9ec89ff3-195c-4873-9012-dead9daa14ef, 3cb5d15b-0a50-48d2-9746-4ad25b1a0073, 64a465a5-bf3b-425c-8a87-28fcff94f5ef, 0518c79f-cda7-45ac-9132-8d4bafcbed6e, b3072e66-9833-4837-959b-62710c4f94c6 | Finding IDs: 172; review diagnostics in artifacts before treating them as defects. |
| Ch2 | 5678fa18-3356-486b-bef7-d9127709ed7b | Static CPPCHECK | 36 production C translation units under src/ | INCONCLUSIVE | STATIC_FINDINGS_DETECTED | cd005682-9de1-44c9-a9a2-3187594af08a, f6745ccd-150d-4385-a48a-66ed7516c3fe, 31b922c8-059b-47dc-aa9c-3b67b71b0519, 7d0c21b6-7452-41c3-99c7-e3e472942526, 2c33fbda-895e-4531-9a35-7ebb176e344e | Finding IDs: 17; review diagnostics in artifacts before treating them as defects. |
| Ch2 | 74f2e094-32df-470d-b047-7b1816e8fadf | Memory LEAK_CHECKER | 36 production C translation units under src/ | INCONCLUSIVE | LEAK_DETECTION_UNAVAILABLE | 8f960bd5-6af6-41a5-b8e7-3c599669971b | Leak detection is unavailable on this platform. |
| Ch2 | dda60bfb-2aa6-4b4d-a289-d96cbaf0e5ad | Static CLANG-STATIC-ANALYZER | 36 production C translation units under src/ | TOOL_ERROR | STATIC_ANALYZER_UNAVAILABLE | c9170a09-0ff6-4b9c-8bc0-032f971942b0 | Finding IDs: 0; review diagnostics in artifacts before treating them as defects. |
| Ch2 | e24fd860-bf83-419a-81c3-f329d4a8acad | Memory ADDRESSSANITIZER | 36 production C translation units under src/ | BUILD_ERROR | SANITIZER_BUILD_FAILED | bc519c4e-729a-4d0a-8ecf-aa1896ca117a, b59bf6be-dd68-4069-8623-f556f4c60608, e2f7bc8c-2573-43b5-a02b-75cf83087ac9 | Instrumented compilation failed. |
| Ch2 | f537c409-ad2b-4de2-a1e9-04dc38dff345 | Memory UNDEFINEDBEHAVIORSANITIZER | 36 production C translation units under src/ | BUILD_ERROR | SANITIZER_BUILD_FAILED | b3500ed3-9455-419f-8082-c26229f0b9e4, db1279c9-02ad-4ee6-9784-0f0fa873ecf4, ce655b20-1a75-4439-96eb-c8d983732f7f | Instrumented compilation failed. |
| Ch3 | SMT-gd12_charging_rate_positive_time | SMT condition | energy_wh >= 0 and time_seconds > 0 and energy_wh <= 79200 | PASS | SAT | ff4df95a-b2f2-4528-973b-f846459e34fc, 8967ecc6-1601-4cfe-9290-4f296a4ac7c7, 047c4ee8-3850-480c-bf2d-8bb4a38aef4c, b1140a4f-028c-4d50-9ed6-eb08857cdcd8 | Requirement REQ-CHG-01; expected SAT; result object 28b74117-a1dc-42ab-9d7e-c288b1a2759e-SAT-1. Model: energy_wh=60060, time_seconds=1. |
| Ch3 | SMT-gd12_charging_rate_positive_time | SMT condition | energy_wh >= 0 and time_seconds > 0 and energy_wh <= 79200 | PASS | SAT | ff4df95a-b2f2-4528-973b-f846459e34fc, 8967ecc6-1601-4cfe-9290-4f296a4ac7c7, 047c4ee8-3850-480c-bf2d-8bb4a38aef4c, b1140a4f-028c-4d50-9ed6-eb08857cdcd8 | Requirement REQ-EMG-01; expected SAT; result object 28b74117-a1dc-42ab-9d7e-c288b1a2759e-SAT-2. Model: energy_wh=60060, time_seconds=1. |
| Ch3 | SMT-gd12_charging_rate_positive_time-OVERFLOW | SMT signed int32 overflow | energy_wh >= 0 and time_seconds > 0 and energy_wh <= 79200 AND (energy_wh + time_seconds) outside signed int32 | FAIL | SAT | 2c9dc087-19ed-4be9-9e83-1182e2126830, ef282caa-dd78-4ca2-941a-56175525e3d0, b12026c2-6b4d-4b06-951f-9f39a223a8c5, 9ef2bcb0-0b88-4cd8-bd9e-8451d6a9d9bd | Requirement REQ-CHG-01; expected UNSAT; result object e753785b-6a6f-484e-b46e-8f10d10f24a3-OVERFLOW-1. Model: energy_wh=0, time_seconds=2147483648. |
| Ch3 | SMT-gd12_charging_rate_positive_time-OVERFLOW | SMT signed int32 overflow | energy_wh >= 0 and time_seconds > 0 and energy_wh <= 79200 AND (energy_wh + time_seconds) outside signed int32 | FAIL | SAT | 2c9dc087-19ed-4be9-9e83-1182e2126830, ef282caa-dd78-4ca2-941a-56175525e3d0, b12026c2-6b4d-4b06-951f-9f39a223a8c5, 9ef2bcb0-0b88-4cd8-bd9e-8451d6a9d9bd | Requirement REQ-EMG-01; expected UNSAT; result object e753785b-6a6f-484e-b46e-8f10d10f24a3-OVERFLOW-2. Model: energy_wh=0, time_seconds=2147483648. |
| Ch3 | SMT-gd12_emergency_power_zero | SMT condition | emergency == 1 and total_power == 0 | PASS | SAT | 83ede856-fea1-444b-97fc-4b16d84edd03, 578f7412-9496-4a80-bfc5-6b26715724c8, ee1e57db-2ac7-4dd3-b39f-d066930d63a5, b2e24962-fbed-44b1-b1f6-7af27c106174 | Requirement REQ-CHG-01; expected SAT; result object 08531e80-c96f-40bb-b73a-ca7829144b4d-SAT-1. Model: emergency=1, total_power=0. |
| Ch3 | SMT-gd12_emergency_power_zero | SMT condition | emergency == 1 and total_power == 0 | PASS | SAT | 83ede856-fea1-444b-97fc-4b16d84edd03, 578f7412-9496-4a80-bfc5-6b26715724c8, ee1e57db-2ac7-4dd3-b39f-d066930d63a5, b2e24962-fbed-44b1-b1f6-7af27c106174 | Requirement REQ-EMG-01; expected SAT; result object 08531e80-c96f-40bb-b73a-ca7829144b4d-SAT-2. Model: emergency=1, total_power=0. |
| Ch3 | SMT-gd12_power_cap_not_exceeded | SMT condition | power_port1 >= 0 and power_port1 <= 22 and power_port2 >= 0 and power_port2 <= 22 and power_port3 >= 0 and power_port3 <= 22 and power_port4 >= 0 and power_port4 <= 22 and power_port5 >= 0 and power_port5 <= 22 | PASS | SAT | 0c8a0e09-bbc2-4d69-9d61-61372af5a46b, 4276cdeb-dff3-4119-a7ce-a45abd1f058d, 8193b694-f7ba-4c74-b1f0-d4b8ee4cbe6b, 6286e628-7050-4164-a015-75634df01d85 | Requirement REQ-CHG-01; expected SAT; result object 43b29e85-96fb-4880-ad3c-93ec6161e397-SAT-1. Model: power_port1=0, power_port2=0, power_port3=0, power_port4=0, power_port5=0. |
| Ch3 | SMT-gd12_power_cap_not_exceeded | SMT condition | power_port1 >= 0 and power_port1 <= 22 and power_port2 >= 0 and power_port2 <= 22 and power_port3 >= 0 and power_port3 <= 22 and power_port4 >= 0 and power_port4 <= 22 and power_port5 >= 0 and power_port5 <= 22 | PASS | SAT | 0c8a0e09-bbc2-4d69-9d61-61372af5a46b, 4276cdeb-dff3-4119-a7ce-a45abd1f058d, 8193b694-f7ba-4c74-b1f0-d4b8ee4cbe6b, 6286e628-7050-4164-a015-75634df01d85 | Requirement REQ-EMG-01; expected SAT; result object 43b29e85-96fb-4880-ad3c-93ec6161e397-SAT-2. Model: power_port1=0, power_port2=0, power_port3=0, power_port4=0, power_port5=0. |
| Ch3 | SMT-gd12_power_cap_not_exceeded-OVERFLOW | SMT signed int32 overflow | power_port1 >= 0 and power_port1 <= 22 and power_port2 >= 0 and power_port2 <= 22 and power_port3 >= 0 and power_port3 <= 22 and power_port4 >= 0 and power_port4 <= 22 and power_port5 >= 0 and power_port5 <= 22 AND (power_port1 + power_port2 + power_port3 + power_port4 + power_port5) outside signed int32 | PASS | UNSAT | 03437c8a-b41d-4052-a4ec-8bda224777e3, 93bbf194-715d-424b-9c2d-90980544ab87, a1554bc9-ed53-435e-9342-7b3e520d4292 | Requirement REQ-CHG-01; expected UNSAT; result object c80fb3b1-f5d0-486a-b36c-ab72b130e9ce-OVERFLOW-1. |
| Ch3 | SMT-gd12_power_cap_not_exceeded-OVERFLOW | SMT signed int32 overflow | power_port1 >= 0 and power_port1 <= 22 and power_port2 >= 0 and power_port2 <= 22 and power_port3 >= 0 and power_port3 <= 22 and power_port4 >= 0 and power_port4 <= 22 and power_port5 >= 0 and power_port5 <= 22 AND (power_port1 + power_port2 + power_port3 + power_port4 + power_port5) outside signed int32 | PASS | UNSAT | 03437c8a-b41d-4052-a4ec-8bda224777e3, 93bbf194-715d-424b-9c2d-90980544ab87, a1554bc9-ed53-435e-9342-7b3e520d4292 | Requirement REQ-EMG-01; expected UNSAT; result object c80fb3b1-f5d0-486a-b36c-ab72b130e9ce-OVERFLOW-2. |
| Ch3 | SMT-gd12_soc_charging_blocked_when_full | SMT condition | soc >= 100 and charging == 0 | PASS | SAT | 09cb4c3e-6a32-47ec-beeb-d97d9ce0e480, 28780517-d6fb-45fc-883a-c50b3cfb3170, a637d7c2-1b89-45da-b7c6-34018e00dc25, 0c13fd94-bc5a-4139-bb87-80b05ab7f542 | Requirement REQ-SOC-01; expected SAT; result object df77dbe5-00c2-4c19-9674-041a25e5b597-SAT-1. Model: charging=0, soc=100. |
| Ch3 | SMT-gd12_soc_charging_blocked_when_full | SMT condition | soc >= 100 and charging == 0 | PASS | SAT | 09cb4c3e-6a32-47ec-beeb-d97d9ce0e480, 28780517-d6fb-45fc-883a-c50b3cfb3170, a637d7c2-1b89-45da-b7c6-34018e00dc25, 0c13fd94-bc5a-4139-bb87-80b05ab7f542 | Requirement REQ-SOC-02; expected SAT; result object df77dbe5-00c2-4c19-9674-041a25e5b597-SAT-2. Model: charging=0, soc=100. |
| Ch3 | SMT-gd12_soc_full_threshold_sat | SMT condition | soc >= 100 | PASS | SAT | f64abf28-7241-4cf6-9ec9-018a8ad857db, ba6f3ed6-5aff-4b29-9283-7a22169047f9, 83401b12-82ba-4e83-bdc3-f375b1fcd0a6, 0c627d2f-6537-4014-8e40-b90fec8a4ae9 | Requirement REQ-SOC-01; expected SAT; result object c8acece0-3821-4963-a9c6-f82caf3b7641-SAT-1. Model: soc=100. |
| Ch3 | SMT-gd12_soc_full_threshold_sat | SMT condition | soc >= 100 | PASS | SAT | f64abf28-7241-4cf6-9ec9-018a8ad857db, ba6f3ed6-5aff-4b29-9283-7a22169047f9, 83401b12-82ba-4e83-bdc3-f375b1fcd0a6, 0c627d2f-6537-4014-8e40-b90fec8a4ae9 | Requirement REQ-SOC-02; expected SAT; result object c8acece0-3821-4963-a9c6-f82caf3b7641-SAT-2. Model: soc=100. |
| Ch3 | SMT-gd12_soc_update_no_overflow | SMT condition | soc_current >= 0 and soc_current <= 100 and soc_delta >= 0 and soc_delta <= 100 | PASS | SAT | 4c3afc79-36c5-49ab-8b99-99c88b74190a, 13a13f16-7d2a-4b3b-8ad7-a2a99489b748, 77bc7b84-ab1c-4b23-864d-458f727c72f5, 86cda298-1a5f-4f60-a8b5-f579df615a60 | Requirement REQ-SOC-01; expected SAT; result object c263e222-22c6-4bd3-8602-ea1f3d449799-SAT-1. Model: soc_current=0, soc_delta=0. |
| Ch3 | SMT-gd12_soc_update_no_overflow | SMT condition | soc_current >= 0 and soc_current <= 100 and soc_delta >= 0 and soc_delta <= 100 | PASS | SAT | 4c3afc79-36c5-49ab-8b99-99c88b74190a, 13a13f16-7d2a-4b3b-8ad7-a2a99489b748, 77bc7b84-ab1c-4b23-864d-458f727c72f5, 86cda298-1a5f-4f60-a8b5-f579df615a60 | Requirement REQ-SOC-02; expected SAT; result object c263e222-22c6-4bd3-8602-ea1f3d449799-SAT-2. Model: soc_current=0, soc_delta=0. |
| Ch3 | SMT-gd12_soc_update_no_overflow-OVERFLOW | SMT signed int32 overflow | soc_current >= 0 and soc_current <= 100 and soc_delta >= 0 and soc_delta <= 100 AND (soc_current + soc_delta) outside signed int32 | PASS | UNSAT | 0cf1c9bd-186b-49c7-bc6b-2a64f9a98852, dae56eb8-cf8f-4078-a16e-695cc6a03049, e7503544-67b6-4ac4-9f16-7aa477a2968d | Requirement REQ-SOC-01; expected UNSAT; result object 93e5249a-2e4b-4740-bb46-e7d0b847c757-OVERFLOW-1. |
| Ch3 | SMT-gd12_soc_update_no_overflow-OVERFLOW | SMT signed int32 overflow | soc_current >= 0 and soc_current <= 100 and soc_delta >= 0 and soc_delta <= 100 AND (soc_current + soc_delta) outside signed int32 | PASS | UNSAT | 0cf1c9bd-186b-49c7-bc6b-2a64f9a98852, dae56eb8-cf8f-4078-a16e-695cc6a03049, e7503544-67b6-4ac4-9f16-7aa477a2968d | Requirement REQ-SOC-02; expected UNSAT; result object 93e5249a-2e4b-4740-bb46-e7d0b847c757-OVERFLOW-2. |
| Ch3 | SMT-gd12_soc_valid_domain_sat | SMT condition | soc >= 0 and soc <= 100 | PASS | SAT | d71e9d47-4f0f-41e3-8c1b-28d6bb554973, f8db5464-044b-41cf-9c09-94e9dc918820, 355b1245-8a83-4b1c-b2d7-2b8ff7dae9d2, 287f28fe-0a56-4156-93b3-6a168e8a4c56 | Requirement REQ-SOC-01; expected SAT; result object a95445d1-e056-4e8e-a23d-c7dfd62052c9-SAT-1. Model: soc=4. |
| Ch3 | SMT-gd12_soc_valid_domain_sat | SMT condition | soc >= 0 and soc <= 100 | PASS | SAT | d71e9d47-4f0f-41e3-8c1b-28d6bb554973, f8db5464-044b-41cf-9c09-94e9dc918820, 355b1245-8a83-4b1c-b2d7-2b8ff7dae9d2, 287f28fe-0a56-4156-93b3-6a168e8a4c56 | Requirement REQ-SOC-02; expected SAT; result object a95445d1-e056-4e8e-a23d-c7dfd62052c9-SAT-2. Model: soc=4. |
| Ch3 | SMT-gd12_soc_violation_contradiction_unsat | SMT condition | soc >= 0 and soc <= 100 and (soc < 0 or soc > 100) | PASS | UNSAT | ab99e780-a9e5-44cf-92b1-4fea2863513c, 124eefdc-cc7c-4947-9f9a-60931a670369, 55a81b70-b299-46a3-8a88-50b8eb71282f | Requirement REQ-SOC-01; expected UNSAT; result object 02d9dbff-083f-431e-8ea2-5d3ffec03f9d-SAT-1. |
| Ch3 | SMT-gd12_soc_violation_contradiction_unsat | SMT condition | soc >= 0 and soc <= 100 and (soc < 0 or soc > 100) | PASS | UNSAT | ab99e780-a9e5-44cf-92b1-4fea2863513c, 124eefdc-cc7c-4947-9f9a-60931a670369, 55a81b70-b299-46a3-8a88-50b8eb71282f | Requirement REQ-SOC-02; expected UNSAT; result object 02d9dbff-083f-431e-8ea2-5d3ffec03f9d-SAT-2. |
| Ch3 | SMT-gd12_temp_charging_blocked_when_overheat | SMT condition | temperature >= 60 and charging == 0 | PASS | SAT | e473f038-df2d-4bdd-8da5-f94fb1ba7e9a, ed4d4020-2fc6-4e3c-8211-b91afe88b3d3, 1dd439f2-92e5-4217-8b28-fec8eec53b48, d443b9d9-9b73-4776-887d-ed646bd6e2df | Requirement REQ-TEMP-01; expected SAT; result object 93239af0-6601-492b-a4f9-59614834191b-SAT-1. Model: charging=0, temperature=60. |
| Ch3 | SMT-gd12_temp_overheat_contradiction_unsat | SMT condition | temperature >= 60 and temperature < 60 | PASS | UNSAT | de5a74ea-ca6c-432b-8c96-19ddd9ef68f8, b88b0714-0ea8-4649-9fee-d4d25a8a5726, 1cd7e9a2-db81-4e02-8d90-da134d1e9198 | Requirement REQ-TEMP-01; expected UNSAT; result object 9b87e462-6386-4222-8fe1-7a18d1b5d2c4-SAT-1. |
| Ch3 | SMT-gd12_temp_overheat_threshold_sat | SMT condition | temperature >= 60 | PASS | SAT | 86e7f2fc-3613-449d-afe3-787a67935d23, 1ed0348a-05a2-49d9-9097-8545cfd10a6d, 93afdf2f-c193-4e0c-aa48-1c69848d2193, b42e4367-3211-4e38-adf7-7881a4d0d890 | Requirement REQ-TEMP-01; expected SAT; result object 993c77bf-9903-4993-abb4-ee77ceaa6d84-SAT-1. Model: temperature=60. |
| Ch3 | SMT-gd12_temp_safe_range_sat | SMT condition | offset >= 0 and offset <= 79 and temperature == offset and temperature < 60 | PASS | SAT | 568eb363-1955-4977-86c3-1ef5d6952e14, 789d50a6-275d-417f-93da-4a1ad809c2ec, a3d39217-462d-432b-9510-1083b0593ce6, 81293087-aa3a-4ea6-a6b1-184f16e6c78a | Requirement REQ-TEMP-01; expected SAT; result object 3577623b-295d-4215-9027-534bf77cc62c-SAT-1. Model: offset=0, temperature=0. |

## 9. Environment limitations

- Windows 11, Python 3.12.5.
- MinGW GCC/G++ 8.1.0; Clang/Clang++ 22.1.7.
- Cppcheck 2.21.0 and Clang-tidy are installed and ran. Their reports are heuristic/static diagnostics and need review; findings alone do not prove a requirement violation.
- Z3 Python backend is available and completed the SMT checks. The external `z3` executable is absent. CBMC is absent, and the specification has no BMC formulas regardless.
- gcov/LLVM coverage tools are installed, but coverage did not run because there is no executable test suite. The prior gcov nested-path limitation was therefore not exercised here.
- Address/undefined sanitizer builds failed on missing include-directory configuration; LeakSanitizer is unsupported on this Windows environment.
- PySide6 is unavailable; GUI was not part of this CLI integration run.

## 10. Unsupported items and difference from teacher app

The teacher JSON is not Specification Core v1 JSON, so a format adapter is needed. The independent tool does not implement the teacher app's Ch2/Ch4 code generators, standalone `check_c_source`, Python probe generator, or concolic probe execution. It does not convert narrative steps into executable tests. Consequently, expected probe CWEs are not observed findings, named function hashes are unavailable, and Chapter 4/5 campaigns are not run. The independent system does run the real formal model and all 12 arithmetic conditions, while static/memory tools analyze the actual C source set under the project's `src/` directory.

## 11. Test and build verification

The dedicated integration test is `tests/integration/test_real_smart_ev_spec.py`. It loads the original JSON, checks and records the raw-format schema failure, adapts/validates/normalizes it, runs the full available pipeline, and verifies stages, result statuses, evidence IDs/hashes, traceability IDs, workspace confinement, and unchanged hashes. Historical milestone run: the full suite passed with **236 passed, 4 skipped**. `python -m compileall -q src tests` passed. The suite needed a short Windows basetemp (`E:\seclab-verification-tool\t` in that run); a longer nested temp path made the existing gcov fixture fail to create its `.gcno` file. This earlier count is superseded by the current canonical baseline in [architecture-freeze.md](architecture-freeze.md): **282 passed, 5 skipped, 0 failed**.
