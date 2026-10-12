# Fuzzing Core v1

The fuzzing package runs bounded, reproducible campaigns through the existing `TestRunner`. Coverage-guided campaigns use `CoverageRunner` once per input with an isolated backend build/profile. The engine does not edit SUT files or invoke a second process API.

## Inputs, corpus, and replay

`FuzzInput` distinguishes bytes, text, and scalar mappings, and records an origin, parent, generation, and JSON-safe metadata. Its SHA-256 covers the typed payload. `Corpus` deduplicates by that hash and orders entries by discovery iteration, content hash, and ID.

Each campaign creates a local `random.Random(random_seed)`. Replaying the same seed corpus, configuration, and source hashes yields the same candidate inputs and mutation decisions; execution timing and platform behavior can differ. The campaign manifest records those source hashes and a canonical configuration hash. `max_iterations`, `max_executions`, `max_input_count`, `max_seconds`, `timeout_per_input`, `max_input_size`, and the separate minimization execution cap bound work. The time budget also limits each target timeout and minimization callback.

## Strategies

- **BLACKBOX** generates random bytes, text, or scalar values without source or coverage feedback.
- **BOUNDARY** uses declared specification domains when supplied; it emits integer edges, booleans, finite values, and bounded string edge cases. Without a specification it labels bounded random fallback inputs as boundary fallback in metadata.
- **MUTATION** selects a corpus parent and applies byte, text, or scalar input operators. The operator is recorded in metadata. This module does not change program source.
- **COVERAGE_GUIDED** mutates corpus inputs, runs each candidate through the real coverage backend, and retains it only for new line/branch identities or a finding. It uses `CoverageSnapshot` and `CoverageDelta`, not percentages. Each testcase has isolated instrumented build/profile state.
- **CONCOLIC** is a **PROTOTYPE**, not a supported target strategy. `ConcolicGenerator` accepts a caller-supplied branch constraint and current-path operator, asks the existing SMT verifier for a satisfying valuation of the alternate expression, and returns that candidate. It does not capture a concrete execution path, trace source branches or replay generated inputs against target instrumentation. `FuzzEngine` reports concolic campaigns as **UNSUPPORTED** until those pieces exist.

## Findings and results

The analyzer treats timeouts, recognized abnormal termination, sanitizer diagnostics, and declared oracle violations as findings. A nonzero exit by itself is not a crash. Failure signatures omit volatile raw stderr and deduplicate by failure kind plus stable exit/signal, sanitizer, or oracle identity. Timeout findings are not automatically a safety verdict; a finding yields a scoped `FAIL` for the observed campaign condition. Campaigns without findings return `INCONCLUSIVE/NO_FAILURE_FOUND_WITHIN_FUZZ_BUDGET`, never `PASS`.

Input minimization is bounded and retains reductions only when the observed failure signature equals the original signature. Unsupported structured scalar minimization and runner errors preserve the original input.

## Budgets and evidence

`FuzzConfig` requires an iteration count, per-input timeout, random seed (or generates and records one), and maximum input size. It optionally accepts elapsed-time, execution-count and candidate-input-count limits, stop-on-first-failure, mutation limit, and a separate minimization execution limit. Campaign summaries record strategy, budgets, seed, iteration and finding counts, corpus size, coverage entity signatures/delta, duration, stop reason, source hashes, and evidence references. If a target testcase times out, it is recorded as a timeout observation; the campaign remains inconclusive unless a separately declared oracle gives that timeout a failure meaning.

Every candidate input, testcase, process stdout/stderr, command/execution record, observation, result and per-iteration analysis record is persisted. Findings add a stable crash/timeout/oracle signature; coverage runs retain backend reports and record the observed entity set/delta. Seed and interesting inputs are kept in a content-hash-deduplicated corpus, and minimization executions retain only the same failure signature. Source hashes are compared around every campaign.

No failure found during fuzzing does not prove absence of defects. Coverage measurement does not create a safety `PASS`.
