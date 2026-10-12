# Results and Evidence Core v1

## Purpose and status contract

The results layer records semantic outcomes shared by verification techniques. Its canonical statuses are `PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_RUN`, `TOOL_ERROR`, `SPEC_ERROR`, and `BUILD_ERROR`. `reason_code` provides the machine-readable detail, independently of the status. Raw engine outcomes are classified before a `VerificationResult` is created; raw solver terms such as SAT are not semantic verdicts on their own.

`VerificationResult` is immutable and JSON serializable. It records the verification stage, technique, message, optional requirement/property/source identifiers, the checked `scope`, evidence references, optional counterexample data, duration, and JSON metadata. A result describes only its own check and scope. `ResultCollector.summary()` counts statuses; it deliberately does not calculate a project-wide verdict.

The classifier maps a satisfied property to `PASS`, a violated property to `FAIL`, invalid input to `SPEC_ERROR`, build and tool failures to their corresponding error statuses, and timeout or unknown outcomes to `INCONCLUSIVE`. A check that did not run maps to `NOT_RUN`. For CTL, syntax and unknown-atom errors are specification errors; a model-checking implementation error is a tool error. Missing initial states do not produce a property verdict and are inconclusive.

## Evidence and artifact storage

`Evidence` records the artifact type, stage, source, workspace-relative path, UTC timestamp, SHA-256 digest, optional requirement/property IDs, and metadata. The digest is computed from the exact stored bytes. JSON artifacts are UTF-8, sorted by key, and indented for review.

`ArtifactStore` stores files under `<workspace>/evidence/<stage>/<filename>`. Stage and filename are single safe path components; absolute paths, separators in filenames, traversal components, and resolved paths outside the evidence root are rejected. Artifacts are created exclusively and cannot silently overwrite an existing file. It supports text, JSON, and byte-preserving file-copy operations.

`EvidenceCollector` provides duplicate-safe collection and filtering by stage, requirement, or evidence type. `RunManifest` binds run metadata, environment and tool versions, semantic results, evidence entries, input artifact references, and a status-count summary. It checks duplicate IDs and ensures every result evidence reference resolves within the manifest. The summary remains a count, not a project verdict.

The pipeline writes one stage-execution envelope for every stage record, including stages skipped by selection, dependency, or cancellation. The envelope records run/stage ID, lifecycle status, source and specification hashes, a canonical configuration hash and reproducibility ID, tool versions, timestamps, results and stage references. Pipeline evidence metadata carries the same run-level provenance. Manifest reopening verifies workspace confinement, file size and SHA-256, run/checker attribution, provenance fields, and that every stage record resolves to an execution envelope whose identity, status, and configuration fingerprint match. The self-hash of the manifest is kept in the adjacent `run-integrity.json` record to avoid a recursive self-reference.

The reproducibility ID fingerprints the source set, specification inputs/normalized specification, configuration (including explicit fuzz seeds), and available tool versions. Timing, run ID, and generated evidence IDs are excluded from that fingerprint. Repeated runs can therefore be compared by reproducibility ID and checker/stage observations without requiring timestamped evidence bytes to have identical hashes.

Pipeline reports remain checker- and stage-scoped: they contain stage statuses, checker results, evidence/traceability, limitations, and reproducibility metadata. Their `accuracy` field is explicitly `NOT_RUN` with fixture-level scope unless a separate benchmark run is attached. There is no `overall_verdict`, `overall_status`, `project_pass`, or `project_fail` field. Benchmark TP/TN/FP/FN values are emitted by the separate benchmark report when that benchmark is run.

## CTL integration example

`classify_ctl_result` adapts an existing `CTLCheckResult` without changing the CTL parser, AST, model semantics, or result contract. For failed `AG(safe)`, the caller can serialize the engine-provided counterexample path into a `COUNTEREXAMPLE` artifact, then attach its evidence ID to the semantic `FAIL` result. For satisfied `EF(done)`, the witness path can be stored as `WITNESS` and referenced from the `PASS` result. Both result and artifact references are then captured by `RunManifest`.

## Scope and limitations

CTL result scope describes the supplied finite Kripke structure and formula. Guards retained as transition metadata have not been evaluated by the CTL core. Artifact paths in a manifest are relative to the workspace used when writing the artifacts; consumers should resolve them against that workspace. This core does not infer an aggregate project status, validate artifact contents against their declared type, or implement storage cleanup/retention policy.
