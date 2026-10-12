# Smart-EV tool-capability probes

These four small C programs are intentionally defective, standalone inputs for exercising the existing compiler, static-analysis, and sanitizer integrations. They are not copied from the Smart-EV implementation and are never production SUT evidence.

Run them with:

```powershell
python tools/run_smart_ev_probes.py
```

Each run creates a unique directory under `.runs/smart-ev-probes/`. Commands, outputs, normalized findings, source hashes, manifest entries, and scoped results are stored under that run workspace. The runner does not change analyzer semantics or infer a production vulnerability from a probe finding.

The `expected_cwe` fields are `null` because the current `CWEMapper` has no mapping for these four vulnerability classes. An observed CWE is recorded only when a tool supplies it or the existing mapper maps the finding rule.
