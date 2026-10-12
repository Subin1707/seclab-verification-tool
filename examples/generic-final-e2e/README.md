# Generic final E2E fixture

This project exercises the generic C verification pipeline with a finite state
model, a separately source-derived `model_step` function, a branching/arithmetic
CLI executable using heap allocation, real argv observations, deterministic
fuzz seeds, model-to-C generation and the fixture-level accuracy benchmark.

Run from the repository root:

```powershell
python -m seclab.cli verify --project examples/generic-final-e2e --spec examples/generic-final-e2e/specification.json --config examples/generic-final-e2e/pipeline-config.json --workspace t/generic-final-e2e-runs --run-id generic-final-cli
```

The GUI can open the project and Specification once, set the source model target
to `model_step` with domain `{"mode": [0, 1, 2]}`, enable generated C and the
fixture-level accuracy benchmark, configure the same fuzz seed/budget, review
the model and run all stages in one session. Host tools may report their own
unsupported or environment-limited stage status. Generated C remains a generated
artifact, never production source.
