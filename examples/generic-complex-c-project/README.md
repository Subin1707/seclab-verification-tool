# Generic complex C verification fixture

This tool-independent project exercises a branching explicit-state machine, arithmetic and overflow guards, heap allocation and release, command-line execution, dynamic observations, coverage, generic C model generation, and bounded fuzzing. The specification deliberately keeps model-checking claims scoped to its explicit abstract state graph; it does not claim source-to-model equivalence.

Run from the repository root with:

```powershell
python -m seclab.cli verify --project examples/generic-complex-c-project --spec examples/generic-complex-c-project/specification.json --config examples/generic-complex-c-project/pipeline-config.json --workspace t/generic-complex-e2e-runs --run-id generic-complex-final
```

The accuracy stage records generic fixture benchmark metrics separately from verification results. It does not create an overall project verdict.
