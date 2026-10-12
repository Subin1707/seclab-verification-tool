# Generic C project fixture

This standalone C project is an independent example input for SecLab. It has no external system, package, or runtime dependency.

Run it from the verification tool repository with:

```powershell
seclab verify --project examples/generic-c-project --spec examples/generic-c-project/specification.json
```

The verification workspace is created alongside the project by default. Pass `--workspace` to choose another location.
