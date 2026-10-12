# Generic multi-file C++ project

This project exercises generic source discovery, specification mapping, formal model checks, and dynamic function tests over multiple C++ translation units.

Run it with the same pipeline API as other projects:

```python
from seclab.pipeline import PipelineOptions, run_full_verification

run_full_verification(
    "examples/generic-multifile-cpp-project",
    "runs",
    options=PipelineOptions(
        specification_paths=("examples/generic-multifile-cpp-project/specification.json",),
        static_analyzers=(), run_memory=False, run_coverage=False,
    ),
)
```
