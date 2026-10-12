# Teacher workflow demonstration fixture

This is a small, non-bug-injected input fixture for the independent six-chapter workflow adapters. `specification.json` declares one safe self-looping state machine, CTL/BMC properties, a bounded arithmetic domain with an SMT property, one provided C function, and a test oracle. The implementation is in `project/src/math.c`.

Expected traceability targets include `REQ-SAFE-01 → PROP-CTL-SAFE / PROP-BMC-ERROR-ABSENT`, `REQ-ADD-01 → PROP-SMT-NONNEGATIVE / FUNC-ADD`, and `REQ-ADD-TEST-01 → FUNC-ADD / TEST-ADD-2-3`.

The source is provided production input, not generated code. Function discovery is lexical and matching is explicit by relative file and name. This fixture does not imply that the system can generate implementation code from a specification.
