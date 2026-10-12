# BMC Core v1

BMC Core checks bad-state reachability over the repository's existing finite,
explicit `KripkeStructure`. It reuses the SMT Core `SolverOutcome`, encoded
query representation, and production Z3 backend. The JSON specification and
Model Core contracts are unchanged. This is not BMC of C source code.

## Model and property scope

The input is a `KripkeStructure` containing finite states, one or more initial
states, explicit edges, state labels, and scalar state values. The v1 property
input is one explicit atomic proposition label naming a bad state. Unknown
labels are rejected before calling the solver. State values are included in
decoded traces but are not used as an expression language in this milestone.

Transition `guard` and `action` strings remain uninterpreted metadata. A
transition is available exactly when its edge exists in the explicit Kripke
graph. The checker neither parses nor evaluates the guard/action text.

## Bound and SMT encoding

The bound `k` counts transition steps. The encoded path has `k + 1` integer
state variables `state_0` through `state_k`. State IDs are sorted and mapped
deterministically to integer indices. The formula contains:

- `state_0` equals one of the declared initial-state indices.
- For every adjacent pair, the indices are an explicit graph edge.
- Each state variable is in `[0, number_of_states - 1]`.
- At least one state from step 0 through step `k` has the requested bad label.

The encoder makes a solver query; it does not call Z3 or classify results. The
SMT AST and existing Z3 backend compile and solve the formula. No second solver
or shell command is introduced.

`check_at_bound(k, ...)` encodes a path with exactly `k` transitions and checks
for the bad label anywhere on its `k + 1` states. Thus `k=0` checks only initial
states. Since each deadlock has a virtual self-loop, every shorter path can be
extended; existentially, this query checks for a bad state reachable within at
most `k` steps. `check_up_to_bound(k, ...)` checks depths 0, 1, ..., k in order
and stops at the first SAT depth, producing a shortest-depth bounded
counterexample. It may stop after the graph completeness threshold when all
queries so far are UNSAT.

## Deadlocks and traces

Deadlock self-loops are added only to the encoded transition relation and are
not written back to the Kripke model. A trace step contains its step number,
state ID, sorted labels, and scalar values. Each trace transition includes the
selected explicit edge metadata, or is marked `virtual_deadlock` for a
totalization self-loop. Parallel graph edges share the same solver relation;
the decoder selects the first edge under the model's deterministic edge sort.

Every SAT model is decoded and validated before it can become a FAIL:
the first state must be initial, each consecutive pair must be an explicit
edge or a deadlock self-loop, and some state must carry the bad label. A
missing/malformed model or invalid trace is a `TOOL_ERROR`, not a property
failure.

## Completeness and classification

Completeness analysis uses multi-source BFS from all initial states. The
threshold is the maximum shortest-path distance to any reachable state.
Unreachable states do not increase it. At any bound at least this threshold,
every reachable state has occurred as a path prefix, so an UNSAT bad-state
query proves no bad state is reachable in this finite graph.

| Solver result | Completeness | Verification result |
| --- | --- | --- |
| SAT with validated trace | Any bound | `FAIL / BOUNDED_COUNTEREXAMPLE_FOUND` |
| UNSAT | Bound below threshold | `INCONCLUSIVE / NO_COUNTEREXAMPLE_WITHIN_BOUND` |
| UNSAT | Bound reaches threshold | `PASS / NO_REACHABLE_VIOLATION` |
| UNKNOWN | Any bound | `INCONCLUSIVE / BMC_SOLVER_UNKNOWN` |
| UNKNOWN from timeout | Any bound | `INCONCLUSIVE / BMC_SOLVER_TIMEOUT` |
| Solver/encoding/trace infrastructure error | Any bound | `TOOL_ERROR` |

The result's `complete` field reports whether the checked depth reached the
graph's structural threshold. It does not override `SolverOutcome`: UNKNOWN
or ERROR remains inconclusive/tool error even when the threshold was reached.

The PASS claim is limited to bad-state reachability in the finite explicit
Kripke model. It does not imply that an implementation of the model, a C
program, or unmodeled behavior is safe. An exact-bound UNSAT can prove
completeness only because the query checks every prefix state and virtual
deadlocks make shorter paths extendable.

## Evidence and limitations

With an `ArtifactStore`, each solver attempt persists the BMC query (including
bound and state mapping), solver outcome/model/raw output, and completeness
analysis. SAT also persists the validated structured trace. Artifact hashes
and IDs are referenced by `VerificationResult`; solver identity/version is
included where available.

The core does not implement arbitrary CTL/LTL bounded semantics, transition
guard/action execution, state-space inference from variable domains, CBMC, or
C semantics. CTL and BMC remain independent engines; integration tests compare
their answers on shared finite graphs.
