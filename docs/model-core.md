# Model Core v1

The model layer consumes the normalized Specification from
seclab.specification; it does not parse user files or interpret verification
formulas.

## State generation

The current contract defines named states and transitions. The generator
copies each declared state ID, value mapping and explicit label into a
State, then copies each declared edge into a Transition. It does not create
the Cartesian product of variable domains or infer transitions. Transition
guards use the supported Specification SMT expression subset when all names
have values in the source state. A false guard omits the edge; a true guard
retains it with `EVALUATED_TRUE` status. Guards with unresolved names stay in
the graph marked `UNRESOLVED_VARIABLES` for compatibility with symbolic guard
metadata and are not claimed as evaluated. Invalid syntax, non-boolean results
and evaluation errors are structured model errors. Assignment actions of the
form `variable = expression` are checked against the explicit target state's
valuation; other action strings remain descriptive metadata. The generator
never invents target states.

If initial_state is present it selects that declared state. Otherwise the
single StateSpec.initial marker selects the initial state. A non-empty
explicit state machine with no initial selector is a MODEL_ERROR with reason
MISSING_INITIAL_STATE; the generator never chooses the first state. If no
states are declared, the result is an empty Kripke structure with no initial
states. This represents that the v1 specification has no explicit state
machine and avoids inferring one from variable domains.

max_states may be supplied to generate_kripke_structure. Exceeding the
limit raises STATE_LIMIT_EXCEEDED; the generated graph is never truncated.
There is no shared SecLab configuration module in this repository yet, so the
limit is an explicit generator argument.

## Source-derived model builder (C subset)

`SourceModelBuilder` is an additional generic input path and does not change
the Specification contract or `KripkeStructure` semantics. It reuses
`SourceLoader`, invokes Clang with `-fsyntax-only -ast-dump=json` (the SUT is
not run), then constructs a bounded control-flow abstraction. The current
supported fragment is C translation units with signed `int`/`void` functions,
finite integer parameter domains, initialized automatic integer locals,
direct assignments, integer arithmetic/comparisons/boolean operators,
`if/else`, `while`, `for`, and `return`. Function calls, global/static state,
pointers, uninitialized locals, other types/operators, and invalid syntax
produce `UNSUPPORTED` with a diagnostic and no model. Missing Clang produces
`ENVIRONMENT_LIMITED`.

The standalone builder requires exactly one function definition across its
input translation units. It does not infer an entry point or model a call graph.
The integrated pipeline opts in using `PipelineOptions.source_model_target`,
which must match exactly one declared `FunctionSpec`; that function's `file`
selects the translation unit, which must contain only that function definition.
Finite parameter domains are passed through
`source_model_parameter_domains` keyed by parameter name, and
`source_model_loop_bound` configures loop unwinding. These are orchestration
options, not Specification JSON fields, so the Specification contract is
unchanged.

Parameters are never assigned guessed values. Every parameter requires a
finite integer domain keyed as `function.parameter`; values outside signed
32-bit `int` are rejected. Arithmetic outside that range is not wrapped or
guessed. Branches whose expression cannot be evaluated are represented as
both guarded successors and make the whole model result `INCONCLUSIVE`.
`loop_bound` counts taken loop-condition branches. A still-true loop at the
bound is left as an explicitly incomplete frontier and the result is
`INCONCLUSIVE`; it is not a completed proof model. Constant-unreachable CFG
nodes are omitted and reported in `warnings`.

The result includes a canonical Kripke graph, per-state source locations,
source-line to state/transition IDs, source branch-condition mappings with
CTL-visible labels, unsupported constructs, warnings, parser version, source
SHA-256 values, and evidence IDs/hash values when an `ArtifactStore` is
provided. Branch mappings describe source conditions; they do not create
Specification properties or claim that a source condition is a requirement.
Consumers must check `status` before treating the model as complete.

In the integrated pipeline the source-derived graph remains a distinct
provenance artifact; it does not replace the explicit Specification model.
CTL/BMC use the explicit graph when declared. If no explicit graph exists, they
may use the source graph only when `source_model_target` was explicitly set and
the builder status is `SUPPORTED`. `INCONCLUSIVE`, `UNSUPPORTED`, and
`ENVIRONMENT_LIMITED` outputs remain source-stage evidence; formal properties
receive an `INCONCLUSIVE` result with `SOURCE_MODEL_INCOMPLETE` or
`MODEL_UNAVAILABLE`, and are not passed to a checker. SMT continues to check
Specification constraints independently. An unavailable optional MODEL path
does not block a complete source-derived formal path, and vice versa.

## Kripke and graph behavior

KripkeStructure represents S, S0, R, and L as sorted immutable state
and transition tuples plus each state's explicit labels. It verifies unique
state IDs, a non-empty initial subset for non-empty S, initial membership,
and transition endpoints during construction. The empty model is permitted.
Successor/predecessor queries return unique states in ID order.

Reachability is a breadth-first traversal from all initial states and returns
states in deterministic traversal order. Unreachable states are ID-sorted.
deadlock_states reports all states with no outgoing edge, whether reachable
or not. This is structural information only; it does not classify a terminal
state as a property violation.

The structured graph export is JSON-compatible and deterministic. It includes
the SHA-256 model hash, model statistics, reachable/unreachable/deadlock state
IDs, state-variable names, and traceability lists of state and transition IDs.
Missing transition IDs receive deterministic content-derived IDs. The model
API exposes the same statistics and IDs to non-GUI consumers.
to_dot produces text without requiring Graphviz. Labels are exactly the
explicit StateSpec.labels; no business proposition is inferred.
