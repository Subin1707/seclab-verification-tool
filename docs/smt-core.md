# SMT Core v1

SMT Core checks a boolean property over one valuation of the normalized
Specification v1 variables. It does not encode C execution, temporal behavior,
state transitions, or a bounded path. The JSON specification contract is
unchanged; constraint expressions remain strings and are parsed only by this
SMT layer.

## Expression grammar

The parser accepts identifiers (`[A-Za-z][A-Za-z0-9_.:-]*`), integer and finite
decimal/exponent literals, `true`/`false`, double-quoted strings, parentheses,
unary `!` and `-`, arithmetic `+`, `-`, `*`, comparisons `==`, `!=`, `<`, `<=`,
`>`, `>=`, boolean `&&`, `||`, and right-associative implication `->`.
Precedence from tightest to loosest is unary, `*`, `/`, `+`/`-`, comparison,
`&&`, `||`, and `->`. Chained comparisons are rejected. Division is tokenized
so malformed syntax is diagnosed consistently, then rejected with
`UNSUPPORTED_OPERATOR` in v1: integer/real division and zero-denominator
semantics are not specified by this core. String escapes are limited to `\\`,
`\"`, `\n`, `\r`, and `\t`.

Specification identifiers may contain `-`; such names are lexed as one
identifier. To write subtraction between identifier expressions, put whitespace
around `-` (for example, `x - y`). Unary minus needs no surrounding whitespace.

Expressions are parsed into immutable `Literal`, `Variable`, `Unary`, and
`Binary` nodes. No Python expression evaluation or shell interpolation is
used. Syntax and type errors are structured `SMTError` exceptions and never
become property failures.

## Types and domains

Boolean, integer, real (`number` in Specification v1), and string variables are
supported. Real variables retain Z3 Real sort; integer variables retain Int
sort. Enum/finite values are encoded as equality alternatives for the
underlying primitive type and decoded back to that primitive value. Mixed or
unsupported finite domains are rejected. Numeric `minimum` and `maximum`, and
all finite `values`, become explicit solver constraints. Initial values are
not implicitly assumed: violation search checks the declared state-space
constraints, rather than only the initial valuation. Every Specification
constraint expression is conjoined as an assumption; `kind` metadata does not
add temporal semantics.

Boolean operators require boolean operands. Arithmetic requires numeric
operands; equality permits matching types and mixed integer/real values;
ordering requires numeric operands. Unknown variables are rejected before the
backend is called. Unsupported domain/type semantics fail explicitly.

## Query and outcomes

`SMTEncoder` produces a deterministic, solver-neutral query record with
declarations/types, variable-to-symbol mapping, domain constraints, parsed
Specification assumptions, property AST, query AST, and query intent. It does
not invoke a solver or classify a result. `VIOLATION_SEARCH` means all encoded
constraints and domains conjoined with `NOT(property)`. `SATISFIABILITY` asks
whether they admit a valuation satisfying the property. The Z3 backend uses
the `z3-solver` Python dependency declared by this project; the external `z3`
executable is not used.

`SolverOutcome` (`SAT`, `UNSAT`, `UNKNOWN`, `ERROR`) is separate from the
canonical `VerificationStatus`. For `VIOLATION_SEARCH`, SAT means a violation
model and maps to `FAIL / PROPERTY_VIOLATED`; UNSAT means no violation in the
encoded scope and maps to `PASS / NO_VIOLATION_IN_SMT_SCOPE`. UNKNOWN maps to
`INCONCLUSIVE / SOLVER_UNKNOWN`; a backend timeout maps to
`INCONCLUSIVE / SOLVER_TIMEOUT`; backend infrastructure errors map to
`TOOL_ERROR`. SAT/UNSAT alone have no global PASS/FAIL meaning. Non-violation
query intents remain `INCONCLUSIVE` at the property-classification layer.
Scenario-provided expected outcomes are not used to manufacture SMT property
results; SAT/UNSAT observations and any returned model remain checker output.

The PASS scope is exactly one valuation over the declared variable domains
satisfying all specification constraints. It does not establish safety of a
software implementation without a separately justified connection between
that implementation and this specification model.

## Models and evidence

SAT models are returned as deterministic variable assignments with variable
name, primitive type, and value. A violation result requires a structured
counterexample. When an `ArtifactStore` is supplied, every result stores the
encoded query, solver outcome and identity/version, and raw backend output; a
SAT violation also stores counterexample JSON. `VerificationResult` contains
the evidence IDs, paths, and SHA-256 hashes in metadata. Artifact JSON uses
stable key ordering; run IDs and artifact filenames are intentionally unique.

## Limitations

This core does not implement BMC, CBMC, Kripke unrolling, transition semantics,
integer/real division, or C program semantics. Z3 timeout produces UNKNOWN with
`SOLVER_TIMEOUT`; Z3 unknown reasons are retained. The optional external Z3
binary may remain absent because this backend calls the declared Python
package directly.
