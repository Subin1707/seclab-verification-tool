# CTL Core v1

## Grammar

The parser accepts this CTL fragment. Atoms follow the specification ID shape;
reserved words are uppercase temporal operators, U, true, and false.

    formula       := implication
    implication   := disjunction [ "->" implication ]
    disjunction   := conjunction { "||" conjunction }
    conjunction   := unary { "&&" unary }
    unary         := "!" unary
                   | ("EX" | "AX" | "EF" | "AF" | "EG" | "AG") unary
                   | primary
    primary       := atom | "true" | "false" | "(" formula ")"
                   | "E" "[" formula "U" formula "]"
                   | "A" "[" formula "U" formula "]"

Precedence from highest to lowest is prefix !/temporal operators, &&, ||, then
->. && and || associate left; implication associates right. Whitespace is
ignored. LTL-only G, F, and X operators are not supported. Syntax errors
include the source position (zero-based) and line/column (one-based).

## Semantics

All operations return subsets of the complete model state set S. Atomic
propositions use explicit labels only:

    Sat(p)          = { s in S | p is in L(s) }
    Sat(true)       = S
    Sat(false)      = {}
    Sat(!φ)         = S - Sat(φ)
    Sat(φ && ψ)     = Sat(φ) intersect Sat(ψ)
    Sat(φ || ψ)     = Sat(φ) union Sat(ψ)
    Sat(φ -> ψ)     = (S - Sat(φ)) union Sat(ψ)

Let PreE(Z) be states with at least one semantic successor in Z; PreA(Z) be
states whose every semantic successor is in Z. Then:

    Sat(EX φ)       = PreE(Sat(φ))
    Sat(AX φ)       = PreA(Sat(φ))
    EF φ            = μZ . Sat(φ) union PreE(Z)
    AF φ            = μZ . Sat(φ) union PreA(Z)
    EG φ            = νZ . Sat(φ) intersect PreE(Z)
    AG φ            = S - EF(!φ)
    E[φ U ψ]        = μZ . Sat(ψ) union (Sat(φ) intersect PreE(Z))
    A[φ U ψ]        = μZ . Sat(ψ) union (Sat(φ) intersect PreA(Z))

Here μ is the least fixed point and ν the greatest fixed point. The checker
iterates these set equations until unchanged. Termination follows because the
Kripke state set is finite.

CTL evaluation uses totalized semantics without changing the input graph: a
state with no outgoing transition has a virtual self-loop for temporal
successor operations only. Graph reachability and deadlock reporting continue
to use the original transitions.

Atomic propositions come only from explicit Kripke state labels. Variable
names and transition guards do not implicitly become propositions. Unknown
atoms raise UNKNOWN_ATOM.

check requires a non-empty set of initial states and reports satisfied only
when every initial state satisfies the formula. An empty state set raises
NO_INITIAL_STATE, rather than passing by vacuous truth.

Syntax errors raise CTL_SYNTAX_ERROR with position, token and line/column.
Specification validation maps malformed CTL text to INVALID_CTL_FORMULA.
These errors are input/model errors, not a false property result.

## Evidence and limitations

Evidence paths use breadth-first search with state-ID-sorted successors, so
selection is deterministic:

- EF φ success: initial-to-φ witness.
- AG φ failure: initial-to-!φ counterexample prefix.
- EX φ success: initial state and satisfying successor.
- AX φ failure: initial state and violating successor.

For other top-level operators, the result retains the computed satisfying
state set and initial-state observation. If no path-shaped witness or
counterexample is supported, the persisted observation includes the canonical
model hash, satisfying state IDs, initial state IDs and violating initial IDs;
the independent reference evaluator can recompute it. No path is fabricated.
Syntax/atom errors are input errors, not verification failures.
