# Specification to Kripke model

The `MODEL` stage consumes only the normalized canonical `Specification` held
by the pipeline context. It does not reopen the JSON file or synthesize a graph
for display. `generate_kripke_structure()` maps each declared state, label and
transition into the validated Kripke structure. Initial state, state IDs,
atomic propositions, requirement links and property links remain traceable.

The stage stores `kripke.json`, `model-summary.json`, `model-validation.json`
and `model-graph.dot` in ArtifactStore. The records include specification ID,
canonical specification/model hashes, source path and source hash references,
reachability and deadlock analysis, construction metadata, and the state/edge
IDs. GUI Model page renders that graph with state nodes, labeled directed
transitions, initial-state marker, zoom, pan and fit-to-view.

On the real legacy teacher input, the declared model contains 28 states, 47
transitions, one initial state, 17 reachable states, 11 unreachable states and
no deadlocks. Eleven source-declared state IDs/labels use violation-witness
wording; the adapter does not create them, and they are not reachable counterexamples.
These are counts of the declared graph and do not establish behavior of the
external C implementation. The model links to the full migrated canonical
Specification; unsupported narrative declarations remain metadata.

The independent `SOURCE` stage scans real project files and records source
hashes. Optional source-derived model construction is a separate feature and
must not be conflated with the specification-derived Kripke graph.
