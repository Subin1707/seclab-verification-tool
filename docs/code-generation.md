# Generic C generation

`CODEGEN` consumes the normalized Specification and the canonical Kripke model
from the same run context. The generator emits a reusable C99 static library,
header, data-equivalent Python model runtime, CLI/test harness, CMake project,
build-and-use README, manifest,
generation metadata and generated-line source map. The runtime supports state
and transition lookup, label queries, outgoing-edge enumeration, initial-state
inspection, graph integrity checks and guarded state stepping. Source-map
entries and generation metadata link the canonical specification/model hashes,
requirement IDs, declared function IDs, generated paths and generator version.
Generated implementation files are tagged `GENERATED_ARTIFACT`; build files,
metadata and test harnesses have their own artifact classes.

The independent `BUILD` stage uses configured compiler adapters to compile the
generated C model/harness and execute both the generated C executable and
Python model runtime. Compiler output,
exit status, runtime output, build result, generated file hashes, source map and
manifest are stored as evidence. A generated CMake project also lets users
build the library and run its contract harness outside the verification
pipeline. Build/runtime statuses stay scoped to the generated model artifact
and do not establish a production implementation's safety.

The normalized `FunctionSpec` still does not declare C/Python parameter types,
function behavior or output semantics. The generator therefore does not emit
application function bodies. Declared function languages and unsupported
generation statuses remain visible in the Functions table. Transition actions are preserved as metadata;
unresolved guards must be approved by a caller-supplied runtime callback.

For the migrated legacy teacher file, this stage built and executed the model
harness with both GCC and Clang. The generated graph had 28 states and 47
transitions. The teacher JSON declares nine function names/probes but contains
no function bodies, source bindings, signatures or executable contracts. The
generator therefore does not fabricate these functions or their vulnerabilities;
those declarations remain explicitly classified as unbound capability/probe
metadata. Similarly, nine narrative cases do not become dynamic tests because
they do not supply executable input/oracle pairs.
