# Preview compiler interventions

`rbit discover` helps answer a narrow question: can a small, declaration-only
change make MSVC 4.2 reproduce a reference function, or provide a safe donor
for it? It compiles a finite set of declared states, indexes every emitted
function, and reports three kinds of review candidates:

- a whole matching function produced by one state;
- a private same-project donor with the required object structure; or
- a bounded same-symbol instruction mosaic assembled from a seed and at most
  two qualified donors.

Discovery is a preview tool. It never edits source, applies an intervention, or
turns a finding into certified project authority. The generated intervention
data must still go through the normal adapter review and proof workflow.

## Run a campaign

Start with the guided [declaration-discovery example](../examples/declaration-discovery/README.md).
Its request, source, reference objects, and optional seed objects are resolved
relative to the request file. The committed
[request schema](../schemas/msvc-discovery-request-v1.schema.json)
describes the structural fields and local bounds. The CLI additionally requires
canonical, case-insensitively sorted symbols, references, seeds, and placements;
checks relationships between ranges and `max_cells`; and keeps inputs, the report,
and private state from aliasing one another. Those cross-field rules are stated in
the schema description but cannot all be expressed by portable JSON Schema keywords.

```console
rbit discover discovery-request.json \
  --toolchain-root /opt/toolchains/MSVC420 \
  --jobs 4
```

The request fixes the symbols, compiler arguments, search ranges, and maximum
cell count before any compiler starts. Source is staged under the fixed name
`unit.cpp`; consequently, `__FILE__` observes that name. Local relative headers
are not copied into the cell, so source must be self-contained apart from headers
provided by the locked toolchain. `/Gy` is normally needed so candidate functions
live in isolated COMDAT sections.

Compiler arguments use a finite, path-free allowlist: the documented MSVC 4.x
CPU, calling-convention, runtime, optimization, warning, exception/RTTI, string
pooling, language-conformance, and debug-format switches. The CLI rejects source
inputs, response files, macros, include paths, output/listing/PCH paths, and every
unrecognized switch. ReproBit supplies `/c`, `/Fo`, `/Fd`, `/FI` when needed, and
the fixed `unit.cpp` input itself.

The four supported search families are declaration shapes, padding shapes,
forward-declaration runs, and paired extern runs. They generate declarations
only; arbitrary source rewriting is intentionally outside this command. Mosaic
analysis also has a fixed `max_search_steps` budget and fails closed if the
requested candidates cannot be considered within it.

Every emitted function remains indexed so collateral compiler effects are
reviewable. To keep that promise bounded, one object may contain at most 4,096
functions and the request's `max_observed_functions` caps the campaign total at
100,000; crossing either limit stops the campaign instead of silently dropping
functions.

The default worker count is four. An explicit `--jobs` runs independent cells in
parallel; Wine is capped at four workers. On POSIX hosts ReproBit clears the
campaign's exclusively locked private Wine prefix before compiling, then stops
and reaps its wineserver on success or failure. Use `--wineserver` when it is not
on `PATH`, and `--cleanup-timeout` to change the bounded shutdown limit. Terminal
output shows elapsed progress, while `rbit --format ndjson discover ...` emits
stable cache-hit and cache-miss events for CI and other tools.

## Resume and review

By default, reusable state lives in `.reprobit-discovery` beside the request.
Each completed compiler cell is immutable and keyed by its exact compiler,
generated declarations, and compiler-visible working directory. Repeating an
unchanged request restores those cells. Extending one range compiles only the
new states; changing a reference or seed reruns analysis without recompiling
unchanged cells.

The report defaults to `REQUEST_STEM.report.json`. It includes:

- readable input and compiler receipts plus compile and analysis authority
  digests;
- observations for every emitted function;
- schema-validated intervention proposals;
- the exact state and generated declarations behind each selected cell; and
- content-addressed paths for only the objects referenced by proposals.

Candidate objects remain resolvable under the discovery state directory after a
successful run. Failed workspaces remain available for diagnosis. The report
and artifacts are non-certifying and are safe to discard when review is done.
The committed [report schema](../schemas/discovery-report-v1.schema.json) can be
used by review tools without importing ReproBit.

Discovery state directories are private working state. Every state level must be
a real directory rather than a symbolic link or reparse point; workspace cleanup
removes only the fixed, flat set of compiler files and never follows a redirected
directory tree.
