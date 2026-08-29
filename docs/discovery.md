# Find compiler interventions

ReproBit discovery tries small, declaration-only changes that can steer an old
compiler toward the reference bytes without changing your program's intended
behavior. The normal human workflow is `grind`: give it one source file, symbol,
and reference object, then let it try a small low-cost search.

## Automatic grind

Start from a configured ReproBit project whose normal build already runs. Create
the small search plan once:

```console
rbit discover init . \
  --source src/widget.cpp \
  --symbol '?Transform@Widget@@QAEHH@Z' \
  --reference reference/widget.obj
```

ReproBit finds the matching committed compiler lane and writes the compact
`reprobit/discovery.json` plan. It does not compile anything or change
project files. The default plan tries four declaration states and is
easy to widen deliberately:

```json
{
  "schema_version": 1,
  "reference_object": "reference/widget.obj",
  "target": "widget",
  "translation_unit": "tu.widget",
  "symbol": "?Transform@Widget@@QAEHH@Z",
  "classes": {"start": 1, "stop": 4},
  "functions": {"start": 10, "stop": 10}
}
```

Run a read-only preview first:

```console
rbit discover grind .
```

Each candidate is compiled through the project's locked compiler graph. A
candidate only counts as a solution after a separate cold build reproduces every
target byte for byte and passes the required logic checks. Every completed
bounded search writes a human summary to
`.reprobit-state/reports/grind/report.html`, including searches with no exact
solution. An exact result links to its separate `cold-verification.html` and
`cold-verification.json` evidence in the same directory. The preview does not
change project files.

When the result looks right, authorize a fresh proof run and atomic publication:

```console
rbit discover grind . --accept-exact
git diff -- reprobit/interventions reprobit/proofs
rbit verify .
```

Advance approval is not proof and does not reuse an old preview verdict. ReproBit
recompiles and cold-verifies the solution, then changes only the owning
intervention and proof shards in one compare-and-swap transaction. A concurrent
source, plan, reference, oracle, toolchain, graph, or project-record edit aborts
the save. If no exact solution passes, no project files change. Writing review
reports is separate from saving the accepted intervention and proof records. If
the local report cannot be written after those records were saved, the CLI emits
a nonfatal warning while still reporting the project changes accurately.

Try the complete small project in the
[grind example](../examples/grind/README.md). It intentionally starts one byte
away, finds two low-cost records, and verifies the result again from scratch.

## Advanced: raw request campaigns

`rbit discover run` is the lower-level inspection tool. It compiles a finite set
of declared states, indexes every emitted function, and reports whole-function,
private-donor, and bounded same-symbol mosaic proposals. These proposals are
review evidence only: this advanced command never edits source or project
authority. Use it when you need to study candidates beyond the automatic grind's
small admitted recipe.

### Run a campaign

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
rbit discover run discovery-request.json --jobs 4
```

This uses the compiler location remembered by `rbit setup` or
`rbit toolchain provision`. Pass `--toolchain-root` only to override it for one
run.

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

### Resume and review

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
