# Find compiler interventions

ReproBit discovery is for a project's initial mismatch: the source builds, but
has not yet reproduced the reference bytes. It tries small, declaration-only
changes without changing the program's intended behavior. The normal workflow
is `grind`: let it make a bounded project pass, or select one source and
function when you need precise control. ReproBit saves a result only when you
explicitly approve a run whose candidate passes a fresh proof build. After the
project has reached an exact match, use `rbit repair .` for regressions caused
by later benign source edits instead of starting discovery again. This guide is
the source of truth for discovery workflow and approval behavior; the generated
[option tables](cli-reference.md#rbit-discover-grind) list exact flags and
defaults.

## Automatic grind

Start from a configured ReproBit project whose normal build already runs.
Project-wide grind compares functions from project-owned reference `.obj`
files; it cannot derive those objects from the reference executable alone.
Obtain them from your project's archival or analysis inputs, place them under
`reference/`, then run a read-only project preview:

```console
rbit discover grind .
```

Before compiling, grind reports how many eligible compiler steps have a paired
reference object, how many are missing one, and how many functions fit in this
bounded pass. A missing object skips that compiler step; it does not invalidate
the rest of the preview. Full mapping and skip reasons remain in the report and
NDJSON result.

ReproBit first matches an object to the source filename without its extension:
`src/widget.cpp` maps to `reference/widget.obj`. An exact translation-unit ID
also works. When names collide, provide the pair directly with
`--reference-object TU=PATH`; repeat the option for more translation units. A
single eligible source file and single reference object are paired
automatically.

The bounded search tries at most eight functions by default and samples one
from each source file before returning to the first. `--max-symbols` can raise
that limit to 64. Automatic directory scanning inspects at most 4,096 entries
and accepts at most 64 reference `.obj` files. Each object may index at most
4,096 functions. Exceeding a bound stops with a clear error instead of silently
dropping input.

The summary is written to
`.reprobit-state/reports/grind/project/report.html`. It links every attempted
function to a detailed decision report and keeps the exact bounded plan used for
that decision beside the report. Grind is a low-hanging-fruit pass, not a
promise to solve every compiler mismatch.

The report can offer either of two safe next steps:

- If one adjustment makes every target match, save only that exact result with
  `--accept-exact`.
- If several independent mismatches remain, save the locally proven functions
  with `--accept-progress`. That pass may itself reach an exact project; if it
  does not, run the ordinary preview again.

"Locally proven" has a narrow meaning: the freshly compiled function matches
its project-owned reference object, its logic checks pass in a build from
scratch, and it introduces no new authenticity exception. ReproBit saves these
adjustments one at a time, checks the current project before every atomic
update, and tests later functions against the newly saved state. It does **not**
claim that the executable is closer overall or that the project is certified.
Only a final fresh, byte-exact build can make that claim.
Within each function, progress mode tries candidates cheapest-first and moves on
as soon as one passes the local proof from scratch. Preview and exact-only approval keep
searching the bounded set for a complete project match.

Use the copyable command shown in the report. A typical multi-mismatch loop is:

```console
rbit discover grind . --accept-progress
# If the printed next step says the project still differs:
rbit discover grind .

# When the report offers the exact path instead:
rbit discover grind . --accept-exact
git diff -- reprobit/interventions reprobit/proofs
rbit verify .
```

Both save commands rerun the proof; they never trust an earlier preview. A
preview exits `0` when it finds an exact or locally proven adjustment and `1`
when it finds none. A save command exits `0` only when it actually publishes the
requested kind of result. Invalid input or a runtime failure exits `2`.

For one deliberately selected function, create the small expert plan once:

```console
rbit discover init . \
  --source src/widget.cpp \
  --symbol '?Transform@Widget@@QAEHH@Z' \
  --reference reference/widget.obj
```

ReproBit finds the matching saved compiler step and writes the compact
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

Run that plan explicitly. An ordinary `grind` remains project-wide:

```console
rbit discover grind . --expert-plan reprobit/discovery.json
```

Each candidate is compiled through the project's locked compiler graph. A
candidate can be saved as local progress only after a separate build from
scratch proves the function and required logic checks. It is exact only when
that same build also reproduces every target byte for byte.
Every completed bounded search writes a human summary to
`.reprobit-state/reports/grind/report.html`, including searches with no safe
solution. A chosen result links to its separate fresh-build evidence in the same
directory. The preview does not change project files.

When the result looks right, copy the exact or progress approval command from
the report. For example:

```console
rbit discover grind . \
  --expert-plan reprobit/discovery.json \
  --accept-progress
git diff -- reprobit/interventions reprobit/proofs
```

Advance approval is not proof and does not reuse an old preview verdict. ReproBit
recompiles and verifies the solution from scratch, then changes only the owning
intervention and proof shards in one compare-and-swap transaction. A concurrent
source, plan, reference binary, toolchain, graph, or project-record edit aborts
the save. If no result meets the selected approval mode, no project files
change. Writing review reports is separate from saving the accepted intervention
and proof records. If the local report cannot be written after those records
were saved, the CLI emits a nonfatal warning while still reporting the project
changes accurately.

Try the complete small project in the
[grind example](../examples/grind/README.md). It intentionally starts one byte
away, finds two low-cost records, and verifies the result again from scratch.

## Advanced: raw request campaigns

`rbit discover run` is the lower-level inspection tool. It compiles a finite set
of declared states, indexes every emitted function, and reports whole-function,
private-donor, and bounded same-symbol mosaic proposals. These proposals are
review evidence only: this advanced command never edits source or project
records. Use it when you need to study candidates beyond the automatic grind's
small supported recipe.

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

Without `--jobs` the worker count is the number of CPUs the process may use,
capped at 8. An explicit `--jobs` runs independent cells in parallel; Wine is
capped at four workers either way. On POSIX hosts ReproBit clears the
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

- readable input and compiler receipts plus compile and analysis hashes;
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

Raw campaigns deliberately keep this state separate from a project's
`.reprobit-state`. Preview its size before removal, then use the guarded cleanup
command:

```console
rbit discover clean discovery-request.json --preview
rbit discover clean discovery-request.json
```

The command keeps the JSON and HTML reports. It removes only a state tree marked
by ReproBit for that request, refuses active campaigns, and
never follows symbolic links, junctions, or other redirected entries. If the
campaign used `--state-directory DIR`, pass the same option to `discover clean`.
The request file may be removed after a campaign; the guarded ownership marker
is enough for cleanup when the same request path is supplied.
When several request files deliberately reuse one state directory, cleanup
refuses to remove their shared cache unless you add `--all-requests`; use
`--preview --all-requests` first to review the combined size.
The tiny external lock marker may remain beside the request; reusable campaign
objects and compiler workspaces do not.
