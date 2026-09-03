# Command-line reference

`rbit` keeps project intent, local machine configuration, building, and
verification separate. Commands write plain text by default, and long work uses
one live progress line in an interactive terminal. Pass `--format ndjson`
(before or after the subcommand) when CI or another program needs stable
machine-readable events; see [Machine-readable output](#machine-readable-output).
Pass `--quiet` (before or after the subcommand) to silence text-mode progress:
phase starts, heartbeats, completion lines, unit counts, and the interactive
progress display. Results, warnings, errors, and the context line written when
a phase fails still print. `--quiet` does not change ndjson output, because
machine readers rely on receiving every event. Output is plain by design: no
colour, no shell completion, and no terminal control beyond the transient
progress line, so a log reads the same everywhere it is captured.

This page has one section per command, in the order `rbit --help` lists them.
The option tables are generated from the parser into
[cli-reference.md](cli-reference.md); [Getting started](getting-started.md) is
the narrative walk from a bare CMake project to a verified build.

For an existing project, the everyday path is short:

```console
rbit status .
rbit build .
rbit verify . --report-dir build/reprobit-report
```

`status` names the next missing setup item. `build` is the fast incremental
developer loop; `verify` always starts fresh and writes the trust report. After
editing a file that already belongs to the project—including a shared header
used by many source files—use `rbit repair .`. Run `setup` once on each machine
to prepare and remember its local compiler.

Every command that takes a project accepts it as a positional argument
(`rbit status .`); `--project PATH` is still accepted as an alias.

<details>
<summary>Advanced: progress events</summary>

Redirected logs and CI receive phase starts, heartbeats, completed units, and a
final event, so a compiler or verifier never goes silently idle. Producer work
and overall workflow progress use separate event types. Discovery compiler
totals include declaration experiments only for the source files selected by
the committed overlay graph. In text mode, `--quiet` drops this whole channel
(a heartbeat exists to prove liveness, which is exactly what `--quiet` opts out
of) and keeps only the failure context line; in ndjson mode the events are
always streamed.

</details>

## rbit init

Start a ReproBit project. Name the real CMake target when initializing and
repeat `--target` for projects that produce more than one binary:

```console
rbit init . --target program
```

`init` creates the project entry point, adds root ignore entries for ReproBit's
local state, and creates an empty, explicitly incomplete source record, so a
new project cannot appear build-ready before its real files are reviewed. The
default rebuilt-output and reference filenames follow each target name. For
target-specific custom paths, repeat `--artifact TARGET=PATH` or
`--oracle TARGET=PATH`; for a single target the `TARGET=` prefix is optional:

```console
rbit init . --target program --artifact build/app.exe --oracle reference/program.exe
```

The `--logical-source`, `--logical-build`, and `--logical-toolchain` DOS
paths are the compiler-visible roots recorded in `reprobit.toml` (defaults
`R:\source`, `R:\build`, `R:\toolchain`); see [platforms](platforms.md)
before changing them.

## rbit setup

Prepare the compiler and this machine for a project:

```console
rbit setup .
# Or use an existing installation:
rbit setup . --toolchain-root /opt/toolchains/msvc42
```

`setup` selects or downloads the compiler, authenticates it, remembers the local
path, creates the project lock when absent, verifies an existing lock, and probes
the host backend. That is the normal workflow on macOS, Linux, and Windows. It
ends with the same checklist `status` prints, so a finished machine setup and a
still-incomplete project are reported together. Machine setup and project setup
are separate: `rbit setup` can finish installing and checking the compiler while
`rbit status` still lists missing project files. Exit status 1 means a backend
check failed.

## rbit doctor

`doctor` is the read-only diagnostic underneath setup. It checks the selected
host backend and, when a project and toolchain root are supplied, verifies the
installation against the committed lock:

```console
rbit doctor .
rbit doctor . --toolchain-root /opt/toolchains/msvc42
```

Add `--execute-probe` to execute the bounded Wine probe on POSIX. On native
Windows the opt-in probe creates a fresh, verified logon session and defines a
temporary drive only in that session. The real producer starts suspended inside
a nested Job Object, and the probe requires its descendant to observe the same
drive. The mapping is removed only after that complete producer tree exits.
Without a project, `--toolchain-root` also needs `--toolchain-profile`.

## rbit toolchain provision

Download and authenticate a supported compiler outside any project:

```console
rbit toolchain provision msvc_4_2
```

Automatic acquisition is currently available only for Microsoft Visual C++ 4.2.
The installation goes to this platform's standard user location unless
`--destination` says otherwise, and its path is remembered unless `--no-save`
is given. `rbit setup` runs the same provisioning automatically when a project
needs it, so this command is mainly for machines prepared before any project
exists (the advanced declaration-discovery example uses it).

## rbit toolchain lock

Record the exact compiler files this project expects. `setup` creates the lock
automatically; the lower-level command remains available for CI images and
unusual manual installations that need explicit runtime files:

```console
rbit toolchain lock . --root /opt/toolchains/msvc42 \
  --runtime-file wine/x86/cl \
  --runtime-file wine/x86/rc \
  --runtime-file wine/x86/link \
  --runtime-file wine/x86/lib \
  --runtime-file wine/x86/wine-msvc.sh
```

The lock command hashes required compiler producers and portable include and
library tree receipts. It also writes `profile_sources`, the selected profile's
reviewed immutable repository inputs for each profile-owned installed path.
Those inputs neither prove how local bytes were acquired nor replace the exact
file and tree receipts. The authenticated provisioner and CI workflow establish
acquisition; the lock receipts establish the installed content. Platform wrappers
or support files that participate in execution must be named explicitly with
repeatable `--runtime-file` arguments and remain outside `profile_sources`.
The five paths above are the complete portable runtime set for MSVC 4.2 on
POSIX. `wine/x86/msvcenv.sh` is used only while CMake configures the one-time
import tree; direct ReproBit builds do not execute it, so the provisioner
authenticates it but the portable runtime lock does not include it.
Committed lock paths are relative to the supplied toolchain root; the physical
root itself remains local configuration. `rbit validate` rejects a registered
profile whose locked profile paths are missing, disagree with these reviewed
repository inputs, or assign an extra profile source to a wrapper path.

## rbit source preview

Show source changes and records that need review without writing:

```console
rbit source preview .
```

`source preview` hashes the proposed Git-tracked read set without writing.
Repeat `--path` to provide an explicit complete file or tree set instead. It is
not a filter over the current record: every omitted path is reported as a
removal.

To add a new file to the reviewed source list—or remove a locked one—preview
the new list first. `repair` keeps using the exact locked list and never
silently admits another Git-tracked file. When existing build records still
apply, preview prints the exact `source lock` command to run. If preview says it
cannot safely update which files CMake builds, there is no automatic command for
that case yet; restore the previous file list instead of deleting saved
interventions.

## rbit source export

Write the reviewed effective source view used by compilers and analysis tools:

```console
rbit source export build/reprobit-debug/source
```

Source-aware tools must read the same reviewed source view as the compiler. This
matters when an intervention adds declarations or otherwise moves source lines.
The export contains only project inputs admitted by the source lock, with the
reviewed source adjustments applied. It does not contain reference binaries,
compiler files, build outputs, or private run state. Running the command again
safely replaces the prior export, including files that are no longer part of
the reviewed source view. Point the tool's source root at the exported
directory.

## rbit source lock

Safely record tracked or explicitly named source inputs:

```console
rbit source lock .
```

`source lock` publishes the set shown by `source preview` after review. A
successful lock prints the next required step—usually placing the original
binary, running `rbit import cmake .`, or checking `rbit status .`. Re-run
`rbit import cmake .` only when a successful source lock asks for it.

<details>
<summary>Advanced: source-lock safety and generated project records</summary>

`source lock` publishes the manifest and, when one exists, its build-plan
binding in one content-addressed transaction. Every admitted source file is a
transaction precondition, so an edit racing the lock aborts rather than
committing a stale receipt. Pass `--invalidate-producer-graph` when preview says
the generated graph is stale; rerun `rbit import cmake .` afterward. A graph-v3
command DAG remains valid when bytes change at an already admitted path, but a
direct graph input cannot be removed without invalidating the graph. Unrelated
manifest additions and removals leave the command DAG valid. The command does
not rewrite translation-unit, intervention, or proof checks. If those checks
became stale after a routine edit, use `rbit repair .`. The advanced
[`source regenerate`](#rbit-source-regenerate) command lets you inspect only the
mechanical changes when diagnosing a repair.

</details>

## rbit source regenerate

Advanced maintenance tool. After editing an existing project file, normally run
`rbit repair .` instead. `source regenerate` is the preview used inside the
maintenance flow; it is useful when you want to inspect mechanical record
updates without building or verifying:

```console
rbit source regenerate .          # preview only
rbit source regenerate . --apply  # apply only these mechanical changes
```

It re-renders stale records against the current bytes and can propose changes
for four record families. Staleness is decided by rendering, not by the clean
digest alone: an output whose clean bytes are unchanged but whose reviewed
operations were edited (a retuned declaration-run count, a dropped declaration)
is re-rendered and its effective digest re-derived, and every private donor
rendering is rendered again so a change in the owning unit's canonical
operations reaches the donor's pins too.

* **Source-adjustment outputs** — the clean source and newly rendered output.
* **Private donor renderings** — source prepared for one owning translation
  unit, including its reviewed adjustments.
* **Declaration donors** — their rendered source and the checked insertion
  points around a declaration.
* **Translation-unit source checks** — in both per-unit records and the build
  plan.

The human preview says what would change, prints a concise count and
per-document summary, and writes nothing. With `--format ndjson`, the
event's `changes` field contains each field-level before/after value for
tooling. `--apply` reports what it saved and writes all changed documents in
one guarded transaction that also checks the exact source bytes read by the
plan, so a concurrent edit aborts instead of committing mixed state. It then
points back to `rbit repair .` for the build and exact check.

The command fails closed when it cannot re-derive a check. It only proposes or
applies mechanical record changes: it does not lock, build, verify, or certify
the project. It remains a separate command because this read-only preview is
useful for diagnosis; `repair` already runs the same planner automatically,
then handles compiler-dependent fallout and exact verification. Prefer
`rbit repair .` unless you specifically need the intermediate view.

## rbit import cmake

Prepare and record an ordinary CMake project in one guided run. CMake is a
one-time import input, not a build or certification runtime. For a normal
project, the entire import is one command:

```console
rbit import cmake .
```

`import cmake` derives the initial build plan, records the reference binary,
and creates empty per-source review shards. It then materializes the reviewed
source tree, performs one bounded configure—never a project build—and
atomically commits the closed graph and its initial TU review shards. It uses
**Unix Makefiles** on POSIX or the authenticated **NMake Makefiles** frontend on
native Windows, plus `compile_commands.json` and the reviewed
`reprobit-target-plan.json`. It does not edit `CMakeLists.txt`.

The guided import derives only facts it can check: target mappings, empty
initial intervention/proof records, the protected reference digest, and the
compiler/linker commands CMake exposes. It does not guess entropy
interventions. `rbit status .` keeps every missing item visible afterwards.

The simplest setup passes the real CMake target name to `rbit init --target`, so
the default rebuilt-output and reference filenames follow it. Use
`--target program=your_cmake_target` during import only when the ReproBit ID
intentionally differs and its declared artifact still matches the real output:

```console
rbit init . --target program --artifact build/app.exe --oracle reference/program.exe
# After setup, source review, and placing the reference binary:
rbit import cmake . --target program=app
```

If the import fails, the generated scaffold is removed and the diagnostic
workspace is retained for inspection.

## rbit graph configure

Create a fresh CMake metadata tree without building. Together with
`graph extract` this is the two-step form of `import cmake` for CI or unusual
projects:

```console
rbit graph configure . \
  --workspace-root .reprobit-state/import \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc
```

`graph configure` reports the exact configured/effective roots, target plan,
compile database, effective-source digest, configure log, command digest, and
duration. It refuses a non-empty workspace and detects any source mutation
during CMake configuration.

## rbit graph extract

Record direct compiler and linker steps from the CMake tree that
`graph configure` produced:

```console
rbit graph extract . \
  --configured-build-root .reprobit-state/import/build \
  --effective-source-root .reprobit-state/import/source \
  --effective-source-digest SHA256_FROM_CONFIGURE \
  --toolchain-root /opt/toolchains/msvc42 \
  --directive-input program=oldnames.lib
rbit validate .
rbit explain .
rbit cost .
```

Replace `SHA256_FROM_CONFIGURE` with the digest reported by `graph configure`.
`graph extract` reads expanded compile commands, resource rules, response files,
and link commands; converts physical paths into `${SOURCE}`, `${BUILD}`, and
`${TOOLCHAIN}` seats; rejects unbound producers and paths; and transactionally
publishes `reprobit/producer-graph.json`. Schema v3 binds the declared
direct source inputs, toolchain lock, logical-path profile, exact target set, and
terminal artifact paths; the source manifest and build plan separately bind
current source contents. Certification reloads those documents and never
executes CMake. Re-extract only when a graph input or other command/build
authority changes.
Repeat `--directive-input TARGET=LIBRARY` for reviewed linker-only library
edges discovered in COFF `.drectve` sections. The value must be a known target
and one bare library name; paths, duplicate declarations, and implicit runtime
authorization are rejected. When an edge is missing, the direct runtime emits
copy/paste-ready flags for a new explicit extraction.

## rbit validate

Check every saved project file:

```console
rbit validate .
```

`validate` loads every saved JSON file, rejects duplicate keys and IDs,
checks cross-document references and dependency cycles, compares current files
with their recorded hashes, renders declarative overlays in memory, and checks
effective TU digests. It never runs a build. It is the command that checks
source bytes against saved project records; `explain` and `cost` inspect the
committed metadata only.

## rbit cost

Show intervention cost totals:

```console
rbit cost .
```

The score measures distance from an ordinary build; see the
[cost model](costs.md) for the fixed categories and accounting rules. The text
output names the cost model version and points to `rbit explain` for the
per-intervention view.

## rbit status

Show what is ready and the next project setup step:

```console
rbit status .
```

`status` checks that each saved project file exists and that every JSON record
parses; it does not validate schemas or cross-file agreement until every file is
present (then it runs the same check as `validate`). It also checks that this
machine can find the remembered compiler. Rows marked `[  ]` are missing;
`[!!]` marks a file that exists but cannot be read and points to `validate`.
The exit status is 1 until every check passes.

## rbit clean

Remove inactive workspaces; cache and reports are opt-in. Successful workspaces
are removed automatically; failed ones are kept so you can diagnose them. Check
the space ReproBit manages with [`state status`](#rbit-state-status), then
preview cleanup before removing anything:

```console
rbit state status .
rbit clean . --preview
rbit clean .
```

`clean` removes inactive workspaces but keeps the reusable incremental cache and
saved reports. The following preview includes ordinary inactive-workspace
cleanup and the cache data left by older ReproBit code, and keeps the current
cache:

```console
rbit clean . --obsolete-cache --preview
```

The full-cache and saved-report selections are separate alternatives:

```console
rbit clean . --cache --preview
rbit clean . --reports --preview
```

Use `--cache` only when you intend to clear the complete incremental cache and
the donor probe replay store of `repair`. Use
`--older-than-hours 24` to keep recent workspaces and selected cache records.
Active runs are never removed. The `--keep-workspace` option of `build`, `verify`,
`repair`, and `import cmake` changes which run workspaces are retained in the
first place (`on-failure` by default).

## rbit explain

Explain saved interventions:

```console
rbit explain .
rbit explain . --intervention intervention-id
```

`explain` lists interventions and their fixed costs; pass `--intervention ID`
to select one and print it in full. Like `cost`, it reads the committed metadata
only, so it remains useful while source bytes are being edited. An unknown ID is
an error that lists the known IDs.

## rbit repair

Use this after editing a source file that is already part of the project,
including a shared header used by many source files. Reviewed records are tied
to the source they describe, so the normal workflow after such an edit is one
command:

```console
rbit repair .
```

Repair works in a private workspace. It updates the saved build guidance
affected by your edit, records the current source, rebuilds every target from
scratch, and checks that the result is still exact and trustworthy. If all
checks pass, it publishes the changed project records, verified target
binaries, any matching debug companions, and the JSON/HTML report together.
The default report is `.reprobit-state/reports/report.html`; choose another
project-relative location when useful:

```console
rbit repair . --report-dir build/reprobit-report
```

No partial repair is published. If any update, build, or verification step
fails, your source files remain edited, but saved project records, existing
binaries, debug companions, and reports remain unchanged. The error points to
the retained private workspace or candidate report when one is available. Once
you are finished diagnosing it, reclaim that space with `rbit clean .`.

For example, suppose a project already matches and you add a harmless forward
declaration to a shared header. That one edit may affect several source files;
the workflow is still just `rbit repair .`. ReproBit follows the shared header
to every affected build step, adjusts the saved guidance it can safely
re-derive, and checks every final binary. You do not repair each source file
separately.

Other realistic maintenance edits use the same command: changing harmless
whitespace or comments in a header, adding or moving a declaration,
making an assertion conditional for one build mode, or changing an inline
header body used by several source files. ReproBit tries only a small,
predictable set of safe adjustments and still requires the final binaries to
match exactly. If an edit is not benign, repair stops without publishing a
partial result.

Each analysis pass records every refused adjustment in an affected source file,
not only the first, so one pass exposes the whole fallout of a shared-header
edit. Before any compiler runs, a refused function whose required body another
donor of the same source file already emits -- or whose own donor still emits it,
only under a cheaper record family -- is re-authored onto that donor from the
fresh objects the pass compiled; its old record is retired and beneficiaries
follow it. The nearby-donor search then retunes the declaration-only compiler-state
carriers those adjustments depend on: declaration shapes, pad shapes, forward
declaration runs, extern run pairs, forward runs with a shape, declaration run
triples, and the declaration-run, padding-line and class-member counts inside
donor source overlays (every one-knob move first, then two knobs of one rendering
together, each rendered sequence's line canvas following its items). By default it
tries settings up to a distance of 8 per donor and at most 256 settings per
command. A header used by dozens of source files can need more; the search
bounds can be raised explicitly, and every candidate still has to pass the
ordinary composer and the final cold proof:

```console
rbit repair . --retune-radius 32 --retune-candidates 2048 \
  --donor-candidates 20000 --adjustment-rounds 200
```

A donor source overlay is retuned through the declaration-run, padding and
class-member counts of its rendered sequences; whether or not it has such a
knob, repair also tries inserting a fresh forward-declaration run of
`distance` names at the file end or start of its owning source, rendered
together with the overlay's own operations, so an overlay that only rewrites
source or swaps includes still has a nearby compiler state to move to.

`--retune-radius` is the farthest declaration-count distance tried per donor
(at most 64), `--retune-candidates` caps the settings tried per donor, and
`--donor-candidates` caps the settings compiled by the whole command;
`--adjustment-rounds` raises the number of saved-guidance adjustment rounds
before repair gives up. Wider bounds only cost compile time; they never widen
what a repair may change.

When no saved donor of an affected source file can be retuned any further,
repair compiles fresh carrier states for that file (`--discovery-candidates`
per file, default 64) cheapest first — every declaration shape, then forward
declaration runs of growing length at each placement — and inspects every
compiled object against every refused record of the file: an object carrying a
record's required body re-authors the record onto that new donor under the
cheapest closed family; an object carrying a rewriting record's pinned donor body
moves the saved record onto the new donor unchanged. Discovered donors are
ordinary declaration-only carrier records and pass the same fresh compile and
cold proof as every other adjustment.

Records whose receipts pin a decision rather than a measurement — a web
recolouring, an instruction mosaic, a cross-file complete-target resize —
are repaired like the measured families when only their compiler
observations moved: the seed and witness census, seats, line tables,
metadata digests and seed body are restated from the fresh objects, every
decision, program field and donor body a range is drawn from stays as saved,
and the family producer must compose the retail body again before the
refreshed receipt is accepted. Whatever the family, a receipt that recorded a
retail match is accepted by repair only when the composed body is that retail
body.

Before any donor is retuned, a refused function whose required body another
donor of its file already emits is moved onto that donor: under the cheapest
closed equal-body family the composer proves, or, when no such family can host
the body (the file's own compile of the function changed length, say), as the
saved record itself with its dependency changed and its measurements
refreshed. Fresh carrier states found by discovery are adopted the same way.

Compiler-numbered names are followed, never pinned: `$L`/`$T` labels, `$done$`
serials and the `$S` serial of a file-static are counters that restart with
every declaration change, so a saved declaration that names one is matched by
kind and base name, and its relocation seats and debug-stream references are
restated from the fresh compile. Families that install a body under the
same-slot rules (relocation-divergent, same-slot resize, donor rewriting)
prove that the seed's and the donor's `.debug$S` streams describe the same
function; repair re-derives that record-by-record description (procedure
extent, label serials, one local's type index or location) from the fresh
pair and carries it in the receipt, where the strict validator re-proves it.
A delta the recipe itself declares describes one particular donor pair, so it
is dropped when the record moves to another donor and re-derived there.

Repair never compiles the same candidate twice. Every probe compile is a pure
function of its compiler seat (the rendered private inputs) and its compile
epoch (the producer graph with its toolchain lock, the compiler environment,
the sealed include authority and the sealed source tree), so its object is
kept in the project state under `repair-probes/` and replayed by later rounds
and later commands whenever the epoch still matches; a source or record edit
that changes what the compiler reads changes the epoch and misses. The store
is diagnostic only: the repair's final cold proof, like `verify`, recompiles
everything. `rbit clean . --cache` removes it. Candidates are compiled with
`--jobs` workers continuously, each result is judged as soon as it lands, and
once one donor is restored by some move (say `functions +1` of a declaration
shape) the same move is tried next on every other donor of that family, since
one source edit disturbs every affected file in the same way.

For added or removed files, start with [`source preview`](#rbit-source-preview);
it prints a safe next command when one is available. For a new project that
builds but does not match yet, use [`discover grind`](#rbit-discover-grind)
instead of repair.

### Unrecorded fallout and the composed-body ledger

A source edit can also move functions that carry no saved record at all. Every
accepted `rbit verify` writes a ledger of the bodies the linker selected for
each target (`.reprobit-state/ledger/composed-bodies.json`: per function, the
providing object, its translation unit and the body digest). When that ledger
exists, each clean repair pass also compiles every translation unit (cache
hits when nothing changed), compares the fresh seed body of every function the
linker took from that object with its verified body, and turns each moved,
unrecorded function into a census entry. Carrier discovery then searches fresh
declaration-only compiler states for that translation unit exactly as it does
for a refused record, and a state that carries the verified body is recorded as
a new donor plus function record; nothing is retired. Repair reports success
only when the census is empty.

A moved function in a translation unit the build plan does not list is admitted
first: repair adds the unit to `reprobit/build-plan.json` with the identity a
CMake import would give it, together with an empty intervention shard and proof
shard, and the next pass records the function like any other. One finding stops
the repair instead: a verified function the fresh object no longer defines at
all, which is a semantic change no carrier state can restore. Without a ledger
-- a project that has never verified since the ledger was introduced -- repair
behaves as before and the final cold verify remains the only gate.

## rbit build

Incrementally rebuild changed compiler and linker steps without CMake:

```console
rbit build .
```

`build` uses the compiler location remembered by `rbit setup`. It is the fast
incremental loop: it reuses a stored result only when every relevant input still
matches, then rebuilds the affected compiler steps and their downstream archive
or link steps, and finishes by listing each target output with its size. A
summary explains what was reused and why each rebuilt step was rebuilt (a step
built for the first time on this machine reads
`not cached on this machine yet (first build of this step)`). Use
`rbit build . --cold` for a non-certifying developer build with no cache reads
or writes.

`build`, `verify`, `repair`, and `discover grind` run independent steps in
parallel. Without `--jobs COUNT` the worker count is the number of CPUs the
process may use, capped at 8 (`rbit build --help` prints the rule as
`default: the CPUs this process may use, at most 8`). Pass `--jobs` to pin a
count; values below one are rejected with exit status 2.

### Matched comparison files

If an imported MSVC link asks for debug data, ReproBit automatically writes a
matched binary and `.PDB` inside the sibling `reprobit-debug/` directory. For
example, the pair for `build/GAME.EXE` is
`build/reprobit-debug/GAME.EXE` and `build/reprobit-debug/GAME.PDB`. Tools that
read symbols must use those two files together; do not mix the `.PDB` with the
declared `build/GAME.EXE`. The declared binary remains the only output used for
byte-exact certification or release. There are no extra paths to configure, and
incremental builds cache and restore both comparison files together. Export the
matching source view with [`source export`](#rbit-source-export) before running
a source-aware comparison tool.

<details>
<summary>Advanced: incremental cache and build isolation</summary>

The built-in MSVC adapter requires a valid local compiler installation, but
normal human runs resolve it from `rbit setup`. Plain `build` is a
non-certifying incremental developer build: the first run populates an
immutable project-local CAS, while an unchanged second run restores all nodes
without preparing the logical workspace or starting the shared Wine runtime. It emits
typed per-node hit/miss events in NDJSON and a compact text/NDJSON summary with
hit, miss, elapsed-time, invalidation, and backend-runtime start count. Use
`build --cold` to bypass and construct no cache state.

</details>

## rbit verify

Build every target from scratch and check exact bytes and trust evidence:

```console
rbit verify . --report-dir build/reprobit-report
```

`verify` always builds from scratch, has no warm/cache mode, and never opens
the cache. It writes the trust report as canonical JSON plus self-contained
HTML. Exit status 1 means the result did not satisfy the authenticity policy.

### Reading the report

Open `build/reprobit-report/report.html` in a browser. Start with the overall
result and target summaries: they separately show whether the bytes match, the
saved adjustments passed their logic checks, the output came from the declared
toolchain, and the build started from scratch. Charts summarize build work and
adjustment cost when those details are available. Exact symbols, commands,
receipts, and canonical JSON stay available in collapsed Advanced sections.

<details>
<summary>Advanced: override machine paths and timeouts for one run</summary>

```console
rbit verify . \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc \
  --initialization-timeout 600 \
  --compile-timeout 600 \
  --link-timeout 900 \
  --cleanup-timeout 10 \
  --report-dir build/reprobit-report
```

The two transport options are supplied together on macOS and Linux. Native
Windows rejects those POSIX selectors. The initialization, compile/resource,
librarian/linker, and cleanup deadlines are independently bounded; their
defaults are 600, 600, 900, and 10 seconds. The same options apply to `build`,
`repair`, and `discover grind`; see
[advanced execution options](cli-reference.md#advanced-execution-options).

</details>

<details>
<summary>Advanced: proof details</summary>

`verify` seals each reference binary before execution, builds in a new run
directory, audits current-run producer and intervention evidence, performs
literal comparison, and writes canonical JSON plus self-contained HTML. The two
transport options are only needed for an explicit POSIX override. Before
preparing a native producer arena it reruns the bounded
fresh-LUID lineage-drive probe and fails closed unless the host can admit a
suspended producer and preserve its drive through all producer descendants.
For a project-level `source_overlay_graph`, ReproBit derives a declaration
counterfactual before admitting effective primary products. Declaration-only
leaves require no extra compile. Strict semantic-delta leaves audit their exact
source owners; a strict header conservatively audits every ordinary compiler
because include exposure is not independently sealed. Each invocation is
covered by the compile timeout, and effective overlay receipts can carry
`certified-project-overlay` only after this sparse evidence passes.

The project authenticity policy is authoritative. A command-line policy
override may only narrow acceptance; it cannot silently broaden a clean project
to accept quarantine. Similarly, target and toolchain overrides are checked
against committed project identities.

</details>

## rbit discover init

Create a small automatic search plan without compiling. This is the expert
entry point for precise control over one function:

```console
rbit discover init . \
  --source src/widget.cpp \
  --symbol '?Transform@Widget@@QAEHH@Z' \
  --reference reference/widget.obj
```

`init` finds the matching compile step and writes a four-state plan
(`reprobit/discovery.json` by default) for
[`discover grind --expert-plan`](#rbit-discover-grind).

## rbit discover run

Run a bounded request file (advanced). `discover run REQUEST` is a broader
resumable campaign. It reports whole-function, private-donor, and same-symbol
mosaic proposals but does not save them. Raw proposals are not accepted by
certification commands; candidate exploration stays in ignored state. See the
[discovery guide](discovery.md) for the request format, incremental behavior,
progress events, and reports.

## rbit discover clean

Preview or remove one advanced discovery campaign's reusable state:

```console
rbit discover clean REQUEST --preview
rbit discover clean REQUEST
```

Cleanup removes the campaign's marker-owned reusable state and keeps the
reports. Pass the same `--state-directory` used by the
campaign when it was customized. Cleanup refuses state shared by several
request files unless `--all-requests` is given; preview that combined cleanup
before removing it.

## rbit discover grind

Search a bounded, project-wide set of low-cost adjustments. Use discovery when
a new project's first working build does not yet match its reference. (For a
later regression in a project that was already exact, use `rbit repair .`.)
The default is a read-only preview; repeat fresh proofs and save only when you
approve the result:

```console
rbit discover grind .
rbit discover grind . --accept-progress  # save proven work; follow its printed next step
rbit discover grind . --accept-exact     # require an exact project before saving anything
```

Project-wide grind needs project-owned reference `.obj` files; it cannot derive
them from the reference executable alone. Put those objects under `reference/`
and name them after the source filename without its extension—for example,
`src/widget.cpp` maps to `reference/widget.obj`—or use the exact translation-unit
ID, or pair them explicitly with `--reference-object TU=PATH`. The preview tries
a small round-robin sample across eligible source files (`--max-symbols`) and
keeps its summary at `.reprobit-state/reports/grind/project/report.html`. Each
outcome links to a detailed decision report and a persisted bounded plan. Exact
previews show the copyable, platform-quoted approval command. If the whole
project is not exact, the report can instead offer `--accept-progress` for
functions that matched their project-owned reference objects and passed fresh
logic checks. It saves those adjustments one at a time and may itself reach an
exact project. Follow the printed next step: run another preview if mismatches
remain, or run `rbit verify .` after an exact result. `--accept-exact` is the
stricter path: it publishes nothing unless the current candidate makes the
complete project exact. Review changed files in `git diff`. Saved local
progress does not prove the complete project; only a fresh byte-exact result
does. Exit status 1 means nothing was found or nothing was saved.

The narrow save paths rerun the logic checks and rebuild from scratch:
`--accept-progress` saves only locally proven function adjustments;
`--accept-exact` saves only a complete byte-identical result.

With `--expert-plan reprobit/discovery.json` the command evaluates only the
plan written by [`discover init`](#rbit-discover-init). It writes
`.reprobit-state/reports/grind/report.html`; an exact preview includes its own
fresh approval command, while a locally proven result offers the progress
approval command. See the [discovery guide](discovery.md) for both workflows.

## rbit state status

Show retained runs, cache, reports, active leases, and disk usage:

```console
rbit state status .
```

`state status` separates reusable build records from cache data left by older
ReproBit code and prints the safe cleanup command when it finds any.

## rbit report

Validate JSON and render self-contained HTML from an existing report:

```console
rbit report build/reprobit-report/report.json
```

`report` strictly re-reads canonical report JSON before rendering HTML. The
input must be an existing file.

## rbit cmake-module

Print the packaged CMake module path:

```console
rbit cmake-module --file
```

`cmake-module` prints the installed module directory, or the complete
`ReproBit.cmake` path with `--file`. The module is used only during the one-time
CMake import; normal `build` and `verify` runs do not load it.


## Exit status

Every command follows one contract, enforced in `reprobit.cli.main` and the
individual handlers:

| Code | Meaning | Commands that return it |
|---|---|---|
| 0 | The command completed and its result is ready, clean, or accepted. | all |
| 1 | An honest negative, not an error: the checks ran and the answer is "not yet". | `status` (project not ready), `doctor` (a check failed), `setup` (a backend check failed), `verify` (result not accepted under the policy), `discover grind` (nothing found or nothing saved) |
| 2 | Any error: usage errors, `--jobs` below one, a `CLIError`, an unreadable file, or any unexpected exception. The message starts with `error:`. | all |
| 130 | Interrupted with Ctrl-C; active child processes were asked to drain. | all |

## Machine-readable output

With `--format ndjson`, every line on standard output is one JSON object and
nothing else is written there (diagnostics that text mode sends to standard
error become events too). Keys are sorted, non-ASCII is kept, and NaN is
rejected. Every object carries:

- `event` - the event name from the table below;
- `message` - the same text a human would have seen (multi-line where the
  text rendering is multi-line, for example `project_readiness`);
- `schema_version` - `1`; consumers should reject an unknown version.

Progress is streamed as `workflow_progress` (phase started, finished, failed,
heartbeat) and `producer_progress` (unit finished, cache hit, cache miss)
events with the fields of `reprobit.progress.ProgressEvent`: `sequence`,
`kind`, `phase`, `message`, `elapsed_seconds` and, when present, `completed`,
`total`, `node_id`, `reason`.

Command events (from `CLIOutput.emit` call sites; paths and pydantic models are
serialized as strings and JSON objects):

| Event | Command | Fields besides `event`, `message`, `schema_version` |
|---|---|---|
| `build_complete` | build | `cold`, nodes+hits+misses (warm) or steps (cold), `outputs` |
| `cleanup` | clean | `active_cache_leases`, `cache_blobs`, `cache_records`, `cache_requested`, `obsolete_cache_requested`, `older_than_hours`, `reclaimed_bytes`, `removed`, `report_bytes`, `report_files`, `reports`, `reports_requested`, `skipped_active`, `skipped_recent`, `skipped_recent_cache_records` |
| `cleanup_preview` | clean --preview | `active_cache_leases`, `cache_blobs`, `cache_records`, `cache_requested`, `candidates`, `next_argv`, `next_command`, `obsolete_cache_requested`, `older_than_hours`, `reclaimable_bytes`, `report_bytes`, `report_files`, `reports`, `reports_requested` |
| `cmake_imported` | import cmake | `build_plan`, `next_command`, `nodes`, `producer_graph`, `scaffold_transaction_id`, `translation_units` |
| `cmake_module` | cmake-module | `path` |
| `cost` | cost | `breakdown` |
| `discovery_clean` | discover clean | `bytes`, `files`, `preview`, `removed`, `request`, `requests`, `shared`, `state` |
| `discovery_complete` | discover run | `applied`, `built`, `candidate_kinds`, `cells`, `proposals`, `report_html`, `report_html_digest`, `report_json`, `report_json_digest`, `reused`, `transaction_id` |
| `discovery_grind_complete` | discover grind --expert-plan | `added_cost`, `added_interventions`, `approval_argv`, `authority_files`, `cold_trials`, `cold_verification_report_html`, `cold_verification_report_json`, `compiler_trials`, `declaration_state`, `donor_id`, `exact`, `function_id`, `grind_report_html`, `locally_qualified`, `project`, `proposed_interventions`, `published`, `qualified_candidates`, `rejections`, `report_run_id`, `report_transaction_id`, `report_warning`, `reused_donor`, `states`, `symbol`, `transaction_id` |
| `discovery_grind_plan_created` | discover init | `next_argv`, `next_command`, `plan`, `project`, `reference`, `source`, `states`, `symbol`, `target`, `transaction_id`, `translation_unit` |
| `discovery_grind_report_warning` | discover grind --expert-plan | `artifact`, `error`, `error_type`, `nonfatal`, `project`, `published`, `report` |
| `discovery_project_grind_complete` | discover grind | `accept_mode`, `accepted`, `approval_argv`, `attempted_symbols`, `decision_reports`, `discovered_symbols`, `eligible_units`, `exact_symbols`, `locally_qualified_symbols`, `max_symbols`, `next_argv`, `next_command`, `outcomes`, `persisted_plans`, `project`, `project_wide`, `published_progress_symbols`, `published_symbols`, `reference_objects`, `report_html`, `report_json`, `report_transaction_id`, `report_warning`, `skips`, `truncated_symbols`, `verify_argv` |
| `discovery_project_grind_report_warning` | discover grind | `error`, `error_type`, `nonfatal`, `project`, `report`, `symbol`, `translation_unit` |
| `doctor_check` | doctor | `component`, `detail`, `name`, `passed`, `required` |
| `doctor_result` | doctor | `backend`, `executed_probe`, `passed` |
| `error` | any | `error_type` |
| `hint` | cost, explain |  |
| `incremental_build_summary` | build (warm) | `elapsed_seconds`, `hit_rate`, `hits`, `invalidations`, `misses`, `producer_hits`, `producer_misses`, `published_comparison_pairs`, `published_targets`, `runtime_init_count`, `transform_hits`, `transform_misses`, `unchanged_comparison_pairs`, `unchanged_targets` |
| `initialized` | init | `changed_paths`, `next_command`, `project_id`, `project_root` |
| `interrupted` | any | `error_type`, `exit_code` |
| `intervention` | explain | `beneficiaries`, `cost`, `cost_class`, `dependencies`, `id`, `kind`, `rationale`, `scope`, `units` |
| `producer_graph_configured` | graph configure | `certification_runtime`, `command_digest`, `compile_database`, `configure_log`, `configured_build_root`, `duration_seconds`, `effective_source_digest`, `effective_source_root`, `project_plan`, `target_plan`, `toolchain_root` |
| `producer_graph_extracted` | graph extract, import cmake | `certification_runtime`, `extractor`, `graph_digest`, `nodes`, `output`, `roles`, `skipped_translation_units`, `transaction_id`, `translation_units` |
| `project_readiness` | status | `checks`, `completed`, `next_command`, `next_step`, `ready`, `total` |
| `repair_cleanup_warning` | repair | `project`, `workspace` |
| `repair_complete` | repair | `changed_records`, `cleanup_warning`, `discovered_actions`, `donor_candidates`, `donor_retunes`, `exact`, `measured_checks`, `project`, `reauthored_actions`, `refreshed_checks`, `removed_donors`, `repair_passes`, `repaired_translation_units`, `report_html`, `report_json`, `retired_actions`, `source_inputs`, `transaction_id` |
| `repair_refused` | repair | failure diagnostic fields, `phase` |
| `report_written` | report | `clean`, `html`, `input`, `total_cost` |
| `setup` | setup | `backend`, `backend_failures`, `environment_ready`, `next_command`, `next_step`, `profile`, `project_ready`, `readiness`, `toolchain_lock`, `toolchain_lock_created`, `toolchain_root` |
| `source_exported` | source export | `interventions`, `path` |
| `source_locked` | source lock | `entries`, `next_command`, `next_step`, `output`, `producer_graph_invalidated`, `source_manifest_digest`, `transaction_id` |
| `source_preview` | source preview | `added`, `after_source_manifest_digest`, `authority_checked`, `authority_error`, `before_source_manifest_digest`, `changed`, `checked_overlay_outputs`, `classic_preflight_checked`, `cmake_import_command`, `entries`, `membership_transition_blocked`, `next_command`, `producer_graph_invalidation_required`, `removed`, `repair_required`, `stale_translation_units`, `unchanged`, `up_to_date` |
| `source_regenerated` | source regenerate | `applied`, `changes`, `documents`, `next_command`, `transaction_id` |
| `state_status` | state status | `cache_active_leases`, `cache_blobs`, `cache_bytes`, `cache_current_records`, `cache_files`, `cache_obsolete_records`, `cache_records`, `cache_stale_leases`, `report_bytes`, `report_files`, `root`, `run_bytes`, `run_files`, `runs`, `total_bytes`, `total_files` |
| `toolchain_locked` | toolchain lock | `input_trees`, `output`, `profile`, `runtime_files`, `tools`, `transaction_id` |
| `toolchain_provisioned` | toolchain provision | `next_command`, `profile`, `root`, `saved` |
| `validated` | validate | `interventions`, `project_id`, `proofs`, `targets` |
| `verification` | verify | `accepted`, `exact_targets`, `origin_integrity`, `policy`, `quarantine_actions`, `quarantine_bytes`, `report_html`, `report_json`, `targets`, `total_cost`, `verdict` |
| `workspace_gc_hint` | build, verify | `project` |
| `workspace_retained` | build, verify, repair, import cmake | `outcome`, `path` |

`error` and `interrupted` are the only events with an exit code other than 0
or 1 attached; their `error_type` names the Python exception class
(`CLIError` for expected failures).
