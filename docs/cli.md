# Command-line workflow

`rbit` keeps project intent, local machine configuration, building, and
verification separate. Commands write plain text by default, and long work uses
one live progress line in an interactive terminal. Put the global
`--format ndjson` option before the subcommand when CI or another program needs
stable machine-readable events.

For an existing project, the everyday path is short:

```console
rbit status .
rbit build .
rbit verify . --report-dir build/reprobit-report
```

`status` names the next missing setup item. `build` is the fast incremental
developer loop; `verify` always starts fresh and writes the trust report. The
longer commands below are for first-time project onboarding and unusual hosts.

<details>
<summary>Advanced: progress events</summary>

Redirected logs and CI receive phase starts, heartbeats, completed units, and a
final event, so a compiler or verifier never goes silently idle. Producer work
and overall workflow progress use separate event types. Discovery compiler
totals include declaration experiments only for the source files selected by
the committed overlay graph.

</details>

## Create and inspect a project

This guided path currently initializes one CMake target. Multi-target project
records are supported, but their initial target list still requires advanced
project setup.

```console
rbit init . --project-id sample --profile msvc_4_2
rbit setup .
rbit source preview --project .
rbit source lock --project .
# Put the reference binary at reference/program.exe, then:
rbit import cmake .
rbit status .
```

`init` creates the project entry point and an empty, explicitly incomplete
source record, so a new project cannot appear build-ready before its real files
are reviewed. `setup` prepares and records the compiler. `source preview`
hashes the proposed Git-tracked read set without writing; `source lock` publishes that set
after review. Repeat `--path` on either source command to provide an explicit
complete file or tree set instead. It is not a filter over the current record:
every omitted path is reported as a removal.

`import cmake` is the normal fresh-project path. It derives the initial build
plan, records the reference binary, and creates empty per-source review shards.
It then configures the existing project once and saves the direct compiler and
linker graph. It does not edit `CMakeLists.txt`.
The simplest setup passes the real CMake target name to `rbit init --target`, so
the default rebuilt-output and reference filenames follow it. Use
`--target program=your_cmake_target` during import only when the ReproBit ID
intentionally differs and its declared artifact still matches the real output.
For example, a different CMake target and output can be declared without any
later JSON edit:

```console
rbit init . --target program --artifact build/app.exe --oracle reference/program.exe
# After setup, source review, and placing the reference binary:
rbit import cmake . --target program=app
```

If the import fails, the generated scaffold is removed and the diagnostic
workspace is retained for inspection.

<details>
<summary>Advanced: source-lock safety and generated project records</summary>

`source lock` publishes the manifest and, when one exists, its build-plan
binding in one content-addressed transaction. Every admitted source file is a
transaction precondition, so an edit racing the lock aborts rather than
committing a stale receipt. Pass `--invalidate-producer-graph` when preview says
the generated graph is stale; rerun `rbit import cmake .` afterward. A graph-v2
command DAG remains valid when bytes change at an already admitted path, but a
source-path addition or removal changes its topology receipt. The command does
not rewrite translation-unit, intervention, or proof pins. If effective TU bytes
or a clean overlay input changed, it refuses the transaction and requires the
adapter's reviewed regeneration workflow.

### What setup records

Machine setup and project setup are separate. `rbit setup` can finish installing
and checking the compiler while `rbit status` still lists missing project files.
The guided CMake import derives only facts it can check: target mappings, empty
initial intervention/proof records, the protected reference digest, and the
compiler/linker commands CMake exposes. It does not guess entropy interventions.

For a schema-v2 project, the one-way `rbit manifest migrate` command creates its
reviewable records. For a fresh CMake project, `rbit import cmake .` creates the
minimal initial records and graph. `rbit status .` keeps every missing item
visible; successful compiler setup alone never counts as a build-ready project.

`validate` then loads every shard, rejects duplicate keys and IDs, checks
cross-document references and dependency cycles, receipts current manifest
bytes, renders declarative overlays in memory, and checks effective TU digests.
It never runs a build. `explain` and `cost` inspect the committed metadata only,
so they remain useful while source bytes are being edited; `validate` is the
command that checks those bytes against committed authority. `explain` lists
interventions and their fixed costs; pass `--intervention ID` to select one.

</details>

## Prepare the local compiler

```console
rbit setup .
# Or use an existing installation:
rbit setup . --toolchain-root /opt/toolchains/msvc42
```

`setup` selects or downloads the compiler, authenticates it, remembers the local
path, creates the project lock when absent, verifies an existing lock, and probes
the host backend. That is the normal workflow on macOS, Linux, and Windows.

<details>
<summary>Advanced: lock or probe a compiler installation manually</summary>

The lower-level lock command remains available for CI images and unusual manual
installations that need explicit runtime files:

```console
rbit toolchain lock --project . --root /opt/toolchains/msvc42 \
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

`doctor` is the read-only diagnostic underneath setup. It checks the selected
host backend and, when a project and toolchain root are supplied, verifies the
installation against the committed lock. Add
`--execute-probe` to execute the bounded Wine probe on POSIX. On native Windows
the opt-in probe creates a fresh, verified logon session and defines a temporary
drive only in that session. The real producer starts suspended inside a nested
Job Object, and the probe requires its descendant to observe the same drive.
The mapping is removed only after that complete producer tree exits.

</details>

## Import the direct build steps

CMake is a one-time import input, not a build or certification runtime.
For a normal project, the entire import is one command:

```console
rbit import cmake .
```

It materializes the reviewed source tree, performs one bounded configure—never
a project build—and atomically commits the closed graph and its initial TU
review shards. It uses **Unix Makefiles** on POSIX or the authenticated
**NMake Makefiles** frontend on native Windows, plus `compile_commands.json`
and the reviewed `reprobit-target-plan.json`.

<details>
<summary>Advanced: configure and extract separately for CI or unusual projects</summary>

```console
rbit graph configure --project . \
  --workspace-root .reprobit-state/migration \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc
rbit graph extract --project . \
  --configured-build-root .reprobit-state/migration/build \
  --effective-source-root .reprobit-state/migration/source \
  --toolchain-root /opt/toolchains/msvc42 \
  --directive-input program=oldnames.lib
rbit validate .
rbit explain .
rbit cost .
```

`graph configure` reports the exact configured/effective roots, target plan,
compile database, configure log, command digest, and duration. It refuses a
non-empty workspace and detects any source mutation during CMake configuration.
`graph extract` reads expanded compile commands, resource rules, response files,
and link commands; converts physical paths into `${SOURCE}`, `${BUILD}`, and
`${TOOLCHAIN}` seats; rejects unbound producers and paths; and transactionally
publishes `reprobit/producer-graph.json`. Schema v2 binds the canonical admitted
source path topology, toolchain lock, logical-path profile, exact target set,
and terminal artifact paths; the source manifest and build plan separately bind
current source contents. Certification reloads those documents and never
executes CMake. Re-extract only when source topology or other command/build
authority changes.
Repeat `--directive-input TARGET=LIBRARY` for reviewed linker-only library
edges discovered in COFF `.drectve` sections. The value must be a known target
and one bare library name; paths, duplicate declarations, and implicit runtime
authorization are rejected. When an edge is missing, the direct runtime emits
copy/paste-ready flags for a new explicit extraction.

</details>

## Build and verify

```console
rbit build .
rbit verify . --report-dir build/reprobit-report
```

Both commands use the compiler location remembered by `rbit setup`. `build` is
the fast incremental loop; `verify` always builds from scratch and writes the
trust report.

### Matched comparison files

If an imported MSVC link asks for debug data, ReproBit automatically writes a
matched binary and `.PDB` inside the sibling `reprobit-debug/` directory. For
example, the pair for `build/GAME.EXE` is
`build/reprobit-debug/GAME.EXE` and `build/reprobit-debug/GAME.PDB`. Tools that
read symbols must use those two files together; do not mix the `.PDB` with the
declared `build/GAME.EXE`. The declared binary remains the only output used for
byte-exact certification or release. There are no extra paths to configure, and
incremental builds cache and restore both comparison files together.

Source-aware tools must also read the same reviewed source view as the
compiler. This matters when an intervention adds declarations or otherwise
moves source lines. Export that view into a new or empty directory, then use it
as the tool's source root:

```console
rbit source export build/reprobit-debug/source
```

The export contains only project inputs admitted by the source lock, with the
reviewed source adjustments applied. It does not contain reference binaries,
compiler files, build outputs, or private run state.

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
defaults are 600, 600, 900, and 10 seconds.

</details>

<details>
<summary>Advanced: incremental cache, build isolation, and proof details</summary>

The built-in MSVC adapter requires a valid local compiler installation, but
normal human runs resolve it from `rbit setup`. Plain `build` is a
non-certifying incremental developer build: the first run populates an
immutable project-local CAS, while an unchanged second run restores all nodes
without preparing the logical workspace or starting the shared Wine runtime. It emits
typed per-node hit/miss events in NDJSON and a compact text/NDJSON summary with
hit, miss, elapsed-time, invalidation, and backend-runtime start count. Use
`build --cold` to bypass and construct no cache state. `verify` always builds
from scratch, has no warm/cache mode, and never opens the cache. It seals each
reference binary before execution, builds in a new run directory,
audits current-run producer and intervention evidence, performs literal
comparison, and writes canonical JSON plus self-contained HTML. The two
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

Each command owns a leased run arena. Successful arenas are removed after all
children and backend resources drain; failed arenas are retained for diagnosis.
Use `--keep-workspace never|on-failure|always` to change that policy. Local state
is inspectable and reclaimable without racing active runs:

```console
rbit state status .
rbit clean . --preview
rbit clean .
rbit clean . --cache --preview
```

`clean` removes inactive build workspaces while preserving the reusable
incremental cache. Add `--cache` when you also want to remove eligible cache
records and blobs. It never removes an active build, cache data in use, or a
saved report. Add `--older-than-hours 24` to either scope when you want to keep
the most recent day. `--preview` performs the same safety checks, shows how much
space can be freed, and prints the exact cleanup command without deleting
anything. Verification from scratch never uses the incremental cache as trusted
build input.

The project authenticity policy is authoritative. A command-line policy
override may only narrow acceptance; it cannot silently broaden a clean project
to accept quarantine. Similarly, target and toolchain overrides are checked
against committed project identities.

</details>

## Find and save compiler adjustments

The normal workflow starts with a bounded project preview, then repeats fresh
proofs only when you approve the result:

```console
rbit discover grind . --project-wide
rbit discover grind . --project-wide --accept-exact
rbit verify .
```

Project-wide grind needs project-owned reference `.obj` files; it cannot derive
them from the reference executable alone. Put those objects under `reference/`
and name them after the source filename without its extension—for example,
`src/widget.cpp` maps to `reference/widget.obj`—or use the exact translation-unit
ID. The preview tries a small round-robin sample across eligible source files
and keeps its summary at
`.reprobit-state/reports/grind/project/report.html`. Each outcome links to a
detailed decision report and a persisted bounded plan. Exact previews show the
copyable, platform-quoted approval command. `--accept-exact` grants advance
permission for another fresh proof run to save only the solutions that still
pass byte identity and logic checks. Review the changed files in `git diff`.

For precise control over one function, the expert flow remains available:

```console
rbit discover init . \
  --source src/widget.cpp \
  --symbol '?Transform@Widget@@QAEHH@Z' \
  --reference reference/widget.obj
rbit discover grind .
```

`init` finds the matching compile step and writes a four-state plan. Running
`grind` without `--project-wide` evaluates only that plan. It writes
`.reprobit-state/reports/grind/report.html`; an exact preview includes its own
fresh approval command.

The advanced `rbit discover run REQUEST` command is a broader resumable campaign.
It reports whole-function, private-donor, and same-symbol mosaic proposals but
does not save them. See the [discovery guide](discovery.md) for both workflows,
incremental behavior, progress events, and reports.

Raw `discover run` proposals are not accepted by certification commands.
Candidate exploration stays in ignored state. The narrow project-aware
`discover grind --accept-exact` path reruns the logic checks, rebuilds and
verifies the candidate from scratch, and saves only a passing exact result.

<details>
<summary>Temporary: import an unreleased schema-v2 project</summary>

```console
rbit manifest migrate tools/legacy-manifest.json --project-root .
rbit manifest migrate tools/legacy-manifest.json --project-root . \
  --semantic-claims tools/reprobit-migration-claims.once.json --apply
```

`--semantic-claims` supplies reviewed scope/header facts that schema v2 never
recorded. The strict one-off JSON sidecar is not a runtime input or migration
output; leave the historical manifest unchanged and discard the sidecar after
reviewing the generated schema-v3 project.

The first command is a deterministic preview. `--apply` publishes the complete
schema-v3 tree in one content-addressed transaction after validating it in a
temporary project. Migration is one-way: normal commands never load schema v2.
Raw legacy reference-byte or instruction payload fields become digest-only
redactions; they do not become executable recipe parameters.

</details>

## Render an existing report

```console
rbit report build/reprobit-report/report.json
```

`report` strictly re-reads canonical report JSON before rendering HTML.

<details>
<summary>Advanced: inspect the one-time CMake import module</summary>

```console
rbit cmake-module --file
```

`cmake-module` prints the installed module directory, or the complete
`ReproBit.cmake` path with `--file`. The module is used only during the one-time
CMake import; normal `build` and `verify` runs do not load it.

</details>
