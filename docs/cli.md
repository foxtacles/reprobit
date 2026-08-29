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

```console
rbit init . --project-id sample --profile msvc_4_2
rbit source preview --project .
rbit source lock --project .
```

`init` creates the schema-v3 entry point and locks that initial file in a
portable source manifest. It does not invent build plans, toolchain locks,
interventions, proof expectations, or oracle receipts. `source preview` hashes
the proposed Git-tracked read set without writing and reports added, removed,
and changed paths, required producer-graph invalidation, and any effective
translation-unit or source-overlay pins that no longer hold. Repeat `--path` on
either source command to supply a complete replacement file or tree set. It is
not a filter over the current manifest: every omitted path is reported as a
removal.

`source lock` publishes the manifest and build-plan manifest binding in one
content-addressed transaction. Every admitted source file is a transaction
precondition, so an edit racing the lock aborts rather than committing a stale
receipt. Pass `--invalidate-producer-graph` when preview says the generated
graph is stale; reconfigure and run `rbit graph extract` afterward. A graph-v2
command DAG remains valid when bytes change at an already admitted path, but a
source-path addition or removal changes its topology receipt. The command does
not rewrite translation-unit, intervention, or proof pins. If effective TU bytes
or a clean overlay input changed, it refuses the transaction and requires the
adapter's reviewed regeneration workflow.

### Complete project build authority

Machine setup and project setup are separate. `rbit setup` can finish installing
and checking the compiler while `rbit status` still lists missing project files.
ReproBit deliberately does not guess compile commands, reference metadata, or
interventions for a fresh codebase.

For a schema-v2 project, the one-way `rbit manifest migrate` command creates the
reviewable build plan, intervention, proof, and reference-metadata shards. For a
new project, use the typed files in the [grind example](../examples/grind/README.md)
as a small reference and the [project-format guide](project-format.md) for each
file's role. This pre-release does not yet provide a generic build-plan scaffold.
`rbit status .` keeps every missing item visible; do not treat successful compiler
setup as a build-ready project.

After adding the build plan, intervention, proof, and oracle documents, extract
the migration-time producer graph described below. `validate` then loads every
shard, rejects duplicate keys and IDs, checks
cross-document references and dependency cycles, receipts current manifest
bytes, renders declarative overlays in memory, and checks effective TU digests.
It never runs a build. `explain` and `cost` inspect the committed metadata only,
so they remain useful while source bytes are being edited; `validate` is the
command that checks those bytes against committed authority. `explain` lists
interventions and their fixed costs; pass `--intervention ID` to select one.

## Prepare the local compiler

```console
rbit setup .
# Or use an existing installation:
rbit setup . --toolchain-root /opt/toolchains/msvc42
```

`setup` selects or downloads the compiler, authenticates it, remembers the local
path, creates the project lock when absent, verifies an existing lock, and probes
the host backend. That is the normal workflow on macOS, Linux, and Windows.

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
migration tree; direct ReproBit builds do not execute it, so the provisioner
authenticates it but the portable runtime lock does not include it.
Committed lock paths are relative to the supplied toolchain root; the physical
root itself remains local configuration. `rbit validate` rejects a registered
profile whose locked profile paths are missing, disagree with these reviewed
repository inputs, or assign an extra profile source to a wrapper path.

`doctor` is the read-only diagnostic underneath setup. It checks the selected host backend and, when a project and toolchain root
are supplied, verifies the installation against the committed lock. Add
`--execute-probe` to execute the bounded Wine probe on POSIX. On native Windows
the opt-in probe creates a fresh, verified logon session and defines a temporary
drive only in that session. The real producer starts suspended inside a nested
Job Object, and the probe requires its descendant to observe the same drive.
The mapping is removed only after that complete producer tree exits.

## Commit the direct producer graph

CMake is a one-time migration input, not a build or certification runtime.
The built-in classic migration command materializes the reviewed effective
source tree and performs one bounded configure—never a build—into a new or
empty workspace. It forces **Unix Makefiles**, `compile_commands.json`, and the
reviewed `reprobit-target-plan.json`. Then commit the closed graph:

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

## Build and verify

```console
rbit build .
rbit verify . --report-dir build/reprobit-report
```

Both commands use the compiler location remembered by `rbit setup`. `build` is
the fast incremental loop; `verify` always builds from scratch and writes the
trust report.

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

The built-in classic adapter requires a valid local compiler installation, but
normal human runs resolve it from `rbit setup`. Plain `build` is a
non-certifying incremental developer build: the first run populates an
immutable project-local CAS, while an unchanged second run restores all nodes
without preparing the logical workspace or starting a Wine lane. It emits
typed per-node hit/miss events in NDJSON and a compact text/NDJSON summary with
hit, miss, elapsed-time, invalidation, and initialized-lane counts. Use
`build --cold` to bypass and construct no cache state. `verify` is always cold,
has no warm/cache mode, and never opens the cache. It seals each
reference oracle before execution, builds in a new run directory,
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
anything. Cold verification never uses the incremental cache as trusted build
input.

The project authenticity policy is authoritative. A command-line policy
override may only narrow acceptance; it cannot silently broaden a clean project
to accept quarantine. Similarly, target and toolchain overrides are checked
against committed project identities.

</details>

## Find and save compiler adjustments

The normal workflow needs three short commands:

```console
rbit discover init . \
  --source src/widget.cpp \
  --symbol '?Transform@Widget@@QAEHH@Z' \
  --reference reference/widget.obj
rbit discover grind .
rbit discover grind . --accept-exact
```

`init` finds the matching compile step and creates a four-state project plan.
The first `grind` is a read-only preview. It keeps a human report
at `.reprobit-state/reports/grind/report.html` for both exact and unsuccessful
bounded searches. Exact results link to the separate cold-verification report.
The command only reports a solution after a cold, byte-exact build with passing
logic checks. `--accept-exact` grants
advance permission for another fresh proof run to save the resulting
intervention and proof records together. Follow it with `rbit verify .` and
review the changed project files in `git diff`.

The advanced `rbit discover run REQUEST` command is a broader resumable campaign.
It reports whole-function, private-donor, and same-symbol mosaic proposals but
does not save them. See the [discovery guide](discovery.md) for both workflows,
incremental behavior, progress events, and reports.

## Schema-v2 migration

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
Raw legacy oracle or instruction payload fields become digest-only redactions;
they do not become executable recipe parameters.

## Reports and migration-time CMake

```console
rbit report build/reprobit-report/report.json
rbit cmake-module --file
```

`report` strictly re-reads canonical report JSON before rendering HTML.
`cmake-module` prints the installed module directory, or the complete
`ReproBit.cmake` path with `--file`. The module is used only to configure and
export the reviewed migration graph; normal `build` and `verify` runs do not
load it.

Raw `discover run` proposals and automatic repinning are not accepted by the
certification commands. Candidate exploration stays in ignored state. The
narrow project-aware `discover grind --accept-exact` path is the explicit
transactional adapter: it regenerates proof expectations, cold-verifies them,
and publishes only a passing exact result.
