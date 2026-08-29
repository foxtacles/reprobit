# Command-line workflow

`rbit` keeps project intent, local machine configuration, building, and
certification separate. Commands write plain text by default. Put the global
`--format ndjson` option before the subcommand for stable machine-readable
events; an interactive terminal additionally gets elapsed-time progress. Long
operations emit typed phase-start, heartbeat, unit-completion, and terminal
events, so redirected logs and CI never go silent while a compiler or verifier
is still working. Producer progress and workflow progress remain separate event
types.
Producer totals include declaration-counterfactual compiler work only for the sparse source
owners selected by strict `source_overlay_graph` leaves.

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

After adding the build plan, intervention, proof, and oracle documents, extract
the migration-time producer graph described below. `validate` then loads every
shard, rejects duplicate keys and IDs, checks
cross-document references and dependency cycles, receipts current manifest
bytes, renders declarative overlays in memory, and checks effective TU digests.
It never runs a build. `explain` and `cost` inspect the committed metadata only,
so they remain useful while source bytes are being edited; `validate` is the
command that checks those bytes against committed authority. `explain` lists
interventions and their fixed costs; pass `--intervention ID` to select one.

## Admit a local toolchain

```console
rbit doctor . --toolchain-root /opt/toolchains/msvc42
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

The lock format is pre-release in `0.1.0.dev0`; regenerate existing development
locks with `rbit toolchain lock` instead of expecting compatibility conversion.

`doctor` checks the selected host backend and, when a project and toolchain root
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
executes CMake. Run `rbit graph upgrade --project .` to convert a still-valid v1
graph without CMake. Re-extract only when source topology or other command/build
authority changes.
Repeat `--directive-input TARGET=LIBRARY` for reviewed linker-only library
edges discovered in COFF `.drectve` sections. The value must be a known target
and one bare library name; paths, duplicate declarations, and implicit runtime
authorization are rejected. When an edge is missing, the direct runtime emits
copy/paste-ready flags for a new explicit extraction.

## Build and certify

```console
rbit build . \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc
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

The built-in classic adapter requires a toolchain root. Plain `build` is a
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
transport options are supplied together on POSIX. Native Windows rejects those
POSIX selectors. Before preparing a native producer arena it reruns the bounded
fresh-LUID lineage-drive probe and fails closed unless the host can admit a
suspended producer and preserve its drive through all producer descendants.
The initialization, compile/resource, librarian/linker, and cleanup deadlines
are independently bounded; their defaults are 600, 600, 900, and 10 seconds.
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
rbit state gc . --dry-run --older-than-hours 24
rbit state gc . --older-than-hours 24
```

Garbage collection only removes inactive retained run arenas at least as old as
the requested cutoff. It never treats cache state as certified build input.

The project authenticity policy is authoritative. A command-line policy
override may only narrow acceptance; it cannot silently broaden a clean project
to accept quarantine. Similarly, target and toolchain overrides are checked
against committed project identities.

## Preview compiler interventions

`rbit discover` runs a bounded, resumable MSVC 4.2 declaration campaign outside
the certification boundary. It reports whole-function, private-donor, and
same-symbol mosaic candidates without editing source or applying them. See the
[discovery guide](discovery.md) for the request format, incremental behavior,
progress events, and reviewable artifact outputs.

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

Discovery campaigns and automatic repinning are intentionally not accepted by
the certification commands unless an adapter can regenerate and prove the
affected evidence. Candidate exploration belongs in ignored state; committed
expectations are published only by a successful transactional adapter workflow.
