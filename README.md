# ReproBit

ReproBit is a proof-carrying toolkit for reproducing byte-identical compiler
output. Its current schema-v3 certification path is the reviewed built-in
classic MSVC adapter; the provenance, scheduling, cost, and reporting layers are
designed for additional reviewed adapters. ReproBit is aimed at decompilation
projects whose checked-in source is logically correct but whose original
compiler makes code generation depend on incidental state: declaration
allocation, translation-unit order, debug records, absolute path spelling, PDB
history, COMDAT layout, library scan order, or equivalent entropy.

ReproBit makes those inputs explicit, applies only closed and versioned
interventions, records the ancestry of every produced artifact, and compares the
finished image with a sealed reference oracle. Its purpose is not to make an
arbitrary binary match. Its purpose is to distinguish three questions that a
matching hash alone cannot answer:

- Are the candidate bytes literally equal to the reference?
- Did every intervention satisfy a current-run logic-preservation proof?
- Did all first-party payload bytes descend from admitted compiler, librarian,
  resource-compiler, and linker output?

A result is **clean** only when all three answers are yes, the build was cold,
and no quarantined legacy action ran.

## What ReproBit controls

ReproBit treats compiler-sensitive context as build input. This includes exact
DOS source, build, and toolchain paths; argv and response-file spelling; working
directory; include and forced-include order; definitions; environment; object
and PDB seats; tool digests; source-overlay graph seats; and link admissions.
Workers use private temporary, object, PDB, process-tree, and Wine state so
parallel work cannot silently share compiler entropy.

A project-level `source_overlay_graph` is admitted to primary compilation only
through the built-in closed validator. It derives one in-memory
**declaration counterfactual** from the manifest-clean tree and the reviewed
overlay grammar. Declaration-only edits are discharged by typed source
theorems; only compiler nodes that own strict semantic-delta sources are
recompiled for sparse object congruence (a strict header conservatively selects
all ordinary compiler nodes). Counterfactual objects are evidence only;
effective overlay source receipts receive the runtime origin
`certified-project-overlay`, and only effective primary products enter terminal
ancestry. The separate `donor_source_overlay` family remains private to donor
lanes and can reach a candidate only through a registered binary-family semantic
proof.

Interventions range from non-emitting declaration carriers through intact
compiler donors and narrowly proved IA-32 transformations. Recipes are data,
not project-supplied Python. Normal producers never receive a reference-image
path or raw oracle bytes. Literal comparison is performed later in a separate
verifier capability.

Historical oracle-install actions can be represented only by a frozen,
non-growing legacy allowlist. Their exact ranges and byte count are always
reported, their cost is deliberately extreme, and their presence makes
toolchain-origin and clean authenticity false.

## Supported environments

The built-in classic MSVC adapter defines explicit profiles for:

- Microsoft Visual C++ 4.2
- Microsoft Visual C++ 5.0 RTM
- Microsoft Visual C++ 5.0 SP1
- Microsoft Visual C++ 5.0 SP2
- Microsoft Visual C++ 5.0 SP3

Python 3.11 or newer is required. ReproBit provides a certifying POSIX/Wine
backend for macOS and Linux. Native Windows combines bounded Job Objects with a
process-private NT DeviceMap assigned while each child is suspended. It fails
closed unless an execution probe proves both direct assignment and visibility
through a producer descendant on that Windows image. CI tests the portable
library on all three hosts and runs the strict native probe plus an authenticated
MSVC 4.2 compiler, resource, and linker smoke on `windows-2022`. A classic
compiler run additionally requires a privately provisioned toolchain and a
passing local doctor probe.
The [native Windows gate and external Archaic MSVC acquisition
recipe](docs/windows.md) authenticate the compiler without storing it in this
repository or workflow artifacts. ReproBit does not redistribute proprietary
compilers or reference binaries.

## Install from source

```console
python -m venv .venv
. .venv/bin/activate
python -m pip install /path/to/reprobit
rbit --version
```

For library development:

```console
python -m pip install -e '/path/to/reprobit[test]'
pytest
ruff check src tests
mypy src/reprobit
```

## First project

Create a schema-v3 entry point and lock the admitted source and local compiler
installation:

```console
rbit init . --project-id sample --profile msvc_4_2
rbit source preview --project .
rbit source lock --project .
rbit toolchain lock --project . --root /opt/toolchains/msvc42
rbit doctor . --toolchain-root /opt/toolchains/msvc42 --execute-probe
```

`init` creates the entry point and an initial portable source manifest. Add the
project's build plan, intervention/proof shards, and oracle metadata, then use
the [one-time CMake migration workflow](docs/cmake.md) to extract and commit
`reprobit/producer-graph.json`. New extractions use graph schema v2: the graph
binds the canonical admitted source path topology, while the source manifest
and build plan independently bind current file contents. `rbit validate`
requires that closed graph and checks its source-topology, toolchain-lock,
logical-path, target, and artifact bindings.

Before refreshing an admitted read set, run `source preview`: it is read-only
and identifies changed paths, graph invalidation, and stale effective TU or
source-overlay authority. `source lock` then commits safe manifest/build-plan
updates atomically and can invalidate the producer graph in the same
transaction with `--invalidate-producer-graph`. Editing bytes at an already
admitted path does not invalidate a v2 command graph; adding or removing an
admitted path does. It never repins reviewed TU, intervention, or proof
authority; regenerate that authority when preview reports it stale. Existing
valid v1 graphs can be converted without CMake by running
`rbit graph upgrade --project .`.

If the closed prelink audit reports COFF `/DEFAULTLIB` dependencies that are
absent from the extracted linker argv, re-extract with its exact repeatable
`--directive-input TARGET=LIBRARY` suggestions. These linker-only edges are
reviewed and committed explicitly; certification never authorizes them on the
fly.

Execute the committed producer graph directly for an iterative artifact build,
then run the only command that can issue a certification verdict:

```console
rbit build . \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc
rbit verify . \
  --toolchain-root /opt/toolchains/msvc42 \
  --compiler-transport /opt/toolchains/msvc42/wine/x86/cl \
  --resource-transport /opt/toolchains/msvc42/wine/x86/rc \
  --compile-timeout 600 --link-timeout 900 \
  --report-dir build/reprobit-report
```

`build` is warm and non-certifying by default. Its first run fills the local
immutable CAS; an unchanged second run restores all nodes without constructing
the logical workspace or starting a Wine lane. A one-TU edit rebuilds that
compiler dependency closure and its archive/link consumers. The CLI reports
typed hits/misses, invalidation reasons, elapsed time, and the actual number of
initialized lanes. Use `rbit build . --cold` for a fresh developer build that
constructs or reads no cache state. `verify` is always cold and likewise never
opens the incremental cache.

The two transport options select admitted POSIX host launchers for the locked
compiler and resource compiler. Supply both on POSIX or neither on native
Windows. CMake is not invoked by either command: nodes in the committed graph
directly execute the locked compiler, resource compiler, librarian, and linker.
Run workspaces and cache entries are leased, successful runs are
cleaned automatically, and failed runs remain available by default; inspect or
reclaim them with `rbit state status` and `rbit state gc`. Text terminals get a
progress bar, while redirected text and NDJSON receive bounded-silence phase
heartbeats and producer-completion events.
When a `source_overlay_graph` contains strict semantic-delta leaves, ReproBit
adds one evidence-only counterfactual compile for each exact source owner. A
strict header falls back to every ordinary compiler node because reader exposure
is not independently sealed. A declaration-only overlay adds no counterfactual
compiler work, and projects without the project-level overlay skip this theorem.

The JSON report is canonical and automation-friendly. The HTML report is
self-contained and shows independent authenticity claims, target hashes,
quarantine disclosure, project and function costs, and every intervention.

## Cost is distance from an ordinary build

Every intervention is decomposed into fixed, library-owned cost units. Native
compilation, verification, and exact path transport cost 0. Non-emitting
compiler-state declarations cost 1; generated suppliers and ordering remain
cheap; donors, semantic rewrites, and binary surgery become progressively
expensive; direct oracle-byte installation costs 10,000 per action. A source
overlay is charged separately for each edit, generated translation unit, and
link admission, so putting several actions under one intervention ID cannot
lower its cost. Shared work is counted once and allocated rationally to
beneficiary functions.

```console
rbit cost
rbit explain --intervention intervention-id
```

The ideal project cost is 0: checked-in source compiled normally by the original
toolchain already produces the reference images. ReproBit makes movement toward
that goal measurable without weakening authenticity.

## Project structure

```text
reprobit.toml
reprobit/
  source-manifest.json
  toolchain.lock.json
  build-plan.json
  producer-graph.json
  interventions/
  proofs/
  oracles/
```

The TOML entry point stays small. Large intervention and expectation sets are
sharded by target and translation unit. The loader rejects unknown keys,
duplicate JSON keys or IDs, non-finite numbers, path escapes, cycles, dangling
references, inconsistent target/TU documents, stale overlay authority, and raw
payload fields in clean recipes.

Schema-v2 migration is previewed before one transactional publish:

```console
rbit manifest migrate path/to/manifest.json --project-root .
rbit manifest migrate path/to/manifest.json --project-root . --apply
```

Normal runtime is v3-only; migration does not leave a compatibility loader
behind.

## Documentation

- [Architecture](docs/architecture.md)
- [Authenticity and threat model](docs/authenticity.md)
- [CLI reference](docs/cli.md)
- [Project format](docs/project-format.md)
- [Cost model](docs/costs.md)
- [Platforms and logical paths](docs/platforms.md)
- [Native Windows and external MSVC acquisition](docs/windows.md)
- [CMake migration integration](docs/cmake.md)
- [GitHub Action](docs/action.md)
- [Migration](docs/migration.md)
- [Troubleshooting](docs/troubleshooting.md)

ReproBit is licensed under `LGPL-3.0-only`.
