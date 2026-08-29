# CMake migration integration

CMake is admitted only as a one-time graph-extraction input. It is never invoked
by a certifying run. `rbit graph configure` materializes reviewed effective
source authority, then performs one bounded configure—never a build—in a new or
empty workspace. It forces **Unix Makefiles**,
`CMAKE_EXPORT_COMPILE_COMMANDS=ON`, the locked compiler-role frontends, and
`reprobit-target-plan.json`. This migration receipt is not certification
evidence; only the extracted and reviewed producer graph can become authority.

Run `rbit cmake-module --file` to inspect the installed `ReproBit.cmake`.
`graph configure` supplies that path and a generated project-plan path to a
project containing this thin migration hook:

```cmake
if(REPROBIT_PROJECT_PLAN)
  include("${REPROBIT_CMAKE_MODULE}")
  include("${REPROBIT_PROJECT_PLAN}")
endif()
```

The generated plan is declarative CMake data. It may use these checked graph
operations:

- `reprobit_insert_generated_source` inserts a freshly materialized source at a
  zero-based target index. It checks the existing before/after neighbours, the
  file SHA-256 and size, project-root containment, and that neither the file nor
  its seat is redirected.
- `reprobit_insert_link_item` inserts an existing link item at a checked index
  and validates its exact neighbours.
- `reprobit_register_target` records the selected output and optional PDB for a
  target.
- `reprobit_add_link_admission` records a typed produced-object admission,
  including its exact index or neighbour selector and expected symbol.
- `reprobit_write_plan` emits resolved target and admission metadata at CMake
  generate time. Python re-parses it with duplicate-key and unknown-field
  rejection before it becomes proof input.

For example, an adapter-generated include can contain:

```cmake
reprobit_insert_generated_source(
  TARGET program
  SOURCE generated/carrier.cpp
  INDEX 4
  AFTER src/third.cpp
  BEFORE src/fifth.cpp
  LANGUAGE CXX
  SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  SIZE 128
)

reprobit_insert_link_item(
  TARGET program
  ITEM generated_supplier
  INDEX 2
  AFTER first_library
  BEFORE second_library
)
```

Projects should not duplicate recipe dispatch, source rendering, path transport,
or provenance logic in CMake. Keep target definitions project-specific and let
the adapter own the generated plan.

Create the ignored configure tree, then extract the closed graph using the
exact roots reported by the first command:

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
  --directive-input config=mfcs42 \
  --directive-input config=msvcprt.lib
```

The workspace must be absent or empty; ReproBit will not erase or reuse a
configured tree. The configure command seals the effective source tree before
and after CMake, rejects a changed target universe, and reports a configure log
and command digest for review. The default target-plan path is
`.reprobit-state/migration/build/reprobit-target-plan.json`; use
`--target-plan` only for another path beneath the configured build root. The
extractor reads `compile_commands.json`, resource rules, `link.txt`, and bounded
response files, then rejects commands or inputs outside the effective source,
configured build, and admitted toolchain roots. It publishes a canonical
`reprobit/producer-graph.json` only after validating the complete candidate
project tree and rechecking all authority files transactionally.

Classic COFF objects and archive members can contribute `/DEFAULTLIB` controls
through their `.drectve` sections even though those libraries do not appear in
the extracted linker command. Such edges are never inferred or authorized at
certification time. Run a prelink audit, review its missing-edge diagnostic,
and repeat `--directive-input TARGET=LIBRARY` once for every approved target
and bare library. The extractor lowercases the name, adds `.lib` when omitted,
canonicalizes the references as `system-library/*.lib`, and rejects unknown
targets, paths, and duplicates. A certifying run requires every effective
`DEFAULTLIB` to match exactly one argv-derived or committed directive input;
its failure prints the exact flags needed for the next reviewed extraction.

Review and commit that graph, then discard the ignored configure tree. Later
`rbit build` (warm by default), `rbit build --cold`, and `rbit verify` runs
expand only its symbolic
`${SOURCE}`, `${BUILD}`, and `${TOOLCHAIN}` seats and invoke the locked producer
roles directly. Graph schema v2 binds the canonical admitted source path set,
not file contents: changing bytes at an existing admitted path leaves the
command DAG reusable, while the source manifest and build plan still bind those
new bytes independently. Adding or removing an admitted path, or changing the
toolchain lock, logical-path profile, target set, terminal artifact path, or
producer commands invalidates the graph and requires a new migration
extraction.

Warm `build` stores non-certifying node artifacts in the leased project-local
CAS. The first run normally misses; an unchanged second run should be all-hit
with zero Wine lanes. `build --cold` and the unconditionally cold `verify`
bypass the cache entirely.
