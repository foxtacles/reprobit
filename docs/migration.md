# Schema-v2 migration

Migration is an explicit one-way boundary. The normal loader accepts only
schema v3, so deleting or renaming an old field cannot accidentally fall back to
legacy semantics.

Always preview first:

```console
rbit manifest migrate path/to/manifest.json --project-root .
```

The converter rejects duplicate keys, non-finite values, unknown recipe
families, unsafe paths, ambiguous target ownership, and any value it would have
to guess. It canonicalizes stable IDs, separates interventions from committed
expectations, shards translation-unit records, and validates the resulting tree
in a temporary directory.

Legacy fields named as bytes, payloads, oracle/reference paths, scripts,
callables, Python, or templates cannot enter a clean recipe. The converter
stores only a digest redaction in the expectation receipt. A fresh adapter must
derive candidate slices from compiler-produced seed and donor artifacts.

`simulated_elision` is not converted into an ordinary recipe. It becomes a
`legacy.oracle_install` intervention with an exact range list, input and oracle
digests, a project-level allowlist fingerprint, and frozen range/byte ceilings.
Adding or changing a range requires an explicit project change and can never
produce a clean verdict.

Apply only after reviewing the preview:

```console
rbit manifest migrate path/to/manifest.json --project-root . --apply
```

The publish is content-addressed and journalled. Files appear as one validated
transaction; a crash is recovered before the next transaction.

Old host-specific tree Merkle receipts cannot be relabeled as
portable-tree-v1 receipts in the schema-3 toolchain lock. The migration projects
the current profile's reviewed repository inputs into `profile_sources`; this is
configuration, not evidence that the legacy bytes came from those repositories.
It does not reinterpret a legacy single `toolchain_commit` as acquisition proof.
Regenerate the committed byte/tree authority from the admitted physical compiler:

```console
rbit toolchain lock --project . --root /opt/toolchains/msvc42
rbit doctor . --toolchain-root /opt/toolchains/msvc42 --execute-probe
```

The lock format is pre-release in `0.1.0.dev0`; regenerate existing development
locks with `rbit toolchain lock`. The command replaces an old lock without first
loading it as a valid project tree.

The migrated project uses a committed direct producer graph. Materialize the
reviewed effective source tree, configure one ignored CMake Unix Makefiles tree
with the migration module, and extract it as described in
[CMake migration integration](cmake.md):

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
```

Use repeatable `--directive-input TARGET=LIBRARY` declarations only for
reviewed prelink `.drectve` dependencies reported by the direct-runtime
preflight. They are committed graph authority, not dynamically inferred edges.

Finally run `rbit validate`, inspect `rbit cost`, and require two independent
cold verifications before deleting the old runner. CMake and the legacy runner
are migration inputs only; neither participates in those verification runs.
