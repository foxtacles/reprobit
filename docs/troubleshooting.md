# Troubleshooting

## The compiler path looks right but output changes

Equal path length is not sufficient. Check `reprobit.toml` for the complete DOS
source, build, and toolchain spellings, then run `rbit doctor --execute-probe`.
ReproBit reproduces those strings in a private skeleton; it does not pad a
different physical path.

## A build passes but verification from scratch refuses

A build does not issue a certification verdict. The built-in MSVC adapter
executes the committed producer graph in a new workspace; CMake is not part of
that run. `rbit verify` always builds from scratch and binds every receipt to
that new run. A pre-existing published target is replaced atomically only after the new
private product is complete; pre-existing files inside the fresh run arena are
still rejected.

Successful arenas are removed by default. A failed arena is retained and its
path is printed; pass `--keep-workspace never` to discard it or `always` to keep
successful runs too. Use `rbit state status` to inspect disk use and
`rbit clean --preview` to see how much inactive state can be removed. Run
`rbit clean` when you are finished diagnosing retained failures. The reusable
build cache is kept unless you explicitly select cache cleanup. Add
`--obsolete-cache` to the normal cleanup preview for data this ReproBit version
cannot reuse, or use `rbit clean --cache --preview` before clearing the complete cache.
Generated verification and grind reports are counted by `state status`, kept by
default, and removed only when you add `--reports`.

## Toolchain doctor reports a digest or tree mismatch

Do not repin reflexively. Confirm that the selected profile and physical root
are correct and inspect local modifications, wrapper files, include trees, and
library trees. If the installation change is intentional, regenerate the lock
in a reviewable change. ReproBit does not use a Python-interpreter hash because
the interpreter is not a compiler payload producer.

## Wine or a compiler child hangs

Every command has a deadline and belongs to a runner-owned process tree. On
POSIX, one run-private Wine prefix and wineserver serve every scheduling lane,
while each producer remains in its own bounded host process group. Native
Windows uses bounded Job Object primitives. A timeout kills the complete owned
producer tree. Run `rbit doctor --execute-probe` before a long campaign. On
POSIX it tests the bounded Wine path. On Windows it validates the controller's
sealed physical root, then
launches the logical-drive producer path in a fresh, verified logon session whose local
`DefineDosDeviceW` mapping remains owned until a nested Job Object reports zero
active processes. A Windows failure means the controller architecture, native
APIs, fresh-session drive admission, AuthenticationId isolation, Job admission, or
descendant inheritance is insufficient for certification. An ordinary mapping
in the controller's existing logon session is not a substitute. Never reuse an unknown global Wine prefix as
certification state. Tune
`--initialization-timeout`, `--compile-timeout`, `--link-timeout`, and
`--cleanup-timeout` independently rather than replacing process ownership with
an unbounded shell command.

## Parallel results differ from serial results

Treat this as a failed isolation proof. Object files, compiler PDBs, response
files, and other producer-owned outputs must not collide. Wine is intentionally
shared within the run: every lane uses one private prefix and wineserver, one
Windows process namespace, and one fixed compiler-visible `TEMP` and `TMP`
path. Each producer still has its own bounded host process group. Reduce
`--jobs` for diagnosis, but do not accept the serial result until the adapter
can prove its resource partition. Retained PDB state is a build input, not a
cache detail.

## Source edits made many expectations stale

Start with the normal one-command repair:

```console
rbit repair .
```

ReproBit updates the saved build guidance affected by your edit, records the
current source, rebuilds from scratch, and checks every target. It publishes
updated records, binaries, any matching debug companions, and reports only
after the result is still exact and trustworthy. On failure, your source edits
remain, while the saved records and previously published results remain
unchanged. Follow the printed candidate report or workspace path, then run
`rbit clean .` when you no longer need that diagnostic state.

The same `repair` command covers an edit to a shared header, even when many
source files include it. ReproBit finds the affected work; do not run a command
for each source file.

For an added or removed file, run `rbit source preview .` (with the
same repeatable `--path` values used for an explicit lock). The preview is
read-only and prints a safe `source lock` command when existing build records
still apply. Repair preserves the exact locked list, so it does not silently
admit a newly tracked file. If preview says the change to which files CMake
builds cannot be handled safely, restore the previous file list for now;
ReproBit does not yet have an automatic update that can preserve every saved
intervention. A successful source lock prints the next required step.
The NDJSON event keeps the detailed
source-list, build-graph, and saved-record findings for automation.

For advanced diagnosis, `rbit source regenerate .` previews only the
mechanical record changes that repair can derive. Human output is a concise
per-document summary; global `--format ndjson` includes every field-level
before/after value. Add `--apply` only when you intentionally want that
intermediate update without a build. It is not certification; after applying,
the command points back to `rbit repair .` for the build and exact check. See the
[source regeneration primitive](cli.md#source-regeneration-primitive).

## Bytes match but the command exits nonzero

Read the independent verdict fields. Byte equality can coexist with a failed
logic certificate, incomplete producer ancestry, a warm build, or quarantine.
`allow-quarantine` permits only the exact frozen reference-byte exceptions; it never hides
another origin-integrity defect.
