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
build cache is kept unless you explicitly add `--cache`; preview that broader
cleanup with `rbit clean --cache --preview` first. Generated verification and
grind reports are counted by `state status`, kept by default, and removed only
when you add `--reports`.

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
producer tree. Run `rbit doctor
--execute-probe` before a long campaign: it tests the bounded Wine path on
POSIX. On Windows it validates the controller's sealed physical root, then
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

Run `rbit source preview --project .` (with the same repeatable `--path` values
used for an explicit lock) and keep candidate work under `.reprobit-state`. The
preview is read-only. Its NDJSON event separates source-path changes,
producer-graph invalidation, stale effective translation units, and overlay
rendering errors.

If only the manifest binding changed, run `rbit source lock --project .`; add
`--invalidate-producer-graph` when preview requires it, then rerun the guided
`rbit import cmake .` command described in [Import a CMake project](cmake.md).
The separate `rbit graph configure` and `rbit graph extract` commands are only
for advanced imports that need manual control. With a graph-v3 document,
ordinary byte edits and unrelated manifest additions or removals do not require
invalidation; removing a graph input does. If preview says authority regeneration
is required, do not edit the old digest or rerun lock to bless it. Regenerate
the affected TU, intervention, and proof documents with the adapter and publish
them only after their zero-loss and literal gates pass together.

## Bytes match but the command exits nonzero

Read the independent verdict fields. Byte equality can coexist with a failed
logic certificate, incomplete producer ancestry, a warm build, or quarantine.
`allow-quarantine` permits only the exact frozen reference-byte exceptions; it never hides
another origin-integrity defect.
