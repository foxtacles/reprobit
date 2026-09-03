# Troubleshooting

## First-run errors

The messages below were reproduced with the current CLI; long absolute paths
are shortened to `…`. Every error exits `2`; a not-ready `rbit status` exits
`1`. `rbit status .` is the quickest way to see which of them applies.

### `reprobit.toml has not been created`

```text
$ rbit status .
Project: …/empty
Project files: 0/1 checks ready
[  ] Project: reprobit.toml has not been created
Next: rbit init …/empty
```

You are not in a ReproBit project, or ran the command from the wrong
directory. Every command takes the project root as its `project` argument;
run `rbit init` there first (see [getting-started.md](getting-started.md)).

### `Git could not inspect this directory as a worktree`

```text
$ rbit source preview .
error: cannot select project source automatically: Git could not inspect this directory as a worktree. Make sure Git is installed, then run git init and git add as needed. Alternatively, repeat --path PATH to name the complete source input set explicitly.
```

`rbit init` succeeds outside Git, but `source preview` and `source lock`
select the source set from the Git index. Run `git init` and `git add` the
sources, or name every input with repeated `--path`.

### `required regular file is absent or redirected: …/bin/CL.EXE`

```text
$ rbit setup . --toolchain-root /path/to/empty-directory
authenticating the compiler installation...
authenticating the compiler installation: failed (error: required regular file is absent or redirected: …/bin/CL.EXE)
error: required regular file is absent or redirected: …/bin/CL.EXE
```

The directory given to `--toolchain-root` is not a complete MSVC
installation. Point it at the real root (the one containing `bin/CL.EXE`),
or omit the flag so `setup` downloads and authenticates the pinned compiler.
A later build with a wrong root fails as
`error: toolchain tree root is absent or unsafe: …/include` and retains its
workspace; `rbit clean .` removes it.

### `compiler and resource transports must be supplied together`

```text
$ rbit import cmake . --compiler-transport /path/to/cl-launcher
error: compiler and resource transports must be supplied together
```

`--compiler-transport` and `--resource-transport` describe one POSIX launcher
pair and are only needed for an explicit POSIX override. Pass both or neither
(see [platforms.md](platforms.md)).

### `is not valid JSON` / `Expecting property name enclosed in double quotes`

```text
$ rbit status .
Project: …/project
Project and machine: 9/11 checks ready
[!!] Interventions: reprobit/interventions/tu.transform.json is not valid JSON; run rbit validate
Next: rbit validate …/project

$ rbit validate .
checking every saved project file...
checking every saved project file: failed (error: invalid …/reprobit/interventions/tu.transform.json: Expecting property name enclosed in double quotes: line 1 column 22 (char 21))
error: invalid …/reprobit/interventions/tu.transform.json: Expecting property name enclosed in double quotes: line 1 column 22 (char 21)
```

A committed record was edited by hand or merged badly. `validate` names the
file and the parser position. Restore it from Git (`git checkout -- <file>`)
rather than repairing the JSON by eye; the records are canonical documents.

### `argument --format: invalid choice`

```text
$ rbit status . --format json
usage: rbit status [-h] [--all] [project]
rbit status: error: argument --format: invalid choice: 'json' (choose from 'text', 'ndjson')
```

`--format` accepts `text` or `ndjson` and may be placed before or after the
sub-command (`rbit --format ndjson status .` and `rbit status . --format ndjson`
are equivalent). There is no `json` value; use `ndjson` and read one event per
line (see [cli.md](cli.md#machine-readable-output)).

### `CMake import configure failed` with `fatal error C1005:`

```text
$ rbit import cmake .
configuring the CMake project: failed (error: CMake import configure failed: command failed with exit code 1: …/cmake full output: …
retained failed CMake import workspace: …/.reprobit-state/runs/import-c782933c060a461abce4a24b2eade020
error: CMake import configure failed:
    …
    Building CXX object CMakeFiles/cmTC_4da49.dir/testCXXCompiler.cxx.obj
    "…/ReproBit/toolchains/msvc_4_2/wine/x86/cl"  /nologo /TP -D_MBCS  /DWIN32 /D_WINDOWS /Zm1000 /GX  /Zi /Ob0 /Od /GZ -MDd /FoCMakeFiles/cmTC_4da49.dir/testCXXCompiler.cxx.obj

    testCXXCompiler.cxx
    fatal error C1005:
    make[1]: *** [CMakeFiles/cmTC_4da49.dir/testCXXCompiler.cxx.obj] Error 2
```

CMake's compiler test failed inside MSVC 4.2 before ReproBit's own logical
paths were in effect. This was reproduced with a project checkout roughly 150
characters deep; the same import succeeded from a path of about 55 characters.
Move or clone the project to a short path (for example directly under your home
directory) and rerun `rbit import cmake .`. The retained workspace can be
removed with `rbit clean .` afterwards.

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
the command points back to `rbit repair .` for the build and exact check. See
[`rbit source regenerate`](cli.md#rbit-source-regenerate).

## Repair reports unrecorded fallout it could not record

`rbit repair .` compared the fresh objects with the composed-body ledger of the
last accepted verify and found a function without any saved record whose
linker-selected body moved. Such a function is normally recorded automatically:
its translation unit is admitted to `reprobit/build-plan.json` when the plan
did not list it, and carrier discovery searches fresh declaration-only compiler
states for the verified body. Two errors remain. "could not admit the
translation units" names a source the locked manifest does not contain or an
identity that collides with the plan; lock the source first
(`rbit source preview .`). "could not record unrecorded fallout" means no
carrier state within the discovery budget carried the verified body; raise
`--discovery-candidates` and `--donor-candidates`, or derive the record by
hand. A "verified functions no longer defined by their fresh object" error
names a function the edit removed outright; that is a semantic change the
repair cannot restore.

## Bytes match but the command exits nonzero

Read the independent verdict fields. Byte equality can coexist with a failed
logic certificate, incomplete producer ancestry, a warm build, or quarantine.
`allow-quarantine` permits only the exact frozen reference-byte exceptions; it never hides
another origin-integrity defect.
