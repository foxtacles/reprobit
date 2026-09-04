# Getting started

This guide takes an existing CMake project from nothing to a verified ReproBit
build. Every command below was run in that order against a fresh copy of the
`examples/grind-progress` sources; the printed output is reproduced with only the
absolute project path shortened to `/path/to/project`. For the shortest possible
first contact, run the ready-made [grind example](../examples/grind/README.md)
instead; for what the checks mean, read [Concepts](concepts.md). This page owns
the normal setup sequence. The [command-line guide](cli.md) covers optional and
advanced behavior without interrupting that path.

## Prerequisites

- Python 3.11 or newer with ReproBit installed ([README](../README.md#install)).
- The project directory is a Git working tree with its source files committed.
  `rbit source` reads the Git-tracked file list, so untracked files are invisible
  to it.
- The project's compatible CMake version on `PATH` (used only by CMake import
  and later source-list refreshes).
- On macOS and Linux, Wine and `wineserver` on `PATH`.
- If the first build will need automatic grind, project-owned reference `.obj`
  files for the source files you want it to search. The reference executable
  alone is enough to verify, but it cannot supply function bodies to grind.
  You can skip these objects when the project already matches.
- A short project path. MSVC 4.2 has small internal path buffers: a first
  attempt under a 150-character path failed inside CMake's compiler test with
  `fatal error C1005:`; the same project under a 55-character path worked. See
  [Troubleshooting](troubleshooting.md#first-run-errors).

## The sequence

```console
rbit init . --target program
rbit setup .
# Add /reference/ and /build/ to .gitignore before reviewing source files.
rbit source preview .
rbit source lock .
# Put the reference binary at reference/program.exe, then:
rbit import cmake .
rbit status .
```

`rbit status .` works at every point in between and prints the next command, so
you never have to remember where you stopped. Each step is explained below.

## 1. Create the project entry point

Name the real CMake target when initializing. Repeat `--target` for projects
that produce more than one binary; the default rebuilt-output and reference
filenames follow each target name (`build/NAME.exe`, `reference/NAME.exe`).
When the CMake output name differs from the target name, declare both paths:

```console
$ rbit init . --target grind_progress --artifact build/grind-progress.exe --oracle reference/grind-progress.exe
Created ReproBit project 'gs' at /path/to/project
Next: rbit setup /path/to/project
```

With several targets, qualify custom paths as `--artifact TARGET=PATH` or
`--oracle TARGET=PATH`. Use `--target program=your_cmake_target` during
`import cmake` only when the ReproBit target ID must intentionally differ from
the CMake target name and its declared artifact still matches the real output.

`init` writes `reprobit.toml`, adds root `.gitignore` entries for ReproBit's
local state, and creates an empty, explicitly incomplete source record, so a new
project cannot appear build-ready before its real files are reviewed. It does not
touch `CMakeLists.txt`. `status` now lists everything that is still missing:

```console
$ rbit status .
Project: /path/to/project
Project and machine: 3/12 checks ready
[  ] Compiler lock: run rbit setup to create reprobit/toolchain.lock.json
[  ] Source lock: run rbit source preview to finish reviewing and locking the tracked files
[  ] Protected references: place the original at reference/grind-progress.exe
[  ] Build plan: run rbit import cmake to create reprobit/build-plan.json
[  ] Build graph: run rbit import cmake to create reprobit/producer-graph.json
[  ] Interventions: run rbit import cmake to create reprobit/interventions/
[  ] Proofs: run rbit import cmake to create reprobit/proofs/
[  ] Reference metadata: run rbit import cmake to create reprobit/oracles/
Next: rbit setup /path/to/project
```

`status` exits with 1 while anything is missing; that is an honest "not yet",
not an error (see [Exit status](cli.md#exit-status)).

## 2. Prepare this machine

```console
$ rbit setup .
authenticating the compiler installation...
authenticating the compiler installation: complete (0.0s elapsed)
locking exact compiler files...
locking exact compiler files: complete (0.0s elapsed)
Environment ready for Microsoft Visual C++ 4.2
Compiler: /Users/you/Library/Application Support/ReproBit/toolchains/msvc_4_2
Project lock: created
Project: /path/to/project
Project and machine: 4/12 checks ready
[  ] Source lock: run rbit source preview to finish reviewing and locking the tracked files
[  ] Protected references: place the original at reference/grind-progress.exe
...
Next: rbit source preview /path/to/project
```

`setup` downloads and authenticates the compiler when this machine does not have
it yet (the first run therefore prints a download activity as well), remembers
its location in the user configuration, creates `reprobit/toolchain.lock.json`
when it is absent or checks an existing lock against the installation, and
probes the host backend. Later commands need no machine-specific paths. Pass
`--toolchain-root /path/to/msvc42` to use an installation you already have;
[platform setup](platforms.md) and the [native Windows guide](windows.md)
cover unusual hosts.

Machine setup and project setup are separate: `setup` can finish while `status`
still lists missing project files, and successful compiler setup alone never
counts as a build-ready project. Run `setup` once on each machine that will
build the project.

## 3. Review and lock the source files

Before locking, add `/reference/` and `/build/` to `.gitignore` unless you
intend to commit those directories. `init` adds ignores for ReproBit's local
state; these project output and reference directories are your choice. Finish
these edits now: tracked `.gitignore` files belong to the source read set, so
editing one after `source lock` requires reviewing and locking it again.

```console
$ rbit source preview .
checking the project source files...
checking the project source files: complete (0.0s elapsed)
Source preview: +4 -0 ~0; 4 selected inputs
  add: CMakeLists.txt, prepare_reference.py, transform_one.cpp, transform_two.cpp
  no build plan or saved source-derived records to check
Next: rbit source lock /path/to/project

$ rbit source lock .
checking the project source files...
checking the project source files: complete (0.0s elapsed)
locked 4 project source inputs
Next: place the original at reference/grind-progress.exe
```

`source preview` hashes the proposed Git-tracked read set without writing;
`source lock` publishes that set to `reprobit/source-manifest.json` after your
review. Repeat `--path` on either command to provide an explicit complete file
or tree set instead. It is not a filter over the current record: every omitted
path is reported as a removal.

## 4. Place the reference inputs

Copy the original executable to the declared oracle path
(`reference/grind-progress.exe` here). ReproBit never redistributes reference
binaries. The ignores added before source review keep these inputs and build
outputs out of Git (the shipped examples do the same).

If you expect to use automatic grind after the first verification, also place
the available reference objects under `reference/`. Name each one after its
source filename without the extension—for example, `src/widget.cpp` pairs with
`reference/widget.obj`. Grind's read-only preflight reports how many eligible
compiler steps have an object, how many do not, and how many functions it selected.
Use `--reference-object TU=PATH` when names are ambiguous. The
`examples/grind-progress` script generates both kinds of reference input with
the authenticated compiler; a real project uses its own archival or analysis
inputs. The [grind guide](discovery.md#automatic-grind) covers the full mapping
rules.

## 5. Import the build steps from CMake

```console
$ rbit import cmake .
preparing a reviewable CMake build plan...
preparing a reviewable CMake build plan: complete (0.1s elapsed)
configuring the CMake project...
configuring the CMake project... (5.0s elapsed)
configuring the CMake project: complete (52.0s elapsed)
recording the direct compiler and linker steps...
recording the direct compiler and linker steps: complete (0.0s elapsed)
committed 3 direct producers to reprobit/producer-graph.json
CMake import complete: 3 build steps and 2 TUs recorded
Next: rbit build /path/to/project
```

`import cmake` derives the initial build plan, records the reference binary's
digest, and creates an empty review document for each unambiguous source file so
discovery can start without hand-authored JSON. It configures the existing
CMake project without building it and saves the direct compiler and linker
steps as `reprobit/producer-graph.json`. It derives only facts it can
check and does not guess entropy interventions. It does not edit
`CMakeLists.txt`, and normal ReproBit builds never invoke CMake. If the
import fails, the generated scaffold is removed and the diagnostic workspace is
retained for inspection. [CMake import and refresh](cmake.md) covers projects
that need cache settings, later source-list changes, or the configure and
extract halves separately.

## 6. Confirm and commit

```console
$ rbit status .
Project: /path/to/project
Project and machine ready: 12/12 checks passed

$ git status --short
?? .gitignore
?? reprobit.toml
?? reprobit/
```

Commit `.gitignore`, `reprobit.toml`, and `reprobit/` (the compiler lock, the
source lock, the build plan, the build graph, and one empty intervention and
proof document per target and per source file). `rbit validate .` loads every saved JSON file,
rejects duplicate keys and IDs, checks cross-document references and dependency
cycles, compares current files with their recorded hashes, and never runs a
build:

```console
$ rbit validate .
validated gs: 1 target, 0 interventions
```

## 7. Build, then verify

```console
$ rbit build .
checking the project files...
rebuilding changed steps and reusing unchanged work: complete (8/8; 7.8s elapsed)
Incremental build: 0 reused, 6 rebuilt (0.0% reused); compiler environment started 1 time; 7.77s; target outputs: 0 unchanged, 1 updated
Why steps were rebuilt:
  compiler.grind_progress.0000: not cached on this machine yet (first build of this step)
  compiler.grind_progress.0001: not cached on this machine yet (first build of this step)
Build complete: 6 steps, 1 output
  build/grind-progress.exe (1,536 bytes)
```

`build` is the incremental developer loop. Running it again without any edit
restores every step from the cache without starting the compiler environment:

```text
Incremental build: 6 reused, 0 rebuilt (100.0% reused); compiler environment started 0 times; 0.30s; target outputs: 1 unchanged, 0 updated
```

Use `rbit build . --cold` for a non-certifying build with no cache reads or
writes. Certification is a different command:

```console
$ rbit verify . --report-dir build/reprobit-report
```

`verify` always builds from scratch, never reads the developer cache, compares
the result with the protected reference, and writes `report.json` plus a
self-contained `report.html`. Open the HTML in a browser: its first view explains
the overall result and each target; detailed symbols, commands, and evidence are
in collapsed Advanced sections. A freshly imported project usually does not
match yet. This one prints:

```text
Verification did not satisfy the authenticity policy
Byte identity: 0/1 targets exact
Report: /path/to/project/build/reprobit-report/report.html
```

and exits with 1. That is the starting point for the bounded
[`discover grind` workflow](discovery.md), which finds the first low-cost
adjustments and saves them only after a fresh exact proof. Its first line checks
the reference-object coverage before compiling. Once the project is exact,
`verify` ends with `Verification passed`, `Authenticity: clean`, and the total
intervention cost.

## Debug companions and the exported source view

The declared binary remains the only output used for byte-exact certification
or release. If an imported MSVC link asks for debug data, ReproBit also writes a
matched binary and `.PDB` under the sibling `reprobit-debug/` directory—for
example, `build/reprobit-debug/GAME.EXE` and `build/reprobit-debug/GAME.PDB`.
Give analysis tools those two files together; do not mix the `.PDB` with the
declared binary. ReproBit chooses the paths automatically and caches the pair
during incremental builds.

If the project uses reviewed source adjustments, export the matching source view
before running a source-aware comparison tool, and point the tool's source root
at that directory:

```console
rbit source export . --destination build/reprobit-debug/source
```

This keeps line and symbol information matched to the files the compiler
actually read. The export contains project inputs admitted by the source lock,
with the reviewed source adjustments applied, plus one hidden ownership marker;
it does not contain reference binaries, compiler files, build outputs, or
private run state. Run the same command after later changes; ReproBit safely
replaces the previous view and removes files that are no longer part of it.

## After the project is exact: edits and repair

After editing a file in a project that already matched exactly—even a shared header
used by many source files—let ReproBit repair and verify the project in one
step:

```console
rbit repair .
```

`repair` works on a private copy, follows shared headers to every affected
source file, refreshes the saved guidance it can prove, and checks every target
from scratch. It may take several passes, but publishes the records, binaries,
debug companions, and report together only after the whole project is exact
and trustworthy. If it cannot prove the result, your source edit remains while
previously published records and results stay unchanged. No hand-written JSON
or TOML repair recipe is needed.

This is the maintenance path once a project has reached an exact match; a
project that builds but does not match yet starts with `discover grind`
instead. See [`rbit repair`](cli.md#rbit-repair) for report paths and advanced
search budgets.

To add a new file to the reviewed source list—or remove a locked one—start with
`rbit source preview .`; repair never silently admits newly tracked files.
Before the first import, preview prints a safe `source lock` command. After an
import, it normally prints `rbit import cmake . --refresh` instead. That command
prepares the new source list and CMake records privately, verifies every target
from scratch, and publishes the records, verified outputs, and report only as a
complete passing update. If it cannot keep the existing reviewed records safely,
it refuses without changing the published project. See
[Refreshing a CMake import](cmake.md#refresh-after-adding-or-removing-source-files).

## Reclaiming space

Failed builds keep a private workspace so problems can be inspected. Reclaim
those workspaces with `rbit clean .`; the reusable build cache is kept by
default. `rbit state status .` points out cache data the current ReproBit
version cannot reuse. Include it when cleaning inactive workspaces with
`rbit clean . --obsolete-cache --preview`; the current cache is kept. Use
`--cache` to clear the complete cache, or `--reports` to remove generated
verification and grind reports.

## CI and machine-readable output

ReproBit uses the remembered authenticated compiler and the locked host
launchers. CI can still pass explicit machine paths (`--toolchain-root`,
`--compiler-transport`/`--resource-transport`) and emit NDJSON with
`--format ndjson`; the [GitHub Action](action.md) packages the build-from-scratch
verification workflow. The event format is documented under
[Machine-readable output](cli.md#machine-readable-output).
