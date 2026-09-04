<p align="center">
  <img src="docs/assets/reprobit-mark.svg" width="168" alt="ReproBit: a dot-matrix R assembled from individual bits">
</p>

<h1 align="center">ReproBit</h1>

**Rebuild old software exactly—and show why the result can be trusted.**

ReproBit helps decompilation projects reproduce an original executable byte for byte with its
original compiler. It controls the small, often invisible details that make an old toolchain emit
different bytes, then records how every output was made.

The result is more than a matching checksum. ReproBit checks three separate claims:

1. the rebuilt file is literally identical to the reference file;
2. every special adjustment used to reach that match preserved the program's logic; and
3. the rebuilt program came from the declared source and toolchain, not bytes copied from the
   original executable.

ReproBit is pre-release software. It recognizes profiles for Microsoft Visual C++ 4.2 and the
5.0 releases. Current end-to-end evidence with the real compiler and native Windows CI covers
4.2; the 5.0 profiles are modeled, but do not yet carry equivalent end-to-end proof. The shared
build, verification, reporting, and incremental pieces are designed to support more compiler
families through reviewed library releases.

## Install

You need Python 3.11 or newer and Git. CMake import and later source-list
refreshes need your project's compatible CMake version on `PATH`. On macOS and
Linux, install Wine and `wineserver`; native Windows does not use Wine.

```console
git clone https://github.com/isledecomp/reprobit.git
cd reprobit
python -m venv .venv
source .venv/bin/activate
python -m pip install .
rbit --version
```

In Windows PowerShell, replace the activation line with `.\.venv\Scripts\Activate.ps1`,
then run the same `python -m pip install .` and `rbit --version` commands. Keep
the environment active while using `rbit` in your own project.

ReproBit runs with Wine on macOS and Linux and natively on Windows. It can fetch and authenticate
the supported MSVC 4.2 files from the pinned archaic-msvc repositories, or use an existing local
installation. Reference binaries remain project-owned and are never redistributed by ReproBit.

## Quick start

The [grind example](examples/grind/README.md) is a one-function project that starts one byte
away from its reference executable. From the repository root, with the environment active:

```console
cd examples/grind
rbit setup .
python prepare_reference.py
rbit discover grind .
rbit discover grind . --accept-exact
rbit verify .
```

`setup` downloads and authenticates the compiler the first time, remembers where it is, and
prints the one remaining checklist item: `place the original at reference/grind.exe`.
`prepare_reference.py` generates both the reference executable and the project-owned `.obj`
that automatic grind needs. The first `discover grind` is a read-only preview: it compiles four
bounded declaration candidates, finds the one exact match, and prints the approval command.
`--accept-exact` repeats the proof and saves the matching intervention and proof records
(`git diff` shows both files). `verify` then builds from scratch and ends with:

```text
Verification passed: 1/1 targets are byte-identical
Authenticity: clean; every required claim passed
Intervention cost: 31 relative points
Report: .../examples/grind/.reprobit-state/reports/report.html
```

Open that `report.html` in a browser for the full evidence.

## Everyday commands

In a project that already has its ReproBit records committed:

```console
rbit status .                                   # what, if anything, is still missing
rbit build .                                    # incremental developer build
rbit verify . --report-dir build/reprobit-report  # build from scratch, write the trust report
rbit repair .                                   # after editing a file the project already tracks
```

`status` names the next missing setup item instead of making you remember the sequence.
`build` reuses cached steps whose inputs are unchanged. `verify` never uses that cache and is
the only certification path. `repair` updates the saved records affected by a source edit,
rebuilds every target from scratch, and publishes the result only when it is still exact. Pass
`--format ndjson` to any command for machine-readable events.

To bring a new CMake project under ReproBit, follow [Getting started](docs/getting-started.md).

## The LEGO Island reference case

ReproBit grew out of byte-identity work on the
[LEGO Island decompilation](https://github.com/isledecomp/isle). That project rebuilds a 1997 game
with Microsoft Visual C++ 4.2. It illustrates the gap between two important finish lines:

- **Complete decompilation:** the recovered C++ behaves like the original game.
- **Byte-identical decompilation:** the old compiler also emits the exact original executable and
  DLL, down to every byte.

A function can be logically correct while compiler bookkeeping places or describes it
differently. Paths that were visible to the compiler in 1997 matter. So can declaration order,
shared debug state, parallel compiler processes, and link order.
For a visual explanation, the LEGO Island development video covers
[compiler entropy starting at 9:03](https://youtu.be/gthm-0Av93Q?t=543s).
The campaign exposed these issues at real-project scale; ReproBit packages the resulting controls
and checks into a reusable library. The project's source, targets, and interventions remain in the
decompilation repository rather than being built into ReproBit.

## Documentation

Choose the page for the job at hand. [Getting started](docs/getting-started.md)
owns the setup sequence and stays on the happy path. The
[command-line guide](docs/cli.md) explains command behavior, while its generated
[option tables](docs/cli-reference.md) are the exact source for flags and defaults.
Workflow guides cover their own end-to-end behavior, and
[Troubleshooting](docs/troubleshooting.md) is reserved for recovering from failures.

Start here:

- [Getting started](docs/getting-started.md) — from an existing CMake project to a verified build
- [Concepts](docs/concepts.md) — compiler entropy, the clean verification boundary, costs
- [Runnable examples](examples/README.md)
- [Command-line guide](docs/cli.md) and the generated [option tables](docs/cli-reference.md)
- [Find possible compiler interventions](docs/discovery.md)
- [GitHub Action](docs/action.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Glossary](docs/glossary.md)

Detailed references:

- [Authenticity and threat model](docs/authenticity.md)
- [Project format](docs/project-format.md)
- [Interventions](docs/interventions.md)
- [Cost model](docs/costs.md)
- [Platforms and logical paths](docs/platforms.md)
- [Native Windows and external MSVC setup](docs/windows.md)
- [CMake import and refresh](docs/cmake.md)
- [Architecture](docs/architecture.md)

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test layout and the quality gates.

```console
python -m pip install -e '.[test]'
ruff check && ruff format --check && mypy && python -m pytest -q
```

ReproBit is licensed under `LGPL-3.0-only`.
