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

## Install and set up the pre-release

Python 3.11 or newer is required.

```console
python -m venv .venv
.venv/bin/python -m pip install /path/to/reprobit
.venv/bin/rbit --version
```

Those last two paths are `.venv\Scripts\python.exe` and `.venv\Scripts\rbit.exe` in Windows
PowerShell. Activate the environment instead if that is your usual workflow.

ReproBit runs with Wine on macOS and Linux and natively on Windows. It can fetch and authenticate
the supported MSVC 4.2 files from the pinned archaic-msvc repositories, or use an existing local
installation. Reference binaries remain project-owned and are never redistributed by ReproBit.

### Project setup outline

Start a project and prepare the current machine with the human-first setup command:

```console
rbit init . --project-id sample --profile msvc_4_2
rbit setup .
rbit status .
```

`setup` downloads the compiler when needed, authenticates it, remembers its location, creates or
checks the project lock, and tests the host backend. Pass `--toolchain-root /path/to/msvc42` to use
an existing installation. `status` shows the next incomplete project step instead of requiring you
to remember the setup sequence.

Each project still needs its own source lock, build plan, reference metadata, and producer graph.
Existing CMake projects use CMake once to import their direct compiler and linker commands; normal
ReproBit builds do not invoke it. The [command-line workflow](docs/cli.md) explains those project
files, while [platform setup](docs/platforms.md) and the
[native Windows guide](docs/windows.md) cover unusual hosts.

Once those files are committed, the everyday commands are:

```console
rbit validate .
rbit build .
rbit verify . --report-dir build/reprobit-report
```

ReproBit uses the remembered authenticated compiler and the locked host launchers. CI can still
pass explicit machine paths and emit NDJSON. Use `rbit build . --cold` for a non-certifying
developer build with no cache reads or writes.

## Why exact rebuilds are difficult

Two builds can behave the same and still produce different files. Older compilers may let source
paths, declaration order, object order, debug history, temporary filenames, library scan order,
or other incidental state influence the output. We call that **compiler entropy**: information
that is not part of the program's intended behavior but still changes its bytes.

```mermaid
flowchart TB
    accTitle: How compiler entropy changes a build
    accDescr: The same code enters two builds with different incidental state, so the files do not match.

    subgraph RA["Run A · same program"]
        direction LR
        I1(["Path, order, and state A"]) --> A["Build"] --> X(["Bytes A"])
    end
    subgraph RB["Run B · same program"]
        direction LR
        I2(["Path, order, and state B"]) --> B["Build"] --> Y(["Bytes B"])
    end
    X --> C{"Exact match?"}
    Y --> C
    C -->|"No"| D(["Different files"])

    classDef input fill:#eef2ff,stroke:#6366f1,color:#111827,stroke-width:1.5px
    classDef process fill:#ecfeff,stroke:#0891b2,color:#111827,stroke-width:1.5px
    classDef decision fill:#fffbeb,stroke:#d97706,color:#111827,stroke-width:1.5px
    classDef artifact fill:#f8fafc,stroke:#64748b,color:#111827,stroke-width:1.5px
    classDef mismatch fill:#fef2f2,stroke:#dc2626,color:#111827,stroke-width:1.5px
    class I1,I2 input
    class A,B process
    class C decision
    class X,Y artifact
    class D mismatch
    style RA fill:transparent,stroke:#94a3b8,stroke-width:1.5px
    style RB fill:transparent,stroke:#94a3b8,stroke-width:1.5px
```

_In words: equivalent source can produce different binary files when incidental compiler inputs
change._

ReproBit turns those hidden influences into declared, repeatable build inputs. When a project
needs a small intervention to guide the compiler, it must use one of ReproBit's reviewed,
versioned operations and pass that operation's current-run checks. Project files describe the
work as data; they cannot inject arbitrary Python into a certified build.

## The LEGO Island reference case

ReproBit grew out of byte-identity work on the
[LEGO Island decompilation](https://github.com/isledecomp/isle). That project rebuilds a 1997 game
with Microsoft Visual C++ 4.2. It illustrates the gap between two important finish lines:

- **Functional decompilation:** the recovered C++ behaves like the original game.
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

## What a clean result means

A matching file alone cannot reveal whether someone copied bytes from the original, reused stale
output, or made an unverified source change. ReproBit therefore reports independent answers:

- **Byte exact:** candidate and reference have the same bytes.
- **Logic certified:** each non-ordinary adjustment passed its specific preservation checks in
  this run.
- **Toolchain origin:** the program's own code and data can be traced back to declared outputs of
  the compiler, resource compiler, librarian, and linker.

In the clean path, the part that produces the candidate cannot read the reference file. A
separate verifier receives the finished candidate and the protected reference only after
production, performs the literal comparison, and writes the report.

```mermaid
flowchart LR
    accTitle: ReproBit's clean verification boundary
    accDescr: The producer cannot see the reference. The verifier compares it with the candidate and reports.

    subgraph P["1 · Produce — no reference access"]
        direction LR
        S(["Recorded source"]) --> B["Controlled build"]
        T(["Recorded toolchain"]) --> B
        B --> C(["Candidate"])
    end
    subgraph V["2 · Verify — reference allowed"]
        direction LR
        R(["Protected reference"]) --> Q["Compare bytes<br/>and check evidence"]
        Q --> O(["Trust report"])
    end
    C --> Q
    P ~~~ V

    classDef input fill:#eef2ff,stroke:#6366f1,color:#111827,stroke-width:1.5px
    classDef process fill:#ecfeff,stroke:#0891b2,color:#111827,stroke-width:1.5px
    classDef artifact fill:#f8fafc,stroke:#64748b,color:#111827,stroke-width:1.5px
    classDef result fill:#ecfdf5,stroke:#059669,color:#111827,stroke-width:1.5px
    classDef reference fill:#faf5ff,stroke:#8b5cf6,color:#111827,stroke-width:1.5px
    class S,T input
    class B,Q process
    class C artifact
    class O result
    class R reference
    style P fill:transparent,stroke:#94a3b8,stroke-width:1.5px
    style V fill:transparent,stroke:#94a3b8,stroke-width:1.5px
```

_In words: on the clean path, the original binary is available only to the final verifier, never
as material for the producer._

A verdict is **clean** only when all three claims pass, the verification build starts cold, and no
explicitly quarantined legacy shortcut runs. See the
[authenticity model](docs/authenticity.md) for the exact guarantees and trust boundary.

## Fast enough for everyday iteration

Exact verification should be strict; editing should still feel ordinary. `rbit build` is an
incremental developer build. It reuses a stored result only when every relevant input still
matches, then rebuilds the affected compiler steps and their downstream archive or link steps.
An unchanged build can finish without starting the compiler environment at all. Affected work can
run in parallel, while separate work areas keep compiler scratch and debug state from leaking
between jobs.

`rbit verify` is deliberately different: it always performs a fresh, cold build and never treats
the developer cache as certification evidence.

```mermaid
flowchart TB
    accTitle: ReproBit's incremental build loop
    accDescr: After an edit, valid steps are restored, affected steps run again, and ReproBit reports.

    E(["Edit source or project data"]) --> K["Re-check declared inputs"]
    K --> D{"Step still valid?"}
    D -->|"Yes"| H["Restore cached result"]
    D -->|"No"| M["Run affected steps"]
    H --> F(["Target ready"])
    M --> F
    F --> U["Report reuse, rebuild reasons, and time"]
    U -. "Next edit" .-> E

    classDef input fill:#eef2ff,stroke:#6366f1,color:#111827,stroke-width:1.5px
    classDef process fill:#ecfeff,stroke:#0891b2,color:#111827,stroke-width:1.5px
    classDef decision fill:#fffbeb,stroke:#d97706,color:#111827,stroke-width:1.5px
    classDef result fill:#ecfdf5,stroke:#059669,color:#111827,stroke-width:1.5px
    class E input
    class K,H,M,U process
    class D decision
    class F result
```

_In words: each edit invalidates only the dependent work; the CLI explains what it reused and
what it rebuilt._

Interactive terminals get a progress bar with elapsed time. Redirected text logs receive regular
heartbeats, and `rbit --format ndjson ...` emits stable machine-readable progress events for CI
and other tools. The [GitHub Action](docs/action.md) runs the cold verification workflow and
exports the individual authenticity results.

## Measure how much help the build needs

ReproBit assigns a **cost** to each entropy intervention. The score measures distance from an
ordinary build, not runtime or money: harmless compiler-state declarations are cheap, while
donors, semantic rewrites, and binary transformations cost progressively more. The ideal score is
zero—the checked-in source, built normally by the original toolchain, already matches.

```console
rbit cost .
rbit explain . --intervention intervention-id
```

Costs make remaining compromises visible and give contributors a concrete way to simplify a
project over time. See the [cost model](docs/costs.md) for the fixed categories and accounting
rules.

## Project files

ReproBit keeps the reusable machinery in this package and project-specific facts beside the
decompilation source:

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

The [project format](docs/project-format.md) explains each file. Large intervention and proof sets
can be split into small reviewable documents.

## Documentation

- [Runnable examples](examples/README.md)
- [Command-line workflow](docs/cli.md)
- [Find possible compiler interventions](docs/discovery.md)
- [Authenticity and threat model](docs/authenticity.md)
- [Architecture](docs/architecture.md)
- [Project format](docs/project-format.md)
- [Cost model](docs/costs.md)
- [Platforms and logical paths](docs/platforms.md)
- [Native Windows and external MSVC setup](docs/windows.md)
- [One-time CMake import](docs/cmake.md)
- [GitHub Action](docs/action.md)
- [Migration](docs/migration.md)
- [Troubleshooting](docs/troubleshooting.md)

## Development

```console
python -m pip install -e '/path/to/reprobit[test]'
pytest
ruff check src tests
mypy src/reprobit
```

ReproBit is licensed under `LGPL-3.0-only`.
