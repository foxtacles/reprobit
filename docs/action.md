# GitHub Action

The ReproBit Action performs one build from scratch, checks its authenticity
claims, writes JSON and HTML reports, and fails the job when the selected policy
is not met. It installs ReproBit from the Action's own checkout, checks the
backend and toolchain, and then runs the project's direct compiler and linker
plan without CMake.

This page is the source of truth for Action setup, inputs, outputs, and failure
behavior. The generated [CLI option tables](cli-reference.md) cover commands
run outside the Action.

## Before you run it

The workflow that calls ReproBit must:

1. check out the project and provide Python 3.11 or newer;
2. provide a compiler installation that matches the committed lock—the
   authenticated provisioner is the normal way to prepare one—and provide any
   protected reference binaries at the paths named by `reprobit.toml`;
3. provide Wine launchers on macOS or Linux, when that backend is used; and
4. pass the physical toolchain directory to the Action.

The committed project chooses the compiler profile and verification policy. The
Action does not download, cache, upload, or redistribute proprietary compilers
or reference binaries. Use the same ReproBit release tag or commit for the CLI
and Action. Use maintained major-version tags for
third-party Actions.

## Example

This complete example uses the native Windows runner and shows only the inputs
needed for the normal path. It assumes the protected reference binaries are
already present; add the project's secret/download step before ReproBit when
they are not committed. This example pins both installations to ReproBit `0.1.3`:

```yaml
name: Verify with ReproBit

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  verify:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.11"
      - name: Install the pinned ReproBit CLI for provisioning
        run: >-
          python -m pip install
          "git+https://github.com/isledecomp/reprobit.git@0.1.3"
      - name: Provision and authenticate MSVC 4.2
        run: >-
          rbit toolchain provision
          --destination "${{ runner.temp }}/msvc42"
          --no-save
      - id: reprobit
        uses: isledecomp/reprobit@0.1.3
        with:
          project-directory: .
          toolchain-root: ${{ runner.temp }}/msvc42
      - name: Preserve ReproBit evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: reprobit-report
          path: build/reprobit-report
          if-no-files-found: warn
```

The first ReproBit install makes `rbit toolchain provision` available before
the Action starts. The Action then installs the same pinned checkout for its
verification step. Omitted inputs use the project policy, four workers, bounded
default timeouts, and `build/reprobit-report`.

<details>
<summary>Optional: narrow policy or tune parallelism and timeouts</summary>

Add only the controls your runner actually needs:

```yaml
with:
  # Keep the required toolchain input shown above.
  jobs: 4
  policy: clean
  initialization-timeout: 600
  compile-timeout: 600
  link-timeout: 900
  cleanup-timeout: 10
  report-directory: build/reprobit-report
```

`policy: clean` can only narrow a project that permits quarantine; it cannot
make a clean project less strict. The four timeouts separately limit setup,
compiler/resource work, librarian/linker work, and cleanup.

</details>

On macOS and Linux, install Wine first and add `compiler-transport` and
`resource-transport` for the two locked launchers inside the supplied toolchain
root. Supply both or neither. Leave both empty on native Windows and follow the
[native Windows guide](windows.md) for compiler setup and private-drive
guarantees.

`jobs` limits total parallel work.

## Policy

With no `policy` input, the Action uses the policy committed by the project. An
explicit `clean` input may narrow a project that otherwise permits quarantine;
an Action input can never broaden the committed policy.

`allow-quarantine` is not a general relaxed mode. Byte equality and logic
certification must still pass, and only the project's exact, non-growing
reference-byte exception allowlist may run. The report then states that
toolchain origin did not pass.

## Outputs and failures

The Action exports:

| Output | Meaning |
| --- | --- |
| `report-produced` | This run published and validated its canonical reports. |
| `accepted` | The result met the selected policy. |
| `clean` | Every clean-authenticity claim passed. |
| `byte-exact` | Every selected candidate matched its reference bytes. |
| `logic-certified` | Every intervention passed its required checks. |
| `toolchain-origin` | First-party program bytes came from the declared toolchain. |
| `quarantined` | An allowlisted reference-byte exception ran. |
| `quarantine-count` | Number of declared reference-byte exceptions used. |
| `quarantine-bytes` | Total reference bytes covered by those exceptions. |
| `quarantine-ranges` | Total artifact ranges covered by those exceptions. |
| `quarantine-digest` | SHA-256 identity of the stable declared exception boundary. |
| `total-cost` | Total intervention cost in relative points for the project. |
| `report-json` | Path to the canonical JSON report. |
| `report-html` | Path to the self-contained HTML report. |

If verification stops before a validated report exists, `report-produced` is
`false`. Report-derived outputs stay empty instead of looking like successful
zero values. The summary still runs and includes a bounded reason when current
evidence is missing or invalid. The final Action step requires successful
verification, validated current reports, and policy acceptance; a successful
verification command cannot hide a later report-validation failure. Upload the
report directory with `if: always()` so an independent failed claim remains
inspectable.

Projects that intentionally permit quarantine should assert the expected count,
byte total, range total, and digest. That turns a reviewed exception set into a
non-growing CI boundary instead of checking only that some quarantine occurred.
The digest covers each exception's identity, target, coordinates, size, reason,
and scope. Per-run proof bindings remain fully audited and visible in the report,
but are excluded from this boundary fingerprint so the same reviewed policy has
the same identity on every machine and invocation.

## Protection against stale reports

Every invocation creates a random nonce and keeps its completion receipt outside
the reusable project workspace. Verification publishes that receipt only after
the JSON report and matching HTML rendering both exist. The summary accepts the
report only when the nonce, run ID, and both file digests agree.

This means a report from an earlier self-hosted run, or a partially written
report, is treated as missing rather than reused as current evidence. Inputs are
passed through environment values rather than interpolated into shell programs.

## Optional extra evidence

A project with a `source_overlay_graph` may request extra evidence-only compiles
for declaration changes. Each extra compile has the same `compile-timeout`; a
project without that graph pays no extra compiler work.

## What ReproBit's own CI proves

Portable CI validates the Action metadata and installed package. A dedicated
`windows-2022` job also provisions and authenticates the external Archaic MSVC
4.2 files, tests the native private-drive lifecycle, and runs the real compiler
child chain. Native and Wine jobs cache the compiler tree under a key derived
from its authentication pins and re-authenticate every file before use. Failure
artifacts contain runner identity and diagnostic logs; release assets contain
the ReproBit sdist and wheel. Neither includes the external compiler tree.

That is framework evidence, not certification of a consuming project. Trust a
specific runner and toolchain only after its own `rbit doctor --execute-probe`
and build-from-scratch Action fixture pass.
