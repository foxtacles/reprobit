# GitHub Action

The ReproBit Action performs one cold build, checks its authenticity claims,
writes JSON and HTML reports, and fails the job when the selected policy is not
met. It installs ReproBit from the Action's own checkout, checks the backend and
toolchain, and then runs the project's direct compiler and linker plan without
CMake.

## Before you run it

The workflow that calls ReproBit must:

1. check out the project and provide Python 3.11 or newer;
2. run ReproBit's authenticated compiler provisioner and provide any protected
   reference files;
3. provide Wine launchers on macOS or Linux, when that backend is used; and
4. pass the physical toolchain directory to the Action.

The committed project chooses the compiler profile and verification policy. The
Action does not download, cache, upload, or redistribute proprietary compilers
or reference binaries. Pin ReproBit and every other Action to an immutable
commit.

## Example

This example uses a POSIX runner with Wine:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
    with:
      python-version: "3.11"
  - name: Install the pinned ReproBit CLI
    run: >-
      python -m pip install
      "git+https://github.com/foxtacles/reprobit.git@0123456789abcdef0123456789abcdef01234567"
  - name: Provision and authenticate MSVC 4.2
    run: >-
      rbit toolchain provision
      --destination "${{ runner.temp }}/msvc42"
      --no-save
  - id: reprobit
    uses: foxtacles/reprobit@0123456789abcdef0123456789abcdef01234567
    with:
      project-directory: .
      toolchain-root: ${{ runner.temp }}/msvc42
      compiler-transport: ${{ runner.temp }}/msvc42/wine/x86/cl
      resource-transport: ${{ runner.temp }}/msvc42/wine/x86/rc
      jobs: 4
      policy: clean # optional narrowing override
      initialization-timeout: 600
      compile-timeout: 600
      link-timeout: 900
      cleanup-timeout: 10
      report-directory: build/reprobit-report
  - name: Preserve ReproBit evidence
    if: always()
    uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
    with:
      name: reprobit-report
      path: build/reprobit-report
      if-no-files-found: warn
```

On macOS and Linux, `compiler-transport` and `resource-transport` name the two
locked host launchers inside the supplied toolchain root. Supply both or neither.
Leave both empty on native Windows and follow the [native Windows guide](windows.md)
for compiler setup and private-drive guarantees.

The four timeout inputs separately limit lane setup, each compiler or resource
process, each librarian or linker process, and lane cleanup. `jobs` limits total
parallel work.

## Policy

With no `policy` input, the Action uses the policy committed by the project. An
explicit `clean` input may narrow a project that otherwise permits quarantine;
an Action input can never broaden the committed policy.

`allow-quarantine` is not a general relaxed mode. Byte equality and logic
certification must still pass, and only the project's exact, non-growing legacy
allowlist may run. The report then states that toolchain origin did not pass.

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
| `quarantined` | An allowlisted legacy action ran. |
| `total-cost` | Total intervention cost in relative points for the project. |
| `report-json` | Path to the canonical JSON report. |
| `report-html` | Path to the self-contained HTML report. |

If verification stops before a validated report exists, `report-produced` is
`false`. Report-derived outputs stay empty instead of looking like successful
zero values. The summary still runs, and the final Action step fails the job
when verification failed. Upload the report directory with `if: always()` so an
independent failed claim remains inspectable.

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
child chain without caching or uploading compiler bytes.

That is framework evidence, not certification of a consuming project. Trust a
specific runner and toolchain only after its own `rbit doctor --execute-probe`
and cold Action fixture pass.
