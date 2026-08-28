# GitHub Action

The repository root is a composite Action. A consuming workflow provisions its compiler,
reference images, Wine transport when needed, and Python 3.11 or newer, then supplies the physical
toolchain root. The committed project selects the toolchain profile. The Action installs ReproBit
from its own immutable checkout, runs a backend check, performs a cold direct-producer
verification, writes JSON and HTML reports, and exports authenticity and cost outputs.

By default the Action uses the project's committed policy. An explicit `clean`
input can narrow a project that admits quarantine. `allow-quarantine` still
requires byte equality and logic certification, but permits only the exact
non-growing legacy allowlist while reporting that toolchain origin failed.

The Action does not download or redistribute proprietary tools or reference binaries.

Pin every Action by an immutable commit and provision the compiler before calling ReproBit. This
example targets a POSIX/Wine runner:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
    with:
      python-version: "3.11"
  - name: Provision private compiler inputs
    run: ./ci/provision-toolchain
  - id: reprobit
    uses: owner/reprobit@0123456789abcdef0123456789abcdef01234567
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
admitted host launchers inside the supplied toolchain root. Supply both or
neither. Native Windows leaves both inputs empty. Its controller validates
sealed physical roots; logical-drive paths exist only inside producer trees.
Those trees run through a contained broker with a freshly proved logon-session
`AuthenticationId`; `DefineDosDeviceW` creates the drive only in that isolated
session. Each real producer starts suspended, joins a nested kill-on-close Job
Object, and resumes only after admission. The broker keeps the mapping until
the complete producer Job is empty. The required pre-build probe fails unless
that path remains visible to a descendant. Treat this path as certified only
after that probe and the pinned Windows compiler gate pass on the intended
runner. The four timeout inputs independently bound lane
initialization, each compiler/resource process, each librarian/linker process,
and lane cleanup. CMake is not installed or invoked by the Action.

A project-level `source_overlay_graph` derives one declaration counterfactual.
Declaration-only leaves add no compiler work; strict semantic-delta leaves add
an evidence-only compile for each exact source owner, while a strict header
conservatively selects all ordinary compilers. The Action pairs those sparse
results with effective primary products before overlay receipts can carry the
`certified-project-overlay` origin. Each compile remains independently bounded
by `compile-timeout`; projects without that overlay do not pay this extra cost.

The exported values are `report-produced`, `accepted`, `clean`, `byte-exact`,
`logic-certified`, `toolchain-origin`, `quarantined`, `total-cost`, `report-json`,
and `report-html`. If verification stops before a validated report exists,
`report-produced` is `false` and unknown report-derived values are empty rather
than being presented as successful zero values. The Action passes inputs as
environment values rather than interpolating them into a shell program. Upload
the report directory with `if: always()` so a failed independent claim remains
inspectable.

Each Action invocation creates a fresh random nonce and stores its completion
receipt outside the reused project workspace. The verification step publishes
that receipt only after both the canonical JSON report and the exact HTML
rendering exist and agree. The summary step requires the nonce, report run ID,
and both file digests to match. A report left by an earlier self-hosted run—or a
JSON-only partial publication—is therefore reported as missing, never reused as
current evidence. The composite passes the nonce and receipt path directly to
`rbit verify` as `--action-nonce` and `--action-receipt`; the same verification
process commits the receipt before returning either an accepted status or the
original policy-rejection status.

Public CI checks the Action metadata and portable package. Its dedicated
`windows-2022` job also provisions the pinned external Archaic MSVC authority,
authenticates it, and exercises the native lineage drive plus CL child chain without
caching or uploading compiler bytes. That gate remains conditional evidence:
treat a particular runner/toolchain pairing as ready only after its own
`rbit doctor --execute-probe` and cold Action fixture pass.
