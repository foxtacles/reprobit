# Automatically find one missing compiler adjustment

This small project starts one byte away from its reference executable. The C++
is already correct; Microsoft Visual C++ 4.2 simply chooses a different register
encoding when it compiles the function.

The `grind` command runs a small automatic search over four declaration-only
compiler states. Exactly one
of them reproduces the reference function. Accepting that result should save two
small reviewed records:

- a cheap declaration-shape donor; and
- an equal-body function intervention that uses only that freshly compiled donor.

The pair costs 26 relative points. The project already contains one independent
timestamp-normalization rule so repeated linker runs are deterministic.

## Run it

From the ReproBit repository root, prepare the compiler once and run the
example:

```console
cd examples/grind
rbit setup .
python prepare_reference.py
rbit discover grind . --project-wide
rbit discover grind . --project-wide --accept-exact
rbit verify .
```

`rbit setup` remembers the authenticated compiler location, so the other
commands need no machine-specific paths. If MSVC 4.2 is already set up on this
machine, skip that first line.

The first grind is a read-only preview. Project-wide mode looks at committed
compiler steps and the available objects under `reference/`. This sample has
one of each, so no mapping or plan editing is needed. In a larger project,
name a reference object after its source filename without the extension, use an
exact translation-unit ID, or pair it explicitly with
`--reference-object TU=PATH`.

Review the report, then run the approval command to repeat the proof and save
only matching donor and function records. The search is deliberately bounded to
low-cost candidates; it aims for useful progress, not an exhaustive automatic
solution. The following `verify` is a separate build from scratch: it must not
reuse a grind artifact or the developer cache as certification evidence. Open
`.reprobit-state/reports/grind/project/report.html` for the campaign summary and
links to each per-function decision and winning build-from-scratch verification
report. The bounded plan behind every decision is kept beside the report, and
the page shows the exact copyable command for approval or final verification.

For one deliberately selected function, the original expert flow remains
available through `rbit discover init` followed by `rbit discover grind` without
`--project-wide`.

<details>
<summary>Advanced: pinned binary provenance</summary>

### What is deliberately unsolved

Before the grind, the clean `_transform` body is 137 bytes with SHA-256
`059b98332d6e22d42878a7921fdc7f294f0388d571fdde80a731be79b05f832b`.
The reference body is also 137 bytes, but byte 65 differs and its SHA-256 is
`0592ba1107856e319c261ed45129ab9b518486acbde960ada58b2ace9435ccfb`.
After timestamp normalization, that becomes one differing byte in the PE file at
offset 577. This equal-size, one-byte case intentionally exercises the smallest
classic donor path rather than resize, mosaic, binary surgery, or reference-byte
copying.

### Reference provenance

`prepare_reference.py` compiles this checked-in source with the campaign's
`classes=1, functions=10` declaration state, using the authenticated MSVC 4.2
toolchain pinned by `reprobit/toolchain.lock.json`. It links a minimal PE with no
libraries and normalizes only candidate-owned timestamp fields to zero. It then
checks the known reference function and final image digests before publishing:

- `reference/reference.obj`, used only as sealed discovery input; and
- `reference/grind.exe`, used only by the final literal verifier.

Those generated binaries are intentionally not committed or redistributed. The
normalized reference PE is 1,536 bytes with SHA-256
`9c78bd9cfe3c8ded8a9a587165237d2a394719b48be34021a3cb09aff8220aab`.
The compiler comes from
[`archaic-msvc/msvc420`](https://github.com/archaic-msvc/msvc420) with the two
runtime DLLs pinned from
[`archaic-msvc/msvc500`](https://github.com/archaic-msvc/msvc500), as recorded in
the lock file.

</details>
