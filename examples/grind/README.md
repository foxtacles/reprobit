# Grind one missing compiler intervention

This small project starts one byte away from its reference executable. The C++
is already correct; Microsoft Visual C++ 4.2 simply chooses a different register
encoding when it compiles the function.

ReproBit's bounded grind tries four declaration-only compiler states. Exactly one
of them reproduces the reference function. Accepting that result should save two
small reviewed records:

- a cheap declaration-shape donor; and
- an equal-body function intervention that uses only that freshly compiled donor.

The pair costs 26 relative points. The project already contains one independent
timestamp-normalization rule so repeated linker runs are deterministic.

## Run it

Prepare the compiler once, then run the example:

```console
rbit setup .
python prepare_reference.py
rbit discover grind .
rbit discover grind . --accept-exact
rbit verify .
```

`rbit setup` remembers the authenticated compiler location, so the other
commands need no machine-specific paths. If MSVC 4.2 is already set up on this
machine, skip that first line.

The first grind is a read-only preview. Review its report, then run the approval
command to repeat the proof and save the matching donor and function records
together. Both runs stop at the first exact, low-cost result that passes the
required logic checks. The
following `verify` is a separate cold build: it must not reuse a grind artifact
or the developer cache as certification evidence. Open
`.reprobit-state/reports/grind/report.html` to review the search funnel,
rejections, chosen state, and publication status. It links to the winning cold
verification report and canonical JSON stored beside it.

<details>
<summary>Advanced: pinned binary provenance</summary>

### What is deliberately unsolved

Before the grind, the clean `_transform` body is 137 bytes with SHA-256
`059b98332d6e22d42878a7921fdc7f294f0388d571fdde80a731be79b05f832b`.
The reference body is also 137 bytes, but byte 65 differs and its SHA-256 is
`0592ba1107856e319c261ed45129ab9b518486acbde960ada58b2ace9435ccfb`.
After timestamp normalization, that becomes one differing byte in the PE file at
offset 577. This equal-size, one-byte case intentionally exercises the smallest
classic donor path rather than resize, mosaic, binary surgery, or oracle copying.

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
