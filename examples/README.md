# ReproBit examples

These small projects are meant for experimentation and fast end-to-end checks.
They use only source files that are committed here; compiler outputs and local
state stay untracked.

## Prerequisites

- Python 3.11 or newer;
- ReproBit installed from this checkout (`python -m pip install -e .`);
- internet access for `rbit setup` to fetch and authenticate MSVC 4.2, or an
  existing matching installation;
- Wine and `wineserver` on `PATH` when running on macOS or Linux.

The full [grind project](grind/README.md) prepares and remembers the compiler
with `rbit setup .`. The standalone declaration campaign is not a ReproBit
project, so its guide uses `rbit toolchain provision msvc_4_2` instead.

## Available examples

- [Declaration discovery](declaration-discovery/README.md) — prepare a local
  reference, run a bounded declaration search, reuse completed work, extend it
  by one cell, and review the resulting proposals.
- [Automatic grind](grind/README.md) — start with one unsolved compiler-entropy
  byte, find the lowest-cost matching declaration state, save its two small
  interventions, and confirm the result with a separate build from scratch.

The general discovery example is deliberately preview-only: it suggests
evidence to review and does not edit a project. The narrower grind example
saves only a project-owned result that passes its logic checks and an
independent byte-for-byte build from scratch.
