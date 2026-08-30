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

The recommended [Automatic grind](grind/README.md) project prepares and
remembers the compiler with `rbit setup .`. The advanced declaration campaign
is not a ReproBit project, so its guide uses
`rbit toolchain provision msvc_4_2` instead.

## Available examples

- [Automatic grind](grind/README.md) **(recommended first)** — start with one
  unsolved compiler-entropy byte, find the lowest-cost matching declaration
  state, save its two small interventions, and confirm the result with a
  separate build from scratch.
- [Advanced declaration discovery](declaration-discovery/README.md) — prepare a
  local reference, run a preview-only bounded campaign, reuse completed work,
  extend it by one cell, and inspect its suggestions without changing a
  project.

Start with Automatic grind for the normal human workflow. The advanced campaign
is deliberately preview-only: it suggests evidence to review and does not edit
a project. Grind saves only a project-owned result that passes its logic checks
and an independent byte-for-byte build from scratch.
