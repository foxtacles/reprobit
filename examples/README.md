# ReproBit examples

These small projects are meant for experimentation and fast end-to-end checks.
They use only source files that are committed here; compiler outputs and local
state stay untracked.

## Prerequisites

- Python 3.11 or newer;
- ReproBit installed from this checkout (`python -m pip install -e .`);
- an authenticated [archaic-msvc](https://github.com/archaic-msvc) MSVC 4.2
  installation;
- Wine and `wineserver` on `PATH` when running on macOS or Linux.

The full [grind project](grind/README.md) can prepare and remember the compiler
with `rbit setup .`. The standalone declaration campaign is not a ReproBit
project; run `rbit toolchain provision msvc_4_2` once if no compiler location is
remembered yet, as shown in that example.

## Available examples

- [Declaration discovery](declaration-discovery/README.md) — prepare a local
  reference, run a bounded declaration search, reuse completed work, extend it
  by one cell, and review the resulting proposals.
- [Accepted grind](grind/README.md) — start with one unsolved compiler-entropy
  byte, find the lowest-cost matching declaration state, publish its two small
  interventions, and confirm the result with a separate cold build.

The general discovery example is deliberately noncertifying: it suggests
evidence to review and does not edit a project. The narrower grind example
accepts only a project-owned, semantically checked result that also passes an
independent cold byte-for-byte verification.
