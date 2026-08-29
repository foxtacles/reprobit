# ReproBit examples

These small projects are meant for experimentation and fast end-to-end checks.
They use only source files that are committed here; compiler outputs and local
state stay untracked.

## Prerequisites

- Python 3.11 or newer;
- ReproBit installed from this checkout (`python -m pip install -e .`);
- an [archaic-msvc](https://github.com/archaic-msvc) MSVC 4.2 installation;
- Wine and `wineserver` on `PATH` when running on macOS or Linux.

Set `REPROBIT_MSVC_4_2_ROOT` to your authenticated compiler installation before
running an example. No example depends on a machine-specific path.

## Available example

- [Declaration discovery](declaration-discovery/README.md) — prepare a local
  reference, run a bounded declaration search, reuse completed work, extend it
  by one cell, and review the resulting proposals.

Discovery is deliberately noncertifying. It suggests evidence to review; it
does not edit a project or approve an intervention.
