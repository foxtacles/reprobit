#!/usr/bin/env python3
"""Provision and authenticate ReproBit's external MSVC 4.2 toolchain."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from reprobit.msvc42_provision import (
    ProvisionError,
    provision_msvc42,
    verify_msvc42,
)

# Preserve the original script's import surface during the pre-release transition.
provision = provision_msvc42
verify = verify_msvc42


def _progress(message: str) -> None:
    print(f"[reprobit toolchain] {message}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        required=True,
        type=Path,
        help="new destination, or an existing exact toolchain to verify",
    )
    arguments = parser.parse_args()
    try:
        provision_msvc42(arguments.destination, progress=_progress)
    except (OSError, ProvisionError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
