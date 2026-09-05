"""Refuse a release tag that does not name the packaged version.

``python scripts/check_release_tag.py 1.2.3`` exits 0 only when the tag names
exactly the version that ``pyproject.toml`` declares and ``reprobit`` reports.
The historical ``v`` prefix is also accepted.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import reprobit

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        raise SystemExit("usage: check_release_tag.py TAG")
    tag = argv[1]
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if declared != reprobit.__version__:
        raise SystemExit(
            f"pyproject.toml declares {declared} but reprobit reports {reprobit.__version__}"
        )
    if tag not in {declared, f"v{declared}"}:
        raise SystemExit(
            f"tag {tag} does not name the packaged version {declared} "
            f"(expected {declared} or v{declared})"
        )
    print(f"tag {tag} names the packaged version {declared}")


if __name__ == "__main__":
    main(sys.argv)
