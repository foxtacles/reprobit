"""Stable receipts for the effective source tree used by CMake import."""

from __future__ import annotations

from pathlib import Path

from reprobit.classic_project import _effective_source_seal
from reprobit.model import Digest
from reprobit.strict_json import canonical_json


def effective_source_digest(root: Path) -> Digest:
    """Digest the complete path, size, and content receipt of an effective tree."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "files": [
                    {"path": path, "size": size, "sha256": sha256}
                    for path, size, sha256 in _effective_source_seal(root)
                ],
            }
        )
    )


__all__ = ["effective_source_digest"]
