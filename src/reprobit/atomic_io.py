"""Crash-safe whole-file replacement for small state and settings files.

The writer creates an exclusive private temporary sibling, flushes its
contents to stable storage, renames it over the destination, and then
flushes the parent directory so the rename itself is durable.  Callers
that walk a held directory chain use ``secure_paths`` instead; this
module serves paths the caller already trusts.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from reprobit.strict_json import canonical_json


def _fsync_directory(path: str | os.PathLike[str]) -> None:
    """Flush one directory's entries to stable storage (no-op on Windows)."""

    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


fsync_directory = _fsync_directory


def write_bytes_atomic(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    fsync_directory: bool = True,
) -> None:
    """Replace ``path`` with ``data`` through a durable private temporary."""

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if fsync_directory:
            _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def write_json_atomic(
    path: Path,
    value: object,
    *,
    mode: int = 0o600,
    fsync_directory: bool = True,
) -> None:
    """Replace ``path`` with the canonical JSON encoding of ``value``."""

    write_bytes_atomic(path, canonical_json(value), mode=mode, fsync_directory=fsync_directory)


__all__ = ["fsync_directory", "write_bytes_atomic", "write_json_atomic"]
