"""Portable POSIX no-clobber rename for entries beneath one held directory."""

from __future__ import annotations

import ctypes
import errno
import os
import sys


def rename_noreplace_between(
    source_parent: int,
    source: str,
    destination_parent: int,
    destination: str,
) -> None:
    """Atomically rename one held entry while refusing an existing destination."""

    library = ctypes.CDLL(None, use_errno=True)
    arguments = (
        source_parent,
        os.fsencode(source),
        destination_parent,
        os.fsencode(destination),
    )
    if sys.platform == "darwin" and hasattr(library, "renameatx_np"):
        rename = library.renameatx_np
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        received = rename(*arguments, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        received = rename(*arguments, 0x00000001)  # RENAME_NOREPLACE
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-replace rename is unavailable on this host",
            destination,
        )
    if received != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def rename_noreplace_at(parent: int, source: str, destination: str) -> None:
    """Atomically rename one sibling while refusing an existing destination."""

    rename_noreplace_between(parent, source, parent, destination)


__all__ = ["rename_noreplace_at", "rename_noreplace_between"]
