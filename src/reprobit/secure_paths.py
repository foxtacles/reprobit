"""Public orchestration for handle-relative reads and atomic publication.

Security-sensitive project paths are never traversed by repeatedly resolving
host path strings.  The public operations in this module validate portable
arguments and dispatch to the native handle-relative implementation for the
current platform.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

import reprobit.secure_paths_posix as _posix
import reprobit.secure_paths_windows as _windows
from reprobit.model import Digest
from reprobit.secure_path_contracts import (
    SecureFileIdentity,
    SecureFileSnapshot,
    SecurePathError,
)


def windows_attributes_are_basic_restorable(attributes: int) -> bool:
    """Return whether FileBasicInfo can exactly recreate native attributes."""

    return _windows.windows_attributes_are_basic_restorable(attributes)


def read_relative_file(root: Path, relative: str) -> tuple[bytes, SecureFileSnapshot]:
    """Read one regular file through a fully held, no-follow ancestor chain."""

    if os.name == "nt":
        return _windows.read_relative_file(root, relative)
    return _posix.read_relative_file(root, relative)


def atomic_publish_new_relative_from_stream(
    root: Path,
    relative: str,
    source: BinaryIO,
    *,
    executable: bool = False,
    mode: int | None = None,
    windows_attributes: int | None = None,
    expected_digest: Digest | None = None,
    expected_size: int | None = None,
) -> SecureFileSnapshot:
    """Stream one immutable file into place without replacing an entry.

    At most one fixed-size block is requested from ``source`` at a time.  The
    content digest is computed while writing, the file is fsynced, and the
    commit is a handle-relative atomic create-if-absent.  The held output
    handle and named entry are identity-checked without rereading the bytes.
    """

    if type(executable) is not bool:
        raise TypeError("secure publication executable flag must be bool")
    if mode is not None and (type(mode) is not int or not 0 <= mode <= 0o777):
        raise ValueError("secure publication mode must be POSIX permissions")
    if mode is not None and executable:
        raise ValueError("secure publication cannot combine mode and executable")
    if windows_attributes is not None and (
        type(windows_attributes) is not int or windows_attributes < 0
    ):
        raise ValueError("secure publication Windows attributes must be non-negative")
    if expected_digest is not None and not isinstance(expected_digest, Digest):
        raise TypeError("secure publication expected digest must be Digest")
    if expected_size is not None and (
        not isinstance(expected_size, int) or isinstance(expected_size, bool)
    ):
        raise TypeError("secure publication expected size must be int")
    if expected_size is not None and expected_size < 0:
        raise ValueError("secure publication expected size cannot be negative")
    if os.name == "nt":
        if mode is not None:
            raise SecurePathError("native Windows publication cannot set POSIX mode")
        return _windows.atomic_publish_new_relative_from_stream(
            root,
            relative,
            source,
            executable=executable,
            windows_attributes=windows_attributes,
            expected_digest=expected_digest,
            expected_size=expected_size,
        )
    if windows_attributes is not None:
        raise SecurePathError("POSIX publication cannot set Windows attributes")
    return _posix.atomic_publish_new_relative_from_stream(
        root,
        relative,
        source,
        mode=mode if mode is not None else (0o755 if executable else 0o644),
        expected_digest=expected_digest,
        expected_size=expected_size,
    )


def stat_relative_file(root: Path, relative: str) -> SecureFileIdentity:
    """Inspect one regular file through a held ancestor chain without reading it."""

    if os.name == "nt":
        return _windows.stat_relative_file(root, relative)
    return _posix.stat_relative_file(root, relative)


def digest_relative_file(root: Path, relative: str) -> SecureFileSnapshot:
    """Hash one regular file through a held ancestor chain with bounded memory."""

    if os.name == "nt":
        return _windows.digest_relative_file(root, relative)
    return _posix.digest_relative_file(root, relative)


def atomic_copy_new_relative(
    source_root: Path,
    source_relative: str,
    destination_root: Path,
    destination_relative: str,
    *,
    executable: bool = False,
    expected_digest: Digest | None = None,
    expected_size: int | None = None,
    expected_source: SecureFileIdentity | None = None,
) -> SecureFileSnapshot:
    """Copy one held source to a new held destination in a single pass."""

    if os.name == "nt":
        return _windows.atomic_copy_new_relative(
            source_root,
            source_relative,
            destination_root,
            destination_relative,
            executable=executable,
            expected_digest=expected_digest,
            expected_size=expected_size,
            expected_source=expected_source,
        )
    return _posix.atomic_copy_new_relative(
        source_root,
        source_relative,
        destination_root,
        destination_relative,
        executable=executable,
        expected_digest=expected_digest,
        expected_size=expected_size,
        expected_source=expected_source,
    )


def promote_relative_new(
    root: Path,
    source_relative: str,
    destination_relative: str,
    *,
    expected: SecureFileSnapshot,
) -> SecureFileSnapshot:
    """Move an exact held file to a new name with commit-time no-overwrite."""

    if os.name == "nt":
        return _windows.promote_relative_new(
            root,
            source_relative,
            destination_relative,
            expected=expected,
        )
    return _posix.promote_relative_new(
        root, source_relative, destination_relative, expected=expected
    )


def atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
) -> SecureFileSnapshot:
    """Publish bytes beneath ``root`` by a held-parent atomic replace.

    An existing regular target may be replaced for a later independent cold
    run.  Redirects and non-regular entries are rejected before commit, while
    the final rename itself replaces the directory entry and never follows it.
    """

    if type(payload) is not bytes:
        raise TypeError("secure publication payload must be immutable bytes")
    if os.name == "nt":
        return _windows.atomic_publish_relative(root, relative, payload, replace=True)
    return _posix.atomic_publish_relative(root, relative, payload, replace=True)


def atomic_publish_relative_if_current(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    expected: SecureFileSnapshot | None,
    mode: int | None = None,
    windows_attributes: int | None = None,
) -> SecureFileSnapshot:
    """Publish bytes only when the named preimage is still exact.

    ``expected=None`` is a commit-time create-if-absent operation.  Replacing
    an existing file requires its held identity, content receipt, mode, and
    change time to match both before staging and immediately before commit.
    Callers that coordinate multiple publications must additionally hold one
    shared transaction lock for the complete preimage/commit interval.
    """

    if type(payload) is not bytes:
        raise TypeError("secure publication payload must be immutable bytes")
    if mode is not None and (type(mode) is not int or not 0 <= mode <= 0o777):
        raise ValueError("secure publication mode must be POSIX permissions")
    if windows_attributes is not None and (
        type(windows_attributes) is not int or windows_attributes < 0
    ):
        raise ValueError("secure publication Windows attributes must be non-negative")
    if os.name == "nt":
        if mode is not None:
            raise SecurePathError("native Windows publication cannot set POSIX mode")
        if windows_attributes is not None and not windows_attributes_are_basic_restorable(
            windows_attributes
        ):
            raise SecurePathError("native publication attributes are unsafe")
        return _windows.atomic_publish_relative(
            root,
            relative,
            payload,
            replace=expected is not None,
            expected=expected,
            windows_attributes=windows_attributes,
        )
    if windows_attributes is not None:
        raise SecurePathError("POSIX publication cannot set Windows attributes")
    return _posix.atomic_publish_relative(
        root,
        relative,
        payload,
        replace=expected is not None,
        expected=expected,
        mode=mode if mode is not None else 0o644,
    )


def atomic_publish_new_relative(
    root: Path,
    relative: str,
    payload: bytes,
) -> SecureFileSnapshot:
    """Atomically create one immutable file, refusing every existing entry.

    This is the cache/CAS publication primitive.  The no-overwrite guarantee
    is enforced by the commit operation itself, not by a racy existence check.
    Ancestors and the published inode remain held through content and identity
    verification.
    """

    if type(payload) is not bytes:
        raise TypeError("secure publication payload must be immutable bytes")
    if os.name == "nt":
        return _windows.atomic_publish_relative(root, relative, payload, replace=False)
    return _posix.atomic_publish_relative(root, relative, payload, replace=False)


def remove_published_relative(
    root: Path,
    relative: str,
    *,
    expected: SecureFileSnapshot,
) -> bool:
    """Remove only the exact regular file returned by secure publication.

    This is a rollback primitive, not a general deletion API.  A replaced or
    mutated directory entry is left untouched and reported as ``False``.
    Held-parent deletion never follows a final symlink.
    """

    if os.name == "nt":
        return _windows.remove_published_relative(root, relative, expected=expected)
    return _posix.remove_published_relative(root, relative, expected=expected)


def remove_regular_relative(root: Path, relative: str) -> bool:
    """Remove one named regular file through a held no-follow ancestor chain."""

    if os.name == "nt":
        return _windows.remove_regular_relative(root, relative)
    return _posix.remove_regular_relative(root, relative)


def reseal_relative_file(
    root: Path,
    relative: str,
    *,
    expected: SecureFileSnapshot | None = None,
) -> SecureFileSnapshot:
    """Re-read one published file and optionally require its exact held identity."""

    _payload, received = read_relative_file(root, relative)
    if expected is not None and (
        received.digest != expected.digest
        or received.size != expected.size
        or received.device != expected.device
        or received.inode != expected.inode
        or received.mtime_ns != expected.mtime_ns
        or received.mode != expected.mode
        or received.ctime_ns != expected.ctime_ns
        or received.windows_file_id != expected.windows_file_id
        or received.windows_attributes != expected.windows_attributes
    ):
        raise SecurePathError(f"published file changed before final seal: {relative!r}")
    return received


@contextmanager
def hold_relative_file_set(
    root: Path,
    expected: Mapping[str, SecureFileSnapshot],
) -> Iterator[Mapping[str, SecureFileSnapshot]]:
    """Hold and validate a complete named file set through caller receipt use."""

    if os.name == "nt":
        with _windows.hold_relative_file_set(root, expected) as snapshots:
            yield snapshots
        return
    with _posix.hold_relative_file_set(root, expected) as snapshots:
        yield snapshots


__all__ = [
    "atomic_copy_new_relative",
    "atomic_publish_new_relative",
    "atomic_publish_new_relative_from_stream",
    "atomic_publish_relative",
    "atomic_publish_relative_if_current",
    "digest_relative_file",
    "hold_relative_file_set",
    "promote_relative_new",
    "read_relative_file",
    "remove_published_relative",
    "remove_regular_relative",
    "reseal_relative_file",
    "stat_relative_file",
    "windows_attributes_are_basic_restorable",
]
