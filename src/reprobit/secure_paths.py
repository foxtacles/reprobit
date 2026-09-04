"""Public orchestration for handle-relative reads and atomic publication.

Security-sensitive project paths are never traversed by repeatedly resolving
host path strings.  The public operations in this module validate portable
arguments and dispatch to the native handle-relative implementation for the
current platform.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

import reprobit.secure_paths_posix as _posix
import reprobit.secure_paths_windows as _windows
from reprobit.model import Digest
from reprobit.secure_path_contracts import (
    SecureFileIdentity,
    SecureFileSnapshot,
    SecurePathError,
    canonical_relative_path,
    canonical_system_path,
)

_DirectoryIdentity = tuple[int, int]
_ExpectedDirectories = Mapping[str, _DirectoryIdentity]


class _NativeSecurePaths(Protocol):
    """The platform-independent surface both native implementations provide."""

    def read_relative_file(
        self,
        root: Path,
        relative: str,
        *,
        expected_directories: _ExpectedDirectories = ...,
    ) -> tuple[bytes, SecureFileSnapshot]: ...

    def stat_relative_file(self, root: Path, relative: str) -> SecureFileIdentity: ...

    def digest_relative_file(
        self,
        root: Path,
        relative: str,
        *,
        expected_directories: _ExpectedDirectories = ...,
    ) -> SecureFileSnapshot: ...

    def atomic_copy_new_relative(
        self,
        source_root: Path,
        source_relative: str,
        destination_root: Path,
        destination_relative: str,
        *,
        executable: bool = ...,
        expected_digest: Digest | None = ...,
        expected_size: int | None = ...,
        expected_source: SecureFileIdentity | None = ...,
        expected_source_directories: _ExpectedDirectories = ...,
        expected_destination_directories: _ExpectedDirectories = ...,
    ) -> SecureFileSnapshot: ...

    def promote_relative_new(
        self,
        root: Path,
        source_relative: str,
        destination_relative: str,
        *,
        expected: SecureFileSnapshot,
        expected_directories: _ExpectedDirectories = ...,
    ) -> SecureFileSnapshot: ...

    def atomic_publish_relative(
        self,
        root: Path,
        relative: str,
        payload: bytes,
        *,
        replace: bool,
        expected_directories: _ExpectedDirectories = ...,
    ) -> SecureFileSnapshot: ...

    def remove_published_relative(
        self,
        root: Path,
        relative: str,
        *,
        expected: SecureFileSnapshot,
        expected_directories: _ExpectedDirectories = ...,
    ) -> bool: ...

    def remove_regular_relative(self, root: Path, relative: str) -> bool: ...

    def hold_relative_file_set(
        self, root: Path, expected: Mapping[str, SecureFileSnapshot]
    ) -> AbstractContextManager[Mapping[str, SecureFileSnapshot]]: ...


def _native() -> _NativeSecurePaths:
    """Select the native implementation at call time (tests swap ``os.name``)."""

    return _windows if os.name == "nt" else _posix


def _normalize_expected_directories(
    expected: Mapping[str, tuple[int, int]] | None,
    *,
    relatives: tuple[str, ...],
) -> dict[str, tuple[int, int]]:
    """Validate exact directory identities used by one held path operation."""

    if expected is None:
        return {}
    if not isinstance(expected, Mapping):
        raise TypeError("expected directory identities must be a mapping")
    allowed = {"."}
    for relative in relatives:
        parts = canonical_relative_path(relative).parts[:-1]
        allowed.update(
            PurePosixPath(*parts[:index]).as_posix() for index in range(1, len(parts) + 1)
        )
    checked: dict[str, tuple[int, int]] = {}
    for directory, identity in expected.items():
        if not isinstance(directory, str) or directory not in allowed:
            raise ValueError(
                f"expected directory must be the root or a canonical path ancestor: {directory!r}"
            )
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or any(type(value) is not int or value < 0 for value in identity)
        ):
            raise ValueError("expected directory identity must contain two non-negative integers")
        checked[directory] = identity
    return checked


def windows_attributes_are_basic_restorable(attributes: int) -> bool:
    """Return whether FileBasicInfo can exactly recreate native attributes."""

    return _windows.windows_attributes_are_basic_restorable(attributes)


def split_absolute(path: Path) -> tuple[Path, str]:
    """Anchor one absolute path at its filesystem root for held traversal."""

    absolute = canonical_system_path(path)
    if not absolute.anchor or len(absolute.parts) < 2:
        raise SecurePathError(f"secure path has no relative location below its root: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def read_relative_file(
    root: Path,
    relative: str,
    *,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
) -> tuple[bytes, SecureFileSnapshot]:
    """Read one regular file through a fully held, no-follow ancestor chain."""

    checked = _normalize_expected_directories(expected_directories, relatives=(relative,))
    return _native().read_relative_file(
        root,
        relative,
        expected_directories=checked,
    )


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
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
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
    checked_directories = _normalize_expected_directories(
        expected_directories,
        relatives=(relative,),
    )
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
            expected_directories=checked_directories,
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
        expected_directories=checked_directories,
    )


def stat_relative_file(root: Path, relative: str) -> SecureFileIdentity:
    """Inspect one regular file through a held ancestor chain without reading it."""

    return _native().stat_relative_file(root, relative)


def digest_relative_file(
    root: Path,
    relative: str,
    *,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
) -> SecureFileSnapshot:
    """Hash one regular file through a held ancestor chain with bounded memory."""

    checked = _normalize_expected_directories(expected_directories, relatives=(relative,))
    return _native().digest_relative_file(
        root,
        relative,
        expected_directories=checked,
    )


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
    expected_source_directories: Mapping[str, tuple[int, int]] | None = None,
    expected_destination_directories: Mapping[str, tuple[int, int]] | None = None,
) -> SecureFileSnapshot:
    """Copy one held source to a new held destination in a single pass."""

    checked_source_directories = _normalize_expected_directories(
        expected_source_directories,
        relatives=(source_relative,),
    )
    checked_destination_directories = _normalize_expected_directories(
        expected_destination_directories,
        relatives=(destination_relative,),
    )
    return _native().atomic_copy_new_relative(
        source_root,
        source_relative,
        destination_root,
        destination_relative,
        executable=executable,
        expected_digest=expected_digest,
        expected_size=expected_size,
        expected_source=expected_source,
        expected_source_directories=checked_source_directories,
        expected_destination_directories=checked_destination_directories,
    )


def promote_relative_new(
    root: Path,
    source_relative: str,
    destination_relative: str,
    *,
    expected: SecureFileSnapshot,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
) -> SecureFileSnapshot:
    """Move an exact held file to a new name with commit-time no-overwrite."""

    checked = _normalize_expected_directories(
        expected_directories,
        relatives=(source_relative, destination_relative),
    )
    return _native().promote_relative_new(
        root,
        source_relative,
        destination_relative,
        expected=expected,
        expected_directories=checked,
    )


def atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
) -> SecureFileSnapshot:
    """Publish bytes beneath ``root`` by a held-parent atomic replace.

    An existing regular target may be replaced for a later independent cold
    run.  It is moved aside and rechecked before the candidate is installed
    without overwriting any entry that appears during the handoff.
    """

    if type(payload) is not bytes:
        raise TypeError("secure publication payload must be immutable bytes")
    return _native().atomic_publish_relative(root, relative, payload, replace=True)


def atomic_publish_relative_if_current(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    expected: SecureFileSnapshot | None,
    mode: int | None = None,
    windows_attributes: int | None = None,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
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
    checked_directories = _normalize_expected_directories(
        expected_directories,
        relatives=(relative,),
    )
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
            expected_directories=checked_directories,
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
        expected_directories=checked_directories,
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
    return _native().atomic_publish_relative(root, relative, payload, replace=False)


def remove_published_relative(
    root: Path,
    relative: str,
    *,
    expected: SecureFileSnapshot,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
) -> bool:
    """Remove only the exact regular file returned by secure publication.

    This is a rollback primitive, not a general deletion API.  A replaced or
    mutated directory entry is left untouched and reported as ``False``.
    Held-parent deletion never follows a final symlink.
    """

    checked = _normalize_expected_directories(expected_directories, relatives=(relative,))
    return _native().remove_published_relative(
        root,
        relative,
        expected=expected,
        expected_directories=checked,
    )


def remove_regular_relative(root: Path, relative: str) -> bool:
    """Remove one named regular file through a held no-follow ancestor chain."""

    return _native().remove_regular_relative(root, relative)


def reseal_relative_file(
    root: Path,
    relative: str,
    *,
    expected: SecureFileSnapshot | None = None,
    expected_directories: Mapping[str, tuple[int, int]] | None = None,
) -> SecureFileSnapshot:
    """Re-read one published file and optionally require its exact held identity."""

    _payload, received = read_relative_file(
        root,
        relative,
        expected_directories=expected_directories,
    )
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

    with _native().hold_relative_file_set(root, expected) as snapshots:
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
    "split_absolute",
    "stat_relative_file",
    "windows_attributes_are_basic_restorable",
]
