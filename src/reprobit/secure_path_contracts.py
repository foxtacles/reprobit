"""Shared value contracts for secure handle-relative path operations."""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from reprobit.model import Digest


class SecurePathError(OSError):
    """A relative path operation could not preserve its no-redirection proof."""


@dataclass(frozen=True, slots=True)
class SecureFileSnapshot:
    """Immutable content and identity observed through one held file handle."""

    path: Path
    digest: Digest
    size: int
    device: int
    inode: int
    mtime_ns: int
    mode: int = 0
    ctime_ns: int = 0
    windows_file_id: bytes = b""
    windows_attributes: int = 0


@dataclass(frozen=True, slots=True)
class SecureFileIdentity:
    """Held identity and size for a regular file without reading its content."""

    path: Path
    size: int
    device: int
    inode: int
    mtime_ns: int
    mode: int = 0
    ctime_ns: int = 0
    windows_file_id: bytes = b""
    windows_attributes: int = 0


class BinaryReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...


STREAM_COPY_CHUNK = 1024 * 1024


def no_follow_directory_flags() -> int:
    """Open flags for a held directory that never follows a redirect."""

    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def no_follow_file_flags(access: int = os.O_RDONLY) -> int:
    """Open flags for a held file that never follows a redirect."""

    return (
        access
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


_MACOS_ROOT_ALIASES = {
    "etc": "etc",
    "tmp": "tmp",
    "var": "var",
}


def canonical_system_path(path: Path) -> Path:
    """Normalize Apple's fixed root aliases without resolving project links."""

    absolute = Path(os.path.abspath(path))
    if sys.platform != "darwin" or absolute.anchor != "/" or len(absolute.parts) < 2:
        return absolute
    component = absolute.parts[1]
    expected = _MACOS_ROOT_ALIASES.get(component)
    if expected is None:
        return absolute
    alias = Path("/") / component
    try:
        resolved = alias.resolve(strict=True)
    except OSError:
        return absolute
    canonical = Path("/private") / expected
    if resolved != canonical:
        return absolute
    return canonical.joinpath(*absolute.parts[2:])


def is_reparse_point(metadata: os.stat_result) -> bool:
    """Recognize every Windows redirection primitive, including junctions."""

    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(
        getattr(metadata, "st_reparse_tag", 0)
        or getattr(metadata, "st_file_attributes", 0) & reparse_attribute
    )


def is_redirected_metadata(metadata: os.stat_result) -> bool:
    """Recognize POSIX links and native Windows reparse points from one lstat."""

    return stat.S_ISLNK(metadata.st_mode) or is_reparse_point(metadata)


def is_redirected(path: Path) -> bool:
    """Recognize POSIX links and Windows reparse points; absent entries are not."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return is_redirected_metadata(metadata)


def canonical_relative_path(value: str | PurePosixPath) -> PurePosixPath:
    rendered = value.as_posix() if isinstance(value, PurePosixPath) else value
    path = PurePosixPath(rendered)
    if (
        not rendered
        or "\x00" in rendered
        or "\\" in rendered
        or path.is_absolute()
        or path.as_posix() != rendered
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SecurePathError(f"secure path must be canonical and relative: {value!r}")
    return path


def portable_relative_text(value: str) -> str:
    """Return ``value`` with ``\\`` folded to ``/`` once it is canonical relative text."""

    rendered = value.replace("\\", "/")
    path = PurePosixPath(rendered)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != rendered
    ):
        raise SecurePathError(f"portable path must be canonical and relative: {value!r}")
    return rendered


def validate_stream_expectations(
    digest: Digest,
    size: int,
    *,
    expected_digest: Digest | None,
    expected_size: int | None,
    relative: str,
) -> None:
    if expected_digest is not None and digest != expected_digest:
        raise SecurePathError(f"streamed publication digest differs from expectation: {relative!r}")
    if expected_size is not None and size != expected_size:
        raise SecurePathError(f"streamed publication size differs from expectation: {relative!r}")
