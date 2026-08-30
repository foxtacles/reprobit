"""Shared value contracts for secure handle-relative path operations."""

from __future__ import annotations

import os
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
