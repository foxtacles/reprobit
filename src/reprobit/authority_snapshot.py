"""Immutable JSON-authority directory snapshots for CAS publication."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reprobit.source_lock import SourceLockError, receipt_source_input
from reprobit.transactions import CASTransaction


class AuthoritySnapshotError(ValueError):
    """Authority could not be captured without ambiguity or redirection."""


@dataclass(frozen=True, slots=True)
class JsonAuthorityDirectorySnapshot:
    """Exact recursive JSON membership and file identities for one directory."""

    relative_path: str
    json_members: tuple[str, ...]
    file_digests: tuple[tuple[str, str], ...]


def resolve_project_path(
    root: Path,
    relative: str,
    *,
    error: Callable[[str], Exception],
    subject: str,
) -> Path:
    """Resolve one canonical project-relative path without following a redirected component.

    ``error`` builds the caller's own exception from the failure message so every
    boundary keeps its exception type while sharing one walk.
    """

    value = PurePosixPath(relative)
    if (
        value.is_absolute()
        or not value.parts
        or any(part in {"", ".", ".."} for part in value.parts)
    ):
        raise error(f"{subject} is not canonical: {relative!r}")
    current = root
    for part in value.parts:
        current /= part
        if current.is_symlink():
            raise error(f"{subject} is redirected: {relative!r}")
    try:
        current.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise error(f"{subject} escapes the project: {relative!r}") from exc
    return current


def _directory(root: Path, relative: str) -> Path:
    return resolve_project_path(
        root,
        relative,
        error=AuthoritySnapshotError,
        subject="authority path",
    )


def json_authority_members(root: Path, relative: str) -> tuple[str, ...]:
    """List one authority directory without following any redirected entry."""

    directory = _directory(root, relative)
    if not directory.exists():
        return ()
    if not directory.is_dir():
        raise AuthoritySnapshotError(f"authority directory is unavailable: {relative!r}")
    entries = tuple(directory.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise AuthoritySnapshotError(f"authority directory is redirected: {relative!r}")
    members = tuple(
        sorted(
            (
                path.relative_to(directory).as_posix()
                for path in entries
                if path.is_file() and path.suffix.casefold() == ".json"
            ),
            key=lambda item: (item.casefold(), item),
        )
    )
    if len({item.casefold() for item in members}) != len(members):
        raise AuthoritySnapshotError(f"authority members collide by case: {relative!r}")
    return members


def capture_file_preimage(
    root: Path,
    relative: str,
    *,
    required: bool = False,
) -> str | None:
    """Capture one stable project-relative file digest, or its absence."""

    project_root = root.resolve(strict=True)
    path = _directory(project_root, relative)
    if not path.exists():
        if required:
            raise AuthoritySnapshotError(f"required project file is absent: {relative!r}")
        return None
    if path.is_symlink() or not path.is_file():
        raise AuthoritySnapshotError(f"project file is not regular: {relative!r}")
    try:
        _size, digest, _payload = receipt_source_input(project_root, relative)
    except SourceLockError as exc:
        raise AuthoritySnapshotError(f"cannot seal project file {relative!r}: {exc}") from exc
    return digest.value


def capture_json_authority_directories(
    root: Path,
    relatives: tuple[str, ...],
) -> tuple[JsonAuthorityDirectorySnapshot, ...]:
    """Capture exact JSON bytes read by a validation before its later commit."""

    project_root = root.resolve(strict=True)
    snapshots: list[JsonAuthorityDirectorySnapshot] = []
    for relative in relatives:
        members = json_authority_members(project_root, relative)
        digests: list[tuple[str, str]] = []
        for member in members:
            path = f"{relative.rstrip('/')}/{member}"
            try:
                _size, digest, _payload = receipt_source_input(project_root, path)
            except SourceLockError as exc:
                raise AuthoritySnapshotError(f"cannot seal authority {path!r}: {exc}") from exc
            digests.append((path, digest.value))
        if json_authority_members(project_root, relative) != members:
            raise AuthoritySnapshotError(f"authority membership changed: {relative!r}")
        snapshots.append(JsonAuthorityDirectorySnapshot(relative, members, tuple(digests)))
    return tuple(snapshots)


def assert_json_authority_unchanged(
    transaction: CASTransaction,
    snapshots: tuple[JsonAuthorityDirectorySnapshot, ...],
) -> None:
    """Attach every captured file and directory membership as CAS preconditions."""

    for snapshot in snapshots:
        for relative, digest in snapshot.file_digests:
            transaction.assert_unchanged(relative, expected_sha256=digest)
        transaction.assert_json_members(
            snapshot.relative_path,
            expected_members=snapshot.json_members,
        )


__all__ = [
    "AuthoritySnapshotError",
    "JsonAuthorityDirectorySnapshot",
    "assert_json_authority_unchanged",
    "capture_file_preimage",
    "capture_json_authority_directories",
    "json_authority_members",
    "resolve_project_path",
]
