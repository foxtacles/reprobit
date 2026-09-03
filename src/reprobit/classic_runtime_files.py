"""Shared filesystem validation and sealing for classic execution."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from reprobit.classic_project import ClassicProjectError
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths import remove_regular_relative, split_absolute


def _digest_path(path: Path) -> Digest:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return Digest(value=digest.hexdigest())


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ClassicProjectError(f"unsafe discovered project path: {value!r}")
    return path.as_posix()


def _secure_remove_regular(path: Path) -> None:
    """Remove one exact run-private regular file without following parents."""

    try:
        root, relative = split_absolute(path)
        removed = remove_regular_relative(root, relative)
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(
            f"classic warm output could not be erased safely: {path}: {exc}"
        ) from exc
    if not removed:
        raise ClassicProjectError(f"classic warm output disappeared before erasure: {path}")


def _tree_file_seal(root: Path) -> Mapping[Path, tuple[int, Digest]]:
    """Snapshot regular files beneath a producer-writable seat.

    The tree may not contain symlinks, so every regular file resolves to the
    resolved root joined with its relative path; the root itself is resolved
    once instead of once per file.
    """

    sealed: dict[Path, tuple[int, Digest]] = {}
    if not root.is_dir():
        return MappingProxyType(sealed)
    resolved_root = root.resolve(strict=True)
    entries: list[tuple[str, Path, os.DirEntry[str]]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as listing:
            for entry in listing:
                path = Path(entry.path)
                if entry.is_symlink():
                    raise ClassicProjectError(f"producer build tree contains a symlink: {path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    entries.append((path.as_posix().casefold(), path, entry))
    for _key, path, entry in sorted(entries, key=lambda item: item[0]):
        resolved = resolved_root.joinpath(path.relative_to(root))
        sealed[resolved] = (entry.stat(follow_symlinks=False).st_size, _digest_path(path))
    return MappingProxyType(sealed)


def _require_declared_tree_writes(
    before: Mapping[Path, tuple[int, Digest]],
    *,
    root: Path,
    allowed_outputs: Iterable[Path],
    phase: str,
) -> None:
    """Reject residual producer writes outside the committed output set."""

    after = _tree_file_seal(root)
    changed = {path for path in set(before) | set(after) if before.get(path) != after.get(path)}
    allowed = {path.resolve(strict=False) for path in allowed_outputs}
    unexpected = sorted(changed - allowed, key=str)
    if unexpected:
        raise ClassicProjectError(
            f"{phase} wrote undeclared build-tree files: "
            + ", ".join(str(path) for path in unexpected[:12])
        )


def _require_unchanged_tree(
    before: Mapping[Path, tuple[int, Digest]], *, root: Path, label: str
) -> None:
    """Require a complete read-only seat to retain exact membership and bytes."""

    after = _tree_file_seal(root)
    changed = sorted(
        (path for path in set(before) | set(after) if before.get(path) != after.get(path)),
        key=str,
    )
    if changed:
        raise ClassicProjectError(
            f"{label} changed during execution: " + ", ".join(str(path) for path in changed[:12])
        )


__all__ = []
