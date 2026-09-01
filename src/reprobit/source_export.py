"""Refreshable publication of the reviewed effective source view."""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from uuid import uuid4

from reprobit.classic_project import (
    InterventionWitness,
    materialize_effective_workspace,
)
from reprobit.schema import ProjectBundle
from reprobit.secure_path_contracts import is_redirected


class SourceExportError(RuntimeError):
    """An effective source export cannot be published safely."""


def _entry_exists(path: Path) -> bool:
    """Return whether a directory entry exists, including a broken symlink."""

    return os.path.lexists(path)


def _prepare_export_parent(project_root: Path, destination: Path) -> tuple[Path, Path]:
    """Resolve a real in-project parent without following redirected components."""

    if is_redirected(project_root) or not project_root.is_dir():
        raise SourceExportError("source export project root is absent or redirected")
    root = project_root.resolve(strict=True)
    destination = Path(os.path.abspath(destination))
    try:
        relative = destination.relative_to(root)
    except ValueError as exc:
        raise SourceExportError("source export destination escapes the project root") from exc
    if not relative.parts:
        raise SourceExportError("source export destination cannot be the project root")

    current = root
    for part in relative.parts[:-1]:
        current /= part
        if is_redirected(current):
            raise SourceExportError(f"source export parent is redirected: {current}")
        if current.exists():
            if not current.is_dir():
                raise SourceExportError(f"source export parent is not a directory: {current}")
            continue
        with suppress(FileExistsError):
            current.mkdir()
        if is_redirected(current) or not current.is_dir():
            raise SourceExportError(f"source export parent is redirected: {current}")

    if is_redirected(destination):
        raise SourceExportError(f"source export destination is redirected: {destination}")
    if destination.exists() and not destination.is_dir():
        raise SourceExportError(f"source export destination is not a directory: {destination}")
    return root, destination


def _remove_owned_tree(path: Path) -> None:
    """Remove only a real staging or backup directory created by this operation."""

    if not _entry_exists(path):
        return
    if is_redirected(path) or not path.is_dir():
        raise SourceExportError(f"source export temporary directory was redirected: {path}")
    shutil.rmtree(path)


def _replace_directory(source: Path, destination: Path) -> None:
    """Keep directory promotion patchable without replacing process-wide ``os.replace``."""

    os.replace(source, destination)


def _promote_export(staging: Path, destination: Path) -> None:
    """Promote a sealed sibling directory, restoring the prior export on error."""

    backup: Path | None = None
    if _entry_exists(destination):
        if is_redirected(destination) or not destination.is_dir():
            raise SourceExportError(
                f"source export destination changed before publication: {destination}"
            )
        backup = destination.parent / f".rbit-source-backup-{uuid4().hex}"
        try:
            _replace_directory(destination, backup)
        except OSError as exc:
            raise SourceExportError(
                f"cannot preserve the previous source export: {destination}"
            ) from exc

    try:
        _replace_directory(staging, destination)
    except OSError as exc:
        if backup is not None:
            try:
                _replace_directory(backup, destination)
            except OSError as rollback_error:
                raise SourceExportError(
                    "source export promotion failed and its previous directory could not "
                    f"be restored; the previous complete export remains at {backup}"
                ) from rollback_error
        raise SourceExportError(
            f"source export promotion failed; the previous export was preserved: {destination}"
        ) from exc

    if backup is not None:
        try:
            _remove_owned_tree(backup)
        except OSError as exc:
            raise SourceExportError(
                f"source export is complete, but its previous directory remains at {backup}"
            ) from exc


def refresh_effective_source_export(
    bundle: ProjectBundle,
    project_root: Path,
    destination: Path,
) -> tuple[InterventionWitness, ...]:
    """Build, validate, and transactionally refresh an effective source export."""

    root, destination = _prepare_export_parent(project_root, destination)
    staging = Path(tempfile.mkdtemp(prefix=".rbit-source-staging-", dir=destination.parent))
    try:
        witnesses = materialize_effective_workspace(bundle, root, staging)
        _promote_export(staging, destination)
    finally:
        _remove_owned_tree(staging)
    return witnesses


__all__ = [
    "SourceExportError",
    "refresh_effective_source_export",
]
