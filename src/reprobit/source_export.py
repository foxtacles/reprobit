"""Refreshable publication of the reviewed effective source view."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from reprobit.classic_project import (
    InterventionWitness,
    effective_source_seal,
    materialize_effective_workspace,
)
from reprobit.exact_tree import (
    ExactTreeError,
    create_directory_in_exact_parent,
    ensure_directory_in_exact_root,
    move_directory_in_exact_parent,
    remove_exact_directory_tree,
)
from reprobit.model import Digest
from reprobit.schema import ProjectBundle
from reprobit.secure_path_contracts import SecurePathError, is_redirected
from reprobit.secure_paths import atomic_copy_new_relative


class SourceExportError(RuntimeError):
    """An effective source export cannot be published safely."""


@dataclass(frozen=True, slots=True)
class SourceExportResult:
    """Published effective source plus any refused private cleanup."""

    witnesses: tuple[InterventionWitness, ...]
    cleanup_warning: str | None = None
    preserved_paths: tuple[Path, ...] = ()


_OWNERSHIP_FILE = ".reprobit-source-export"
_OWNERSHIP_PAYLOAD = b"reprobit-source-export-v1\n"
_DirectoryIdentity = tuple[int, int]


def _entry_exists(path: Path) -> bool:
    """Return whether a directory entry exists, including a broken symlink."""

    return os.path.lexists(path)


def _require_owned_export(destination: Path) -> None:
    """Require the fixed marker written into every ReproBit source export."""

    marker = destination / _OWNERSHIP_FILE
    if marker.is_symlink() or not marker.is_file():
        raise SourceExportError(
            f"source export destination already exists but is not owned by ReproBit: {destination}"
        )
    try:
        owned = marker.read_bytes() == _OWNERSHIP_PAYLOAD
    except OSError as exc:
        raise SourceExportError(f"cannot read source export ownership marker: {marker}") from exc
    if not owned:
        raise SourceExportError(f"source export ownership marker is invalid: {marker}")


def _directory_identity(path: Path) -> _DirectoryIdentity:
    status = path.stat(follow_symlinks=False)
    return status.st_dev, status.st_ino


def _prepare_export_parent(
    project_root: Path,
    destination: Path,
) -> tuple[Path, Path, _DirectoryIdentity, _DirectoryIdentity | None]:
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

    root_identity = _directory_identity(root)
    if relative.parts[:-1]:
        parent_relative = PurePosixPath(*relative.parts[:-1]).as_posix()
        try:
            parent, parent_identity = ensure_directory_in_exact_root(
                root,
                root_identity,
                parent_relative,
            )
        except (OSError, SecurePathError) as exc:
            raise SourceExportError(
                f"source export parent cannot be prepared safely: {destination.parent}"
            ) from exc
    else:
        parent = root
        parent_identity = root_identity
    if parent != destination.parent:
        raise SourceExportError("source export parent differs from its project path")

    if is_redirected(destination):
        raise SourceExportError(f"source export destination is redirected: {destination}")
    if destination.exists() and not destination.is_dir():
        raise SourceExportError(f"source export destination is not a directory: {destination}")
    if destination.is_dir():
        _require_owned_export(destination)
        identity: _DirectoryIdentity | None = _directory_identity(destination)
    else:
        identity = None
    return root, destination, parent_identity, identity


def _require_directory_identity(
    path: Path,
    expected: _DirectoryIdentity,
    *,
    description: str,
) -> None:
    """Require that a path still names the exact real directory we inspected."""

    if not _entry_exists(path) or is_redirected(path) or not path.is_dir():
        raise SourceExportError(f"source export {description} changed during publication: {path}")
    try:
        actual = _directory_identity(path)
    except OSError as exc:
        raise SourceExportError(f"cannot inspect source export {description}: {path}") from exc
    if actual != expected:
        raise SourceExportError(f"source export {description} changed during publication: {path}")


def _require_expected_export(
    path: Path,
    expected: _DirectoryIdentity,
    *,
    description: str,
) -> None:
    """Require the expected directory and its fixed export ownership marker."""

    _require_directory_identity(path, expected, description=description)
    _require_owned_export(path)


def _remove_owned_tree(
    path: Path,
    expected: _DirectoryIdentity,
    *,
    expected_parent: _DirectoryIdentity,
    require_marker: bool = False,
) -> None:
    """Quarantine and remove only the exact staging or owned backup directory."""

    if not _entry_exists(path):
        return
    _require_directory_identity(path, expected, description="temporary directory")
    if require_marker:
        _require_owned_export(path)
    quarantine = path.with_name(f".rbit-source-remove-{uuid4().hex}")
    try:
        _replace_directory(
            path,
            quarantine,
            expected_source=expected,
            expected_parent=expected_parent,
        )
    except FileNotFoundError:
        return
    except (OSError, ExactTreeError) as exc:
        raise SourceExportError(f"cannot quarantine source export directory: {path}") from exc
    _require_directory_identity(quarantine, expected, description="quarantined directory")
    if require_marker:
        _require_owned_export(quarantine)
    remove_exact_directory_tree(quarantine, expected)


def _replace_directory(
    source: Path,
    destination: Path,
    *,
    expected_source: _DirectoryIdentity,
    expected_parent: _DirectoryIdentity,
) -> None:
    """Keep exact sibling promotion patchable for deterministic race tests."""

    move_directory_in_exact_parent(
        source,
        expected_source,
        destination,
        expected_parent,
    )


def _promote_export(
    staging: Path,
    expected_staging: _DirectoryIdentity,
    destination: Path,
    expected_destination: _DirectoryIdentity | None,
    expected_parent: _DirectoryIdentity,
) -> tuple[str | None, Path | None]:
    """Promote a sealed sibling, preserving any prior export at a reported backup."""

    backup: Path | None = None
    backup_identity: _DirectoryIdentity | None = None
    if _entry_exists(destination):
        if is_redirected(destination) or not destination.is_dir():
            raise SourceExportError(
                f"source export destination changed before publication: {destination}"
            )
        if expected_destination is None or _directory_identity(destination) != expected_destination:
            raise SourceExportError(
                f"source export destination changed before publication: {destination}"
            )
        _require_owned_export(destination)
        backup = destination.parent / f".rbit-source-backup-{uuid4().hex}"
        backup_identity = expected_destination
        try:
            _replace_directory(
                destination,
                backup,
                expected_source=expected_destination,
                expected_parent=expected_parent,
            )
        except (OSError, ExactTreeError) as exc:
            raise SourceExportError(
                f"cannot preserve the previous source export: {destination}"
            ) from exc
        try:
            _require_expected_export(
                backup,
                expected_destination,
                description="backup",
            )
        except SourceExportError as exc:
            raise SourceExportError(
                "source export destination changed during publication; "
                f"the moved directory was preserved at {backup}"
            ) from exc
    elif expected_destination is not None:
        raise SourceExportError(
            f"source export destination changed before publication: {destination}"
        )

    _require_expected_export(staging, expected_staging, description="staging directory")
    try:
        _replace_directory(
            staging,
            destination,
            expected_source=expected_staging,
            expected_parent=expected_parent,
        )
    except (OSError, ExactTreeError) as exc:
        if backup is not None:
            assert backup_identity is not None
            _require_expected_export(backup, backup_identity, description="backup")
            raise SourceExportError(
                "source export promotion failed; the previous complete export "
                f"was preserved at {backup}"
            ) from exc
        raise SourceExportError(
            f"source export promotion failed before publication: {destination}"
        ) from exc

    try:
        _require_expected_export(
            destination,
            expected_staging,
            description="published destination",
        )
    except SourceExportError as exc:
        if backup is None:
            raise
        raise SourceExportError(
            "source export destination changed during publication; "
            f"the previous complete export remains at {backup}"
        ) from exc

    if backup is not None:
        assert backup_identity is not None
        try:
            _remove_owned_tree(
                backup,
                backup_identity,
                expected_parent=expected_parent,
                require_marker=True,
            )
        except (OSError, SourceExportError):
            return (
                f"previous source export cleanup was refused; preserved at {backup}",
                backup,
            )
    return None, None


def _copy_sealed_export(
    source: Path,
    expected_source: _DirectoryIdentity,
    destination: Path,
    expected_destination: _DirectoryIdentity,
) -> None:
    """Copy one private materialization into an identity-bound candidate."""

    seal = effective_source_seal(source)
    for relative, size, digest in seal:
        try:
            published = atomic_copy_new_relative(
                source,
                relative,
                destination,
                relative,
                expected_digest=Digest(value=digest),
                expected_size=size,
                expected_source_directories={".": expected_source},
                expected_destination_directories={".": expected_destination},
            )
        except SecurePathError as exc:
            raise SourceExportError(
                f"cannot publish materialized source safely: {relative}"
            ) from exc
        if published.size != size or published.digest.value != digest:
            raise SourceExportError(f"published source differs from its seal: {relative}")
    _require_directory_identity(
        destination,
        expected_destination,
        description="staging directory",
    )
    if effective_source_seal(destination) != seal:
        raise SourceExportError("published source differs from its complete seal")
    _require_directory_identity(
        destination,
        expected_destination,
        description="staging directory",
    )


def refresh_effective_source_export(
    bundle: ProjectBundle,
    project_root: Path,
    destination: Path,
) -> SourceExportResult:
    """Build, validate, and transactionally refresh an effective source export."""

    root, destination, parent_identity, previous_destination = _prepare_export_parent(
        project_root,
        destination,
    )
    materialized = Path(tempfile.mkdtemp(prefix="rbit-source-materialize-")).resolve(strict=True)
    materialized_identity = _directory_identity(materialized)
    materialized_parent_identity = _directory_identity(materialized.parent)
    staging = destination.parent / f".rbit-source-staging-{uuid4().hex}"
    staging_identity: _DirectoryIdentity | None = None
    published = False
    cleanup_warnings: list[str] = []
    preserved_paths: list[Path] = []
    try:
        witnesses = materialize_effective_workspace(bundle, root, materialized)
        marker = materialized / _OWNERSHIP_FILE
        if _entry_exists(marker):
            raise SourceExportError(
                f"reviewed source uses ReproBit's reserved export path: {_OWNERSHIP_FILE}"
            )
        marker.write_bytes(_OWNERSHIP_PAYLOAD)
        try:
            staging_identity = create_directory_in_exact_parent(
                staging,
                parent_identity,
            )
        except ExactTreeError as exc:
            raise SourceExportError(
                f"cannot create source export staging directory: {staging}"
            ) from exc
        _copy_sealed_export(
            materialized,
            materialized_identity,
            staging,
            staging_identity,
        )
        cleanup_warning, preserved = _promote_export(
            staging,
            staging_identity,
            destination,
            previous_destination,
            parent_identity,
        )
        published = True
        if cleanup_warning is not None:
            cleanup_warnings.append(cleanup_warning)
        if preserved is not None:
            preserved_paths.append(preserved)
    finally:
        if staging_identity is not None:
            try:
                _remove_owned_tree(
                    staging,
                    staging_identity,
                    expected_parent=parent_identity,
                )
            except (OSError, SourceExportError):
                if not published:
                    raise
                cleanup_warnings.append(
                    f"private source staging cleanup was refused; preserved at {staging}"
                )
                preserved_paths.append(staging)
        try:
            _remove_owned_tree(
                materialized,
                materialized_identity,
                expected_parent=materialized_parent_identity,
            )
        except (OSError, SourceExportError):
            if not published:
                raise
            cleanup_warnings.append(
                f"private source materialization cleanup was refused; preserved at {materialized}"
            )
            preserved_paths.append(materialized)
    return SourceExportResult(
        witnesses,
        "; ".join(cleanup_warnings) if cleanup_warnings else None,
        tuple(preserved_paths),
    )


__all__ = [
    "SourceExportError",
    "SourceExportResult",
    "refresh_effective_source_export",
]
