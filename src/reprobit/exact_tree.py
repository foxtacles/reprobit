"""Identity-bound removal for already-quarantined private directories."""

from __future__ import annotations

import errno
import os
import stat
import uuid
from contextlib import suppress
from pathlib import Path

from reprobit.posix_noreplace import rename_noreplace_at
from reprobit.secure_path_contracts import (
    SecurePathError,
    canonical_relative_path,
    is_redirected_metadata,
    no_follow_directory_flags,
)

DirectoryIdentity = tuple[int, int]


class ExactTreeError(OSError):
    """A private directory changed while it was being removed."""


def _sync_posix_directory(directory: int) -> None:
    """Durably order a held directory mutation where the host supports it."""

    try:
        os.fsync(directory)
    except OSError as exc:
        if exc.errno not in {errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)}:
            raise


def _identity(metadata: os.stat_result) -> DirectoryIdentity:
    return metadata.st_dev, metadata.st_ino


def _restore_or_preserve_posix(
    parent: int,
    moved: str,
    original: str,
) -> str:
    """Restore a raced entry when free, otherwise report its preserved name."""

    try:
        rename_noreplace_at(parent, moved, original)
    except OSError:
        return f"moved replacement preserved as {moved!r}"
    return f"replacement restored as {original!r}"


def _absolute_child(path: Path) -> tuple[Path, str]:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ExactTreeError(f"exact directory path is unsafe: {path}")
    return path.parent, path.name


def _sibling_paths(source: Path, destination: Path) -> tuple[Path, str, str]:
    source_parent, source_name = _absolute_child(source)
    destination_parent, destination_name = _absolute_child(destination)
    if source_parent != destination_parent or source_name == destination_name:
        raise ExactTreeError("exact directory move requires distinct sibling paths")
    return source_parent, source_name, destination_name


def _open_posix_directory_at(parent: int, name: str) -> int:
    """Open a child directory without following it; patchable for race tests."""

    return os.open(name, no_follow_directory_flags(), dir_fd=parent)


def ensure_directory_in_exact_root(
    root: Path,
    expected_root: DirectoryIdentity,
    relative: str,
) -> tuple[Path, DirectoryIdentity]:
    """Create/open a plain directory chain beneath one exact held root."""

    canonical = canonical_relative_path(relative)
    probe = canonical / ".reprobit-directory-seat"
    if os.name == "nt":
        from reprobit.secure_paths_windows import _HeldWindowsRoot

        with _HeldWindowsRoot(root, expected_identity=expected_root) as held:
            handles, edges, _name = held.parent_chain(probe, create=True)
            try:
                identity = held.api.identity(handles[-1])[:2]
                for handle in reversed(handles):
                    held.api.flush_directory(handle)
                held.recheck(edges)
            finally:
                for handle in reversed(handles[1:]):
                    held.api.close(handle)
    else:
        from reprobit.secure_paths_posix import _HeldPosixRoot

        with _HeldPosixRoot(root, expected_identity=expected_root) as held:
            descriptors, edges, _name = held.parent_chain(probe, create=True)
            try:
                identity = _identity(os.fstat(descriptors[-1]))
                for descriptor in reversed(descriptors):
                    _sync_posix_directory(descriptor)
                held.recheck(edges)
            finally:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)
    return root.joinpath(*canonical.parts), identity


def create_directory_in_exact_parent(
    path: Path,
    expected_parent: DirectoryIdentity,
) -> DirectoryIdentity:
    """Create one new private directory through its exact held parent."""

    parent, name = _absolute_child(path)
    if os.name == "nt":
        from reprobit.secure_paths_windows import _HeldWindowsRoot

        try:
            with _HeldWindowsRoot(parent, expected_identity=expected_parent) as held:
                directory = held.api.open_relative(
                    held.handle,
                    name,
                    directory=True,
                    create=True,
                    exclusive=True,
                    deny_other_writes=True,
                )
                assert directory is not None
                try:
                    identity = held.api.identity(directory)[:2]
                    held.api.flush_directory(held.handle)
                    held.verify_root()
                    return identity
                finally:
                    held.api.close(directory)
        except (OSError, SecurePathError) as exc:
            raise ExactTreeError(f"cannot securely create private directory: {path}") from exc

    from reprobit.secure_paths_posix import _HeldPosixRoot

    try:
        with _HeldPosixRoot(parent, expected_identity=expected_parent) as held:
            os.mkdir(name, mode=0o700, dir_fd=held.fd)
            created = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
            directory = _open_posix_directory_at(held.fd, name)
            try:
                identity = _identity(os.fstat(directory))
                named = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(created.st_mode)
                    or not stat.S_ISDIR(named.st_mode)
                    or _identity(created) != identity
                    or _identity(named) != identity
                ):
                    raise ExactTreeError(f"private directory changed during creation: {path}")
                _sync_posix_directory(held.fd)
                held.recheck([])
                return identity
            finally:
                os.close(directory)
    except (OSError, SecurePathError) as exc:
        if isinstance(exc, ExactTreeError):
            raise
        raise ExactTreeError(f"cannot securely create private directory: {path}") from exc


def move_directory_in_exact_parent(
    source: Path,
    expected_source: DirectoryIdentity,
    destination: Path,
    expected_parent: DirectoryIdentity,
) -> None:
    """Move one exact sibling directory to an absent name without clobbering."""

    parent, source_name, destination_name = _sibling_paths(source, destination)
    if os.name == "nt":
        from reprobit.secure_paths_windows import _HeldWindowsRoot

        try:
            with _HeldWindowsRoot(parent, expected_identity=expected_parent) as held:
                source_handle = held.api.open_relative(
                    held.handle,
                    source_name,
                    directory=True,
                    delete=True,
                    deny_other_writes=True,
                )
                assert source_handle is not None
                destination_handle = None
                try:
                    if held.api.identity(source_handle)[:2] != expected_source:
                        raise ExactTreeError(f"private directory changed before move: {source}")
                    try:
                        destination_handle = held.api.open_relative(
                            held.handle,
                            destination_name,
                            directory=True,
                            allow_missing=True,
                        )
                    except SecurePathError as exc:
                        raise ExactTreeError(
                            f"directory destination is occupied: {destination}"
                        ) from exc
                    if destination_handle is not None:
                        raise ExactTreeError(f"directory destination is occupied: {destination}")
                    held.api.rename(
                        source_handle,
                        held.handle,
                        destination_name,
                        replace=False,
                    )
                    # The source handle still denies writes and deletion. This
                    # read-only verifier must share its existing DELETE access;
                    # a second restrictive lease would conflict with our own.
                    destination_handle = held.api.open_relative(
                        held.handle,
                        destination_name,
                        directory=True,
                    )
                    assert destination_handle is not None
                    if held.api.identity(destination_handle)[:2] != expected_source:
                        raise ExactTreeError(f"private directory changed during move: {source}")
                    held.api.flush_directory(held.handle)
                    held.verify_root()
                finally:
                    if destination_handle is not None:
                        held.api.close(destination_handle)
                    held.api.close(source_handle)
        except (OSError, SecurePathError) as exc:
            if isinstance(exc, ExactTreeError):
                raise
            raise ExactTreeError(f"cannot securely move private directory: {source}") from exc
        return

    from reprobit.secure_paths_posix import _HeldPosixRoot

    try:
        with _HeldPosixRoot(parent, expected_identity=expected_parent) as held:
            source_descriptor = os.open(
                source_name,
                no_follow_directory_flags(),
                dir_fd=held.fd,
            )
            try:
                if _identity(os.fstat(source_descriptor)) != expected_source:
                    raise ExactTreeError(f"private directory changed before move: {source}")
                try:
                    os.stat(destination_name, dir_fd=held.fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ExactTreeError(f"directory destination is occupied: {destination}")
                named_source = os.stat(
                    source_name,
                    dir_fd=held.fd,
                    follow_symlinks=False,
                )
                if _identity(named_source) != expected_source:
                    raise ExactTreeError(f"private directory changed before move: {source}")
                try:
                    rename_noreplace_at(held.fd, source_name, destination_name)
                except OSError as exc:
                    if exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                        raise ExactTreeError(
                            f"directory destination appeared: {destination_name!r}"
                        ) from exc
                    raise
                received = os.stat(
                    destination_name,
                    dir_fd=held.fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(received.st_mode) or _identity(received) != expected_source:
                    outcome = _restore_or_preserve_posix(
                        held.fd,
                        destination_name,
                        source_name,
                    )
                    _sync_posix_directory(held.fd)
                    raise ExactTreeError("private directory changed during move; " + outcome)
                _sync_posix_directory(held.fd)
                held.recheck([])
            finally:
                os.close(source_descriptor)
    except (OSError, SecurePathError) as exc:
        if isinstance(exc, ExactTreeError):
            raise
        raise ExactTreeError(f"cannot securely move private directory: {source}") from exc


def _remove_posix_contents(directory: int) -> None:
    """Remove one held directory's initial members without following links."""

    names = tuple(os.listdir(directory))
    for name in names:
        try:
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise ExactTreeError(f"private directory member changed: {name!r}") from exc
        if stat.S_ISDIR(metadata.st_mode) and not is_redirected_metadata(metadata):
            try:
                child = os.open(name, no_follow_directory_flags(), dir_fd=directory)
            except OSError as exc:
                raise ExactTreeError(f"private directory member changed: {name!r}") from exc
            try:
                held = os.fstat(child)
                if _identity(held) != _identity(metadata):
                    raise ExactTreeError(f"private directory member changed: {name!r}")
                _remove_posix_contents(child)
                current = os.fstat(child)
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if _identity(current) != _identity(held) or _identity(named) != _identity(held):
                    raise ExactTreeError(f"private directory member changed: {name!r}")
                quarantine = f".{name}.reprobit-remove-{uuid.uuid4().hex}"
                rename_noreplace_at(directory, name, quarantine)
                moved = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
                if _identity(moved) != _identity(held):
                    outcome = _restore_or_preserve_posix(directory, quarantine, name)
                    _sync_posix_directory(directory)
                    raise ExactTreeError("private directory member changed; " + outcome)
                os.rmdir(quarantine, dir_fd=directory)
            except OSError as exc:
                if isinstance(exc, ExactTreeError):
                    raise
                raise ExactTreeError(f"cannot remove private directory member: {name!r}") from exc
            finally:
                os.close(child)
            continue
        quarantine = f".{name}.reprobit-remove-{uuid.uuid4().hex}"
        try:
            rename_noreplace_at(directory, name, quarantine)
            moved = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
            if _identity(moved) != _identity(metadata):
                outcome = _restore_or_preserve_posix(directory, quarantine, name)
                _sync_posix_directory(directory)
                raise ExactTreeError("private directory member changed; " + outcome)
            os.unlink(quarantine, dir_fd=directory)
        except OSError as exc:
            if isinstance(exc, ExactTreeError):
                raise
            raise ExactTreeError(f"cannot remove private directory member: {name!r}") from exc
    if os.listdir(directory):
        raise ExactTreeError("private directory gained members during cleanup")


def _remove_posix_tree(path: Path, expected: DirectoryIdentity) -> None:
    parent = os.open(path.parent, no_follow_directory_flags())
    directory = -1
    try:
        directory = os.open(path.name, no_follow_directory_flags(), dir_fd=parent)
        held = os.fstat(directory)
        if _identity(held) != expected:
            raise ExactTreeError(f"private directory changed before cleanup: {path}")
        _remove_posix_contents(directory)
        current = os.fstat(directory)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if _identity(current) != expected or _identity(named) != expected:
            raise ExactTreeError(f"private directory changed during cleanup: {path}")
        # Move to one last unguessable name before deletion. A replacement at
        # the caller-visible quarantine seat is preserved, while the random
        # final name is the private boundary for POSIX's name-based rmdir.
        final_name = f".{path.name}.final-remove-{uuid.uuid4().hex}"
        rename_noreplace_at(parent, path.name, final_name)
        moved = os.stat(final_name, dir_fd=parent, follow_symlinks=False)
        if _identity(moved) != expected:
            outcome = _restore_or_preserve_posix(parent, final_name, path.name)
            _sync_posix_directory(parent)
            raise ExactTreeError("private directory changed during cleanup; " + outcome)
        os.rmdir(final_name, dir_fd=parent)
        _sync_posix_directory(parent)
    except OSError as exc:
        if isinstance(exc, ExactTreeError):
            raise
        raise ExactTreeError(f"cannot remove private directory: {path}") from exc
    finally:
        if directory >= 0:
            os.close(directory)
        os.close(parent)


def _windows_members(path: Path) -> tuple[str, ...]:
    try:
        return tuple(entry.name for entry in os.scandir(path))
    except OSError as exc:
        raise ExactTreeError(f"cannot inspect private directory: {path}") from exc


def _remove_windows_contents(api: object, handle: object, path: Path) -> None:
    """Remove children through exact native handles while their parent is held."""

    # The private native API is shared with secure-path publication so this
    # cleanup uses the same no-reparse, handle-relative operations.
    from reprobit.secure_paths_windows import _WindowsHandles

    assert isinstance(api, _WindowsHandles)
    names = _windows_members(path)
    for name in names:
        child_path = path / name
        directory = None
        with suppress(SecurePathError):
            directory = api.open_relative(
                handle,
                name,
                directory=True,
                delete=True,
                deny_other_writes=True,
            )
        if directory is not None:
            try:
                _remove_windows_contents(api, directory, child_path)
                api.delete_on_close(directory)
            finally:
                api.close(directory)
            continue

        file_handle = None
        try:
            file_handle = api.open_relative(
                handle,
                name,
                directory=False,
                delete=True,
                deny_other_writes=True,
                read_data=False,
            )
        except SecurePathError:
            try:
                file_handle = api.open_relative(
                    handle,
                    name,
                    directory=False,
                    delete=True,
                    deny_other_writes=True,
                    read_data=False,
                    allow_redirect=True,
                )
            except SecurePathError as exc:
                raise ExactTreeError(f"private directory member changed: {child_path}") from exc
            assert file_handle is not None
            try:
                api.delete_on_close(file_handle)
            finally:
                api.close(file_handle)
        else:
            assert file_handle is not None
            try:
                api.delete_on_close(file_handle)
            finally:
                api.close(file_handle)
    if _windows_members(path):
        raise ExactTreeError("private directory gained members during cleanup")


def _remove_windows_tree(path: Path, expected: DirectoryIdentity) -> None:
    from reprobit.secure_paths_windows import _WindowsHandles

    api = _WindowsHandles()
    parent = None
    directory = None
    try:
        parent = api.root(path.parent)
        directory = api.open_relative(
            parent,
            path.name,
            directory=True,
            delete=True,
            deny_other_writes=True,
        )
        if directory is None or api.identity(directory)[:2] != expected:
            raise ExactTreeError(f"private directory changed before cleanup: {path}")
        _remove_windows_contents(api, directory, path)
        api.delete_on_close(directory)
    except (OSError, SecurePathError) as exc:
        if isinstance(exc, ExactTreeError):
            raise
        raise ExactTreeError(f"cannot remove private directory: {path}") from exc
    finally:
        if directory is not None:
            api.close(directory)
        if parent is not None:
            api.close(parent)


def remove_exact_empty_directory(path: Path, expected: DirectoryIdentity) -> None:
    """Remove one exact empty directory without sweeping concurrent contents."""

    if os.name == "nt":
        from reprobit.secure_paths_windows import _WindowsHandles

        api = _WindowsHandles()
        parent = None
        directory = None
        try:
            parent = api.root(path.parent)
            directory = api.open_relative(
                parent,
                path.name,
                directory=True,
                delete=True,
                deny_other_writes=True,
            )
            if directory is None or api.identity(directory)[:2] != expected:
                raise ExactTreeError(f"private directory changed before cleanup: {path}")
            if _windows_members(path):
                raise ExactTreeError(f"private directory is not empty: {path}")
            api.delete_on_close(directory)
        except (OSError, SecurePathError) as exc:
            if isinstance(exc, ExactTreeError):
                raise
            raise ExactTreeError(f"cannot remove private empty directory: {path}") from exc
        finally:
            if directory is not None:
                api.close(directory)
            if parent is not None:
                api.close(parent)
        return

    parent = os.open(path.parent, no_follow_directory_flags())
    directory = -1
    try:
        directory = os.open(path.name, no_follow_directory_flags(), dir_fd=parent)
        held = os.fstat(directory)
        if _identity(held) != expected:
            raise ExactTreeError(f"private directory changed before cleanup: {path}")
        if os.listdir(directory):
            raise ExactTreeError(f"private directory is not empty: {path}")
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if _identity(named) != expected:
            raise ExactTreeError(f"private directory changed during cleanup: {path}")
        final_name = f".{path.name}.empty-remove-{uuid.uuid4().hex}"
        rename_noreplace_at(parent, path.name, final_name)
        moved = os.stat(final_name, dir_fd=parent, follow_symlinks=False)
        if _identity(moved) != expected:
            outcome = _restore_or_preserve_posix(parent, final_name, path.name)
            _sync_posix_directory(parent)
            raise ExactTreeError("private directory changed during cleanup; " + outcome)
        try:
            os.rmdir(final_name, dir_fd=parent)
        except OSError as exc:
            outcome = _restore_or_preserve_posix(parent, final_name, path.name)
            _sync_posix_directory(parent)
            raise ExactTreeError(f"private directory was not empty at cleanup; {outcome}") from exc
        _sync_posix_directory(parent)
    except OSError as exc:
        if isinstance(exc, ExactTreeError):
            raise
        raise ExactTreeError(f"cannot remove private empty directory: {path}") from exc
    finally:
        if directory >= 0:
            os.close(directory)
        os.close(parent)


def remove_exact_directory_tree(path: Path, expected: DirectoryIdentity) -> None:
    """Remove only the exact directory already captured by the caller."""

    if os.name == "nt":
        _remove_windows_tree(path, expected)
    else:
        _remove_posix_tree(path, expected)


__all__ = [
    "DirectoryIdentity",
    "ExactTreeError",
    "create_directory_in_exact_parent",
    "ensure_directory_in_exact_root",
    "move_directory_in_exact_parent",
    "remove_exact_directory_tree",
    "remove_exact_empty_directory",
]
