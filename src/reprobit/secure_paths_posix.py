"""POSIX handle-relative secure path implementation."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TypeVar

from reprobit.model import Digest
from reprobit.secure_path_contracts import (
    STREAM_COPY_CHUNK,
    BinaryReader,
    SecureFileIdentity,
    SecureFileSnapshot,
    SecurePathError,
    canonical_relative_path,
    no_follow_directory_flags,
    no_follow_file_flags,
    validate_stream_expectations,
)

_T = TypeVar("_T")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
    )


def _publication_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    """Identity fields that must survive a legitimate link/rename commit.

    POSIX may advance ctime when a link count or name changes.  Publication
    therefore captures a new ctime immediately after commit, while requiring
    every other file attribute—including mode—to remain the staged value.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_mode,
    )


def _matches_posix_snapshot(
    metadata: os.stat_result,
    expected: SecureFileSnapshot,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_dev == expected.device
        and metadata.st_ino == expected.inode
        and metadata.st_size == expected.size
        and metadata.st_mtime_ns == expected.mtime_ns
        and metadata.st_ctime_ns == expected.ctime_ns
        and metadata.st_mode == expected.mode
    )


class _HeldPosixRoot:
    def __init__(self, root: Path) -> None:
        if os.name != "posix" or os.open not in os.supports_dir_fd:
            raise SecurePathError(
                "certifying path operations require POSIX handle-relative opens; "
                "native Windows support is not yet implemented"
            )
        self.path = root.resolve(strict=True)
        try:
            self.fd = os.open(self.path, no_follow_directory_flags())
        except OSError as exc:
            raise SecurePathError(f"cannot hold secure path root {self.path}: {exc}") from exc
        metadata = os.fstat(self.fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(self.fd)
            raise SecurePathError(f"secure path root is not a directory: {self.path}")
        self.identity = (metadata.st_dev, metadata.st_ino)
        self._verify_root_path()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> _HeldPosixRoot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _verify_root_path(self) -> None:
        try:
            metadata = os.stat(self.path, follow_symlinks=False)
        except OSError as exc:
            raise SecurePathError(
                f"secure path root changed while held: {self.path}: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != self.identity
        ):
            raise SecurePathError(f"secure path root changed while held: {self.path}")

    def parent_chain(
        self, relative: PurePosixPath, *, create: bool
    ) -> tuple[list[int], list[tuple[int, str, tuple[int, int]]], str]:
        descriptors = [os.dup(self.fd)]
        edges: list[tuple[int, str, tuple[int, int]]] = []
        try:
            for component in relative.parts[:-1]:
                parent = descriptors[-1]
                if create:
                    try:
                        os.mkdir(component, mode=0o755, dir_fd=parent)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise SecurePathError(
                            f"cannot create secure path component {component!r}: {exc}"
                        ) from exc
                try:
                    child = os.open(component, no_follow_directory_flags(), dir_fd=parent)
                except OSError as exc:
                    raise SecurePathError(
                        f"secure path component is absent or redirected: {component!r}"
                    ) from exc
                metadata = os.fstat(child)
                if not stat.S_ISDIR(metadata.st_mode):
                    os.close(child)
                    raise SecurePathError(
                        f"secure path component is not a directory: {component!r}"
                    )
                edges.append((parent, component, (metadata.st_dev, metadata.st_ino)))
                descriptors.append(child)
            return descriptors, edges, relative.parts[-1]
        except BaseException:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    def recheck(
        self,
        edges: list[tuple[int, str, tuple[int, int]]],
    ) -> None:
        self._verify_root_path()
        for parent, component, expected in edges:
            try:
                metadata = os.stat(component, dir_fd=parent, follow_symlinks=False)
            except OSError as exc:
                raise SecurePathError(
                    f"secure path component changed while held: {component!r}"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != expected:
                raise SecurePathError(f"secure path component changed while held: {component!r}")


def _inspect_leaf(
    root: Path,
    relative: str,
    *,
    consume: Callable[[int], _T],
    verify: Callable[[os.stat_result, _T], bool] | None = None,
    action: str,
    verb: str,
    open_failure: str | None = None,
) -> tuple[Path, os.stat_result, _T]:
    """Open one regular leaf no-follow, consume it, and prove it never changed.

    The leaf is opened through a held ancestor chain, ``consume`` runs on the
    open descriptor, and the descriptor, the directory entry and every held
    ancestor are then re-verified before ``(path, metadata, result)`` returns.
    """

    canonical = canonical_relative_path(relative)
    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=parent,
                )
            except OSError as exc:
                if open_failure is None:
                    raise
                raise SecurePathError(f"{open_failure}: {relative!r}") from exc
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise SecurePathError(f"secure source input is not regular: {relative!r}")
            result = consume(descriptor)
            after = os.fstat(descriptor)
            if _identity(before) != _identity(after) or (
                verify is not None and not verify(after, result)
            ):
                raise SecurePathError(f"secure source input changed while {verb}: {relative!r}")
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(terminal) != _identity(after) or not stat.S_ISREG(terminal.st_mode):
                raise SecurePathError(
                    f"secure source input changed identity while {verb}: {relative!r}"
                )
            held.recheck(edges)
            return held.path.joinpath(*canonical.parts), after, result
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"cannot securely {action} source input {relative!r}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def _read_whole(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, STREAM_COPY_CHUNK):
        chunks.append(chunk)
    return b"".join(chunks)


def _hash_whole(descriptor: int) -> tuple[Digest, int]:
    hasher = hashlib.sha256()
    size = 0
    while block := os.read(descriptor, STREAM_COPY_CHUNK):
        hasher.update(block)
        size += len(block)
    return Digest(value=hasher.hexdigest()), size


def read_relative_file(root: Path, relative: str) -> tuple[bytes, SecureFileSnapshot]:
    """Read one regular file through a fully held, no-follow ancestor chain."""

    path, after, payload = _inspect_leaf(
        root,
        relative,
        consume=_read_whole,
        verify=lambda metadata, payload: len(payload) == metadata.st_size,
        action="read",
        verb="read",
        open_failure="secure source input is absent or redirected",
    )
    return payload, SecureFileSnapshot(
        path,
        Digest.from_bytes(payload),
        len(payload),
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_mode,
        after.st_ctime_ns,
    )


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        if exc.errno not in {errno.EINVAL, getattr(errno, "ENOTSUP", errno.EINVAL)}:
            raise


def _unlink_posix_name_if_exact(
    parent: int,
    name: str,
    descriptor: int,
    expected: os.stat_result,
) -> bool:
    """Remove only the still-named inode held by ``descriptor``.

    Publication rollback runs after a destination name has become shared
    state.  A peer replacement must survive even when our later validation
    fails.
    """

    try:
        terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
        held = os.fstat(descriptor)
        if (
            not stat.S_ISREG(terminal.st_mode)
            or _identity(terminal) != _identity(held)
            or _publication_identity(held) != _publication_identity(expected)
        ):
            return False
        os.unlink(name, dir_fd=parent)
    except OSError:
        return False
    return True


def atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    replace: bool,
    expected: SecureFileSnapshot | None = None,
    mode: int = 0o644,
) -> SecureFileSnapshot:
    canonical = canonical_relative_path(relative)
    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=True)
        temporary = f".{name}.reprobit-{uuid.uuid4().hex}"
        descriptor = -1
        temporary_exists = False
        published = False
        committed = False
        try:
            parent = descriptors[-1]
            try:
                previous = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if expected is not None:
                    raise SecurePathError(
                        f"publication preimage disappeared: {relative!r}"
                    ) from None
            except OSError as exc:
                raise SecurePathError(
                    f"cannot inspect publication target {relative!r}: {exc}"
                ) from exc
            else:
                if not stat.S_ISREG(previous.st_mode):
                    raise SecurePathError(
                        f"secure publication refuses a redirected/non-regular target: {relative!r}"
                    )
                if expected is not None and not _matches_posix_snapshot(previous, expected):
                    raise SecurePathError(f"publication preimage changed: {relative!r}")
                if not replace:
                    raise SecurePathError(
                        f"secure create-if-absent target already exists: {relative!r}"
                    )
            descriptor = os.open(
                temporary,
                no_follow_file_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL),
                0o600,
                dir_fd=parent,
            )
            temporary_exists = True
            os.fchmod(descriptor, mode)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SecurePathError(f"short secure publication write: {relative!r}")
                view = view[written:]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(payload):
                raise SecurePathError(
                    f"secure publication produced a non-regular/short file: {relative!r}"
                )
            try:
                if replace:
                    if expected is not None:
                        try:
                            current_preimage = os.stat(
                                name,
                                dir_fd=parent,
                                follow_symlinks=False,
                            )
                        except FileNotFoundError as exc:
                            raise SecurePathError(
                                f"publication preimage disappeared: {relative!r}"
                            ) from exc
                        if not _matches_posix_snapshot(current_preimage, expected):
                            raise SecurePathError(f"publication preimage changed: {relative!r}")
                    os.replace(
                        temporary,
                        name,
                        src_dir_fd=parent,
                        dst_dir_fd=parent,
                    )
                else:
                    # A same-directory hard-link is an atomic no-overwrite
                    # commit.  The still-held descriptor continues to name the
                    # published inode, so content/identity can be revalidated
                    # before the temporary name is removed.
                    os.link(
                        temporary,
                        name,
                        src_dir_fd=parent,
                        dst_dir_fd=parent,
                        follow_symlinks=False,
                    )
                    published = True
                    os.unlink(temporary, dir_fd=parent)
            except OSError as exc:
                action = "replace" if replace else "create"
                raise SecurePathError(
                    f"cannot atomically {action} publication target {relative!r}: {exc}"
                ) from exc
            published = True
            temporary_exists = False
            published_metadata = os.fstat(descriptor)
            if _publication_identity(published_metadata) != _publication_identity(metadata):
                raise SecurePathError(
                    f"publication target attributes changed during commit: {relative!r}"
                )
            _sync_directory(parent)
            os.lseek(descriptor, 0, os.SEEK_SET)
            received_parts: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                received_parts.append(block)
            after = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(terminal.st_mode)
                or _identity(after) != _identity(published_metadata)
                or _identity(terminal) != _identity(published_metadata)
                or Digest.from_bytes(b"".join(received_parts)) != Digest.from_bytes(payload)
            ):
                raise SecurePathError(f"publication target changed during commit: {relative!r}")
            held.recheck(edges)
            committed = True
            return SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                Digest.from_bytes(payload),
                len(payload),
                terminal.st_dev,
                terminal.st_ino,
                terminal.st_mtime_ns,
                terminal.st_mode,
                terminal.st_ctime_ns,
            )
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(f"secure publication failed for {relative!r}: {exc}") from exc
        finally:
            if temporary_exists:
                with suppress(OSError):
                    os.unlink(temporary, dir_fd=descriptors[-1])
            if published and not committed:
                _unlink_posix_name_if_exact(descriptors[-1], name, descriptor, metadata)
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def atomic_publish_new_relative_from_stream(
    root: Path,
    relative: str,
    source: BinaryReader,
    *,
    mode: int,
    expected_digest: Digest | None,
    expected_size: int | None,
) -> SecureFileSnapshot:
    canonical = canonical_relative_path(relative)
    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=True)
        temporary = f".{name}.reprobit-{uuid.uuid4().hex}"
        descriptor = -1
        temporary_exists = False
        published = False
        committed = False
        try:
            parent = descriptors[-1]
            try:
                previous = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise SecurePathError(
                    f"cannot inspect streamed publication target {relative!r}: {exc}"
                ) from exc
            else:
                if not stat.S_ISREG(previous.st_mode):
                    raise SecurePathError(
                        "secure streamed publication refuses a redirected/non-regular "
                        f"target: {relative!r}"
                    )
                raise SecurePathError(
                    f"secure create-if-absent target already exists: {relative!r}"
                )
            descriptor = os.open(
                temporary,
                no_follow_file_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                0o600,
                dir_fd=parent,
            )
            temporary_exists = True
            os.fchmod(descriptor, mode)
            hasher = hashlib.sha256()
            size = 0
            while True:
                block = source.read(STREAM_COPY_CHUNK)
                if not block:
                    break
                if type(block) is not bytes:
                    raise TypeError("secure publication stream must return bytes")
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SecurePathError(f"short streamed publication write: {relative!r}")
                    view = view[written:]
                hasher.update(block)
                size += len(block)
            os.fsync(descriptor)
            digest = Digest(value=hasher.hexdigest())
            validate_stream_expectations(
                digest,
                size,
                expected_digest=expected_digest,
                expected_size=expected_size,
                relative=relative,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
                raise SecurePathError(
                    f"streamed publication produced a non-regular/short file: {relative!r}"
                )
            try:
                os.link(
                    temporary,
                    name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                published = True
                os.unlink(temporary, dir_fd=parent)
            except OSError as exc:
                raise SecurePathError(
                    f"cannot atomically create publication target {relative!r}: {exc}"
                ) from exc
            temporary_exists = False
            published_metadata = os.fstat(descriptor)
            if _publication_identity(published_metadata) != _publication_identity(metadata):
                raise SecurePathError(
                    f"streamed publication target attributes changed during commit: {relative!r}"
                )
            _sync_directory(parent)
            after = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(terminal.st_mode)
                or _identity(after) != _identity(published_metadata)
                or _identity(terminal) != _identity(published_metadata)
            ):
                raise SecurePathError(
                    f"streamed publication target changed during commit: {relative!r}"
                )
            held.recheck(edges)
            committed = True
            return SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                digest,
                size,
                terminal.st_dev,
                terminal.st_ino,
                terminal.st_mtime_ns,
                terminal.st_mode,
                terminal.st_ctime_ns,
            )
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"secure streamed publication failed for {relative!r}: {exc}"
            ) from exc
        finally:
            if temporary_exists:
                with suppress(OSError):
                    os.unlink(temporary, dir_fd=descriptors[-1])
            if published and not committed:
                _unlink_posix_name_if_exact(descriptors[-1], name, descriptor, metadata)
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def stat_relative_file(root: Path, relative: str) -> SecureFileIdentity:
    """Inspect one regular file through a held ancestor chain without reading it."""

    path, metadata, _nothing = _inspect_leaf(
        root, relative, consume=lambda _descriptor: None, action="inspect", verb="inspected"
    )
    return SecureFileIdentity(
        path,
        metadata.st_size,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mtime_ns,
        metadata.st_mode,
        metadata.st_ctime_ns,
    )


def digest_relative_file(root: Path, relative: str) -> SecureFileSnapshot:
    """Hash one regular file through a held ancestor chain with bounded memory."""

    path, after, (digest, size) = _inspect_leaf(
        root,
        relative,
        consume=_hash_whole,
        verify=lambda metadata, hashed: hashed[1] == metadata.st_size,
        action="hash",
        verb="hashed",
    )
    return SecureFileSnapshot(
        path,
        digest,
        size,
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_mode,
        after.st_ctime_ns,
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
) -> SecureFileSnapshot:
    """Copy one held source to a new held destination in a single pass."""

    source_path = canonical_relative_path(source_relative)

    with _HeldPosixRoot(source_root) as held:
        descriptors, edges, name = held.parent_chain(source_path, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            descriptor = os.open(
                name,
                no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                dir_fd=parent,
            )
            before_stat = os.fstat(descriptor)
            if not stat.S_ISREG(before_stat.st_mode):
                raise SecurePathError(f"secure copy source is not regular: {source_relative!r}")
            if expected_source is not None and (
                before_stat.st_dev != expected_source.device
                or before_stat.st_ino != expected_source.inode
                or before_stat.st_size != expected_source.size
                or before_stat.st_mtime_ns != expected_source.mtime_ns
                or before_stat.st_mode != expected_source.mode
                or before_stat.st_ctime_ns != expected_source.ctime_ns
            ):
                raise SecurePathError(
                    f"secure copy source changed before read: {source_relative!r}"
                )
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                result = atomic_publish_new_relative_from_stream(
                    destination_root,
                    destination_relative,
                    stream,
                    mode=0o755 if executable else 0o644,
                    expected_digest=expected_digest,
                    expected_size=expected_size,
                )
            after_stat = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            content_authorized = expected_digest is not None and expected_size is not None
            source_identity = _publication_identity if content_authorized else _identity
            if (
                source_identity(before_stat) != source_identity(after_stat)
                or source_identity(after_stat) != source_identity(terminal)
                or not stat.S_ISREG(terminal.st_mode)
                or result.size != after_stat.st_size
            ):
                raise SecurePathError(f"secure copy source changed while read: {source_relative!r}")
            held.recheck(edges)
            return result
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"secure copy failed for source {source_relative!r}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def promote_relative_new(
    root: Path,
    source_relative: str,
    destination_relative: str,
    *,
    expected: SecureFileSnapshot,
) -> SecureFileSnapshot:
    """Move an exact held file to a new name with commit-time no-overwrite."""

    source_path = canonical_relative_path(source_relative)
    destination_path = canonical_relative_path(destination_relative)
    if source_path == destination_path:
        raise SecurePathError("secure promotion source and destination overlap")

    with _HeldPosixRoot(root) as held:
        source_descriptors, source_edges, source_name = held.parent_chain(source_path, create=False)
        destination_descriptors, destination_edges, destination_name = held.parent_chain(
            destination_path, create=True
        )
        descriptor = -1
        destination_published = False
        source_removed = False
        try:
            source_parent = source_descriptors[-1]
            destination_parent = destination_descriptors[-1]
            descriptor = os.open(
                source_name,
                no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                dir_fd=source_parent,
            )
            before_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before_stat.st_mode)
                or before_stat.st_dev != expected.device
                or before_stat.st_ino != expected.inode
                or before_stat.st_size != expected.size
                or before_stat.st_mtime_ns != expected.mtime_ns
            ):
                raise SecurePathError(f"secure promotion source changed: {source_relative!r}")
            try:
                previous = os.stat(
                    destination_name,
                    dir_fd=destination_parent,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(previous.st_mode):
                    raise SecurePathError(
                        "secure promotion refuses a redirected/non-regular target: "
                        f"{destination_relative!r}"
                    )
                raise SecurePathError(
                    f"secure create-if-absent target already exists: {destination_relative!r}"
                )
            os.link(
                source_name,
                destination_name,
                src_dir_fd=source_parent,
                dst_dir_fd=destination_parent,
                follow_symlinks=False,
            )
            destination_published = True
            terminal = os.stat(
                destination_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            after_stat = os.fstat(descriptor)
            if _publication_identity(after_stat) != _publication_identity(before_stat) or _identity(
                terminal
            ) != _identity(after_stat):
                raise SecurePathError(f"secure promotion target changed: {destination_relative!r}")
            held.recheck(source_edges)
            held.recheck(destination_edges)
            _sync_directory(destination_parent)
            os.unlink(source_name, dir_fd=source_parent)
            source_removed = True
            _sync_directory(source_parent)
            final_stat = os.fstat(descriptor)
            final_terminal = os.stat(
                destination_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            if _publication_identity(final_stat) != _publication_identity(after_stat) or _identity(
                final_terminal
            ) != _identity(final_stat):
                raise SecurePathError(f"secure promotion target changed: {destination_relative!r}")
            return SecureFileSnapshot(
                held.path.joinpath(*destination_path.parts),
                expected.digest,
                expected.size,
                final_terminal.st_dev,
                final_terminal.st_ino,
                final_terminal.st_mtime_ns,
                final_terminal.st_mode,
                final_terminal.st_ctime_ns,
            )
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"secure promotion failed for {destination_relative!r}: {exc}"
            ) from exc
        finally:
            if destination_published and not source_removed:
                _unlink_posix_name_if_exact(
                    destination_descriptors[-1],
                    destination_name,
                    descriptor,
                    before_stat,
                )
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(destination_descriptors):
                os.close(current)
            for current in reversed(source_descriptors):
                os.close(current)


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

    canonical = canonical_relative_path(relative)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=parent,
                )
            except FileNotFoundError:
                return False
            except OSError:
                return False
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_dev != expected.device
                or before.st_ino != expected.inode
                or before.st_size != expected.size
                or before.st_mtime_ns != expected.mtime_ns
                or before.st_mode != expected.mode
                or before.st_ctime_ns != expected.ctime_ns
            ):
                return False
            payload_parts: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                payload_parts.append(block)
            after = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                _identity(before) != _identity(after)
                or _identity(after) != _identity(terminal)
                or Digest.from_bytes(b"".join(payload_parts)) != expected.digest
            ):
                return False
            os.unlink(name, dir_fd=parent)
            _sync_directory(parent)
            held.recheck(edges)
            return True
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def remove_regular_relative(root: Path, relative: str) -> bool:
    """Remove one named regular file through a held no-follow ancestor chain."""

    canonical = canonical_relative_path(relative)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=parent,
                )
            except FileNotFoundError:
                return False
            before = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(terminal):
                raise SecurePathError(
                    f"secure removal target is redirected/non-regular: {relative!r}"
                )
            os.unlink(name, dir_fd=parent)
            _sync_directory(parent)
            held.recheck(edges)
            return True
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(f"secure removal failed for {relative!r}: {exc}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


@contextmanager
def hold_relative_file_set(
    root: Path,
    expected: Mapping[str, SecureFileSnapshot],
) -> Iterator[Mapping[str, SecureFileSnapshot]]:
    """Hold and validate one complete named file set through caller receipt use.

    Every file handle is opened before the set is yielded.  After all content
    has been hashed, and again after the caller finishes constructing receipts,
    every named entry is compared with its still-held capability.  This gives
    multi-output callers one bounded validation interval without pretending
    that unrelated POSIX directory entries can be atomically committed.
    """

    canonical = {
        value: canonical_relative_path(value) for value in sorted(expected, key=str.casefold)
    }
    if len({value.casefold() for value in canonical}) != len(canonical):
        raise SecurePathError("held file set contains a DOS-case path collision")

    with _HeldPosixRoot(root) as held:
        opened_posix: list[
            tuple[str, list[int], list[tuple[int, str, tuple[int, int]]], str, int]
        ] = []
        snapshots = {}
        try:
            for relative, path in canonical.items():
                descriptors, edges, name = held.parent_chain(path, create=False)
                descriptor = os.open(
                    name,
                    no_follow_file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=descriptors[-1],
                )
                opened_posix.append((relative, descriptors, edges, name, descriptor))
                before = os.fstat(descriptor)
                expected_snapshot = expected[relative]
                if not _matches_posix_snapshot(before, expected_snapshot):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                hasher = hashlib.sha256()
                size = 0
                while block := os.read(descriptor, STREAM_COPY_CHUNK):
                    hasher.update(block)
                    size += len(block)
                after = os.fstat(descriptor)
                if (
                    _identity(before) != _identity(after)
                    or size != expected_snapshot.size
                    or Digest(value=hasher.hexdigest()) != expected_snapshot.digest
                ):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                snapshots[relative] = SecureFileSnapshot(
                    held.path.joinpath(*path.parts),
                    expected_snapshot.digest,
                    expected_snapshot.size,
                    after.st_dev,
                    after.st_ino,
                    after.st_mtime_ns,
                    after.st_mode,
                    after.st_ctime_ns,
                )
            for relative, descriptors, edges, name, descriptor in opened_posix:
                named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
                current = os.fstat(descriptor)
                if _identity(named) != _identity(current) or not _matches_posix_snapshot(
                    current, expected[relative]
                ):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                held.recheck(edges)
            yield MappingProxyType(snapshots)
            for relative, descriptors, edges, name, descriptor in opened_posix:
                named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
                current = os.fstat(descriptor)
                if _identity(named) != _identity(current) or not _matches_posix_snapshot(
                    current, expected[relative]
                ):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                held.recheck(edges)
        finally:
            for _relative_value, descriptors, _edges, _name, descriptor in reversed(opened_posix):
                os.close(descriptor)
                for current_descriptor in reversed(descriptors):
                    os.close(current_descriptor)
