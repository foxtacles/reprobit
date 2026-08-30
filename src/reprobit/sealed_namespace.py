"""Lifetime seals for producer-readable filesystem namespaces.

Certification cannot infer the bytes read by an opaque classic compiler from a
later diagnostic replay.  Instead, ReproBit exposes a finite run-private
namespace and holds that complete namespace immutable for the producer
lifetime.  Every regular file is retained by handle and every directory entry
and change-time is rechecked before the lease is released.

The POSIX implementation uses ``openat``/``O_NOFOLLOW`` throughout.  A write
followed by byte restoration still changes the held inode's ``ctime``; a
transient create/delete or path swap changes a held directory's membership or
``ctime``.  Native Windows uses share-read-only handles for every admitted
file and directory plus a recursive directory-change watcher for each tree.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol, Self

try:
    import resource
except ImportError:  # pragma: no cover - native Windows
    resource = None  # type: ignore[assignment]

from reprobit.model import Digest
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths_windows import _WindowsHandles


class SealedNamespaceError(SecurePathError):
    """A producer-readable namespace changed during its lifetime lease."""


@dataclass(frozen=True, slots=True)
class NamespaceTree:
    """One complete readable tree rooted beneath a held trusted anchor."""

    label: str
    root: Path
    anchor: Path


@dataclass(frozen=True, slots=True)
class NamespaceFile:
    """One standalone readable file rooted beneath a held trusted anchor."""

    label: str
    path: Path
    anchor: Path


@dataclass(frozen=True, slots=True)
class SealedNamespaceFile:
    """Immutable payload and identity of one held readable file."""

    label: str
    relative_path: str
    path: Path
    digest: Digest
    size: int
    payload: bytes | None = None


@dataclass(frozen=True, slots=True)
class SealedNamespaceSnapshot:
    """Canonical complete file census carried by one active lease."""

    files: tuple[SealedNamespaceFile, ...]

    def files_for(self, label: str) -> tuple[SealedNamespaceFile, ...]:
        return tuple(item for item in self.files if item.label == label)


_Metadata = tuple[int, int, int, int, int, int, int]
_DESCRIPTOR_RESERVE = 128


def _metadata(value: os.stat_result) -> _Metadata:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _read_descriptor(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            break
        chunks.append(block)
        offset += len(block)
    payload = b"".join(chunks)
    if len(payload) != size:
        raise SealedNamespaceError("held namespace file produced a short read")
    return payload


def estimate_namespace_descriptor_requirement(
    trees: Sequence[NamespaceTree],
    files: Sequence[NamespaceFile],
) -> int:
    """Estimate the exact lexical file/directory handles for a POSIX lease."""

    directories: set[Path] = set()
    regular_files = len(files)

    def add_chain(path: Path) -> None:
        lexical = path.absolute()
        current = Path(lexical.anchor)
        directories.add(current)
        for component in lexical.parts[1:]:
            current /= component
            directories.add(current)

    for tree in trees:
        add_chain(tree.anchor)
        add_chain(tree.root)
        try:
            for entry in tree.root.rglob("*"):
                if entry.is_dir() and not entry.is_symlink():
                    directories.add(entry.absolute())
                else:
                    regular_files += 1
        except OSError as exc:
            raise SealedNamespaceError(
                f"cannot census namespace descriptor demand: {tree.root}"
            ) from exc
    for item in files:
        add_chain(item.anchor)
        add_chain(item.path.parent)
    return len(directories) + regular_files


def _open_descriptor_count() -> int:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            return len(tuple(root.iterdir()))
        except OSError:
            continue
    return 0


@dataclass(slots=True)
class _PosixDirectory:
    path: Path
    descriptor: int
    parent: int | None
    name: str | None
    metadata: _Metadata
    members: tuple[str, ...]
    seal_change: bool
    seal_contents: bool


@dataclass(slots=True)
class _PosixFile:
    public: SealedNamespaceFile
    descriptor: int
    parent: int
    name: str
    metadata: _Metadata


class _PosixNamespaceLease:
    def __init__(
        self,
        trees: Sequence[NamespaceTree],
        files: Sequence[NamespaceFile],
        *,
        retain_payload_labels: frozenset[str],
    ) -> None:
        if os.name != "posix" or os.open not in os.supports_dir_fd:
            raise SealedNamespaceError("POSIX namespace lease is unavailable")
        self._directories: dict[tuple[int, int], _PosixDirectory] = {}
        self._files: list[_PosixFile] = []
        self._closed = False
        self._retain_payload_labels = retain_payload_labels
        self._require_descriptor_capacity(trees, files)
        try:
            for tree in sorted(trees, key=lambda item: (item.label, str(item.root))):
                root = self._open_path(tree.anchor, tree.root, expect_directory=True)
                self._walk_tree(tree.label, root, PurePosixPath())
            for item in sorted(files, key=lambda value: (value.label, str(value.path))):
                self._open_standalone_file(item)
        except BaseException:
            self._close_descriptors()
            raise

    @staticmethod
    def _require_descriptor_capacity(
        trees: Sequence[NamespaceTree], files: Sequence[NamespaceFile]
    ) -> None:
        estimated = estimate_namespace_descriptor_requirement(trees, files)
        try:
            if resource is None:
                return
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            current = _open_descriptor_count()
        except (OSError, ValueError):
            return
        required_limit = current + estimated + _DESCRIPTOR_RESERVE
        if soft == resource.RLIM_INFINITY or required_limit <= soft:
            return
        hard_allows = hard == resource.RLIM_INFINITY or required_limit <= hard
        if hard_allows:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (required_limit, hard))
                soft, _unchanged_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            except (OSError, ValueError):
                pass
            else:
                if soft == resource.RLIM_INFINITY or required_limit <= soft:
                    return
        hard_text = "unlimited" if hard == resource.RLIM_INFINITY else str(hard)
        if soft != resource.RLIM_INFINITY and required_limit > soft:
            raise SealedNamespaceError(
                "producer-readable namespace descriptor preflight failed: "
                f"lease={estimated}, open={current}, reserve={_DESCRIPTOR_RESERVE}, "
                f"required-soft-limit={required_limit}, soft={soft}, hard={hard_text}; "
                f"raise the hard limit if needed, then run `ulimit -n {required_limit}`"
            )

    def _open_anchor(self, anchor: Path) -> _PosixDirectory:
        lexical = anchor.absolute()
        filesystem_root = Path(lexical.anchor)
        try:
            descriptor = os.open(filesystem_root, _directory_flags())
        except OSError as exc:
            raise SealedNamespaceError(
                f"namespace filesystem root is absent or redirected: {filesystem_root}"
            ) from exc
        received = os.fstat(descriptor)
        if not stat.S_ISDIR(received.st_mode):
            os.close(descriptor)
            raise SealedNamespaceError(f"namespace anchor is not a directory: {lexical}")
        key = (received.st_dev, received.st_ino)
        existing = self._directories.get(key)
        if existing is not None:
            os.close(descriptor)
            current = existing
        else:
            held = _PosixDirectory(
                filesystem_root,
                descriptor,
                None,
                None,
                _metadata(received),
                (),
                False,
                False,
            )
            self._directories[key] = held
            current = held
        try:
            relative = lexical.relative_to(filesystem_root)
        except ValueError as exc:
            raise SealedNamespaceError(
                f"namespace anchor lacks one filesystem root: {lexical}"
            ) from exc
        for component in relative.parts:
            current = self._open_child_directory(current, component, current.path / component)
        if not current.seal_change:
            current.metadata = _metadata(os.fstat(current.descriptor))
            current.seal_change = True
        return current

    def _open_child_directory(
        self,
        parent: _PosixDirectory,
        name: str,
        path: Path,
        *,
        seal_change: bool = False,
        seal_contents: bool = False,
    ) -> _PosixDirectory:
        try:
            descriptor = os.open(name, _directory_flags(), dir_fd=parent.descriptor)
        except OSError as exc:
            raise SealedNamespaceError(
                f"namespace directory is absent or redirected: {path}"
            ) from exc
        received = os.fstat(descriptor)
        if not stat.S_ISDIR(received.st_mode):
            os.close(descriptor)
            raise SealedNamespaceError(f"namespace path is not a directory: {path}")
        key = (received.st_dev, received.st_ino)
        existing = self._directories.get(key)
        if existing is not None:
            os.close(descriptor)
            if existing.path != path:
                raise SealedNamespaceError(
                    f"namespace aliases one directory at {existing.path} and {path}"
                )
            if (seal_change or seal_contents) and not existing.seal_change:
                existing.metadata = _metadata(os.fstat(existing.descriptor))
                existing.seal_change = True
            if seal_contents and not existing.seal_contents:
                existing.metadata = _metadata(os.fstat(existing.descriptor))
                existing.members = tuple(sorted(os.listdir(existing.descriptor), key=str.casefold))
                existing.seal_contents = True
            return existing
        held = _PosixDirectory(
            path,
            descriptor,
            parent.descriptor,
            name,
            _metadata(received),
            (tuple(sorted(os.listdir(descriptor), key=str.casefold)) if seal_contents else ()),
            seal_change or seal_contents,
            seal_contents,
        )
        self._directories[key] = held
        return held

    def _open_path(self, anchor: Path, target: Path, *, expect_directory: bool) -> _PosixDirectory:
        del expect_directory
        anchor_path = anchor.absolute()
        target_path = target.absolute()
        try:
            relative = target_path.relative_to(anchor_path)
        except ValueError as exc:
            raise SealedNamespaceError(
                f"namespace target {target_path} escapes anchor {anchor_path}"
            ) from exc
        current = self._open_anchor(anchor_path)
        for component in relative.parts:
            current = self._open_child_directory(
                current,
                component,
                current.path / component,
                seal_change=True,
            )
        if not current.seal_contents:
            current.metadata = _metadata(os.fstat(current.descriptor))
            current.members = tuple(sorted(os.listdir(current.descriptor), key=str.casefold))
            current.seal_contents = True
        return current

    def _walk_tree(self, label: str, directory: _PosixDirectory, relative: PurePosixPath) -> None:
        for name in directory.members:
            try:
                lexical = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
            except OSError as exc:
                raise SealedNamespaceError(
                    f"namespace entry disappeared during capture: {directory.path / name}"
                ) from exc
            child_relative = relative / name
            child_path = directory.path / name
            if stat.S_ISDIR(lexical.st_mode):
                child = self._open_child_directory(
                    directory,
                    name,
                    child_path,
                    seal_change=True,
                    seal_contents=True,
                )
                self._walk_tree(label, child, child_relative)
                continue
            if not stat.S_ISREG(lexical.st_mode):
                raise SealedNamespaceError(
                    f"namespace entry is not a regular file/directory: {child_path}"
                )
            self._open_file(
                label,
                child_relative.as_posix(),
                child_path,
                directory,
                name,
            )

    def _open_file(
        self,
        label: str,
        relative: str,
        path: Path,
        parent: _PosixDirectory,
        name: str,
    ) -> None:
        try:
            descriptor = os.open(name, _file_flags(), dir_fd=parent.descriptor)
        except OSError as exc:
            raise SealedNamespaceError(f"namespace file is absent or redirected: {path}") from exc
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            os.close(descriptor)
            raise SealedNamespaceError(f"namespace file is not regular: {path}")
        payload = _read_descriptor(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if _metadata(before) != _metadata(after):
            os.close(descriptor)
            raise SealedNamespaceError(f"namespace file changed during capture: {path}")
        self._files.append(
            _PosixFile(
                SealedNamespaceFile(
                    label,
                    relative,
                    path,
                    Digest.from_bytes(payload),
                    len(payload),
                    payload if label in self._retain_payload_labels else None,
                ),
                descriptor,
                parent.descriptor,
                name,
                _metadata(after),
            )
        )

    def _open_standalone_file(self, item: NamespaceFile) -> None:
        anchor = item.anchor.absolute()
        target = item.path.absolute()
        try:
            relative = target.relative_to(anchor)
        except ValueError as exc:
            raise SealedNamespaceError(f"namespace file {target} escapes anchor {anchor}") from exc
        if not relative.parts:
            raise SealedNamespaceError("namespace standalone file cannot equal its anchor")
        parent = self._open_anchor(anchor)
        for component in relative.parts[:-1]:
            parent = self._open_child_directory(
                parent,
                component,
                parent.path / component,
                seal_change=True,
            )
        self._open_file(
            item.label,
            relative.as_posix(),
            target,
            parent,
            relative.parts[-1],
        )

    @property
    def snapshot(self) -> SealedNamespaceSnapshot:
        return SealedNamespaceSnapshot(
            tuple(
                sorted(
                    (item.public for item in self._files),
                    key=lambda item: (item.label.casefold(), item.relative_path.casefold()),
                )
            )
        )

    def verify(self) -> None:
        failures: list[str] = []
        for held_directory in self._directories.values():
            try:
                received = os.fstat(held_directory.descriptor)
                members = (
                    tuple(sorted(os.listdir(held_directory.descriptor), key=str.casefold))
                    if held_directory.seal_contents
                    else ()
                )
                if (
                    held_directory.seal_change and _metadata(received) != held_directory.metadata
                ) or members != held_directory.members:
                    failures.append(str(held_directory.path))
                if held_directory.parent is not None and held_directory.name is not None:
                    named = os.stat(
                        held_directory.name,
                        dir_fd=held_directory.parent,
                        follow_symlinks=False,
                    )
                    named_changed = (
                        _metadata(named) != held_directory.metadata
                        if held_directory.seal_change
                        else (named.st_dev, named.st_ino)
                        != (
                            held_directory.metadata[0],
                            held_directory.metadata[1],
                        )
                    )
                    if named_changed:
                        failures.append(str(held_directory.path))
            except OSError:
                failures.append(str(held_directory.path))
        for held_file in self._files:
            try:
                received = os.fstat(held_file.descriptor)
                named = os.stat(
                    held_file.name,
                    dir_fd=held_file.parent,
                    follow_symlinks=False,
                )
                payload = _read_descriptor(held_file.descriptor, received.st_size)
                if (
                    _metadata(received) != held_file.metadata
                    or _metadata(named) != held_file.metadata
                    or len(payload) != held_file.public.size
                    or Digest.from_bytes(payload) != held_file.public.digest
                ):
                    failures.append(str(held_file.public.path))
            except OSError:
                failures.append(str(held_file.public.path))
        if failures:
            raise SealedNamespaceError(
                "producer-readable namespace changed while held: "
                + ", ".join(sorted(set(failures), key=str.casefold)[:12])
            )

    def _close_descriptors(self) -> None:
        if self._closed:
            return
        self._closed = True
        for held_file in reversed(self._files):
            os.close(held_file.descriptor)
        for held_directory in reversed(tuple(self._directories.values())):
            os.close(held_directory.descriptor)

    def close(self) -> None:
        try:
            self.verify()
        finally:
            self._close_descriptors()


_WindowsMetadata = tuple[int, bytes, int, int, int, int, int, bool, int]


@dataclass(slots=True)
class _WindowsDirectory:
    path: Path
    handle: Any
    parent: Any | None
    name: str | None
    metadata: _WindowsMetadata
    members: tuple[str, ...]
    seal_contents: bool


@dataclass(slots=True)
class _WindowsFile:
    public: SealedNamespaceFile
    handle: Any
    parent: Any
    name: str
    metadata: _WindowsMetadata


class _WindowsDirectoryWatcher:
    """One pending recursive ReadDirectoryChangesW request."""

    _ERROR_IO_INCOMPLETE = 996
    _ERROR_IO_PENDING = 997
    _ERROR_OPERATION_ABORTED = 995
    _BUFFER_SIZE = 1024 * 1024
    _NOTIFY_FILTER = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x100

    def __init__(
        self,
        api: _WindowsHandles,
        path: Path,
        expected_identity: _WindowsMetadata,
    ) -> None:
        self.api = api
        self.path = path
        ctypes = api.ctypes
        wintypes = api.wintypes

        Overlapped = type(
            "Overlapped",
            (ctypes.Structure,),
            {
                "_fields_": [
                    ("internal", ctypes.c_size_t),
                    ("internal_high", ctypes.c_size_t),
                    ("offset", wintypes.DWORD),
                    ("offset_high", wintypes.DWORD),
                    ("event", wintypes.HANDLE),
                ]
            },
        )

        api.kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        api.kernel32.CreateEventW.restype = wintypes.HANDLE
        api.kernel32.ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(Overlapped),
            ctypes.c_void_p,
        ]
        api.kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
        api.kernel32.GetOverlappedResult.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Overlapped),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
        ]
        api.kernel32.GetOverlappedResult.restype = wintypes.BOOL
        api.kernel32.CancelIoEx.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Overlapped),
        ]
        api.kernel32.CancelIoEx.restype = wintypes.BOOL

        handle = api.kernel32.CreateFileW(
            str(path),
            api._FILE_LIST_DIRECTORY,
            0x1,
            None,
            3,
            0x02000000 | 0x00200000 | 0x40000000,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise SealedNamespaceError(
                f"cannot watch native namespace tree {path}: {api.get_last_error()}"
            )
        self.handle = handle
        self.event: Any = None
        try:
            received = api.strong_identity(handle)
            if received != expected_identity:
                raise SealedNamespaceError(
                    f"native namespace watcher opened a different tree: {path}"
                )
            event = api.kernel32.CreateEventW(None, True, False, None)
            if not event:
                raise SealedNamespaceError(
                    f"cannot create native namespace watcher event: {api.get_last_error()}"
                )
            self.event = event
            self.overlapped = Overlapped()
            self.overlapped.event = event
            self.buffer = ctypes.create_string_buffer(self._BUFFER_SIZE)
            immediate = wintypes.DWORD()
            if not api.kernel32.ReadDirectoryChangesW(
                handle,
                self.buffer,
                len(self.buffer),
                True,
                self._NOTIFY_FILTER,
                ctypes.byref(immediate),
                ctypes.byref(self.overlapped),
                None,
            ):
                error = int(api.get_last_error())
                if error != self._ERROR_IO_PENDING:
                    raise SealedNamespaceError(
                        f"cannot arm native namespace watcher for {path}: {error}"
                    )
        except BaseException:
            self._discard()
            raise

    def changed(self) -> bool:
        transferred = self.api.wintypes.DWORD()
        if self.api.kernel32.GetOverlappedResult(
            self.handle,
            self.api.ctypes.byref(self.overlapped),
            self.api.ctypes.byref(transferred),
            False,
        ):
            # A completed zero-byte notification means the kernel overflowed
            # the caller's buffer.  It is still a namespace change.
            return True
        error = int(self.api.get_last_error())
        if error == self._ERROR_IO_INCOMPLETE:
            return False
        raise SealedNamespaceError(f"native namespace watcher failed for {self.path}: {error}")

    def _discard(self) -> None:
        handle = getattr(self, "handle", None)
        event = getattr(self, "event", None)
        overlapped = getattr(self, "overlapped", None)
        if handle and overlapped is not None:
            self.api.kernel32.CancelIoEx(handle, self.api.ctypes.byref(overlapped))
            transferred = self.api.wintypes.DWORD()
            if not self.api.kernel32.GetOverlappedResult(
                handle,
                self.api.ctypes.byref(overlapped),
                self.api.ctypes.byref(transferred),
                True,
            ):
                error = int(self.api.get_last_error())
                if error not in {self._ERROR_OPERATION_ABORTED, self._ERROR_IO_INCOMPLETE}:
                    raise SealedNamespaceError(
                        f"cannot reap native namespace watcher for {self.path}: {error}"
                    )
        if event:
            self.api.close(event)
            self.event = None
        if handle:
            self.api.close(handle)
            self.handle = None

    def close(self) -> None:
        self._discard()


class _WindowsNamespaceLease:
    """Share-deny handle lease with recursive tree-change observation."""

    _MAX_HANDLES = 16_384

    def __init__(
        self,
        trees: Sequence[NamespaceTree],
        files: Sequence[NamespaceFile],
        *,
        retain_payload_labels: frozenset[str],
    ) -> None:
        self.api = _WindowsHandles()
        self._directories: dict[tuple[int, bytes], _WindowsDirectory] = {}
        self._files: list[_WindowsFile] = []
        self._watchers: list[_WindowsDirectoryWatcher] = []
        self._closed = False
        self._retain_payload_labels = retain_payload_labels
        self._require_handle_capacity(trees, files)
        try:
            for tree in sorted(trees, key=lambda item: (item.label, str(item.root))):
                root = self._open_tree_root(tree.anchor, tree.root)
                watcher = _WindowsDirectoryWatcher(self.api, root.path, root.metadata)
                self._watchers.append(watcher)
                self._walk_tree(tree.label, root, PurePosixPath())
            for item in sorted(files, key=lambda value: (value.label, str(value.path))):
                self._open_standalone_file(item)
        except BaseException:
            self._close_handles()
            raise

    def _require_handle_capacity(
        self, trees: Sequence[NamespaceTree], files: Sequence[NamespaceFile]
    ) -> None:
        estimated = len(files) + len(trees)
        for tree in trees:
            try:
                estimated += 1 + sum(1 for _ in tree.root.rglob("*"))
            except OSError as exc:
                raise SealedNamespaceError(
                    f"cannot census native namespace handle demand: {tree.root}"
                ) from exc
            estimated += len(tree.anchor.absolute().parts)
        for item in files:
            estimated += len(item.path.absolute().parts)
        current = self.api.wintypes.DWORD()
        self.api.kernel32.GetProcessHandleCount.argtypes = [
            self.api.wintypes.HANDLE,
            self.api.ctypes.POINTER(self.api.wintypes.DWORD),
        ]
        self.api.kernel32.GetProcessHandleCount.restype = self.api.wintypes.BOOL
        self.api.kernel32.GetCurrentProcess.restype = self.api.wintypes.HANDLE
        process = self.api.kernel32.GetCurrentProcess()
        if not self.api.kernel32.GetProcessHandleCount(process, self.api.ctypes.byref(current)):
            raise SealedNamespaceError("cannot preflight native namespace handle capacity")
        if int(current.value) + estimated + 128 > self._MAX_HANDLES:
            raise SealedNamespaceError(
                "producer-readable namespace exceeds the bounded native handle "
                f"capacity: need~{estimated + 128}, current={current.value}, "
                f"limit={self._MAX_HANDLES}"
            )

    @staticmethod
    def _members(path: Path) -> tuple[str, ...]:
        try:
            return tuple(sorted((entry.name for entry in os.scandir(path)), key=str.casefold))
        except OSError as exc:
            raise SealedNamespaceError(
                f"cannot enumerate native namespace directory: {path}"
            ) from exc

    def _register_directory(
        self,
        path: Path,
        handle: Any,
        *,
        parent: Any | None,
        name: str | None,
        seal_contents: bool,
    ) -> _WindowsDirectory:
        metadata = self.api.strong_identity(handle)
        if (
            metadata[8] & self.api._ATTRIBUTE_REPARSE
            or not metadata[8] & self.api._ATTRIBUTE_DIRECTORY
        ):
            self.api.close(handle)
            raise SealedNamespaceError(f"native namespace path is not a plain directory: {path}")
        key = (metadata[0], metadata[1])
        existing = self._directories.get(key)
        if existing is not None:
            self.api.close(handle)
            if existing.path != path:
                raise SealedNamespaceError(
                    f"native namespace aliases one directory at {existing.path} and {path}"
                )
            if seal_contents and not existing.seal_contents:
                existing.metadata = self.api.strong_identity(existing.handle)
                existing.members = self._members(existing.path)
                existing.seal_contents = True
            return existing
        value = _WindowsDirectory(
            path,
            handle,
            parent,
            name,
            metadata,
            self._members(path) if seal_contents else (),
            seal_contents,
        )
        self._directories[key] = value
        return value

    def _open_anchor(self, anchor: Path) -> _WindowsDirectory:
        lexical = anchor.absolute()
        filesystem_root = Path(lexical.anchor)
        if not lexical.anchor:
            raise SealedNamespaceError(f"native namespace anchor has no volume root: {lexical}")
        root_handle = self.api.root(filesystem_root, deny_other_writes=True)
        current = self._register_directory(
            filesystem_root,
            root_handle,
            parent=None,
            name=None,
            seal_contents=False,
        )
        try:
            relative = lexical.relative_to(filesystem_root)
        except ValueError as exc:
            raise SealedNamespaceError(
                f"native namespace anchor escapes its volume: {lexical}"
            ) from exc
        for component in relative.parts:
            current = self._open_child_directory(current, component, current.path / component)
        return current

    def _open_child_directory(
        self,
        parent: _WindowsDirectory,
        name: str,
        path: Path,
        *,
        seal_contents: bool = False,
    ) -> _WindowsDirectory:
        try:
            handle = self.api.open_relative(
                parent.handle,
                name,
                directory=True,
                deny_other_writes=True,
            )
        except SecurePathError as exc:
            raise SealedNamespaceError(
                f"native namespace directory is absent or redirected: {path}"
            ) from exc
        if handle is None:
            raise SealedNamespaceError(f"native namespace directory is absent: {path}")
        return self._register_directory(
            path,
            handle,
            parent=parent.handle,
            name=name,
            seal_contents=seal_contents,
        )

    def _open_tree_root(self, anchor: Path, target: Path) -> _WindowsDirectory:
        anchor_path = anchor.absolute()
        target_path = target.absolute()
        try:
            relative = target_path.relative_to(anchor_path)
        except ValueError as exc:
            raise SealedNamespaceError(
                f"native namespace target {target_path} escapes anchor {anchor_path}"
            ) from exc
        current = self._open_anchor(anchor_path)
        for component in relative.parts:
            current = self._open_child_directory(current, component, current.path / component)
        if not current.seal_contents:
            current.metadata = self.api.strong_identity(current.handle)
            current.members = self._members(current.path)
            current.seal_contents = True
        return current

    def _walk_tree(self, label: str, directory: _WindowsDirectory, relative: PurePosixPath) -> None:
        for name in directory.members:
            path = directory.path / name
            directory_handle: Any | None
            try:
                directory_handle = self.api.open_relative(
                    directory.handle,
                    name,
                    directory=True,
                    allow_missing=True,
                    deny_other_writes=True,
                )
            except SecurePathError:
                directory_handle = None
            if directory_handle is not None:
                child = self._register_directory(
                    path,
                    directory_handle,
                    parent=directory.handle,
                    name=name,
                    seal_contents=True,
                )
                self._walk_tree(label, child, relative / name)
                continue
            self._open_file(
                label,
                (relative / name).as_posix(),
                path,
                directory,
                name,
            )

    def _open_file(
        self,
        label: str,
        relative: str,
        path: Path,
        parent: _WindowsDirectory,
        name: str,
    ) -> None:
        try:
            handle = self.api.open_relative(
                parent.handle,
                name,
                directory=False,
                deny_other_writes=True,
            )
        except SecurePathError as exc:
            raise SealedNamespaceError(
                f"native namespace file is absent or redirected: {path}"
            ) from exc
        if handle is None:
            raise SealedNamespaceError(f"native namespace file is absent: {path}")
        try:
            before = self.api.strong_identity(handle)
            if before[8] & (self.api._ATTRIBUTE_REPARSE | self.api._ATTRIBUTE_DIRECTORY):
                raise SealedNamespaceError(
                    f"native namespace file is redirected/non-regular: {path}"
                )
            payload = self.api.read(handle)
            after = self.api.strong_identity(handle)
            if before != after or len(payload) != after[5]:
                raise SealedNamespaceError(f"native namespace file changed during capture: {path}")
        except BaseException:
            self.api.close(handle)
            raise
        self._files.append(
            _WindowsFile(
                SealedNamespaceFile(
                    label,
                    relative,
                    path,
                    Digest.from_bytes(payload),
                    len(payload),
                    payload if label in self._retain_payload_labels else None,
                ),
                handle,
                parent.handle,
                name,
                after,
            )
        )

    def _open_standalone_file(self, item: NamespaceFile) -> None:
        anchor = item.anchor.absolute()
        target = item.path.absolute()
        try:
            relative = target.relative_to(anchor)
        except ValueError as exc:
            raise SealedNamespaceError(
                f"native namespace file {target} escapes anchor {anchor}"
            ) from exc
        if not relative.parts:
            raise SealedNamespaceError("native namespace standalone file cannot equal its anchor")
        parent = self._open_anchor(anchor)
        for component in relative.parts[:-1]:
            parent = self._open_child_directory(parent, component, parent.path / component)
        self._open_file(
            item.label,
            relative.as_posix(),
            target,
            parent,
            relative.parts[-1],
        )

    @property
    def snapshot(self) -> SealedNamespaceSnapshot:
        return SealedNamespaceSnapshot(
            tuple(
                sorted(
                    (item.public for item in self._files),
                    key=lambda item: (item.label.casefold(), item.relative_path.casefold()),
                )
            )
        )

    def verify(self) -> None:
        failures: list[str] = []
        for watcher in self._watchers:
            if watcher.changed():
                failures.append(f"{watcher.path} (directory change/overflow)")
        for directory in self._directories.values():
            try:
                received = self.api.strong_identity(directory.handle)
                members = self._members(directory.path) if directory.seal_contents else ()
                if (
                    directory.seal_contents and received != directory.metadata
                ) or members != directory.members:
                    failures.append(str(directory.path))
                if directory.parent is not None and directory.name is not None:
                    named = self.api.open_relative(
                        directory.parent,
                        directory.name,
                        directory=True,
                        deny_other_writes=True,
                    )
                    if named is None:
                        failures.append(str(directory.path))
                    else:
                        try:
                            if self.api.strong_identity(named)[:2] != directory.metadata[:2]:
                                failures.append(str(directory.path))
                        finally:
                            self.api.close(named)
            except (OSError, SecurePathError):
                failures.append(str(directory.path))
        for item in self._files:
            try:
                received = self.api.strong_identity(item.handle)
                self.api.rewind(item.handle)
                payload = self.api.read(item.handle)
                named = self.api.open_relative(
                    item.parent,
                    item.name,
                    directory=False,
                    deny_other_writes=True,
                )
                if named is None:
                    failures.append(str(item.public.path))
                else:
                    try:
                        named_identity = self.api.strong_identity(named)
                    finally:
                        self.api.close(named)
                    if (
                        received != item.metadata
                        or named_identity != item.metadata
                        or len(payload) != item.public.size
                        or Digest.from_bytes(payload) != item.public.digest
                    ):
                        failures.append(str(item.public.path))
            except (OSError, SecurePathError):
                failures.append(str(item.public.path))
        if failures:
            raise SealedNamespaceError(
                "producer-readable native namespace changed while held: "
                + ", ".join(sorted(set(failures), key=str.casefold)[:12])
            )

    def _close_handles(self) -> None:
        if self._closed:
            return
        self._closed = True
        watcher_errors: list[BaseException] = []
        for watcher in reversed(self._watchers):
            try:
                watcher.close()
            except BaseException as exc:
                watcher_errors.append(exc)
        for item in reversed(self._files):
            self.api.close(item.handle)
        for directory in reversed(tuple(self._directories.values())):
            self.api.close(directory.handle)
        if watcher_errors:
            raise SealedNamespaceError(
                f"failed to reap {len(watcher_errors)} native namespace watcher(s)"
            ) from watcher_errors[0]

    def close(self) -> None:
        try:
            self.verify()
        finally:
            self._close_handles()


class _NamespaceLeaseImplementation(Protocol):
    @property
    def snapshot(self) -> SealedNamespaceSnapshot: ...

    def verify(self) -> None: ...

    def close(self) -> None: ...


class SealedNamespaceLease(AbstractContextManager["SealedNamespaceLease"]):
    """Hold a finite producer-readable namespace immutable until close."""

    def __init__(
        self,
        *,
        trees: Sequence[NamespaceTree],
        files: Sequence[NamespaceFile] = (),
        retain_payload_labels: Sequence[str] = (),
    ) -> None:
        if not trees and not files:
            raise SealedNamespaceError("sealed namespace is empty")
        labels = [item.label for item in trees]
        labels.extend(item.label for item in files)
        if any(not label or "\x00" in label for label in labels):
            raise SealedNamespaceError("sealed namespace label is invalid")
        retained = frozenset(retain_payload_labels)
        if not retained.issubset(labels):
            raise SealedNamespaceError("payload-retention labels are outside the namespace")
        declarations: list[tuple[str, str, bool]] = []
        for tree in trees:
            declarations.append((tree.label, str(tree.root.absolute()), True))
        for standalone in files:
            declarations.append((standalone.label, str(standalone.path.absolute()), False))
        folded = [(label.casefold(), path.casefold()) for label, path, _ in declarations]
        if len(folded) != len(set(folded)):
            raise SealedNamespaceError("sealed namespace repeats a label/path declaration")
        for index, (left_label, left_path, left_tree) in enumerate(declarations):
            for _right_label, right_path, right_tree in declarations[index + 1 :]:
                left = left_path.casefold().rstrip(os.sep)
                right = right_path.casefold().rstrip(os.sep)
                if (
                    left == right
                    or (left_tree and right.startswith(left + os.sep))
                    or (right_tree and left.startswith(right + os.sep))
                ):
                    raise SealedNamespaceError(
                        "sealed namespace declarations overlap: "
                        f"{left_label!r} {left_path!r} and {right_path!r}"
                    )
        implementation: _NamespaceLeaseImplementation
        if os.name == "nt":
            implementation = _WindowsNamespaceLease(trees, files, retain_payload_labels=retained)
        else:
            implementation = _PosixNamespaceLease(trees, files, retain_payload_labels=retained)
        self._implementation = implementation
        self.snapshot: SealedNamespaceSnapshot = implementation.snapshot
        visible = [
            (item.label.casefold(), item.relative_path.casefold()) for item in self.snapshot.files
        ]
        if len(visible) != len(set(visible)):
            implementation.close()
            raise SealedNamespaceError("sealed namespace file census has a DOS-case collision")
        self._closed = False

    def verify(self) -> None:
        self._implementation.verify()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._implementation.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, traceback
        try:
            self.close()
        except BaseException as seal_error:
            if isinstance(exc, BaseException):
                exc.add_note(f"namespace verification also failed: {seal_error}")
                return
            raise


def namespace_snapshot_by_label(
    snapshot: SealedNamespaceSnapshot,
) -> Mapping[str, tuple[SealedNamespaceFile, ...]]:
    """Return the canonical census grouped by caller-owned authority label."""

    labels = sorted({item.label for item in snapshot.files}, key=str.casefold)
    return MappingProxyType({label: snapshot.files_for(label) for label in labels})


__all__ = [
    "NamespaceFile",
    "NamespaceTree",
    "SealedNamespaceError",
    "SealedNamespaceFile",
    "SealedNamespaceLease",
    "SealedNamespaceSnapshot",
    "estimate_namespace_descriptor_requirement",
    "namespace_snapshot_by_label",
]
