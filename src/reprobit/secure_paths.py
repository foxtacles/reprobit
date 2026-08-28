"""Handle-relative project reads and atomic publication.

Security-sensitive project paths are never traversed by repeatedly resolving
host path strings.  On POSIX, every descendant is opened relative to a held
directory descriptor with ``O_NOFOLLOW``; the complete held chain is rechecked
after the operation.  This prevents a concurrent rename or symlink swap from
redirecting a manifest read or terminal publication outside its declared root.

On native Windows the same contract is implemented with ``NtCreateFile``
relative to held directory handles, reparse-point opens, and an atomic
``FileRenameInfo`` commit.  A path-based ``CreateFileW`` check is used only to
hold/recheck the trusted root; descendants are never reopened by host path.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol

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


class _BinaryReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...


_MACOS_ROOT_ALIASES = {
    "etc": "etc",
    "tmp": "tmp",
    "var": "var",
}

_WINDOWS_BASIC_RESTORABLE_ATTRIBUTES = (
    0x0001  # READONLY
    | 0x0002  # HIDDEN
    | 0x0004  # SYSTEM
    | 0x0020  # ARCHIVE
    | 0x0080  # NORMAL
    | 0x0100  # TEMPORARY
    | 0x1000  # OFFLINE
    | 0x2000  # NOT_CONTENT_INDEXED
)


def windows_attributes_are_basic_restorable(attributes: int) -> bool:
    """Return whether FileBasicInfo can exactly recreate native attributes."""

    return (
        isinstance(attributes, int)
        and not isinstance(attributes, bool)
        and attributes >= 0
        and not attributes & ~_WINDOWS_BASIC_RESTORABLE_ATTRIBUTES
        and (not attributes & 0x0080 or attributes == 0x0080)
    )


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


def _relative(value: str | PurePosixPath) -> PurePosixPath:
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


def _matches_windows_snapshot(
    basic: tuple[int, int, int, int, int],
    strong: tuple[int, bytes, int, int, int, int, int, bool, int],
    expected: SecureFileSnapshot,
) -> bool:
    """Compare one native handle with a strong publication capability."""

    return (
        basic[0] == expected.device
        and basic[1] == expected.inode
        and basic[2] == expected.size
        and basic[3] == expected.mtime_ns
        and (not expected.windows_file_id or strong[1] == expected.windows_file_id)
        and (not expected.ctime_ns or strong[4] == expected.ctime_ns)
        and (not expected.windows_attributes or strong[8] == expected.windows_attributes)
        and (strong[0] & 0xFFFFFFFF) == basic[0]
        and strong[3] == basic[3]
        and strong[5] == basic[2]
        and not strong[7]
    )


def _windows_snapshot_mismatch_fields(
    basic: tuple[int, int, int, int, int],
    strong: tuple[int, bytes, int, int, int, int, int, bool, int],
    expected: SecureFileSnapshot,
) -> tuple[str, ...]:
    """Name failed native snapshot invariants without exposing host values."""

    mismatches: list[str] = []
    checks = (
        (basic[0] == expected.device, "volume"),
        (basic[1] == expected.inode, "file-index"),
        (basic[2] == expected.size, "size"),
        (basic[3] == expected.mtime_ns, "write-time"),
        (
            not expected.windows_file_id or strong[1] == expected.windows_file_id,
            "file-id",
        ),
        (not expected.ctime_ns or strong[4] == expected.ctime_ns, "change-time"),
        (
            not expected.windows_attributes
            or strong[8] == expected.windows_attributes,
            "attributes",
        ),
        ((strong[0] & 0xFFFFFFFF) == basic[0], "native-volume-consistency"),
        (strong[3] == basic[3], "native-write-time-consistency"),
        (strong[5] == basic[2], "native-size-consistency"),
        (not strong[7], "delete-pending"),
    )
    mismatches.extend(label for passed, label in checks if not passed)
    return tuple(mismatches)


def _same_windows_identity_except_change_time(
    before: tuple[int, bytes, int, int, int, int, int, bool, int],
    after: tuple[int, bytes, int, int, int, int, int, bool, int],
) -> bool:
    """Compare native identity across an expected metadata-time transition.

    A rename, or finalizing access metadata when a read handle closes, may
    advance Windows' file change time even though the continuously held file
    object, payload, write time, links, and attributes remain unchanged.
    """

    return before[:4] == after[:4] and before[5:] == after[5:]


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags(mode: int) -> int:
    return (
        mode
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
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
            self.fd = os.open(self.path, _directory_flags())
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
                    child = os.open(component, _directory_flags(), dir_fd=parent)
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


class _WindowsHandles:
    """Minimal NT handle-relative file API used only on native Windows."""

    _DELETE = 0x00010000
    _SYNCHRONIZE = 0x00100000
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_LIST_DIRECTORY = 0x0001
    _FILE_TRAVERSE = 0x0020
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_WRITE_ATTRIBUTES = 0x0100
    _SHARE_ALL = 0x1 | 0x2 | 0x4
    _FILE_OPEN = 1
    _FILE_CREATE = 2
    _FILE_OPEN_IF = 3
    _DIRECTORY_OPTIONS = 0x1 | 0x20 | 0x00200000
    _FILE_OPTIONS = 0x40 | 0x20 | 0x00200000
    _OBJ_CASE_INSENSITIVE = 0x40
    _ATTRIBUTE_DIRECTORY = 0x10
    _ATTRIBUTE_REPARSE = 0x400
    _FILE_RENAME_INFORMATION = 10
    _NOT_FOUND = frozenset({0xC0000034, 0xC000003A})

    def __init__(self) -> None:
        if os.name != "nt":
            raise SecurePathError("native Windows handle API requested off Windows")
        import ctypes
        from ctypes import wintypes

        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise SecurePathError("ctypes WinDLL is unavailable")

        class UnicodeString(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR),
            ]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.ULONG),
                ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(UnicodeString)),
                ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p),
            ]

        class IoStatusBlock(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        class FileTime(ctypes.Structure):
            _fields_ = [
                ("low", wintypes.DWORD),
                ("high", wintypes.DWORD),
            ]

        class ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("creation", FileTime),
                ("access", FileTime),
                ("write", FileTime),
                ("volume", wintypes.DWORD),
                ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD),
                ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD),
                ("index_low", wintypes.DWORD),
            ]

        class FileDispositionInfoEx(ctypes.Structure):
            _fields_ = [("flags", wintypes.DWORD)]

        class FileBasicInfo(ctypes.Structure):
            _fields_ = [
                ("creation", ctypes.c_longlong),
                ("access", ctypes.c_longlong),
                ("write", ctypes.c_longlong),
                ("change", ctypes.c_longlong),
                ("attributes", wintypes.DWORD),
            ]

        class FileStandardInfo(ctypes.Structure):
            _fields_ = [
                ("allocation_size", ctypes.c_longlong),
                ("end_of_file", ctypes.c_longlong),
                ("links", wintypes.DWORD),
                ("delete_pending", ctypes.c_ubyte),
                ("directory", ctypes.c_ubyte),
            ]

        class FileId128(ctypes.Structure):
            _fields_ = [("identifier", ctypes.c_ubyte * 16)]

        class FileIdInfo(ctypes.Structure):
            _fields_ = [
                ("volume", ctypes.c_ulonglong),
                ("file_id", FileId128),
            ]

        class FileRenameOptions(ctypes.Union):
            _fields_ = [
                ("replace", ctypes.c_ubyte),
                ("flags", wintypes.DWORD),
            ]

        class FileRenameInfo(ctypes.Structure):
            _anonymous_ = ("options",)
            _fields_ = [
                ("options", FileRenameOptions),
                ("root", wintypes.HANDLE),
                ("name_length", wintypes.DWORD),
                ("name", ctypes.c_uint16 * 1),
            ]

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.UnicodeString = UnicodeString
        self.ObjectAttributes = ObjectAttributes
        self.IoStatusBlock = IoStatusBlock
        self.ByHandleFileInformation = ByHandleFileInformation
        self.FileDispositionInfoEx = FileDispositionInfoEx
        self.FileBasicInfo = FileBasicInfo
        self.FileStandardInfo = FileStandardInfo
        self.FileIdInfo = FileIdInfo
        self.FileRenameInfo = FileRenameInfo
        self.kernel32 = win_dll("kernel32", use_last_error=True)
        self.ntdll = win_dll("ntdll", use_last_error=True)
        self.get_last_error = getattr(ctypes, "get_last_error", lambda: 0)

        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ByHandleFileInformation),
        ]
        self.kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        self.kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
        self.kernel32.ReadFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        self.kernel32.ReadFile.restype = wintypes.BOOL
        self.kernel32.SetFilePointerEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        self.kernel32.SetFilePointerEx.restype = wintypes.BOOL
        self.kernel32.WriteFile.argtypes = self.kernel32.ReadFile.argtypes
        self.kernel32.WriteFile.restype = wintypes.BOOL
        self.kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        self.kernel32.FlushFileBuffers.restype = wintypes.BOOL
        self.kernel32.SetFileInformationByHandle.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
        self.ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            ctypes.POINTER(ObjectAttributes),
            ctypes.POINTER(IoStatusBlock),
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.ntdll.NtCreateFile.restype = ctypes.c_long
        self.ntdll.NtSetInformationFile.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(IoStatusBlock),
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_int,
        ]
        self.ntdll.NtSetInformationFile.restype = ctypes.c_long

    @staticmethod
    def _status_value(status: int) -> int:
        return status & 0xFFFFFFFF

    def close(self, handle: Any) -> None:
        if handle:
            self.kernel32.CloseHandle(handle)

    def root(self, path: Path, *, deny_other_writes: bool = False) -> Any:
        handle = self.kernel32.CreateFileW(
            str(path),
            self._FILE_LIST_DIRECTORY
            | self._FILE_TRAVERSE
            | self._FILE_READ_ATTRIBUTES
            | self._SYNCHRONIZE,
            0x1 if deny_other_writes else self._SHARE_ALL,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        if handle == self.ctypes.c_void_p(-1).value:
            raise SecurePathError(
                f"cannot hold native secure path root {path}: {self.get_last_error()}"
            )
        attributes = self.identity(handle)[4]
        if not attributes & self._ATTRIBUTE_DIRECTORY or attributes & self._ATTRIBUTE_REPARSE:
            self.close(handle)
            raise SecurePathError(f"native secure path root is not a plain directory: {path}")
        return handle

    def open_relative(
        self,
        parent: Any,
        name: str,
        *,
        directory: bool,
        create: bool = False,
        write: bool = False,
        delete: bool = False,
        allow_missing: bool = False,
        deny_other_writes: bool = False,
        read_data: bool = True,
    ) -> Any | None:
        buffer = self.ctypes.create_unicode_buffer(name)
        length = len(name.encode("utf-16-le"))
        unicode = self.UnicodeString(
            length,
            length + 2,
            self.ctypes.cast(buffer, self.wintypes.LPWSTR),
        )
        attributes = self.ObjectAttributes(
            self.ctypes.sizeof(self.ObjectAttributes),
            parent,
            self.ctypes.pointer(unicode),
            self._OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        status_block = self.IoStatusBlock()
        handle = self.wintypes.HANDLE()
        access = self._FILE_READ_ATTRIBUTES | self._SYNCHRONIZE
        if directory:
            # Every held directory can become FILE_RENAME_INFO.RootDirectory.
            access |= self._FILE_LIST_DIRECTORY | self._FILE_TRAVERSE
        elif write:
            access |= self._GENERIC_READ | self._GENERIC_WRITE
        elif read_data:
            access |= self._GENERIC_READ
        if delete:
            # FileDispositionInfoEx needs FILE_WRITE_ATTRIBUTES when deleting
            # an admitted READONLY artifact with IGNORE_READONLY_ATTRIBUTE.
            access |= self._DELETE | self._FILE_WRITE_ATTRIBUTES
        disposition = (
            self._FILE_OPEN_IF
            if directory and create
            else (self._FILE_CREATE if create else self._FILE_OPEN)
        )
        status = int(
            self.ntdll.NtCreateFile(
                self.ctypes.byref(handle),
                access,
                self.ctypes.byref(attributes),
                self.ctypes.byref(status_block),
                None,
                0x80,
                0x1 if deny_other_writes else self._SHARE_ALL,
                disposition,
                self._DIRECTORY_OPTIONS if directory else self._FILE_OPTIONS,
                None,
                0,
            )
        )
        unsigned = self._status_value(status)
        if status < 0:
            if allow_missing and unsigned in self._NOT_FOUND:
                return None
            raise SecurePathError(
                f"native handle-relative open failed for {name!r}: 0x{unsigned:08x}"
            )
        received = handle.value
        identity = self.identity(received)
        is_directory = bool(identity[4] & self._ATTRIBUTE_DIRECTORY)
        if identity[4] & self._ATTRIBUTE_REPARSE or is_directory != directory:
            self.close(received)
            raise SecurePathError(
                f"native path component is redirected or has the wrong kind: {name!r}"
            )
        return received

    def identity(self, handle: Any) -> tuple[int, int, int, int, int]:
        information = self.ByHandleFileInformation()
        if not self.kernel32.GetFileInformationByHandle(handle, self.ctypes.byref(information)):
            raise SecurePathError(f"GetFileInformationByHandle failed: {self.get_last_error()}")
        size = (information.size_high << 32) | information.size_low
        index = (information.index_high << 32) | information.index_low
        modified = (information.write.high << 32) | information.write.low
        return information.volume, index, size, modified, information.attributes

    def strong_identity(
        self, handle: Any
    ) -> tuple[int, bytes, int, int, int, int, int, bool, int]:
        """Return stable identity/change metadata for one held native handle."""

        basic = self.FileBasicInfo()
        standard = self.FileStandardInfo()
        file_id = self.FileIdInfo()
        requests = (
            (0, basic),  # FileBasicInfo
            (1, standard),  # FileStandardInfo
            (18, file_id),  # FileIdInfo
        )
        for information_class, value in requests:
            if not self.kernel32.GetFileInformationByHandleEx(
                handle,
                information_class,
                self.ctypes.byref(value),
                self.ctypes.sizeof(value),
            ):
                raise SecurePathError(
                    "GetFileInformationByHandleEx failed: "
                    f"{self.get_last_error()}"
                )
        identifier = bytes(file_id.file_id.identifier)
        return (
            int(file_id.volume),
            identifier,
            int(basic.creation),
            int(basic.write),
            int(basic.change),
            int(standard.end_of_file),
            int(standard.links),
            bool(standard.delete_pending),
            int(basic.attributes),
        )

    def read(self, handle: Any) -> bytes:
        chunks: list[bytes] = []
        while True:
            block = self.read_block(handle, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)

    def read_block(self, handle: Any, size: int) -> bytes:
        buffer = self.ctypes.create_string_buffer(size)
        received = self.wintypes.DWORD()
        if not self.kernel32.ReadFile(
            handle,
            buffer,
            len(buffer),
            self.ctypes.byref(received),
            None,
        ):
            raise SecurePathError(f"ReadFile failed: {self.get_last_error()}")
        return buffer.raw[: received.value]

    def rewind(self, handle: Any) -> None:
        if not self.kernel32.SetFilePointerEx(handle, 0, None, 0):
            raise SecurePathError(
                f"SetFilePointerEx failed: {self.get_last_error()}"
            )

    def write(self, handle: Any, payload: bytes) -> None:
        for offset in range(0, len(payload), 1024 * 1024):
            self.write_block(handle, payload[offset : offset + 1024 * 1024])
        self.flush_file(handle)

    def write_block(self, handle: Any, payload: bytes) -> None:
        buffer = self.ctypes.create_string_buffer(payload)
        written = self.wintypes.DWORD()
        if not self.kernel32.WriteFile(
            handle,
            buffer,
            len(payload),
            self.ctypes.byref(written),
            None,
        ) or written.value != len(payload):
            raise SecurePathError(f"WriteFile failed: {self.get_last_error()}")

    def flush_file(self, handle: Any) -> None:
        if not self.kernel32.FlushFileBuffers(handle):
            raise SecurePathError(
                f"FlushFileBuffers failed for publication: {self.get_last_error()}"
            )

    def rename(self, handle: Any, parent: Any, name: str, *, replace: bool) -> None:
        encoded_name = name.encode("utf-16-le")
        name_offset = self.FileRenameInfo.name.offset
        # Stay on the same NT handle-relative API used to open both handles.
        # This avoids another Win32 path interpretation step and supplies the
        # counted FILE_RENAME_INFORMATION contract directly to the kernel.
        buffer = self.ctypes.create_string_buffer(
            self.ctypes.sizeof(self.FileRenameInfo) + len(encoded_name)
        )
        information = self.ctypes.cast(
            buffer,
            self.ctypes.POINTER(self.FileRenameInfo),
        ).contents
        information.replace = int(replace)
        information.root = parent
        information.name_length = len(encoded_name)
        self.ctypes.memmove(
            self.ctypes.addressof(buffer) + name_offset,
            encoded_name,
            len(encoded_name),
        )
        status_block = self.IoStatusBlock()
        status = int(
            self.ntdll.NtSetInformationFile(
                handle,
                self.ctypes.byref(status_block),
                buffer,
                len(buffer),
                self._FILE_RENAME_INFORMATION,
            )
        )
        if status < 0:
            raise SecurePathError(
                "atomic native publication rename failed: "
                f"0x{self._status_value(status):08x}"
            )

    def delete_on_close(self, handle: Any) -> None:
        # The native lane requires Server 2022.  The extended disposition
        # contract preserves exact READONLY artifacts while still allowing
        # rollback/removal through the already identity-held handle.
        information = self.FileDispositionInfoEx(0x01 | 0x10)
        if not self.kernel32.SetFileInformationByHandle(
            handle,
            21,
            self.ctypes.byref(information),
            self.ctypes.sizeof(information),
        ):
            raise SecurePathError(
                f"cannot discard failed native publication: {self.get_last_error()}"
            )

    def suppress_time_updates(self, handle: Any) -> None:
        """Keep publication metadata stable when this writer eventually closes."""

        basic = self.FileBasicInfo()
        basic.access = -1
        basic.write = -1
        basic.change = -1
        if not self.kernel32.SetFileInformationByHandle(
            handle,
            0,
            self.ctypes.byref(basic),
            self.ctypes.sizeof(basic),
        ):
            raise SecurePathError(
                "cannot stabilize native publication timestamps: "
                f"{self.get_last_error()}"
            )

    def set_attributes(self, handle: Any, attributes: int) -> None:
        """Restore exact ordinary DOS file attributes on a held file."""

        if not windows_attributes_are_basic_restorable(attributes):
            raise SecurePathError("native publication attributes are unsafe")
        basic = self.FileBasicInfo()
        basic.attributes = attributes
        if not self.kernel32.SetFileInformationByHandle(
            handle,
            0,
            self.ctypes.byref(basic),
            self.ctypes.sizeof(basic),
        ):
            raise SecurePathError(
                f"cannot restore native publication attributes: {self.get_last_error()}"
            )

    def flush_directory(self, handle: Any) -> None:
        if self.kernel32.FlushFileBuffers(handle):
            return
        error = int(self.get_last_error())
        if error not in {1, 5, 50}:
            raise SecurePathError(f"native directory flush failed: {error}")


class _HeldWindowsRoot:
    def __init__(self, root: Path) -> None:
        self.api = _WindowsHandles()
        self.path = root.resolve(strict=True)
        self.handle = self.api.root(self.path)
        self.identity = self.api.identity(self.handle)[:2]
        self.verify_root()

    def close(self) -> None:
        if self.handle:
            self.api.close(self.handle)
            self.handle = None

    def __enter__(self) -> _HeldWindowsRoot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def verify_root(self) -> None:
        received = self.api.root(self.path)
        try:
            if self.api.identity(received)[:2] != self.identity:
                raise SecurePathError(f"native secure path root changed while held: {self.path}")
        finally:
            self.api.close(received)

    def parent_chain(
        self, relative: PurePosixPath, *, create: bool
    ) -> tuple[list[Any], list[tuple[Any, str, tuple[int, int]]], str]:
        handles: list[Any] = [self.handle]
        edges: list[tuple[Any, str, tuple[int, int]]] = []
        try:
            for component in relative.parts[:-1]:
                child = self.api.open_relative(
                    handles[-1], component, directory=True, create=create
                )
                if child is None:
                    raise SecurePathError(f"native path component is absent: {component!r}")
                identity = self.api.identity(child)[:2]
                edges.append((handles[-1], component, identity))
                handles.append(child)
            return handles, edges, relative.parts[-1]
        except BaseException:
            for handle in reversed(handles[1:]):
                self.api.close(handle)
            raise

    def recheck(self, edges: list[tuple[Any, str, tuple[int, int]]]) -> None:
        self.verify_root()
        for parent, component, expected in edges:
            received = self.api.open_relative(parent, component, directory=True)
            if received is None:
                raise SecurePathError(f"native path component disappeared: {component!r}")
            try:
                if self.api.identity(received)[:2] != expected:
                    raise SecurePathError(
                        f"native path component changed while held: {component!r}"
                    )
            finally:
                self.api.close(received)


def _windows_read_relative_file(root: Path, relative: str) -> tuple[bytes, SecureFileSnapshot]:
    canonical = _relative(relative)
    with _HeldWindowsRoot(root) as held:
        handles, edges, name = held.parent_chain(canonical, create=False)
        file_handle: Any = None
        terminal: Any = None
        try:
            file_handle = held.api.open_relative(handles[-1], name, directory=False)
            if file_handle is None:
                raise SecurePathError(f"native source input is absent: {relative!r}")
            before = held.api.identity(file_handle)
            before_strong = held.api.strong_identity(file_handle)
            payload = held.api.read(file_handle)
            after = held.api.identity(file_handle)
            after_strong = held.api.strong_identity(file_handle)
            if (
                before != after
                or before_strong != after_strong
                or len(payload) != after[2]
            ):
                raise SecurePathError(f"native source input changed while read: {relative!r}")
            terminal = held.api.open_relative(
                handles[-1],
                name,
                directory=False,
                deny_other_writes=True,
                read_data=False,
            )
            if terminal is None:
                raise SecurePathError(f"native source input disappeared: {relative!r}")
            if (
                held.api.identity(terminal) != after
                or held.api.strong_identity(terminal) != after_strong
            ):
                raise SecurePathError(f"native source input changed identity: {relative!r}")

            # Windows may finalize access/change metadata only when the handle
            # that performed the read closes.  Transfer the deny-write lease to
            # a metadata-only handle first, then capture the settled snapshot.
            held.api.close(file_handle)
            file_handle = None
            settled = held.api.identity(terminal)
            settled_strong = held.api.strong_identity(terminal)
            if settled != after or not _same_windows_identity_except_change_time(
                after_strong, settled_strong
            ):
                raise SecurePathError(
                    f"native source input changed while finalizing read: {relative!r}"
                )
            held.recheck(edges)
            return payload, SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                Digest.from_bytes(payload),
                len(payload),
                settled[0],
                settled[1],
                settled[3],
                0,
                settled_strong[4],
                settled_strong[1],
                settled_strong[8],
            )
        finally:
            if terminal is not None:
                held.api.close(terminal)
            if file_handle is not None:
                held.api.close(file_handle)
            for handle in reversed(handles[1:]):
                held.api.close(handle)


def _windows_atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    replace: bool,
    expected: SecureFileSnapshot | None = None,
    windows_attributes: int | None = None,
) -> SecureFileSnapshot:
    canonical = _relative(relative)
    with _HeldWindowsRoot(root) as held:
        handles, edges, name = held.parent_chain(canonical, create=True)
        temporary = f".{name}.reprobit-{uuid.uuid4().hex}"
        handle: Any = None
        published = False
        committed = False
        try:
            previous = held.api.open_relative(
                handles[-1], name, directory=False, allow_missing=True
            )
            if previous is not None:
                try:
                    previous_identity = held.api.identity(previous)
                    previous_strong = held.api.strong_identity(previous)
                    if expected is not None and (
                        not _matches_windows_snapshot(
                            previous_identity, previous_strong, expected
                        )
                        or Digest.from_bytes(held.api.read(previous)) != expected.digest
                        or held.api.strong_identity(previous) != previous_strong
                    ):
                        raise SecurePathError(
                            f"publication preimage changed: {relative!r}"
                        )
                    if not replace:
                        raise SecurePathError(
                            f"secure create-if-absent target already exists: {relative!r}"
                        )
                finally:
                    held.api.close(previous)
            else:
                if expected is not None:
                    raise SecurePathError(f"publication preimage disappeared: {relative!r}")
                # A directory/reparse target must not be mistaken for absence.
                try:
                    wrong_kind = held.api.open_relative(
                        handles[-1], name, directory=True, allow_missing=True
                    )
                except SecurePathError as exc:
                    raise SecurePathError(
                        f"native publication target is redirected/non-regular: {relative!r}"
                    ) from exc
                if wrong_kind is not None:
                    held.api.close(wrong_kind)
                    raise SecurePathError(f"native publication target is a directory: {relative!r}")
            handle = held.api.open_relative(
                handles[-1],
                temporary,
                directory=False,
                create=True,
                write=True,
                delete=True,
                deny_other_writes=True,
            )
            if handle is None:
                raise SecurePathError("native publication temp file was not created")
            held.api.suppress_time_updates(handle)
            payload_digest = Digest.from_bytes(payload)
            held.api.write(handle, payload)
            before = held.api.identity(handle)
            if before[2] != len(payload):
                raise SecurePathError(f"native publication produced a short file: {relative!r}")
            if expected is not None:
                current = held.api.open_relative(handles[-1], name, directory=False)
                if current is None:
                    raise SecurePathError(
                        f"publication preimage disappeared: {relative!r}"
                    )
                try:
                    current_identity = held.api.identity(current)
                    current_strong = held.api.strong_identity(current)
                    if (
                        not _matches_windows_snapshot(
                            current_identity, current_strong, expected
                        )
                        or Digest.from_bytes(held.api.read(current)) != expected.digest
                        or held.api.strong_identity(current) != current_strong
                    ):
                        raise SecurePathError(
                            f"publication preimage changed: {relative!r}"
                        )
                finally:
                    held.api.close(current)
            held.api.rename(handle, handles[-1], name, replace=replace)
            published = True
            if windows_attributes is not None:
                # Windows rename may add ARCHIVE.  Apply the admitted final
                # attributes only after the name transition, without resetting
                # the writer's timestamp-suppression state.
                held.api.set_attributes(handle, windows_attributes)
                held.api.flush_file(handle)
            published_identity = held.api.identity(handle)
            published_strong = held.api.strong_identity(handle)
            if published_identity[2] != len(payload):
                raise SecurePathError(
                    f"native publication target changed during commit: {relative!r}"
                )
            final = held.api.open_relative(
                handles[-1],
                name,
                directory=False,
                read_data=False,
            )
            if final is None:
                raise SecurePathError(
                    f"native publication target disappeared: {relative!r}"
                )
            try:
                after = held.api.identity(final)
                after_strong = held.api.strong_identity(final)
                if after != published_identity or after_strong != published_strong:
                    raise SecurePathError(
                        f"native publication target changed during commit: {relative!r}"
                    )
            finally:
                held.api.close(final)

            held.api.rewind(handle)
            received_payload = held.api.read(handle)
            settled = held.api.identity(handle)
            settled_strong = held.api.strong_identity(handle)
            if (
                settled != published_identity
                or settled_strong != published_strong
                or len(received_payload) != len(payload)
                or Digest.from_bytes(received_payload) != payload_digest
            ):
                raise SecurePathError(
                    f"native publication target changed while finalizing: {relative!r}"
                )
            held.recheck(edges)
            held.api.flush_directory(handles[-1])
            committed = True
            return SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                payload_digest,
                len(payload),
                settled[0],
                settled[1],
                settled[3],
                0,
                settled_strong[4],
                settled_strong[1],
                settled_strong[8],
            )
        finally:
            if handle is not None:
                if not committed:
                    held.api.delete_on_close(handle)
                held.api.close(handle)
            if published and not committed:
                held.api.flush_directory(handles[-1])
            for current in reversed(handles[1:]):
                held.api.close(current)


def read_relative_file(root: Path, relative: str) -> tuple[bytes, SecureFileSnapshot]:
    """Read one regular file through a fully held, no-follow ancestor chain."""

    if os.name == "nt":
        return _windows_read_relative_file(root, relative)
    canonical = _relative(relative)
    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=parent,
                )
            except OSError as exc:
                raise SecurePathError(
                    f"secure source input is absent or redirected: {relative!r}"
                ) from exc
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode):
                    raise SecurePathError(f"secure source input is not regular: {relative!r}")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if _identity(before) != _identity(after):
                raise SecurePathError(f"secure source input changed while read: {relative!r}")
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(terminal) != _identity(after) or not stat.S_ISREG(terminal.st_mode):
                raise SecurePathError(
                    f"secure source input changed identity while read: {relative!r}"
                )
            held.recheck(edges)
            payload = b"".join(chunks)
            return payload, SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                Digest.from_bytes(payload),
                len(payload),
                after.st_dev,
                after.st_ino,
                after.st_mtime_ns,
                after.st_mode,
                after.st_ctime_ns,
            )
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


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


def _posix_atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    replace: bool,
    expected: SecureFileSnapshot | None = None,
    mode: int = 0o644,
) -> SecureFileSnapshot:
    canonical = _relative(relative)
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
                _file_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL),
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
                            raise SecurePathError(
                                f"publication preimage changed: {relative!r}"
                            )
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
                or Digest.from_bytes(b"".join(received_parts))
                != Digest.from_bytes(payload)
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
                _unlink_posix_name_if_exact(
                    descriptors[-1], name, descriptor, metadata
                )
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


_STREAM_COPY_CHUNK = 1024 * 1024


def _validate_stream_expectations(
    digest: Digest,
    size: int,
    *,
    expected_digest: Digest | None,
    expected_size: int | None,
    relative: str,
) -> None:
    if expected_digest is not None and digest != expected_digest:
        raise SecurePathError(
            f"streamed publication digest differs from expectation: {relative!r}"
        )
    if expected_size is not None and size != expected_size:
        raise SecurePathError(
            f"streamed publication size differs from expectation: {relative!r}"
        )


def _windows_atomic_publish_new_relative_from_stream(
    root: Path,
    relative: str,
    source: _BinaryReader,
    *,
    executable: bool,
    windows_attributes: int | None,
    expected_digest: Digest | None,
    expected_size: int | None,
) -> SecureFileSnapshot:
    del executable  # Native Windows does not encode POSIX executable mode bits.
    canonical = _relative(relative)
    with _HeldWindowsRoot(root) as held:
        handles, edges, name = held.parent_chain(canonical, create=True)
        temporary = f".{name}.reprobit-{uuid.uuid4().hex}"
        handle: Any = None
        published = False
        committed = False
        try:
            previous = held.api.open_relative(
                handles[-1], name, directory=False, allow_missing=True
            )
            if previous is not None:
                held.api.close(previous)
                raise SecurePathError(
                    f"secure create-if-absent target already exists: {relative!r}"
                )
            try:
                wrong_kind = held.api.open_relative(
                    handles[-1], name, directory=True, allow_missing=True
                )
            except SecurePathError as exc:
                raise SecurePathError(
                    f"native publication target is redirected/non-regular: {relative!r}"
                ) from exc
            if wrong_kind is not None:
                held.api.close(wrong_kind)
                raise SecurePathError(
                    f"native publication target is a directory: {relative!r}"
                )
            handle = held.api.open_relative(
                handles[-1],
                temporary,
                directory=False,
                create=True,
                write=True,
                delete=True,
                deny_other_writes=True,
            )
            if handle is None:
                raise SecurePathError("native streamed publication temp was not created")
            held.api.suppress_time_updates(handle)
            hasher = hashlib.sha256()
            size = 0
            while True:
                block = source.read(_STREAM_COPY_CHUNK)
                if not block:
                    break
                if type(block) is not bytes:
                    raise TypeError("secure publication stream must return bytes")
                held.api.write_block(handle, block)
                hasher.update(block)
                size += len(block)
            held.api.flush_file(handle)
            digest = Digest(value=hasher.hexdigest())
            _validate_stream_expectations(
                digest,
                size,
                expected_digest=expected_digest,
                expected_size=expected_size,
                relative=relative,
            )
            before = held.api.identity(handle)
            if before[2] != size:
                raise SecurePathError(
                    f"native streamed publication produced a short file: {relative!r}"
                )
            held.api.rename(handle, handles[-1], name, replace=False)
            published = True
            if windows_attributes is not None:
                held.api.set_attributes(handle, windows_attributes)
                held.api.flush_file(handle)
            published_identity = held.api.identity(handle)
            published_strong = held.api.strong_identity(handle)
            if published_identity[2] != size:
                raise SecurePathError(
                    f"native streamed publication target changed during commit: {relative!r}"
                )
            final = held.api.open_relative(
                handles[-1],
                name,
                directory=False,
                read_data=False,
            )
            if final is None:
                raise SecurePathError(
                    f"native streamed publication target disappeared: {relative!r}"
                )
            try:
                after = held.api.identity(final)
                after_strong = held.api.strong_identity(final)
                if after != published_identity or after_strong != published_strong:
                    raise SecurePathError(
                        f"native streamed publication target changed during commit: {relative!r}"
                    )
            finally:
                held.api.close(final)
            settled = held.api.identity(handle)
            settled_strong = held.api.strong_identity(handle)
            if (
                settled != published_identity
                or settled_strong != published_strong
            ):
                raise SecurePathError(
                    f"native streamed publication target changed while finalizing: {relative!r}"
                )
            held.recheck(edges)
            held.api.flush_directory(handles[-1])
            committed = True
            return SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                digest,
                size,
                settled[0],
                settled[1],
                settled[3],
                0,
                settled_strong[4],
                settled_strong[1],
                settled_strong[8],
            )
        finally:
            if handle is not None:
                if not committed:
                    held.api.delete_on_close(handle)
                held.api.close(handle)
            if published and not committed:
                held.api.flush_directory(handles[-1])
            for current in reversed(handles[1:]):
                held.api.close(current)


def _posix_atomic_publish_new_relative_from_stream(
    root: Path,
    relative: str,
    source: _BinaryReader,
    *,
    mode: int,
    expected_digest: Digest | None,
    expected_size: int | None,
) -> SecureFileSnapshot:
    canonical = _relative(relative)
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
                _file_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                0o600,
                dir_fd=parent,
            )
            temporary_exists = True
            os.fchmod(descriptor, mode)
            hasher = hashlib.sha256()
            size = 0
            while True:
                block = source.read(_STREAM_COPY_CHUNK)
                if not block:
                    break
                if type(block) is not bytes:
                    raise TypeError("secure publication stream must return bytes")
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SecurePathError(
                            f"short streamed publication write: {relative!r}"
                        )
                    view = view[written:]
                hasher.update(block)
                size += len(block)
            os.fsync(descriptor)
            digest = Digest(value=hasher.hexdigest())
            _validate_stream_expectations(
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
                    "streamed publication target attributes changed during commit: "
                    f"{relative!r}"
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
                _unlink_posix_name_if_exact(
                    descriptors[-1], name, descriptor, metadata
                )
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


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
    if (
        expected_size is not None
        and (not isinstance(expected_size, int) or isinstance(expected_size, bool))
    ):
        raise TypeError("secure publication expected size must be int")
    if expected_size is not None and expected_size < 0:
        raise ValueError("secure publication expected size cannot be negative")
    if os.name == "nt":
        if mode is not None:
            raise SecurePathError("native Windows publication cannot set POSIX mode")
        return _windows_atomic_publish_new_relative_from_stream(
            root,
            relative,
            source,
            executable=executable,
            windows_attributes=windows_attributes,
            expected_digest=expected_digest,
            expected_size=expected_size,
        )
    if windows_attributes is not None:
        raise SecurePathError("POSIX publication cannot set Windows attributes")
    return _posix_atomic_publish_new_relative_from_stream(
        root,
        relative,
        source,
        mode=mode if mode is not None else (0o755 if executable else 0o644),
        expected_digest=expected_digest,
        expected_size=expected_size,
    )


class _WindowsHandleReader:
    def __init__(self, api: _WindowsHandles, handle: Any) -> None:
        self.api = api
        self.handle = handle

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = _STREAM_COPY_CHUNK
        return self.api.read_block(self.handle, size)


def stat_relative_file(root: Path, relative: str) -> SecureFileIdentity:
    """Inspect one regular file through a held ancestor chain without reading it."""

    canonical = _relative(relative)
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            handles, edges, name = held.parent_chain(canonical, create=False)
            handle: Any = None
            try:
                handle = held.api.open_relative(handles[-1], name, directory=False)
                if handle is None:
                    raise SecurePathError(
                        f"native source input is absent: {relative!r}"
                    )
                before = held.api.strong_identity(handle)
                terminal = held.api.open_relative(handles[-1], name, directory=False)
                if terminal is None:
                    raise SecurePathError(
                        f"native source input disappeared: {relative!r}"
                    )
                try:
                    if held.api.strong_identity(terminal) != before:
                        raise SecurePathError(
                            f"native source input changed identity: {relative!r}"
                        )
                finally:
                    held.api.close(terminal)
                held.recheck(edges)
                basic = held.api.identity(handle)
                return SecureFileIdentity(
                    held.path.joinpath(*canonical.parts),
                    basic[2],
                    basic[0],
                    basic[1],
                    basic[3],
                    0,
                    before[4],
                    before[1],
                    before[8],
                )
            finally:
                if handle is not None:
                    held.api.close(handle)
                for current in reversed(handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            descriptor = os.open(
                name,
                _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                dir_fd=parent,
            )
            before_stat = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(before_stat.st_mode)
                or _identity(before_stat) != _identity(terminal)
            ):
                raise SecurePathError(
                    f"secure source input is redirected/non-regular: {relative!r}"
                )
            held.recheck(edges)
            return SecureFileIdentity(
                held.path.joinpath(*canonical.parts),
                before_stat.st_size,
                before_stat.st_dev,
                before_stat.st_ino,
                before_stat.st_mtime_ns,
                before_stat.st_mode,
                before_stat.st_ctime_ns,
            )
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"cannot securely inspect source input {relative!r}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def digest_relative_file(root: Path, relative: str) -> SecureFileSnapshot:
    """Hash one regular file through a held ancestor chain with bounded memory."""

    canonical = _relative(relative)
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            handles, edges, name = held.parent_chain(canonical, create=False)
            handle: Any = None
            terminal: Any = None
            try:
                handle = held.api.open_relative(handles[-1], name, directory=False)
                if handle is None:
                    raise SecurePathError(
                        f"native source input is absent: {relative!r}"
                    )
                before_strong = held.api.strong_identity(handle)
                hasher = hashlib.sha256()
                size = 0
                reader = _WindowsHandleReader(held.api, handle)
                while block := reader.read(_STREAM_COPY_CHUNK):
                    hasher.update(block)
                    size += len(block)
                after_strong = held.api.strong_identity(handle)
                if before_strong != after_strong or size != after_strong[5]:
                    raise SecurePathError(
                        f"native source input changed while hashed: {relative!r}"
                    )
                basic = held.api.identity(handle)
                terminal = held.api.open_relative(
                    handles[-1],
                    name,
                    directory=False,
                    deny_other_writes=True,
                    read_data=False,
                )
                if terminal is None:
                    raise SecurePathError(
                        f"native source input disappeared: {relative!r}"
                    )
                if (
                    held.api.identity(terminal) != basic
                    or held.api.strong_identity(terminal) != after_strong
                ):
                    raise SecurePathError(
                        f"native source input changed identity: {relative!r}"
                    )

                # Query the final timestamp state only after closing the handle
                # that performed I/O.  The metadata-only handle continuously
                # denies writes, so accepting Windows' own change-time advance
                # does not admit an external mutation.
                held.api.close(handle)
                handle = None
                settled = held.api.identity(terminal)
                settled_strong = held.api.strong_identity(terminal)
                if settled != basic or not _same_windows_identity_except_change_time(
                    after_strong, settled_strong
                ):
                    raise SecurePathError(
                        f"native source input changed while finalizing hash: {relative!r}"
                    )
                held.recheck(edges)
                return SecureFileSnapshot(
                    held.path.joinpath(*canonical.parts),
                    Digest(value=hasher.hexdigest()),
                    size,
                    settled[0],
                    settled[1],
                    settled[3],
                    0,
                    settled_strong[4],
                    settled_strong[1],
                    settled_strong[8],
                )
            finally:
                if terminal is not None:
                    held.api.close(terminal)
                if handle is not None:
                    held.api.close(handle)
                for current in reversed(handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            descriptor = os.open(
                name,
                _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                dir_fd=parent,
            )
            before_stat = os.fstat(descriptor)
            if not stat.S_ISREG(before_stat.st_mode):
                raise SecurePathError(
                    f"secure source input is not regular: {relative!r}"
                )
            hasher = hashlib.sha256()
            size = 0
            while block := os.read(descriptor, _STREAM_COPY_CHUNK):
                hasher.update(block)
                size += len(block)
            after_stat = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                _identity(before_stat) != _identity(after_stat)
                or _identity(after_stat) != _identity(terminal)
                or before_stat.st_ctime_ns != after_stat.st_ctime_ns
                or not stat.S_ISREG(terminal.st_mode)
                or size != after_stat.st_size
            ):
                raise SecurePathError(
                    f"secure source input changed while hashed: {relative!r}"
                )
            held.recheck(edges)
            return SecureFileSnapshot(
                held.path.joinpath(*canonical.parts),
                Digest(value=hasher.hexdigest()),
                size,
                after_stat.st_dev,
                after_stat.st_ino,
                after_stat.st_mtime_ns,
                after_stat.st_mode,
                after_stat.st_ctime_ns,
            )
        except OSError as exc:
            if isinstance(exc, SecurePathError):
                raise
            raise SecurePathError(
                f"cannot securely hash source input {relative!r}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


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

    source_path = _relative(source_relative)
    if os.name == "nt":
        with _HeldWindowsRoot(source_root) as held:
            handles, edges, name = held.parent_chain(source_path, create=False)
            handle: Any = None
            try:
                handle = held.api.open_relative(handles[-1], name, directory=False)
                if handle is None:
                    raise SecurePathError(
                        f"native copy source is absent: {source_relative!r}"
                    )
                before_strong = held.api.strong_identity(handle)
                basic_before = held.api.identity(handle)
                if expected_source is not None and (
                    basic_before[0] != expected_source.device
                    or basic_before[1] != expected_source.inode
                    or basic_before[2] != expected_source.size
                    or basic_before[3] != expected_source.mtime_ns
                    or (
                        expected_source.windows_file_id
                        and before_strong[1] != expected_source.windows_file_id
                    )
                    or (
                        expected_source.ctime_ns
                        and before_strong[4] != expected_source.ctime_ns
                    )
                    or (
                        expected_source.windows_attributes
                        and before_strong[8] != expected_source.windows_attributes
                    )
                ):
                    raise SecurePathError(
                        f"native copy source changed before read: {source_relative!r}"
                    )
                result = _windows_atomic_publish_new_relative_from_stream(
                    destination_root,
                    destination_relative,
                    _WindowsHandleReader(held.api, handle),
                    executable=executable,
                    windows_attributes=None,
                    expected_digest=expected_digest,
                    expected_size=expected_size,
                )
                after_strong = held.api.strong_identity(handle)
                terminal = held.api.open_relative(handles[-1], name, directory=False)
                if terminal is None:
                    raise SecurePathError(
                        f"native copy source disappeared: {source_relative!r}"
                    )
                try:
                    named = held.api.strong_identity(terminal)
                finally:
                    held.api.close(terminal)
                if (
                    before_strong != after_strong
                    or after_strong != named
                    or result.size != after_strong[5]
                ):
                    raise SecurePathError(
                        f"native copy source changed while read: {source_relative!r}"
                    )
                held.recheck(edges)
                return result
            finally:
                if handle is not None:
                    held.api.close(handle)
                for current in reversed(handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(source_root) as held:
        descriptors, edges, name = held.parent_chain(source_path, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            descriptor = os.open(
                name,
                _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                dir_fd=parent,
            )
            before_stat = os.fstat(descriptor)
            if not stat.S_ISREG(before_stat.st_mode):
                raise SecurePathError(
                    f"secure copy source is not regular: {source_relative!r}"
                )
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
                result = _posix_atomic_publish_new_relative_from_stream(
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
            source_identity = (
                _publication_identity
                if content_authorized
                else _identity
            )
            if (
                source_identity(before_stat) != source_identity(after_stat)
                or source_identity(after_stat) != source_identity(terminal)
                or not stat.S_ISREG(terminal.st_mode)
                or result.size != after_stat.st_size
            ):
                raise SecurePathError(
                    f"secure copy source changed while read: {source_relative!r}"
                )
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

    source_path = _relative(source_relative)
    destination_path = _relative(destination_relative)
    if source_path == destination_path:
        raise SecurePathError("secure promotion source and destination overlap")
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            source_handles, source_edges, source_name = held.parent_chain(
                source_path, create=False
            )
            destination_handles, destination_edges, destination_name = (
                held.parent_chain(destination_path, create=True)
            )
            source_handle: Any = None
            try:
                source_handle = held.api.open_relative(
                    source_handles[-1],
                    source_name,
                    directory=False,
                    delete=True,
                    deny_other_writes=True,
                )
                if source_handle is None:
                    raise SecurePathError(
                        f"native promotion source is absent: {source_relative!r}"
                    )
                before_native = held.api.identity(source_handle)
                before_strong = held.api.strong_identity(source_handle)
                if not _matches_windows_snapshot(
                    before_native, before_strong, expected
                ):
                    raise SecurePathError(
                        f"native promotion source changed: {source_relative!r}"
                    )
                previous = held.api.open_relative(
                    destination_handles[-1],
                    destination_name,
                    directory=False,
                    allow_missing=True,
                )
                if previous is not None:
                    held.api.close(previous)
                    raise SecurePathError(
                        "secure create-if-absent target already exists: "
                        f"{destination_relative!r}"
                    )
                held.api.rename(
                    source_handle,
                    destination_handles[-1],
                    destination_name,
                    replace=False,
                )
                final = held.api.open_relative(
                    destination_handles[-1], destination_name, directory=False
                )
                if final is None:
                    raise SecurePathError(
                        f"native promotion target disappeared: {destination_relative!r}"
                    )
                try:
                    after_native = held.api.identity(final)
                    after_strong = held.api.strong_identity(final)
                    if (
                        after_native != before_native
                        or not _same_windows_identity_except_change_time(
                            before_strong, after_strong
                        )
                    ):
                        raise SecurePathError(
                            f"native promotion target changed: {destination_relative!r}"
                        )
                finally:
                    held.api.close(final)
                held.recheck(source_edges)
                held.recheck(destination_edges)
                held.api.flush_directory(destination_handles[-1])
                return SecureFileSnapshot(
                    held.path.joinpath(*destination_path.parts),
                    expected.digest,
                    expected.size,
                    after_native[0],
                    after_native[1],
                    after_native[3],
                    expected.mode,
                    after_strong[4],
                    after_strong[1],
                    after_strong[8],
                )
            finally:
                if source_handle is not None:
                    held.api.close(source_handle)
                for current in reversed(destination_handles[1:]):
                    held.api.close(current)
                for current in reversed(source_handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(root) as held:
        source_descriptors, source_edges, source_name = held.parent_chain(
            source_path, create=False
        )
        destination_descriptors, destination_edges, destination_name = (
            held.parent_chain(destination_path, create=True)
        )
        descriptor = -1
        destination_published = False
        source_removed = False
        try:
            source_parent = source_descriptors[-1]
            destination_parent = destination_descriptors[-1]
            descriptor = os.open(
                source_name,
                _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
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
                raise SecurePathError(
                    f"secure promotion source changed: {source_relative!r}"
                )
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
                    "secure create-if-absent target already exists: "
                    f"{destination_relative!r}"
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
            if (
                _publication_identity(after_stat) != _publication_identity(before_stat)
                or _identity(terminal) != _identity(after_stat)
            ):
                raise SecurePathError(
                    f"secure promotion target changed: {destination_relative!r}"
                )
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
            if (
                _publication_identity(final_stat) != _publication_identity(after_stat)
                or _identity(final_terminal) != _identity(final_stat)
            ):
                raise SecurePathError(
                    f"secure promotion target changed: {destination_relative!r}"
                )
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


def atomic_publish_relative(
    root: Path,
    relative: str,
    payload: bytes,
) -> SecureFileSnapshot:
    """Publish bytes beneath ``root`` by a held-parent atomic replace.

    An existing regular target may be replaced for a later independent cold
    run.  Redirects and non-regular entries are rejected before commit, while
    the final rename itself replaces the directory entry and never follows it.
    """

    if type(payload) is not bytes:
        raise TypeError("secure publication payload must be immutable bytes")
    if os.name == "nt":
        return _windows_atomic_publish_relative(root, relative, payload, replace=True)
    return _posix_atomic_publish_relative(root, relative, payload, replace=True)


def atomic_publish_relative_if_current(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    expected: SecureFileSnapshot | None,
    mode: int | None = None,
    windows_attributes: int | None = None,
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
    if os.name == "nt":
        if mode is not None:
            raise SecurePathError("native Windows publication cannot set POSIX mode")
        if windows_attributes is not None and not windows_attributes_are_basic_restorable(
            windows_attributes
        ):
            raise SecurePathError("native publication attributes are unsafe")
        return _windows_atomic_publish_relative(
            root,
            relative,
            payload,
            replace=expected is not None,
            expected=expected,
            windows_attributes=windows_attributes,
        )
    if windows_attributes is not None:
        raise SecurePathError("POSIX publication cannot set Windows attributes")
    return _posix_atomic_publish_relative(
        root,
        relative,
        payload,
        replace=expected is not None,
        expected=expected,
        mode=mode if mode is not None else 0o644,
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
    if os.name == "nt":
        return _windows_atomic_publish_relative(root, relative, payload, replace=False)
    return _posix_atomic_publish_relative(root, relative, payload, replace=False)


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

    canonical = _relative(relative)
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            handles, edges, name = held.parent_chain(canonical, create=False)
            handle: Any = None
            try:
                handle = held.api.open_relative(
                    handles[-1],
                    name,
                    directory=False,
                    delete=True,
                    allow_missing=True,
                    deny_other_writes=True,
                )
                if handle is None:
                    return False
                identity = held.api.identity(handle)
                strong = held.api.strong_identity(handle)
                if not _matches_windows_snapshot(identity, strong, expected):
                    return False
                payload = held.api.read(handle)
                after_identity = held.api.identity(handle)
                after_strong = held.api.strong_identity(handle)
                if (
                    identity != after_identity
                    or strong != after_strong
                    or Digest.from_bytes(payload) != expected.digest
                ):
                    return False
                held.api.delete_on_close(handle)
                held.recheck(edges)
                return True
            finally:
                if handle is not None:
                    held.api.close(handle)
                for current in reversed(handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
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

    canonical = _relative(relative)
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            handles, edges, name = held.parent_chain(canonical, create=False)
            handle: Any = None
            try:
                handle = held.api.open_relative(
                    handles[-1],
                    name,
                    directory=False,
                    delete=True,
                    allow_missing=True,
                )
                if handle is None:
                    return False
                held.api.delete_on_close(handle)
                held.recheck(edges)
                return True
            finally:
                if handle is not None:
                    held.api.close(handle)
                for current in reversed(handles[1:]):
                    held.api.close(current)

    with _HeldPosixRoot(root) as held:
        descriptors, edges, name = held.parent_chain(canonical, create=False)
        descriptor = -1
        try:
            parent = descriptors[-1]
            try:
                descriptor = os.open(
                    name,
                    _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=parent,
                )
            except FileNotFoundError:
                return False
            before = os.fstat(descriptor)
            terminal = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or _identity(before) != _identity(terminal)
            ):
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
            raise SecurePathError(
                f"secure removal failed for {relative!r}: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            for current in reversed(descriptors):
                os.close(current)


def reseal_relative_file(
    root: Path,
    relative: str,
    *,
    expected: SecureFileSnapshot | None = None,
) -> SecureFileSnapshot:
    """Re-read one published file and optionally require its exact held identity."""

    _payload, received = read_relative_file(root, relative)
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
    """Hold and validate one complete named file set through caller receipt use.

    Every file handle is opened before the set is yielded.  After all content
    has been hashed, and again after the caller finishes constructing receipts,
    every named entry is compared with its still-held capability.  This gives
    multi-output callers one bounded validation interval without pretending
    that unrelated POSIX directory entries can be atomically committed.
    """

    canonical = {
        value: _relative(value)
        for value in sorted(expected, key=str.casefold)
    }
    if len({value.casefold() for value in canonical}) != len(canonical):
        raise SecurePathError("held file set contains a DOS-case path collision")
    if os.name == "nt":
        with _HeldWindowsRoot(root) as held:
            opened: list[
                tuple[
                    str,
                    list[Any],
                    list[tuple[Any, str, tuple[int, int]]],
                    str,
                    Any,
                    tuple[int, int, int, int, int],
                    tuple[int, bytes, int, int, int, int, int, bool, int],
                ]
            ] = []
            snapshots: dict[str, SecureFileSnapshot] = {}
            try:
                for relative, path in canonical.items():
                    handles, edges, name = held.parent_chain(path, create=False)
                    handle = held.api.open_relative(
                        handles[-1],
                        name,
                        directory=False,
                        deny_other_writes=True,
                    )
                    if handle is None:
                        raise SecurePathError(f"held file set member is absent: {relative!r}")
                    identity = held.api.identity(handle)
                    strong = held.api.strong_identity(handle)
                    opened.append((relative, handles, edges, name, handle, identity, strong))
                    payload = held.api.read(handle)
                    after_identity = held.api.identity(handle)
                    after_strong = held.api.strong_identity(handle)
                    expected_snapshot = expected[relative]
                    snapshot_mismatches = _windows_snapshot_mismatch_fields(
                        identity,
                        strong,
                        expected_snapshot,
                    )
                    digest_matches = (
                        Digest.from_bytes(payload) == expected_snapshot.digest
                    )
                    if (
                        identity != after_identity
                        or strong != after_strong
                        or snapshot_mismatches
                        or not digest_matches
                    ):
                        reasons = []
                        if identity != after_identity:
                            reasons.append("basic identity changed during read")
                        if strong != after_strong:
                            reasons.append("strong identity changed during read")
                        if snapshot_mismatches:
                            reasons.append(
                                "snapshot fields differ: "
                                + ", ".join(snapshot_mismatches)
                            )
                        if not digest_matches:
                            reasons.append("digest differs")
                        raise SecurePathError(
                            f"held file set member changed: {relative!r} "
                            f"({'; '.join(reasons)})"
                        )
                    snapshots[relative] = expected_snapshot
                yield MappingProxyType(snapshots)
                for relative, handles, edges, name, handle, identity, strong in opened:
                    named = held.api.open_relative(
                        handles[-1],
                        name,
                        directory=False,
                        deny_other_writes=True,
                    )
                    if named is None:
                        raise SecurePathError(
                            f"held file set member disappeared: {relative!r}"
                        )
                    try:
                        held_identity = held.api.identity(handle)
                        held_strong = held.api.strong_identity(handle)
                        expected_snapshot = expected[relative]
                        named_identity = held.api.identity(named)
                        named_strong = held.api.strong_identity(named)
                        snapshot_mismatches = _windows_snapshot_mismatch_fields(
                            held_identity,
                            held_strong,
                            expected_snapshot,
                        )
                        if (
                            held_identity != identity
                            or held_strong != strong
                            or named_identity != identity
                            or named_strong != strong
                            or snapshot_mismatches
                        ):
                            reasons = []
                            if held_identity != identity or held_strong != strong:
                                reasons.append("held capability changed")
                            if named_identity != identity or named_strong != strong:
                                reasons.append("named entry changed")
                            if snapshot_mismatches:
                                reasons.append(
                                    "snapshot fields differ: "
                                    + ", ".join(snapshot_mismatches)
                                )
                            raise SecurePathError(
                                f"held file set member changed: {relative!r} "
                                f"({'; '.join(reasons)})"
                            )
                    finally:
                        held.api.close(named)
                    held.recheck(edges)
            finally:
                for (
                    _relative_value,
                    handles,
                    _edges,
                    _name,
                    handle,
                    _identity_value,
                    _strong_value,
                ) in reversed(opened):
                    held.api.close(handle)
                    for current in reversed(handles[1:]):
                        held.api.close(current)
        return

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
                    _file_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)),
                    dir_fd=descriptors[-1],
                )
                opened_posix.append((relative, descriptors, edges, name, descriptor))
                before = os.fstat(descriptor)
                expected_snapshot = expected[relative]
                if not _matches_posix_snapshot(before, expected_snapshot):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                hasher = hashlib.sha256()
                size = 0
                while block := os.read(descriptor, _STREAM_COPY_CHUNK):
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
                if (
                    _identity(named) != _identity(current)
                    or not _matches_posix_snapshot(current, expected[relative])
                ):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                held.recheck(edges)
            yield MappingProxyType(snapshots)
            for relative, descriptors, edges, name, descriptor in opened_posix:
                named = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
                current = os.fstat(descriptor)
                if (
                    _identity(named) != _identity(current)
                    or not _matches_posix_snapshot(current, expected[relative])
                ):
                    raise SecurePathError(f"held file set member changed: {relative!r}")
                held.recheck(edges)
        finally:
            for _relative_value, descriptors, _edges, _name, descriptor in reversed(
                opened_posix
            ):
                os.close(descriptor)
                for current in reversed(descriptors):
                    os.close(current)


__all__ = [
    "SecureFileIdentity",
    "SecureFileSnapshot",
    "SecurePathError",
    "atomic_copy_new_relative",
    "atomic_publish_new_relative",
    "atomic_publish_new_relative_from_stream",
    "atomic_publish_relative",
    "atomic_publish_relative_if_current",
    "canonical_system_path",
    "digest_relative_file",
    "hold_relative_file_set",
    "promote_relative_new",
    "read_relative_file",
    "remove_published_relative",
    "remove_regular_relative",
    "reseal_relative_file",
    "stat_relative_file",
    "windows_attributes_are_basic_restorable",
]
