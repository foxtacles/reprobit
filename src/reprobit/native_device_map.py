"""Run-private DOS device maps for native Windows producer processes.

The public Win32 ``DefineDosDevice`` API writes to a logon-session namespace,
so it cannot isolate a reproducible build from peer processes.  This module is
the deliberately small native-API boundary used to construct an unnamed Object
Manager directory, shadow the caller's existing DOS namespace, and add exactly
one private drive mapping.  The backend remains responsible for holding the
mapped filesystem namespace immutable for the same lifetime.

The ntdll entry points used here are not a supported Win32 contract.  Every
entry point is therefore resolved at runtime, every NTSTATUS is checked, WOW64
is rejected, and the original process map is retained by handle and compared
after restoration.  Callers must keep the lease alive until every process to
which it was assigned has exited.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
import sys
import tempfile
import textwrap
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Self

_PROCESS_DEVICE_MAP = 23
_OBJ_CASE_INSENSITIVE = 0x00000040
_DIRECTORY_QUERY = 0x0001
_DIRECTORY_TRAVERSE = 0x0002
_DIRECTORY_CREATE_OBJECT = 0x0004
_SYMBOLIC_LINK_QUERY = 0x0001
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_NOT_SAME_OBJECT = 1656
_MAX_UNICODE_CHARS = 32767
_CURRENT_PROCESS = -1
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_VOLUME_NAME_NT = 0x00000002

_PROCESS_MAP_LOCK = Lock()


class NativeDeviceMapError(RuntimeError):
    """A native device-map capability or lifetime invariant failed closed."""


@dataclass(frozen=True, slots=True)
class NativeDeviceMapProbe:
    """Feature-probe result without claiming backend certification."""

    available: bool
    detail: str


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", ctypes.c_uint32),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _ProcessDeviceMapSet(ctypes.Structure):
    _fields_ = [("DirectoryHandle", ctypes.c_void_p)]


class _ProcessDeviceMapQuery(ctypes.Structure):
    _fields_ = [
        ("DriveMap", ctypes.c_uint32),
        ("DriveType", ctypes.c_uint8 * 32),
    ]


class _ProcessDeviceMapInformation(ctypes.Union):
    """Exact non-EX ``PROCESS_DEVICEMAP_INFORMATION`` input buffer.

    Windows validates the size of the complete union for ``ProcessDeviceMap``
    even when ``NtSetInformationProcess`` consumes only the set arm.  The
    36-byte query arm therefore makes this a 40-byte, pointer-aligned union on
    the supported 64-bit controller.
    """

    _fields_ = [
        ("Set", _ProcessDeviceMapSet),
        ("Query", _ProcessDeviceMapQuery),
    ]


def _handle(value: int) -> ctypes.c_void_p:
    return ctypes.c_void_p(value)


def _unicode_string(value: str) -> tuple[ctypes.Array[ctypes.c_wchar], _UnicodeString]:
    if not value or "\0" in value:
        raise NativeDeviceMapError("native object names must be non-empty and NUL-free")
    encoded_length = len(value.encode("utf-16-le"))
    if encoded_length > 0xFFFC:
        raise NativeDeviceMapError("native object name exceeds UNICODE_STRING capacity")
    buffer = ctypes.create_unicode_buffer(value)
    native = _UnicodeString(
        encoded_length,
        encoded_length + 2,
        ctypes.cast(buffer, ctypes.c_void_p),
    )
    return buffer, native


def _object_attributes(
    name: str | None, *, root: int | None = None
) -> tuple[ctypes.Array[ctypes.c_wchar] | None, _UnicodeString | None, _ObjectAttributes]:
    buffer: ctypes.Array[ctypes.c_wchar] | None = None
    native_name: _UnicodeString | None = None
    name_pointer: Any = None
    if name is not None:
        buffer, native_name = _unicode_string(name)
        name_pointer = ctypes.pointer(native_name)
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes),
        None if root is None else _handle(root),
        name_pointer,
        _OBJ_CASE_INSENSITIVE,
        None,
        None,
    )
    return buffer, native_name, attributes


def _status_hex(status: int) -> str:
    return f"0x{status & 0xFFFFFFFF:08X}"


class _NativeApi:
    """Exact ctypes bindings for the small native surface used by the lease."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise NativeDeviceMapError("native process device maps require Windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            # ProcessDeviceMap is known to be broken through the WOW64 thunk.
            # Requiring a native 64-bit controller is both simpler and fail-closed.
            raise NativeDeviceMapError(
                "native process device maps require a 64-bit Python controller"
            )
        if ctypes.sizeof(_ProcessDeviceMapInformation) != 40:
            raise NativeDeviceMapError(
                "native process device-map binding has an unexpected layout"
            )
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise NativeDeviceMapError("ctypes WinDLL is unavailable")
        try:
            self.ntdll = win_dll("ntdll", use_last_error=True)
            self.kernel32 = win_dll("kernel32", use_last_error=True)
            self.kernelbase = win_dll("kernelbase", use_last_error=True)
            self.NtOpenDirectoryObject = self.ntdll.NtOpenDirectoryObject
            self.NtCreateDirectoryObjectEx = self.ntdll.NtCreateDirectoryObjectEx
            self.NtCreateSymbolicLinkObject = self.ntdll.NtCreateSymbolicLinkObject
            self.NtQuerySymbolicLinkObject = self.ntdll.NtQuerySymbolicLinkObject
            self.NtSetInformationProcess = self.ntdll.NtSetInformationProcess
            self.NtClose = self.ntdll.NtClose
            self.RtlNtStatusToDosError = self.ntdll.RtlNtStatusToDosError
            self.QueryDosDeviceW = self.kernel32.QueryDosDeviceW
            self.CreateFileW = self.kernel32.CreateFileW
            self.GetFinalPathNameByHandleW = self.kernel32.GetFinalPathNameByHandleW
            self.GetCurrentProcess = self.kernel32.GetCurrentProcess
            self.IsWow64Process2 = self.kernel32.IsWow64Process2
            self.CompareObjectHandles = self.kernelbase.CompareObjectHandles
        except AttributeError as error:
            raise NativeDeviceMapError(
                f"required native device-map entry point is unavailable: {error}"
            ) from error

        pointer = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        self._get_last_error = getattr(ctypes, "get_last_error", lambda: 0)
        self._set_last_error = getattr(ctypes, "set_last_error", lambda _value: None)
        self.NtOpenDirectoryObject.argtypes = [
            ctypes.POINTER(pointer),
            uint32,
            ctypes.POINTER(_ObjectAttributes),
        ]
        self.NtOpenDirectoryObject.restype = ctypes.c_int32
        self.NtCreateDirectoryObjectEx.argtypes = [
            ctypes.POINTER(pointer),
            uint32,
            ctypes.POINTER(_ObjectAttributes),
            pointer,
            uint32,
        ]
        self.NtCreateDirectoryObjectEx.restype = ctypes.c_int32
        self.NtCreateSymbolicLinkObject.argtypes = [
            ctypes.POINTER(pointer),
            uint32,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.POINTER(_UnicodeString),
        ]
        self.NtCreateSymbolicLinkObject.restype = ctypes.c_int32
        self.NtQuerySymbolicLinkObject.argtypes = [
            pointer,
            ctypes.POINTER(_UnicodeString),
            ctypes.POINTER(uint32),
        ]
        self.NtQuerySymbolicLinkObject.restype = ctypes.c_int32
        self.NtSetInformationProcess.argtypes = [pointer, uint32, pointer, uint32]
        self.NtSetInformationProcess.restype = ctypes.c_int32
        self.NtClose.argtypes = [pointer]
        self.NtClose.restype = ctypes.c_int32
        self.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        self.RtlNtStatusToDosError.restype = uint32
        self.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, uint32]
        self.QueryDosDeviceW.restype = uint32
        self.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            uint32,
            uint32,
            pointer,
            uint32,
            uint32,
            pointer,
        ]
        self.CreateFileW.restype = pointer
        self.GetFinalPathNameByHandleW.argtypes = [
            pointer,
            ctypes.c_wchar_p,
            uint32,
            uint32,
        ]
        self.GetFinalPathNameByHandleW.restype = uint32
        self.GetCurrentProcess.argtypes = []
        self.GetCurrentProcess.restype = pointer
        self.IsWow64Process2.argtypes = [
            pointer,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        self.IsWow64Process2.restype = ctypes.c_int
        self.CompareObjectHandles.argtypes = [pointer, pointer]
        self.CompareObjectHandles.restype = ctypes.c_int

        process_machine = ctypes.c_uint16()
        native_machine = ctypes.c_uint16()
        if not self.IsWow64Process2(
            self.GetCurrentProcess(),
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        ):
            raise NativeDeviceMapError(
                f"IsWow64Process2 failed with Win32 error {self._get_last_error()}"
            )
        if process_machine.value != 0:
            raise NativeDeviceMapError("WOW64 cannot safely set ProcessDeviceMap")

    def _check(self, status: int, operation: str) -> None:
        if status >= 0:
            return
        win32 = int(self.RtlNtStatusToDosError(status))
        raise NativeDeviceMapError(
            f"{operation} failed with NTSTATUS {_status_hex(status)} (Win32 {win32})"
        )

    def open_current_directory(self) -> int:
        _buffer, _name, attributes = _object_attributes(r"\??")
        result = ctypes.c_void_p()
        status = int(
            self.NtOpenDirectoryObject(
                ctypes.byref(result),
                _DIRECTORY_QUERY | _DIRECTORY_TRAVERSE,
                ctypes.byref(attributes),
            )
        )
        self._check(status, r"NtOpenDirectoryObject(\??)")
        if result.value is None:
            raise NativeDeviceMapError("NtOpenDirectoryObject returned a null handle")
        return int(result.value)

    def create_shadow_directory(self, shadow: int) -> int:
        _buffer, _name, attributes = _object_attributes(None)
        result = ctypes.c_void_p()
        status = int(
            self.NtCreateDirectoryObjectEx(
                ctypes.byref(result),
                _DIRECTORY_QUERY | _DIRECTORY_TRAVERSE | _DIRECTORY_CREATE_OBJECT,
                ctypes.byref(attributes),
                _handle(shadow),
                0,
            )
        )
        self._check(status, "NtCreateDirectoryObjectEx")
        if result.value is None:
            raise NativeDeviceMapError("NtCreateDirectoryObjectEx returned a null handle")
        return int(result.value)

    def create_symbolic_link(self, directory: int, name: str, target: str) -> int:
        _name_buffer, _name, attributes = _object_attributes(name, root=directory)
        _target_buffer, target_string = _unicode_string(target)
        result = ctypes.c_void_p()
        status = int(
            self.NtCreateSymbolicLinkObject(
                ctypes.byref(result),
                _SYMBOLIC_LINK_QUERY,
                ctypes.byref(attributes),
                ctypes.byref(target_string),
            )
        )
        self._check(status, f"NtCreateSymbolicLinkObject({name})")
        if result.value is None:
            raise NativeDeviceMapError(
                "NtCreateSymbolicLinkObject returned a null handle"
            )
        return int(result.value)

    def query_symbolic_link(self, link: int) -> str:
        buffer = ctypes.create_unicode_buffer(_MAX_UNICODE_CHARS)
        result = _UnicodeString(
            0,
            ctypes.sizeof(buffer),
            ctypes.cast(buffer, ctypes.c_void_p),
        )
        returned = ctypes.c_uint32()
        status = int(
            self.NtQuerySymbolicLinkObject(
                _handle(link), ctypes.byref(result), ctypes.byref(returned)
            )
        )
        self._check(status, "NtQuerySymbolicLinkObject")
        if result.Length % 2 or result.Length > result.MaximumLength:
            raise NativeDeviceMapError("NtQuerySymbolicLinkObject returned invalid length")
        return ctypes.wstring_at(buffer, result.Length // 2)

    def set_process_map(self, process: int, directory: int) -> None:
        information = _ProcessDeviceMapInformation()
        information.Set.DirectoryHandle = _handle(directory)
        status = int(
            self.NtSetInformationProcess(
                _handle(process),
                _PROCESS_DEVICE_MAP,
                ctypes.byref(information),
                ctypes.sizeof(information),
            )
        )
        self._check(status, "NtSetInformationProcess(ProcessDeviceMap)")

    def same_object(self, first: int, second: int) -> bool:
        self._set_last_error(0)
        if self.CompareObjectHandles(_handle(first), _handle(second)):
            return True
        error = int(self._get_last_error())
        if error == _ERROR_NOT_SAME_OBJECT:
            return False
        raise NativeDeviceMapError(
            f"CompareObjectHandles failed with Win32 error {error}"
        )

    def query_drive(self, drive: str) -> str | None:
        buffer = ctypes.create_unicode_buffer(_MAX_UNICODE_CHARS)
        self._set_last_error(0)
        length = int(self.QueryDosDeviceW(drive, buffer, len(buffer)))
        if length:
            return buffer.value
        error = int(self._get_last_error())
        if error in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
            return None
        raise NativeDeviceMapError(
            f"QueryDosDeviceW({drive}) failed with Win32 error {error}"
        )

    def final_nt_path(self, path: Path) -> str:
        """Resolve one directory handle to its final NT device-object path."""

        self._set_last_error(0)
        raw_handle = self.CreateFileW(
            str(path),
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if raw_handle is None or raw_handle == invalid:
            raise NativeDeviceMapError(
                f"cannot open native logical-drive root: Win32 {self._get_last_error()}"
            )
        handle = int(raw_handle)
        try:
            capacity = 1024
            while True:
                buffer = ctypes.create_unicode_buffer(capacity)
                self._set_last_error(0)
                length = int(
                    self.GetFinalPathNameByHandleW(
                        _handle(handle), buffer, capacity, _VOLUME_NAME_NT
                    )
                )
                if length == 0:
                    raise NativeDeviceMapError(
                        "GetFinalPathNameByHandleW(VOLUME_NAME_NT) failed with "
                        f"Win32 error {self._get_last_error()}"
                    )
                if length < capacity:
                    result = buffer.value
                    if not result.startswith("\\Device\\") or "\0" in result:
                        raise NativeDeviceMapError(
                            "native logical-drive root lacks an absolute device path"
                        )
                    return result.rstrip("\\")
                if length > _MAX_UNICODE_CHARS:
                    raise NativeDeviceMapError(
                        "native logical-drive root exceeds Windows path capacity"
                    )
                # On insufficient space the wide API returns the required
                # capacity including its terminator.
                capacity = length
        finally:
            self.close(handle, "logical-drive-root")

    def close(self, handle: int, label: str) -> None:
        status = int(self.NtClose(_handle(handle)))
        self._check(status, f"NtClose({label})")


def probe_native_device_map() -> NativeDeviceMapProbe:
    """Probe exports and harmless construction, without mutating a DeviceMap."""

    if os.name != "nt":
        return NativeDeviceMapProbe(False, "native process device maps require Windows")
    api: _NativeApi | None = None
    original: int | None = None
    private: int | None = None
    result: NativeDeviceMapProbe
    try:
        api = _NativeApi()
        original = api.open_current_directory()
        private = api.create_shadow_directory(original)
        current = api.open_current_directory()
        try:
            if not api.same_object(current, original):
                raise NativeDeviceMapError(
                    "current DOS directory identity changed during feature probe"
                )
        finally:
            api.close(current, "probe-current-directory")
        result = NativeDeviceMapProbe(
            True,
            "anonymous shadow-directory primitives available; map mutation unprobed",
        )
    except (NativeDeviceMapError, OSError) as error:
        result = NativeDeviceMapProbe(False, str(error))
    if api is not None:
        cleanup_errors: list[BaseException] = []
        for handle, label in (
            (private, "probe-private-directory"),
            (original, "probe-original-directory"),
        ):
            if handle is None:
                continue
            try:
                api.close(handle, label)
            except (NativeDeviceMapError, OSError) as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            return NativeDeviceMapProbe(
                False,
                "feature-probe cleanup failed: "
                + "; ".join(str(error) for error in cleanup_errors),
            )
    return result


def probe_native_device_map_execution() -> NativeDeviceMapProbe:
    """Mutate one temporary map and prove direct-child plus descendant visibility."""

    primitives = probe_native_device_map()
    if not primitives.available:
        return primitives
    try:
        api = _NativeApi()
        drive = next(
            (letter for letter in "RQPONMLKJIHGFEDBA" if api.query_drive(f"{letter}:") is None),
            None,
        )
        if drive is None:
            return NativeDeviceMapProbe(False, "no free logical drive is available for probing")

        from reprobit.process import CommandSpec, ProcessSupervisor

        with tempfile.TemporaryDirectory(prefix="reprobit-device-map-probe-") as raw_root:
            root = Path(raw_root).resolve(strict=True)
            (root / "marker.txt").write_text("private-descendant", encoding="ascii")
            grandchild = (
                "from pathlib import Path; "
                f"print(Path(r'{drive}:\\marker.txt').read_text(encoding='ascii'))"
            )
            child = textwrap.dedent(
                f"""
                import subprocess
                import sys

                result = subprocess.run(
                    [sys.executable, "-c", {grandchild!r}],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=15,
                )
                sys.stdout.buffer.write(result.stdout)
                raise SystemExit(result.returncode)
                """
            )
            environment = {}
            system_root = os.environ.get("SYSTEMROOT")
            if system_root:
                environment["SYSTEMROOT"] = system_root
            with (
                NativeDeviceMapLease(root, drive) as lease,
                ProcessSupervisor() as supervisor,
            ):
                result = supervisor.run(
                    CommandSpec.create(
                        (sys.executable, "-c", child),
                        cwd=root,
                        environment=environment,
                        timeout_seconds=20,
                    ),
                    suspended_process_initializer=lease.assign_to_suspended_process,
                )
        if result.output.strip() != b"private-descendant":
            return NativeDeviceMapProbe(
                False,
                "private DeviceMap did not remain visible through a child descendant",
            )
        return NativeDeviceMapProbe(
            True,
            "private DeviceMap direct assignment and descendant inheritance verified",
        )
    except Exception as error:
        return NativeDeviceMapProbe(False, f"private DeviceMap execution probe failed: {error}")


class NativeDeviceMapLease(AbstractContextManager["NativeDeviceMapLease"]):
    """One process-private logical drive with exact original-map restoration.

    ``assign_to_suspended_process`` exists because modern Win32 process
    creation must not be assumed to inherit a parent's custom DeviceMap.  The
    caller must invoke it after ``CREATE_SUSPENDED`` and before resuming the
    target.  This lease also installs the map in the controller process for its
    bounded lifetime so direct logical-path checks use the identical namespace.
    """

    def __init__(self, root: Path | str, drive_letter: str) -> None:
        if not isinstance(drive_letter, str) or not re.fullmatch(
            r"[A-Za-z]", drive_letter
        ):
            raise NativeDeviceMapError("logical drive must be one ASCII letter")
        self.root = Path(root)
        self.drive_letter = drive_letter.upper()
        self._api: _NativeApi | None = None
        self._original: int | None = None
        self._private: int | None = None
        self._link: int | None = None
        self._active = False
        self._owns_lock = False
        self._target: str | None = None

    def _require_api(self) -> _NativeApi:
        if self._api is None:
            raise NativeDeviceMapError("native device-map lease is not active")
        return self._api

    def _assert_current_map(self, expected: int, phase: str) -> None:
        api = self._require_api()
        current = api.open_current_directory()
        try:
            if not api.same_object(current, expected):
                raise NativeDeviceMapError(
                    f"current DOS directory identity differs {phase}"
                )
        finally:
            api.close(current, f"{phase}-current-directory")

    def open(self) -> None:
        if self._active or self._owns_lock:
            raise NativeDeviceMapError("native device-map lease is already active")
        if not _PROCESS_MAP_LOCK.acquire(blocking=False):
            raise NativeDeviceMapError(
                "another native device-map lease is active in this process"
            )
        self._owns_lock = True
        try:
            api = _NativeApi()
            self._api = api
            if not self.root.is_absolute():
                raise NativeDeviceMapError(
                    "native logical-drive root must be absolute"
                )
            try:
                root_metadata = self.root.lstat()
            except OSError as error:
                raise NativeDeviceMapError(
                    f"cannot inspect native logical-drive root {self.root}: {error}"
                ) from error
            if (
                stat.S_ISLNK(root_metadata.st_mode)
                or int(getattr(root_metadata, "st_reparse_tag", False))
                or int(getattr(root_metadata, "st_file_attributes", False))
                & _FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise NativeDeviceMapError(
                    f"native logical-drive root must not be redirected: {self.root}"
                )
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise NativeDeviceMapError(
                    f"native logical-drive root is not a plain directory: {self.root}"
                )
            resolved = self.root.resolve(strict=True)
            if not resolved.is_dir():
                raise NativeDeviceMapError(
                    f"native logical-drive root is not a plain directory: {resolved}"
                )
            physical = str(resolved)
            if not re.match(r"^[A-Za-z]:\\", physical):
                raise NativeDeviceMapError(
                    "native logical-drive root must reside on a local drive"
                )
            device = f"{self.drive_letter}:"
            conflict = api.query_drive(device)
            if conflict is not None:
                raise NativeDeviceMapError(
                    f"native logical drive {device} is already mapped to {conflict}"
                )
            self._original = api.open_current_directory()
            self._target = api.final_nt_path(resolved)
            self._private = api.create_shadow_directory(self._original)
            self._link = api.create_symbolic_link(
                self._private, device, self._target
            )
            if api.query_symbolic_link(self._link) != self._target:
                raise NativeDeviceMapError(
                    "private logical-drive link differs from its admitted target"
                )
            api.set_process_map(_CURRENT_PROCESS, self._private)
            self._active = True
            self._assert_current_map(self._private, "after installation")
            if api.query_drive(device) != self._target:
                raise NativeDeviceMapError(
                    "private logical drive does not resolve to its admitted target"
                )
        except BaseException as original_error:
            try:
                self._rollback_open()
            except BaseException as cleanup_error:
                original_error.add_note(
                    f"native device-map rollback also failed: {cleanup_error}"
                )
            raise

    def assign_to_suspended_process(self, process_handle: int) -> None:
        """Install this exact map in an admitted process before its first resume."""

        if (
            not self._active
            or self._private is None
            or isinstance(process_handle, bool)
            or process_handle <= 0
        ):
            raise NativeDeviceMapError(
                "device-map assignment requires an active lease and process handle"
            )
        self._require_api().set_process_map(process_handle, self._private)

    def _close_handle(self, attribute: str, label: str) -> None:
        handle = getattr(self, attribute)
        if handle is None:
            return
        self._require_api().close(handle, label)
        setattr(self, attribute, None)

    def _release_resources(self) -> None:
        errors: list[BaseException] = []
        for attribute, label in (
            ("_link", "private-logical-drive"),
            ("_private", "private-directory"),
            ("_original", "original-directory"),
        ):
            try:
                self._close_handle(attribute, label)
            except BaseException as error:
                errors.append(error)
        self._api = None
        self._target = None
        if self._owns_lock:
            self._owns_lock = False
            _PROCESS_MAP_LOCK.release()
        if errors:
            raise NativeDeviceMapError(
                "; ".join(str(error) for error in errors)
            ) from errors[0]

    def _rollback_open(self) -> None:
        if self._active:
            if self._original is None:
                raise NativeDeviceMapError(
                    "active private map lost its original-directory handle"
                )
            self._require_api().set_process_map(_CURRENT_PROCESS, self._original)
            self._assert_current_map(self._original, "after rollback")
            self._active = False
        self._release_resources()

    def close(self) -> None:
        if not self._active and not self._owns_lock:
            return
        if self._active:
            if self._original is None:
                raise NativeDeviceMapError(
                    "active private map lost its original-directory handle"
                )
            # Restoration and identity proof happen before any object handle is
            # released.  On failure handles and the process lock remain owned so
            # a caller can retry instead of silently continuing in an unknown map.
            self._require_api().set_process_map(_CURRENT_PROCESS, self._original)
            self._assert_current_map(self._original, "after restoration")
            self._active = False
        self._release_resources()

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "NativeDeviceMapError",
    "NativeDeviceMapLease",
    "NativeDeviceMapProbe",
    "probe_native_device_map",
    "probe_native_device_map_execution",
]
