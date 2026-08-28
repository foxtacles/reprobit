"""Run-private DOS drives for native Windows producer trees.

The controller validates and seals a physical root without mapping a drive in
its own logon session. A contained broker receives a fresh LSA logon session,
proves its ``AuthenticationId`` changed, defines one LUID-local drive, and
starts the real producer suspended inside a nested Job Object. The mapping
remains owned until that complete producer tree is empty.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Mapping
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from reprobit.process import CommandSpec

_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_MAX_UNICODE_CHARS = 32767
_CURRENT_PROCESS = -1
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_VOLUME_NAME_NT = 0x00000002
_DDD_RAW_TARGET_PATH = 0x00000001
_DDD_REMOVE_DEFINITION = 0x00000002
_DDD_EXACT_MATCH_ON_REMOVE = 0x00000004
_DDD_NO_BROADCAST_SYSTEM = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_LOGON_NETCREDENTIALS_ONLY = 0x00000002
_STARTF_USESTDHANDLES = 0x00000100
_TOKEN_QUERY = 0x0008
_TOKEN_STATISTICS = 10
_SYSTEM_AUTHENTICATION_ID = (0x000003E7, 0)
_BROKER_DRAIN_TIMEOUT_SECONDS = 5.0
_DUPLICATE_SAME_ACCESS = 0x00000002


class NativeDeviceMapError(RuntimeError):
    """A native Windows logical-path or lifetime invariant failed closed."""


@dataclass(frozen=True, slots=True)
class NativeDeviceMapProbe:
    """Feature-probe result without claiming backend certification."""

    available: bool
    detail: str


class _Luid(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _TokenStatistics(ctypes.Structure):
    _fields_ = [
        ("TokenId", _Luid),
        ("AuthenticationId", _Luid),
        ("ExpirationTime", ctypes.c_int64),
        ("TokenType", ctypes.c_uint32),
        ("ImpersonationLevel", ctypes.c_uint32),
        ("DynamicCharged", ctypes.c_uint32),
        ("DynamicAvailable", ctypes.c_uint32),
        ("GroupCount", ctypes.c_uint32),
        ("PrivilegeCount", ctypes.c_uint32),
        ("ModifiedId", _Luid),
    ]


def _handle(value: int) -> ctypes.c_void_p:
    return ctypes.c_void_p(value)


class _LineageApi:
    """Narrow supported Win32 surface used inside lineage brokers."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise NativeDeviceMapError("Windows lineage namespaces require Windows")
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise NativeDeviceMapError("ctypes WinDLL is unavailable")
        try:
            self.kernel32 = win_dll("kernel32", use_last_error=True)
            self.advapi32 = win_dll("advapi32", use_last_error=True)
            self.QueryDosDeviceW = self.kernel32.QueryDosDeviceW
            self.DefineDosDeviceW = self.kernel32.DefineDosDeviceW
            self.CloseHandle = self.kernel32.CloseHandle
            self.CreateFileW = self.kernel32.CreateFileW
            self.GetFinalPathNameByHandleW = self.kernel32.GetFinalPathNameByHandleW
            self.OpenProcessToken = self.advapi32.OpenProcessToken
            self.GetTokenInformation = self.advapi32.GetTokenInformation
        except AttributeError as error:
            raise NativeDeviceMapError(
                f"required lineage-namespace entry point is unavailable: {error}"
            ) from error

        pointer = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        self._get_last_error = getattr(ctypes, "get_last_error", lambda: 0)
        self._set_last_error = getattr(ctypes, "set_last_error", lambda _value: None)
        self.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, uint32]
        self.QueryDosDeviceW.restype = uint32
        self.DefineDosDeviceW.argtypes = [uint32, ctypes.c_wchar_p, ctypes.c_wchar_p]
        self.DefineDosDeviceW.restype = ctypes.c_int
        self.CloseHandle.argtypes = [pointer]
        self.CloseHandle.restype = ctypes.c_int
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
        self.OpenProcessToken.argtypes = [pointer, uint32, ctypes.POINTER(pointer)]
        self.OpenProcessToken.restype = ctypes.c_int
        self.GetTokenInformation.argtypes = [
            pointer,
            ctypes.c_int,
            pointer,
            uint32,
            ctypes.POINTER(uint32),
        ]
        self.GetTokenInformation.restype = ctypes.c_int

    def close_handle(self, handle: int, label: str) -> None:
        self._set_last_error(0)
        if not self.CloseHandle(_handle(handle)):
            raise NativeDeviceMapError(
                f"CloseHandle({label}) failed with Win32 error "
                f"{self._get_last_error()}"
            )

    def process_authentication_id(self, process: int) -> tuple[int, int]:
        """Return the target token's exact local-DOS-namespace identity."""

        token = ctypes.c_void_p()
        self._set_last_error(0)
        if not self.OpenProcessToken(
            _handle(process), _TOKEN_QUERY, ctypes.byref(token)
        ):
            raise NativeDeviceMapError(
                f"OpenProcessToken failed with Win32 error {self._get_last_error()}"
            )
        if token.value is None:
            raise NativeDeviceMapError("OpenProcessToken returned a null handle")
        try:
            statistics = _TokenStatistics()
            returned = ctypes.c_uint32()
            self._set_last_error(0)
            if not self.GetTokenInformation(
                token,
                _TOKEN_STATISTICS,
                ctypes.byref(statistics),
                ctypes.sizeof(statistics),
                ctypes.byref(returned),
            ):
                raise NativeDeviceMapError(
                    "GetTokenInformation(TokenStatistics) failed with Win32 error "
                    f"{self._get_last_error()}"
                )
            if returned.value != ctypes.sizeof(statistics):
                raise NativeDeviceMapError(
                    "GetTokenInformation(TokenStatistics) returned an unexpected size"
                )
            authentication_id = statistics.AuthenticationId
            return int(authentication_id.LowPart), int(authentication_id.HighPart)
        finally:
            self.close_handle(int(token.value), "process-token")

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

    def define_local_drive(self, drive: str, target: str) -> None:
        """Define and verify one mapping in the caller's LUID-local namespace."""

        if self.query_drive(drive) is not None:
            raise NativeDeviceMapError(
                f"lineage-local logical drive {drive} already exists"
            )
        flags = _DDD_RAW_TARGET_PATH | _DDD_NO_BROADCAST_SYSTEM
        self._set_last_error(0)
        if not self.DefineDosDeviceW(flags, drive, target):
            raise NativeDeviceMapError(
                f"DefineDosDeviceW({drive}) failed with Win32 error "
                f"{self._get_last_error()}"
            )
        try:
            if self.query_drive(drive) != target:
                raise NativeDeviceMapError(
                    "lineage-local logical drive differs from its admitted target"
                )
        except BaseException:
            self.remove_local_drive(drive, target)
            raise

    def remove_local_drive(self, drive: str, target: str) -> None:
        """Remove exactly the mapping created by :meth:`define_local_drive`."""

        flags = (
            _DDD_RAW_TARGET_PATH
            | _DDD_REMOVE_DEFINITION
            | _DDD_EXACT_MATCH_ON_REMOVE
            | _DDD_NO_BROADCAST_SYSTEM
        )
        self._set_last_error(0)
        if not self.DefineDosDeviceW(flags, drive, target):
            raise NativeDeviceMapError(
                f"DefineDosDeviceW removal for {drive} failed with Win32 error "
                f"{self._get_last_error()}"
            )
        if self.query_drive(drive) == target:
            raise NativeDeviceMapError(
                "lineage-local logical drive remained after exact removal"
            )

    def final_nt_path(self, path: Path) -> str:
        """Seal one directory to its final NT device-object path."""

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
                capacity = length
        finally:
            self.close_handle(handle, "logical-drive-root")



def probe_native_device_map() -> NativeDeviceMapProbe:
    """Probe the supported Win32 surface without creating a drive mapping."""

    if os.name != "nt":
        return NativeDeviceMapProbe(False, "native lineage drives require Windows")
    try:
        authentication_id = _LineageApi().process_authentication_id(_CURRENT_PROCESS)
        if authentication_id == _SYSTEM_AUTHENTICATION_ID:
            raise NativeDeviceMapError(
                "LocalSystem uses the global DOS namespace and is not a safe lineage controller"
            )
        return NativeDeviceMapProbe(
            True,
            "fresh-LUID local-drive primitives available; execution unprobed",
        )
    except (NativeDeviceMapError, OSError) as error:
        return NativeDeviceMapProbe(False, str(error))


def probe_native_device_map_execution() -> NativeDeviceMapProbe:
    """Prove one fresh-LUID drive through a producer and descendant."""

    primitives = probe_native_device_map()
    if not primitives.available:
        return primitives
    try:
        api = _LineageApi()
        drive = next(
            (letter for letter in "RQPONMLKJIHGFEDBA" if api.query_drive(f"{letter}:") is None),
            None,
        )
        if drive is None:
            return NativeDeviceMapProbe(
                False,
                "no controller-unmapped logical-drive candidate is available for probing",
            )

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
                from pathlib import Path

                print(Path(r'{drive}:\\marker.txt').read_text(encoding='ascii'))

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
                    windows_lineage_planner=lease,
                )
        if result.output.splitlines() != [
            b"private-descendant",
            b"private-descendant",
        ]:
            return NativeDeviceMapProbe(
                False,
                "fresh-LUID drive did not remain visible through a child descendant",
            )
        return NativeDeviceMapProbe(
            True,
            "fresh-LUID local drive and descendant lifetime verified",
        )
    except Exception as error:
        return NativeDeviceMapProbe(False, f"lineage-drive execution probe failed: {error}")


class NativeDeviceMapLease(AbstractContextManager["NativeDeviceMapLease"]):
    """One sealed physical root plus a descendant-safe producer namespace."""

    def __init__(self, root: Path | str, drive_letter: str) -> None:
        if not isinstance(drive_letter, str) or not re.fullmatch(
            r"[A-Za-z]", drive_letter
        ):
            raise NativeDeviceMapError("logical drive must be one ASCII letter")
        self.root = Path(root)
        self.drive_letter = drive_letter.upper()
        self._active = False
        self._target: str | None = None
        self._controller_authentication_id: tuple[int, int] | None = None

    def open(self) -> None:
        if self._active:
            raise NativeDeviceMapError("native lineage lease is already active")
        try:
            api = _LineageApi()
            if not self.root.is_absolute():
                raise NativeDeviceMapError("native logical-drive root must be absolute")
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
            if re.match(r"^[A-Za-z]:\\", str(resolved)) is None:
                raise NativeDeviceMapError(
                    "native logical-drive root must reside on a local drive"
                )
            authentication_id = api.process_authentication_id(_CURRENT_PROCESS)
            if authentication_id == _SYSTEM_AUTHENTICATION_ID:
                raise NativeDeviceMapError(
                    "LocalSystem uses the global DOS namespace and cannot isolate a producer"
                )
            self._target = api.final_nt_path(resolved)
            self._controller_authentication_id = authentication_id
            self._active = True
        except BaseException:
            self._target = None
            self._controller_authentication_id = None
            raise

    def windows_lineage_plan(self, spec: CommandSpec) -> bytes:
        """Serialize the producer contract for the inherited-handle broker."""

        if (
            not self._active
            or self._target is None
            or self._controller_authentication_id is None
        ):
            raise NativeDeviceMapError(
                "Windows lineage planning requires an active lineage lease"
            )
        document = {
            "argv": list(spec.argv),
            "controller_authentication_id": list(
                self._controller_authentication_id
            ),
            "cwd": str(spec.cwd),
            "drive": f"{self.drive_letter}:",
            "environment": [list(entry) for entry in spec.environment],
            "target": self._target,
            "version": 1,
        }
        return json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def close(self) -> None:
        self._active = False
        self._target = None
        self._controller_authentication_id = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _lineage_inner_command() -> tuple[str, ...]:
    return (
        sys.executable,
        "-I",
        "-m",
        "reprobit.native_device_map",
        "--lineage-inner",
    )


def _minimal_broker_environment(
    source: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    folded = {key.casefold(): value for key, value in source.items()}
    if "systemroot" not in folded:
        raise NativeDeviceMapError("Windows lineage broker environment lacks SystemRoot")
    return tuple(
        (name, folded[name.casefold()])
        for name in ("SystemRoot", "WINDIR")
        if name.casefold() in folded
    )


def _serialize_windows_environment(
    entries: tuple[tuple[str, str], ...],
) -> str:
    seen: set[str] = set()
    normalized: list[tuple[str, str]] = []
    for key, value in entries:
        if not key or "=" in key or "\0" in key or "\0" in value:
            raise NativeDeviceMapError("Windows lineage broker environment is invalid")
        folded = key.casefold()
        if folded in seen:
            raise NativeDeviceMapError(
                f"duplicate Windows lineage broker environment key: {key}"
            )
        seen.add(folded)
        normalized.append((key, value))
    ordered = sorted(normalized, key=lambda entry: (entry[0].casefold(), entry[0]))
    return "\0".join(f"{key}={value}" for key, value in ordered) + "\0\0"


def _duplicate_standard_handles(
    kernel32: Any,
    api: _LineageApi,
    stack: ExitStack,
) -> tuple[int, int, int]:
    """Create inheritable copies for STARTF_USESTDHANDLES."""

    current_process = kernel32.GetCurrentProcess()
    invalid = ctypes.c_void_p(-1).value
    duplicated: list[int] = []
    for identifier, label in (
        (-10, "broker-stdin"),
        (-11, "broker-stdout"),
        (-12, "broker-stderr"),
    ):
        source = kernel32.GetStdHandle(ctypes.c_uint32(identifier & 0xFFFFFFFF))
        if source in {None, invalid}:
            raise NativeDeviceMapError(
                f"Windows lineage broker lacks valid {label.removeprefix('broker-')}"
            )
        target = ctypes.c_void_p()
        if not kernel32.DuplicateHandle(
            current_process,
            source,
            current_process,
            ctypes.byref(target),
            0,
            True,
            _DUPLICATE_SAME_ACCESS,
        ):
            raise NativeDeviceMapError(
                f"DuplicateHandle({label}) failed with Win32 error "
                f"{api._get_last_error()}"
            )
        if target.value is None:
            raise NativeDeviceMapError(f"DuplicateHandle({label}) returned null")
        handle = int(target.value)
        stack.callback(api.close_handle, handle, label)
        duplicated.append(handle)
    return duplicated[0], duplicated[1], duplicated[2]



def _read_lineage_plan() -> tuple[dict[str, Any], CommandSpec]:
    """Read and validate the broker contract from the inherited input handle."""

    from reprobit.process import CommandSpec

    payload = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
    if not payload or len(payload) > 16 * 1024 * 1024:
        raise NativeDeviceMapError("Windows lineage plan is absent or too large")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeviceMapError("Windows lineage plan is not valid UTF-8 JSON") from error
    if not isinstance(document, dict) or set(document) != {
        "argv",
        "controller_authentication_id",
        "cwd",
        "drive",
        "environment",
        "target",
        "version",
    }:
        raise NativeDeviceMapError("Windows lineage plan has an unexpected shape")
    if document["version"] != 1:
        raise NativeDeviceMapError("Windows lineage plan version is unsupported")
    argv = document["argv"]
    environment = document["environment"]
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise NativeDeviceMapError("Windows lineage argv is invalid")
    if not isinstance(environment, list) or not all(
        isinstance(entry, list)
        and len(entry) == 2
        and all(isinstance(value, str) for value in entry)
        for entry in environment
    ):
        raise NativeDeviceMapError("Windows lineage environment is invalid")
    spec = CommandSpec.create(
        argv,
        cwd=document["cwd"],
        environment=[(entry[0], entry[1]) for entry in environment],
    )
    return document, spec


def _run_logon_broker() -> int:
    """Launch the mapping broker in one fresh, verified LSA logon session."""

    if os.name != "nt":
        raise NativeDeviceMapError("Windows lineage broker requires native Windows")
    from ctypes import wintypes

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise NativeDeviceMapError("ctypes WinDLL is unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    advapi32 = win_dll("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    uint32 = ctypes.c_uint32
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = pointer
    kernel32.GetStdHandle.argtypes = [uint32]
    kernel32.GetStdHandle.restype = pointer
    kernel32.DuplicateHandle.argtypes = [
        pointer,
        pointer,
        pointer,
        ctypes.POINTER(pointer),
        uint32,
        ctypes.c_int,
        uint32,
    ]
    kernel32.DuplicateHandle.restype = ctypes.c_int
    kernel32.ResumeThread.argtypes = [pointer]
    kernel32.ResumeThread.restype = uint32
    kernel32.WaitForSingleObject.argtypes = [pointer, uint32]
    kernel32.WaitForSingleObject.restype = uint32
    kernel32.GetExitCodeProcess.argtypes = [pointer, ctypes.POINTER(uint32)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int
    kernel32.TerminateProcess.argtypes = [pointer, uint32]
    kernel32.TerminateProcess.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [pointer]
    kernel32.CloseHandle.restype = ctypes.c_int
    advapi32.CreateProcessWithLogonW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        uint32,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        uint32,
        pointer,
        ctypes.c_wchar_p,
        ctypes.POINTER(StartupInfo),
        ctypes.POINTER(ProcessInformation),
    ]
    advapi32.CreateProcessWithLogonW.restype = ctypes.c_int
    get_last_error = getattr(ctypes, "get_last_error", lambda: 0)

    command = _lineage_inner_command()
    command_line = subprocess.list2cmdline(command)
    if len(command_line) > 1023:
        raise NativeDeviceMapError(
            "internal broker exceeds CreateProcessWithLogonW's command-line limit"
        )
    command_buffer = ctypes.create_unicode_buffer(command_line)
    environment = _serialize_windows_environment(
        _minimal_broker_environment(os.environ)
    )
    environment_buffer = (ctypes.c_wchar * len(environment))(*environment)
    startup = StartupInfo()
    startup.cb = ctypes.sizeof(startup)
    startup.dwFlags = _STARTF_USESTDHANDLES

    api = _LineageApi()
    parent_authentication_id = api.process_authentication_id(_CURRENT_PROCESS)
    if parent_authentication_id == _SYSTEM_AUTHENTICATION_ID:
        raise NativeDeviceMapError(
            "LocalSystem uses the global DOS namespace and is not a safe lineage broker"
        )
    process = ProcessInformation()

    def close_created_handles(primary_error: BaseException | None = None) -> None:
        cleanup_errors: list[str] = []
        for attribute, label in (
            ("hThread", "inner-thread"),
            ("hProcess", "inner-process"),
        ):
            handle = getattr(process, attribute)
            if not handle:
                continue
            if kernel32.CloseHandle(handle):
                setattr(process, attribute, None)
            else:
                cleanup_errors.append(
                    f"CloseHandle({label}) failed with Win32 error {get_last_error()}"
                )
        if not cleanup_errors:
            return
        if primary_error is not None:
            for cleanup_error in cleanup_errors:
                primary_error.add_note(f"inner broker cleanup also failed: {cleanup_error}")
            return
        failure = NativeDeviceMapError("inner broker handle cleanup failed")
        for cleanup_error in cleanup_errors:
            failure.add_note(cleanup_error)
        raise failure

    def cleanup_created_process(primary_error: BaseException) -> None:
        cleanup_errors: list[str] = []
        if process.hProcess:
            if not kernel32.TerminateProcess(process.hProcess, 125):
                cleanup_errors.append(
                    f"TerminateProcess failed with Win32 error {get_last_error()}"
                )
            wait_result = kernel32.WaitForSingleObject(
                process.hProcess,
                int(_BROKER_DRAIN_TIMEOUT_SECONDS * 1000),
            )
            if wait_result != 0:
                cleanup_errors.append(
                    "inner process did not terminate during cleanup "
                    f"(wait result {wait_result}, Win32 error {get_last_error()})"
                )
        for cleanup_error in cleanup_errors:
            primary_error.add_note(f"inner broker cleanup also failed: {cleanup_error}")
        close_created_handles(primary_error)

    # LOGON_NETCREDENTIALS_ONLY preserves the caller's local identity while
    # creating a fresh LSA logon session. Windows does not validate these
    # network-only credentials. Make them unique and intentionally unusable so
    # this isolation primitive never depends on or exposes an account secret.
    credential_nonce = secrets.token_hex(16)
    credential_username = f"rbit-{credential_nonce[:10]}"
    credential_password = secrets.token_hex(32)
    try:
        create_error = 0
        with ExitStack() as standard_handles:
            (
                startup.hStdInput,
                startup.hStdOutput,
                startup.hStdError,
            ) = _duplicate_standard_handles(kernel32, api, standard_handles)
            created = advapi32.CreateProcessWithLogonW(
                credential_username,
                "REPROBIT",
                credential_password,
                _LOGON_NETCREDENTIALS_ONLY,
                sys.executable,
                command_buffer,
                _CREATE_SUSPENDED
                | _CREATE_NEW_PROCESS_GROUP
                | _CREATE_UNICODE_ENVIRONMENT,
                ctypes.cast(environment_buffer, pointer),
                str(Path(sys.executable).resolve(strict=True).parent),
                ctypes.byref(startup),
                ctypes.byref(process),
            )
            # ExitStack closes the temporary inherited handles below, and
            # CloseHandle is allowed to overwrite the calling thread's
            # last-error value. Capture the creation failure while it is still
            # authoritative.
            if not created:
                create_error = int(get_last_error())
        if not created:
            raise NativeDeviceMapError(
                "CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY) failed "
                f"with Win32 error {create_error}"
            )
        child_authentication_id = api.process_authentication_id(int(process.hProcess))
        if child_authentication_id == parent_authentication_id:
            raise NativeDeviceMapError(
                "LOGON_NETCREDENTIALS_ONLY did not create a fresh AuthenticationId"
            )
        if kernel32.ResumeThread(process.hThread) == 0xFFFFFFFF:
            raise NativeDeviceMapError(
                f"ResumeThread failed with Win32 error {get_last_error()}"
            )
        if kernel32.WaitForSingleObject(process.hProcess, 0xFFFFFFFF) != 0:
            raise NativeDeviceMapError(
                f"WaitForSingleObject failed with Win32 error {get_last_error()}"
            )
        exit_code = uint32()
        if not kernel32.GetExitCodeProcess(process.hProcess, ctypes.byref(exit_code)):
            raise NativeDeviceMapError(
                f"GetExitCodeProcess failed with Win32 error {get_last_error()}"
            )
        result = int(exit_code.value)
    except BaseException as caught_error:
        cleanup_created_process(caught_error)
        raise
    close_created_handles()
    return result


def _run_suspended_producer_tree(spec: CommandSpec) -> int:
    """Run one producer tree and return only after its nested Job is empty."""

    from reprobit.process import _WindowsJob

    job = _WindowsJob()
    producer: subprocess.Popen[bytes] | None = None
    assigned = False
    try:
        producer = subprocess.Popen(
            spec.argv,
            cwd=spec.cwd,
            env=spec.environment_mapping,
            stdin=subprocess.DEVNULL,
            creationflags=_CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP,
        )
        job.assign(producer)
        assigned = True
        job.resume(producer)
        exit_code = producer.wait()
        job.close_process_handle(producer)
        if exit_code == 0:
            # A successful leader may deliberately leave a descendant doing
            # final work. Keep the LUID mapping until the complete tree exits.
            if not job.wait_empty(None):
                raise NativeDeviceMapError(
                    "lineage producer Job Object unexpectedly timed out"
                )
        else:
            # A failed leader does not get to leave work behind.
            job.terminate_and_drain(_BROKER_DRAIN_TIMEOUT_SECONDS)
        return exit_code
    except BaseException as error:
        cleanup_errors: list[BaseException] = []
        if producer is not None:
            if assigned:
                try:
                    job.terminate()
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            else:
                try:
                    if producer.poll() is None:
                        producer.kill()
                    producer.wait(timeout=5)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if producer.poll() is None:
                try:
                    producer.wait(timeout=5)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if producer.returncode is not None:
                try:
                    job.close_process_handle(producer)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if assigned:
                try:
                    if not job.wait_empty(_BROKER_DRAIN_TIMEOUT_SECONDS):
                        raise NativeDeviceMapError(
                            "lineage producer Job Object did not drain"
                        )
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        for item in cleanup_errors:
            error.add_note(f"lineage producer cleanup also failed: {item}")
        raise
    finally:
        active_error = sys.exception()
        try:
            job.close()
        except BaseException as close_error:
            if active_error is None:
                raise
            active_error.add_note(f"lineage Job Object close also failed: {close_error}")


def _run_lineage_broker() -> int:
    """Define one LUID-local drive, run its producer tree, and remove it."""

    if os.name != "nt":
        raise NativeDeviceMapError("Windows lineage broker requires native Windows")
    document, spec = _read_lineage_plan()
    drive = document["drive"]
    target = document["target"]
    expected = document["controller_authentication_id"]
    if not isinstance(drive, str) or re.fullmatch(r"[A-Z]:", drive) is None:
        raise NativeDeviceMapError("Windows lineage drive is invalid")
    if (
        not isinstance(target, str)
        or "\0" in target
        or not target.startswith("\\Device\\")
    ):
        raise NativeDeviceMapError("Windows lineage target is invalid")
    if (
        not isinstance(expected, list)
        or len(expected) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) for value in expected)
    ):
        raise NativeDeviceMapError(
            "Windows lineage controller AuthenticationId is invalid"
        )

    api = _LineageApi()
    authentication_id = api.process_authentication_id(_CURRENT_PROCESS)
    if authentication_id == (expected[0], expected[1]):
        raise NativeDeviceMapError(
            "Windows lineage broker did not receive a fresh AuthenticationId"
        )

    api.define_local_drive(drive, target)
    result = _run_suspended_producer_tree(spec)
    # That call returns only after the nested producer Job is proved empty.
    # On failure, retain the mapping for any survivor; Windows destroys the
    # fresh-LUID namespace after its final token/process reference disappears.
    api.remove_local_drive(drive, target)
    return result


def _main(argv: list[str]) -> int:
    if argv == ["--lineage-broker"]:
        operation = _run_logon_broker
    elif argv == ["--lineage-inner"]:
        operation = _run_lineage_broker
    else:
        print("native_device_map is an internal ReproBit helper", file=sys.stderr)
        return 2
    try:
        return operation()
    except Exception as error:
        print(f"reprobit Windows lineage broker failed: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"cleanup note: {note}", file=sys.stderr)
        return 125


__all__ = [
    "NativeDeviceMapError",
    "NativeDeviceMapLease",
    "NativeDeviceMapProbe",
    "probe_native_device_map",
    "probe_native_device_map_execution",
]


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
