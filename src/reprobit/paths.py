"""Compiler-visible path contracts and host-to-logical path transport.

Classic compilers may encode path spelling and length into their output.  A
``LogicalPathSkeleton`` therefore treats DOS paths as build inputs instead of
as presentation details.  Physical host paths are deliberately kept out of
the compiler receipt.
"""

from __future__ import annotations

import ntpath
import os
import re
import shutil
import stat
import struct
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PureWindowsPath


class PathContractError(ValueError):
    """A logical path or skeleton violates the declared path contract."""


_DOS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
    | {f"com{index}" for index in "¹²³"}
    | {f"lpt{index}" for index in "¹²³"}
)
_DOS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
_DOS_DRIVE_LETTER = re.compile(r"[A-Za-z]", re.ASCII)
_LOGICAL_SEAT_NAME = re.compile(r"[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*", re.ASCII)


@lru_cache(maxsize=65_536)
def normalize_logical_path(value: str | PureWindowsPath) -> str:
    """Return one canonical absolute DOS path without changing its length.

    Forward slashes, relative paths, device paths, UNC paths, and parent
    traversal are rejected.  The drive letter is upper-cased; all other
    components retain their spelling and case.
    """

    raw = str(value)
    if not raw or "\0" in raw:
        raise PathContractError("logical path is empty or contains NUL")
    if "/" in raw:
        raise PathContractError("logical paths must use DOS backslashes")
    drive, tail = ntpath.splitdrive(raw)
    if len(drive) != 2 or drive[1] != ":" or _DOS_DRIVE_LETTER.fullmatch(drive[0]) is None:
        raise PathContractError(f"logical path is not drive-absolute: {raw!r}")
    if not tail.startswith("\\") or tail.startswith("\\\\"):
        raise PathContractError(f"logical path is not drive-absolute: {raw!r}")
    components = tail.split("\\")[1:]
    # The root itself is the sole useful empty-component exception.
    if any(part in {"", ".", ".."} for part in components) and components != [""]:
        raise PathContractError(f"logical path is not canonical: {raw!r}")
    for component in components:
        if not component:
            continue
        basename = component.split(".", 1)[0].casefold()
        if (
            component.endswith((" ", "."))
            or any(
                character in _DOS_FORBIDDEN_COMPONENT_CHARACTERS or ord(character) < 32
                for character in component
            )
            or basename in _DOS_RESERVED_NAMES
        ):
            raise PathContractError(f"logical path has an unsafe DOS component: {raw!r}")
    canonical = drive[0].upper() + ":" + tail
    if ntpath.normpath(canonical) != canonical:
        raise PathContractError(f"logical path is not canonical: {raw!r}")
    return canonical


def logical_relative_to(path: str, root: str) -> PureWindowsPath:
    """Return ``path`` relative to ``root`` using DOS case semantics."""

    path_value = normalize_logical_path(path)
    root_value = normalize_logical_path(root)
    try:
        common = ntpath.commonpath((path_value, root_value))
    except ValueError as error:
        raise PathContractError(f"{path_value!r} is outside {root_value!r}") from error
    if ntpath.normcase(common) != ntpath.normcase(root_value):
        raise PathContractError(f"{path_value!r} is outside {root_value!r}")
    relative = ntpath.relpath(path_value, root_value)
    return PureWindowsPath("." if relative == "." else relative)


def _absolute_host_path(path: Path | str) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute():
        raise PathContractError(f"physical path is not absolute: {value}")
    return value.resolve(strict=False)


def _host_relative_to(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError as error:
        raise PathContractError(f"physical path {path} is outside seat {root}") from error


@dataclass(frozen=True, slots=True)
class LogicalSeat:
    """One physical tree mounted at one compiler-visible DOS path."""

    name: str
    physical_root: Path
    logical_root: str
    writable: bool = False

    def __post_init__(self) -> None:
        if _LOGICAL_SEAT_NAME.fullmatch(self.name) is None:
            raise PathContractError(f"unsafe logical seat name: {self.name!r}")
        object.__setattr__(self, "physical_root", _absolute_host_path(self.physical_root))
        object.__setattr__(self, "logical_root", normalize_logical_path(self.logical_root))


@dataclass(frozen=True, slots=True)
class MaterializedSkeleton:
    """A run-private host tree ready to be mapped as a DOS drive."""

    root: Path
    drive_letter: str
    created_entries: tuple[Path, ...]
    physical_targets: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise PathContractError("materialized skeleton root must be absolute")
        letter = self.drive_letter.upper().rstrip(":")
        if _DOS_DRIVE_LETTER.fullmatch(letter) is None:
            raise PathContractError("materialized skeleton drive letter is invalid")
        object.__setattr__(self, "drive_letter", letter)
        for entry in self.created_entries:
            try:
                entry.relative_to(self.root)
            except ValueError as error:
                raise PathContractError(
                    f"materialized entry is outside its skeleton: {entry}"
                ) from error
        if len(self.physical_targets) not in {0, len(self.created_entries)}:
            raise PathContractError("materialized target records are incomplete")

    @property
    def logical_root(self) -> str:
        return f"{self.drive_letter}:\\"


def _create_windows_junction(destination: Path, target: Path) -> None:
    """Create a directory mount-point reparse record without elevation."""

    if os.name != "nt":
        raise PathContractError("directory junctions require Windows")
    import ctypes
    from ctypes import wintypes

    target_text = str(target.resolve(strict=True))
    drive, _ = ntpath.splitdrive(target_text)
    if not drive:
        raise PathContractError(f"junction target is not drive-absolute: {target}")
    substitute = "\\??\\" + target_text
    print_name = target_text
    substitute_bytes = substitute.encode("utf-16-le")
    print_bytes = print_name.encode("utf-16-le")
    path_buffer = substitute_bytes + b"\0\0" + print_bytes + b"\0\0"
    payload = (
        struct.pack(
            "<HHHH",
            0,
            len(substitute_bytes),
            len(substitute_bytes) + 2,
            len(print_bytes),
        )
        + path_buffer
    )
    reparse_data = struct.pack("<IHH", 0xA0000003, len(payload), 0) + payload

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise PathContractError("ctypes WinDLL is unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    destination.mkdir()
    handle = kernel32.CreateFileW(
        str(destination),
        0x40000000,
        0,
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        destination.rmdir()
        get_last_error = getattr(ctypes, "get_last_error", lambda: 0)
        raise PathContractError(f"cannot open junction directory: {get_last_error()}")
    try:
        returned = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(reparse_data)
        if not kernel32.DeviceIoControl(
            handle,
            0x000900A4,
            buffer,
            len(reparse_data),
            None,
            0,
            ctypes.byref(returned),
            None,
        ):
            get_last_error = getattr(ctypes, "get_last_error", lambda: 0)
            raise PathContractError(f"cannot install junction record: {get_last_error()}")
    except BaseException:
        kernel32.CloseHandle(handle)
        destination.rmdir()
        raise
    kernel32.CloseHandle(handle)


def _remove_materialized_entry(entry: Path) -> None:
    if os.name != "nt":
        if not entry.is_symlink():
            raise PathContractError(f"owned skeleton entry changed type: {entry}")
        entry.unlink()
        return
    metadata = entry.lstat()
    mount_point_tag = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
    if getattr(metadata, "st_reparse_tag", None) != mount_point_tag:
        raise PathContractError(f"owned skeleton entry is no longer a junction: {entry}")
    entry.rmdir()


def _remove_empty_skeleton_parents(root: Path, entries: Sequence[Path]) -> None:
    parents = {
        parent
        for entry in entries
        for parent in entry.parents
        if parent != root and root in parent.parents
    }
    for parent in sorted(parents, key=lambda value: len(value.parts), reverse=True):
        with suppress(OSError):
            parent.rmdir()


class LogicalPathSkeleton:
    """A collection of non-overlapping physical/logical path seats."""

    def __init__(self, seats: Sequence[LogicalSeat]) -> None:
        if not seats:
            raise PathContractError("a logical path skeleton needs at least one seat")
        self._seats = tuple(seats)
        names = [seat.name for seat in self._seats]
        if len(set(names)) != len(names):
            raise PathContractError("logical seat names must be unique")
        drives = {seat.logical_root[0].upper() for seat in self._seats}
        if len(drives) != 1:
            raise PathContractError("all logical seats must share one drive")
        self._drive_letter = drives.pop()
        self._validate_non_overlapping()

    @property
    def seats(self) -> tuple[LogicalSeat, ...]:
        return self._seats

    @property
    def drive_letter(self) -> str:
        return self._drive_letter

    def _validate_non_overlapping(self) -> None:
        for index, left in enumerate(self._seats):
            for right in self._seats[index + 1 :]:
                left_logical = left.logical_root.casefold().rstrip("\\")
                right_logical = right.logical_root.casefold().rstrip("\\")
                if (
                    left_logical == right_logical
                    or left_logical.startswith(right_logical + "\\")
                    or right_logical.startswith(left_logical + "\\")
                ):
                    raise PathContractError(
                        f"logical seats overlap: {left.logical_root} and {right.logical_root}"
                    )
                left_physical = os.path.normcase(str(left.physical_root))
                right_physical = os.path.normcase(str(right.physical_root))
                separator = os.sep
                if (
                    left_physical == right_physical
                    or left_physical.startswith(right_physical + separator)
                    or right_physical.startswith(left_physical + separator)
                ):
                    raise PathContractError(
                        f"physical seats overlap: {left.physical_root} and {right.physical_root}"
                    )

    def to_logical(self, physical_path: Path | str) -> str:
        """Translate a physical path through the most specific matching seat."""

        path = _absolute_host_path(physical_path)
        matches: list[tuple[int, LogicalSeat, Path]] = []
        for seat in self._seats:
            try:
                relative = _host_relative_to(path, seat.physical_root)
            except PathContractError:
                continue
            matches.append((len(seat.physical_root.parts), seat, relative))
        if not matches:
            raise PathContractError(f"physical path has no logical seat: {path}")
        _, seat, relative = max(matches, key=lambda item: item[0])
        if relative == Path("."):
            return seat.logical_root
        suffix = "\\".join(relative.parts)
        return normalize_logical_path(seat.logical_root.rstrip("\\") + "\\" + suffix)

    def to_physical(self, logical_path: str | PureWindowsPath) -> Path:
        """Translate a logical path back to its declared physical tree."""

        logical = normalize_logical_path(logical_path)
        matches: list[tuple[int, LogicalSeat, PureWindowsPath]] = []
        for seat in self._seats:
            try:
                relative = logical_relative_to(logical, seat.logical_root)
            except PathContractError:
                continue
            matches.append((len(PureWindowsPath(seat.logical_root).parts), seat, relative))
        if not matches:
            raise PathContractError(f"logical path has no physical seat: {logical}")
        _, seat, relative = max(matches, key=lambda item: item[0])
        if str(relative) == ".":
            return seat.physical_root
        target = seat.physical_root.joinpath(*relative.parts).resolve(strict=False)
        _host_relative_to(target, seat.physical_root)
        return target

    def verify_round_trip(self) -> None:
        """Fail closed unless every seat root round-trips exactly."""

        for seat in self._seats:
            if self.to_logical(seat.physical_root) != seat.logical_root:
                raise PathContractError(f"logical seat does not round-trip: {seat.name}")
            if self.to_physical(seat.logical_root) != seat.physical_root:
                raise PathContractError(f"physical seat does not round-trip: {seat.name}")

    def materialize(self, staging_root: Path | str) -> MaterializedSkeleton:
        """Create a run-private skeleton whose leaves are physical-seat links.

        The caller owns ``staging_root``.  Existing entries are refused rather
        than reused, preventing a stale or attacker-controlled mapping from
        becoming part of a proof run.
        """

        staging = _absolute_host_path(staging_root)
        if staging.exists() and any(staging.iterdir()):
            raise PathContractError(f"staging root is not empty: {staging}")
        staging.mkdir(parents=True, exist_ok=True)
        created: list[Path] = []
        targets: list[Path] = []
        try:
            for seat in sorted(self._seats, key=lambda item: item.logical_root.casefold()):
                relative = PureWindowsPath(seat.logical_root).parts[1:]
                if not relative:
                    raise PathContractError(
                        "a drive-root seat cannot be combined with a staging skeleton"
                    )
                destination = staging.joinpath(*relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if os.path.lexists(destination):
                    raise PathContractError(f"logical skeleton entry already exists: {destination}")
                try:
                    if os.name == "nt":
                        _create_windows_junction(destination, seat.physical_root)
                    else:
                        destination.symlink_to(seat.physical_root, target_is_directory=True)
                except OSError as error:
                    raise PathContractError(
                        f"cannot create logical skeleton entry {destination}"
                    ) from error
                created.append(destination)
                targets.append(seat.physical_root)
        except BaseException:
            for entry in reversed(created):
                _remove_materialized_entry(entry)
            _remove_empty_skeleton_parents(staging, created)
            raise
        return MaterializedSkeleton(
            staging,
            self.drive_letter,
            tuple(created),
            tuple(targets),
        )

    @contextmanager
    def temporary_materialization(self, parent: Path | str) -> Iterator[MaterializedSkeleton]:
        """Materialize beneath ``parent`` and remove only the owned tree."""

        parent_path = _absolute_host_path(parent)
        parent_path.mkdir(parents=True, exist_ok=True)
        import tempfile

        temporary = Path(tempfile.mkdtemp(prefix="path-skeleton-", dir=parent_path))
        materialized: MaterializedSkeleton | None = None
        try:
            materialized = self.materialize(temporary)
            yield materialized
        finally:
            if materialized is not None:
                for entry in reversed(materialized.created_entries):
                    _remove_materialized_entry(entry)
                _remove_empty_skeleton_parents(temporary, materialized.created_entries)
            shutil.rmtree(temporary)


__all__ = [
    "LogicalPathSkeleton",
    "LogicalSeat",
    "MaterializedSkeleton",
    "PathContractError",
    "logical_relative_to",
    "normalize_logical_path",
]
