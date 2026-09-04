from __future__ import annotations

import os
import struct
import time
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import pytest

from reprobit import secure_paths_windows as windows
from reprobit.classic_repair_probe_cache import ProbeStoreGCResult, gc_probe_store
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileSnapshot, SecurePathError
from reprobit.secure_paths import atomic_publish_relative_if_current, reseal_relative_file

_VOLUME = 0x1234567889ABCDEF
_INDEX = 0xFEDCBA9876543210
_FILE_ID = ((0xABCDEF << 64) | _INDEX).to_bytes(16, "little")
_WRITE_NS = 1_780_000_000_123_456_700
_WRITE_TIME = windows._FILETIME_UNIX_EPOCH + _WRITE_NS // 100
_NATIVE = pytest.mark.skipif(os.name != "nt", reason="native Windows metadata and sharing")


def _metadata_api() -> windows._WindowsHandles:
    """Exercise the real metadata adapters with Windows-shaped API results."""

    api = object.__new__(windows._WindowsHandles)
    api.ctypes = SimpleNamespace(byref=lambda value: value, sizeof=lambda _value: 0)
    api.ByHandleFileInformation = SimpleNamespace
    api.FileIdInfo = SimpleNamespace
    api.FileBasicInfo = SimpleNamespace
    api.FileStandardInfo = SimpleNamespace

    def information(_handle: object, result: Any) -> bool:
        result.volume = _VOLUME & 0xFFFFFFFF
        result.index_high, result.index_low = _INDEX >> 32, _INDEX & 0xFFFFFFFF
        result.size_high, result.size_low = 0, 12
        result.write = SimpleNamespace(high=_WRITE_TIME >> 32, low=_WRITE_TIME & 0xFFFFFFFF)
        result.attributes = 0x20
        return True

    def information_ex(_handle: object, kind: int, result: Any, _size: int) -> bool:
        if kind == 18:
            result.volume = _VOLUME
            result.file_id = SimpleNamespace(identifier=_FILE_ID)
        elif kind == 0:
            result.creation = _WRITE_TIME - 20
            result.write = _WRITE_TIME
            result.change = _WRITE_TIME + 30
            result.attributes = 0x20
        else:
            assert kind == 1
            result.end_of_file, result.links, result.delete_pending = 12, 1, False
        return True

    api.kernel32 = SimpleNamespace(
        GetFileInformationByHandle=information,
        GetFileInformationByHandleEx=information_ex,
    )
    return api


@pytest.mark.parametrize("modern_stat", [False, True])
def test_windows_metadata_matches_each_supported_stat_dialect(
    monkeypatch: pytest.MonkeyPatch, modern_stat: bool, tmp_path: Path
) -> None:
    monkeypatch.setattr(windows, "_STAT_USES_FILE_ID_INFO", modern_stat)
    api = _metadata_api()
    basic = api.identity(1)
    strong = api.strong_identity(1)
    expected_id = (
        (_VOLUME, int.from_bytes(_FILE_ID, "little"))
        if modern_stat
        else (_VOLUME & 0xFFFFFFFF, _INDEX)
    )

    assert basic == (*expected_id, 12, _WRITE_NS, 0x20)
    assert api.file_identity(1) == (_VOLUME, int.from_bytes(_FILE_ID, "little"))
    assert strong[:5] == (_VOLUME, _FILE_ID, _WRITE_NS - 2000, _WRITE_NS, _WRITE_NS + 3000)
    snapshot = SecureFileSnapshot(
        tmp_path / "file",
        Digest.from_bytes(b"payload"),
        12,
        *expected_id,
        _WRITE_NS,
        ctime_ns=_WRITE_NS + 3000,
        windows_file_id=_FILE_ID,
        windows_attributes=0x20,
    )
    assert windows._matches_windows_snapshot(basic, strong, snapshot)
    assert windows._windows_snapshot_mismatch_fields(basic, strong, snapshot) == ()
    if modern_stat:
        truncated = (_VOLUME & 0xFFFFFFFF, _INDEX, *basic[2:])
        assert not windows._matches_windows_snapshot(truncated, strong, snapshot)
        assert "native-volume-consistency" in windows._windows_snapshot_mismatch_fields(
            truncated, strong, snapshot
        )


@pytest.mark.parametrize("changed_part", ["volume", "file-id"])
def test_windows_root_recheck_retains_full_id_on_legacy_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_part: str
) -> None:
    class Api:
        replacement = False

        def root(self, _path: Path) -> str:
            return "root"

        def identity(self, _handle: object) -> tuple[int, int, int, int, int]:
            return _VOLUME & 0xFFFFFFFF, _INDEX, 0, 0, 0x10

        def file_identity(self, _handle: object) -> tuple[int, int]:
            volume, inode = _VOLUME, int.from_bytes(_FILE_ID, "little")
            if self.replacement:
                if changed_part == "volume":
                    volume ^= 1 << 40
                else:
                    inode ^= 1 << 100
            return volume, inode

        def close(self, _handle: object) -> None:
            pass

    api = Api()
    monkeypatch.setattr(windows, "_WindowsHandles", lambda: api)
    with windows._HeldWindowsRoot(
        tmp_path, expected_identity=(_VOLUME & 0xFFFFFFFF, _INDEX)
    ) as held:
        api.replacement = True
        with pytest.raises(SecurePathError, match="root changed while held"):
            held.verify_root()


def test_windows_nested_edges_recheck_the_original_parent_and_full_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Api:
        replacement = False

        def root(self, _path: Path) -> str:
            return "root"

        def identity(self, handle: str) -> tuple[int, int, int, int, int]:
            return 7, {"root": 1, "seat": 2, "inner": 3}[handle], 0, 0, 0x10

        def file_identity(self, handle: str) -> tuple[int, int]:
            volume, inode = self.identity(handle)[:2]
            return volume, inode | (1 << 100 if self.replacement and handle == "inner" else 0)

        def open_relative(self, parent: str, name: str, **_kwargs: object) -> str:
            assert (parent, name) in {("root", "seat"), ("seat", "inner")}
            return name

        def close(self, _handle: object) -> None:
            pass

    api = Api()
    monkeypatch.setattr(windows, "_WindowsHandles", lambda: api)
    with windows._HeldWindowsRoot(tmp_path) as held:
        _handles, edges, leaf = held.parent_chain(
            PurePosixPath("seat/inner/file"),
            create=False,
            expected_directories={"seat": (7, 2), "seat/inner": (7, 3)},
        )
        assert leaf == "file"
        assert edges == [("root", "seat", (7, 2)), ("seat", "inner", (7, 3))]
        held.recheck(edges)
        api.replacement = True
        with pytest.raises(SecurePathError, match="component changed while held"):
            held.recheck(edges)


@pytest.mark.parametrize("entrypoint", ["root", "relative"])
def test_windows_new_handle_closes_when_full_identity_query_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entrypoint: str
) -> None:
    monkeypatch.setattr(windows, "_STAT_USES_FILE_ID_INFO", True)
    api = _metadata_api()
    closed: list[int] = []
    api.get_last_error = lambda: 123
    api.kernel32.GetFileInformationByHandleEx = lambda *_args: False
    api.kernel32.CreateFileW = lambda *_args: 42
    api.kernel32.CloseHandle = closed.append
    api.ctypes.c_void_p = lambda value: SimpleNamespace(value=value)
    api.ctypes.create_unicode_buffer = lambda name: name
    api.ctypes.cast = lambda *_args: None
    api.ctypes.pointer = lambda value: value
    api.wintypes = SimpleNamespace(HANDLE=lambda: SimpleNamespace(value=42), LPWSTR=object())
    api.UnicodeString = lambda *_args: object()
    api.ObjectAttributes = lambda *_args: object()
    api.IoStatusBlock = object
    api.ntdll = SimpleNamespace(NtCreateFile=lambda *_args: 0)

    with pytest.raises(SecurePathError, match="GetFileInformationByHandleEx failed"):
        if entrypoint == "root":
            api.root(tmp_path)
        else:
            api.open_relative(1, "file", directory=False, delete=True, deny_other_writes=True)
    assert closed == [42]


@_NATIVE
def test_windows_admits_stat_bound_nested_output_and_rejects_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seat = tmp_path / "seat"
    seat.mkdir()
    authority = {
        ".": (tmp_path.stat().st_dev, tmp_path.stat().st_ino),
        "seat": (seat.stat().st_dev, seat.stat().st_ino),
    }
    original_chain = windows._HeldWindowsRoot.parent_chain
    pinned = False

    def chain(held: Any, relative: object, **kwargs: Any) -> Any:
        nonlocal pinned
        result = original_chain(held, relative, **kwargs)
        # No child file is open yet: the ancestor lease itself must pin its name.
        assert tuple(seat.iterdir()) == ()
        with pytest.raises(OSError):
            seat.rename(tmp_path / "racing-seat")
        pinned = True
        return result

    monkeypatch.setattr(windows._HeldWindowsRoot, "parent_chain", chain)
    snapshot = atomic_publish_relative_if_current(
        tmp_path, "seat/file.bin", b"first", expected=None, expected_directories=authority
    )
    assert pinned
    metadata = snapshot.path.stat()
    assert (snapshot.device, snapshot.inode, snapshot.mtime_ns) == (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mtime_ns,
    )
    seat.rename(tmp_path / "old-seat")
    seat.mkdir()
    with pytest.raises(SecurePathError, match="directory changed before use"):
        atomic_publish_relative_if_current(
            tmp_path,
            "seat/second.bin",
            b"second",
            expected=None,
            expected_directories=authority,
        )
    assert not (seat / "second.bin").exists()


def _make_existing_directory_a_junction(api: Any, seat: Path, target: Path) -> None:
    """Apply a native reparse record without renaming the held directory."""

    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    display = str(target).encode("utf-16-le")
    payload = (
        struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(display))
        + substitute
        + b"\0\0"
        + display
        + b"\0\0"
    )
    record = struct.pack("<IHH", 0xA0000003, len(payload), 0) + payload
    ctypes, wintypes = api.ctypes, api.wintypes
    api.kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    api.kernel32.DeviceIoControl.restype = wintypes.BOOL
    handle = api.kernel32.CreateFileW(
        str(seat), 0x100, 0x1 | 0x2 | 0x4, None, 3, 0x00200000 | 0x02000000, None
    )
    assert handle != ctypes.c_void_p(-1).value, api.get_last_error()
    try:
        returned = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(record)
        assert api.kernel32.DeviceIoControl(
            handle, 0x000900A4, buffer, len(record), None, 0, ctypes.byref(returned), None
        ), api.get_last_error()
    finally:
        api.close(handle)


@_NATIVE
def test_windows_pinned_ancestor_reparse_change_cannot_publish_outside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, outside = tmp_path / "project", tmp_path / "outside"
    seat = project / "seat"
    seat.mkdir(parents=True)
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"untouched")
    expected = {"seat": (seat.stat().st_dev, seat.stat().st_ino)}
    original_chain = windows._HeldWindowsRoot.parent_chain
    original_open = windows._WindowsHandles.open_relative
    redirected = False
    outside_creations: list[str] = []

    def chain(held: Any, relative: object, **kwargs: Any) -> Any:
        nonlocal redirected
        result = original_chain(held, relative, **kwargs)
        if not redirected:
            _make_existing_directory_a_junction(held.api, seat, outside)
            redirected = True
        return result

    def open_relative(api: Any, parent: object, name: str, **kwargs: Any) -> object:
        received = original_open(api, parent, name, **kwargs)
        if redirected and kwargs.get("create"):
            outside_creations.extend(
                path.name for path in outside.iterdir() if path.name != "keep.txt"
            )
        return received

    monkeypatch.setattr(windows._HeldWindowsRoot, "parent_chain", chain)
    monkeypatch.setattr(windows._WindowsHandles, "open_relative", open_relative)
    with pytest.raises(SecurePathError):
        atomic_publish_relative_if_current(
            project,
            "seat/file.bin",
            b"candidate",
            expected=None,
            expected_directories=expected,
        )
    assert redirected
    assert outside_creations == []
    assert tuple(path.name for path in outside.iterdir()) == ("keep.txt",)
    assert (outside / "keep.txt").read_bytes() == b"untouched"


@_NATIVE
def test_windows_probe_gc_preserves_recent_files_without_hashing_them(tmp_path: Path) -> None:
    state = tmp_path / "state"
    directory = state / "repair-probes" / "v1" / "aa"
    directory.mkdir(parents=True)
    old, recent = directory / "old.bin", directory / "recent.bin"
    old.write_bytes(b"old")
    recent.write_bytes(b"recent")
    now = time.time_ns()
    old_time = now - 7_200_000_000_000
    os.utime(old, ns=(old_time, old_time))

    assert (
        windows.stat_relative_file(tmp_path, recent.relative_to(tmp_path).as_posix()).mtime_ns
        == recent.stat().st_mtime_ns
    )
    assert gc_probe_store(state, older_than_seconds=3600, now_ns=now) == ProbeStoreGCResult(1, 3, 1)
    assert not old.exists()
    assert recent.read_bytes() == b"recent"


@_NATIVE
def test_windows_guarded_replacement_retains_write_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = atomic_publish_relative_if_current(tmp_path, "outcome.json", b"first", expected=None)
    original_open = windows._WindowsHandles.open_relative
    verified = False

    def open_relative(api: Any, parent: object, name: str, **kwargs: Any) -> object:
        nonlocal verified
        if ".reprobit-guard-" in name and not kwargs.get("read_data", True):
            # The original handle must still deny another writer while the
            # compatible metadata-only verification handle is being opened.
            with pytest.raises(SecurePathError, match="0xc0000043"):
                original_open(api, parent, name, directory=False, write=True)
            verified = True
        return original_open(api, parent, name, **kwargs)

    monkeypatch.setattr(windows._WindowsHandles, "open_relative", open_relative)
    second = atomic_publish_relative_if_current(tmp_path, "outcome.json", b"second", expected=first)
    assert verified
    assert reseal_relative_file(tmp_path, "outcome.json", expected=second) == second
    assert second.path.read_bytes() == b"second"
    assert tuple(path.name for path in tmp_path.iterdir()) == ("outcome.json",)
