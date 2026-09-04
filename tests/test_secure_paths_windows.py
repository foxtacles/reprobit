from __future__ import annotations

import ctypes
import io
import os
from pathlib import Path
from typing import Any

import pytest

from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths import (
    atomic_copy_new_relative,
    atomic_publish_new_relative_from_stream,
    atomic_publish_relative,
    atomic_publish_relative_if_current,
    digest_relative_file,
    promote_relative_new,
    read_relative_file,
    remove_published_relative,
    reseal_relative_file,
)
from reprobit.secure_paths_windows import _HeldWindowsRoot, _WindowsHandles

_FILE_ATTRIBUTE_HIDDEN = 0x0002
_FILE_ATTRIBUTE_ARCHIVE = 0x0020
_FILE_ATTRIBUTE_READONLY = 0x0001

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="native Windows handle-relative implementation"
)


def _set_windows_attributes(path: Path, attributes: int) -> None:
    kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.SetFileAttributesW.restype = ctypes.c_int
    ctypes.set_last_error(0)
    if not kernel32.SetFileAttributesW(str(path), attributes):
        raise OSError(
            int(ctypes.get_last_error()),
            f"SetFileAttributesW failed for {path}",
        )


def _windows_attributes(path: Path) -> int:
    return int(path.stat().st_file_attributes)


def test_windows_file_rename_info_uses_native_union_layout() -> None:
    information = _WindowsHandles().FileRenameInfo

    assert ctypes.sizeof(information) == 24
    assert information.replace.offset == 0
    assert information.flags.offset == 0
    assert information.root.offset == 8
    assert information.name_length.offset == 16
    assert information.name.offset == 20


def test_windows_file_rename_uses_native_handle_relative_contract() -> None:
    api = _WindowsHandles()
    calls: list[tuple[int, int, int, int, bytes]] = []

    def set_information(
        _handle: object,
        _status_block: object,
        _information: Any,
        size: int,
        information_class: int,
    ) -> int:
        rename = ctypes.cast(
            _information,
            ctypes.POINTER(api.FileRenameInfo),
        ).contents
        name_offset = api.FileRenameInfo.name.offset
        calls.append(
            (
                information_class,
                size,
                int(rename.root),
                rename.name_length,
                ctypes.string_at(ctypes.addressof(_information), size)[
                    name_offset : name_offset + rename.name_length
                ],
            )
        )
        return 0

    def reject_win32_wrapper(*_args: object) -> int:
        pytest.fail("rename must not pass an NT directory handle through the Win32 wrapper")

    api.ntdll.NtSetInformationFile = set_information
    api.kernel32.SetFileInformationByHandle = reject_win32_wrapper
    api.rename(1, 2, "APP.EXE", replace=False)

    encoded_name = "APP.EXE".encode("utf-16-le")
    assert calls == [
        (
            api._FILE_RENAME_INFORMATION,
            ctypes.sizeof(api.FileRenameInfo) + len(encoded_name),
            2,
            len(encoded_name),
            encoded_name,
        )
    ]


def test_windows_file_rename_reports_native_status() -> None:
    api = _WindowsHandles()

    def invalid_parameter(*_args: object) -> int:
        return -1073741811  # STATUS_INVALID_PARAMETER (0xc000000d)

    api.ntdll.NtSetInformationFile = invalid_parameter

    with pytest.raises(SecurePathError, match="0xc000000d"):
        api.rename(1, 2, "APP.EXE", replace=False)


def test_windows_handle_relative_publication_replaces_and_reseals(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    first = atomic_publish_relative(root, "build/APP.EXE", b"first")
    second = atomic_publish_relative(root, "build/APP.EXE", b"second")

    assert first.digest != second.digest
    assert (root / "build/APP.EXE").read_bytes() == b"second"
    assert reseal_relative_file(root, "build/APP.EXE", expected=second) == second


def test_windows_stream_publication_and_promotion_return_settled_snapshots(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    staged = atomic_publish_new_relative_from_stream(
        root,
        "incoming/object",
        io.BytesIO(b"streamed candidate"),
        windows_attributes=_FILE_ATTRIBUTE_ARCHIVE,
    )

    assert reseal_relative_file(root, "incoming/object", expected=staged) == staged
    promoted = promote_relative_new(
        root,
        "incoming/object",
        "blobs/object",
        expected=digest_relative_file(root, "incoming/object"),
    )
    assert reseal_relative_file(root, "blobs/object", expected=promoted) == promoted


def test_windows_atomic_copy_binds_source_and_destination_roots(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    moved = tmp_path / "destination-original"
    source.mkdir()
    destination.mkdir()
    (source / "input.bin").write_bytes(b"input")
    source_metadata = source.stat(follow_symlinks=False)
    destination_metadata = destination.stat(follow_symlinks=False)

    published = atomic_copy_new_relative(
        source,
        "input.bin",
        destination,
        "output.bin",
        expected_source_directories={
            ".": (source_metadata.st_dev, source_metadata.st_ino),
        },
        expected_destination_directories={
            ".": (destination_metadata.st_dev, destination_metadata.st_ino),
        },
    )
    assert published.digest == digest_relative_file(destination, "output.bin").digest

    os.replace(destination, moved)
    destination.mkdir()
    with pytest.raises(SecurePathError, match="root changed before use"):
        atomic_copy_new_relative(
            source,
            "input.bin",
            destination,
            "second.bin",
            expected_source_directories={
                ".": (source_metadata.st_dev, source_metadata.st_ino),
            },
            expected_destination_directories={
                ".": (destination_metadata.st_dev, destination_metadata.st_ino),
            },
        )

    assert not (destination / "second.bin").exists()


def test_windows_expected_directory_identity_blocks_a_replacement_seat(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    seat = root / "seat"
    moved = root / "moved"
    (seat / "incoming").mkdir(parents=True)
    (seat / "incoming" / "object").write_bytes(b"staged")
    staged = digest_relative_file(root, "seat/incoming/object")
    metadata = seat.stat(follow_symlinks=False)
    expected_directories = {"seat": (metadata.st_dev, metadata.st_ino)}
    os.replace(seat, moved)
    seat.mkdir()
    (seat / "keep.txt").write_bytes(b"replacement")

    with pytest.raises(SecurePathError, match="directory changed"):
        atomic_publish_new_relative_from_stream(
            root,
            "seat/staged/new",
            io.BytesIO(b"new"),
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        promote_relative_new(
            root,
            "seat/incoming/object",
            "published/object",
            expected=staged,
            expected_directories=expected_directories,
        )

    assert tuple(path.name for path in seat.iterdir()) == ("keep.txt",)
    assert (moved / "incoming" / "object").read_bytes() == b"staged"
    assert not (root / "published").exists()


def test_windows_handle_relative_paths_reject_reparse_ancestor(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "input.h").write_bytes(b"outside")
    try:
        (root / "vendor").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"fixture host cannot create a directory reparse point: {exc}")

    with pytest.raises(SecurePathError, match="redirected"):
        read_relative_file(root, "vendor/input.h")


def test_windows_publication_rejects_nonregular_final_target(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "build/APP.EXE").mkdir(parents=True)

    with pytest.raises(SecurePathError):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")


def test_windows_publication_rollback_is_snapshot_bound(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = atomic_publish_relative(root, "report/result.json", b"report")
    assert remove_published_relative(root, "report/result.json", expected=snapshot)
    assert not (root / "report/result.json").exists()


def test_windows_conditional_publication_applies_attributes_and_rolls_back(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    relative = "build/APP.EXE"
    attributes = _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_ARCHIVE
    first = atomic_publish_relative(root, relative, b"first")

    replacement = atomic_publish_relative_if_current(
        root,
        relative,
        b"replacement",
        expected=first,
        windows_attributes=attributes,
    )

    target = root / relative
    assert target.read_bytes() == b"replacement"
    assert replacement.windows_attributes == attributes
    assert _windows_attributes(target) == attributes
    assert reseal_relative_file(root, relative, expected=replacement) == replacement
    assert remove_published_relative(root, relative, expected=replacement)
    assert not target.exists()


def test_windows_replace_preserves_a_target_created_after_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    relative = "build/APP.EXE"
    target = root / relative
    expected = atomic_publish_relative(root, relative, b"original")
    original_rename = _WindowsHandles.rename
    raced = False

    def create_peer_before_publish(
        api: _WindowsHandles,
        handle: Any,
        parent: Any,
        name: str,
        *,
        replace: bool,
    ) -> None:
        nonlocal raced
        if name == "APP.EXE" and not raced:
            target.write_bytes(b"peer")
            raced = True
        original_rename(api, handle, parent, name, replace=replace)

    monkeypatch.setattr(_WindowsHandles, "rename", create_peer_before_publish)

    with pytest.raises(SecurePathError, match="private guard"):
        atomic_publish_relative_if_current(
            root,
            relative,
            b"candidate",
            expected=expected,
        )

    assert raced
    assert target.read_bytes() == b"peer"
    guards = tuple(target.parent.glob(".APP.EXE.reprobit-guard-*"))
    assert len(guards) == 1
    assert guards[0].read_bytes() == b"original"


def test_windows_readonly_publication_can_be_removed_and_rolled_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    attributes = _FILE_ATTRIBUTE_READONLY | _FILE_ATTRIBUTE_ARCHIVE
    removable = atomic_publish_relative_if_current(
        root,
        "build/removable.exe",
        b"removable",
        expected=None,
        windows_attributes=attributes,
    )
    assert remove_published_relative(
        root,
        "build/removable.exe",
        expected=removable,
    )
    assert not (root / "build/removable.exe").exists()

    original_recheck = _HeldWindowsRoot.recheck

    def fail_after_publication(
        held: _HeldWindowsRoot,
        edges: list[tuple[Any, str, tuple[int, int]]],
    ) -> None:
        original_recheck(held, edges)
        raise SecurePathError("injected post-publication failure")

    monkeypatch.setattr(_HeldWindowsRoot, "recheck", fail_after_publication)
    with pytest.raises(SecurePathError, match="injected post-publication failure"):
        atomic_publish_relative_if_current(
            root,
            "build/rollback.exe",
            b"rollback",
            expected=None,
            windows_attributes=attributes,
        )
    assert not (root / "build/rollback.exe").exists()


def test_windows_attribute_only_preimage_change_blocks_replace_and_rollback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    relative = "build/APP.EXE"
    target = root / relative
    attributes = _FILE_ATTRIBUTE_HIDDEN | _FILE_ATTRIBUTE_ARCHIVE
    first = atomic_publish_relative(root, relative, b"first")
    expected = atomic_publish_relative_if_current(
        root,
        relative,
        b"published",
        expected=first,
        windows_attributes=attributes,
    )
    _set_windows_attributes(target, _FILE_ATTRIBUTE_ARCHIVE)

    with pytest.raises(SecurePathError, match="preimage changed"):
        atomic_publish_relative_if_current(
            root,
            relative,
            b"candidate",
            expected=expected,
            windows_attributes=attributes,
        )

    assert target.read_bytes() == b"published"
    assert _windows_attributes(target) == _FILE_ATTRIBUTE_ARCHIVE
    assert not remove_published_relative(root, relative, expected=expected)
    assert target.read_bytes() == b"published"
