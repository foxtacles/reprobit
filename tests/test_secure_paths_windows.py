from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any

import pytest

from reprobit.secure_paths import (
    SecurePathError,
    atomic_publish_relative,
    atomic_publish_relative_if_current,
    read_relative_file,
    remove_published_relative,
    reseal_relative_file,
)

_FILE_ATTRIBUTE_HIDDEN = 0x0002
_FILE_ATTRIBUTE_ARCHIVE = 0x0020

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
