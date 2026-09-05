from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import pytest

from reprobit import secure_paths_windows as windows
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileSnapshot, SecurePathError
from reprobit.secure_paths import digest_relative_file, promote_relative_new, reseal_relative_file


class _PromotionApi:
    """Model an NTFS rename that tunnels the destination's creation time."""

    def __init__(self, phase: str, changed_field: int | None) -> None:
        self.phase = phase
        self.changed_field = changed_field
        self.strong: tuple[Any, ...] = (
            7,
            (11).to_bytes(16, "little"),
            100,
            200,
            300,
            7,
            1,
            False,
            32,
        )
        self.closed: list[str] = []
        self.renamed = False
        self.rechecks = 0
        self.flushed = False

    def mutate(self) -> None:
        fields = list(self.strong)
        assert self.changed_field is not None
        old = fields[self.changed_field]
        fields[self.changed_field] = (
            (12).to_bytes(16, "little")
            if self.changed_field == 1
            else not old
            if self.changed_field == 7
            else old + 1
        )
        self.strong = tuple(fields)

    def identity(self, _handle: str) -> tuple[int, int, int, int, int]:
        return (
            self.strong[0],
            int.from_bytes(self.strong[1], "little"),
            self.strong[5],
            self.strong[3],
            self.strong[8],
        )

    def strong_identity(self, _handle: str) -> tuple[Any, ...]:
        return self.strong

    def open_relative(self, _parent: str, name: str, **kwargs: Any) -> str | None:
        if name == "source":
            assert kwargs["delete"] and kwargs["deny_other_writes"]
            return "source"
        assert name == "target"
        if kwargs.get("allow_missing"):
            return None
        assert self.renamed
        assert "source" not in self.closed
        assert not kwargs.get("deny_other_writes", False)
        assert kwargs["read_data"] is False
        if self.phase == "verify":
            self.mutate()
        return "named"

    def rename(self, source: str, _parent: str, name: str, *, replace: bool) -> None:
        assert source == "source" and name == "target" and not replace
        self.renamed = True
        fields = list(self.strong)
        fields[2], fields[4] = 50, 301
        self.strong = tuple(fields)
        if self.phase == "rename":
            self.mutate()

    def close(self, handle: str) -> None:
        if handle == "named" and self.phase == "finalize":
            self.mutate()
        self.closed.append(handle)

    def parent_chain(self, relative: PurePosixPath, **_kwargs: object) -> tuple[Any, ...]:
        return ["root"], [], relative.name

    def recheck(self, _edges: object) -> None:
        assert "source" not in self.closed
        self.rechecks += 1

    def flush_directory(self, _handle: str) -> None:
        assert "source" not in self.closed
        self.flushed = True


def _promotion_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str = "none",
    changed_field: int | None = None,
) -> tuple[_PromotionApi, SecureFileSnapshot]:
    api = _PromotionApi(phase, changed_field)
    expected = SecureFileSnapshot(
        tmp_path / "source",
        Digest.from_bytes(b"payload"),
        7,
        7,
        11,
        200,
        ctime_ns=300,
        windows_file_id=api.strong[1],
        windows_attributes=32,
    )
    held = SimpleNamespace(
        api=api, path=tmp_path, parent_chain=api.parent_chain, recheck=api.recheck
    )
    monkeypatch.setattr(windows, "_STAT_USES_FILE_ID_INFO", True)
    monkeypatch.setattr(windows, "_hold_root", lambda *_args: nullcontext(held))
    if phase == "before":
        api.mutate()
    return api, expected


def test_promotion_accepts_tunneling_only_across_its_held_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, expected = _promotion_fixture(tmp_path, monkeypatch)

    result = windows.promote_relative_new(tmp_path, "source", "target", expected=expected)

    assert result.path == tmp_path / "target"
    assert result.digest == expected.digest
    assert result.windows_file_id == expected.windows_file_id
    assert result.ctime_ns == 301
    assert api.strong[2] == 50
    assert api.rechecks == 2 and api.flushed
    assert api.closed == ["named", "source"]


@pytest.mark.parametrize("changed_field", [0, 1, 3, 4, 5, 7, 8])
def test_promotion_rejects_stale_source_before_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_field: int
) -> None:
    api, expected = _promotion_fixture(tmp_path, monkeypatch, "before", changed_field)

    with pytest.raises(SecurePathError, match="promotion source changed"):
        windows.promote_relative_new(tmp_path, "source", "target", expected=expected)

    assert not api.renamed
    assert api.closed == ["source"]


@pytest.mark.parametrize("changed_field", [0, 1, 3, 5, 6, 7, 8])
def test_promotion_rejects_non_timestamp_changes_during_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_field: int
) -> None:
    api, expected = _promotion_fixture(tmp_path, monkeypatch, "rename", changed_field)

    with pytest.raises(SecurePathError, match="promotion source changed"):
        windows.promote_relative_new(tmp_path, "source", "target", expected=expected)

    assert api.renamed
    assert api.closed == ["source"]


@pytest.mark.parametrize("phase", ["verify", "finalize"])
@pytest.mark.parametrize("changed_field", range(9))
def test_promotion_rejects_all_metadata_changes_after_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, changed_field: int
) -> None:
    api, expected = _promotion_fixture(tmp_path, monkeypatch, phase, changed_field)

    with pytest.raises(SecurePathError, match="promotion target changed"):
        windows.promote_relative_new(tmp_path, "source", "target", expected=expected)

    assert api.renamed
    assert api.closed == ["named", "source"]


@pytest.mark.skipif(os.name != "nt", reason="native Windows file-system tunneling")
def test_native_promotion_into_a_vacated_name_returns_a_settled_snapshot(tmp_path: Path) -> None:
    authority = tmp_path / "authority.json"
    authority.write_bytes(b"previous")
    # Give the old filename a distinct creation time without relying on clock
    # resolution or sleeping.  NTFS can tunnel this value to the incoming file.
    with windows._HeldWindowsRoot(tmp_path) as held:
        handle = held.api.open_relative(held.handle, authority.name, directory=False, delete=True)
        assert handle is not None
        try:
            info = held.api.FileBasicInfo()
            info.creation = windows._FILETIME_UNIX_EPOCH + 946_684_800 * 10_000_000
            assert held.api.kernel32.SetFileInformationByHandle(
                handle, 0, held.api.ctypes.byref(info), held.api.ctypes.sizeof(info)
            )
        finally:
            held.api.close(handle)

    (tmp_path / "staged.json").write_bytes(b"replacement")
    staged = digest_relative_file(tmp_path, "staged.json")
    previous = digest_relative_file(tmp_path, authority.name)
    promote_relative_new(tmp_path, authority.name, "backup.json", expected=previous)

    published = promote_relative_new(tmp_path, "staged.json", authority.name, expected=staged)

    assert published.windows_file_id == staged.windows_file_id
    assert published.digest == staged.digest
    assert published.mtime_ns == staged.mtime_ns
    assert published.windows_attributes == staged.windows_attributes
    assert reseal_relative_file(tmp_path, authority.name, expected=published) == published
    assert authority.read_bytes() == b"replacement"
    assert (tmp_path / "backup.json").read_bytes() == b"previous"
    assert not (tmp_path / "staged.json").exists()
