from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import reprobit.exact_tree as exact_tree
import reprobit.secure_paths_windows as windows
from reprobit.secure_path_contracts import SecurePathError


@pytest.mark.parametrize(
    "interference", ["none", "wrong-source", "occupied", "wrong-destination", "root-changed"]
)
def test_windows_move_verifies_the_new_name_while_retaining_its_exclusive_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interference: str,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source_identity = (1, 20)
    parent_identity = (1, 10)
    parent_handle, source_handle, destination_handle = object(), object(), object()
    source_held = False
    opened: list[object] = []
    closed: list[object] = []
    boundaries: list[str] = []

    def open_relative(parent: object, name: str, **options: object) -> object | None:
        nonlocal source_held
        assert parent is parent_handle
        assert options["directory"] is True
        if name == source.name:
            assert options["delete"] is True
            assert options["deny_other_writes"] is True
            source_held = True
            opened.append(source_handle)
            return source_handle
        assert name == destination.name
        assert source_held
        if options.get("allow_missing"):
            if interference == "occupied":
                opened.append(destination_handle)
                return destination_handle
            return None
        # Windows checks sharing in both directions: the verifier must share
        # DELETE access already granted to the held rename handle.
        if options.get("deny_other_writes"):
            raise SecurePathError("sharing violation with the held rename handle")
        opened.append(destination_handle)
        return destination_handle

    def identity(handle: object) -> tuple[int, int]:
        assert source_held
        if (handle is source_handle and interference == "wrong-source") or (
            handle is destination_handle and interference == "wrong-destination"
        ):
            return (1, 99)
        return source_identity

    def rename(handle: object, parent: object, name: str, *, replace: bool) -> None:
        assert source_held
        assert handle is source_handle and parent is parent_handle
        assert name == destination.name and replace is False
        boundaries.append("rename")

    def flush_directory(handle: object) -> None:
        assert source_held and handle is parent_handle
        boundaries.append("flush")

    def verify_root() -> None:
        assert source_held
        boundaries.append("verify-root")
        if interference == "root-changed":
            raise SecurePathError("root changed")

    def close(handle: object) -> None:
        nonlocal source_held
        if handle is source_handle:
            source_held = False
        else:
            assert source_held
        closed.append(handle)

    @contextmanager
    def held_root(root: Path, *, expected_identity: tuple[int, int]) -> Iterator[object]:
        assert root == tmp_path and expected_identity == parent_identity
        yield SimpleNamespace(
            handle=parent_handle,
            api=SimpleNamespace(
                open_relative=open_relative,
                identity=identity,
                rename=rename,
                flush_directory=flush_directory,
                close=close,
            ),
            verify_root=verify_root,
        )

    monkeypatch.setattr(exact_tree, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows, "_HeldWindowsRoot", held_root)
    if interference == "none":
        exact_tree.move_directory_in_exact_parent(
            source, source_identity, destination, parent_identity
        )
    else:
        with pytest.raises(exact_tree.ExactTreeError):
            exact_tree.move_directory_in_exact_parent(
                source, source_identity, destination, parent_identity
            )

    assert not source_held
    assert closed == list(reversed(opened))
    if interference in {"wrong-source", "occupied"}:
        assert boundaries == []
    elif interference == "wrong-destination":
        assert boundaries == ["rename"]
    else:
        assert boundaries == ["rename", "flush", "verify-root"]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows directory handles")
def test_native_windows_move_keeps_the_destination_protected_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "owned.bin").write_bytes(b"owned")
    destination = tmp_path / "destination"
    source_stat = source.stat()
    parent_stat = tmp_path.stat()
    source_identity = (source_stat.st_dev, source_stat.st_ino)
    real_open = windows._WindowsHandles.open_relative
    checked_protection = False

    def open_relative(
        api: windows._WindowsHandles, parent: object, name: str, **options: Any
    ) -> object | None:
        nonlocal checked_protection
        result = real_open(api, parent, name, **options)
        if name == destination.name and not options.get("allow_missing"):
            try:
                try:
                    unexpected = real_open(api, parent, name, directory=True, delete=True)
                except SecurePathError:
                    pass
                else:
                    api.close(unexpected)
                    pytest.fail("the retained move handle must block independent deletion")
                checked_protection = True
            except BaseException:
                api.close(result)
                raise
        return result

    monkeypatch.setattr(windows._WindowsHandles, "open_relative", open_relative)
    exact_tree.move_directory_in_exact_parent(
        source,
        source_identity,
        destination,
        (parent_stat.st_dev, parent_stat.st_ino),
    )

    assert checked_protection
    assert not source.exists()
    destination_stat = destination.stat()
    assert (destination_stat.st_dev, destination_stat.st_ino) == source_identity
    assert (destination / "owned.bin").read_bytes() == b"owned"
