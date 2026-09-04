from __future__ import annotations

import os
from pathlib import Path

import pytest

import reprobit.exact_tree as exact_tree
from reprobit.exact_tree import (
    ExactTreeError,
    create_directory_in_exact_parent,
    move_directory_in_exact_parent,
    remove_exact_directory_tree,
)
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths_windows import _WindowsHandles


def _identity(directory: Path) -> tuple[int, int]:
    metadata = directory.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
@pytest.mark.parametrize("swap_after_cleanup", (False, True))
def test_exact_tree_preserves_a_replacement_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_after_cleanup: bool,
) -> None:
    tree = tmp_path / "quarantine"
    tree.mkdir()
    (tree / "owned.bin").write_bytes(b"owned")
    expected = _identity(tree)
    moved = tmp_path / "moved-owned-tree"
    real_cleanup = exact_tree._remove_posix_contents
    swapped = False

    def swap_seat(directory: int) -> None:
        nonlocal swapped
        if not swap_after_cleanup:
            tree.rename(moved)
            tree.mkdir()
            (tree / "valuable.bin").write_bytes(b"keep me")
            swapped = True
        real_cleanup(directory)
        if swap_after_cleanup:
            tree.rename(moved)
            tree.mkdir()
            (tree / "valuable.bin").write_bytes(b"keep me")
            swapped = True

    monkeypatch.setattr(exact_tree, "_remove_posix_contents", swap_seat)

    with pytest.raises(ExactTreeError, match="changed during cleanup"):
        remove_exact_directory_tree(tree, expected)

    assert swapped
    assert (tree / "valuable.bin").read_bytes() == b"keep me"
    assert moved.is_dir()
    assert not tuple(moved.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
def test_exact_tree_restores_a_leaf_replaced_before_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "quarantine"
    tree.mkdir()
    leaf = tree / "owned.bin"
    leaf.write_bytes(b"owned")
    expected = _identity(tree)
    original = tree / "original-owned.bin"
    real_rename = exact_tree.rename_noreplace_at
    swapped = False

    def swap_leaf(parent: int, source: str, destination: str) -> None:
        nonlocal swapped
        if source == leaf.name and not swapped:
            swapped = True
            os.rename(
                source,
                original.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            descriptor = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent,
            )
            try:
                os.write(descriptor, b"keep me")
            finally:
                os.close(descriptor)
        real_rename(parent, source, destination)

    monkeypatch.setattr(exact_tree, "rename_noreplace_at", swap_leaf)

    with pytest.raises(ExactTreeError, match="private directory member changed"):
        remove_exact_directory_tree(tree, expected)

    assert swapped
    assert leaf.read_bytes() == b"keep me"
    assert original.read_bytes() == b"owned"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
def test_exact_tree_restores_a_root_replaced_during_final_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "quarantine"
    tree.mkdir()
    expected = _identity(tree)
    original = tmp_path / "original-quarantine"
    real_rename = exact_tree.rename_noreplace_at
    swapped = False

    def swap_root(parent: int, source: str, destination: str) -> None:
        nonlocal swapped
        if source == tree.name and not swapped:
            swapped = True
            tree.rename(original)
            tree.mkdir()
        real_rename(parent, source, destination)

    monkeypatch.setattr(exact_tree, "rename_noreplace_at", swap_root)

    with pytest.raises(ExactTreeError, match="private directory changed during cleanup"):
        remove_exact_directory_tree(tree, expected)

    assert swapped
    assert tree.is_dir()
    assert not tuple(tree.iterdir())
    assert original.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
def test_exact_directory_creation_preserves_a_detected_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    expected_parent = _identity(parent)
    candidate = parent / "candidate"
    original = parent / "original-candidate"
    real_open = exact_tree._open_posix_directory_at
    swapped = False

    def swap_before_child_open(dir_fd: int, name: str) -> int:
        nonlocal swapped
        if name == candidate.name and not swapped:
            swapped = True
            os.rename(
                candidate.name,
                original.name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            os.mkdir(candidate.name, dir_fd=dir_fd)
        return real_open(dir_fd, name)

    monkeypatch.setattr(exact_tree, "_open_posix_directory_at", swap_before_child_open)

    with pytest.raises(ExactTreeError, match="changed during creation"):
        create_directory_in_exact_parent(candidate, expected_parent)

    assert swapped
    assert candidate.is_dir()
    assert original.is_dir()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
def test_exact_directory_move_does_not_clobber_a_raced_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    source = parent / "source"
    source.mkdir()
    expected_source = _identity(source)
    expected_parent = _identity(parent)
    destination = parent / "destination"
    real_rename = exact_tree.rename_noreplace_at
    competitor: tuple[int, int] | None = None

    def compete(parent_fd: int, source_name: str, destination_name: str) -> None:
        nonlocal competitor
        if source_name == source.name and competitor is None:
            destination.mkdir()
            competitor = _identity(destination)
        real_rename(parent_fd, source_name, destination_name)

    monkeypatch.setattr(exact_tree, "rename_noreplace_at", compete)

    with pytest.raises(ExactTreeError, match="destination appeared"):
        move_directory_in_exact_parent(
            source,
            expected_source,
            destination,
            expected_parent,
        )

    assert source.is_dir()
    assert competitor is not None
    assert _identity(destination) == competitor


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX held-directory operations")
def test_exact_directory_mutations_sync_the_held_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    expected_parent = _identity(parent)
    staging = parent / "staging"
    destination = parent / "destination"
    synced: list[tuple[int, int]] = []

    def record_sync(directory: int) -> None:
        metadata = os.fstat(directory)
        synced.append((metadata.st_dev, metadata.st_ino))

    monkeypatch.setattr(exact_tree, "_sync_posix_directory", record_sync)

    staging_identity = create_directory_in_exact_parent(staging, expected_parent)
    assert synced[-1] == expected_parent

    synced.clear()
    move_directory_in_exact_parent(
        staging,
        staging_identity,
        destination,
        expected_parent,
    )
    assert synced == [expected_parent]

    synced.clear()
    remove_exact_directory_tree(destination, staging_identity)
    assert synced[-1] == expected_parent


def test_windows_exact_tree_deletes_a_redirect_through_its_held_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    redirect = tree / "redirect"
    redirect.write_bytes(b"stand-in directory entry")
    api = _WindowsHandles.__new__(_WindowsHandles)
    held_redirect = object()
    opens: list[dict[str, object]] = []

    def open_relative(_parent: object, name: str, **options: object) -> object:
        assert name == redirect.name
        opens.append(options)
        if options.get("allow_redirect") is True:
            return held_redirect
        raise SecurePathError("fixture redirect")

    def delete_on_close(handle: object) -> None:
        assert handle is held_redirect
        redirect.unlink()

    monkeypatch.setattr(api, "open_relative", open_relative)
    monkeypatch.setattr(api, "delete_on_close", delete_on_close)
    monkeypatch.setattr(api, "close", lambda _handle: None)

    exact_tree._remove_windows_contents(api, object(), tree)

    assert not redirect.exists()
    assert opens[-1]["allow_redirect"] is True
    assert opens[-1]["delete"] is True
    assert opens[-1]["deny_other_writes"] is True


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows directory handles")
def test_windows_exact_tree_holds_its_directory_seat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "quarantine"
    tree.mkdir()
    (tree / "owned.bin").write_bytes(b"owned")
    expected = _identity(tree)
    moved = tmp_path / "moved-owned-tree"
    real_cleanup = exact_tree._remove_windows_contents
    replacement_was_blocked = False

    def attempt_swap(api: object, handle: object, path: Path) -> None:
        nonlocal replacement_was_blocked
        with pytest.raises(OSError):
            tree.rename(moved)
        replacement_was_blocked = True
        real_cleanup(api, handle, path)

    monkeypatch.setattr(exact_tree, "_remove_windows_contents", attempt_swap)

    remove_exact_directory_tree(tree, expected)

    assert replacement_was_blocked
    assert not tree.exists()
    assert not moved.exists()
