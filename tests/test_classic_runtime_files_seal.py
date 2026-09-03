"""The producer tree seal walks with scandir and still refuses symlinks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reprobit import classic_runtime_files as subject
from reprobit.classic_project import ClassicProjectError
from reprobit.model import Digest


def test_tree_seal_lists_regular_files_by_resolved_path(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "inc" / "deep").mkdir(parents=True)
    (root / "s.cpp").write_bytes(b"int s;\n")
    (root / "inc" / "deep" / "h.h").write_bytes(b"#pragma once\n")
    (root / "inc" / "empty").mkdir()

    seal = subject._tree_file_seal(root)

    resolved = root.resolve()
    assert dict(seal) == {
        resolved / "s.cpp": (7, Digest.from_bytes(b"int s;\n")),
        resolved / "inc" / "deep" / "h.h": (13, Digest.from_bytes(b"#pragma once\n")),
    }
    assert subject._tree_file_seal(tmp_path / "absent") == {}
    assert subject._tree_file_seal(root / "s.cpp") == {}


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_tree_seal_refuses_any_symlink(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "real.txt").write_bytes(b"x")
    (root / "link.txt").symlink_to(root / "real.txt")
    with pytest.raises(ClassicProjectError, match="contains a symlink"):
        subject._tree_file_seal(root)
    (root / "link.txt").unlink()
    (root / "dirlink").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ClassicProjectError, match="contains a symlink"):
        subject._tree_file_seal(root)
