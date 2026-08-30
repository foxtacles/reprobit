from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.cli_paths import (
    CLIError,
    canonical_project_relative,
    real_directory,
)


def test_canonical_project_relative_preserves_canonical_text() -> None:
    assert canonical_project_relative("src/unit.cpp", label="source") == "src/unit.cpp"


@pytest.mark.parametrize(
    "value",
    ("", "/absolute", "../escape", "nested/../escape", "nested\\file", "./file"),
)
def test_canonical_project_relative_rejects_ambiguous_paths(value: str) -> None:
    with pytest.raises(CLIError, match="source must be a canonical project-relative path"):
        canonical_project_relative(value, label="source")


def test_shared_cli_directory_resolution_rejects_redirects(tmp_path: Path) -> None:
    directory = tmp_path / "toolchain"
    directory.mkdir()
    assert real_directory(directory, label="toolchain") == directory.resolve()

    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(directory, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(CLIError, match="toolchain is not an existing real directory"):
        real_directory(redirected, label="toolchain")
