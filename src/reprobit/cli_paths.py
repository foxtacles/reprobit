"""Canonical filesystem and executable inputs for ReproBit commands."""

from __future__ import annotations

import shutil
from pathlib import Path


class CLIError(RuntimeError):
    """A command cannot honestly complete with the supplied inputs."""


def project_root(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_dir() or path.is_symlink():
        raise CLIError(f"project root is not an existing real directory: {path}")
    return path.resolve(strict=True)


def safe_project_path(root: Path, value: str) -> Path:
    path = (root / value.replace("\\", "/")).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise CLIError(f"path escapes the project root: {value}") from error
    return path


def relative_output(root: Path, value: str) -> Path:
    candidate = Path(value)
    absolute = candidate if candidate.is_absolute() else root / candidate
    absolute = absolute.resolve(strict=False)
    try:
        return absolute.relative_to(root)
    except ValueError as error:
        raise CLIError(f"transaction output is outside the project: {absolute}") from error


def resolve_program(value: str, cwd: Path) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=True)
    elif "/" in value or "\\" in value:
        resolved = (cwd / candidate).resolve(strict=True)
    else:
        located = shutil.which(value)
        if located is None:
            raise CLIError(f"build executable is not available: {value}")
        resolved = Path(located).resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise CLIError(f"build executable is absent or unsafe: {resolved}")
    return str(resolved)
