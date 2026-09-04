"""Canonical filesystem and executable inputs for ReproBit commands."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Sequence
from os import PathLike
from pathlib import Path
from typing import Any

from reprobit.secure_path_contracts import SecurePathError, canonical_relative_path


class CLIError(RuntimeError):
    """A command cannot honestly complete with the supplied inputs."""


def _folded_parts(path: str | PathLike[str]) -> tuple[str, ...]:
    """Return one absolute path key using ReproBit's portable case rules."""

    absolute = Path(path).expanduser().resolve(strict=False)
    return tuple(part.casefold() for part in absolute.parts)


def paths_alias(first: str | PathLike[str], second: str | PathLike[str]) -> bool:
    """Return whether two path spellings identify the same portable location."""

    return _folded_parts(first) == _folded_parts(second)


def paths_overlap(first: str | PathLike[str], second: str | PathLike[str]) -> bool:
    """Return whether either portable path contains the other."""

    first_parts = _folded_parts(first)
    second_parts = _folded_parts(second)
    common = min(len(first_parts), len(second_parts))
    return first_parts[:common] == second_parts[:common]


def path_is_within(path: str | PathLike[str], parent: str | PathLike[str]) -> bool:
    """Return whether one portable path is the parent itself or is below it."""

    path_parts = _folded_parts(path)
    parent_parts = _folded_parts(parent)
    return len(path_parts) >= len(parent_parts) and path_parts[: len(parent_parts)] == parent_parts


def protected_project_paths(
    root: Path,
    spec: Any,
    *,
    source_paths: Iterable[str] = (),
) -> tuple[tuple[str, Path], ...]:
    """Return project locations that user-selected outputs must not replace."""

    declared = [
        ("project configuration", "reprobit.toml"),
        ("compiler lock", spec.toolchain.lock_file),
        ("source lock", spec.layout.source_manifest),
        ("build plan", spec.layout.build_plan),
        ("build graph", spec.layout.producer_graph),
        ("intervention records", spec.layout.interventions),
        ("proof records", spec.layout.proofs),
        ("reference metadata", spec.layout.oracles),
        ("local state", spec.state_dir),
    ]
    declared.extend(("locked source input", path) for path in source_paths)
    for target in spec.targets:
        declared.extend(
            (
                (f"{target.id} output", target.artifact),
                (f"{target.id} reference", target.oracle),
            )
        )
    return tuple((label, safe_project_path(root, path)) for label, path in declared)


def report_output_conflict(
    root: Path,
    spec: Any,
    outputs: Sequence[tuple[str, Path]],
    *,
    source_paths: Iterable[str],
) -> str | None:
    """Describe the first report-seat conflict shared by verify and repair."""

    managed_reports = safe_project_path(root, spec.state_dir) / "reports"
    locked_sources = tuple(source_paths)
    for index, (label, path) in enumerate(outputs):
        for other_label, other in outputs[index + 1 :]:
            if paths_alias(path, other):
                return f"{label} and {other_label} must use different paths"
        for protected_label, protected in protected_project_paths(
            root,
            spec,
            source_paths=locked_sources,
        ):
            if protected_label == "local state" and path_is_within(path, managed_reports):
                continue
            if paths_overlap(path, protected):
                return f"{label} overlaps {protected_label}: {protected}"
    return None


def canonical_project_relative(value: str, *, label: str) -> str:
    """Require one canonical, portable project-relative CLI value."""

    try:
        canonical_relative_path(value)
    except SecurePathError:
        raise CLIError(f"{label} must be a canonical project-relative path") from None
    return value


def project_root(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_dir() or path.is_symlink():
        raise CLIError(f"project root is not an existing real directory: {path}")
    return path.resolve(strict=True)


def real_directory(value: str | PathLike[str], *, label: str) -> Path:
    """Resolve an existing directory without accepting a redirected entry."""

    candidate = Path(value).expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise CLIError(f"{label} is not an existing real directory: {candidate}")
    return candidate.resolve(strict=True)


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
