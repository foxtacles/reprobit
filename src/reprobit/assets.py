"""Locate reviewed non-code assets in source and installed layouts."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath


def _safe_component(name: str, label: str) -> str:
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError(f"{label} must be one safe path component")
    relative = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (
        len(relative.parts) != 1
        or len(windows.parts) != 1
        or windows.drive
        or relative.name in {"", ".", ".."}
    ):
        raise ValueError(f"{label} must be one safe path component")
    return relative.name


def _runtime_candidates(name: str) -> tuple[Path, Path]:
    package_directory = Path(__file__).resolve(strict=True).parent
    repository_root = package_directory.parents[1]
    return (
        repository_root / "runtime" / name,
        package_directory.parent / "share" / "reprobit" / "runtime" / name,
    )


def runtime_asset_path(name: str) -> Path:
    """Return one regular packaged runtime asset by its single-file name."""

    component = _safe_component(name, "runtime asset name")
    for candidate in _runtime_candidates(component):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        return candidate.resolve(strict=True)
    raise FileNotFoundError(f"the packaged runtime asset is missing: {name}")


def runtime_asset_directory(name: str) -> Path:
    """Return one real packaged runtime directory by its single-component name."""

    component = _safe_component(name, "runtime asset directory name")
    for candidate in _runtime_candidates(component):
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        return candidate.resolve(strict=True)
    raise FileNotFoundError(f"the packaged runtime asset directory is missing: {name}")


__all__ = ["runtime_asset_directory", "runtime_asset_path"]
