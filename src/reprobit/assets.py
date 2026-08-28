"""Locate reviewed non-code assets in source and installed layouts."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath


def runtime_asset_path(name: str) -> Path:
    """Return one regular packaged runtime asset by its single-file name."""

    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("runtime asset name must be one safe path component")
    relative = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (
        len(relative.parts) != 1
        or len(windows.parts) != 1
        or windows.drive
        or relative.name in {"", ".", ".."}
    ):
        raise ValueError("runtime asset name must be one safe path component")
    package_directory = Path(__file__).resolve(strict=True).parent
    repository_root = package_directory.parents[1]
    candidates = (
        repository_root / "runtime" / relative.name,
        package_directory.parent / "share" / "reprobit" / "runtime" / relative.name,
    )
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        return candidate.resolve(strict=True)
    raise FileNotFoundError(f"the packaged runtime asset is missing: {name}")


__all__ = ["runtime_asset_path"]
