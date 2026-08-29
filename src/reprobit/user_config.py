"""Machine-local ReproBit preferences outside project authority."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from reprobit.strict_json import StrictJSONError, strict_loads
from reprobit.toolchains import ToolchainProfile
from reprobit.toolchains import profile as load_profile

_SCHEMA = "reprobit.user-config.v1"


class UserConfigError(RuntimeError):
    """Machine-local configuration is absent or malformed."""


@dataclass(frozen=True, slots=True)
class _RootSelection:
    value: Path
    source: str


def _selected_profile(value: ToolchainProfile | str) -> ToolchainProfile:
    return load_profile(value) if isinstance(value, str) else value


def _environment_variable(selected: ToolchainProfile) -> str:
    return f"REPROBIT_{selected.identifier.upper()}_ROOT"


def _home_directory() -> Path:
    return Path.home()


def _platform_name() -> str:
    return sys.platform


def _absolute_environment_path(
    environment: Mapping[str, str], name: str
) -> Path | None:
    raw = environment.get(name)
    if raw is None or not raw.strip():
        return None
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_absolute() else None


def _user_roots() -> tuple[Path, Path]:
    environment = os.environ
    home = _home_directory()
    platform_name = _platform_name()
    if platform_name == "win32":
        config = _absolute_environment_path(environment, "APPDATA")
        data = _absolute_environment_path(environment, "LOCALAPPDATA")
        return (
            (config or home / "AppData" / "Roaming") / "ReproBit",
            (data or home / "AppData" / "Local") / "ReproBit",
        )
    if platform_name == "darwin":
        root = home / "Library" / "Application Support" / "ReproBit"
        return root, root
    config = _absolute_environment_path(environment, "XDG_CONFIG_HOME")
    data = _absolute_environment_path(environment, "XDG_DATA_HOME")
    return (
        (config or home / ".config") / "reprobit",
        (data or home / ".local" / "share") / "reprobit",
    )


def _settings_path() -> Path:
    config_root, _ = _user_roots()
    return config_root / "settings.json"


def default_toolchain_root(profile: ToolchainProfile | str) -> Path:
    """Return the conventional machine-local installation path for a profile."""

    selected = _selected_profile(profile)
    _, data_root = _user_roots()
    return (data_root / "toolchains" / selected.identifier).resolve(strict=False)


def _read_roots(path: Path) -> dict[str, str]:
    if not path.exists() and not path.is_symlink():
        return {}
    if path.is_symlink() or not path.is_file():
        raise UserConfigError(f"user settings are not a regular file: {path}")
    try:
        document = strict_loads(path.read_bytes())
    except (OSError, StrictJSONError) as error:
        raise UserConfigError(f"cannot read user settings {path}: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != _SCHEMA:
        raise UserConfigError(f"user settings have an unsupported format: {path}")
    roots = document.get("toolchain_roots")
    if not isinstance(roots, dict):
        raise UserConfigError(f"user settings contain invalid toolchain roots: {path}")
    normalized: dict[str, str] = {}
    for key, value in roots.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise UserConfigError(f"user settings contain invalid toolchain roots: {path}")
        if not value.strip() or not Path(value).expanduser().is_absolute():
            raise UserConfigError(
                f"user settings contain non-absolute toolchain roots: {path}"
            )
        normalized[key] = value
    return normalized


def _selection(
    selected: ToolchainProfile,
    explicit: str | os.PathLike[str] | None,
) -> _RootSelection:
    if explicit is not None:
        return _RootSelection(Path(explicit), "the explicit toolchain root")
    environment_name = _environment_variable(selected)
    environment_value = os.environ.get(environment_name)
    if environment_value is not None and environment_value.strip():
        return _RootSelection(Path(environment_value), environment_name)
    settings = _settings_path()
    saved = _read_roots(settings).get(selected.identifier)
    if saved is not None and saved.strip():
        return _RootSelection(Path(saved), f"the saved setting in {settings}")
    return _RootSelection(default_toolchain_root(selected), "the standard location")


def resolve_toolchain_root(
    profile: ToolchainProfile | str,
    explicit: str | os.PathLike[str] | None = None,
    require: bool = True,
) -> Path:
    """Resolve a physical root without changing project authority or policy.

    Selection priority is explicit argument, profile environment variable,
    machine-local saved setting, then the conventional installation path.
    """

    selected = _selected_profile(profile)
    selection = _selection(selected, explicit)
    candidate = selection.value.expanduser().resolve(strict=False)
    if require and not candidate.is_dir():
        environment_name = _environment_variable(selected)
        raise UserConfigError(
            f"{selected.display_name} was selected from {selection.source}, but its "
            f"directory is unavailable: {candidate}. Provide --toolchain-root, set "
            f"{environment_name}, or provision the toolchain at the standard location."
        )
    return candidate


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_roots(path: Path, roots: Mapping[str, str]) -> None:
    payload = (
        json.dumps(
            {"schema": _SCHEMA, "toolchain_roots": dict(roots)},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def save_toolchain_root(
    profile: ToolchainProfile | str,
    root: str | os.PathLike[str],
) -> None:
    """Atomically remember one existing physical root for the current user."""

    selected = _selected_profile(profile)
    candidate = Path(root).expanduser().resolve(strict=False)
    if not candidate.is_dir():
        raise UserConfigError(
            f"cannot save an unavailable toolchain directory for "
            f"{selected.display_name}: {candidate}"
        )
    settings = _settings_path()
    roots = _read_roots(settings)
    roots[selected.identifier] = str(candidate)
    try:
        _write_roots(settings, roots)
    except OSError as error:
        raise UserConfigError(f"cannot save user settings {settings}: {error}") from error


__all__ = [
    "UserConfigError",
    "default_toolchain_root",
    "resolve_toolchain_root",
    "save_toolchain_root",
]
