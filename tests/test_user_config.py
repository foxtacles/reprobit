from __future__ import annotations

import json
from pathlib import Path

import pytest

from reprobit import user_config
from reprobit.toolchains import (
    MSVC_42,
    MSVC_50_RTM,
    MSVC_50_SP1,
    MSVC_50_SP2,
    MSVC_50_SP3,
)
from reprobit.user_config import (
    UserConfigError,
    default_toolchain_root,
    resolve_toolchain_root,
    save_toolchain_root,
)


def _use_settings(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
) -> None:
    monkeypatch.setattr(user_config, "_settings_path", lambda: path)


def test_root_selection_priority_is_explicit_environment_saved_then_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = tmp_path / "config" / "settings.json"
    _use_settings(monkeypatch, settings)
    explicit = tmp_path / "explicit"
    environment = tmp_path / "environment"
    saved = tmp_path / "saved"
    standard = tmp_path / "standard"
    for path in (explicit, environment, saved, standard):
        path.mkdir()
    monkeypatch.setattr(user_config, "default_toolchain_root", lambda _profile: standard)
    save_toolchain_root(MSVC_42, saved)
    monkeypatch.setenv("REPROBIT_MSVC_4_2_ROOT", str(environment))

    assert resolve_toolchain_root(MSVC_42, explicit) == explicit
    assert resolve_toolchain_root(MSVC_42) == environment
    monkeypatch.delenv("REPROBIT_MSVC_4_2_ROOT")
    assert resolve_toolchain_root(MSVC_42) == saved
    settings.unlink()
    assert resolve_toolchain_root(MSVC_42) == standard


def test_missing_selected_root_is_actionable_and_never_silently_falls_through(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_settings(monkeypatch, tmp_path / "settings.json")
    configured = tmp_path / "missing"
    fallback = tmp_path / "standard"
    fallback.mkdir()
    monkeypatch.setenv("REPROBIT_MSVC_4_2_ROOT", str(configured))
    monkeypatch.setattr(user_config, "default_toolchain_root", lambda _profile: fallback)

    assert resolve_toolchain_root(MSVC_42, require=False) == configured
    with pytest.raises(UserConfigError, match="REPROBIT_MSVC_4_2_ROOT") as captured:
        resolve_toolchain_root(MSVC_42)
    assert str(configured) in str(captured.value)


@pytest.mark.parametrize(
    ("profile", "environment_name"),
    (
        (MSVC_42, "REPROBIT_MSVC_4_2_ROOT"),
        (MSVC_50_RTM, "REPROBIT_MSVC_5_0_RTM_ROOT"),
        (MSVC_50_SP1, "REPROBIT_MSVC_5_0_SP1_ROOT"),
        (MSVC_50_SP2, "REPROBIT_MSVC_5_0_SP2_ROOT"),
        (MSVC_50_SP3, "REPROBIT_MSVC_5_0_SP3_ROOT"),
    ),
)
def test_each_profile_uses_its_existing_environment_variable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    environment_name: str,
) -> None:
    _use_settings(monkeypatch, tmp_path / "settings.json")
    configured = tmp_path / profile
    configured.mkdir()
    monkeypatch.setenv(environment_name, str(configured))

    assert resolve_toolchain_root(profile) == configured


def test_save_is_atomic_and_preserves_other_profile_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = tmp_path / "config" / "settings.json"
    _use_settings(monkeypatch, settings)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    save_toolchain_root(MSVC_42, first)
    save_toolchain_root(MSVC_50_RTM, second)

    document = json.loads(settings.read_text(encoding="utf-8"))
    assert document == {
        "schema": "reprobit.user-config.v1",
        "toolchain_roots": {
            MSVC_42: str(first),
            MSVC_50_RTM: str(second),
        },
    }
    assert not tuple(settings.parent.glob(f".{settings.name}.*"))


def test_failed_atomic_replace_keeps_previous_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = tmp_path / "config" / "settings.json"
    _use_settings(monkeypatch, settings)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    save_toolchain_root(MSVC_42, first)
    before = settings.read_bytes()

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(user_config.os, "replace", fail_replace)
    with pytest.raises(UserConfigError, match="cannot save user settings"):
        save_toolchain_root(MSVC_50_RTM, second)

    assert settings.read_bytes() == before
    assert not tuple(settings.parent.glob(f".{settings.name}.*"))


@pytest.mark.parametrize(
    "payload",
    (
        b"{}\n",
        b'{"schema":"reprobit.user-config.v1","toolchain_roots":[]}\n',
        b'{"schema":"reprobit.user-config.v1","toolchain_roots":{"msvc_4_2":"relative"}}\n',
        b'{"schema":"reprobit.user-config.v1","schema":"duplicate","toolchain_roots":{}}\n',
    ),
)
def test_malformed_user_settings_are_not_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    settings = tmp_path / "settings.json"
    settings.write_bytes(payload)
    _use_settings(monkeypatch, settings)

    with pytest.raises(UserConfigError):
        resolve_toolchain_root(MSVC_42, require=False)


def test_platform_defaults_use_standard_user_data_locations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(user_config, "_home_directory", lambda: tmp_path / "home")

    monkeypatch.setattr(user_config, "_platform_name", lambda: "darwin")
    assert default_toolchain_root(MSVC_42) == (
        tmp_path / "home" / "Library" / "Application Support" / "ReproBit" / "toolchains" / MSVC_42
    )

    monkeypatch.setattr(user_config, "_platform_name", lambda: "linux")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    assert default_toolchain_root(MSVC_42) == (
        tmp_path / "xdg-data" / "reprobit" / "toolchains" / MSVC_42
    )

    monkeypatch.setattr(user_config, "_platform_name", lambda: "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    assert default_toolchain_root(MSVC_42) == (
        tmp_path / "local-app-data" / "ReproBit" / "toolchains" / MSVC_42
    )


def test_save_requires_an_existing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_settings(monkeypatch, tmp_path / "settings.json")

    with pytest.raises(UserConfigError, match="unavailable toolchain directory"):
        save_toolchain_root(MSVC_42, tmp_path / "missing")
