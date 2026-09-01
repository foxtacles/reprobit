"""Suite-wide isolation from the developer's machine.

Every test runs against a private, empty user-configuration home so no test can
read or write the real ReproBit settings (saved toolchain roots) of whoever runs
the suite. Tests that need a toolchain declare it explicitly through
``REPROBIT_MSVC_4_2_ROOT`` or by monkeypatching ``reprobit.user_config``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reprobit import user_config


@pytest.fixture(autouse=True)
def _isolated_user_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    home = tmp_path_factory.mktemp("user-home")
    monkeypatch.setattr(user_config, "_home_directory", lambda: home)
    for name in ("APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)
    return home
