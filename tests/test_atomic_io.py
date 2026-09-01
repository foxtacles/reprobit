from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from reprobit.atomic_io import write_bytes_atomic, write_json_atomic
from reprobit.strict_json import canonical_json


def test_write_json_atomic_publishes_canonical_json_privately(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    value = {"b": [1, 2], "a": {"nested": None}}

    write_json_atomic(target, value)

    assert target.read_bytes() == canonical_json(value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_write_bytes_atomic_replaces_existing_content_and_discards_the_temporary(
    tmp_path: Path,
) -> None:
    target = tmp_path / "settings.json"
    target.write_bytes(b"old\n")

    write_bytes_atomic(target, b"new\n", fsync_directory=False)

    assert target.read_bytes() == b"new\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["settings.json"]


def test_write_json_atomic_rejects_non_finite_numbers_before_touching_the_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "state.json"
    target.write_bytes(b"kept\n")

    with pytest.raises(ValueError):
        write_json_atomic(target, {"value": float("nan")})

    assert target.read_bytes() == b"kept\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["state.json"]
