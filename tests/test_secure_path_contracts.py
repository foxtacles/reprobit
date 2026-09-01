from __future__ import annotations

import pytest

from reprobit.secure_path_contracts import (
    SecurePathError,
    canonical_relative_path,
    portable_relative_text,
)


@pytest.mark.parametrize(
    "value",
    ("", "\0", "/absolute", "../escape", "nested/../escape", "nested\\file", "./file", "a//b"),
)
def test_canonical_relative_path_rejects_non_canonical_text(value: str) -> None:
    with pytest.raises(SecurePathError):
        canonical_relative_path(value)


def test_canonical_relative_path_keeps_canonical_text() -> None:
    assert canonical_relative_path("src/unit.cpp").as_posix() == "src/unit.cpp"


@pytest.mark.parametrize(
    ("value", "expected"),
    (("src/unit.cpp", "src/unit.cpp"), ("src\\unit.cpp", "src/unit.cpp")),
)
def test_portable_relative_text_folds_backslashes(value: str, expected: str) -> None:
    assert portable_relative_text(value) == expected


@pytest.mark.parametrize(
    "value",
    ("", ".", "/absolute", "../escape", "nested/../escape", "./file", "a//b", "a/"),
)
def test_portable_relative_text_rejects_non_canonical_text(value: str) -> None:
    with pytest.raises(SecurePathError):
        portable_relative_text(value)
