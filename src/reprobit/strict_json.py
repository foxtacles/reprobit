"""Strict and deterministic JSON helpers.

The standard :mod:`json` decoder silently accepts duplicate object keys and
non-finite numbers.  Both behaviours are dangerous for signed build evidence:
two readers can otherwise interpret the same bytes differently.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Any, TypeAlias, cast

from pydantic import BaseModel

JsonScalar: TypeAlias = bool | int | float | str | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class StrictJSONError(ValueError):
    """Base class for JSON that cannot be used as canonical evidence."""


class DuplicateKeyError(StrictJSONError):
    """Raised when a JSON object contains the same member name twice."""

    def __init__(self, key: str) -> None:
        super().__init__(f"duplicate JSON object key: {key!r}")
        self.key = key


class NonFiniteNumberError(StrictJSONError):
    """Raised for NaN and infinite values."""


def _object_from_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> JsonValue:
    raise NonFiniteNumberError(f"non-finite JSON number: {value}")


def strict_loads(data: str | bytes | bytearray) -> JsonValue:
    """Decode JSON while rejecting duplicates and non-finite values."""

    try:
        decoded = json.loads(
            data,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except (DuplicateKeyError, NonFiniteNumberError):
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StrictJSONError(str(exc)) from exc
    return cast(JsonValue, decoded)


def strict_load(path: str | Path) -> JsonValue:
    """Read a UTF-8 JSON file through :func:`strict_loads`."""

    source = Path(path)
    try:
        return strict_loads(source.read_bytes())
    except OSError as exc:
        raise StrictJSONError(f"cannot read {source}: {exc}") from exc


def _jsonable(value: Any) -> JsonValue:
    if isinstance(value, BaseModel):
        return _jsonable(
            value.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
                exclude_computed_fields=True,
            )
        )
    if isinstance(value, Enum):
        return _jsonable(value.value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise NonFiniteNumberError(f"non-finite JSON number: {value!r}")
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object key must be str, got {type(key).__name__}")
            if key in result:
                raise DuplicateKeyError(key)
            result[key] = _jsonable(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_jsonable(item) for item in value]
    raise TypeError(f"value of type {type(value).__name__} is not JSON serializable")


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes with one trailing newline."""

    normalized = _jsonable(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (encoded + "\n").encode("utf-8")


__all__ = [
    "DuplicateKeyError",
    "JsonScalar",
    "JsonValue",
    "NonFiniteNumberError",
    "StrictJSONError",
    "canonical_json",
    "strict_load",
    "strict_loads",
]
