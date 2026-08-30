"""Shared validation helpers for typed classic-overlay generators."""

from __future__ import annotations

from collections.abc import Mapping

from reprobit.classic.overlay_types import _Layout
from reprobit.classic.overlay_validation import (
    _LAYOUT_KEYS,
    _array,
    _fail,
    _identifier,
    _keys,
    _layout,
    _qualified,
)


def _generator_contract(
    value: Mapping[str, object],
    context: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
    semantic_lines: bool = False,
) -> _Layout:
    semantic = {"k"} | required
    optional_fields = (optional or set()) | (
        _LAYOUT_KEYS - ({"lines"} if semantic_lines else set())
    )
    _keys(value, semantic, context, optional=optional_fields)
    return _layout(value, context, semantic_lines=semantic_lines)


def _string_array(
    value: object,
    context: str,
    *,
    minimum: int = 0,
    maximum: int = 4096,
    qualified: bool = False,
) -> list[str]:
    validator = _qualified if qualified else _identifier
    result = [
        validator(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context, minimum=minimum, maximum=maximum))
    ]
    if len(set(result)) != len(result):
        _fail(f"{context} contains duplicates")
    return result
