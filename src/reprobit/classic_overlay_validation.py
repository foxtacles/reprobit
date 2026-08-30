"""Primitive validation and physical-layout rules for classic overlays."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import NoReturn, cast

from reprobit.classic_overlay_types import SourceEditError, _Layout

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_QUALIFIED_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)*")
_OPERATION_ID_RE = re.compile(r"op_[a-z0-9_]{1,120}")
_RANGE_DEPENDENCY_RE = re.compile(r"[a-z][a-z0-9_]{1,160}")
_TARGET_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*")
_SOURCE_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
)
_COMPILE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})
_LAYOUT_KEYS = frozenset({"lines", "at", "indent", "nl", "blank_indent"})
_BOUNDARIES = {
    "start": "file_start",
    "end": "file_end",
    "before_token": "before_next_token",
    "after_token": "after_previous_token",
}


def _fail(message: str) -> NoReturn:
    raise SourceEditError(message)


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _fail(f"{context} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _array(value: object, context: str, *, maximum: int, minimum: int = 0) -> list[object]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _fail(f"{context} must contain between {minimum} and {maximum} items")
    return cast(list[object], value)


def _keys(
    value: Mapping[str, object],
    required: set[str],
    context: str,
    *,
    optional: set[str] | None = None,
) -> None:
    admitted = required | (optional or set())
    actual = set(value)
    if not required <= actual or not actual <= admitted:
        _fail(
            f"{context} fields differ: required={sorted(required)}, "
            f"optional={sorted(optional or set())}, actual={sorted(actual)}"
        )


def _integer(value: object, context: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{context} must be an integer in [{minimum}, {maximum}]")
    return value


def _boolean(value: object, context: str) -> bool:
    if type(value) is not bool:
        _fail(f"{context} must be a boolean")
    return value


def _string(value: object, context: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\0" in value:
        _fail(f"{context} must be a non-empty bounded string")
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{context} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        _fail(f"{context} must be a C/C++ identifier")
    return value


def _qualified(value: object, context: str) -> str:
    if not isinstance(value, str) or _QUALIFIED_RE.fullmatch(value) is None:
        _fail(f"{context} must be a qualified C/C++ identifier")
    return value


def _relative_path(value: object, context: str) -> str:
    text = _string(value, context)
    if "\\" in text or ";" in text or "\n" in text or "\r" in text:
        _fail(f"{context} must use a safe POSIX path")
    pure = PurePosixPath(text)
    if (
        pure.is_absolute()
        or pure.as_posix() != text
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.suffix.casefold() not in _SOURCE_SUFFIXES
    ):
        _fail(f"{context} must be a canonical relative C/C++ source path")
    return text


def _safe_header(value: object, context: str) -> str:
    text = _string(value, context, maximum=256)
    pure = PurePosixPath(text)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or "\\" in text
        or any(character in text for character in "<>\"'\n\r")
    ):
        _fail(f"{context} is not a safe include identity")
    return text


def _operation_id(value: object, context: str, fallback: str) -> str:
    if value is None:
        return fallback
    if not isinstance(value, str) or _OPERATION_ID_RE.fullmatch(value) is None:
        _fail(f"{context} is not a valid operation id")
    return value


def _indentation_units(value: object, context: str) -> bytes:
    items = _array(value, context, maximum=32)
    result = bytearray()
    prior: str | None = None
    for index, raw in enumerate(items):
        item = _object(raw, f"{context}[{index}]")
        _keys(item, {"unit", "count"}, f"{context}[{index}]")
        unit = item.get("unit")
        if unit not in {"tab", "space"} or unit == prior:
            _fail(f"{context}[{index}].unit differs or is noncanonical")
        prior = unit
        count = _integer(item.get("count"), f"{context}[{index}].count", minimum=1, maximum=4096)
        result.extend((b"\t" if unit == "tab" else b" ") * count)
    return bytes(result)


def _layout(value: Mapping[str, object], context: str, *, semantic_lines: bool = False) -> _Layout:
    lines: int | None = None
    positions: tuple[int, ...] | None = None
    if not semantic_lines and ("lines" in value or "at" in value):
        lines = _integer(value.get("lines"), f"{context}.lines", minimum=1, maximum=2_000_000)
        raw_positions = value.get("at")
        if raw_positions is not None:
            positions_list = [
                _integer(item, f"{context}.at[{index}]", minimum=1, maximum=lines)
                for index, item in enumerate(_array(raw_positions, f"{context}.at", maximum=lines))
            ]
            if len(set(positions_list)) != len(positions_list):
                _fail(f"{context}.at contains duplicate positions")
            positions = tuple(positions_list)
    elif not semantic_lines and "blank_indent" in value:
        _fail(f"{context}.blank_indent requires an explicit canvas")

    indent: list[tuple[int, bytes]] = []
    if "indent" in value:
        seen: set[int] = set()
        for index, raw in enumerate(
            _array(value.get("indent"), f"{context}.indent", minimum=1, maximum=4096)
        ):
            if not isinstance(raw, list) or len(raw) != 2:
                _fail(f"{context}.indent[{index}] must be a [line, units] pair")
            pair = cast(list[object], raw)
            line = _integer(
                pair[0], f"{context}.indent[{index}].line", minimum=1, maximum=2_000_000
            )
            if line in seen:
                _fail(f"{context}.indent[{index}].line is duplicated")
            seen.add(line)
            indent.append((line, _indentation_units(pair[1], f"{context}.indent[{index}].units")))

    newline: bool | str = True
    if "nl" in value:
        raw_newline = value.get("nl")
        if raw_newline is not False and raw_newline != "open":
            _fail(f"{context}.nl must be false or 'open'")
        newline = cast(bool | str, raw_newline)

    blank_indent: list[tuple[int, int, bytes]] = []
    if "blank_indent" in value:
        if lines is None:
            _fail(f"{context}.blank_indent requires a canvas")
        previous_end = 0
        for index, raw in enumerate(
            _array(
                value.get("blank_indent"),
                f"{context}.blank_indent",
                minimum=1,
                maximum=4096,
            )
        ):
            if not isinstance(raw, list) or len(raw) != 3:
                _fail(f"{context}.blank_indent[{index}] must be [first, count, units]")
            triple = cast(list[object], raw)
            first = _integer(
                triple[0], f"{context}.blank_indent[{index}].first", minimum=1, maximum=lines
            )
            count = _integer(
                triple[1], f"{context}.blank_indent[{index}].count", minimum=1, maximum=lines
            )
            if first <= previous_end or first + count - 1 > lines:
                _fail(f"{context}.blank_indent[{index}] overlaps or leaves its canvas")
            previous_end = first + count - 1
            indentation = _indentation_units(triple[2], f"{context}.blank_indent[{index}].units")
            if not indentation:
                _fail(f"{context}.blank_indent[{index}] must contain whitespace")
            blank_indent.append((first, count, indentation))
    return _Layout(lines, positions, tuple(indent), newline, tuple(blank_indent))


def _seat_fragment(kind: str, semantic: bytes, layout: _Layout) -> bytes:
    if b"\r" in semantic or not semantic.isascii():
        _fail(f"typed source overlay fragment is not ASCII/LF: {kind}")
    raw_lines = semantic.split(b"\n")
    if raw_lines and raw_lines[-1] == b"":
        raw_lines.pop()
    indent_by_line = dict(layout.indent)

    def seated(content_index: int, line: bytes) -> bytes:
        stripped = line.lstrip(b" \t")
        if stripped != stripped.rstrip(b" \t"):
            _fail(f"typed source overlay semantic line has trailing whitespace: {kind}")
        replacement = indent_by_line.get(content_index + 1)
        return line if replacement is None else replacement + stripped

    if layout.lines is not None:
        content = [line for line in raw_lines if line.strip(b" \t")]
        positions = layout.positions or tuple(range(1, len(content) + 1))
        if len(positions) != len(content) or any(
            not 1 <= position <= layout.lines for position in positions
        ):
            _fail(f"typed source overlay canvas placement differs: {kind}")
        physical: list[bytes | None] = [None] * layout.lines
        for index, line in enumerate(content):
            seat = positions[index] - 1
            if physical[seat] is not None:
                _fail(f"typed source overlay content seat is duplicated: {kind}")
            physical[seat] = seated(index, line)
        for first, count, indentation in layout.blank_indent:
            for line_number in range(first, first + count):
                if physical[line_number - 1] is not None:
                    _fail(f"typed source overlay transparent seat overlaps: {kind}")
                physical[line_number - 1] = indentation
        rendered_lines = [b"" if line is None else line for line in physical]
        content_count = len(content)
    else:
        rendered_lines = []
        content_count = 0
        for line in raw_lines:
            if line.strip(b" \t"):
                rendered_lines.append(seated(content_count, line))
                content_count += 1
            else:
                rendered_lines.append(line)
    if any(not 1 <= line <= content_count for line in indent_by_line):
        _fail(f"typed source overlay indentation override is unseated: {kind}")
    if layout.newline is False:
        if len(rendered_lines) > 1:
            _fail(f"typed source overlay unterminated fragment differs: {kind}")
        return rendered_lines[0] if rendered_lines else b""
    body = b"\n".join(rendered_lines)
    if layout.newline is True and rendered_lines:
        body += b"\n"
    return body
