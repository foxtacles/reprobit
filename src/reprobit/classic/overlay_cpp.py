"""Closed C++ type parsing and parameter rendering for classic overlays."""

from __future__ import annotations

import re
from dataclasses import dataclass

from reprobit.classic.overlay_validation import (
    _fail,
    _identifier,
    _integer,
    _keys,
    _object,
    _string,
)


@dataclass(frozen=True, slots=True)
class _CppType:
    base_kind: str
    name: tuple[str, ...]
    arguments: tuple[_CppType, ...]
    base_const: bool
    indirection: tuple[str, ...]
    trailing_const: bool


_BUILTINS = frozenset(
    {"void", "bool", "char", "short", "int", "long", "signed", "unsigned", "float", "double"}
)
_TYPE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")


def _parse_cpp_type_at(text: str, position: int, context: str, depth: int) -> tuple[_CppType, int]:
    if depth > 8:
        _fail(f"{context} exceeds the type recursion bound")
    base_const = text.startswith("const ", position)
    if base_const:
        position += 6
    match = _TYPE_NAME_RE.match(text, position)
    if match is None:
        _fail(f"{context} is not a closed type spelling")
    first = match.group(0)
    position = match.end()
    arguments: list[_CppType] = []
    if first in _BUILTINS:
        specifiers = [first]
        while len(specifiers) < 3 and text.startswith(" ", position):
            follow = _TYPE_NAME_RE.match(text, position + 1)
            if follow is None or follow.group(0) not in _BUILTINS:
                break
            specifiers.append(follow.group(0))
            position = follow.end()
        base_kind = "builtin"
        name = tuple(specifiers)
    elif text.startswith("<", position):
        base_kind = "template"
        name = tuple(first.split("::"))
        position += 1
        while True:
            argument, position = _parse_cpp_type_at(text, position, context, depth + 1)
            arguments.append(argument)
            if text.startswith(", ", position):
                position += 2
                continue
            if not text.startswith(">", position):
                _fail(f"{context} template argument list is unterminated")
            position += 1
            break
    else:
        base_kind = "named"
        name = tuple(first.split("::"))
    indirection: list[str] = []
    trailing_const = False
    while position < len(text):
        if text.startswith("*", position):
            indirection.append("pointer")
            position += 1
        elif text.startswith("&", position):
            indirection.append("reference")
            position += 1
        elif text.startswith(" const", position):
            trailing_const = True
            position += 6
        else:
            break
    if (
        len(indirection) > 2
        or indirection.count("pointer") > 1
        or indirection.count("reference") > 1
    ):
        _fail(f"{context} has unsupported indirection")
    return _CppType(
        base_kind, name, tuple(arguments), base_const, tuple(indirection), trailing_const
    ), position


def _render_cpp_type(value: _CppType) -> str:
    if value.base_kind == "builtin":
        rendered = " ".join(value.name)
    else:
        rendered = "::".join(value.name)
        if value.base_kind == "template":
            rendered += "<" + ", ".join(_render_cpp_type(item) for item in value.arguments) + ">"
    if value.base_const:
        rendered = "const " + rendered
    trailing_rendered = False
    for item in value.indirection:
        rendered += "*" if item == "pointer" else "&"
        if item == "pointer" and value.trailing_const:
            rendered += " const"
            trailing_rendered = True
    if value.trailing_const and not trailing_rendered:
        rendered += " const"
    return rendered


def _cpp_type(value: object, context: str) -> _CppType:
    text = _string(value, context, maximum=1024)
    if not text.isascii():
        _fail(f"{context} must be ASCII")
    parsed, position = _parse_cpp_type_at(text, 0, context, 0)
    if position != len(text) or _render_cpp_type(parsed) != text:
        _fail(f"{context} is not a canonical closed type spelling")
    return parsed


def _parameter(value: object, context: str) -> tuple[_CppType, str | None]:
    item = _object(value, context)
    if set(item) not in ({"type"}, {"type", "identifier"}):
        _fail(f"{context} has unexpected fields")
    identifier = None
    if "identifier" in item:
        identifier = _identifier(item.get("identifier"), f"{context}.identifier")
    return _cpp_type(item.get("type"), f"{context}.type"), identifier


def _render_parameter(value: object, context: str) -> str:
    type_value, identifier = _parameter(value, context)
    rendered = _render_cpp_type(type_value)
    return rendered if identifier is None else f"{rendered} {identifier}"


def _identifier_run(value: object, context: str, *, allow_list: bool = False) -> list[str]:
    if allow_list and isinstance(value, list):
        result = [_identifier(item, f"{context}[{index}]") for index, item in enumerate(value)]
        if len(result) > 4096 or len(set(result)) != len(result):
            _fail(f"{context} is too large or contains duplicates")
        return result
    item = _object(value, context)
    _keys(item, {"kind", "stem", "first", "count", "width"}, context)
    if item.get("kind") != "identifier_run":
        _fail(f"{context}.kind must be 'identifier_run'")
    stem = _identifier(item.get("stem"), f"{context}.stem")
    first = _integer(item.get("first"), f"{context}.first", minimum=0, maximum=1_000_000)
    count = _integer(item.get("count"), f"{context}.count", minimum=1, maximum=4096)
    width = _integer(item.get("width"), f"{context}.width", minimum=1, maximum=8)
    result = [stem + str(number).zfill(width) for number in range(first, first + count)]
    if len(set(result)) != len(result):
        _fail(f"{context} expands to duplicate identifiers")
    return result
