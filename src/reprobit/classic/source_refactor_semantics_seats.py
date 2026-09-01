"""Donor-private source refactor semantics: source seats, owners and freshness."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast

from .source_refactor_semantics_schema import (
    _BUILTIN_INTEGRAL_TOKEN_FORMS,
    _IDENTIFIER_RE,
    _need,
    _pin,
    _significant,
    _string,
    _token_text,
    _type_tokens,
)


def _unique_bytes(haystack: bytes, needle: bytes, context: str) -> int:
    _need(bool(needle) and haystack.count(needle) == 1, f"{context} is absent or ambiguous")
    return haystack.index(needle)


def _unique_tokens(
    tokens: Sequence[tuple[str, int, int]], wanted: Sequence[str], context: str
) -> tuple[int, int, int]:
    matches = [
        index
        for index in range(len(tokens) - len(wanted) + 1)
        if [item[0] for item in tokens[index : index + len(wanted)]] == list(wanted)
    ]
    _need(len(matches) == 1, f"{context} is absent or ambiguous")
    index = matches[0]
    return index, tokens[index][1], tokens[index + len(wanted) - 1][2]


def _unique_class_body(
    data: bytes, identifier: str, context: str
) -> tuple[list[tuple[str, int, int]], int, int, int]:
    tokens = _significant(data)
    candidates: list[tuple[int, int, int]] = []
    for index in range(len(tokens) - 2):
        if tokens[index][0] not in {"class", "struct"} or tokens[index + 1][0] != identifier:
            continue
        opening = next(
            (cursor for cursor in range(index + 2, len(tokens)) if tokens[cursor][0] in {"{", ";"}),
            None,
        )
        if opening is None or tokens[opening][0] != "{":
            continue
        depth = 1
        closing = None
        for cursor in range(opening + 1, len(tokens)):
            if tokens[cursor][0] == "{":
                depth += 1
            elif tokens[cursor][0] == "}":
                depth -= 1
                if depth == 0:
                    closing = cursor
                    break
        _need(closing is not None, f"{context} is unbalanced")
        candidates.append((index, opening, cast(int, closing)))
    _need(len(candidates) == 1, f"{context} is absent or ambiguous")
    start, opening, closing = candidates[0]
    return tokens, start, opening, closing


def _class_level_range(
    tokens: Sequence[tuple[str, int, int]],
    opening: int,
    closing: int,
    wanted: Sequence[str],
    context: str,
) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    depth = 1
    for index in range(opening + 1, closing):
        token = tokens[index][0]
        if depth == 1 and [item[0] for item in tokens[index : index + len(wanted)]] == list(wanted):
            matches.append((tokens[index][1], tokens[index + len(wanted) - 1][2]))
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
    _need(len(matches) == 1, f"{context} is absent or ambiguous")
    return matches[0]


def _line(data: bytes, token_range: tuple[int, int]) -> bytes:
    start, end = token_range
    line_start = data.rfind(b"\n", 0, start) + 1
    newline = data.find(b"\n", end)
    return data[line_start : len(data) if newline < 0 else newline + 1]


def _include_edge(
    clean_sources: Mapping[str, bytes],
    including_path: str,
    including_data: bytes,
    included_path: str,
    pin: object,
    context: str,
) -> None:
    basename = PurePosixPath(included_path).name
    candidates = [path for path in clean_sources if PurePosixPath(path).name == basename]
    _need(candidates == [included_path], f"{context} included basename is not unique")
    wanted = ["#", "include", f'"{basename}"']
    lines = [
        line for line in including_data.splitlines(keepends=True) if _token_text(line) == wanted
    ]
    _need(len(lines) == 1, f"{context} include edge is absent or ambiguous")
    _pin(lines[0], pin, f"{context} include line")


def _quoted_include_closure(
    clean_sources: Mapping[str, bytes], start_path: str
) -> Mapping[str, bytes]:
    """Resolve the unambiguous quoted-include closure inside source authority."""

    pending = [start_path]
    result: dict[str, bytes] = {}
    while pending:
        current = pending.pop()
        if current in result:
            continue
        data = clean_sources.get(current)
        _need(data is not None, f"integral-type include source {current!r} is absent")
        result[current] = cast(bytes, data)
        for line in cast(bytes, data).splitlines():
            tokens = _token_text(line)
            if (
                len(tokens) != 3
                or tokens[:2] != ["#", "include"]
                or len(tokens[2]) < 2
                or not tokens[2].startswith('"')
                or not tokens[2].endswith('"')
            ):
                continue
            include_name = tokens[2][1:-1]
            relative = (PurePosixPath(current).parent / include_name).as_posix()
            if relative in clean_sources:
                pending.append(relative)
                continue
            suffix = f"/{include_name}"
            matches = sorted(
                path for path in clean_sources if path == include_name or path.endswith(suffix)
            )
            if len(matches) == 1:
                pending.append(matches[0])
    return MappingProxyType(result)


def _require_integral_type(
    clean_sources: Mapping[str, bytes], start_path: str, type_text: str, context: str
) -> None:
    """Prove a spelling reaches a built-in integral type through typedefs."""

    initial = tuple(_type_tokens(type_text, context))
    closure = _quoted_include_closure(clean_sources, start_path)
    current = initial
    seen: set[tuple[str, ...]] = set()
    while current not in _BUILTIN_INTEGRAL_TOKEN_FORMS:
        _need(
            len(current) == 1 and _IDENTIFIER_RE.fullmatch(current[0]) is not None,
            f"{context} is not a built-in integral type or a simple typedef",
        )
        _need(current not in seen, f"{context} typedef chain is cyclic")
        seen.add(current)
        alias = current[0]
        candidates: list[tuple[str, ...]] = []
        for data in closure.values():
            tokens = _significant(data)
            for index, (token, _start, _end) in enumerate(tokens):
                if token != alias or index + 1 >= len(tokens) or tokens[index + 1][0] != ";":
                    continue
                cursor = index - 1
                while cursor >= 0 and tokens[cursor][0] not in {";", "{", "}"}:
                    if tokens[cursor][0] == "typedef":
                        candidates.append(tuple(item[0] for item in tokens[cursor + 1 : index]))
                        break
                    cursor -= 1
        _need(
            len(candidates) == 1 and bool(candidates[0]),
            f"{context} typedef is absent or ambiguous in its include closure",
        )
        current = candidates[0]


def _owner_from_mangled(mangled: object, context: str) -> str:
    text = _string(mangled, context)
    constructor = re.match(r"^\?\?[01]([A-Za-z_][A-Za-z0-9_]*)@@", text)
    ordinary = re.match(r"^\?[A-Za-z_][A-Za-z0-9_]*@([A-Za-z_][A-Za-z0-9_]*)@@", text)
    match = constructor or ordinary
    _need(match is not None, f"{context} is outside the closed member form")
    return cast(re.Match[str], match).group(1)


def _source_owner(target: bytes, expected: str, context: str) -> None:
    tokens = _significant(target)
    opening = next((index for index, item in enumerate(tokens) if item[0] == "{"), None)
    _need(opening is not None, f"{context} has no body")
    qualifiers = [
        index for index, item in enumerate(tokens[: cast(int, opening)]) if item[0] == "::"
    ]
    _need(
        bool(qualifiers) and tokens[qualifiers[-1] - 1][0] == expected,
        f"{context} owner differs",
    )


def _lexical_stack(
    tokens: Sequence[tuple[str, int, int]], position: int, context: str
) -> tuple[int, ...]:
    stack: list[int] = []
    serial = 0
    for token, start, _end in tokens:
        if start >= position:
            break
        if token == "{":
            serial += 1
            stack.append(serial)
        elif token == "}":
            _need(bool(stack), f"{context} braces are unbalanced")
            stack.pop()
    return tuple(stack)


def _require_identifier_fresh_at_seat(
    target: bytes, seat: int, identifier: str, context: str
) -> None:
    """Reject only identifiers visible from the destination lexical block."""

    _need(0 <= seat <= len(target), f"{context} seat leaves its target")
    tokens = _significant(target)
    scopes: list[list[int | None]] = []
    stack: list[list[int | None]] = []
    for token, start, end in tokens:
        if token == "{":
            scope: list[int | None] = [end, None]
            scopes.append(scope)
            stack.append(scope)
        elif token == "}":
            _need(bool(stack), f"{context} braces are unbalanced")
            stack.pop()[1] = start
    _need(
        not stack and bool(scopes) and all(scope[1] is not None for scope in scopes),
        f"{context} braces are unbalanced",
    )

    def contains(scope: Sequence[int | None], position: int) -> bool:
        return cast(int, scope[0]) <= position <= cast(int, scope[1])

    ancestors = [scope for scope in scopes if contains(scope, seat)]
    _need(bool(ancestors), f"{context} seat has no lexical scope")
    target_scope = min(
        ancestors,
        key=lambda scope: cast(int, scope[1]) - cast(int, scope[0]),
    )
    ancestor_ids = {id(scope) for scope in ancestors}
    for token, position, _end in tokens:
        if token != identifier:
            continue
        _need(
            not contains(target_scope, position),
            f"{context} local is not fresh in its destination block",
        )
        containing = [scope for scope in scopes if contains(scope, position)]
        _need(bool(containing), f"{context} local collides with the function declaration")
        occurrence_scope = min(
            containing,
            key=lambda scope: cast(int, scope[1]) - cast(int, scope[0]),
        )
        _need(
            id(occurrence_scope) not in ancestor_ids,
            f"{context} local collides with a visible ancestor",
        )
