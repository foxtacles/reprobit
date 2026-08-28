"""Closed recursive-read analysis for classic Microsoft resource scripts.

Microsoft RC 4.x has no complete dependency-trace mode.  Certification uses a
strict, deliberately small parser over the exact sealed bytes instead: every
literal preprocessor include and every file-backed resource operand is resolved
inside the same DOS-path authority used by the compiler trace.  Unsupported
forms fail closed instead of being guessed.
"""

from __future__ import annotations

import ntpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    SealedIncludeAuthority,
    resolve_sealed_logical_read,
)
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path


class ClassicResourceDependencyError(ValueError):
    """A resource script has an unprovable or authority-escaping read."""


class ResourceReadKind(StrEnum):
    ROOT = "root"
    INCLUDE = "include"
    PAYLOAD = "resource-payload"


@dataclass(frozen=True, slots=True)
class ResourceRead:
    logical_path: str
    digest: Digest
    size: int
    origin: IncludeOrigin
    kind: ResourceReadKind
    parent_path: str | None


@dataclass(frozen=True, slots=True)
class ResourceDependencyReceipt:
    source_path: str
    reads: tuple[ResourceRead, ...]


_INCLUDE = re.compile(r"^\s*#\s*include\s*(.*?)\s*$", re.IGNORECASE)
_DIRECTIVE = re.compile(r"^\s*#\s*([A-Za-z_][A-Za-z0-9_]*)\b(.*?)$", re.IGNORECASE)
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s,]+|,')
_CONDITIONAL_OPEN = frozenset({"if", "ifdef", "ifndef"})
_CONDITIONAL_MIDDLE = frozenset({"elif", "else"})
_CONDITIONAL_CLOSE = frozenset({"endif"})
_PASSIVE_DIRECTIVES = frozenset(
    {"define", "undef", "pragma", "error", "line", "warning"}
)
_RESOURCE_FILE_TYPES = frozenset(
    {
        "aniicon",
        "anicursor",
        "avi",
        "bitmap",
        "cursor",
        "dlginIt".casefold(),
        "font",
        "html",
        "icon",
        "messagetable",
        "plugplay",
        "vxd",
    }
)
_OPTIONAL_FILE_TYPES = frozenset({"rcdata"})
_LOAD_MEMORY_OPTIONS = frozenset(
    {
        "preload",
        "loadoncall",
        "fixed",
        "moveable",
        "pure",
        "impure",
        "discardable",
    }
)
_PATHLIKE = re.compile(r"(?i)(?:[\\/]|\.[A-Za-z0-9]{1,16}$)")


def _strip_comments(payload: bytes, *, label: str) -> str:
    if b"\0" in payload:
        raise ClassicResourceDependencyError(f"{label} contains NUL bytes")
    text = payload.decode("latin-1")
    if re.search(r"\\\r?\n", text):
        raise ClassicResourceDependencyError(
            f"{label} uses a continued line that the closed RC scanner forbids"
        )
    output: list[str] = []
    index = 0
    block = False
    string = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if block:
            if char == "*" and following == "/":
                block = False
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if string:
            output.append(char)
            if char == "\\" and following:
                output.append(following)
                index += 2
                continue
            if char == '"':
                string = False
            index += 1
            continue
        if char == "/" and following == "*":
            block = True
            output.extend("  ")
            index += 2
            continue
        if char == "/" and following == "/":
            while index < len(text) and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        output.append(char)
        if char == '"':
            string = True
        index += 1
    if block or string:
        raise ClassicResourceDependencyError(
            f"{label} has an unterminated comment or string"
        )
    return "".join(output)


def _quoted_path(token: str, *, label: str) -> str:
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise ClassicResourceDependencyError(
            f"{label} requires one literal quoted path"
        )
    value = token[1:-1]
    if not value or '"' in value or "\0" in value:
        raise ClassicResourceDependencyError(f"{label} has an invalid path literal")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ClassicResourceDependencyError(
            f"{label} path literals must be ASCII"
        ) from exc
    return value


def _payload_map(
    authority: SealedIncludeAuthority,
    payloads: Mapping[str, bytes],
) -> Mapping[str, bytes]:
    folded: dict[str, bytes] = {}
    for path, payload in payloads.items():
        normalized = normalize_logical_path(path)
        if normalized != path or path.casefold() in folded:
            raise ClassicResourceDependencyError(
                "resource payload authority is not canonical and unique"
            )
        folded[path.casefold()] = payload
    expected = {item.logical_path.casefold(): item for item in authority.files}
    if set(folded) != set(expected):
        raise ClassicResourceDependencyError(
            "resource payload bytes differ from sealed include authority"
        )
    for folded_path, item in expected.items():
        payload = folded[folded_path]
        if len(payload) != item.size or Digest.from_bytes(payload) != item.digest:
            raise ClassicResourceDependencyError(
                f"resource payload changed after sealing: {item.logical_path!r}"
            )
    return MappingProxyType(folded)


def scan_msvc_resource_dependencies(
    *,
    source_path: str,
    include_directories: tuple[str, ...],
    environment_directories: tuple[str, ...],
    authority: SealedIncludeAuthority,
    payloads: Mapping[str, bytes],
) -> ResourceDependencyReceipt:
    """Conservatively scan every possible literal RC include and payload read.

    Conditional branches are all scanned, so no preprocessor evaluation is
    trusted.  Macro-expanded includes or payload names cannot be proven by this
    grammar and are rejected.
    """

    source_path = normalize_logical_path(source_path.replace("/", "\\"))
    source_drive = ntpath.splitdrive(source_path)[0]

    def search_directory(value: str) -> str:
        raw = value.replace("/", "\\")
        drive, _tail = ntpath.splitdrive(raw)
        if not drive and raw.startswith("\\") and not raw.startswith("\\\\"):
            raw = source_drive + raw
        return normalize_logical_path(raw)

    payload_by_path = _payload_map(authority, payloads)
    by_path = {item.logical_path.casefold(): item for item in authority.files}
    source = by_path.get(source_path.casefold())
    if source is None:
        raise ClassicResourceDependencyError(
            "resource root source is outside sealed authority"
        )
    for directory in (*include_directories, *environment_directories):
        canonical = search_directory(directory)
        if not any(
            ntpath.commonpath((canonical, root)).casefold() == root.casefold()
            for root in authority.logical_roots
            if ntpath.splitdrive(canonical)[0].casefold()
            == ntpath.splitdrive(root)[0].casefold()
        ):
            raise ClassicResourceDependencyError(
                f"resource include root leaves sealed authority: {directory!r}"
            )
    include_directories = tuple(
        search_directory(item) for item in include_directories
    )
    environment_directories = tuple(
        search_directory(item) for item in environment_directories
    )

    reads: list[ResourceRead] = [
        ResourceRead(
            source.logical_path,
            source.digest,
            source.size,
            source.origin,
            ResourceReadKind.ROOT,
            None,
        )
    ]
    pending = [source]
    scanned: set[str] = set()
    while pending:
        current = pending.pop()
        folded_current = current.logical_path.casefold()
        if folded_current in scanned:
            continue
        scanned.add(folded_current)
        payload = payload_by_path[folded_current]
        text = _strip_comments(payload, label=current.logical_path)
        conditional_stack: list[bool] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            directive = _DIRECTIVE.match(line)
            if directive is not None:
                name = directive.group(1).casefold()
                if name == "include":
                    match = _INCLUDE.match(line)
                    if match is None:
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: malformed include"
                        )
                    operand = match.group(1)
                    quoted = operand.startswith('"') and operand.endswith('"')
                    angled = operand.startswith("<") and operand.endswith(">")
                    if not (quoted or angled):
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: macro include is forbidden"
                        )
                    raw_path = operand[1:-1]
                    if not raw_path or any(char in raw_path for char in '"<>'):
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: include path is invalid"
                        )
                    roots = (
                        (() if angled else (ntpath.dirname(current.logical_path),))
                        + include_directories
                        + environment_directories
                    )
                    try:
                        included = resolve_sealed_logical_read(
                            raw_path,
                            search_roots=roots,
                            authority=authority,
                            first_match=True,
                        )
                    except ClassicIncludeTraceError as exc:
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: {exc}"
                        ) from exc
                    reads.append(
                        ResourceRead(
                            included.logical_path,
                            included.digest,
                            included.size,
                            included.origin,
                            ResourceReadKind.INCLUDE,
                            current.logical_path,
                        )
                    )
                    pending.append(included)
                elif name in _CONDITIONAL_OPEN:
                    conditional_stack.append(False)
                elif name in _CONDITIONAL_MIDDLE:
                    if not conditional_stack:
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: unmatched #{name}"
                        )
                    if name == "else":
                        if conditional_stack[-1]:
                            raise ClassicResourceDependencyError(
                                f"{current.logical_path}:{line_number}: repeated #else"
                            )
                        conditional_stack[-1] = True
                elif name in _CONDITIONAL_CLOSE:
                    if not conditional_stack:
                        raise ClassicResourceDependencyError(
                            f"{current.logical_path}:{line_number}: unmatched #endif"
                        )
                    conditional_stack.pop()
                elif name not in _PASSIVE_DIRECTIVES:
                    raise ClassicResourceDependencyError(
                        f"{current.logical_path}:{line_number}: unknown directive #{name}"
                    )
                continue

            tokens = _TOKEN.findall(line)
            significant = [item for item in tokens if item != ","]
            if (
                len(significant) < 3
                or significant[0].startswith('"')
                or significant[1].startswith('"')
            ):
                continue
            resource_type = significant[1].casefold()
            index = 2
            while (
                index < len(significant)
                and significant[index].casefold() in _LOAD_MEMORY_OPTIONS
            ):
                index += 1
            operand = significant[index] if index < len(significant) else ""
            file_backed = resource_type in _RESOURCE_FILE_TYPES
            optional_file = resource_type in _OPTIONAL_FILE_TYPES
            if file_backed and not operand.startswith('"'):
                raise ClassicResourceDependencyError(
                    f"{current.logical_path}:{line_number}: file-backed "
                    f"{resource_type} lacks a literal path"
                )
            if not file_backed and not (optional_file and operand.startswith('"')):
                if (
                    operand.startswith('"')
                    and operand.endswith('"')
                    and _PATHLIKE.search(operand[1:-1])
                ):
                    raise ClassicResourceDependencyError(
                        f"{current.logical_path}:{line_number}: unknown file-backed "
                        "resource form"
                    )
                continue
            raw_path = _quoted_path(
                operand,
                label=f"{current.logical_path}:{line_number} {resource_type}",
            )
            try:
                resource = resolve_sealed_logical_read(
                    raw_path,
                    search_roots=(
                        ntpath.dirname(current.logical_path),
                        *include_directories,
                        *environment_directories,
                    ),
                    authority=authority,
                    first_match=True,
                )
            except ClassicIncludeTraceError as exc:
                raise ClassicResourceDependencyError(
                    f"{current.logical_path}:{line_number}: {exc}"
                ) from exc
            reads.append(
                ResourceRead(
                    resource.logical_path,
                    resource.digest,
                    resource.size,
                    resource.origin,
                    ResourceReadKind.PAYLOAD,
                    current.logical_path,
                )
            )
        if conditional_stack:
            raise ClassicResourceDependencyError(
                f"{current.logical_path}: unterminated conditional directive"
            )
    return ResourceDependencyReceipt(source.logical_path, tuple(reads))


__all__ = [
    "ClassicResourceDependencyError",
    "ResourceDependencyReceipt",
    "ResourceRead",
    "ResourceReadKind",
    "scan_msvc_resource_dependencies",
]
