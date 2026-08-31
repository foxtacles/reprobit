"""Strict current-run include traces for classic Microsoft compilers.

Visual C++ 4.x predates ``/showIncludes``.  Its supported ``/Fr`` browser
output contains a complete, nested ENTER/LEAVE stream, which ReproBit parses
without executing an external helper.  Resolution is deliberately DOS-case
aware and closed over caller-supplied sealed logical roots.
"""

from __future__ import annotations

import ntpath
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import PureWindowsPath
from types import MappingProxyType

from reprobit.model import Digest
from reprobit.paths import PathContractError, normalize_logical_path


class ClassicIncludeTraceError(ValueError):
    """A compiler dependency trace is malformed or leaves sealed authority."""


class IncludeOrigin(StrEnum):
    PROJECT_SOURCE = "project-source"
    TOOLCHAIN_TREE = "toolchain-tree"
    DONOR_ARENA = "donor-arena"


@dataclass(frozen=True, slots=True)
class MsvcSbrSource:
    raw_path: str
    parent_index: int | None


@dataclass(frozen=True, slots=True)
class MsvcSbrTrace:
    working_directory: str
    sources: tuple[MsvcSbrSource, ...]


@dataclass(frozen=True, slots=True)
class SealedIncludeFile:
    logical_path: str
    digest: Digest
    size: int
    origin: IncludeOrigin


@dataclass(frozen=True, slots=True)
class SealedIncludeAuthority:
    logical_roots: tuple[str, ...]
    files: tuple[SealedIncludeFile, ...]

    def __post_init__(self) -> None:
        roots = tuple(normalize_logical_path(item) for item in self.logical_roots)
        if (
            roots != self.logical_roots
            or len({item.casefold() for item in roots}) != len(roots)
            or tuple(sorted(roots, key=str.casefold)) != roots
        ):
            raise ClassicIncludeTraceError("include authority roots are not unique and canonical")
        for index, left in enumerate(roots):
            for right in roots[index + 1 :]:
                if _within(left, right) or _within(right, left):
                    raise ClassicIncludeTraceError(
                        "include authority roots overlap under DOS path semantics"
                    )
        folded = [item.logical_path.casefold() for item in self.files]
        if len(folded) != len(set(folded)):
            raise ClassicIncludeTraceError("include authority contains DOS-case-colliding files")
        if tuple(sorted(self.files, key=lambda item: item.logical_path.casefold())) != (self.files):
            raise ClassicIncludeTraceError("include authority files are not canonical")
        for item in self.files:
            if normalize_logical_path(item.logical_path) != item.logical_path:
                raise ClassicIncludeTraceError(
                    f"include authority path is not canonical: {item.logical_path!r}"
                )
            containing_roots = tuple(root for root in roots if _within(item.logical_path, root))
            if item.size < 0 or len(containing_roots) != 1:
                raise ClassicIncludeTraceError(
                    f"include authority file escapes its roots: {item.logical_path!r}"
                )


@dataclass(frozen=True, slots=True)
class SealedIncludeIndex:
    """One reusable DOS-folded lookup index bound to an authority instance."""

    authority: SealedIncludeAuthority
    by_path: Mapping[str, SealedIncludeFile]


def index_sealed_include_authority(
    authority: SealedIncludeAuthority,
) -> SealedIncludeIndex:
    return SealedIncludeIndex(
        authority,
        MappingProxyType({item.logical_path.casefold(): item for item in authority.files}),
    )


@dataclass(frozen=True, slots=True)
class ResolvedInclude:
    raw_path: str
    logical_path: str
    digest: Digest
    size: int
    origin: IncludeOrigin
    parent_index: int | None


def resolve_sealed_logical_read(
    raw_path: str,
    *,
    search_roots: tuple[str, ...],
    authority: SealedIncludeAuthority,
    first_match: bool = False,
) -> SealedIncludeFile:
    """Resolve one producer read to exactly one file in a sealed DOS authority."""

    by_path = {item.logical_path.casefold(): item for item in authority.files}
    raw = _normal(raw_path)
    drive, _ = ntpath.splitdrive(raw)
    candidates: dict[str, SealedIncludeFile] = {}
    if drive or raw.startswith("\\"):
        base = search_roots[0] if search_roots else None
        logical = _absolute(raw, base=base)
        item = by_path.get(logical.casefold())
        if item is not None:
            candidates[item.logical_path.casefold()] = item
    else:
        for root in search_roots:
            canonical_root = _absolute(root)
            if not _within_any_root(canonical_root, authority.logical_roots):
                raise ClassicIncludeTraceError(
                    f"producer search root leaves sealed authority: {root!r}"
                )
            logical = _absolute(raw, base=canonical_root)
            item = by_path.get(logical.casefold())
            if item is not None:
                if first_match:
                    return item
                candidates[item.logical_path.casefold()] = item
    if len(candidates) != 1:
        raise ClassicIncludeTraceError(
            f"producer read {raw_path!r} resolves to {len(candidates)} sealed files"
        )
    return next(iter(candidates.values()))


class _Reader:
    def __init__(self, payload: bytes) -> None:
        if not payload or len(payload) > 64 * 1024 * 1024:
            raise ClassicIncludeTraceError("SBR payload size is invalid")
        self.payload = payload
        self.offset = 0

    def exact(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.payload):
            raise ClassicIncludeTraceError(f"SBR payload is truncated at offset 0x{self.offset:x}")
        result = self.payload[self.offset : end]
        self.offset = end
        return result

    def byte(self) -> int:
        return self.exact(1)[0]

    def word(self) -> int:
        return int(struct.unpack("<H", self.exact(2))[0])

    def address(self, width: int) -> int:
        if width not in {2, 3}:
            raise AssertionError("unsupported SBR address width")
        return int.from_bytes(self.exact(width), "little")

    def cstring(self) -> str:
        end = self.payload.find(b"\0", self.offset)
        if end < 0 or end - self.offset > 32768:
            raise ClassicIncludeTraceError(
                f"SBR string is missing or oversized at offset 0x{self.offset:x}"
            )
        raw = self.payload[self.offset : end]
        self.offset = end + 1
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ClassicIncludeTraceError("SBR paths and identifiers must be ASCII") from exc
        if not value or "\0" in value:
            raise ClassicIncludeTraceError("SBR string is empty or invalid")
        return value

    @property
    def done(self) -> bool:
        return self.offset == len(self.payload)


def _bind_identifier(
    reader: _Reader,
    identifiers: dict[int, str],
    *,
    identifier_width: int,
    name_width: int | None = None,
) -> None:
    identifier_code = reader.address(identifier_width)
    if identifier_code not in {0x01, 0x02, 0x21, 0x22, 0x40, 0x60}:
        # VC4 browser streams permit forward symbol references.  They carry no
        # payload beyond this fixed-width code and cannot affect source nesting.
        return
    name_code = reader.address(name_width or identifier_width)
    name = reader.cstring()
    previous = identifiers.setdefault(name_code, name)
    if previous != name:
        raise ClassicIncludeTraceError("SBR identifier table is inconsistent")


def _statement(reader: _Reader, identifiers: dict[int, str], width: int) -> None:
    kind = reader.byte()
    if kind in {1, 3, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17}:
        reader.word()
        code = reader.address(width)
        name = reader.cstring()
        previous = identifiers.setdefault(code, name)
        if previous != name:
            raise ClassicIncludeTraceError("SBR statement identifier changed")
        return
    if kind == 4:
        _bind_identifier(
            reader,
            identifiers,
            identifier_width=2,
            name_width=width,
        )
        return
    raise ClassicIncludeTraceError(f"SBR statement opcode 0x{kind:02x} is unknown")


def parse_msvc_sbr(payload: bytes) -> MsvcSbrTrace:
    """Parse one complete VC4.x C/C++ browser-information stream."""

    reader = _Reader(payload)
    magic = reader.exact(5)
    if magic not in {b"\x00\x02\x00\x02\x00", b"\x00\x02\x00\x07\x00"}:
        raise ClassicIncludeTraceError("SBR payload has an unsupported compiler magic")
    working_directory = reader.cstring()
    identifiers: dict[int, str] = {}
    sources: list[MsvcSbrSource] = []
    stack: list[int] = []
    while not reader.done:
        raw_opcode = reader.byte()
        width = 3 if raw_opcode & 0x40 else 2
        opcode = raw_opcode & ~0x40
        if opcode == 1:
            if len(sources) >= 100_000 or len(stack) >= 4096:
                raise ClassicIncludeTraceError("SBR source nesting is excessive")
            source = MsvcSbrSource(reader.cstring(), stack[-1] if stack else None)
            sources.append(source)
            stack.append(len(sources) - 1)
        elif opcode == 2:
            reader.word()
        elif opcode == 3:
            _statement(reader, identifiers, width)
        elif opcode == 4:
            _bind_identifier(reader, identifiers, identifier_width=width)
        elif opcode in {7, 8, 9}:
            continue
        elif opcode == 10:
            if not stack:
                raise ClassicIncludeTraceError("SBR source stack underflow")
            stack.pop()
        elif opcode in {11, 13}:
            reader.address(width)
        elif opcode == 12:
            while True:
                parent_type = reader.address(width)
                if parent_type not in identifiers:
                    raise ClassicIncludeTraceError(
                        "SBR parent class references an unknown identifier"
                    )
                parent_opcode = reader.word()
                if parent_opcode in {0x0C02, 0x0C03, 0x0C04, 0x0C05, 0x4C04}:
                    width = 3 if parent_opcode & 0x4000 else 2
                    continue
                if parent_opcode in {0x0902, 0x0904}:
                    break
                if parent_opcode in {0x0202, 0x0203, 0x0204, 0x0205, 0x0208}:
                    reader.word()
                    break
                raise ClassicIncludeTraceError(
                    f"SBR parent opcode 0x{parent_opcode:04x} is unknown"
                )
        else:
            raise ClassicIncludeTraceError(f"SBR opcode 0x{raw_opcode:02x} is unknown")
    if stack:
        raise ClassicIncludeTraceError("SBR source stack is unterminated")
    if not sources or sources[0].parent_index is not None:
        raise ClassicIncludeTraceError("SBR payload has no unique primary source")
    return MsvcSbrTrace(working_directory, tuple(sources))


def _normal(value: str) -> str:
    return value.replace("/", "\\")


@lru_cache(maxsize=32_768)
def _absolute(value: str, *, base: str | None = None) -> str:
    raw = _normal(value)
    if not raw or raw.startswith("\\\\") or value.startswith("/"):
        raise ClassicIncludeTraceError(f"include path is not a DOS path: {value!r}")
    drive, _ = ntpath.splitdrive(raw)
    if drive:
        candidate = raw
    elif raw.startswith("\\"):
        if base is None:
            raise ClassicIncludeTraceError(f"rooted include path lacks a drive: {value!r}")
        candidate = PureWindowsPath(base).drive + raw
    elif base is not None:
        candidate = ntpath.join(base, raw)
    else:
        raise ClassicIncludeTraceError(f"relative include path lacks a base: {value!r}")
    try:
        return normalize_logical_path(ntpath.normpath(candidate))
    except PathContractError as exc:
        raise ClassicIncludeTraceError(f"include path is unsafe: {value!r}") from exc


def _within(path: str, root: str) -> bool:
    try:
        return ntpath.normcase(ntpath.commonpath((path, root))) == ntpath.normcase(root)
    except ValueError:
        return False


def _within_any_root(path: str, roots: tuple[str, ...]) -> bool:
    return any(_within(path, root) for root in roots)


def _canonical_search_roots(
    values: tuple[str, ...], *, working_directory: str, authority_roots: tuple[str, ...]
) -> tuple[str, ...]:
    result: dict[str, str] = {}
    for value in values:
        raw = _normal(value)
        drive, _ = ntpath.splitdrive(raw)
        root = _absolute(value, base=None if drive else working_directory)
        if not _within_any_root(root, authority_roots):
            raise ClassicIncludeTraceError(
                f"compiler include search root leaves sealed authority: {value!r}"
            )
        result.setdefault(root.casefold(), root)
    return tuple(result.values())


def resolve_msvc_include_trace(
    trace: MsvcSbrTrace,
    *,
    expected_working_directory: str,
    expected_source: str,
    include_directories: tuple[str, ...],
    environment_directories: tuple[str, ...],
    force_includes: tuple[str, ...],
    authority: SealedIncludeAuthority,
    authority_index: SealedIncludeIndex | None = None,
) -> tuple[ResolvedInclude, ...]:
    """Resolve every SBR ENTER record uniquely within sealed logical roots."""

    working_directory = _absolute(trace.working_directory)
    expected_working_directory = _absolute(expected_working_directory)
    expected_source = _absolute(expected_source)
    if working_directory.casefold() != expected_working_directory.casefold():
        raise ClassicIncludeTraceError("SBR working directory differs from the invocation")
    if authority_index is None:
        authority_index = index_sealed_include_authority(authority)
    elif authority_index.authority is not authority:
        raise ClassicIncludeTraceError("sealed include index is bound to a different authority")
    by_path = authority_index.by_path
    if expected_source.casefold() not in by_path:
        raise ClassicIncludeTraceError("compiler source is outside sealed include authority")
    search_roots = _canonical_search_roots(
        (*include_directories, *environment_directories),
        working_directory=working_directory,
        authority_roots=authority.logical_roots,
    )
    resolved: list[ResolvedInclude] = []
    for index, source in enumerate(trace.sources):
        if source.parent_index is not None and not 0 <= source.parent_index < index:
            raise ClassicIncludeTraceError("SBR source parent is invalid")
        raw = _normal(source.raw_path)
        drive, _ = ntpath.splitdrive(raw)
        candidates: dict[str, SealedIncludeFile] = {}
        if drive or raw.startswith("\\"):
            logical = _absolute(raw, base=working_directory)
            item = by_path.get(logical.casefold())
            if item is not None:
                candidates[item.logical_path.casefold()] = item
        else:
            roots: list[str] = []
            if index == 0:
                roots.append(ntpath.dirname(expected_source))
            if source.parent_index is not None:
                roots.append(ntpath.dirname(resolved[source.parent_index].logical_path))
            roots.extend((working_directory, *search_roots))
            for root in roots:
                logical = _absolute(raw, base=root)
                item = by_path.get(logical.casefold())
                if item is not None:
                    candidates[item.logical_path.casefold()] = item
        if len(candidates) != 1:
            raise ClassicIncludeTraceError(
                f"SBR source {source.raw_path!r} resolves to {len(candidates)} sealed files"
            )
        item = next(iter(candidates.values()))
        resolved.append(
            ResolvedInclude(
                source.raw_path,
                item.logical_path,
                item.digest,
                item.size,
                item.origin,
                source.parent_index,
            )
        )
    if resolved[0].logical_path.casefold() != expected_source.casefold():
        raise ClassicIncludeTraceError("SBR primary source differs from the invocation")
    resolved_paths = {item.logical_path.casefold() for item in resolved}
    for force_include in force_includes:
        raw = _normal(force_include)
        drive, _ = ntpath.splitdrive(raw)
        if drive or raw.startswith("\\"):
            logical = _absolute(raw, base=working_directory)
            forced_candidates = {logical.casefold()} & set(by_path)
        else:
            forced_candidates = {
                _absolute(raw, base=root).casefold() for root in (working_directory, *search_roots)
            } & set(by_path)
        if len(forced_candidates) != 1 or not forced_candidates.issubset(resolved_paths):
            raise ClassicIncludeTraceError(
                f"forced include {force_include!r} is absent or ambiguous in the SBR trace"
            )
    return tuple(resolved)


__all__ = [
    "ClassicIncludeTraceError",
    "IncludeOrigin",
    "MsvcSbrSource",
    "MsvcSbrTrace",
    "ResolvedInclude",
    "SealedIncludeAuthority",
    "SealedIncludeFile",
    "SealedIncludeIndex",
    "index_sealed_include_authority",
    "parse_msvc_sbr",
    "resolve_msvc_include_trace",
    "resolve_sealed_logical_read",
]
