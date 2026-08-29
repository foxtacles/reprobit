"""Closed linker-control inputs for classic producer-graph execution.

Classic COFF objects can extend a link command through ``.drectve`` sections,
and module-definition files can name exports or (through ``STUB``) cause an
otherwise invisible file read.  This module turns both inputs into small,
immutable receipts before the linker is allowed to run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType

from reprobit.classic.coff_evidence import (
    ClassicImportObjectReceipt,
    CoffDirectiveReceipt,
    parse_classic_archive_member_directives,
    parse_classic_coff_directives,
    parse_classic_import_object,
)
from reprobit.formats import FormatError, parse_coff_archive
from reprobit.model import Digest
from reprobit.producer_graph import ProducerNode, ProducerRole


class ClassicLinkClosureError(ValueError):
    """A linker input contains an unmodeled control or hidden read."""


class MissingDirectiveInputsError(ClassicLinkClosureError):
    """Effective DEFAULTLIB controls lack committed directive input edges."""

    def __init__(self, libraries: tuple[str, ...]) -> None:
        super().__init__(
            "DEFAULTLIB controls lack committed directive inputs: " + ", ".join(libraries)
        )
        self.libraries = libraries


@dataclass(frozen=True, slots=True)
class CoffDirectiveInputReceipt:
    """Directives parsed from one complete ordinary COFF input."""

    label: str
    digest: Digest
    size: int
    directives: CoffDirectiveReceipt


@dataclass(frozen=True, slots=True)
class CoffArchiveDirectiveReceipt:
    """Complete member classification for one raw archive."""

    reference: str
    digest: Digest
    size: int
    member_count: int
    content_member_count: int
    ordinary_members: tuple[CoffDirectiveInputReceipt, ...]
    import_members: tuple[ClassicImportObjectReceipt, ...]


@dataclass(frozen=True, slots=True)
class DefaultLibraryResolution:
    """One effective ``DEFAULTLIB`` name bound to one declared graph edge."""

    name: str
    reference: str


@dataclass(frozen=True, slots=True)
class ClassicLinkDirectiveClosure:
    """Complete hidden linker-control closure for one target."""

    objects: tuple[CoffDirectiveInputReceipt, ...]
    archives: tuple[CoffArchiveDirectiveReceipt, ...]
    default_libraries: tuple[DefaultLibraryResolution, ...]
    include_symbols: tuple[str, ...]
    export_symbols: tuple[str, ...]
    merge_sections: tuple[tuple[str, str], ...]
    disallowed_libraries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModuleDefinitionReceipt:
    """Strictly parsed, file-read-free module-definition authority."""

    label: str
    digest: Digest
    size: int
    module_name: str | None
    description: str | None
    exports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TerminalLinkControlReferences:
    """The direct file controls visible to one terminal LINK invocation."""

    objects: tuple[str, ...]
    archives: tuple[str, ...]
    definitions: tuple[str, ...]


def direct_terminal_link_control_references(
    linker: ProducerNode,
) -> TerminalLinkControlReferences:
    """Classify only files consumed by ``linker``, stopping at linked targets."""

    if linker.role is not ProducerRole.LINKER or linker.target_id is None:
        raise ClassicLinkClosureError(
            "terminal link-control references require one terminal linker node"
        )

    def suffix(reference: str) -> str:
        return PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold()

    objects = tuple(
        sorted(
            (reference for reference in linker.inputs if suffix(reference) == ".obj"),
            key=str.casefold,
        )
    )
    archives = tuple(
        sorted(
            (
                reference
                for reference in (*linker.inputs, *linker.directive_inputs)
                if suffix(reference) in {".a", ".lib"}
            ),
            key=str.casefold,
        )
    )
    definitions = tuple(reference for reference in linker.inputs if suffix(reference) == ".def")
    if len(definitions) > 1:
        raise ClassicLinkClosureError(f"target {linker.target_id!r} names more than one DEF input")
    return TerminalLinkControlReferences(objects, archives, definitions)


def link_directive_closure_material(closure: ClassicLinkDirectiveClosure) -> object:
    """Return the one canonical JSON-shaped cold/warm closure identity."""

    def ordinary(receipt: CoffDirectiveInputReceipt) -> object:
        return {
            "label": receipt.label,
            "digest": receipt.digest.model_dump(mode="json"),
            "size": receipt.size,
            "tokens": list(receipt.directives.tokens),
            "default_libraries": list(receipt.directives.default_libraries),
            "include_symbols": list(receipt.directives.include_symbols),
            "export_symbols": list(receipt.directives.export_symbols),
            "merge_sections": [list(value) for value in receipt.directives.merge_sections],
            "disallowed_libraries": list(receipt.directives.disallowed_libraries),
        }

    return {
        "objects": [ordinary(item) for item in closure.objects],
        "archives": [
            {
                "reference": archive.reference,
                "digest": archive.digest.model_dump(mode="json"),
                "size": archive.size,
                "member_count": archive.member_count,
                "content_member_count": archive.content_member_count,
                "ordinary_members": [ordinary(item) for item in archive.ordinary_members],
                "import_members": [
                    {
                        "label": item.label,
                        "digest": item.digest.model_dump(mode="json"),
                        "symbol": item.symbol,
                        "dll": item.dll,
                        "import_type": item.import_type,
                        "name_type": item.name_type,
                        "definitions": sorted(item.definitions, key=str.casefold),
                    }
                    for item in archive.import_members
                ],
            }
            for archive in closure.archives
        ],
        "default_libraries": [
            {"name": item.name, "reference": item.reference} for item in closure.default_libraries
        ],
        "include_symbols": list(closure.include_symbols),
        "export_symbols": list(closure.export_symbols),
        "merge_sections": [list(value) for value in closure.merge_sections],
        "disallowed_libraries": list(closure.disallowed_libraries),
    }


def module_definition_material(receipt: ModuleDefinitionReceipt | None) -> object:
    """Return the canonical JSON-shaped module-definition identity."""

    if receipt is None:
        return None
    return {
        "label": receipt.label,
        "digest": receipt.digest.model_dump(mode="json"),
        "size": receipt.size,
        "module_name": receipt.module_name,
        "description": receipt.description,
        "exports": list(receipt.exports),
    }


_LIBRARY_NAME = re.compile(r"(?i)^(?:library|name)(?:\s+([^\s]+))?(?:\s+base=(?:0x)?[0-9a-f]+)?$")
_EXPORT_SYMBOL = re.compile(r"^[A-Za-z0-9_?$@.]+$")
_EXPORT_ORDINAL = re.compile(r"^@[0-9]+$")


def _strip_def_comment(line: str, *, label: str, line_number: int) -> str:
    quote: str | None = None
    output: list[str] = []
    for character in line:
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            output.append(character)
            continue
        if character == ";" and quote is None:
            break
        if ord(character) < 0x20 and character != "\t":
            raise ClassicLinkClosureError(
                f"{label} line {line_number} contains a control character"
            )
        output.append(character)
    if quote is not None:
        raise ClassicLinkClosureError(
            f"{label} line {line_number} has an unterminated quoted value"
        )
    return "".join(output).strip()


def _def_export(line: str, *, label: str, line_number: int) -> str:
    fields = line.split()
    if not fields:
        raise ClassicLinkClosureError(f"{label} line {line_number} has an empty export")
    declaration = fields.pop(0)
    names = declaration.split("=", 1)
    if any(_EXPORT_SYMBOL.fullmatch(value) is None for value in names):
        raise ClassicLinkClosureError(
            f"{label} line {line_number} has a malformed export declaration"
        )
    saw_ordinal = False
    saw_flags: set[str] = set()
    for field in fields:
        if _EXPORT_ORDINAL.fullmatch(field):
            if saw_ordinal:
                raise ClassicLinkClosureError(
                    f"{label} line {line_number} repeats an export ordinal"
                )
            saw_ordinal = True
            continue
        folded = field.casefold()
        if folded not in {"data", "noname", "private"} or folded in saw_flags:
            raise ClassicLinkClosureError(
                f"{label} line {line_number} has an unsupported export attribute"
            )
        saw_flags.add(folded)
    return names[-1]


def parse_classic_module_definition(payload: bytes, *, label: str) -> ModuleDefinitionReceipt:
    """Parse the closed, read-free subset of the classic DEF grammar.

    ``STUB`` is rejected wherever it appears because its operand is a nested
    file read.  Other unsupported sections also fail closed instead of being
    mistaken for export rows.
    """

    if type(payload) is not bytes or not payload:
        raise ClassicLinkClosureError(f"{label} is not immutable DEF bytes")
    if not label or "\x00" in label:
        raise ClassicLinkClosureError("module-definition label is malformed")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClassicLinkClosureError(f"{label} is not ASCII") from exc
    if "\x00" in text:
        raise ClassicLinkClosureError(f"{label} contains a NUL byte")

    module_name: str | None = None
    description: str | None = None
    exports: list[str] = []
    in_exports = False
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_def_comment(raw_line, label=label, line_number=line_number)
        if not line:
            continue
        keyword, _, tail = line.partition(" ")
        folded = keyword.casefold()
        if folded == "stub":
            raise ClassicLinkClosureError(
                f"{label} line {line_number} declares forbidden STUB input"
            )
        if folded in {"library", "name"}:
            match = _LIBRARY_NAME.fullmatch(line)
            if match is None or module_name is not None:
                raise ClassicLinkClosureError(
                    f"{label} line {line_number} has a malformed/repeated module name"
                )
            module_name = match.group(1)
            in_exports = False
            continue
        if folded == "description":
            value = tail.strip()
            if (
                description is not None
                or len(value) < 2
                or value[0] not in {"'", '"'}
                or value[-1] != value[0]
            ):
                raise ClassicLinkClosureError(
                    f"{label} line {line_number} has a malformed/repeated DESCRIPTION"
                )
            description = value[1:-1]
            in_exports = False
            continue
        if folded == "exports":
            in_exports = True
            inline = tail.strip()
            if inline:
                exports.append(_def_export(inline, label=label, line_number=line_number))
            continue
        if folded in {
            "code",
            "data",
            "heapsize",
            "imports",
            "sections",
            "stacksize",
            "version",
        }:
            raise ClassicLinkClosureError(
                f"{label} line {line_number} uses unsupported DEF section {keyword!r}"
            )
        if not in_exports:
            raise ClassicLinkClosureError(
                f"{label} line {line_number} is outside the closed DEF grammar"
            )
        exports.append(_def_export(line, label=label, line_number=line_number))
    if len({item.casefold() for item in exports}) != len(exports):
        raise ClassicLinkClosureError(f"{label} repeats an export symbol")
    return ModuleDefinitionReceipt(
        label,
        Digest.from_bytes(payload),
        len(payload),
        module_name,
        description,
        tuple(exports),
    )


def _directive_input(payload: bytes, *, label: str) -> CoffDirectiveInputReceipt:
    try:
        directives = parse_classic_coff_directives(payload, label=label)
    except Exception as exc:
        raise ClassicLinkClosureError(f"cannot close directives for {label}: {exc}") from exc
    return CoffDirectiveInputReceipt(label, Digest.from_bytes(payload), len(payload), directives)


def _archive_directives(payload: bytes, *, reference: str) -> CoffArchiveDirectiveReceipt:
    try:
        parsed = parse_coff_archive(payload)
    except FormatError as exc:
        raise ClassicLinkClosureError(f"cannot parse archive {reference!r}: {exc}") from exc
    ordinary: list[CoffDirectiveInputReceipt] = []
    imports: list[ClassicImportObjectReceipt] = []
    content_count = 0
    for index, member in enumerate(parsed.members):
        if member.name in {"/", "//", "/SYM64/"}:
            continue
        content_count += 1
        label = f"{reference}({index}:{member.name})"
        try:
            imported = parse_classic_import_object(member.data, label=label)
            if imported is not None:
                imports.append(imported)
                continue
            directives = parse_classic_archive_member_directives(member.data, label=label)
        except Exception as exc:
            raise ClassicLinkClosureError(f"cannot classify archive member {label}: {exc}") from exc
        ordinary.append(
            CoffDirectiveInputReceipt(
                label,
                Digest.from_bytes(member.data),
                len(member.data),
                directives,
            )
        )
    if content_count == 0:
        raise ClassicLinkClosureError(f"archive {reference!r} has no content members")
    return CoffArchiveDirectiveReceipt(
        reference,
        Digest.from_bytes(payload),
        len(payload),
        len(parsed.members),
        content_count,
        tuple(ordinary),
        tuple(imports),
    )


def _normalized_library_name(value: str) -> str:
    folded = value.casefold()
    return folded if folded.endswith(".lib") else folded + ".lib"


def _node_default_suppression(arguments: Sequence[str]) -> tuple[bool, frozenset[str]]:
    suppress_all = False
    names: set[str] = set()
    for argument in arguments:
        folded = argument.casefold()
        if folded in {"/nodefaultlib", "-nodefaultlib"}:
            suppress_all = True
            continue
        if folded.startswith(("/nodefaultlib:", "-nodefaultlib:")):
            raw = argument.split(":", 1)[1]
            if not raw or re.fullmatch(r"[A-Za-z0-9_.+@-]+", raw) is None:
                raise ClassicLinkClosureError(f"malformed NODEFAULTLIB declaration {argument!r}")
            names.add(_normalized_library_name(raw))
    return suppress_all, frozenset(names)


def audit_classic_link_directives(
    *,
    object_inputs: Mapping[str, bytes],
    archive_inputs: Mapping[str, bytes],
    declared_archive_refs: Sequence[str],
    linker_arguments: Sequence[str],
) -> ClassicLinkDirectiveClosure:
    """Parse all hidden controls and bind effective default libraries to edges."""

    def unique(values: Mapping[str, bytes], label: str) -> Mapping[str, bytes]:
        folded: dict[str, tuple[str, bytes]] = {}
        for name, payload in values.items():
            if not name or "\x00" in name or type(payload) is not bytes or not payload:
                raise ClassicLinkClosureError(f"{label} input is malformed")
            previous = folded.setdefault(name.casefold(), (name, payload))
            if previous[0] != name:
                raise ClassicLinkClosureError(f"{label} labels collide by DOS case")
        return MappingProxyType(
            {
                name: payload
                for name, payload in sorted(values.items(), key=lambda item: item[0].casefold())
            }
        )

    objects = tuple(
        _directive_input(payload, label=label)
        for label, payload in unique(object_inputs, "COFF object").items()
    )
    archives = tuple(
        _archive_directives(payload, reference=reference)
        for reference, payload in unique(archive_inputs, "archive").items()
    )
    expected_archives = {item.casefold() for item in declared_archive_refs}
    actual_archives = {item.reference.casefold() for item in archives}
    if actual_archives != expected_archives:
        raise ClassicLinkClosureError(
            "raw archive directive closure differs from declared archive edges"
        )

    directive_receipts = [item.directives for item in objects]
    directive_receipts.extend(
        item.directives for archive in archives for item in archive.ordinary_members
    )
    suppress_all, suppressed_names = _node_default_suppression(linker_arguments)
    by_basename: dict[str, list[str]] = {}
    for reference in declared_archive_refs:
        basename = reference.rsplit("/", 1)[-1].casefold()
        by_basename.setdefault(basename, []).append(reference)
    disallowed = {
        _normalized_library_name(item)
        for receipt in directive_receipts
        for item in receipt.disallowed_libraries
    }
    forbidden_edges = sorted(disallowed.intersection(by_basename))
    if forbidden_edges:
        raise ClassicLinkClosureError(
            "DISALLOWLIB conflicts with declared archive edges: " + ", ".join(forbidden_edges)
        )
    resolutions: dict[str, DefaultLibraryResolution] = {}
    missing_libraries: set[str] = set()
    for receipt in directive_receipts:
        for raw_name in receipt.default_libraries:
            name = _normalized_library_name(raw_name)
            if suppress_all or name in suppressed_names:
                continue
            if name in disallowed:
                raise ClassicLinkClosureError(f"DEFAULTLIB {raw_name!r} conflicts with DISALLOWLIB")
            matches = by_basename.get(name, [])
            if not matches:
                missing_libraries.add(name)
                continue
            if len(matches) != 1:
                raise ClassicLinkClosureError(
                    f"DEFAULTLIB {raw_name!r} has {len(matches)} declared archive edges"
                )
            previous = resolutions.setdefault(name, DefaultLibraryResolution(name, matches[0]))
            if previous.reference.casefold() != matches[0].casefold():
                raise ClassicLinkClosureError(
                    f"DEFAULTLIB {raw_name!r} has inconsistent graph authority"
                )
    if missing_libraries:
        raise MissingDirectiveInputsError(tuple(sorted(missing_libraries)))
    includes = tuple(
        sorted(
            {item for receipt in directive_receipts for item in receipt.include_symbols},
            key=str.casefold,
        )
    )
    exports = tuple(
        sorted(
            {item for receipt in directive_receipts for item in receipt.export_symbols},
            key=str.casefold,
        )
    )
    merge_map: dict[str, tuple[str, str]] = {}
    for receipt in directive_receipts:
        for source, destination in receipt.merge_sections:
            merge_previous = merge_map.setdefault(source.casefold(), (source, destination))
            if merge_previous[1].casefold() != destination.casefold():
                raise ClassicLinkClosureError(
                    f"MERGE section {source!r} has conflicting destinations"
                )
    return ClassicLinkDirectiveClosure(
        objects,
        archives,
        tuple(sorted(resolutions.values(), key=lambda item: item.name)),
        includes,
        exports,
        tuple(sorted(merge_map.values(), key=lambda item: item[0].casefold())),
        tuple(sorted(disallowed)),
    )


__all__ = [
    "ClassicLinkClosureError",
    "ClassicLinkDirectiveClosure",
    "CoffArchiveDirectiveReceipt",
    "CoffDirectiveInputReceipt",
    "DefaultLibraryResolution",
    "MissingDirectiveInputsError",
    "ModuleDefinitionReceipt",
    "TerminalLinkControlReferences",
    "audit_classic_link_directives",
    "direct_terminal_link_control_references",
    "link_directive_closure_material",
    "module_definition_material",
    "parse_classic_module_definition",
]
