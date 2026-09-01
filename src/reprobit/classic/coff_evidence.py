"""Strict, closed i386 COFF evidence parsing for classic builds.

The parser rejects unknown or non-canonical structures.  Its receipts are the
single byte-level authority used by linker-closure and semantic proof code.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

_DEFAULTLIB = re.compile(r"(?i)^[/-]defaultlib:([a-z0-9_.+@-]+)$")
_DISALLOWLIB = re.compile(r"(?i)^[/-]disallowlib:([a-z0-9_.+@-]+)$")
_MERGE_SECTION = re.compile(r"(?i)^[/-]merge:([.$?@_a-z0-9-]+)=([.$?@_a-z0-9-]+)$")
_LINK_SYMBOL_CONTROL = re.compile(r"(?i)^[/-](include|export):([a-z0-9_?$@.]+)(?:,(data|noname))?$")

# Classic LINK/LIB's long-form import-library members carry two exact local
# section-name anchors without section-definition auxiliaries.  They are
# ordinary C_STAT relocation/debug anchors, not truncated section definitions.
# Keep this disposition archive-only and pinned to the two shapes observed in
# the complete supported VC4.2/VC5 library corpus; direct objects remain strict.
_ARCHIVE_AUXLESS_SECTION_ANCHORS = frozenset(
    {
        (0x014C, 0, 0x0100, ".debug$S", 0x42100040),
        (0x014C, 0x00E0, 0x0100, ".idata$6", 0xC0200040),
    }
)
_LONG_IMPORT_OPTIONAL_HEADER_LINKER_VERSION_OFFSETS = frozenset({2, 3})
_LONG_IMPORT_OPTIONAL_HEADER_INVARIANT_NONZERO = {
    0: 0x0B,
    1: 0x01,
    33: 0x10,
    37: 0x02,
    74: 0x10,
    77: 0x10,
    82: 0x10,
    85: 0x10,
    92: 0x10,
}


def _is_supported_long_import_optional_header(payload: bytes) -> bool:
    """Recognize the one invariant classic import-descriptor PE32 template."""

    if len(payload) != 0x00E0:
        return False
    if int.from_bytes(payload[40:42], "little") not in {1, 4} or any(payload[42:44]):
        return False
    return all(
        offset in _LONG_IMPORT_OPTIONAL_HEADER_LINKER_VERSION_OFFSETS
        or offset in {40, 41, 42, 43}
        or value == _LONG_IMPORT_OPTIONAL_HEADER_INVARIANT_NONZERO.get(offset, 0)
        for offset, value in enumerate(payload)
    )


@dataclass(frozen=True, slots=True)
class CoffDirectiveReceipt:
    """Strict linker controls carried by one ordinary COFF object."""

    tokens: tuple[str, ...]
    default_libraries: tuple[str, ...]
    include_symbols: tuple[str, ...]
    export_symbols: tuple[str, ...]
    merge_sections: tuple[tuple[str, str], ...] = ()
    disallowed_libraries: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _CoffSymbol:
    index: int
    name: str
    value: int
    section: int
    symbol_type: int
    storage: int
    auxiliary_count: int
    auxiliary: bytes


@dataclass(frozen=True, slots=True)
class _CoffRelocation:
    offset: int
    relocation_type: int
    target_index: int
    target: str
    target_section: int
    target_value: int
    target_type: int
    target_storage: int
    addend: bytes


@dataclass(frozen=True, slots=True)
class _CoffLineNumber:
    line_number: int
    address: int | None
    target: str | None
    target_section: int | None
    target_value: int | None
    target_type: int | None
    target_storage: int | None
    target_index: int | None = None


@dataclass(frozen=True, slots=True)
class _CoffSection:
    number: int
    name: str
    body: bytes
    characteristics: int
    line_numbers: tuple[_CoffLineNumber, ...]
    relocations: tuple[_CoffRelocation, ...]
    comdat_selection: int | None
    comdat_associated: int | None
    line_offset: int = 0


@dataclass(frozen=True, slots=True)
class _CoffObject:
    label: str
    digest: Digest
    header_characteristics: int
    sections: tuple[_CoffSection, ...]
    symbols: tuple[_CoffSymbol, ...]


@dataclass(frozen=True, slots=True)
class ClassicImportObjectReceipt:
    """Strict disposition for one i386 IMPORT_OBJECT_HEADER member."""

    label: str
    digest: Digest
    symbol: str
    dll: str
    import_type: int
    name_type: int

    @property
    def definitions(self) -> frozenset[str]:
        # IMPORT_OBJECT_HEADER causes the linker to synthesize the public
        # import and its address-table form.  Over-approximating both is safe
        # for carrier collision analysis.
        return frozenset({self.symbol, f"__imp_{self.symbol}"})


def _slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ClassicSemanticError(f"{label} is outside the COFF object")
    return data[offset : offset + size]


def _decode_name(raw: bytes, string_table: bytes, label: str) -> str:
    if raw[:4] == b"\0\0\0\0":
        offset = int.from_bytes(raw[4:8], "little")
        if offset < 4 or offset >= len(string_table):
            raise ClassicSemanticError(f"{label} string offset is invalid")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ClassicSemanticError(f"{label} is not NUL-terminated")
        encoded = string_table[offset:end]
    else:
        encoded = raw.rstrip(b"\0")
    # COFF symbol names are byte strings.  Latin-1 is a lossless one-byte
    # projection used only for equality/reachability; no locale decoding is
    # permitted here.
    return encoded.decode("latin-1")


def _decode_section_name(raw: bytes, string_table: bytes, label: str) -> str:
    short = raw.rstrip(b"\0")
    if short.startswith(b"/"):
        if not short[1:].isdigit():
            raise ClassicSemanticError(f"{label} long-name offset is malformed")
        offset = int(short[1:])
        if offset < 4 or offset >= len(string_table):
            raise ClassicSemanticError(f"{label} long-name offset is invalid")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ClassicSemanticError(f"{label} is not NUL-terminated")
        short = string_table[offset:end]
    try:
        return short.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClassicSemanticError(f"{label} is not ASCII") from exc


def _parse_coff(
    payload: bytes,
    label: str,
    *,
    allow_archive_extensions: bool = False,
    allow_archive_auxless_section_anchors: bool = False,
) -> _CoffObject:
    """Parse the strict i386 COFF subset needed for reachability evidence."""

    if allow_archive_auxless_section_anchors and not allow_archive_extensions:
        raise ClassicSemanticError(
            f"{label} enables archive anchors outside the archive-member domain"
        )
    if len(payload) < 20:
        raise ClassicSemanticError(f"{label} has a truncated COFF header")
    (
        machine,
        section_count,
        _timestamp,
        symbol_offset,
        symbol_count,
        optional_size,
        header_characteristics,
    ) = struct.unpack_from("<HHIIIHH", payload)
    if machine not in ({0, 0x14C} if allow_archive_extensions else {0x14C}) or (
        (not section_count or optional_size) and not allow_archive_extensions
    ):
        raise ClassicSemanticError(f"{label} is not a supported i386 COFF object")
    optional_header = b""
    if optional_size:
        optional_header = _slice(payload, 20, optional_size, f"{label} optional header")
        if len(optional_header) < 2 or int.from_bytes(optional_header[:2], "little") != 0x10B:
            raise ClassicSemanticError(f"{label} has an unknown COFF optional header")
        if allow_archive_extensions and (
            machine != 0x014C
            or header_characteristics != 0x0100
            or not _is_supported_long_import_optional_header(optional_header)
        ):
            raise ClassicSemanticError(
                f"{label} has a non-canonical classic import optional header"
            )
    section_table_at = 20 + optional_size
    section_table_end = section_table_at + section_count * 40
    _slice(
        payload,
        section_table_at,
        section_count * 40,
        f"{label} section table",
    )
    if not symbol_offset or not symbol_count:
        raise ClassicSemanticError(f"{label} has no closed COFF symbol table")
    symbols_end = symbol_offset + symbol_count * 18
    _slice(payload, symbol_offset, symbol_count * 18, f"{label} symbol table")
    string_size = int.from_bytes(
        _slice(payload, symbols_end, 4, f"{label} string-table size"), "little"
    )
    if string_size < 4 or symbols_end + string_size != len(payload):
        raise ClassicSemanticError(f"{label} has a non-canonical COFF string table")
    string_table = _slice(payload, symbols_end, string_size, f"{label} string table")

    symbols: list[_CoffSymbol] = []
    auxiliary_indexes: set[int] = set()
    auxiliary_records: dict[int, bytes] = {}
    index = 0
    while index < symbol_count:
        raw = _slice(payload, symbol_offset + index * 18, 18, f"{label} symbol {index}")
        name = _decode_name(raw[:8], string_table, f"{label} symbol {index}")
        value, section, symbol_type, storage, auxiliary_count = struct.unpack_from("<IhHBB", raw, 8)
        if index + auxiliary_count >= symbol_count:
            raise ClassicSemanticError(f"{label} symbol {index} auxiliaries are truncated")
        symbol = _CoffSymbol(
            index,
            name,
            value,
            section,
            symbol_type,
            storage,
            auxiliary_count,
            _slice(
                payload,
                symbol_offset + (index + 1) * 18,
                auxiliary_count * 18,
                f"{label} symbol {index} auxiliaries",
            )
            if auxiliary_count
            else b"",
        )
        symbols.append(symbol)
        if auxiliary_count:
            auxiliary_records[index] = _slice(
                payload,
                symbol_offset + (index + 1) * 18,
                auxiliary_count * 18,
                f"{label} symbol {index} auxiliaries",
            )
            auxiliary_indexes.update(range(index + 1, index + 1 + auxiliary_count))
        index += 1 + auxiliary_count
    by_index = {item.index: item for item in symbols}

    raw_sections: list[tuple[str, bytes, int, int, int, int, int]] = []
    for section_index in range(section_count):
        at = section_table_at + section_index * 40
        raw = _slice(payload, at, 40, f"{label} section {section_index + 1}")
        name = _decode_section_name(raw[:8], string_table, f"{label} section {section_index + 1}")
        (
            _virtual_size,
            _virtual_address,
            raw_size,
            raw_offset,
            relocation_offset,
            line_offset,
            relocation_count,
            line_count,
            section_characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", raw, 8)
        uninitialized = bool(section_characteristics & 0x00000080)
        if raw_size and not raw_offset and not uninitialized:
            raise ClassicSemanticError(f"{label} section {name!r} has no raw data offset")
        if raw_size and raw_offset and raw_offset < section_table_end:
            raise ClassicSemanticError(f"{label} section {name!r} overlaps its headers")
        body = (
            bytes(raw_size)
            if raw_size and not raw_offset and uninitialized
            else _slice(payload, raw_offset, raw_size, f"{label} section {name!r} body")
        )
        if relocation_count and relocation_offset < section_table_end:
            raise ClassicSemanticError(
                f"{label} section {name!r} relocation table overlaps its headers"
            )
        if bool(line_offset) != bool(line_count):
            raise ClassicSemanticError(
                f"{label} section {name!r} has a non-canonical COFF line table"
            )
        if line_count:
            if line_offset < section_table_end:
                raise ClassicSemanticError(
                    f"{label} section {name!r} line table overlaps its headers"
                )
            _slice(
                payload,
                line_offset,
                line_count * 6,
                f"{label} section {name!r} line table",
            )
        raw_sections.append(
            (
                name,
                body,
                section_characteristics,
                relocation_offset,
                relocation_count,
                line_offset,
                line_count,
            )
        )

    definitions: dict[int, tuple[int, int]] = {}
    section_metadata_symbols: dict[int, _CoffSymbol] = {}
    for symbol in symbols:
        if not (0 < symbol.section <= section_count and symbol.storage == 3):
            continue
        section_name = raw_sections[symbol.section - 1][0]
        if symbol.name != section_name:
            continue
        previous_metadata = section_metadata_symbols.get(symbol.section)
        if previous_metadata is not None:
            if (
                previous_metadata.value == 0
                and previous_metadata.symbol_type == 0
                and previous_metadata.auxiliary_count == 1
                and symbol.value == 0
                and symbol.symbol_type == 0
                and symbol.auxiliary_count == 1
            ):
                raise ClassicSemanticError(
                    f"{label} section {section_name!r} has duplicate definition symbols"
                )
            raise ClassicSemanticError(
                f"{label} section {section_name!r} has duplicate section-metadata symbols"
            )
        section_metadata_symbols[symbol.section] = symbol
        section_characteristics = raw_sections[symbol.section - 1][2]
        if (
            allow_archive_auxless_section_anchors
            and symbol.value == 0
            and symbol.symbol_type == 0
            and symbol.auxiliary_count == 0
            and (
                machine,
                optional_size,
                header_characteristics,
                section_name,
                section_characteristics,
            )
            in _ARCHIVE_AUXLESS_SECTION_ANCHORS
        ):
            continue
        if (
            symbol.value != 0
            or symbol.symbol_type != 0
            or symbol.auxiliary_count != 1
            or len(symbol.auxiliary) != 18
        ):
            raise ClassicSemanticError(
                f"{label} section {section_name!r} definition symbol is non-canonical"
            )
        if symbol.section in definitions:
            raise ClassicSemanticError(
                f"{label} section {section_name!r} has duplicate definition symbols"
            )
        auxiliary = auxiliary_records[symbol.index]
        raw_section = raw_sections[symbol.section - 1]
        if (
            int.from_bytes(auxiliary[:4], "little") != len(raw_section[1])
            or int.from_bytes(auxiliary[4:6], "little") != raw_section[4]
            or int.from_bytes(auxiliary[6:8], "little") != raw_section[6]
        ):
            raise ClassicSemanticError(
                f"{label} section {section_name!r} definition length or table counts differ"
            )
        associated = int.from_bytes(auxiliary[12:14], "little") | (
            int.from_bytes(auxiliary[16:18], "little") << 16
        )
        definitions[symbol.section] = (auxiliary[14], associated)

    sections: list[_CoffSection] = []
    for section_index, raw_section in enumerate(raw_sections):
        (
            name,
            body,
            characteristics,
            relocation_offset,
            relocation_count,
            line_offset,
            line_count,
        ) = raw_section
        relocations: list[_CoffRelocation] = []
        for relocation_index in range(relocation_count):
            at = relocation_offset + relocation_index * 10
            offset, target_index, relocation_type = struct.unpack(
                "<IIH", _slice(payload, at, 10, f"{label} relocation")
            )
            if target_index in auxiliary_indexes or target_index not in by_index:
                raise ClassicSemanticError(f"{label} relocation names an auxiliary symbol")
            target = by_index[target_index]
            width = {6: 4, 7: 4, 10: 2, 11: 4, 20: 4}.get(relocation_type)
            if width is None:
                raise ClassicSemanticError(
                    f"{label} has unsupported relocation type 0x{relocation_type:04x}"
                )
            addend = _slice(body, offset, width, f"{label} relocation addend")
            relocations.append(
                _CoffRelocation(
                    offset,
                    relocation_type,
                    target_index,
                    target.name,
                    target.section,
                    target.value,
                    target.symbol_type,
                    target.storage,
                    addend,
                )
            )
        line_numbers: list[_CoffLineNumber] = []
        for line_index in range(line_count):
            value, line_number = struct.unpack(
                "<IH",
                _slice(
                    payload,
                    line_offset + line_index * 6,
                    6,
                    f"{label} section {name!r} line record",
                ),
            )
            if line_number:
                if value > len(body):
                    raise ClassicSemanticError(
                        f"{label} section {name!r} line address is outside its body"
                    )
                line_numbers.append(
                    _CoffLineNumber(line_number, value, None, None, None, None, None)
                )
                continue
            if value in auxiliary_indexes or value not in by_index:
                raise ClassicSemanticError(
                    f"{label} section {name!r} line record names an invalid symbol"
                )
            target = by_index[value]
            line_numbers.append(
                _CoffLineNumber(
                    0,
                    None,
                    target.name,
                    target.section,
                    target.value,
                    target.symbol_type,
                    target.storage,
                    target.index,
                )
            )
        selection = definitions.get(section_index + 1)
        sections.append(
            _CoffSection(
                section_index + 1,
                name,
                body,
                characteristics,
                tuple(line_numbers),
                tuple(relocations),
                selection[0] if selection is not None else None,
                selection[1] if selection is not None else None,
                line_offset,
            )
        )
    return _CoffObject(
        label,
        Digest.from_bytes(payload),
        header_characteristics,
        tuple(sections),
        tuple(symbols),
    )


def _parse_import_object(payload: bytes, label: str) -> ClassicImportObjectReceipt | None:
    """Recognize one strict i386 IMPORT_OBJECT_HEADER archive member."""

    if len(payload) < 20 or payload[:4] != b"\0\0\xff\xff":
        return None
    (
        signature_one,
        signature_two,
        version,
        machine,
        _timestamp,
        data_size,
        _ordinal_or_hint,
        type_info,
    ) = struct.unpack_from("<HHHHIIHH", payload)
    if signature_one != 0 or signature_two != 0xFFFF:
        raise ClassicSemanticError(f"{label} has a malformed import-object signature")
    if version not in {0, 1} or machine != 0x14C or data_size != len(payload) - 20:
        raise ClassicSemanticError(f"{label} is not a supported i386 import object")
    import_type = type_info & 0x3
    name_type = (type_info >> 2) & 0x7
    reserved = type_info >> 5
    if import_type > 2 or name_type > 4 or reserved:
        raise ClassicSemanticError(f"{label} has unsupported import-object flags")
    data = payload[20:]
    values = data.split(b"\0")
    expected_strings = 3 if name_type == 4 else 2
    if (
        len(values) != expected_strings + 1
        or values[-1] != b""
        or any(not item for item in values[:-1])
    ):
        raise ClassicSemanticError(f"{label} import strings are not canonical")
    try:
        symbol = values[0].decode("ascii")
        dll = values[1].decode("ascii")
        if name_type == 4:
            values[2].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClassicSemanticError(f"{label} import strings are not ASCII") from exc
    if any(character.isspace() for character in symbol + dll):
        raise ClassicSemanticError(f"{label} import strings contain whitespace")
    return ClassicImportObjectReceipt(
        label,
        Digest.from_bytes(payload),
        symbol,
        dll.casefold(),
        import_type,
        name_type,
    )


def parse_classic_import_object(payload: bytes, *, label: str) -> ClassicImportObjectReceipt | None:
    """Classify a raw archive member as a strict import object or ordinary COFF."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable archive-member bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("import-object label is malformed")
    return _parse_import_object(payload, label)


def _coff_directive_receipt(coff: _CoffObject) -> CoffDirectiveReceipt:
    tokens: list[str] = []
    libraries: list[str] = []
    includes: list[str] = []
    exports: list[str] = []
    merges: list[tuple[str, str]] = []
    disallowed: list[str] = []
    for section in coff.sections:
        if section.name.casefold() != ".drectve":
            continue
        body = section.body
        # LINK 4.x libraries contain one observed, semantically inert terminal
        # NUL on a directive section.  Admit exactly one padding byte; multiple
        # or embedded NULs remain malformed rather than becoming token separators.
        if body.endswith(b"\0"):
            body = body[:-1]
        if b"\0" in body:
            raise ClassicSemanticError(
                f"{coff.label} linker directives contain malformed NUL padding"
            )
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ClassicSemanticError(f"{coff.label} linker directives are not ASCII") from exc
        if any(ord(character) < 0x20 and character not in "\t\r\n" for character in text):
            raise ClassicSemanticError(
                f"{coff.label} linker directives contain a control character"
            )
        for token in text.split():
            default_library = _DEFAULTLIB.fullmatch(token)
            if default_library is not None:
                tokens.append(token)
                libraries.append(default_library.group(1))
                continue
            disallow_library = _DISALLOWLIB.fullmatch(token)
            if disallow_library is not None:
                tokens.append(token)
                disallowed.append(disallow_library.group(1))
                continue
            merge = _MERGE_SECTION.fullmatch(token)
            if merge is not None:
                tokens.append(token)
                merges.append((merge.group(1), merge.group(2)))
                continue
            control = _LINK_SYMBOL_CONTROL.fullmatch(token)
            if control is None or (
                control.group(1).casefold() == "include" and control.group(3) is not None
            ):
                raise ClassicSemanticError(
                    f"{coff.label} contains unsafe linker directive {token!r}"
                )
            tokens.append(token)
            if control.group(1).casefold() == "include":
                includes.append(control.group(2))
            else:
                exports.append(control.group(2))
    return CoffDirectiveReceipt(
        tuple(tokens),
        tuple(libraries),
        tuple(includes),
        tuple(exports),
        tuple(merges),
        tuple(disallowed),
    )


def parse_classic_coff_directives(payload: bytes, *, label: str) -> CoffDirectiveReceipt:
    """Parse the complete closed `.drectve` language of one i386 COFF object."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable COFF bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("COFF directive label is malformed")
    return _coff_directive_receipt(_parse_coff(payload, label))


def parse_classic_archive_member_directives(payload: bytes, *, label: str) -> CoffDirectiveReceipt:
    """Parse directives from a classified ordinary COFF archive member."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable archive-member bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("archive-member directive label is malformed")
    if _parse_import_object(payload, label) is not None:
        raise ClassicSemanticError(f"{label} is an import object, not ordinary COFF")
    return _coff_directive_receipt(
        _parse_coff(
            payload,
            label,
            allow_archive_extensions=True,
            allow_archive_auxless_section_anchors=True,
        )
    )


def _external_definitions(coff: _CoffObject) -> dict[str, _CoffSection]:
    result: dict[str, _CoffSection] = {}
    for symbol in coff.symbols:
        if symbol.storage != 2 or symbol.section <= 0:
            continue
        if symbol.section > len(coff.sections):
            raise ClassicSemanticError(f"{coff.label} definition has an invalid section")
        previous = result.setdefault(symbol.name, coff.sections[symbol.section - 1])
        if previous.number != symbol.section:
            raise ClassicSemanticError(
                f"{coff.label} defines external symbol {symbol.name!r} more than once"
            )
    return result


def _external_references(coff: _CoffObject) -> set[str]:
    return {
        relocation.target
        for section in coff.sections
        for relocation in section.relocations
        if relocation.target_section == 0 and relocation.target_storage in {2, 105}
    }


def _default_libraries_for_ordinary(coff: _CoffObject) -> set[str]:
    return {item.casefold() for item in _coff_directive_receipt(coff).default_libraries}


__all__ = [
    "ClassicImportObjectReceipt",
    "CoffDirectiveReceipt",
    "parse_classic_archive_member_directives",
    "parse_classic_coff_directives",
    "parse_classic_import_object",
]
