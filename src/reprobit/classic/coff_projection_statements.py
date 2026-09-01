"""Strict COFF projections: section, symbol, relocation and linkage statements."""

from __future__ import annotations

import struct
from collections import defaultdict
from collections.abc import Mapping, Sequence
from types import MappingProxyType

from reprobit.binary import ByteIdentityError
from reprobit.classic.coff_evidence import (
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
)
from reprobit.classic.foundation import local_symbol_kind
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.ia32_decode import supported_ia32_instruction_length
from reprobit.model import Digest
from reprobit.strict_json import canonical_json


class _SemanticCodePartitionError(ClassicSemanticError):
    """A ``.text`` payload has no closed IA-32 instruction partition."""


def _coff_header_statement(coff: _CoffObject) -> dict[str, object]:
    """Bind the parsed linker-relevant COFF file-header state once."""

    return {
        "machine": "i386",
        "characteristics": coff.header_characteristics,
    }


def _msvc_static_serial_stem(name: str) -> str | None:
    """Return the stable part of one MSVC ``name$S<digits>`` static."""

    marker = name.rfind("$S")
    if marker <= 0 or not name[marker + 2 :].isdigit():
        return None
    return name[:marker]


def _ordinary_readonly_rdata_section(coff: _CoffObject, section: _CoffSection) -> bool:
    associated_parents = {
        item.comdat_associated for item in coff.sections if item.comdat_associated not in {None, 0}
    }
    characteristics = section.characteristics
    return (
        section.name.casefold() == ".rdata"
        and section.comdat_selection in {None, 0}
        and section.comdat_associated in {None, 0}
        and section.number not in associated_parents
        and bool(characteristics & 0x00000040)  # initialized data
        and not bool(characteristics & 0x00000020)  # code
        and not bool(characteristics & 0x00000080)  # uninitialized data
        and not bool(characteristics & 0x00001000)  # COMDAT
        and bool(characteristics & 0x40000000)  # readable
        and not bool(characteristics & 0x20000000)  # executable
        and not bool(characteristics & 0x80000000)  # writable
        and not section.line_numbers
        and not section.relocations
    )


_CODE_SECTION_PREFIXES = (".text",)
_COMPILER_CONTROL_SECTION_PREFIXES = (".pdata", ".xdata")
_INITIALIZED_DATA_SECTION_PREFIXES = (".data", ".rdata")
_UNINITIALIZED_DATA_SECTION_PREFIXES = (".bss",)
_RELOCATION_WIDTHS = MappingProxyType({6: 4, 7: 4, 10: 2, 11: 4, 20: 4})
_IA32_DIRECTION_EQUIVALENTS = MappingProxyType(
    {
        0x03: 0x01,  # ADD r32,r/m32 <-> ADD r/m32,r32
        0x0B: 0x09,  # OR
        0x13: 0x11,  # ADC
        0x1B: 0x19,  # SBB
        0x23: 0x21,  # AND
        0x2B: 0x29,  # SUB
        0x33: 0x31,  # XOR
        0x3B: 0x39,  # CMP
        0x8B: 0x89,  # MOV
    }
)


def _is_section_symbol(symbol: _CoffSymbol, section: _CoffSection) -> bool:
    return (
        symbol.storage == 3
        and symbol.name == section.name
        and symbol.section == section.number
        and symbol.value == 0
        and symbol.symbol_type == 0
        and symbol.auxiliary_count == 1
        and len(symbol.auxiliary) == 18
        and int.from_bytes(symbol.auxiliary[:4], "little") == len(section.body)
        and int.from_bytes(symbol.auxiliary[4:6], "little") == len(section.relocations)
        and int.from_bytes(symbol.auxiliary[6:8], "little") == len(section.line_numbers)
    )


def _section_definition_symbol(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> _CoffSymbol | None:
    candidates = tuple(
        symbol
        for symbol in symbols.get(section.number, ())
        if symbol.storage == 3 and symbol.name == section.name
    )
    if not candidates:
        return None
    if len(candidates) != 1 or not _is_section_symbol(candidates[0], section):
        raise ClassicSemanticError(
            f"section {section.number} {section.name!r} has a non-canonical or duplicate "
            "definition symbol"
        )
    return candidates[0]


def _section_definition_statement(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    symbol = _section_definition_symbol(section, symbols)
    if symbol is None:
        return None
    non_length_auxiliary = bytearray(symbol.auxiliary[4:])
    if section.comdat_associated not in {None, 0}:
        # IMAGE_AUX_SYMBOL_SECTION stores the associated COMDAT's positional
        # section number in the low/high words at bytes 12 and 16.  The
        # topology statement below binds that association by the target's
        # semantic identity, so retaining the raw seat as well would make a
        # harmless global section reorder look like a control-flow change.
        raw_associated = int.from_bytes(symbol.auxiliary[12:14], "little") | (
            int.from_bytes(symbol.auxiliary[16:18], "little") << 16
        )
        if raw_associated != section.comdat_associated:
            raise ClassicSemanticError(
                f"section {section.number} {section.name!r} has inconsistent COMDAT "
                "association evidence"
            )
        non_length_auxiliary[8:10] = b"\0\0"
        non_length_auxiliary[12:14] = b"\0\0"
    return {
        "length": int.from_bytes(symbol.auxiliary[:4], "little"),
        "non_length_auxiliary": bytes(non_length_auxiliary).hex(),
    }


def _compiler_local_definition_kind(symbol: _CoffSymbol) -> str | None:
    if (
        symbol.storage not in {3, 6}
        or symbol.section <= 0
        or symbol.symbol_type != 0
        or symbol.auxiliary_count
        or symbol.auxiliary
    ):
        return None
    return local_symbol_kind(symbol.name)


def _msvc_static_definition_stem(
    section: _CoffSection,
    symbol: _CoffSymbol,
) -> str | None:
    """Recognize one linker-internal MSVC ``name$S<digits>`` datum."""

    if (
        symbol.storage != 3
        or symbol.section != section.number
        or symbol.symbol_type != 0
        or symbol.auxiliary_count
        or symbol.auxiliary
        or not 0 <= symbol.value < len(section.body)
    ):
        return None
    return _msvc_static_serial_stem(symbol.name)


def _defined_symbol_name_statement(
    section: _CoffSection,
    symbol: _CoffSymbol,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> object:
    """Bind a defined local name while removing only closed MSVC serials."""

    local_kind = _compiler_local_definition_kind(symbol)
    if local_kind is not None:
        return {"compiler_local_kind": local_kind}
    static_stem = _msvc_static_definition_stem(section, symbol)
    if static_stem is None:
        return symbol.name
    matches = [
        candidate
        for candidate in symbols.get(section.number, ())
        if _msvc_static_definition_stem(section, candidate) == static_stem
    ]
    if len(matches) != 1:
        # Keep ambiguous objects exact.  Normalizing two same-stem definitions
        # would lose the evidence needed to decide which internal symbol moved.
        return symbol.name
    return {"msvc_static_serial_stem": static_stem}


def _symbols_by_section(coff: _CoffObject) -> dict[int, tuple[_CoffSymbol, ...]]:
    result: dict[int, list[_CoffSymbol]] = defaultdict(list)
    for symbol in coff.symbols:
        if symbol.section > 0:
            if symbol.section > len(coff.sections):
                raise ClassicSemanticError(
                    f"{coff.label} symbol {symbol.name!r} has an invalid section"
                )
            result[symbol.section].append(symbol)
    return {
        number: tuple(
            sorted(
                values,
                key=lambda item: (
                    item.name,
                    item.value,
                    item.symbol_type,
                    item.storage,
                ),
            )
        )
        for number, values in result.items()
    }


def _section_owner_statement(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> list[dict[str, object]]:
    definition = _section_definition_symbol(section, symbols)
    result: list[dict[str, object]] = []
    for symbol in symbols.get(section.number, ()):
        if definition is not None and symbol.index == definition.index:
            continue
        statement: dict[str, object] = {
            "name": _defined_symbol_name_statement(section, symbol, symbols),
            "value": symbol.value,
            "type": symbol.symbol_type,
            "storage": symbol.storage,
        }
        result.append(statement)
    return sorted(result, key=canonical_json)


def _association_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    associated = section.comdat_associated
    if not associated:
        return None
    if not 0 < associated <= len(coff.sections):
        raise ClassicSemanticError(
            f"{coff.label} section {section.name!r} has an invalid COMDAT association"
        )
    target = coff.sections[associated - 1]
    return {
        "name": target.name,
        "selection": target.comdat_selection,
        "owners": _section_owner_statement(target, symbols),
    }


def _section_topology_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    return {
        "name": section.name,
        "characteristics": section.characteristics,
        "definition": _section_definition_statement(section, symbols),
        "selection": section.comdat_selection,
        "association": _association_statement(coff, section, symbols),
        "owners": _section_owner_statement(section, symbols),
    }


def _preliminary_section_identity(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    folded = section.name.casefold()
    topology = _section_topology_statement(coff, section, symbols)
    if folded.startswith(_CODE_SECTION_PREFIXES):
        return {"kind": "code", "topology": topology}
    if folded.startswith(_COMPILER_CONTROL_SECTION_PREFIXES):
        return {"kind": "compiler-control", "topology": topology}
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS.get(relocation.relocation_type)
        if width is None or relocation.offset + width > len(masked):
            raise ClassicSemanticError(
                f"{coff.label} section {section.name!r} has an invalid relocation field"
            )
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    return {
        "kind": "data",
        "topology": topology,
        "masked_body": bytes(masked).hex(),
    }


def _relocation_target_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    if relocation.target_section == 0:
        kind = (
            "weak"
            if relocation.target_storage == 105
            else "common"
            if relocation.target_storage == 2 and relocation.target_value > 0
            else "undefined"
        )
        return {
            "kind": kind,
            "name": relocation.target,
            "value": relocation.target_value,
            "type": relocation.target_type,
            "storage": relocation.target_storage,
        }
    if not 0 < relocation.target_section <= len(coff.sections):
        raise ClassicSemanticError(f"{coff.label} relocation target has an invalid section")
    target = coff.sections[relocation.target_section - 1]
    by_index = {symbol.index: symbol for symbol in coff.symbols}
    target_symbol = by_index.get(relocation.target_index)
    if target_symbol is None:
        raise ClassicSemanticError(f"{coff.label} relocation target symbol is absent")
    statement: dict[str, object] = {
        "kind": "defined",
        "symbol": {
            "name": _defined_symbol_name_statement(target, target_symbol, symbols),
            "type": relocation.target_type,
            "storage": relocation.target_storage,
            "section_symbol": (relocation.target_storage == 3 and relocation.target == target.name),
            "value": relocation.target_value,
        },
        "section": _preliminary_section_identity(coff, target, symbols),
    }
    return statement


def _relocation_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
    *,
    include_offset: bool,
) -> dict[str, object]:
    result: dict[str, object] = {
        "type": relocation.relocation_type,
        "target": _relocation_target_statement(coff, relocation, symbols),
        "addend": relocation.addend.hex(),
    }
    if include_offset:
        result["offset"] = relocation.offset
    return result


def _associated_eh_control_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    associated = [
        section
        for section in coff.sections
        if section.comdat_associated == primary.number
        and section.name.casefold().startswith(_COMPILER_CONTROL_SECTION_PREFIXES)
    ]
    if not associated:
        return None
    if len(associated) != 1 or associated[0].name.casefold() != ".xdata$x":
        raise ClassicSemanticError(
            f"{coff.label} code section {primary.number} has no unique paired .xdata$x control"
        )
    section = associated[0]
    return {
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }


def _associated_fpo_evidence_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> tuple[dict[str, object], bytes] | None:
    """Return the exact FPO child receipt for the one admitted FPO closure."""

    associated = [
        section for section in coff.sections if section.comdat_associated == primary.number
    ]
    if tuple(sorted(section.name for section in associated)) != (".debug$F", ".debug$S"):
        return None
    fpo = [section for section in associated if section.name == ".debug$F"]
    if len(fpo) != 1:
        return None
    section = fpo[0]
    statement: dict[str, object] = {
        "closure": [".debug$F", ".debug$S"],
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }
    return statement, section.body


def _associated_debug_evidence_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> tuple[dict[str, object], bytes] | None:
    """Return the exact ``.debug$S`` child from the admitted FPO closure."""

    associated = [
        section for section in coff.sections if section.comdat_associated == primary.number
    ]
    if tuple(sorted(section.name for section in associated)) != (".debug$F", ".debug$S"):
        return None
    streams = [section for section in associated if section.name == ".debug$S"]
    if len(streams) != 1:
        return None
    section = streams[0]
    statement: dict[str, object] = {
        "closure": [".debug$F", ".debug$S"],
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }
    return statement, section.body


def _canonical_multiset(values: Sequence[object]) -> list[dict[str, object]]:
    counts: dict[bytes, int] = defaultdict(int)
    for value in values:
        counts[canonical_json(value)] += 1
    return [
        {
            "value": Digest.from_bytes(encoded).model_dump(mode="json"),
            "count": count,
        }
        for encoded, count in sorted(counts.items())
    ]


def _canonical_ia32_instruction(encoded: bytes) -> str:
    """Normalize only proven direction-bit register/register encodings."""

    result = bytearray(encoded)
    opcode_index = 0
    while opcode_index < len(result) and result[opcode_index] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        opcode_index += 1
    if opcode_index + 1 >= len(result):
        return result.hex()
    canonical_opcode = _IA32_DIRECTION_EQUIVALENTS.get(result[opcode_index])
    if canonical_opcode is None:
        return result.hex()
    modrm_index = opcode_index + 1
    modrm = result[modrm_index]
    if modrm >> 6 != 3:
        # Swapping a register with a memory operand is not the same operation.
        return result.hex()
    result[opcode_index] = canonical_opcode
    result[modrm_index] = (modrm & 0xC0) | ((modrm & 0x07) << 3) | ((modrm >> 3) & 0x07)
    return result.hex()


def _semantic_code_stream(
    coff: _CoffObject, section: _CoffSection
) -> tuple[list[str], tuple[tuple[int, int], ...]]:
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS[relocation.relocation_type]
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    result: list[str] = []
    boundaries: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(masked):
        try:
            length = supported_ia32_instruction_length(
                bytes(masked[cursor:]),
                f"{coff.label} section {section.name!r} at {cursor}",
            )
        except ByteIdentityError as exc:
            raise _SemanticCodePartitionError(
                f"{coff.label} code section has no closed IA-32 partition"
            ) from exc
        if length <= 0 or cursor + length > len(masked):
            raise _SemanticCodePartitionError(
                f"{coff.label} code section has an invalid IA-32 partition"
            )
        result.append(_canonical_ia32_instruction(bytes(masked[cursor : cursor + length])))
        boundaries.append((cursor, cursor + length))
        cursor += length
    return result, tuple(boundaries)


def _weak_external_statement(coff: _CoffObject, symbol: _CoffSymbol) -> object:
    if (
        symbol.section != 0
        or symbol.value != 0
        or symbol.auxiliary_count != 1
        or (len(symbol.auxiliary) != 18)
    ):
        raise ClassicSemanticError(f"{coff.label} weak external {symbol.name!r} is malformed")
    tag_index, characteristics = struct.unpack_from("<II", symbol.auxiliary)
    by_index = {item.index: item for item in coff.symbols}
    fallback = by_index.get(tag_index)
    if fallback is None or fallback.storage not in {2, 105}:
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has an invalid fallback"
        )
    if any(symbol.auxiliary[8:]):
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has unknown auxiliary state"
        )
    return {
        "name": symbol.name,
        "fallback": fallback.name,
        "characteristics": characteristics,
        "type": symbol.symbol_type,
    }


def _linkage_statement(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int],
    excluded_undefineds: frozenset[tuple[str, int]] = frozenset(),
) -> dict[str, object]:
    symbols = _symbols_by_section(coff)
    definitions: list[dict[str, object]] = []
    undefineds: list[dict[str, object]] = []
    commons: list[dict[str, object]] = []
    weaks: list[object] = []
    absolute: list[dict[str, object]] = []
    for symbol in coff.symbols:
        if symbol.storage == 105:
            weaks.append(_weak_external_statement(coff, symbol))
            continue
        if symbol.storage != 2:
            continue
        if symbol.section > 0:
            if symbol.section in excluded_sections:
                continue
            section = coff.sections[symbol.section - 1]
            definitions.append(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "type": symbol.symbol_type,
                    "section": _section_topology_statement(coff, section, symbols),
                }
            )
        elif symbol.section == 0 and symbol.value > 0:
            commons.append(
                {
                    "name": symbol.name,
                    "size": symbol.value,
                    "type": symbol.symbol_type,
                }
            )
        elif symbol.section == 0:
            if (symbol.name, symbol.symbol_type) not in excluded_undefineds:
                undefineds.append(
                    {
                        "name": symbol.name,
                        "type": symbol.symbol_type,
                    }
                )
        elif symbol.section < 0:
            absolute.append(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "section": symbol.section,
                    "type": symbol.symbol_type,
                }
            )
    relocation_dependencies = sorted(
        {
            relocation.target
            for section in coff.sections
            if section.number not in excluded_sections
            and not section.name.casefold().startswith(".debug")
            for relocation in section.relocations
            if relocation.target_section == 0
            and relocation.target_storage in {2, 105}
            and not (relocation.target_storage == 2 and relocation.target_value > 0)
        }
    )
    return {
        "definitions": sorted(definitions, key=lambda item: str(item["name"])),
        "undefineds": sorted(undefineds, key=lambda item: canonical_json(item)),
        "relocation_dependencies": relocation_dependencies,
        "commons": sorted(commons, key=lambda item: str(item["name"])),
        "weaks": sorted(weaks, key=lambda item: canonical_json(item)),
        "absolutes": sorted(absolute, key=lambda item: str(item["name"])),
    }
