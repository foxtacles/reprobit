"""Strict, compiler-neutral reader for classic i386 COFF objects."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from contextlib import suppress
from types import MappingProxyType
from typing import Any, cast

from reprobit.binary import ByteIdentityError, require
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

CoffSection = dict[str, Any]
CoffSymbol = dict[str, Any]
Relocation = dict[str, Any]
RELOCATION_WIDTHS = {6: 4, 7: 4, 10: 2, 11: 4, 20: 4}
_EMPTY_ASSOCIATED: Mapping[str, CoffSection] = MappingProxyType({})


def coff_unpack(
    format_string: str,
    data: bytes,
    offset: int,
    context: str,
) -> tuple[Any, ...]:
    size = struct.calcsize(format_string)
    require(0 <= offset <= len(data) - size, f"{context} is outside the COFF file")
    return struct.unpack_from(format_string, data, offset)


class CoffObject:
    """Fail-closed reader for the i386 COFF emitted by VC 4.x."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        require(len(data) >= 20, "COFF header is truncated")
        (
            self.machine,
            self.section_count,
            self.timestamp,
            self.symbol_offset,
            self.symbol_count,
            optional_size,
            self.characteristics,
        ) = coff_unpack("<HHIIIHH", data, 0, "COFF header")
        require(self.machine == 0x14C, "only i386 COFF objects are supported")
        require(optional_size == 0, "COFF optional headers are unsupported")
        require(0 < self.section_count < 65536, "COFF section count is invalid")
        require(self.symbol_count > 0, "COFF object has no symbol table")
        self.string_offset = self.symbol_offset + self.symbol_count * 18
        (string_size,) = coff_unpack("<I", data, self.string_offset, "COFF string table")
        require(
            string_size >= 4 and self.string_offset <= len(data) - string_size,
            "COFF string table is invalid",
        )
        self.string_end = self.string_offset + string_size
        require(
            self.string_end == len(data),
            "bytes after the COFF string table are unsupported",
        )
        table_end = 20 + self.section_count * 40
        require(table_end <= len(data), "COFF section table is truncated")
        self.sections: list[CoffSection] = []
        for index in range(self.section_count):
            header_offset = 20 + index * 40
            name = self._section_name(data[header_offset : header_offset + 8])
            (
                _,
                _,
                raw_size,
                raw_offset,
                relocation_offset,
                line_offset,
                relocation_count,
                line_count,
                characteristics,
            ) = coff_unpack(
                "<IIIIIIHHI",
                data,
                header_offset + 8,
                f"section {index + 1} header",
            )
            if raw_size and not characteristics & 0x80:
                require(
                    raw_offset >= table_end and raw_offset <= len(data) - raw_size,
                    f"section {index + 1} raw data is invalid",
                )
            elif raw_size:
                require(
                    raw_offset == 0,
                    f"section {index + 1} uninitialized raw pointer is invalid",
                )
            else:
                require(
                    raw_offset == 0 or raw_offset >= table_end,
                    f"section {index + 1} empty raw pointer is invalid",
                )
            if relocation_count:
                require(
                    relocation_offset >= table_end
                    and relocation_offset <= len(data) - relocation_count * 10,
                    f"section {index + 1} relocation table is invalid",
                )
            if line_count:
                require(
                    line_offset >= table_end and line_offset <= len(data) - line_count * 6,
                    f"section {index + 1} line table is invalid",
                )
            self.sections.append(
                {
                    "number": index + 1,
                    "header_offset": header_offset,
                    "name": name,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "relocation_offset": relocation_offset,
                    "relocation_count": relocation_count,
                    "line_offset": line_offset,
                    "line_count": line_count,
                    "characteristics": characteristics,
                }
            )
        require(
            self.symbol_offset >= table_end
            and self.symbol_offset <= len(data) - self.symbol_count * 18,
            "COFF symbol table is invalid",
        )
        self.symbols: dict[int, CoffSymbol] = {}
        symbol_index = 0
        while symbol_index < self.symbol_count:
            offset = self.symbol_offset + symbol_index * 18
            name = self._symbol_name(data[offset : offset + 8])
            value, section, symbol_type, storage, auxiliary_count = coff_unpack(
                "<IhHBB", data, offset + 8, f"symbol {symbol_index}"
            )
            require(
                symbol_index + auxiliary_count < self.symbol_count,
                f"symbol {symbol_index} auxiliary records are truncated",
            )
            self.symbols[symbol_index] = {
                "index": symbol_index,
                "name": name,
                "value": value,
                "section": section,
                "type": symbol_type,
                "storage": storage,
                "aux_count": auxiliary_count,
            }
            symbol_index += 1 + auxiliary_count

    def _string(self, relative: int, context: str) -> str:
        require(
            4 <= relative < self.string_end - self.string_offset,
            f"{context} string offset is invalid",
        )
        absolute = self.string_offset + relative
        end = self.data.find(b"\0", absolute, self.string_end)
        require(end >= 0, f"{context} is not NUL-terminated")
        return self.data[absolute:end].decode("ascii", "strict")

    def _section_name(self, raw: bytes) -> str:
        if raw.startswith(b"/"):
            digits = raw[1:].rstrip(b"\0")
            require(digits.isdigit(), "long COFF section name is invalid")
            return self._string(int(digits), "section name")
        return raw.rstrip(b"\0").decode("ascii", "strict")

    def _symbol_name(self, raw: bytes) -> str:
        if raw[:4] == b"\0\0\0\0":
            (relative,) = coff_unpack("<I", raw, 4, "long symbol name")
            return self._string(relative, "symbol name")
        return raw.rstrip(b"\0").decode("ascii", "strict")

    def function_section(self, mangled: str) -> CoffSection:
        matches = [
            symbol
            for symbol in self.symbols.values()
            if symbol["name"] == mangled
            and symbol["section"] > 0
            and symbol["value"] == 0
            and symbol["type"] == 0x20
            and symbol["storage"] in (2, 3)
        ]
        require(
            len(matches) == 1,
            f"expected one definition of {mangled!r}, found {len(matches)}",
        )
        section = self.sections[int(matches[0]["section"]) - 1]
        require(section["name"].startswith(".text"), f"{mangled!r} is not text")
        require(section["characteristics"] & 0x1000, f"{mangled!r} is not COMDAT")
        return section


def coff_body(coff: CoffObject, section: CoffSection) -> bytes:
    if not section["raw_size"] or section["characteristics"] & 0x80:
        return b""
    start = int(section["raw_offset"])
    return coff.data[start : start + int(section["raw_size"])]


def coff_table(coff: CoffObject, section: CoffSection, kind: str) -> bytes:
    if kind == "relocations":
        start = int(section["relocation_offset"])
        size = int(section["relocation_count"]) * 10
    elif kind == "lines":
        start = int(section["line_offset"])
        size = int(section["line_count"]) * 6
    else:
        raise ByteIdentityError(f"unknown COFF table kind: {kind}")
    return coff.data[start : start + size] if size else b""


def coff_auxiliary(coff: CoffObject, symbol_index: int, symbol: CoffSymbol) -> bytes:
    require(symbol["aux_count"] >= 1, f"symbol {symbol['name']!r} has no auxiliary")
    offset = coff.symbol_offset + (symbol_index + 1) * 18
    return coff.data[offset : offset + 18]


_SECTION_DEFINITIONS_ATTRIBUTE = "_reprobit_section_definitions"


def section_definitions(coff: CoffObject) -> dict[int, CoffSection]:
    """Every COMDAT section definition record of the object, computed once per object."""

    cached = getattr(coff, _SECTION_DEFINITIONS_ATTRIBUTE, None)
    if cached is not None:
        return cast(dict[int, CoffSection], cached)
    result = _section_definitions(coff)
    with suppress(AttributeError):
        setattr(coff, _SECTION_DEFINITIONS_ATTRIBUTE, result)
    return result


def _section_definitions(coff: CoffObject) -> dict[int, CoffSection]:
    result: dict[int, CoffSection] = {}
    for index, symbol in coff.symbols.items():
        if not (
            0 < symbol["section"] <= len(coff.sections)
            and symbol["storage"] == 3
            and symbol["aux_count"] >= 1
        ):
            continue
        section = coff.sections[symbol["section"] - 1]
        if symbol["name"] != section["name"]:
            continue
        auxiliary = coff_auxiliary(coff, index, symbol)
        associated = int.from_bytes(auxiliary[12:14], "little") | (
            int.from_bytes(auxiliary[16:18], "little") << 16
        )
        result[int(section["number"])] = {
            "symbol_index": index,
            "raw": auxiliary,
            "length": int.from_bytes(auxiliary[0:4], "little"),
            "relocations": int.from_bytes(auxiliary[4:6], "little"),
            "lines": int.from_bytes(auxiliary[6:8], "little"),
            "checksum": int.from_bytes(auxiliary[8:12], "little"),
            "associated": associated,
            "selection": auxiliary[14],
        }
    return result


def detailed_relocations(coff: CoffObject, section: CoffSection) -> list[Relocation]:
    result: list[Relocation] = []
    for ordinal in range(int(section["relocation_count"])):
        offset = int(section["relocation_offset"]) + ordinal * 10
        virtual_address, symbol_index, relocation_type = coff_unpack(
            "<IIH",
            coff.data,
            offset,
            f"section {section['number']} relocation {ordinal}",
        )
        require(
            symbol_index in coff.symbols,
            f"section {section['number']} relocation {ordinal} references auxiliary data",
        )
        width = RELOCATION_WIDTHS.get(relocation_type)
        require(width is not None, f"unsupported i386 relocation 0x{relocation_type:04x}")
        require(
            virtual_address <= section["raw_size"] - width,
            f"section {section['number']} relocation {ordinal} escapes raw data",
        )
        operand = int(section["raw_offset"]) + virtual_address
        addend = int.from_bytes(coff.data[operand : operand + width], "little")
        target = coff.symbols[symbol_index]
        result.append(
            {
                "ordinal": ordinal,
                "offset": virtual_address,
                "symbol_index": symbol_index,
                "type": relocation_type,
                "width": width,
                "addend": addend,
                "target": target["name"],
                "target_section": target["section"],
                "target_value": target["value"],
                "target_type": target["type"],
                "target_storage": target["storage"],
            }
        )
    return result


class CoffMetadataIndex:
    """One object-local index for repeated COMDAT and relocation queries."""

    def __init__(self, coff: CoffObject) -> None:
        self.coff = coff
        self.definitions: Mapping[int, CoffSection] = MappingProxyType(section_definitions(coff))
        associated: dict[int, dict[str, CoffSection]] = {}
        for section in coff.sections:
            definition = self.definitions.get(section["number"])
            if definition is None or definition["selection"] != 5:
                continue
            primary_number = int(definition["associated"])
            by_name = associated.setdefault(primary_number, {})
            name = str(section["name"])
            require(name not in by_name, f"duplicate associated COMDAT section {name!r}")
            by_name[name] = section
        self._associated = {
            primary: MappingProxyType(dict(sorted(children.items())))
            for primary, children in associated.items()
        }
        self._relocations: dict[int, tuple[Relocation, ...]] = {}

    def associated(self, primary: CoffSection) -> Mapping[str, CoffSection]:
        """Return associated COMDATs by section name without rescanning the object."""

        self._require_section(primary)
        return self._associated.get(int(primary["number"]), _EMPTY_ASSOCIATED)

    def relocations(self, section: CoffSection) -> tuple[Relocation, ...]:
        """Return one immutable relocation index for a section."""

        number = self._require_section(section)
        cached = self._relocations.get(number)
        if cached is None:
            cached = tuple(detailed_relocations(self.coff, section))
            self._relocations[number] = cached
        return cached

    def _require_section(self, section: CoffSection) -> int:
        number = int(section["number"])
        require(
            0 < number <= len(self.coff.sections) and self.coff.sections[number - 1] is section,
            "COFF metadata index received a section from another object",
        )
        return number


def _associated_names(
    coff: CoffObject,
    section: CoffSection,
    index: CoffMetadataIndex | None = None,
) -> tuple[str, ...]:
    if index is not None:
        require(index.coff is coff, "COFF metadata index belongs to another object")
        return tuple(index.associated(section))
    definitions = section_definitions(coff)
    return tuple(
        sorted(
            item["name"]
            for item in coff.sections
            if definitions.get(item["number"], {}).get("selection") == 5
            and definitions[item["number"]]["associated"] == section["number"]
        )
    )


def _comdat_identity(
    coff: CoffObject,
    section: CoffSection,
    index: CoffMetadataIndex | None = None,
) -> tuple[Any, ...]:
    if index is not None:
        require(index.coff is coff, "COFF metadata index belongs to another object")
        definition = index.definitions.get(section["number"])
    else:
        definition = section_definitions(coff).get(section["number"])
    require(
        definition is not None and definition["selection"] not in (0, 5),
        f"section {section['number']} is not a primary COMDAT",
    )
    assert definition is not None
    owners = [
        symbol
        for symbol in coff.symbols.values()
        if symbol["section"] == section["number"]
        and symbol["value"] == 0
        and symbol["name"] != section["name"]
        and symbol["storage"] in (2, 3)
    ]
    external = [symbol for symbol in owners if symbol["storage"] == 2]
    owners = external or owners
    require(len(owners) == 1, f"COMDAT section {section['number']} has no unique owner")
    owner = owners[0]
    return (
        owner["name"],
        owner["type"],
        owner["storage"],
        section["name"],
        definition["selection"],
        _associated_names(coff, section, index),
    )


def _local_symbol_kind(name: str) -> str | None:
    if len(name) > 2 and name[0] == "$" and name[1] in "LT" and name[2:].isdigit():
        return name[1]
    if name.startswith("$done$") and name[6:].isdigit():
        return "done"
    return None


def require_mosaic_relocation_compatibility(
    seed: CoffObject,
    seed_section: CoffSection,
    donor: CoffObject,
    donor_section: CoffSection,
    context: str,
    *,
    seed_index: CoffMetadataIndex | None = None,
    donor_index: CoffMetadataIndex | None = None,
) -> None:
    """Require same-offset relocation semantics for a donor range campaign."""

    if seed_index is not None:
        require(seed_index.coff is seed, "seed COFF metadata index differs")
    if donor_index is not None:
        require(donor_index.coff is donor, "donor COFF metadata index differs")
    left = (
        seed_index.relocations(seed_section)
        if seed_index is not None
        else tuple(detailed_relocations(seed, seed_section))
    )
    right = (
        donor_index.relocations(donor_section)
        if donor_index is not None
        else tuple(detailed_relocations(donor, donor_section))
    )
    require(len(left) == len(right), f"{context}: relocation counts differ")
    for index, (seed_row, donor_row) in enumerate(zip(left, right, strict=True)):
        require(
            all(seed_row[key] == donor_row[key] for key in ("offset", "type", "width", "addend")),
            f"{context}: relocation {index} geometry differs",
        )
        same_name = seed_row["target"] == donor_row["target"]
        seed_kind = _local_symbol_kind(seed_row["target"])
        donor_kind = _local_symbol_kind(donor_row["target"])
        require(
            same_name or (seed_kind is not None and seed_kind == donor_kind),
            f"{context}: relocation {index} changes symbol identity",
        )
        require(
            all(
                seed_row[key] == donor_row[key]
                for key in ("target_value", "target_type", "target_storage")
            ),
            f"{context}: relocation {index} target structure differs",
        )
        if seed_row["target_section"] == donor_row["target_section"]:
            continue
        require(
            same_name
            and seed_kind is None
            and seed_row["target_section"] > 0
            and donor_row["target_section"] > 0,
            f"{context}: relocation {index} changes target seat",
        )
        seed_target = seed.sections[seed_row["target_section"] - 1]
        donor_target = donor.sections[donor_row["target_section"] - 1]
        require(
            _comdat_identity(seed, seed_target, seed_index)
            == _comdat_identity(donor, donor_target, donor_index),
            f"{context}: relocation {index} reseats a different COMDAT",
        )


def _associated_sections(
    coff: CoffObject,
    primary: CoffSection,
    index: CoffMetadataIndex | None = None,
) -> Mapping[str, CoffSection]:
    if index is not None:
        require(index.coff is coff, "COFF metadata index belongs to another object")
        return index.associated(primary)
    definitions = section_definitions(coff)
    result: dict[str, CoffSection] = {}
    for section in coff.sections:
        definition = definitions.get(section["number"])
        if (
            definition is None
            or definition["selection"] != 5
            or definition["associated"] != primary["number"]
        ):
            continue
        name = section["name"]
        require(name not in result, f"duplicate associated COMDAT section {name!r}")
        result[name] = section
    return result


def _normalized_section_body(
    coff: CoffObject,
    section: CoffSection,
    index: CoffMetadataIndex | None = None,
) -> bytes:
    body = bytearray(coff_body(coff, section))
    relocations = (
        index.relocations(section)
        if index is not None
        else tuple(detailed_relocations(coff, section))
    )
    for relocation in relocations:
        start = relocation["offset"]
        end = start + relocation["width"]
        body[start:end] = b"\0" * relocation["width"]
    return bytes(body)


def require_associated_comdat_compatibility(
    left: CoffObject,
    left_primary: CoffSection,
    right: CoffObject,
    right_primary: CoffSection,
    context: str,
    *,
    left_index: CoffMetadataIndex | None = None,
    right_index: CoffMetadataIndex | None = None,
) -> None:
    """Require equal normalized contents and metadata for associated COMDATs."""

    left_children = _associated_sections(left, left_primary, left_index)
    right_children = _associated_sections(right, right_primary, right_index)
    require(
        tuple(sorted(left_children)) == tuple(sorted(right_children)),
        f"{context}: associated COMDAT names differ",
    )
    left_definitions = (
        left_index.definitions if left_index is not None else section_definitions(left)
    )
    right_definitions = (
        right_index.definitions if right_index is not None else section_definitions(right)
    )
    for name in sorted(left_children):
        left_child = left_children[name]
        right_child = right_children[name]
        left_definition = left_definitions[left_child["number"]]
        right_definition = right_definitions[right_child["number"]]
        require(
            all(
                left_child[key] == right_child[key]
                for key in (
                    "raw_size",
                    "relocation_count",
                    "line_count",
                    "characteristics",
                )
            ),
            f"{context}: associated COMDAT {name!r} geometry differs",
        )
        require(
            all(
                left_definition[key] == right_definition[key]
                for key in (
                    "length",
                    "relocations",
                    "lines",
                    "checksum",
                    "selection",
                )
            ),
            f"{context}: associated COMDAT {name!r} definition differs",
        )
        require(
            _normalized_section_body(left, left_child, left_index)
            == _normalized_section_body(right, right_child, right_index),
            f"{context}: associated COMDAT {name!r} content differs",
        )
        require(
            coff_table(left, left_child, "lines") == coff_table(right, right_child, "lines"),
            f"{context}: associated COMDAT {name!r} line metadata differs",
        )
        require_mosaic_relocation_compatibility(
            left,
            left_child,
            right,
            right_child,
            f"{context}: associated COMDAT {name!r}",
            seed_index=left_index,
            donor_index=right_index,
        )


def coff_mosaic_metadata_digest(
    coff: CoffObject,
    primary: CoffSection,
    *,
    index: CoffMetadataIndex | None = None,
) -> Digest:
    """Hash the target line/relocation tables and associated COMDAT closure."""

    definitions = index.definitions if index is not None else section_definitions(coff)
    children: list[dict[str, Any]] = []
    associated = _associated_sections(coff, primary, index)
    for name in sorted(associated):
        child = associated[name]
        definition = definitions[child["number"]]
        children.append(
            {
                "name": name,
                "section_number": child["number"],
                "raw_size": child["raw_size"],
                "relocation_count": child["relocation_count"],
                "line_count": child["line_count"],
                "characteristics": child["characteristics"],
                "selection": definition["selection"],
                "associated": definition["associated"],
                "body": Digest.from_bytes(coff_body(coff, child)),
                "relocations": Digest.from_bytes(coff_table(coff, child, "relocations")),
                "lines": Digest.from_bytes(coff_table(coff, child, "lines")),
            }
        )
    return Digest.from_bytes(
        canonical_json(
            {
                "target_lines": Digest.from_bytes(coff_table(coff, primary, "lines")),
                "target_relocations": Digest.from_bytes(coff_table(coff, primary, "relocations")),
                "closure": children,
            }
        )
    )


__all__ = [
    "RELOCATION_WIDTHS",
    "CoffMetadataIndex",
    "CoffObject",
    "CoffSection",
    "coff_auxiliary",
    "coff_body",
    "coff_mosaic_metadata_digest",
    "coff_table",
    "coff_unpack",
    "detailed_relocations",
    "require_associated_comdat_compatibility",
    "require_mosaic_relocation_compatibility",
    "section_definitions",
]
