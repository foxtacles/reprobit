"""Small, strict readers for the binary formats used by reproduction proofs.

The readers return immutable values and never repair malformed inputs.  A proof
must fail closed when a range, table, or count is inconsistent with the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from reprobit.binary import ByteIdentityError
from reprobit.pe32 import parse_pe32_headers


class FormatError(ValueError):
    """Raised when a binary format is malformed or unsupported."""


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B

_COFF_HEADER = struct.Struct("<HHLLLHH")
_SECTION_HEADER = struct.Struct("<8sLLLLLLHHL")
_RELOCATION = struct.Struct("<LLH")


def _require(data: bytes, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise FormatError(
            f"{label} range [{offset}, {offset + size}) exceeds file size {len(data)}"
        )
    return memoryview(data)[offset : offset + size]


def _ascii_integer(raw: bytes, label: str, *, base: int = 10) -> int:
    value = raw.strip()
    if not value:
        return 0
    try:
        return int(value, base)
    except ValueError as error:
        raise FormatError(f"invalid {label}: {raw!r}") from error


@dataclass(frozen=True, slots=True)
class CoffHeader:
    machine: int
    section_count: int
    timestamp: int
    symbol_table_offset: int
    symbol_count: int
    optional_header_size: int
    characteristics: int


@dataclass(frozen=True, slots=True)
class CoffRelocation:
    virtual_address: int
    symbol_index: int
    type: int


@dataclass(frozen=True, slots=True)
class CoffSection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_data_offset: int
    raw_data: bytes
    relocations: tuple[CoffRelocation, ...]
    characteristics: int


@dataclass(frozen=True, slots=True)
class CoffObject:
    header: CoffHeader
    sections: tuple[CoffSection, ...]
    string_table: bytes

    def section(self, name: str) -> CoffSection:
        matches = [section for section in self.sections if section.name == name]
        if len(matches) != 1:
            raise FormatError(f"expected one section named {name!r}, found {len(matches)}")
        return matches[0]


def _parse_header(data: bytes, offset: int, label: str) -> CoffHeader:
    raw = _require(data, offset, _COFF_HEADER.size, f"{label} header")
    values = _COFF_HEADER.unpack(raw)
    return CoffHeader(*values)


def _coff_string_table(data: bytes, header: CoffHeader) -> bytes:
    if header.symbol_table_offset == 0:
        if header.symbol_count:
            raise FormatError("COFF symbol count is non-zero but its table offset is zero")
        return b""
    symbols_size = header.symbol_count * 18
    strings_at = header.symbol_table_offset + symbols_size
    length_raw = _require(data, strings_at, 4, "COFF string-table length")
    length = struct.unpack("<L", length_raw)[0]
    if length < 4:
        raise FormatError("COFF string table is shorter than its length field")
    return bytes(_require(data, strings_at, length, "COFF string table"))


def _decode_section_name(raw: bytes, string_table: bytes) -> str:
    short = raw.rstrip(b"\0")
    if short.startswith(b"/") and short[1:].isdigit():
        if not string_table:
            raise FormatError("long COFF section name has no string table")
        offset = int(short[1:])
        if offset < 4 or offset >= len(string_table):
            raise FormatError(f"COFF section-name offset {offset} is out of range")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise FormatError("unterminated long COFF section name")
        short = string_table[offset:end]
    try:
        return short.decode("ascii")
    except UnicodeDecodeError as error:
        raise FormatError(f"non-ASCII COFF section name: {short!r}") from error


def _parse_sections(
    data: bytes,
    *,
    table_offset: int,
    count: int,
    string_table: bytes = b"",
) -> tuple[CoffSection, ...]:
    sections: list[CoffSection] = []
    for index in range(count):
        offset = table_offset + index * _SECTION_HEADER.size
        raw = _require(data, offset, _SECTION_HEADER.size, f"section {index} header")
        (
            raw_name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            relocation_offset,
            _line_number_offset,
            relocation_count,
            _line_number_count,
            characteristics,
        ) = _SECTION_HEADER.unpack(raw)
        section_data = (
            bytes(_require(data, raw_offset, raw_size, f"section {index} data"))
            if raw_size
            else b""
        )
        relocations: list[CoffRelocation] = []
        if relocation_count and relocation_offset == 0:
            raise FormatError(f"section {index} has relocations but no relocation offset")
        for relocation_index in range(relocation_count):
            relocation_at = relocation_offset + relocation_index * _RELOCATION.size
            relocation_raw = _require(
                data, relocation_at, _RELOCATION.size, f"section {index} relocation"
            )
            relocations.append(CoffRelocation(*_RELOCATION.unpack(relocation_raw)))
        sections.append(
            CoffSection(
                name=_decode_section_name(raw_name, string_table),
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_data_offset=raw_offset,
                raw_data=section_data,
                relocations=tuple(relocations),
                characteristics=characteristics,
            )
        )
    return tuple(sections)


def parse_coff_object(data: bytes, *, require_i386: bool = True) -> CoffObject:
    """Parse a standard COFF object and validate every referenced range."""

    header = _parse_header(data, 0, "COFF")
    if require_i386 and header.machine != IMAGE_FILE_MACHINE_I386:
        raise FormatError(f"unsupported COFF machine 0x{header.machine:04x}")
    if header.optional_header_size:
        raise FormatError("an object file cannot contain a PE optional header")
    section_table = _COFF_HEADER.size
    _require(
        data,
        section_table,
        header.section_count * _SECTION_HEADER.size,
        "COFF section table",
    )
    string_table = _coff_string_table(data, header)
    sections = _parse_sections(
        data,
        table_offset=section_table,
        count=header.section_count,
        string_table=string_table,
    )
    return CoffObject(header=header, sections=sections, string_table=string_table)


@dataclass(frozen=True, slots=True)
class Pe32Image:
    header: CoffHeader
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    checksum: int
    sections: tuple[CoffSection, ...]
    pe_offset: int

    def rva_to_file_offset(self, rva: int) -> int:
        for section in self.sections:
            extent = max(section.virtual_size, len(section.raw_data))
            if section.virtual_address <= rva < section.virtual_address + extent:
                delta = rva - section.virtual_address
                if delta >= len(section.raw_data):
                    raise FormatError(f"RVA 0x{rva:x} belongs to an unbacked section tail")
                return section.raw_data_offset + delta
        raise FormatError(f"RVA 0x{rva:x} is not mapped by a section")


def parse_pe32(data: bytes, *, require_i386: bool = True) -> Pe32Image:
    """Parse the headers and sections of a PE32 image."""

    if bytes(_require(data, 0, 2, "DOS signature")) != b"MZ":
        raise FormatError("missing DOS MZ signature")
    pe_offset = struct.unpack("<L", _require(data, 0x3C, 4, "PE offset"))[0]
    if pe_offset < 64:
        raise FormatError("PE offset points into the DOS header")
    try:
        headers = parse_pe32_headers(data, minimum_optional_size=68, require_i386=require_i386)
    except ByteIdentityError as error:
        raise FormatError(str(error)) from error
    header = _parse_header(data, pe_offset + 4, "PE COFF")
    sections = _parse_sections(
        data,
        table_offset=headers.section_table_offset,
        count=header.section_count,
    )
    previous_end = 0
    for section in sorted(sections, key=lambda item: item.virtual_address):
        if section.virtual_address < previous_end:
            raise FormatError(f"section {section.name!r} overlaps its neighbor")
        previous_end = section.virtual_address + max(section.virtual_size, len(section.raw_data))
    return Pe32Image(
        header=header,
        image_base=headers.image_base,
        section_alignment=headers.section_alignment,
        file_alignment=headers.file_alignment,
        size_of_image=headers.size_of_image,
        checksum=headers.checksum,
        sections=sections,
        pe_offset=pe_offset,
    )


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    name: str
    timestamp: int
    user_id: int
    group_id: int
    mode: int
    data: bytes


@dataclass(frozen=True, slots=True)
class CoffArchive:
    members: tuple[ArchiveMember, ...]

    def named(self, name: str) -> tuple[ArchiveMember, ...]:
        return tuple(member for member in self.members if member.name == name)


def _gnu_archive_name(raw_name: bytes, long_names: bytes) -> str:
    value = raw_name.rstrip()
    if value.startswith(b"/") and value[1:].isdigit():
        offset = int(value[1:])
        if offset >= len(long_names):
            raise FormatError(f"archive long-name offset {offset} is out of range")
        terminators = (
            long_names.find(b"/\n", offset),
            long_names.find(b"\0", offset),
        )
        candidates = [position for position in terminators if position >= 0]
        if not candidates:
            raise FormatError("unterminated archive long name")
        value = long_names[offset : min(candidates)]
    elif value.endswith(b"/") and value not in {b"/", b"//"}:
        value = value[:-1]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FormatError(f"invalid archive member name: {value!r}") from error


def parse_coff_archive(data: bytes) -> CoffArchive:
    """Parse the common COFF/GNU archive container."""

    if not data.startswith(b"!<arch>\n"):
        raise FormatError("missing archive signature")
    offset = 8
    raw_members: list[tuple[bytes, int, int, int, int, bytes]] = []
    long_names = b""
    while offset < len(data):
        header = bytes(_require(data, offset, 60, "archive member header"))
        if header[58:60] != b"`\n":
            raise FormatError(f"invalid archive member trailer at offset {offset}")
        size = _ascii_integer(header[48:58], "archive member size")
        member_data = bytes(_require(data, offset + 60, size, "archive member data"))
        raw_name = header[:16]
        if raw_name.rstrip() == b"//":
            long_names = member_data
        raw_members.append(
            (
                raw_name,
                _ascii_integer(header[16:28], "archive timestamp"),
                _ascii_integer(header[28:34], "archive user id"),
                _ascii_integer(header[34:40], "archive group id"),
                _ascii_integer(header[40:48], "archive mode", base=8),
                member_data,
            )
        )
        offset += 60 + size + (size & 1)
    if offset != len(data):
        raise FormatError("archive has an incomplete alignment byte")

    members: list[ArchiveMember] = []
    for raw_name, timestamp, user_id, group_id, mode, member_data in raw_members:
        value = raw_name.rstrip()
        if value.startswith(b"#1/"):
            name_length = _ascii_integer(value[3:], "BSD archive name length")
            name_raw = bytes(_require(member_data, 0, name_length, "BSD archive member name"))
            try:
                name = name_raw.rstrip(b"\0").decode("utf-8")
            except UnicodeDecodeError as error:
                raise FormatError(f"invalid BSD archive member name: {name_raw!r}") from error
            member_data = member_data[name_length:]
        else:
            name = _gnu_archive_name(raw_name, long_names)
        members.append(
            ArchiveMember(
                name=name,
                timestamp=timestamp,
                user_id=user_id,
                group_id=group_id,
                mode=mode,
                data=member_data,
            )
        )
    return CoffArchive(tuple(members))
