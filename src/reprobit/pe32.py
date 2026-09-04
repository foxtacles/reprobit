"""Fail-closed PE32 header geometry shared by every image reader.

Each reader of a PE32 image needs the same nine invariants before it may
trust a section: a DOS stub carrying ``MZ``; a PE signature reachable from
``e_lfanew`` with room for the COFF header; an i386 machine; a section count
between one and the format's maximum of 96; an optional header that is at
least as long as the fields the reader consumes and lies inside the file;
the PE32 magic; a section table inside the file; every non-empty raw range
inside the file; and pairwise-disjoint raw ranges.  Reader-specific
requirements (directory minima, ``SizeOfHeaders`` containment, printable
names, ...) remain post-conditions in the reader that needs them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from itertools import pairwise

from reprobit.binary import require

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
MAXIMUM_SECTION_COUNT = 96
SECTION_HEADER_SIZE = 40
MINIMUM_OPTIONAL_HEADER_SIZE = 32
DATA_DIRECTORY_OFFSET = 96
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3

_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")


@dataclass(frozen=True, slots=True)
class Pe32Section:
    """One section-table row with its raw 40-byte descriptor."""

    header_offset: int
    raw_descriptor: bytes
    raw_name: bytes
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size

    def backs_rva(self, rva: int, size: int) -> bool:
        delta = rva - self.virtual_address
        return delta >= 0 and delta <= self.raw_size - size

    def holds_offset(self, offset: int, size: int) -> bool:
        return self.raw_offset <= offset and offset + size <= self.raw_end


@dataclass(frozen=True, slots=True)
class Pe32Headers:
    """Validated PE32 headers; optional-header fields are read on demand."""

    data: bytes
    pe_offset: int
    machine: int
    section_count: int
    optional_offset: int
    optional_size: int
    sections: tuple[Pe32Section, ...]

    @property
    def coff_timestamp_offset(self) -> int:
        return self.pe_offset + 8

    @property
    def section_table_offset(self) -> int:
        return self.optional_offset + self.optional_size

    def optional_field(self, offset: int, label: str) -> int:
        require(
            offset >= 0 and offset + 4 <= self.optional_size,
            f"PE32 optional header lacks {label}",
        )
        return int(struct.unpack_from("<I", self.data, self.optional_offset + offset)[0])

    @property
    def image_base(self) -> int:
        return self.optional_field(28, "ImageBase")

    @property
    def section_alignment(self) -> int:
        return self.optional_field(32, "SectionAlignment")

    @property
    def file_alignment(self) -> int:
        return self.optional_field(36, "FileAlignment")

    @property
    def size_of_image(self) -> int:
        return self.optional_field(56, "SizeOfImage")

    @property
    def size_of_headers(self) -> int:
        return self.optional_field(60, "SizeOfHeaders")

    @property
    def checksum(self) -> int:
        return self.optional_field(64, "CheckSum")

    @property
    def directory_count(self) -> int:
        return self.optional_field(92, "NumberOfRvaAndSizes")

    def data_directory(self, index: int, label: str) -> tuple[int, int]:
        """Return ``(rva, size)`` of one declared data directory."""

        require(0 <= index < self.directory_count, f"PE image lacks {label}")
        at = DATA_DIRECTORY_OFFSET + index * 8
        return self.optional_field(at, label), self.optional_field(at + 4, label)

    def section_for_rva(self, rva: int, size: int = 1, *, context: str) -> Pe32Section:
        require(size >= 0, f"{context} has a negative size")
        matches = [section for section in self.sections if section.backs_rva(rva, size)]
        require(len(matches) == 1, f"{context} does not map uniquely to raw data")
        return matches[0]

    def rva_to_offset(self, rva: int, size: int = 1, *, context: str) -> int:
        section = self.section_for_rva(rva, size, context=context)
        return section.raw_offset + rva - section.virtual_address

    def offset_to_rva(self, offset: int, size: int = 1) -> int:
        matches = [section for section in self.sections if section.holds_offset(offset, size)]
        require(len(matches) == 1, "file range does not map uniquely to a PE section")
        section = matches[0]
        return section.virtual_address + offset - section.raw_offset


def parse_pe32_headers(
    data: bytes,
    *,
    minimum_optional_size: int = MINIMUM_OPTIONAL_HEADER_SIZE,
    require_i386: bool = True,
) -> Pe32Headers:
    """Validate the shared PE32 invariants and return the header geometry."""

    minimum_optional_size = max(minimum_optional_size, MINIMUM_OPTIONAL_HEADER_SIZE)
    require(len(data) >= 64 and data[:2] == b"MZ", "missing DOS MZ header")
    pe = int(struct.unpack_from("<I", data, 0x3C)[0])
    require(64 <= pe <= len(data) - 24 and data[pe : pe + 4] == b"PE\0\0", "missing PE signature")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = int(struct.unpack_from("<H", data, pe + 20)[0])
    if require_i386:
        require(machine == IMAGE_FILE_MACHINE_I386, "only i386 PE images are supported")
    require(0 < count <= MAXIMUM_SECTION_COUNT, "invalid PE section count")
    optional = pe + 24
    require(
        optional_size >= minimum_optional_size and optional + optional_size <= len(data),
        "invalid PE32 optional header",
    )
    require(
        struct.unpack_from("<H", data, optional)[0] == IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        "only PE32 images are supported",
    )
    table = optional + optional_size
    require(table + count * SECTION_HEADER_SIZE <= len(data), "section table extends past EOF")
    sections: list[Pe32Section] = []
    for index in range(count):
        header = table + index * SECTION_HEADER_SIZE
        raw_descriptor = data[header : header + SECTION_HEADER_SIZE]
        (
            raw_name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            _relocation_offset,
            _line_number_offset,
            _relocation_count,
            _line_number_count,
            characteristics,
        ) = _SECTION_HEADER.unpack(raw_descriptor)
        name = raw_name.rstrip(b"\0")
        require(
            raw_size == 0 or raw_offset <= len(data) - raw_size,
            f"section {name!r} raw data extends past EOF",
        )
        sections.append(
            Pe32Section(
                header,
                raw_descriptor,
                raw_name,
                int(virtual_size),
                int(virtual_address),
                int(raw_size),
                int(raw_offset),
                int(characteristics),
            )
        )
    occupied = sorted(
        (section.raw_offset, section.raw_end) for section in sections if section.raw_size
    )
    require(
        all(left[1] <= right[0] for left, right in pairwise(occupied)),
        "PE sections overlap in the file",
    )
    return Pe32Headers(
        data=data,
        pe_offset=pe,
        machine=int(machine),
        section_count=int(count),
        optional_offset=optional,
        optional_size=optional_size,
        sections=tuple(sections),
    )


def pe32_highlow_relocation_offsets(data: bytes) -> frozenset[int]:
    """Return every complete i386 HIGHLOW relocation operand in a PE32 image."""

    headers = parse_pe32_headers(data, minimum_optional_size=144)
    reloc_rva, reloc_size = headers.data_directory(5, "base-relocation directory")
    if reloc_rva == 0 and reloc_size == 0:
        return frozenset()
    require(
        reloc_rva != 0 and reloc_size >= 8,
        "base-relocation directory is malformed",
    )
    start = headers.rva_to_offset(
        reloc_rva,
        reloc_size,
        context="base-relocation directory",
    )
    end = start + reloc_size
    cursor = start
    sites: set[int] = set()
    while cursor < end:
        require(cursor <= end - 8, "base-relocation block header is truncated")
        page_rva, block_size = struct.unpack_from("<II", data, cursor)
        require(page_rva % 0x1000 == 0, "base-relocation page is not aligned")
        require(block_size >= 8 and block_size % 4 == 0, "invalid base-relocation block")
        require(block_size <= end - cursor, "base-relocation block extends past directory")
        for entry_offset in range(cursor + 8, cursor + block_size, 2):
            value = struct.unpack_from("<H", data, entry_offset)[0]
            kind, page_offset = value >> 12, value & 0x0FFF
            if kind in {IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW}:
                if kind == IMAGE_REL_BASED_ABSOLUTE:
                    continue
                site = headers.rva_to_offset(
                    page_rva + page_offset,
                    4,
                    context="HIGHLOW base-relocation operand",
                )
                require(site not in sites, "duplicate HIGHLOW base-relocation site")
                sites.add(site)
        cursor += block_size
    require(cursor == end, "base-relocation directory was not consumed")
    return frozenset(sites)


__all__ = [
    "DATA_DIRECTORY_OFFSET",
    "IMAGE_FILE_MACHINE_I386",
    "IMAGE_NT_OPTIONAL_HDR32_MAGIC",
    "IMAGE_REL_BASED_ABSOLUTE",
    "IMAGE_REL_BASED_HIGHLOW",
    "MAXIMUM_SECTION_COUNT",
    "MINIMUM_OPTIONAL_HEADER_SIZE",
    "SECTION_HEADER_SIZE",
    "Pe32Headers",
    "Pe32Section",
    "parse_pe32_headers",
    "pe32_highlow_relocation_offsets",
]
