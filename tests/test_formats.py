from __future__ import annotations

import struct

import pytest

from reprobit.formats import (
    IMAGE_FILE_MACHINE_I386,
    FormatError,
    parse_coff_archive,
    parse_coff_object,
    parse_pe32,
)


def _coff_object() -> bytes:
    header = struct.pack("<HHLLLHH", IMAGE_FILE_MACHINE_I386, 1, 7, 74, 0, 0, 0)
    section = struct.pack(
        "<8sLLLLLLHHL",
        b".text\0\0\0",
        4,
        0,
        4,
        60,
        64,
        0,
        1,
        0,
        0x60000020,
    )
    relocation = struct.pack("<LLH", 1, 3, 6)
    return header + section + b"\x90\x90\xc3\x00" + relocation + struct.pack("<L", 4)


def test_parse_i386_coff_sections_and_relocations() -> None:
    parsed = parse_coff_object(_coff_object())

    assert parsed.header.timestamp == 7
    assert parsed.section(".text").raw_data == b"\x90\x90\xc3\x00"
    assert parsed.section(".text").relocations[0].symbol_index == 3


def test_coff_reader_rejects_out_of_bounds_tables() -> None:
    malformed = bytearray(_coff_object())
    struct.pack_into("<L", malformed, 20 + 24, 1000)
    with pytest.raises(FormatError, match="exceeds file size"):
        parse_coff_object(bytes(malformed))


def _pe32() -> bytes:
    pe_offset = 0x80
    optional_size = 224
    section_table = pe_offset + 4 + 20 + optional_size
    raw_offset = section_table + 40
    data = bytearray(raw_offset + 4)
    data[:2] = b"MZ"
    struct.pack_into("<L", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHLLLHH",
        data,
        pe_offset + 4,
        IMAGE_FILE_MACHINE_I386,
        1,
        11,
        0,
        0,
        optional_size,
        0x010F,
    )
    optional_at = pe_offset + 24
    struct.pack_into("<H", data, optional_at, 0x10B)
    struct.pack_into("<L", data, optional_at + 28, 0x400000)
    struct.pack_into("<L", data, optional_at + 32, 0x1000)
    struct.pack_into("<L", data, optional_at + 36, 0x200)
    struct.pack_into("<L", data, optional_at + 56, 0x2000)
    struct.pack_into("<L", data, optional_at + 64, 0x1234)
    struct.pack_into(
        "<8sLLLLLLHHL",
        data,
        section_table,
        b".text\0\0\0",
        4,
        0x1000,
        4,
        raw_offset,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[raw_offset:] = b"CODE"
    return bytes(data)


def test_parse_pe32_and_map_rva() -> None:
    image = parse_pe32(_pe32())

    assert image.image_base == 0x400000
    assert image.checksum == 0x1234
    assert image.rva_to_file_offset(0x1002) == image.sections[0].raw_data_offset + 2
    with pytest.raises(FormatError, match="not mapped"):
        image.rva_to_file_offset(0x3000)


def _archive_member(name: bytes, payload: bytes) -> bytes:
    header = (
        name.ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(payload)).encode().ljust(10)
        + b"`\n"
    )
    return header + payload + (b"\n" if len(payload) & 1 else b"")


def test_parse_archive_preserves_member_metadata_and_payload() -> None:
    data = b"!<arch>\n" + _archive_member(b"module.obj/", b"abc")
    archive = parse_coff_archive(data)

    assert archive.members[0].name == "module.obj"
    assert archive.members[0].mode == 0o100644
    assert archive.named("module.obj")[0].data == b"abc"


def test_archive_rejects_bad_trailer() -> None:
    data = bytearray(b"!<arch>\n" + _archive_member(b"unit.obj/", b"x"))
    data[8 + 58 : 8 + 60] = b"xx"
    with pytest.raises(FormatError, match="trailer"):
        parse_coff_archive(bytes(data))


def test_parse_pe32_rejects_pe_offset_inside_dos_header():
    """A forged e_lfanew pointing back into the DOS header is refused even
    when the signature bytes happen to appear there."""
    image = bytearray(_pe32())
    image[0x10:0x14] = b"PE\0\0"
    image[0x3C:0x40] = (0x10).to_bytes(4, "little")
    with pytest.raises(FormatError, match="DOS header"):
        parse_pe32(bytes(image))
