from __future__ import annotations

import struct
from collections.abc import Callable

import pytest

import reprobit.classic.pe as pe_algorithms
import reprobit.classic.pe_imports as pe_import_algorithms
import reprobit.classic.pe_metadata as pe_metadata_algorithms
import reprobit.classic.pe_text as pe_text_algorithms
import reprobit.msvc42_pe_debug as pe_debug
from reprobit.binary import ByteIdentityError
from reprobit.formats import FormatError, parse_pe32
from reprobit.pe32 import parse_pe32_headers

PE = 0x80
OPTIONAL = PE + 24
OPTIONAL_SIZE = 224
TABLE = OPTIONAL + OPTIONAL_SIZE
SIZE_OF_HEADERS = 0x400
TEXT_RAW = 0x400
RDATA_RAW = 0x600
IMAGE_SIZE = 0x800
PDB_PATH = "C:\\build\\test.pdb"


def _image() -> bytearray:
    data = bytearray(IMAGE_SIZE)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE)
    data[PE : PE + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, PE + 4, 0x14C, 2, 0x1234, 0, 0, OPTIONAL_SIZE, 0x10F)
    struct.pack_into("<H", data, OPTIONAL, 0x10B)
    struct.pack_into("<I", data, OPTIONAL + 28, 0x400000)
    struct.pack_into("<II", data, OPTIONAL + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, OPTIONAL + 56, 0x3000)
    struct.pack_into("<I", data, OPTIONAL + 60, SIZE_OF_HEADERS)
    struct.pack_into("<I", data, OPTIONAL + 64, 0)
    struct.pack_into("<I", data, OPTIONAL + 92, 16)
    for index, (name, rva, raw) in enumerate(
        ((b".text\0\0\0", 0x1000, TEXT_RAW), (b".rdata\0\0", 0x2000, RDATA_RAW))
    ):
        struct.pack_into(
            "<8sIIIIIIHHI", data, TABLE + index * 40, name, 0x100, rva, 0x200, raw, 0, 0, 0, 0, 0
        )
    data[TEXT_RAW : TEXT_RAW + 4] = b"CODE"
    return data


def _set(offset: int, layout: str, *values: int) -> Callable[[bytearray], None]:
    def corrupt(data: bytearray) -> None:
        struct.pack_into(layout, data, offset, *values)

    return corrupt


def _bytes(offset: int, value: bytes) -> Callable[[bytearray], None]:
    def corrupt(data: bytearray) -> None:
        data[offset : offset + len(value)] = value

    return corrupt


SHARED_CORRUPTIONS = (
    pytest.param(_bytes(0, b"XX"), "MZ", id="dos-signature"),
    pytest.param(_bytes(PE, b"PX\0\0"), "PE signature", id="pe-signature"),
    pytest.param(_set(0x3C, "<I", IMAGE_SIZE - 20), "PE signature", id="pe-offset-past-eof"),
    pytest.param(_set(PE + 4, "<H", 0x8664), "i386", id="machine"),
    pytest.param(_set(PE + 6, "<H", 0), "section count", id="zero-sections"),
    pytest.param(_set(PE + 6, "<H", 97), "section count", id="too-many-sections"),
    pytest.param(_set(PE + 20, "<H", 16), "optional header", id="short-optional-header"),
    pytest.param(_set(PE + 20, "<H", 0xFFFF), "optional header", id="optional-header-past-eof"),
    pytest.param(_set(OPTIONAL, "<H", 0x20B), "PE32", id="pe32-plus-magic"),
    pytest.param(_set(PE + 6, "<H", 42), "section table", id="section-table-past-eof"),
    pytest.param(_set(TABLE + 20, "<I", 0x700), "raw data extends past EOF", id="raw-past-eof"),
    pytest.param(_set(TABLE + 40 + 20, "<I", 0x500), "overlap", id="raw-ranges-overlap"),
)


def _pe_debug_map(data: bytes) -> object:
    return pe_debug._Pe32DebugMap(data, PDB_PATH)


WRAPPERS = (
    pytest.param(parse_pe32_headers, ByteIdentityError, None, id="core"),
    pytest.param(pe_algorithms._PE32AddressMap, ByteIdentityError, None, id="classic.pe"),
    pytest.param(pe_text_algorithms._PE32, ByteIdentityError, None, id="classic.pe_text"),
    pytest.param(
        pe_metadata_algorithms._PE32MetadataMap, ByteIdentityError, None, id="classic.pe_metadata"
    ),
    pytest.param(
        pe_import_algorithms._PE32Imports,
        ByteIdentityError,
        "missing or undersized import directory",
        id="classic.pe_imports",
    ),
    pytest.param(
        _pe_debug_map,
        ByteIdentityError,
        "PE debug data directory is missing or malformed",
        id="msvc42_pe_debug",
    ),
    pytest.param(parse_pe32, FormatError, None, id="formats"),
)


@pytest.mark.parametrize(("reader", "error", "baseline_failure"), WRAPPERS)
def test_readers_accept_the_shared_baseline_headers(
    reader: Callable[[bytes], object],
    error: type[Exception],
    baseline_failure: str | None,
) -> None:
    if baseline_failure is None:
        reader(bytes(_image()))
        return
    with pytest.raises(error, match=baseline_failure):
        reader(bytes(_image()))


@pytest.mark.parametrize(("reader", "error", "_baseline"), WRAPPERS)
@pytest.mark.parametrize(("corrupt", "message"), SHARED_CORRUPTIONS)
def test_every_reader_rejects_each_shared_invariant_violation(
    reader: Callable[[bytes], object],
    error: type[Exception],
    _baseline: str | None,
    corrupt: Callable[[bytearray], None],
    message: str,
) -> None:
    data = _image()
    corrupt(data)
    with pytest.raises(error, match=message):
        reader(bytes(data))


@pytest.mark.parametrize(
    ("reader", "corrupt", "message"),
    (
        pytest.param(
            pe_metadata_algorithms._PE32MetadataMap,
            _set(OPTIONAL + 92, "<I", 2),
            "lacks export/resource directories",
            id="pe_metadata-directories",
        ),
        pytest.param(
            pe_import_algorithms._PE32Imports,
            _set(OPTIONAL + 92, "<I", 5),
            "lacks import/base-relocation directories",
            id="pe_imports-directories",
        ),
        pytest.param(
            pe_import_algorithms._PE32Imports,
            _set(OPTIONAL + 32, "<I", 0),
            "section alignment must be nonzero",
            id="pe_imports-alignment",
        ),
        pytest.param(
            pe_text_algorithms._PE32,
            _bytes(TABLE, b"\x01text\0\0\0"),
            "invalid PE section name",
            id="pe_text-name",
        ),
        pytest.param(
            _pe_debug_map,
            _set(OPTIONAL + 64, "<I", 1),
            "checksum is not zero",
            id="pe_debug-checksum",
        ),
        pytest.param(
            _pe_debug_map,
            _set(OPTIONAL + 92, "<I", 6),
            "lacks the PE debug data directory",
            id="pe_debug-directories",
        ),
        pytest.param(
            _pe_debug_map,
            _set(OPTIONAL + 60, "<I", 0x100),
            "outside SizeOfHeaders",
            id="pe_debug-size-of-headers",
        ),
        pytest.param(
            _pe_debug_map,
            _set(TABLE + 20, "<I", 0x200),
            "raw data is invalid",
            id="pe_debug-raw-below-headers",
        ),
    ),
)
def test_reader_specific_post_conditions_survive(
    reader: Callable[[bytes], object],
    corrupt: Callable[[bytearray], None],
    message: str,
) -> None:
    data = _image()
    corrupt(data)
    with pytest.raises(ByteIdentityError, match=message):
        reader(bytes(data))


def test_pe_imports_rejects_non_ascii_section_names_with_value_error() -> None:
    data = _image()
    data[TABLE : TABLE + 8] = b".t\xffxt\0\0\0"
    with pytest.raises(ValueError, match="not ASCII"):
        pe_import_algorithms._PE32Imports(bytes(data))


def test_formats_keeps_its_own_dos_header_and_virtual_overlap_checks() -> None:
    forged = _image()
    forged[0x10:0x14] = b"PE\0\0"
    struct.pack_into("<I", forged, 0x3C, 0x10)
    with pytest.raises(FormatError, match="DOS header"):
        parse_pe32(bytes(forged))

    overlapping = _image()
    struct.pack_into("<I", overlapping, TABLE + 40 + 12, 0x1050)
    with pytest.raises(FormatError, match="overlaps its neighbor"):
        parse_pe32(bytes(overlapping))


def test_core_exposes_geometry_and_maps_ranges_uniquely() -> None:
    headers = parse_pe32_headers(bytes(_image()))

    assert headers.pe_offset == PE
    assert headers.coff_timestamp_offset == PE + 8
    assert headers.section_table_offset == TABLE
    assert headers.section_count == 2
    assert (headers.image_base, headers.section_alignment, headers.file_alignment) == (
        0x400000,
        0x1000,
        0x200,
    )
    assert (headers.size_of_image, headers.size_of_headers, headers.checksum) == (
        0x3000,
        SIZE_OF_HEADERS,
        0,
    )
    assert headers.directory_count == 16
    assert headers.data_directory(6, "debug") == (0, 0)
    assert headers.rva_to_offset(0x1004, 4, context="probe") == TEXT_RAW + 4
    assert headers.offset_to_rva(RDATA_RAW + 8, 2) == 0x2008
    assert headers.sections[0].raw_name == b".text\0\0\0"
    assert headers.sections[1].header_offset == TABLE + 40
    with pytest.raises(ByteIdentityError, match="lacks the export directory"):
        headers.data_directory(16, "the export directory")
    with pytest.raises(ByteIdentityError, match="probe has a negative size"):
        headers.rva_to_offset(0x1000, -1, context="probe")
    with pytest.raises(ByteIdentityError, match="probe does not map uniquely"):
        headers.rva_to_offset(0x1000, 0x201, context="probe")
    with pytest.raises(ByteIdentityError, match="does not map uniquely to a PE section"):
        headers.offset_to_rva(TEXT_RAW + 0x1FF, 2)
    with pytest.raises(ByteIdentityError, match="lacks the trailing field"):
        headers.optional_field(OPTIONAL_SIZE - 2, "the trailing field")


def test_core_never_admits_optional_headers_below_the_format_minimum() -> None:
    data = _image()
    struct.pack_into("<H", data, PE + 20, 28)
    with pytest.raises(ByteIdentityError, match="optional header"):
        parse_pe32_headers(bytes(data), minimum_optional_size=0)
