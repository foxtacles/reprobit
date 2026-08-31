from __future__ import annotations

import os
import struct
from hashlib import sha256
from pathlib import Path

import pytest

from reprobit.binary import ByteIdentityError
from reprobit.classic.pe_metadata import apply_pe_metadata_candidate, read_pe32_metadata_times
from reprobit.msvc42_debug_companion import (
    MSVC42_DEBUG_PAIR_POLICY,
    stabilize_msvc42_debug_companion,
)
from reprobit.msvc42_pdb import read_msvc42_pdb_identity
from reprobit.msvc42_pe_debug import read_msvc42_debug_companion_identity
from reprobit.small_msf import SMALL_MSF_MAGIC

RAW_TIME = 0x11223344
RAW_RESOURCE_TIME = 0x22334455
EXACT_LINK_TIME = 0x55667788
EXACT_RESOURCE_TIME = 0x66778899
PDB_PATH = r"Z:\work\sample\build\SAMPLE.PDB"

PAGE_SIZE = 1024
PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 24
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 0xE0
EXPORT_OFFSET = 0x200
RESOURCE_OFFSET = 0x400
DEBUG_DIRECTORY_OFFSET = 0x600
NB10_OFFSET = 0x800


def _stream_table(streams: list[tuple[int, int, tuple[int, ...]]]) -> bytes:
    data = bytearray(struct.pack("<HH", len(streams), 0))
    for size, pointer, _pages in streams:
        data.extend(struct.pack("<II", size, pointer))
    for _size, _pointer, pages in streams:
        for page in pages:
            data.extend(struct.pack("<H", page))
    return bytes(data)


def _synthetic_pdb(*, signature: int = RAW_TIME) -> bytes:
    """Build the smallest complete old-PDB shape admitted by the strict policy."""

    stream_zero = _stream_table([(0, 0xA1000010, ())])
    pdb_info = struct.pack("<III", 19950814, signature, 0) + b"named-payload"
    tpi = struct.pack("<IHHIH2x", 19951122, 0x1000, 0x1000, 0, 4)
    dbi = bytearray(24)
    struct.pack_into("<HHH", dbi, 0, 0xFFFF, 0xFFFF, 0xFFFF)
    dbi[6:8] = b"\x71\x72"
    payloads = (stream_zero, pdb_info, tpi, bytes(dbi), b"")
    stream_pages = (17, 18, 19, 20)
    directory_streams: list[tuple[int, int, tuple[int, ...]]] = []
    for index, payload in enumerate(payloads):
        pages = () if not payload else (stream_pages[index],)
        directory_streams.append((len(payload), 0xB0000000 + index, pages))
    directory = _stream_table(directory_streams)

    page_count = 24
    directory_page = 21
    active_fpm = 9
    data = bytearray(page_count * PAGE_SIZE)
    data[: len(SMALL_MSF_MAGIC)] = SMALL_MSF_MAGIC
    struct.pack_into(
        "<IHHII",
        data,
        44,
        PAGE_SIZE,
        active_fpm,
        page_count,
        len(directory),
        0xCAFEBABE,
    )
    struct.pack_into("<H", data, 60, directory_page)
    for page in (17, 22, 23):
        data[active_fpm * PAGE_SIZE + page // 8] |= 1 << (page % 8)
        data[page * PAGE_SIZE : (page + 1) * PAGE_SIZE] = bytes((page,)) * PAGE_SIZE
    for page, payload in zip(stream_pages, payloads[:-1], strict=True):
        data[page * PAGE_SIZE : page * PAGE_SIZE + len(payload)] = payload
    start = directory_page * PAGE_SIZE
    data[start : start + len(directory)] = directory
    return bytes(data)


def _section(
    data: bytearray,
    index: int,
    name: bytes,
    *,
    rva: int,
    raw_offset: int,
) -> None:
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        SECTION_TABLE_OFFSET + index * 40,
        name,
        0x200,
        rva,
        0x200,
        raw_offset,
        0,
        0,
        0,
        0,
        0x40000040,
    )


def _raw_debug_image(
    *,
    pe_time: int = RAW_TIME,
    nb10_signature: int = RAW_TIME,
) -> bytes:
    nb10 = struct.pack("<4sIII", b"NB10", 0, nb10_signature, 0) + PDB_PATH.encode() + b"\0"
    data = bytearray(NB10_OFFSET + len(nb10))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE_OFFSET)
    data[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        PE_OFFSET + 4,
        0x014C,
        3,
        pe_time,
        0,
        0,
        0xE0,
        0x010F,
    )
    struct.pack_into("<H", data, OPTIONAL_OFFSET, 0x010B)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 28, 0x00400000)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 56, 0x4000)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 60, 0x200)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 64, 0)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 92, 16)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 96, 0x1000, 40)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 112, 0x2000, 0x80)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 144, 0x3000, 28)
    _section(data, 0, b".edata\0\0", rva=0x1000, raw_offset=EXPORT_OFFSET)
    _section(data, 1, b".rsrc\0\0\0", rva=0x2000, raw_offset=RESOURCE_OFFSET)
    _section(data, 2, b".rdata\0\0", rva=0x3000, raw_offset=DEBUG_DIRECTORY_OFFSET)

    struct.pack_into("<I", data, EXPORT_OFFSET + 4, RAW_TIME)
    struct.pack_into(
        "<IIHHHH",
        data,
        RESOURCE_OFFSET,
        0,
        RAW_RESOURCE_TIME,
        0,
        0,
        0,
        1,
    )
    struct.pack_into("<II", data, RESOURCE_OFFSET + 16, 1, 0x80000020)
    struct.pack_into(
        "<IIHHHH",
        data,
        RESOURCE_OFFSET + 0x20,
        0,
        RAW_RESOURCE_TIME,
        0,
        0,
        0,
        1,
    )
    struct.pack_into("<II", data, RESOURCE_OFFSET + 0x30, 2, 0x60)
    struct.pack_into(
        "<IIHHIIII",
        data,
        DEBUG_DIRECTORY_OFFSET,
        0,
        pe_time,
        0,
        0,
        2,
        len(nb10),
        0,
        NB10_OFFSET,
    )
    data[NB10_OFFSET:] = nb10
    return bytes(data)


def _certified_image(raw_image: bytes) -> bytes:
    result, _proof = apply_pe_metadata_candidate(
        raw_image,
        {"link_time": EXACT_LINK_TIME, "resource_time": EXACT_RESOURCE_TIME},
    )
    return result


def _stabilize(
    *,
    certified_image: bytes | None = None,
    raw_image: bytes | None = None,
    raw_pdb: bytes | None = None,
):
    image = _raw_debug_image() if raw_image is None else raw_image
    return stabilize_msvc42_debug_companion(
        _certified_image(image) if certified_image is None else certified_image,
        image,
        _synthetic_pdb() if raw_pdb is None else raw_pdb,
        expected_pdb_path=PDB_PATH,
    )


def test_debug_recoupling_precedes_general_pe_metadata_normalization() -> None:
    result = _stabilize()
    debug_writes = {write.file_offset: write for write in result.audit.image_debug.writes}
    metadata_writes = {write.file_offset: write for write in result.audit.image_metadata_writes}

    assert result.audit.policy_version == MSVC42_DEBUG_PAIR_POLICY
    assert result.audit.image_debug.raw_sha256 == sha256(_raw_debug_image()).hexdigest()
    assert result.audit.image_metadata_input_sha256 == result.audit.image_debug.output_sha256
    assert debug_writes[PE_OFFSET + 8].before == RAW_TIME
    assert debug_writes[PE_OFFSET + 8].after == EXACT_LINK_TIME
    assert metadata_writes[PE_OFFSET + 8].before == EXACT_LINK_TIME
    assert metadata_writes[PE_OFFSET + 8].after == EXACT_LINK_TIME
    assert result.audit.image_metadata_output_sha256 == sha256(result.image).hexdigest()
    assert len(result.audit.image_bytes_outside_policy_ranges_sha256) == 64


def test_raw_image_and_pdb_must_be_the_same_producer_pair() -> None:
    with pytest.raises(ByteIdentityError, match=r"raw MSVC 4.2 debug image and PDB identities"):
        _stabilize(raw_pdb=_synthetic_pdb(signature=RAW_TIME + 1))


def test_separate_raw_pe_and_pdb_clock_samples_are_recoupled() -> None:
    raw = _raw_debug_image(pe_time=RAW_TIME + 1)
    result = _stabilize(raw_image=raw)

    assert result.audit.image_debug.input_identity.signature == RAW_TIME
    assert result.audit.image_debug.writes[0].before == RAW_TIME + 1
    assert result.audit.image_debug.output_identity.signature == EXACT_LINK_TIME
    assert result.audit.pdb.output_identity.signature == EXACT_LINK_TIME


def test_certified_image_is_the_only_metadata_authority() -> None:
    raw = _raw_debug_image()
    certified = _certified_image(raw)
    result = _stabilize(certified_image=certified, raw_image=raw)
    changed_certified = bytearray(certified)
    changed_certified[0x70] ^= 0x5A
    same_times = _stabilize(certified_image=bytes(changed_certified), raw_image=raw)

    assert read_pe32_metadata_times(result.image) == read_pe32_metadata_times(certified)
    assert result.audit.times.link_time == EXACT_LINK_TIME
    assert result.audit.times.resource_time == EXACT_RESOURCE_TIME
    assert result.audit.certified_image_sha256 == sha256(certified).hexdigest()
    assert result.image == same_times.image
    assert result.pdb == same_times.pdb
    assert result.audit.certified_image_sha256 != same_times.audit.certified_image_sha256


def test_final_pair_is_recoupled_and_the_whole_composition_is_idempotent() -> None:
    raw_image = _raw_debug_image()
    certified = _certified_image(raw_image)
    first = _stabilize(certified_image=certified, raw_image=raw_image)
    image_identity = read_msvc42_debug_companion_identity(
        first.image,
        expected_pdb_path=PDB_PATH,
    )
    pdb_identity = read_msvc42_pdb_identity(first.pdb)
    second = _stabilize(
        certified_image=certified,
        raw_image=first.image,
        raw_pdb=first.pdb,
    )

    assert image_identity.pdb_identity == pdb_identity
    assert image_identity.signature == EXACT_LINK_TIME
    assert first.audit.image_debug.output_identity.pdb_identity == first.audit.pdb.output_identity
    assert second.image == first.image
    assert second.pdb == first.pdb
    assert second.audit.image_debug.changed_bytes == 0
    assert second.audit.pdb.changed_bytes == 0
    assert (
        second.audit.image_bytes_outside_policy_ranges_sha256
        == first.audit.image_bytes_outside_policy_ranges_sha256
    )
    assert all(write.before == write.after for write in second.audit.image_metadata_writes)


def test_export_and_recursive_resource_timestamps_are_normalized_and_audited() -> None:
    result = _stabilize()
    writes = {write.file_offset: write for write in result.audit.image_metadata_writes}

    assert struct.unpack_from("<I", result.image, EXPORT_OFFSET + 4)[0] == EXACT_LINK_TIME
    assert struct.unpack_from("<I", result.image, RESOURCE_OFFSET + 4)[0] == EXACT_RESOURCE_TIME
    assert struct.unpack_from("<I", result.image, RESOURCE_OFFSET + 0x24)[0] == EXACT_RESOURCE_TIME
    assert set(writes) == {
        PE_OFFSET + 8,
        EXPORT_OFFSET + 4,
        RESOURCE_OFFSET + 4,
        RESOURCE_OFFSET + 0x24,
    }
    assert writes[EXPORT_OFFSET + 4].before == RAW_TIME
    assert writes[RESOURCE_OFFSET + 4].before == RAW_RESOURCE_TIME
    assert writes[RESOURCE_OFFSET + 0x24].before == RAW_RESOURCE_TIME


_REAL_FIXTURES = ("A", "B", "C")


@pytest.mark.parametrize("name", _REAL_FIXTURES)
def test_captured_windows_and_wine_pairs_converge(name: str) -> None:
    wine_root = os.environ.get("REPROBIT_MSVC42_PE_WINE_FIXTURES")
    windows_root = os.environ.get("REPROBIT_MSVC42_PE_WINDOWS_FIXTURES")
    image_name = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_IMAGE")
    pdb_name = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_PDB")
    logical_pdb = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_LOGICAL_PDB")
    certified_name = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_CERTIFIED_IMAGE")
    if None in (
        wine_root,
        windows_root,
        image_name,
        pdb_name,
        logical_pdb,
        certified_name,
    ):
        pytest.skip("set the paired MSVC 4.2 PE/PDB fixture corpus to run convergence")

    assert wine_root is not None
    assert windows_root is not None
    assert image_name is not None
    assert pdb_name is not None
    assert logical_pdb is not None
    assert certified_name is not None
    certified = (Path(wine_root) / certified_name).read_bytes()
    outputs = []
    for root in (Path(wine_root), Path(windows_root)):
        outputs.append(
            stabilize_msvc42_debug_companion(
                certified,
                (root / image_name).read_bytes(),
                (root / pdb_name).read_bytes(),
                expected_pdb_path=logical_pdb,
            )
        )

    assert outputs[0].image == outputs[1].image
    assert outputs[0].pdb == outputs[1].pdb
