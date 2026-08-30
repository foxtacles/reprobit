from __future__ import annotations

import struct

import pytest

import reprobit.classic.pe_metadata as pe_metadata_algorithms
from reprobit.binary import ByteIdentityError

PE = 0x80
OPTIONAL = PE + 24
SECTIONS = OPTIONAL + 0xE0
EDATA_RAW = 0x200
RSRC_RAW = 0x400
EDATA_RVA = 0x1000
RSRC_RVA = 0x2000


def _image(*, cyclic_resource: bool = False) -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE)
    data[PE : PE + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, PE + 4, 0x14C, 2, 11, 0, 0, 0xE0, 0x10F)
    struct.pack_into("<H", data, OPTIONAL, 0x10B)
    struct.pack_into("<I", data, OPTIONAL + 28, 0x400000)
    struct.pack_into("<I", data, OPTIONAL + 32, 0x1000)
    struct.pack_into("<I", data, OPTIONAL + 92, 16)
    struct.pack_into("<II", data, OPTIONAL + 96, EDATA_RVA, 40)
    struct.pack_into("<II", data, OPTIONAL + 112, RSRC_RVA, 0x80)
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        SECTIONS,
        b".edata\0\0",
        0x100,
        EDATA_RVA,
        0x200,
        EDATA_RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        SECTIONS + 40,
        b".rsrc\0\0\0",
        0x100,
        RSRC_RVA,
        0x200,
        RSRC_RAW,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    struct.pack_into("<I", data, EDATA_RAW + 4, 22)
    struct.pack_into("<IIHHHH", data, RSRC_RAW, 0, 33, 0, 0, 0, 1)
    struct.pack_into("<II", data, RSRC_RAW + 16, 1, 0x80000020)
    struct.pack_into("<IIHHHH", data, RSRC_RAW + 0x20, 0, 44, 0, 0, 0, 1)
    struct.pack_into(
        "<II",
        data,
        RSRC_RAW + 0x30,
        2,
        0x80000000 if cyclic_resource else 0x60,
    )
    return bytes(data)


def test_pe_metadata_normalizes_only_declared_timestamp_fields() -> None:
    source = _image()
    result, proof = pe_metadata_algorithms.apply_pe_metadata_candidate(
        source,
        {"link_time": 123, "resource_time": 456},
    )

    assert struct.unpack_from("<I", result, PE + 8)[0] == 123
    assert struct.unpack_from("<I", result, EDATA_RAW + 4)[0] == 123
    assert struct.unpack_from("<I", result, RSRC_RAW + 4)[0] == 456
    assert struct.unpack_from("<I", result, RSRC_RAW + 0x24)[0] == 456
    assert proof["candidate_only"] is True
    assert proof["oracle_payload_bytes_read"] == 0
    allowed = {
        byte
        for offset in (PE + 8, EDATA_RAW + 4, RSRC_RAW + 4, RSRC_RAW + 0x24)
        for byte in range(offset, offset + 4)
    }
    assert {
        index for index, pair in enumerate(zip(source, result, strict=True)) if pair[0] != pair[1]
    } <= allowed

    assert pe_metadata_algorithms.read_pe32_metadata_times(result) == (
        pe_metadata_algorithms.PE32MetadataTimes(123, 456)
    )


def test_pe_metadata_reader_rejects_incoherent_link_timestamp() -> None:
    source, _proof = pe_metadata_algorithms.apply_pe_metadata_candidate(
        _image(),
        {"link_time": 123, "resource_time": 456},
    )
    changed = bytearray(source)
    struct.pack_into("<I", changed, EDATA_RAW + 4, 999)

    with pytest.raises(ByteIdentityError, match="export timestamp"):
        pe_metadata_algorithms.read_pe32_metadata_times(bytes(changed))


def test_pe_metadata_reader_rejects_incoherent_resource_timestamps() -> None:
    source, _proof = pe_metadata_algorithms.apply_pe_metadata_candidate(
        _image(),
        {"link_time": 123, "resource_time": 456},
    )
    changed = bytearray(source)
    struct.pack_into("<I", changed, RSRC_RAW + 0x24, 999)

    with pytest.raises(ByteIdentityError, match="resource directories"):
        pe_metadata_algorithms.read_pe32_metadata_times(bytes(changed))


def test_pe_metadata_rejects_resource_cycles() -> None:
    with pytest.raises(ByteIdentityError, match="cycle"):
        pe_metadata_algorithms.apply_pe_metadata_candidate(
            _image(cyclic_resource=True),
            {"link_time": 123, "resource_time": 456},
        )


def test_pe_metadata_rejects_payload_fields() -> None:
    with pytest.raises(ByteIdentityError, match="payload"):
        pe_metadata_algorithms.apply_pe_metadata_candidate(
            _image(),
            {"link_time": 123, "resource_time": 456, "payload": "AAAA"},
        )
