from __future__ import annotations

import struct

import pytest

from reprobit import classic

PE = 0x80
OPTIONAL = PE + 24
SECTIONS = OPTIONAL + 0xE0
TEXT_RAW = 0x200
IDATA_RAW = 0x400
RELOC_RAW = 0x800
TEXT_RVA = 0x1000
IDATA_RVA = 0x2000
RELOC_RVA = 0x3000
IMAGE_BASE = 0x400000
IMAGE_ORDINAL_FLAG32 = 0x80000000
OFT_RVA = IDATA_RVA + 0x80
FT_RVA = IDATA_RVA + 0xC0


def _named(name: str, occurrence: int = 0) -> tuple[str, str, int]:
    return ("name", name, occurrence)


def _ordinal(value: int) -> tuple[str, int, int]:
    return ("ordinal", value, 0)


def _image(order: list[tuple[str, str | int, int]]) -> bytes:
    data = bytearray(0xA00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE)
    data[PE : PE + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, PE + 4, 0x14C, 3, 0, 0, 0, 0xE0, 0x10F)
    struct.pack_into("<H", data, OPTIONAL, 0x10B)
    struct.pack_into("<I", data, OPTIONAL + 28, IMAGE_BASE)
    struct.pack_into("<I", data, OPTIONAL + 32, 0x1000)
    struct.pack_into("<I", data, OPTIONAL + 92, 16)
    struct.pack_into("<II", data, OPTIONAL + 104, IDATA_RVA, 40)
    for offset, values in (
        (SECTIONS, (b".text\0\0\0", 0x100, TEXT_RVA, 0x200, TEXT_RAW, 0x60000020)),
        (SECTIONS + 40, (b".idata\0\0", 0x300, IDATA_RVA, 0x400, IDATA_RAW, 0xC0000040)),
        (SECTIONS + 80, (b".reloc\0\0", 0x200, RELOC_RVA, 0x200, RELOC_RAW, 0x42000040)),
    ):
        name, virtual_size, rva, raw_size, raw_offset, flags = values
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            offset,
            name,
            virtual_size,
            rva,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            flags,
        )
    name_rva = IDATA_RVA + 0x40
    struct.pack_into("<IIIII", data, IDATA_RAW, OFT_RVA, 0, 0, name_rva, FT_RVA)
    data[IDATA_RAW + 0x40 : IDATA_RAW + 0x4C] = b"TESTDLL.DLL\0"
    named = sorted(
        {item for item in order if item[0] == "name"}, key=lambda item: (item[1], item[2])
    )
    name_thunks = {}
    for index, token in enumerate(named):
        rva = IDATA_RVA + 0x100 + index * 0x20
        name_thunks[token] = rva
        offset = IDATA_RAW + rva - IDATA_RVA
        struct.pack_into("<H", data, offset, index)
        encoded = str(token[1]).encode("ascii") + b"\0"
        data[offset + 2 : offset + 2 + len(encoded)] = encoded
    for index, token in enumerate(order):
        thunk = (
            IMAGE_ORDINAL_FLAG32 | int(token[1]) if token[0] == "ordinal" else name_thunks[token]
        )
        struct.pack_into("<I", data, IDATA_RAW + OFT_RVA - IDATA_RVA + index * 4, thunk)
        struct.pack_into("<I", data, IDATA_RAW + FT_RVA - IDATA_RVA + index * 4, thunk)
        struct.pack_into("<I", data, TEXT_RAW + 0x10 + index * 8, IMAGE_BASE + FT_RVA + index * 4)
    relocations = [0x3000 | (0x10 + index * 8) for index in range(len(order))]
    size = 8 + len(relocations) * 2
    if size % 4:
        relocations.append(0)
        size += 2
    struct.pack_into("<II", data, RELOC_RAW, TEXT_RVA, size)
    for index, item in enumerate(relocations):
        struct.pack_into("<H", data, RELOC_RAW + 8 + index * 2, item)
    struct.pack_into("<II", data, OPTIONAL + 136, RELOC_RVA, size)
    return bytes(data)


def test_import_order_uses_locked_identities_and_candidate_thunks() -> None:
    alpha = _named("Alpha")
    beta = _named("Beta")
    ordinal = _ordinal(17)
    candidate = _image([alpha, ordinal, beta])
    declaration = classic.capture_pe_import_order(_image([beta, alpha, ordinal]))

    output, proof = classic.apply_pe_import_order_candidate(candidate, declaration)

    assert proof["total_slots"] == 3
    assert proof["moved_slots"] == 3
    assert proof["rewritten_operands"] == 3
    assert proof["candidate_only"] is True
    assert classic.capture_pe_import_order(output)["imports"] == declaration["imports"]


def test_duplicate_import_occurrences_are_not_collapsed() -> None:
    duplicate_0 = _named("Duplicate", 0)
    duplicate_1 = _named("Duplicate", 1)
    beta = _named("Beta")
    candidate = _image([duplicate_0, duplicate_1, beta])
    declaration = classic.capture_pe_import_order(_image([duplicate_1, beta, duplicate_0]))

    _, proof = classic.apply_pe_import_order_candidate(candidate, declaration)

    assert proof["total_slots"] == 3
    assert proof["moved_slots"] == 2


def test_unrelocated_iat_looking_operand_refuses() -> None:
    alpha = _named("Alpha")
    beta = _named("Beta")
    candidate = bytearray(_image([alpha, beta]))
    struct.pack_into("<H", candidate, RELOC_RAW + 8, 0x0010)
    declaration = classic.capture_pe_import_order(_image([beta, alpha]))

    with pytest.raises(classic.ByteIdentityError, match="lack HIGHLOW"):
        classic.apply_pe_import_order_candidate(bytes(candidate), declaration)


def test_import_order_declaration_carries_no_reference_payload() -> None:
    declaration = classic.capture_pe_import_order(_image([_named("Alpha")]))
    assert "payload" not in repr(declaration).casefold()
    with pytest.raises(classic.ByteIdentityError, match="payload"):
        classic.apply_pe_import_order_candidate(
            _image([_named("Alpha")]),
            {**declaration, "reference_payload": "AAAA"},
        )
