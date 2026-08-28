from __future__ import annotations

import struct

import pytest

from reprobit import classic

POOL_CHARACTERISTICS = 0x40400040
TEXT_CHARACTERISTICS = 0x60500020
PREFIX = b"PREFIX!!"
LITERALS = (("$T1", 4, 8), ("$T2", 8, 16))
NEW_OFFSETS = {"$T2": 8, "$T1": 16}
REFERENCES = (("$T1", 0), ("$T2", 4))


def _pool() -> bytes:
    pool = bytearray(24)
    pool[:8] = PREFIX
    pool[8:12] = b"ONE!"
    pool[16:24] = b"TWO-TWO!"
    return bytes(pool)


POOL = _pool()
PACKED_POOL = PREFIX + b"TWO-TWO!" + b"ONE!"


def _section_aux(length: int, relocations: int, lines: int, number: int) -> bytes:
    return struct.pack("<IHHIHB", length, relocations, lines, 0, number, 0) + b"\0\0\0"


def _object(*, pool: bytes = POOL, references: tuple[tuple[str, int], ...] = REFERENCES) -> bytes:
    names = [("_prefix$S1", 0), *((symbol, offset) for symbol, _, offset in LITERALS)]
    index_of = {name: 4 + index for index, (name, _) in enumerate(names)}
    text_relocations = [(offset, index_of[symbol], 0x0006) for symbol, offset in references]
    debug_relocations = [(0, index_of["_prefix$S1"], 0x000B)]
    debug_lines = struct.pack("<IH", 0, 0) + struct.pack("<IH", 4, 11)
    sections = [
        {
            "name": ".text",
            "raw": bytes(0x20),
            "relocations": text_relocations,
            "lines": b"",
            "characteristics": TEXT_CHARACTERISTICS,
        },
        {
            "name": ".rdata",
            "raw": pool,
            "relocations": [],
            "lines": b"",
            "characteristics": POOL_CHARACTERISTICS,
        },
        {
            "name": ".debug$S",
            "raw": bytes(range(8)),
            "relocations": debug_relocations,
            "lines": debug_lines,
            "characteristics": 0x42101048,
        },
    ]
    offset = 20 + len(sections) * 40
    payload = bytearray()
    for section in sections:
        section["raw_offset"] = offset
        raw = section["raw"]
        assert isinstance(raw, bytes)
        payload.extend(raw)
        offset += len(raw)
        relocations = section["relocations"]
        assert isinstance(relocations, list)
        relocation_table = b"".join(struct.pack("<IIH", *row) for row in relocations)
        section["relocation_offset"] = offset if relocation_table else 0
        payload.extend(relocation_table)
        offset += len(relocation_table)
        lines = section["lines"]
        assert isinstance(lines, bytes)
        section["line_offset"] = offset if lines else 0
        payload.extend(lines)
        offset += len(lines)

    symbols = [
        (".text", 0, 1, 0, 3, _section_aux(0x20, len(text_relocations), 0, 1)),
        (".rdata", 0, 2, 0, 3, _section_aux(len(pool), 0, 0, 2)),
        *((name, value, 2, 0, 3, None) for name, value in names),
        (".debug$S", 0, 3, 0, 3, _section_aux(8, 1, 2, 3)),
    ]
    string_offsets: dict[str, int] = {}
    strings = bytearray(b"\0\0\0\0")

    def encoded(name: str) -> bytes:
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", string_offsets[name])

    symbol_table = bytearray()
    count = 0
    for name, value, section_number, symbol_type, storage, auxiliary in symbols:
        symbol_table.extend(
            encoded(name)
            + struct.pack(
                "<IhHBB",
                value,
                section_number,
                symbol_type,
                storage,
                1 if auxiliary is not None else 0,
            )
        )
        count += 1
        if auxiliary is not None:
            symbol_table.extend(auxiliary)
            count += 1
    struct.pack_into("<I", strings, 0, len(strings))

    headers = bytearray()
    for section in sections:
        raw = section["raw"]
        relocations = section["relocations"]
        lines = section["lines"]
        assert isinstance(raw, bytes)
        assert isinstance(relocations, list)
        assert isinstance(lines, bytes)
        headers.extend(str(section["name"]).encode("ascii").ljust(8, b"\0"))
        headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0,
                0,
                len(raw),
                section["raw_offset"],
                section["relocation_offset"],
                section["line_offset"],
                len(relocations),
                len(lines) // 6,
                section["characteristics"],
            )
        )
    header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0x1234, offset, count, 0, 0)
    return bytes(header + headers + payload + symbol_table + strings)


def _declaration() -> dict[str, object]:
    return {
        "schema": "rdata_pool_repack_v1",
        "rationale": "SYNTHETIC candidate-owned constant-pool ordering construct.",
        "object": "CMakeFiles/fixture.dir/fixture.cpp.obj",
        "translation_unit": "src/fixture.cpp",
        "section": {
            "index": 2,
            "name": ".rdata",
            "characteristics": f"0x{POOL_CHARACTERISTICS:08x}",
            "relocation_count": 0,
            "line_number_count": 0,
        },
        "pad_fill": "00",
        "pre_image": {
            "size": len(POOL),
            "sha256": classic.sha256_bytes(POOL),
            "fixed_prefix": {
                "size": len(PREFIX),
                "sha256": classic.sha256_bytes(PREFIX),
                "symbols": [{"symbol": "_prefix$S1", "offset": 0, "size": len(PREFIX)}],
            },
        },
        "permutation": [
            {"symbol": "$T2", "old_offset": 16, "new_offset": 8, "size": 8, "references": 1},
            {"symbol": "$T1", "old_offset": 8, "new_offset": 16, "size": 4, "references": 1},
        ],
        "post_image": {"size": len(PACKED_POOL), "sha256": classic.sha256_bytes(PACKED_POOL)},
    }


def test_rdata_repack_moves_only_candidate_pool_literals() -> None:
    candidate = _object()
    output, receipt = classic.apply_rdata_pool_repack_candidate(candidate, _declaration())
    parsed = classic.CoffObject(output)
    pool_section = parsed.sections[1]

    assert output[pool_section["raw_offset"] : pool_section["raw_offset"] + 20] == PACKED_POOL
    assert receipt["candidate_only"] is True
    assert receipt["oracle_payload_bytes_read"] == 0
    assert len(output) == len(candidate) - 4


def test_rdata_repack_refuses_a_reference_count_mismatch() -> None:
    declaration = _declaration()
    permutation = declaration["permutation"]
    assert isinstance(permutation, list)
    permutation[0]["references"] = 2
    with pytest.raises(classic.ByteIdentityError, match="reference count differs"):
        classic.apply_rdata_pool_repack_candidate(_object(), declaration)


def test_rdata_repack_refuses_a_drifted_compiler_pool() -> None:
    drifted = bytearray(POOL)
    drifted[9] ^= 1
    with pytest.raises(classic.ByteIdentityError, match="pre-image digest differs"):
        classic.apply_rdata_pool_repack_candidate(_object(pool=bytes(drifted)), _declaration())


def test_rdata_repack_declaration_cannot_carry_target_payload() -> None:
    declaration = _declaration()
    declaration["retail_body"] = PACKED_POOL
    with pytest.raises(classic.ByteIdentityError, match="embedded payload"):
        classic.apply_rdata_pool_repack_candidate(_object(), declaration)
