from __future__ import annotations

import struct

import pytest

import reprobit.classic.foundation as foundation_algorithms
import reprobit.classic.pe as pe_algorithms
import reprobit.classic.pe_text as pe_text_algorithms
from reprobit.binary import ByteIdentityError


def _candidate_and_expected() -> tuple[bytes, bytes, int, list[int]]:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    section = optional + 0xE0
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section,
        b".text\0\0\0",
        0x100,
        0x1000,
        0x100,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    first_call = 0x200
    second_call = 0x205
    pair = 0x220
    data[first_call] = data[second_call] = 0xE8
    data[first_call + 1 : first_call + 5] = (0x1B).to_bytes(4, "little", signed=True)
    data[second_call + 1 : second_call + 5] = (0x1C).to_bytes(4, "little", signed=True)
    data[pair : pair + 12] = bytes.fromhex("ff2500504000ff2504504000")

    expected = bytearray(data)
    expected[pair + 2 : pair + 6], expected[pair + 8 : pair + 12] = (
        data[pair + 8 : pair + 12],
        data[pair + 2 : pair + 6],
    )
    expected[first_call + 1 : first_call + 5] = (0x21).to_bytes(4, "little", signed=True)
    expected[second_call + 1 : second_call + 5] = (0x16).to_bytes(4, "little", signed=True)
    return bytes(data), bytes(expected), pair, [first_call, second_call]


def _plan(candidate: bytes, expected: bytes, pair: int, calls: list[int]) -> dict[str, object]:
    return {
        "schema": "adjacent_import_thunk_swap_v1",
        "pair_file_offset": pair,
        "call_file_offsets": calls,
        "input_sha256": foundation_algorithms.sha256_bytes(candidate),
        "output_sha256": foundation_algorithms.sha256_bytes(expected),
    }


def test_declarative_thunk_swap_uses_only_candidate_bytes() -> None:
    candidate, expected, pair, calls = _candidate_and_expected()
    output, receipt = pe_algorithms.apply_adjacent_import_thunk_swap(
        candidate, _plan(candidate, expected, pair, calls)
    )

    assert output == expected
    assert receipt["candidate_only"] is True
    assert receipt["oracle_payload_bytes_read"] == 0
    assert candidate[pair + 2 : pair + 6] == output[pair + 8 : pair + 12]
    assert candidate[pair + 8 : pair + 12] == output[pair + 2 : pair + 6]


def test_thunk_swap_refuses_a_postimage_pin_that_does_not_match() -> None:
    candidate, expected, pair, calls = _candidate_and_expected()
    plan = _plan(candidate, expected, pair, calls)
    plan["output_sha256"] = "0" * 64
    with pytest.raises(ByteIdentityError, match="output pin"):
        pe_algorithms.apply_adjacent_import_thunk_swap(candidate, plan)


def test_thunk_swap_declaration_cannot_carry_target_payload() -> None:
    candidate, expected, pair, calls = _candidate_and_expected()
    plan = _plan(candidate, expected, pair, calls)
    plan["target_bytes"] = expected.hex()
    with pytest.raises(ByteIdentityError, match=r"embedded payload|unknown"):
        pe_algorithms.apply_adjacent_import_thunk_swap(candidate, plan)


def _text_repack_candidate_and_plan() -> tuple[bytes, bytes, dict[str, object]]:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    section = optional + 0xE0
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section,
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section + 40,
        b".reloc\0\0",
        8,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x42000040,
    )
    data[0x210:0x214] = b"\xcc" * 4
    data[0x214:0x218] = b"\x01\x02\x03\x04"

    expected = bytearray(data)
    expected[0x210:0x214] = data[0x214:0x218]
    expected[0x214:0x218] = b"\0" * 4
    struct.pack_into("<I", expected, section + 8, 0x1FC)
    plan: dict[str, object] = {
        "schema": "comdat_tail_thunk_repack_v1",
        "rationale": "Re-seat candidate-owned linker contributions and rederive every fixup.",
        "pieces": [{"src_lo": "0x00401014", "src_hi": "0x00401018", "shift": 4}],
        "expected_pads": [{"va": "0x00401010", "length": 4, "fill": "cc"}],
        "vacated_fill": {"va": "0x00401014", "length": 4, "fill": "00"},
        "expected_rel32_fixups": [],
        "expected_absolute_fixups": [],
        "expected_reloc_entry_moves": [],
        "text_virtual_size": {"old": "0x00000200", "new": "0x000001fc"},
    }
    return bytes(data), bytes(expected), plan


def test_text_repack_moves_only_candidate_owned_pieces() -> None:
    candidate, expected, plan = _text_repack_candidate_and_plan()
    output, receipt = pe_text_algorithms.apply_text_repack_candidate(candidate, plan)

    assert output == expected
    assert receipt["candidate_only"] is True
    assert receipt["oracle_payload_bytes_read"] == 0
    assert output[0x210:0x214] == candidate[0x214:0x218]


def test_text_repack_rederives_its_fixup_set() -> None:
    candidate, _, plan = _text_repack_candidate_and_plan()
    plan["expected_rel32_fixups"] = [{"site_va": "0x00401000", "imm_offset": 1, "old": 0, "new": 1}]
    with pytest.raises(ByteIdentityError, match="derived rel32"):
        pe_text_algorithms.apply_text_repack_candidate(candidate, plan)


def test_text_repack_declaration_cannot_carry_target_payload() -> None:
    candidate, expected, plan = _text_repack_candidate_and_plan()
    plan["target_bytes"] = expected
    with pytest.raises(ByteIdentityError, match="embedded payload"):
        pe_text_algorithms.apply_text_repack_candidate(candidate, plan)
