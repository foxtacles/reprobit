"""Declarative PE32 transforms that move only candidate-owned bytes."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from typing import TypedDict

from .foundation import (
    exact_audit_keys,
    require,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    raw_size: int
    raw_offset: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


class _ThunkPlan(TypedDict):
    schema: str
    pair_file_offset: int
    call_file_offsets: list[int]
    input_sha256: str
    output_sha256: str


class _PE32AddressMap:
    """The small, fail-closed PE surface needed by the thunk transform."""

    def __init__(self, data: bytes) -> None:
        require(len(data) >= 64 and data[:2] == b"MZ", "missing DOS MZ header")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        require(pe <= len(data) - 24 and data[pe : pe + 4] == b"PE\0\0", "missing PE signature")
        machine, count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        require(machine == 0x14C, "only i386 PE images are supported")
        require(0 < count <= 96, "invalid PE section count")
        optional = pe + 24
        require(
            optional_size >= 32 and optional + optional_size <= len(data),
            "invalid PE32 optional header",
        )
        require(
            struct.unpack_from("<H", data, optional)[0] == 0x10B, "only PE32 images are supported"
        )
        self.image_base: int = int(struct.unpack_from("<I", data, optional + 28)[0])
        table = optional + optional_size
        require(table + count * 40 <= len(data), "section table extends past EOF")
        sections: list[_Section] = []
        for index in range(count):
            header = table + index * 40
            virtual_address, raw_size, raw_offset = struct.unpack_from("<III", data, header + 12)
            require(
                raw_size == 0 or raw_offset <= len(data) - raw_size,
                "section raw data extends past EOF",
            )
            sections.append(_Section(virtual_address, raw_size, raw_offset))
        occupied = sorted(
            (section.raw_offset, section.raw_end) for section in sections if section.raw_size
        )
        require(
            all(left[1] <= right[0] for left, right in pairwise(occupied)),
            "PE sections overlap in the file",
        )
        self.sections: tuple[_Section, ...] = tuple(sections)

    def offset_to_va(self, offset: int, size: int = 1) -> int:
        matches = [
            section
            for section in self.sections
            if section.raw_offset <= offset and offset + size <= section.raw_end
        ]
        require(len(matches) == 1, "file range does not map uniquely to a PE section")
        section = matches[0]
        return self.image_base + section.virtual_address + offset - section.raw_offset


def _validated_thunk_plan(value: object, body_length: int) -> _ThunkPlan:
    require(isinstance(value, dict), "adjacent thunk plan must be an object")
    assert isinstance(value, dict)
    exact_audit_keys(
        value,
        {
            "schema",
            "pair_file_offset",
            "call_file_offsets",
            "input_sha256",
            "output_sha256",
        },
        "adjacent thunk plan",
    )
    schema = value.get("schema")
    require(schema == "adjacent_import_thunk_swap_v1", "unsupported adjacent thunk plan")
    assert isinstance(schema, str)
    pair_offset = require_exact_int(
        value.get("pair_file_offset"),
        "adjacent thunk plan.pair_file_offset",
        minimum=0,
        maximum=max(0, body_length - 12),
    )
    calls = value.get("call_file_offsets")
    require(
        isinstance(calls, list)
        and bool(calls)
        and calls == sorted(set(calls))
        and all(type(item) is int and 0 <= item <= body_length - 5 for item in calls),
        "adjacent thunk plan.call_file_offsets is invalid",
    )
    assert isinstance(calls, list)
    normalized_calls = [int(item) for item in calls]
    return {
        "schema": schema,
        "pair_file_offset": pair_offset,
        "call_file_offsets": normalized_calls,
        "input_sha256": require_sha(value.get("input_sha256"), "adjacent thunk plan.input_sha256"),
        "output_sha256": require_sha(
            value.get("output_sha256"), "adjacent thunk plan.output_sha256"
        ),
    }


def apply_adjacent_import_thunk_swap(
    candidate: bytes, declaration: Mapping[str, object]
) -> tuple[bytes, dict[str, object]]:
    """Swap one declared adjacent thunk pair and preserve call identities.

    The declaration selects geometry and pins digests; it carries no target
    payload.  Both thunk operands and every rewritten displacement are derived
    from ``candidate``.  Literal identity is established later by the sealed
    verifier.
    """

    require(isinstance(candidate, bytes), "PE candidate must be immutable bytes")
    require_payload_free_declaration(declaration, "adjacent thunk plan")
    plan = _validated_thunk_plan(dict(declaration), len(candidate))
    require(
        sha256_bytes(candidate) == plan["input_sha256"], "PE candidate differs from its input pin"
    )
    address_map = _PE32AddressMap(candidate)
    pair_offset = plan["pair_file_offset"]
    address_map.offset_to_va(pair_offset, 12)
    require(
        candidate[pair_offset : pair_offset + 2] == b"\xff\x25"
        and candidate[pair_offset + 6 : pair_offset + 8] == b"\xff\x25",
        "declared range is not an adjacent pair of six-byte import thunks",
    )
    first_operand = candidate[pair_offset + 2 : pair_offset + 6]
    second_operand = candidate[pair_offset + 8 : pair_offset + 12]
    require(first_operand != second_operand, "adjacent import thunks are identical")
    first_va = address_map.offset_to_va(pair_offset)
    second_va = address_map.offset_to_va(pair_offset + 6)

    output = bytearray(candidate)
    output[pair_offset + 2 : pair_offset + 6] = second_operand
    output[pair_offset + 8 : pair_offset + 12] = first_operand
    calls: list[dict[str, int]] = []
    for call_offset in plan["call_file_offsets"]:
        address_map.offset_to_va(call_offset, 5)
        require(candidate[call_offset] == 0xE8, "declared call site is not CALL rel32")
        displacement = int.from_bytes(
            candidate[call_offset + 1 : call_offset + 5], "little", signed=True
        )
        target = address_map.offset_to_va(call_offset) + 5 + displacement
        require(target in (first_va, second_va), "declared call does not target the thunk pair")
        moved = displacement + 6 if target == first_va else displacement - 6
        output[call_offset + 1 : call_offset + 5] = moved.to_bytes(4, "little", signed=True)
        calls.append(
            {
                "file_offset": call_offset,
                "old_target_va": target,
                "new_target_va": second_va if target == first_va else first_va,
            }
        )

    result = bytes(output)
    require(result != candidate, "adjacent thunk swap changes no bytes")
    require(
        sha256_bytes(result) == plan["output_sha256"], "PE candidate differs from its output pin"
    )
    return result, {
        "schema": plan["schema"],
        "pair_file_offset": pair_offset,
        "call_sites": calls,
        "input_sha256": plan["input_sha256"],
        "output_sha256": plan["output_sha256"],
        "candidate_only": True,
        "oracle_payload_bytes_read": 0,
    }


__all__ = ["apply_adjacent_import_thunk_swap"]
