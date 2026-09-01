"""Candidate-only PE32 ``.text`` packing transforms."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise

from reprobit.binary import require
from reprobit.pe32 import Pe32Headers, parse_pe32_headers

from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    sha256_bytes,
)


@dataclass(frozen=True, slots=True)
class _Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    header_offset: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


class _PE32:
    """Fail-closed PE32 geometry used by the text repacker."""

    def __init__(self, data: bytes) -> None:
        self._headers: Pe32Headers = parse_pe32_headers(data)
        self.image_base = self._headers.image_base
        sections: list[_Section] = []
        for row in self._headers.sections:
            raw_name = row.raw_name.split(b"\0", 1)[0]
            require(
                bool(raw_name) and all(32 <= byte < 127 for byte in raw_name),
                "invalid PE section name",
            )
            sections.append(
                _Section(
                    raw_name.decode("ascii"),
                    row.virtual_size,
                    row.virtual_address,
                    row.raw_size,
                    row.raw_offset,
                    row.header_offset,
                )
            )
        self.sections = tuple(sections)

    def section(self, name: str) -> _Section:
        matches = [section for section in self.sections if section.name == name]
        require(len(matches) == 1, f"PE must contain exactly one {name} section")
        return matches[0]

    def va_to_offset(self, va: int, size: int = 1) -> int:
        context = f"virtual range 0x{va:08x}+{size}"
        return self._headers.rva_to_offset(va - self.image_base, size, context=context)


@dataclass(frozen=True, slots=True)
class _Piece:
    low: int
    high: int
    shift: int

    def contains(self, va: int) -> bool:
        return self.low <= va < self.high


def _hex_int(value: object, context: str) -> int:
    require(
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) <= 10
        and all(character in "0123456789abcdef" for character in value[2:]),
        f"{context} must be a lowercase hexadecimal address",
    )
    assert isinstance(value, str)
    return int(value, 16)


def _validated_plan(value: object) -> tuple[dict[str, object], tuple[_Piece, ...]]:
    require(isinstance(value, dict), "text-repack declaration must be an object")
    assert isinstance(value, dict)
    exact_audit_keys(
        value,
        {
            "schema",
            "rationale",
            "pieces",
            "expected_pads",
            "vacated_fill",
            "expected_rel32_fixups",
            "expected_absolute_fixups",
            "expected_reloc_entry_moves",
            "text_virtual_size",
        },
        "text-repack declaration",
    )
    require(value.get("schema") == "comdat_tail_thunk_repack_v1", "unsupported text-repack schema")
    require(
        isinstance(value.get("rationale"), str) and bool(value["rationale"]),
        "text-repack rationale is required",
    )
    raw_pieces = value.get("pieces")
    require(
        isinstance(raw_pieces, list) and 1 <= len(raw_pieces) <= 4, "text repack needs 1..4 pieces"
    )
    assert isinstance(raw_pieces, list)
    pieces: list[_Piece] = []
    for index, raw in enumerate(raw_pieces):
        require(isinstance(raw, dict), f"text-repack piece {index} must be an object")
        assert isinstance(raw, dict)
        exact_audit_keys(raw, {"src_lo", "src_hi", "shift"}, f"text-repack piece {index}")
        low = _hex_int(raw.get("src_lo"), f"text-repack piece {index}.src_lo")
        high = _hex_int(raw.get("src_hi"), f"text-repack piece {index}.src_hi")
        shift = require_exact_int(
            raw.get("shift"), f"text-repack piece {index}.shift", minimum=1, maximum=63
        )
        require(low < high, f"text-repack piece {index} is empty")
        pieces.append(_Piece(low, high, shift))
    source = sorted((piece.low, piece.high) for piece in pieces)
    destinations = sorted((piece.low - piece.shift, piece.high - piece.shift) for piece in pieces)
    require(
        all(left[1] <= right[0] for left, right in pairwise(source)), "text-repack sources overlap"
    )
    require(
        all(left[1] <= right[0] for left, right in pairwise(destinations)),
        "text-repack destinations overlap",
    )
    return dict(value), tuple(pieces)


def _piece_shift(pieces: tuple[_Piece, ...], va: int) -> int | None:
    matches = [piece.shift for piece in pieces if piece.contains(va)]
    require(len(matches) <= 1, f"virtual address 0x{va:08x} belongs to overlapping pieces")
    return matches[0] if matches else None


def _declared_fill(raw: object, context: str) -> tuple[int, int, int]:
    require(isinstance(raw, dict), f"{context} must be an object")
    assert isinstance(raw, dict)
    exact_audit_keys(raw, {"va", "length", "fill"}, context)
    va = _hex_int(raw.get("va"), f"{context}.va")
    length = require_exact_int(raw.get("length"), f"{context}.length", minimum=1, maximum=4096)
    fill = raw.get("fill")
    require(
        isinstance(fill, str)
        and len(fill) == 2
        and all(character in "0123456789abcdef" for character in fill),
        f"{context}.fill must be one lowercase byte",
    )
    assert isinstance(fill, str)
    return va, length, int(fill, 16)


def apply_text_repack_candidate(
    candidate: bytes, declaration: Mapping[str, object]
) -> tuple[bytes, dict[str, object]]:
    """Re-seat declared ``.text`` pieces using only candidate-owned bytes."""

    require(isinstance(candidate, bytes), "PE candidate must be immutable bytes")
    require_payload_free_declaration(declaration, "text-repack declaration")
    plan, pieces = _validated_plan(dict(declaration))
    image = _PE32(candidate)
    text = image.section(".text")
    reloc = image.section(".reloc")
    text_start = image.image_base + text.virtual_address
    text_end = text_start + text.raw_size
    for piece in pieces:
        require(
            text_start <= piece.low < piece.high <= text_end
            and text_start <= piece.low - piece.shift < piece.high - piece.shift <= text_end,
            "text-repack piece leaves the file-backed .text section",
        )

    raw_pads = plan["expected_pads"]
    require(isinstance(raw_pads, list), "text-repack expected_pads must be a list")
    assert isinstance(raw_pads, list)
    for index, raw_pad in enumerate(raw_pads):
        va, length, fill = _declared_fill(raw_pad, f"text-repack expected_pads[{index}]")
        at = image.va_to_offset(va, length)
        require(
            candidate[at : at + length] == bytes([fill]) * length,
            f"text-repack pad {index} differs",
        )

    def shift(va: int) -> int | None:
        return _piece_shift(pieces, va)

    body = candidate[text.raw_offset : text.raw_end]
    derived_rel32: list[dict[str, object]] = []
    index = 0
    while index + 5 <= len(body):
        opcode = body[index]
        if opcode in (0xE8, 0xE9):
            length, immediate = 5, index + 1
        elif index + 6 <= len(body) and opcode == 0x0F and 0x80 <= body[index + 1] <= 0x8F:
            length, immediate = 6, index + 2
        else:
            index += 1
            continue
        site = text_start + index
        displacement = int(struct.unpack_from("<i", body, immediate)[0])
        target = (site + length + displacement) & 0xFFFFFFFF
        site_shift = shift(site)
        target_shift = shift(target)
        if (site_shift is not None or target_shift is not None) and text_start <= target < text_end:
            moved = (target - (target_shift or 0)) - (site - (site_shift or 0)) - length
            if moved != displacement:
                derived_rel32.append(
                    {
                        "site_va": f"0x{site:08x}",
                        "imm_offset": immediate - index,
                        "old": displacement,
                        "new": moved,
                    }
                )
        index += 1
    require(
        derived_rel32 == plan["expected_rel32_fixups"],
        "derived rel32 fixup set differs from its declaration",
    )

    entries: list[tuple[int, int]] = []
    cursor = reloc.raw_offset
    reloc_end = reloc.raw_offset + min(reloc.virtual_size, reloc.raw_size)
    while cursor < reloc_end:
        require(cursor + 8 <= reloc_end, "truncated base-relocation block")
        page, block = struct.unpack_from("<II", candidate, cursor)
        if block == 0:
            break
        require(
            block >= 8 and block % 2 == 0 and cursor + block <= reloc_end,
            "invalid base-relocation block",
        )
        for ordinal in range((block - 8) // 2):
            entry_at = cursor + 8 + ordinal * 2
            entry = int(struct.unpack_from("<H", candidate, entry_at)[0])
            if entry >> 12 == 3:
                entries.append((entry_at, int(page) + (entry & 0xFFF)))
        cursor += int(block)

    derived_absolute: list[dict[str, object]] = []
    derived_moves: list[dict[str, object]] = []
    for entry_at, rva in entries:
        site_va = image.image_base + rva
        at = image.va_to_offset(site_va, 4)
        value = int(struct.unpack_from("<I", candidate, at)[0])
        value_shift = shift(value)
        if value_shift is not None:
            derived_absolute.append(
                {
                    "site_va": f"0x{site_va:08x}",
                    "old": f"0x{value:08x}",
                    "new": f"0x{value - value_shift:08x}",
                }
            )
        site_shift = shift(site_va)
        if site_shift is not None:
            new_rva = rva - site_shift
            require(
                rva >> 12 == new_rva >> 12, "moved relocation crosses its PE base-relocation page"
            )
            derived_moves.append(
                {
                    "entry_file_offset": entry_at,
                    "old_rva": f"0x{rva:x}",
                    "new_rva": f"0x{new_rva:x}",
                }
            )
    require(
        derived_absolute == plan["expected_absolute_fixups"],
        "derived absolute fixup set differs from its declaration",
    )
    require(
        derived_moves == plan["expected_reloc_entry_moves"],
        "derived relocation-entry move set differs from its declaration",
    )

    output = bytearray(candidate)
    allowed: set[int] = set()
    for piece in pieces:
        source_at = image.va_to_offset(piece.low, piece.high - piece.low)
        destination_at = image.va_to_offset(piece.low - piece.shift, piece.high - piece.low)
        block = candidate[source_at : source_at + piece.high - piece.low]
        output[destination_at : destination_at + len(block)] = block
        allowed.update(range(destination_at, destination_at + len(block)))

    vacated_va, vacated_length, vacated_fill = _declared_fill(
        plan["vacated_fill"], "text-repack vacated_fill"
    )
    vacated_at = image.va_to_offset(vacated_va, vacated_length)
    output[vacated_at : vacated_at + vacated_length] = bytes([vacated_fill]) * vacated_length
    allowed.update(range(vacated_at, vacated_at + vacated_length))

    for fixup in derived_rel32:
        site = _hex_int(fixup["site_va"], "rel32 site")
        new_site = site - (shift(site) or 0)
        immediate = require_exact_int(fixup["imm_offset"], "rel32 immediate", minimum=1, maximum=2)
        at = image.va_to_offset(new_site, immediate + 4) + immediate
        new_displacement = require_exact_int(fixup["new"], "new rel32 displacement")
        struct.pack_into("<i", output, at, new_displacement)
        allowed.update(range(at, at + 4))
    for fixup in derived_absolute:
        site = _hex_int(fixup["site_va"], "absolute-fixup site")
        new_site = site - (shift(site) or 0)
        at = image.va_to_offset(new_site, 4)
        struct.pack_into("<I", output, at, _hex_int(fixup["new"], "absolute-fixup value"))
        allowed.update(range(at, at + 4))
    for move in derived_moves:
        entry_at = require_exact_int(
            move["entry_file_offset"], "relocation entry offset", minimum=0
        )
        entry = int(struct.unpack_from("<H", output, entry_at)[0])
        new_rva = _hex_int(move["new_rva"], "new relocation RVA")
        struct.pack_into("<H", output, entry_at, (entry & 0xF000) | (new_rva & 0xFFF))
        allowed.update(range(entry_at, entry_at + 2))

    virtual = plan["text_virtual_size"]
    require(isinstance(virtual, dict), "text_virtual_size must be an object")
    assert isinstance(virtual, dict)
    exact_audit_keys(virtual, {"old", "new"}, "text_virtual_size")
    old_virtual = _hex_int(virtual.get("old"), "text_virtual_size.old")
    new_virtual = _hex_int(virtual.get("new"), "text_virtual_size.new")
    require(
        text.virtual_size == old_virtual and 0 < new_virtual <= text.raw_size,
        ".text virtual size pin differs",
    )
    struct.pack_into("<I", output, text.header_offset + 8, new_virtual)
    allowed.update(range(text.header_offset + 8, text.header_offset + 12))

    result = bytes(output)
    changed = {
        index
        for index, pair in enumerate(zip(candidate, result, strict=True))
        if pair[0] != pair[1]
    }
    require(
        bool(changed) and changed <= allowed,
        "text repack changed bytes outside its derived mutation set",
    )
    _PE32(result)
    return result, {
        "schema": "comdat_tail_thunk_repack_v1",
        "candidate_only": True,
        "oracle_payload_bytes_read": 0,
        "piece_count": len(pieces),
        "rel32_fixups": len(derived_rel32),
        "absolute_fixups": len(derived_absolute),
        "relocation_entry_moves": len(derived_moves),
        "changed_byte_count": len(changed),
        "input_sha256": sha256_bytes(candidate),
        "output_sha256": sha256_bytes(result),
    }


__all__ = ["apply_text_repack_candidate"]
