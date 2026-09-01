from __future__ import annotations

from typing import Any

from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import coff_unpack as _coff_unpack
from reprobit.ia32_decode import (
    supported_ia32_instruction_length as _supported_ia32_instruction_length,
)
from reprobit.model import is_identifier

from .coff import _coff_table_bytes, function_symbol
from .foundation import (
    exact_audit_keys,
    local_symbol_kind,
    require_exact_int,
    require_sha,
    sha256_bytes,
)

"""Classic compiler algorithms: ia32."""
RETAIL_RELOCATION_ORACLE_KEYS = {
    "offset",
    "type",
    "addend",
    "target",
    "target_section",
    "target_value",
    "target_type",
    "target_storage",
    "retail_target",
}


INSTRUCTION_MOSAIC_RANGE_KEYS = {
    "kind",
    "start",
    "end",
    "seed_sha256",
    "donor_sha256",
    "donor",
    "relocation_reseat",
    "seed_relocation_offsets",
    "donor_relocation_offsets",
}
INSTRUCTION_MOSAIC_RANGE_OPTIONAL_KEYS = {
    "donor",
    "relocation_reseat",
    "seed_relocation_offsets",
    "donor_relocation_offsets",
}
INSTRUCTION_MOSAIC_SEQUENCE_RANGE_KEYS = INSTRUCTION_MOSAIC_RANGE_KEYS | {
    "seed_instruction_lengths",
    "donor_instruction_lengths",
}
ORDINARY_FPO_SELF_PERMUTATION_KIND = "commuting_xor_zero_stack_load_v1"
INDEPENDENT_PAIR_SELF_PERMUTATION_KIND = "commuting_independent_register_write_pair_v1"
SELF_PERMUTATION_KINDS = frozenset(
    {ORDINARY_FPO_SELF_PERMUTATION_KIND, INDEPENDENT_PAIR_SELF_PERMUTATION_KIND}
)
ORDINARY_FPO_CLOSURE_CHILDREN = (".debug$F", ".debug$S")
EH_CLOSURE_CHILDREN = (".debug$S", ".xdata$x")
ORDINARY_FPO_MOSAIC_IDENTITY_KIND = "seed_authoritative_fpo_codeview_v1"
SOURCE_FPO_MOSAIC_IDENTITY_KIND = "seed_authoritative_source_refactor_fpo_codeview_v1"
CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS = "retail_exact_cross_tu_instruction_hybrid_resize"
SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS = "retail_exact_source_instruction_hybrid_resize"
SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS = "retail_exact_same_tu_instruction_hybrid_resize"
CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS = "retail_exact_cross_tu_complete_target_resize"
RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS = "retail_exact_source_equal_body"
CROSS_TU_INSTRUCTION_HYBRID_RANGE_KEYS = {
    "kind",
    "target_start",
    "target_end",
    "target_sha256",
    "instruction_donor_start",
    "instruction_donor_end",
    "instruction_donor_sha256",
}


def require_supported_complete_ia32_instruction(encoded: bytes, context: str) -> int:
    """Require that an isolated range is exactly one supported instruction."""
    length = _supported_ia32_instruction_length(encoded, context)
    require(
        length == len(encoded),
        f"{context}: encoding is not one complete supported IA-32 instruction",
    )
    return length


def require_coff_line_certified_ia32_boundaries(
    coff,
    section: dict[str, Any],
    body: bytes,
    ranges: list[dict[str, Any]],
    role: str,
    mangled: str,
    context: str,
) -> int:
    """Decode from the nearest compiler COFF line boundary through each span."""
    require(
        role in {"target", "instruction_donor", "seed", "donor"},
        f"{context}: IA-32 range role differs",
    )
    line_bytes = _coff_table_bytes(coff, section, "lines")
    require(
        len(line_bytes) == section["line_count"] * 6 and len(line_bytes) >= 12,
        f"{context}: compiler line-boundary certificate is missing",
    )
    marker_index, marker_line = _coff_unpack("<IH", line_bytes, 0, context + " line sentinel")
    function_index, _ = function_symbol(coff, mangled, section["number"])
    require(
        marker_line == 0 and marker_index == function_index,
        f"{context}: compiler line sentinel differs",
    )
    line_offsets = []
    previous = -1
    for index in range(1, section["line_count"]):
        offset, line = _coff_unpack("<IH", line_bytes, index * 6, f"{context} line row {index}")
        require(
            line != 0 and previous <= offset < len(body),
            f"{context}: compiler line boundary is invalid",
        )
        previous = offset
        line_offsets.append(offset)
    require(line_offsets, f"{context}: compiler line boundaries are absent")
    prefixed = role in {"target", "instruction_donor"}
    prefix = role if prefixed else ""
    decoded_count = 0
    for index, item in enumerate(ranges):
        start = item[f"{prefix}_start"] if prefixed else item["start"]
        end = item[f"{prefix}_end"] if prefixed else item["end"]
        anchors = [offset for offset in line_offsets if offset <= start]
        require(anchors, f"{context}: range {index} has no preceding compiler line boundary")
        cursor = max(anchors)
        boundaries = {cursor}
        in_range_lengths = []
        while cursor < end:
            instruction_start = cursor
            length = _supported_ia32_instruction_length(
                body[cursor:], f"{context} range {index} at {cursor}"
            )
            cursor += length
            require(cursor <= len(body), f"{context}: decoded instruction escapes the COMDAT")
            boundaries.add(cursor)
            if start <= instruction_start and cursor <= end:
                in_range_lengths.append(length)
            decoded_count += 1
        require(
            start in boundaries and end in boundaries,
            f"{context}: range {index} is not one containing-stream IA-32 instruction boundary",
        )
        lengths_key = f"{role}_instruction_lengths"
        if lengths_key in item:
            require(
                in_range_lengths == item[lengths_key],
                f"{context}: range {index} decoded instruction partition differs from {lengths_key}",
            )
    return decoded_count


def validate_cross_tu_instruction_hybrid_ranges(
    value: object,
    context: str,
    target_body_length: int,
    instruction_donor_body_length: int,
    *,
    range_kind: str = "cross_tu_same_mangled_complete_x86_instruction_v1",
    require_same_offsets: bool = False,
) -> list[dict[str, Any]]:
    """Validate payload-free ranges in two independent compiler artifacts.

    Only geometry and digest commitments may enter through the declaration.
    The live composer derives and decodes both instruction slices from the
    supplied fresh compiler artifacts.
    """
    require(
        isinstance(value, list) and 1 <= len(value) <= 64,
        f"{context} must contain 1..64 instruction ranges",
    )
    normalized = []
    previous_target_end = 0
    previous_source_end = 0
    for index, item in enumerate(value):
        item_context = f"{context}[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(item, CROSS_TU_INSTRUCTION_HYBRID_RANGE_KEYS, item_context)
        require(item.get("kind") == range_kind, f"{item_context}.kind differs")
        target_start = require_exact_int(
            item.get("target_start"),
            item_context + ".target_start",
            minimum=0,
            maximum=target_body_length - 1,
        )
        target_end = require_exact_int(
            item.get("target_end"),
            item_context + ".target_end",
            minimum=1,
            maximum=target_body_length,
        )
        source_start = require_exact_int(
            item.get("instruction_donor_start"),
            item_context + ".instruction_donor_start",
            minimum=0,
            maximum=instruction_donor_body_length - 1,
        )
        source_end = require_exact_int(
            item.get("instruction_donor_end"),
            item_context + ".instruction_donor_end",
            minimum=1,
            maximum=instruction_donor_body_length,
        )
        target_width = target_end - target_start
        source_width = source_end - source_start
        require(
            1 <= target_width == source_width <= 15,
            f"{item_context} is not one equal-width x86 instruction",
        )
        require(
            target_start >= previous_target_end and source_start >= previous_source_end,
            f"{context} is unsorted or overlapping",
        )
        if require_same_offsets:
            require(
                (target_start, target_end) == (source_start, source_end),
                f"{item_context}: source-aware hybrid offsets differ",
            )
        previous_target_end = target_end
        previous_source_end = source_end
        role_values = {}
        for role in ("target", "instruction_donor"):
            digest = require_sha(item.get(f"{role}_sha256"), f"{item_context}.{role}_sha256")
            role_values[role] = digest
        require(
            role_values["target"] != role_values["instruction_donor"],
            f"{item_context} does not change compiler output",
        )
        normalized.append(
            {
                "kind": item["kind"],
                "target_start": target_start,
                "target_end": target_end,
                "target_sha256": role_values["target"],
                "instruction_donor_start": source_start,
                "instruction_donor_end": source_end,
                "instruction_donor_sha256": role_values["instruction_donor"],
            }
        )
    return normalized


_IA32_GENERAL_REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
_IA32_COMMUTABLE_OPCODES = {139: ("mov_r32_rm32", False, False), 51: ("xor_r32_rm32", True, True)}


def decode_commutable_ia32_instruction(encoded: bytes, context: str) -> dict[str, Any]:
    """Decode one instruction of the closed commutable subset.

    Returns its exact register read set, register write set, and whether it
    reads or writes memory.  Prefixes, immediates and every opcode outside
    the subset are refused, and the encoding must be consumed exactly, so an
    instruction that cannot be reasoned about can never reach the proof.
    """
    require(
        isinstance(encoded, (bytes, bytearray)) and len(encoded) >= 2,
        f"{context}: commutable instruction is too short",
    )
    encoded = bytes(encoded)
    entry = _IA32_COMMUTABLE_OPCODES.get(encoded[0])
    require(entry is not None, f"{context}: opcode is outside the commutable instruction subset")
    _, reads_destination, writes_flags = entry
    modrm = encoded[1]
    mod = modrm >> 6
    reg = modrm >> 3 & 7
    rm = modrm & 7
    cursor = 2
    reads: set[str] = set()
    writes = {_IA32_GENERAL_REGISTERS[reg]}
    if reads_destination:
        reads.add(_IA32_GENERAL_REGISTERS[reg])
    if writes_flags:
        writes.add("flags")
    reads_memory = mod != 3
    if mod == 3:
        reads.add(_IA32_GENERAL_REGISTERS[rm])
    elif rm == 4:
        require(len(encoded) > cursor, f"{context}: SIB byte is missing")
        sib = encoded[cursor]
        cursor += 1
        index = sib >> 3 & 7
        base = sib & 7
        if index != 4:
            reads.add(_IA32_GENERAL_REGISTERS[index])
        if base == 5 and mod == 0:
            cursor += 4
        else:
            reads.add(_IA32_GENERAL_REGISTERS[base])
    elif rm == 5 and mod == 0:
        cursor += 4
    else:
        reads.add(_IA32_GENERAL_REGISTERS[rm])
    if mod == 1:
        cursor += 1
    elif mod == 2:
        cursor += 4
    require(cursor == len(encoded), f"{context}: commutable instruction encoding is not exact")
    return {"reads": reads, "writes": writes, "reads_memory": reads_memory, "writes_memory": False}


def require_commuting_ia32_instruction_pair(
    first: bytes, second: bytes, context: str
) -> dict[str, Any]:
    """Prove two adjacent instructions may be exchanged without effect.

    Both must decode inside the closed subset, neither may write memory, and
    their register/flag read and write sets must be independent.  Two
    instructions that satisfy this leave the same architectural state in
    either order, so exchanging them is a pure reordering of the same
    compiler output rather than a rewrite of it.
    """
    decoded = [
        decode_commutable_ia32_instruction(first, f"{context} first"),
        decode_commutable_ia32_instruction(second, f"{context} second"),
    ]
    require(
        not any(item["writes_memory"] for item in decoded),
        f"{context}: a commuting instruction writes memory",
    )
    require(
        not decoded[0]["writes"] & decoded[1]["writes"],
        f"{context}: commuting instructions write the same location",
    )
    require(
        not decoded[0]["reads"] & decoded[1]["writes"]
        and (not decoded[1]["reads"] & decoded[0]["writes"]),
        f"{context}: commuting instructions carry a register dependency",
    )
    return {
        "first_reads": sorted(decoded[0]["reads"]),
        "first_writes": sorted(decoded[0]["writes"]),
        "second_reads": sorted(decoded[1]["reads"]),
        "second_writes": sorted(decoded[1]["writes"]),
    }


def validate_instruction_self_permutation(
    value: object, context: str, body: bytes
) -> dict[str, Any]:
    """Validate a payload-free bijective commute from a fresh donor body."""
    require(isinstance(body, bytes) and body, f"{context}: donor body is missing")
    body_length = len(body)
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
        {
            "kind",
            "source_start",
            "source_end",
            "target_start",
            "target_end",
            "source_instruction_lengths",
            "target_instruction_lengths",
            "moves",
            "expected_changed_offsets",
            "expected_function_multiset_sha256",
            "expected_comdat_multiset_sha256",
            "expected_section_shape_sha256",
            "expected_linker_payload_count",
            "expected_linker_payload_sha256",
        },
        context,
    )
    require(value.get("kind") in SELF_PERMUTATION_KINDS, f"{context}.kind differs")
    bounds = {}
    for role in ("source", "target"):
        start = require_exact_int(
            value.get(f"{role}_start"),
            f"{context}.{role}_start",
            minimum=0,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            value.get(f"{role}_end"), f"{context}.{role}_end", minimum=1, maximum=body_length
        )
        require(start < end, f"{context}.{role} range is empty")
        bounds[role] = (start, end)
    require(bounds["source"] == bounds["target"], f"{context}: self-permutation windows differ")
    width = bounds["source"][1] - bounds["source"][0]
    declared_lengths = {}
    for role in ("source", "target"):
        lengths = value.get(f"{role}_instruction_lengths")
        require(
            isinstance(lengths, list)
            and len(lengths) == 2
            and all(type(length) is int and 1 <= length <= 15 for length in lengths)
            and (sum(lengths) == width),
            f"{context}.{role}_instruction_lengths differs",
        )
        declared_lengths[role] = list(lengths)
    moves = value.get("moves")
    require(
        isinstance(moves, list) and len(moves) == 2,
        f"{context}.moves must contain exactly two instructions",
    )
    normalized_moves = []
    for index, move in enumerate(moves):
        move_context = f"{context}.moves[{index}]"
        require(isinstance(move, dict), f"{move_context} must be an object")
        exact_audit_keys(
            move,
            {
                "target_start",
                "target_end",
                "target_sha256",
                "donor_start",
                "donor_end",
                "donor_sha256",
            },
            move_context,
        )
        intervals = {}
        for role, prefix in (("target", "target"), ("source", "donor")):
            outer_start, outer_end = bounds[role]
            start = require_exact_int(
                move.get(f"{prefix}_start"),
                f"{move_context}.{prefix}_start",
                minimum=outer_start,
                maximum=outer_end - 1,
            )
            end = require_exact_int(
                move.get(f"{prefix}_end"),
                f"{move_context}.{prefix}_end",
                minimum=outer_start + 1,
                maximum=outer_end,
            )
            require(start < end, f"{move_context}.{prefix} interval is empty")
            intervals[role] = (start, end)
        require(
            intervals["target"][1] - intervals["target"][0]
            == intervals["source"][1] - intervals["source"][0],
            f"{move_context} source/target widths differ",
        )
        target_sha = require_sha(move.get("target_sha256"), f"{move_context}.target_sha256")
        donor_sha = require_sha(move.get("donor_sha256"), f"{move_context}.donor_sha256")
        require(
            target_sha == donor_sha, f"{move_context} does not copy one exact donor instruction"
        )
        donor_raw = body[intervals["source"][0] : intervals["source"][1]]
        require(
            sha256_bytes(donor_raw) == donor_sha,
            f"{move_context} differs from the fresh donor artifact",
        )
        require_supported_complete_ia32_instruction(donor_raw, f"{move_context}.donor")
        normalized_moves.append(
            {
                "target_start": intervals["target"][0],
                "target_end": intervals["target"][1],
                "target_sha256": target_sha,
                "donor_start": intervals["source"][0],
                "donor_end": intervals["source"][1],
                "donor_sha256": donor_sha,
            }
        )
    for role, start_key, end_key in (
        ("target", "target_start", "target_end"),
        ("source", "donor_start", "donor_end"),
    ):
        ordered = sorted(normalized_moves, key=lambda item: item[start_key])
        cursor = bounds[role][0]
        lengths = []
        for move in ordered:
            require(
                move[start_key] == cursor, f"{context}: {role} partition is overlapping or gapped"
            )
            cursor = move[end_key]
            lengths.append(move[end_key] - move[start_key])
        require(
            cursor == bounds[role][1] and lengths == declared_lengths[role],
            f"{context}: {role} partition differs from its declaration",
        )
    require(
        [(item["donor_start"], item["donor_end"]) for item in normalized_moves]
        == list(
            reversed(
                [
                    (item["donor_start"], item["donor_end"])
                    for item in sorted(normalized_moves, key=lambda item: item["donor_start"])
                ]
            )
        ),
        f"{context}: target order is not the exact two-instruction reversal",
    )
    source_order = sorted(normalized_moves, key=lambda item: item["donor_start"])
    first = body[source_order[0]["donor_start"] : source_order[0]["donor_end"]]
    second = body[source_order[1]["donor_start"] : source_order[1]["donor_end"]]
    if value["kind"] == ORDINARY_FPO_SELF_PERMUTATION_KIND:
        require(
            first == b"3\xff",
            f"{context}: first source instruction is not the closed XOR-zero encoding",
        )
        zero_modrm = first[1]
        zero_reg = zero_modrm >> 3 & 7
        require(
            zero_modrm >> 6 == 3 and zero_modrm & 7 == zero_reg,
            f"{context}: XOR does not zero exactly one register",
        )
        require(
            second == b"\x8bT$\x14",
            f"{context}: second source instruction is not the closed stack-load encoding",
        )
    independence = require_commuting_ia32_instruction_pair(
        first, second, f"{context} commuting pair"
    )
    normalized = {
        "kind": value["kind"],
        "commuting_pair_independence": independence,
        "source_start": bounds["source"][0],
        "source_end": bounds["source"][1],
        "target_start": bounds["target"][0],
        "target_end": bounds["target"][1],
        "source_instruction_lengths": declared_lengths["source"],
        "target_instruction_lengths": declared_lengths["target"],
        "moves": normalized_moves,
        "expected_changed_offsets": [],
        "expected_linker_payload_count": require_exact_int(
            value.get("expected_linker_payload_count"),
            f"{context}.expected_linker_payload_count",
            minimum=0,
        ),
    }
    changed_offsets = value.get("expected_changed_offsets")
    require(
        isinstance(changed_offsets, list)
        and changed_offsets
        and (changed_offsets == sorted(set(changed_offsets)))
        and all(type(offset) is int and 0 <= offset < body_length for offset in changed_offsets),
        f"{context}.expected_changed_offsets differs",
    )
    normalized["expected_changed_offsets"] = list(changed_offsets)
    for name in (
        "expected_function_multiset_sha256",
        "expected_comdat_multiset_sha256",
        "expected_section_shape_sha256",
        "expected_linker_payload_sha256",
    ):
        normalized[name] = require_sha(value.get(name), f"{context}.{name}")
    return normalized


def validate_instruction_mosaic_ranges(
    value: object, context: str, body_length: int
) -> list[dict[str, Any]]:
    """Validate payload-free same-offset instruction range declarations.

    The declaration closes geometry, digests, and partitions.  Both byte
    slices are derived later from fresh compiler objects and checked before
    any donor bytes cross into the candidate.
    """
    require(
        isinstance(value, list) and 1 <= len(value) <= 64,
        f"{context} must contain 1..64 instruction ranges",
    )
    normalized = []
    previous_end = 0
    for index, item in enumerate(value):
        item_context = f"{context}[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        kind = item.get("kind")
        if kind == "same_offset_complete_x86_instruction_v1":
            exact_audit_keys(
                item,
                INSTRUCTION_MOSAIC_RANGE_KEYS,
                item_context,
                optional=INSTRUCTION_MOSAIC_RANGE_OPTIONAL_KEYS,
            )
        elif kind == "same_offset_complete_x86_instruction_sequence_v1":
            exact_audit_keys(
                item,
                INSTRUCTION_MOSAIC_SEQUENCE_RANGE_KEYS,
                item_context,
                optional=INSTRUCTION_MOSAIC_RANGE_OPTIONAL_KEYS,
            )
        else:
            raise ByteIdentityError(f"{item_context}.kind differs")
        start = require_exact_int(
            item.get("start"), item_context + ".start", minimum=0, maximum=body_length - 1
        )
        end = require_exact_int(
            item.get("end"), item_context + ".end", minimum=1, maximum=body_length
        )
        maximum = 15 if kind == "same_offset_complete_x86_instruction_v1" else 64
        require(
            start < end and end - start <= maximum,
            f"{item_context} is not a bounded x86 instruction range",
        )
        require(start >= previous_end, f"{context} is unsorted or overlapping")
        previous_end = end
        seed_sha = require_sha(item.get("seed_sha256"), item_context + ".seed_sha256")
        donor_sha = require_sha(item.get("donor_sha256"), item_context + ".donor_sha256")
        require(seed_sha != donor_sha, f"{item_context} does not move compiler state")
        normalized_item = {
            "kind": kind,
            "start": start,
            "end": end,
            "seed_sha256": seed_sha,
            "donor_sha256": donor_sha,
        }
        if "donor" in item:
            donor_id = item.get("donor")
            require(is_identifier(donor_id), f"{item_context}.donor is invalid")
            normalized_item["donor"] = donor_id
        reseat_keys = {"relocation_reseat", "seed_relocation_offsets", "donor_relocation_offsets"}
        if reseat_keys & set(item):
            require(
                item.get("relocation_reseat") is True and reseat_keys <= set(item),
                f"{item_context} relocation reseat declaration is incomplete",
            )
            offsets = {}
            for role in ("seed", "donor"):
                values = item.get(f"{role}_relocation_offsets")
                require(
                    isinstance(values, list)
                    and 1 <= len(values) <= 16
                    and all(type(v) is int and start <= v and (v + 4 <= end) for v in values)
                    and (values == sorted(set(values))),
                    f"{item_context}.{role}_relocation_offsets differ",
                )
                offsets[role] = list(values)
            require(
                len(offsets["seed"]) == len(offsets["donor"])
                and offsets["seed"] != offsets["donor"],
                f"{item_context} relocation reseat does not move a relocation operand",
            )
            normalized_item["relocation_reseat"] = True
            normalized_item["seed_relocation_offsets"] = offsets["seed"]
            normalized_item["donor_relocation_offsets"] = offsets["donor"]
        if kind == "same_offset_complete_x86_instruction_sequence_v1":
            for role in ("seed", "donor"):
                lengths = item.get(f"{role}_instruction_lengths")
                require(
                    isinstance(lengths, list)
                    and lengths
                    and (len(lengths) <= 64)
                    and all(type(length) is int and 1 <= length <= 15 for length in lengths)
                    and (sum(lengths) == end - start),
                    f"{item_context}.{role}_instruction_lengths differ",
                )
                normalized_item[f"{role}_instruction_lengths"] = list(lengths)
        normalized.append(normalized_item)
    return normalized


def require_declared_relocation_semantics(
    donor_rows: list[dict[str, Any]], oracle: list[dict[str, Any]], context: str
) -> dict[str, Any]:
    """Bind candidate relocations to declarative symbol semantics.

    The producer receives only relocation records re-derived from a fresh
    compiler artifact and declarative symbol metadata.  Literal reference
    bytes are intentionally unavailable here; final linked-byte equality is
    a verifier-only concern.
    """
    require(
        len(donor_rows) == len(oracle),
        f"{context} relocation count differs from its declared semantics",
    )
    fields = (
        "offset",
        "type",
        "addend",
        "target_section",
        "target_value",
        "target_type",
        "target_storage",
    )
    for index, (record, expected) in enumerate(zip(donor_rows, oracle)):
        # `$L`/`$T`/`$done$` suffixes are compiler-local counters, not symbol
        # semantics.  The COFF composer already pairs these names by their
        # local kind; apply the same rule at this declarative boundary while
        # retaining every offset, section, value, type, and storage pin.
        record_target = record["target"]
        expected_target = expected["target"]
        record_local_kind = local_symbol_kind(record_target)
        target_matches = record_target == expected_target or (
            record_local_kind is not None
            and record_local_kind == local_symbol_kind(expected_target)
        )
        require(
            target_matches and all(record[field] == expected[field] for field in fields),
            f"{context} relocation {index} differs from its declared COFF semantics",
        )
    return {
        "semantic_relocation_count": len(donor_rows),
        "oracle_payload_bytes_read": 0,
    }
