"""Length-changing register-bijection declarations and transformations."""

from __future__ import annotations

import itertools
from typing import Any

from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import CoffObject, coff_body

from .coff import _comdat_child, _comdat_child_closure
from .debug import FPO_RECORD_KEYS, parse_fpo_data
from .foundation import (
    exact_audit_keys,
    exact_keys,
    require_exact_int,
    require_payload_free_declaration,
)
from .register_bijection import REGISTER_BIJECTION_CLASS
from .register_semantics import (
    _IA32_REGISTER_NUMBERS,
    IA32_GENERAL_REGISTER_NAMES,
    _bijection_form_for,
    _ia32_atom_registers,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
    ia32_register_atoms,
)


def validate_register_bijection_reencoding(
    value: object, context: str, preimage_length: int, image_length: int
) -> dict[str, Any]:
    """Validate one re-encoding register-bijection declaration.

    Every quantity the composer will MEASURE is declared here first, so a
    manifest that disagrees with the objects refuses before anything is
    installed.  The regions are the only free parameters; growth, branch
    repairs, reseats and the boundary-derived debug ranges are consequences,
    and pinning them is what makes a silent change to the primitive visible.
    """
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
        {
            "kind",
            "regions",
            "expected_fpo_record",
            "expected_growth",
            "expected_branch_repairs",
            "expected_relocation_reseat",
            "expected_rewritten_field_offsets",
            "expected_region_instruction_counts",
            "expected_instruction_count",
            "expected_image_code_length",
            "expected_procedure_range",
            "expected_carried_code_symbols",
            "authenticity_rationale",
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
        context,
        optional={"expected_code_length", "expected_internal_relocation_targets"},
    )
    require(value.get("kind") == REGISTER_BIJECTION_REENCODING_KIND, f"{context}.kind differs")
    regions = value.get("regions")
    require(isinstance(regions, list) and 1 <= len(regions) <= 8, f"{context}.regions is invalid")
    normalized = []
    previous_end = 0
    names_ebp = False
    for index, item in enumerate(regions):
        item_context = f"{context}.regions[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_keys(item, {"start", "end", "mapping"}, item_context)
        start = require_exact_int(
            item.get("start"), f"{item_context}.start", minimum=1, maximum=preimage_length - 1
        )
        end = require_exact_int(
            item.get("end"), f"{item_context}.end", minimum=2, maximum=preimage_length - 1
        )
        require(
            start >= previous_end and start < end,
            f"{item_context}: regions are unsorted, empty or overlapping",
        )
        previous_end = end
        mapping = item.get("mapping")
        require(
            isinstance(mapping, dict)
            and 2 <= len(mapping) <= 8
            and all(
                (
                    isinstance(key, str)
                    and isinstance(entry, str)
                    and (key in _IA32_REGISTER_NUMBERS)
                    and (entry in _IA32_REGISTER_NUMBERS)
                    for key, entry in mapping.items()
                )
            ),
            f"{item_context}.mapping is invalid",
        )
        require(
            set(mapping) == set(mapping.values())
            and len(set(mapping.values())) == len(mapping)
            and all((key != entry for key, entry in mapping.items())),
            f"{item_context}.mapping is not a fixed-point-free bijection",
        )
        require(
            "esp" not in set(mapping) | set(mapping.values()), f"{item_context}.mapping touches ESP"
        )
        if "ebp" in set(mapping) | set(mapping.values()):
            names_ebp = True
        normalized.append({"start": start, "end": end, "mapping": dict(sorted(mapping.items()))})
    require(
        names_ebp,
        f"{context}: no region names EBP, so this is an ordinary {REGISTER_BIJECTION_CLASS} and must be declared as one",
    )
    record = value.get("expected_fpo_record")
    require(
        isinstance(record, dict) and set(record) == FPO_RECORD_KEYS - {"raw_sha256"},
        f"{context}.expected_fpo_record is invalid",
    )
    require(
        record.get("cbFrame") == FPO_FRAME_KIND_FPO and record.get("fHasSEH") == 0,
        f"{context}.expected_fpo_record does not declare a frame-pointer-free, SEH-free frame",
    )
    growth = value.get("expected_growth")
    require(
        isinstance(growth, list)
        and growth
        and (len(growth) <= 64)
        and all(
            isinstance(row, list)
            and len(row) == 4
            and all(type(entry) is int for entry in row)
            and (0 <= row[0] < preimage_length)
            and (0 <= row[1] < image_length)
            and (1 <= row[2] <= 15)
            and (1 <= row[3] <= 15)
            and (abs(row[3] - row[2]) == 1)
            for row in growth
        )
        and ([row[0] for row in growth] == sorted({row[0] for row in growth})),
        f"{context}.expected_growth is invalid",
    )
    require(
        image_length - preimage_length == sum(row[3] - row[2] for row in growth),
        f"{context}.expected_growth does not account for the image's length change",
    )
    repairs = value.get("expected_branch_repairs")
    require(
        isinstance(repairs, list)
        and len(repairs) <= 256
        and (repairs == sorted(set(repairs)))
        and all(type(entry) is int and 0 <= entry < image_length for entry in repairs),
        f"{context}.expected_branch_repairs is invalid",
    )
    reseat = value.get("expected_relocation_reseat")
    require(
        isinstance(reseat, list)
        and len(reseat) <= 256
        and all(
            isinstance(pair, list)
            and len(pair) == 2
            and all(type(entry) is int for entry in pair)
            and (0 <= pair[0] < preimage_length)
            and (0 <= pair[1] < image_length)
            and (pair[0] != pair[1])
            for pair in reseat
        )
        and ([pair[0] for pair in reseat] == sorted({pair[0] for pair in reseat}))
        and (len({pair[1] for pair in reseat}) == len(reseat)),
        f"{context}.expected_relocation_reseat is invalid",
    )
    fields = value.get("expected_rewritten_field_offsets")
    require(
        isinstance(fields, list)
        and fields
        and (fields == sorted(set(fields)))
        and all(
            type(entry) is int and any(item["start"] <= entry < item["end"] for item in normalized)
            for entry in fields
        ),
        f"{context}.expected_rewritten_field_offsets is invalid",
    )
    counts = value.get("expected_region_instruction_counts")
    total = require_exact_int(
        value.get("expected_instruction_count"), f"{context}.expected_instruction_count", minimum=2
    )
    require(
        isinstance(counts, list)
        and len(counts) == len(normalized)
        and all(type(entry) is int and entry >= 1 for entry in counts)
        and (sum(counts) <= total),
        f"{context}.expected_region_instruction_counts is invalid",
    )
    require(
        require_exact_int(
            value.get("expected_image_code_length"),
            f"{context}.expected_image_code_length",
            minimum=1,
        )
        <= image_length,
        f"{context}.expected_image_code_length exceeds the image",
    )
    procedure = value.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all(type(entry) is int for entry in procedure)
        and (procedure[0] == image_length)
        and (0 <= procedure[1] <= procedure[2] < image_length),
        f"{context}.expected_procedure_range is invalid",
    )
    carried = value.get("expected_carried_code_symbols")
    require(
        isinstance(carried, list)
        and len(carried) <= 64
        and all(
            isinstance(row, list)
            and len(row) == 3
            and isinstance(row[0], str)
            and row[0]
            and (type(row[1]) is int)
            and (type(row[2]) is int)
            and (0 <= row[1] < preimage_length)
            and (0 <= row[2] < image_length)
            for row in carried
        ),
        f"{context}.expected_carried_code_symbols is invalid",
    )
    targets = value.get("expected_internal_relocation_targets")
    if targets is not None:
        require(
            isinstance(targets, list)
            and targets == sorted(set(targets))
            and all(type(entry) is int and 0 <= entry < preimage_length for entry in targets),
            f"{context}.expected_internal_relocation_targets is invalid",
        )
    code_length = value.get("expected_code_length")
    if code_length is not None:
        require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=1, maximum=preimage_length
        )
    normalized_value = {
        **value,
        "regions": normalized,
        "expected_fpo_record": dict(sorted(record.items())),
    }
    return normalized_value


REGISTER_BIJECTION_REENCODING_CLASS = "retail_exact_register_bijection_reencoding"
REGISTER_BIJECTION_REENCODING_KIND = "frame_pointer_free_register_bijection_v1"
FPO_FRAME_KIND_FPO = 0


def require_no_ebp_frame_derivation(body: bytes, instructions, context: str) -> None:
    """Prove that decoded instructions never establish EBP from ESP."""
    for item in instructions:
        if "ebp" not in item["writes"]:
            continue
        encoding = item["encoding"]
        direct = set()
        for byte_index, shift in item["fields"]:
            name = IA32_GENERAL_REGISTER_NAMES[body[byte_index] >> shift & 7]
            if encoding is None:
                direct.add(name)
                continue
            memory_base = (
                byte_index
                == (encoding["sib_at"] if encoding["sib_at"] is not None else encoding["modrm_at"])
                and shift == 0
                and (encoding["mode"] != 3)
            )
            memory_index = (
                encoding["sib_at"] is not None
                and byte_index == encoding["sib_at"]
                and (shift == 3)
                and (encoding["mode"] != 3)
            )
            if memory_base or memory_index:
                if item["opcode"] == 141:
                    direct.add(name)
                continue
            direct.add(name)
        require(
            "esp" not in direct,
            f"{context}: the instruction at {item['offset']} derives EBP from ESP, which establishes a frame pointer",
        )


def require_frame_pointer_free_frame(
    coff: CoffObject,
    section: dict[str, Any],
    body: bytes,
    instructions: list[dict[str, Any]],
    context: str,
) -> dict[str, Any]:
    """Obligation 11: prove EBP is not this body's frame pointer.

    Two independent facts are required, and BOTH come from the object itself:
    the compiler's own FPO record for this COMDAT declares FRAME_FPO with no
    structured exception handling, and no instruction in the decoded body
    derives EBP from ESP.  The first is the compiler's statement that the
    function has no EBP frame; the second is a structural check on the code
    that no `mov ebp, esp` / `lea ebp, [esp+d]` establishes one anyway.
    """
    closure = _comdat_child_closure(coff, section)
    require(
        closure == (2, (".debug$F", ".debug$S")),
        f"{context}: a frame-pointer-free proof needs the FPO closure",
    )
    record = parse_fpo_data(
        bytes(coff_body(coff, _comdat_child(coff, section, ".debug$F"))),
        expected_proc_size=section["raw_size"],
    )
    require(
        record["cbFrame"] == FPO_FRAME_KIND_FPO,
        f"{context}: the FPO record does not declare FRAME_FPO, so EBP may be this body's frame pointer",
    )
    require(
        record["fHasSEH"] == 0,
        f"{context}: the FPO record declares structured exception handling, whose unwind may read EBP",
    )
    require_no_ebp_frame_derivation(body, instructions, context)
    return record


def _reencoding_region_for(regions: list[dict[str, Any]], offset: int) -> dict[str, Any] | None:
    """The declared region covering one instruction, or None."""
    for region in regions:
        if region["start"] <= offset < region["end"]:
            return region
    return None


def _reencoded_instruction(
    body: bytes,
    item: dict[str, Any],
    mapping: dict[str, Any],
    numbers: dict[int, int],
    relocation_offsets: frozenset[int],
    context: str,
) -> tuple[bytes, str, list[int]]:
    """Rewrite ONE instruction's register fields, re-encoding if EBP forces it.

    Obligation 12.  Returns the new encoding, the class of change and the
    pre-image byte offsets whose value the rewrite changed:
    `"field"` when only register fields moved, `"reencode"` when the ModRM
    `mod` field additionally had to change because the memory BASE crossed
    EBP.  The re-encoding is derived from the decoder's own layout
    description, never by re-disassembling this function's own output.
    """
    start, length = (item["offset"], item["length"])
    raw = bytearray(body[start : start + length])
    encoding = item["encoding"]
    base_field = None
    if encoding is not None and encoding["mode"] != 3 and (not encoding["absolute"]):
        base_field = encoding["sib_at"] if encoding["sib_at"] is not None else encoding["modrm_at"]
    base_before = None
    base_after = None
    touched = []
    for byte_index, shift in item["fields"]:
        value = raw[byte_index - start] >> shift & 7
        if byte_index == base_field and shift == 0:
            base_before = value
        if value not in numbers:
            if byte_index == base_field and shift == 0:
                base_after = value
            continue
        require(
            byte_index not in relocation_offsets,
            f"{context}: a rewritten byte at {byte_index} overlaps a relocation",
        )
        raw[byte_index - start] = (
            raw[byte_index - start] & ~(7 << shift) | numbers[value] << shift
        ) & 255
        if raw[byte_index - start] != body[byte_index]:
            touched.append(byte_index)
        if byte_index == base_field and shift == 0:
            base_after = numbers[value]
    touched = sorted(set(touched))
    if base_field is None or base_before is None or base_before == base_after:
        return (bytes(raw), "field", touched)
    ebp = _IA32_REGISTER_NUMBERS["ebp"]
    modrm_local = encoding["modrm_at"] - start
    mode = encoding["mode"]
    if base_after == ebp:
        require(mode in (0, 1, 2), f"{context}: unexpected ModRM mode at {start}")
        if mode != 0:
            return (bytes(raw), "field", touched)
        insert_at = (
            encoding["sib_at"] - start + 1 if encoding["sib_at"] is not None else modrm_local + 1
        )
        require(
            encoding["displacement_size"] == 0,
            f"{context}: a mod-00 operand at {start} already carries a displacement",
        )
        raw[modrm_local] = raw[modrm_local] & 63 | 64
        raw = raw[:insert_at] + bytearray(b"\x00") + raw[insert_at:]
        return (bytes(raw), "reencode", touched)
    if base_before == ebp:
        if mode != 1:
            return (bytes(raw), "field", touched)
        require(
            encoding["displacement_size"] == 1 and encoding["displacement_at"] is not None,
            f"{context}: a mod-01 operand at {start} has no disp8",
        )
        displacement_local = encoding["displacement_at"] - start
        if raw[displacement_local] != 0:
            return (bytes(raw), "field", touched)
        raw[modrm_local] = raw[modrm_local] & 63
        del raw[displacement_local]
        return (bytes(raw), "reencode", touched)
    return (bytes(raw), "field", touched)


IA32_REPAIRABLE_BRANCH_WIDTHS = (1, 4)
REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS = 64


def apply_slot_bijection(
    body: bytes,
    mapping: dict[str, Any],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Exchange two (or more) EBP frame slots' displacements body-wide.

    Renaming same-width private stack slots consistently everywhere is an
    isomorphism of the machine function: every read, write and address
    formation moves with its slot, so no execution can tell the difference.
    The soundness rests on TOTALITY and NON-OVERLAP, and both are checked
    here: every instruction whose EBP-based operand touches a mapped slot
    must reference it exactly (same displacement, dword width or an address
    formation), any partial overlap refuses, any ESP-based operand in the
    body refuses (it could alias a mapped slot at a distance this check
    cannot bound), and a displacement byte under a relocation refuses.
    Length preservation is structural: only displacement BYTES change, and
    each rewritten value must fit the encoded displacement size.
    """
    require_payload_free_declaration(
        list(mapping.items()) if isinstance(mapping, dict) else mapping, f"{context} slot mapping"
    )
    require(
        isinstance(mapping, dict) and len(mapping) >= 2, f"{context}: the slot mapping is empty"
    )
    slots = {int(key): int(value) for key, value in mapping.items()}
    require(
        set(slots) == set(slots.values())
        and len(set(slots.values())) == len(slots)
        and all((key != value for key, value in slots.items())),
        f"{context}: the slot mapping is not a fixed-point-free bijection",
    )
    require(
        all((key < 0 and value < 0 for key, value in slots.items())),
        f"{context}: the slot mapping leaves the local frame",
    )
    ordered = sorted(slots)
    for left, right in itertools.pairwise(ordered):
        require(right - left >= 4, f"{context}: mapped slots overlap")
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    image = bytearray(body)
    rewritten = []
    for item in instructions:
        memory = item.get("memory")
        if not memory or memory.get("absolute"):
            continue
        base = memory.get("base")
        require(
            base != "esp",
            f"{context}: an ESP-based operand at {item['offset']} could alias a mapped slot",
        )
        if base != "ebp":
            continue
        displacement = memory.get("displacement")
        width = memory.get("width") or 4
        if displacement in slots:
            is_lea = item["opcode"] == 141
            require(
                is_lea or width == 4,
                f"{context}: the access at {item['offset']} reads a mapped slot at a different width",
            )
            encoding = item.get("encoding") or {}
            at = encoding.get("displacement_at")
            size = encoding.get("displacement_size")
            require(
                at is not None and size in (1, 4),
                f"{context}: the instruction at {item['offset']} has no rewritable displacement field",
            )
            require(
                not any(at + k in relocation_offsets for k in range(size)),
                f"{context}: the displacement at {item['offset']} is relocated",
            )
            value = slots[displacement]
            limit = 1 << 8 * size - 1
            require(
                -limit <= value < limit,
                f"{context}: the exchanged displacement at {item['offset']} does not fit its field",
            )
            image[at : at + size] = value.to_bytes(size, "little", signed=True)
            rewritten.extend(range(at, at + size))
        else:
            for slot in slots:
                require(
                    displacement + width <= slot or slot + 4 <= displacement,
                    f"{context}: the access at {item['offset']} partially overlaps a mapped slot",
                )
    require(rewritten, f"{context}: the slot bijection rewrites nothing")
    reencoded = decode_ia32_bijection_body(
        bytes(image), f"{context} image", relocations, code_length
    )
    require(
        len(reencoded) == len(instructions)
        and all(
            (
                left["offset"] == right["offset"] and left["length"] == right["length"]
                for left, right in zip(instructions, reencoded)
            )
        ),
        f"{context}: the exchange changed the instruction grid",
    )
    changed = [offset for offset in rewritten if image[offset] != body[offset]]
    return (bytes(image), {"rewritten_offsets": sorted(changed)})


def apply_register_bijection_reencoding(
    body: bytes,
    regions: list[dict[str, Any]],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
    internal_targets: frozenset[int] | None = None,
    frame_pointer_free: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Rewrite several regions under proved bijections, re-encoding for EBP.

    This is `apply_register_bijection` generalised on two axes: sigma may name
    EBP when the caller has discharged obligation 11, and an instruction may
    change length when -- and only when -- the ModRM `mod` field forces it.
    Every obligation of the parent still holds, and obligations 12 to 14 are
    checked here.  The result is re-decoded to exhaustion so that every claim
    about the image is measured ON the image.
    """
    require_payload_free_declaration(regions, f"{context} register re-encoding declaration")
    body = bytes(body)
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    limit = len(body) if code_length is None else code_length
    boundaries = {item["offset"] for item in instructions}
    boundaries.add(limit)
    index_of = {item["offset"]: index for index, item in enumerate(instructions)}
    require(regions, f"{context}: no region is declared")
    previous_end = 0
    for position, region in enumerate(regions):
        region_context = f"{context} region {position}"
        start, end = (region["start"], region["end"])
        require(
            start >= previous_end and start < end,
            f"{region_context}: regions are unsorted, empty or overlapping",
        )
        previous_end = end
        require(end <= limit, f"{region_context}: region reaches past the body's code")
        require(
            start in boundaries and end in boundaries,
            f"{region_context}: region does not span whole instructions",
        )
        mapping = region["mapping"]
        require(
            set(mapping.values()) == set(mapping)
            and all((source != destination for source, destination in mapping.items())),
            f"{region_context}: mapping is not a bijection of one register set",
        )
        for name in set(mapping) | set(mapping.values()):
            require(
                name in _IA32_REGISTER_NUMBERS,
                f"{region_context}: mapping names an unknown register",
            )
        support = set(mapping) | set(mapping.values())
        require(
            "esp" not in support,
            f"{region_context}: ESP cannot be a ModRM base or a SIB index, so a rename to or from it is not an encoding change",
        )
        require(
            frame_pointer_free or "ebp" not in support,
            f"{region_context}: EBP is refused without a frame-pointer-free proof for this body",
        )
    if any(item["indirect"] for item in instructions):
        require(
            internal_targets is not None,
            f"{context}: a computed jump requires the relocated in-body target set",
        )
        for position, region in enumerate(regions):
            entered = sorted(
                target for target in internal_targets if region["start"] < target < region["end"]
            )
            require(
                not entered,
                f"{context} region {position}: a relocated in-body target at {entered[:1]} enters the region other than at its first instruction",
            )
    live, successors = _register_bijection_live_sets(instructions, context)
    for position, region in enumerate(regions):
        region_context = f"{context} region {position}"
        start, end = (region["start"], region["end"])
        mapping = region["mapping"]
        support = set(mapping) | set(mapping.values())
        inside = [item for item in instructions if start <= item["offset"] < end]
        require(inside, f"{region_context}: region contains no instruction")
        require(
            inside[-1]["offset"] + inside[-1]["length"] == end,
            f"{region_context}: region does not end on an instruction boundary",
        )
        entry = index_of[inside[0]["offset"]]
        for item in inside:
            blocked = support & set(item.get("frozen", frozenset()))
            require(
                not blocked,
                f"{region_context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that sigma cannot rewrite",
            )
        for index, item in enumerate(instructions):
            for edge in successors[index]:
                if (
                    not start <= item["offset"] < end
                    and start <= instructions[edge]["offset"] < end
                ):
                    require(
                        edge == entry,
                        f"{region_context}: control enters the region other than at its first instruction",
                    )
        support_atoms = ia32_register_atoms(support)
        dead_in = support_atoms & set(live[entry])
        require(
            not dead_in,
            f"{region_context}: {_ia32_atom_registers(dead_in)} is live on entry to the region",
        )
        for index, item in enumerate(instructions):
            if not start <= item["offset"] < end:
                continue
            for edge in successors[index]:
                if start <= instructions[edge]["offset"] < end:
                    continue
                leaking = support_atoms & set(live[edge])
                require(
                    not leaking,
                    f"{region_context}: {_ia32_atom_registers(leaking)} is live on an edge leaving the region at {item['offset']}",
                )
            if item["flow"] in ("ret", "exit"):
                leaking = support_atoms & set(item["read_atoms"])
                require(
                    not leaking,
                    f"{region_context}: {_ia32_atom_registers(leaking)} is live at the region's return",
                )
    pieces = []
    classes = []
    rewritten_fields = []
    for item in instructions:
        region = _reencoding_region_for(regions, item["offset"])
        if region is None:
            pieces.append(body[item["offset"] : item["offset"] + item["length"]])
            classes.append("unchanged")
            continue
        numbers = {
            _IA32_REGISTER_NUMBERS[source]: _IA32_REGISTER_NUMBERS[destination]
            for source, destination in region["mapping"].items()
        }
        raw, kind, touched = _reencoded_instruction(
            body, item, region["mapping"], numbers, relocation_offsets, context
        )
        rewritten_fields.extend(touched)
        require(
            len(raw) - item["length"] in (-1, 0, 1),
            f"{context}: the re-encoding at {item['offset']} changed the length by more than the one byte a mod field forces",
        )
        require(
            kind == "reencode" or len(raw) == item["length"],
            f"{context}: the instruction at {item['offset']} changed length without a mod re-encoding",
        )
        pieces.append(raw)
        classes.append(kind)
    tail = body[limit:]

    def _starts(current: list[bytes]) -> list[int]:
        cursor, out = (0, [])
        for raw in current:
            out.append(cursor)
            cursor += len(raw)
        return out

    repaired = set()
    for _round in range(REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS):
        starts = _starts(pieces)
        changed = False
        for index, item in enumerate(instructions):
            if item["flow"] not in ("jcc", "jmp") or item["target"] is None:
                continue
            raw = bytearray(pieces[index])
            width = _reencoding_branch_width(item, raw, context)
            destination = starts[index_of[item["target"]]]
            delta = destination - (starts[index] + len(raw))
            require(
                -(1 << 8 * width - 1) <= delta < 1 << 8 * width - 1,
                f"{context}: the branch at {item['offset']} no longer reaches its target in {width} displacement byte(s); widening it would be a code change, not a renaming",
            )
            encoded = delta.to_bytes(width, "little", signed=True)
            if bytes(raw[len(raw) - width :]) != encoded:
                raw[len(raw) - width :] = encoded
                pieces[index] = bytes(raw)
                repaired.add(item["offset"])
                changed = True
        if not changed:
            break
    else:
        raise ByteIdentityError(f"{context}: the branch-displacement fixpoint did not converge")
    starts = _starts(pieces)
    image = b"".join(pieces) + tail
    offset_map = {item["offset"]: starts[index] for index, item in enumerate(instructions)}
    image_limit = starts[-1] + len(pieces[-1]) if pieces else 0
    offset_map[limit] = image_limit
    require(
        len(image) == image_limit + len(tail),
        f"{context}: the image is not the concatenation of its pieces",
    )
    for index, item in enumerate(instructions):
        original = body[item["offset"] : item["offset"] + item["length"]]
        if pieces[index] == original:
            continue
        require(
            classes[index] in ("field", "reencode") or item["offset"] in repaired,
            f"{context}: the instruction at {item['offset']} changed outside a declared region and is not a branch repair",
        )
    reseat = []
    for offset in sorted(relocations or {}):
        record = (relocations or {})[offset]
        width = record["width"]
        owner = None
        for index, item in enumerate(instructions):
            if item["offset"] <= offset and offset + width <= item["offset"] + item["length"]:
                owner = index
                break
        require(
            owner is not None,
            f"{context}: the relocation at {offset} does not lie wholly inside one decoded instruction",
        )
        item = instructions[owner]
        growth = len(pieces[owner]) - item["length"]
        from_end = item["offset"] + item["length"] - offset
        new_offset = starts[owner] + len(pieces[owner]) - from_end
        if growth:
            encoding = item["encoding"]
            require(
                encoding is not None,
                f"{context}: a re-encoded instruction at {item['offset']} has no ModRM layout",
            )
            fixed_end = (
                encoding["sib_at"] if encoding["sib_at"] is not None else encoding["modrm_at"]
            ) + 1
            require(
                offset >= fixed_end,
                f"{context}: the relocation at {offset} overlaps the ModRM/SIB bytes the re-encoding changed",
            )
            require(
                new_offset == offset + (starts[owner] - item["offset"]) + growth,
                f"{context}: the reseat of {offset} is inconsistent",
            )
        require(
            starts[owner] <= new_offset
            and new_offset + width <= starts[owner] + len(pieces[owner]),
            f"{context}: the reseat of {offset} leaves its instruction",
        )
        reseat.append([offset, new_offset])
    require(
        len({pair[1] for pair in reseat}) == len(reseat),
        f"{context}: the reseat collides two relocation records",
    )
    image_relocations = None
    if relocations is not None:
        moved = dict(reseat)
        image_relocations = {moved[offset]: record for offset, record in relocations.items()}
    if internal_targets is not None:
        for target in internal_targets:
            require(
                target in offset_map,
                f"{context}: a relocated in-body target at {target} is not an instruction boundary",
            )
    image_instructions = decode_ia32_bijection_body(
        image, f"{context} image", image_relocations, None if code_length is None else image_limit
    )
    require(
        len(image_instructions) == len(instructions),
        f"{context}: the image has a different instruction count",
    )
    for left, right, raw in zip(image_instructions, instructions, pieces):
        require(
            left["offset"] == offset_map[right["offset"]] and left["length"] == len(raw),
            f"{context}: the image's instruction at {right['offset']} did not land where the layout says",
        )
        form = _bijection_form_for(right["opcode"])
        opreg = form is not None and form["opreg"] is not None
        mask = 248 if opreg else 65535
        require(
            left["opcode"] & mask == right["opcode"] & mask and left["flow"] == right["flow"],
            f"{context}: the image changed an opcode or a control flow at {right['offset']}",
        )
        require(
            left["target"] == (None if right["target"] is None else offset_map[right["target"]]),
            f"{context}: the image changed a branch target at {right['offset']}",
        )
        region = _reencoding_region_for(regions, right["offset"])
        mapping = {} if region is None else region["mapping"]
        require(
            left["reads"] == frozenset(mapping.get(name, name) for name in right["reads"])
            and left["writes"] == frozenset(mapping.get(name, name) for name in right["writes"]),
            f"{context}: the image's operand set at {right['offset']} is not the bijection's image",
        )
    require(image[image_limit:] == tail, f"{context}: the image changed the body's data tail")
    growth_detail = [
        [item["offset"], starts[index], item["length"], len(pieces[index])]
        for index, item in enumerate(instructions)
        if len(pieces[index]) != item["length"]
    ]
    rewritten = sorted(set(rewritten_fields))
    require(rewritten, f"{context}: the bijection rewrites no register field")
    require(image != body or growth_detail, f"{context}: the bijection moves nothing")
    return (
        image,
        {
            "offset_map": {str(key): value for key, value in sorted(offset_map.items())},
            "growth": growth_detail,
            "branch_repairs": sorted(offset_map[offset] for offset in repaired),
            "relocation_reseat": [pair for pair in reseat if pair[0] != pair[1]],
            "region_instruction_counts": [
                sum(1 for item in instructions if region["start"] <= item["offset"] < region["end"])
                for region in regions
            ],
            "rewritten_field_offsets": rewritten,
            "instruction_count": len(instructions),
            "code_length": limit,
            "image_code_length": image_limit,
        },
    )


def _reencoding_branch_width(item: dict[str, Any], raw: bytes, context: str) -> int:
    """The displacement width of one repairable relative branch.

    Read off the module's own closed form table, never guessed, and refused
    for any encoding whose displacement this class will not repair.
    """
    form = _bijection_form_for(item["opcode"])
    require(
        form is not None and form["displacement"] in IA32_REPAIRABLE_BRANCH_WIDTHS,
        f"{context}: the branch at {item['offset']} has no repairable displacement field",
    )
    require(
        len(raw) == item["length"],
        f"{context}: the branch at {item['offset']} changed its own encoding length",
    )
    return form["displacement"]
