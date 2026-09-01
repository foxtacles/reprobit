"""Quarantined classic-MSVC simulated-elision composer.

This module is the only classic producer allowed to read reference-image bytes.
It preserves one finite quarantined action while proving its declared code
regions equivalent, rebuilding all branch and COFF offsets, and making the
resulting provenance permanently ineligible for a clean verdict.
Normal candidate producers must never import this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import (
    CoffObject,
    coff_body,
    detailed_relocations,
    section_definitions,
)
from reprobit.ia32_decode import supported_ia32_instruction_length

from .coff import (
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_same_slot import compose_same_slot_resize
from .foundation import RelocationView, sha256_bytes
from .register_candidates import _reencoded_donor_object
from .register_reencoding import (
    REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS,
    _reencoding_branch_width,
)
from .register_semantics import (
    _IA32_ATOMS_OF,
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
)
from .relational import (
    ia32_relational_flag_liveness,
    ia32_relational_flow_walk,
    relational_form_external_entries,
)
from .rewriting_exchanges import _SIMULATOR_REGS
from .rewriting_region_simulation import _srr_simulate, _srr_slot_scratch_proof
from .scheduling import INSTRUCTION_SCHEDULE_EH_CLOSURE, INSTRUCTION_SCHEDULE_FPO_CLOSURE


def require_retail_relocation_oracle(
    donor_rows: list[dict[str, Any]],
    retail_body: bytes,
    retail_address: int,
    oracle: list[dict[str, Any]],
    context: str,
) -> dict[str, int]:
    """Bind every masked operand to the symbol it resolves to in retail.

    Masked body equality alone is insufficient: two COFF objects can carry
    identical instruction bytes while naming different callees.  This check
    decodes each pinned retail operand before the mask is applied.
    """
    require(
        len(donor_rows) == len(oracle),
        f"{context} relocation count differs from its semantic oracle",
    )
    fields = (
        "offset",
        "type",
        "addend",
        "target",
        "target_section",
        "target_value",
        "target_type",
        "target_storage",
    )
    for index, (record, expected) in enumerate(zip(donor_rows, oracle, strict=True)):
        require(
            all(record[field] == expected[field] for field in fields),
            f"{context} relocation {index} differs from its COFF oracle",
        )
        offset = record["offset"]
        raw = retail_body[offset : offset + 4]
        require(len(raw) == 4, f"{context} relocation {index} leaves the retail body")
        if record["type"] == 0x0006:  # IMAGE_REL_I386_DIR32
            resolved = int.from_bytes(raw, "little")
        else:  # IMAGE_REL_I386_REL32
            displacement = int.from_bytes(raw, "little", signed=True)
            resolved = (retail_address + offset + 4 + displacement) & 0xFFFFFFFF
        symbol_base = (resolved - record["addend"]) & 0xFFFFFFFF
        require(
            symbol_base == int(expected["retail_target"], 16),
            f"{context} relocation {index} resolves to 0x{symbol_base:08x}, "
            f"not {expected['retail_target']}",
        )
    return {"semantic_relocation_count": len(donor_rows)}


SIMULATED_ELISION_KIND = "simulated_elision_v1"
SIMULATED_ELISION_CLASS = "retail_exact_simulated_elision"


def _srr_entry_load_proof(
    decoded: list[dict[str, Any]],
    branch_targets: set[int],
    at_offset: int,
    register: str,
    disp: int,
    context: str,
) -> int:
    """Prove a region entry condition: REGISTER holds [ebp+DISP] on entry.

    The proof is a backward scan from the region start over the dominating
    straight-line run: the defining instruction must be `mov reg, [ebp+disp]`
    and nothing between it and the region may redefine the register, write
    memory, call, branch, or be branched into.  Anything else refuses."""
    index = None
    for position, item in enumerate(decoded):
        if item["offset"] == at_offset:
            index = position
            break
    require(index is not None, f"{context}: the region start is not an instruction boundary")
    assert index is not None
    atoms = _IA32_ATOMS_OF[register]
    number = _IA32_REGISTER_NUMBERS[register]
    for position in range(index - 1, -1, -1):
        item = decoded[position]
        memory = item.get("memory")
        encoding = item.get("encoding") or {}
        if (
            item["opcode"] == 0x8B
            and memory
            and memory.get("base") == "ebp"
            and memory.get("displacement") == disp
            and encoding.get("reg") == number
            and encoding.get("mode") != 3
        ):
            # The defining load itself may be a branch target: entering AT
            # the definition still executes it before the region.
            return int(item["offset"])
        require(
            item["offset"] not in branch_targets,
            f"{context}: a branch target interrupts the entry-load scan at {item['offset']}",
        )
        # A conditional branch may sit between the load and the region: its
        # fallthrough edge is the only path that reaches the region from
        # here, and it writes nothing.  Anything without a fallthrough --
        # or with an effect -- refuses.
        require(
            item["flow"] in ("fall", "jcc"),
            f"{context}: control flow interrupts the entry-load scan at {item['offset']}",
        )
        require(
            not (frozenset(item["write_atoms"]) & atoms),
            f"{context}: {register} is redefined at {item['offset']} "
            "before the region without the declared load",
        )
        require(
            not (memory and memory.get("write")),
            f"{context}: a memory write at {item['offset']} interrupts the entry-load scan",
        )
    require(False, f"{context}: no dominating mov {register}, [ebp{disp:+#x}] was found")
    raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True, kw_only=True)
class ElisionInput:
    """The retail side of a simulated elision.

    ``retail_body`` is the oracle body whose bytes replace each declared
    region, ``image_relocations`` its relocation targets by offset,
    ``branch_widenings`` the declared widenings of branches that cross a
    resized region, and ``oracles`` the callee and vtable oracles the
    simulator resolves calls through.
    """

    retail_body: bytes
    image_relocations: dict[int, str] | None = None
    branch_widenings: list[int] | None = None
    oracles: dict[str, Any] | None = None


def apply_simulated_elision(
    body: bytes,
    regions: list[dict[str, Any]],
    relocation_offsets: frozenset[int],
    context: str,
    retail: ElisionInput,
    *,
    view: RelocationView | None = None,
    external_entries: frozenset[int] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Replace declared regions with the RETAIL ORACLE's own bytes, each
    replacement proved equivalent to the seed's region by symbolic execution.

    This is the copy-elision-with-RESIZE primitive: a region's image may have
    a DIFFERENT length than its source, so the whole body is rebuilt around
    the replacements, every relative branch that crosses a region is repaired
    through the derived boundary map (the re-encoding class's fixpoint,
    reused verbatim in shape), and every dependent COFF record is reseated by
    the same map.  Soundness never comes from the oracle: `_srr_simulate`
    runs BOTH versions and the composition refuses unless their exit states
    agree exactly -- registers, frame slots, FP stack, push sequence, and the
    final flag/terminal-call effect -- modulo a declared dead set that is
    then proved dead by the bijection certificate's own liveness.  A region
    whose two versions compute different things cannot compose, whatever the
    oracle says.
    """
    retail_body = retail.retail_body
    image_relocations = retail.image_relocations
    branch_widenings = retail.branch_widenings
    oracles = retail.oracles
    if view is None:
        view = RelocationView()
    relocations = view.relocations
    code_length = view.code_length
    internal_targets = view.internal_targets
    require(bool(isinstance(body, (bytes, bytearray)) and body), f"{context}: body is empty")
    body = bytes(body)
    require(
        bool(isinstance(retail_body, (bytes, bytearray)) and retail_body),
        f"{context}: retail oracle body is missing",
    )
    require(bool(isinstance(regions, list) and regions), f"{context}: no region is declared")
    limit = len(body) if code_length is None else code_length
    require(0 < limit <= len(body), f"{context}: code length is invalid")
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    index_of = {item["offset"]: index for index, item in enumerate(instructions)}
    boundaries = set(index_of)
    boundaries.add(limit)
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    walk_items = items
    flag_live = ia32_relational_flag_liveness(items, successors, context)
    walk_index = {item["offset"]: index for index, item in enumerate(items)}
    # The liveness refinement the parent SRR uses: an indirect call cannot
    # read EAX under any convention of this toolchain.
    refined: list[dict[str, Any]] = []
    for entry in instructions:
        if entry["flow"] == "call" and entry["opcode"] == 0xFF:
            entry = {**entry, "read_atoms": frozenset(entry["read_atoms"]) - _IA32_ATOMS_OF["eax"]}
        refined.append(entry)
    live, _succ = _register_bijection_live_sets(refined, f"{context} liveness")

    previous_end = 0
    delta = 0
    proved: list[dict[str, Any]] = []
    replacements: dict[int, tuple[int, bytes]] = {}
    paired_reseat: dict[int, tuple[int, int]] = {}
    for ordinal, item in enumerate(regions):
        item_context = f"{context} region {ordinal}"
        start, end = item["region_start"], item["region_end"]
        image_start = item["image_start"]
        image_length = item["image_length"]
        require(
            type(start) is int
            and type(end) is int
            and type(image_start) is int
            and type(image_length) is int
            and 0 < start < end <= limit
            and image_length > 0,
            f"{item_context}: bounds are out of range",
        )
        require(previous_end <= start, f"{item_context}: regions are unsorted or overlapping")
        previous_end = end
        require(
            start in boundaries and end in boundaries,
            f"{item_context}: region does not span whole instructions",
        )
        # The image start is DECLARED, not derived: branch widenings that
        # the fixpoint discovers later also shift the retail layout, so the
        # cumulative region delta alone cannot predict it.  A wrong
        # declaration cannot compose -- the final retail-equality check
        # compares every byte of the rebuilt body against the oracle.
        require(
            image_start + image_length <= len(retail_body),
            f"{item_context}: the image slice leaves the oracle",
        )
        require(
            not any(start < target < end for target in branch_targets),
            f"{item_context}: a branch targets the region interior",
        )
        require(
            not any(start < walk_items[entry]["offset"] < end for entry in entries[1:]),
            f"{item_context}: an external entry lies inside the region",
        )
        require(
            not any(start < target < end for target in (internal_targets or frozenset())),
            f"{item_context}: a relocated target lies inside the region",
        )
        pairs = item.get("relocation_pairs")
        region_reloc_offsets = sorted(
            offset for offset in (relocations or {}) if start <= offset < end
        )
        paired: list[tuple[int, int, int]] = []
        if pairs is None:
            require(
                not any(start <= offset < end for offset in relocation_offsets),
                f"{item_context}: a relocation lies inside the region; "
                "the elision does not reseat relocations it replaces",
            )
        else:
            # A region MAY carry relocations when every one is paired with
            # its position in the image and the image position names the
            # SAME symbol in the declared retail relocation table.  The
            # simulator then reads both fields as that symbol, so the two
            # versions' relocated values compare by identity, and the
            # reseat below moves each seed record to its paired position.
            require(
                [pair[0] for pair in pairs] == region_reloc_offsets,
                f"{item_context}: relocation_pairs do not cover the region's relocations exactly",
            )
            for seed_offset, image_offset in pairs:
                row = (relocations or {})[seed_offset]
                width = row["width"] if isinstance(row, dict) else 4
                require(
                    image_start <= image_offset
                    and image_offset + width <= image_start + image_length,
                    f"{item_context}: a paired relocation leaves the image slice",
                )
                seed_target = row["target"] if isinstance(row, dict) else row
                image_target = (image_relocations or {}).get(image_offset)
                require(
                    image_target is not None and image_target == seed_target,
                    f"{item_context}: the relocation at {seed_offset} "
                    f"names '{seed_target}' but the image position "
                    f"{image_offset} names '{image_target}'",
                )
                paired.append((seed_offset, image_offset, width))
                paired_reseat[seed_offset] = (start, image_offset - image_start)
        entry_loads = item.get("entry_loads") or {}
        if entry_loads:
            require(
                isinstance(entry_loads, dict)
                and all(
                    name in _IA32_REGISTER_NUMBERS
                    and name not in _IA32_STRUCTURAL_REGISTERS
                    and type(value) is int
                    for name, value in entry_loads.items()
                ),
                f"{item_context}.entry_loads is invalid",
            )
            # The image side has no relocations to mark its funclet tail,
            # so the strict decoder cannot walk it; the proof instead rides
            # the seed's: the image's dominating window must be BYTE-EQUAL
            # to the seed's proved window, and a tolerant linear scan of
            # the whole image must show no branch targeting the window's
            # interior (which would bypass the defining load).
            image_branch_targets: set[int] = set()
            cursor = 0
            while cursor < len(retail_body):
                step = supported_ia32_instruction_length(
                    retail_body[cursor:], f"{item_context} image scan"
                )
                lead = retail_body[cursor]
                follow = retail_body[cursor + 1] if step >= 2 else None
                relative = None
                if lead == 0xEB or 0x70 <= lead <= 0x7F:
                    relative = int.from_bytes(
                        retail_body[cursor + 1 : cursor + 2], "little", signed=True
                    )
                elif lead == 0xE9 or (
                    lead == 0x0F and follow is not None and 0x80 <= follow <= 0x8F
                ):
                    relative = int.from_bytes(
                        retail_body[cursor + step - 4 : cursor + step], "little", signed=True
                    )
                if relative is not None:
                    image_branch_targets.add(cursor + step + relative)
                cursor += step
            for name, value in entry_loads.items():
                definition = _srr_entry_load_proof(
                    instructions,
                    branch_targets,
                    start,
                    name,
                    value,
                    f"{item_context} seed entry {name}",
                )
                image_definition = image_start - (start - definition)
                require(
                    image_definition >= 0,
                    f"{item_context} image entry {name}: the image's "
                    "dominating window leaves the body",
                )
                # A conditional branch inside the window may aim elsewhere
                # in each version (the elision re-derives every crossing
                # displacement): the fallthrough state that reaches the
                # region does not depend on where the taken edge goes, and
                # the target-interior check above rules out entries that
                # would bypass the load.  So the comparison masks exactly
                # the branch displacement bytes and nothing else.
                for entry in instructions:
                    if not (definition <= entry["offset"] < start):
                        continue
                    seed_raw = body[entry["offset"] : entry["offset"] + entry["length"]]
                    shifted = image_definition + (entry["offset"] - definition)
                    image_raw = retail_body[shifted : shifted + entry["length"]]
                    if entry["flow"] in ("jcc", "jmp"):
                        width = _reencoding_branch_width(
                            entry, seed_raw, f"{item_context} image entry width"
                        )
                        seed_raw = seed_raw[: len(seed_raw) - width]
                        image_raw = image_raw[: len(image_raw) - width]
                    require(
                        seed_raw == image_raw,
                        f"{item_context} image entry {name}: the "
                        "image's dominating window differs from the "
                        f"seed's at {entry['offset']}",
                    )
                require(
                    not any(
                        image_definition < target <= image_start - 1
                        for target in image_branch_targets
                    ),
                    f"{item_context} image entry {name}: a branch "
                    "targets the image window's interior",
                )
        image_slice = bytes(retail_body[image_start : image_start + image_length])
        installed_slice = bytearray(image_slice)
        for _, image_offset, width in paired:
            # The retail bytes carry the linker-resolved operand; the
            # derived OBJECT must carry a zero addend there so the next
            # link resolves the paired symbol cleanly.  The final
            # retail-equality comparison masks exactly these fields.
            base_at = image_offset - image_start
            installed_slice[base_at : base_at + width] = b"\0" * width
        seed_region_map = {offset: (relocations or {})[offset] for offset in region_reloc_offsets}
        image_region_map = {
            image_offset - image_start: {
                "target": (image_relocations or {})[image_offset],
                "width": width,
            }
            for _, image_offset, width in paired
        }
        # Both versions execute symbolically; the closed simulator set is
        # the guard against any branch inside either version.
        seed_state = _srr_simulate(
            body, start, end, f"{item_context} seed", seed_region_map, oracles, entry_loads or None
        )
        image_state = _srr_simulate(
            image_slice,
            0,
            image_length,
            f"{item_context} image",
            image_region_map,
            oracles,
            entry_loads or None,
        )
        for label, seed_part, image_part in (
            ("FP stack", seed_state[1], image_state[1]),
            ("push sequence", seed_state[2], image_state[2]),
        ):
            require(
                seed_part == image_part,
                f"{item_context}: the two versions leave a different {label}",
            )
        seed_slots, image_slots = seed_state[3], image_state[3]
        dead_slots = item.get("dead_slots") or []
        require(
            isinstance(dead_slots, list) and all(type(d) is int for d in dead_slots),
            f"{item_context}.dead_slots is invalid",
        )
        require(
            set(seed_slots) == set(image_slots),
            f"{item_context}: the two versions write different frame slots",
        )
        differing_slots = sorted(d for d in seed_slots if seed_slots[d] != image_slots[d])
        require(
            differing_slots == sorted(dead_slots),
            f"{item_context}: the slots left differing "
            f"{differing_slots} are not the declared dead set "
            f"{sorted(dead_slots)}",
        )
        seed_flags, image_flags = seed_state[4], image_state[4]
        terminal = tuple(
            isinstance(flags, tuple) and flags[0] == "terminal_call"
            for flags in (seed_flags, image_flags)
        )
        require(
            terminal[0] == terminal[1], f"{item_context}: only one version ends at a terminal call"
        )
        if any(terminal):
            require(
                seed_flags == image_flags,
                f"{item_context}: the two versions reach the terminal "
                "call with a different target or argument sequence",
            )
        elif seed_flags != image_flags:
            symmetric = (
                isinstance(seed_flags, tuple)
                and isinstance(image_flags, tuple)
                and len(seed_flags) == 3
                and len(image_flags) == 3
                and seed_flags[0] == "cmp"
                and image_flags[0] == "cmp"
                and seed_flags[1] == image_flags[2]
                and seed_flags[2] == image_flags[1]
            )
            if symmetric:
                # A mirrored compare: ZF is symmetric under operand
                # exchange, the other arithmetic flags are not.  The
                # divergence is sound exactly when the region's exit
                # instruction is an equality branch -- the only consumer,
                # and it reads ZF alone -- and no flag survives past it on
                # either successor edge.
                require(
                    end in walk_index,
                    f"{item_context}: the mirrored compare's exit is not a flow boundary",
                )
                opcode = body[end] if end < len(body) else None
                equality = opcode in (0x74, 0x75) or (
                    opcode == 0x0F and end + 1 < len(body) and body[end + 1] in (0x84, 0x85)
                )
                require(
                    equality,
                    f"{item_context}: the mirrored compare's consumer is not an equality branch",
                )
                for edge in successors[walk_index[end]]:
                    require(
                        not flag_live[edge],
                        f"{item_context}: a flag outlives the mirrored compare's equality branch",
                    )
            else:
                require(
                    end in walk_index and not flag_live[walk_index[end]],
                    f"{item_context}: the two versions leave different "
                    "flag state and a flag is live at the exit",
                )
        differing = sorted(
            name for name in _SIMULATOR_REGS if seed_state[0][name] != image_state[0][name]
        )
        declared_dead = item.get("dead_registers") or []
        require(
            differing == sorted(declared_dead),
            f"{item_context}: the registers left differing {differing} "
            f"are not the declared dead set {sorted(declared_dead)}",
        )
        require(
            end in index_of or end == limit,
            f"{item_context}: the region end is not an instruction boundary of the body",
        )
        if end != limit:
            live_in = live[index_of[end]]
            for name in declared_dead:
                overlap = _IA32_ATOMS_OF[name] & live_in
                require(
                    not overlap,
                    f"{item_context}: {name} is live on the region's exit edge ({sorted(overlap)})",
                )
        else:
            require(
                not declared_dead,
                f"{item_context}: a region ending at the code limit can declare no dead register",
            )
        for disp in dead_slots:
            _srr_slot_scratch_proof(
                instructions,
                walk_items,
                successors,
                entries,
                end,
                disp,
                f"{item_context} slot {disp:#x}",
                body,
            )
        replacements[start] = (end, bytes(installed_slice))
        delta += image_length - (end - start)
        proof_entry: dict[str, Any] = {
            "region_start": start,
            "region_end": end,
            "image_start": image_start,
            "image_length": image_length,
            "dead_registers": sorted(declared_dead),
            "dead_slots": sorted(dead_slots),
        }
        if pairs is not None:
            proof_entry["relocation_pairs"] = [list(pair[:2]) for pair in paired]
        proved.append(proof_entry)

    # Rebuild the body: one piece per instruction outside every region, one
    # opaque piece per region.  Then the branch-displacement fixpoint.
    pieces: list[bytearray] = []
    piece_owner: list[int | tuple[str, int]] = []
    cursor = 0
    for index, item in enumerate(instructions):
        offset = item["offset"]
        if offset < cursor:
            continue
        if offset in replacements:
            end, image_slice = replacements[offset]
            pieces.append(bytearray(image_slice))
            piece_owner.append(("region", offset))
            cursor = end
            continue
        pieces.append(bytearray(body[offset : offset + item["length"]]))
        piece_owner.append(index)
        cursor = offset + item["length"]
    require(cursor == limit, f"{context}: the rebuilt pieces do not cover the code")
    tail = body[limit:]

    def _starts(current: list[bytearray]) -> list[int]:
        at = 0
        out: list[int] = []
        for raw in current:
            out.append(at)
            at += len(raw)
        return out

    def _map_offset(offset: int, starts: list[int]) -> int | None:
        # Map a seed boundary to the image frame: region starts map to the
        # region piece's start; other boundaries to their own piece.
        for piece_index, owner in enumerate(piece_owner):
            if owner == ("region", offset):
                return starts[piece_index]
            if isinstance(owner, int) and instructions[owner]["offset"] == offset:
                return starts[piece_index]
        return None

    repaired: set[int] = set()
    widened_set: set[int] = set()
    for _round in range(REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS):
        starts = _starts(pieces)
        changed = False
        for piece_index, owner in enumerate(piece_owner):
            if not isinstance(owner, int):
                continue
            item = instructions[owner]
            if item["flow"] not in ("jcc", "jmp") or item["target"] is None:
                continue
            if item["offset"] in widened_set:
                raw = pieces[piece_index]
                destination = _map_offset(item["target"], starts)
                require(
                    destination is not None,
                    f"{context}: the branch at {item['offset']} targets an offset "
                    "the elision erased",
                )
                assert destination is not None
                new_delta = destination - (starts[piece_index] + len(raw))
                encoded = new_delta.to_bytes(4, "little", signed=True)
                if bytes(raw[len(raw) - 4 :]) != encoded:
                    raw[len(raw) - 4 :] = encoded
                    changed = True
                continue
            raw = pieces[piece_index]
            width = _reencoding_branch_width(item, bytes(raw), context)
            destination = _map_offset(item["target"], starts)
            require(
                destination is not None,
                f"{context}: the branch at {item['offset']} targets an offset the elision erased",
            )
            assert destination is not None
            new_delta = destination - (starts[piece_index] + len(raw))
            if (
                not (-(1 << (8 * width - 1)) <= new_delta < (1 << (8 * width - 1)))
                and width == 1
                and item["offset"] in (branch_widenings or [])
            ):
                # The optimizer's own forced widening: a rel8 branch whose
                # target the layout pushed out of range becomes the rel32
                # form of the SAME condition.  Only a DECLARED offset may
                # widen, so an unexpected out-of-range branch still refuses.
                opcode = raw[0]
                if opcode == 0xEB:
                    widened = bytearray(b"\xe9\x00\x00\x00\x00")
                else:
                    require(
                        0x70 <= opcode <= 0x7F,
                        f"{context}: the branch at {item['offset']} has no rel32 form to widen to",
                    )
                    widened = bytearray(bytes((0x0F, 0x80 | (opcode & 0x0F))) + b"\x00" * 4)
                pieces[piece_index] = widened
                widened_set.add(item["offset"])
                repaired.add(item["offset"])
                changed = True
                continue
            require(
                -(1 << (8 * width - 1)) <= new_delta < (1 << (8 * width - 1)),
                f"{context}: the branch at {item['offset']} no longer "
                f"reaches its target in {width} displacement byte(s)",
            )
            encoded = new_delta.to_bytes(width, "little", signed=True)
            if bytes(raw[len(raw) - width :]) != encoded:
                raw[len(raw) - width :] = encoded
                repaired.add(item["offset"])
                changed = True
        if not changed:
            break
    else:
        raise ByteIdentityError(f"{context}: the branch-displacement fixpoint did not converge")

    starts = _starts(pieces)
    image = b"".join(bytes(piece) for piece in pieces) + tail
    image_limit = starts[-1] + len(pieces[-1]) if pieces else 0
    offset_map: dict[int, int] = {}
    for piece_index, owner in enumerate(piece_owner):
        if isinstance(owner, int):
            offset_map[instructions[owner]["offset"]] = starts[piece_index]
        else:
            offset_map[owner[1]] = starts[piece_index]
    offset_map[limit] = image_limit
    reseat: list[list[int]] = []
    for offset in sorted(relocations or {}):
        if offset in paired_reseat:
            region_offset, slice_delta = paired_reseat[offset]
            piece_index = next(
                index
                for index, owner_item in enumerate(piece_owner)
                if owner_item == ("region", region_offset)
            )
            moved_to = starts[piece_index] + slice_delta
            if moved_to != offset:
                reseat.append([offset, moved_to])
            continue
        width = (relocations or {})[offset]["width"]
        relocation_owner: tuple[int, dict[str, Any]] | None = None
        for candidate_index, piece_owner_item in enumerate(piece_owner):
            if not isinstance(piece_owner_item, int):
                continue
            instruction = instructions[piece_owner_item]
            if (
                instruction["offset"] <= offset
                and offset + width <= instruction["offset"] + instruction["length"]
            ):
                relocation_owner = (candidate_index, instruction)
                break
        require(
            relocation_owner is not None,
            f"{context}: the relocation at {offset} does not lie wholly "
            "inside one instruction outside every region",
        )
        assert relocation_owner is not None
        relocation_piece_index, relocation_item = relocation_owner
        require(
            len(pieces[relocation_piece_index]) == relocation_item["length"],
            f"{context}: the relocation at {offset} sits in an instruction the fixpoint resized",
        )
        moved_to = starts[relocation_piece_index] + (offset - relocation_item["offset"])
        if moved_to != offset:
            reseat.append([offset, moved_to])
    require(image != body, f"{context}: the elision moves nothing")
    return image, {
        "kind": SIMULATED_ELISION_KIND,
        "regions": proved,
        "branch_repairs": sorted(offset_map[offset] for offset in repaired),
        "branch_widenings": sorted(offset_map[offset] for offset in widened_set),
        "relocation_reseat": reseat,
        "offset_map": {str(key): value for key, value in sorted(offset_map.items())},
        "instruction_count": len(instructions),
        "code_length": limit,
        "image_code_length": image_limit,
    }


def compose_retail_exact_simulated_elision(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    retail_body: bytes,
    oracle_bodies: dict[str, bytes] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Install the elision image after proving it is retail's own code.

    The pre-image is the SEED's own body (the donor is a provenance witness
    required to reproduce it, exactly as in composed rewriting); each
    declared region is replaced by the retail oracle's bytes only after
    `_srr_simulate` proves both versions compute the same machine state; the
    rebuilt body's crossing branches are repaired -- and, where declared,
    widened to their rel32 forms -- through the derived boundary map; every
    dependent COFF record is reseated by the same map; and the composition
    is refused unless the result equals the pinned retail oracle under the
    reseated relocation mask.  Installation is the same-slot resize.
    """
    require(
        function.get("splice_class") == SIMULATED_ELISION_CLASS,
        "splice class is not retail_exact_simulated_elision",
    )
    require(
        "target_source_refactor" not in function,
        "simulated-elision functions carry no source refactor",
    )
    require(
        bool(isinstance(retail_body, (bytes, bytearray)) and retail_body),
        "retail oracle body is missing",
    )
    spec = function["simulated_elision"]
    require(spec.get("kind") == SIMULATED_ELISION_KIND, "simulated-elision kind differs")
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == function["expected_section_number"]
        and dp["number"] == function["expected_donor_section_number"],
        f"simulated-elision target section seat changed: seed {sp['number']} donor {dp['number']}",
    )
    require(
        len(seed.sections) == function["expected_section_count"]
        and len(donor.sections) == function["expected_donor_section_count"],
        "simulated-elision global section count changed: seed "
        f"{len(seed.sections)} donor {len(donor.sections)}",
    )
    seed_functions = function_multiset(seed)
    require(
        seed_functions == function_multiset(donor)
        and sum(seed_functions.values()) == function["expected_function_count"],
        "simulated-elision witness function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(
        seed_comdats == comdat_primary_identity_multiset(donor)
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "simulated-elision witness COMDAT identity set differs",
    )
    donor_pre_image = function["simulated_elision"].get("pre_image") == "donor"
    if donor_pre_image:
        require(
            sp["raw_size"] == function["expected_seed_length"]
            and dp["raw_size"] == function["expected_pre_image_length"]
            and sp["relocation_count"] == function["expected_relocation_count"]
            and dp["relocation_count"] == function["expected_donor_relocation_count"]
            and sp["line_count"] == function["expected_seed_line_count"]
            and dp["line_count"] == function["expected_donor_line_count"]
            and sp["name"] == dp["name"]
            and sp["characteristics"]
            == dp["characteristics"]
            == function["expected_characteristics"],
            "simulated-elision target header/count pins changed",
        )
    else:
        require(
            sp["raw_size"] == dp["raw_size"] == function["expected_seed_length"]
            and sp["relocation_count"]
            == dp["relocation_count"]
            == function["expected_relocation_count"]
            and sp["line_count"] == function["expected_seed_line_count"]
            and dp["line_count"] == function["expected_donor_line_count"]
            and sp["name"] == dp["name"]
            and sp["characteristics"]
            == dp["characteristics"]
            == function["expected_characteristics"],
            "simulated-elision target header/count pins changed",
        )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "simulated-elision COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        "simulated-elision target closure changed",
    )
    require(
        list(expected_closure)
        in (INSTRUCTION_SCHEDULE_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "simulated-elision closure pin names no installation delegate",
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "simulated-elision metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "simulated-elision seed/witness body differs from its pin",
    )
    if donor_pre_image:
        # The DONOR is the pre-image: an authentic compiler object rendered
        # from its own declared recipe over the seed source, transformed in
        # place of the seed's body.  Its relocation table and record
        # geometry carry through the boundary map below, exactly as the
        # seed's do in the witness mode.
        pre_image_bytes = donor_bytes
        pre_image_object, pre_image_section = donor, dp
    else:
        require(
            donor_body == seed_body, "simulated-elision witness does not reproduce the seed's body"
        )
        pre_image_bytes = seed_bytes
        pre_image_object, pre_image_section = seed, sp
    pre_image_body = bytes(coff_body(pre_image_object, pre_image_section))

    seed_rows = detailed_relocations(pre_image_object, pre_image_section)
    relocation_offsets = frozenset(
        row["offset"] + byte for row in seed_rows for byte in range(row["width"])
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in seed_rows
    }
    internal_targets = frozenset(
        row["target_value"]
        for row in seed_rows
        if row["target_section"] == pre_image_section["number"]
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "simulated-elision in-body relocated target set changed",
        )
    external_entries = relational_form_external_entries(
        pre_image_object, pre_image_section, "simulated-elision external entries"
    )
    require(
        sorted(external_entries) == spec["expected_external_entries"],
        "simulated-elision external entry set differs from its declaration",
    )

    callee_specs = spec.get("callee_oracles") or []
    vtable_specs = spec.get("vtable_oracles") or []
    oracles: dict[str, Any] | None = None
    if callee_specs or vtable_specs:
        # Every oracle body is pinned by length and digest; a vtable
        # oracle's slots must each hold the retail ADDRESS of a declared
        # callee oracle, so a devirtualised call can only reach a body this
        # certificate proves.  The symbol/address binding itself is
        # re-checked against the accepted comparison rows after the link.
        provided: dict[str, bytes] = oracle_bodies or {}
        callees: dict[str, bytes] = {}
        for oracle in callee_specs:
            blob = provided.get(oracle["symbol"])
            require(
                blob is not None,
                f"simulated-elision callee oracle '{oracle['symbol']}' has no fetched body",
            )
            assert blob is not None
            require(
                len(blob) == oracle["length"]
                and sha256_bytes(bytes(blob)) == oracle["body_sha256"],
                f"simulated-elision callee oracle '{oracle['symbol']}' differs from its pin",
            )
            callees[oracle["symbol"]] = bytes(blob)
        callee_addresses = {oracle["symbol"]: int(oracle["address"], 16) for oracle in callee_specs}
        vtables: dict[str, dict[int, str]] = {}
        for oracle in vtable_specs:
            blob = provided.get(oracle["symbol"])
            require(
                blob is not None,
                f"simulated-elision vtable oracle '{oracle['symbol']}' has no fetched body",
            )
            assert blob is not None
            require(
                len(blob) == oracle["length"]
                and sha256_bytes(bytes(blob)) == oracle["body_sha256"],
                f"simulated-elision vtable oracle '{oracle['symbol']}' differs from its pin",
            )
            table: dict[int, str] = {}
            for key, target in oracle["slots"].items():
                slot = int(key)
                require(
                    slot + 4 <= len(blob),
                    "simulated-elision vtable oracle "
                    f"'{oracle['symbol']}' slot {slot} leaves the "
                    "table",
                )
                word = int.from_bytes(blob[slot : slot + 4], "little")
                require(
                    word == callee_addresses.get(target),
                    "simulated-elision vtable slot "
                    f"{slot} of '{oracle['symbol']}' holds "
                    f"{word:#x}, not its declared callee "
                    f"'{target}'",
                )
                table[slot] = target
            vtables[oracle["symbol"]] = table
        oracles = {"callees": callees, "vtables": vtables}
        # The retail image's own displacements are the address authority:
        # every relocation row naming an oracle symbol must resolve to the
        # oracle's declared address, so the simulated bodies are the bytes
        # retail itself reaches from this very function.
        declared_addresses = dict(callee_addresses)
        for oracle in vtable_specs:
            declared_addresses[oracle["symbol"]] = int(oracle["address"], 16)
        for row in function["retail_relocations"]:
            target = row.get("target")
            if target in declared_addresses:
                require(
                    int(row["retail_target"], 16) == declared_addresses[target],
                    "simulated-elision oracle address for "
                    f"'{target}' contradicts the retail relocation "
                    "table",
                )
    image_relocation_targets = {
        row["offset"]: row["target"] for row in function["retail_relocations"]
    }

    image, proof = apply_simulated_elision(
        pre_image_body,
        spec["regions"],
        relocation_offsets,
        "simulated-elision image",
        ElisionInput(
            retail_body=bytes(retail_body),
            image_relocations=image_relocation_targets,
            branch_widenings=spec.get("branch_widenings") or [],
            oracles=oracles,
        ),
        view=RelocationView(
            relocations=relocation_symbols,
            code_length=spec.get("expected_code_length"),
            internal_targets=internal_targets,
        ),
        external_entries=frozenset(external_entries),
    )
    require(
        proof["branch_repairs"] == spec["expected_branch_repairs"]
        and proof["branch_widenings"] == spec["expected_branch_widenings"]
        and proof["relocation_reseat"] == spec["expected_relocation_reseat"]
        and proof["instruction_count"] == spec["expected_instruction_count"]
        and proof["image_code_length"] == spec["expected_image_code_length"],
        "simulated-elision image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "simulated-elision image differs from its pin",
    )
    require(
        len(image) == function["expected_donor_length"],
        "simulated-elision image length differs from its pin",
    )

    pinned_length = function["retail_oracle"]["length"]
    require(
        len(retail_body) == pinned_length == len(image), "simulated-elision retail length changed"
    )
    moved = dict(proof["relocation_reseat"])
    offset_map = {int(key): value for key, value in proof["offset_map"].items()}
    for pair in spec.get("line_row_positions") or []:
        seed_offset, image_offset = pair
        # A COFF line row inside a rewritten region: its statement moved
        # WITHIN the region, so its image position is declared, and the
        # declaration is checked -- it must fall inside the very region
        # that holds the row, and it must land on an instruction boundary
        # of that region's image slice.  Line rows carry no semantics; the
        # obligation is object plausibility, and both halves of it are
        # enforced here.
        region_owner: dict[str, Any] | None = None
        for region in proof["regions"]:
            if region["region_start"] < seed_offset < region["region_end"]:
                region_owner = region
                break
        require(
            region_owner is not None,
            f"simulated-elision line row position at {seed_offset} is not inside any region",
        )
        assert region_owner is not None
        image_span_start = offset_map[region_owner["region_start"]]
        require(
            image_span_start <= image_offset < image_span_start + region_owner["image_length"],
            f"simulated-elision line row position at {seed_offset} leaves its region's image",
        )
        cursor = image_span_start
        boundary = False
        while cursor < image_span_start + region_owner["image_length"]:
            if cursor == image_offset:
                boundary = True
                break
            cursor += supported_ia32_instruction_length(
                image[cursor:], "simulated-elision line row"
            )
        require(
            boundary,
            "simulated-elision line row position at "
            f"{seed_offset} is not an instruction boundary of the "
            "image",
        )
        require(
            seed_offset not in offset_map,
            f"simulated-elision line row position at {seed_offset} collides with the boundary map",
        )
        offset_map[seed_offset] = image_offset
    proof = {**proof, "offset_map": {str(key): value for key, value in offset_map.items()}}
    installed_rows: list[dict[str, Any]] = []
    for row in seed_rows:
        installed = {**row, "offset": moved.get(row["offset"], row["offset"])}
        if row["target_section"] == sp["number"]:
            # An in-body label's VALUE is a code offset; the derived object
            # carries it through the boundary map, so the pin describes the
            # installed image, not the pre-image.
            require(
                row["target_value"] in offset_map,
                "simulated-elision relocation names an in-body target "
                f"at {row['target_value']} that is not an instruction "
                "boundary",
            )
            installed["target_value"] = offset_map[row["target_value"]]
        installed_rows.append(installed)
    semantic_detail = require_retail_relocation_oracle(
        installed_rows,
        bytes(retail_body),
        int(function["retail_oracle"]["address"], 16),
        function["retail_relocations"],
        "simulated-elision retail relocation oracle",
    )
    masked_image = bytearray(image)
    masked_retail = bytearray(retail_body)
    for row in installed_rows:
        start, width = row["offset"], row["width"]
        masked_image[start : start + width] = b"\0" * width
        masked_retail[start : start + width] = b"\0" * width
    differing = sum(left != right for left, right in zip(masked_image, masked_retail, strict=True))
    require(
        differing == 0,
        f"simulated-elision output is not retail-exact: {differing} "
        "byte(s) differ under the relocation mask",
    )

    derived_object, derived_detail = _reencoded_donor_object(
        pre_image_bytes,
        mangled,
        image,
        proof,
        "simulated-elision derived",
        fpo_required=False,
    )
    effective = {
        "mangled": mangled,
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": function["expected_seed_length"],
        "expected_donor_length": function["expected_donor_length"],
        "expected_linked_span": function["expected_linked_span"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_seed_line_count": function["expected_seed_line_count"],
        "expected_donor_line_count": (
            function["expected_donor_line_count"]
            if donor_pre_image
            else function["expected_seed_line_count"]
        ),
        "retail_oracle": function["retail_oracle"],
        "retail_relocations": function["retail_relocations"],
    }
    composed, detail = compose_same_slot_resize(seed_bytes, derived_object, effective)

    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        coff_body(checked, cp) == image, "simulated-elision composed body differs from the image"
    )
    composed_rows = detailed_relocations(checked, cp)
    require(
        len(composed_rows) == len(installed_rows),
        "simulated-elision composed relocation table is not the proved reseat",
    )
    for composed_row, proved_row in zip(composed_rows, installed_rows, strict=True):
        # A compiler-numbered local ($L label, $T constant) is its LOCATION:
        # the number restarts with the witness's extra declarations, the
        # seat and value do not.  Everything else is its name.
        renumbered = (
            composed_row["target_storage"] in (3, 6)
            and proved_row["target_storage"] in (3, 6)
            and composed_row["target"].startswith("$")
            and proved_row["target"].startswith("$")
            and composed_row["target_type"] == proved_row["target_type"]
            and composed_row["target_value"] == proved_row["target_value"]
        )
        require(
            composed_row["offset"] == proved_row["offset"]
            and (composed_row["target"] == proved_row["target"] or renumbered),
            "simulated-elision composed relocation table is not the proved reseat",
        )
    return composed, {
        **detail,
        "splice_class": SIMULATED_ELISION_CLASS,
        "simulated_elision": proof["regions"],
        "branch_repairs": proof["branch_repairs"],
        "branch_widenings": proof["branch_widenings"],
        "relocation_reseat": proof["relocation_reseat"],
        "carried_code_symbols": derived_detail["carried_code_symbols"],
        "procedure_range": derived_detail["procedure_range"],
        "retail_exact": True,
        **semantic_detail,
    }


__all__ = [
    "SIMULATED_ELISION_CLASS",
    "SIMULATED_ELISION_KIND",
    "apply_simulated_elision",
    "compose_retail_exact_simulated_elision",
]
