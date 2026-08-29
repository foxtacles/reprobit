"""Coordinator for compiler-scoped IA-32 stack-frontier proofs."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require

from .stack_frontier_balance import derive_stack_depths
from .stack_frontier_eh import (
    derive_strict_eh_stack_ceiling,
    is_strict_eh_frame,
    require_local_strict_eh_window,
    strict_ebp_address,
)
from .stack_frontier_foundation import (
    MAX_INSTRUCTIONS,
    Affine,
    AffineState,
    address_form,
    ancestors,
    frame_floor,
    predecessors,
    stack_change,
)
from .stack_frontier_fpo import (
    address_affine,
    derive_affine_states,
    transfer_affines,
)


def _adjusted_body(
    body: bytes,
    instructions: list[dict[str, Any]],
    window: list[int],
    adjustments: list[list[int]],
    context: str,
) -> bytes:
    adjusted = bytearray(body)
    for local, at, old, new in adjustments:
        encoding = instructions[window[local]]["encoding"]
        require(isinstance(encoding, dict), f"{context}: adjusted instruction has no encoding")
        size = int(encoding["displacement_size"])
        require(
            int.from_bytes(body[at : at + size], "little", signed=True) == old,
            f"{context}: adjusted displacement changed before its boundary proof",
        )
        adjusted[at : at + size] = new.to_bytes(size, "little", signed=True)
    return bytes(adjusted)


def _fpo_target_addresses(
    body: bytes,
    instructions: list[dict[str, Any]],
    window: list[int],
    target_order: list[int],
    state: AffineState,
    floor: int,
    context: str,
) -> dict[int, Affine | None]:
    addresses: dict[int, Affine | None] = {}
    depth = floor
    for local in target_order:
        item = instructions[window[local]]
        addresses[local] = address_affine(state, address_form(body, item), depth, context)
        state = transfer_affines(body, item, state, depth, context)
        change = stack_change(body, item)
        require(change is not None, f"{context}: target order has an unknown ESP update")
        assert change is not None
        depth += change
    return addresses


def derive_stack_frontier_boundary(
    body: bytes,
    instructions: list[dict[str, Any]],
    successors: list[list[int]],
    relocations: dict[int, dict[str, object]],
    external_entries: frozenset[int],
    start: int,
    end: int,
    target_order: list[int],
    stack_adjustments: list[list[int]],
    discharged: list[dict[str, Any]],
    context: str,
) -> dict[str, object]:
    """Prove every discharged explicit address is above every consumed seat."""
    require(
        1 <= len(instructions) <= MAX_INSTRUCTIONS,
        f"{context}: body exceeds the bounded stack-frontier analysis",
    )
    index_of = {int(item["offset"]): index for index, item in enumerate(instructions)}
    window = [
        index for index, item in enumerate(instructions) if start <= int(item["offset"]) < end
    ]
    require(
        bool(window)
        and int(instructions[window[-1]]["offset"]) + int(instructions[window[-1]]["length"])
        == end,
        f"{context}: stack-frontier window boundaries changed",
    )
    predecessor_rows = predecessors(successors)
    ancestor_set = ancestors(predecessor_rows, set(window))
    unresolved = sorted(
        entry for entry in external_entries if entry in index_of and index_of[entry] in ancestor_set
    )
    require(
        not unresolved,
        f"{context}: an external entry reaches the stack-frontier window at {unresolved[:1]}",
    )
    strict_frame = is_strict_eh_frame(body, instructions)
    floor, first_call = frame_floor(body, instructions, context, strict_frame)
    require(window[0] > first_call, f"{context}: window precedes the fixed-frame floor")
    strict_entry: dict[str, object] | None = None
    if strict_frame:
        strict_entry = require_local_strict_eh_window(
            instructions, predecessor_rows, ancestor_set, window, start, context
        )
        depths, call_balance = derive_strict_eh_stack_ceiling(
            body,
            instructions,
            successors,
            ancestor_set,
            floor,
            first_call,
            relocations,
            context,
        )
        window_ceiling = depths[window[0]]
        require(
            window_ceiling is not None and window_ceiling <= floor,
            f"{context}: the strict-frame window can rise above its fixed-frame floor",
        )
        assert window_ceiling is not None
        states: list[AffineState | None] = [None] * len(instructions)
        window_depth = window_ceiling
    else:
        depths, call_balance = derive_stack_depths(
            body,
            instructions,
            successors,
            ancestor_set,
            floor,
            first_call,
            relocations,
            context,
        )
        measured_depth = depths[window[0]]
        require(measured_depth == floor, f"{context}: window is not at the fixed-frame floor")
        assert measured_depth is not None
        window_depth = measured_depth
        states = derive_affine_states(
            body,
            instructions,
            successors,
            ancestor_set,
            depths,
            context,
        )
    adjusted = _adjusted_body(body, instructions, window, stack_adjustments, context)
    if strict_frame:
        target_addresses = {
            local: strict_ebp_address(adjusted, instructions, window[local])
            for local in target_order
        }
    else:
        target_state = states[window[0]]
        require(target_state is not None, f"{context}: target order has no boundary state")
        assert target_state is not None
        target_addresses = _fpo_target_addresses(
            adjusted, instructions, window, target_order, target_state, floor, context
        )
    positions = {source: target for target, source in enumerate(target_order)}
    memory_receipt: list[dict[str, object]] = []
    private_slots: dict[tuple[int, int], dict[str, object]] = {}
    push_seats: dict[int, dict[str, object]] = {}
    for pair in discharged:
        local_memory = int(pair["memory_instruction"])
        local_push = int(pair["push_instruction"])
        memory_index = window[local_memory]
        memory = instructions[memory_index]["memory"]
        require(isinstance(memory, dict), f"{context}: discharged memory operand disappeared")
        if strict_frame:
            address = strict_ebp_address(body, instructions, memory_index)
        else:
            state, depth = states[memory_index], depths[memory_index]
            require(state is not None and depth is not None, f"{context}: missing affine state")
            assert state is not None and depth is not None
            address = address_affine(
                state, address_form(body, instructions[memory_index]), depth, context
            )
        target_address = target_addresses[local_memory]
        require(
            address is not None and bool(address),
            f"{context}: unresolved base {memory['base']} at "
            f"{instructions[memory_index]['offset']}",
        )
        assert address is not None
        require(
            target_address is not None and set(target_address) == set(address),
            f"{context}: target order changes a discharged explicit address",
        )
        spans = sorted([value - floor, value - floor + int(memory["width"])] for value in address)
        require(
            all(left >= 0 and left < right for left, right in spans),
            f"{context}: discharged address is not above the fixed stack frontier",
        )
        definitions = sorted({definition for values in address.values() for definition in values})
        if not strict_frame:
            for definition in definitions:
                defining_index = index_of.get(definition)
                if defining_index is None:
                    continue
                defining = instructions[defining_index]
                defining_state, defining_depth = states[defining_index], depths[defining_index]
                if not (
                    isinstance(defining.get("memory"), dict)
                    and defining["memory"]["read"]
                    and int(defining["memory"]["width"]) == 4
                    and defining_state is not None
                    and defining_depth is not None
                ):
                    continue
                locations = address_affine(
                    defining_state,
                    address_form(body, defining),
                    defining_depth,
                    context,
                )
                if locations is None or len(locations) != 1:
                    continue
                slot = next(iter(locations))
                values = defining_state.slots.get(slot)
                if values is not None:
                    private_slots[(slot, definition)] = {
                        "slot_from_entry_esp": slot,
                        "load_offset": definition,
                        "value_definition_offsets": sorted(
                            {origin for origins in values.values() for origin in origins}
                        ),
                        "address_materialized_or_escaped": False,
                    }
        span_basis = "frame_floor" if strict_frame else "window_esp"
        memory_receipt.append(
            {
                "instruction": local_memory,
                "offset": int(instructions[memory_index]["offset"]),
                "base": memory["base"],
                "base_definition_offsets": definitions,
                f"source_spans_from_{span_basis}": spans,
                f"target_spans_from_{span_basis}": spans,
            }
        )
        source_rank = sum(
            int(instructions[window[item]]["opcode"]) in range(0x50, 0x58)
            for item in range(local_push + 1)
        )
        target_rank = sum(
            int(instructions[window[item]]["opcode"]) in range(0x50, 0x58)
            for item in target_order[: positions[local_push] + 1]
        )
        source_span = [-4 * source_rank, -4 * (source_rank - 1)]
        target_span = [-4 * target_rank, -4 * (target_rank - 1)]
        require(
            all(right <= 0 for _left, right in (source_span, target_span)),
            f"{context}: PUSH seat is not below the frontier",
        )
        push_seats[local_push] = {
            "instruction": local_push,
            "offset": int(instructions[window[local_push]]["offset"]),
            "source_span_from_window_esp": source_span,
            "target_span_from_window_esp": target_span,
        }
    family = "strict-eh-ebp-frame-v1" if strict_frame else "fpo-stack-affine-v1"
    if not strict_frame:
        first_change = stack_change(body, instructions[0])
        require(
            first_change is not None and first_change < 0,
            f"{context}: FPO proof lacks an allocating prologue",
        )
    receipt: dict[str, object] = {
        "kind": family,
        "frame_floor_from_entry_esp": floor,
        "first_call_offset": int(instructions[first_call]["offset"]),
        "call_balance": call_balance,
        "private_slots": [private_slots[key] for key in sorted(private_slots)],
        "memory_addresses": memory_receipt,
        "push_seats": [push_seats[key] for key in sorted(push_seats)],
    }
    if strict_entry is not None:
        receipt["window_entry_esp_ceiling_from_entry"] = window_depth
        receipt["strict_frame_entry"] = strict_entry
    else:
        receipt["window_entry_esp_from_entry"] = window_depth
    return receipt
