"""Strict MSVC 4.20 frame and exception-state schedule proofs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.registers import IA32_GENERAL_REGISTER_NAMES
from reprobit.classic.scheduling import (
    ia32_schedule_body_walk,
    ia32_schedule_dependence_edges,
    require_topological_instruction_order,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .compiler_state_foundation import (
    CompilerStateCodePair,
    _EhFrame,
    _FreshAllocationEvidence,
    _ImageState,
    _Instruction,
    _instructions,
    _RelocationRecord,
    _ScheduleDeclaration,
)

_SYNCHRONOUS_EXCEPTION_MODEL = "msvc-4.20-synchronous-gx"


def _register_source_value(
    body: bytes,
    instructions: Sequence[_Instruction],
    position: int,
    register: str,
) -> int | None:
    for previous in range(position - 1, -1, -1):
        item = instructions[previous]
        if register not in item["writes"]:
            if item["flow"] != "fall":
                return None
            continue
        start = int(item["offset"])
        end = start + int(item["length"])
        encoded = body[start:end]
        opcode = int(item["opcode"])
        expected = IA32_GENERAL_REGISTER_NAMES.index(register)
        if opcode == 0xB8 + expected and len(encoded) == 5:
            return int.from_bytes(encoded[1:], "little")
        return None
    return None


def _state_store_value(
    body: bytes,
    instructions: Sequence[_Instruction],
    position: int,
    displacement: int,
) -> int | None:
    item = instructions[position]
    memory = item.get("memory")
    if not isinstance(memory, dict) or not (
        memory.get("base") == "ebp"
        and memory.get("index") is None
        and memory.get("displacement") == displacement
        and memory.get("write") is True
        and memory.get("read") is False
    ):
        return None
    start = int(item["offset"])
    end = start + int(item["length"])
    encoded = body[start:end]
    opcode = int(item["opcode"])
    if opcode == 0xC6 and memory.get("width") == 1:
        return encoded[-1]
    if opcode == 0xC7 and memory.get("width") == 4:
        return int.from_bytes(encoded[-4:], "little")
    if opcode not in {0x88, 0x89}:
        return None
    sources = set(item["reads"]) - {"ebp"}
    if len(sources) != 1:
        return None
    return _register_source_value(body, instructions, position, sources.pop())


def _relocations_by_offset(
    offsets: Sequence[int], statements: Sequence[Mapping[str, object]]
) -> dict[int, Mapping[str, object]]:
    return dict(zip(offsets, statements, strict=True))


def _exact_external_data_relocation(statement: Mapping[str, object]) -> bool:
    target = statement.get("target")
    return (
        statement.get("type") == 0x06
        and statement.get("addend") == "00000000"
        and isinstance(target, dict)
        and target.get("kind") == "undefined"
        and target.get("value") == 0
        and target.get("type") == 0
        and target.get("storage") == 2
        and target.get("name") == "__except_list"
    )


def _internal_handler_entry(
    statement: Mapping[str, object], pair: CompilerStateCodePair
) -> int | None:
    target = statement.get("target")
    if not (
        statement.get("type") == 0x06
        and statement.get("addend") == "00000000"
        and isinstance(target, dict)
        and target.get("kind") == "defined"
    ):
        return None
    symbol = target.get("symbol")
    section = target.get("section")
    topology = section.get("topology") if isinstance(section, dict) else None
    if not (
        isinstance(symbol, dict)
        and symbol.get("type") == 0
        and symbol.get("storage") == 6
        and isinstance(symbol.get("value"), int)
        and isinstance(section, dict)
        and section.get("kind") == "code"
        and isinstance(topology, dict)
        and Digest.from_bytes(canonical_json(topology)).value == pair.topology_digest
    ):
        return None
    return int(symbol["value"])


def _derive_msvc_eh_state_slot(
    body: bytes,
    pair: CompilerStateCodePair,
    relocation_offsets: Sequence[int],
    relocation_statements: Sequence[Mapping[str, object]],
    records: Mapping[int, _RelocationRecord],
) -> tuple[list[_Instruction], _EhFrame]:
    """Bind the state word from one strict MSVC registration prologue."""

    instructions = _instructions(body, records, "MSVC 4.20 compiler-state EH frame")
    expected = (
        "64a100000000",  # mov eax, fs:[__except_list]
        "55",  # push ebp
        "8bec",  # mov ebp, esp
        "6aff",  # push -1: the initial state word
        "6800000000",  # push relocated handler entry
        "50",  # push the previous registration
        "64892500000000",  # mov fs:[__except_list], esp
    )
    if len(instructions) < len(expected):
        raise ClassicSemanticError("MSVC 4.20 compiler-state code has no complete MSVC EH prologue")
    measured = tuple(
        body[int(item["offset"]) : int(item["offset"]) + int(item["length"])].hex()
        for item in instructions[: len(expected)]
    )
    by_offset = _relocations_by_offset(relocation_offsets, relocation_statements)
    fs_read = by_offset.get(2)
    handler = by_offset.get(12)
    fs_write = by_offset.get(20)
    handler_entry = _internal_handler_entry(handler or {}, pair)
    if (
        measured != expected
        or int(instructions[0]["offset"]) != 0
        or fs_read is None
        or fs_write is None
        or not _exact_external_data_relocation(fs_read)
        or {key: value for key, value in fs_read.items() if key != "offset"}
        != {key: value for key, value in fs_write.items() if key != "offset"}
        or handler_entry is None
        or handler_entry not in pair.external_entries
        or pair.eh_control_digest is None
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state code lacks one closed MSVC 4.20 EH registration frame"
        )
    # The pushed -1 is one 32-bit machine word below the EBP value established
    # immediately before it. The displacement is therefore derived, not chosen
    # from the later stores whose movement is under proof.
    word_width = 4
    return instructions, {
        "base": "ebp",
        "displacement": -word_width,
        "width": word_width,
        "initial_value": -1,
        "handler_entry": handler_entry,
        "exception_list_target_digest": Digest.from_bytes(canonical_json(fs_read["target"])).value,
        "eh_control_digest": pair.eh_control_digest,
    }


def _previous_state_value(
    body: bytes,
    instructions: Sequence[_Instruction],
    before: int,
    displacement: int,
    initial_value: int,
) -> int:
    for position in range(before - 1, 2, -1):
        item = instructions[position]
        memory = item.get("memory")
        if not (
            isinstance(memory, dict)
            and memory.get("base") == "ebp"
            and memory.get("index") is None
            and memory.get("displacement") == displacement
            and memory.get("write") is True
        ):
            continue
        value = _state_store_value(body, instructions, position, displacement)
        if value is None:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code has an unrecognized EH-state write"
            )
        return value
    return initial_value


def _require_fresh_allocation_base(
    body: bytes,
    instructions: Sequence[_Instruction],
    before: int,
    base: str,
    relocation_offsets: Sequence[int],
    relocation_statements: Sequence[Mapping[str, object]],
    control_targets: frozenset[int],
) -> _FreshAllocationEvidence:
    definition = next(
        (
            position
            for position in range(before - 1, -1, -1)
            if base in instructions[position]["writes"]
        ),
        None,
    )
    if definition is None:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window has no definition for its memory base"
        )
    item = instructions[definition]
    if not (
        item["flow"] == "fall"
        and item.get("memory") is None
        and item["reads"] == frozenset({"eax"})
        and item["writes"] == frozenset({base})
        and int(item["opcode"]) in {0x89, 0x8B}
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window memory is not based on a fresh allocation"
        )
    call = next(
        (
            position
            for position in range(definition - 1, -1, -1)
            if "eax" in instructions[position]["writes"]
        ),
        None,
    )
    if call is None or instructions[call]["flow"] != "call":
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window allocation base lacks one returning call"
        )
    if any(
        instructions[position]["flow"] != "fall" for position in range(call + 1, definition + 1)
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window allocation result crosses control flow"
        )
    call_start = int(instructions[call]["offset"])
    call_end = call_start + int(instructions[call]["length"])
    by_offset = _relocations_by_offset(relocation_offsets, relocation_statements)
    call_rows = [
        statement for offset, statement in by_offset.items() if call_start <= offset < call_end
    ]
    target = call_rows[0].get("target") if len(call_rows) == 1 else None
    allocation_target = "??2@YAPAXI@Z"
    expected_target = {
        "kind": "undefined",
        "name": allocation_target,
        "value": 0,
        "type": 0x20,
        "storage": 2,
    }
    if not (
        len(call_rows) == 1
        and call_rows[0].get("type") == 0x14
        and call_rows[0].get("addend") == "00000000"
        and target == expected_target
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window is not based on the locked MSVC scalar operator new"
        )
    call_end = call_start + int(instructions[call]["length"])
    window_start = int(instructions[before]["offset"])
    if any(call_end <= target_offset <= window_start for target_offset in control_targets):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window allocation provenance can be bypassed"
        )
    return {
        "register": base,
        "definition_offset": int(item["offset"]),
        "allocation_call_offset": call_start,
        "allocation_target": allocation_target,
        "allocation_relocation_digest": Digest.from_bytes(canonical_json(call_rows[0])).value,
    }


def _ebp_relative_stack_depth(
    body: bytes,
    instructions: Sequence[_Instruction],
    before: int,
) -> int:
    """Derive ESP-EBP from the strict frame establishment to one window."""

    depth = 0
    for position in range(3, before):
        item = instructions[position]
        start = int(item["offset"])
        encoded = body[start : start + int(item["length"])]
        opcode = int(item["opcode"])
        if opcode in {*range(0x50, 0x58), 0x68, 0x6A}:
            depth -= 4
            continue
        if encoded.startswith(b"\x83\xec") and len(encoded) == 3:
            depth -= encoded[-1]
            continue
        if encoded.startswith(b"\x81\xec") and len(encoded) == 6:
            depth -= int.from_bytes(encoded[-4:], "little")
            continue
        if "esp" in item["writes"]:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state frame schedule has an unknown pre-window ESP update"
            )
    return depth


def _apply_frame_push_schedule(
    state: _ImageState,
    pair: CompilerStateCodePair,
    declaration: _ScheduleDeclaration,
    records: Mapping[int, _RelocationRecord],
    relocation_statements: Sequence[Mapping[str, object]],
) -> tuple[_ImageState, dict[str, object]]:
    instructions, frame = _derive_msvc_eh_state_slot(
        state.body,
        pair,
        state.relocation_offsets,
        relocation_statements,
        records,
    )
    start = int(declaration["start"])
    end = int(declaration["end"])
    inside_positions = [
        position for position, item in enumerate(instructions) if start <= int(item["offset"]) < end
    ]
    inside = [instructions[position] for position in inside_positions]
    pushes = [
        local for local, item in enumerate(inside) if int(item["opcode"]) in range(0x50, 0x58)
    ]
    canonical_push = (
        len(pushes) == 1
        and int(inside[pushes[0]]["length"]) == 1
        and state.body[int(inside[pushes[0]]["offset"])] in range(0x50, 0x58)
    )
    if (
        len(pushes) != 1
        or not canonical_push
        or not inside
        or int(inside[0]["offset"]) != start
        or int(inside[-1]["offset"]) + int(inside[-1]["length"]) != end
        or any(item["flow"] != "fall" for item in inside)
        or any(
            "ebp" in instructions[position]["writes"]
            for position in range(3, inside_positions[-1] + 1)
        )
        or any(local not in pushes and "esp" in item["writes"] for local, item in enumerate(inside))
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule is not one closed single-push window"
        )
    try:
        _spans, branch_targets = ia32_schedule_body_walk(
            state.body,
            dict(records),
            "MSVC 4.20 compiler-state frame schedule",
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    entries = frozenset(branch_targets) | frozenset(pair.external_entries)
    if any(start <= entry < end for entry in entries):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule has a branch or funclet entry at its window"
        )
    depth = _ebp_relative_stack_depth(state.body, instructions, inside_positions[0])
    push_span = set(range(depth - 4, depth))
    memory_positions: set[int] = set()
    memory_receipt: list[dict[str, object]] = []
    for local, item in enumerate(inside):
        if local in pushes:
            continue
        memory = item.get("memory")
        if not isinstance(memory, dict):
            continue
        width = memory.get("width")
        if not (
            memory.get("base") == "ebp"
            and memory.get("index") is None
            and memory.get("absolute") is False
            and memory.get("unknown") is False
            and isinstance(width, int)
            and width > 0
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state frame schedule has unprovable memory aliasing"
            )
        span = set(
            range(
                int(memory["displacement"]),
                int(memory["displacement"]) + width,
            )
        )
        if span & push_span:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state frame schedule push aliases an EBP-relative operand"
            )
        memory_positions.add(local)
        memory_receipt.append(
            {
                "instruction": local,
                "displacement": int(memory["displacement"]),
                "width": width,
                "read": memory["read"],
                "write": memory["write"],
            }
        )
    _facts, edges = ia32_schedule_dependence_edges(
        cast(list[dict[Any, Any]], inside),
        "MSVC 4.20 compiler-state frame schedule",
        state.body,
    )
    if declaration.get("expected_dependence_edges") != edges:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule dependence graph changed after derivation"
        )
    retained: list[list[object]] = []
    discharged = 0
    push = pushes[0]
    for left, right, reasons in edges:
        pair_is_disjoint = (left == push and right in memory_positions) or (
            right == push and left in memory_positions
        )
        kept = [reason for reason in reasons if not (pair_is_disjoint and reason == "memory")]
        discharged += len(reasons) - len(kept)
        if kept:
            retained.append([left, right, kept])
    if not discharged:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule discharges no implicit push-memory edge"
        )
    order = list(declaration["target_order"])
    try:
        require_topological_instruction_order(
            len(inside), retained, order, "MSVC 4.20 compiler-state frame schedule"
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    pieces = [
        state.body[int(item["offset"]) : int(item["offset"]) + int(item["length"])]
        for item in inside
    ]
    if [len(piece) for piece in pieces] != declaration.get("source_instruction_lengths"):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule instruction partition changed"
        )
    image = bytearray(state.body)
    image[start:end] = b"".join(pieces[index] for index in order)
    moved = {
        int(source): int(target) for source, target in declaration.get("relocation_reseat", [])
    }
    image_offsets = [moved.get(offset, offset) for offset in state.relocation_offsets]
    if len(set(image_offsets)) != len(image_offsets):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state frame schedule collides relocation seats"
        )
    return _ImageState(bytes(image), image_offsets), {
        "kind": "ebp-frame-push-schedule-v1",
        "start": start,
        "end": end,
        "target_order": order,
        "eh_frame": frame,
        "esp_relative_to_ebp": depth,
        "push_span_relative_to_ebp": [depth - 4, depth],
        "disjoint_ebp_memory": memory_receipt,
        "discharged_push_memory_edge_count": discharged,
        "retained_dependence_edge_digest": Digest.from_bytes(canonical_json(retained)).value,
    }


def _apply_synchronous_eh_schedule(
    state: _ImageState,
    pair: CompilerStateCodePair,
    declaration: _ScheduleDeclaration,
    records: Mapping[int, _RelocationRecord],
    relocation_statements: Sequence[Mapping[str, object]],
    exception_mode: Mapping[str, object] | None,
) -> tuple[_ImageState, dict[str, object]]:
    if pair.eh_control_digest is None:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH scheduling lacks paired EH-control evidence"
        )
    if exception_mode is None or exception_mode.get("model") != _SYNCHRONOUS_EXCEPTION_MODEL:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH scheduling lacks exact synchronous /GX evidence"
        )
    instructions, frame = _derive_msvc_eh_state_slot(
        state.body,
        pair,
        state.relocation_offsets,
        relocation_statements,
        records,
    )
    start = int(declaration["start"])
    end = int(declaration["end"])
    inside_positions = [
        position for position, item in enumerate(instructions) if start <= int(item["offset"]) < end
    ]
    inside = [instructions[position] for position in inside_positions]
    if (
        not inside
        or int(inside[0]["offset"]) != start
        or int(inside[-1]["offset"]) + int(inside[-1]["length"]) != end
        or any(
            item["flow"] != "fall" or bool({"esp", "ebp"} & set(item["writes"])) for item in inside
        )
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule is not one stack-stable "
            "call-free fallthrough window"
        )
    if any("ebp" in instructions[position]["writes"] for position in range(3, inside_positions[0])):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule does not retain the registered EBP frame"
        )
    try:
        _spans, targets = ia32_schedule_body_walk(
            state.body,
            dict(records),
            "MSVC 4.20 compiler-state EH schedule",
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    control_targets = frozenset(targets) | frozenset(pair.external_entries)
    if any(start <= target < end for target in control_targets):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule has a control-flow or funclet entry"
        )
    order = list(declaration["target_order"])
    lengths = [int(item["length"]) for item in inside]
    if (
        declaration.get("source_instruction_lengths") != lengths
        or sorted(order) != list(range(len(inside)))
        or order == list(range(len(inside)))
    ):
        raise ClassicSemanticError("MSVC 4.20 compiler-state EH schedule declaration is malformed")
    _facts, edges = ia32_schedule_dependence_edges(
        cast(list[dict[Any, Any]], inside),
        "MSVC 4.20 compiler-state EH schedule",
        state.body,
    )
    if declaration.get("expected_dependence_edges") != edges:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule dependence graph changed after derivation"
        )
    displacement = int(frame["displacement"])
    state_positions = [
        local
        for local, full in enumerate(inside_positions)
        if _state_store_value(state.body, instructions, full, displacement) is not None
    ]
    if len(state_positions) < 2:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule has fewer than two state stores"
        )
    fresh_bases = {
        str(memory["base"])
        for item in inside
        if isinstance((memory := item.get("memory")), dict)
        and memory.get("base") not in {None, "ebp"}
    }
    if len(fresh_bases) != 1:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule has no unique program-memory base"
        )
    fresh = _require_fresh_allocation_base(
        state.body,
        instructions,
        inside_positions[0],
        next(iter(fresh_bases)),
        state.relocation_offsets,
        relocation_statements,
        control_targets,
    )
    if any(fresh["register"] in item["writes"] for item in inside):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH window redefines its fresh allocation base"
        )
    state_span = set(range(displacement, displacement + int(frame["width"])))
    for local, item in enumerate(inside):
        memory = item.get("memory")
        if int(item["opcode"]) == 0x8D:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state EH schedule exposes an untracked address with LEA"
            )
        if not isinstance(memory, dict):
            continue
        width = memory.get("width")
        if (
            memory.get("unknown") is True
            or memory.get("absolute") is True
            or not isinstance(width, int)
            or width <= 0
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state EH schedule has unprovable memory aliasing"
            )
        if local in state_positions:
            if not (
                memory.get("base") == "ebp"
                and memory.get("index") is None
                and memory.get("displacement") == displacement
                and memory.get("write") is True
                and memory.get("read") is False
            ):
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state EH state seat has a read or inexact write"
                )
            continue
        if memory.get("base") == "ebp" and memory.get("index") is None:
            program_span = set(
                range(
                    int(memory["displacement"]),
                    int(memory["displacement"]) + width,
                )
            )
            if program_span & state_span:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state EH schedule aliases its state frame slot"
                )
            continue
        if not (memory.get("base") == fresh["register"] and memory.get("index") is None):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state EH schedule has memory without "
                "fresh-allocation provenance"
            )
    removed_edges: list[list[object]] = []
    retained_edges: list[list[object]] = []
    for left, right, reasons in edges:
        one_state = (left in state_positions) != (right in state_positions)
        if reasons == ["memory"] and one_state:
            removed_edges.append([left, right, reasons])
        else:
            retained_edges.append([left, right, reasons])
    if not removed_edges:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule removes no private-state memory edge"
        )
    try:
        require_topological_instruction_order(
            len(inside), retained_edges, order, "MSVC 4.20 compiler-state EH schedule"
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    source_values = [
        _state_store_value(state.body, instructions, inside_positions[local], displacement)
        for local in state_positions
    ]
    if any(value is None for value in source_values):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule has an unknown state-store value"
        )
    entry_value = _previous_state_value(
        state.body,
        instructions,
        inside_positions[0],
        displacement,
        int(frame["initial_value"]),
    )
    pieces = [
        state.body[int(item["offset"]) : int(item["offset"]) + int(item["length"])]
        for item in inside
    ]
    image = bytearray(state.body)
    image[start:end] = b"".join(pieces[index] for index in order)
    moved = {
        int(source): int(target) for source, target in declaration.get("relocation_reseat", [])
    }
    image_offsets = [moved.get(offset, offset) for offset in state.relocation_offsets]
    image_records = {moved.get(offset, offset): record for offset, record in records.items()}
    if len(image_records) != len(records):
        raise ClassicSemanticError("MSVC 4.20 compiler-state EH schedule collides relocations")
    image_bytes = bytes(image)
    target_instructions = _instructions(
        image_bytes, image_records, "MSVC 4.20 compiler-state scheduled code"
    )
    target_values = [
        value
        for position, item in enumerate(target_instructions)
        if start <= int(item["offset"]) < end
        and (value := _state_store_value(image_bytes, target_instructions, position, displacement))
        is not None
    ]
    if source_values != target_values:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state EH schedule changes its ordered state-store sequence"
        )
    proof = {
        "kind": "msvc-synchronous-eh-state-schedule-v1",
        "exception_mode": dict(exception_mode),
        "eh_control_digest": pair.eh_control_digest,
        "start": start,
        "end": end,
        "target_order": order,
        "state_slot": frame,
        "fresh_allocation": fresh,
        "state_store_positions": state_positions,
        "state_values": source_values,
        "entry_state": entry_value,
        "exit_state": source_values[-1],
        "removed_synchronous_memory_edges": removed_edges,
        "retained_dependence_edge_digest": Digest.from_bytes(canonical_json(retained_edges)).value,
        "external_entries": list(pair.external_entries),
        "relocation_reseat": [list(item) for item in declaration.get("relocation_reseat", [])],
    }
    return _ImageState(image_bytes, image_offsets), proof
