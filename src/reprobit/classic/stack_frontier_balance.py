"""Entry-to-window stack-depth proof for the FPO stack frontier."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require

from .stack_frontier_foundation import (
    address_form,
    msvc420_direct_cdecl_call,
    predecessors,
    stack_change,
)

_MSVC420_MEMBER_CLASSES = frozenset("ABEFIJMNQRUV")
_MSVC420_MEMBER_CV = frozenset("ABCD")


def _direct_stack_argument_shape(symbol: object) -> dict[str, object] | None:
    """Decode only the reviewed zero/one-word VC 4.20 thiscall forms."""
    if not isinstance(symbol, str) or not symbol.startswith("?") or not symbol.endswith("Z"):
        return None
    readings: list[dict[str, object]] = []
    for index in range(len(symbol) - 1):
        if symbol[index : index + 2] != "@@":
            continue
        cursor = index + 2
        if (
            cursor + 4 > len(symbol)
            or symbol[cursor] not in _MSVC420_MEMBER_CLASSES
            or symbol[cursor + 1] not in _MSVC420_MEMBER_CV
            or symbol[cursor + 2] != "E"
            or symbol[cursor + 3] not in "JX"
        ):
            continue
        arguments = symbol[cursor + 4 :]
        if arguments == "XZ":
            argument = "none"
            stack_argument_bytes = 0
        elif arguments == "H@Z":
            argument = "signed-int32"
            stack_argument_bytes = 4
        elif arguments.startswith("ABV") and arguments.endswith("@@@Z"):
            components = arguments[3:-4].split("@")
            if not components or any(
                not component
                or any(not (character.isalnum() or character in "_$") for character in component)
                for component in components
            ):
                continue
            argument = "const-named-class-reference"
            stack_argument_bytes = 4
        else:
            continue
        readings.append(
            {
                "calling_convention": "thiscall",
                "scope_terminator_offset": index,
                "return_encoding": symbol[cursor + 3],
                "argument_encoding": arguments[:-2],
                "argument_kind": argument,
                "stack_argument_bytes": stack_argument_bytes,
            }
        )
    return readings[0] if len(readings) == 1 else None


def _is_one_unprefixed_register_push(body: bytes, item: dict[str, Any]) -> bool:
    offset = int(item["offset"])
    return bool(
        int(item["length"]) == 1
        and int(item["opcode"]) in range(0x50, 0x58)
        and body[offset] == int(item["opcode"])
    )


def _direct_call_shape(
    body: bytes,
    instructions: list[dict[str, Any]],
    predecessor_rows: list[list[int]],
    relocations: dict[int, dict[str, object]],
    call: int,
) -> dict[str, object] | None:
    item = instructions[call]
    start = int(item["offset"])
    if int(item["opcode"]) != 0xE8 or int(item["length"]) != 5:
        return None
    row = relocations.get(start + 1)
    if row is None or row.get("width") != 4:
        return None
    if sorted(offset for offset in relocations if start <= offset < start + 5) != [start + 1]:
        return None
    argument = _direct_stack_argument_shape(row.get("target"))
    if argument is None:
        return None
    argument_bytes = argument["stack_argument_bytes"]
    if not isinstance(argument_bytes, int) or isinstance(argument_bytes, bool):
        return None
    if argument_bytes == 0:
        return {
            "theorem": "msvc420-decorated-fixed-thiscall-cleanup-v1",
            "target": row.get("target"),
            "argument_push_offsets": [],
            "stack_argument_bytes": 0,
            "stack_argument_shape": argument,
        }
    current = call
    push_offset: int | None = None
    for _ in range(64):
        incoming = predecessor_rows[current]
        if len(incoming) != 1:
            return None
        previous = incoming[0]
        item = instructions[previous]
        if item["flow"] != "fall":
            return None
        change = stack_change(body, item)
        if change == -4 and _is_one_unprefixed_register_push(body, item):
            push_offset = int(item["offset"])
            break
        if change != 0:
            return None
        current = previous
    if push_offset is None:
        return None
    return {
        "theorem": "msvc420-decorated-one-word-thiscall-cleanup-v1",
        "target": row.get("target"),
        "argument_push_offsets": [push_offset],
        "stack_argument_bytes": 4,
        "stack_argument_shape": argument,
    }


def _one_word_vcall_shape(
    body: bytes,
    instructions: list[dict[str, Any]],
    predecessor_rows: list[list[int]],
    relocations: dict[int, dict[str, object]],
    call: int,
) -> dict[str, object] | None:
    if call < 4:
        return None
    item = instructions[call]
    memory = item.get("memory")
    receiver_index, vtable_index, argument_index, push_index = range(call - 4, call)
    if not (
        item["flow"] == "call"
        and int(item["opcode"]) == 0xFF
        and isinstance(memory, dict)
        and memory["read"]
        and not memory["write"]
        and memory["base"] not in (None, "esp")
        and memory["index"] is None
        and int(memory["width"]) == 4
        and predecessor_rows[call] == [push_index]
        and predecessor_rows[push_index] == [argument_index]
        and predecessor_rows[argument_index] == [vtable_index]
        and predecessor_rows[vtable_index] == [receiver_index]
        and all(
            instructions[index]["flow"] == "fall"
            for index in (receiver_index, vtable_index, argument_index, push_index)
        )
    ):
        return None
    push = instructions[push_index]
    push_offset = int(push["offset"])
    if not _is_one_unprefixed_register_push(body, push):
        return None
    push_opcode = int(push["opcode"])
    if push_opcode != 0x50:
        return None
    pushed_register = "eax"
    vtable_register = memory["base"]
    displacement = memory["displacement"]
    if (
        not isinstance(vtable_register, str)
        or vtable_register == "ecx"
        or pushed_register in ("ecx", vtable_register)
        or not isinstance(displacement, int)
        or isinstance(displacement, bool)
        or displacement < 0
        or displacement % 4
        or address_form(body, item) != (vtable_register, None, 1, displacement)
    ):
        return None
    receiver, vtable = instructions[receiver_index], instructions[vtable_index]
    argument = instructions[argument_index]
    vtable_memory = vtable.get("memory")
    if not (
        set(receiver["writes"]) - {"esp"} == {"ecx"}
        and set(vtable["writes"]) - {"esp"} == {vtable_register}
        and int(vtable["opcode"]) == 0x8B
        and isinstance(vtable_memory, dict)
        and vtable_memory["read"]
        and not vtable_memory["write"]
        and int(vtable_memory["width"]) == 4
        and int(argument["opcode"]) == 0x8D
        and address_form(body, argument) is not None
        and int(argument["offset"]) + int(argument["length"]) == push_offset
        and set(argument["writes"]) - {"esp"} == {pushed_register}
        and stack_change(body, argument) == 0
        and all(
            "ecx" not in instructions[index]["writes"]
            for index in (vtable_index, argument_index, push_index)
        )
        and all(
            vtable_register not in instructions[index]["writes"]
            for index in (argument_index, push_index)
        )
    ):
        return None

    chain_start = int(receiver["offset"])
    chain_end = int(item["offset"]) + int(item["length"])
    for relocation_offset, row in relocations.items():
        width = row.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            return None
        if relocation_offset < chain_end and relocation_offset + width > chain_start:
            return None

    def normalized(candidate: dict[str, Any]) -> tuple[object, ...] | None:
        return address_form(body, candidate)

    receiver_address = (
        normalized(receiver) if int(receiver["opcode"]) == 0x8D else None
    )
    if receiver_address is None and receiver.get("memory") is None:
        sources = set(receiver["reads"])
        if int(receiver["opcode"]) in (0x89, 0x8B) and len(sources) == 1:
            receiver_address = (next(iter(sources)), None, 1, 0)
    if receiver_address is None or receiver_address != normalized(vtable):
        return None
    return {
        "theorem": "msvc420-strong-eax-one-word-vcall-callee-clean-v1",
        "receiver_register": "ecx",
        "receiver_definition_offset": int(receiver["offset"]),
        "vtable_register": vtable_register,
        "vtable_load_offset": int(vtable["offset"]),
        "vtable_slot": displacement,
        "argument_push_offsets": [push_offset],
        "argument_definition_offset": int(argument["offset"]),
        "argument_register": pushed_register,
    }


def derive_stack_depths(
    body: bytes,
    instructions: list[dict[str, Any]],
    successors: list[list[int]],
    ancestor_set: set[int],
    floor: int,
    first_call: int,
    relocations: dict[int, dict[str, object]],
    context: str,
) -> tuple[list[int | None], list[dict[str, object]]]:
    """Derive exact stack depths on the entry-to-window ancestor slice."""
    require(0 in ancestor_set, f"{context}: the window is unreachable from function entry")
    predecessor_rows = predecessors(successors)
    direct_shapes = {
        index: shape
        for index in sorted(ancestor_set)
        if index >= first_call
        if (shape := _direct_call_shape(body, instructions, predecessor_rows, relocations, index))
        is not None
    }
    vcall_shapes = {
        index: shape
        for index in sorted(ancestor_set)
        if index >= first_call
        if (
            shape := _one_word_vcall_shape(
                body, instructions, predecessor_rows, relocations, index
            )
        )
        is not None
    }
    depths: list[int | None] = [None] * len(instructions)
    receipts: dict[int, dict[str, object]] = {}
    depths[0] = 0
    work = [0]
    while work:
        index = work.pop()
        depth = depths[index]
        assert depth is not None
        item = instructions[index]
        change = stack_change(body, item)
        require(change is not None, f"{context}: unknown ESP update at {item['offset']}")
        assert change is not None
        outgoing = depth + change
        if item["flow"] == "call" and index >= first_call:
            pending = floor - outgoing
            direct = direct_shapes.get(index)
            strong_vcall = vcall_shapes.get(index)
            if direct is not None:
                cleanup = direct["stack_argument_bytes"]
                require(
                    isinstance(cleanup, int) and not isinstance(cleanup, bool),
                    f"{context}: decorated cleanup evidence is malformed",
                )
                assert isinstance(cleanup, int)
                require(
                    pending >= cleanup,
                    f"{context}: decorated call at {item['offset']} lacks its stack argument",
                )
                outgoing += cleanup
                if pending > 0 or cleanup > 0:
                    receipts[index] = {
                        "offset": int(item["offset"]),
                        "kind": "decorated-fixed-thiscall",
                        "total_stack_deficit_before_call": pending,
                        "cleanup_bytes": cleanup,
                        **direct,
                    }
            elif strong_vcall is not None:
                require(
                    pending == 4,
                    f"{context}: strong one-word vcall at {item['offset']} "
                    "does not have exactly one pending word",
                )
                outgoing += 4
                receipts[index] = {
                    "offset": int(item["offset"]),
                    "kind": "strong-one-word-vcall-callee-clean",
                    "total_stack_deficit_before_call": pending,
                    "cleanup_bytes": 4,
                    "member_call_shape": strong_vcall,
                }
            elif pending > 0:
                cdecl = msvc420_direct_cdecl_call(body, instructions, relocations, index)
                require(
                    cdecl is not None,
                    f"{context}: call at {item['offset']} has {pending} unresolved pending bytes",
                )
                receipts[index] = {
                    "offset": int(item["offset"]),
                    "kind": "direct-cdecl-caller-clean",
                    "pending_bytes": pending,
                    "cleanup_bytes": 0,
                    "cdecl_call": cdecl,
                }
        require(outgoing <= 0, f"{context}: ESP rises above its entry value")
        for target in (candidate for candidate in successors[index] if candidate in ancestor_set):
            measured = depths[target]
            require(
                measured is None or measured == outgoing,
                f"{context}: stack depth disagrees at CFG join {instructions[target]['offset']}",
            )
            if measured is None:
                depths[target] = outgoing
                work.append(target)
    require(
        all(depths[index] is not None for index in ancestor_set),
        f"{context}: the window ancestor slice lacks an entry-derived stack depth",
    )
    require(
        all(
            depth is not None and depth <= floor
            for depth in (depths[index] for index in ancestor_set if index >= first_call)
        ),
        f"{context}: a window ancestor rises above the fixed-frame floor",
    )
    return depths, [receipts[index] for index in sorted(receipts)]
