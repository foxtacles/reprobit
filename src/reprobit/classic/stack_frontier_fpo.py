"""Bounded FPO stack-affine proof for compiler-scoped PUSH scheduling."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require

from .stack_frontier_foundation import (
    MAX_AFFINES,
    Affine,
    AffineState,
    address_form,
    stack_change,
)


def _join_affines(left: Affine, right: Affine, context: str) -> Affine:
    values = set(left) | set(right)
    require(len(values) <= MAX_AFFINES, f"{context}: too many stack-affine values")
    return {value: left.get(value, frozenset()) | right.get(value, frozenset()) for value in values}


def _register_affine(state: AffineState, register: str | None, depth: int) -> Affine | None:
    if register == "esp":
        return {depth: frozenset()}
    return None if register is None else state.registers.get(register)


def address_affine(
    state: AffineState,
    form: tuple[str | None, str | None, int, int] | None,
    depth: int,
    context: str,
) -> Affine | None:
    if form is None:
        return None
    base, indexed, scale, displacement = form
    bases = _register_affine(state, base, depth)
    indexes = {0: frozenset()} if indexed is None else _register_affine(state, indexed, depth)
    if bases is None or indexes is None:
        return None
    result: Affine = {}
    for base_value, base_defs in bases.items():
        for index_value, index_defs in indexes.items():
            value = base_value + index_value * scale + displacement
            result[value] = result.get(value, frozenset()) | base_defs | index_defs
    require(len(result) <= MAX_AFFINES, f"{context}: an address has too many affine values")
    return result


def transfer_affines(
    body: bytes, item: dict[str, Any], state: AffineState, depth: int, context: str
) -> AffineState:
    registers = {name: dict(values) for name, values in state.registers.items()}
    slots = {slot: dict(values) for slot, values in state.slots.items()}
    offset = int(item["offset"])
    address = address_affine(state, address_form(body, item), depth, context)
    written = set(item["writes"]) - {"esp"}
    result: Affine | None = None
    if len(written) == 1 and int(item["opcode"]) == 0x8D and address is not None:
        result = {value: definitions | {offset} for value, definitions in address.items()}
    memory = item.get("memory")
    opcode = int(item["opcode"])
    if opcode in {*range(0x50, 0x58), 0x68, 0x6A}:
        seat = depth - 4
        for slot in list(slots):
            if seat < slot + 4 and slot < seat + 4:
                slots.pop(slot, None)
        escaped = {
            value
            for register in set(item["reads"]) - {"esp"}
            for value in state.registers.get(register, {})
        }
        for slot in set(slots) & escaped:
            slots.pop(slot, None)
    if item["flow"] == "call":
        slots.clear()
    if (
        len(written) == 1
        and isinstance(memory, dict)
        and memory["read"]
        and int(memory["width"]) == 4
        and address is not None
    ):
        loaded: Affine = {}
        for location in address:
            values = slots.get(location)
            if values is None:
                loaded = {}
                break
            loaded = _join_affines(loaded, values, context)
        if loaded:
            result = {value: definitions | {offset} for value, definitions in loaded.items()}
    if len(written) == 1 and memory is None and opcode in (0x89, 0x8B):
        sources = set(item["reads"])
        if len(sources) == 1:
            source = _register_affine(state, next(iter(sources)), depth)
            if source is not None:
                result = {value: definitions | {offset} for value, definitions in source.items()}
    for register in written:
        registers.pop(register, None)
    if result is not None:
        registers[next(iter(written))] = result
        if opcode == 0x8D:
            for slot in set(slots) & set(result):
                slots.pop(slot, None)
    if isinstance(memory, dict) and memory["write"]:
        width = int(memory["width"])
        if address is None or width <= 0:
            slots.clear()
        else:
            for slot in list(slots):
                if any(value < slot + 4 and slot < value + width for value in address):
                    slots.pop(slot, None)
    if (
        isinstance(memory, dict)
        and memory["write"]
        and int(memory["width"]) == 4
        and address is not None
        and len(address) == 1
    ):
        location = next(iter(address))
        address_registers = {name for name in (memory["base"], memory["index"]) if name}
        sources = set(item["reads"]) - address_registers - {"esp"}
        stored = _register_affine(state, next(iter(sources)), depth) if len(sources) == 1 else None
        if stored is None or location < depth:
            slots.pop(location, None)
        else:
            slots[location] = {
                value: definitions | {offset} for value, definitions in stored.items()
            }
    change = stack_change(body, item)
    if change is not None and change > 0:
        new_depth = depth + change
        for slot in list(slots):
            if slot < new_depth:
                slots.pop(slot, None)
    return AffineState(registers, slots)
