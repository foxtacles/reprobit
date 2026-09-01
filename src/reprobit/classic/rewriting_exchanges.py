"""Classic compiler algorithms: ESP-argument and frame-pointer operand exchanges."""

from __future__ import annotations

from typing import Any, cast

from reprobit.binary import require
from reprobit.ia32_decode import supported_ia32_instruction_length

from .foundation import (
    require_payload_free_declaration,
)
from .register_semantics import (
    _IA32_ATOMS_OF,
    IA32_GENERAL_REGISTER_NAMES,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
)
from .relational import (
    ia32_relational_flag_liveness,
    ia32_relational_flow_walk,
)


def apply_esp_argument_exchange(
    body: bytes,
    exchanges: list[Any],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Exchange two incoming pointer arguments' roles, or refuse.

    The certificate: two `mov r32, [esp+disp8]` argument loads in the
    function's linear prologue prefix take each other's incoming argument
    slot, and every later use of either destination register is renamed
    under the corresponding two-register bijection.  The pair composes to
    an isomorphism of the machine function: the same two argument values
    flow through exchanged register names.

    Obligations, all discharged here on the measured body:
      E1  both offsets decode as `8B /r` with mod=01, rm=100, SIB=24 --
          `mov r32, [esp+disp8]` -- inside a totally decoded prefix;
      E2  the destinations are distinct and neither is ESP or EBP;
      E3  the prefix from entry through the second load consists ONLY of
          `push r32`, `sub esp, imm8`, and `mov r32, [esp+disp8]`
          instructions, so the ESP depth at each site is exact and no
          instruction can have consumed either destination register;
      E4  no relocation byte lies inside either instruction;
      E5  the two loads address DIFFERENT incoming argument slots (the
          slot is disp MINUS the tracked ESP depth, entry-relative), both
          above the return address;
      E6  the exchanged displacements still encode as disp8;
      E7  no other prologue load addresses either exchanged slot, and no
          instruction after the prologue prefix has an ESP-based memory
          operand at all (so nothing else can alias an argument slot);
      E8  after the prefix, neither destination register is WRITTEN again
          (a `pop r32` restoring a prologue `push r32` is the structural
          exception and is left unrenamed), every register field naming
          either destination is flipped to the other, instruction
          boundaries survive re-decoding, and each rewritten
          instruction's read/write sets are exactly the originals with
          the two registers exchanged.
    """
    require_payload_free_declaration(exchanges, f"{context} ESP argument declaration")
    require(isinstance(body, (bytes, bytearray)) and bool(body), f"{context}: body is empty")
    body = bytes(body)
    require(
        isinstance(exchanges, list) and len(exchanges) == 1,
        f"{context}: exactly one exchange must be declared",
    )
    item = exchanges[0]
    item_context = f"{context} exchange 0"
    first, second = (item["first_offset"], item["second_offset"])
    require(
        type(first) is int and type(second) is int and (0 <= first < second < len(body)),
        f"{item_context}: offsets are out of range",
    )
    depth = 0
    at = 0
    depths = {}
    loads = {}
    pushed = []
    while at < len(body):
        opcode = body[at]
        if 80 <= opcode <= 87:
            depth += 4
            pushed.append(opcode - 80)
            at += 1
            continue
        if opcode == 131 and at + 3 <= len(body) and (body[at + 1] == 236):
            depth += body[at + 2]
            at += 3
            continue
        if (
            opcode == 139
            and at + 4 <= len(body)
            and (body[at + 1] >> 6 == 1)
            and (body[at + 1] & 7 == 4)
            and (body[at + 2] == 36)
        ):
            register = body[at + 1] >> 3 & 7
            displacement = body[at + 3]
            loads[at] = (register, displacement)
            depths[at] = depth
            at += 4
            continue
        require(
            at > second,
            f"{item_context}: the prologue prefix holds an instruction outside the closed form at {at}",
        )
        break
    prefix_end = at
    require(
        first in loads and second in loads,
        f"{item_context}: a declared offset is not an argument load",
    )
    first_register, first_disp = loads[first]
    second_register, second_disp = loads[second]
    require(
        first_register != second_register
        and first_register not in (4, 5)
        and (second_register not in (4, 5)),
        f"{item_context}: destination registers are not two distinct general registers",
    )
    for offset in (first + 3, second + 3):
        require(
            offset not in relocation_offsets,
            f"{item_context}: a relocation lies under the displacement",
        )
    first_slot = first_disp - depths[first]
    second_slot = second_disp - depths[second]
    require(
        first_slot != second_slot and first_slot >= 4 and (second_slot >= 4),
        f"{item_context}: the loads do not take two distinct incoming argument slots",
    )
    for load_at, (_, load_disp) in loads.items():
        if load_at in (first, second):
            continue
        require(
            load_disp - depths[load_at] not in (first_slot, second_slot),
            f"{item_context}: another prefix load addresses an exchanged slot",
        )
    new_first = second_slot + depths[first]
    new_second = first_slot + depths[second]
    require(
        0 <= new_first <= 127 and 0 <= new_second <= 127,
        f"{item_context}: an exchanged displacement does not encode as disp8",
    )
    decoded = decode_ia32_bijection_body(body, f"{context} body", relocations, code_length)
    numbers = {first_register: second_register, second_register: first_register}
    names = {
        IA32_GENERAL_REGISTER_NAMES[first_register]: IA32_GENERAL_REGISTER_NAMES[second_register],
        IA32_GENERAL_REGISTER_NAMES[second_register]: IA32_GENERAL_REGISTER_NAMES[first_register],
    }
    exchanged_names = frozenset(names)
    remaining_pops = list(pushed)
    structural_pops = set()
    image = bytearray(body)
    image[first + 3] = new_first
    image[second + 3] = new_second
    rewritten = [first + 3, second + 3]
    for instruction in decoded:
        offset = instruction["offset"]
        if offset < prefix_end:
            continue
        memory = instruction.get("memory")
        require(
            memory is None or memory.get("base") != "esp",
            f"{item_context}: an ESP-based memory operand after the prologue prefix could alias an argument slot (at {offset})",
        )
        opcode = instruction["opcode"]
        if (
            instruction["length"] == 1
            and 88 <= body[offset] <= 95
            and (body[offset] - 88 in remaining_pops)
        ):
            remaining_pops.remove(body[offset] - 88)
            structural_pops.add(offset)
            continue
        require(
            not instruction["writes"] & exchanged_names or instruction["flow"] in ("ret", "exit"),
            f"{item_context}: an instruction at {offset} writes an exchanged register after the prologue prefix",
        )
        for byte_index, shift in instruction["fields"]:
            value = image[byte_index] >> shift & 7
            if value not in numbers:
                continue
            require(
                byte_index not in relocation_offsets,
                f"{item_context}: a rewritten register field overlaps a relocation",
            )
            image[byte_index] = (image[byte_index] & ~(7 << shift) | numbers[value] << shift) & 255
            rewritten.append(byte_index)
    output = bytes(image)
    image_instructions = decode_ia32_bijection_body(
        output, f"{context} image", relocations, code_length
    )
    require(
        [(entry["offset"], entry["length"]) for entry in image_instructions]
        == [(entry["offset"], entry["length"]) for entry in decoded],
        f"{item_context}: the exchange changed an instruction boundary",
    )
    for left, right in zip(image_instructions, decoded, strict=True):
        if (
            right["offset"] < prefix_end
            or right["offset"] in structural_pops
            or right["offset"] in (first, second)
        ):
            continue
        if right["flow"] in ("ret", "exit"):
            continue
        if not right["fields"]:
            require(
                not (right["reads"] | right["writes"]) & exchanged_names,
                f"{item_context}: an implicit use of an exchanged register at {right['offset']} cannot be renamed",
            )
            continue
        expected_reads = frozenset(names.get(name, name) for name in right["reads"])
        expected_writes = frozenset(names.get(name, name) for name in right["writes"])
        require(
            left["reads"] == expected_reads and left["writes"] == expected_writes,
            f"{item_context}: the rewrite at {right['offset']} is not the declared two-register exchange",
        )
    rewritten = sorted(set(offset for offset in rewritten if output[offset] != body[offset]))
    sites = [
        {
            "first_offset": first,
            "second_offset": second,
            "registers": [
                IA32_GENERAL_REGISTER_NAMES[first_register],
                IA32_GENERAL_REGISTER_NAMES[second_register],
            ],
            "rewritten_offsets": rewritten,
        }
    ]
    return (output, {"sites": sites})


FP_POINTER_EXCHANGE_KIND = "fp_pointer_addend_exchange_v1"


_SIMULATOR_REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def _fp_exchange_simulate(
    body: bytes, start: int, end: int, context: str
) -> tuple[dict[str, Any], list[Any], tuple[int, Any] | None]:
    """Symbolically execute [start, end); return the end state."""
    regs: dict[str, Any] = {name: ("reg0", name) for name in _SIMULATOR_REGS}
    stack: list[Any] = []
    last_flags: tuple[int, Any] | None = None
    offset = start

    def norm_sum(left: Any, right: Any) -> tuple[Any, ...]:
        parts: list[Any] = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "fsum":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("fsum", tuple(sorted(parts, key=repr)))

    while offset < end:
        length = supported_ia32_instruction_length(body[offset:], context)
        require(
            offset + length <= end,
            f"{context}: an instruction straddles the region boundary at {offset}",
        )
        encoded = body[offset : offset + length]
        op = encoded[0]
        modrm = encoded[1] if length >= 2 else None
        mod = modrm >> 6 if modrm is not None else None
        reg_field = modrm >> 3 & 7 if modrm is not None else None
        rm = modrm & 7 if modrm is not None else None

        def mem_operand(
            cursor_base: int,
            *,
            mod: int | None = mod,
            rm: int | None = rm,
            offset: int = offset,
            encoded: bytes = encoded,
        ) -> tuple[Any, ...]:
            require(rm != 4, f"{context}: SIB addressing at {offset} is outside the simulator set")
            base = regs[_SIMULATOR_REGS[cast(int, rm)]]
            cursor = cursor_base
            if mod == 1:
                disp = int.from_bytes(encoded[cursor : cursor + 1], "little", signed=True)
            elif mod == 2:
                disp = int.from_bytes(encoded[cursor : cursor + 4], "little", signed=True)
            elif mod == 0 and rm == 5:
                require(False, f"{context}: absolute address at {offset}")
            else:
                disp = 0
            return ("addr", base, disp)

        if op == 139 and mod != 3:
            regs[_SIMULATOR_REGS[cast(int, reg_field)]] = ("load", mem_operand(2))
        elif op == 139 and mod == 3:
            regs[_SIMULATOR_REGS[cast(int, reg_field)]] = regs[_SIMULATOR_REGS[cast(int, rm)]]
        elif op == 137 and mod == 3:
            regs[_SIMULATOR_REGS[cast(int, rm)]] = regs[_SIMULATOR_REGS[cast(int, reg_field)]]
        elif op == 131 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:3], "little", signed=True)
            name = _SIMULATOR_REGS[cast(int, rm)]
            regs[name] = ("add", regs[name], value)
            last_flags = (offset - start, ("addflags", regs[name]))
        elif op == 129 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:6], "little", signed=True)
            name = _SIMULATOR_REGS[cast(int, rm)]
            regs[name] = ("add", regs[name], value)
            last_flags = (offset - start, ("addflags", regs[name]))
        elif op == 133 and mod == 3:
            last_flags = (
                offset - start,
                (
                    "test",
                    regs[_SIMULATOR_REGS[cast(int, rm)]],
                    regs[_SIMULATOR_REGS[cast(int, reg_field)]],
                ),
            )
        elif op == 217 and mod != 3 and (reg_field == 0):
            stack.append(("load32", mem_operand(2)))
        elif op == 216 and mod != 3 and (reg_field == 1):
            require(bool(stack), f"{context}: fmul at {offset} multiplies the unknown stack base")
            stack[-1] = ("fmul", stack[-1], ("load32", mem_operand(2)))
        elif encoded == b"\xde\xc1":
            require(len(stack) >= 2, f"{context}: faddp at {offset} reaches the unknown stack base")
            right = stack.pop()
            stack[-1] = norm_sum(stack[-1], right)
        else:
            require(
                False,
                f"{context}: the instruction at {offset} is outside the simulator's closed set",
            )
        offset += length
    require(offset == end, f"{context}: the region does not end on an instruction boundary")
    return (regs, stack, last_flags)


def apply_fp_pointer_exchange(
    body: bytes,
    exchanges: list[Any],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
    external_entries: frozenset[int] | None = None,
    internal_targets: frozenset[int] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Exchange declared pointer-setup immediates, or refuse."""
    require_payload_free_declaration(exchanges, f"{context} FP pointer declaration")
    require(isinstance(body, (bytes, bytearray)) and bool(body), f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(exchanges, list) and bool(exchanges), f"{context}: no exchange is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    flag_live = ia32_relational_flag_liveness(items, successors, context)
    walk_index = {item["offset"]: index for index, item in enumerate(items)}
    decoded = decode_ia32_bijection_body(body, f"{context} liveness", relocations, code_length)
    live, _live_successors = _register_bijection_live_sets(decoded, f"{context} liveness")
    exit_index = {item["offset"]: index for index, item in enumerate(decoded)}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, item in enumerate(exchanges):
        item_context = f"{context} exchange {ordinal}"
        start, end = (item["region_start"], item["region_end"])
        require(
            type(start) is int and type(end) is int and (0 < start < end <= len(body)),
            f"{item_context}: bounds are out of range",
        )
        require(previous_end <= start, f"{item_context}: exchanges are unsorted or overlapping")
        previous_end = end
        require(
            not any(start <= offset < end for offset in relocation_offsets),
            f"{item_context}: a relocation lies inside the region",
        )
        require(
            not any(start < target < end for target in branch_targets),
            f"{item_context}: a branch targets the region interior",
        )
        require(
            not any(start < items[entry]["offset"] < end for entry in entries[1:]),
            f"{item_context}: an external entry lies inside the region",
        )
        require(
            not any(start < target < end for target in internal_targets or frozenset()),
            f"{item_context}: a relocated target lies inside the region",
        )
        first, second = item["swap_offsets"]
        require(
            start <= first < second < end,
            f"{item_context}: the swapped adds are outside the region",
        )
        forms = []
        for at in (first, second):
            length = supported_ia32_instruction_length(body[at:], item_context)
            encoded = body[at : at + length]
            require(
                encoded[0] in (129, 131) and encoded[1] >> 6 == 3 and (encoded[1] >> 3 & 7 == 0),
                f"{item_context}: the instruction at {at} is not add r32, imm",
            )
            forms.append((encoded[0], length))
        require(forms[0] == forms[1], f"{item_context}: the two adds have different forms")
        width = 1 if forms[0][0] == 131 else 4
        imm_a = image[first + 2 : first + 2 + width]
        imm_b = image[second + 2 : second + 2 + width]
        require(imm_a != imm_b, f"{item_context}: the immediates are already equal")
        image[first + 2 : first + 2 + width] = imm_b
        image[second + 2 : second + 2 + width] = imm_a
        seed_state = _fp_exchange_simulate(body, start, end, f"{item_context} seed")
        image_state = _fp_exchange_simulate(bytes(image), start, end, f"{item_context} image")
        seed_regs, seed_stack, seed_flags = seed_state
        image_regs, image_stack, image_flags = image_state
        require(
            seed_stack == image_stack,
            f"{item_context}: the two versions leave different FP stacks -- the exchange is not a reassociation of one sum",
        )
        if seed_flags != image_flags:
            require(end in walk_index, f"{item_context}: the region end is not a flow boundary")
            live_flags = flag_live[walk_index[end]]
            require(
                not live_flags,
                f"{item_context}: the two versions leave different flag state and {sorted(live_flags)} is live at the exit",
            )
        differing = sorted(name for name in _SIMULATOR_REGS if seed_regs[name] != image_regs[name])
        declared_dead = item["dead_registers"]
        require(
            differing == sorted(declared_dead),
            f"{item_context}: the registers left differing {differing} are not the declared dead set {sorted(declared_dead)}",
        )
        require(
            end in exit_index or end == len(body),
            f"{item_context}: the region end is not an instruction boundary of the body",
        )
        if end in exit_index:
            live_in = live[exit_index[end]]
            for name in declared_dead:
                overlap = _IA32_ATOMS_OF[name] & live_in
                require(
                    not overlap,
                    f"{item_context}: {name} is live on the region's exit edge ({sorted(overlap)})",
                )
        proved.append(
            {
                "region_start": start,
                "region_end": end,
                "swap_offsets": [first, second],
                "immediate_width": width,
                "dead_registers": sorted(declared_dead),
                "rewritten_offsets": sorted(
                    offset for offset in range(start, end) if body[offset] != image[offset]
                ),
            }
        )
    output = bytes(image)
    require(image != body, f"{context}: the image does not move the body")
    changed = {offset for offset in range(len(body)) if body[offset] != output[offset]}
    declared = {offset for item in proved for offset in item["rewritten_offsets"]}
    require(
        changed <= declared, f"{context}: the image changed a byte outside the declared exchanges"
    )
    return (output, {"kind": FP_POINTER_EXCHANGE_KIND, "exchanges": proved})
