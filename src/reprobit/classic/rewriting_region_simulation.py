"""Classic compiler algorithms: simulated region rewrite and its IA-32 simulator."""

from __future__ import annotations

import itertools
from typing import Any, TypeAlias, cast

from reprobit.binary import require
from reprobit.ia32_decode import supported_ia32_instruction_length

from .foundation import (
    require_payload_free_declaration,
)
from .register_semantics import (
    _IA32_ATOMS_OF,
    _IA32_REGISTER_NUMBERS,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
    decode_ia32_bijection_instruction,
)
from .relational import (
    ia32_relational_flag_liveness,
    ia32_relational_flow_walk,
)
from .rewriting_exchanges import _SIMULATOR_REGS

SIMULATED_REGION_REWRITE_KIND = "simulated_region_rewrite_v1"

# A symbolic term of the region simulator: a tagged tuple such as ("load", addr)
# or ("add", term, int), a literal int/bytes, a symbol name, or None.  The term
# language is open (every opcode branch below builds its own shape), so the
# simulator's state is typed by this alias rather than a closed union.
_Term: TypeAlias = Any


def _srr_simulate(
    body: bytes,
    start: int,
    end: int,
    context: str,
    relocations: dict[int, Any] | None = None,
    oracles: dict[str, Any] | None = None,
    entry_loads: dict[str, Any] | None = None,
) -> tuple[
    dict[str, _Term],
    list[_Term],
    list[_Term],
    dict[_Term, _Term],
    _Term,
    _Term,
    dict[_Term, tuple[_Term, int]],
]:
    """Symbolically execute [start, end); return the end state.

    `relocations` maps a byte offset (of a relocated field inside the
    executed bytes) to its target symbol, so a relocated immediate reads as
    the SYMBOL rather than its raw bytes and two versions that name the same
    target through different encodings still compare equal.  `oracles`, when
    present, carries verified callee bodies ({"callees": {symbol: bytes}})
    and vtable slot maps ({"vtables": {symbol: {slot: symbol}}}); a direct
    call whose relocation names an oracle callee -- or an indirect call
    through a register holding an oracle vtable symbol -- is executed by
    stepping INTO the callee's own bytes, so the region's proof carries the
    callee's real effect instead of an assumption about it.  Everything
    outside the closed set still refuses.
    """
    relocations = relocations or {}
    oracles = oracles or {}
    oracle_callees = oracles.get("callees") or {}
    oracle_vtables = oracles.get("vtables") or {}
    regs: dict[str, _Term] = {name: ("reg0", name) for name in _SIMULATOR_REGS}
    for name, disp in (entry_loads or {}).items():
        regs[name] = ("load", ("addr", ("reg0", "ebp"), disp))
    stack: list[_Term] = []
    pushes: list[_Term] = []
    slots: dict[_Term, _Term] = {}
    widths: dict[_Term, int] = {}
    heap_slots: dict[_Term, tuple[_Term, int]] = {}
    heap_base: list[_Term] = [None]
    last_flags: _Term = None
    frames: list[tuple[bytes, int, int, int]] = []
    cur_body, offset, cur_end = (body, start, end)
    reloc_base = 0
    reloc_maps: list[dict[Any, Any]] = [relocations]

    def norm_isub(left: _Term, right: _Term) -> _Term:
        if isinstance(left, tuple) and left[0] == "isub":
            base, parts = (left[1], left[2])
        else:
            base, parts = (left, ())
        return ("isub", base, tuple(sorted((*parts, right), key=repr)))

    def norm_iadd(left: _Term, right: _Term) -> _Term:
        parts: list[_Term] = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "iadd":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("iadd", tuple(sorted(parts, key=repr)))

    def norm_sum(left: _Term, right: _Term) -> _Term:
        parts: list[_Term] = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "fsum":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("fsum", tuple(sorted(parts, key=repr)))

    def flatten_add(value: _Term) -> tuple[_Term, int]:
        total = 0
        while isinstance(value, tuple) and value[0] == "add" and isinstance(value[2], int):
            total += value[2]
            value = value[1]
        return (value, total)

    def frame_address(value: _Term) -> int | None:
        base, extra = flatten_add(value)
        if isinstance(base, tuple) and base[0] == "lea":
            addr = base[1]
            if addr[1] == ("reg0", "ebp") and isinstance(addr[2], int):
                return addr[2] + extra
        return None

    while True:
        if offset >= cur_end:
            require(
                offset == cur_end, f"{context}: the region does not end on an instruction boundary"
            )
            require(
                not frames, f"{context}: an inlined callee runs past its body without returning"
            )
            intervals = sorted((key, key + widths[key]) for key in slots if isinstance(key, int))
            for former, latter in itertools.pairwise(intervals):
                require(
                    former[1] <= latter[0],
                    f"{context}: the frame stores at {former[0]:#x} and {latter[0]:#x} overlap; the slot map cannot represent their order",
                )
            break
        length = supported_ia32_instruction_length(cur_body[offset:], context)
        require(
            offset + length <= cur_end,
            f"{context}: an instruction straddles the region boundary at {offset}",
        )
        encoded = cur_body[offset : offset + length]
        op = encoded[0]
        modrm = encoded[1] if length >= 2 else None
        mod = modrm >> 6 if modrm is not None else None
        reg_field = modrm >> 3 & 7 if modrm is not None else None
        rm = modrm & 7 if modrm is not None else None
        # Only the branches for opcodes that carry a ModR/M byte read these two.
        reg = cast(int, reg_field)
        rm_index = cast(int, rm)
        cur_relocs = reloc_maps[-1]

        def reloc_symbol(
            field_offset: int,
            *,
            cur_relocs: dict[Any, Any] = cur_relocs,
            reloc_base: int = reloc_base,
        ) -> _Term:
            entry = cur_relocs.get(reloc_base + field_offset)
            if entry is None:
                return None
            return entry["target"] if isinstance(entry, dict) else entry

        def mem_operand(
            cursor_base: int,
            *,
            mod: int | None = mod,
            rm: int | None = rm,
            offset: int = offset,
            encoded: bytes = encoded,
        ) -> _Term:
            require(not (mod == 0 and rm == 5), f"{context}: absolute address at {offset}")
            cursor = cursor_base
            if rm == 4:
                sib = encoded[cursor]
                cursor += 1
                require(
                    sib >> 3 & 7 == 4 and sib >> 6 == 0,
                    f"{context}: an indexed SIB at {offset} is outside the simulator set",
                )
                base = regs[_SIMULATOR_REGS[sib & 7]]
            else:
                base = regs[_SIMULATOR_REGS[cast(int, rm)]]
            if mod == 1:
                disp = int.from_bytes(encoded[cursor : cursor + 1], "little", signed=True)
            elif mod == 2:
                disp = int.from_bytes(encoded[cursor : cursor + 4], "little", signed=True)
            else:
                disp = 0
            if isinstance(base, tuple) and base[0] == "add" and isinstance(base[2], int):
                return ("addr", base[1], disp + base[2])
            return ("addr", base, disp)

        def frame_disp(addr: _Term, *, offset: int = offset) -> _Term:
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp"):
                require(
                    addr[2] >= 0,
                    f"{context}: an esp store below the region-entry stack pointer at {offset} aliases the push sequence",
                )
                return ("esp", addr[2])
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def heap_key(addr: _Term, *, offset: int = offset) -> _Term:
            """The single-base heap map's key, or None for a frame address.

            Non-frame stores are admitted under two invariants the emitting
            compiler itself relies on: (a) every non-frame access in one
            region goes through ONE common symbolic base, so two keys with
            different displacements name provably different bytes, and
            (b) the compiler's own esp/ebp frame addressing is private --
            no indirect pointer aliases it -- which is exactly the license
            MSVC uses to reorder its own spill traffic around such stores.
            A second, different non-frame base in the same region refuses.
            """
            if frame_disp_quiet(addr) is not None:
                return None
            base = addr[1]
            if heap_base[0] is None:
                heap_base[0] = base
            require(
                base == heap_base[0],
                f"{context}: a second non-frame base at {offset} leaves the single-base heap set",
            )
            return addr[2]

        def frame_disp_quiet(addr: _Term) -> _Term:
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp") and addr[2] >= 0:
                return ("esp", addr[2])
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def heap_store(addr: _Term, value: _Term, width: int, *, offset: int = offset) -> None:
            key = heap_key(addr)
            for other, (_, other_width) in heap_slots.items():
                if other == key:
                    continue
                require(
                    key + width <= other or other + other_width <= key,
                    f"{context}: overlapping heap stores at {offset}",
                )
            require(
                heap_slots.get(key, (None, width))[1] == width,
                f"{context}: the heap store at {offset} resizes a slot",
            )
            heap_slots[key] = (value, width)

        def heap_load(addr: _Term, width: int) -> _Term:
            key = heap_key(addr)
            held = heap_slots.get(key)
            if held is not None and held[1] == width:
                return held[0]
            return None

        def read_disp(addr: _Term) -> _Term:
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp"):
                return ("esp", addr[2]) if addr[2] >= 0 else None
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def read_slot(addr: _Term) -> _Term:
            disp = read_disp(addr)
            if disp is not None and disp in slots:
                return slots[disp]
            return None

        def resolve_pushed(addr: _Term) -> _Term:
            base, _extra = flatten_add(regs["esp"])
            if base != ("reg0", "esp") or addr[1] != ("reg0", "esp"):
                return None
            if addr[2] >= 0 or addr[2] % 4 != 0:
                return None
            index = -(addr[2] // 4) - 1
            if 0 <= index < len(pushes):
                return pushes[index]
            return None

        def do_push(value: _Term) -> None:
            pushes.append(value)
            esp = regs["esp"]
            if isinstance(esp, tuple) and esp[0] == "add" and isinstance(esp[2], int):
                regs["esp"] = ("add", esp[1], esp[2] - 4)
            else:
                regs["esp"] = ("add", esp, -4)

        def enter_callee(
            symbol: _Term,
            *,
            offset: int = offset,
            length: int = length,
            cur_body: bytes = cur_body,
            cur_end: int = cur_end,
            reloc_base: int = reloc_base,
        ) -> bytes:
            callee = oracle_callees.get(symbol)
            require(
                callee is not None,
                f"{context}: the call at {offset} names '{symbol}', which no verified callee oracle covers",
            )
            require(len(frames) < 4, f"{context}: callee inlining exceeds the depth bound")
            do_push(("return_to", len(frames), offset + length))
            frames.append((cur_body, offset + length, cur_end, reloc_base))
            reloc_maps.append((oracles.get("callee_relocations") or {}).get(symbol, {}))
            return cast(bytes, callee)

        advanced = False
        if op == 139 and mod != 3:
            addr = mem_operand(2)
            pushed = resolve_pushed(addr)
            forwarded = read_slot(addr) if pushed is None else None
            if forwarded is not None:
                regs[_SIMULATOR_REGS[reg]] = forwarded
            elif pushed is not None:
                regs[_SIMULATOR_REGS[reg]] = pushed
            elif heap_slots and frame_disp_quiet(addr) is None:
                held = heap_load(addr, 4)
                regs[_SIMULATOR_REGS[reg]] = held if held is not None else ("load", addr)
            else:
                regs[_SIMULATOR_REGS[reg]] = ("load", addr)
        elif op in (139, 137) and mod == 3:
            if op == 139:
                regs[_SIMULATOR_REGS[reg]] = regs[_SIMULATOR_REGS[rm_index]]
            else:
                regs[_SIMULATOR_REGS[rm_index]] = regs[_SIMULATOR_REGS[reg]]
        elif op == 137 and mod != 3:
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            if disp is None:
                heap_store(addr, regs[_SIMULATOR_REGS[reg]], 4)
            else:
                require(
                    widths.get(disp, 4) == 4, f"{context}: the store at {offset} resizes a slot"
                )
                slots[disp] = regs[_SIMULATOR_REGS[reg]]
                widths[disp] = 4
        elif op == 138 and mod != 3:
            addr = mem_operand(2)
            disp = read_disp(addr)
            forwarded = slots.get(disp) if disp is not None and widths.get(disp) == 1 else None
            name = _SIMULATOR_REGS[reg & 3]
            value = forwarded if forwarded is not None else ("load8", addr)
            regs[name] = ("setbyte", regs[name], reg >> 2, value)
        elif op == 136 and mod != 3:
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            if disp is None:
                heap_store(addr, ("byte", regs[_SIMULATOR_REGS[reg & 3]], reg >> 2), 1)
            else:
                require(
                    widths.get(disp, 1) == 1,
                    f"{context}: the byte store at {offset} resizes a slot",
                )
                slots[disp] = ("byte", regs[_SIMULATOR_REGS[reg & 3]], reg >> 2)
                widths[disp] = 1
        elif 184 <= op <= 191:
            require(
                length == 5,
                f"{context}: an operand-size-prefixed immediate move at {offset} is outside the simulator set",
            )
            symbol = reloc_symbol(offset + 1)
            regs[_SIMULATOR_REGS[op - 184]] = (
                ("sym", symbol)
                if symbol is not None
                else ("imm", int.from_bytes(encoded[1:5], "little"))
            )
        elif op == 199 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            imm_at = length - 4
            symbol = reloc_symbol(offset + imm_at)
            value = (
                ("sym", symbol)
                if symbol is not None
                else ("imm", bytes(encoded[imm_at : imm_at + 4]))
            )
            if disp is None:
                heap_store(addr, value, 4)
            else:
                require(
                    widths.get(disp, 4) == 4, f"{context}: the store at {offset} resizes a slot"
                )
                slots[disp] = value
                widths[disp] = 4
        elif op == 198 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            value = ("imm8", encoded[length - 1])
            if disp is None:
                heap_store(addr, value, 1)
            else:
                require(
                    widths.get(disp, 1) == 1,
                    f"{context}: the byte store at {offset} resizes a slot",
                )
                slots[disp] = value
                widths[disp] = 1
        elif op == 141 and mod != 3:
            regs[_SIMULATOR_REGS[reg]] = ("lea", mem_operand(2))
        elif op == 131 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame read-modify-write at {offset} is outside the simulator set",
            )
            require(widths.get(disp, 4) == 4, f"{context}: the add at {offset} resizes a slot")
            current = slots.get(disp, ("load", addr))
            value = int.from_bytes(encoded[length - 1 : length], "little", signed=True)
            slots[disp] = norm_iadd(current, value)
            widths[disp] = 4
            last_flags = ("addflags", slots[disp])
        elif op == 255 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame increment at {offset} is outside the simulator set",
            )
            require(
                widths.get(disp, 4) == 4, f"{context}: the increment at {offset} resizes a slot"
            )
            current = slots.get(disp, ("load", addr))
            slots[disp] = norm_iadd(current, 1)
            widths[disp] = 4
            last_flags = ("incflags", slots[disp])
        elif op == 131 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:3], "little", signed=True)
            name = _SIMULATOR_REGS[rm_index]
            regs[name] = ("add", regs[name], value)
            last_flags = ("addflags", regs[name])
        elif op == 129 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:6], "little", signed=True)
            name = _SIMULATOR_REGS[rm_index]
            regs[name] = ("add", regs[name], value)
            last_flags = ("addflags", regs[name])
        elif op == 133 and mod == 3:
            last_flags = ("test", regs[_SIMULATOR_REGS[rm_index]], regs[_SIMULATOR_REGS[reg]])
        elif op == 128 and mod != 3 and (reg_field == 7):
            last_flags = ("cmp8", mem_operand(2), encoded[length - 1])
        elif op == 131 and mod != 3 and (reg_field == 7):
            addr = mem_operand(2)
            left = read_slot(addr)
            last_flags = (
                "cmp",
                left if left is not None else ("load", addr),
                ("imm", int.from_bytes(encoded[length - 1 : length], "little", signed=True)),
            )
        elif op == 57 and mod == 3:
            last_flags = ("cmp", regs[_SIMULATOR_REGS[rm_index]], regs[_SIMULATOR_REGS[reg]])
        elif op == 57 and mod != 3:
            addr = mem_operand(2)
            left = read_slot(addr)
            last_flags = (
                "cmp",
                left if left is not None else ("load", addr),
                regs[_SIMULATOR_REGS[reg]],
            )
        elif op == 59 and mod == 3:
            last_flags = ("cmp", regs[_SIMULATOR_REGS[reg]], regs[_SIMULATOR_REGS[rm_index]])
        elif op == 59 and mod != 3:
            addr = mem_operand(2)
            right = read_slot(addr)
            last_flags = (
                "cmp",
                regs[_SIMULATOR_REGS[reg]],
                right if right is not None else ("load", addr),
            )
        elif op == 43 and mod != 3:
            name = _SIMULATOR_REGS[reg]
            regs[name] = norm_isub(regs[name], ("load", mem_operand(2)))
            last_flags = ("subflags", regs[name])
        elif op == 43 and mod == 3:
            name = _SIMULATOR_REGS[reg]
            regs[name] = norm_isub(regs[name], regs[_SIMULATOR_REGS[rm_index]])
            last_flags = ("subflags", regs[name])
        elif 64 <= op <= 71:
            name = _SIMULATOR_REGS[op - 64]
            regs[name] = ("add", regs[name], 1)
            last_flags = ("incflags", regs[name])
        elif 72 <= op <= 79:
            name = _SIMULATOR_REGS[op - 72]
            regs[name] = norm_iadd(regs[name], -1)
            last_flags = ("decflags", regs[name])
        elif op == 3 and mod == 3:
            name = _SIMULATOR_REGS[reg]
            regs[name] = norm_iadd(regs[name], regs[_SIMULATOR_REGS[rm_index]])
            last_flags = ("addflags", regs[name])
        elif op == 3 and mod != 3:
            name = _SIMULATOR_REGS[reg]
            regs[name] = norm_iadd(regs[name], ("load", mem_operand(2)))
            last_flags = ("addflags", regs[name])
        elif op == 51 and mod == 3 and (reg_field == rm):
            name = _SIMULATOR_REGS[reg]
            regs[name] = ("imm", 0)
            last_flags = ("zeroflags",)
        elif op == 193 and mod == 3 and (reg_field == 4):
            name = _SIMULATOR_REGS[rm_index]
            regs[name] = ("shl", regs[name], encoded[length - 1])
            last_flags = ("shlflags", regs[name])
        elif op == 193 and mod == 3 and (reg_field == 5):
            name = _SIMULATOR_REGS[rm_index]
            regs[name] = ("shr", regs[name], encoded[length - 1])
            last_flags = ("shrflags", regs[name])
        elif op == 193 and mod == 3 and (reg_field == 7):
            name = _SIMULATOR_REGS[rm_index]
            regs[name] = ("sar", regs[name], encoded[length - 1])
            last_flags = ("sarflags", regs[name])
        elif 80 <= op <= 87:
            do_push(regs[_SIMULATOR_REGS[op - 80]])
        elif op == 106:
            do_push(("imm", int.from_bytes(encoded[1:2], "little", signed=True)))
        elif op == 104:
            symbol = reloc_symbol(offset + 1)
            do_push(
                ("sym", symbol)
                if symbol is not None
                else ("imm", int.from_bytes(encoded[1:5], "little"))
            )
        elif op == 232:
            symbol = reloc_symbol(offset + 1)
            require(
                symbol is not None,
                f"{context}: a direct call at {offset} carries no relocation to name its target",
            )
            callee = enter_callee(symbol)
            cur_body, offset, cur_end = (callee, 0, len(callee))
            reloc_base = 0
            advanced = True
        elif op == 255 and mod != 3 and (reg_field == 2):
            operand = mem_operand(2)
            base_probe, _extra_probe = flatten_add(operand[1])
            covered = (
                isinstance(base_probe, tuple)
                and base_probe[0] == "sym"
                and (base_probe[1] in oracle_vtables)
            )
            if not covered and offset + length == cur_end and (not frames):
                last_flags = ("terminal_call", operand, tuple(pushes))
                for name in ("eax", "ecx", "edx"):
                    regs[name] = ("call_clobber", name)
                regs["esp"] = ("call_balanced", regs["esp"])
            else:
                base_value, extra = flatten_add(operand[1])
                slot = operand[2] + extra
                require(
                    isinstance(base_value, tuple)
                    and base_value[0] == "sym"
                    and (base_value[1] in oracle_vtables),
                    f"{context}: the indirect call at {offset} does not dispatch through a verified vtable oracle",
                )
                table = oracle_vtables[base_value[1]]
                target = table.get(slot) or table.get(str(slot))
                require(
                    target is not None,
                    f"{context}: vtable slot {slot} of '{base_value[1]}' has no verified target",
                )
                callee = enter_callee(target)
                cur_body, offset, cur_end = (callee, 0, len(callee))
                reloc_base = 0
                advanced = True
        elif op in (194, 195):
            require(bool(frames), f"{context}: a return at {offset} outside any inlined callee")
            popped = int.from_bytes(encoded[1:3], "little") if op == 194 else 0
            require(popped % 4 == 0, f"{context}: the callee pops a non-dword argument size")
            count = popped // 4 + 1
            require(
                len(pushes) >= count, f"{context}: the callee at {offset} pops more than was pushed"
            )
            ret_slot = pushes[-1]
            require(
                isinstance(ret_slot, tuple) and ret_slot[0] == "return_to",
                f"{context}: the callee's return slot was overwritten",
            )
            del pushes[-count:]
            base_value, extra = flatten_add(regs["esp"])
            new_extra = extra + 4 * count
            regs["esp"] = base_value if new_extra == 0 else ("add", base_value, new_extra)
            cur_body, ret_offset, cur_end, reloc_base = frames.pop()
            reloc_maps.pop()
            require(
                ret_slot[1] == len(frames) and ret_slot[2] == ret_offset,
                f"{context}: the callee returns somewhere else than its call site",
            )
            offset = ret_offset
            advanced = True
        elif op == 217 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack.append(forwarded if forwarded is not None else ("load32", addr))
        elif op == 217 and mod != 3 and (reg_field == 3):
            require(bool(stack), f"{context}: fstp at {offset} pops the unknown stack base")
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame fstp at {offset} is outside the simulator set",
            )
            require(widths.get(disp, 4) == 4, f"{context}: the fstp at {offset} resizes a slot")
            slots[disp] = ("f32", stack.pop())
            widths[disp] = 4
        elif op == 217 and mod == 3 and (encoded[:2] == b"\xd9\xfa"):
            require(bool(stack), f"{context}: fsqrt at {offset} reads the unknown stack base")
            stack[-1] = ("fsqrt", stack[-1])
        elif op == 216 and mod != 3 and (reg_field == 0):
            require(bool(stack), f"{context}: fadd at {offset} adds to the unknown stack base")
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = norm_sum(
                stack[-1], forwarded if forwarded is not None else ("load32", addr)
            )
        elif op == 216 and mod != 3 and (reg_field == 4):
            require(
                bool(stack), f"{context}: fsub at {offset} subtracts from the unknown stack base"
            )
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = (
                "fsub",
                stack[-1],
                forwarded if forwarded is not None else ("load32", addr),
            )
        elif op == 216 and mod != 3 and (reg_field == 1):
            require(bool(stack), f"{context}: fmul at {offset} multiplies the unknown stack base")
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = (
                "fmul",
                stack[-1],
                forwarded if forwarded is not None else ("load32", addr),
            )
        elif op == 221 and mod != 3 and (reg_field == 0):
            stack.append(("load64", mem_operand(2)))
        elif op == 220 and mod != 3 and (reg_field == 1):
            require(bool(stack), f"{context}: fmul at {offset} multiplies the unknown stack base")
            stack[-1] = ("fmul", stack[-1], ("load64", mem_operand(2)))
        elif encoded == b"\xde\xc1":
            require(len(stack) >= 2, f"{context}: faddp at {offset} reaches the unknown stack base")
            right = stack.pop()
            stack[-1] = norm_sum(stack[-1], right)
        else:
            require(
                False,
                f"{context}: the instruction at {offset} is outside the simulator's closed set",
            )
        if not advanced:
            offset += length
    return (regs, stack, pushes, slots, last_flags, heap_base[0], heap_slots)


def _srr_slot_scratch_proof(
    decoded: list[Any],
    items: list[Any],
    successors: list[Any],
    entries: list[Any],
    exit_offset: int,
    disp: int,
    context: str,
    body_bytes: bytes = b"",
) -> None:
    """R5: [ebp+disp] is written before read on every path from the exit,
    and its address is never taken anywhere in the body."""
    lea_offsets = set()
    for item in decoded:
        if item["opcode"] != 141:
            continue
        enc = item.get("encoding") or {}
        if (
            enc.get("mode") not in (1, 2)
            or enc.get("rm") != 5
            or enc.get("sib_at") is not None
            or enc.get("absolute")
        ):
            continue
        at, size = (enc["displacement_at"], enc["displacement_size"])
        lea_disp = int.from_bytes(body_bytes[at : at + size], "little", signed=True)
        if lea_disp == disp:
            lea_offsets.add(item["offset"])
    index_of = {item["offset"]: index for index, item in enumerate(items)}
    require(exit_offset in index_of, f"{context}: the region exit is not a flow boundary")
    decoded_at = {item["offset"]: item for item in decoded}
    seen = set()
    frontier = [index_of[exit_offset]]
    while frontier:
        index = frontier.pop()
        if index in seen:
            continue
        seen.add(index)
        item = items[index]
        require(
            item["offset"] not in lea_offsets,
            f"{context}: the scratch slot's address is taken at {item['offset']} before any write",
        )
        info = decoded_at.get(item["offset"])
        if info is not None:
            mem = info.get("memory")
            if mem and mem.get("base") == "ebp" and (mem.get("displacement") in (disp, disp - 4)):
                covers = mem.get("displacement") == disp or mem.get("width", 0) >= 8
                if covers:
                    opcode = info["opcode"]
                    enc = info.get("encoding") or {}
                    reg = enc.get("reg")
                    if opcode == 217 and reg in (2, 3):
                        kills = mem.get("displacement") == disp
                    elif opcode == 221 and reg in (2, 3):
                        kills = True
                    elif opcode in (216, 220, 217, 221, 219, 223, 218, 222):
                        kills = False
                    else:
                        kills = (
                            mem.get("write")
                            and (not mem.get("read"))
                            and (mem.get("width") == 4)
                            and (mem.get("displacement") == disp)
                        )
                    if kills:
                        continue
                    require(
                        False,
                        f"{context}: the scratch slot is read at {item['offset']} before any write",
                    )
        for edge in successors[index]:
            if edge not in seen:
                frontier.append(edge)
        if item["flow"] in ("ret", "exit"):
            continue


def apply_simulated_region_rewrite(
    body: bytes,
    regions: list[Any],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
    external_entries: frozenset[int] | None = None,
    internal_targets: frozenset[int] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Apply declared permutation+field rewrites, proved by simulation."""
    require_payload_free_declaration(regions, f"{context} simulated-region declaration")
    require(isinstance(body, (bytes, bytearray)) and bool(body), f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(regions, list) and bool(regions), f"{context}: no region is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    flag_live = ia32_relational_flag_liveness(items, successors, context)
    walk_index = {item["offset"]: index for index, item in enumerate(items)}
    decoded = decode_ia32_bijection_body(body, f"{context} liveness", relocations, code_length)
    refined = []
    for entry in decoded:
        if entry["flow"] == "call" and entry["opcode"] == 255:
            entry = {**entry, "read_atoms": frozenset(entry["read_atoms"]) - _IA32_ATOMS_OF["eax"]}
        refined.append(entry)
    live, _succ = _register_bijection_live_sets(refined, f"{context} liveness")
    exit_index = {item["offset"]: index for index, item in enumerate(decoded)}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, item in enumerate(regions):
        item_context = f"{context} region {ordinal}"
        start, end = (item["region_start"], item["region_end"])
        require(
            type(start) is int and type(end) is int and (0 < start < end <= len(body)),
            f"{item_context}: bounds are out of range",
        )
        require(previous_end <= start, f"{item_context}: regions are unsorted or overlapping")
        previous_end = end
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
        pieces = []
        offset = start
        while offset < end:
            length = supported_ia32_instruction_length(body[offset:], item_context)
            require(offset + length <= end, f"{item_context}: an instruction straddles the region")
            pieces.append((offset, bytes(body[offset : offset + length])))
            offset += length
        order = item["target_order"]
        require(
            isinstance(order, list) and sorted(order) == list(range(len(pieces))),
            f"{item_context}: the order is not a permutation of the {len(pieces)} instructions",
        )
        rewrites: dict[int, list[tuple[int, str]]] = {}
        for rewrite in item.get("field_rewrites") or []:
            index, field_ordinal, register = rewrite
            require(
                type(index) is int
                and 0 <= index < len(pieces)
                and (type(field_ordinal) is int)
                and (register in _IA32_REGISTER_NUMBERS)
                and (register not in ("esp", "ebp")),
                f"{item_context}: field rewrite {rewrite} is invalid",
            )
            rewrites.setdefault(index, []).append((field_ordinal, register))
        rebuilt = []
        cursor = start
        moved_offsets = {}
        region_reseat = []
        for _position, source_index in enumerate(order):
            source_offset, encoded = pieces[source_index]
            carried = [
                offs
                for offs in range(source_offset, source_offset + len(encoded))
                if offs in relocation_offsets
            ]
            if carried and cursor != source_offset:
                heads = sorted({offs for offs in carried})
                for offs in heads:
                    if offs - 1 in carried:
                        continue
                    region_reseat.append([offs, cursor + (offs - source_offset)])
            if source_index in rewrites:
                info = decode_ia32_bijection_instruction(
                    body, source_offset, item_context, relocations
                )
                fields = info["fields"]
                mutable = bytearray(encoded)
                for field_ordinal, register in rewrites[source_index]:
                    require(
                        0 <= field_ordinal < len(fields),
                        f"{item_context}: instruction {source_index} has no field {field_ordinal}",
                    )
                    byte_at, shift = fields[field_ordinal]
                    local = byte_at - source_offset
                    mutable[local] = (
                        mutable[local] & ~(7 << shift) | _IA32_REGISTER_NUMBERS[register] << shift
                    )
                encoded = bytes(mutable)
            moved_offsets[pieces[source_index][0]] = cursor
            rebuilt.append(encoded)
            cursor += len(encoded)
        permuted = b"".join(rebuilt)
        require(len(permuted) == end - start, f"{item_context}: the permuted region changed length")
        image[start:end] = permuted
        seed_state = _srr_simulate(body, start, end, f"{item_context} seed")
        image_state = _srr_simulate(bytes(image), start, end, f"{item_context} image")
        for label, seed_part, image_part in (
            ("FP stack", seed_state[1], image_state[1]),
            ("push sequence", seed_state[2], image_state[2]),
        ):
            require(
                seed_part == image_part,
                f"{item_context}: the two versions leave a different {label}",
            )
        seed_slots, image_slots = (seed_state[3], image_state[3])
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
            f"{item_context}: the slots left differing {differing_slots} are not the declared dead set {sorted(dead_slots)}",
        )
        seed_flags, image_flags = (seed_state[4], image_state[4])
        if seed_flags != image_flags:
            require(
                end in walk_index and (not flag_live[walk_index[end]]),
                f"{item_context}: the two versions leave different flag state and a flag is live at the exit",
            )
        differing = sorted(
            name for name in _SIMULATOR_REGS if seed_state[0][name] != image_state[0][name]
        )
        declared_dead = item.get("dead_registers") or []
        require(
            differing == sorted(declared_dead),
            f"{item_context}: the registers left differing {differing} are not the declared dead set {sorted(declared_dead)}",
        )
        require(
            end in exit_index,
            f"{item_context}: the region end is not an instruction boundary of the body",
        )
        live_in = live[exit_index[end]]
        for name in declared_dead:
            overlap = _IA32_ATOMS_OF[name] & live_in
            require(
                not overlap,
                f"{item_context}: {name} is live on the region's exit edge ({sorted(overlap)})",
            )
        for disp in dead_slots:
            _srr_slot_scratch_proof(
                decoded,
                items,
                successors,
                entries,
                end,
                disp,
                f"{item_context} slot {disp:#x}",
                body,
            )
        proved.append(
            {
                "region_start": start,
                "region_end": end,
                "target_order": list(order),
                "field_rewrites": [
                    [index, ordinal, register]
                    for index, pairs in sorted(rewrites.items())
                    for ordinal, register in pairs
                ],
                "dead_registers": sorted(declared_dead),
                "dead_slots": sorted(dead_slots),
                "relocation_reseat": sorted(region_reseat),
                "instruction_moves": sorted(
                    ([old, new] for old, new in moved_offsets.items() if old != new)
                ),
                "rewritten_offsets": sorted(
                    offs for offs in range(start, end) if body[offs] != image[offs]
                ),
            }
        )
    output = bytes(image)
    require(output != body, f"{context}: the image does not move the body")
    changed = {offs for offs in range(len(body)) if body[offs] != output[offs]}
    declared = {offs for region in proved for offs in region["rewritten_offsets"]}
    require(
        changed <= declared, f"{context}: the output changed a byte outside the declared regions"
    )
    return (
        output,
        {
            "kind": SIMULATED_REGION_REWRITE_KIND,
            "regions": proved,
            "relocation_reseat": sorted(
                pair for region in proved for pair in region["relocation_reseat"]
            ),
        },
    )
