"""Classic compiler algorithms: IA-32 dependence facts and stack-frontier projections for instruction scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from reprobit.binary import require

from .compiler_identity import MSVC420_WIN32_I386_TARGET, Msvc420CompilerIdentity
from .register_semantics import (
    _IA32_INERT_SEGMENT_PREFIXES,
    _IA32_OPERAND_SIZE_PREFIX,
    _IA32_REGISTER_NUMBERS,
    IA32_GENERAL_REGISTER_NAMES,
)


def _ia32_schedule_flag_table() -> dict[int, tuple[bool, bool]]:
    table = {}
    for opcode in (136, 137, 138, 139, 141, 198, 199):
        table[opcode] = (False, False)
    for index in range(8):
        table[184 + index] = (False, False)
    for opcode in (3, 11, 35, 43, 49, 51, 56, 57, 58, 59, 128, 129, 131, 132, 133):
        table[opcode] = (False, True)
    for index in range(8):
        table[64 + index] = (False, True)
        table[72 + index] = (False, True)
    for opcode in (26, 27):
        table[opcode] = (True, True)
    table[246] = (False, True)
    for index in range(8):
        table[80 + index] = (False, False)
    table[0x6A] = (False, False)
    return table


_IA32_SCHEDULE_REGISTER_PUSH_OPCODES = frozenset(range(0x50, 0x58))
_IA32_SCHEDULE_STACK_PUSH_OPCODES = _IA32_SCHEDULE_REGISTER_PUSH_OPCODES | frozenset({0x6A})
IA32_SCHEDULE_FLAG_EFFECTS = _ia32_schedule_flag_table()
IA32_STACK_SLOT_BYTES = 4
IA32_SCHEDULE_STACK_FRONTIER_THEOREM = "msvc-4.20-win32-register-push-stack-frontier-v1"
IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM = "msvc-4.20-win32-private-stack-object-frontier-v1"
_IA32_SCHEDULE_STACK_FRONTIER_THEOREMS = frozenset(
    {
        IA32_SCHEDULE_STACK_FRONTIER_THEOREM,
        IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM,
    }
)


def ia32_schedule_stack_delta(body: bytes, item: dict[str, Any], context: str) -> int | None:
    """Return one closed schedule-safe ESP delta, or ``None``.

    The schedule theorem admits only the compiler spellings it can re-encode
    without changing an instruction boundary: unprefixed 32-bit register
    PUSH, unprefixed PUSH imm8, and positive four-byte-aligned ``add esp``.
    Other ESP writers remain ordinary dependence edges and can never gain
    stack-motion authority from this helper.
    """

    start = int(item["offset"])
    raw = body[start : start + int(item["length"])]
    opcode = int(item["opcode"])
    if opcode in _IA32_SCHEDULE_REGISTER_PUSH_OPCODES and len(raw) == 1 and raw[0] == opcode:
        return -IA32_STACK_SLOT_BYTES
    if opcode == 0x6A and len(raw) == 2 and raw[0] == 0x6A:
        return -IA32_STACK_SLOT_BYTES
    if len(raw) == 3 and raw[:2] == b"\x83\xc4":
        amount = int.from_bytes(raw[2:], "little", signed=True)
        return amount if amount > 0 and amount % IA32_STACK_SLOT_BYTES == 0 else None
    return None


def ia32_esp_relative_displacement(body: bytes, item: dict[str, Any]) -> tuple[Any, ...] | None:
    """(byte offset, size, signed value) of an ESP-relative displacement.

    ESP can only be a memory base through a SIB whose base field is 4, so this
    reads the SIB rather than guessing from the r/m field.  It deliberately
    covers `lea` as well as loads and stores: `lea edx, [esp+0x14]` carries an
    ESP displacement that a moved push shifts exactly as it shifts a load's,
    and `lea` has no memory OPERAND for the decoder to report.

    Returns None when the instruction has no ESP displacement, and also when
    it has an ESP base with NO displacement byte (mod 0), which cannot absorb
    an adjustment without growing an encoding -- the caller refuses that.
    """
    encoding = item["encoding"]
    if encoding is None or encoding["mode"] == 3 or encoding["absolute"]:
        return None
    if encoding["sib_at"] is None:
        return None
    sib = body[encoding["sib_at"]]
    base = sib & 7
    if base != _IA32_REGISTER_NUMBERS["esp"]:
        return None
    if encoding["mode"] == 0:
        return ("no_displacement", 0, 0)
    at, size = (encoding["displacement_at"], encoding["displacement_size"])
    if at is None or size == 0:
        return ("no_displacement", 0, 0)
    return (at, size, int.from_bytes(body[at : at + size], "little", signed=True))


def ia32_esp_used_only_as_a_base(body: bytes, item: dict[str, Any]) -> bool:
    """Does this instruction touch ESP ONLY through an adjusted address?

    True when the instruction has a real ESP-relative displacement AND ESP
    appears in no register-direct field.  For such an instruction the stack
    adjustment restores the exact address it names, so a moved push changes
    nothing it observes -- which is what lets the ESP dependence between the
    two be discharged.  `lea edx, [esp+0x14]` qualifies: its displacement is
    adjusted too, so the ADDRESS it computes is preserved.
    """
    found = ia32_esp_relative_displacement(body, item)
    if found is None or found[0] == "no_displacement":
        return False
    encoding = item["encoding"]
    for byte_index, shift in item["fields"]:
        name = IA32_GENERAL_REGISTER_NAMES[body[byte_index] >> shift & 7]
        if name != "esp":
            continue
        is_base = (
            encoding is not None
            and encoding["sib_at"] is not None
            and (byte_index == encoding["sib_at"])
            and (shift == 0)
        )
        if not is_base:
            return False
    return True


def ia32_schedule_stack_adjustments(
    body: bytes,
    inside: list[dict[str, Any]],
    order: list[int],
    context: str,
    *,
    private_stack_object: bool = False,
) -> list[list[Any]]:
    """Obligation 6c: rebase direct ESP operands across exact stack updates.

    An ESP-relative operand moved across a closed stack update must change its
    displacement to keep naming the same address.  The adjustment is derived
    from the permutation and the exact encoded deltas -- never supplied as a
    free parameter -- as

        new_disp(i) = old_disp(i)
                      + source_prefix_esp_delta(i)
                      - target_prefix_esp_delta(i)

    and it is required to be absorbable without changing the instruction's
    encoded length, so a `disp8` that would overflow, or an ESP base with no
    displacement byte at all, REFUSES rather than growing an encoding.

    Returns `[[source index, byte offset, old value, new value], ...]`, sorted.
    """
    updates = [
        (index, delta)
        for index, item in enumerate(inside)
        if (delta := ia32_schedule_stack_delta(body, item, context)) is not None
        if private_stack_object or int(item["opcode"]) in _IA32_SCHEDULE_REGISTER_PUSH_OPCODES
    ]
    if not updates:
        return []
    position = {source: index for index, source in enumerate(order)}
    adjustments = []
    for index, item in enumerate(inside):
        found = ia32_esp_relative_displacement(body, item)
        if found is None:
            continue
        source_delta = sum(delta for update, delta in updates if update < index)
        target_delta = sum(delta for update, delta in updates if position[update] < position[index])
        delta = source_delta - target_delta
        if not delta:
            continue
        at, size, value = found
        require(
            at != "no_displacement",
            f"{context}: the instruction at {item['offset']} has an ESP base with no displacement byte, so it cannot absorb the {delta:+d} stack rebase without growing its encoding",
        )
        updated = value + delta
        low, high = (-(1 << 8 * size - 1), (1 << 8 * size - 1) - 1)
        require(
            low <= updated <= high,
            f"{context}: adjusting the ESP displacement at {item['offset']} by {delta:+d} would overflow its {size}-byte field, which would change the encoding's length",
        )
        adjustments.append([index, at, value, updated])
    return sorted(adjustments)


def ia32_schedule_instruction_facts(instruction: dict[str, Any], context: str) -> dict[str, Any]:
    """Flag effect and memory operand of one window instruction, or refuse."""
    opcode = instruction["opcode"]
    effect = IA32_SCHEDULE_FLAG_EFFECTS.get(opcode)
    require(
        effect is not None,
        f"{context}: opcode 0x{opcode:02x} is outside the instruction-schedule table",
    )
    require(
        instruction["flow"] == "fall",
        f"{context}: a control-transfer instruction is outside the instruction-schedule table",
    )
    memory = instruction["memory"]
    if opcode in _IA32_SCHEDULE_STACK_PUSH_OPCODES:
        require(
            memory is None, f"{context}: a register push also reports an explicit memory operand"
        )
        # PUSH writes one four-byte seat immediately below its incoming ESP.
        # Keeping that implicit store in the ordinary DAG prevents an
        # unproved move across frame, object, or otherwise unknown memory.
        memory = {
            "base": "esp",
            "index": None,
            "scale": 1,
            "displacement": -4,
            "absolute": False,
            "width": 4,
            "read": False,
            "write": True,
            "unknown": False,
        }
    if memory is not None:
        require(
            not memory.get("unknown"),
            f"{context}: a repeated string operation's memory span is an unknown extent and cannot be disambiguated",
        )
        require(
            not memory["absolute"], f"{context}: an absolute memory operand cannot be disambiguated"
        )
        require(
            memory["index"] is None, f"{context}: an indexed memory operand cannot be disambiguated"
        )
        require(
            memory["base"] is not None,
            f"{context}: a memory operand without a base register cannot be disambiguated",
        )
    return {
        "offset": instruction["offset"],
        "length": instruction["length"],
        "opcode": opcode,
        "reads": instruction["reads"],
        "writes": instruction["writes"],
        "reads_flags": effect[0],
        "writes_flags": effect[1],
        "memory": memory,
    }


def ia32_memory_provably_disjoint(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Two memory cells that provably cannot alias.

    The ONLY admitted proof: the same base register, no index on either side,
    neither absolute, and non-overlapping [displacement, displacement+width)
    spans.  Two different base registers are NOT a proof of anything and this
    returns False for them, which makes the pair a dependence edge.
    """
    if left["absolute"] or right["absolute"]:
        return False
    if left["index"] is not None or right["index"] is not None:
        return False
    if left["base"] is None or left["base"] != right["base"]:
        return False
    return (
        left["displacement"] + left["width"] <= right["displacement"]
        or right["displacement"] + right["width"] <= left["displacement"]
    )


def _ia32_schedule_has_segment_override(body: bytes, instruction: dict[str, Any]) -> bool:
    start = int(instruction["offset"])
    raw = body[start : start + int(instruction["length"])]
    for byte in raw:
        if byte in _IA32_INERT_SEGMENT_PREFIXES:
            return True
        if byte == _IA32_OPERAND_SIZE_PREFIX:
            continue
        break
    return False


def _require_ia32_schedule_stack_frontier(
    theorem: object,
    instructions: list[dict[str, Any]],
    facts: list[dict[str, Any]],
    body: bytes | None,
    stack_adjusted: bool,
    context: str,
) -> None:
    """Bind the one narrow compiler-output stack-frontier theorem.

    Win32 has no caller-owned red zone below ESP.  VC 4.20 can therefore move
    a one-byte register PUSH across an otherwise independent explicit memory
    operation: the PUSH's implicit four-byte store consumes fresh stack, not
    an object cell named by the source program.  This is an exact compiler
    theorem opt-in, not the generic IA-32 alias rule or a whole-body pointer
    analysis.  The canonical compiler identity, local source/target taint,
    exact rebase, and dependence-DAG checks below are its complete authority.

    The marker has no parameters.  In particular, it cannot bless immediate,
    memory, prefixed/16-bit, or otherwise differently shaped PUSH encodings,
    and it cannot hide another instruction changing ESP inside the window.
    """
    require(
        type(theorem) is str and theorem == IA32_SCHEDULE_STACK_FRONTIER_THEOREM,
        f"{context}: stack-frontier theorem differs",
    )
    require(body is not None, f"{context}: the stack-frontier theorem needs its body")
    pushes = [
        index
        for index, item in enumerate(facts)
        if item["opcode"] in _IA32_SCHEDULE_STACK_PUSH_OPCODES
    ]
    require(pushes, f"{context}: the stack-frontier theorem names no register PUSH")
    for index, (instruction, fact) in enumerate(zip(instructions, facts, strict=True)):
        if index in pushes:
            offset = instruction["offset"]
            require(
                instruction["length"] == 1
                and 0 <= offset < len(body)
                and body[offset] == fact["opcode"],
                f"{context}: the stack-frontier theorem only admits an unprefixed 32-bit register PUSH",
            )
        else:
            require(
                "esp" not in fact["writes"],
                f"{context}: the non-PUSH instruction at {fact['offset']} changes ESP inside a stack-frontier window",
            )
            if "esp" not in fact["reads"]:
                continue
            direct = ia32_esp_used_only_as_a_base(body, instruction)
            if direct:
                found = ia32_esp_relative_displacement(body, instruction)
                require(
                    stack_adjusted,
                    f"{context}: the ESP-derived address at {fact['offset']} has no exact stack-adjustment declaration",
                )
                require(
                    found is not None and found[0] != "no_displacement" and found[2] >= 0,
                    f"{context}: the ESP-derived address at {fact['offset']} is not a nonnegative directly encoded displacement",
                )
            else:
                require(
                    fact["memory"] is None,
                    f"{context}: the explicit memory instruction at {fact['offset']} uses ESP as more than its directly adjusted base",
                )


def _require_ia32_schedule_stack_frontier_taint(
    instructions: list[dict[str, Any]], facts: list[dict[str, Any]], order: list[int], context: str
) -> None:
    """Refuse an ESP-derived value that becomes an explicit memory address.

    The source and target orders are checked independently.  Register-only
    transformations (including LEA) propagate the taint; a value loaded from
    a direct ESP address does not.  Consuming the value as register-PUSH data
    is permitted, but using it as an explicit base or index is not.
    """
    tainted = {"esp"}
    for position in order:
        fact = facts[position]
        is_push = fact["opcode"] in _IA32_SCHEDULE_STACK_PUSH_OPCODES
        memory = None if is_push else fact["memory"]
        address_registers = set()
        if memory is not None:
            address_registers = {
                name for name in (memory["base"], memory["index"]) if name is not None
            }
            escaped = sorted((address_registers & tainted) - {"esp"})
            require(
                not escaped,
                f"{context}: the ESP-derived register {escaped[:1]} becomes an explicit memory address at {fact['offset']}",
            )
        reads_tainted_value = bool((set(fact["reads"]) & tainted) - address_registers)
        written = set(fact["writes"]) - {"esp"}
        tainted -= written
        if reads_tainted_value:
            tainted |= written


def _ia32_schedule_stack_frontier_pair(
    left: int, right: int, facts: list[dict[str, Any]]
) -> tuple[int, int] | None:
    """Return (PUSH, explicit-memory instruction), if that is this pair."""
    left_push = facts[left]["opcode"] in _IA32_SCHEDULE_STACK_PUSH_OPCODES
    right_push = facts[right]["opcode"] in _IA32_SCHEDULE_STACK_PUSH_OPCODES
    if left_push == right_push:
        return None
    push, explicit = (left, right) if left_push else (right, left)
    memory = facts[explicit]["memory"]
    return (push, explicit) if memory is not None and memory["base"] != "esp" else None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScheduleTheoremContext:
    """One window's strict dependence DAG and the scope a stack theorem projects it in.

    ``instructions`` and ``facts`` are the window's decoded instructions and
    their dependence facts, ``strict_edges`` the DAG measured without any
    theorem, ``order`` the declared target permutation, ``theorem`` the
    declared marker, ``body`` the whole function body the offsets index and
    ``compiler_identity`` the evidence the theorem is scoped to.
    """

    instructions: list[dict[str, Any]]
    facts: list[dict[str, Any]]
    strict_edges: list[list[Any]]
    order: list[int]
    theorem: object
    body: bytes
    compiler_identity: Msvc420CompilerIdentity | None


def _ia32_schedule_stack_frontier_projection(
    theorem_context: ScheduleTheoremContext, stack_adjusted: bool, context: str
) -> tuple[list[list[Any]], dict[str, Any]]:
    """Project only crossed PUSH/non-ESP memory edges from one strict DAG."""
    instructions = theorem_context.instructions
    facts = theorem_context.facts
    strict_edges = theorem_context.strict_edges
    order = theorem_context.order
    theorem = theorem_context.theorem
    body = theorem_context.body
    compiler_identity = theorem_context.compiler_identity
    require(
        type(compiler_identity) is Msvc420CompilerIdentity
        and compiler_identity.target == MSVC420_WIN32_I386_TARGET,
        f"{context}: the stack-frontier theorem requires canonical MSVC 4.20 Win32 i386 compiler evidence",
    )
    _require_ia32_schedule_stack_frontier(
        theorem, instructions, facts, body, stack_adjusted, context
    )
    _require_ia32_schedule_stack_frontier_taint(
        instructions, facts, list(range(len(facts))), f"{context} source order"
    )
    _require_ia32_schedule_stack_frontier_taint(
        instructions, facts, order, f"{context} target order"
    )
    position = {source: target for target, source in enumerate(order)}
    projected = []
    discharged = []
    for left, right, strict_reasons in strict_edges:
        crossed = (left < right) != (position[left] < position[right])
        push_pair = _ia32_schedule_stack_frontier_pair(left, right, facts)
        if not crossed or push_pair is None or "memory" not in strict_reasons:
            projected.append([left, right, list(strict_reasons)])
            continue
        reasons = [reason for reason in strict_reasons if reason != "memory"]
        if reasons:
            projected.append([left, right, reasons])
        push, explicit = push_pair
        memory = facts[explicit]["memory"]
        discharged.append(
            {
                "source_pair": [left, right],
                "push_instruction": push,
                "push_offset": facts[push]["offset"],
                "memory_instruction": explicit,
                "memory_offset": facts[explicit]["offset"],
                "memory": {
                    "base": memory["base"],
                    "displacement": memory["displacement"],
                    "width": memory["width"],
                    "read": memory["read"],
                    "write": memory["write"],
                },
                "crosses_in_target_order": crossed,
            }
        )
    require(discharged, f"{context}: the stack-frontier theorem has no moved PUSH-memory crossing")
    return (
        projected,
        {
            "theorem": theorem,
            "compiler_identity": compiler_identity.proof_receipt(),
            "discharged_memory_pairs": discharged,
        },
    )


def _ia32_schedule_private_stack_object_projection(
    theorem_context: ScheduleTheoremContext, stack_adjustments: list[list[int]], context: str
) -> tuple[list[list[Any]], dict[str, Any]]:
    """Project crossed private-stack/object memory edges for one compiler.

    This phase is deliberately only a candidate projection.  The full-body
    FPO, CFG, paired-debug ``this`` provenance, exact stack addresses, and
    source/target address equality are proved by the boundary checker before
    the schedule can be installed.
    """

    instructions = theorem_context.instructions
    facts = theorem_context.facts
    strict_edges = theorem_context.strict_edges
    order = theorem_context.order
    theorem = theorem_context.theorem
    body = theorem_context.body
    compiler_identity = theorem_context.compiler_identity
    require(
        theorem == IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM,
        f"{context}: private-stack/object theorem differs",
    )
    require(
        type(compiler_identity) is Msvc420CompilerIdentity
        and compiler_identity.target == MSVC420_WIN32_I386_TARGET,
        f"{context}: the private-stack/object theorem requires canonical MSVC 4.20 Win32 i386 compiler evidence",
    )
    for instruction, fact in zip(instructions, facts, strict=True):
        require(
            instruction["flow"] == "fall",
            f"{context}: the private-stack/object window contains a control transfer",
        )
        if "esp" in fact["writes"]:
            require(
                ia32_schedule_stack_delta(body, instruction, context) is not None,
                f"{context}: the private-stack/object window has an unknown ESP update at {fact['offset']}",
            )

    position = {source: target for target, source in enumerate(order)}
    projected: list[list[Any]] = []
    discharged: list[dict[str, object]] = []
    for left, right, strict_reasons in strict_edges:
        crossed = (left < right) != (position[left] < position[right])
        left_memory = facts[left]["memory"]
        right_memory = facts[right]["memory"]
        stack_object_pair = (
            left_memory is not None
            and right_memory is not None
            and ((left_memory["base"] == "esp") != (right_memory["base"] == "esp"))
        )
        if not crossed or not stack_object_pair or "memory" not in strict_reasons:
            projected.append([left, right, list(strict_reasons)])
            continue
        stack = left if left_memory["base"] == "esp" else right
        object_index = right if stack == left else left
        object_memory = facts[object_index]["memory"]
        require(
            object_memory is not None
            and object_memory["base"] not in (None, "esp")
            and object_memory["index"] is None
            and not object_memory["absolute"],
            f"{context}: a projected object operand has no closed base",
        )
        retained_reasons = [reason for reason in strict_reasons if reason != "memory"]
        if retained_reasons:
            projected.append([left, right, retained_reasons])
        discharged.append(
            {
                "source_pair": [left, right],
                "stack_instruction": stack,
                "stack_offset": facts[stack]["offset"],
                "object_instruction": object_index,
                "object_offset": facts[object_index]["offset"],
                "crosses_in_target_order": True,
            }
        )
    require(
        discharged,
        f"{context}: the private-stack/object theorem discharges no moved memory crossing",
    )
    stack_dependency_rebases: list[dict[str, object]] = []
    for adjustment in stack_adjustments:
        operand, _at, old, new = adjustment
        contribution = 0
        for stack, instruction in enumerate(instructions):
            delta = ia32_schedule_stack_delta(body, instruction, context)
            if delta is None or stack == operand:
                continue
            crossed = (stack < operand) != (position[stack] < position[operand])
            if not crossed:
                continue
            signed = delta if stack < operand else -delta
            contribution += signed
            stack_dependency_rebases.append(
                {
                    "source_pair": sorted([stack, operand]),
                    "reason": "register_raw" if stack < operand else "register_war",
                    "stack_instruction": stack,
                    "operand_instruction": operand,
                    "stack_delta": delta,
                    "adjustment": list(adjustment),
                }
            )
        require(
            contribution == new - old,
            f"{context}: exact stack dependency crossings do not derive "
            f"displacement rebase {adjustment}",
        )
    return projected, {
        "theorem": theorem,
        "compiler_identity": compiler_identity.proof_receipt(),
        "discharged_memory_pairs": discharged,
        "discharged_esp_dependencies": stack_dependency_rebases,
    }


def ia32_schedule_dependence_edges(
    instructions: list[dict[str, Any]],
    context: str,
    body: bytes | None = None,
    stack_adjusted: bool = False,
    *,
    private_stack_object: bool = False,
    adjusted_instructions: frozenset[int] | None = None,
) -> tuple[list[dict[str, Any]], list[list[Any]]]:
    """The window's dependence DAG (obligation 4).

    Every ordered pair carries an edge unless it is proved independent on
    registers, on flags AND on memory.  The memory proof is the conservative
    one above, and a base register written anywhere inside the window
    invalidates every displacement comparison against it, so that is refused
    outright rather than reasoned around.

    `stack_adjusted` says the caller has DECLARED the ESP-displacement
    adjustments a moved push forces (obligation 6c).  Without it a push in the
    window is refused exactly as before, so every landed entry is unaffected.

    This always returns the strict DAG.  A compiler-scoped stack-frontier
    marker is projected later, once the target order is known, so only memory
    reasons for pairs that actually cross can ever be discharged.
    """
    facts = [
        ia32_schedule_instruction_facts(item, f"{context} at {item['offset']}")
        for item in instructions
    ]
    if body is not None:
        segment_overrides = sorted(
            int(item["offset"])
            for item in instructions
            if item.get("memory") is not None and _ia32_schedule_has_segment_override(body, item)
        )
        require(
            not segment_overrides,
            f"{context}: an explicit memory instruction has a segment override at "
            f"{segment_overrides[:1]}",
        )
    if any(item["opcode"] in _IA32_SCHEDULE_STACK_PUSH_OPCODES for item in facts):
        offending = sorted(
            item["offset"]
            for item in facts
            if item["opcode"] not in _IA32_SCHEDULE_STACK_PUSH_OPCODES
            and item["memory"] is not None
            and item["memory"]["base"] == "esp"
        )
        require(
            not offending or stack_adjusted,
            f"{context}: a push shares the window with the esp-relative memory operand at {offending[:1]}, whose address the push's own esp delta would move",
        )
        if stack_adjusted:
            require(body is not None, f"{context}: a stack-adjusted window needs its body")
            for item in instructions:
                found = ia32_esp_relative_displacement(body, item)
                if found is None or found[0] == "no_displacement":
                    continue
                require(
                    found[2] >= 0,
                    f"{context}: the ESP displacement {found[2]} at {item['offset']} is below ESP, where a push in this window writes, so disjointness does not hold",
                )
    written = set()
    for item in facts:
        written |= set(item["writes"])
    esp_compensated = [
        stack_adjusted
        and body is not None
        and ia32_esp_used_only_as_a_base(body, item)
        and (adjusted_instructions is None or index in adjusted_instructions)
        for index, item in enumerate(instructions)
    ]
    stack_deltas = [
        (
            ia32_schedule_stack_delta(body, item, context)
            if body is not None
            and (
                private_stack_object or int(item["opcode"]) in _IA32_SCHEDULE_REGISTER_PUSH_OPCODES
            )
            else None
        )
        for item in instructions
    ]
    is_stack_operation = [delta is not None for delta in stack_deltas]
    if stack_adjusted:
        require(body is not None, f"{context}: a stack-adjusted window needs its body")
    edges = []
    for left in range(len(facts)):
        for right in range(left + 1, len(facts)):
            first, second = (facts[left], facts[right])
            reasons = []
            discharged = (
                frozenset({"esp"})
                if (is_stack_operation[left] and esp_compensated[right])
                or (is_stack_operation[right] and esp_compensated[left])
                else frozenset()
            )
            first_reads = first["reads"] - discharged
            first_writes = first["writes"] - discharged
            second_reads = second["reads"] - discharged
            second_writes = second["writes"] - discharged
            if first_writes & second_reads:
                reasons.append("register_raw")
            if first_reads & second_writes:
                reasons.append("register_war")
            if first_writes & second_writes:
                reasons.append("register_waw")
            if first["writes_flags"] and second["reads_flags"]:
                reasons.append("flags_raw")
            if first["reads_flags"] and second["writes_flags"]:
                reasons.append("flags_war")
            if first["writes_flags"] and second["writes_flags"]:
                reasons.append("flags_waw")
            one, two = (first["memory"], second["memory"])
            if one is not None and two is not None and (one["write"] or two["write"]):
                base_is_written = one["base"] in written or two["base"] in written
                canonical_disjoint = False
                if (
                    stack_adjusted
                    and body is not None
                    and (one["base"] == "esp" == two["base"])
                    and all(
                        facts[k]["opcode"]
                        in (
                            _IA32_SCHEDULE_STACK_PUSH_OPCODES
                            if private_stack_object
                            else _IA32_SCHEDULE_REGISTER_PUSH_OPCODES
                        )
                        or "esp" not in facts[k]["writes"]
                        for k in range(len(facts))
                    )
                ):

                    def _canonical(mem, index):
                        depth = sum(
                            1
                            for k in range(index)
                            if facts[k]["opcode"]
                            in (
                                _IA32_SCHEDULE_STACK_PUSH_OPCODES
                                if private_stack_object
                                else _IA32_SCHEDULE_REGISTER_PUSH_OPCODES
                            )
                        )
                        adjusted = dict(mem)
                        adjusted["displacement"] = mem["displacement"] - 4 * depth
                        return adjusted

                    canonical_disjoint = ia32_memory_provably_disjoint(
                        _canonical(one, left), _canonical(two, right)
                    )
                if not canonical_disjoint and (
                    base_is_written or not ia32_memory_provably_disjoint(one, two)
                ):
                    reasons.append("memory")
            if reasons:
                edges.append([left, right, sorted(reasons)])
    return (facts, edges)
