"""Shared IA-32 facts for the two stack-frontier proof families."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from reprobit.binary import require

REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
MAX_AFFINES = 8
MAX_INSTRUCTIONS = 4096

Affine = dict[int, frozenset[int]]


@dataclass(frozen=True)
class AffineState:
    registers: dict[str, Affine]
    slots: dict[int, Affine]


def stack_change(body: bytes, item: dict[str, Any]) -> int | None:
    """Return an exact explicit ESP delta, or None for an unresolved write."""
    if "esp" not in item["writes"]:
        return 0
    start = int(item["offset"])
    raw = body[start : start + int(item["length"])]
    opcode = int(item["opcode"])
    if opcode in {*range(0x50, 0x58), 0x68, 0x6A}:
        return -4
    if opcode in range(0x58, 0x60):
        return None if opcode == 0x5C else 4
    if len(raw) == 3 and raw[:2] in (b"\x83\xec", b"\x83\xc4"):
        amount = int.from_bytes(raw[2:], "little", signed=True)
        return None if amount <= 0 else amount if raw[1] == 0xC4 else -amount
    if len(raw) == 6 and raw[:2] in (b"\x81\xec", b"\x81\xc4"):
        amount = int.from_bytes(raw[2:], "little", signed=True)
        return None if amount <= 0 else amount if raw[1] == 0xC4 else -amount
    return None


def msvc420_direct_cdecl_call(
    body: bytes,
    instructions: list[dict[str, Any]],
    relocations: dict[int, dict[str, object]],
    call: int,
) -> dict[str, object] | None:
    """Recognize only direct, relocation-bound VC 4.20 cdecl spellings."""
    item = instructions[call]
    start = int(item["offset"])
    if item["flow"] != "call" or int(item["opcode"]) != 0xE8 or int(item["length"]) != 5:
        return None
    row = relocations.get(start + 1)
    if row is None or row.get("width") != 4:
        return None
    if sorted(offset for offset in relocations if start <= offset < start + 5) != [start + 1]:
        return None
    target = row.get("target")
    if not isinstance(target, str):
        return None
    spelling: str | None = None
    if (
        len(target) > 1
        and target[0] == "_"
        and (target[1].isalpha() or target[1] == "_")
        and all(character.isalnum() or character == "_" for character in target[1:])
    ):
        spelling = "c-leading-underscore"
    elif target.startswith("?") and target.endswith("Z"):
        classes = [
            target[index + 2 : index + 4]
            for index in range(len(target) - 3)
            if target[index : index + 2] == "@@"
        ]
        if target.startswith("??"):
            operator_end = target.find("@", 2)
            if operator_end >= 0:
                classes.append(target[operator_end + 1 : operator_end + 3])
        accepted = [value for value in classes if value in ("YA", "CA", "KA", "SA")]
        if len(accepted) == 1:
            spelling = "msvc-global-or-static-member"
    if spelling is None:
        return None
    return {
        "theorem": "msvc420-direct-cdecl-relocation-v1",
        "call_offset": start,
        "relocation_offset": start + 1,
        "relocation_width": 4,
        "target": target,
        "spelling": spelling,
    }


def frame_floor(
    body: bytes,
    instructions: list[dict[str, Any]],
    context: str,
    canonical_eh_setup: bool = False,
) -> tuple[int, int]:
    """Measure the fixed-frame floor immediately before the first call."""
    depth = 0
    allocation: int | None = None
    saved_nonvolatiles: set[int] = set()
    for index, item in enumerate(instructions):
        require(
            item["flow"] not in ("jcc", "jmp", "ret", "exit"),
            f"{context}: control flow precedes the fixed-frame floor",
        )
        if item["flow"] == "call":
            require(
                index > 0 and depth <= -16 and allocation is not None,
                f"{context}: no fixed compiler frame precedes the first call",
            )
            return depth, index
        change = stack_change(body, item)
        require(
            change is not None,
            f"{context}: the prologue has an unknown ESP update at {item['offset']}",
        )
        assert change is not None
        if change < 0:
            start = int(item["offset"])
            raw = body[start : start + int(item["length"])]
            fixed_allocation = (len(raw) == 3 and raw[:2] == b"\x83\xec" and raw[2] > 0) or (
                len(raw) == 6
                and raw[:2] == b"\x81\xec"
                and int.from_bytes(raw[2:], "little", signed=True) > 0
            )
            if fixed_allocation:
                require(
                    allocation is None,
                    f"{context}: the prologue has more than one fixed ESP allocation",
                )
                allocation = index
            elif allocation is None:
                require(
                    canonical_eh_setup and index < 7,
                    f"{context}: a PUSH precedes the fixed ESP allocation at {item['offset']}",
                )
            elif allocation is not None:
                opcode = int(item["opcode"])
                require(
                    int(item["length"]) == 1
                    and opcode in (0x53, 0x55, 0x56, 0x57)
                    and body[start] == opcode
                    and opcode not in saved_nonvolatiles,
                    f"{context}: a non-frame PUSH precedes the first call at {item['offset']}",
                )
                saved_nonvolatiles.add(opcode)
        elif change > 0 and allocation is not None:
            require(
                False,
                f"{context}: the fixed frame changes again before the first call "
                f"at {item['offset']}",
            )
        depth += change
        require(depth <= 0, f"{context}: the prologue raises ESP above its entry value")
    raise ValueError(f"{context}: the fixed-frame proof found no call")


def predecessors(successors: list[list[int]]) -> list[list[int]]:
    result: list[list[int]] = [[] for _ in successors]
    for source, targets in enumerate(successors):
        for target in targets:
            result[target].append(source)
    return result


def ancestors(predecessor_rows: list[list[int]], sinks: set[int]) -> set[int]:
    result: set[int] = set()
    work = list(sinks)
    while work:
        current = work.pop()
        if current in result:
            continue
        result.add(current)
        work.extend(predecessor_rows[current])
    return result


def address_form(
    body: bytes, item: dict[str, Any]
) -> tuple[str | None, str | None, int, int] | None:
    """Decode a non-FS/GS effective address into base/index/scale/displacement."""
    raw = body[int(item["offset"]) : int(item["offset"]) + int(item["length"])]
    cursor = 0
    while cursor < len(raw) and raw[cursor] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66):
        if raw[cursor] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):
            return None
        cursor += 1
    encoding = item.get("encoding")
    if not isinstance(encoding, dict) or encoding["mode"] == 3 or encoding["absolute"]:
        return None
    base: str | None
    indexed: str | None = None
    scale = 1
    sib_at = encoding["sib_at"]
    if sib_at is None:
        base = REGISTERS[int(encoding["rm"])]
    else:
        sib = body[int(sib_at)]
        base = None if encoding["mode"] == 0 and (sib & 7) == 5 else REGISTERS[sib & 7]
        indexed = None if (sib >> 3 & 7) == 4 else REGISTERS[sib >> 3 & 7]
        scale = 1 << (sib >> 6)
    displacement_at = encoding["displacement_at"]
    size = int(encoding["displacement_size"])
    displacement = (
        0
        if displacement_at is None
        else int.from_bytes(
            body[int(displacement_at) : int(displacement_at) + size], "little", signed=True
        )
    )
    return base, indexed, scale, displacement
