"""Local fixed-EBP stack-frontier proof for canonical MSVC EH functions."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require

from .stack_frontier_foundation import (
    Affine,
    address_form,
    msvc420_direct_cdecl_call,
    stack_change,
)


def derive_strict_eh_stack_ceiling(
    body: bytes,
    instructions: list[dict[str, Any]],
    successors: list[list[int]],
    ancestor_set: set[int],
    floor: int,
    first_call: int,
    relocations: dict[int, dict[str, object]],
    context: str,
) -> tuple[list[int | None], list[dict[str, object]]]:
    """Derive an ESP upper bound on every path reaching an EH window.

    A relocation-bound cdecl call retains its lower pre-call bound because
    cdecl is caller-clean.  Otherwise canonical Win32 compiler output may
    restore its own argument PUSHes, but never bytes in the caller's fixed
    frame, so its conservative ceiling is the fixed-frame floor.  Any later
    explicit update that could raise ESP above that floor refuses the proof.
    """
    ceilings: list[int | None] = [None] * len(instructions)
    receipts: dict[int, dict[str, object]] = {}
    ceilings[0] = 0
    work = [0]
    rounds = 0
    while work:
        rounds += 1
        require(
            rounds <= len(instructions) * 32,
            f"{context}: strict-frame stack ceiling does not converge",
        )
        index = work.pop()
        if index not in ancestor_set:
            continue
        ceiling = ceilings[index]
        require(ceiling is not None, f"{context}: an ancestor has no ESP ceiling")
        assert ceiling is not None
        item = instructions[index]
        change = stack_change(body, item)
        require(change is not None, f"{context}: unknown ESP update at {item['offset']}")
        assert change is not None
        outgoing = ceiling + change
        if item["flow"] == "call" and index >= first_call and outgoing < floor:
            pending = floor - outgoing
            cdecl = msvc420_direct_cdecl_call(body, instructions, relocations, index)
            if cdecl is None:
                receipts[index] = {
                    "offset": int(item["offset"]),
                    "kind": "callee-return-floor-ceiling",
                    "incoming_ceiling": outgoing,
                    "outgoing_ceiling": floor,
                }
                outgoing = floor
            else:
                receipts[index] = {
                    "offset": int(item["offset"]),
                    "kind": "direct-cdecl-caller-clean",
                    "incoming_ceiling": outgoing,
                    "outgoing_ceiling": outgoing,
                    "pending_bytes": pending,
                    "cdecl_call": cdecl,
                }
        if index >= first_call:
            require(
                outgoing <= floor,
                f"{context}: ESP can rise above the fixed-frame floor at {item['offset']}",
            )
        for target in successors[index]:
            if target not in ancestor_set:
                continue
            previous = ceilings[target]
            updated = outgoing if previous is None else max(previous, outgoing)
            if updated != previous:
                ceilings[target] = updated
                work.append(target)
    missing = sorted(
        int(instructions[index]["offset"]) for index in ancestor_set if ceilings[index] is None
    )
    require(not missing, f"{context}: no entry-derived ESP ceiling reaches {missing[:1]}")
    return ceilings, [receipts[index] for index in sorted(receipts)]


def is_strict_eh_frame(body: bytes, instructions: list[dict[str, Any]]) -> bool:
    if len(instructions) < 7:
        return False
    raw = [
        body[int(item["offset"]) : int(item["offset"]) + int(item["length"])]
        for item in instructions[:7]
    ]
    return (
        raw[0] == b"\x64\xa1\x00\x00\x00\x00"
        and raw[1:4] == [b"\x55", b"\x8b\xec", b"\x6a\xff"]
        and len(raw[4]) == 5
        and raw[4][0] == 0x68
        and raw[5:] == [b"\x50", b"\x64\x89\x25\x00\x00\x00\x00"]
    )


def require_local_strict_eh_window(
    instructions: list[dict[str, Any]],
    predecessor_rows: list[list[int]],
    ancestor_set: set[int],
    window: list[int],
    start: int,
    context: str,
) -> dict[str, object]:
    """Bind a schedule window to one canonical fixed-frame control entry."""
    incoming = predecessor_rows[window[0]]
    require(
        len(incoming) == 1,
        f"{context}: the strict-frame window has an ambiguous control entry",
    )
    entry = instructions[incoming[0]]
    require(
        entry["flow"] in ("jcc", "jmp")
        and entry["target"] == start
        and "esp" not in entry["reads"]
        and "esp" not in entry["writes"],
        f"{context}: the strict-frame window entry is not a compiler control boundary",
    )
    require(
        all("ebp" not in instructions[index]["writes"] for index in ancestor_set if index > 2),
        f"{context}: EBP changes after the strict EH frame is established",
    )
    require(
        all(
            item["flow"] == "fall"
            and ("esp" not in item["writes"] or int(item["opcode"]) in range(0x50, 0x58))
            for item in (instructions[index] for index in window)
        ),
        f"{context}: the strict-frame window contains a nonlocal observer",
    )
    return {
        "predecessor_offset": int(entry["offset"]),
        "predecessor_flow": entry["flow"],
        "target": start,
        "ebp_from_entry_esp": -4,
    }


def strict_ebp_address(
    body: bytes, instructions: list[dict[str, Any]], index: int
) -> Affine | None:
    form = address_form(body, instructions[index])
    return (
        {-4 + form[3]: frozenset({int(instructions[2]["offset"])})}
        if form is not None and form[:3] == ("ebp", None, 1)
        else None
    )
