"""Classic compiler algorithms: IA-32 control flow, reaching definitions and register webs."""

from __future__ import annotations

from typing import Any, cast

from reprobit.binary import require


def ia32_web_control_flow(
    instructions: list[dict[str, Any]],
    context: str,
    internal_targets: frozenset[int] | None = None,
    entry_offsets: frozenset[int] | None = None,
) -> list[list[int]]:
    """The body's complete control-flow graph, or a refusal.

    Successors are the fall-through and the decoded branch target.  A computed
    jump has no decodable successors, so it is admitted only against the
    relocated in-body target set, whose in-code members become its successors.
    `ret` and a relocated tail-jump out of the COMDAT have none.  Every
    instruction must then be reachable from an entry: an unreachable block
    would make every reaching-definition statement about it vacuous.  The
    entries are the function head plus `entry_offsets` -- on a C++ EH function
    the unwind funclet heads the `.xdata$x` table hands to the runtime, a
    DERIVED set (`relational_form_external_entries`), never an author's claim.
    """
    index_of = {item["offset"]: index for index, item in enumerate(instructions)}
    successors = []
    for index, item in enumerate(instructions):
        edges = []
        if item["flow"] in ("fall", "jcc", "call"):
            if index + 1 < len(instructions):
                edges.append(index + 1)
            else:
                require(item["flow"] != "fall", f"{context}: body falls off its end")
        if item["flow"] in ("jcc", "jmp") and item["target"] is not None:
            edges.append(index_of[item["target"]])
        if item["indirect"]:
            require(
                internal_targets is not None,
                f"{context}: a computed jump at {item['offset']} requires the relocated in-body target set",
            )
            edges.extend(
                index_of[target]
                for target in sorted(cast(frozenset[int], internal_targets))
                if target in index_of
            )
        successors.append(sorted(set(edges)))
    seen = set()
    stack = [0]
    if entry_offsets:
        stack.extend(index_of[offset] for offset in sorted(entry_offsets) if offset in index_of)
    while stack:
        index = stack.pop()
        if index in seen:
            continue
        seen.add(index)
        stack.extend(successors[index])
    unreachable = sorted(
        instructions[index]["offset"] for index in range(len(instructions)) if index not in seen
    )
    require(
        not unreachable,
        f"{context}: the instruction at {unreachable[:1]} is unreachable from the entry, so the control-flow graph is incomplete",
    )
    return successors


def _ia32_web_predecessors(successors: list[list[int]]) -> list[list[int]]:
    predecessors: list[list[int]] = [[] for _ in successors]
    for index, edges in enumerate(successors):
        for edge in edges:
            predecessors[edge].append(index)
    return predecessors


def _ia32_web_reached_uses(
    instructions: list[dict[str, Any]],
    successors: list[list[int]],
    definitions: list[int],
    atoms: frozenset[str],
    context: str,
) -> tuple[set[Any], set[Any]]:
    """Every reader of `atoms` a definition reaches, and the range between.

    Traversal stops at a full redefinition.  A PARTIAL redefinition inside the
    range refuses: the value would be half the web's and half something else,
    which no rename can express.
    """
    reached = set()
    interior = set()
    stack = [edge for index in definitions for edge in successors[index]]
    while stack:
        index = stack.pop()
        if index in interior:
            continue
        interior.add(index)
        item = instructions[index]
        if atoms & item["read_atoms"]:
            reached.add(index)
        overlap = atoms & item["write_atoms"]
        if overlap:
            require(
                atoms <= item["write_atoms"],
                f"{context}: the instruction at {item['offset']} partially redefines the web's register inside its range",
            )
            continue
        stack.extend(successors[index])
    return (reached, interior)


def _ia32_web_reaching_definitions(
    instructions: list[dict[str, Any]],
    predecessors: list[list[int]],
    uses: list[int],
    atoms: frozenset[str],
    context: str,
) -> tuple[set[Any], set[Any]]:
    """Every definition of `atoms` that reaches one of `uses`.

    Also returns the backward cone -- every instruction that can reach a use
    without passing a redefinition.  Intersected with the forward cone that
    is the web's LIVE RANGE, and nothing outside it is the coalesce's concern.
    """
    reaching = set()
    seen = set()
    stack = list(uses)
    while stack:
        index = stack.pop()
        if index in seen:
            continue
        seen.add(index)
        require(
            index != 0 or index in uses,
            f"{context}: the function's entry reaches a declared use, so the web's value is not defined on every path",
        )
        for previous in predecessors[index]:
            item = instructions[previous]
            if atoms & item["write_atoms"]:
                require(
                    atoms <= item["write_atoms"],
                    f"{context}: the instruction at {item['offset']} partially defines the web's register",
                )
                reaching.add(previous)
            else:
                stack.append(previous)
        require(
            bool(predecessors[index]) or index in uses,
            f"{context}: the instruction at {instructions[index]['offset']} has no predecessor, so a use is reached by no definition",
        )
    return (reaching, seen)


def _ia32_web_membership(web: dict[str, Any], role: str, context: str) -> tuple[Any, ...]:
    """Split a web's membership list into offsets and their field scopes.

    An entry is an instruction offset, or a two-element `[offset, ordinal]`
    pair naming WHICH register field of that instruction belongs to the web.
    Both the manifest schema and the composer read membership through here,
    so a declaration means the same thing on both sides -- the composer is
    handed the RAW manifest dict, and a normalizer that lived only in the
    schema would be silently bypassed.
    """
    entries = web.get(role)
    require(isinstance(entries, list) and bool(entries), f"{context}.{role} is invalid")
    offsets = []
    scopes = {}
    for item in cast(list[Any], entries):
        if type(item) is int:
            offsets.append(item)
            continue
        require(
            isinstance(item, list)
            and len(item) == 2
            and (type(item[0]) is int)
            and (type(item[1]) is int)
            and (item[1] >= 0),
            f"{context}.{role} entry is invalid",
        )
        require(item[0] not in scopes, f"{context}.{role} scopes {item[0]} twice")
        scopes[item[0]] = item[1]
        offsets.append(item[0])
    declared = web.get("field_scopes") or {}
    for offset, ordinal in declared.items():
        offset = int(offset)
        require(
            offset not in scopes or scopes[offset] == ordinal,
            f"{context}.{role} scopes {offset} twice",
        )
        if offset in offsets:
            scopes[offset] = ordinal
    return (offsets, scopes)
