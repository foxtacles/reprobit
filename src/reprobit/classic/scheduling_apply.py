"""Classic compiler algorithms: applying an instruction schedule to a function body."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.ia32_decode import supported_ia32_instruction_length

from .compiler_identity import MSVC420_WIN32_I386_TARGET, Msvc420CompilerIdentity
from .foundation import (
    RelocationView,
    require_payload_free_declaration,
)
from .register_semantics import (
    _IA32_INERT_SEGMENT_PREFIXES,
    _IA32_OPERAND_SIZE_PREFIX,
    decode_ia32_bijection_body,
    decode_ia32_bijection_instruction,
)
from .scheduling_dependence import (
    _IA32_SCHEDULE_STACK_FRONTIER_THEOREMS,
    IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM,
    IA32_SCHEDULE_STACK_FRONTIER_THEOREM,
    ScheduleTheoremContext,
    _ia32_schedule_private_stack_object_projection,
    _ia32_schedule_stack_frontier_projection,
    ia32_esp_relative_displacement,
    ia32_schedule_dependence_edges,
    ia32_schedule_stack_adjustments,
)
from .scheduling_webs import ia32_web_control_flow
from .stack_frontier_object import (
    DebugEvidence,
    StackObjectQuery,
    derive_private_stack_object_boundary,
)


def require_topological_instruction_order(
    count: int, edges: list[list[Any]], order: list[int], context: str
) -> None:
    """The declared order must respect every edge of the DAG."""
    require(
        sorted(order) == list(range(count)),
        f"{context}: the target order is not a permutation of the window",
    )
    position = {source: index for index, source in enumerate(order)}
    for left, right, reasons in edges:
        require(
            position[left] < position[right],
            f"{context}: the target order moves instruction {right} before {left}, which the dependence DAG forbids ({', '.join(reasons)})",
        )
    require(
        order != list(range(count)), f"{context}: the declared order does not reorder the window"
    )


_IA32_SCHEDULE_INTERIOR_PREFIXES = _IA32_INERT_SEGMENT_PREFIXES | frozenset(
    {_IA32_OPERAND_SIZE_PREFIX}
)
_IA32_SCHEDULE_TERMINAL_OPCODES = frozenset({194, 195, 202, 203, 233, 235})


def ia32_schedule_body_walk(
    body: bytes,
    relocations: dict[int, Any] | None,
    context: str,
    code_length: int | None = None,
    internal_targets: frozenset[int] | None = None,
) -> tuple[list[tuple[int, int]], set[Any]]:
    """Boundaries and interior branch targets of a whole COMDAT body."""
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    relocations = relocations or {}
    limit = len(body) if code_length is None else code_length
    require(
        isinstance(limit, int) and (not isinstance(limit, bool)) and (0 < limit <= len(body)),
        f"{context}: code length is out of range",
    )
    code = body[:limit]
    spans = []
    targets = set()
    computed = []
    offset = 0
    while offset < len(code):
        length = supported_ia32_instruction_length(code[offset:], f"{context} at {offset}")
        spans.append((offset, length))
        cursor = offset
        while code[cursor] in _IA32_SCHEDULE_INTERIOR_PREFIXES:
            cursor += 1
            require(
                cursor < offset + length, f"{context}: instruction at {offset} is only prefixes"
            )
        opcode = code[cursor]
        width = 0
        if opcode in range(112, 128) or opcode in (235, 224, 225, 226, 227):
            width = 1
        elif opcode in (233, 232) or (
            opcode == 15 and cursor + 1 < offset + length and (128 <= code[cursor + 1] <= 143)
        ):
            width = 4
        elif opcode == 255:
            require(cursor + 1 < offset + length, f"{context}: FF form at {offset} lacks its ModRM")
            extension = code[cursor + 1] >> 3 & 7
            require(
                extension not in (3, 5),
                f"{context}: a far jump at {offset} makes the window's entry set unknowable",
            )
            if extension == 4:
                computed.append(offset)
        if width:
            displacement_at = offset + length - width
            row = relocations.get(displacement_at)
            if row is None or row.get("width") != width:
                relative = int.from_bytes(
                    code[displacement_at : offset + length], "little", signed=True
                )
                targets.add(offset + length + relative)
        offset += length
    require(offset == len(code), f"{context}: body does not decode to exhaustion")
    starts = {start for start, _ in spans}
    for target in sorted(targets):
        require(
            target in starts,
            f"{context}: a branch targets {target}, which is not an instruction boundary of this body",
        )
    if limit < len(body):
        last_at, _last_length = spans[-1]
        cursor = last_at
        while code[cursor] in _IA32_SCHEDULE_INTERIOR_PREFIXES:
            cursor += 1
        opcode = code[cursor]
        terminal = opcode in _IA32_SCHEDULE_TERMINAL_OPCODES
        if opcode == 255:
            terminal = code[cursor + 1] >> 3 & 7 == 4
        require(terminal, f"{context}: code falls through into the body's data tail")
    if computed:
        require(
            internal_targets is not None,
            f"{context}: a computed jump at {computed[0]} makes the window's entry set unknowable without the relocated in-body target set",
        )
        stray = sorted(
            target for target in internal_targets if target < limit and target not in starts
        )
        require(
            not stray,
            f"{context}: the relocated in-body target {stray[:1]} is not an instruction boundary of this body",
        )
        targets |= set(internal_targets)
    return (spans, targets)


def apply_instruction_schedule(
    body: bytes,
    windows: list[dict[str, Any]],
    relocation_offsets: frozenset[int],
    context: str,
    *,
    view: RelocationView | None = None,
    external_entries: frozenset[int] | None = None,
    compiler_identity: Msvc420CompilerIdentity | None = None,
    debug_evidence: DebugEvidence | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Reorder each declared window under a proved dependence DAG.

    Obligations 2 through 6 are checked here, and the result is re-decoded to
    exhaustion so that every claim about the image is measured on the image.

    `view.code_length` pins where a switch-table body's code ends; the tail
    is never decoded, never inside a window and never rewritten.  A window
    under the private-stack/object theorem consumes `debug_evidence`; without
    it the boundary proof refuses.
    """
    if view is None:
        view = RelocationView()
    relocations = view.relocations
    code_length = view.code_length
    internal_targets = view.internal_targets
    require_payload_free_declaration(windows, f"{context} instruction schedule declaration")
    frontier_markers = [
        window.get("stack_frontier_theorem")
        for window in windows
        if window.get("stack_frontier_theorem") is not None
    ]
    if frontier_markers:
        require(
            all(
                type(marker) is str and marker in _IA32_SCHEDULE_STACK_FRONTIER_THEOREMS
                for marker in frontier_markers
            ),
            f"{context}: stack_frontier_theorem differs from the supported exact marker",
        )
        require(
            type(compiler_identity) is Msvc420CompilerIdentity
            and compiler_identity.target == MSVC420_WIN32_I386_TARGET,
            f"{context}: the stack-frontier theorem requires canonical MSVC 4.20 Win32 i386 compiler evidence",
        )
    body = bytes(body)
    limit = len(body) if code_length is None else code_length
    spans, targets = ia32_schedule_body_walk(
        body, relocations, context, code_length, internal_targets
    )
    instructions = [{"offset": start, "length": length} for start, length in spans]
    boundaries = {start for start, _ in spans}
    boundaries.add(limit)
    frontier_instructions = None
    frontier_successors = None
    if IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM in frontier_markers:
        frontier_instructions = decode_ia32_bijection_body(
            body, f"{context} private-stack/object body", relocations, code_length
        )
        frontier_successors = ia32_web_control_flow(
            frontier_instructions,
            f"{context} private-stack/object flow",
            internal_targets,
            external_entries,
        )
    image = bytearray(body)
    detail = []
    previous_end = 0
    for index, window in enumerate(windows):
        window_context = f"{context} window {index}"
        start, end = (window["start"], window["end"])
        require(start >= previous_end, f"{window_context}: windows are unsorted or overlapping")
        previous_end = end
        require(end <= limit, f"{window_context}: the window reaches into the body's data tail")
        require(
            start in boundaries and end in boundaries and (start < end),
            f"{window_context}: the window does not span whole instructions",
        )
        inside = [item for item in instructions if start <= item["offset"] < end]
        require(
            inside and inside[-1]["offset"] + inside[-1]["length"] == end,
            f"{window_context}: the window does not end on an instruction boundary",
        )
        require(len(inside) >= 2, f"{window_context}: a window needs at least two instructions")
        inside = [
            decode_ia32_bijection_instruction(
                body, item["offset"], f"{window_context} at {item['offset']}", relocations
            )
            for item in inside
        ]
        require(
            [item["offset"] + item["length"] for item in inside][-1] == end,
            f"{window_context}: the decoded window does not end on the window boundary",
        )
        crossing = sorted(target for target in targets if start < target < end)
        require(
            not crossing, f"{window_context}: a branch targets the window interior at {crossing}"
        )
        external_crossing = sorted(
            target for target in (external_entries or ()) if start < target < end
        )
        require(
            not external_crossing,
            f"{window_context}: a derived external entry targets the window interior at {external_crossing}",
        )
        overlapping = sorted(offset for offset in range(start, end) if offset in relocation_offsets)
        declared_reseat = window.get("relocation_reseat")
        window_reseat = []
        if declared_reseat is None:
            require(
                not overlapping,
                f"{window_context}: a relocation operand lies inside the window at {overlapping[:4]}; this class refuses to move a relocation rather than reseat it approximately",
            )
        else:
            require(
                overlapping,
                f"{window_context}: a relocation reseat is declared but no relocation operand lies inside the window",
            )
            require(
                relocations, f"{window_context}: a relocation reseat needs the relocation records"
            )
            lengths_in = [item["length"] for item in inside]
            starts_in = [item["offset"] for item in inside]
            seated = {}
            cursor = start
            for position in window["target_order"]:
                seated[position] = cursor
                cursor += lengths_in[position]
            for offset in sorted(relocations):
                record = relocations[offset]
                width = record["width"]
                if offset + width <= start or offset >= end:
                    require(
                        not (start < offset + width and offset < end),
                        f"{window_context}: a relocation straddles the window boundary at {offset}",
                    )
                    continue
                require(
                    start <= offset and offset + width <= end,
                    f"{window_context}: a relocation straddles the window boundary at {offset}",
                )
                position = next(
                    (
                        index
                        for index in range(len(inside))
                        if starts_in[index] <= offset
                        and offset + width <= starts_in[index] + lengths_in[index]
                    ),
                    None,
                )
                require(
                    position is not None,
                    f"{window_context}: the relocation at {offset} straddles an instruction boundary",
                )
                window_reseat.append([offset, seated[position] + (offset - starts_in[position])])
            require(
                window_reseat == declared_reseat,
                f"{window_context}: the measured relocation reseat {window_reseat} differs from its declaration",
            )
        declared_stack = window.get("stack_adjustments")
        stack_frontier_theorem = window.get("stack_frontier_theorem")
        order = list(window["target_order"])
        private_stack_object = stack_frontier_theorem == IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM
        window_stack = ia32_schedule_stack_adjustments(
            body,
            inside,
            order,
            window_context,
            private_stack_object=private_stack_object,
        )
        stack_scope = bool(window_stack) or private_stack_object
        facts, strict_edges = ia32_schedule_dependence_edges(
            inside,
            window_context,
            body,
            stack_scope,
            private_stack_object=private_stack_object,
            # Standard v1 is the original VC 4.20 compiler-output theorem:
            # every direct ESP-base operand is expressed in the canonical
            # window-entry stack space.  A pair that actually crosses a PUSH
            # necessarily has a derived row in ``window_stack``; operands
            # that do not cross may omit the otherwise irrelevant ESP edge.
            # The newer private-object theorem keeps its narrower, concrete
            # adjustment set.
            adjusted_instructions=(
                frozenset(row[0] for row in window_stack) if private_stack_object else None
            ),
        )
        if declared_stack is None:
            require(
                not window_stack,
                f"{window_context}: the permutation moves a push past an ESP-relative operand but declares no stack adjustment",
            )
        else:
            require(
                window_stack == declared_stack,
                f"{window_context}: the measured stack adjustment {window_stack} differs from its declaration",
            )
        stack_frontier = None
        if stack_frontier_theorem is None:
            edges = strict_edges
        else:
            theorem_context = ScheduleTheoremContext(
                instructions=inside,
                facts=facts,
                strict_edges=strict_edges,
                order=order,
                theorem=stack_frontier_theorem,
                body=body,
                compiler_identity=compiler_identity,
            )
            if stack_frontier_theorem == IA32_SCHEDULE_STACK_FRONTIER_THEOREM:
                edges, stack_frontier = _ia32_schedule_stack_frontier_projection(
                    theorem_context, declared_stack is not None, window_context
                )
            else:
                edges, stack_frontier = _ia32_schedule_private_stack_object_projection(
                    theorem_context, window_stack, window_context
                )
                require(
                    frontier_instructions is not None and frontier_successors is not None,
                    f"{window_context}: private-stack/object body evidence is absent",
                )
                stack_frontier["boundary"] = derive_private_stack_object_boundary(
                    StackObjectQuery(
                        body=body,
                        instructions=frontier_instructions,
                        successors=frontier_successors,
                        relocations=relocations or {},
                        external_entries=frozenset(external_entries or ()),
                        start=start,
                        end=end,
                        target_order=order,
                        stack_adjustments=window_stack,
                        discharged=stack_frontier["discharged_memory_pairs"],
                    ),
                    debug_evidence if debug_evidence is not None else DebugEvidence(),
                    window_context,
                )
        require(
            edges == window["expected_dependence_edges"],
            f"{window_context}: the measured dependence DAG differs from its declaration",
        )
        require_topological_instruction_order(len(inside), edges, order, window_context)
        original = [
            bytes(body[item["offset"] : item["offset"] + item["length"]]) for item in inside
        ]
        require(
            [len(piece) for piece in original] == list(window["source_instruction_lengths"]),
            f"{window_context}: the window's instruction partition differs from its declaration",
        )
        pieces = [bytearray(piece) for piece in original]
        adjusted_spans = {}
        for index, at, _old_value, new_value in window_stack:
            found = ia32_esp_relative_displacement(body, inside[index])
            local = at - inside[index]["offset"]
            size = found[1]
            pieces[index][local : local + size] = new_value.to_bytes(size, "little", signed=True)
            adjusted_spans[index] = list(range(local, local + size))
        pieces = [bytes(piece) for piece in pieces]
        for index, (before_piece, after_piece) in enumerate(zip(original, pieces, strict=True)):
            changed_bytes = [
                position
                for position in range(len(before_piece))
                if before_piece[position] != after_piece[position]
            ]
            require(
                changed_bytes == adjusted_spans.get(index, []),
                f"{window_context}: the instruction at {inside[index]['offset']} changed outside its declared ESP displacement",
            )
        reordered = b"".join(pieces[source] for source in order)
        require(
            sorted(pieces)
            == sorted(
                (
                    reordered[offset : offset + length]
                    for offset, length in _instruction_spans(order, pieces)
                )
            ),
            f"{window_context}: the reordering is not a permutation of the window's own instructions",
        )
        require(
            len(reordered) == end - start,
            f"{window_context}: the reordering changed the window length",
        )
        image[start:end] = reordered
        window_detail = {
            "start": start,
            "end": end,
            "relocation_reseat": window_reseat,
            "stack_adjustments": window_stack,
            "adjusted_instructions": sorted(pieces),
            "instruction_count": len(inside),
            "source_instruction_lengths": [len(piece) for piece in pieces],
            "target_order": order,
            "dependence_edges": edges,
            "memory_disambiguation": [
                {
                    "instruction": position,
                    "base": item["memory"]["base"],
                    "displacement": item["memory"]["displacement"],
                    "width": item["memory"]["width"],
                    "read": item["memory"]["read"],
                    "write": item["memory"]["write"],
                }
                for position, item in enumerate(facts)
                if item["memory"] is not None
            ],
        }
        if stack_frontier is not None:
            window_detail["stack_frontier"] = stack_frontier
        detail.append(window_detail)
    image = bytes(image)
    require(len(image) == len(body), f"{context}: the reordering changed the body length")
    require(image != body, f"{context}: the reordering moves nothing")
    reseat = [pair for item in detail for pair in item["relocation_reseat"]]
    image_relocations = relocations
    if reseat:
        moved = dict(reseat)
        image_relocations = {
            moved.get(offset, offset): record for offset, record in (relocations or {}).items()
        }
        require(
            len(image_relocations) == len(relocations or {}),
            f"{context}: the reseat collides two relocation records",
        )
    image_spans, _ = ia32_schedule_body_walk(
        image, image_relocations, f"{context} image", code_length, internal_targets
    )
    image_instructions = [{"offset": start, "length": length} for start, length in image_spans]
    window_spans = [(item["start"], item["end"]) for item in windows]

    def _in_window(offset):
        return any((start <= offset < end for start, end in window_spans))

    require(
        [
            (item["offset"], item["length"])
            for item in image_instructions
            if not _in_window(item["offset"])
        ]
        == [
            (item["offset"], item["length"])
            for item in instructions
            if not _in_window(item["offset"])
        ],
        f"{context}: the image moved an instruction boundary outside a declared window",
    )
    for (start, end), item in zip(window_spans, detail, strict=True):
        before = item["adjusted_instructions"]
        after = sorted(
            image[position["offset"] : position["offset"] + position["length"]]
            for position in image_instructions
            if start <= position["offset"] < end
        )
        require(
            before == after,
            f"{context}: window {start:#x} is not the same instruction multiset in the image",
        )
    changed = sorted(index for index in range(len(body)) if body[index] != image[index])
    require(
        all(_in_window(offset) for offset in changed),
        f"{context}: the image changed a byte outside a declared window",
    )
    for item in detail:
        item.pop("adjusted_instructions", None)
    return (
        image,
        {
            "windows": detail,
            "instruction_count": len(instructions),
            "changed_offsets": changed,
            "relocation_reseat": reseat,
            "stack_adjustments": [pair for item in detail for pair in item["stack_adjustments"]],
            "code_length": limit,
        },
    )


def _instruction_spans(order: list[int], pieces: list[bytes]):
    """The (offset, length) spans the reordered pieces occupy."""
    cursor = 0
    for source in order:
        yield (cursor, len(pieces[source]))
        cursor += len(pieces[source])
