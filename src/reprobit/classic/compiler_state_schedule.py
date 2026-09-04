"""Dependence-DAG schedule derivation for compiler-state projection."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import permutations, product
from math import factorial
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.compiler_identity import (
    MSVC420_WIN32_I386_TARGET,
    Msvc420CompilerIdentity,
)
from reprobit.classic.foundation import RelocationView
from reprobit.classic.scheduling_apply import apply_instruction_schedule
from reprobit.classic.scheduling_dependence import (
    IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM,
    ScheduleTheoremContext,
    _ia32_schedule_private_stack_object_projection,
    ia32_esp_relative_displacement,
    ia32_esp_used_only_as_a_base,
    ia32_schedule_dependence_edges,
    ia32_schedule_stack_adjustments,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.stack_frontier_object import DebugEvidence

from .compiler_state_eh import (
    _apply_frame_push_schedule,
    _apply_synchronous_eh_schedule,
)
from .compiler_state_foundation import (
    CompilerStateCodePair,
    _ImageState,
    _Instruction,
    _instructions,
    _relocation_bytes,
    _relocation_parts,
    _RelocationRecord,
    _tokens,
)

_MAX_SCHEDULE_PAIRINGS = 32


def _schedule_window(
    source_tokens: Sequence[bytes],
    target_tokens: Sequence[bytes],
    source_instructions: Sequence[_Instruction],
    target_instructions: Sequence[_Instruction],
) -> tuple[int, int] | None:
    """Locate the first closed permutation window without choosing a pairing."""

    if len(source_tokens) != len(target_tokens):
        return None
    first = next(
        (
            index
            for index, pair in enumerate(zip(source_tokens, target_tokens, strict=True))
            if pair[0] != pair[1]
        ),
        None,
    )
    if first is None:
        return None
    if source_instructions[first]["offset"] != target_instructions[first]["offset"]:
        return None
    for stop in range(first + 2, len(source_tokens) + 1):
        source_end = int(source_instructions[stop - 1]["offset"]) + int(
            source_instructions[stop - 1]["length"]
        )
        target_end = int(target_instructions[stop - 1]["offset"]) + int(
            target_instructions[stop - 1]["length"]
        )
        if source_end == target_end and Counter(source_tokens[first:stop]) == Counter(
            target_tokens[first:stop]
        ):
            return first, stop
    return None


def _schedule_pairing_candidates(
    source_tokens: Sequence[bytes],
    target_tokens: Sequence[bytes],
    source_instructions: Sequence[_Instruction],
    target_instructions: Sequence[_Instruction],
) -> tuple[tuple[int, int, list[int]], ...]:
    """Enumerate the bounded instruction pairings for one closed window."""

    window = _schedule_window(
        source_tokens,
        target_tokens,
        source_instructions,
        target_instructions,
    )
    if window is None:
        return ()
    first, stop = window
    source_window = list(source_tokens[first:stop])
    target_window = list(target_tokens[first:stop])
    distinct = tuple(dict.fromkeys(source_window))
    choices: list[tuple[tuple[int, ...], ...]] = []
    candidate_count = 1
    for token in distinct:
        source_positions = tuple(
            index for index, candidate in enumerate(source_window) if candidate == token
        )
        candidate_count *= factorial(len(source_positions))
        if candidate_count > _MAX_SCHEDULE_PAIRINGS:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code schedule exceeds its closed pairing bound"
            )
        options = tuple(permutations(source_positions))
        choices.append(options)

    candidates: list[tuple[int, int, list[int]]] = []
    target_positions = {
        token: tuple(index for index, candidate in enumerate(target_window) if candidate == token)
        for token in distinct
    }
    for selection in product(*choices):
        order = [-1] * len(source_window)
        for token, source_positions in zip(distinct, selection, strict=True):
            for target_position, source_position in zip(
                target_positions[token], source_positions, strict=True
            ):
                order[target_position] = source_position
        candidates.append((first, stop, order))
    return tuple(candidates)


def _schedule_candidate(
    source_tokens: Sequence[bytes],
    target_tokens: Sequence[bytes],
    source_instructions: Sequence[_Instruction],
    target_instructions: Sequence[_Instruction],
) -> tuple[int, int, list[int]] | None:
    window = _schedule_window(
        source_tokens,
        target_tokens,
        source_instructions,
        target_instructions,
    )
    if window is None:
        return None
    first, stop = window
    source_window = list(source_tokens[first:stop])
    target_window = list(target_tokens[first:stop])
    counts = Counter(source_window)
    if any(count != 1 for count in counts.values()):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state code schedule has no unique instruction pairing"
        )
    positions = {token: index for index, token in enumerate(source_window)}
    return first, stop, [positions[token] for token in target_window]


def _stack_normalized_tokens(
    body: bytes,
    instructions: Sequence[_Instruction],
    relocation_offsets: Sequence[int],
    relocation_statements: Sequence[Mapping[str, object]],
    *,
    structural: bool,
) -> list[bytes]:
    """Erase only direct ESP displacement fields for schedule discovery.

    This is not proof authority.  The schedule primitive later derives every
    required displacement rebase from the permutation, re-encodes it in the
    original-width field, and requires exact effective-image rejoin.
    """

    normalized = bytearray(body)
    for item in instructions:
        if not ia32_esp_used_only_as_a_base(body, cast(dict[Any, Any], item)):
            continue
        found = ia32_esp_relative_displacement(body, cast(dict[Any, Any], item))
        if found is None or found[0] == "no_displacement":
            continue
        at, size, _value = found
        if any(offset < at + size and at < offset + 4 for offset in relocation_offsets):
            continue
        normalized[at : at + size] = bytes(size)
    return _tokens(
        bytes(normalized),
        instructions,
        relocation_offsets,
        relocation_statements,
        structural=structural,
    )


def _is_topological(edges: Sequence[Sequence[object]], order: Sequence[int]) -> bool:
    position = {source: target for target, source in enumerate(order)}
    return all(position[cast(int, edge[0])] < position[cast(int, edge[1])] for edge in edges)


def _window_declaration(
    *,
    body: bytes,
    instructions: Sequence[_Instruction],
    first: int,
    stop: int,
    order: Sequence[int],
    records: Mapping[int, _RelocationRecord],
    compiler_identity: Msvc420CompilerIdentity | None,
    private_stack_object: bool,
) -> dict[str, Any]:
    inside = list(instructions[first:stop])
    start = inside[0]["offset"]
    end = inside[-1]["offset"] + inside[-1]["length"]
    order_list = list(order)
    try:
        stack_adjustments = ia32_schedule_stack_adjustments(
            body,
            cast(list[dict[Any, Any]], inside),
            order_list,
            "MSVC 4.20 compiler-state schedule",
            private_stack_object=private_stack_object,
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    try:
        facts, edges = ia32_schedule_dependence_edges(
            cast(list[dict[Any, Any]], inside),
            "MSVC 4.20 compiler-state schedule",
            body,
            bool(stack_adjustments),
            private_stack_object=private_stack_object,
            adjusted_instructions=frozenset(row[0] for row in stack_adjustments),
        )
    except ByteIdentityError as error:
        if not private_stack_object:
            raise ClassicSemanticError(str(error)) from error
        try:
            facts, edges = ia32_schedule_dependence_edges(
                cast(list[dict[Any, Any]], inside),
                "MSVC 4.20 compiler-state schedule",
                body,
                True,
                private_stack_object=True,
                adjusted_instructions=frozenset(row[0] for row in stack_adjustments),
            )
        except ByteIdentityError as retry_error:
            raise ClassicSemanticError(str(retry_error)) from retry_error
    stack_frontier_theorem: str | None = None
    if private_stack_object and not _is_topological(edges, order_list):
        try:
            projected, _receipt = _ia32_schedule_private_stack_object_projection(
                ScheduleTheoremContext(
                    instructions=cast(list[dict[Any, Any]], inside),
                    facts=facts,
                    strict_edges=edges,
                    order=order_list,
                    theorem=IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM,
                    body=body,
                    compiler_identity=compiler_identity,
                ),
                stack_adjustments,
                "MSVC 4.20 compiler-state schedule",
            )
        except ByteIdentityError:
            projected = edges
        if _is_topological(projected, order_list):
            edges = projected
            stack_frontier_theorem = IA32_SCHEDULE_PRIVATE_STACK_OBJECT_THEOREM
    source_starts = [item["offset"] for item in inside]
    lengths = [item["length"] for item in inside]
    target_starts: dict[int, int] = {}
    cursor = start
    for position in order_list:
        target_starts[position] = cursor
        cursor += lengths[position]
    reseat: list[list[int]] = []
    for offset, record in sorted(records.items()):
        width = int(record["width"])
        if offset + width <= start or offset >= end:
            continue
        seat_position = next(
            (
                index
                for index, source_start in enumerate(source_starts)
                if source_start <= offset and offset + width <= source_start + lengths[index]
            ),
            None,
        )
        if seat_position is None:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code relocation straddles a schedule instruction"
            )
        reseat.append(
            [
                offset,
                target_starts[seat_position] + (offset - source_starts[seat_position]),
            ]
        )
    result: dict[str, object] = {
        "start": start,
        "end": end,
        "source_instruction_lengths": lengths,
        "target_order": order_list,
        "expected_dependence_edges": edges,
    }
    if stack_adjustments:
        result["stack_adjustments"] = stack_adjustments
    if stack_frontier_theorem is not None:
        result["stack_frontier_theorem"] = stack_frontier_theorem
    if reseat:
        result["relocation_reseat"] = reseat
    return result


def _apply_schedules(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_statements: Sequence[Mapping[str, object]],
    target_offsets: Sequence[int],
    target_records: Mapping[int, _RelocationRecord],
    target_statements: Sequence[Mapping[str, object]],
    *,
    structural: bool,
    exception_mode: Mapping[str, object] | None,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[_ImageState, list[dict[str, object]]]:
    proofs: list[dict[str, object]] = []
    base_offsets, base_records = _relocation_parts(
        source_statements, "MSVC 4.20 compiler-state source code"
    )
    while True:
        source_records = {
            current: base_records[original]
            for current, original in zip(state.relocation_offsets, base_offsets, strict=True)
        }
        source_instructions = _instructions(
            state.body, source_records, "MSVC 4.20 compiler-state source code"
        )
        target_instructions = _instructions(
            pair.effective_body, target_records, "MSVC 4.20 compiler-state effective code"
        )
        source_tokens = _tokens(
            state.body,
            source_instructions,
            state.relocation_offsets,
            source_statements,
            structural=structural,
        )
        target_tokens = _tokens(
            pair.effective_body,
            target_instructions,
            target_offsets,
            target_statements,
            structural=structural,
        )
        private_stack_object = bool(
            pair.eh_control_digest is None
            and type(compiler_identity) is Msvc420CompilerIdentity
            and compiler_identity.target == MSVC420_WIN32_I386_TARGET
            and pair.fpo_evidence is not None
            and pair.debug_evidence is not None
            and pair.fpo_evidence.clean_body == pair.fpo_evidence.effective_body
            and pair.debug_evidence.clean_body == pair.debug_evidence.effective_body
        )
        candidate = _schedule_candidate(
            source_tokens, target_tokens, source_instructions, target_instructions
        )
        if candidate is None and private_stack_object:
            candidate = _schedule_candidate(
                _stack_normalized_tokens(
                    state.body,
                    source_instructions,
                    state.relocation_offsets,
                    source_statements,
                    structural=structural,
                ),
                _stack_normalized_tokens(
                    pair.effective_body,
                    target_instructions,
                    target_offsets,
                    target_statements,
                    structural=structural,
                ),
                source_instructions,
                target_instructions,
            )
        if candidate is None:
            return state, proofs
        first, stop, order = candidate
        declaration = _window_declaration(
            body=state.body,
            instructions=source_instructions,
            first=first,
            stop=stop,
            order=order,
            records=source_records,
            compiler_identity=compiler_identity,
            private_stack_object=private_stack_object,
        )
        if any(
            int(declaration["start"]) < entry < int(declaration["end"])
            for entry in pair.external_entries
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state schedule has a funclet entry inside its window"
            )
        relocation_bytes = _relocation_bytes(state.relocation_offsets, source_records)
        try:
            image, proof = apply_instruction_schedule(
                state.body,
                [declaration],
                relocation_bytes,
                "MSVC 4.20 compiler-state schedule",
                view=RelocationView(relocations=source_records),
                external_entries=frozenset(pair.external_entries),
                compiler_identity=compiler_identity,
                debug_evidence=DebugEvidence(
                    fpo_body=(
                        pair.fpo_evidence.clean_body if pair.fpo_evidence is not None else None
                    ),
                    debug_body=(
                        pair.debug_evidence.clean_body if pair.debug_evidence is not None else None
                    ),
                    fpo_receipt_digest=(
                        pair.fpo_evidence.receipt_digest if pair.fpo_evidence is not None else None
                    ),
                    debug_receipt_digest=(
                        pair.debug_evidence.receipt_digest
                        if pair.debug_evidence is not None
                        else None
                    ),
                    function_owner=pair.owner,
                ),
            )
            moved = {int(source): int(target) for source, target in proof["relocation_reseat"]}
            state = _ImageState(
                image,
                [moved.get(offset, offset) for offset in state.relocation_offsets],
            )
            proofs.append({"kind": "dependence-dag-schedule-v1", **proof})
        except ByteIdentityError as error:
            inside = source_instructions[first:stop]
            if pair.eh_control_digest is not None and any(
                int(item["opcode"]) in range(0x50, 0x58) for item in inside
            ):
                state, proof = _apply_frame_push_schedule(
                    state,
                    pair,
                    declaration,
                    source_records,
                    source_statements,
                )
            elif pair.eh_control_digest is not None:
                state, proof = _apply_synchronous_eh_schedule(
                    state,
                    pair,
                    declaration,
                    source_records,
                    source_statements,
                    exception_mode,
                )
            else:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state ordinary schedule is forbidden by "
                    f"its dependence DAG: {error}"
                ) from error
            proofs.append(proof)
