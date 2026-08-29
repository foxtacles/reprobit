"""Bounded window discovery and stack-DAG helpers for saved-prologue proofs."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import Any, TypedDict, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.registers import IA32_GENERAL_REGISTER_NAMES
from reprobit.classic.scheduling import (
    ia32_esp_relative_displacement,
    ia32_esp_used_only_as_a_base,
    ia32_schedule_dependence_edges,
    ia32_schedule_stack_adjustments,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .compiler_state_foundation import _Instruction
from .compiler_state_prologue_evidence import _NONVOLATILES, _register_push
from .stack_frontier_foundation import address_form, stack_change

_MAX_WINDOW_INSTRUCTIONS = 12
_MAX_WINDOW_BYTES = 64


class _SavedPrologueCandidate(TypedDict):
    start: int
    end: int
    clean_indexes: list[int]
    effective_indexes: list[int]
    clean_window: list[_Instruction]
    effective_window: list[_Instruction]
    cycle: dict[str, str]
    order: list[int]
    pair_index: dict[int, int]


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ClassicSemanticError(message)


def _window_token(body: bytes, item: _Instruction, cycle: frozenset[str]) -> bytes | None:
    start = int(item["offset"])
    piece = bytearray(body[start : start + int(item["length"])])
    pushed = _register_push(body, item)
    if pushed is None:
        for byte_index, shift in item["fields"]:
            local = int(byte_index) - start
            register = IA32_GENERAL_REGISTER_NAMES[piece[local] >> int(shift) & 7]
            if register in cycle:
                piece[local] &= ~(7 << int(shift)) & 0xFF
    memory = item.get("memory")
    if isinstance(memory, dict) and memory.get("base") == "esp":
        if not (
            memory.get("index") is None
            and ia32_esp_used_only_as_a_base(body, cast(dict[str, Any], item))
        ):
            return None
        found = ia32_esp_relative_displacement(body, cast(dict[str, Any], item))
        if found is None or found[0] == "no_displacement":
            return None
        assert isinstance(found[0], int)
        at, size, _value = found
        local = at - start
        piece[local : local + size] = bytes(size)
    return canonical_json({"encoding": bytes(piece).hex(), "flow": item["flow"]})


def _find_cycle_and_order(
    clean_body: bytes,
    effective_body: bytes,
    clean_window: Sequence[_Instruction],
    effective_window: Sequence[_Instruction],
) -> tuple[dict[str, str], list[int]] | None:
    """Return the unique nonidentity two-web window candidate, if one exists.

    This is theorem selection rather than theorem authority.  A window outside
    the closed token vocabulary belongs to another proof family, so it must
    fall through instead of turning a tentative dispatch into a rejection.
    """

    candidates: list[tuple[dict[str, str], list[int]]] = []
    for left, right in combinations(_NONVOLATILES, 2):
        cycle = frozenset({left, right})
        clean_tokens = [_window_token(clean_body, item, cycle) for item in clean_window]
        effective_tokens = [_window_token(effective_body, item, cycle) for item in effective_window]
        if any(token is None for token in [*clean_tokens, *effective_tokens]):
            return None
        counts = Counter(clean_tokens)
        if counts != Counter(effective_tokens) or any(count != 1 for count in counts.values()):
            continue
        positions = {token: index for index, token in enumerate(clean_tokens)}
        order = [positions[token] for token in effective_tokens]
        if order != list(range(len(order))):
            candidates.append(({left: right, right: left}, order))
    return candidates[0] if len(candidates) == 1 else None


def _raw_prologue_saves(
    body: bytes,
    instructions: Sequence[_Instruction],
    prolog_end: int,
) -> list[tuple[str, int, int]] | None:
    if not 0 < prolog_end <= len(body):
        return None
    prefix = [item for item in instructions if int(item["offset"]) < prolog_end]
    if not prefix or not all(item["flow"] == "fall" for item in prefix):
        return None
    saves = [
        (pushed, index, int(item["offset"]))
        for index, item in enumerate(prefix)
        if (pushed := _register_push(body, item)) in _NONVOLATILES
    ]
    return saves or None


def _instruction_skeleton_matches(
    clean_body: bytes,
    effective_body: bytes,
    clean: _Instruction,
    effective: _Instruction,
    cycle: Mapping[str, str],
    *,
    in_window: bool,
) -> bool:
    clean_start = int(clean["offset"])
    effective_start = int(effective["offset"])
    length = int(clean["length"])
    if not (length == int(effective["length"]) and clean["flow"] == effective["flow"]):
        return False
    clean_fields = [
        (int(byte_index) - clean_start, int(shift)) for byte_index, shift in clean["fields"]
    ]
    effective_fields = [
        (int(byte_index) - effective_start, int(shift)) for byte_index, shift in effective["fields"]
    ]
    if clean_fields != effective_fields:
        return False
    clean_piece = bytearray(clean_body[clean_start : clean_start + length])
    effective_piece = bytearray(effective_body[effective_start : effective_start + length])
    for local, shift in clean_fields:
        if not 0 <= local < length:
            return False
        source = IA32_GENERAL_REGISTER_NAMES[clean_piece[local] >> shift & 7]
        target = IA32_GENERAL_REGISTER_NAMES[effective_piece[local] >> shift & 7]
        if target not in {source, cycle.get(source)}:
            return False
        clean_piece[local] &= ~(7 << shift) & 0xFF
        effective_piece[local] &= ~(7 << shift) & 0xFF
    if in_window:
        clean_esp = ia32_esp_relative_displacement(clean_body, cast(dict[str, Any], clean))
        effective_esp = ia32_esp_relative_displacement(
            effective_body, cast(dict[str, Any], effective)
        )
        if clean_esp is not None or effective_esp is not None:
            if not (
                clean_esp is not None
                and effective_esp is not None
                and isinstance(clean_esp[0], int)
                and isinstance(effective_esp[0], int)
                and clean_esp[1] == effective_esp[1]
                and clean_esp[0] - clean_start == effective_esp[0] - effective_start
            ):
                return False
            clean_local = clean_esp[0] - clean_start
            effective_local = effective_esp[0] - effective_start
            clean_piece[clean_local : clean_local + clean_esp[1]] = bytes(clean_esp[1])
            effective_piece[effective_local : effective_local + effective_esp[1]] = bytes(
                effective_esp[1]
            )
    return clean_piece == effective_piece


def _try_saved_prologue_candidate(
    clean_body: bytes,
    effective_body: bytes,
    clean_instructions: Sequence[_Instruction],
    effective_instructions: Sequence[_Instruction],
    clean_prolog_end: int,
    effective_prolog_end: int,
) -> _SavedPrologueCandidate | None:
    """Select only the theorem's complete bounded code skeleton."""

    clean_saves = _raw_prologue_saves(clean_body, clean_instructions, clean_prolog_end)
    effective_saves = _raw_prologue_saves(
        effective_body, effective_instructions, effective_prolog_end
    )
    if not (
        clean_saves
        and effective_saves
        and [name for name, _index, _offset in clean_saves]
        == [name for name, _index, _offset in effective_saves]
        and clean_saves[0][0] == effective_saves[0][0]
        and clean_saves[0][2] == effective_saves[0][2]
    ):
        return None
    start = clean_saves[0][2]
    first_save_end = start + int(clean_instructions[clean_saves[0][1]]["length"])
    if clean_body[:first_save_end] != effective_body[:first_save_end]:
        return None
    clean_boundaries = {int(item["offset"]) for item in clean_instructions}
    effective_boundaries = {int(item["offset"]) for item in effective_instructions}
    common_after = sorted(
        boundary
        for boundary in clean_boundaries & effective_boundaries
        if boundary > max(clean_prolog_end, effective_prolog_end)
    )
    if not common_after:
        return None
    end = common_after[0]
    clean_indexes = [
        index for index, item in enumerate(clean_instructions) if start <= int(item["offset"]) < end
    ]
    effective_indexes = [
        index
        for index, item in enumerate(effective_instructions)
        if start <= int(item["offset"]) < end
    ]
    clean_window = [clean_instructions[index] for index in clean_indexes]
    effective_window = [effective_instructions[index] for index in effective_indexes]
    if not (
        len(clean_window) == len(effective_window)
        and 2 <= len(clean_window) <= _MAX_WINDOW_INSTRUCTIONS
        and end - start <= _MAX_WINDOW_BYTES
        and all(item["flow"] == "fall" for item in [*clean_window, *effective_window])
    ):
        return None
    found = _find_cycle_and_order(clean_body, effective_body, clean_window, effective_window)
    if found is None:
        return None
    cycle, order = found
    if not set(cycle) <= {name for name, _index, _offset in clean_saves}:
        return None
    clean_to_effective_local = {source: target for target, source in enumerate(order)}
    pair_index = {index: index for index in range(len(clean_instructions))}
    for source, target in clean_to_effective_local.items():
        pair_index[clean_indexes[source]] = effective_indexes[target]
    if set(pair_index.values()) != set(range(len(effective_instructions))):
        return None
    clean_window_set = set(clean_indexes)
    if not all(
        _instruction_skeleton_matches(
            clean_body,
            effective_body,
            clean_instructions[clean_index],
            effective_instructions[effective_index],
            cycle,
            in_window=clean_index in clean_window_set,
        )
        for clean_index, effective_index in pair_index.items()
    ):
        return None
    return {
        "start": start,
        "end": end,
        "clean_indexes": clean_indexes,
        "effective_indexes": effective_indexes,
        "clean_window": clean_window,
        "effective_window": effective_window,
        "cycle": cycle,
        "order": order,
        "pair_index": pair_index,
    }


def _depths(body: bytes, window: Sequence[_Instruction], context: str) -> list[int]:
    result: list[int] = []
    depth = 0
    for item in window:
        result.append(depth)
        change = stack_change(body, cast(dict[str, Any], item))
        _require(change is not None, f"{context} has an unknown ESP update")
        assert change is not None
        depth += change
    return result


def _is_topological(edges: Sequence[Sequence[object]], order: Sequence[int]) -> bool:
    position = {source: target for target, source in enumerate(order)}
    return all(position[cast(int, edge[0])] < position[cast(int, edge[1])] for edge in edges)


def _prove_window_stack_and_dag(
    clean_body: bytes,
    effective_body: bytes,
    clean_window: Sequence[_Instruction],
    effective_window: Sequence[_Instruction],
    clean_to_effective_local: Mapping[int, int],
    clean_window_indexes: Sequence[int],
    clean_saves: Sequence[tuple[str, int, int]],
    order: Sequence[int],
    cycle: Mapping[str, str],
) -> tuple[list[list[int]], dict[str, int], dict[int, int], dict[str, object]]:
    try:
        adjustments = cast(
            list[list[int]],
            ia32_schedule_stack_adjustments(
                clean_body,
                cast(list[dict[str, Any]], clean_window),
                list(order),
                "MSVC 4.20 saved-prologue stack rebase",
            ),
        )
        _facts, strict_edges = ia32_schedule_dependence_edges(
            cast(list[dict[str, Any]], clean_window),
            "MSVC 4.20 saved-prologue schedule",
            clean_body,
            bool(adjustments),
            adjusted_instructions=frozenset(row[0] for row in adjustments),
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error

    clean_depths = _depths(clean_body, clean_window, "clean saved-prologue window")
    effective_depths = _depths(effective_body, effective_window, "effective saved-prologue window")
    _require(
        sum(
            cast(int, stack_change(clean_body, cast(dict[str, Any], item))) for item in clean_window
        )
        == sum(
            cast(int, stack_change(effective_body, cast(dict[str, Any], item)))
            for item in effective_window
        ),
        "MSVC 4.20 saved-prologue window changes its exit depth",
    )
    stack_observations: list[dict[str, object]] = []
    for source_local, target_local in clean_to_effective_local.items():
        source_item = clean_window[source_local]
        target_item = effective_window[target_local]
        source_change = stack_change(clean_body, cast(dict[str, Any], source_item))
        target_change = stack_change(effective_body, cast(dict[str, Any], target_item))
        _require(source_change == target_change, "saved-prologue paired stack effects differ")
        if source_change:
            _require(
                _register_push(clean_body, source_item)
                == _register_push(effective_body, target_item)
                and clean_depths[source_local] == effective_depths[target_local],
                "MSVC 4.20 saved-prologue PUSH identity or save seat changes",
            )
        for side, body, item, depth in (
            ("clean", clean_body, source_item, clean_depths[source_local]),
            ("effective", effective_body, target_item, effective_depths[target_local]),
        ):
            memory = item.get("memory")
            if not isinstance(memory, dict):
                continue
            _require(
                memory["base"] == "esp"
                and memory["index"] is None
                and not memory["absolute"]
                and not memory["unknown"]
                and address_form(body, cast(dict[str, Any], item))
                == ("esp", None, 1, memory["displacement"]),
                f"MSVC 4.20 saved-prologue {side} memory is not direct ESP-relative",
            )
            stack_observations.append(
                {
                    "source_instruction": source_local,
                    "side": side,
                    "entry_span": [
                        depth + int(memory["displacement"]),
                        depth + int(memory["displacement"]) + int(memory["width"]),
                    ],
                    "read": memory["read"],
                    "write": memory["write"],
                }
            )
        source_memory = source_item.get("memory")
        target_memory = target_item.get("memory")
        if isinstance(source_memory, dict) or isinstance(target_memory, dict):
            _require(
                isinstance(source_memory, dict)
                and isinstance(target_memory, dict)
                and clean_depths[source_local] + int(source_memory["displacement"])
                == effective_depths[target_local] + int(target_memory["displacement"])
                and source_memory["width"] == target_memory["width"]
                and source_memory["read"] == target_memory["read"]
                and source_memory["write"] == target_memory["write"],
                "MSVC 4.20 saved-prologue ESP operand changes its entry-relative span",
            )

    save_by_register = {
        name: clean_window_indexes.index(index)
        for name, index, _offset in clean_saves
        if index in clean_window_indexes
    }
    projected_edges: list[list[object]] = []
    discharged_edges: list[dict[str, object]] = []
    target_position = {source: target for target, source in enumerate(order)}
    for edge in strict_edges:
        left, right, reasons = edge
        if target_position[left] < target_position[right]:
            projected_edges.append(edge)
            continue
        source_register = _register_push(clean_body, clean_window[left])
        target_register = cycle.get(source_register or "")
        right_item = clean_window[right]
        _require(
            reasons == ["register_war"]
            and source_register in cycle
            and target_register is not None
            and source_register not in right_item["reads"]
            and source_register in right_item["writes"]
            and target_register in save_by_register
            and target_position[save_by_register[target_register]] < target_position[right],
            "MSVC 4.20 saved-prologue permutation crosses an unproved dependence",
        )
        assert isinstance(target_register, str)
        discharged_edges.append(
            {
                "source_pair": [left, right],
                "reason": "saved-register-war-after-web-image",
                "source_register": source_register,
                "image_register": target_register,
                "image_save_source_instruction": save_by_register[target_register],
            }
        )
    _require(
        bool(discharged_edges) and _is_topological(projected_edges, order),
        "MSVC 4.20 saved-prologue projection does not close its dependence DAG",
    )
    proof: dict[str, object] = {
        "stack_observations_digest": Digest.from_bytes(canonical_json(stack_observations)).value,
        "strict_dependence_edges": strict_edges,
        "projected_dependence_edges": projected_edges,
        "discharged_dependence_edges": discharged_edges,
    }
    return adjustments, save_by_register, target_position, proof
