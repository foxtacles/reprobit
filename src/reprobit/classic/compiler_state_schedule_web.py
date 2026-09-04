"""Atomic schedule and register-web proof for compiler-state code images."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.compiler_identity import (
    MSVC420_WIN32_I386_TARGET,
    Msvc420CompilerIdentity,
)
from reprobit.classic.register_semantics import IA32_GENERAL_REGISTER_NAMES, ia32_register_atoms
from reprobit.classic.rewriting_region_simulation import _srr_simulate
from reprobit.classic.scheduling_webs import ia32_web_control_flow
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .compiler_state_foundation import (
    CompilerStateCodePair,
    _ImageState,
    _Instruction,
    _instruction_relocation_observations,
    _instructions,
    _relocation_bytes,
    _RelocationRecord,
    _tokens,
)
from .compiler_state_schedule import _schedule_pairing_candidates
from .compiler_state_web import _field_registers, _web_reaching_definitions

_THEOREM = "msvc-4.20-atomic-schedule-register-web-v1"
_MAX_WINDOW_INSTRUCTIONS = 8
_MAX_WINDOW_BYTES = 48
_MAX_PAIRINGS = 4


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ClassicSemanticError(message)


def _instruction_fields(
    source_body: bytes,
    target_body: bytes,
    source: _Instruction,
    target: _Instruction,
    source_relocation_bytes: frozenset[int],
    target_relocation_bytes: frozenset[int],
) -> tuple[dict[str, str], list[dict[str, object]]]:
    source_start = int(source["offset"])
    target_start = int(target["offset"])
    length = int(source["length"])
    _require(
        length == int(target["length"]) and source["flow"] == target["flow"],
        "MSVC 4.20 atomic schedule/web changes instruction structure",
    )
    source_positions = [
        (int(byte_index) - source_start, int(shift)) for byte_index, shift in source["fields"]
    ]
    target_positions = [
        (int(byte_index) - target_start, int(shift)) for byte_index, shift in target["fields"]
    ]
    _require(
        source_positions == target_positions,
        "MSVC 4.20 atomic schedule/web changes register-field structure",
    )
    source_piece = bytearray(source_body[source_start : source_start + length])
    target_piece = bytearray(target_body[target_start : target_start + length])
    source_names = _field_registers(source_body, source)
    target_names = _field_registers(target_body, target)
    local: dict[str, str] = {}
    rewritten: list[dict[str, object]] = []
    for ordinal, ((local_at, shift), source_name, target_name) in enumerate(
        zip(source_positions, source_names, target_names, strict=True)
    ):
        _require(
            source_start + local_at not in source_relocation_bytes
            and target_start + local_at not in target_relocation_bytes,
            "MSVC 4.20 atomic schedule/web register field overlaps a relocation",
        )
        previous = local.setdefault(source_name, target_name)
        _require(
            previous == target_name,
            "MSVC 4.20 atomic schedule/web has a non-functional field image",
        )
        source_piece[local_at] &= ~(7 << shift) & 0xFF
        target_piece[local_at] &= ~(7 << shift) & 0xFF
        if source_name != target_name:
            rewritten.append(
                {
                    "field": ordinal,
                    "source_register": source_name,
                    "target_register": target_name,
                }
            )
    _require(
        source_piece == target_piece,
        "MSVC 4.20 atomic schedule/web changes a non-register byte",
    )
    observed = set(source["reads"]) | set(source["writes"])
    for register in observed:
        local.setdefault(register, register)
    _require(
        len({local[register] for register in source["reads"]}) == len(source["reads"])
        and len({local[register] for register in source["writes"]}) == len(source["writes"])
        and {local[register] for register in source["reads"]} == set(target["reads"])
        and {local[register] for register in source["writes"]} == set(target["writes"]),
        "MSVC 4.20 atomic schedule/web changes an operand observation",
    )
    for source_name, target_name in local.items():
        if source_name == target_name:
            continue
        _require(
            not ({source_name, target_name} & {"esp", "ebp"})
            and not ({source_name, target_name} & set(source["frozen"]))
            and not ({source_name, target_name} & set(target["frozen"])),
            "MSVC 4.20 atomic schedule/web touches a structural or partial register",
        )
        if source_name in source["reads"]:
            _require(
                ia32_register_atoms({source_name}) <= source["read_atoms"]
                and ia32_register_atoms({target_name}) <= target["read_atoms"],
                "MSVC 4.20 atomic schedule/web changes a partial register read",
            )
        if source_name in source["writes"]:
            _require(
                ia32_register_atoms({source_name}) <= source["write_atoms"]
                and ia32_register_atoms({target_name}) <= target["write_atoms"],
                "MSVC 4.20 atomic schedule/web changes a partial register definition",
            )
    return local, rewritten


def _prove_candidate(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source: Sequence[_Instruction],
    target: Sequence[_Instruction],
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    first: int,
    stop: int,
    order: Sequence[int],
    compiler_identity: Msvc420CompilerIdentity,
) -> tuple[_ImageState, dict[str, object]]:
    count = stop - first
    start = int(source[first]["offset"])
    end = int(source[stop - 1]["offset"]) + int(source[stop - 1]["length"])
    _require(
        first > 0 and 2 <= count <= _MAX_WINDOW_INSTRUCTIONS and end - start <= _MAX_WINDOW_BYTES,
        "MSVC 4.20 atomic schedule/web window is outside its closed bound",
    )
    source_window = set(range(first, stop))
    _require(
        all(item["flow"] == "fall" for item in [*source[first:stop], *target[first:stop]]),
        "MSVC 4.20 atomic schedule/web window is not straight-line code",
    )
    _require(
        not any(start <= entry < end for entry in pair.external_entries),
        "MSVC 4.20 atomic schedule/web window contains an external entry",
    )
    for instructions in (source, target):
        _require(
            not any(
                item.get("target") is not None and start <= cast(int, item["target"]) < end
                for item in instructions
            )
            and not any(item["flow"] == "computed" for item in instructions),
            "MSVC 4.20 atomic schedule/web has an unclosed control-flow entry",
        )
    _require(
        not any(
            offset < end and start < offset + int(record["width"])
            for records in (source_records, target_records)
            for offset, record in records.items()
        ),
        "MSVC 4.20 atomic schedule/web window contains a relocation",
    )

    pair_index = {index: index for index in range(len(source))}
    for target_local, source_local in enumerate(order):
        pair_index[first + int(source_local)] = first + target_local
    _require(
        set(pair_index.values()) == set(range(len(target))),
        "MSVC 4.20 atomic schedule/web instruction pairing is not bijective",
    )

    source_relocation_bytes = _relocation_bytes(state.relocation_offsets, source_records)
    target_relocation_bytes = _relocation_bytes(state.relocation_offsets, target_records)
    local_maps: list[dict[str, str]] = []
    rewritten_fields: list[dict[str, object]] = []
    outside_cycle: dict[str, str] = {}
    call_observations: list[dict[str, object]] = []
    correspondence: list[list[int]] = []
    for source_index, source_item in enumerate(source):
        target_index = pair_index[source_index]
        target_item = target[target_index]
        if source_index not in source_window:
            _require(
                source_item.get("target") == target_item.get("target"),
                "MSVC 4.20 atomic schedule/web changes control flow outside its window",
            )
        local, rewritten = _instruction_fields(
            state.body,
            pair.effective_body,
            source_item,
            target_item,
            source_relocation_bytes,
            target_relocation_bytes,
        )
        source_start = int(source_item["offset"])
        target_start = int(target_item["offset"])
        source_relocations = _instruction_relocation_observations(
            source_start,
            source_start + int(source_item["length"]),
            source_records,
        )
        target_relocations = _instruction_relocation_observations(
            target_start,
            target_start + int(target_item["length"]),
            target_records,
        )
        _require(
            source_relocations == target_relocations,
            "MSVC 4.20 atomic schedule/web changes a relocation observation",
        )
        for row in rewritten:
            rewritten_fields.append(
                {
                    "source_instruction": source_index,
                    "target_instruction": target_index,
                    **row,
                }
            )
            if source_index < first:
                raise ClassicSemanticError(
                    "MSVC 4.20 atomic schedule/web changes its symbolic window entry"
                )
            if source_index >= stop:
                source_name = cast(str, row["source_register"])
                target_name = cast(str, row["target_register"])
                previous = outside_cycle.setdefault(source_name, target_name)
                _require(
                    previous == target_name,
                    "MSVC 4.20 atomic schedule/web has no single exit register web",
                )
        if source_item["flow"] == "call":
            call_observations.append(
                {
                    "source_instruction": source_index,
                    "target_instruction": target_index,
                    "relocations": source_relocations,
                    "source_reads": sorted(source_item["reads"]),
                    "target_reads": sorted(target_item["reads"]),
                    "source_writes": sorted(source_item["writes"]),
                    "target_writes": sorted(target_item["writes"]),
                }
            )
        local_maps.append(local)
        correspondence.append([source_index, target_index])

    cycle = outside_cycle
    _require(
        2 <= len(cycle) <= 3
        and set(cycle) == set(cycle.values())
        and all(source_name != target_name for source_name, target_name in cycle.items()),
        "MSVC 4.20 atomic schedule/web exit image is not one bounded register cycle",
    )
    for source_index, local in enumerate(local_maps):
        if source_index in source_window:
            continue
        _require(
            all(
                target_name in {source_name, cycle.get(source_name)}
                for source_name, target_name in local.items()
            ),
            "MSVC 4.20 atomic schedule/web changes a field outside its exit web",
        )

    try:
        source_state = _srr_simulate(
            state.body,
            start,
            end,
            "MSVC 4.20 atomic schedule/web source window",
        )
        target_state = _srr_simulate(
            pair.effective_body,
            start,
            end,
            "MSVC 4.20 atomic schedule/web target window",
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    _require(
        all(
            source_state[0][source_name] == target_state[0][cycle.get(source_name, source_name)]
            for source_name in source_state[0]
        )
        and source_state[1:] == target_state[1:],
        "MSVC 4.20 atomic schedule/web window changes its mapped exit state",
    )

    try:
        source_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], source),
            "MSVC 4.20 atomic schedule/web source CFG",
            entry_offsets=frozenset(pair.external_entries),
        )
        target_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], target),
            "MSVC 4.20 atomic schedule/web target CFG",
            entry_offsets=frozenset(pair.external_entries),
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    for source_index, successors in enumerate(source_successors):
        if source_index in source_window:
            continue
        mapped = sorted(
            first if successor in source_window else pair_index[successor]
            for successor in successors
        )
        _require(
            mapped == sorted(target_successors[pair_index[source_index]]),
            "MSVC 4.20 atomic schedule/web changes control flow outside its window",
        )

    source_by_offset = {int(item["offset"]): index for index, item in enumerate(source)}
    target_by_offset = {int(item["offset"]): index for index, item in enumerate(target)}
    source_entries = frozenset({0} | {source_by_offset[offset] for offset in pair.external_entries})
    target_entries = frozenset({0} | {target_by_offset[offset] for offset in pair.external_entries})
    _require(
        {pair_index[index] for index in source_entries} == target_entries,
        "MSVC 4.20 atomic schedule/web changes a function entry",
    )
    source_incoming = _web_reaching_definitions(source, source_successors, source_entries)
    target_incoming = _web_reaching_definitions(target, target_successors, target_entries)
    definition_map = {
        ("entry", source_entry, register): ("entry", pair_index[source_entry], register)
        for source_entry in source_entries
        for register in IA32_GENERAL_REGISTER_NAMES
    }
    for source_index, source_item in enumerate(source):
        target_index = pair_index[source_index]
        local = local_maps[source_index]
        for register in source_item["writes"]:
            definition_map[("instruction", source_index, register)] = (
                "instruction",
                target_index,
                local[register],
            )
    target_definitions = {
        ("entry", entry, register)
        for entry in target_entries
        for register in IA32_GENERAL_REGISTER_NAMES
    } | {
        ("instruction", index, register)
        for index, item in enumerate(target)
        for register in item["writes"]
    }
    _require(
        set(definition_map.values()) == target_definitions,
        "MSVC 4.20 atomic schedule/web definition image is not bijective",
    )
    reaching_observations: list[dict[str, object]] = []
    for source_index, source_item in enumerate(source):
        if source_index in source_window:
            continue
        target_index = pair_index[source_index]
        local = local_maps[source_index]
        for register in sorted(source_item["reads"]):
            mapped_definitions = frozenset(
                definition_map[value] for value in source_incoming[source_index][register]
            )
            target_register = local[register]
            _require(
                mapped_definitions == target_incoming[target_index][target_register],
                "MSVC 4.20 atomic schedule/web changes a reaching definition",
            )
            reaching_observations.append(
                {
                    "source_instruction": source_index,
                    "target_instruction": target_index,
                    "source_register": register,
                    "target_register": target_register,
                    "definitions": sorted(mapped_definitions),
                }
            )

    return _ImageState(pair.effective_body, list(state.relocation_offsets)), {
        "kind": _THEOREM,
        "compiler_identity": compiler_identity.proof_receipt(),
        "window": {"start": start, "end": end, "target_order": list(order)},
        "exit_register_cycle": dict(sorted(cycle.items())),
        "instruction_correspondence_digest": Digest.from_bytes(
            canonical_json(correspondence)
        ).value,
        "rewritten_field_count": len(rewritten_fields),
        "rewritten_field_digest": Digest.from_bytes(canonical_json(rewritten_fields)).value,
        "simulation": {
            "mapped_registers": sorted(cycle.items()),
            "exact_components": [
                "floating-point-stack",
                "push-sequence",
                "frame-slots",
                "flags",
                "heap-base",
                "heap-slots",
            ],
        },
        "control_flow_digest": Digest.from_bytes(
            canonical_json(
                {
                    "source": source_successors,
                    "target": target_successors,
                    "instruction_correspondence": correspondence,
                }
            )
        ).value,
        "call_observation_count": len(call_observations),
        "call_observation_digest": Digest.from_bytes(canonical_json(call_observations)).value,
        "reaching_definition_observation_count": len(reaching_observations),
        "reaching_definition_digest": Digest.from_bytes(
            canonical_json(reaching_observations)
        ).value,
        "exact_image_digest": Digest.from_bytes(pair.effective_body).value,
        "relocation_offsets": list(state.relocation_offsets),
    }


def _try_atomic_schedule_register_web(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    compiler_identity: Msvc420CompilerIdentity | None,
) -> tuple[_ImageState, dict[str, object]] | None:
    """Prove one uniquely paired straight-line schedule and live register web."""

    if not (
        type(compiler_identity) is Msvc420CompilerIdentity
        and compiler_identity.target == MSVC420_WIN32_I386_TARGET
        and pair.eh_control_digest is None
        and len(state.body) == len(pair.effective_body)
        and state.relocation_offsets == list(target_records)
        and source_records == target_records
    ):
        return None
    source = _instructions(state.body, source_records, "MSVC 4.20 atomic schedule/web source")
    target = _instructions(
        pair.effective_body,
        target_records,
        "MSVC 4.20 atomic schedule/web target",
    )
    if len(source) != len(target):
        return None
    try:
        pairings = _schedule_pairing_candidates(
            _tokens(
                state.body,
                source,
                state.relocation_offsets,
                pair.clean_relocations,
                structural=True,
            ),
            _tokens(
                pair.effective_body,
                target,
                state.relocation_offsets,
                pair.effective_relocations,
                structural=True,
            ),
            source,
            target,
        )
    except ClassicSemanticError:
        return None
    if not pairings:
        return None
    if len(pairings) > _MAX_PAIRINGS:
        return None
    candidates: list[tuple[_ImageState, dict[str, object]]] = []
    for first, stop, order in pairings:
        try:
            candidates.append(
                _prove_candidate(
                    state,
                    pair,
                    source,
                    target,
                    source_records,
                    target_records,
                    first,
                    stop,
                    order,
                    compiler_identity,
                )
            )
        except ClassicSemanticError:
            continue
    if len(candidates) > 1:
        return None
    return candidates[0] if candidates else None


__all__ = []
