"""Register bijection and atomic def-use web proofs for compiler-state projection."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import combinations, permutations
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.registers import (
    IA32_GENERAL_REGISTER_NAMES,
    apply_register_bijection,
    ia32_register_atoms,
)
from reprobit.classic.scheduling import apply_web_recolour, ia32_web_control_flow
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
    _relocation_parts,
    _RelocationRecord,
    _ScheduleDeclaration,
    _tokens,
)
from .compiler_state_schedule import _schedule_candidate


def _try_register_bijection(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_statements: Sequence[Mapping[str, object]],
    target_offsets: Sequence[int],
    target_records: Mapping[int, _RelocationRecord],
    target_statements: Sequence[Mapping[str, object]],
) -> tuple[_ImageState, dict[str, object]] | None:
    source_base_offsets, source_base_records = _relocation_parts(
        source_statements, "MSVC 4.20 compiler-state source code"
    )
    source_records = {
        offset: source_base_records[original]
        for offset, original in zip(state.relocation_offsets, source_base_offsets, strict=True)
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
        structural=False,
    )
    target_tokens = _tokens(
        pair.effective_body,
        target_instructions,
        target_offsets,
        target_statements,
        structural=False,
    )
    if len(source_tokens) != len(target_tokens):
        return None
    changed = [
        index
        for index, (source, target) in enumerate(zip(source_tokens, target_tokens, strict=True))
        if source != target
    ]
    if not changed:
        return None
    first, last = changed[0], changed[-1]
    start = int(source_instructions[first]["offset"])
    end = int(source_instructions[last]["offset"]) + int(source_instructions[last]["length"])
    if start != int(target_instructions[first]["offset"]) or end != int(
        target_instructions[last]["offset"]
    ) + int(target_instructions[last]["length"]):
        return None
    if any(start < entry < end for entry in pair.external_entries):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state register region contains a funclet entry"
        )
    # A register web can end at an interior boundary of a pending schedule.
    # Keep discovery bounded to boundaries supplied by the one exact
    # structural permutation already visible in the paired compiler images;
    # the bijection primitive still proves dead entry/exit and the caller then
    # proves the schedule independently.
    structural_candidate = _schedule_candidate(
        _tokens(
            state.body,
            source_instructions,
            state.relocation_offsets,
            source_statements,
            structural=True,
        ),
        _tokens(
            pair.effective_body,
            target_instructions,
            target_offsets,
            target_statements,
            structural=True,
        ),
        source_instructions,
        target_instructions,
    )
    region_ends = {end}
    if structural_candidate is not None:
        schedule_first, schedule_stop, _order = structural_candidate
        region_ends.update(
            boundary
            for boundary in (
                int(source_instructions[index]["offset"])
                for index in range(schedule_first + 1, schedule_stop)
            )
            if start < boundary < end
        )
    relocation_bytes = _relocation_bytes(state.relocation_offsets, source_records)
    registers = tuple(name for name in IA32_GENERAL_REGISTER_NAMES if name != "esp")
    candidates: list[tuple[dict[str, str], int, bytes, dict[str, object]]] = []
    for region_end in sorted(region_ends):
        for size in (2, 3):
            for support in combinations(registers, size):
                for image_support in permutations(support):
                    if any(
                        source == target
                        for source, target in zip(support, image_support, strict=True)
                    ):
                        continue
                    mapping = dict(zip(support, image_support, strict=True))
                    try:
                        image, proof = apply_register_bijection(
                            state.body,
                            mapping,
                            (start, region_end),
                            relocation_bytes,
                            "MSVC 4.20 compiler-state register bijection",
                            source_records,
                        )
                    except ByteIdentityError:
                        continue
                    image_instructions = _instructions(
                        image,
                        source_records,
                        "MSVC 4.20 compiler-state register image",
                    )
                    image_tokens = _tokens(
                        image,
                        image_instructions,
                        state.relocation_offsets,
                        source_statements,
                        structural=False,
                    )
                    if (
                        image_tokens[:first] == target_tokens[:first]
                        and image_tokens[last + 1 :] == target_tokens[last + 1 :]
                        and Counter(image_tokens[first : last + 1])
                        == Counter(target_tokens[first : last + 1])
                    ):
                        candidates.append((mapping, region_end, image, proof))
    if len(candidates) != 1:
        return None
    mapping, region_end, image, proof = candidates[0]
    return _ImageState(image, list(state.relocation_offsets)), {
        "kind": "dead-boundary-register-bijection-v1",
        "mapping": dict(sorted(mapping.items())),
        "region": {"start": start, "end": region_end},
        **proof,
    }


def _field_registers(body: bytes, item: _Instruction) -> list[str]:
    return [
        IA32_GENERAL_REGISTER_NAMES[body[int(byte_index)] >> int(shift) & 7]
        for byte_index, shift in item["fields"]
    ]


def _derived_web_declarations(
    source_body: bytes,
    target_body: bytes,
    source: Sequence[_Instruction],
    target: Sequence[_Instruction],
    *,
    frame_pointer_free: bool = False,
) -> list[dict[str, Any]]:
    if len(source) != len(target):
        raise ClassicSemanticError("MSVC 4.20 compiler-state web proof changes instruction count")
    changed: dict[tuple[str, str], list[tuple[int, int, int]]] = {}
    for index, (source_item, target_item) in enumerate(zip(source, target, strict=True)):
        if (
            source_item["offset"] != target_item["offset"]
            or source_item["length"] != target_item["length"]
            or source_item["flow"] != target_item["flow"]
            or source_item.get("target") != target_item.get("target")
            or source_item["fields"] != target_item["fields"]
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state web proof changes instruction or control-flow structure"
            )
        source_fields = _field_registers(source_body, source_item)
        target_fields = _field_registers(target_body, target_item)
        for ordinal, (source_register, target_register) in enumerate(
            zip(source_fields, target_fields, strict=True)
        ):
            if source_register == target_register:
                continue
            byte_index, _shift = source_item["fields"][ordinal]
            changed.setdefault((source_register, target_register), []).append(
                (index, ordinal, int(byte_index))
            )
    if not changed:
        raise ClassicSemanticError("MSVC 4.20 compiler-state web proof recolours no register web")
    declarations: list[dict[str, Any]] = []
    structural_registers = {"esp"} if frame_pointer_free else {"esp", "ebp"}
    for (source_register, target_register), entries in sorted(changed.items()):
        if {source_register, target_register} & structural_registers:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state web proof touches a structural register"
            )
        by_instruction: dict[int, list[tuple[int, int]]] = {}
        for index, ordinal, byte_index in entries:
            by_instruction.setdefault(index, []).append((ordinal, byte_index))
        definitions: list[object] = []
        uses: list[object] = []
        rewritten: set[int] = set()
        for index, fields in sorted(by_instruction.items()):
            item = source[index]
            reads = source_register in item["reads"]
            writes = source_register in item["writes"]
            if not reads and not writes:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state web field has no decoded register role"
                )
            ordinals = [ordinal for ordinal, _byte in fields]
            source_ordinals = [
                ordinal
                for ordinal, name in enumerate(_field_registers(source_body, item))
                if name == source_register
            ]
            offset = int(item["offset"])
            if reads and writes:
                if sorted(ordinals) != source_ordinals:
                    raise ClassicSemanticError(
                        "MSVC 4.20 compiler-state web partially recolours a read-write definition"
                    )
                member: object = offset
            elif len(ordinals) == 1:
                member = [offset, ordinals[0]]
            elif sorted(ordinals) == source_ordinals:
                member = offset
            else:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state web has an ambiguous operand-field subset"
                )
            if writes:
                definitions.append(member)
            if reads:
                uses.append(member)
            rewritten.update(byte for _ordinal, byte in fields)
        if not definitions or not uses:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state web lacks one complete definition/use closure"
            )
        declarations.append(
            {
                "source_register": source_register,
                "image_register": target_register,
                "definitions": definitions,
                "uses": uses,
                "expected_rewritten_offsets": sorted(rewritten),
            }
        )
    return declarations


_Definition = tuple[str, int, str]


def _web_predecessors(successors: Sequence[Sequence[int]]) -> list[list[int]]:
    result: list[list[int]] = [[] for _ in successors]
    for source, edges in enumerate(successors):
        for target in edges:
            result[target].append(source)
    return result


def _web_reaching_definitions(
    instructions: Sequence[_Instruction],
    successors: Sequence[Sequence[int]],
    entry_indexes: frozenset[int],
) -> list[dict[str, frozenset[_Definition]]]:
    registers = tuple(IA32_GENERAL_REGISTER_NAMES)
    predecessors = _web_predecessors(successors)
    incoming: list[dict[str, frozenset[_Definition]]] = [
        {register: frozenset() for register in registers} for _ in instructions
    ]
    outgoing: list[dict[str, frozenset[_Definition]]] = [
        {register: frozenset() for register in registers} for _ in instructions
    ]
    changed = True
    while changed:
        changed = False
        for index, item in enumerate(instructions):
            merged: dict[str, frozenset[_Definition]] = {}
            for register in registers:
                values: set[_Definition] = set()
                if index in entry_indexes:
                    values.add(("entry", index, register))
                for previous in predecessors[index]:
                    values.update(outgoing[previous][register])
                merged[register] = frozenset(values)
            updated = dict(merged)
            for register in item["writes"]:
                updated[register] = frozenset({("instruction", index, register)})
            if merged != incoming[index] or updated != outgoing[index]:
                incoming[index] = merged
                outgoing[index] = updated
                changed = True
    return incoming


def _prove_simultaneous_register_webs(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    declarations: Sequence[_ScheduleDeclaration],
    *,
    frame_pointer_free: bool = False,
) -> tuple[_ImageState, dict[str, object]]:
    if not 2 <= len(declarations) <= 3:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web cycle is outside its closed size bound"
        )
    mapping = {str(item["source_register"]): str(item["image_register"]) for item in declarations}
    if (
        len(mapping) != len(declarations)
        or set(mapping) != set(mapping.values())
        or any(source == target for source, target in mapping.items())
        or ({"esp"} if frame_pointer_free else {"esp", "ebp"})
        & (set(mapping) | set(mapping.values()))
    ):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web fields are not one "
            "structural-register-free cycle"
        )
    source = _instructions(state.body, source_records, "MSVC 4.20 compiler-state source web cycle")
    target = _instructions(
        pair.effective_body,
        target_records,
        "MSVC 4.20 compiler-state effective web cycle",
    )
    if len(source) != len(target):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web cycle changes instruction count"
        )
    try:
        source_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], source),
            "MSVC 4.20 compiler-state source web cycle",
            entry_offsets=frozenset(pair.external_entries),
        )
        target_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], target),
            "MSVC 4.20 compiler-state effective web cycle",
            entry_offsets=frozenset(pair.external_entries),
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    if source_successors != target_successors:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web cycle changes control flow"
        )
    index_of = {int(item["offset"]): index for index, item in enumerate(source)}
    entry_indexes = frozenset(
        {0} | {index_of[offset] for offset in pair.external_entries if offset in index_of}
    )
    source_incoming = _web_reaching_definitions(source, source_successors, entry_indexes)
    target_incoming = _web_reaching_definitions(target, target_successors, entry_indexes)
    relocation_bytes = _relocation_bytes(state.relocation_offsets, source_records)
    image = bytearray(state.body)
    source_masked = bytearray(state.body)
    target_masked = bytearray(pair.effective_body)
    definition_map: dict[_Definition, _Definition] = {
        ("entry", entry, register): ("entry", entry, register)
        for entry in entry_indexes
        for register in IA32_GENERAL_REGISTER_NAMES
    }
    instruction_maps: list[dict[str, str]] = []
    rewritten: set[int] = set()
    call_observations: list[dict[str, object]] = []
    for index, (source_item, target_item) in enumerate(zip(source, target, strict=True)):
        if (
            source_item["offset"] != target_item["offset"]
            or source_item["length"] != target_item["length"]
            or source_item["flow"] != target_item["flow"]
            or source_item.get("target") != target_item.get("target")
            or source_item["fields"] != target_item["fields"]
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state simultaneous web cycle changes instruction structure"
            )
        local: dict[str, str] = {}
        source_fields = _field_registers(state.body, source_item)
        target_fields = _field_registers(pair.effective_body, target_item)
        for ordinal, (source_register, target_register) in enumerate(
            zip(source_fields, target_fields, strict=True)
        ):
            previous = local.setdefault(source_register, target_register)
            if previous != target_register:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web has a non-functional field image"
                )
            byte_index, shift = source_item["fields"][ordinal]
            byte_index = int(byte_index)
            shift = int(shift)
            source_masked[byte_index] &= ~(7 << shift) & 0xFF
            target_masked[byte_index] &= ~(7 << shift) & 0xFF
            if source_register == target_register:
                continue
            if source_register not in mapping or mapping[source_register] != target_register:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web changes a field outside its cycle"
                )
            if byte_index in relocation_bytes:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web overlaps a relocation field"
                )
            if {source_register, target_register} & set(source_item.get("frozen", frozenset())):
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web touches a partial register field"
                )
            image[byte_index] = (
                image[byte_index] & ~(7 << shift)
                | IA32_GENERAL_REGISTER_NAMES.index(target_register) << shift
            ) & 0xFF
            rewritten.add(byte_index)
        for register in set(source_item["reads"]) | set(source_item["writes"]):
            local.setdefault(register, register)
        mapped_reads = {local[register] for register in source_item["reads"]}
        mapped_writes = {local[register] for register in source_item["writes"]}
        if mapped_reads != set(target_item["reads"]) or mapped_writes != set(target_item["writes"]):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state simultaneous web changes an operand observation"
            )
        if len(mapped_writes) != len(source_item["writes"]):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state simultaneous web merges definitions"
            )
        if source_item["flow"] == "call":
            start = int(source_item["offset"])
            end = start + int(source_item["length"])
            call_observations.append(
                {
                    "instruction": index,
                    "offset": start,
                    "source_relocations": _instruction_relocation_observations(
                        start, end, source_records
                    ),
                    "effective_relocations": _instruction_relocation_observations(
                        start, end, target_records
                    ),
                    "source_reads": sorted(source_item["reads"]),
                    "effective_reads": sorted(target_item["reads"]),
                    "mapped_source_reads": sorted(mapped_reads),
                    "source_writes": sorted(source_item["writes"]),
                    "effective_writes": sorted(target_item["writes"]),
                    "mapped_source_writes": sorted(mapped_writes),
                    "observed_cycle_registers": sorted(
                        set(source_item["reads"]) & (set(mapping) | set(mapping.values()))
                    ),
                }
            )
        for register in source_item["writes"]:
            target_register = local[register]
            if target_register != register and (
                not ia32_register_atoms({register}) <= source_item["write_atoms"]
                or not ia32_register_atoms({target_register}) <= target_item["write_atoms"]
            ):
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web changes a partial definition"
                )
            definition_map[("instruction", index, register)] = (
                "instruction",
                index,
                target_register,
            )
        instruction_maps.append(local)
    for offset in relocation_bytes:
        source_masked[offset] = 0
        target_masked[offset] = 0
    if source_masked != target_masked or bytes(image) != pair.effective_body:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web does not reproduce only register fields"
        )
    if len(set(definition_map.values())) != len(definition_map):
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state simultaneous web is not a definition bijection"
        )
    observations: list[dict[str, object]] = []
    for index, item in enumerate(source):
        local = instruction_maps[index]
        for register in sorted(item["reads"]):
            target_register = local[register]
            mapped = frozenset(definition_map[value] for value in source_incoming[index][register])
            if mapped != target_incoming[index][target_register]:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state simultaneous web changes a reaching definition"
                )
            observations.append(
                {
                    "instruction": index,
                    "source_register": register,
                    "target_register": target_register,
                    "reaching_definitions": sorted(mapped),
                }
            )
    return _ImageState(pair.effective_body, list(state.relocation_offsets)), {
        "kind": "simultaneous-register-web-cycle-v1",
        "mapping": dict(sorted(mapping.items())),
        "declarations": [dict(item) for item in declarations],
        "rewritten_offsets": sorted(rewritten),
        "instruction_count": len(source),
        "control_flow_digest": Digest.from_bytes(canonical_json(source_successors)).value,
        "call_observation_count": len(call_observations),
        "call_observation_digest": Digest.from_bytes(canonical_json(call_observations)).value,
        "reaching_definition_observation_count": len(observations),
        "reaching_definition_digest": Digest.from_bytes(canonical_json(observations)).value,
    }


def _prove_register_web_recolour(
    state: _ImageState,
    pair: CompilerStateCodePair,
    source_records: Mapping[int, _RelocationRecord],
    target_records: Mapping[int, _RelocationRecord],
    *,
    frame_pointer_free: bool = False,
) -> tuple[_ImageState, dict[str, object]]:
    source = _instructions(state.body, source_records, "MSVC 4.20 compiler-state source web")
    target = _instructions(
        pair.effective_body, target_records, "MSVC 4.20 compiler-state effective web"
    )
    declarations = _derived_web_declarations(
        state.body,
        pair.effective_body,
        source,
        target,
        frame_pointer_free=frame_pointer_free,
    )
    if len(declarations) > 3:
        raise ClassicSemanticError(
            "MSVC 4.20 compiler-state web recolour exceeds its closed three-web bound"
        )
    relocation_bytes = _relocation_bytes(state.relocation_offsets, source_records)
    for candidate in permutations(declarations):
        try:
            image, proof = apply_web_recolour(
                state.body,
                list(candidate),
                relocation_bytes,
                "MSVC 4.20 compiler-state web recolour",
                dict(source_records),
                frame_pointer_free=frame_pointer_free,
                entry_offsets=frozenset(pair.external_entries),
            )
        except ByteIdentityError:
            continue
        if image == pair.effective_body:
            return _ImageState(pair.effective_body, list(state.relocation_offsets)), {
                "kind": "derived-register-web-recolour-v1",
                "declaration": list(candidate),
                **proof,
            }
    return _prove_simultaneous_register_webs(
        state,
        pair,
        source_records,
        target_records,
        declarations,
        frame_pointer_free=frame_pointer_free,
    )
