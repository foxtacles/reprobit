"""Whole-function web correspondence for an atomic saved-prologue permutation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypedDict, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.register_semantics import IA32_GENERAL_REGISTER_NAMES, ia32_register_atoms
from reprobit.classic.scheduling_dependence import ia32_esp_relative_displacement
from reprobit.classic.scheduling_webs import ia32_web_control_flow
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .compiler_state_foundation import (
    CompilerStateCodePair,
    _Instruction,
    _instruction_relocation_observations,
    _RelocationRecord,
)
from .compiler_state_prologue_evidence import _register_push
from .compiler_state_web import _field_registers, _web_reaching_definitions


class _CycleDefinition(TypedDict):
    source_instruction: int
    source_register: str
    target_instruction: int
    target_register: str


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ClassicSemanticError(message)


def _prove_whole_function_web(
    pair: CompilerStateCodePair,
    clean_instructions: Sequence[_Instruction],
    effective_instructions: Sequence[_Instruction],
    clean_records: Mapping[int, _RelocationRecord],
    effective_records: Mapping[int, _RelocationRecord],
    clean_window_indexes: Sequence[int],
    effective_window_indexes: Sequence[int],
    pair_index: Mapping[int, int],
    cycle: Mapping[str, str],
    adjustments: Sequence[Sequence[int]],
    save_by_register: Mapping[str, int],
    target_position: Mapping[int, int],
) -> tuple[bytes, dict[str, object]]:
    try:
        clean_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], clean_instructions),
            "MSVC 4.20 saved-prologue clean CFG",
            entry_offsets=frozenset(),
        )
        effective_successors = ia32_web_control_flow(
            cast(list[dict[Any, Any]], effective_instructions),
            "MSVC 4.20 saved-prologue effective CFG",
            entry_offsets=frozenset(),
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    clean_window_set = set(clean_window_indexes)
    for source_index, successors in enumerate(clean_successors):
        if source_index in clean_window_set:
            continue
        mapped_successors = sorted(pair_index[target] for target in successors)
        _require(
            mapped_successors == sorted(effective_successors[pair_index[source_index]]),
            "MSVC 4.20 saved-prologue control flow changes outside its linear window",
        )

    clean_incoming = _web_reaching_definitions(clean_instructions, clean_successors, frozenset({0}))
    effective_incoming = _web_reaching_definitions(
        effective_instructions, effective_successors, frozenset({0})
    )
    definition_map = {
        ("entry", 0, register): ("entry", 0, register) for register in IA32_GENERAL_REGISTER_NAMES
    }
    local_maps: list[dict[str, str]] = []
    rewritten_fields: list[dict[str, object]] = []
    call_observations: list[dict[str, object]] = []
    image = bytearray(len(pair.clean_body))
    covered = bytearray(len(pair.clean_body))
    adjustment_by_local = {row[0]: row for row in adjustments}
    source_window_local = {
        global_index: local for local, global_index in enumerate(clean_window_indexes)
    }
    cycle_definitions: list[_CycleDefinition] = []
    for source_index, source_item in enumerate(clean_instructions):
        target_index = pair_index[source_index]
        target_item = effective_instructions[target_index]
        source_start = int(source_item["offset"])
        target_start = int(target_item["offset"])
        source_length = int(source_item["length"])
        target_length = int(target_item["length"])
        _require(
            source_length == target_length
            and source_item["flow"] == target_item["flow"]
            and (
                source_index in clean_window_set
                or source_item.get("target") == target_item.get("target")
            ),
            "MSVC 4.20 saved-prologue instruction or control-flow structure changes",
        )
        source_fields = _field_registers(pair.clean_body, source_item)
        target_fields = _field_registers(pair.effective_body, target_item)
        source_field_positions = [
            (int(at) - source_start, int(shift)) for at, shift in source_item["fields"]
        ]
        target_field_positions = [
            (int(at) - target_start, int(shift)) for at, shift in target_item["fields"]
        ]
        _require(
            source_field_positions == target_field_positions
            and len(source_fields) == len(target_fields),
            "MSVC 4.20 saved-prologue register field structure changes",
        )
        local: dict[str, str] = {}
        piece = bytearray(pair.clean_body[source_start : source_start + source_length])
        window_local = source_window_local.get(source_index)
        adjustment = adjustment_by_local.get(window_local) if window_local is not None else None
        if adjustment is not None:
            _local_index, at, old, new = adjustment
            local_at = at - source_start
            found = ia32_esp_relative_displacement(
                pair.clean_body, cast(dict[str, Any], source_item)
            )
            _require(found is not None and found[0] != "no_displacement", "invalid ESP field")
            assert found is not None and isinstance(found[0], int)
            size = found[1]
            _require(
                int.from_bytes(piece[local_at : local_at + size], "little", signed=True) == old,
                "MSVC 4.20 saved-prologue stack field changed before reconstruction",
            )
            piece[local_at : local_at + size] = int(new).to_bytes(size, "little", signed=True)
        for ordinal, (source_register, target_register) in enumerate(
            zip(source_fields, target_fields, strict=True)
        ):
            previous = local.setdefault(source_register, target_register)
            _require(previous == target_register, "saved-prologue field map is non-functional")
            if source_register != target_register:
                _require(
                    cycle.get(source_register) == target_register,
                    "MSVC 4.20 saved-prologue changes a field outside its two-web cycle",
                )
                _require(
                    _register_push(pair.clean_body, source_item) is None
                    or source_index not in clean_window_set,
                    "MSVC 4.20 saved-prologue recolours a physical save PUSH",
                )
                byte_local, shift = source_field_positions[ordinal]
                piece[byte_local] = (
                    piece[byte_local] & ~(7 << shift)
                    | IA32_GENERAL_REGISTER_NAMES.index(target_register) << shift
                ) & 0xFF
                rewritten_fields.append(
                    {
                        "source_instruction": source_index,
                        "source_offset": source_start,
                        "target_instruction": target_index,
                        "target_offset": target_start,
                        "field": ordinal,
                        "source_register": source_register,
                        "image_register": target_register,
                    }
                )
        for register in set(source_item["reads"]) | set(source_item["writes"]):
            local.setdefault(register, register)
        mapped_reads = {local[register] for register in source_item["reads"] if register != "esp"}
        mapped_writes = {local[register] for register in source_item["writes"] if register != "esp"}
        _require(
            mapped_reads == set(target_item["reads"]) - {"esp"}
            and mapped_writes == set(target_item["writes"]) - {"esp"}
            and ("esp" in source_item["reads"]) == ("esp" in target_item["reads"])
            and ("esp" in source_item["writes"]) == ("esp" in target_item["writes"]),
            "MSVC 4.20 saved-prologue operand observations change",
        )
        for source_register, target_register in local.items():
            if source_register == target_register:
                continue
            _require(
                not ({source_register, target_register} & set(source_item["frozen"])),
                "MSVC 4.20 saved-prologue touches a partial register field",
            )
            if source_register in source_item["reads"]:
                _require(
                    ia32_register_atoms({source_register}) <= source_item["read_atoms"]
                    and ia32_register_atoms({target_register}) <= target_item["read_atoms"],
                    "MSVC 4.20 saved-prologue changes a partial register read",
                )
            if source_register in source_item["writes"]:
                _require(
                    ia32_register_atoms({source_register}) <= source_item["write_atoms"]
                    and ia32_register_atoms({target_register}) <= target_item["write_atoms"],
                    "MSVC 4.20 saved-prologue changes a partial register definition",
                )
                cycle_definitions.append(
                    {
                        "source_instruction": source_index,
                        "source_register": source_register,
                        "target_instruction": target_index,
                        "target_register": target_register,
                    }
                )
        source_relocations = _instruction_relocation_observations(
            source_start, source_start + source_length, clean_records
        )
        target_relocations = _instruction_relocation_observations(
            target_start, target_start + target_length, effective_records
        )
        _require(
            source_relocations == target_relocations,
            "MSVC 4.20 saved-prologue relocation observation changes",
        )
        if source_item["flow"] == "call":
            call_observations.append(
                {
                    "source_instruction": source_index,
                    "target_instruction": target_index,
                    "relocations": source_relocations,
                    "source_reads": sorted(source_item["reads"]),
                    "mapped_reads": sorted(mapped_reads),
                    "target_reads": sorted(set(target_item["reads"]) - {"esp"}),
                    "source_writes": sorted(source_item["writes"]),
                    "mapped_writes": sorted(mapped_writes),
                    "target_writes": sorted(set(target_item["writes"]) - {"esp"}),
                }
            )
        target_piece = pair.effective_body[target_start : target_start + target_length]
        _require(
            bytes(piece) == target_piece,
            "MSVC 4.20 saved-prologue reconstruction changes an unproved byte",
        )
        _require(
            not any(covered[target_start : target_start + target_length]),
            "MSVC 4.20 saved-prologue instruction correspondence overlaps an image seat",
        )
        image[target_start : target_start + target_length] = piece
        covered[target_start : target_start + target_length] = bytes([1]) * target_length
        for register in source_item["writes"]:
            if register != "esp":
                definition_map[("instruction", source_index, register)] = (
                    "instruction",
                    target_index,
                    local[register],
                )
        local_maps.append(local)
    _require(
        all(covered)
        and bytes(image) == pair.effective_body
        and len(definition_map) == len(set(definition_map.values())),
        "MSVC 4.20 saved-prologue exact image or definition bijection does not rejoin",
    )

    target_save_indexes = {
        name: effective_window_indexes[target_position[save_by_register[name]]] for name in cycle
    }
    for definition in cycle_definitions:
        _require(
            definition["target_instruction"] > target_save_indexes[definition["target_register"]],
            "MSVC 4.20 saved-prologue defines a web before saving its image register",
        )

    reaching_observations: list[dict[str, object]] = []
    for source_index, source_item in enumerate(clean_instructions):
        target_index = pair_index[source_index]
        local = local_maps[source_index]
        for register in sorted(set(source_item["reads"]) - {"esp"}):
            mapped_definitions = frozenset(
                definition_map[value] for value in clean_incoming[source_index][register]
            )
            target_register = local[register]
            _require(
                mapped_definitions == effective_incoming[target_index][target_register],
                "MSVC 4.20 saved-prologue changes a reaching definition",
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

    proof = {
        "rewritten_field_count": len(rewritten_fields),
        "rewritten_field_digest": Digest.from_bytes(canonical_json(rewritten_fields)).value,
        "control_flow_digest": Digest.from_bytes(
            canonical_json(
                {
                    "clean": clean_successors,
                    "effective": effective_successors,
                    "instruction_correspondence": sorted(pair_index.items()),
                }
            )
        ).value,
        "call_observation_count": len(call_observations),
        "call_observation_digest": Digest.from_bytes(canonical_json(call_observations)).value,
        "reaching_definition_observation_count": len(reaching_observations),
        "reaching_definition_digest": Digest.from_bytes(
            canonical_json(reaching_observations)
        ).value,
    }
    return bytes(image), proof
