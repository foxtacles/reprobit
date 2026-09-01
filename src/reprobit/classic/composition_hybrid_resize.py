"""Classic compiler algorithms: cross-TU complete-target and instruction hybrid resize candidates."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    coff_auxiliary,
    coff_body,
    coff_unpack,
    detailed_relocations,
    section_definitions,
)

from .coff import (
    _coff_marker,
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity,
    comdat_primary_identity_multiset,
    function_multiset,
    function_symbol,
)
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_relocations import require_instruction_mosaic_semantic_relocations
from .composition_same_slot import compose_same_slot_resize
from .debug import (
    parse_fpo_data,
)
from .foundation import (
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import (
    CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS,
    CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
    SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
    SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS,
    require_coff_line_certified_ia32_boundaries,
    require_supported_complete_ia32_instruction,
    validate_cross_tu_instruction_hybrid_ranges,
)
from .source_proofs import (
    require_same_tu_source_identity,
)


def produce_cross_tu_complete_target_resize_candidate(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    complete_donor_bytes: bytes,
    function: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    """Normalize one complete cross-TU COMDAT into an owner-TU carrier.

    The complete donor supplies the entire code body, COFF line rows, FPO
    record, and CodeView procedure range.  The equal-sized owner-TU carrier
    supplies only object-local seats, symbol indices, and CodeView type-index
    namespace.  No instruction ranges or partial code transfers exist in
    this class.  The normalized whole target is then passed to the unchanged
    retail-exact same-slot resize composer.
    """
    require_payload_free_declaration(function, "complete-target resize declaration")
    require(
        function.get("splice_class") == CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS,
        "splice class is not the cross-TU complete-target resize",
    )
    forbidden = {
        "instruction_ranges",
        "instruction_donor",
        "target_bytes",
        "instruction_donor_bytes",
        "donor_variants",
    }
    require(
        not forbidden.intersection(function),
        "complete-target resize may not carry instruction ranges",
    )
    seed = CoffObject(seed_bytes)
    target = CoffObject(target_donor_bytes)
    complete = CoffObject(complete_donor_bytes)
    mangled = function["mangled"]
    seed_primary = seed.function_section(mangled)
    target_primary = target.function_section(mangled)
    complete_primary = complete.function_section(mangled)

    def require_object_pins(role, coff, primary, prefix, length_name):
        require(
            len(coff.sections) == function[f"expected_{prefix}_section_count"]
            and primary["number"] == function[f"expected_{prefix}_section_number"],
            f"{role} section census or seat changed",
        )
        require(
            primary["raw_size"] == function[length_name]
            and primary["relocation_count"] == function[f"expected_{prefix}_relocation_count"]
            and (primary["line_count"] == function[f"expected_{prefix}_line_count"]),
            f"{role} body/table census changed",
        )
        require(
            sha256_bytes(coff_body(coff, primary)) == function[f"expected_{prefix}_body_sha256"],
            f"{role} body differs from its pin",
        )
        require(
            instruction_mosaic_metadata_sha256(coff, primary)
            == function[f"expected_{prefix}_metadata_sha256"],
            f"{role} metadata differs from its pin",
        )
        require(
            sum(function_multiset(coff).values()) == function[f"expected_{prefix}_function_count"]
            and sum(comdat_primary_identity_multiset(coff).values())
            == function[f"expected_{prefix}_comdat_count"],
            f"{role} function/COMDAT census changed",
        )

    require_object_pins("seed", seed, seed_primary, "seed", "expected_seed_length")
    require_object_pins(
        "target donor", target, target_primary, "target_donor", "expected_donor_length"
    )
    require_object_pins(
        "complete donor",
        complete,
        complete_primary,
        "complete_donor",
        "expected_complete_donor_length",
    )
    require(
        function_multiset(seed) == function_multiset(target)
        and comdat_primary_identity_multiset(seed) == comdat_primary_identity_multiset(target),
        "target donor is not an owner-TU topology carrier",
    )
    require(
        comdat_primary_identity(seed, seed_primary)
        == comdat_primary_identity(target, target_primary)
        == comdat_primary_identity(complete, complete_primary),
        "complete donor is not the exact same mangled COMDAT",
    )
    for role, coff, primary in (
        ("seed", seed, seed_primary),
        ("target donor", target, target_primary),
        ("complete donor", complete, complete_primary),
    ):
        require(
            primary["characteristics"] == function["expected_characteristics"]
            and section_definitions(coff)[primary["number"]]["selection"]
            == function["expected_selection"],
            f"{role} COMDAT characteristics or selection changed",
        )
        require(
            _comdat_child_closure(coff, primary) == (2, tuple(function["expected_donor_closure"])),
            f"{role} complete-target closure changed",
        )
    require(
        target_primary["raw_size"] == complete_primary["raw_size"]
        and target_primary["relocation_count"] == complete_primary["relocation_count"]
        and (target_primary["line_count"] == complete_primary["line_count"]),
        "complete donor and owner carrier target shapes differ",
    )

    def preceding_file_aux(coff, primary):
        function_index, _ = function_symbol(coff, mangled, primary["number"])
        candidates = [
            (index, symbol)
            for index, symbol in coff.symbols.items()
            if index < function_index
            and symbol["name"] == ".file"
            and (symbol["storage"] == 103)
            and (symbol["section"] == -2)
            and (symbol["aux_count"] >= 1)
        ]
        require(candidates, "complete-target function has no preceding .file record")
        index, symbol = max(candidates, key=lambda item: item[0])
        start = coff.symbol_offset + (index + 1) * 18
        end = start + symbol["aux_count"] * 18
        require(end <= len(coff.data), "complete-target preceding .file record is truncated")
        return coff.data[start:end]

    file_aux = preceding_file_aux(seed, seed_primary)
    require(
        file_aux
        == preceding_file_aux(target, target_primary)
        == preceding_file_aux(complete, complete_primary)
        and sha256_bytes(file_aux) == function["expected_preceding_file_aux_sha256"],
        "complete-target preceding .file bytes differ",
    )

    def relocation_semantics(coff, section, primary_number):
        return [
            (
                row["offset"],
                row["type"],
                row["addend"],
                row["target"],
                "primary" if row["target_section"] == primary_number else "external",
                row["target_value"],
                row["target_type"],
                row["target_storage"],
            )
            for row in detailed_relocations(coff, section)
        ]

    require(
        relocation_semantics(target, target_primary, target_primary["number"])
        == relocation_semantics(complete, complete_primary, complete_primary["number"]),
        "complete donor primary relocation semantics differ",
    )
    target_children = {}
    complete_children = {}
    for child_name in function["expected_donor_closure"]:
        target_child = _comdat_child(target, target_primary, child_name)
        complete_child = _comdat_child(complete, complete_primary, child_name)
        target_children[child_name] = target_child
        complete_children[child_name] = complete_child
        require(
            all(
                target_child[field] == complete_child[field]
                for field in (
                    "name",
                    "raw_size",
                    "relocation_count",
                    "line_count",
                    "characteristics",
                )
            ),
            f"complete donor {child_name} geometry differs",
        )
        require(
            relocation_semantics(target, target_child, target_primary["number"])
            == relocation_semantics(complete, complete_child, complete_primary["number"]),
            f"complete donor {child_name} relocation semantics differ",
        )
    for marker_name in (".bf", ".ef"):
        target_index, target_marker = _coff_marker(target, marker_name, target_primary["number"])
        complete_index, complete_marker = _coff_marker(
            complete, marker_name, complete_primary["number"]
        )
        target_aux = coff_auxiliary(target, target_index, target_marker)
        complete_aux = coff_auxiliary(complete, complete_index, complete_marker)
        require(
            target_aux[4:6] == complete_aux[4:6]
            and target_aux[:4] == complete_aux[:4]
            and (target_aux[6:12] == complete_aux[6:12])
            and (target_aux[16:] == complete_aux[16:]),
            f"complete donor {marker_name} source-line identity differs",
        )
    target_lines = _coff_table_bytes(target, target_primary, "lines")
    complete_lines = bytearray(_coff_table_bytes(complete, complete_primary, "lines"))
    target_function_index, _ = function_symbol(target, mangled, target_primary["number"])
    complete_function_index, _ = function_symbol(complete, mangled, complete_primary["number"])
    require(
        coff_unpack("<IH", target_lines, 0, "target line sentinel") == (target_function_index, 0)
        and coff_unpack("<IH", bytes(complete_lines), 0, "complete line sentinel")
        == (complete_function_index, 0),
        "complete-target COFF line sentinel is invalid",
    )
    complete_lines[0:4] = target_function_index.to_bytes(4, "little")
    previous = -1
    for index in range(1, complete_primary["line_count"]):
        offset, line = coff_unpack(
            "<IH", bytes(complete_lines), index * 6, "complete-target line row"
        )
        require(
            line != 0 and previous <= offset < complete_primary["raw_size"],
            "complete-target COFF line row is outside/nonmonotonic",
        )
        previous = offset
    normalized_lines = bytes(complete_lines)
    target_fpo_section = target_children[".debug$F"]
    complete_fpo_section = complete_children[".debug$F"]
    complete_fpo = coff_body(complete, complete_fpo_section)
    parse_fpo_data(complete_fpo, expected_proc_size=complete_primary["raw_size"])
    target_debug_section = target_children[".debug$S"]
    complete_debug_section = complete_children[".debug$S"]
    target_debug = coff_body(target, target_debug_section)
    complete_debug = coff_body(complete, complete_debug_section)
    require(
        len(target_debug) == len(complete_debug) >= 28
        and target_debug[2:4] == complete_debug[2:4] == b"\x05\x02",
        "complete-target debug$S is not one S_*PROC32 record",
    )
    complete_cbproc, complete_dbgstart, complete_dbgend = coff_unpack(
        "<III", complete_debug, 16, "complete-target debug range"
    )
    require(
        complete_cbproc == complete_primary["raw_size"]
        and 0 <= complete_dbgstart <= complete_dbgend < complete_cbproc,
        "complete-target debug procedure range is stale",
    )
    debug_differences = [
        index
        for index, (left, right) in enumerate(zip(target_debug, complete_debug, strict=True))
        if left != right
    ]
    require(
        debug_differences == function["expected_debug_s_diff_offsets"],
        "complete-target debug$S difference set changed",
    )
    type_bytes = {
        byte
        for offset in function["expected_codeview_type_index_offsets"]
        for byte in (offset, offset + 1)
    }
    require(
        set(debug_differences) - set(range(16, 28)) == type_bytes,
        "complete-target CodeView differences are not type-index words",
    )
    normalized_debug = bytearray(target_debug)
    normalized_debug[16:28] = complete_debug[16:28]
    normalized_debug = bytes(normalized_debug)
    normalized = bytearray(target_donor_bytes)
    normalized[
        target_primary["raw_offset"] : target_primary["raw_offset"] + target_primary["raw_size"]
    ] = coff_body(complete, complete_primary)
    normalized[
        target_primary["line_offset"] : target_primary["line_offset"] + len(normalized_lines)
    ] = normalized_lines
    normalized[
        target_fpo_section["raw_offset"] : target_fpo_section["raw_offset"] + len(complete_fpo)
    ] = complete_fpo
    normalized[
        target_debug_section["raw_offset"] : target_debug_section["raw_offset"]
        + len(normalized_debug)
    ] = normalized_debug
    normalized = bytes(normalized)
    allowed_offsets = (
        set(
            range(
                target_primary["raw_offset"],
                target_primary["raw_offset"] + target_primary["raw_size"],
            )
        )
        | set(
            range(
                target_primary["line_offset"], target_primary["line_offset"] + len(normalized_lines)
            )
        )
        | set(
            range(
                target_fpo_section["raw_offset"],
                target_fpo_section["raw_offset"] + target_fpo_section["raw_size"],
            )
        )
        | set(
            range(target_debug_section["raw_offset"] + 16, target_debug_section["raw_offset"] + 28)
        )
    )
    changed_offsets = {
        index
        for index, (left, right) in enumerate(zip(target_donor_bytes, normalized, strict=True))
        if left != right
    }
    require(
        changed_offsets and changed_offsets <= allowed_offsets,
        "complete-target normalizer changed a non-target byte",
    )
    normalized_coff = CoffObject(normalized)
    normalized_primary = normalized_coff.function_section(mangled)
    normalized_fpo_section = _comdat_child(normalized_coff, normalized_primary, ".debug$F")
    normalized_debug_section = _comdat_child(normalized_coff, normalized_primary, ".debug$S")
    require(
        sha256_bytes(coff_body(normalized_coff, normalized_primary))
        == function["expected_normalized_body_sha256"]
        and sha256_bytes(_coff_table_bytes(normalized_coff, normalized_primary, "lines"))
        == function["expected_normalized_line_sha256"]
        and (
            sha256_bytes(coff_body(normalized_coff, normalized_fpo_section))
            == function["expected_normalized_fpo_sha256"]
        )
        and (
            sha256_bytes(coff_body(normalized_coff, normalized_debug_section))
            == function["expected_normalized_debug_s_sha256"]
        )
        and (
            instruction_mosaic_metadata_sha256(normalized_coff, normalized_primary)
            == function["expected_normalized_metadata_sha256"]
        ),
        "complete-target normalized closure differs from its pins",
    )
    require(
        function_multiset(normalized_coff) == function_multiset(target)
        and comdat_primary_identity_multiset(normalized_coff)
        == comdat_primary_identity_multiset(target)
        and (
            detailed_relocations(normalized_coff, normalized_primary)
            == detailed_relocations(target, target_primary)
        ),
        "complete-target normalization changed owner topology/relocations",
    )
    effective = {
        "mangled": mangled,
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": function["expected_seed_length"],
        "expected_donor_length": function["expected_donor_length"],
        "expected_linked_span": function["expected_linked_span"],
        "expected_body_sha256": function["expected_normalized_body_sha256"],
        "retail_oracle": function["retail_oracle"],
        "retail_relocations": function["retail_relocations"],
    }
    if function["expected_target_donor_section_number"] != function["expected_seed_section_number"]:
        effective["expected_donor_section_number"] = function[
            "expected_target_donor_section_number"
        ]
    composed, detail = compose_same_slot_resize(seed_bytes, normalized, effective)
    return (
        composed,
        {
            **detail,
            "splice_class": CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS,
            "complete_donor_body_sha256": sha256_bytes(coff_body(complete, complete_primary)),
            "normalized_metadata_sha256": instruction_mosaic_metadata_sha256(
                normalized_coff, normalized_primary
            ),
            "normalized_changed_byte_count": len(changed_offsets),
        },
    )


def _produce_instruction_hybrid_resize_candidate_core(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    instruction_donor_bytes: bytes,
    function: dict[str, Any],
    *,
    source_aware: bool,
    same_tu_source_identical: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Import complete same-mangled instructions, then resize normally.

    The target donor supplies the complete resize closure.  A second freshly
    compiled donor state may supply only manifest-pinned instruction bytes
    from its definition of that exact mangled COMDAT.  The temporary hybrid
    is never a link input: after proving that it differs from the target donor
    only inside the declared text ranges, it is handed to the unchanged
    retail-exact same-slot composer.
    """
    require(
        not (source_aware and same_tu_source_identical), "instruction hybrid source modes overlap"
    )
    expected_class = (
        SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
        if same_tu_source_identical
        else SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS
        if source_aware
        else CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
    )
    fully_pinned = source_aware or same_tu_source_identical
    require(
        function.get("splice_class") == expected_class,
        "splice class is not the selected instruction hybrid resize",
    )
    seed = CoffObject(seed_bytes)
    target = CoffObject(target_donor_bytes)
    instruction_donor = CoffObject(instruction_donor_bytes)
    mangled = function["mangled"]
    seed_primary = seed.function_section(mangled)
    target_primary = target.function_section(mangled)
    instruction_primary = instruction_donor.function_section(mangled)
    require(
        len(target.sections) == function["expected_target_donor_section_count"]
        and target_primary["number"] == function["expected_target_donor_section_number"],
        "target donor section census or seat changed",
    )
    require(
        len(instruction_donor.sections) == function["expected_instruction_donor_section_count"]
        and instruction_primary["number"] == function["expected_instruction_donor_section_number"],
        "instruction donor section census or seat changed",
    )
    require(
        target_primary["raw_size"] == function["expected_donor_length"]
        and target_primary["relocation_count"] == function["expected_target_donor_relocation_count"]
        and (target_primary["line_count"] == function["expected_target_donor_line_count"]),
        "target donor body/table census changed",
    )
    require(
        instruction_primary["raw_size"] == function["expected_instruction_donor_length"]
        and instruction_primary["relocation_count"]
        == function["expected_instruction_donor_relocation_count"]
        and (
            instruction_primary["line_count"] == function["expected_instruction_donor_line_count"]
        ),
        "instruction donor body/table census changed",
    )
    require(
        comdat_primary_identity(target, target_primary)
        == comdat_primary_identity(instruction_donor, instruction_primary),
        "instruction donor is not the exact same mangled COMDAT",
    )
    require(
        all(
            target_primary[field] == instruction_primary[field]
            for field in ("name", "characteristics")
        ),
        "same-mangled donor COMDAT header class changed",
    )
    if fully_pinned:
        require(
            len(seed.sections) == function["expected_seed_section_count"]
            and seed_primary["number"] == function["expected_seed_section_number"],
            "source hybrid seed section census or seat changed",
        )
        require(
            seed_primary["raw_size"] == function["expected_seed_length"]
            and seed_primary["relocation_count"] == function["expected_seed_relocation_count"]
            and (seed_primary["line_count"] == function["expected_seed_line_count"]),
            "source hybrid seed body/table census changed",
        )
        require(
            sha256_bytes(coff_body(seed, seed_primary)) == function["expected_seed_body_sha256"],
            "source hybrid seed body differs from its pin",
        )
        require(
            instruction_mosaic_metadata_sha256(seed, seed_primary)
            == function["expected_seed_metadata_sha256"],
            "source hybrid seed metadata differs from its pin",
        )
        require(
            sum(function_multiset(seed).values()) == function["expected_seed_function_count"]
            and sum(function_multiset(target).values())
            == function["expected_target_donor_function_count"]
            and (
                sum(function_multiset(instruction_donor).values())
                == function["expected_instruction_donor_function_count"]
            ),
            "source hybrid donor function census changed",
        )
        require(
            sum(comdat_primary_identity_multiset(seed).values())
            == function["expected_seed_comdat_count"]
            and sum(comdat_primary_identity_multiset(target).values())
            == function["expected_target_donor_comdat_count"]
            and (
                sum(comdat_primary_identity_multiset(instruction_donor).values())
                == function["expected_instruction_donor_comdat_count"]
            ),
            "source hybrid donor COMDAT census changed",
        )
        closure = tuple(function["expected_donor_closure"])
        expected_closure = (len(closure), closure)
        require(
            all(
                value == expected_closure
                for value in (
                    _comdat_child_closure(seed, seed_primary),
                    _comdat_child_closure(target, target_primary),
                    _comdat_child_closure(instruction_donor, instruction_primary),
                )
            ),
            "source hybrid donor closure changed",
        )
        require(
            instruction_mosaic_metadata_sha256(target, target_primary)
            == function["expected_target_donor_metadata_sha256"],
            "source hybrid target-donor metadata differs from its pin",
        )
        require(
            instruction_mosaic_metadata_sha256(instruction_donor, instruction_primary)
            == function["expected_instruction_donor_metadata_sha256"],
            "source hybrid instruction-donor metadata differs from its pin",
        )
    if same_tu_source_identical:
        require(
            function_multiset(seed)
            == function_multiset(target)
            == function_multiset(instruction_donor),
            "same-TU hybrid function universe changed",
        )
        require(
            comdat_primary_identity_multiset(seed)
            == comdat_primary_identity_multiset(target)
            == comdat_primary_identity_multiset(instruction_donor),
            "same-TU hybrid COMDAT universe changed",
        )
        require_instruction_mosaic_semantic_relocations(
            target, target_primary, instruction_donor, instruction_primary, "same-TU hybrid code"
        )
    target_body = coff_body(target, target_primary)
    instruction_body = coff_body(instruction_donor, instruction_primary)
    require(
        sha256_bytes(target_body) == function["expected_target_donor_body_sha256"],
        "target donor body differs from its pin",
    )
    require(
        sha256_bytes(instruction_body) == function["expected_instruction_donor_body_sha256"],
        "instruction donor body differs from its pin",
    )
    ranges = validate_cross_tu_instruction_hybrid_ranges(
        function.get("instruction_ranges"),
        "instruction hybrid ranges",
        len(target_body),
        len(instruction_body),
        range_kind="same_tu_source_identical_complete_x86_instruction_v1"
        if same_tu_source_identical
        else "source_same_mangled_complete_x86_instruction_v1"
        if source_aware
        else "cross_tu_same_mangled_complete_x86_instruction_v1",
        require_same_offsets=fully_pinned,
    )
    require_coff_line_certified_ia32_boundaries(
        target,
        target_primary,
        target_body,
        ranges,
        "target",
        mangled,
        "instruction hybrid target donor",
    )
    require_coff_line_certified_ia32_boundaries(
        instruction_donor,
        instruction_primary,
        instruction_body,
        ranges,
        "instruction_donor",
        mangled,
        "instruction hybrid instruction donor",
    )
    target_relocations = detailed_relocations(target, target_primary)
    instruction_relocations = detailed_relocations(instruction_donor, instruction_primary)
    hybrid = bytearray(target_donor_bytes)
    range_detail = []
    for index, item in enumerate(ranges):
        target_start, target_end = (item["target_start"], item["target_end"])
        source_start, source_end = (item["instruction_donor_start"], item["instruction_donor_end"])
        target_instruction = target_body[target_start:target_end]
        source_instruction = instruction_body[source_start:source_end]
        require(
            sha256_bytes(target_instruction) == item["target_sha256"],
            f"cross-TU target instruction {index} drifted",
        )
        require(
            sha256_bytes(source_instruction) == item["instruction_donor_sha256"],
            f"cross-TU instruction donor instruction {index} drifted",
        )
        require_supported_complete_ia32_instruction(
            target_instruction, f"cross-TU target instruction {index}"
        )
        require_supported_complete_ia32_instruction(
            source_instruction, f"cross-TU instruction donor instruction {index}"
        )
        for role, rows, start, end in (
            ("target donor", target_relocations, target_start, target_end),
            ("instruction donor", instruction_relocations, source_start, source_end),
        ):
            require(
                all(end <= row["offset"] or start >= row["offset"] + row["width"] for row in rows),
                f"cross-TU range {index} overlaps a {role} relocation operand",
            )
        at = target_primary["raw_offset"] + target_start
        hybrid[at : at + target_end - target_start] = source_instruction
        range_detail.append(
            {
                "target_start": target_start,
                "target_end": target_end,
                "instruction_donor_start": source_start,
                "instruction_donor_end": source_end,
                "target_sha256": item["target_sha256"],
                "instruction_donor_sha256": item["instruction_donor_sha256"],
            }
        )
    hybrid = bytes(hybrid)
    # A range may resize the body; only the offsets both carry are compared here.
    changed_file_offsets = {
        offset
        for offset, (before, after) in enumerate(zip(target_donor_bytes, hybrid, strict=False))
        if before != after
    }
    allowed_file_offsets = {
        target_primary["raw_offset"] + offset
        for item in ranges
        for offset in range(item["target_start"], item["target_end"])
    }
    require(
        changed_file_offsets and changed_file_offsets <= allowed_file_offsets,
        "cross-TU hybrid changed a non-target-donor byte",
    )
    hybrid_coff = CoffObject(hybrid)
    hybrid_primary = hybrid_coff.function_section(mangled)
    hybrid_body = coff_body(hybrid_coff, hybrid_primary)
    require(
        sha256_bytes(hybrid_body) == function["expected_hybrid_body_sha256"],
        "cross-TU hybrid body differs from its pin",
    )
    require(
        detailed_relocations(hybrid_coff, hybrid_primary) == target_relocations,
        "cross-TU hybrid changed target-donor relocations",
    )
    require(
        _coff_table_bytes(hybrid_coff, hybrid_primary, "lines")
        == _coff_table_bytes(target, target_primary, "lines"),
        "cross-TU hybrid changed the target-donor line table",
    )
    require(
        _comdat_child_closure(hybrid_coff, hybrid_primary)
        == _comdat_child_closure(target, target_primary),
        "cross-TU hybrid changed the target-donor closure",
    )
    if fully_pinned:
        require(
            instruction_mosaic_metadata_sha256(hybrid_coff, hybrid_primary)
            == function["expected_target_donor_metadata_sha256"],
            "source hybrid changed target-donor metadata",
        )
    effective_function = dict(function)
    effective_function["splice_class"] = "retail_exact_reloc_divergent"
    effective_function["expected_body_sha256"] = function["expected_hybrid_body_sha256"]
    if fully_pinned:
        effective_function["expected_donor_line_count"] = function[
            "expected_target_donor_line_count"
        ]
    composed, detail = compose_same_slot_resize(seed_bytes, hybrid, effective_function)
    return (
        composed,
        {
            **detail,
            "splice_class": expected_class,
            "target_donor_body_sha256": sha256_bytes(target_body),
            "instruction_donor_body_sha256": sha256_bytes(instruction_body),
            "hybrid_body_sha256": sha256_bytes(hybrid_body),
            "instruction_ranges": range_detail,
        },
    )


def produce_same_tu_instruction_hybrid_resize_candidate(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    instruction_donor_bytes: bytes,
    function: dict[str, Any],
    seed_source: bytes,
    target_donor_source: bytes,
    instruction_donor_source: bytes,
) -> tuple[bytes, dict[str, Any]]:
    """Compose two source-identical, declaration-carrier same-TU donors."""
    require_payload_free_declaration(function, "same-TU instruction-hybrid declaration")
    require(
        function.get("splice_class") == SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS
        and "same_tu_source_identity" in function
        and ("instruction_donor_source_refactor" not in function),
        "same-TU instruction-hybrid contract is missing",
    )
    proof = function["same_tu_source_identity"]
    require(
        proof.get("source_owner_mangled") == function.get("mangled"),
        "same-TU instruction-hybrid owner differs",
    )
    owner = proof["source_owner_mangled"]
    for data in (seed_bytes, target_donor_bytes, instruction_donor_bytes):
        CoffObject(data).function_section(owner)
    source_detail = require_same_tu_source_identity(
        seed_source,
        target_donor_source,
        instruction_donor_source,
        proof,
        "same-TU instruction-hybrid source proof",
    )
    composed, detail = _produce_instruction_hybrid_resize_candidate_core(
        seed_bytes,
        target_donor_bytes,
        instruction_donor_bytes,
        function,
        source_aware=False,
        same_tu_source_identical=True,
    )
    return (composed, {**detail, **source_detail})
