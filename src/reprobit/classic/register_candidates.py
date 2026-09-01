"""Object-level candidate production for register interventions."""

from __future__ import annotations

from typing import Any

from reprobit.binary import ByteIdentityError, require
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
    _coff_section_symbol,
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
    function_symbol,
)
from .composition import compose_equal_body_comdat
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_relocations import require_instruction_mosaic_semantic_relocations
from .composition_same_slot import compose_same_slot_resize
from .debug import _apply_replacements, parse_fpo_data, shifted_pointer
from .foundation import local_symbol_kind, require_payload_free_declaration, sha256_bytes
from .ia32 import require_declared_relocation_semantics
from .register_bijection import (
    REGISTER_BIJECTION_CLASS,
    REGISTER_BIJECTION_EH_CLOSURE,
    REGISTER_BIJECTION_FPO_CLOSURE,
    apply_codeview_register_bijection,
    apply_register_bijection,
    register_bijection_delegate,
)
from .register_reencoding import (
    REGISTER_BIJECTION_REENCODING_CLASS,
    REGISTER_BIJECTION_REENCODING_KIND,
    apply_register_bijection_reencoding,
    require_frame_pointer_free_frame,
)
from .register_semantics import decode_ia32_bijection_body


def produce_register_bijection_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Produce sigma(donor body) from a fresh compiler artifact.

    See the class comment above: this is a certificate.  The donor is an
    ordinary, census-pinned carrier compile of the same translation unit; the
    bijection is proved sound against the body's own control flow; and the
    result is constrained by declarative relocation semantics.  Body
    installation itself is delegated, unchanged, to the
    equal-body primitive, so output conservation is proved by the same code
    every other equal-body class uses.
    """
    require_payload_free_declaration(function, "register-bijection declaration")
    require(
        function.get("splice_class") == REGISTER_BIJECTION_CLASS,
        "splice class is not retail_exact_register_bijection",
    )
    require(
        "target_source_refactor" not in function,
        "register-bijection functions carry no source refactor",
    )
    spec = function["register_bijection"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    donor_seat = function.get("expected_donor_section_number")
    if donor_seat is None:
        require(
            sp["number"] == dp["number"] == function["expected_section_number"],
            "register-bijection target section seat changed",
        )
    else:
        require(
            sp["number"] == function["expected_section_number"] and dp["number"] == donor_seat,
            "register-bijection target section seat changed",
        )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "register-bijection global section count changed",
    )
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(
        seed_functions == donor_functions
        and sum(seed_functions.values()) == function["expected_function_count"],
        "register-bijection donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(
        seed_comdats == donor_comdats
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "register-bijection donor COMDAT identity set differs",
    )
    require(
        sp["raw_size"] == dp["raw_size"] == function["expected_body_length"]
        and sp["relocation_count"]
        == dp["relocation_count"]
        == function["expected_relocation_count"]
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        "register-bijection target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "register-bijection COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        "register-bijection target closure changed",
    )
    require(
        list(expected_closure) in (REGISTER_BIJECTION_FPO_CLOSURE, REGISTER_BIJECTION_EH_CLOSURE),
        "register-bijection closure pin names no installation delegate",
    )
    delegate = register_bijection_delegate(
        function["expected_closure"],
        function["expected_code_renames"],
        function.get("expected_relocation_moves"),
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "register-bijection metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "register-bijection seed/donor body differs from its pin",
    )
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    if (
        register_bijection_delegate(
            function["expected_closure"],
            function["expected_code_renames"],
            function.get("expected_relocation_moves"),
        )
        == "equal_body_eh_reloc_layout"
    ):
        require(
            len(seed_rows) == len(donor_rows), "register-bijection donor relocation count differs"
        )
        code_renames = []
        for left, right in zip(seed_rows, donor_rows, strict=True):
            if left["target"] == right["target"]:
                continue
            kind = local_symbol_kind(left["target"])
            require(
                kind is not None
                and kind == local_symbol_kind(right["target"])
                and all(
                    left["target_" + field] == right["target_" + field]
                    for field in ("section", "value", "type", "storage")
                ),
                "register-bijection donor renames a non-local relocation",
            )
            code_renames.append((right["offset"], kind))
    else:
        code_renames = require_instruction_mosaic_semantic_relocations(
            seed, sp, donor, dp, "register-bijection code"
        )
    require(
        [[offset, kind] for offset, kind in code_renames] == function["expected_code_renames"],
        "register-bijection code rename set changed",
    )
    seed_targets = {
        right["offset"]: left["target"] for left, right in zip(seed_rows, donor_rows, strict=True)
    }
    donor_targets = {row["offset"]: row["target"] for row in donor_rows}
    require(
        [
            [offset, seed_targets.get(offset), donor_targets.get(offset)]
            for offset, _ in code_renames
        ]
        == function.get("expected_code_rename_symbols", []),
        "register-bijection code rename symbol pair changed",
    )
    require(
        len(seed_rows) == len(donor_rows)
        and [(row["type"], row["addend"]) for row in seed_rows]
        == [(row["type"], row["addend"]) for row in donor_rows],
        "register-bijection donor relocation layout differs from the seed",
    )
    moves = [
        [left["offset"], right["offset"]]
        for left, right in zip(seed_rows, donor_rows, strict=True)
        if left["offset"] != right["offset"]
    ]
    require(
        moves == (function.get("expected_relocation_moves") or []),
        "register-bijection relocation move set changed",
    )
    require(
        [row["target"] for row in seed_rows if row["type"] == 20]
        == [row["target"] for row in donor_rows if row["type"] == 20],
        "register-bijection donor call/branch relocation targets differ from the seed",
    )
    installed_rows = [
        {**left, "offset": right["offset"]}
        for left, right in zip(seed_rows, donor_rows, strict=True)
    ]
    relocation_offsets = frozenset(
        row["offset"] + byte for row in installed_rows for byte in range(row["width"])
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in installed_rows
    }
    internal_targets = frozenset(
        row["target_value"] for row in donor_rows if row["target_section"] == dp["number"]
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "register-bijection in-body relocated target set changed",
        )
    image, proof = apply_register_bijection(
        donor_body,
        spec["mapping"],
        (spec["region_start"], spec["region_end"]),
        relocation_offsets,
        "register-bijection image",
        relocation_symbols,
        spec.get("expected_code_length"),
        internal_targets,
    )
    require(
        proof["code_length"] == (spec.get("expected_code_length") or len(donor_body)),
        "register-bijection code length differs from its pin",
    )
    require(
        proof["rewritten_offsets"] == spec["expected_rewritten_offsets"]
        and proof["region_instruction_count"] == spec["expected_region_instruction_count"]
        and (proof["instruction_count"] == spec["expected_instruction_count"]),
        "register-bijection image differs from its declaration",
    )
    require(
        donor_body[: spec["region_start"]] == image[: spec["region_start"]]
        and donor_body[spec["region_end"] :] == image[spec["region_end"] :],
        "register-bijection changed the prologue or epilogue",
    )
    require(
        sorted(
            offset for offset in proof["rewritten_offsets"] if seed_body[offset] == image[offset]
        )
        == (spec.get("expected_rewritten_offsets_restoring_seed") or []),
        "register-bijection seed-restoring rewrite set changed",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "register-bijection image differs from its pin",
    )
    require(image != donor_body, "register-bijection image does not move the donor body")
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "register-bijection linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "register-bijection candidate relocation semantics",
    )
    derived = bytearray(donor_bytes)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    derived = bytes(derived)
    effective = {
        "mangled": mangled,
        "splice_class": delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    if delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = function["expected_code_renames"]
        effective["expected_xdata_rename_offsets"] = function["expected_xdata_rename_offsets"]
    elif delegate == "equal_body_eh_reloc_layout":
        effective["expected_relocation_moves"] = function["expected_relocation_moves"]
        effective["expected_xdata_rename_offsets"] = function["expected_xdata_rename_offsets"]
    composed, detail = compose_equal_body_comdat(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        coff_body(checked, cp) == image, "register-bijection composed body differs from the image"
    )
    composed_rows = detailed_relocations(checked, cp)
    require(
        composed_rows == installed_rows
        and [row["symbol_index"] for row in composed_rows]
        == [row["symbol_index"] for row in seed_rows]
        and (_coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")),
        "register-bijection output changed seed relocation/line bytes",
    )
    debug_child = _comdat_child(checked, cp, ".debug$S")
    debug_stream = coff_body(checked, debug_child)
    require(
        sha256_bytes(debug_stream) == spec["expected_seed_debug_s_sha256"],
        "register-bijection debug$S differs from its pin",
    )
    donor_debug = None
    if delegate == "equal_body_eh_reloc_layout":
        donor_debug = bytes(coff_body(donor, _comdat_child(donor, dp, ".debug$S")))
    debug_image = apply_codeview_register_bijection(
        debug_stream,
        spec["mapping"],
        spec["debug_s_register_map"],
        "register-bijection debug$S",
        donor_debug,
    )
    require(
        sha256_bytes(debug_image) == spec["expected_image_debug_s_sha256"],
        "register-bijection mapped debug$S differs from its pin",
    )
    composed = bytearray(composed)
    composed[debug_child["raw_offset"] : debug_child["raw_offset"] + debug_child["raw_size"]] = (
        debug_image
    )
    composed = bytes(composed)
    final = CoffObject(composed)
    fp = final.function_section(mangled)
    require(coff_body(final, fp) == image, "register-bijection output changed the installed body")
    for child_name in expected_closure:
        if child_name == ".debug$S":
            continue
        require(
            coff_body(final, _comdat_child(final, fp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"register-bijection output changed its {child_name} child",
        )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    allowed |= set(
        range(debug_child["raw_offset"], debug_child["raw_offset"] + debug_child["raw_size"])
    )
    if delegate == "equal_body_eh_reloc_layout":
        moving = [
            ordinal
            for ordinal, (left, right) in enumerate(zip(seed_rows, donor_rows, strict=True))
            if left["offset"] != right["offset"]
        ]
        allowed |= {
            sp["relocation_offset"] + ordinal * 10 + byte for ordinal in moving for byte in range(4)
        }
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "register-bijection changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": REGISTER_BIJECTION_CLASS,
            "register_bijection": dict(sorted(spec["mapping"].items())),
            "region": [spec["region_start"], spec["region_end"]],
            "rewritten_offsets": proof["rewritten_offsets"],
            "region_instruction_count": proof["region_instruction_count"],
            "instruction_count": proof["instruction_count"],
            "debug_s_register_map": spec["debug_s_register_map"],
            "candidate_only": True,
            **semantic_detail,
        },
    )


def _reencoded_donor_object(
    donor_bytes: bytes,
    mangled: str,
    image: bytes,
    proof: dict[str, Any],
    context: str,
    fpo_required: bool = True,
) -> bytes:
    """Re-seat one COMDAT's dependent COFF records around a resized body.

    Obligations 14 to 16.  The donor is an authentic compiler object; this
    produces the same object with the proved image in place of the target
    body and every record that states a code offset carried through the
    bijection's own boundary map.  Nothing outside the target COMDAT's own
    data, tables and closure children is touched, and the result is re-parsed
    and re-checked before it is handed to the installation primitive.
    """
    donor = CoffObject(donor_bytes)
    primary = donor.function_section(mangled)
    offset_map = {int(key): value for key, value in proof["offset_map"].items()}
    body_length = len(image)
    require(
        offset_map[primary["raw_size"]] == body_length
        if primary["raw_size"] in offset_map
        else True,
        f"{context}: the boundary map does not end at the image length",
    )
    line_bytes = _coff_table_bytes(donor, primary, "lines")
    require(
        len(line_bytes) == primary["line_count"] * 6 and primary["line_count"] >= 1,
        f"{context}: the donor line table is missing",
    )
    rebuilt_lines = bytearray(line_bytes[:6])
    require(
        coff_unpack("<IH", line_bytes, 0, f"{context} line sentinel")[1] == 0,
        f"{context}: the donor line sentinel is invalid",
    )
    for position in range(1, primary["line_count"]):
        offset, line = coff_unpack(
            "<IH", line_bytes, position * 6, f"{context} line row {position}"
        )
        require(line != 0, f"{context}: line row {position} has no line number")
        require(
            offset in offset_map,
            f"{context}: line row {position} at {offset} is not an instruction boundary of the pre-image",
        )
        rebuilt_lines += offset_map[offset].to_bytes(4, "little")
        rebuilt_lines += line.to_bytes(2, "little")
    require(
        len(rebuilt_lines) == len(line_bytes), f"{context}: the rebuilt line table changed size"
    )
    relocation_bytes = _coff_table_bytes(donor, primary, "relocations")
    moved = dict(proof["relocation_reseat"])
    rebuilt_relocations = bytearray(relocation_bytes)
    for ordinal in range(primary["relocation_count"]):
        at = ordinal * 10
        offset = int.from_bytes(relocation_bytes[at : at + 4], "little")
        rebuilt_relocations[at : at + 4] = moved.get(offset, offset).to_bytes(4, "little")
    require(
        len(rebuilt_relocations) == len(relocation_bytes),
        f"{context}: the rebuilt relocation table changed size",
    )
    debug_child = _comdat_child(donor, primary, ".debug$S")
    debug_raw = bytes(coff_body(donor, debug_child))
    require(
        len(debug_raw) >= 28 and debug_raw[2:4] in (b"\x04\x02", b"\x05\x02"),
        f"{context}: the donor debug$S is not a procedure record",
    )
    code_length, debug_start, debug_end = coff_unpack(
        "<III", debug_raw, 16, f"{context} debug range"
    )
    require(
        code_length == primary["raw_size"] and 0 <= debug_start <= debug_end < code_length,
        f"{context}: the donor debug procedure range is stale",
    )
    require(
        debug_start in offset_map and debug_end in offset_map,
        f"{context}: the debug range is not on instruction boundaries",
    )
    rebuilt_debug = bytearray(debug_raw)
    rebuilt_debug[16:28] = (
        body_length.to_bytes(4, "little")
        + offset_map[debug_start].to_bytes(4, "little")
        + offset_map[debug_end].to_bytes(4, "little")
    )
    fpo_child = None
    if fpo_required:
        fpo_child = _comdat_child(donor, primary, ".debug$F")
    else:
        try:
            fpo_child = _comdat_child(donor, primary, ".debug$F")
        except ByteIdentityError:
            fpo_child = None
    if fpo_child is not None:
        fpo_raw = bytes(coff_body(donor, fpo_child))
        parse_fpo_data(fpo_raw, expected_proc_size=primary["raw_size"])
        rebuilt_fpo = bytearray(fpo_raw)
        rebuilt_fpo[4:8] = body_length.to_bytes(4, "little")
        parse_fpo_data(bytes(rebuilt_fpo), expected_proc_size=body_length)
        require(
            rebuilt_fpo[:4] == fpo_raw[:4] and rebuilt_fpo[8:] == fpo_raw[8:],
            f"{context}: the rebuilt FPO record changed a field other than cbProcSize",
        )
    replacements = [
        (primary["raw_offset"], primary["raw_offset"] + primary["raw_size"], bytes(image)),
        (
            primary["line_offset"],
            primary["line_offset"] + primary["line_count"] * 6,
            bytes(rebuilt_lines),
        ),
        (
            primary["relocation_offset"],
            primary["relocation_offset"] + primary["relocation_count"] * 10,
            bytes(rebuilt_relocations),
        ),
        (
            debug_child["raw_offset"],
            debug_child["raw_offset"] + debug_child["raw_size"],
            bytes(rebuilt_debug),
        ),
    ]
    if fpo_child is not None:
        replacements.append(
            (
                fpo_child["raw_offset"],
                fpo_child["raw_offset"] + fpo_child["raw_size"],
                bytes(rebuilt_fpo),
            )
        )
        replacements.sort()
    output = bytearray(_apply_replacements(donor_bytes, replacements))

    def shifted(pointer: int) -> int:
        return shifted_pointer(pointer, replacements)

    new_symbol_offset = shifted(donor.symbol_offset)
    output[8:12] = new_symbol_offset.to_bytes(4, "little")
    for section in donor.sections:
        header = 20 + (section["number"] - 1) * 40
        if section["number"] == primary["number"]:
            output[header + 16 : header + 20] = body_length.to_bytes(4, "little")
        for field, relative in (("raw_offset", 20), ("relocation_offset", 24), ("line_offset", 28)):
            pointer = shifted(section[field])
            if pointer != section[field]:
                output[header + relative : header + relative + 4] = pointer.to_bytes(4, "little")
    for symbol_index, item in donor.symbols.items():
        if item["type"] == 32 and item["aux_count"] >= 1:
            auxiliary = coff_auxiliary(donor, symbol_index, item)
            line_pointer = int.from_bytes(auxiliary[8:12], "little")
            mapped = shifted(line_pointer) if line_pointer else line_pointer
            if mapped != line_pointer:
                at = new_symbol_offset + (symbol_index + 1) * 18
                output[at + 8 : at + 12] = mapped.to_bytes(4, "little")
    function_index, function_symbol_record = function_symbol(donor, mangled, primary["number"])
    function_aux = coff_auxiliary(donor, function_index, function_symbol_record)
    require(
        int.from_bytes(function_aux[4:8], "little") == primary["raw_size"],
        f"{context}: the donor Function Definition TotalSize is stale",
    )
    at = new_symbol_offset + (function_index + 1) * 18
    output[at + 4 : at + 8] = body_length.to_bytes(4, "little")
    section_index, section_symbol_record = _coff_section_symbol(donor, primary)
    aux_at = new_symbol_offset + (section_index + 1) * 18
    require(
        int.from_bytes(coff_auxiliary(donor, section_index, section_symbol_record)[0:4], "little")
        == primary["raw_size"],
        f"{context}: the donor COMDAT auxiliary Length is stale",
    )
    output[aux_at : aux_at + 4] = body_length.to_bytes(4, "little")
    end_index, end_symbol = _coff_marker(donor, ".ef", primary["number"])
    require(end_symbol["value"] == primary["raw_size"], f"{context}: the donor .ef marker is stale")
    output[new_symbol_offset + end_index * 18 + 8 : new_symbol_offset + end_index * 18 + 12] = (
        body_length.to_bytes(4, "little")
    )
    carried = []
    for symbol_index, item in donor.symbols.items():
        if item["section"] != primary["number"]:
            continue
        if symbol_index in (function_index, section_index, end_index):
            continue
        if item["name"] in (".bf", ".lf"):
            continue
        require(
            item["value"] in offset_map,
            f"{context}: the symbol {item['name']} at {item['value']} is not an instruction boundary of the pre-image",
        )
        mapped = offset_map[item["value"]]
        if mapped != item["value"]:
            at = new_symbol_offset + symbol_index * 18
            output[at + 8 : at + 12] = mapped.to_bytes(4, "little")
            carried.append([item["name"], item["value"], mapped])
    derived = bytes(output)
    checked = CoffObject(derived)
    checked_primary = checked.function_section(mangled)
    require(
        coff_body(checked, checked_primary) == bytes(image),
        f"{context}: the derived donor body is not the image",
    )
    require(
        checked_primary["raw_size"] == body_length
        and checked_primary["line_count"] == primary["line_count"]
        and (checked_primary["relocation_count"] == primary["relocation_count"])
        and (checked_primary["number"] == primary["number"])
        and (checked_primary["characteristics"] == primary["characteristics"]),
        f"{context}: the derived donor target header is inconsistent",
    )
    require(
        function_multiset(checked) == function_multiset(donor)
        and comdat_primary_identity_multiset(checked) == comdat_primary_identity_multiset(donor)
        and (len(checked.sections) == len(donor.sections)),
        f"{context}: the derived donor changed the object's topology",
    )
    require(
        _comdat_child_closure(checked, checked_primary) == _comdat_child_closure(donor, primary),
        f"{context}: the derived donor changed the target closure",
    )
    require(
        [row["target"] for row in detailed_relocations(checked, checked_primary)]
        == [row["target"] for row in detailed_relocations(donor, primary)],
        f"{context}: the derived donor changed a relocation target",
    )
    require(
        [row["offset"] for row in detailed_relocations(checked, checked_primary)]
        == [
            moved.get(row["offset"], row["offset"]) for row in detailed_relocations(donor, primary)
        ],
        f"{context}: the derived donor relocation offsets are not the proved reseat",
    )
    return (
        derived,
        {
            "carried_code_symbols": carried,
            "line_rows": primary["line_count"],
            "procedure_range": [body_length, offset_map[debug_start], offset_map[debug_end]],
        },
    )


def produce_register_bijection_reencoding_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Produce a resized sigma(donor body) from compiler output.

    The parent class with EBP admitted: see the class comment above for the
    seven obligations that admission costs.  The pre-image is an ordinary,
    census-pinned carrier compile of the same translation unit; the renaming
    is proved sound against the body's own control flow AND against the
    compiler's own frame declaration; the resized image is re-seated through
    the bijection's own boundary map. Installation is delegated, unchanged, to `compose_same_slot_resize`
    in the mode a dozen landed rows already use.
    """
    require_payload_free_declaration(function, "register-bijection re-encoding declaration")
    require(
        function.get("splice_class") == REGISTER_BIJECTION_REENCODING_CLASS,
        "splice class is not retail_exact_register_bijection_reencoding",
    )
    require(
        "target_source_refactor" not in function,
        "register-bijection functions carry no source refactor",
    )
    spec = function["register_bijection_reencoding"]
    require(
        spec["kind"] == REGISTER_BIJECTION_REENCODING_KIND, "re-encoding bijection kind differs"
    )
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        "re-encoding target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "re-encoding global section count changed",
    )
    seed_functions = function_multiset(seed)
    require(
        seed_functions == function_multiset(donor)
        and sum(seed_functions.values()) == function["expected_function_count"],
        "re-encoding donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(
        seed_comdats == comdat_primary_identity_multiset(donor)
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "re-encoding donor COMDAT identity set differs",
    )
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_preimage_length"]
        and (
            sp["relocation_count"]
            == dp["relocation_count"]
            == function["expected_relocation_count"]
        )
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        "re-encoding target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "re-encoding COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure)
        and list(expected_closure) == REGISTER_BIJECTION_FPO_CLOSURE,
        "re-encoding target closure is not the FPO debug pair",
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "re-encoding metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = bytes(coff_body(donor, dp))
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "re-encoding seed/donor body differs from its pin",
    )
    donor_rows = detailed_relocations(donor, dp)
    require(
        [row["target"] for row in donor_rows]
        == [row["target"] for row in detailed_relocations(seed, sp)],
        "re-encoding donor relocation targets differ from the seed",
    )
    relocation_offsets = frozenset(
        row["offset"] + byte for row in donor_rows for byte in range(row["width"])
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in donor_rows
    }
    internal_targets = frozenset(
        row["target_value"] for row in donor_rows if row["target_section"] == dp["number"]
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "re-encoding in-body relocated target set changed",
        )
    instructions = decode_ia32_bijection_body(
        donor_body, "re-encoding frame proof", relocation_symbols, spec.get("expected_code_length")
    )
    fpo_record = require_frame_pointer_free_frame(
        donor, dp, donor_body, instructions, "re-encoding frame proof"
    )
    measured_fpo = {key: value for key, value in fpo_record.items() if key != "raw_sha256"}
    require(
        measured_fpo == spec["expected_fpo_record"],
        "re-encoding FPO record differs from its declaration",
    )
    regions = [
        {"start": item["start"], "end": item["end"], "mapping": dict(item["mapping"])}
        for item in spec["regions"]
    ]
    image, proof = apply_register_bijection_reencoding(
        donor_body,
        regions,
        relocation_offsets,
        "re-encoding image",
        relocation_symbols,
        spec.get("expected_code_length"),
        internal_targets or None,
        True,
    )
    require(
        proof["code_length"] == (spec.get("expected_code_length") or len(donor_body)),
        "re-encoding code length differs from its pin",
    )
    require(
        proof["growth"] == spec["expected_growth"]
        and proof["branch_repairs"] == spec["expected_branch_repairs"]
        and (proof["relocation_reseat"] == spec["expected_relocation_reseat"])
        and (proof["rewritten_field_offsets"] == spec["expected_rewritten_field_offsets"])
        and (proof["region_instruction_counts"] == spec["expected_region_instruction_counts"])
        and (proof["instruction_count"] == spec["expected_instruction_count"])
        and (proof["image_code_length"] == spec["expected_image_code_length"]),
        "re-encoding image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "re-encoding image differs from its pin",
    )
    require(
        len(image) == function["expected_body_length"] == function["expected_donor_length"],
        "re-encoding image length differs from its pin",
    )
    require(image != donor_body, "re-encoding image does not move the donor body")
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "re-encoding linked length changed")
    moved = dict(proof["relocation_reseat"])
    installed_rows = [
        {**row, "offset": moved.get(row["offset"], row["offset"])} for row in donor_rows
    ]
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "re-encoding candidate relocation semantics",
    )
    derived, derived_detail = _reencoded_donor_object(
        donor_bytes, mangled, image, proof, "re-encoding derived donor"
    )
    require(
        derived_detail["procedure_range"] == spec["expected_procedure_range"]
        and derived_detail["carried_code_symbols"] == spec["expected_carried_code_symbols"],
        "re-encoding derived donor differs from its declaration",
    )
    effective = {
        "mangled": mangled,
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": function["expected_seed_length"],
        "expected_donor_length": function["expected_donor_length"],
        "expected_linked_span": function["expected_linked_span"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_seed_line_count": function["expected_seed_line_count"],
        "expected_donor_line_count": function["expected_donor_line_count"],
        "retail_oracle": function["retail_oracle"],
        "retail_relocations": function["retail_relocations"],
    }
    composed, detail = compose_same_slot_resize(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, "re-encoding composed body differs from the image")
    require(
        [row["offset"] for row in detailed_relocations(checked, cp)]
        == [row["offset"] for row in installed_rows]
        and [row["target"] for row in detailed_relocations(checked, cp)]
        == [row["target"] for row in installed_rows],
        "re-encoding composed relocation table is not the proved reseat",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": REGISTER_BIJECTION_REENCODING_CLASS,
            "register_bijection_reencoding": [
                {
                    "start": item["start"],
                    "end": item["end"],
                    "mapping": dict(sorted(item["mapping"].items())),
                }
                for item in regions
            ],
            "fpo_record": measured_fpo,
            "growth": proof["growth"],
            "branch_repairs": proof["branch_repairs"],
            "relocation_reseat": proof["relocation_reseat"],
            "rewritten_field_offsets": proof["rewritten_field_offsets"],
            "instruction_count": proof["instruction_count"],
            "carried_code_symbols": derived_detail["carried_code_symbols"],
            "procedure_range": derived_detail["procedure_range"],
            "candidate_only": True,
            **semantic_detail,
        },
    )
