from __future__ import annotations

import struct

import reprobit.declaration_shapes as entropy_generator
from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import (
    CoffObject,
    coff_auxiliary,
    coff_body,
    coff_table,
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
    associated_sections,
    canonical_counter_receipt_sha256,
    comdat_primary_identity,
    comdat_primary_identity_multiset,
    comdat_primary_section,
    function_multiset,
    function_symbol,
    marker_symbol,
    require_source_target_closure_topology,
    require_target_closure_extraction_topology,
    section_shape_receipt_sha256,
    section_symbol,
)
from .debug import (
    LOCAL_SET_DELTA_REFACTOR_KINDS,
    _apply_replacements,
    linker_payload_multiset,
    normalized_donor_lines,
    parse_fpo_data,
    relocation_compatibility,
    require_debug_symbol_representation_delta,
    require_removed_caller_locals_delta,
    shifted_pointer,
    verify_non_emitting_donor,
)
from .foundation import (
    canonical_json_bytes,
    exact_audit_keys,
    exact_json_equal,
    local_symbol_kind,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)
from .ia32 import (
    CROSS_TU_COMPLETE_TARGET_RESIZE_CLASS,
    CROSS_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
    EH_CLOSURE_CHILDREN,
    ORDINARY_FPO_CLOSURE_CHILDREN,
    RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS,
    SAME_TU_INSTRUCTION_HYBRID_RESIZE_CLASS,
    SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS,
    require_coff_line_certified_ia32_boundaries,
    require_declared_relocation_semantics,
    require_supported_complete_ia32_instruction,
    validate_cross_tu_instruction_hybrid_ranges,
    validate_instruction_mosaic_ranges,
    validate_instruction_self_permutation,
)
from .source_proofs import (
    require_same_tu_source_identity,
    require_target_source_range_identity,
    require_target_source_refactor_identity,
)

"""Classic compiler algorithms: composition."""


def _normalized_relocation_renames(
    seed: CoffObject,
    seed_section: dict,
    donor: CoffObject,
    donor_section: dict,
    context: str,
    seat_map: dict | None = None,
) -> list[tuple[int, str]]:
    """Require literal relocation equality except paired object-local $L/$T
    serial renames whose targets are structurally identical.

    seat_map maps a declared cross-lane donor's spliced-group section
    numbers onto the seed's, so in-group targets compare structurally."""
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    renames = []
    for a, b in zip(left, right):
        require(
            (a["offset"], a["type"], a["addend"]) == (b["offset"], b["type"], b["addend"]),
            f"{context}: relocation offset/type/addend differs",
        )
        if a["target"] == b["target"]:
            continue
        kind = local_symbol_kind(a["target"])
        if kind is None:
            left_base, _, left_serial = a["target"].rpartition("$S")
            right_base, _, right_serial = b["target"].rpartition("$S")
            require(
                left_base
                and left_base == right_base
                and left_serial.isdigit()
                and right_serial.isdigit()
                and (a["target_type"] == b["target_type"])
                and (a["target_storage"] == b["target_storage"]),
                f"{context}: non-local relocation rename {a['target']!r} -> {b['target']!r}",
            )
            renames.append((a["offset"], "S"))
            continue
        require(
            kind == local_symbol_kind(b["target"]),
            f"{context}: non-local relocation rename {a['target']!r} -> {b['target']!r}",
        )
        donor_target_section = b["target_section"]
        if seat_map:
            donor_target_section = seat_map.get(donor_target_section, donor_target_section)
        require(
            a["target_section"] == donor_target_section
            and all(
                (
                    a["target_" + field] == b["target_" + field]
                    for field in ("value", "type", "storage")
                )
            ),
            f"{context}: renamed local relocation target structure differs",
        )
        renames.append((a["offset"], kind))
    return renames


def require_same_semantic_relocations(
    seed: CoffObject, seed_section: dict, donor: CoffObject, donor_section: dict, context: str
) -> list[tuple[int, str]]:
    """Require identical resolved relocation semantics at identical offsets.

    Compiler-local ``$L``/``$T`` serials may be renamed, but only when their
    section seat, value, type, and storage class are unchanged.  Ordinary
    symbols must retain their literal identity and the same structural target.
    This is deliberately stricter than the relocation pairing used by resize
    composers: an instruction mosaic retains the seed table verbatim.
    """
    renames = _normalized_relocation_renames(seed, seed_section, donor, donor_section, context)
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    target_fields = ("target_section", "target_value", "target_type", "target_storage")
    for index, (seed_row, donor_row) in enumerate(zip(left, right)):
        require(
            seed_row["width"] == donor_row["width"], f"{context}: relocation {index} width differs"
        )
        if seed_row["target"] != donor_row["target"]:
            seed_kind = local_symbol_kind(seed_row["target"])
            require(
                seed_kind is not None and seed_kind == local_symbol_kind(donor_row["target"]),
                f"{context}: relocation {index} changes symbol identity",
            )
        require(
            all((seed_row[field] == donor_row[field] for field in target_fields)),
            f"{context}: relocation {index} target structure differs",
        )
    return renames


MOSAIC_PERMUTED_RELOCATION_ORDER = "permuted_outside_ranges"


def _mosaic_relocation_pair_rename(
    seed: CoffObject, donor: CoffObject, a: dict, b: dict
) -> tuple[bool, tuple[int, str] | None]:
    """Judge one same-offset seed/donor relocation pair under the strict
    instruction-mosaic rule (``require_instruction_mosaic_semantic_relocations``
    plus ``_normalized_relocation_renames``) without raising.

    Returns ``(ok, rename)`` where ``rename`` is the recorded local
    ``$L``/``$T`` serial rename, if any."""
    if (a["offset"], a["type"], a["addend"], a["width"]) != (
        b["offset"],
        b["type"],
        b["addend"],
        b["width"],
    ):
        return (False, None)
    if a["target"] == b["target"]:
        if any(
            (a[field] != b[field] for field in ("target_value", "target_type", "target_storage"))
        ):
            return (False, None)
        if a["target_section"] == b["target_section"]:
            return (True, None)
        if (
            local_symbol_kind(a["target"]) is not None
            or a["target_section"] <= 0
            or b["target_section"] <= 0
        ):
            return (False, None)
        seed_target = seed.sections[a["target_section"] - 1]
        donor_target = donor.sections[b["target_section"] - 1]
        return (
            comdat_primary_identity(seed, seed_target)
            == comdat_primary_identity(donor, donor_target),
            None,
        )
    kind = local_symbol_kind(a["target"])
    if kind is None:
        return (False, None)
    if kind != local_symbol_kind(b["target"]):
        return (False, None)
    if a["target_section"] != b["target_section"] or any(
        (a["target_" + field] != b["target_" + field] for field in ("value", "type", "storage"))
    ):
        return (False, None)
    return (True, (a["offset"], kind))


def _permuted_relocation_key(row: dict) -> tuple:
    """Offset-free identity of one relocation record for the multiset rule.

    Compiler-local ``$L``/``$T`` serials are reduced to their kind; their
    structural target (section seat, value, type, storage) stays literal."""
    kind = local_symbol_kind(row["target"])
    target = row["target"] if kind is None else "$" + kind
    return (
        row["width"],
        row["type"],
        row["addend"],
        target,
        row["target_section"],
        row["target_value"],
        row["target_type"],
        row["target_storage"],
    )


def _require_permuted_instruction_mosaic_relocations(
    seed: CoffObject,
    seed_section: dict,
    donor: CoffObject,
    donor_section: dict,
    permuted_ranges: list[tuple[int, int]],
    context: str,
) -> list[tuple[int, str]]:
    """The ``permuted_outside_ranges`` relocation-order rule.

    A declaration-only carrier may re-order otherwise identical constant
    stores, so the donor's relocation records outside the imported ranges may
    stand at other offsets and in another order.  The output still retains
    the seed relocation table verbatim; the donor only proves that it is the
    same compiler output of the same source: every same-offset pair obeys the
    strict rule, and the remaining records are an exact offset-free multiset
    permutation of each other that touches no imported range.  A donor that
    satisfies the strict rule must be declared under it (an empty permutation
    is refused), so this mode is never a silent relaxation.
    """
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    right_by_offset = {}
    for index, row in enumerate(right):
        require(
            row["offset"] not in right_by_offset, f"{context}: donor relocation offsets collide"
        )
        right_by_offset[row["offset"]] = index
    renames = []
    unmatched_left = []
    matched_right = set()
    for a in left:
        index = right_by_offset.get(a["offset"])
        if index is not None and index not in matched_right:
            ok, rename = _mosaic_relocation_pair_rename(seed, donor, a, right[index])
            if ok:
                matched_right.add(index)
                if rename is not None:
                    renames.append(rename)
                continue
        unmatched_left.append(a)
    unmatched_right = [row for index, row in enumerate(right) if index not in matched_right]
    require(
        unmatched_left,
        f"{context}: relocation permutation is empty; the strict relocation order applies",
    )
    require(
        sorted((_permuted_relocation_key(row) for row in unmatched_left))
        == sorted((_permuted_relocation_key(row) for row in unmatched_right)),
        f"{context}: relocations outside the imported ranges are not a permutation of the seed's",
    )
    for role, rows in (("seed", unmatched_left), ("donor", unmatched_right)):
        for row in rows:
            operand_start = row["offset"]
            operand_end = operand_start + row["width"]
            require(
                all(
                    (operand_end <= start or operand_start >= end for start, end in permuted_ranges)
                ),
                f"{context}: permuted {role} relocation at offset {operand_start} lies inside an imported range",
            )
    return renames


def _require_reseat_instruction_mosaic_relocations(
    seed: CoffObject,
    seed_section: dict,
    donor: CoffObject,
    donor_section: dict,
    reseat_windows: list[tuple[int, int]],
    context: str,
) -> list[tuple[int, str]]:
    """The ``relocation_reseat`` relocation rule.

    Records pair by ordinal exactly as under the strict rule; the only
    relaxation is that a paired record may carry its operand at another
    offset when both the seed's and the donor's operand lie inside the same
    declared reseat window.  Everything else about the pair (type, width,
    addend, target identity and structure, COMDAT seat) is the strict rule.
    """
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    renames = []
    for index, (a, b) in enumerate(zip(left, right)):
        if a["offset"] != b["offset"]:
            window = next(
                (
                    (start, end)
                    for start, end in reseat_windows
                    if start <= a["offset"] and a["offset"] + a["width"] <= end
                ),
                None,
            )
            require(
                window is not None
                and window[0] <= b["offset"]
                and (b["offset"] + b["width"] <= window[1]),
                f"{context}: relocation {index} moves outside a declared reseat window",
            )
            b = dict(b)
            b["offset"] = a["offset"]
        ok, rename = _mosaic_relocation_pair_rename(seed, donor, a, b)
        require(ok, f"{context}: relocation {index} differs from the seed")
        if rename is not None:
            renames.append(rename)
    return renames


def require_instruction_mosaic_semantic_relocations(
    seed: CoffObject,
    seed_section: dict,
    donor: CoffObject,
    donor_section: dict,
    context: str,
    *,
    permuted_ranges: list[tuple[int, int]] | None = None,
    reseat_windows: list[tuple[int, int]] | None = None,
) -> list[tuple[int, str]]:
    """Compare mosaic relocations while permitting benign COMDAT reseating.

    With ``reseat_windows`` (the declared ``relocation_reseat`` ranges) the
    ordinal rule still applies to every record, but a paired record may stand
    at another offset when both operands lie inside the same declared window
    (``_require_reseat_instruction_mosaic_relocations``).

    With ``permuted_ranges`` (the imported instruction ranges of a mosaic
    declared ``relocation_order: permuted_outside_ranges``) the offset-free
    multiset rule of ``_require_permuted_instruction_mosaic_relocations``
    applies instead of the ordinal rule.

    A declaration-only carrier can reorder otherwise identical vtable/data
    COMDATs.  The output retains the seed relocation table, so a same-named
    ordinary target may move seats only when both seats describe the exact
    same primary COMDAT identity.  Compiler-local symbols remain under the
    stricter ordinary mosaic rule.
    """
    require(
        permuted_ranges is None or reseat_windows is None,
        f"{context}: relocation permutation and reseat are exclusive",
    )
    if permuted_ranges is not None:
        return _require_permuted_instruction_mosaic_relocations(
            seed, seed_section, donor, donor_section, permuted_ranges, context
        )
    if reseat_windows is not None:
        return _require_reseat_instruction_mosaic_relocations(
            seed, seed_section, donor, donor_section, reseat_windows, context
        )
    renames = _normalized_relocation_renames(seed, seed_section, donor, donor_section, context)
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    for index, (seed_row, donor_row) in enumerate(zip(left, right)):
        require(
            seed_row["width"] == donor_row["width"], f"{context}: relocation {index} width differs"
        )
        same_name = seed_row["target"] == donor_row["target"]
        local = (
            local_symbol_kind(seed_row["target"]) is not None
            or local_symbol_kind(donor_row["target"]) is not None
        )
        common_fields = ("target_value", "target_type", "target_storage")
        require(same_name or local, f"{context}: relocation {index} changes symbol identity")
        require(
            all((seed_row[field] == donor_row[field] for field in common_fields)),
            f"{context}: relocation {index} target structure differs",
        )
        if seed_row["target_section"] == donor_row["target_section"]:
            continue
        require(
            same_name
            and (not local)
            and (seed_row["target_section"] > 0)
            and (donor_row["target_section"] > 0),
            f"{context}: relocation {index} changes target seat",
        )
        seed_target = seed.sections[seed_row["target_section"] - 1]
        donor_target = donor.sections[donor_row["target_section"] - 1]
        require(
            comdat_primary_identity(seed, seed_target)
            == comdat_primary_identity(donor, donor_target),
            f"{context}: relocation {index} reseats a different COMDAT",
        )
    return renames


def require_ordinary_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict,
    donor: CoffObject,
    donor_primary: dict,
    function: dict,
    identity: dict,
    context: str,
) -> list[tuple[dict, dict]]:
    """Authenticate one ordinary mosaic's exact FPO/CodeView closure."""
    mangled = function["mangled"]
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    require(
        seed_primary["characteristics"]
        == donor_primary["characteristics"]
        == identity["expected_primary_characteristics"],
        f"{context}: primary characteristics differ",
    )
    require(
        seed_definitions[seed_primary["number"]]["selection"]
        == donor_definitions[donor_primary["number"]]["selection"]
        == identity["expected_primary_selection"],
        f"{context}: primary COMDAT selection differs",
    )
    for role, coff in (("seed", seed), ("donor", donor)):
        require(
            sum(function_multiset(coff).values()) == identity["expected_function_count"],
            f"{context}: {role} function census differs",
        )
        require(
            sum(comdat_primary_identity_multiset(coff).values())
            == identity["expected_comdat_count"],
            f"{context}: {role} COMDAT census differs",
        )
    require(
        linker_payload_multiset(seed) == linker_payload_multiset(donor),
        f"{context}: declaration carrier changed linker payload",
    )
    require(
        sha256_bytes(_coff_table_bytes(seed, seed_primary, "lines"))
        == identity["expected_seed_line_sha256"]
        and sha256_bytes(_coff_table_bytes(donor, donor_primary, "lines"))
        == identity["expected_donor_line_sha256"],
        f"{context}: target line-table pin differs",
    )
    require(
        _comdat_child_closure(seed, seed_primary)
        == _comdat_child_closure(donor, donor_primary)
        == (2, (".debug$F", ".debug$S")),
        f"{context}: closure is not the exact FPO pair",
    )
    pairs = []
    for key, name in (("debug_f", ".debug$F"), ("debug_s", ".debug$S")):
        pin = identity[key]
        left = _comdat_child(seed, seed_primary, name)
        right = _comdat_child(donor, donor_primary, name)
        for role, coff, section, definitions in (
            ("seed", seed, left, seed_definitions),
            ("donor", donor, right, donor_definitions),
        ):
            definition = definitions[section["number"]]
            require(
                section["number"] == pin["section_number"]
                and section["raw_size"] == pin["raw_size"]
                and (section["relocation_count"] == pin["relocation_count"])
                and (section["line_count"] == pin["line_count"])
                and (section["characteristics"] == pin["characteristics"])
                and (definition["selection"] == pin["selection"])
                and (definition["associated"] == pin["associated"]),
                f"{context}: {role} {name} geometry differs",
            )
            require(
                sha256_bytes(coff_body(coff, section)) == pin[f"expected_{role}_body_sha256"],
                f"{context}: {role} {name} body pin differs",
            )
            require(
                sha256_bytes(_coff_table_bytes(coff, section, "relocations"))
                == pin[f"expected_{role}_relocation_sha256"],
                f"{context}: {role} {name} relocation-table pin differs",
            )
        require_same_semantic_relocations(seed, left, donor, right, f"{context} {name}")
        left_rows = detailed_relocations(seed, left)
        right_rows = detailed_relocations(donor, right)
        expected_rows = [(0, 4, 7)] if name == ".debug$F" else [(28, 4, 11), (32, 2, 10)]
        for role, rows in (("seed", left_rows), ("donor", right_rows)):
            require(
                len(rows) == len(expected_rows)
                and all(
                    (
                        (row["offset"], row["width"], row["type"]) == expected
                        and row["addend"] == 0
                        and (row["target"] == mangled)
                        and (row["target_section"] == seed_primary["number"])
                        and (row["target_value"] == 0)
                        and (row["target_type"] == 32)
                        and (row["target_storage"] == 2)
                        for row, expected in zip(rows, expected_rows)
                    )
                ),
                f"{context}: {role} {name} semantic relocations differ",
            )
        pairs.append((left, right))
    seed_f = coff_body(seed, pairs[0][0])
    donor_f = coff_body(donor, pairs[0][1])
    require(seed_f == donor_f, f"{context}: FPO raw bytes differ between compiler states")
    require(
        exact_json_equal(
            parse_fpo_data(seed_f, expected_proc_size=seed_primary["raw_size"]),
            identity["debug_f"]["expected_record"],
        )
        and exact_json_equal(
            parse_fpo_data(donor_f, expected_proc_size=donor_primary["raw_size"]),
            identity["debug_f"]["expected_record"],
        ),
        f"{context}: parsed FPO record differs",
    )
    seed_s = coff_body(seed, pairs[1][0])
    donor_s = coff_body(donor, pairs[1][1])
    debug_pin = identity["debug_s"]
    require(
        len(seed_s) == len(donor_s) == debug_pin["raw_size"]
        and seed_s[:28] == donor_s[:28]
        and (sha256_bytes(seed_s[:28]) == debug_pin["expected_common_prefix_sha256"])
        and (seed_s[2:4].hex() == debug_pin["expected_record_kind"]),
        f"{context}: CodeView procedure identity differs",
    )
    for role, raw in (("seed", seed_s), ("donor", donor_s)):
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", raw, 16)
        require(
            (cb_proc, dbg_start, dbg_end)
            == (
                debug_pin["expected_cb_proc"],
                debug_pin["expected_dbg_start"],
                debug_pin["expected_dbg_end"],
            )
            and 0 <= dbg_start <= dbg_end < cb_proc,
            f"{context}: {role} CodeView procedure range differs",
        )
    return pairs


def require_ordinary_fpo_self_permutation_receipts(
    seed: CoffObject, donor: CoffObject, function: dict, context: str
) -> dict:
    """Pin all object-wide identities for the isolated FPO permutation."""
    return require_self_permutation_receipts(
        seed, donor, function, ORDINARY_FPO_CLOSURE_CHILDREN, context
    )


def require_self_permutation_receipts(
    seed: CoffObject,
    donor: CoffObject,
    function: dict,
    closure_children: tuple[str, ...],
    context: str,
) -> dict:
    """Pin all object-wide identities for one isolated self-permutation.

    The permutation exchanges two of the seed's own complete instructions,
    so the donor is a witness rather than a byte source: it must be the same
    translation unit in a different declaration-carrier state, with an
    identical function set, COMDAT identity set, section shape and linker
    payload, and a COMDAT closure that describes the same procedure.
    """
    require(
        closure_children in (ORDINARY_FPO_CLOSURE_CHILDREN, EH_CLOSURE_CHILDREN),
        f"{context}: self-permutation closure class is not supported",
    )
    permutation = function["instruction_self_permutation"]
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    seed_linker = linker_payload_multiset(seed)
    donor_linker = linker_payload_multiset(donor)
    require(
        seed_functions == donor_functions
        and canonical_counter_receipt_sha256(seed_functions)
        == canonical_counter_receipt_sha256(donor_functions)
        == permutation["expected_function_multiset_sha256"],
        f"{context}: function multiset receipt differs",
    )
    require(
        seed_comdats == donor_comdats
        and canonical_counter_receipt_sha256(seed_comdats)
        == canonical_counter_receipt_sha256(donor_comdats)
        == permutation["expected_comdat_multiset_sha256"],
        f"{context}: COMDAT multiset receipt differs",
    )
    require(
        len(seed.sections) == len(donor.sections)
        and section_shape_receipt_sha256(seed)
        == section_shape_receipt_sha256(donor)
        == permutation["expected_section_shape_sha256"],
        f"{context}: section shape receipt differs",
    )
    require(
        seed_linker == donor_linker
        and sum(seed_linker.values())
        == sum(donor_linker.values())
        == permutation["expected_linker_payload_count"]
        and (
            canonical_counter_receipt_sha256(seed_linker)
            == canonical_counter_receipt_sha256(donor_linker)
            == permutation["expected_linker_payload_sha256"]
        ),
        f"{context}: linker payload receipt differs",
    )
    seed_primary = seed.function_section(function["mangled"])
    donor_primary = donor.function_section(function["mangled"])
    for child_name in closure_children:
        seed_child = _comdat_child(seed, seed_primary, child_name)
        donor_child = _comdat_child(donor, donor_primary, child_name)
        seed_child_body = coff_body(seed, seed_child)
        donor_child_body = coff_body(donor, donor_child)
        if closure_children == EH_CLOSURE_CHILDREN and child_name == ".debug$S":
            require(
                len(seed_child_body) == len(donor_child_body) >= 28
                and seed_child_body[:28] == donor_child_body[:28]
                and (seed_child_body[2:4] == b"\x05\x02"),
                f"{context}: {child_name} procedure identity differs between compiler states",
            )
        else:
            require(
                seed_child_body == donor_child_body,
                f"{context}: {child_name} body differs between compiler states",
            )
    source_identity = function["same_function_source_identity"]
    carrier = validate_donor_source_compiler_state_carrier(
        source_identity.get("carrier"), f"{context} carrier descriptor"
    )
    identifiers = [
        f"{carrier[f'{role}_prefix']}{index:0{carrier['width']}d}"
        for role in DONOR_SOURCE_CARRIER_SEATS[carrier["kind"]][1]
        for index in range(carrier[f"{role}_count"])
    ]
    normalized_identifiers = source_identity.get("carrier_identifiers")
    require(
        normalized_identifiers is None or normalized_identifiers == identifiers,
        f"{context}: normalized carrier identifier set differs",
    )
    leaked_symbols = [
        symbol["name"]
        for symbol in donor.symbols.values()
        if any((identifier in symbol["name"] for identifier in identifiers))
    ]
    leaked_bytes = [
        identifier for identifier in identifiers if identifier.encode("ascii") in donor.data
    ]
    require(
        not leaked_symbols and (not leaked_bytes),
        f"{context}: generated declarations leaked into donor output",
    )
    return {
        "function_multiset_sha256": permutation["expected_function_multiset_sha256"],
        "comdat_multiset_sha256": permutation["expected_comdat_multiset_sha256"],
        "section_shape_sha256": permutation["expected_section_shape_sha256"],
        "linker_payload_sha256": permutation["expected_linker_payload_sha256"],
        "carrier_identifiers_absent": True,
    }


def require_source_fpo_mosaic_identity(
    seed: CoffObject,
    seed_primary: dict,
    donor: CoffObject,
    donor_primary: dict,
    function: dict,
    identity: dict,
    context: str,
) -> list[tuple[dict, dict]]:
    """Authenticate one source-refactor mosaic's exact FPO closure.

    The seed and donor may have separately pinned CodeView payload sizes and
    bodies, but they must describe the same procedure and retain identical
    FPO data and semantic child relocations. The composed output remains
    seed-authoritative for both children.
    """
    mangled = function["mangled"]
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    require(
        seed_primary["characteristics"]
        == donor_primary["characteristics"]
        == identity["expected_primary_characteristics"],
        f"{context}: primary characteristics differ",
    )
    require(
        seed_definitions[seed_primary["number"]]["selection"]
        == donor_definitions[donor_primary["number"]]["selection"]
        == identity["expected_primary_selection"],
        f"{context}: primary COMDAT selection differs",
    )
    for role, coff in (("seed", seed), ("donor", donor)):
        require(
            sum(function_multiset(coff).values()) == identity["expected_function_count"],
            f"{context}: {role} function census differs",
        )
        require(
            sum(comdat_primary_identity_multiset(coff).values())
            == identity["expected_comdat_count"],
            f"{context}: {role} COMDAT census differs",
        )
    require(
        linker_payload_multiset(seed) == linker_payload_multiset(donor),
        f"{context}: source refactor changed linker payload",
    )
    require(
        sha256_bytes(_coff_table_bytes(seed, seed_primary, "lines"))
        == identity["expected_seed_line_sha256"]
        and sha256_bytes(_coff_table_bytes(donor, donor_primary, "lines"))
        == identity["expected_donor_line_sha256"],
        f"{context}: target line-table pin differs",
    )
    require(
        _comdat_child_closure(seed, seed_primary)
        == _comdat_child_closure(donor, donor_primary)
        == (2, (".debug$F", ".debug$S")),
        f"{context}: closure is not the exact FPO pair",
    )
    pairs = []
    for key, name in (("debug_f", ".debug$F"), ("debug_s", ".debug$S")):
        pin = identity[key]
        left = _comdat_child(seed, seed_primary, name)
        right = _comdat_child(donor, donor_primary, name)
        for role, coff, section, definitions, primary in (
            ("seed", seed, left, seed_definitions, seed_primary),
            ("donor", donor, right, donor_definitions, donor_primary),
        ):
            definition = definitions[section["number"]]
            require(
                section["number"] == pin["section_number"]
                and section["raw_size"] == pin[f"expected_{role}_raw_size"]
                and (section["relocation_count"] == pin["relocation_count"])
                and (section["line_count"] == pin["line_count"])
                and (section["characteristics"] == pin["characteristics"])
                and (definition["selection"] == pin["selection"])
                and (definition["associated"] == primary["number"] == pin["associated"]),
                f"{context}: {role} {name} geometry differs",
            )
            require(
                sha256_bytes(coff_body(coff, section)) == pin[f"expected_{role}_body_sha256"],
                f"{context}: {role} {name} body pin differs",
            )
            require(
                sha256_bytes(_coff_table_bytes(coff, section, "relocations"))
                == pin[f"expected_{role}_relocation_sha256"],
                f"{context}: {role} {name} relocation-table pin differs",
            )
        require_same_semantic_relocations(seed, left, donor, right, f"{context} {name}")
        expected_rows = [(0, 4, 7)] if name == ".debug$F" else [(28, 4, 11), (32, 2, 10)]
        expected_extra = [] if name == ".debug$F" else pin.get("expected_extra_relocations", [])
        for role, coff, section, primary in (
            ("seed", seed, left, seed_primary),
            ("donor", donor, right, donor_primary),
        ):
            rows = detailed_relocations(coff, section)
            require(
                len(rows) == len(expected_rows) + len(expected_extra)
                and all(
                    (
                        (row["offset"], row["width"], row["type"]) == expected
                        and row["addend"] == 0
                        and (row["target"] == mangled)
                        and (row["target_section"] == primary["number"])
                        and (row["target_value"] == 0)
                        and (row["target_type"] == 32)
                        and (row["target_storage"] == 2)
                        for row, expected in zip(rows, expected_rows)
                    )
                ),
                f"{context}: {role} {name} semantic relocations differ",
            )
            require(
                all(
                    (
                        all(
                            (
                                row[field] == expected[field]
                                for field in (
                                    "offset",
                                    "width",
                                    "type",
                                    "addend",
                                    "target",
                                    "target_section",
                                    "target_value",
                                    "target_type",
                                    "target_storage",
                                )
                            )
                        )
                        for row, expected in zip(rows[len(expected_rows) :], expected_extra)
                    )
                ),
                f"{context}: {role} {name} extra semantic relocations differ",
            )
        pairs.append((left, right))
    seed_f = coff_body(seed, pairs[0][0])
    donor_f = coff_body(donor, pairs[0][1])
    fpo_pin = identity["debug_f"]["expected_record"]
    require(
        seed_f == donor_f and sha256_bytes(seed_f) == fpo_pin["raw_sha256"],
        f"{context}: FPO raw bytes differ",
    )
    require(
        exact_json_equal(
            parse_fpo_data(seed_f, expected_proc_size=seed_primary["raw_size"]), fpo_pin
        )
        and exact_json_equal(
            parse_fpo_data(donor_f, expected_proc_size=donor_primary["raw_size"]), fpo_pin
        ),
        f"{context}: parsed FPO record differs",
    )
    seed_s = coff_body(seed, pairs[1][0])
    donor_s = coff_body(donor, pairs[1][1])
    debug_pin = identity["debug_s"]
    require(
        len(seed_s) == debug_pin["expected_seed_raw_size"]
        and len(donor_s) == debug_pin["expected_donor_raw_size"]
        and (seed_s[:28] == donor_s[:28])
        and (sha256_bytes(seed_s[:28]) == debug_pin["expected_common_prefix_sha256"])
        and (seed_s[2:4].hex() == debug_pin["expected_record_kind"])
        and (sha256_bytes(seed_s[28:]) == debug_pin["expected_seed_tail_sha256"])
        and (sha256_bytes(donor_s[28:]) == debug_pin["expected_donor_tail_sha256"]),
        f"{context}: CodeView procedure identity differs",
    )
    for role, raw in (("seed", seed_s), ("donor", donor_s)):
        cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", raw, 16)
        require(
            (cb_proc, dbg_start, dbg_end)
            == (
                debug_pin["expected_cb_proc"],
                debug_pin["expected_dbg_start"],
                debug_pin["expected_dbg_end"],
            )
            and 0 <= dbg_start <= dbg_end < cb_proc,
            f"{context}: {role} CodeView procedure range differs",
        )
    return pairs


def _pair_same_slot_relocations(
    seed_rows, donor_rows, seed_primary, donor_primary, seed_xdata, donor_xdata, mapping, context
):
    """Pair ordinal relocation semantics allowing offset movement and
    consistently mapped object-local symbols inside the target closure."""
    require(len(seed_rows) == len(donor_rows), f"{context}: relocation counts differ")
    reverse = {right: left for left, right in mapping.items()}

    def role(section_number, primary, xdata):
        if section_number == primary:
            return "primary"
        if section_number == xdata:
            return "xdata"
        return "external"

    pairs = []
    for left, right in zip(seed_rows, donor_rows):
        require(
            left["type"] == right["type"] and left["addend"] == right["addend"],
            f"{context}: relocation type/addend differs",
        )
        require(
            role(left["target_section"], seed_primary, seed_xdata)
            == role(right["target_section"], donor_primary, donor_xdata),
            f"{context}: relocation target role differs",
        )
        left_local = local_symbol_kind(left["target"]) is not None
        right_local = local_symbol_kind(right["target"]) is not None
        if left_local or right_local:
            require(
                left_local
                and right_local
                and (left["target"][1] == right["target"][1])
                and (left["target_type"] == right["target_type"])
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: local relocation target class differs",
            )
            if role(left["target_section"], seed_primary, seed_xdata) in ("primary", "xdata"):
                require(
                    mapping.setdefault(left["symbol_index"], right["symbol_index"])
                    == right["symbol_index"]
                    and reverse.setdefault(right["symbol_index"], left["symbol_index"])
                    == left["symbol_index"],
                    f"{context}: local symbol mapping is inconsistent",
                )
            else:
                require(
                    left["target_section"] == right["target_section"]
                    and left["target_value"] == right["target_value"],
                    f"{context}: external local relocation target differs",
                )
        else:
            require(
                left["target"] == right["target"]
                and left["target_type"] == right["target_type"]
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: relocation target differs",
            )
        pairs.append((left, right))
    return pairs


def _resolve_substituted_seed_symbol(seed: CoffObject, donor_record: dict, context: str) -> int:
    """B5/B6: map a donor relocation's EXTERNAL target onto the seed's own
    symbol table, by name, unambiguously, with matching class.

    Compiler-local `$L`/`$T`/`$S` serials are deliberately NOT routed here --
    they are assigned per compile, are never present in the seed, and stay
    with the existing rename machinery (spec amendment 2).
    """
    name = donor_record["target"]
    require(
        local_symbol_kind(name) is None,
        f"{context}: compiler-local target {name!r} must not be remapped",
    )
    matches = [(index, symbol) for index, symbol in seed.symbols.items() if symbol["name"] == name]
    require(
        matches,
        f"{context}: donor relocation target {name!r} is not declared or defined by the seed object",
    )
    require(
        len(matches) == 1,
        f"{context}: ambiguous symbol remap for {name!r} -- {len(matches)} seed symbols share the name",
    )
    index, symbol = matches[0]
    require(
        symbol["type"] == donor_record["target_type"]
        and symbol["storage"] == donor_record["target_storage"],
        f"{context}: seed symbol {name!r} differs in type or storage class (seed type=0x{symbol['type']:02x} storage={symbol['storage']}, donor type=0x{donor_record['target_type']:02x} storage={donor_record['target_storage']})",
    )
    return index


def _source_target_relocation_substitutions(
    seed: CoffObject,
    donor_rows: list[dict],
    mapping: dict[int, int],
    expected_imports: list[str],
    section_map: dict[int, int],
    context: str,
) -> tuple[dict[int, int], list[tuple[str, int, int]]]:
    """Resolve a whole donor target table into seed locals/externals."""
    reverse = {donor_index: seed_index for seed_index, donor_index in mapping.items()}
    imports = {}
    substitutions = {}
    for ordinal, record in enumerate(donor_rows):
        if local_symbol_kind(record["target"]) is not None:
            if record["symbol_index"] not in reverse:
                candidates = [
                    index
                    for index, symbol in seed.symbols.items()
                    if local_symbol_kind(symbol["name"]) == local_symbol_kind(record["target"])
                    and symbol["section"] == section_map.get(record["target_section"])
                    and (symbol["value"] == record["target_value"])
                    and (symbol["type"] == record["target_type"])
                    and (symbol["storage"] == record["target_storage"])
                ]
                require(
                    len(candidates) == 1, f"{context}: target local has no unique seed structure"
                )
                mapping[candidates[0]] = record["symbol_index"]
                reverse[record["symbol_index"]] = candidates[0]
            substitutions[ordinal] = reverse[record["symbol_index"]]
            continue
        matches = [
            index for index, symbol in seed.symbols.items() if symbol["name"] == record["target"]
        ]
        if matches:
            substitutions[ordinal] = _resolve_substituted_seed_symbol(seed, record, context)
            continue
        name = record["target"]
        require(
            name in expected_imports
            and record["target_value"] == 0
            and (record["target_type"] == 32)
            and (record["target_storage"] == 2),
            f"{context}: donor target {name!r} is absent from the seed",
        )
        imports.setdefault(name, (name, record["target_type"], record["target_storage"]))
        substitutions[ordinal] = seed.symbol_count + expected_imports.index(name)
    require(
        sorted(imports) == expected_imports, f"{context}: imported undefined symbol set differs"
    )
    return (substitutions, [imports[name] for name in expected_imports])


def _append_undefined_external_symbols(data: bytes, symbols: list[tuple[str, int, int]]) -> bytes:
    if not symbols:
        return data
    coff = CoffObject(data)
    strings = bytearray(data[coff.string_offset : coff.string_end])
    records = bytearray()
    for name, symbol_type, storage in symbols:
        encoded = name.encode("ascii")
        if len(encoded) <= 8:
            name_field = encoded.ljust(8, b"\x00")
        else:
            name_field = b"\x00\x00\x00\x00" + len(strings).to_bytes(4, "little")
            strings.extend(encoded + b"\x00")
        records.extend(name_field + struct.pack("<IhHBB", 0, 0, symbol_type, storage, 0))
    strings[:4] = len(strings).to_bytes(4, "little")
    output = bytearray(data[: coff.string_offset] + records + strings)
    output[12:16] = (coff.symbol_count + len(symbols)).to_bytes(4, "little")
    return bytes(output)


def _pair_reloc_divergent(
    seed,
    donor,
    seed_rows,
    donor_rows,
    seed_primary,
    donor_primary,
    seed_xdata,
    donor_xdata,
    mapping,
    context,
):
    """Pair the primary table allowing a divergent EXTERNAL target set.

    Identical to `_pair_same_slot_relocations` except that where both sides
    name ordinary (non-local) symbols and those names DIFFER, the ordinal is
    recorded as a substitution and the donor's target is resolved into the
    seed's symbol table under B5/B6.  Returns (pairs, substitutions) where
    substitutions maps the ordinal index to the seed symbol index to write.
    """
    require(
        len(donor_rows) >= len(seed_rows),
        f"{context}: the donor carries FEWER relocations than the seed; the shrinking path is not implemented",
    )
    appended_rows = donor_rows[len(seed_rows) :]
    donor_rows = donor_rows[: len(seed_rows)]
    reverse = {right: left for left, right in mapping.items()}

    def role(section_number, primary, xdata):
        if section_number == primary:
            return "primary"
        if section_number == xdata:
            return "xdata"
        return "external"

    pairs = []
    substitutions: dict[int, int] = {}
    for ordinal, (left, right) in enumerate(zip(seed_rows, donor_rows)):
        require(left["type"] == right["type"], f"{context}: relocation type differs")
        left_local = local_symbol_kind(left["target"]) is not None
        right_local = local_symbol_kind(right["target"]) is not None
        if left_local or right_local:
            require(left["addend"] == right["addend"], f"{context}: relocation addend differs")
            require(
                role(left["target_section"], seed_primary, seed_xdata)
                == role(right["target_section"], donor_primary, donor_xdata),
                f"{context}: relocation target role differs",
            )
            require(
                left_local
                and right_local
                and (left["target"][1] == right["target"][1])
                and (left["target_type"] == right["target_type"])
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: local relocation target class differs",
            )
            if role(left["target_section"], seed_primary, seed_xdata) in ("primary", "xdata"):
                require(
                    mapping.setdefault(left["symbol_index"], right["symbol_index"])
                    == right["symbol_index"]
                    and reverse.setdefault(right["symbol_index"], left["symbol_index"])
                    == left["symbol_index"],
                    f"{context}: local symbol mapping is inconsistent",
                )
            else:
                left_section_number = left["target_section"]
                right_section_number = right["target_section"]
                require(
                    0 < left_section_number <= len(seed.sections)
                    and right_section_number <= len(donor.sections)
                    and (left_section_number == right_section_number)
                    and (left["target_value"] == right["target_value"]),
                    f"{context}: external local relocation target differs",
                )
                left_section = seed.sections[left_section_number - 1]
                right_section = donor.sections[right_section_number - 1]
                left_definition = section_definitions(seed).get(left_section_number)
                right_definition = section_definitions(donor).get(right_section_number)
                require(
                    all(
                        (
                            left_section[key] == right_section[key]
                            for key in (
                                "name",
                                "raw_size",
                                "relocation_count",
                                "line_count",
                                "characteristics",
                            )
                        )
                    )
                    and coff_body(seed, left_section) == coff_body(donor, right_section)
                    and (
                        _coff_table_bytes(seed, left_section, "relocations")
                        == _coff_table_bytes(donor, right_section, "relocations")
                    )
                    and (
                        _coff_table_bytes(seed, left_section, "lines")
                        == _coff_table_bytes(donor, right_section, "lines")
                    )
                    and (left_definition is not None)
                    and (right_definition is not None)
                    and (left_definition["raw"] == right_definition["raw"]),
                    f"{context}: external local target section differs",
                )
        elif left["target"] == right["target"]:
            require(left["addend"] == right["addend"], f"{context}: relocation addend differs")
            require(
                left["target_type"] == right["target_type"]
                and left["target_storage"] == right["target_storage"],
                f"{context}: relocation target class differs",
            )
            require(
                _resolve_substituted_seed_symbol(seed, right, context) == left["symbol_index"],
                f"{context}: same-name relocation target is ambiguous or does not name the paired seed symbol",
            )
        else:
            left_base, left_sep, left_serial = left["target"].rpartition("$S")
            right_base, right_sep, right_serial = right["target"].rpartition("$S")
            if (
                left_sep
                and right_sep
                and left_base
                and (left_base == right_base)
                and left_serial.isdigit()
                and right_serial.isdigit()
            ):
                require(
                    left["addend"] == right["addend"]
                    and left["target_type"] == right["target_type"]
                    and (left["target_storage"] == right["target_storage"])
                    and (left["target_value"] == right["target_value"]),
                    f"{context}: renamed $S relocation target class differs",
                )
                left_section_number = left["target_section"]
                right_section_number = right["target_section"]
                require(
                    0 < left_section_number <= len(seed.sections)
                    and 0 < right_section_number <= len(donor.sections),
                    f"{context}: renamed $S relocation names no section",
                )
                left_section = seed.sections[left_section_number - 1]
                right_section = donor.sections[right_section_number - 1]
                require(
                    all(
                        (
                            left_section[key] == right_section[key]
                            for key in (
                                "name",
                                "raw_size",
                                "relocation_count",
                                "line_count",
                                "characteristics",
                            )
                        )
                    )
                    and coff_body(seed, left_section) == coff_body(donor, right_section)
                    and (
                        _coff_table_bytes(seed, left_section, "relocations")
                        == _coff_table_bytes(donor, right_section, "relocations")
                    ),
                    f"{context}: renamed $S target section differs",
                )
                matches = [
                    index
                    for index, symbol in seed.symbols.items()
                    if symbol["name"] == left["target"]
                ]
                require(
                    len(matches) == 1,
                    f"{context}: renamed $S seed symbol {left['target']!r} is not unique",
                )
                substitutions[ordinal] = matches[0]
            else:
                substitutions[ordinal] = _resolve_substituted_seed_symbol(seed, right, context)
        pairs.append((left, right))
    appended: list[tuple[dict, int]] = []
    for extra_index, record in enumerate(appended_rows):
        where = f"{context} appended relocation {extra_index}"
        require(
            local_symbol_kind(record["target"]) is None,
            f"{where}: appended compiler-local target {record['target']!r} has no seed symbol to name it",
        )
        appended.append((record, _resolve_substituted_seed_symbol(seed, record, where)))
    return (pairs, substitutions, appended)


def compose_same_slot_resize(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    *,
    target_closure_extract: bool = False,
    source_target_extract: bool = False,
    declared_donor_extras: list | None = None,
    declared_seed_only: list | None = None,
) -> tuple[bytes, dict]:
    """Install a donor code body of a different size that occupies the same
    16-byte linked contribution slot, repairing every dependent COFF record.

    The seed supplies the object, symbol table, CodeView types/names, xdata
    raw bytes/relocations, and every non-target section.  The donor supplies
    the compiler-generated target code, COFF line offsets, and procedure
    debug range.  Mapped object-local symbol values move to the donor's.

    A declared divergent class may use a different EXTERNAL relocation target
    set.  The producer proves that set against declarative symbol semantics;
    it never receives reference bytes.  Final linked-byte equality belongs to
    the sealed verifier.  ``target_closure_extract`` replaces only the two
    whole-donor topology guards with a pinned strict-subset proof; every
    target-closure and output-conservation guard remains shared.
    """
    require_payload_free_declaration(function, "same-slot resize declaration")
    splice_class = function.get("splice_class")
    require(
        splice_class
        in (
            "same_slot_resize",
            "retail_exact_reloc_divergent",
            "retail_exact_target_closure",
            "retail_exact_source_target_closure",
        ),
        "same-slot composer received an unsupported splice class",
    )
    expected_divergent = splice_class != "same_slot_resize"
    expected_extract = splice_class == "retail_exact_target_closure"
    expected_source_extract = splice_class == "retail_exact_source_target_closure"
    require(
        target_closure_extract == expected_extract,
        "target-closure topology mode differs from the splice class",
    )
    require(
        source_target_extract == expected_source_extract,
        "source-target topology mode differs from the splice class",
    )
    divergent = expected_divergent
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_donor_length"],
        "target body lengths changed",
    )
    require(
        (dp["raw_size"] + 15) // 16 * 16 == function["expected_linked_span"],
        "donor 16-byte linked contribution span changed",
    )
    declared_donor_seat = function.get("expected_donor_section_number")
    if declared_donor_seat is None:
        require(sp["number"] == dp["number"], "target section seat changed")
    else:
        require(dp["number"] == declared_donor_seat, "declared cross-lane donor seat changed")
    topology_detail = {}
    if source_target_extract:
        topology_detail = require_source_target_closure_topology(
            seed, donor, function, "source-target closure extraction"
        )
    elif target_closure_extract:
        topology_detail = require_target_closure_extraction_topology(
            seed, donor, function, "target-closure extraction"
        )
    elif declared_donor_extras or declared_seed_only:
        seed_fns = function_multiset(seed)
        donor_fns = function_multiset(donor)
        measured_extra = []
        measured_only = []
        for name in set(seed_fns) | set(donor_fns):
            left, right = (seed_fns.get(name, 0), donor_fns.get(name, 0))
            if right == left:
                continue
            if right == left + 1:
                measured_extra.append(name)
                continue
            require(left == right + 1, f"donor function census diverges at {name}")
            measured_only.append(name)
        require(
            sorted(measured_extra) == sorted(declared_donor_extras or []),
            "donor function set differs from its declared extras",
        )
        require(
            sorted(measured_only) == sorted(declared_seed_only or []),
            "donor function set differs from its declared seed-only names",
        )
        require(
            mangled not in (declared_seed_only or []),
            "the target itself cannot be a seed-only name",
        )
    else:
        require(len(seed.sections) == len(donor.sections), "global section count differs")
        require(function_multiset(seed) == function_multiset(donor), "donor function set differs")
    require(
        all((sp[key] == dp[key] for key in ("name", "characteristics"))),
        "target header shape changed",
    )
    require(
        divergent or sp["relocation_count"] == dp["relocation_count"], "target header shape changed"
    )
    if "expected_seed_line_count" in function or "expected_donor_line_count" in function:
        require(
            sp["line_count"] == function["expected_seed_line_count"]
            and dp["line_count"] == function["expected_donor_line_count"],
            "target COFF line counts differ from their split pins",
        )
    else:
        require(sp["line_count"] == dp["line_count"], "target header shape changed")
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[sp["number"]]["selection"] == donor_defs[dp["number"]]["selection"],
        "target COMDAT selection changed",
    )
    closure = _comdat_child_closure(seed, (seed_primary := sp))
    require(
        closure == _comdat_child_closure(donor, dp)
        and closure in ((2, (".debug$S", ".xdata$x")), (2, (".debug$F", ".debug$S"))),
        "target closure is not an EH or FPO debug pair",
    )
    fpo_closure = closure == (2, (".debug$F", ".debug$S"))
    if fpo_closure:
        sx = _comdat_child(seed, sp, ".debug$F")
        dx = _comdat_child(donor, dp, ".debug$F")
    else:
        sx = _comdat_child(seed, sp, ".xdata$x")
        dx = _comdat_child(donor, dp, ".xdata$x")
    sd = _comdat_child(seed, sp, ".debug$S")
    dd = _comdat_child(donor, dp, ".debug$S")
    if declared_donor_seat is None:
        require(
            sx["number"] == dx["number"] and sd["number"] == dd["number"],
            "closure section seats changed",
        )
    local_set_delta = function.get("local_set_delta")
    representation_delta = function.get("debug_representation_delta")
    local_set_detail = {}
    reduced_debug_raw = None
    debug_shape_keys = ("name", "raw_size", "relocation_count", "line_count", "characteristics")
    if local_set_delta is not None:
        require(
            "target_source_refactor" in function
            and function["target_source_refactor"]["kind"] in LOCAL_SET_DELTA_REFACTOR_KINDS,
            "local-set delta is outside its closed source-refactor kinds",
        )
        debug_shape_keys = ("name", "relocation_count", "line_count", "characteristics")
    if representation_delta is not None:
        require(
            local_set_delta is None,
            "debug representation delta cannot combine with a local-set delta",
        )
        debug_shape_keys = ("name", "relocation_count", "line_count", "characteristics")
    for left, right, name, keys in (
        (
            sx,
            dx,
            "xdata",
            ("name", "raw_size", "relocation_count", "line_count", "characteristics"),
        ),
        (sd, dd, "debug$S", debug_shape_keys),
    ):
        require(all((left[key] == right[key] for key in keys)), f"{name} section shape changed")
    if local_set_delta is not None:
        local_set_detail, reduced_debug_raw = require_removed_caller_locals_delta(
            coff_body(seed, sd),
            coff_body(donor, dd),
            [item["offset"] for item in detailed_relocations(seed, sd)],
            local_set_delta,
            "debug$S local-set delta",
        )
    representation_detail = []
    if representation_delta is not None:
        representation_detail = require_debug_symbol_representation_delta(
            bytes(coff_body(seed, sd)),
            bytes(coff_body(donor, dd)),
            representation_delta,
            function["expected_seed_length"],
            function["expected_donor_length"],
            "debug$S representation delta",
        )
    if fpo_closure:
        parse_fpo_data(coff_body(seed, sx), expected_proc_size=sp["raw_size"])
        donor_fpo = coff_body(donor, dx)
        parse_fpo_data(donor_fpo, expected_proc_size=dp["raw_size"])
    else:
        require(coff_body(seed, sx) == coff_body(donor, dx), "runtime xdata bytes differ")
    donor_code = coff_body(donor, dp)
    require(
        sha256_bytes(donor_code) == function["expected_body_sha256"],
        "donor body differs from its pinned compiler output",
    )
    spr = detailed_relocations(seed, sp)
    dpr = detailed_relocations(donor, dp)
    sxr = detailed_relocations(seed, sx)
    dxr = detailed_relocations(donor, dx)
    sdr = detailed_relocations(seed, sd)
    ddr = detailed_relocations(donor, dd)
    mapping: dict[int, int] = {}
    substitutions: dict[int, int] = {}
    appended_relocations: list[tuple[dict, int]] = []
    imported_symbols: list[tuple[str, int, int]] = []
    xdata_pairs = _pair_same_slot_relocations(
        sxr, dxr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "xdata"
    )
    debug_pairs = _pair_same_slot_relocations(
        sdr, ddr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "debug$S"
    )
    if divergent:
        pinned_length = function["retail_oracle"]["length"]
        require(
            len(donor_code) == pinned_length,
            "candidate body differs from its declared linked length",
        )
        semantic_detail = require_declared_relocation_semantics(
            dpr, function["retail_relocations"], "candidate relocation semantics"
        )
        if source_target_extract:
            require(len(spr) == len(dpr), "source-target relocation table count changed")
            substitutions, imported_symbols = _source_target_relocation_substitutions(
                seed,
                dpr,
                mapping,
                function["expected_imported_undefined_symbols"],
                {dp["number"]: sp["number"], dx["number"]: sx["number"]},
                "source-target primary",
            )
        else:
            _, substitutions, appended_relocations = _pair_reloc_divergent(
                seed,
                donor,
                spr,
                dpr,
                sp["number"],
                dp["number"],
                sx["number"],
                dx["number"],
                mapping,
                "primary",
            )
    else:
        semantic_detail = {}
        _pair_same_slot_relocations(
            spr, dpr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "primary"
        )
    require(
        all((a["offset"] == b["offset"] for a, b in xdata_pairs)), "xdata relocation offsets moved"
    )
    require(
        all((a["offset"] == b["offset"] for a, b in debug_pairs)),
        "debug$S relocation offsets moved",
    )
    allowed_sections = {sp["number"], sx["number"], sd["number"]}
    for section in seed.sections:
        for record in (
            detailed_relocations(seed, section)
            if section["relocation_count"] and section["number"] not in allowed_sections
            else []
        ):
            require(
                record["symbol_index"] not in mapping,
                "mapped local is consumed outside the target closure",
            )
    for seed_index, donor_index in mapping.items():
        left = seed.symbols[seed_index]
        right = donor.symbols[donor_index]
        if declared_donor_seat is None:
            require(
                (left["section"], left["type"], left["storage"])
                == (right["section"], right["type"], right["storage"]),
                "mapped local symbol class changed",
            )
        else:
            require(
                (left["section"] - sp["number"], left["type"], left["storage"])
                == (right["section"] - dp["number"], right["type"], right["storage"]),
                "mapped local symbol class changed",
            )
    seed_function_index, seed_function = function_symbol(seed, mangled, sp["number"])
    donor_function_index, donor_function = function_symbol(donor, mangled, dp["number"])
    require(sp["line_count"] > 0 and dp["line_count"] > 0, "target COFF line count changed")
    seed_lines = _coff_table_bytes(seed, sp, "lines")
    donor_lines = bytearray(_coff_table_bytes(donor, dp, "lines"))
    require(
        coff_unpack("<IH", seed_lines, 0, "seed line sentinel") == (seed_function_index, 0)
        and coff_unpack("<IH", donor_lines, 0, "donor line sentinel") == (donor_function_index, 0),
        "COFF line sentinel is invalid",
    )
    donor_lines[0:4] = seed_function_index.to_bytes(4, "little")
    previous = -1
    for index in range(1, dp["line_count"]):
        offset, line = coff_unpack("<IH", bytes(donor_lines), index * 6, "donor line row")
        require(
            line != 0 and previous <= offset < dp["raw_size"],
            "donor COFF line row is outside/nonmonotonic",
        )
        previous = offset
    donor_lines = bytes(donor_lines)
    seed_debug_raw = coff_body(seed, sd)
    donor_debug_raw = coff_body(donor, dd)
    require(
        len(seed_debug_raw) >= 28
        and seed_debug_raw[2:4] == b"\x05\x02"
        and (donor_debug_raw[2:4] == b"\x05\x02"),
        "debug$S is not an S_*PROC32 record",
    )
    donor_cbproc, donor_dbgstart, donor_dbgend = coff_unpack(
        "<III", donor_debug_raw, 16, "donor debug range"
    )
    require(
        donor_cbproc == dp["raw_size"] and 0 <= donor_dbgstart <= donor_dbgend < donor_cbproc,
        "donor debug procedure range is stale",
    )
    expected_debug_raw = bytearray(
        seed_debug_raw if reduced_debug_raw is None else reduced_debug_raw
    )
    expected_debug_raw[16:28] = donor_debug_raw[16:28]
    old_end = sp["raw_offset"] + sp["raw_size"]
    replacements = [
        (sp["raw_offset"], old_end, donor_code),
        (sp["line_offset"], sp["line_offset"] + sp["line_count"] * 6, donor_lines),
    ]
    if reduced_debug_raw is not None:
        replacements.append(
            (sd["raw_offset"], sd["raw_offset"] + sd["raw_size"], bytes(expected_debug_raw))
        )
    if appended_relocations:
        grown = bytearray()
        for index, (left, right) in enumerate(zip(spr, dpr)):
            grown += right["offset"].to_bytes(4, "little")
            grown += substitutions.get(index, left["symbol_index"]).to_bytes(4, "little")
            grown += right["type"].to_bytes(2, "little")
        for record, seed_symbol_index in appended_relocations:
            grown += record["offset"].to_bytes(4, "little")
            grown += seed_symbol_index.to_bytes(4, "little")
            grown += record["type"].to_bytes(2, "little")
        require(
            len(grown) == dp["relocation_count"] * 10,
            "rebuilt relocation table size does not match the donor count",
        )
        replacements.append(
            (
                sp["relocation_offset"],
                sp["relocation_offset"] + sp["relocation_count"] * 10,
                bytes(grown),
            )
        )
    total_delta = sum(
        (len(replacement) - (end - start) for start, end, replacement in replacements)
    )

    def shifted(pointer: int) -> int:
        return shifted_pointer(pointer, replacements)

    output = bytearray(_apply_replacements(seed_bytes, replacements))
    new_symbol_offset = shifted(seed.symbol_offset)
    output[8:12] = new_symbol_offset.to_bytes(4, "little")
    for section in seed.sections:
        header = 20 + (section["number"] - 1) * 40
        if section["number"] == sp["number"]:
            output[header + 16 : header + 20] = dp["raw_size"].to_bytes(4, "little")
            output[header + 34 : header + 36] = dp["line_count"].to_bytes(2, "little")
            if appended_relocations:
                output[header + 32 : header + 34] = dp["relocation_count"].to_bytes(2, "little")
        if reduced_debug_raw is not None and section["number"] == sd["number"]:
            output[header + 16 : header + 20] = len(expected_debug_raw).to_bytes(4, "little")
        for field, relative in (("raw_offset", 20), ("relocation_offset", 24), ("line_offset", 28)):
            pointer = shifted(section[field])
            if pointer != section[field]:
                output[header + relative : header + relative + 4] = pointer.to_bytes(4, "little")
    primary_relocation_output = shifted(sp["relocation_offset"])
    for index, (left, right) in enumerate([] if appended_relocations else zip(spr, dpr)):
        at = primary_relocation_output + index * 10
        symbol_index = substitutions.get(index, left["symbol_index"])
        output[at : at + 4] = right["offset"].to_bytes(4, "little")
        output[at + 4 : at + 8] = symbol_index.to_bytes(4, "little")
        output[at + 8 : at + 10] = right["type"].to_bytes(2, "little")
    for symbol_index, item in seed.symbols.items():
        if item["type"] != 32 or item["aux_count"] < 1:
            continue
        auxiliary = coff_auxiliary(seed, symbol_index, item)
        line_pointer = int.from_bytes(auxiliary[8:12], "little")
        mapped = shifted(line_pointer) if line_pointer else line_pointer
        if mapped != line_pointer:
            at = new_symbol_offset + (symbol_index + 1) * 18
            output[at + 8 : at + 12] = mapped.to_bytes(4, "little")
    local_value_updates = 0
    for seed_index, donor_index in sorted(mapping.items()):
        value = donor.symbols[donor_index]["value"]
        if value != seed.symbols[seed_index]["value"]:
            local_value_updates += 1
        at = new_symbol_offset + seed_index * 18
        output[at + 8 : at + 12] = value.to_bytes(4, "little")
    donor_function_aux = coff_auxiliary(donor, donor_function_index, donor_function)
    require(
        int.from_bytes(donor_function_aux[4:8], "little") == dp["raw_size"],
        "donor Function Definition TotalSize is stale",
    )
    at = new_symbol_offset + (seed_function_index + 1) * 18
    output[at + 4 : at + 8] = dp["raw_size"].to_bytes(4, "little")
    seed_begin_index, seed_begin = _coff_marker(seed, ".bf", sp["number"])
    donor_begin_index, donor_begin = _coff_marker(donor, ".bf", dp["number"])
    seed_begin_aux = coff_auxiliary(seed, seed_begin_index, seed_begin)
    donor_begin_aux = coff_auxiliary(donor, donor_begin_index, donor_begin)
    require(
        seed_begin_aux[:4] == donor_begin_aux[:4]
        and seed_begin_aux[6:12] == donor_begin_aux[6:12]
        and (seed_begin_aux[16:] == donor_begin_aux[16:]),
        ".bf non-line metadata changed",
    )
    seed_end_index, seed_end = _coff_marker(seed, ".ef", sp["number"])
    donor_end_index, donor_end = _coff_marker(donor, ".ef", dp["number"])
    require(donor_end["value"] == dp["raw_size"], "donor .ef value is stale")
    seed_end_aux = coff_auxiliary(seed, seed_end_index, seed_end)
    donor_end_aux = coff_auxiliary(donor, donor_end_index, donor_end)
    require(
        seed_end_aux[:4] == donor_end_aux[:4] and seed_end_aux[6:] == donor_end_aux[6:],
        ".ef non-line metadata changed",
    )
    at = new_symbol_offset + seed_end_index * 18
    output[at + 8 : at + 12] = donor_end["value"].to_bytes(4, "little")
    seed_lf = [
        (index, symbol)
        for index, symbol in seed.symbols.items()
        if symbol["name"] == ".lf"
        and symbol["section"] == sp["number"]
        and (symbol["storage"] == 101)
    ]
    donor_lf = [
        (index, symbol)
        for index, symbol in donor.symbols.items()
        if symbol["name"] == ".lf"
        and symbol["section"] == dp["number"]
        and (symbol["storage"] == 101)
    ]
    require(len(seed_lf) == len(donor_lf) <= 1, "target .lf line-count markers differ in presence")
    if seed_lf:
        seed_lf_index, seed_lf_symbol = seed_lf[0]
        _, donor_lf_symbol = donor_lf[0]
        require(
            seed_lf_symbol["value"] == sp["line_count"]
            and donor_lf_symbol["value"] == dp["line_count"],
            ".lf line-count marker is stale",
        )
        at = new_symbol_offset + seed_lf_index * 18
        output[at + 8 : at + 12] = donor_lf_symbol["value"].to_bytes(4, "little")
    seed_section_index, seed_section_sym = _coff_section_symbol(seed, sp)
    donor_section_index, donor_section_sym = _coff_section_symbol(donor, dp)
    at = new_symbol_offset + (seed_section_index + 1) * 18
    output[at : at + 18] = coff_auxiliary(donor, donor_section_index, donor_section_sym)
    if reduced_debug_raw is not None:
        debug_section_index, _ = _coff_section_symbol(seed, sd)
        aux_at = new_symbol_offset + (debug_section_index + 1) * 18
        output[aux_at : aux_at + 4] = len(expected_debug_raw).to_bytes(4, "little")
    debug_output = shifted(sd["raw_offset"])
    output[debug_output : debug_output + len(expected_debug_raw)] = expected_debug_raw
    if fpo_closure:
        fpo_output = shifted(sx["raw_offset"])
        output[fpo_output : fpo_output + len(donor_fpo)] = donor_fpo
    composed = _append_undefined_external_symbols(bytes(output), imported_symbols)
    total_delta += len(composed) - len(output)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(len(composed) == len(seed_bytes) + total_delta, "output file-size delta is wrong")
    require(coff_body(checked, cp) == donor_code, "output target body differs from donor")
    cx = _comdat_child(checked, cp, ".debug$F" if fpo_closure else ".xdata$x")
    cd = _comdat_child(checked, cp, ".debug$S")
    require(
        coff_body(checked, cx) == (donor_fpo if fpo_closure else coff_body(seed, sx)),
        "output xdata/FPO record differs from its policy source",
    )
    require(coff_body(checked, cd) == bytes(expected_debug_raw), "output debug$S policy differs")
    if reduced_debug_raw is not None:
        checked_debug_index, checked_debug_symbol = _coff_section_symbol(checked, cd)
        require(
            int.from_bytes(
                coff_auxiliary(checked, checked_debug_index, checked_debug_symbol)[:4], "little"
            )
            == cd["raw_size"]
            == len(expected_debug_raw),
            "output debug$S section symbol still claims the removed locals",
        )
    require(function_multiset(checked) == function_multiset(seed), "output function set changed")
    require(
        checked.symbol_count == seed.symbol_count + len(imported_symbols)
        and all(
            (
                checked.symbols[seed.symbol_count + index]["name"] == item[0]
                and checked.symbols[seed.symbol_count + index]["section"] == 0
                and (checked.symbols[seed.symbol_count + index]["value"] == 0)
                and (checked.symbols[seed.symbol_count + index]["type"] == item[1])
                and (checked.symbols[seed.symbol_count + index]["storage"] == item[2])
                for index, item in enumerate(imported_symbols)
            )
        ),
        "output imported undefined symbol set changed",
    )
    require(
        _coff_table_bytes(checked, cp, "lines") == donor_lines,
        "output line table differs from the normalized donor",
    )
    require(
        _coff_table_bytes(checked, cx, "relocations") == _coff_table_bytes(seed, sx, "relocations"),
        "output xdata relocation records changed",
    )
    require(
        _coff_table_bytes(checked, cd, "relocations") == _coff_table_bytes(seed, sd, "relocations"),
        "output debug$S relocation records changed",
    )
    for before, after in zip(seed.sections, checked.sections):
        if before["number"] in allowed_sections:
            continue
        require(
            coff_body(seed, before) == coff_body(checked, after),
            f"non-target raw section changed: {before['number']}",
        )
        require(
            _coff_table_bytes(seed, before, "relocations")
            == _coff_table_bytes(checked, after, "relocations"),
            f"non-target relocation table changed: {before['number']}",
        )
        require(
            _coff_table_bytes(seed, before, "lines") == _coff_table_bytes(checked, after, "lines"),
            f"non-target line table changed: {before['number']}",
        )
    if divergent:
        composed_rows = detailed_relocations(checked, cp)
        require(
            len(composed_rows) == len(dpr), "composed relocation count differs from the donor's"
        )
        for left, right in zip(composed_rows, dpr):
            if local_symbol_kind(right["target"]) is not None:
                require(
                    local_symbol_kind(left["target"]) == local_symbol_kind(right["target"]),
                    f"composed local relocation class changed at offset {left['offset']}",
                )
                continue
            left_base, left_sep, left_serial = left["target"].rpartition("$S")
            right_base, right_sep, right_serial = right["target"].rpartition("$S")
            if (
                left["target"] != right["target"]
                and left_sep
                and right_sep
                and left_base
                and (left_base == right_base)
                and left_serial.isdigit()
                and right_serial.isdigit()
            ):
                continue
            require(
                left["target"] == right["target"],
                f"composed relocation target {left['target']!r} is not the donor's {right['target']!r}",
            )
    return (
        composed,
        {
            "mangled": mangled,
            "splice_class": function["splice_class"] if divergent else "same_slot_resize",
            "section_number": cp["number"],
            "seed_length": sp["raw_size"],
            "donor_length": dp["raw_size"],
            "file_size_delta": total_delta,
            "linked_span": function["expected_linked_span"],
            "mapped_locals": len(mapping),
            "changed_local_values": local_value_updates,
            "substituted_relocations": len(substitutions),
            "imported_undefined_symbols": [item[0] for item in imported_symbols],
            "candidate_only": bool(divergent),
            **(
                {"debug_representation_delta": representation_detail}
                if representation_detail
                else {}
            ),
            **local_set_detail,
            **topology_detail,
            **semantic_detail,
        },
    )


DONOR_SOURCE_CARRIER_SEATS = {
    "extern_run_pair_v1": ("after_includes_and_eof_v1", ("header", "seat")),
    "declaration_run_triple_v1": ("start_after_includes_and_eof_v1", ("pre", "post", "eof")),
}
DONOR_SOURCE_FORCE_INCLUDE_CARRIERS = {
    "force_included_shape_v1": ("force_include_v1", "generate_shape", ("classes", "functions")),
    "force_included_pad_shape_v1": (
        "force_include_v1",
        "generate_pad_shape",
        ("classes", "functions_per_class"),
    ),
}


def _donor_source_force_included_shape(kind: str, params: dict) -> bytes:
    """Render one force-included carrier's declaration-only shape."""
    _, generator_name, names = DONOR_SOURCE_FORCE_INCLUDE_CARRIERS[kind]
    generator = getattr(entropy_generator, generator_name)
    return generator(*(params[name] for name in names)).encode("ascii")


def validate_donor_source_compiler_state_carrier(value: object, context: str) -> dict:
    """Validate one closed, declaration-only multi-seat source carrier.

    Two grammars are admitted, both already part of the mosaic carrier
    vocabulary and both emitting nothing at all: the two-seat extern run
    (declarations of never-defined objects, after the include block and at
    physical EOF) and the three-seat forward-declaration run (bare class
    declarations at file start, after the include block, and at EOF).  Every
    obligation -- per-seat count bounds, identity non-collision, and the
    exact generated-declaration digest -- applies to both.
    """
    require(isinstance(value, dict), f"{context} must be an object")
    kind = value.get("kind")
    if kind in DONOR_SOURCE_FORCE_INCLUDE_CARRIERS:
        placement, _, names = DONOR_SOURCE_FORCE_INCLUDE_CARRIERS[kind]
        exact_audit_keys(
            value, {"kind", "placement", "generated_declarations_sha256", *names}, context
        )
        require(value.get("placement") == placement, f"{context} kind or placement differs")
        params = {
            name: require_exact_int(value.get(name), f"{context}.{name}", minimum=1, maximum=4096)
            for name in names
        }
        try:
            generated = _donor_source_force_included_shape(kind, params)
        except ValueError as error:
            raise ByteIdentityError(f"{context} declaration shape is invalid: {error}") from error
        require(
            require_sha(
                value.get("generated_declarations_sha256"),
                context + ".generated_declarations_sha256",
            )
            == sha256_bytes(generated),
            f"{context} generated declarations differ from their pin",
        )
        return {
            "kind": kind,
            "placement": placement,
            **params,
            "generated_declarations_sha256": sha256_bytes(generated),
        }
    require(kind in DONOR_SOURCE_CARRIER_SEATS, f"{context} kind or placement differs")
    placement, roles = DONOR_SOURCE_CARRIER_SEATS[kind]
    keys = {"kind", "placement", "width", "generated_declarations_sha256"}
    for role in roles:
        keys |= {f"{role}_prefix", f"{role}_count"}
    exact_audit_keys(value, keys, context)
    require(value.get("placement") == placement, f"{context} kind or placement differs")
    width = require_exact_int(value.get("width"), context + ".width", minimum=1, maximum=3)
    generator = (
        entropy_generator.generate_extern_run
        if kind == "extern_run_pair_v1"
        else entropy_generator.generate_forward_run
    )
    counts = {}
    payloads = []
    identities = set()
    for role in roles:
        prefix = value.get(f"{role}_prefix")
        count = require_exact_int(
            value.get(f"{role}_count"), context + f".{role}_count", minimum=1, maximum=999
        )
        require(isinstance(prefix, str), f"{context}.{role}_prefix differs")
        try:
            payload = generator(prefix, count, width).encode("ascii")
        except ValueError as error:
            raise ByteIdentityError(
                f"{context}.{role} declaration run is invalid: {error}"
            ) from error
        names = {f"{prefix}{index:0{width}d}" for index in range(count)}
        require(
            len(names) == count and (not identities.intersection(names)),
            f"{context} declaration identities collide",
        )
        identities.update(names)
        payloads.append(payload)
        counts[role] = (prefix, count)
    generated = b"".join(payloads)
    require(
        require_sha(
            value.get("generated_declarations_sha256"), context + ".generated_declarations_sha256"
        )
        == sha256_bytes(generated),
        f"{context} generated declarations differ from their pin",
    )
    normalized = {
        "kind": kind,
        "placement": placement,
        "width": width,
        "generated_declarations_sha256": sha256_bytes(generated),
    }
    for role in roles:
        normalized[f"{role}_prefix"] = counts[role][0]
        normalized[f"{role}_count"] = counts[role][1]
    return normalized


def instruction_mosaic_metadata_sha256(coff: CoffObject, primary: dict) -> str:
    """Hash the target's seed-authoritative line/debug/EH metadata closure."""
    definitions = section_definitions(coff)
    closure = _comdat_child_closure(coff, primary)
    children = []
    for name in closure[1]:
        child = _comdat_child(coff, primary, name)
        definition = definitions[child["number"]]
        children.append(
            {
                "name": name,
                "section_number": child["number"],
                "raw_size": child["raw_size"],
                "relocation_count": child["relocation_count"],
                "line_count": child["line_count"],
                "characteristics": child["characteristics"],
                "selection": definition["selection"],
                "associated": definition["associated"],
                "body_sha256": sha256_bytes(coff_body(coff, child)),
                "relocations_sha256": sha256_bytes(_coff_table_bytes(coff, child, "relocations")),
                "lines_sha256": sha256_bytes(_coff_table_bytes(coff, child, "lines")),
            }
        )
    return sha256_bytes(
        canonical_json_bytes(
            {
                "target_line_table_sha256": sha256_bytes(_coff_table_bytes(coff, primary, "lines")),
                "target_relocation_table_sha256": sha256_bytes(
                    _coff_table_bytes(coff, primary, "relocations")
                ),
                "closure": children,
            }
        )
    )


def _require_instruction_mosaic_metadata_pin(
    coff: CoffObject,
    primary: dict,
    expected_sha256: str,
    context: str,
) -> None:
    """Refuse changed mosaic metadata while exposing both diagnostic hashes."""

    actual_sha256 = instruction_mosaic_metadata_sha256(coff, primary)
    require(
        actual_sha256 == expected_sha256,
        f"{context} metadata SHA-256 pin mismatch: "
        f"expected {expected_sha256}, actual {actual_sha256}",
    )


def produce_cross_tu_complete_target_resize_candidate(
    seed_bytes: bytes, target_donor_bytes: bytes, complete_donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
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
                (
                    target_child[field] == complete_child[field]
                    for field in (
                        "name",
                        "raw_size",
                        "relocation_count",
                        "line_count",
                        "characteristics",
                    )
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
        for index, (left, right) in enumerate(zip(target_debug, complete_debug))
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
        for index, (left, right) in enumerate(zip(target_donor_bytes, normalized))
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


def _validate_instruction_mosaic_source_variant(
    seed: CoffObject,
    seed_primary: dict,
    donor_bytes: bytes,
    function: dict,
    variant: dict,
    context: str,
    reseat_windows: list[tuple[int, int]] | None = None,
) -> tuple[CoffObject, dict, bytes]:
    """Authenticate one independently compiled same-COMDAT donor variant."""
    donor = CoffObject(donor_bytes)
    primary = donor.function_section(function["mangled"])
    require(
        primary["number"] == seed_primary["number"] == function["expected_section_number"],
        f"{context} target section seat changed",
    )
    require(
        len(donor.sections) == len(seed.sections) == function["expected_section_count"],
        f"{context} global section count changed",
    )
    require(function_multiset(seed) == function_multiset(donor), f"{context} function set differs")
    require(
        comdat_primary_identity_multiset(seed) == comdat_primary_identity_multiset(donor),
        f"{context} COMDAT identity set differs",
    )
    require(
        all(
            (
                seed_primary[field] == primary[field]
                for field in ("name", "relocation_count", "characteristics")
            )
        ),
        f"{context} target section header changed",
    )
    require(
        primary["raw_size"] == variant["expected_body_length"]
        and primary["line_count"] == variant["expected_line_count"]
        and (primary["relocation_count"] == function["expected_relocation_count"]),
        f"{context} target size/table counts changed",
    )
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[seed_primary["number"]]["selection"]
        == donor_defs[primary["number"]]["selection"],
        f"{context} COMDAT selection changed",
    )
    closure = _comdat_child_closure(seed, seed_primary)
    require(
        closure == _comdat_child_closure(donor, primary)
        and closure in {(2, (".debug$F", ".debug$S")), (2, (".debug$S", ".xdata$x"))},
        f"{context} target closure changed",
    )
    for child_name in closure[1]:
        left = _comdat_child(seed, seed_primary, child_name)
        right = _comdat_child(donor, primary, child_name)
        require(
            left["number"] == right["number"]
            and all((left[field] == right[field] for field in ("name", "characteristics"))),
            f"{context} {child_name} seat/header changed",
        )
        require_same_semantic_relocations(seed, left, donor, right, f"{context} {child_name}")
    require_instruction_mosaic_semantic_relocations(
        seed, seed_primary, donor, primary, f"{context} code", reseat_windows=reseat_windows or None
    )
    body = coff_body(donor, primary)
    require(
        sha256_bytes(body) == variant["expected_body_sha256"],
        f"{context} body differs from its pin",
    )
    _require_instruction_mosaic_metadata_pin(
        donor,
        primary,
        variant["expected_metadata_sha256"],
        context,
    )
    lines = _coff_table_bytes(donor, primary, "lines")
    require(
        len(lines) >= 6
        and lines[4:6] == b"\x00\x00"
        and (
            donor.symbols.get(int.from_bytes(lines[:4], "little"), {}).get("name")
            == function["mangled"]
        ),
        f"{context} line marker changed identity",
    )
    return (donor, primary, body)


def _compose_instruction_mosaic_variant_object(
    seed_bytes: bytes,
    main_donor_bytes: bytes,
    additional_donor_bytes: dict[str, bytes],
    function: dict,
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict]:
    """Build one provenance-checked donor view from same-COMDAT variants.

    The returned object is an internal view only.  Every copied instruction
    still comes from its named fresh compiler output; no synthesized bytes or
    manifest literals enter the result.
    """
    variants = function.get("donor_variants", [])
    require(variants, "instruction mosaic has no additional donor variants")
    expected_ids = {item["donor"] for item in variants}
    require(
        set(additional_donor_bytes) == expected_ids,
        "instruction-mosaic additional donor set differs",
    )
    require(
        primary_donor_id not in expected_ids, "instruction-mosaic primary donor repeats a variant"
    )
    seed = CoffObject(seed_bytes)
    seed_primary = seed.function_section(function["mangled"])
    records = {
        primary_donor_id: {
            "expected_body_length": function["expected_donor_body_length"],
            "expected_line_count": function["expected_donor_line_count"],
            "expected_body_sha256": function["expected_donor_body_sha256"],
            "expected_metadata_sha256": function["expected_donor_metadata_sha256"],
        },
        **{item["donor"]: item for item in variants},
    }
    objects = {primary_donor_id: main_donor_bytes, **additional_donor_bytes}
    ranges = validate_instruction_mosaic_ranges(
        function["instruction_ranges"],
        "instruction mosaic ranges",
        function["expected_body_length"],
    )
    reseat_windows = [
        (item["start"], item["end"]) for item in ranges if item.get("relocation_reseat")
    ]
    parsed = {}
    for donor_id, record in records.items():
        parsed[donor_id] = _validate_instruction_mosaic_source_variant(
            seed,
            seed_primary,
            objects[donor_id],
            function,
            record,
            f"instruction-mosaic variant {donor_id}",
            reseat_windows=reseat_windows,
        )
    main = parsed[primary_donor_id]
    hybrid = bytearray(main_donor_bytes)
    used = set()
    for index, item in enumerate(ranges):
        donor_id = item.get("donor", primary_donor_id)
        require(donor_id in parsed, f"instruction-mosaic range {index} donor is not declared")
        used.add(donor_id)
        variant_coff, primary, body = parsed[donor_id]
        start, end = (item["start"], item["end"])
        require(end <= len(body), f"instruction-mosaic range {index} leaves its donor")
        require(
            sha256_bytes(body[start:end]) == item["donor_sha256"],
            f"instruction-mosaic range {index} donor provenance differs",
        )
        at = main[1]["raw_offset"] + start
        hybrid[at : at + end - start] = body[start:end]
        if item.get("relocation_reseat") and donor_id != primary_donor_id:
            for row in detailed_relocations(variant_coff, primary):
                if start <= row["offset"] and row["offset"] + row["width"] <= end:
                    record_offset = main[1]["relocation_offset"] + 10 * row["ordinal"]
                    hybrid[record_offset : record_offset + 4] = row["offset"].to_bytes(4, "little")
    require(used == set(records), "instruction-mosaic donor variant is unused")
    hybrid = bytes(hybrid)
    hybrid_coff = CoffObject(hybrid)
    hybrid_primary = hybrid_coff.function_section(function["mangled"])
    hybrid_body = coff_body(hybrid_coff, hybrid_primary)
    require(
        sha256_bytes(hybrid_body) == function["expected_mosaic_donor_body_sha256"],
        "instruction-mosaic combined donor view differs from its pin",
    )
    return (
        hybrid,
        {
            "variant_donors": sorted(records),
            "combined_donor_body_sha256": sha256_bytes(hybrid_body),
        },
    )


def _instruction_mosaic_range_donor_label(item: dict, primary_donor_id: str) -> str:
    """Name a range's donor from current typed intervention authority."""
    return item.get("donor", primary_donor_id)


def _produce_instruction_mosaic_candidate_core(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    *,
    source_permutation: bool,
    primary_donor_id: str,
) -> tuple[bytes, dict]:
    """Import pinned complete instructions into an otherwise canonical COMDAT.

    Both objects are fresh compiler outputs of the same checked-in source;
    only the manifest-declared compiler-state carrier differs.  The output is
    the seed object byte-for-byte except for authenticated, same-offset donor
    instructions.  In particular the seed relocation, line, debug and EH
    tables remain authoritative.  Declarative relocation semantics constrain
    the candidate without exposing reference bytes to the producer.
    """
    require(
        function.get("splice_class") == "retail_exact_instruction_mosaic",
        "splice class is not retail_exact_instruction_mosaic",
    )
    ordinary_fpo = "ordinary_fpo_identity" in function
    source_fpo = "source_fpo_identity" in function
    self_permutation = "instruction_self_permutation" in function
    require(
        not (ordinary_fpo and source_fpo),
        "instruction mosaic FPO identity classes are mutually exclusive",
    )
    require(
        not (source_permutation and ordinary_fpo),
        "ordinary FPO mosaic cannot cross the source-permutation branch",
    )
    require(
        not source_fpo or source_permutation,
        "source FPO mosaic requires the source-permutation branch",
    )
    require(
        not self_permutation
        or (
            not source_fpo
            and (not source_permutation)
            and ("same_function_source_identity" in function)
        ),
        "instruction self-permutation requires an isolated source-authentic mosaic class",
    )
    permuted_relocations = "relocation_order" in function
    require(
        not permuted_relocations
        or function["relocation_order"] == MOSAIC_PERMUTED_RELOCATION_ORDER,
        "instruction mosaic names an unknown relocation order",
    )
    require(
        not permuted_relocations
        or not (
            ordinary_fpo
            or source_fpo
            or self_permutation
            or source_permutation
            or ("donor_variants" in function)
        ),
        "permuted relocation order requires the plain single-donor declaration-carrier mosaic class",
    )
    expected_length = function["expected_body_length"]
    donor_expected_length = function.get("expected_donor_body_length", expected_length)
    ranges = validate_instruction_mosaic_ranges(
        function.get("instruction_ranges"), "instruction mosaic ranges", expected_length
    )
    variant_ids = {item["donor"] for item in function.get("donor_variants", [])}
    require(
        primary_donor_id not in variant_ids, "instruction-mosaic primary donor repeats a variant"
    )
    declared_donor_ids = {primary_donor_id, *variant_ids}
    require(
        all((item.get("donor", primary_donor_id) in declared_donor_ids for item in ranges)),
        "instruction-mosaic range names an undeclared donor",
    )
    reseat_windows = [
        (item["start"], item["end"]) for item in ranges if item.get("relocation_reseat")
    ]
    reseated = bool(reseat_windows)
    require(
        not reseated
        or not (source_fpo or self_permutation or source_permutation or permuted_relocations),
        "relocation reseat requires the plain or ordinary-FPO declaration-carrier mosaic class",
    )
    require(
        reseated == ("expected_output_relocation_sha256" in function),
        "relocation reseat requires exactly its output relocation table pin",
    )
    require(
        (reseated and ordinary_fpo) == ("expected_output_metadata_sha256" in function),
        "ordinary FPO relocation reseat requires exactly its output metadata pin",
    )
    permutation = None
    if ordinary_fpo or source_fpo or self_permutation:
        require(
            all(
                (
                    item["kind"] == "same_offset_complete_x86_instruction_sequence_v1"
                    for item in ranges
                )
            ),
            "FPO and self-permutation instruction mosaics require exact sequence partitions",
        )
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        "instruction-mosaic target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "instruction-mosaic global section count changed",
    )
    require(
        function_multiset(seed) == function_multiset(donor),
        "instruction-mosaic donor function set differs",
    )
    require(
        comdat_primary_identity_multiset(seed) == comdat_primary_identity_multiset(donor),
        "instruction-mosaic donor COMDAT identity set differs",
    )
    common_header_fields = ("name", "relocation_count", "characteristics")
    require(
        all((sp[field] == dp[field] for field in common_header_fields)),
        "instruction-mosaic target section header changed",
    )
    if not source_permutation:
        require(
            all((sp[field] == dp[field] for field in ("raw_size", "line_count"))),
            "instruction-mosaic target size/line header changed",
        )
    require(
        sp["raw_size"] == expected_length
        and dp["raw_size"] == donor_expected_length
        and (sp["relocation_count"] == function["expected_relocation_count"])
        and (sp["line_count"] == function["expected_line_count"]),
        "instruction-mosaic target size/table counts changed",
    )
    if source_permutation:
        require(
            dp["line_count"] == function["expected_donor_line_count"],
            "instruction-mosaic donor line count changed",
        )
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[sp["number"]]["selection"] == donor_defs[dp["number"]]["selection"],
        "instruction-mosaic COMDAT selection changed",
    )
    closure = _comdat_child_closure(seed, sp)
    require(
        closure == _comdat_child_closure(donor, dp), "instruction-mosaic target closure changed"
    )
    if ordinary_fpo:
        require(
            closure == (2, (".debug$F", ".debug$S")),
            "ordinary FPO instruction-mosaic closure class differs",
        )
        require_ordinary_fpo_mosaic_identity(
            seed,
            sp,
            donor,
            dp,
            function,
            function["ordinary_fpo_identity"],
            "ordinary FPO instruction mosaic",
        )
        if self_permutation:
            require_ordinary_fpo_self_permutation_receipts(
                seed, donor, function, "ordinary FPO instruction self-permutation"
            )
    elif source_fpo:
        require(
            closure == (2, (".debug$F", ".debug$S")),
            "source FPO instruction-mosaic closure class differs",
        )
        require_source_fpo_mosaic_identity(
            seed,
            sp,
            donor,
            dp,
            function,
            function["source_fpo_identity"],
            "source FPO instruction mosaic",
        )
    else:
        allowed_closures = {(2, EH_CLOSURE_CHILDREN)}
        if source_permutation:
            allowed_closures.add((2, ORDINARY_FPO_CLOSURE_CHILDREN))
        require(closure in allowed_closures, "instruction-mosaic target closure class differs")
        if self_permutation:
            require(
                closure == (2, EH_CLOSURE_CHILDREN),
                "EH-closure instruction self-permutation closure class differs",
            )
            require_self_permutation_receipts(
                seed,
                donor,
                function,
                EH_CLOSURE_CHILDREN,
                "EH-closure instruction self-permutation",
            )
    closure_pairs = []
    closure_relocation_renames = {}
    for child_name in closure[1]:
        left = _comdat_child(seed, sp, child_name)
        right = _comdat_child(donor, dp, child_name)
        require(left["number"] == right["number"], f"instruction-mosaic {child_name} seat changed")
        require(
            all((left[field] == right[field] for field in ("name", "characteristics"))),
            f"instruction-mosaic {child_name} header changed",
        )
        closure_relocation_renames[child_name] = require_same_semantic_relocations(
            seed, left, donor, right, f"instruction-mosaic {child_name}"
        )
        left_body = coff_body(seed, left)
        right_body = coff_body(donor, right)
        if source_permutation or ordinary_fpo:
            pass
        elif child_name == ".xdata$x":
            require(left_body == right_body, "instruction-mosaic EH xdata raw bytes changed")
        else:
            require(
                len(left_body) >= 28
                and left_body[:28] == right_body[:28]
                and (left_body[2:4] == b"\x05\x02"),
                "instruction-mosaic debug procedure identity changed",
            )
        closure_pairs.append((left, right))
    if source_permutation or ordinary_fpo or self_permutation:
        _require_instruction_mosaic_metadata_pin(
            seed,
            sp,
            function["expected_seed_metadata_sha256"],
            "instruction-mosaic seed",
        )
        _require_instruction_mosaic_metadata_pin(
            donor,
            dp,
            function["expected_donor_metadata_sha256"],
            "instruction-mosaic donor",
        )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"],
        "instruction-mosaic seed body differs from its pin",
    )
    require(
        sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "instruction-mosaic donor body differs from its pin",
    )
    if self_permutation:
        permutation = validate_instruction_self_permutation(
            function["instruction_self_permutation"], "instruction self-permutation", donor_body
        )
        require(
            all(
                (
                    item["end"] <= permutation["target_start"]
                    or item["start"] >= permutation["target_end"]
                    for item in ranges
                )
            ),
            "instruction mosaic same-offset ranges overlap the self-permutation window",
        )
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    require(
        len(seed_rows) == len(donor_rows) == function["expected_relocation_count"],
        "instruction-mosaic relocation count changed",
    )
    seed_lines = _coff_table_bytes(seed, sp, "lines")
    donor_lines = _coff_table_bytes(donor, dp, "lines")
    require(
        len(seed_lines) >= 6 and len(donor_lines) >= 6,
        "instruction-mosaic function line table is missing",
    )
    if not source_permutation:
        require(
            len(seed_lines) == len(donor_lines) and seed_lines[4:] == donor_lines[4:],
            "instruction-mosaic function line table changed",
        )
    for role, coff, line_bytes in (("seed", seed, seed_lines), ("donor", donor, donor_lines)):
        symbol_index = int.from_bytes(line_bytes[:4], "little")
        function_index, _ = function_symbol(
            coff, mangled, sp["number"] if role == "seed" else dp["number"]
        )
        require(
            line_bytes[4:6] == b"\x00\x00" and symbol_index == function_index,
            f"instruction-mosaic {role} line marker changed identity",
        )
    if self_permutation:
        window = (permutation["target_start"], permutation["target_end"])
        for role, coff, section, line_bytes in (
            ("seed", seed, sp, seed_lines),
            ("donor", donor, dp, donor_lines),
        ):
            for index in range(1, section["line_count"]):
                offset, line = coff_unpack(
                    "<IH",
                    line_bytes,
                    index * 6,
                    f"instruction self-permutation {role} line row {index}",
                )
                require(
                    line != 0 and (not window[0] < offset < window[1]),
                    f"instruction self-permutation crosses a {role} compiler line boundary",
                )
    if ordinary_fpo or source_fpo or self_permutation:
        require_coff_line_certified_ia32_boundaries(
            seed, sp, seed_body, ranges, "seed", mangled, "instruction-mosaic seed"
        )
        require_coff_line_certified_ia32_boundaries(
            donor, dp, donor_body, ranges, "donor", mangled, "instruction-mosaic donor"
        )
    code_relocation_renames = require_instruction_mosaic_semantic_relocations(
        seed,
        sp,
        donor,
        dp,
        "instruction-mosaic code",
        permuted_ranges=[(item["start"], item["end"]) for item in ranges]
        if permuted_relocations
        else None,
        reseat_windows=reseat_windows if reseated else None,
    )
    mosaic = bytearray(seed_body)
    range_detail = []
    output_rows = [dict(row) for row in seed_rows]
    reseat_detail = []
    for index, item in enumerate(ranges):
        start, end = (item["start"], item["end"])
        require(end <= len(donor_body), f"instruction-mosaic donor instruction {index} is absent")
        seed_instruction = seed_body[start:end]
        donor_instruction = donor_body[start:end]
        require(
            sha256_bytes(seed_instruction) == item["seed_sha256"],
            f"instruction-mosaic seed instruction {index} drifted",
        )
        require(
            sha256_bytes(donor_instruction) == item["donor_sha256"],
            f"instruction-mosaic donor instruction {index} drifted",
        )
        contained = []
        for role, rows, body in (("seed", seed_rows, seed_body), ("donor", donor_rows, donor_body)):
            ordinals = []
            for ordinal, row in enumerate(rows):
                operand_start = row["offset"]
                operand_end = operand_start + row["width"]
                if end <= operand_start or start >= operand_end:
                    continue
                require(
                    start <= operand_start and operand_end <= end,
                    f"instruction-mosaic range {index} partially overlaps a {role} relocation operand",
                )
                ordinals.append(ordinal)
            contained.append(ordinals)
        if permuted_relocations:
            require(
                len(contained[0]) == len(contained[1]),
                f"instruction-mosaic range {index} contains unpaired relocation operands",
            )
            pairs = list(
                zip(
                    sorted(contained[0], key=lambda o: seed_rows[o]["offset"]),
                    sorted(contained[1], key=lambda o: donor_rows[o]["offset"]),
                )
            )
        else:
            require(
                contained[0] == contained[1],
                f"instruction-mosaic range {index} contains unpaired relocation operands",
            )
            pairs = [(ordinal, ordinal) for ordinal in contained[0]]
        if source_fpo:
            require(
                not contained[0],
                f"source FPO instruction-mosaic range {index} overlaps a relocation operand",
            )
        reseat = bool(item.get("relocation_reseat"))
        if reseat:
            require(
                [seed_rows[o]["offset"] for o in contained[0]] == item["seed_relocation_offsets"]
                and [donor_rows[o]["offset"] for o in contained[1]]
                == item["donor_relocation_offsets"],
                f"instruction-mosaic range {index} relocation operands differ from the declared reseat",
            )
        for seed_ordinal, donor_ordinal in pairs:
            left, right = (seed_rows[seed_ordinal], donor_rows[donor_ordinal])
            strict_fields = (
                "offset",
                "width",
                "type",
                "addend",
                "target",
                "target_section",
                "target_value",
                "target_type",
                "target_storage",
            )
            if reseat:
                strict_fields = strict_fields[1:]
                if (
                    left["target_storage"] in (3, 6)
                    and right["target_storage"] in (3, 6)
                    and left["target"].startswith("$")
                    and right["target"].startswith("$")
                    and (
                        left["target"].rstrip("0123456789") == right["target"].rstrip("0123456789")
                    )
                ):
                    strict_fields = tuple((field for field in strict_fields if field != "target"))
            require(
                all((left[field] == right[field] for field in strict_fields)),
                f"instruction-mosaic range {index} contains a changed relocation",
            )
            if reseat:
                output_rows[seed_ordinal]["offset"] = right["offset"]
                reseat_detail.append(
                    {
                        "range": index,
                        "ordinal": seed_ordinal,
                        "seed_offset": left["offset"],
                        "output_offset": right["offset"],
                        "target": left["target"],
                    }
                )
                continue
            operand_start, width = (left["offset"], left["width"])
            require(
                seed_body[operand_start : operand_start + width]
                == donor_body[operand_start : operand_start + width],
                f"instruction-mosaic range {index} relocation operand bytes differ",
            )
        mosaic[start:end] = donor_instruction
        range_detail.append(
            {
                "start": start,
                "end": end,
                "donor": _instruction_mosaic_range_donor_label(item, primary_donor_id),
                "seed_sha256": item["seed_sha256"],
                "donor_sha256": item["donor_sha256"],
            }
        )
    permutation_detail = []
    if self_permutation:
        source_start = permutation["source_start"]
        source_end = permutation["source_end"]
        target_start = permutation["target_start"]
        target_end = permutation["target_end"]
        for role, rows, start, end in (
            ("seed target", seed_rows, target_start, target_end),
            ("donor source", donor_rows, source_start, source_end),
        ):
            require(
                all(
                    (end <= row["offset"] or start >= row["offset"] + row["width"] for row in rows)
                ),
                f"instruction self-permutation intersects a {role} relocation operand",
            )
        for index, move in enumerate(permutation["moves"]):
            donor_instruction = donor_body[move["donor_start"] : move["donor_end"]]
            require(
                sha256_bytes(donor_instruction) == move["donor_sha256"],
                f"instruction self-permutation donor instruction {index} drifted",
            )
            require(
                sha256_bytes(donor_instruction) == move["target_sha256"],
                f"instruction self-permutation target instruction {index} differs from its donor",
            )
            mosaic[move["target_start"] : move["target_end"]] = donor_instruction
            permutation_detail.append(
                {
                    "target_start": move["target_start"],
                    "target_end": move["target_end"],
                    "donor_start": move["donor_start"],
                    "donor_end": move["donor_end"],
                    "sha256": move["donor_sha256"],
                }
            )
    mosaic = bytes(mosaic)
    if self_permutation:
        source_certificate = [
            {
                "start": permutation["source_start"],
                "end": permutation["source_end"],
                "donor_instruction_lengths": permutation["source_instruction_lengths"],
            }
        ]
        target_certificate = [
            {
                "start": permutation["target_start"],
                "end": permutation["target_end"],
                "seed_instruction_lengths": permutation["target_instruction_lengths"],
            }
        ]
        require_coff_line_certified_ia32_boundaries(
            donor,
            dp,
            donor_body,
            source_certificate,
            "donor",
            mangled,
            "FPO self-permutation donor source",
        )
        require_coff_line_certified_ia32_boundaries(
            seed,
            sp,
            mosaic,
            target_certificate,
            "seed",
            mangled,
            "FPO self-permutation target output",
        )
    require(
        sha256_bytes(mosaic) == function["expected_body_sha256"],
        "instruction-mosaic final body differs from its pin",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == expected_length, "instruction-mosaic linked length changed")
    if reseated:
        require(reseat_detail, "relocation reseat ranges reseat no relocation")
        require(
            all(
                (
                    a["offset"] + a["width"] <= b["offset"]
                    for a, b in zip(output_rows, output_rows[1:])
                )
            ),
            "reseated relocation table is not in ascending operand order",
        )
    semantic_detail = require_declared_relocation_semantics(
        output_rows,
        function["retail_relocations"],
        "instruction-mosaic candidate relocation semantics",
    )
    replacements = [
        (
            sp["raw_offset"] + item["start"],
            sp["raw_offset"] + item["end"],
            donor_body[item["start"] : item["end"]],
        )
        for item in ranges
    ]
    if self_permutation:
        replacements.extend(
            (
                (
                    sp["raw_offset"] + item["target_start"],
                    sp["raw_offset"] + item["target_end"],
                    donor_body[item["donor_start"] : item["donor_end"]],
                )
                for item in permutation["moves"]
            )
        )
        replacements.sort(key=lambda item: item[0])
    reseat_file_offsets = set()
    for entry in reseat_detail:
        record_offset = sp["relocation_offset"] + 10 * entry["ordinal"]
        replacements.append(
            (record_offset, record_offset + 4, entry["output_offset"].to_bytes(4, "little"))
        )
        reseat_file_offsets.update(range(record_offset, record_offset + 4))
    replacements.sort(key=lambda item: item[0])
    output = _apply_replacements(seed_bytes, replacements)
    require(len(output) == len(seed_bytes), "instruction-mosaic object size changed")
    changed_file_offsets = {
        index for index, (before, after) in enumerate(zip(seed_bytes, output)) if before != after
    }
    allowed_file_offsets = {
        sp["raw_offset"] + offset for item in ranges for offset in range(item["start"], item["end"])
    }
    if self_permutation:
        allowed_file_offsets.update(
            (
                sp["raw_offset"] + offset
                for item in permutation["moves"]
                for offset in range(item["target_start"], item["target_end"])
            )
        )
    allowed_file_offsets |= reseat_file_offsets
    require(
        changed_file_offsets and changed_file_offsets <= allowed_file_offsets,
        "instruction mosaic changed a non-target byte",
    )
    if self_permutation:
        changed_body_offsets = sorted(
            (offset - sp["raw_offset"] for offset in changed_file_offsets)
        )
        require(
            changed_body_offsets == permutation["expected_changed_offsets"],
            "instruction self-permutation changed-offset set differs",
        )
    checked = CoffObject(output)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == mosaic, "instruction-mosaic output body differs")
    require(
        detailed_relocations(checked, cp) == output_rows,
        "instruction-mosaic seed relocations changed",
    )
    if reseated:
        require(
            sha256_bytes(_coff_table_bytes(checked, cp, "relocations"))
            == function["expected_output_relocation_sha256"],
            "instruction-mosaic reseated relocation table differs from its pin",
        )
    else:
        require(
            _coff_table_bytes(checked, cp, "relocations")
            == _coff_table_bytes(seed, sp, "relocations"),
            "instruction-mosaic seed relocation table changed",
        )
    require(
        _coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines"),
        "instruction-mosaic seed line table changed",
    )
    if ordinary_fpo or source_fpo or self_permutation:
        require(
            instruction_mosaic_metadata_sha256(checked, cp)
            == function[
                "expected_output_metadata_sha256" if reseated else "expected_seed_metadata_sha256"
            ],
            "instruction-mosaic output metadata changed",
        )
    require(
        function_multiset(checked) == function_multiset(seed),
        "instruction-mosaic output function set changed",
    )
    for left, _ in closure_pairs:
        child = _comdat_child(checked, cp, left["name"])
        require(
            coff_body(checked, child) == coff_body(seed, left)
            and _coff_table_bytes(checked, child, "relocations")
            == _coff_table_bytes(seed, left, "relocations")
            and (
                _coff_table_bytes(checked, child, "lines") == _coff_table_bytes(seed, left, "lines")
            ),
            f"instruction-mosaic seed {left['name']} changed",
        )
    return (
        output,
        {
            "mangled": mangled,
            "splice_class": "retail_exact_instruction_mosaic",
            "section_number": cp["number"],
            "body_length": cp["raw_size"],
            "instruction_ranges": range_detail,
            "instruction_self_permutation": permutation_detail,
            "body_changed_offsets": sorted(
                (offset - sp["raw_offset"] for offset in changed_file_offsets - reseat_file_offsets)
            ),
            "relocations": len(seed_rows),
            "relocation_reseats": reseat_detail,
            "line_count": cp["line_count"],
            "closure": list(closure[1]),
            "ordinary_fpo_identity": ordinary_fpo,
            "source_fpo_identity": source_fpo,
            "code_relocation_renames": code_relocation_renames,
            "closure_relocation_renames": closure_relocation_renames,
            "relocation_order": MOSAIC_PERMUTED_RELOCATION_ORDER
            if permuted_relocations
            else "ordinal",
            "candidate_only": True,
            **semantic_detail,
        },
    )


def produce_instruction_mosaic_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    additional_donor_bytes: dict[str, bytes] | None = None,
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict]:
    """Compose a declaration-carrier instruction mosaic.

    With ``donor_variants`` the mosaic may draw its same-offset complete
    instructions from several freshly compiled declaration-carrier states of
    the same translation unit.  Every variant is authenticated against the
    seed exactly like the main donor (seat, section census, function and
    COMDAT identity sets, relocation semantics, closure, pinned body and
    metadata) before its instructions enter the combined donor view, and the
    combined view is then handed to the unchanged single-donor composer.
    """
    require_payload_free_declaration(function, "instruction-mosaic declaration")
    require(
        "target_source_refactor" not in function,
        "source-permutation mosaic requires its source-proof composer",
    )
    variant_detail = {}
    effective_donor = donor_bytes
    effective_function = function
    if function.get("donor_variants"):
        seed = CoffObject(seed_bytes)
        _require_instruction_mosaic_metadata_pin(
            seed,
            seed.function_section(function["mangled"]),
            function["expected_seed_metadata_sha256"],
            "instruction-mosaic seed",
        )
        effective_donor, variant_detail = _compose_instruction_mosaic_variant_object(
            seed_bytes,
            donor_bytes,
            additional_donor_bytes or {},
            function,
            primary_donor_id=primary_donor_id,
        )
        effective_function = dict(function)
        effective_function["expected_donor_body_sha256"] = function[
            "expected_mosaic_donor_body_sha256"
        ]
        if "instruction_self_permutation" in function:
            window = function["instruction_self_permutation"]
            start, end = (window["target_start"], window["target_end"])
            main = CoffObject(donor_bytes)
            combined = CoffObject(effective_donor)
            main_body = coff_body(main, main.function_section(function["mangled"]))
            combined_body = coff_body(combined, combined.function_section(function["mangled"]))
            require(
                len(main_body) == len(combined_body)
                and main_body[start:end] == combined_body[start:end],
                "instruction self-permutation window is not the source-authentic main donor's own output",
            )
    else:
        require(not additional_donor_bytes, "instruction mosaic names undeclared donor variants")
    composed, detail = _produce_instruction_mosaic_candidate_core(
        seed_bytes,
        effective_donor,
        effective_function,
        source_permutation=False,
        primary_donor_id=primary_donor_id,
    )
    return (composed, {**detail, **variant_detail})


def produce_source_instruction_mosaic_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    seed_source: bytes,
    donor_source: bytes,
    additional_donor_bytes: dict[str, bytes] | None = None,
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict]:
    """Compose a mosaic from one authenticated source permutation."""
    require_payload_free_declaration(function, "source instruction-mosaic declaration")
    require(
        function.get("splice_class") == "retail_exact_instruction_mosaic"
        and "target_source_refactor" in function,
        "source-permutation mosaic contract is missing",
    )
    owner = function["target_source_refactor"].get("source_owner_mangled")
    if owner is not None:
        CoffObject(seed_bytes).function_section(owner)
        CoffObject(donor_bytes).function_section(owner)
    source_detail = require_target_source_refactor_identity(
        seed_source,
        donor_source,
        function["target_source_refactor"],
        "retail-exact instruction-mosaic source proof",
    )
    variant_detail = {}
    effective_donor = donor_bytes
    effective_function = function
    if function.get("donor_variants"):
        effective_donor, variant_detail = _compose_instruction_mosaic_variant_object(
            seed_bytes,
            donor_bytes,
            additional_donor_bytes or {},
            function,
            primary_donor_id=primary_donor_id,
        )
        effective_function = dict(function)
        effective_function["expected_donor_body_sha256"] = function[
            "expected_mosaic_donor_body_sha256"
        ]
    composed, detail = _produce_instruction_mosaic_candidate_core(
        seed_bytes,
        effective_donor,
        effective_function,
        source_permutation=True,
        primary_donor_id=primary_donor_id,
    )
    return (composed, {**detail, **source_detail, **variant_detail})


def _produce_instruction_hybrid_resize_candidate_core(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    instruction_donor_bytes: bytes,
    function: dict,
    *,
    source_aware: bool,
    same_tu_source_identical: bool = False,
) -> tuple[bytes, dict]:
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
            (
                target_primary[field] == instruction_primary[field]
                for field in ("name", "characteristics")
            )
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
                (
                    value == expected_closure
                    for value in (
                        _comdat_child_closure(seed, seed_primary),
                        _comdat_child_closure(target, target_primary),
                        _comdat_child_closure(instruction_donor, instruction_primary),
                    )
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
                all(
                    (end <= row["offset"] or start >= row["offset"] + row["width"] for row in rows)
                ),
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
    changed_file_offsets = {
        offset
        for offset, (before, after) in enumerate(zip(target_donor_bytes, hybrid))
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


def produce_cross_tu_instruction_hybrid_resize_candidate(
    seed_bytes: bytes, target_donor_bytes: bytes, instruction_donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
    """Compose the existing clean-current-source cross-TU hybrid class."""
    require_payload_free_declaration(function, "cross-TU instruction-hybrid declaration")
    require(
        "instruction_donor_source_refactor" not in function,
        "clean cross-TU hybrid may not carry a source-refactor proof",
    )
    return _produce_instruction_hybrid_resize_candidate_core(
        seed_bytes, target_donor_bytes, instruction_donor_bytes, function, source_aware=False
    )


def produce_source_instruction_hybrid_resize_candidate(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    instruction_donor_bytes: bytes,
    function: dict,
    seed_source: bytes,
    instruction_donor_source: bytes,
) -> tuple[bytes, dict]:
    """Authenticate one source permutation before importing instructions."""
    require_payload_free_declaration(function, "source instruction-hybrid declaration")
    require(
        function.get("splice_class") == SOURCE_INSTRUCTION_HYBRID_RESIZE_CLASS
        and "instruction_donor_source_refactor" in function,
        "source instruction-hybrid contract is missing",
    )
    proof = function["instruction_donor_source_refactor"]
    require(
        proof.get("source_owner_mangled") == function.get("mangled"),
        "source instruction-hybrid owner differs",
    )
    owner = proof["source_owner_mangled"]
    CoffObject(target_donor_bytes).function_section(owner)
    CoffObject(instruction_donor_bytes).function_section(owner)
    source_detail = require_target_source_refactor_identity(
        seed_source, instruction_donor_source, proof, "source instruction-hybrid source proof"
    )
    composed, detail = _produce_instruction_hybrid_resize_candidate_core(
        seed_bytes, target_donor_bytes, instruction_donor_bytes, function, source_aware=True
    )
    return (composed, {**detail, **source_detail})


def produce_same_tu_instruction_hybrid_resize_candidate(
    seed_bytes: bytes,
    target_donor_bytes: bytes,
    instruction_donor_bytes: bytes,
    function: dict,
    seed_source: bytes,
    target_donor_source: bytes,
    instruction_donor_source: bytes,
) -> tuple[bytes, dict]:
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


def produce_reloc_divergent_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
    """Splice a donor body whose EXTERNAL relocation target set diverges.

    Every `same_slot_resize` check applies except relocation-target equality.
    In its place stands a closed declarative relocation contract.  The final
    image still has to pass the sealed literal verifier before byte identity
    can be claimed.
    """
    require_payload_free_declaration(function, "relocation-divergent declaration")
    require(
        function.get("splice_class") == "retail_exact_reloc_divergent",
        "splice class is not retail_exact_reloc_divergent",
    )
    require(
        "target_source_refactor" not in function,
        "source-refactor function requires its source-proof composer",
    )
    return compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
        declared_seed_only=function.get("expected_seed_only_functions") or None,
    )


def produce_source_refactor_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict, seed_source: bytes, donor_source: bytes
) -> tuple[bytes, dict]:
    """Install one relocation-divergent body from a proved source refactor.

    The source proof is deliberately inseparable from this entry point.  The
    ordinary relocation-divergent producer continues to reject these
    declarations, while this wrapper authenticates the complete source
    permutation before delegating to the same candidate-only COFF composer.
    """
    require_payload_free_declaration(function, "source-refactor declaration")
    require(
        function.get("splice_class") == "retail_exact_reloc_divergent"
        and "target_source_refactor" in function,
        "retail-exact source-refactor contract is missing",
    )
    source_detail = require_target_source_refactor_identity(
        seed_source,
        donor_source,
        function["target_source_refactor"],
        "retail-exact source-refactor proof",
    )
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
        declared_seed_only=function.get("expected_seed_only_functions") or None,
    )
    return (composed, {**detail, **source_detail})


def produce_source_target_closure_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    seed_source: bytes,
    donor_source: bytes,
) -> tuple[bytes, dict]:
    """Extract one compiler-produced target from a source-closed donor.

    The producer receives no reference-image body.  The donor body is pinned
    as a fresh compiler product, the source window is proved byte-identical,
    and the source-target COFF topology contract accounts for every omitted
    or imported contribution.  Literal image equality remains solely the
    sealed verifier's responsibility.
    """
    require_payload_free_declaration(function, "source-target closure declaration")
    require(
        function.get("splice_class") == "retail_exact_source_target_closure",
        "splice class is not retail_exact_source_target_closure",
    )
    require(
        isinstance(function.get("target_source_range"), dict),
        "source-target closure source proof is missing",
    )
    source_detail = require_target_source_range_identity(
        seed_source,
        donor_source,
        function["target_source_range"],
        "source-target closure source proof",
    )
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        source_target_extract=True,
    )
    return composed, {**detail, **source_detail}


def compose_swap_comdat_group_order(seed_bytes: bytes, specification: dict) -> tuple[bytes, dict]:
    """Swap the link-visible order of two complete compiler-produced COMDAT
    groups (primary + associated children) inside one object, renumbering
    section ordinals and associations only.

    No raw code, relocation, xdata, data, line, or debug payload byte moves;
    every symbol keeps its exact raw contribution.  The permutation makes
    the `first` function's group precede the `second` function's group; the
    intervening contributions keep their relative order.
    """
    require_payload_free_declaration(specification, "COMDAT group-order declaration")
    seed = CoffObject(seed_bytes)
    first = seed.function_section(specification["first"])
    second = seed.function_section(specification["second"])
    definitions = section_definitions(seed)

    def group(primary: dict) -> list[int]:
        children = [
            section["number"]
            for section in seed.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"] == primary["number"]
        ]
        return [primary["number"], *children]

    first_group = group(first)
    second_group = group(second)
    require(not set(first_group) & set(second_group), "COMDAT groups overlap")
    require(second["number"] < first["number"], "the requested group order already holds")
    window = sorted(set(first_group) | set(second_group))
    low, high = (min(window), max(max(first_group), max(second_group)))
    window_numbers = list(range(low, high + 1))
    rest = [
        number
        for number in window_numbers
        if number not in first_group and number not in second_group
    ]
    new_order = first_group + second_group + rest
    require(sorted(new_order) == window_numbers, "group window is not a permutation")
    old_to_new = {old: window_numbers[index] for index, old in enumerate(new_order)}

    def mapped(number: int) -> int:
        return old_to_new.get(number, number)

    work = bytearray(seed_bytes)
    original_headers = {
        number: seed_bytes[20 + (number - 1) * 40 : 20 + number * 40] for number in window_numbers
    }
    for old, new in old_to_new.items():
        start = 20 + (new - 1) * 40
        work[start : start + 40] = original_headers[old]
    symbol_writes = 0
    association_writes = 0
    for index, symbol in seed.symbols.items():
        if symbol["section"] > 0 and mapped(symbol["section"]) != symbol["section"]:
            offset = seed.symbol_offset + index * 18 + 12
            work[offset : offset + 2] = mapped(symbol["section"]).to_bytes(2, "little", signed=True)
            symbol_writes += 1
        definition = definitions.get(symbol["section"])
        if (
            definition is not None
            and symbol["storage"] == 3
            and symbol["aux_count"]
            and (symbol["name"] == seed.sections[symbol["section"] - 1]["name"])
            and (definition["selection"] == 5)
            and (mapped(definition["associated"]) != definition["associated"])
        ):
            aux = seed.symbol_offset + (index + 1) * 18
            parent = mapped(definition["associated"])
            work[aux + 12 : aux + 14] = (parent & 65535).to_bytes(2, "little")
            work[aux + 16 : aux + 18] = (parent >> 16).to_bytes(2, "little")
            association_writes += 1
    composed = bytes(work)
    require(len(composed) == len(seed_bytes), "object size changed")
    checked = CoffObject(composed)
    checked_definitions = section_definitions(checked)
    section_fields = (
        "name",
        "raw_size",
        "raw_offset",
        "relocation_offset",
        "relocation_count",
        "line_offset",
        "line_count",
        "characteristics",
    )
    for section in seed.sections:
        peer = checked.sections[mapped(section["number"]) - 1]
        require(
            all((section[field] == peer[field] for field in section_fields)),
            f"semantic section changed: old {section['number']}",
        )
    require(seed.symbols.keys() == checked.symbols.keys(), "symbol index set changed")
    for index, symbol in seed.symbols.items():
        peer = checked.symbols[index]
        require(
            all(
                (
                    symbol[field] == peer[field]
                    for field in ("name", "value", "type", "storage", "aux_count")
                )
            )
            and peer["section"] == mapped(symbol["section"]),
            f"symbol identity changed at {index}",
        )
    for old_number, definition in definitions.items():
        peer = checked_definitions.get(mapped(old_number))
        require(
            peer is not None
            and peer["selection"] == definition["selection"]
            and (peer["associated"] == mapped(definition["associated"])),
            f"section definition mapping changed: {old_number}",
        )
    checked_first = checked.function_section(specification["first"])
    checked_second = checked.function_section(specification["second"])
    require(
        checked_first["number"] < checked_second["number"], "target group order was not swapped"
    )
    for name in sorted(
        {section["name"] for section in seed.sections if not section["name"].startswith(".debug$")}
    ):
        before = [section["raw_offset"] for section in seed.sections if section["name"] == name]
        after = [section["raw_offset"] for section in checked.sections if section["name"] == name]
        if name == first["name"]:
            expected = list(before)
            left = expected.index(first["raw_offset"])
            right = expected.index(second["raw_offset"])
            require(left > right, "target contributions were already ordered")
            expected[left], expected[right] = (expected[right], expected[left])
            require(after == expected, "more than the target contribution pair moved")
        else:
            require(after == before, f"link-visible {name} contribution order changed")
    return (
        composed,
        {
            "first": specification["first"],
            "second": specification["second"],
            "window": [low, high],
            "symbol_section_writes": symbol_writes,
            "association_writes": association_writes,
        },
    )


def compose_restore_comdat_group_order(
    seed_bytes: bytes, specification: dict
) -> tuple[bytes, dict]:
    """Restore the link-visible order of several complete compiler-produced
    `.text` COMDAT groups (primary + associated children) inside one object.

    This is the list form of :func:`compose_swap_comdat_group_order`: the
    ``group_order`` list names `.text` COMDAT primaries in the desired
    (retail-anchored) first-to-last order.  The permutation window is the
    contiguous section-number range spanned by the listed groups.  Every
    `.text` COMDAT group inside that window must be listed (fail-closed), so
    the transform is a pure whole-group permutation of text contributions.
    Sections of any other kind that sit inside the window (string literals,
    data, vftables and their children) keep their own relative order and are
    reseated after the listed groups, so no other link-visible contribution
    order changes.  Only section ordinals and associations are renumbered;
    no raw code, relocation, xdata, data, line, or debug payload byte moves
    and every symbol keeps its exact raw contribution.
    """
    require_payload_free_declaration(specification, "COMDAT group-order declaration")
    order = specification["group_order"]
    require(
        isinstance(order, list) and 2 <= len(order) <= 512 and (len(set(order)) == len(order)),
        "group_order must be a list of 2..512 distinct names",
    )
    require(
        all((isinstance(name, str) and name for name in order)),
        "group_order names must be non-empty strings",
    )
    seed = CoffObject(seed_bytes)
    definitions = section_definitions(seed)

    def group(primary: dict) -> list[int]:
        children = [
            section["number"]
            for section in seed.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"] == primary["number"]
        ]
        return [primary["number"], *children]

    groups = []
    listed = set()
    kinds = set()
    for name in order:
        primary = comdat_primary_section(seed, name)
        members = group(primary)
        require(not set(members) & listed, f"COMDAT groups overlap: {name}")
        listed.update(members)
        kinds.add(primary["name"].split("$")[0])
        groups.append((name, primary, members))
    require(len(kinds) == 1, "group_order must name COMDATs of one section kind")
    kind = next(iter(kinds))
    low = min((min(members) for _, _, members in groups))
    high = max((max(members) for _, _, members in groups))
    window_numbers = list(range(low, high + 1))
    unlisted = [number for number in window_numbers if number not in listed]
    for number in unlisted:
        section = seed.sections[number - 1]
        require(
            section["name"].split("$")[0] != kind,
            f"unlisted {kind} contribution inside the window: section {number}",
        )
        definition = definitions.get(number)
        if definition is not None and definition.get("selection") == 5:
            require(
                definition["associated"] not in listed,
                f"orphaned associated section inside the window: section {number}",
            )
    new_order = [number for _, _, members in groups for number in members]
    new_order += unlisted
    require(sorted(new_order) == window_numbers, "group window is not a permutation")
    old_to_new = {old: window_numbers[index] for index, old in enumerate(new_order)}
    require(
        any((old != new for old, new in old_to_new.items())),
        "the requested group order already holds",
    )

    def mapped(number: int) -> int:
        return old_to_new.get(number, number)

    work = bytearray(seed_bytes)
    original_headers = {
        number: seed_bytes[20 + (number - 1) * 40 : 20 + number * 40] for number in window_numbers
    }
    for old, new in old_to_new.items():
        start = 20 + (new - 1) * 40
        work[start : start + 40] = original_headers[old]
    symbol_writes = 0
    association_writes = 0
    for index, symbol in seed.symbols.items():
        if symbol["section"] > 0 and mapped(symbol["section"]) != symbol["section"]:
            offset = seed.symbol_offset + index * 18 + 12
            work[offset : offset + 2] = mapped(symbol["section"]).to_bytes(2, "little", signed=True)
            symbol_writes += 1
        definition = definitions.get(symbol["section"])
        if (
            definition is not None
            and symbol["storage"] == 3
            and symbol["aux_count"]
            and (symbol["name"] == seed.sections[symbol["section"] - 1]["name"])
            and (definition["selection"] == 5)
            and (mapped(definition["associated"]) != definition["associated"])
        ):
            aux = seed.symbol_offset + (index + 1) * 18
            parent = mapped(definition["associated"])
            work[aux + 12 : aux + 14] = (parent & 65535).to_bytes(2, "little")
            work[aux + 16 : aux + 18] = (parent >> 16).to_bytes(2, "little")
            association_writes += 1
    composed = bytes(work)
    require(len(composed) == len(seed_bytes), "object size changed")
    checked = CoffObject(composed)
    checked_definitions = section_definitions(checked)
    section_fields = (
        "name",
        "raw_size",
        "raw_offset",
        "relocation_offset",
        "relocation_count",
        "line_offset",
        "line_count",
        "characteristics",
    )
    for section in seed.sections:
        peer = checked.sections[mapped(section["number"]) - 1]
        require(
            all((section[field] == peer[field] for field in section_fields)),
            f"semantic section changed: old {section['number']}",
        )
    require(seed.symbols.keys() == checked.symbols.keys(), "symbol index set changed")
    for index, symbol in seed.symbols.items():
        peer = checked.symbols[index]
        require(
            all(
                (
                    symbol[field] == peer[field]
                    for field in ("name", "value", "type", "storage", "aux_count")
                )
            )
            and peer["section"] == mapped(symbol["section"]),
            f"symbol identity changed at {index}",
        )
    for old_number, definition in definitions.items():
        peer = checked_definitions.get(mapped(old_number))
        require(
            peer is not None
            and peer["selection"] == definition["selection"]
            and (peer["associated"] == mapped(definition["associated"])),
            f"section definition mapping changing: {old_number}",
        )
    final_numbers = [comdat_primary_section(checked, name)["number"] for name in order]
    require(final_numbers == sorted(final_numbers), "target group order was not restored")
    listed_offsets = {
        seed.sections[number - 1]["raw_offset"] for _, _, members in groups for number in members
    }
    for name in sorted(
        {section["name"] for section in seed.sections if not section["name"].startswith(".debug$")}
    ):
        before = [section["raw_offset"] for section in seed.sections if section["name"] == name]
        after = [section["raw_offset"] for section in checked.sections if section["name"] == name]
        require(sorted(before) == sorted(after), f"{name} contribution set changed")
        require(
            [offset for offset in before if offset not in listed_offsets]
            == [offset for offset in after if offset not in listed_offsets],
            f"an unlisted {name} contribution moved",
        )
        if name.split("$")[0] != kind:
            group_rank = {}
            for rank, (_, _, members) in enumerate(groups):
                for number in members:
                    group_rank[seed.sections[number - 1]["raw_offset"]] = rank
            ranks = [group_rank[offset] for offset in after if offset in listed_offsets]
            require(ranks == sorted(ranks), f"listed {name} children do not follow the group order")
    return (
        composed,
        {
            "group_order": list(order),
            "window": [low, high],
            "unlisted_reseated": len(unlisted),
            "symbol_section_writes": symbol_writes,
            "association_writes": association_writes,
        },
    )


def produce_comdat_selection_override_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
    """Class C: install another object's copy of a multiply-defined COMDAT.

    Some template instantiations are emitted by several objects in one link.
    The linker keeps whichever comes first and discards the rest, so the
    copies are interchangeable *to the linker* and the choice is pure link
    order.  This installs a copy the linker itself could have chosen -- it
    selects among genuine compiler outputs and invents nothing.

    The donor is a DIFFERENT translation unit, so the whole-object
    equivalences every other class relies on (section count, function
    multiset, section seat) do not apply and are deliberately not required.
    What replaces them is a complete declarative pin plus an exact structural
    match of the COMDAT and its closure.  The sealed final-image verifier owns
    literal reference comparison.
    """
    require_payload_free_declaration(function, "COMDAT selection declaration")
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"],
        "COMDAT selection differs between the two copies",
    )
    require(
        all(
            (
                sp[key] == dp[key]
                for key in ("name", "raw_size", "relocation_count", "line_count", "characteristics")
            )
        ),
        "the two COMDAT copies differ in shape",
    )
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_donor_length"],
        "target body lengths changed",
    )
    donor_code = coff_body(donor, dp)
    require(
        sha256_bytes(donor_code) == function["expected_body_sha256"],
        "donor body differs from its pinned compiler output",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(len(donor_code) == pinned_length, "candidate length differs from its linked-length pin")
    spr = detailed_relocations(seed, sp)
    dpr = detailed_relocations(donor, dp)
    require(len(spr) == len(dpr), "relocation counts differ")
    for index, (left, right) in enumerate(zip(spr, dpr)):
        require(
            (left["offset"], left["type"], left["addend"])
            == (right["offset"], right["type"], right["addend"]),
            f"relocation {index}: offset/type/addend differs",
        )
        require(
            local_symbol_kind(right["target"]) is None,
            f"relocation {index}: compiler-local target {right['target']!r} cannot cross objects",
        )
        require(
            left["target"] == right["target"],
            f"relocation {index}: target name differs ({left['target']!r} vs {right['target']!r})",
        )
    seed_lines = _coff_table_bytes(seed, sp, "lines")
    donor_lines = _coff_table_bytes(donor, dp, "lines")
    require(
        len(seed_lines) == len(donor_lines) and seed_lines[4:] == donor_lines[4:],
        "COFF line rows differ between the two copies",
    )
    closure = _comdat_child_closure(seed, sp)
    require(
        closure == _comdat_child_closure(donor, dp)
        and closure in ((2, (".debug$S", ".xdata$x")), (2, (".debug$F", ".debug$S"))),
        "target closure is not an EH or FPO debug pair",
    )
    fpo = closure == (2, (".debug$F", ".debug$S"))
    child = ".debug$F" if fpo else ".xdata$x"
    sx = _comdat_child(seed, sp, child)
    dx = _comdat_child(donor, dp, child)
    require(
        coff_body(seed, sx) == coff_body(donor, dx), f"{child} bytes differ between the two copies"
    )
    sd = _comdat_child(seed, sp, ".debug$S")
    dd = _comdat_child(donor, dp, ".debug$S")
    seed_debug = coff_body(seed, sd)
    donor_debug = coff_body(donor, dd)
    require(
        len(seed_debug) >= 28
        and seed_debug[2:4] == b"\x05\x02"
        and (donor_debug[2:4] == b"\x05\x02"),
        "debug$S is not an S_*PROC32 record",
    )
    require(
        seed_debug[16:28] == donor_debug[16:28],
        "debug$S procedure range differs between the two copies",
    )
    old_end = sp["raw_offset"] + sp["raw_size"]
    output = _apply_replacements(seed_bytes, [(sp["raw_offset"], old_end, donor_code)])
    checked = CoffObject(output)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == donor_code, "composed body is not the donor body")
    require(
        _coff_table_bytes(checked, cp, "relocations") == _coff_table_bytes(seed, sp, "relocations"),
        "composed relocation table changed",
    )
    require(len(output) == len(seed_bytes), "composed object size changed")
    return (
        output,
        {
            "splice_class": "comdat_selection_override",
            "mangled": mangled,
            "seed_section": sp["number"],
            "donor_section": dp["number"],
            "body_length": len(donor_code),
            "relocations": len(dpr),
            "candidate_only": True,
            "oracle_payload_bytes_read": 0,
        },
    )


REPINNABLE_SPLICE_CLASSES = frozenset(
    {
        "equal_body_strict",
        "equal_body_eh_structural_local",
        "equal_body_eh_reloc_layout",
        "same_slot_resize",
    }
)
REPINNABLE_PIN_KEYS = {
    "equal_body_strict": frozenset(
        {"expected_body_length", "expected_body_sha256", "expected_changed_offsets"}
    ),
    "equal_body_eh_structural_local": frozenset(
        {
            "expected_body_length",
            "expected_body_sha256",
            "expected_changed_offsets",
            "expected_code_renames",
            "expected_xdata_rename_offsets",
            "expected_donor_section_number",
        }
    ),
    "equal_body_eh_reloc_layout": frozenset(
        {
            "expected_body_length",
            "expected_body_sha256",
            "expected_changed_offsets",
            "expected_relocation_moves",
            "expected_xdata_rename_offsets",
        }
    ),
    "same_slot_resize": frozenset(
        {
            "expected_seed_length",
            "expected_donor_length",
            "expected_linked_span",
            "expected_body_sha256",
            "expected_seed_line_count",
            "expected_donor_line_count",
        }
    ),
}


def measure_composition_pins(
    seed_bytes: bytes, donor_bytes: bytes, function: dict, context: str
) -> dict:
    """Measure, from the two objects, every pin this entry states about them.

    Returns only keys the entry ALREADY carries.  Raises for a splice class
    outside the closed repinnable set.
    """
    splice_class = function.get("splice_class")
    require(
        splice_class in REPINNABLE_SPLICE_CLASSES,
        f"{context}: {splice_class} is outside the repinnable classes; its free parameters are decisions, not measurements",
    )
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    seed_primary = seed.function_section(mangled)
    donor_primary = donor.function_section(mangled)
    seed_body = bytes(coff_body(seed, seed_primary))
    donor_body = bytes(coff_body(donor, donor_primary))
    measured = {
        "expected_body_sha256": sha256_bytes(donor_body),
        "expected_seed_length": seed_primary["raw_size"],
        "expected_donor_length": donor_primary["raw_size"],
        "expected_seed_line_count": seed_primary["line_count"],
        "expected_donor_line_count": donor_primary["line_count"],
        "expected_linked_span": (donor_primary["raw_size"] + 15) // 16 * 16,
        "expected_donor_section_number": donor_primary["number"],
    }
    if splice_class != "same_slot_resize":
        require(
            seed_primary["raw_size"] == donor_primary["raw_size"],
            f"{context}: an equal-body entry's seed and donor bodies are no longer the same length; the composition is not a re-pin away from valid",
        )
        measured["expected_body_length"] = seed_primary["raw_size"]
        measured["expected_changed_offsets"] = [
            index for index, pair in enumerate(zip(seed_body, donor_body)) if pair[0] != pair[1]
        ]
    if splice_class in ("equal_body_eh_structural_local", "equal_body_eh_reloc_layout"):
        closure = _comdat_child_closure(seed, seed_primary)
        seat_map = None
        if "expected_donor_section_number" in function:
            seat_map = {donor_primary["number"]: seed_primary["number"]}
            for child_name in (".debug$S", ".xdata$x"):
                seat_map[_comdat_child(donor, donor_primary, child_name)["number"]] = _comdat_child(
                    seed, seed_primary, child_name
                )["number"]
        if closure in ((2, (".debug$F", ".debug$S")), (1, (".debug$S",))):
            measured["expected_xdata_rename_offsets"] = []
        else:
            measured["expected_xdata_rename_offsets"] = [
                offset
                for offset, _ in _normalized_relocation_renames(
                    seed,
                    _comdat_child(seed, seed_primary, ".xdata$x"),
                    donor,
                    _comdat_child(donor, donor_primary, ".xdata$x"),
                    "xdata",
                    seat_map=seat_map,
                )
            ]
        if splice_class == "equal_body_eh_structural_local":
            measured["expected_code_renames"] = [
                [offset, kind]
                for offset, kind in _normalized_relocation_renames(
                    seed, seed_primary, donor, donor_primary, "code", seat_map=seat_map
                )
            ]
        else:
            left = detailed_relocations(seed, seed_primary)
            right = detailed_relocations(donor, donor_primary)
            require(
                len(left) == len(right),
                f"{context}: relocation counts differ, so the reloc-layout move set is not a re-pin away from valid",
            )
            measured["expected_relocation_moves"] = [
                [a["offset"], b["offset"]]
                for a, b in zip(left, right)
                if a["offset"] != b["offset"]
            ]
    return {
        key: value
        for key, value in measured.items()
        if key in function and key in REPINNABLE_PIN_KEYS[splice_class]
    }


def repin_composition_function(
    seed_bytes: bytes, donor_bytes: bytes, function: dict, context: str
) -> tuple[dict, list[str]]:
    """Refresh one composition entry's measured pins.

    Returns the refreshed entry and the names of the pins that moved.  The
    caller is expected to run the refreshed entry through the ordinary
    composer: this function proves nothing on its own, it only restates what
    the objects say, and every obligation the class carries still has to hold
    afterwards.
    """
    measured = measure_composition_pins(seed_bytes, donor_bytes, function, context)
    moved = sorted((key for key, value in measured.items() if function[key] != value))
    return ({**function, **measured}, moved)


def compose_equal_body_comdat(
    seed_bytes: bytes, donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
    """Copy one equal-size compiler-produced COMDAT code body from a donor
    object into the seed object, retaining every seed relocation, xdata,
    debug, and symbol byte.

    Two proved splice classes:
    - equal_body_strict: (.debug$F, .debug$S) closure, literal-equal
      relocation tuples.
    - equal_body_eh_structural_local: (.debug$S, .xdata$x) closure with
      byte-identical xdata and paired object-local $L/$T relocation renames
      resolving to structurally identical targets.
    """
    require_payload_free_declaration(function, "equal-body declaration")
    require(
        "target_source_refactor" not in function, "equal-body source permutations are unsupported"
    )
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    splice_class = function["splice_class"]
    seed_primary = seed.function_section(mangled)
    donor_primary = donor.function_section(mangled)
    require(
        seed_primary["raw_size"] == donor_primary["raw_size"] == function["expected_body_length"],
        "target COMDAT body length changed",
    )
    for field in ("name", "characteristics"):
        require(seed_primary[field] == donor_primary[field], f"target section {field} differs")
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    seed_definition = seed_definitions.get(seed_primary["number"])
    donor_definition = donor_definitions.get(donor_primary["number"])
    require(
        seed_definition is not None and donor_definition is not None,
        "target COMDAT definition record is missing",
    )
    require(
        all(
            (
                seed_definition[field] == donor_definition[field]
                for field in ("selection", "associated", "length", "relocations")
            )
        ),
        "target COMDAT definition record differs",
    )
    donor_body = coff_body(donor, donor_primary)
    require(
        sha256_bytes(donor_body) == function["expected_body_sha256"],
        "donor body differs from its pinned compiler output",
    )
    seed_body = coff_body(seed, seed_primary)
    changed = [index for index, pair in enumerate(zip(seed_body, donor_body)) if pair[0] != pair[1]]
    require(changed == function["expected_changed_offsets"], "seed/donor body delta changed")
    closure = _comdat_child_closure(seed, seed_primary)
    require(
        closure == _comdat_child_closure(donor, donor_primary),
        "target COMDAT child closure differs",
    )
    relocation_moves = []
    if splice_class == "equal_body_eh_reloc_layout":
        left = detailed_relocations(seed, seed_primary)
        right = detailed_relocations(donor, donor_primary)
        require(len(left) == len(right), "reloc-layout splice: relocation counts differ")
        for a, b in zip(left, right):
            require(
                a["type"] == b["type"] and a["addend"] == b["addend"],
                "reloc-layout splice: relocation type/addend differs",
            )
            if a["target"] != b["target"]:
                kind = local_symbol_kind(a["target"])
                if kind is None:
                    left_base, _, left_serial = a["target"].rpartition("$S")
                    right_base, _, right_serial = b["target"].rpartition("$S")
                    require(
                        left_base
                        and left_base == right_base
                        and left_serial.isdigit()
                        and right_serial.isdigit()
                        and (a["target_type"] == b["target_type"])
                        and (a["target_storage"] == b["target_storage"]),
                        "reloc-layout splice: non-local relocation rename",
                    )
                else:
                    require(
                        kind == local_symbol_kind(b["target"])
                        and all(
                            (
                                a["target_" + field] == b["target_" + field]
                                for field in ("section", "value", "type", "storage")
                            )
                        ),
                        "reloc-layout splice: non-local relocation rename",
                    )
            if a["offset"] != b["offset"]:
                relocation_moves.append([a["offset"], b["offset"]])
        require(
            relocation_moves == function["expected_relocation_moves"],
            "reloc-layout splice: relocation move set changed",
        )
    if splice_class == "equal_body_strict":
        require(
            closure == (2, (".debug$F", ".debug$S")), "strict splice requires the FPO debug closure"
        )
        renames = _normalized_relocation_renames(seed, seed_primary, donor, donor_primary, "code")
        require(renames == [], "strict splice forbids relocation renames")
        detail = {"code_renames": []}
    else:
        require(
            splice_class in ("equal_body_eh_structural_local", "equal_body_eh_reloc_layout"),
            "unsupported equal-body splice class",
        )
        fpo_closure = closure in ((2, (".debug$F", ".debug$S")), (1, (".debug$S",)))
        require(
            closure == (2, (".debug$S", ".xdata$x")) or fpo_closure,
            "splice closure kind is unsupported for this class",
        )
        if "expected_donor_section_number" in function:
            require(
                donor_primary["number"] == function["expected_donor_section_number"],
                "declared cross-lane donor seat changed",
            )
            seat_map = {donor_primary["number"]: seed_primary["number"]}
            for child_name in closure[1]:
                seat_map[_comdat_child(donor, donor_primary, child_name)["number"]] = _comdat_child(
                    seed, seed_primary, child_name
                )["number"]
        else:
            require(
                seed_primary["number"] == donor_primary["number"], "target closure seats differ"
            )
            seat_map = None
        if fpo_closure:
            require(
                function["expected_xdata_rename_offsets"] == [],
                "FPO-closure splice cannot declare xdata renames",
            )
            xdata_renames = []
        else:
            seed_xdata = _comdat_child(seed, seed_primary, ".xdata$x")
            donor_xdata = _comdat_child(donor, donor_primary, ".xdata$x")
            require(
                coff_body(seed, seed_xdata) == coff_body(donor, donor_xdata),
                "EH xdata raw bytes differ",
            )
            xdata_renames = _normalized_relocation_renames(
                seed, seed_xdata, donor, donor_xdata, "xdata", seat_map=seat_map
            )
            require(
                [offset for offset, _ in xdata_renames]
                == function["expected_xdata_rename_offsets"],
                "xdata local-relocation rename set changed",
            )
        if splice_class == "equal_body_eh_structural_local":
            code_renames = _normalized_relocation_renames(
                seed, seed_primary, donor, donor_primary, "code", seat_map=seat_map
            )
            require(
                [[offset, kind] for offset, kind in code_renames]
                == function["expected_code_renames"],
                "code local-relocation rename set changed",
            )
            relocation_mask = {
                record["offset"] + byte
                for record in detailed_relocations(donor, donor_primary)
                for byte in range(record["width"])
            }
            require(
                all((offset not in relocation_mask for offset in changed)),
                "donor changes a relocated operand",
            )
            detail = {
                "code_renames": code_renames,
                "xdata_rename_offsets": [o for o, _ in xdata_renames],
            }
        else:
            detail = {
                "relocation_moves": relocation_moves,
                "xdata_rename_offsets": [o for o, _ in xdata_renames],
            }
    composed = bytearray(seed_bytes)
    start = seed_primary["raw_offset"]
    composed[start : start + seed_primary["raw_size"]] = donor_body
    if relocation_moves:
        donor_offsets = [record["offset"] for record in detailed_relocations(donor, donor_primary)]
        for ordinal, offset in enumerate(donor_offsets):
            record_at = seed_primary["relocation_offset"] + ordinal * 10
            composed[record_at : record_at + 4] = offset.to_bytes(4, "little")
    composed = bytes(composed)
    checked = CoffObject(composed)
    checked_primary = checked.function_section(mangled)
    require(
        coff_body(checked, checked_primary) == donor_body, "composed body differs from the donor"
    )
    checked_relocations = detailed_relocations(checked, checked_primary)
    seed_relocations = detailed_relocations(seed, seed_primary)
    if relocation_moves:
        donor_relocations = detailed_relocations(donor, donor_primary)
        require(
            [(r["offset"], r["type"], r["addend"], r["symbol_index"]) for r in checked_relocations]
            == [
                (d["offset"], d["type"], d["addend"], s["symbol_index"])
                for d, s in zip(donor_relocations, seed_relocations)
            ],
            "composed relocations differ from the donor layout",
        )
    else:
        require(
            checked_relocations == seed_relocations, "composed relocations differ from the seed"
        )
    changed_offsets = [
        index for index, pair in enumerate(zip(seed_bytes, composed)) if pair[0] != pair[1]
    ]
    allowed = set(range(start, start + seed_primary["raw_size"]))
    if relocation_moves:
        allowed |= {
            seed_primary["relocation_offset"] + ordinal * 10 + byte
            for ordinal in range(seed_primary["relocation_count"])
            for byte in range(4)
        }
    require(set(changed_offsets) <= allowed, "composition changed bytes outside the selected body")
    return (
        composed,
        {
            "mangled": mangled,
            "splice_class": splice_class,
            "section_number": seed_primary["number"],
            "body_length": seed_primary["raw_size"],
            "body_changed_offsets": changed,
            **detail,
        },
    )


def produce_source_equal_body_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict, seed_source: bytes, donor_source: bytes
) -> tuple[bytes, dict]:
    """Install one complete equal-size body from a closed source refactor.

    This is deliberately a separate wrapper around the ordinary equal-body
    composer.  The ordinary entry point continues to reject source proofs;
    this class adds the source identity, complete target/closure pins,
    semantic-relocation equivalence before delegating the
    one allowed mutation: replacing the target's raw body while retaining all
    seed line, debug, unwind/FPO, relocation, and symbol bytes.
    """
    require_payload_free_declaration(function, "source equal-body declaration")
    require(
        function.get("splice_class") == RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS
        and "target_source_refactor" in function,
        "retail-exact source equal-body contract is missing",
    )
    source_detail = require_target_source_refactor_identity(
        seed_source,
        donor_source,
        function["target_source_refactor"],
        "retail-exact source equal-body proof",
    )
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        "source equal-body target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "source equal-body global section count changed",
    )
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(
        seed_functions == donor_functions
        and sum(seed_functions.values()) == function["expected_function_count"],
        "source equal-body donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(
        seed_comdats == donor_comdats
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "source equal-body donor COMDAT identity set differs",
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
        "source equal-body target header/count pins changed",
    )
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[sp["number"]]["selection"]
        == donor_defs[dp["number"]]["selection"]
        == function["expected_selection"],
        "source equal-body COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    closure = _comdat_child_closure(seed, sp)
    source_fpo = "source_fpo_identity" in function
    required_closure = (
        (2, (".debug$F", ".debug$S")) if source_fpo else (2, (".debug$S", ".xdata$x"))
    )
    require(
        closure
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure)
        == required_closure,
        "source equal-body target closure changed",
    )
    if source_fpo:
        closure_pairs = require_source_fpo_mosaic_identity(
            seed,
            sp,
            donor,
            dp,
            function,
            function["source_fpo_identity"],
            "source equal-body FPO identity",
        )
    else:
        closure_pairs = [
            (_comdat_child(seed, sp, child_name), _comdat_child(donor, dp, child_name))
            for child_name in expected_closure
        ]
    closure_renames = {}
    for child_name, (left, right) in zip(expected_closure, closure_pairs, strict=True):
        if not source_fpo:
            require(
                left["number"] == right["number"]
                and all(
                    (
                        left[field] == right[field]
                        for field in (
                            "name",
                            "raw_size",
                            "relocation_count",
                            "line_count",
                            "characteristics",
                        )
                    )
                ),
                f"source equal-body {child_name} closure geometry changed",
            )
        closure_renames[child_name] = require_same_semantic_relocations(
            seed, left, donor, right, f"source equal-body {child_name}"
        )
    if source_fpo:
        require(
            function["expected_xdata_rename_offsets"] == [],
            "source equal-body FPO closure cannot declare xdata renames",
        )
    else:
        require(
            [offset for offset, _ in closure_renames[".xdata$x"]]
            == function["expected_xdata_rename_offsets"],
            "source equal-body xdata rename set changed",
        )
    require(
        [[offset, kind] for offset, kind in closure_renames[".debug$S"]]
        == function["expected_debug_s_renames"],
        "source equal-body debug$S rename set changed",
    )
    if not source_fpo:
        seed_xdata = _comdat_child(seed, sp, ".xdata$x")
        donor_xdata = _comdat_child(donor, dp, ".xdata$x")
        require(
            coff_body(seed, seed_xdata) == coff_body(donor, donor_xdata),
            "source equal-body runtime xdata bytes changed",
        )
        seed_debug = coff_body(seed, _comdat_child(seed, sp, ".debug$S"))
        donor_debug = coff_body(donor, _comdat_child(donor, dp, ".debug$S"))
        require(
            len(seed_debug) >= 28
            and len(seed_debug) == len(donor_debug)
            and (seed_debug[:28] == donor_debug[:28])
            and (seed_debug[2:4] == b"\x05\x02"),
            "source equal-body CodeView procedure identity changed",
        )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "source equal-body metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body)
        == function["expected_donor_body_sha256"]
        == function["expected_body_sha256"],
        "source equal-body target body differs from its pin",
    )
    code_renames = require_instruction_mosaic_semantic_relocations(
        seed, sp, donor, dp, "source equal-body code"
    )
    require(
        [[offset, kind] for offset, kind in code_renames] == function["expected_code_renames"],
        "source equal-body code rename set changed",
    )
    seed_rows = detailed_relocations(seed, sp)
    require(
        len(seed_rows) == function["expected_relocation_count"],
        "source equal-body relocation count changed",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(donor_body), "source equal-body linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        seed_rows,
        function["retail_relocations"],
        "source equal-body candidate relocation semantics",
    )
    effective = {
        "mangled": mangled,
        "splice_class": "equal_body_eh_structural_local",
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
        "expected_code_renames": function["expected_code_renames"],
        "expected_xdata_rename_offsets": function["expected_xdata_rename_offsets"],
    }
    composed, detail = compose_equal_body_comdat(seed_bytes, donor_bytes, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        _coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")
        and detailed_relocations(checked, cp) == seed_rows
        and (
            instruction_mosaic_metadata_sha256(checked, cp)
            == function["expected_seed_metadata_sha256"]
        ),
        "source equal-body output changed seed-authoritative metadata",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS,
            "closure": list(expected_closure),
            "closure_relocation_renames": closure_renames,
            "source_fpo_identity": source_fpo,
            "candidate_only": True,
            **semantic_detail,
            **source_detail,
        },
    )


def compose_equal_linked_span_fpo(
    seed_bytes: bytes, donor_bytes: bytes, function: dict, shape_identifiers: set[str]
) -> tuple[bytes, dict]:
    """Compose one compiler-produced FPO COMDAT and prove its full closure."""
    require_payload_free_declaration(function, "equal-linked-span FPO declaration")
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    seed_primary = seed.function_section(mangled)
    donor_primary = donor.function_section(mangled)
    require(
        seed_primary["number"] == donor_primary["number"] == function["expected_section_number"],
        "target COMDAT section seat changed",
    )
    require(
        seed_primary["raw_size"] == function["expected_seed_length"], "seed target length changed"
    )
    require(
        donor_primary["raw_size"] == function["expected_donor_length"],
        "donor target length changed",
    )
    require(
        (seed_primary["raw_size"] + 15) // 16 * 16
        == function["expected_linked_span"]
        == (donor_primary["raw_size"] + 15) // 16 * 16,
        "target 16-byte linked contribution span changed",
    )
    require(
        seed_primary["name"] == donor_primary["name"]
        and seed_primary["characteristics"]
        == donor_primary["characteristics"]
        == function["expected_characteristics"],
        "target section kind or characteristics changed",
    )
    require(
        seed_primary["characteristics"] & 15728640 == 5242880,
        "target COMDAT does not declare 16-byte section alignment",
    )
    require(
        seed_primary["relocation_count"]
        == donor_primary["relocation_count"]
        == function["expected_relocation_count"],
        "target relocation count changed",
    )
    require(
        seed_primary["line_count"] == function["expected_seed_line_count"]
        and donor_primary["line_count"] == function["expected_donor_line_count"],
        "target COFF line count changed",
    )
    seed_definitions = section_definitions(seed)
    donor_definitions = section_definitions(donor)
    require(
        seed_primary["number"] in seed_definitions and donor_primary["number"] in donor_definitions,
        "target Section Definition auxiliary record is absent",
    )
    require(
        seed_definitions[seed_primary["number"]]["selection"]
        == donor_definitions[donor_primary["number"]]["selection"]
        == function["expected_selection"],
        "target COMDAT selection changed",
    )
    seed_associated = associated_sections(seed, seed_definitions, seed_primary["number"])
    donor_associated = associated_sections(donor, donor_definitions, donor_primary["number"])
    require(seed_associated == donor_associated, "target associative-section seats changed")
    require(
        tuple(sorted((name for _, name in seed_associated))) == (".debug$F", ".debug$S"),
        "target closure is not exactly .debug$S + .debug$F; xdata is unsupported",
    )
    provenance = verify_non_emitting_donor(seed, donor, shape_identifiers)
    seed_closure = {name: seed.sections[number - 1] for number, name in seed_associated}
    donor_closure = {name: donor.sections[number - 1] for number, name in donor_associated}
    for name in (".debug$S", ".debug$F"):
        left = seed_closure[name]
        right = donor_closure[name]
        require(
            left["number"] == right["number"]
            and left["raw_size"] == right["raw_size"]
            and (left["relocation_count"] == right["relocation_count"])
            and (left["line_count"] == right["line_count"] == 0)
            and (left["characteristics"] == right["characteristics"]),
            f"{name} closure geometry changed",
        )
        left_rows = detailed_relocations(seed, left)
        right_rows = detailed_relocations(donor, right)
        require(
            [
                (
                    row["offset"],
                    row["type"],
                    row["addend"],
                    row["target"],
                    row["target_section"],
                    row["target_value"],
                    row["target_type"],
                    row["target_storage"],
                )
                for row in left_rows
            ]
            == [
                (
                    row["offset"],
                    row["type"],
                    row["addend"],
                    row["target"],
                    row["target_section"],
                    row["target_value"],
                    row["target_type"],
                    row["target_storage"],
                )
                for row in right_rows
            ],
            f"{name} relocation target/type/addend closure changed",
        )
    seed_relocations = detailed_relocations(seed, seed_primary)
    donor_relocations = detailed_relocations(donor, donor_primary)
    compatibility = relocation_compatibility(
        seed_relocations, donor_relocations, seed_primary["number"], donor_primary["number"]
    )
    require(compatibility is not None, "primary relocation target/type/addend semantics changed")
    require(
        len(compatibility["local_updates"]) == function["expected_local_symbol_updates"],
        "primary local-symbol update count changed",
    )
    donor_body = coff_body(donor, donor_primary)
    require(
        sha256_bytes(donor_body) == function["compiler_output_body_sha256"],
        "compiler donor body hash differs from the retail-approved oracle pin",
    )
    seed_function_index, seed_function = function_symbol(seed, mangled, seed_primary["number"])
    donor_function_index, donor_function = function_symbol(donor, mangled, donor_primary["number"])
    donor_lines = normalized_donor_lines(
        seed, donor, seed_primary, donor_primary, seed_function_index, donor_function_index
    )
    replacements = [
        (
            seed_primary["raw_offset"],
            seed_primary["raw_offset"] + seed_primary["raw_size"],
            donor_body,
        ),
        (
            seed_primary["line_offset"],
            seed_primary["line_offset"] + seed_primary["line_count"] * 6,
            donor_lines,
        ),
    ]
    output = bytearray(_apply_replacements(seed_bytes, replacements))
    total_delta = sum(
        (len(replacement) - (end - start) for start, end, replacement in replacements)
    )
    new_symbol_offset = shifted_pointer(seed.symbol_offset, replacements)
    struct.pack_into("<I", output, 8, new_symbol_offset)
    expected_headers = bytearray(seed.data[20 : 20 + seed.section_count * 40])
    for section in seed.sections:
        relative_header = (section["number"] - 1) * 40
        if section["number"] == seed_primary["number"]:
            struct.pack_into(
                "<I", expected_headers, relative_header + 16, donor_primary["raw_size"]
            )
            struct.pack_into(
                "<H", expected_headers, relative_header + 34, donor_primary["line_count"]
            )
        for field, relative in (("raw_offset", 20), ("relocation_offset", 24), ("line_offset", 28)):
            struct.pack_into(
                "<I",
                expected_headers,
                relative_header + relative,
                shifted_pointer(section[field], replacements),
            )
    output[20 : 20 + len(expected_headers)] = expected_headers
    new_primary_relocation_offset = shifted_pointer(seed_primary["relocation_offset"], replacements)
    for ordinal, (seed_row, donor_row) in enumerate(zip(seed_relocations, donor_relocations)):
        struct.pack_into(
            "<IIH",
            output,
            new_primary_relocation_offset + ordinal * 10,
            donor_row["offset"],
            seed_row["symbol_index"],
            donor_row["type"],
        )
    expected_symbols = bytearray(
        seed.data[seed.symbol_offset : seed.symbol_offset + seed.symbol_count * 18]
    )
    shifted_function_line_pointers = 0
    for symbol_index, symbol in seed.symbols.items():
        if symbol["type"] != 32 or symbol["aux_count"] < 1:
            continue
        auxiliary_offset = (symbol_index + 1) * 18
        (line_pointer,) = struct.unpack_from("<I", expected_symbols, auxiliary_offset + 8)
        mapped = shifted_pointer(line_pointer, replacements)
        if mapped != line_pointer:
            struct.pack_into("<I", expected_symbols, auxiliary_offset + 8, mapped)
            shifted_function_line_pointers += 1
    for symbol_index, donor_value in compatibility["local_updates"].items():
        struct.pack_into("<I", expected_symbols, symbol_index * 18 + 8, donor_value)
    donor_function_auxiliary = coff_auxiliary(donor, donor_function_index, donor_function)
    seed_function_auxiliary = coff_auxiliary(seed, seed_function_index, seed_function)
    require(
        seed_function["type"] == donor_function["type"]
        and seed_function["storage"] == donor_function["storage"]
        and (seed_function["aux_count"] == donor_function["aux_count"] == 1)
        and (seed_function_auxiliary[:4] == donor_function_auxiliary[:4])
        and (seed_function_auxiliary[12:] == donor_function_auxiliary[12:]),
        "Function Definition tag/next-function auxiliary metadata changed",
    )
    seed_total_size, seed_line_pointer = struct.unpack_from("<II", seed_function_auxiliary, 4)
    donor_total_size, donor_line_pointer = struct.unpack_from("<II", donor_function_auxiliary, 4)
    require(
        seed_total_size == seed_primary["raw_size"]
        and seed_line_pointer == seed_primary["line_offset"],
        "seed Function Definition size/line pointer is stale",
    )
    require(
        donor_total_size == donor_primary["raw_size"]
        and donor_line_pointer == donor_primary["line_offset"],
        "donor Function Definition size/line pointer is stale",
    )
    struct.pack_into("<I", expected_symbols, (seed_function_index + 1) * 18 + 4, donor_total_size)
    seed_begin_index, seed_begin = marker_symbol(seed, ".bf", seed_primary["number"])
    donor_begin_index, donor_begin = marker_symbol(donor, ".bf", donor_primary["number"])
    seed_begin_auxiliary = coff_auxiliary(seed, seed_begin_index, seed_begin)
    donor_begin_auxiliary = coff_auxiliary(donor, donor_begin_index, donor_begin)
    require(
        seed_begin["aux_count"] == donor_begin["aux_count"] == 1
        and seed_begin["value"] == donor_begin["value"]
        and (seed_begin["type"] == donor_begin["type"])
        and (seed_begin["storage"] == donor_begin["storage"])
        and (seed_begin_auxiliary[:4] == donor_begin_auxiliary[:4])
        and (seed_begin_auxiliary[6:] == donor_begin_auxiliary[6:]),
        ".bf tag/next-function auxiliary metadata changed",
    )
    expected_symbols[(seed_begin_index + 1) * 18 + 4 : (seed_begin_index + 1) * 18 + 6] = (
        donor_begin_auxiliary[4:6]
    )
    seed_end_index, seed_end = marker_symbol(seed, ".ef", seed_primary["number"])
    donor_end_index, donor_end = marker_symbol(donor, ".ef", donor_primary["number"])
    require(seed_end["value"] == seed_primary["raw_size"], "seed .ef value is stale")
    require(donor_end["value"] == donor_primary["raw_size"], "donor .ef value is stale")
    seed_end_auxiliary = coff_auxiliary(seed, seed_end_index, seed_end)
    donor_end_auxiliary = coff_auxiliary(donor, donor_end_index, donor_end)
    require(
        seed_end["aux_count"] == donor_end["aux_count"] == 1
        and seed_end["type"] == donor_end["type"]
        and (seed_end["storage"] == donor_end["storage"])
        and (seed_end_auxiliary[:4] == donor_end_auxiliary[:4])
        and (seed_end_auxiliary[6:] == donor_end_auxiliary[6:]),
        ".ef tag/next-function auxiliary metadata changed",
    )
    struct.pack_into("<I", expected_symbols, seed_end_index * 18 + 8, donor_end["value"])
    expected_symbols[(seed_end_index + 1) * 18 + 4 : (seed_end_index + 1) * 18 + 6] = (
        donor_end_auxiliary[4:6]
    )
    seed_section_index, seed_section_symbol = section_symbol(seed, seed_primary)
    donor_section_index, donor_section_symbol = section_symbol(donor, donor_primary)
    donor_section_auxiliary = coff_auxiliary(donor, donor_section_index, donor_section_symbol)
    seed_section_auxiliary = coff_auxiliary(seed, seed_section_index, seed_section_symbol)
    require(
        seed_section_symbol["aux_count"] == donor_section_symbol["aux_count"] == 1
        and seed_section_symbol["type"] == donor_section_symbol["type"]
        and (seed_section_symbol["storage"] == donor_section_symbol["storage"])
        and (seed_section_auxiliary[12:] == donor_section_auxiliary[12:])
        and (int.from_bytes(seed_section_auxiliary[0:4], "little") == seed_primary["raw_size"])
        and (
            int.from_bytes(seed_section_auxiliary[4:6], "little")
            == seed_primary["relocation_count"]
        )
        and (int.from_bytes(seed_section_auxiliary[6:8], "little") == seed_primary["line_count"])
        and (int.from_bytes(donor_section_auxiliary[0:4], "little") == donor_primary["raw_size"])
        and (
            int.from_bytes(donor_section_auxiliary[4:6], "little")
            == donor_primary["relocation_count"]
        )
        and (int.from_bytes(donor_section_auxiliary[6:8], "little") == donor_primary["line_count"])
        and (donor_section_auxiliary[14] == function["expected_selection"]),
        "donor Section Definition auxiliary record is stale",
    )
    expected_symbols[(seed_section_index + 1) * 18 : (seed_section_index + 2) * 18] = (
        donor_section_auxiliary
    )
    output[new_symbol_offset : new_symbol_offset + len(expected_symbols)] = expected_symbols
    seed_debug_s_raw = coff_body(seed, seed_closure[".debug$S"])
    donor_debug_s_raw = coff_body(donor, donor_closure[".debug$S"])
    require(
        len(seed_debug_s_raw) == len(donor_debug_s_raw) >= 28,
        "CodeView procedure record size changed or is truncated",
    )
    require(
        seed_debug_s_raw[2:4] == donor_debug_s_raw[2:4] == b"\x05\x02",
        "associated CodeView record is not S_*PROC32",
    )
    donor_cbproc, donor_dbgstart, donor_dbgend = struct.unpack_from("<III", donor_debug_s_raw, 16)
    require(
        donor_cbproc == donor_primary["raw_size"]
        and 0 <= donor_dbgstart <= donor_dbgend < donor_cbproc,
        "donor CodeView procedure range is invalid",
    )
    expected_debug_s = bytearray(seed_debug_s_raw)
    expected_debug_s[16:28] = donor_debug_s_raw[16:28]
    debug_s_offset = shifted_pointer(seed_closure[".debug$S"]["raw_offset"], replacements)
    output[debug_s_offset : debug_s_offset + len(expected_debug_s)] = expected_debug_s
    seed_debug_f_raw = coff_body(seed, seed_closure[".debug$F"])
    donor_debug_f_raw = coff_body(donor, donor_closure[".debug$F"])
    seed_fpo = parse_fpo_data(seed_debug_f_raw, expected_proc_size=seed_primary["raw_size"])
    donor_fpo = parse_fpo_data(donor_debug_f_raw, expected_proc_size=donor_primary["raw_size"])
    require(
        exact_json_equal(donor_fpo, function["expected_donor_fpo"]),
        "compiler donor FPO record differs from the manifest pin",
    )
    require(
        donor_fpo["cbProcSize"] == donor_cbproc, "donor FPO and CodeView procedure sizes differ"
    )
    debug_f_offset = shifted_pointer(seed_closure[".debug$F"]["raw_offset"], replacements)
    output[debug_f_offset : debug_f_offset + 16] = donor_debug_f_raw
    output_bytes = bytes(output)
    checked = CoffObject(output_bytes)
    checked_primary = checked.function_section(mangled)
    require(
        len(output_bytes) == len(seed_bytes) + total_delta,
        "composed COFF file length delta is wrong",
    )
    require(
        function_multiset(checked) == function_multiset(seed),
        "composed COFF function multiset changed",
    )
    require(
        coff_body(checked, checked_primary) == donor_body,
        "composed target body differs from compiler donor",
    )
    require(
        coff_table(checked, checked_primary, "lines") == donor_lines,
        "composed COFF line table differs from normalized donor",
    )
    checked_relocations = detailed_relocations(checked, checked_primary)
    require(
        [
            (row["offset"], row["symbol_index"], row["type"], row["addend"])
            for row in checked_relocations
        ]
        == [
            (donor_row["offset"], seed_row["symbol_index"], donor_row["type"], donor_row["addend"])
            for seed_row, donor_row in zip(seed_relocations, donor_relocations)
        ],
        "composed primary relocation table is incoherent",
    )
    checked_definitions = section_definitions(checked)
    checked_associated = associated_sections(
        checked, checked_definitions, checked_primary["number"]
    )
    require(checked_associated == seed_associated, "composed associative closure changed")
    expected_closure_raw = {
        seed_closure[".debug$S"]["number"]: bytes(expected_debug_s),
        seed_closure[".debug$F"]["number"]: donor_debug_f_raw,
    }
    for before, after in zip(seed.sections, checked.sections):
        require(
            before["number"] == after["number"]
            and before["name"] == after["name"]
            and (before["characteristics"] == after["characteristics"]),
            "composed section order/characteristics changed",
        )
        number = before["number"]
        if number in expected_closure_raw:
            require(
                coff_body(checked, after) == expected_closure_raw[number],
                f"composed debug closure raw bytes differ: section {number}",
            )
            require(
                coff_table(seed, before, "relocations")
                == coff_table(checked, after, "relocations"),
                f"composed debug closure relocations changed: section {number}",
            )
        elif number != seed_primary["number"]:
            require(
                coff_body(seed, before) == coff_body(checked, after),
                f"non-target raw section changed: section {number}",
            )
            require(
                coff_table(seed, before, "relocations")
                == coff_table(checked, after, "relocations"),
                f"non-target relocation table changed: section {number}",
            )
        if number != seed_primary["number"]:
            require(
                coff_table(seed, before, "lines") == coff_table(checked, after, "lines"),
                f"non-target COFF line table changed: section {number}",
            )
    require(
        checked.data[checked.symbol_offset : checked.symbol_offset + checked.symbol_count * 18]
        == bytes(expected_symbols),
        "composed symbol/auxiliary table differs from the proven reconstruction",
    )
    checked_function_index, checked_function = function_symbol(
        checked, mangled, checked_primary["number"]
    )
    checked_function_auxiliary = coff_auxiliary(checked, checked_function_index, checked_function)
    require(
        struct.unpack_from("<I", checked_function_auxiliary, 4)[0] == donor_primary["raw_size"]
        and struct.unpack_from("<I", checked_function_auxiliary, 8)[0]
        == checked_primary["line_offset"],
        "composed Function Definition auxiliary record is stale",
    )
    checked_begin_index, checked_begin = marker_symbol(checked, ".bf", checked_primary["number"])
    require(
        coff_auxiliary(checked, checked_begin_index, checked_begin)[4:6]
        == donor_begin_auxiliary[4:6],
        "composed .bf line is stale",
    )
    checked_end_index, checked_end = marker_symbol(checked, ".ef", checked_primary["number"])
    require(
        checked_end["value"] == donor_primary["raw_size"]
        and coff_auxiliary(checked, checked_end_index, checked_end)
        == coff_auxiliary(donor, donor_end_index, donor_end),
        "composed .ef metadata differs from donor",
    )
    checked_section_index, checked_section_symbol = section_symbol(checked, checked_primary)
    require(
        coff_auxiliary(checked, checked_section_index, checked_section_symbol)
        == donor_section_auxiliary,
        "composed Section Definition auxiliary record differs from donor",
    )
    require(
        not any((identifier.encode("ascii") in output_bytes for identifier in shape_identifiers)),
        "declaration-shape identifiers leaked into the composed object",
    )
    return (
        output_bytes,
        {
            "mangled": mangled,
            "address": function["retail_oracle"]["address"],
            "retail_oracle": dict(function["retail_oracle"]),
            "retail_payload_bytes_read": 0,
            "section_number": checked_primary["number"],
            "seed_length": seed_primary["raw_size"],
            "donor_length": donor_primary["raw_size"],
            "linked_span": function["expected_linked_span"],
            "file_size_delta": total_delta,
            "relocation_count": len(checked_relocations),
            "relocation_offsets_moved": sum(
                (
                    left["offset"] != right["offset"]
                    for left, right in zip(seed_relocations, donor_relocations)
                )
            ),
            "local_symbols_updated": len(compatibility["local_updates"]),
            "function_line_pointers_shifted": shifted_function_line_pointers,
            "coff_line_policy": "whole_donor_normalized_function_index",
            "coff_line_rows": donor_primary["line_count"],
            "codeview_policy": "seed_types_names_locals_with_donor_cbProc_DbgStart_DbgEnd",
            "codeview_range": {
                "cbProc": donor_cbproc,
                "DbgStart": donor_dbgstart,
                "DbgEnd": donor_dbgend,
            },
            "fpo_policy": "whole_donor_debug_F_record",
            "seed_fpo": seed_fpo,
            "donor_fpo": donor_fpo,
            "target_body_sha256": sha256_bytes(donor_body),
            "input_sha256": sha256_bytes(seed_bytes),
            "donor_sha256": sha256_bytes(donor_bytes),
            "output_sha256": sha256_bytes(output_bytes),
            "provenance": provenance,
        },
    )
