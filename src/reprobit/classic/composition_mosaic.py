"""Classic compiler algorithms: retail-exact instruction mosaic candidates."""

from __future__ import annotations

import itertools
from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    coff_body,
    coff_unpack,
    detailed_relocations,
    section_definitions,
)

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
    function_symbol,
)
from .composition_fpo_identity import (
    require_ordinary_fpo_mosaic_identity,
    require_ordinary_fpo_self_permutation_receipts,
    require_self_permutation_receipts,
    require_source_fpo_mosaic_identity,
)
from .composition_relocations import (
    MOSAIC_PERMUTED_RELOCATION_ORDER,
    require_instruction_mosaic_semantic_relocations,
    require_same_semantic_relocations,
)
from .debug import (
    _apply_replacements,
)
from .foundation import (
    canonical_json_bytes,
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import (
    EH_CLOSURE_CHILDREN,
    ORDINARY_FPO_CLOSURE_CHILDREN,
    require_coff_line_certified_ia32_boundaries,
    require_declared_relocation_semantics,
    validate_instruction_mosaic_ranges,
    validate_instruction_self_permutation,
)
from .source_proofs import (
    require_target_source_refactor_identity,
)


def instruction_mosaic_metadata_sha256(coff: CoffObject, primary: dict[str, Any]) -> str:
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
    primary: dict[str, Any],
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


def _validate_instruction_mosaic_source_variant(
    seed: CoffObject,
    seed_primary: dict[str, Any],
    donor_bytes: bytes,
    function: dict[str, Any],
    variant: dict[str, Any],
    context: str,
    reseat_windows: list[tuple[int, int]] | None = None,
) -> tuple[CoffObject, dict[str, Any], bytes]:
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
            seed_primary[field] == primary[field]
            for field in ("name", "relocation_count", "characteristics")
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
            and all(left[field] == right[field] for field in ("name", "characteristics")),
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
    function: dict[str, Any],
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict[str, Any]]:
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


def _instruction_mosaic_range_donor_label(item: dict[str, Any], primary_donor_id: str) -> str:
    """Name a range's donor from current typed intervention authority."""
    return item.get("donor", primary_donor_id)


def _produce_instruction_mosaic_candidate_core(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    source_permutation: bool,
    primary_donor_id: str,
) -> tuple[bytes, dict[str, Any]]:
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
        all(item.get("donor", primary_donor_id) in declared_donor_ids for item in ranges),
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
                item["kind"] == "same_offset_complete_x86_instruction_sequence_v1"
                for item in ranges
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
        all(sp[field] == dp[field] for field in common_header_fields),
        "instruction-mosaic target section header changed",
    )
    if not source_permutation:
        require(
            all(sp[field] == dp[field] for field in ("raw_size", "line_count")),
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
            all(left[field] == right[field] for field in ("name", "characteristics")),
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
                item["end"] <= permutation["target_start"]
                or item["start"] >= permutation["target_end"]
                for item in ranges
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
        for role, section, line_bytes in (
            ("seed", sp, seed_lines),
            ("donor", dp, donor_lines),
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
        for role, rows, _body in (
            ("seed", seed_rows, seed_body),
            ("donor", donor_rows, donor_body),
        ):
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
                    strict=True,
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
                    strict_fields = tuple(field for field in strict_fields if field != "target")
            require(
                all(left[field] == right[field] for field in strict_fields),
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
                all(end <= row["offset"] or start >= row["offset"] + row["width"] for row in rows),
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
                    for a, b in itertools.pairwise(output_rows)
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
                sp["raw_offset"] + item["target_start"],
                sp["raw_offset"] + item["target_end"],
                donor_body[item["donor_start"] : item["donor_end"]],
            )
            for item in permutation["moves"]
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
        index
        for index, (before, after) in enumerate(zip(seed_bytes, output, strict=True))
        if before != after
    }
    allowed_file_offsets = {
        sp["raw_offset"] + offset for item in ranges for offset in range(item["start"], item["end"])
    }
    if self_permutation:
        allowed_file_offsets.update(
            sp["raw_offset"] + offset
            for item in permutation["moves"]
            for offset in range(item["target_start"], item["target_end"])
        )
    allowed_file_offsets |= reseat_file_offsets
    require(
        changed_file_offsets and changed_file_offsets <= allowed_file_offsets,
        "instruction mosaic changed a non-target byte",
    )
    if self_permutation:
        changed_body_offsets = sorted(offset - sp["raw_offset"] for offset in changed_file_offsets)
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
                offset - sp["raw_offset"] for offset in changed_file_offsets - reseat_file_offsets
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
    function: dict[str, Any],
    additional_donor_bytes: dict[str, bytes] | None = None,
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict[str, Any]]:
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
    function: dict[str, Any],
    seed_source: bytes,
    donor_source: bytes,
    additional_donor_bytes: dict[str, bytes] | None = None,
    *,
    primary_donor_id: str,
) -> tuple[bytes, dict[str, Any]]:
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
