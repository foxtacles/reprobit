"""Classic compiler algorithms: rewriting."""

from __future__ import annotations

from typing import Any

from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import CoffObject, coff_body, detailed_relocations, section_definitions

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .commutative import apply_commutative_operand_form
from .compiler_identity import Msvc420CompilerIdentity
from .composition import compose_equal_body_comdat
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_same_slot import compose_same_slot_resize
from .debug import parse_codeview_symbol_stream
from .floating import apply_fp_sum_reassociation, apply_x87_squared_addend_exchange
from .foundation import (
    RelocationView,
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import require_declared_relocation_semantics
from .register_bijection import (
    CODEVIEW_REGISTER_RECORD_TYPE,
    REGISTER_BIJECTION_FPO_CLOSURE,
    _codeview_register_field,
    _codeview_register_name,
    apply_codeview_register_bijection,
    apply_register_bijection,
)
from .register_reencoding import apply_slot_bijection
from .register_semantics import (
    decode_ia32_bijection_body,
)
from .relational import (
    apply_relational_form,
    relational_form_external_entries,
)
from .rewriting_certificates import DONOR_REWRITING_KIND
from .rewriting_exchanges import apply_esp_argument_exchange, apply_fp_pointer_exchange
from .rewriting_region_simulation import apply_simulated_region_rewrite
from .scheduling import INSTRUCTION_SCHEDULE_EH_CLOSURE, INSTRUCTION_SCHEDULE_FPO_CLOSURE
from .scheduling_apply import apply_instruction_schedule
from .scheduling_certificates import require_instruction_schedule_debug_fidelity

COMPOSED_REWRITING_CLASS = "retail_exact_composed_rewriting"


def composed_rewriting_delegate(expected_closure: object) -> str:
    """Name the installation delegate from the closure pin alone.

    The installed object is the SEED with its own body replaced, so there is
    no donor rename to express and no relocation to move: the FPO closure
    takes the strict primitive and the EH closure takes the structural-local
    one, whose rename and xdata-rename sets are then required to be empty.
    """
    if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE:
        return "equal_body_strict"
    return "equal_body_eh_structural_local"


def produce_composed_rewriting_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Apply a reordering, then regional bijections, then reversed compares.

    See the class comment above.  Each primitive is the LANDED one, called
    unchanged; C1 fixes the order, C2 the disjointness, C3 the debug$S
    claims and C4 the provenance. Literal comparison is verifier-only.
    """
    require_payload_free_declaration(function, "composed-rewriting declaration")
    require(
        function.get("splice_class") == COMPOSED_REWRITING_CLASS,
        "splice class is not retail_exact_composed_rewriting",
    )
    require(
        "target_source_refactor" not in function,
        "composed-rewriting functions carry no source refactor",
    )
    spec = function["composed_rewriting"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == function["expected_section_number"]
        and dp["number"] == function["expected_donor_section_number"],
        f"composed-rewriting target section seat changed: seed {sp['number']} donor {dp['number']}",
    )
    require(
        len(seed.sections) == function["expected_section_count"]
        and len(donor.sections) == function["expected_donor_section_count"],
        f"composed-rewriting global section count changed: seed {len(seed.sections)} donor {len(donor.sections)}",
    )
    seed_functions = function_multiset(seed)
    require(
        seed_functions == function_multiset(donor)
        and sum(seed_functions.values()) == function["expected_function_count"],
        f"composed-rewriting witness function set differs: {sum(seed_functions.values())} vs {sum(function_multiset(donor).values())}",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(
        seed_comdats == comdat_primary_identity_multiset(donor)
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        f"composed-rewriting witness COMDAT identity set differs: {sum(seed_comdats.values())} vs {sum(comdat_primary_identity_multiset(donor).values())}",
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
        f"composed-rewriting target header/count pins changed: raw {sp['raw_size']}/{dp['raw_size']} relocations {sp['relocation_count']}/{dp['relocation_count']} lines {sp['line_count']}/{dp['line_count']} characteristics {sp['characteristics']}/{dp['characteristics']}",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        f"composed-rewriting COMDAT selection changed: {section_definitions(seed)[sp['number']]['selection']}",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        f"composed-rewriting target closure changed: seed {_comdat_child_closure(seed, sp)} donor {_comdat_child_closure(donor, dp)}",
    )
    require(
        list(expected_closure)
        in (INSTRUCTION_SCHEDULE_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "composed-rewriting closure pin names no installation delegate",
    )
    delegate = composed_rewriting_delegate(function["expected_closure"])
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        f"composed-rewriting metadata differs from its pin: seed {instruction_mosaic_metadata_sha256(seed, sp)} donor {instruction_mosaic_metadata_sha256(donor, dp)}",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        f"composed-rewriting seed/witness body differs from its pin: seed {sha256_bytes(seed_body)} witness {sha256_bytes(donor_body)}",
    )
    require(
        donor_body == seed_body, "composed-rewriting witness does not reproduce the seed's body"
    )
    seed_rows = detailed_relocations(seed, sp)
    relocation_offsets = frozenset(
        row["offset"] + byte for row in seed_rows for byte in range(row["width"])
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in seed_rows
    }
    internal_targets = frozenset(
        row["target_value"] for row in seed_rows if row["target_section"] == sp["number"]
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "composed-rewriting in-body relocated target set changed",
        )
    code_length = spec.get("expected_code_length")
    view = RelocationView(
        relocations=relocation_symbols, code_length=code_length, internal_targets=internal_targets
    )
    image = seed_body
    external_entries = relational_form_external_entries(
        seed, sp, "composed-rewriting external entries"
    )
    require(
        sorted(external_entries) == spec["expected_external_entries"],
        "composed-rewriting external entry set differs from its declaration",
    )
    schedule_detail = []
    windows = spec.get("windows") or []
    if windows:
        image, schedule_proof = apply_instruction_schedule(
            image,
            windows,
            relocation_offsets,
            "composed-rewriting schedule",
            view=view,
            external_entries=frozenset(external_entries),
            compiler_identity=compiler_identity,
        )
        require(
            not schedule_proof["relocation_reseat"],
            "composed-rewriting refuses to move a relocation",
        )
        schedule_detail = schedule_proof["windows"]
    fp_detail = []
    if spec.get("fp_sum_rotations"):
        image, fp_proof = apply_fp_sum_reassociation(
            image,
            spec["fp_sum_rotations"],
            relocation_offsets,
            "composed-rewriting fp-sum",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, chain) in enumerate(
            zip(spec["fp_sum_rotations"], fp_proof["chains"], strict=False)
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting fp-sum chain {index} rewrote a different byte set from its declaration",
            )
        fp_detail = fp_proof["chains"]
    x87_detail = []
    x87_relocation_moves = {}
    if spec.get("x87_squared_addend_exchanges"):
        image, x87_proof = apply_x87_squared_addend_exchange(
            image,
            spec["x87_squared_addend_exchanges"],
            relocation_offsets,
            "composed-rewriting x87 exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        seed_row_offsets = {row["offset"] for row in seed_rows}
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, chain) in enumerate(
            zip(spec["x87_squared_addend_exchanges"], x87_proof["chains"], strict=False)
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting x87 exchange {index} rewrote a different byte set from its declaration",
            )
            for old_at, new_at in chain["relocation_reseat"]:
                require(
                    old_at in seed_row_offsets,
                    f"composed-rewriting x87 exchange {index} reseats an offset that heads no seed relocation record",
                )
                require(
                    old_at not in x87_relocation_moves,
                    f"composed-rewriting x87 exchange {index} reseats a relocation twice",
                )
                x87_relocation_moves[old_at] = new_at
        x87_detail = x87_proof["chains"]
    region_rewrite_detail = []
    if spec.get("simulated_region_rewrites"):
        image, region_proof = apply_simulated_region_rewrite(
            image,
            spec["simulated_region_rewrites"],
            relocation_offsets,
            "composed-rewriting simulated rewrite",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        require(
            not region_proof["relocation_reseat"], "composed-rewriting refuses to move a relocation"
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, region) in enumerate(
            zip(spec["simulated_region_rewrites"], region_proof["regions"], strict=False)
        ):
            require(
                region["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting simulated rewrite {index} rewrote a different byte set from its declaration",
            )
        region_rewrite_detail = region_proof["regions"]
    form_detail = []
    if spec.get("commutative_operand_forms"):
        image, form_proof = apply_commutative_operand_form(
            image,
            spec["commutative_operand_forms"],
            relocation_offsets,
            "composed-rewriting commutative form",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, site) in enumerate(
            zip(spec["commutative_operand_forms"], form_proof["sites"], strict=False)
        ):
            require(
                site["expected_rewritten_offsets"] == item["expected_rewritten_offsets"]
                and site["pair_offset"] == item["pair_offset"]
                and (site["operation"] == item["operation"]),
                f"composed-rewriting commutative form {index} rewrote a different site from its declaration",
            )
        form_detail = form_proof["sites"]
    exchange_site_detail = []
    if spec.get("esp_argument_exchanges"):
        image, exchange_site_proof = apply_esp_argument_exchange(
            image,
            spec["esp_argument_exchanges"],
            relocation_offsets,
            "composed-rewriting argument exchange",
            relocation_symbols,
            code_length,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, site) in enumerate(
            zip(spec["esp_argument_exchanges"], exchange_site_proof["sites"], strict=False)
        ):
            require(
                site["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting argument exchange {index} rewrote a different byte set from its declaration",
            )
        exchange_site_detail = exchange_site_proof["sites"]
    bijection_detail = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        image, proof = apply_register_bijection(
            image,
            item["mapping"],
            (item["region_start"], item["region_end"]),
            relocation_offsets,
            f"composed-rewriting bijection {index}",
            relocation_symbols,
            code_length,
            internal_targets,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"composed-rewriting bijection {index} rewrote a different byte set from its declaration",
        )
        require(
            proof["region_instruction_count"] == item["expected_region_instruction_count"],
            f"composed-rewriting bijection {index} region instruction count differs from its declaration",
        )
        bijection_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "region": [item["region_start"], item["region_end"]],
                "rewritten_offsets": proof["rewritten_offsets"],
                "region_instruction_count": proof["region_instruction_count"],
            }
        )
    slot_detail = []
    for index, item in enumerate(spec.get("slot_bijections") or []):
        image, proof = apply_slot_bijection(
            image,
            item["mapping"],
            relocation_offsets,
            f"composed-rewriting slot bijection {index}",
            relocation_symbols,
            code_length,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"composed-rewriting slot bijection {index} rewrote a different byte set from its declaration",
        )
        slot_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "rewritten_offsets": proof["rewritten_offsets"],
            }
        )
    relational_detail = []
    if spec.get("relational_sites"):
        sites = [
            {
                key: item[key]
                for key in (
                    "compare_offset",
                    "branch_offset",
                    "seed_condition",
                    "image_condition",
                    "reencode",
                )
                if key in item
            }
            for item in spec["relational_sites"]
        ]
        image, proof = apply_relational_form(
            image,
            sites,
            relocation_offsets,
            "composed-rewriting relational",
            relocation_symbols,
            code_length,
            external_entries,
        )
        require(
            proof["rewritten_offsets"]
            == sorted(
                offset
                for item in spec["relational_sites"]
                for offset in item["expected_rewritten_offsets"]
            ),
            "composed-rewriting relational rewrite set differs from its declaration",
        )
        relational_detail = proof["sites"]
    require(image != seed_body, "composed-rewriting image does not move the seed body")
    image_instructions = decode_ia32_bijection_body(
        image, "composed-rewriting image", relocation_symbols, code_length
    )
    require(
        len(image_instructions) == spec["expected_instruction_count"],
        "composed-rewriting instruction count differs from its declaration",
    )
    changed = sorted(index for index in range(len(seed_body)) if seed_body[index] != image[index])
    require(
        changed == spec["expected_changed_offsets"],
        "composed-rewriting image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "composed-rewriting image differs from its pin",
    )
    require(
        changed == function["expected_changed_offsets"],
        "composed-rewriting changed offsets differ from their pin",
    )
    line_moves = {}
    for region in region_rewrite_detail:
        for old_at, new_at in region["instruction_moves"]:
            line_moves[old_at] = new_at
    for chain in x87_detail:
        for old_at, new_at in chain["instruction_moves"]:
            line_moves[old_at] = new_at
    lined_seed_bytes = bytearray(seed_bytes)
    if line_moves:
        table_at = sp["line_offset"]
        rows_lined = []
        for position in range(1, sp["line_count"]):
            entry_at = table_at + position * 6
            old_off = int.from_bytes(lined_seed_bytes[entry_at : entry_at + 4], "little")
            line_no = int.from_bytes(lined_seed_bytes[entry_at + 4 : entry_at + 6], "little")
            rows_lined.append((line_moves.get(old_off, old_off), line_no))
        rows_lined.sort()
        for position, (offset, line_no) in enumerate(rows_lined, start=1):
            entry_at = table_at + position * 6
            lined_seed_bytes[entry_at : entry_at + 4] = offset.to_bytes(4, "little")
            lined_seed_bytes[entry_at + 4 : entry_at + 6] = line_no.to_bytes(2, "little")
    installed_rows = seed_rows
    if x87_relocation_moves:
        table_at = sp["relocation_offset"]
        records = []
        for position in range(sp["relocation_count"]):
            entry_at = table_at + position * 10
            record = bytearray(lined_seed_bytes[entry_at : entry_at + 10])
            old_at = int.from_bytes(record[0:4], "little")
            if old_at in x87_relocation_moves:
                record[0:4] = x87_relocation_moves[old_at].to_bytes(4, "little")
            records.append(bytes(record))
        records.sort(key=lambda record: int.from_bytes(record[0:4], "little"))
        lined_seed_bytes[table_at : table_at + sp["relocation_count"] * 10] = b"".join(records)
        installed_rows = sorted(
            [
                {**row, "offset": x87_relocation_moves.get(row["offset"], row["offset"])}
                for row in seed_rows
            ],
            key=lambda row: row["offset"],
        )
        installed_rows = [
            {**row, "ordinal": position} for position, row in enumerate(installed_rows)
        ]
    moved_tables = bool(line_moves) or bool(x87_relocation_moves)
    lined_seed = CoffObject(bytes(lined_seed_bytes)) if moved_tables else seed
    lined_sp = lined_seed.function_section(mangled) if moved_tables else sp
    debug_detail = require_instruction_schedule_debug_fidelity(
        lined_seed,
        lined_sp,
        image,
        windows,
        spec,
        mangled,
        "composed-rewriting debug fidelity",
        view=view,
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "composed-rewriting linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "composed-rewriting candidate relocation semantics",
    )
    derived = bytearray(lined_seed_bytes)
    derived[sp["raw_offset"] : sp["raw_offset"] + sp["raw_size"]] = image
    effective = {
        "mangled": mangled,
        "splice_class": delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    require(
        function["expected_code_renames"] == [] and function["expected_xdata_rename_offsets"] == [],
        "composed-rewriting installs the seed's own tables and can declare no rename",
    )
    if delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = []
        effective["expected_xdata_rename_offsets"] = []
    composed, detail = compose_equal_body_comdat(bytes(lined_seed_bytes), bytes(derived), effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        coff_body(checked, cp) == image, "composed-rewriting composed body differs from the image"
    )
    require(
        detailed_relocations(checked, cp) == installed_rows
        and _coff_table_bytes(checked, cp, "relocations")
        == _coff_table_bytes(lined_seed, lined_sp, "relocations")
        and (
            _coff_table_bytes(checked, cp, "lines")
            == _coff_table_bytes(lined_seed, lined_sp, "lines")
        ),
        "composed-rewriting output changed seed relocation/line bytes",
    )
    debug_child = _comdat_child(checked, cp, ".debug$S")
    debug_stream = coff_body(checked, debug_child)
    require(
        sha256_bytes(debug_stream) == spec["expected_seed_debug_s_sha256"],
        "composed-rewriting debug$S differs from its pin",
    )
    claimed = {}
    for index, item in enumerate(spec.get("register_bijections") or []):
        for record in parse_codeview_symbol_stream(debug_stream, "composed-rewriting debug$S"):
            if record["type"] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(record, "composed-rewriting debug$S")
            try:
                name = _codeview_register_name(debug_stream, field_at, "composed-rewriting debug$S")
            except ByteIdentityError:
                continue
            if name not in item["mapping"]:
                continue
            require(
                record["offset"] not in claimed,
                f"composed-rewriting bijections {claimed.get(record['offset'])} and {index} both name the S_REGISTER record {record['name']!r}",
            )
            claimed[record["offset"]] = index
    debug_image = debug_stream
    debug_maps = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        mapped = apply_codeview_register_bijection(
            debug_stream,
            item["mapping"],
            item["debug_s_register_map"],
            f"composed-rewriting debug$S bijection {index}",
        )
        moved = bytearray(debug_image)
        for position in range(len(debug_stream)):
            if mapped[position] != debug_stream[position]:
                moved[position] = mapped[position]
        debug_image = bytes(moved)
        debug_maps.append(item["debug_s_register_map"])
    for item in spec.get("slot_bijections") or []:
        slot_map = {int(key): value for key, value in item["mapping"].items()}
        declared = set(item["debug_s_bprel_offsets"])
        moved = bytearray(debug_image)
        seen = set()
        for record in parse_codeview_symbol_stream(
            debug_stream, "composed-rewriting debug$S bprel"
        ):
            if record["type"] != 512:
                continue
            field_at = record["offset"] + 4
            off_value = int.from_bytes(debug_stream[field_at : field_at + 4], "little", signed=True)
            if off_value in slot_map:
                require(
                    record["offset"] in declared,
                    f"composed-rewriting slot bijection misses the S_BPREL32 record at {record['offset']}",
                )
                seen.add(record["offset"])
                moved[field_at : field_at + 4] = slot_map[off_value].to_bytes(
                    4, "little", signed=True
                )
        require(
            seen == declared,
            "composed-rewriting slot bijection declares an S_BPREL32 record that names no mapped slot",
        )
        debug_image = bytes(moved)
    require(
        sha256_bytes(debug_image) == spec["expected_image_debug_s_sha256"],
        "composed-rewriting mapped debug$S differs from its pin",
    )
    composed = bytearray(composed)
    composed[debug_child["raw_offset"] : debug_child["raw_offset"] + debug_child["raw_size"]] = (
        debug_image
    )
    composed = bytes(composed)
    final = CoffObject(composed)
    fp = final.function_section(mangled)
    require(coff_body(final, fp) == image, "composed-rewriting output changed the installed body")
    for child_name in expected_closure:
        if child_name == ".debug$S":
            continue
        require(
            coff_body(final, _comdat_child(final, fp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"composed-rewriting output changed its {child_name} child",
        )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    allowed |= set(
        range(debug_child["raw_offset"], debug_child["raw_offset"] + debug_child["raw_size"])
    )
    if line_moves:
        allowed |= set(range(sp["line_offset"], sp["line_offset"] + sp["line_count"] * 6))
        require(
            _coff_table_bytes(
                CoffObject(composed), CoffObject(composed).function_section(mangled), "lines"
            )
            == _coff_table_bytes(lined_seed, lined_sp, "lines"),
            "composed-rewriting line rows differ from the proved moves",
        )
    if x87_relocation_moves:
        allowed |= set(
            range(sp["relocation_offset"], sp["relocation_offset"] + sp["relocation_count"] * 10)
        )
        require(
            _coff_table_bytes(
                CoffObject(composed), CoffObject(composed).function_section(mangled), "relocations"
            )
            == _coff_table_bytes(lined_seed, lined_sp, "relocations"),
            "composed-rewriting relocation records differ from the proved reseat",
        )
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "composed-rewriting changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": COMPOSED_REWRITING_CLASS,
            "instruction_schedule": schedule_detail,
            "fp_sum_reassociation": fp_detail,
            "commutative_operand_forms": form_detail,
            "esp_argument_exchanges": exchange_site_detail,
            "x87_squared_addend_exchanges": x87_detail,
            "simulated_region_rewrites": region_rewrite_detail,
            "register_bijections": bijection_detail,
            "slot_bijections": slot_detail,
            "relational_form": relational_detail,
            "instruction_count": len(image_instructions),
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "debug_s_register_maps": debug_maps,
            "external_entries": sorted(external_entries),
            "candidate_only": True,
            **semantic_detail,
        },
    )


DONOR_REWRITING_CLASS = "retail_exact_donor_rewriting"


def produce_donor_rewriting_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Produce REWRITE(donor body) from a fresh compiler artifact."""
    require_payload_free_declaration(function, "donor-rewriting declaration")
    require(
        function.get("splice_class") == DONOR_REWRITING_CLASS,
        "splice class is not retail_exact_donor_rewriting",
    )
    require(
        "target_source_refactor" not in function,
        "donor-rewriting functions carry no source refactor",
    )
    spec = function["donor_rewriting"]
    require(spec["kind"] == DONOR_REWRITING_KIND, "donor-rewriting kind differs")
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    declared_donor_seat = function.get("expected_donor_section_number")
    if declared_donor_seat is None:
        require(
            sp["number"] == dp["number"] == function["expected_section_number"],
            "donor-rewriting target section seat changed",
        )
    else:
        require(
            sp["number"] == function["expected_section_number"]
            and dp["number"] == declared_donor_seat,
            "donor-rewriting declared donor seat changed",
        )
    require(
        len(seed.sections) == function["expected_section_count"]
        and len(donor.sections)
        == function.get("expected_donor_section_count", function["expected_section_count"]),
        "donor-rewriting global section count changed",
    )
    extras = sorted(function.get("expected_donor_extra_functions") or [])
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    measured_extra = []
    for name in set(seed_functions) | set(donor_functions):
        left = seed_functions.get(name, 0)
        right = donor_functions.get(name, 0)
        if right == left:
            continue
        require(right == left + 1, f"donor-rewriting donor function census diverges at {name}")
        measured_extra.append(name)
    require(
        sorted(measured_extra) == extras
        and sum(seed_functions.values()) == function["expected_function_count"],
        "donor-rewriting donor function set differs from its declared extras",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    extra_heads = []
    for key in set(seed_comdats) | set(donor_comdats):
        left = seed_comdats.get(key, 0)
        right = donor_comdats.get(key, 0)
        if right == left:
            continue
        require(right == left + 1, f"donor-rewriting donor COMDAT census diverges at {key}")
        extra_heads.append(key[0])
    require(
        sorted(extra_heads) == extras
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "donor-rewriting donor COMDAT identity set differs from its declared extras",
    )
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_donor_length"]
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
        "donor-rewriting target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "donor-rewriting COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure)
        and list(expected_closure)
        in (REGISTER_BIJECTION_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "donor-rewriting target closure is neither the FPO debug pair nor the EH pair",
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "donor-rewriting metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = bytes(coff_body(donor, dp))
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "donor-rewriting seed/donor body differs from its pin",
    )
    donor_rows = detailed_relocations(donor, dp)

    def _relocation_identity(row: dict[str, Any]) -> tuple[Any, ...]:
        if row["target_storage"] in (3, 6) and row["target"].startswith("$"):
            return (
                "static",
                row["type"],
                row["addend"],
                row["target_section"],
                row["target_value"],
                row["target_type"],
            )
        if row["target_storage"] == 3:
            base, sep, serial = row["target"].rpartition("$S")
            if sep and base and serial.isdigit():
                return (
                    "static-s",
                    row["type"],
                    row["addend"],
                    base,
                    row["target_section"],
                    row["target_value"],
                    row["target_type"],
                )
        return (
            "named",
            row["type"],
            row["addend"],
            row["target"],
            row["target_type"],
            row["target_storage"],
        )

    seed_rows_d1 = detailed_relocations(seed, sp)
    divergences = {
        item[0]: (item[1], item[2])
        for item in function.get("expected_relocation_divergences") or []
    }
    require(
        len(donor_rows) == len(seed_rows_d1),
        "donor-rewriting relocation count differs from the seed",
    )
    for ordinal, (donor_row, seed_row) in enumerate(zip(donor_rows, seed_rows_d1, strict=True)):
        if ordinal in divergences:
            expected_seed, expected_donor = divergences[ordinal]
            require(
                seed_row["target"] == expected_seed and donor_row["target"] == expected_donor,
                f"donor-rewriting declared divergence {ordinal} differs ({seed_row['target']} -> {donor_row['target']})",
            )
            continue
        require(
            _relocation_identity(donor_row) == _relocation_identity(seed_row),
            f"donor-rewriting donor relocation target {ordinal} differs from the seed",
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
            "donor-rewriting in-body relocated target set changed",
        )
    code_length = spec.get("expected_code_length")
    view = RelocationView(
        relocations=relocation_symbols, code_length=code_length, internal_targets=internal_targets
    )
    external_entries = relational_form_external_entries(
        donor, dp, "donor-rewriting external entries"
    )
    require(
        sorted(external_entries) == spec["expected_external_entries"],
        "donor-rewriting external entry set differs from its declaration",
    )
    image = donor_body
    bijection_detail = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        image, proof = apply_register_bijection(
            image,
            item["mapping"],
            (item["region_start"], item["region_end"]),
            relocation_offsets,
            f"donor-rewriting bijection {index}",
            relocation_symbols,
            code_length,
            internal_targets,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"donor-rewriting bijection {index} rewrote a different byte set from its declaration",
        )
        require(
            proof["region_instruction_count"] == item["expected_region_instruction_count"],
            f"donor-rewriting bijection {index} region instruction count differs from its declaration",
        )
        bijection_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "region": [item["region_start"], item["region_end"]],
                "rewritten_offsets": proof["rewritten_offsets"],
                "region_instruction_count": proof["region_instruction_count"],
            }
        )
    slot_detail = []
    for index, item in enumerate(spec.get("slot_bijections") or []):
        image, proof = apply_slot_bijection(
            image,
            item["mapping"],
            relocation_offsets,
            f"donor-rewriting slot bijection {index}",
            relocation_symbols,
            code_length,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"donor-rewriting slot bijection {index} rewrote a different byte set from its declaration",
        )
        slot_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "rewritten_offsets": proof["rewritten_offsets"],
            }
        )
    fp_detail = []
    if spec.get("fp_sum_rotations"):
        image, fp_proof = apply_fp_sum_reassociation(
            image,
            spec["fp_sum_rotations"],
            relocation_offsets,
            "donor-rewriting fp-sum",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, chain) in enumerate(
            zip(spec["fp_sum_rotations"], fp_proof["chains"], strict=False)
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting fp-sum chain {index} rewrote a different byte set from its declaration",
            )
        fp_detail = fp_proof["chains"]
    exchange_detail = []
    if spec.get("fp_pointer_exchanges"):
        image, exchange_proof = apply_fp_pointer_exchange(
            image,
            spec["fp_pointer_exchanges"],
            relocation_offsets,
            "donor-rewriting fp-exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, exchange) in enumerate(
            zip(spec["fp_pointer_exchanges"], exchange_proof["exchanges"], strict=False)
        ):
            require(
                exchange["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting fp-exchange {index} rewrote a different byte set from its declaration",
            )
        exchange_detail = exchange_proof["exchanges"]
    form_detail = []
    if spec.get("commutative_operand_forms"):
        image, form_proof = apply_commutative_operand_form(
            image,
            spec["commutative_operand_forms"],
            relocation_offsets,
            "donor-rewriting commutative form",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, site) in enumerate(
            zip(spec["commutative_operand_forms"], form_proof["sites"], strict=False)
        ):
            require(
                site["expected_rewritten_offsets"] == item["expected_rewritten_offsets"]
                and site["pair_offset"] == item["pair_offset"]
                and (site["operation"] == item["operation"]),
                f"donor-rewriting commutative form {index} rewrote a different site from its declaration",
            )
        form_detail = form_proof["sites"]
    rewrite_detail = []
    relocation_moves = {}
    if spec.get("simulated_region_rewrites"):
        image, rewrite_proof = apply_simulated_region_rewrite(
            image,
            spec["simulated_region_rewrites"],
            relocation_offsets,
            "donor-rewriting simulated rewrite",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, region) in enumerate(
            zip(spec["simulated_region_rewrites"], rewrite_proof["regions"], strict=False)
        ):
            require(
                region["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting simulated rewrite {index} rewrote a different byte set from its declaration",
            )
            require(
                [list(pair) for pair in region["relocation_reseat"]]
                == [list(pair) for pair in item.get("relocation_reseat") or []],
                f"donor-rewriting simulated rewrite {index} reseated a different relocation set from its declaration",
            )
        rewrite_detail = rewrite_proof["regions"]
        relocation_moves = dict(((old, new) for old, new in rewrite_proof["relocation_reseat"]))
    x87_detail = []
    if spec.get("x87_squared_addend_exchanges"):
        image, x87_proof = apply_x87_squared_addend_exchange(
            image,
            spec["x87_squared_addend_exchanges"],
            relocation_offsets,
            "donor-rewriting x87 exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        # The primitive returns one item per declaration; that count is not pinned here.
        for index, (item, chain) in enumerate(
            zip(spec["x87_squared_addend_exchanges"], x87_proof["chains"], strict=False)
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting x87 exchange {index} rewrote a different byte set from its declaration",
            )
            for old, new in chain["relocation_reseat"]:
                require(
                    old not in relocation_moves,
                    f"donor-rewriting x87 exchange {index} reseats a relocation another certificate already moved",
                )
                relocation_moves[old] = new
        x87_detail = x87_proof["chains"]
    schedule_detail = []
    windows = spec.get("windows") or []
    if windows:
        image, schedule_proof = apply_instruction_schedule(
            image,
            windows,
            relocation_offsets,
            "donor-rewriting schedule",
            view=view,
            external_entries=frozenset(external_entries),
            compiler_identity=compiler_identity,
        )
        require(
            not schedule_proof["relocation_reseat"],
            "donor-rewriting refuses to move a relocation inside a window",
        )
        schedule_detail = schedule_proof["windows"]
    relational_detail = []
    if spec.get("relational_sites"):
        sites = [
            {
                key: item[key]
                for key in (
                    "compare_offset",
                    "branch_offset",
                    "seed_condition",
                    "image_condition",
                    "reencode",
                )
                if key in item
            }
            for item in spec["relational_sites"]
        ]
        image, proof = apply_relational_form(
            image,
            sites,
            relocation_offsets,
            "donor-rewriting relational",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
        )
        require(
            proof["rewritten_offsets"]
            == sorted(
                offset
                for item in spec["relational_sites"]
                for offset in item["expected_rewritten_offsets"]
            ),
            "donor-rewriting relational rewrite set differs from its declaration",
        )
        relational_detail = proof["sites"]
    require(image != donor_body, "donor-rewriting image does not move the donor body")
    donor_instructions = decode_ia32_bijection_body(
        donor_body, "donor-rewriting pre-image", relocation_symbols, code_length
    )
    image_instructions = decode_ia32_bijection_body(
        image, "donor-rewriting image", relocation_symbols, code_length
    )
    require(
        len(image_instructions) == len(donor_instructions) == spec["expected_instruction_count"],
        "donor-rewriting image instruction count differs from its declaration",
    )
    window_bytes = {
        offset for window in windows for offset in range(window["start"], window["end"])
    }
    for item in spec.get("simulated_region_rewrites") or []:
        window_bytes |= set(range(item["region_start"], item["region_end"]))
    for item in spec.get("x87_squared_addend_exchanges") or []:
        window_bytes |= set(range(item["chain_start"], item["chain_end"]))
    require(
        all(
            (
                left["offset"] == right["offset"] and left["length"] == right["length"]
                for left, right in zip(donor_instructions, image_instructions, strict=True)
                if left["offset"] not in window_bytes
            )
        ),
        "donor-rewriting image does not preserve the donor's instruction grid outside the declared windows and rewrite regions",
    )
    line_moves = {}
    for window in windows:
        cursor = window["start"]
        starts = []
        for length in window["source_instruction_lengths"]:
            starts.append(cursor)
            cursor += length
        cursor = window["start"]
        for source_index in window["target_order"]:
            if starts[source_index] != cursor:
                line_moves[starts[source_index]] = cursor
            cursor += window["source_instruction_lengths"][source_index]
    for region in rewrite_detail:
        for old, new in region["instruction_moves"]:
            line_moves[old] = new
    for chain in x87_detail:
        for old, new in chain["instruction_moves"]:
            line_moves[old] = new
    lined_donor = bytearray(donor_bytes)
    if line_moves:
        table_at = dp["line_offset"]
        rows_lined = []
        for position in range(1, dp["line_count"]):
            entry_at = table_at + position * 6
            old = int.from_bytes(lined_donor[entry_at : entry_at + 4], "little")
            line_no = int.from_bytes(lined_donor[entry_at + 4 : entry_at + 6], "little")
            rows_lined.append((line_moves.get(old, old), line_no))
        rows_lined.sort()
        for position, (offset, line_no) in enumerate(rows_lined, start=1):
            entry_at = table_at + position * 6
            lined_donor[entry_at : entry_at + 4] = offset.to_bytes(4, "little")
            lined_donor[entry_at + 4 : entry_at + 6] = line_no.to_bytes(2, "little")
    lined = CoffObject(bytes(lined_donor))
    lp = lined.function_section(mangled)
    debug_detail = require_instruction_schedule_debug_fidelity(
        lined,
        lp,
        image,
        windows,
        spec,
        mangled,
        "donor-rewriting debug fidelity",
        view=view,
    )
    changed = sorted(index for index in range(len(donor_body)) if donor_body[index] != image[index])
    require(
        changed == spec["expected_changed_offsets"],
        "donor-rewriting image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "donor-rewriting image differs from its pin",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(
        pinned_length == len(image) == function["expected_donor_length"],
        "donor-rewriting linked length changed",
    )
    installed_rows = [
        {**row, "offset": relocation_moves.get(row["offset"], row["offset"])} for row in donor_rows
    ]
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "donor-rewriting candidate relocation semantics",
    )
    derived = bytearray(lined_donor)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    if relocation_moves:
        table_at = dp["relocation_offset"]
        for position in range(dp["relocation_count"]):
            entry_at = table_at + position * 10
            old = int.from_bytes(derived[entry_at : entry_at + 4], "little")
            if old in relocation_moves:
                derived[entry_at : entry_at + 4] = relocation_moves[old].to_bytes(4, "little")
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
    if "debug_representation_delta" in function:
        effective["debug_representation_delta"] = function["debug_representation_delta"]
    if "expected_donor_section_number" in function:
        effective["expected_donor_section_number"] = function["expected_donor_section_number"]
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        bytes(derived),
        effective,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
    )
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, "donor-rewriting composed body differs from the image")
    require(
        [_relocation_identity(row) for row in detailed_relocations(checked, cp)]
        == [_relocation_identity(row) for row in installed_rows],
        "donor-rewriting composed relocation table is not the proved reseat",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": DONOR_REWRITING_CLASS,
            "instruction_schedule": schedule_detail,
            "fp_sum_reassociation": fp_detail,
            "fp_pointer_exchanges": exchange_detail,
            "commutative_operand_forms": form_detail,
            "simulated_region_rewrites": rewrite_detail,
            "x87_squared_addend_exchanges": x87_detail,
            "register_bijections": bijection_detail,
            "slot_bijections": slot_detail,
            "relational_form": relational_detail,
            "instruction_count": len(image_instructions),
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "external_entries": sorted(external_entries),
            "candidate_only": True,
            **semantic_detail,
        },
    )
