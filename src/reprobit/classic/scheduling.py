"""Classic compiler algorithms: scheduling."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    coff_body,
    detailed_relocations,
    section_definitions,
)

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .compiler_identity import Msvc420CompilerIdentity
from .composition import compose_equal_body_comdat
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_relocations import require_instruction_mosaic_semantic_relocations
from .foundation import (
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import require_declared_relocation_semantics
from .register_reencoding import require_frame_pointer_free_frame
from .register_semantics import (
    decode_ia32_bijection_body,
)
from .relational import relational_form_external_entries
from .scheduling_apply import apply_instruction_schedule
from .scheduling_certificates import require_instruction_schedule_debug_fidelity
from .scheduling_web_recolour import apply_web_recolour, require_web_recolour_debug_registers

INSTRUCTION_SCHEDULE_CLASS = "retail_exact_instruction_schedule"
INSTRUCTION_SCHEDULE_FPO_CLOSURE = [".debug$F", ".debug$S"]
INSTRUCTION_SCHEDULE_EH_CLOSURE = [".debug$S", ".xdata$x"]


def instruction_schedule_delegate(
    expected_closure: object, expected_code_renames: object, relocation_reseat: bool = False
) -> str:
    """Name the installation delegate from the PINS alone.

    Identical policy to the register-bijection certificate: the composer
    requires the objects' own closure and rename set to equal these pins
    first, so a pin that disagrees refuses before this is reached.

    A window that moves a relocated operand needs the one primitive that can
    install a moved relocation record -- `equal_body_eh_reloc_layout`, which
    already pairs the two tables by ordinal, proves type/addend/target
    identity, and rewrites nothing but the four offset bytes.  The other two
    delegates retain the seed table verbatim and so cannot express a reseat.
    """
    if relocation_reseat:
        return "equal_body_eh_reloc_layout"
    if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE and (not expected_code_renames):
        return "equal_body_strict"
    return "equal_body_eh_structural_local"


def produce_web_recolour_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Produce a recoloured def-use web from compiler output.

    See the class comment above.  The pre-image is the SEED's own
    compiler-produced body -- no donor bytes are installed, and the donor the
    manifest names is required to reproduce that body exactly, which is what
    makes it a provenance witness rather than decoration.  A declared
    reordering is applied first through the unchanged
    `apply_instruction_schedule` primitive; every web obligation is then
    measured on the reordered body. Installation is delegated, unchanged, to
    the equal-body primitive; literal comparison remains verifier-only.
    """
    require_payload_free_declaration(function, "web-recolour declaration")
    require(
        function.get("splice_class") == WEB_RECOLOUR_CLASS,
        "splice class is not retail_exact_web_recolour",
    )
    require(
        "target_source_refactor" not in function, "web-recolour functions carry no source refactor"
    )
    spec = function["web_recolour"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        "web-recolour target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "web-recolour global section count changed",
    )
    seed_functions = function_multiset(seed)
    require(
        seed_functions == function_multiset(donor)
        and sum(seed_functions.values()) == function["expected_function_count"],
        "web-recolour donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(
        seed_comdats == comdat_primary_identity_multiset(donor)
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "web-recolour donor COMDAT identity set differs",
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
        "web-recolour target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "web-recolour COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        "web-recolour target closure changed",
    )
    require(
        list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE
        or list(expected_closure) == [".debug$S", ".xdata$x"],
        "web-recolour closure pin names no installation delegate",
    )
    installation_delegate = (
        "equal_body_strict"
        if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE
        else "equal_body_eh_structural_local"
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "web-recolour metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "web-recolour seed/donor body differs from its pin",
    )
    require(donor_body == seed_body, "web-recolour donor does not reproduce the seed's body")
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
            "web-recolour in-body relocated target set changed",
        )
    code_length = spec.get("expected_code_length")
    seed_external_entries = frozenset(
        relational_form_external_entries(seed, sp, "web-recolour seed funclet entries")
    )
    donor_external_entries = frozenset(
        relational_form_external_entries(donor, dp, "web-recolour donor funclet entries")
    )
    require(
        seed_external_entries == donor_external_entries,
        "web-recolour donor external entry set differs from the seed",
    )

    def _schedule(windows, phase):
        nonlocal image
        if not windows:
            return []
        image, schedule_proof = apply_instruction_schedule(
            image,
            windows,
            relocation_offsets,
            f"web-recolour {phase}",
            relocation_symbols,
            code_length,
            internal_targets,
            seed_external_entries,
            compiler_identity,
        )
        require(
            not schedule_proof["relocation_reseat"], "web-recolour refuses to move a relocation"
        )
        return schedule_proof["windows"]

    image = seed_body
    schedule_detail = _schedule(spec.get("windows") or [], "schedule")
    declared_fpo = spec.get("expected_fpo_record")
    names_ebp = any(
        "ebp" in {web.get("source_register"), web.get("image_register")} for web in spec["webs"]
    )
    require(
        declared_fpo is not None or not names_ebp,
        "web-recolour names EBP without a frame-pointer-free record",
    )
    if declared_fpo is not None:
        measured = require_frame_pointer_free_frame(
            seed,
            sp,
            seed_body,
            decode_ia32_bijection_body(
                seed_body, "web-recolour frame proof", relocation_symbols, code_length
            ),
            "web-recolour frame proof",
        )
        require(
            {key: value for key, value in measured.items() if key != "raw_sha256"} == declared_fpo,
            "web-recolour FPO record differs from its declaration",
        )
    image, proof = apply_web_recolour(
        image,
        spec["webs"],
        relocation_offsets,
        "web-recolour image",
        relocation_symbols,
        code_length,
        internal_targets,
        declared_fpo is not None,
        seed_external_entries,
    )
    require(
        proof["code_length"] == (code_length or len(seed_body)),
        "web-recolour code length differs from its pin",
    )
    require(
        proof["instruction_count"] == spec["expected_instruction_count"],
        "web-recolour instruction count differs from its declaration",
    )
    schedule_detail = schedule_detail + _schedule(
        spec.get("trailing_windows") or [], "trailing schedule"
    )
    changed = sorted(index for index in range(len(seed_body)) if seed_body[index] != image[index])
    require(
        changed == spec["expected_changed_offsets"],
        "web-recolour image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "web-recolour image differs from its pin",
    )
    require(
        changed == function["expected_changed_offsets"],
        "web-recolour changed offsets differ from their pin",
    )
    debug_detail = require_instruction_schedule_debug_fidelity(
        seed,
        sp,
        image,
        (spec.get("windows") or []) + (spec.get("trailing_windows") or []),
        spec,
        mangled,
        "web-recolour debug fidelity",
        relocation_symbols,
        code_length,
        internal_targets,
    )
    debug_registers = require_web_recolour_debug_registers(
        coff_body(seed, _comdat_child(seed, sp, ".debug$S")),
        spec["expected_debug_s_registers"],
        "web-recolour debug registers",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "web-recolour linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        seed_rows,
        function["retail_relocations"],
        "web-recolour candidate relocation semantics",
    )
    derived = bytearray(seed_bytes)
    derived[sp["raw_offset"] : sp["raw_offset"] + sp["raw_size"]] = image
    effective = {
        "mangled": mangled,
        "splice_class": installation_delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    if installation_delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = []
        effective["expected_xdata_rename_offsets"] = []
    composed, detail = compose_equal_body_comdat(seed_bytes, bytes(derived), effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, "web-recolour composed body differs from the image")
    require(
        detailed_relocations(checked, cp) == seed_rows
        and _coff_table_bytes(checked, cp, "relocations")
        == _coff_table_bytes(seed, sp, "relocations")
        and (_coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")),
        "web-recolour output changed seed relocation/line bytes",
    )
    for child_name in expected_closure:
        require(
            coff_body(checked, _comdat_child(checked, cp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"web-recolour output changed its {child_name} child",
        )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "web-recolour changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": WEB_RECOLOUR_CLASS,
            "instruction_schedule": schedule_detail,
            "web_recolour": proof["webs"],
            "instruction_count": proof["instruction_count"],
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "debug_s_registers": debug_registers,
            "candidate_only": True,
            **semantic_detail,
        },
    )


WEB_RECOLOUR_CLASS = "retail_exact_web_recolour"


def produce_instruction_schedule_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Produce a topological reordering from compiler output.

    See the class comment above: this is a certificate.  The pre-image is an
    ordinary, census-pinned compile of the same translation unit; the
    reordering is proved to respect the window's own dependence DAG. Body
    installation itself is delegated, unchanged, to the
    equal-body primitive.
    """
    require_payload_free_declaration(function, "instruction-schedule declaration")
    require(
        function.get("splice_class") == INSTRUCTION_SCHEDULE_CLASS,
        "splice class is not retail_exact_instruction_schedule",
    )
    require(
        "target_source_refactor" not in function,
        "instruction-schedule functions carry no source refactor",
    )
    spec = function["instruction_schedule"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == function["expected_section_number"]
        and dp["number"] == function["expected_donor_section_number"],
        "instruction-schedule target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "instruction-schedule global section count changed",
    )
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(
        seed_functions == donor_functions
        and sum(seed_functions.values()) == function["expected_function_count"],
        "instruction-schedule donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(
        seed_comdats == donor_comdats
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "instruction-schedule donor COMDAT identity set differs",
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
        "instruction-schedule target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "instruction-schedule COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        "instruction-schedule target closure changed",
    )
    require(
        list(expected_closure)
        in (INSTRUCTION_SCHEDULE_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "instruction-schedule closure pin names no installation delegate",
    )
    reseat_declared = any(window.get("relocation_reseat") for window in spec["windows"])
    delegate = instruction_schedule_delegate(
        function["expected_closure"], function["expected_code_renames"], reseat_declared
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "instruction-schedule metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "instruction-schedule seed/donor body differs from its pin",
    )
    code_renames = require_instruction_mosaic_semantic_relocations(
        seed, sp, donor, dp, "instruction-schedule code"
    )
    require(
        [[offset, kind] for offset, kind in code_renames] == function["expected_code_renames"],
        "instruction-schedule code rename set changed",
    )
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    seed_targets = {row["offset"]: row["target"] for row in seed_rows}
    donor_targets = {row["offset"]: row["target"] for row in donor_rows}
    require(
        [
            [offset, seed_targets.get(offset), donor_targets.get(offset)]
            for offset, _ in code_renames
        ]
        == function.get("expected_code_rename_symbols", []),
        "instruction-schedule code rename symbol pair changed",
    )
    require(
        [(row["offset"], row["type"], row["addend"]) for row in seed_rows]
        == [(row["offset"], row["type"], row["addend"]) for row in donor_rows],
        "instruction-schedule donor relocation layout differs from the seed",
    )
    require(
        [(row["offset"], row["target"]) for row in seed_rows if row["type"] == 20]
        == [(row["offset"], row["target"]) for row in donor_rows if row["type"] == 20],
        "instruction-schedule donor call/branch relocation targets differ from the seed",
    )
    relocation_offsets = frozenset(
        row["offset"] + byte for row in seed_rows for byte in range(row["width"])
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in seed_rows
    }
    internal_targets = frozenset(
        row["target_value"] for row in donor_rows if row["target_section"] == dp["number"]
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "instruction-schedule in-body relocated target set changed",
        )
    seed_external_entries = frozenset(
        relational_form_external_entries(seed, sp, "instruction-schedule seed funclet entries")
    )
    donor_external_entries = frozenset(
        relational_form_external_entries(donor, dp, "instruction-schedule donor funclet entries")
    )
    require(
        seed_external_entries == donor_external_entries,
        "instruction-schedule donor external entry set differs from the seed",
    )
    image, proof = apply_instruction_schedule(
        donor_body,
        spec["windows"],
        relocation_offsets,
        "instruction-schedule image",
        relocation_symbols,
        spec.get("expected_code_length"),
        internal_targets,
        donor_external_entries,
        compiler_identity,
    )
    require(
        proof["code_length"] == (spec.get("expected_code_length") or len(donor_body)),
        "instruction-schedule code length differs from its pin",
    )
    require(
        proof["changed_offsets"] == spec["expected_changed_offsets"]
        and proof["instruction_count"] == spec["expected_instruction_count"],
        "instruction-schedule image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "instruction-schedule image differs from its pin",
    )
    require(image != donor_body, "instruction-schedule image does not move the donor body")
    moved = {old_offset: new_offset for old_offset, new_offset in proof["relocation_reseat"]}
    require(
        bool(moved) == reseat_declared,
        "instruction-schedule reseat declaration and measurement differ",
    )
    if moved:
        require(
            function.get("expected_relocation_moves")
            == [
                [old_offset, new_offset]
                for old_offset, new_offset in proof["relocation_reseat"]
                if old_offset != new_offset
            ],
            "instruction-schedule relocation move set differs from its pin",
        )
    image_rows = []
    for row in seed_rows:
        if row["offset"] in moved:
            row = dict(row)
            row["offset"] = moved[row["offset"]]
        image_rows.append(row)
    require(
        [row["offset"] for row in image_rows] == sorted(row["offset"] for row in image_rows),
        "instruction-schedule reseat breaks the relocation table's ascending offset order",
    )
    image_relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in image_rows
    }
    require(
        len(image_relocation_symbols) == len(image_rows),
        "instruction-schedule reseat collides two relocation records",
    )
    debug_detail = require_instruction_schedule_debug_fidelity(
        seed,
        sp,
        image,
        spec["windows"],
        spec,
        mangled,
        "instruction-schedule debug fidelity",
        image_relocation_symbols,
        spec.get("expected_code_length"),
        internal_targets,
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "instruction-schedule linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        image_rows,
        function["retail_relocations"],
        "instruction-schedule candidate relocation semantics",
    )
    derived = bytearray(donor_bytes)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    if moved:
        for ordinal, row in enumerate(donor_rows):
            if row["offset"] not in moved:
                continue
            record_at = dp["relocation_offset"] + ordinal * 10
            derived[record_at : record_at + 4] = moved[row["offset"]].to_bytes(4, "little")
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
    if delegate == "equal_body_eh_reloc_layout":
        effective["expected_relocation_moves"] = function["expected_relocation_moves"]
        effective["expected_xdata_rename_offsets"] = function["expected_xdata_rename_offsets"]
    composed, detail = compose_equal_body_comdat(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        coff_body(checked, cp) == image, "instruction-schedule composed body differs from the image"
    )
    expected_relocation_table = bytearray(_coff_table_bytes(seed, sp, "relocations"))
    for ordinal, row in enumerate(seed_rows):
        if row["offset"] in moved:
            record_at = ordinal * 10
            expected_relocation_table[record_at : record_at + 4] = moved[row["offset"]].to_bytes(
                4, "little"
            )
    require(
        detailed_relocations(checked, cp) == image_rows
        and _coff_table_bytes(checked, cp, "relocations") == bytes(expected_relocation_table)
        and (_coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")),
        "instruction-schedule output changed seed relocation/line bytes",
    )
    for child_name in expected_closure:
        require(
            coff_body(checked, _comdat_child(checked, cp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"instruction-schedule output changed its {child_name} child",
        )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    if moved:
        allowed |= {
            sp["relocation_offset"] + ordinal * 10 + byte
            for ordinal, row in enumerate(seed_rows)
            if row["offset"] in moved
            for byte in range(4)
        }
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "instruction-schedule changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": INSTRUCTION_SCHEDULE_CLASS,
            "instruction_schedule": proof["windows"],
            "instruction_count": proof["instruction_count"],
            "changed_offsets": proof["changed_offsets"],
            "debug_fidelity": debug_detail,
            "relocation_reseat": proof["relocation_reseat"],
            "candidate_only": True,
            **semantic_detail,
        },
    )
