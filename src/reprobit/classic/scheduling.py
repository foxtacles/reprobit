"""Classic compiler algorithms: scheduling."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    coff_body,
    detailed_relocations,
)

from .candidate_recipe import (
    CandidateRecipe,
    candidate_proof,
    candidate_relocation_semantics,
    comdat_body_range,
    equal_body_effective,
    install_equal_body,
    internal_relocation_targets,
    open_candidate_seats,
    pin_candidate_bodies,
    relocated_byte_offsets,
    relocation_symbol_map,
    require_changes_within,
    require_closure_children_unchanged,
    require_declared_internal_targets,
    require_pinned_length,
)
from .coff import (
    _coff_table_bytes,
    _comdat_child,
)
from .compiler_identity import Msvc420CompilerIdentity
from .composition_relocations import require_instruction_mosaic_semantic_relocations
from .foundation import (
    RelocationView,
    sha256_bytes,
)
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
INSTRUCTION_SCHEDULE_RECIPE = CandidateRecipe(
    label="instruction-schedule",
    splice_class=INSTRUCTION_SCHEDULE_CLASS,
    spec_key="instruction_schedule",
    admissible_closures=(
        tuple(INSTRUCTION_SCHEDULE_FPO_CLOSURE),
        tuple(INSTRUCTION_SCHEDULE_EH_CLOSURE),
    ),
    donor_seat="declared",
)


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
    seats = open_candidate_seats(seed_bytes, donor_bytes, function, WEB_RECOLOUR_RECIPE)
    seed, donor, mangled = seats.seed, seats.donor, seats.mangled
    sp, dp, spec = seats.seed_section, seats.donor_section, seats.spec
    installation_delegate = (
        "equal_body_strict"
        if list(seats.expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE
        else "equal_body_eh_structural_local"
    )
    seed_body, donor_body = pin_candidate_bodies(seats, function, WEB_RECOLOUR_RECIPE)
    require(donor_body == seed_body, "web-recolour donor does not reproduce the seed's body")
    seed_rows = detailed_relocations(seed, sp)
    relocation_offsets = relocated_byte_offsets(seed_rows)
    relocation_symbols = relocation_symbol_map(seed_rows)
    internal_targets = internal_relocation_targets(seed_rows, sp["number"])
    require_declared_internal_targets(spec, internal_targets, "web-recolour")
    code_length = spec.get("expected_code_length")
    view = RelocationView(
        relocations=relocation_symbols, code_length=code_length, internal_targets=internal_targets
    )
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
            view=view,
            external_entries=seed_external_entries,
            compiler_identity=compiler_identity,
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
        view=view,
        frame_pointer_free=declared_fpo is not None,
        entry_offsets=seed_external_entries,
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
        view=view,
    )
    debug_registers = require_web_recolour_debug_registers(
        coff_body(seed, _comdat_child(seed, sp, ".debug$S")),
        spec["expected_debug_s_registers"],
        "web-recolour debug registers",
    )
    require_pinned_length(function, image, "web-recolour")
    semantic_detail = candidate_relocation_semantics(seed_rows, function, "web-recolour")
    derived = bytearray(seed_bytes)
    derived[sp["raw_offset"] : sp["raw_offset"] + sp["raw_size"]] = image
    effective = equal_body_effective(
        function, mangled, installation_delegate, declared_renames=False
    )
    composed, detail, checked, cp = install_equal_body(
        seed_bytes, bytes(derived), effective, mangled, image, "web-recolour"
    )
    require(
        detailed_relocations(checked, cp) == seed_rows
        and _coff_table_bytes(checked, cp, "relocations")
        == _coff_table_bytes(seed, sp, "relocations")
        and (_coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")),
        "web-recolour output changed seed relocation/line bytes",
    )
    require_closure_children_unchanged(seats, checked, cp, "web-recolour")
    require_changes_within(seed_bytes, composed, comdat_body_range(sp), "web-recolour")
    return composed, candidate_proof(
        detail,
        WEB_RECOLOUR_CLASS,
        {
            "instruction_schedule": schedule_detail,
            "web_recolour": proof["webs"],
            "instruction_count": proof["instruction_count"],
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "debug_s_registers": debug_registers,
        },
        semantic_detail,
    )


WEB_RECOLOUR_CLASS = "retail_exact_web_recolour"
WEB_RECOLOUR_RECIPE = CandidateRecipe(
    label="web-recolour",
    splice_class=WEB_RECOLOUR_CLASS,
    spec_key="web_recolour",
    admissible_closures=(
        tuple(INSTRUCTION_SCHEDULE_FPO_CLOSURE),
        tuple(INSTRUCTION_SCHEDULE_EH_CLOSURE),
    ),
)


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
    seats = open_candidate_seats(seed_bytes, donor_bytes, function, INSTRUCTION_SCHEDULE_RECIPE)
    seed, donor, mangled = seats.seed, seats.donor, seats.mangled
    sp, dp, spec = seats.seed_section, seats.donor_section, seats.spec
    reseat_declared = any(window.get("relocation_reseat") for window in spec["windows"])
    delegate = instruction_schedule_delegate(
        function["expected_closure"], function["expected_code_renames"], reseat_declared
    )
    _, donor_body = pin_candidate_bodies(seats, function, INSTRUCTION_SCHEDULE_RECIPE)
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
    relocation_offsets = relocated_byte_offsets(seed_rows)
    relocation_symbols = relocation_symbol_map(seed_rows)
    internal_targets = internal_relocation_targets(donor_rows, dp["number"])
    require_declared_internal_targets(spec, internal_targets, "instruction-schedule")
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
        view=RelocationView(
            relocations=relocation_symbols,
            code_length=spec.get("expected_code_length"),
            internal_targets=internal_targets,
        ),
        external_entries=donor_external_entries,
        compiler_identity=compiler_identity,
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
    image_relocation_symbols = relocation_symbol_map(image_rows)
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
        view=RelocationView(
            relocations=image_relocation_symbols,
            code_length=spec.get("expected_code_length"),
            internal_targets=internal_targets,
        ),
    )
    require_pinned_length(function, image, "instruction-schedule")
    semantic_detail = candidate_relocation_semantics(image_rows, function, "instruction-schedule")
    derived = bytearray(donor_bytes)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    if moved:
        for ordinal, row in enumerate(donor_rows):
            if row["offset"] not in moved:
                continue
            record_at = dp["relocation_offset"] + ordinal * 10
            derived[record_at : record_at + 4] = moved[row["offset"]].to_bytes(4, "little")
    derived = bytes(derived)
    effective = equal_body_effective(function, mangled, delegate, declared_renames=True)
    composed, detail, checked, cp = install_equal_body(
        seed_bytes, derived, effective, mangled, image, "instruction-schedule"
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
    require_closure_children_unchanged(seats, checked, cp, "instruction-schedule")
    allowed = comdat_body_range(sp)
    if moved:
        allowed |= {
            sp["relocation_offset"] + ordinal * 10 + byte
            for ordinal, row in enumerate(seed_rows)
            if row["offset"] in moved
            for byte in range(4)
        }
    require_changes_within(seed_bytes, composed, allowed, "instruction-schedule")
    return composed, candidate_proof(
        detail,
        INSTRUCTION_SCHEDULE_CLASS,
        {
            "instruction_schedule": proof["windows"],
            "instruction_count": proof["instruction_count"],
            "changed_offsets": proof["changed_offsets"],
            "debug_fidelity": debug_detail,
            "relocation_reseat": proof["relocation_reseat"],
        },
        semantic_detail,
    )
