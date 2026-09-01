"""Classic compiler algorithms: composition."""

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
from .composition_fpo_identity import require_source_fpo_mosaic_identity
from .composition_mosaic import instruction_mosaic_metadata_sha256
from .composition_relocations import (
    _normalized_relocation_renames,
    require_instruction_mosaic_semantic_relocations,
    require_same_semantic_relocations,
)
from .foundation import (
    local_symbol_kind,
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import (
    RETAIL_EXACT_SOURCE_EQUAL_BODY_CLASS,
    require_declared_relocation_semantics,
)
from .source_proofs import (
    require_target_source_refactor_identity,
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
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any], context: str
) -> dict[str, Any]:
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
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any], context: str
) -> tuple[dict[str, Any], list[str]]:
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
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
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
            seed_definition[field] == donor_definition[field]
            for field in ("selection", "associated", "length", "relocations")
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
                            a["target_" + field] == b["target_" + field]
                            for field in ("section", "value", "type", "storage")
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
                all(offset not in relocation_mask for offset in changed),
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
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    seed_source: bytes,
    donor_source: bytes,
) -> tuple[bytes, dict[str, Any]]:
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
                    left[field] == right[field]
                    for field in (
                        "name",
                        "raw_size",
                        "relocation_count",
                        "line_count",
                        "characteristics",
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
