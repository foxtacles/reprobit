"""Conservative repair of measured classic-function receipt pins.

This module does not discover new interventions or change recipe decisions.  It
only re-measures a small, closed set of fields already owned by one matching
proof receipt, then asks the ordinary family dispatcher to accept the complete
candidate again.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Literal

import reprobit.classic.composition as composition
import reprobit.classic.composition_mosaic as composition_mosaic
from reprobit.binary import ByteIdentityError
from reprobit.classic.coff import (
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from reprobit.classic.debug import derive_debug_representation_delta
from reprobit.classic.foundation import declared_symbol_kind, local_symbol_kind
from reprobit.classic_donors import merge_candidate_constraints
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
)
from reprobit.coff_format import CoffObject, CoffSection, coff_body, detailed_relocations
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    NativeJsonValue,
)

MeasuredPinRepairStage = Literal["measurement", "ordinary_validation"]


class MeasuredPinRepairError(RuntimeError):
    """Fresh compiler products cannot safely refresh one saved receipt."""

    def __init__(
        self,
        message: str,
        *,
        stage: MeasuredPinRepairStage = "measurement",
    ) -> None:
        super().__init__(message)
        self.stage = stage


@dataclass(frozen=True, slots=True)
class MeasuredPinRepair:
    """A validated replacement receipt and the candidate it produced."""

    receipt: ClassicProofReceipt
    changed_keys: tuple[str, ...]
    candidate: ClassicCandidate


_IMMUTABLE_BODY_GOAL_KEYS = frozenset(
    {
        "expected_body_sha256",
        "expected_donor_body_sha256",
    }
)

# Every entry is measured by ``repin_composition_function``.  The immutable
# donor-body goal is deliberately removed from its wider public allowlist.
_SAFE_COMPOSITION_PIN_KEYS = {
    splice_class: keys - _IMMUTABLE_BODY_GOAL_KEYS
    for splice_class, keys in composition.REPINNABLE_PIN_KEYS.items()
}

# Source-equal-body is stricter: only compiler-produced observations may move.
# The donor body remains the immutable exact-output goal.  In particular, none
# of the source-refactor declaration, retail relocation, closure, or semantic
# rename fields is repaired here.
_SAFE_SOURCE_EQUAL_BODY_PIN_KEYS = frozenset(
    {
        "expected_body_length",
        "expected_changed_offsets",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_seed_body_sha256",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
    }
)

# Donor rewriting keeps its transformation program, retail addresses, semantic
# relocation fields, and donor body immutable. These are only the fresh
# compiler observations that may move around that fixed candidate.  The
# ``retail_relocations`` entry is admitted only through the closed helper below,
# which can refresh object-local section seats for exact named externals and no
# other field; ``expected_relocation_divergences`` only through the helper that
# follows a compiler-numbered local ($L/$T) whose serial moved but whose kind
# and seat did not.
_SAFE_DONOR_REWRITING_PIN_KEYS = frozenset(
    {
        "donor_rewriting.expected_code_symbol_references",
        "expected_donor_length",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_relocation_divergences",
        "expected_seed_body_sha256",
        "expected_seed_length",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
        "retail_relocations",
    }
)

# Relocation-divergent records pin the donor body (the goal), its length and linked
# span, the retail oracle and every semantic relocation field.  Only these seed-side
# and object-layout observations may move; ``retail_relocations`` moves only through
# the named-external seat helper shared with donor rewriting.
_SAFE_RELOC_DIVERGENT_PIN_KEYS = frozenset(
    {
        "expected_donor_line_count",
        "expected_donor_section_number",
        "expected_seed_length",
        "expected_seed_line_count",
        "retail_relocations",
    }
)

# Families whose receipts pin decisions (a recolouring, a range mosaic, a
# cross-TU body resize) around compiler observations of the seed and its
# witness donors.  The decisions, the retail goal (``expected_body_sha256``),
# every body the decision reads ranges from, and the closure and COMDAT
# selection never move; the observations below describe the particular fresh
# objects the decision is replayed against, and each producer still verifies
# its composed body against the retail goal before anything is accepted.
_SAFE_WEB_RECOLOUR_PIN_KEYS = frozenset(
    {
        "expected_body_length",
        "expected_comdat_count",
        # The donor is a provenance witness: the producer requires it to
        # reproduce the seed body exactly, so both move together or not at all.
        "expected_donor_body_sha256",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_function_count",
        "expected_relocation_count",
        "expected_section_count",
        "expected_section_number",
        "expected_seed_body_sha256",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
        "retail_relocations",
    }
)

_SAFE_INSTRUCTION_MOSAIC_PIN_KEYS = frozenset(
    {
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_line_count",
        "expected_relocation_count",
        "expected_section_count",
        "expected_section_number",
        "expected_seed_body_sha256",
        "expected_seed_metadata_sha256",
        "retail_relocations",
    }
)
_MOSAIC_VARIANT_PIN_SUFFIXES = ("expected_line_count", "expected_metadata_sha256")

_SAFE_CROSS_TU_RESIZE_PIN_KEYS = frozenset(
    {
        "expected_seed_body_sha256",
        "expected_seed_comdat_count",
        "expected_seed_function_count",
        "expected_seed_length",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
        "expected_seed_relocation_count",
        "expected_seed_section_count",
        "expected_seed_section_number",
        "expected_target_donor_comdat_count",
        "expected_target_donor_function_count",
        "expected_target_donor_line_count",
        "expected_target_donor_metadata_sha256",
        "expected_target_donor_relocation_count",
        "expected_target_donor_section_count",
        "expected_target_donor_section_number",
    }
)

_SEAT_OBSERVATION_FAMILIES: dict[ClassicRecipeFamily, frozenset[str]] = {
    ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR: _SAFE_WEB_RECOLOUR_PIN_KEYS,
    ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC: _SAFE_INSTRUCTION_MOSAIC_PIN_KEYS,
    ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE: (
        _SAFE_CROSS_TU_RESIZE_PIN_KEYS
    ),
}

_FIXED_NAMED_RELOCATION_FIELDS = (
    "type",
    "addend",
    "target_value",
    "target_type",
    "target_storage",
)


def _require_material_bytes(materials: ClassicDispatchMaterials) -> tuple[bytes, bytes]:
    seed = materials.seed_object
    donor = materials.donor_object
    if type(seed) is not bytes or not seed:
        raise MeasuredPinRepairError("repair requires a fresh, non-empty seed COFF object")
    if type(donor) is not bytes or not donor:
        raise MeasuredPinRepairError("repair requires a fresh, non-empty donor COFF object")
    return seed, donor


def _require_matching_authority(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> None:
    if intervention.role is not ClassicRecipeRole.FUNCTION or intervention.symbol is None:
        raise MeasuredPinRepairError("measured-pin repair accepts only classic function recipes")
    if receipt.intervention_id != intervention.id:
        raise MeasuredPinRepairError("proof receipt names a different intervention")
    if receipt.family is not intervention.family:
        raise MeasuredPinRepairError("proof receipt family differs from its intervention")


def _target_body(payload: bytes, symbol: str) -> bytes:
    coff = CoffObject(payload)
    return bytes(coff_body(coff, coff.function_section(symbol)))


def _require_immutable_donor_goal(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    donor: bytes,
    *,
    source_equal_body: bool,
) -> str:
    goal = receipt.expected_values.get("expected_body_sha256")
    if not isinstance(goal, str) or len(goal) != 64:
        raise MeasuredPinRepairError("receipt has no immutable expected_body_sha256 goal")
    donor_digest = sha256(_target_body(donor, intervention.symbol or "")).hexdigest()
    if donor_digest != goal:
        raise MeasuredPinRepairError(
            "fresh donor body no longer matches immutable expected_body_sha256 goal"
        )
    if source_equal_body:
        donor_pin = receipt.expected_values.get("expected_donor_body_sha256")
        if donor_pin != goal:
            raise MeasuredPinRepairError(
                "source-equal-body donor pin differs from immutable expected_body_sha256 goal"
            )
    return goal


def _composition_measurements(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed: bytes,
    donor: bytes,
) -> tuple[dict[str, object], frozenset[str]]:
    splice_class = intervention.family.value
    safe_keys = _SAFE_COMPOSITION_PIN_KEYS.get(splice_class)
    if safe_keys is None:
        raise MeasuredPinRepairError(
            f"classic family {splice_class!r} has no conservative measured-pin repair"
        )
    constraints = merge_candidate_constraints(intervention, receipt).materialize()
    declared_splice = constraints.get("splice_class")
    if declared_splice not in {None, splice_class}:
        raise MeasuredPinRepairError("candidate splice class differs from its typed family")
    declared_symbol = constraints.get("mangled")
    if declared_symbol not in {None, intervention.symbol}:
        raise MeasuredPinRepairError("candidate symbol differs from its typed scope")
    function = {
        **constraints,
        "mangled": intervention.symbol,
        "splice_class": splice_class,
    }
    repinned, _moved = composition.repin_composition_function(
        seed,
        donor,
        function,
        f"measured-pin repair for {intervention.id}",
    )
    return repinned, safe_keys


def _source_equal_body_measurements(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed_bytes: bytes,
    donor_bytes: bytes,
) -> tuple[dict[str, object], frozenset[str]]:
    symbol = intervention.symbol or ""
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    seed_primary = seed.function_section(symbol)
    donor_primary = donor.function_section(symbol)
    seed_body = bytes(coff_body(seed, seed_primary))
    donor_body = bytes(coff_body(donor, donor_primary))
    if len(seed_body) != len(donor_body):
        raise MeasuredPinRepairError(
            "source-equal-body seed and donor lengths differ; this is not a measured-pin repair"
        )

    # Reuse the existing closed measurement path for the equal-body geometry
    # and byte-difference set.  Source-specific seed/metadata observations are
    # then measured from the same parsed objects.
    projection = {
        "mangled": symbol,
        "splice_class": ClassicRecipeFamily.EQUAL_BODY_STRICT.value,
        **{
            key: deepcopy(receipt.expected_values[key])
            for key in ("expected_body_length", "expected_body_sha256", "expected_changed_offsets")
            if key in receipt.expected_values
        },
    }
    measured, _moved = composition.repin_composition_function(
        seed_bytes,
        donor_bytes,
        projection,
        f"source-equal-body measured-pin repair for {intervention.id}",
    )
    measured.update(
        {
            "expected_seed_body_sha256": sha256(seed_body).hexdigest(),
            "expected_seed_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
                seed, seed_primary
            ),
            "expected_donor_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
                donor, donor_primary
            ),
            "expected_seed_line_count": seed_primary["line_count"],
            "expected_donor_line_count": donor_primary["line_count"],
        }
    )
    return measured, _SAFE_SOURCE_EQUAL_BODY_PIN_KEYS


def _named_external_relocation_seats(
    receipt: ClassicProofReceipt,
    donor: CoffObject,
    donor_primary: CoffSection,
    *,
    follow_locals: bool = False,
) -> list[NativeJsonValue] | None:
    """Refresh only compiler-local section seats for exact named externals.

    A declaration-only edit can reorder otherwise identical COMDAT sections.
    The relocation's named target and retail address remain authoritative; its
    positive COFF section number is an observation of that particular compiler
    object.  Keep every semantic field fixed and refuse broader drift here so
    the ordinary family producer can still validate the complete refreshed
    oracle afterward.  Offsets are intentionally left to that post-rewrite
    check because an existing recipe may declare relocation reseating.

    With ``follow_locals`` a compiler-numbered local (``$L``/``$T``) that stays
    in the function's own section may also follow that section's new number
    and its renumbered serial; its kind, offset and every other semantic field
    must be unchanged.
    """

    declared = receipt.expected_values.get("retail_relocations")
    if not isinstance(declared, list):
        return None
    observed = detailed_relocations(donor, donor_primary)
    if len(observed) != len(declared):
        return None

    refreshed = deepcopy(declared)
    moved = False
    for index, (record, expected) in enumerate(zip(observed, declared, strict=True)):
        if not isinstance(expected, dict):
            return None
        observed_section = record["target_section"]
        expected_section = expected.get("target_section")
        observed_target = record["target"]
        expected_target = expected.get("target")
        same_seat = observed_section == expected_section
        if same_seat and (observed_target == expected_target or not follow_locals):
            continue  # Unmoved seat; a renamed local is the producer's own kind-paired check.
        refreshed_row = refreshed[index]
        if not isinstance(refreshed_row, dict):  # Defensive: ``declared`` was deep-copied.
            raise MeasuredPinRepairError("retail relocation receipt changed during repair")
        kind = declared_symbol_kind(expected_target) if isinstance(expected_target, str) else None
        renumbered = (
            follow_locals
            and kind is not None
            and kind == declared_symbol_kind(observed_target)
            and record.get("offset") == expected.get("offset")
        )
        if same_seat:
            if not renumbered:
                raise MeasuredPinRepairError(
                    "fresh donor relocation target drift is not a compiler-serial renumbering"
                )
            refreshed_row["target"] = observed_target
            moved = True
            continue
        fixed_fields_match = all(
            record[field] == expected.get(field) for field in _FIXED_NAMED_RELOCATION_FIELDS
        )
        exact_named_external = (
            isinstance(expected_section, int)
            and not isinstance(expected_section, bool)
            and expected_section > 0
            and observed_section > 0
            and record["target_storage"] == 2
            and isinstance(expected_target, str)
            and observed_target == expected_target
        )
        renumbered_local = (
            renumbered
            and local_symbol_kind(str(expected_target)) is not None
            and observed_section == donor_primary["number"]
            and expected_section == receipt.expected_values.get("expected_section_number")
        )
        if not fixed_fields_match or not (exact_named_external or renumbered_local):
            raise MeasuredPinRepairError(
                "fresh donor relocation section drift is not an exact named-external seat move"
            )
        refreshed_row["target_section"] = observed_section
        if renumbered_local:
            refreshed_row["target"] = observed_target
        moved = True
    return refreshed if moved else None


def _renumbered_code_symbol_references(
    receipt: ClassicProofReceipt,
    donor: CoffObject,
    donor_primary: CoffSection,
) -> list[NativeJsonValue] | None:
    """Follow renumbered compiler locals in a rewriting's debug closure references.

    ``donor_rewriting.expected_code_symbol_references`` lists, per closure
    child, the code symbols its relocations name and the offsets those symbols
    sit at.  After a declaration change the compiler restarts its ``$L``/``$T``
    serials, so the same reference carries a new name at the very same offset.
    Only that renumbering is followed: the child, the offset and the local's
    kind must be unchanged, and a named symbol never moves.
    """

    key = "donor_rewriting.expected_code_symbol_references"
    declared = receipt.expected_values.get(key)
    if not isinstance(declared, list) or not declared:
        return None
    values = {
        symbol["name"]: symbol["value"]
        for symbol in donor.symbols.values()
        if symbol["section"] == donor_primary["number"]
    }
    fresh: dict[tuple[str, int], list[str]] = {}
    for child_name in _comdat_child_closure(donor, donor_primary)[1]:
        sibling = _comdat_child(donor, donor_primary, child_name)
        for row in detailed_relocations(donor, sibling):
            target = row["target"]
            if target in values:
                fresh.setdefault((child_name, int(values[target])), []).append(target)
    refreshed = deepcopy(declared)
    moved = False
    for item in refreshed:
        if not isinstance(item, list) or len(item) != 3:
            return None
        child_name, name, value = item
        if not isinstance(child_name, str) or not isinstance(name, str) or type(value) is not int:
            return None
        candidates = fresh.get((child_name, value), [])
        if name in candidates:
            continue
        kind = declared_symbol_kind(name)
        renamed = [candidate for candidate in candidates if declared_symbol_kind(candidate) == kind]
        if kind is None or len(set(renamed)) != 1:
            return None  # Not a renumbering: leave the declaration for the producer to judge.
        item[1] = renamed[0]
        moved = True
    return refreshed if moved else None


def _renumbered_relocation_divergences(
    receipt: ClassicProofReceipt,
    seed: CoffObject,
    seed_primary: CoffSection,
    donor: CoffObject,
    donor_primary: CoffSection,
) -> list[NativeJsonValue] | None:
    """Follow compiler-numbered locals whose serials moved in a declared divergence.

    A declared divergence names the seed's and the donor's relocation target at
    one ordinal.  Both compilers restart their ``$L``/``$T`` serials with every
    declaration change, so after a benign source edit the very same divergence
    carries new numbers.  Only that renumbering is followed here: the local's
    kind must be unchanged on each side and a named target never moves.  The
    ordinary composer still re-proves the complete relocation contract afterward.
    """

    declared = receipt.expected_values.get("expected_relocation_divergences")
    if not isinstance(declared, list) or not declared:
        return None
    seed_rows = detailed_relocations(seed, seed_primary)
    donor_rows = detailed_relocations(donor, donor_primary)
    if len(seed_rows) != len(donor_rows):
        return None
    refreshed = deepcopy(declared)
    moved = False
    for item in refreshed:
        if not isinstance(item, list) or len(item) != 3:
            return None
        ordinal, expected_seed, expected_donor = item
        if type(ordinal) is not int or not 0 <= ordinal < len(seed_rows):
            return None
        fresh = (seed_rows[ordinal]["target"], donor_rows[ordinal]["target"])
        if fresh == (expected_seed, expected_donor):
            continue
        for old, new in zip((expected_seed, expected_donor), fresh, strict=True):
            if old == new:
                continue
            kind = local_symbol_kind(old) if isinstance(old, str) else None
            if kind is None or kind != local_symbol_kind(new):
                raise MeasuredPinRepairError(
                    "fresh donor-rewriting relocation divergence is not a compiler-local "
                    f"renumbering ({old!r} -> {new!r})"
                )
        item[1], item[2] = fresh
        moved = True
    return refreshed if moved else None


def _donor_rewriting_measurements(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed_bytes: bytes,
    donor_bytes: bytes,
) -> tuple[dict[str, object], frozenset[str]]:
    symbol = intervention.symbol or ""
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    seed_primary = seed.function_section(symbol)
    donor_primary = donor.function_section(symbol)
    donor_body = bytes(coff_body(donor, donor_primary))
    if receipt.expected_values.get("expected_donor_body_sha256") != sha256(donor_body).hexdigest():
        raise MeasuredPinRepairError(
            "fresh donor body no longer matches immutable expected_donor_body_sha256 goal"
        )
    relocation_seats = _named_external_relocation_seats(receipt, donor, donor_primary)
    measured: dict[str, object] = {
        "expected_seed_body_sha256": sha256(bytes(coff_body(seed, seed_primary))).hexdigest(),
        "expected_seed_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            seed, seed_primary
        ),
        "expected_donor_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            donor, donor_primary
        ),
        "expected_seed_length": seed_primary["raw_size"],
        "expected_donor_length": donor_primary["raw_size"],
        "expected_seed_line_count": seed_primary["line_count"],
        "expected_donor_line_count": donor_primary["line_count"],
    }
    if relocation_seats is not None:
        measured["retail_relocations"] = relocation_seats
    divergences = _renumbered_relocation_divergences(
        receipt, seed, seed_primary, donor, donor_primary
    )
    if divergences is not None:
        measured["expected_relocation_divergences"] = divergences
    references = _renumbered_code_symbol_references(receipt, donor, donor_primary)
    if references is not None:
        measured["donor_rewriting.expected_code_symbol_references"] = references
    return (
        measured,
        _SAFE_DONOR_REWRITING_PIN_KEYS,
    )


def _reloc_divergent_measurements(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed_bytes: bytes,
    donor_bytes: bytes,
) -> tuple[dict[str, object], frozenset[str]]:
    symbol = intervention.symbol or ""
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    seed_primary = seed.function_section(symbol)
    donor_primary = donor.function_section(symbol)
    measured: dict[str, object] = {
        "expected_seed_length": seed_primary["raw_size"],
        "expected_seed_line_count": seed_primary["line_count"],
        "expected_donor_line_count": donor_primary["line_count"],
        "expected_donor_section_number": donor_primary["number"],
    }
    relocation_seats = _named_external_relocation_seats(receipt, donor, donor_primary)
    if relocation_seats is not None:
        measured["retail_relocations"] = relocation_seats
    return measured, _SAFE_RELOC_DIVERGENT_PIN_KEYS


def _seat_observations(seed: CoffObject, donor: CoffObject, symbol: str) -> dict[str, object]:
    """Every compiler observation a candidate seat pins, under each receipt spelling."""

    seed_primary = seed.function_section(symbol)
    donor_primary = donor.function_section(symbol)
    seed_body = bytes(coff_body(seed, seed_primary))
    donor_body = bytes(coff_body(donor, donor_primary))
    seed_functions = sum(function_multiset(seed).values())
    seed_comdats = sum(comdat_primary_identity_multiset(seed).values())
    donor_functions = sum(function_multiset(donor).values())
    donor_comdats = sum(comdat_primary_identity_multiset(donor).values())
    seed_metadata = composition_mosaic.instruction_mosaic_metadata_sha256(seed, seed_primary)
    donor_metadata = composition_mosaic.instruction_mosaic_metadata_sha256(donor, donor_primary)
    return {
        "expected_body_length": seed_primary["raw_size"],
        "expected_comdat_count": seed_comdats,
        "expected_donor_body_sha256": sha256(donor_body).hexdigest(),
        "expected_donor_line_count": donor_primary["line_count"],
        "expected_donor_metadata_sha256": donor_metadata,
        "expected_donor_section_number": donor_primary["number"],
        "expected_function_count": seed_functions,
        "expected_line_count": seed_primary["line_count"],
        "expected_relocation_count": seed_primary["relocation_count"],
        "expected_section_count": len(seed.sections),
        "expected_section_number": seed_primary["number"],
        "expected_seed_body_sha256": sha256(seed_body).hexdigest(),
        "expected_seed_comdat_count": seed_comdats,
        "expected_seed_function_count": seed_functions,
        "expected_seed_length": seed_primary["raw_size"],
        "expected_seed_line_count": seed_primary["line_count"],
        "expected_seed_metadata_sha256": seed_metadata,
        "expected_seed_relocation_count": seed_primary["relocation_count"],
        "expected_seed_section_count": len(seed.sections),
        "expected_seed_section_number": seed_primary["number"],
        "expected_target_donor_comdat_count": donor_comdats,
        "expected_target_donor_function_count": donor_functions,
        "expected_target_donor_line_count": donor_primary["line_count"],
        "expected_target_donor_metadata_sha256": donor_metadata,
        "expected_target_donor_relocation_count": donor_primary["relocation_count"],
        "expected_target_donor_section_count": len(donor.sections),
        "expected_target_donor_section_number": donor_primary["number"],
    }


def measure_mosaic_seat_observations(
    seed: CoffObject, donor: CoffObject, symbol: str
) -> dict[str, object]:
    """Measure the compiler-object observations used by mosaic receipts."""

    return _seat_observations(seed, donor, symbol)


def _seat_observation_measurements(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed_bytes: bytes,
    donor_bytes: bytes,
    materials: ClassicDispatchMaterials,
) -> tuple[dict[str, object], frozenset[str]]:
    """Measure seed and witness observations for a decision-pinning family.

    Nothing the decision reads bytes from moves: the retail goal, the donor
    bodies a mosaic draws ranges from, the resized body of a cross-TU
    complete donor, and every closure, selection, offset and program field
    stay as saved.  Only the census, seat, line, metadata and seed-body
    observations of the fresh objects are restated, and the family producer
    then has to compose the retail body from them.
    """

    family = intervention.family
    safe_keys = set(_SEAT_OBSERVATION_FAMILIES[family])
    symbol = intervention.symbol or ""
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    measured = _seat_observations(seed, donor, symbol)
    if family is ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC:
        constraints = merge_candidate_constraints(intervention, receipt).materialize()
        variants = constraints.get("donor_variants")
        if isinstance(variants, list):
            for index, item in enumerate(variants):
                donor_id = item.get("donor") if isinstance(item, dict) else None
                payload = (
                    materials.additional_donor_objects.get(donor_id)
                    if isinstance(donor_id, str)
                    else None
                )
                if payload is None:
                    raise MeasuredPinRepairError(
                        f"instruction-mosaic variant {donor_id!r} object was not captured"
                    )
                variant = CoffObject(payload)
                variant_primary = variant.function_section(symbol)
                prefix = f"donor_variants[{index}]."
                measured[prefix + "expected_line_count"] = variant_primary["line_count"]
                measured[prefix + "expected_metadata_sha256"] = (
                    composition_mosaic.instruction_mosaic_metadata_sha256(variant, variant_primary)
                )
                safe_keys.update(prefix + suffix for suffix in _MOSAIC_VARIANT_PIN_SUFFIXES)
    if "retail_relocations" in safe_keys:
        # The composed body keeps the seed's own relocations, so their
        # object-local section seats are observations of the fresh seed.
        relocation_seats = _named_external_relocation_seats(
            receipt, seed, seed.function_section(symbol), follow_locals=True
        )
        if relocation_seats is not None:
            measured["retail_relocations"] = relocation_seats
    return measured, frozenset(safe_keys)


def _require_retail_output(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    candidate: ClassicCandidate,
) -> None:
    """A receipt that recorded a retail match must compose exactly that body again."""

    oracle = receipt.expected_values.get("retail_oracle")
    goal = receipt.expected_values.get("expected_body_sha256")
    if (
        not isinstance(oracle, dict)
        or oracle.get("verdict") != "MATCH"
        or not isinstance(goal, str)
        or len(goal) != 64
    ):
        return
    output = getattr(candidate, "output", None)
    if not isinstance(output, bytes):
        return  # Test doubles without an object; real producers always return one.
    try:
        composed = sha256(_target_body(output, intervention.symbol or "")).hexdigest()
    except (ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(
            f"composed candidate does not expose the target body: {exc}",
            stage="ordinary_validation",
        ) from exc
    if composed != goal:
        raise MeasuredPinRepairError(
            "composed body differs from the retail-matching expected_body_sha256 goal",
            stage="ordinary_validation",
        )


_DEBUG_DELTA_FAMILIES = frozenset(
    {
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        ClassicRecipeFamily.SAME_SLOT_RESIZE,
        ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
    }
)
_DEBUG_DELTA_KEY = "debug_representation_delta"


def _debug_stream(payload: bytes, symbol: str) -> bytes | None:
    coff = CoffObject(payload)
    primary = coff.function_section(symbol)
    if ".debug$S" not in _comdat_child_closure(coff, primary)[1]:
        return None
    return bytes(coff_body(coff, _comdat_child(coff, primary, ".debug$S")))


def _followed_debug_delta(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    seed: bytes,
    donor: bytes,
) -> ClassicProofReceipt:
    """Restate the seed<->donor debug-stream identity a same-slot install proves.

    The same-slot delegate proves the two objects describe the same function
    by pairing their ``.debug$S`` records and admitting differences only in
    closed forms (procedure extent, label serial, one local's type index or
    location).  Those forms are observations of the two fresh compiles, so the
    declaration is re-derived from them here and handed to the strict validator
    through the receipt.  A delta the recipe itself declares is never rewritten:
    a fresh pair it no longer describes is refused as before.
    """

    symbol = intervention.symbol or ""
    try:
        seed_stream = _debug_stream(seed, symbol)
        donor_stream = _debug_stream(donor, symbol)
    except (ByteIdentityError, ClassicProjectError, KeyError, ValueError):
        return receipt
    if seed_stream is None or donor_stream is None:
        return receipt
    derived = derive_debug_representation_delta(
        seed_stream, donor_stream, f"measured-pin repair for {intervention.id}"
    )
    if derived is None:
        return receipt  # Not a closed difference: the producer decides, as before.
    declared = {field.name: field.value for field in intervention.parameters}.get(_DEBUG_DELTA_KEY)
    if declared is not None:
        if derived and derived != declared:
            raise MeasuredPinRepairError(
                "the recipe's declared debug representation delta no longer describes the "
                "fresh objects; that declaration is not a measurement"
            )
        return receipt
    values = deepcopy(receipt.expected_values)
    if derived:
        if values.get(_DEBUG_DELTA_KEY) == derived:
            return receipt
        values[_DEBUG_DELTA_KEY] = derived  # type: ignore[assignment]
    elif _DEBUG_DELTA_KEY in values:
        del values[_DEBUG_DELTA_KEY]
    else:
        return receipt
    document = receipt.model_dump(mode="python")
    document["expected_values"] = dict(sorted(values.items()))
    return ClassicProofReceipt.model_validate(document)


def _replay_saved_record(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    materials: ClassicDispatchMaterials,
    dispatcher: ClassicFamilyDispatcher,
) -> MeasuredPinRepair:
    """Accept a record whose receipt holds only decisions when it composes as saved.

    Rewriting, mosaic and bijection receipts pin programs and immutable goals;
    no field of theirs is a measurement to refresh.  A retuned donor that emits
    the pinned donor body again makes the saved record compose unchanged, which
    is the only repair such a family admits.
    """

    try:
        constraints = merge_candidate_constraints(intervention, receipt).materialize()
        candidate = dispatcher.dispatch(
            intervention, replace(materials, candidate_constraints=constraints)
        )
    except (ByteIdentityError, ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(
            f"classic family {intervention.family.value!r} has no conservative measured-pin "
            f"repair and its saved record does not compose against the fresh objects: {exc}",
            stage="ordinary_validation",
        ) from exc
    _require_retail_output(intervention, receipt, candidate)
    return MeasuredPinRepair(receipt, (), candidate)


def _updated_receipt(
    receipt: ClassicProofReceipt,
    measured: dict[str, object],
    safe_keys: frozenset[str],
) -> tuple[ClassicProofReceipt, tuple[str, ...]]:
    values = deepcopy(receipt.expected_values)
    changed: list[str] = []
    for key in sorted(safe_keys & values.keys() & measured.keys()):
        if values[key] == measured[key]:
            continue
        values[key] = measured[key]  # type: ignore[assignment]
        changed.append(key)
    document = receipt.model_dump(mode="python")
    document["expected_values"] = values
    return ClassicProofReceipt.model_validate(document), tuple(changed)


def repair_measured_pins(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    materials: ClassicDispatchMaterials,
    *,
    dispatcher: ClassicFamilyDispatcher | None = None,
) -> MeasuredPinRepair:
    """Refresh existing measured pins and replay the ordinary family producer.

    ``materials`` must contain fresh seed/donor compiler products and every
    additional source or object required by the family dispatcher.  No field is
    added to the receipt.  Recipe parameters, semantic decisions, retail pins,
    and the donor-body goal are immutable.  Decision-pinning families (web
    recolour, instruction mosaic, cross-TU complete-target resize) restate only
    the seed and witness observations their producers replay the decision
    against.  A family whose receipt carries no measurement at all is replayed
    as saved and accepted only if it composes.  Whatever the family, a receipt
    that recorded a retail match is accepted only when the composed body is
    that retail body again.
    """

    try:
        _require_matching_authority(intervention, receipt)
        seed, donor = _require_material_bytes(materials)
        family = intervention.family
        source_equal_body = family is ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY
        donor_rewriting = family is ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING
        reloc_divergent = family is ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT
        seat_observation = family in _SEAT_OBSERVATION_FAMILIES
        repinnable = (
            donor_rewriting
            or source_equal_body
            or reloc_divergent
            or seat_observation
            or family.value in _SAFE_COMPOSITION_PIN_KEYS
        )
    except MeasuredPinRepairError:
        raise
    except (ByteIdentityError, ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(f"candidate rejected measured-pin repair: {exc}") from exc
    if not repinnable:
        return _replay_saved_record(
            intervention, receipt, materials, dispatcher or ClassicFamilyDispatcher()
        )
    try:
        if donor_rewriting:
            measured, safe_keys = _donor_rewriting_measurements(intervention, receipt, seed, donor)
        elif seat_observation:
            measured, safe_keys = _seat_observation_measurements(
                intervention, receipt, seed, donor, materials
            )
        else:
            _require_immutable_donor_goal(
                intervention,
                receipt,
                donor,
                source_equal_body=source_equal_body,
            )
        if source_equal_body:
            measured, safe_keys = _source_equal_body_measurements(
                intervention, receipt, seed, donor
            )
        elif reloc_divergent:
            measured, safe_keys = _reloc_divergent_measurements(intervention, receipt, seed, donor)
        elif not donor_rewriting and not seat_observation:
            measured, safe_keys = _composition_measurements(intervention, receipt, seed, donor)
        refreshed, changed_keys = _updated_receipt(receipt, measured, safe_keys)
        if family in _DEBUG_DELTA_FAMILIES:
            followed = _followed_debug_delta(intervention, refreshed, seed, donor)
            if followed != refreshed:
                refreshed = followed
                # The session compares the declaration with the sorted set of
                # keys whose values differ (the delta may be a newly stated pin).
                changed_keys = tuple(sorted((*changed_keys, _DEBUG_DELTA_KEY)))
        constraints = merge_candidate_constraints(intervention, refreshed).materialize()
    except MeasuredPinRepairError:
        raise
    except (ByteIdentityError, ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(f"candidate rejected measured-pin repair: {exc}") from exc

    try:
        candidate = (dispatcher or ClassicFamilyDispatcher()).dispatch(
            intervention,
            replace(materials, candidate_constraints=constraints),
        )
        _require_retail_output(intervention, receipt, candidate)
        return MeasuredPinRepair(refreshed, changed_keys, candidate)
    except (ByteIdentityError, ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(
            f"ordinary {intervention.family.value} candidate rejected measured-pin repair: {exc}",
            stage="ordinary_validation",
        ) from exc


__all__ = [
    "MeasuredPinRepair",
    "MeasuredPinRepairError",
    "MeasuredPinRepairStage",
    "measure_mosaic_seat_observations",
    "repair_measured_pins",
]
