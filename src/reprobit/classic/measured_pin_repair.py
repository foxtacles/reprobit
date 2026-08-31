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

import reprobit.classic.composition as composition
from reprobit.binary import ByteIdentityError
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


class MeasuredPinRepairError(RuntimeError):
    """Fresh compiler products cannot safely refresh one saved receipt."""


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
# other field.
_SAFE_DONOR_REWRITING_PIN_KEYS = frozenset(
    {
        "expected_donor_length",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_seed_body_sha256",
        "expected_seed_length",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
        "retail_relocations",
    }
)

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
            "expected_seed_metadata_sha256": composition.instruction_mosaic_metadata_sha256(
                seed, seed_primary
            ),
            "expected_donor_metadata_sha256": composition.instruction_mosaic_metadata_sha256(
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
) -> list[NativeJsonValue] | None:
    """Refresh only compiler-local section seats for exact named externals.

    A declaration-only edit can reorder otherwise identical COMDAT sections.
    The relocation's named target and retail address remain authoritative; its
    positive COFF section number is an observation of that particular compiler
    object.  Keep every semantic field fixed and refuse broader drift here so
    the ordinary family producer can still validate the complete refreshed
    oracle afterward.  Offsets are intentionally left to that post-rewrite
    check because an existing recipe may declare relocation reseating.
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
        if observed_section == expected_section:
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
            and isinstance(expected.get("target"), str)
            and record["target"] == expected["target"]
        )
        if not fixed_fields_match or not exact_named_external:
            raise MeasuredPinRepairError(
                "fresh donor relocation section drift is not an exact named-external seat move"
            )
        refreshed_row = refreshed[index]
        if not isinstance(refreshed_row, dict):  # Defensive: ``declared`` was deep-copied.
            raise MeasuredPinRepairError("retail relocation receipt changed during repair")
        refreshed_row["target_section"] = observed_section
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
        "expected_seed_metadata_sha256": composition.instruction_mosaic_metadata_sha256(
            seed, seed_primary
        ),
        "expected_donor_metadata_sha256": composition.instruction_mosaic_metadata_sha256(
            donor, donor_primary
        ),
        "expected_seed_length": seed_primary["raw_size"],
        "expected_donor_length": donor_primary["raw_size"],
        "expected_seed_line_count": seed_primary["line_count"],
        "expected_donor_line_count": donor_primary["line_count"],
    }
    if relocation_seats is not None:
        measured["retail_relocations"] = relocation_seats
    return (
        measured,
        _SAFE_DONOR_REWRITING_PIN_KEYS,
    )


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
    and the donor-body goal are immutable.
    """

    try:
        _require_matching_authority(intervention, receipt)
        seed, donor = _require_material_bytes(materials)
        source_equal_body = (
            intervention.family is ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY
        )
        donor_rewriting = intervention.family is ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING
        if donor_rewriting:
            measured, safe_keys = _donor_rewriting_measurements(intervention, receipt, seed, donor)
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
        elif not donor_rewriting:
            measured, safe_keys = _composition_measurements(intervention, receipt, seed, donor)
        refreshed, changed_keys = _updated_receipt(receipt, measured, safe_keys)
        constraints = merge_candidate_constraints(intervention, refreshed).materialize()
        candidate = (dispatcher or ClassicFamilyDispatcher()).dispatch(
            intervention,
            replace(materials, candidate_constraints=constraints),
        )
        return MeasuredPinRepair(refreshed, changed_keys, candidate)
    except MeasuredPinRepairError:
        raise
    except (ByteIdentityError, ClassicProjectError, KeyError, TypeError, ValueError) as exc:
        raise MeasuredPinRepairError(
            f"ordinary {intervention.family.value} candidate rejected measured-pin repair: {exc}"
        ) from exc


__all__ = [
    "MeasuredPinRepair",
    "MeasuredPinRepairError",
    "repair_measured_pins",
]
