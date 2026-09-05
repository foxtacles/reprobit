"""Re-author refused classic function records from donors the unit already compiles.

After a benign source edit a function's saved record can stop composing while the
very same body it must produce is still emitted by another donor of its
translation unit -- or by its own donor, only no longer under the recorded
family.  Retuning cannot express either repair: it moves one donor's counts and
keeps the record's dependency and family fixed.

This module plans replacements from the fresh donor objects a repair analysis
captured with each refusal.  The goal is the record's own immutable retail-body
digest; a donor whose fresh body carries it may back a new
record of the cheapest closed equal-body family the ordinary composer proves,
or, when no closed family hosts that body (the seed changed length, say), the
saved record itself is moved onto that donor and its measurements refreshed.
A replaced record and its receipt are removed, beneficiaries follow the
function, and a donor left without consumers is retired.  Nothing here compiles, reads a
reference image, or invents a decision: every pin is measured and every result
still has to pass the fresh cold proof.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256

from reprobit.classic_donor_usage import beneficiary_keys, direct_donor_consumers, donor_after_usage
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError, repair_measured_pins
from reprobit.classic_mosaic_repair import (
    MosaicRepairError,
    instruction_mosaic_semantics_required,
    reauthor_instruction_mosaic,
)
from reprobit.classic_relational_repair import (
    RelationalRepairError,
    reauthor_relational_donor_rewriting,
)
from reprobit.classic_repair_authority import (
    ClassicDependencyEdit,
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
)
from reprobit.classic_repair_session import (
    ClassicRepairRefusal,
    ClassicRepairSessionError,
    dropped_move_parameters,
    repoint_refusal_materials,
    repointed_action,
)
from reprobit.classic_retail_repair import RetailRepairError, retail_body_goal_digest
from reprobit.coff_format import CoffObject, coff_body
from reprobit.discovery_authoring import (
    REAUTHORABLE_FAMILIES,
    DiscoveryAuthoringError,
    build_measured_function_record,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    classic_function_donor_ids,
)


class ClassicReauthorError(RuntimeError):
    """The captured refusals cannot be turned into a consistent replacement plan."""


@dataclass(frozen=True, slots=True)
class ClassicFunctionReauthoring:
    """One refused function record replaced by a measured record on another donor state."""

    unit_id: str
    symbol: str
    removed_action_id: str
    previous_donor_id: str
    donor_id: str
    family: str
    addition: ClassicRecordAddition | None
    """A new record under a closed family; ``None`` when the saved record is re-pointed."""
    dependency_edit: ClassicDependencyEdit | None = None
    receipt_edit: ClassicReceiptEdit | None = None


@dataclass(frozen=True, slots=True)
class ClassicReauthorPlan:
    """Typed authority changes for every function this pass could re-author."""

    reauthorings: tuple[ClassicFunctionReauthoring, ...]
    intervention_edits: tuple[ClassicInterventionEdit, ...]
    receipt_edits: tuple[ClassicReceiptEdit, ...]
    additions: tuple[ClassicRecordAddition, ...]
    skipped: tuple[tuple[str, str, str], ...]
    """``(unit_id, action_id, reason)`` for refusals no available donor could re-author."""
    dependency_edits: tuple[ClassicDependencyEdit, ...] = ()


def _goal_digest(action: ClassicRecipeIntervention, receipt: ClassicProofReceipt) -> str | None:
    try:
        return retail_body_goal_digest(action, receipt)
    except RetailRepairError:
        return None


def _function_body_digest(payload: bytes, symbol: str) -> str | None:
    try:
        obj = CoffObject(payload)
        return sha256(bytes(coff_body(obj, obj.function_section(symbol)))).hexdigest()
    except Exception:
        return None


def _donor_order(refusal: ClassicRepairRefusal) -> list[str]:
    """The refused action's own donor first, then the unit's other declaration carriers.

    A donor source overlay is a TU-private rendering bound to exactly one consumer
    (its source-mutating operations are proved against that consumer), so another
    function is never re-seated onto one; a function may keep its own overlay
    donor when only the record family changes.
    """

    primary = refusal.intervention.dependencies[0] if refusal.intervention.dependencies else None
    ordered = [
        item.intervention.id
        for item in refusal.unit.donors
        if item.intervention.id == primary
        or item.intervention.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
    ]
    if primary in ordered:
        ordered.remove(primary)
        ordered.insert(0, primary)
    return [donor_id for donor_id in ordered if donor_id in refusal.unit_donor_objects]


def plan_function_reauthoring(
    refusals: Sequence[ClassicRepairRefusal],
) -> ClassicReauthorPlan:
    """Plan exact-body replacements for refused function records.

    Refusals of other roles, records without a body goal, and functions no
    captured donor object reproduces are reported in ``skipped``; a plan with no
    re-authoring changes nothing.  Donor edits are merged per donor so that one
    pass may move several functions between the same donors consistently.
    """

    reauthorings: list[ClassicFunctionReauthoring] = []
    skipped: list[tuple[str, str, str]] = []
    # donor id -> (saved intervention, beneficiary set after this plan)
    donor_state: dict[str, tuple[ClassicRecipeIntervention, set[tuple[str, str, str]]]] = {}
    # donor id -> consumers after this plan (function ids depending on it)
    consumers: dict[str, set[str]] = {}
    unit_receipts: dict[str, ClassicProofReceipt] = {}
    seen_actions: set[str] = set()
    saved_actions: dict[str, ClassicRecipeIntervention] = {}

    for refusal in refusals:
        action = refusal.intervention
        if not getattr(refusal, "unit_donor_objects", None):
            skipped.append(
                (refusal.unit_id, getattr(action, "id", ""), "no fresh donor objects were captured")
            )
            continue
        if action.role is not ClassicRecipeRole.FUNCTION or action.symbol is None:
            skipped.append((refusal.unit_id, action.id, "not a classic function record"))
            continue
        if action.id in seen_actions:
            raise ClassicReauthorError(f"refusal {action.id!r} was captured more than once")
        seen_actions.add(action.id)
        saved_actions[action.id] = action
        goal = _goal_digest(action, refusal.receipt)
        if goal is None and refusal.retail_body is None:
            skipped.append(
                (refusal.unit_id, action.id, "receipt carries no immutable retail body goal")
            )
            continue
        if not action.dependencies:
            skipped.append((refusal.unit_id, action.id, "record names no primary donor"))
            continue
        unit = refusal.unit
        for item in unit.donors:
            donor_state.setdefault(
                item.intervention.id,
                (
                    item.intervention,
                    beneficiary_keys(item.intervention),
                ),
            )
            consumers.setdefault(
                item.intervention.id,
                direct_donor_consumers(unit, item.intervention.id),
            )
        for receipt in unit.receipts:
            unit_receipts.setdefault(receipt.intervention_id, receipt)

        chosen: ClassicFunctionReauthoring | None = None
        reasons: list[str] = []
        if (
            action.family is ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC
            and refusal.retail_body is not None
        ):
            donor_interventions = {
                item.intervention.id: item.intervention for item in refusal.unit.donors
            }
            try:
                mosaic = reauthor_instruction_mosaic(
                    action,
                    refusal.receipt,
                    refusal.materials,
                    refusal.retail_body,
                    donor_objects=refusal.unit_donor_objects,
                    donor_interventions=donor_interventions,
                    donor_sources={
                        item.intervention.id: item.request.logical_outputs.get(
                            refusal.unit.plan.source
                        )
                        for item in refusal.unit.donors
                    },
                    donor_shape_identifiers={
                        item.intervention.id: item.request.carrier_identifiers
                        for item in refusal.unit.donors
                    },
                )
            except MosaicRepairError as exc:
                reasons.append(f"bounded mosaic re-author: {exc}")
            else:
                primary_id = mosaic.intervention.dependencies[0]
                chosen = ClassicFunctionReauthoring(
                    refusal.unit_id,
                    action.symbol,
                    action.id,
                    action.dependencies[0],
                    primary_id,
                    action.family.value,
                    ClassicRecordAddition(
                        mosaic.intervention,
                        mosaic.receipt,
                        replaces_intervention_id=action.id,
                    ),
                )
        semantic_mosaic = instruction_mosaic_semantics_required(action)
        if semantic_mosaic and chosen is None:
            skipped.append(
                (
                    refusal.unit_id,
                    action.id,
                    "saved mosaic semantics could not be preserved"
                    + (f" ({reasons[-1]})" if reasons else ""),
                )
            )
            continue
        donor_order = [] if chosen is not None else _donor_order(refusal)
        prepared_donors = {item.intervention.id: item for item in refusal.unit.donors}
        for donor_id in donor_order if goal is not None else ():
            donor_object = refusal.unit_donor_objects[donor_id]
            if _function_body_digest(donor_object, action.symbol) != goal:
                continue
            for family in REAUTHORABLE_FAMILIES:
                try:
                    record = build_measured_function_record(
                        target_id=action.scope.target,
                        translation_unit_id=refusal.unit_id,
                        build_target=action.build_target,
                        symbol=action.symbol,
                        family=family,
                        donor_id=donor_id,
                        seed_object=refusal.materials.seed_object,
                        donor_object=donor_object,
                    )
                except DiscoveryAuthoringError as exc:
                    reasons.append(f"{donor_id}/{family.value}: {exc}")
                    continue
                chosen = ClassicFunctionReauthoring(
                    refusal.unit_id,
                    action.symbol,
                    action.id,
                    action.dependencies[0],
                    donor_id,
                    family.value,
                    ClassicRecordAddition(
                        record.intervention,
                        record.receipt,
                        replaces_intervention_id=action.id,
                    ),
                )
                break
            if chosen is not None:
                break
            if donor_id == action.dependencies[0]:
                continue
            # No closed family hosts the goal body on this donor, but the saved
            # record's own family may compose from it: keep the record and move it.
            moved = repointed_action(action, donor_id)
            try:
                repaired = repair_measured_pins(
                    moved,
                    refusal.receipt,
                    repoint_refusal_materials(
                        refusal,
                        moved,
                        prepared_donors[donor_id],
                        donor_object,
                    ),
                )
            except (ClassicRepairSessionError, MeasuredPinRepairError) as exc:
                reasons.append(f"{donor_id}/{action.family.value} re-point: {exc}")
                continue
            chosen = ClassicFunctionReauthoring(
                refusal.unit_id,
                action.symbol,
                action.id,
                action.dependencies[0],
                donor_id,
                action.family.value,
                None,
                ClassicDependencyEdit(action, donor_id, dropped_move_parameters(action)),
                (
                    ClassicReceiptEdit(refusal.receipt, repaired.receipt)
                    if repaired.receipt != refusal.receipt
                    else None
                ),
            )
            break
        if chosen is None and refusal.retail_body is not None:
            for donor_id in donor_order:
                donor_object = refusal.unit_donor_objects[donor_id]
                prepared = prepared_donors[donor_id]
                try:
                    rewritten = reauthor_relational_donor_rewriting(
                        action,
                        refusal.receipt,
                        refusal.materials,
                        refusal.retail_body,
                        donor_id=donor_id,
                        donor_object=donor_object,
                        donor_source=prepared.request.logical_outputs.get(refusal.unit.plan.source),
                        shape_identifiers=prepared.request.carrier_identifiers,
                    )
                except RelationalRepairError as exc:
                    reasons.append(f"{donor_id}/relational rewrite: {exc}")
                    continue
                chosen = ClassicFunctionReauthoring(
                    refusal.unit_id,
                    action.symbol,
                    action.id,
                    action.dependencies[0],
                    donor_id,
                    ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING.value,
                    ClassicRecordAddition(
                        rewritten.intervention,
                        rewritten.receipt,
                        replaces_intervention_id=action.id,
                    ),
                )
                break
        if chosen is None:
            skipped.append(
                (
                    refusal.unit_id,
                    action.id,
                    "no captured donor object carries the goal body or can reproduce it by a "
                    "proved relational rewrite" + (f" ({reasons[-1]})" if reasons else ""),
                )
            )
            continue
        reauthorings.append(chosen)
        key = (action.scope.target, refusal.unit_id, action.symbol)
        if chosen.addition is not None:
            after_action = chosen.addition.intervention
            after_receipt = chosen.addition.receipt
        else:
            if chosen.dependency_edit is None:
                raise ClassicReauthorError(
                    f"re-pointed action {chosen.removed_action_id!r} names no donor"
                )
            after_action = chosen.dependency_edit.after
            after_receipt = (
                chosen.receipt_edit.after
                if chosen.receipt_edit is not None and chosen.receipt_edit.after is not None
                else refusal.receipt
            )
        before_donors = classic_function_donor_ids(action, refusal.receipt)
        after_donors = classic_function_donor_ids(after_action, after_receipt)
        unknown = (before_donors | after_donors) - donor_state.keys()
        if unknown:
            raise ClassicReauthorError(
                f"function {action.id!r} names donors outside its prepared unit: {sorted(unknown)}"
            )
        for donor_id in before_donors:
            consumers[donor_id].discard(action.id)
            donor_state[donor_id][1].discard(key)
        for donor_id in after_donors:
            consumers[donor_id].add(after_action.id)
            donor_state[donor_id][1].add(key)

    intervention_edits: list[ClassicInterventionEdit] = []
    receipt_edits: list[ClassicReceiptEdit] = []
    dependency_edits: list[ClassicDependencyEdit] = []
    removed_receipts: set[str] = set()
    for entry in reauthorings:
        if entry.addition is None:
            if entry.dependency_edit is None:
                raise ClassicReauthorError(
                    f"re-pointed action {entry.removed_action_id!r} names no donor"
                )
            dependency_edits.append(entry.dependency_edit)
            if entry.receipt_edit is not None:
                receipt_edits.append(entry.receipt_edit)
            continue
        old_receipt = unit_receipts.get(entry.removed_action_id)
        if old_receipt is None:
            raise ClassicReauthorError(f"refused action {entry.removed_action_id!r} has no receipt")
        intervention_edits.append(
            ClassicInterventionEdit(saved_actions[entry.removed_action_id], None)
        )
        receipt_edits.append(ClassicReceiptEdit(old_receipt, None))
        removed_receipts.add(old_receipt.id)
    for donor_id, (saved, beneficiaries) in donor_state.items():
        after = donor_after_usage(saved, beneficiaries, consumers[donor_id])
        if after is saved:
            continue
        intervention_edits.append(ClassicInterventionEdit(saved, after))
        if after is None:
            donor_receipt = unit_receipts.get(donor_id)
            if donor_receipt is not None and donor_receipt.id not in removed_receipts:
                receipt_edits.append(ClassicReceiptEdit(donor_receipt, None))
    return ClassicReauthorPlan(
        tuple(reauthorings),
        tuple(intervention_edits),
        tuple(receipt_edits),
        tuple(entry.addition for entry in reauthorings if entry.addition is not None),
        tuple(skipped),
        tuple(dependency_edits),
    )


def describe_reauthorings(items: Iterable[ClassicFunctionReauthoring]) -> str:
    """One human line per re-authored function for progress output."""

    return "; ".join(
        f"{entry.symbol} -> {entry.family} on {entry.donor_id}"
        + (" (re-pointed)" if entry.addition is None else "")
        + ("" if entry.donor_id == entry.previous_donor_id else f" (was {entry.previous_donor_id})")
        for entry in items
    )


__all__ = [
    "ClassicFunctionReauthoring",
    "ClassicReauthorError",
    "ClassicReauthorPlan",
    "describe_reauthorings",
    "plan_function_reauthoring",
]
