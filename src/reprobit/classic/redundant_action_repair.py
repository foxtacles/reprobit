"""Plan removal of classic function actions made redundant by fresh source."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from reprobit.classic.repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.coff_format import CoffObject, coff_body
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    Intervention,
    candidate_auxiliary_donor_ids,
)


class RedundantActionRepairError(RuntimeError):
    """Fresh compiler output does not prove that an action is redundant."""


@dataclass(frozen=True, slots=True)
class RedundantActionRetirement:
    """Exact authority edits needed to retire now-redundant actions."""

    intervention_edits: tuple[ClassicInterventionEdit, ...]
    receipt_edits: tuple[ClassicReceiptEdit, ...]
    removed_donors: tuple[str, ...]


def _fresh_body(materials: ClassicDispatchMaterials, symbol: str) -> bytes:
    if type(materials.seed_object) is not bytes or not materials.seed_object:
        raise RedundantActionRepairError("redundant-action repair needs a fresh seed object")
    try:
        parsed = CoffObject(materials.seed_object)
        return bytes(coff_body(parsed, parsed.function_section(symbol)))
    except (KeyError, ValueError) as exc:
        raise RedundantActionRepairError(
            "fresh seed object does not expose the action's exact function"
        ) from exc


def _receipt_by_intervention(
    receipts: tuple[ClassicProofReceipt, ...],
) -> dict[str, ClassicProofReceipt]:
    values: dict[str, ClassicProofReceipt] = {}
    for receipt in receipts:
        if receipt.intervention_id in values:
            raise RedundantActionRepairError(
                f"intervention {receipt.intervention_id!r} has ambiguous proof receipts"
            )
        values[receipt.intervention_id] = receipt
    return values


def _consumer_donor_ids(
    intervention: Intervention,
    receipts: dict[str, ClassicProofReceipt],
) -> set[str]:
    result = set(intervention.dependencies)
    if not (
        isinstance(intervention, ClassicRecipeIntervention)
        and intervention.role is ClassicRecipeRole.FUNCTION
    ):
        return result
    receipt = receipts.get(intervention.id)
    if receipt is None:
        raise RedundantActionRepairError(
            f"classic function {intervention.id!r} lacks one proof receipt"
        )
    parameters = {field.name: field.value for field in intervention.parameters}
    result.update(candidate_auxiliary_donor_ids(parameters, receipt.expected_values))
    return result


def plan_redundant_action_retirements(
    interventions: tuple[Intervention, ...],
    receipts: tuple[ClassicProofReceipt, ...],
    candidates: tuple[
        tuple[
            ClassicRecipeIntervention,
            ClassicProofReceipt,
            ClassicDispatchMaterials,
        ],
        ...,
    ],
) -> RedundantActionRetirement:
    """Retire proven actions and reconcile their shared donors in one atomic plan."""

    if not candidates:
        raise RedundantActionRepairError("redundant-action repair needs at least one candidate")
    action_ids = [action.id for action, _, _ in candidates]
    if len(set(action_ids)) != len(action_ids):
        raise RedundantActionRepairError(
            "redundant-action repair candidates contain duplicate actions"
        )
    receipt_ids = [receipt.id for _, receipt, _ in candidates]
    if len(set(receipt_ids)) != len(receipt_ids):
        raise RedundantActionRepairError(
            "redundant-action repair candidates contain duplicate proof receipts"
        )

    for action, receipt, materials in candidates:
        if action.role is not ClassicRecipeRole.FUNCTION or action.symbol is None:
            raise RedundantActionRepairError(
                "redundant-action repair accepts only function recipes"
            )
        matches = [item for item in interventions if item.id == action.id]
        if len(matches) != 1 or matches[0] != action:
            raise RedundantActionRepairError("failed action differs from committed authority")
        receipt_matches = [item for item in receipts if item.intervention_id == action.id]
        if len(receipt_matches) != 1 or receipt_matches[0] != receipt:
            raise RedundantActionRepairError("failed action proof differs from committed authority")
        goal = receipt.expected_values.get("expected_body_sha256")
        if not isinstance(goal, str) or len(goal) != 64:
            raise RedundantActionRepairError("failed action has no immutable body goal")
        body = _fresh_body(materials, action.symbol)
        if sha256(body).hexdigest() != goal:
            raise RedundantActionRepairError(
                "fresh source does not already emit the immutable body goal"
            )
        expected_length = receipt.expected_values.get("expected_body_length")
        if expected_length is not None and expected_length != len(body):
            raise RedundantActionRepairError("fresh source body length differs from its saved goal")

    retiring_ids = set(action_ids)
    remaining = tuple(item for item in interventions if item.id not in retiring_ids)
    remaining_receipts = tuple(
        item for item in receipts if item.intervention_id not in retiring_ids
    )
    receipt_index = _receipt_by_intervention(remaining_receipts)
    retiring_receipt_index = _receipt_by_intervention(
        tuple(receipt for _, receipt, _ in candidates)
    )
    affected_donors: set[str] = set()
    for action, _, _ in candidates:
        affected_donors.update(_consumer_donor_ids(action, retiring_receipt_index))
    references: set[str] = set()
    consumers: dict[str, dict[tuple[str, str, str], object]] = {}
    for intervention in remaining:
        donor_ids = _consumer_donor_ids(intervention, receipt_index)
        references.update(donor_ids)
        scope = intervention.scope
        if scope.function is None or scope.translation_unit is None:
            continue
        key = (scope.target, scope.translation_unit, scope.function)
        for donor_id in donor_ids:
            consumers.setdefault(donor_id, {})[key] = scope

    intervention_edits = [ClassicInterventionEdit(action, None) for action, _, _ in candidates]
    removed_donors: list[str] = []
    removed_ids = set(retiring_ids)
    for intervention in interventions:
        if not (
            isinstance(intervention, ClassicRecipeIntervention)
            and intervention.role is ClassicRecipeRole.DONOR
            and intervention.id in affected_donors
        ):
            continue
        expected = tuple(
            consumers.get(intervention.id, {})[key]
            for key in sorted(consumers.get(intervention.id, {}))
        )
        if expected == intervention.beneficiaries:
            continue
        if intervention.id not in references:
            intervention_edits.append(ClassicInterventionEdit(intervention, None))
            removed_donors.append(intervention.id)
            removed_ids.add(intervention.id)
            continue
        intervention_edits.append(
            ClassicInterventionEdit(
                intervention,
                intervention.model_copy(update={"beneficiaries": expected}),
            )
        )

    receipt_edits = tuple(
        ClassicReceiptEdit(item, None) for item in receipts if item.intervention_id in removed_ids
    )
    selected_receipt_ids = {item.before.id for item in receipt_edits}
    if not set(receipt_ids).issubset(selected_receipt_ids):
        raise RedundantActionRepairError("failed action proof was not selected for retirement")
    return RedundantActionRetirement(
        tuple(intervention_edits),
        receipt_edits,
        tuple(sorted(removed_donors, key=str.casefold)),
    )


__all__ = [
    "RedundantActionRepairError",
    "RedundantActionRetirement",
    "plan_redundant_action_retirements",
]
