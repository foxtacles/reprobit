"""Closed measured-repair seam for classic function composition."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Protocol

from reprobit.binary import ByteIdentityError
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic_donors import DonorSourceError, matching_candidate_constraints
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicTranslationUnitPlan,
)


class _ClassicRepairUnit(Protocol):
    """Small unit view needed at the dispatch boundary."""

    @property
    def plan(self) -> ClassicTranslationUnitPlan: ...


@dataclass(frozen=True, slots=True)
class ClassicMeasuredReceiptRepairRequest:
    """One failed saved action plus the exact fresh materials that rejected it."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    materials: ClassicDispatchMaterials
    failure: Exception
    unit: _ClassicRepairUnit
    action_index: int
    unit_donor_objects: Mapping[str, bytes] = field(default_factory=dict)
    """Every fresh donor object of the unit, so a repair may re-seat the action."""


class ClassicMeasuredReceiptRepair(Protocol):
    """Repair-only measured-pin callback; certification never supplies one."""

    def __call__(
        self, request: ClassicMeasuredReceiptRepairRequest
    ) -> ClassicProofReceipt | None: ...


@dataclass(frozen=True, slots=True)
class ClassicActionDispatchResult:
    """Ordinary dispatch result, or an incomplete repair-analysis boundary."""

    candidate: ClassicCandidate | None
    provisional_repair: bool


_DISPATCH_FAILURES = (
    ByteIdentityError,
    ClassicProjectError,
    ClassicSemanticError,
    DonorSourceError,
)


def dispatch_classic_action(
    dispatcher: ClassicFamilyDispatcher,
    intervention: ClassicRecipeIntervention,
    materials: ClassicDispatchMaterials,
    receipt: ClassicProofReceipt,
    unit: _ClassicRepairUnit,
    action_index: int,
    measured_receipt_repair: ClassicMeasuredReceiptRepair | None,
    unit_donor_objects: Mapping[str, bytes] | None = None,
) -> ClassicActionDispatchResult:
    """Dispatch normally, then retry one narrowly repaired receipt when authorized."""

    try:
        candidate = dispatcher.dispatch(intervention, materials)
    except _DISPATCH_FAILURES as exc:
        repaired_receipt = (
            measured_receipt_repair(
                ClassicMeasuredReceiptRepairRequest(
                    intervention,
                    receipt,
                    materials,
                    exc,
                    unit,
                    action_index,
                    dict(unit_donor_objects or {}),
                )
            )
            if measured_receipt_repair is not None
            else None
        )
        if repaired_receipt is None:
            if measured_receipt_repair is not None:
                return ClassicActionDispatchResult(None, True)
            raise ClassicProjectError(
                f"classic action {intervention.id!r} "
                f"({intervention.family.value}, {intervention.symbol!r}) failed: {exc}"
            ) from exc
        if (
            repaired_receipt.id != receipt.id
            or repaired_receipt.intervention_id != receipt.intervention_id
            or repaired_receipt.family is not receipt.family
            or repaired_receipt.expected_values.keys() != receipt.expected_values.keys()
            or repaired_receipt.model_copy(update={"expected_values": receipt.expected_values})
            != receipt
        ):
            raise ClassicProjectError(
                f"repair for classic action {intervention.id!r} changed more than expected values"
            ) from exc
        repaired_values = matching_candidate_constraints(
            intervention, (repaired_receipt,)
        ).materialize()
        try:
            candidate = dispatcher.dispatch(
                intervention,
                replace(materials, candidate_constraints=repaired_values),
            )
        except _DISPATCH_FAILURES as repaired_exc:
            raise ClassicProjectError(
                f"classic action {intervention.id!r} repair did not satisfy its ordinary "
                f"composer: {repaired_exc}"
            ) from repaired_exc
        return ClassicActionDispatchResult(candidate, True)
    return ClassicActionDispatchResult(candidate, False)


__all__ = [
    "ClassicActionDispatchResult",
    "ClassicMeasuredReceiptRepair",
    "ClassicMeasuredReceiptRepairRequest",
    "dispatch_classic_action",
]
