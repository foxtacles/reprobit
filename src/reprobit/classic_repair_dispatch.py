"""Closed measured-repair seam for classic function composition."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

from reprobit.binary import ByteIdentityError
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic_donors import DonorSourceError, matching_candidate_constraints
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicTranslationUnitPlan,
    LegacyOracleInstallIntervention,
)
from reprobit.strict_json import canonical_json

if TYPE_CHECKING:
    from reprobit.oracle_pe32 import PE32VirtualAddressReader

ADMITTED_ADDED_PIN_KEYS = frozenset({"debug_representation_delta"})
"""Pins a measured repair may state on a receipt that never carried them.

The debug representation delta is an observation of the fresh seed/donor
pair the same-slot validator consumes; every other pin is refreshed in
place and never added or dropped.
"""


class _ClassicRepairUnit(Protocol):
    """Small unit view needed at the dispatch boundary."""

    @property
    def plan(self) -> ClassicTranslationUnitPlan: ...


@dataclass(frozen=True, slots=True)
class CapturedDonorObject:
    """One fresh donor object a repair analysis composed with, bound to its recipe.

    ``identity`` digests the donor intervention that produced ``data``; a later
    pass that retuned the donor no longer matches it, so the capture is dropped.
    """

    identity: str
    data: bytes


def donor_recipe_identity(intervention: ClassicRecipeIntervention) -> str:
    """Digest of the exact donor recipe a captured object was compiled from.

    Beneficiaries name consumers, not compiler input, so widening them keeps
    the identity (and the capture) valid.
    """

    return Digest.from_bytes(
        canonical_json(intervention.model_dump(mode="json", exclude={"beneficiaries"}))
    ).value


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
    oracle: PE32VirtualAddressReader | None = None
    """Repair-only sealed target reader; callbacks must retain only finite bytes."""


@dataclass(frozen=True, slots=True)
class LegacyOracleInstallRepairRequest:
    """One failed legacy action at its exact staged composition seat."""

    intervention: LegacyOracleInstallIntervention
    receipt: ClassicProofReceipt
    materials: ClassicDispatchMaterials
    failure: Exception
    unit: _ClassicRepairUnit
    action_index: int
    oracle: PE32VirtualAddressReader
    unit_donor_objects: Mapping[str, bytes] = field(default_factory=dict)


class ClassicMeasuredReceiptRepair(Protocol):
    """Repair-only measured-pin callback; certification never supplies one."""

    def record_action_preimage(
        self,
        unit_id: str,
        action_index: int,
        intervention_id: str,
        preimage: bytes,
    ) -> None: ...

    def release_completed_unit_preimages(self, unit_id: str) -> None: ...

    def __call__(
        self, request: ClassicMeasuredReceiptRepairRequest
    ) -> ClassicProofReceipt | None: ...

    def record_legacy_failure(self, request: LegacyOracleInstallRepairRequest) -> None: ...


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
    repair_oracle: PE32VirtualAddressReader | None = None,
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
                    repair_oracle,
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
            or receipt.expected_values.keys() - repaired_receipt.expected_values.keys()
            or (repaired_receipt.expected_values.keys() - receipt.expected_values.keys())
            - ADMITTED_ADDED_PIN_KEYS
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
    "CapturedDonorObject",
    "ClassicActionDispatchResult",
    "ClassicMeasuredReceiptRepair",
    "ClassicMeasuredReceiptRepairRequest",
    "LegacyOracleInstallRepairRequest",
    "dispatch_classic_action",
    "donor_recipe_identity",
]
