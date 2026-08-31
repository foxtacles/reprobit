from __future__ import annotations

from typing import cast

import pytest

from reprobit.classic.repair_dispatch import (
    ClassicActionDispatchResult,
    ClassicMeasuredReceiptRepair,
    ClassicMeasuredReceiptRepairRequest,
    dispatch_classic_action,
)
from reprobit.classic_donors import matching_candidate_constraints
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)


def _intervention() -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="function.repair",
        scope=Scope(target="program", translation_unit="unit", function="?work@@YAXXZ"),
        rationale="Exercise the measured repair dispatch boundary.",
        dependencies=("donor",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?work@@YAXXZ",
    )


def _receipt(
    intervention: ClassicRecipeIntervention,
    length: int,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof.repair",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values={"expected_body_length": length},
    )


class _Dispatcher:
    def __init__(self, *outcomes: ClassicCandidate | Exception) -> None:
        self.outcomes = list(outcomes)
        self.materials: list[ClassicDispatchMaterials] = []

    def dispatch(
        self,
        _intervention: ClassicRecipeIntervention,
        materials: ClassicDispatchMaterials,
    ) -> ClassicCandidate:
        self.materials.append(materials)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _dispatch(
    dispatcher: _Dispatcher,
    repair: ClassicMeasuredReceiptRepair | None,
) -> tuple[ClassicActionDispatchResult, ClassicProofReceipt, ClassicRecipeIntervention]:
    intervention = _intervention()
    receipt = _receipt(intervention, 7)
    result = dispatch_classic_action(
        cast(ClassicFamilyDispatcher, dispatcher),
        intervention,
        ClassicDispatchMaterials(
            seed_object=b"seed",
            donor_object=b"donor",
            candidate_constraints=matching_candidate_constraints(
                intervention, (receipt,)
            ).materialize(),
        ),
        receipt,
        cast(ClassicPreparedUnit, object()),
        3,
        repair,
    )
    return result, receipt, intervention


def test_ordinary_dispatch_does_not_enter_the_repair_seam() -> None:
    candidate = cast(ClassicCandidate, object())

    def unexpected(request: ClassicMeasuredReceiptRepairRequest) -> ClassicProofReceipt | None:
        del request
        pytest.fail("ordinary dispatch must not request a repair")

    result, _receipt_value, _intervention_value = _dispatch(_Dispatcher(candidate), unexpected)

    assert result.candidate is candidate
    assert result.provisional_repair is False


def test_declined_repair_marks_analysis_incomplete_without_broadening_authority() -> None:
    requests: list[ClassicMeasuredReceiptRepairRequest] = []

    def decline(request: ClassicMeasuredReceiptRepairRequest) -> None:
        requests.append(request)

    result, receipt, intervention = _dispatch(
        _Dispatcher(ClassicProjectError("saved measurement is stale")), decline
    )

    assert result.candidate is None
    assert result.provisional_repair is True
    assert len(requests) == 1
    assert requests[0].intervention is intervention
    assert requests[0].receipt is receipt
    assert requests[0].action_index == 3
    assert str(requests[0].failure) == "saved measurement is stale"


def test_repaired_receipt_retries_the_same_ordinary_dispatcher() -> None:
    candidate = cast(ClassicCandidate, object())
    dispatcher = _Dispatcher(ClassicProjectError("stale"), candidate)

    def repair(request: ClassicMeasuredReceiptRepairRequest) -> ClassicProofReceipt:
        return request.receipt.model_copy(update={"expected_values": {"expected_body_length": 8}})

    result, _receipt_value, _intervention_value = _dispatch(dispatcher, repair)

    assert result.candidate is candidate
    assert result.provisional_repair is True
    assert len(dispatcher.materials) == 2
    assert dispatcher.materials[1].candidate_constraints == {"expected_body_length": 8}


def test_repair_cannot_change_the_receipt_shape() -> None:
    def broaden(request: ClassicMeasuredReceiptRepairRequest) -> ClassicProofReceipt:
        return request.receipt.model_copy(
            update={
                "expected_values": {
                    "expected_body_length": 8,
                    "unexpected_new_authority": True,
                }
            }
        )

    with pytest.raises(ClassicProjectError, match="changed more than expected values"):
        _dispatch(_Dispatcher(ClassicProjectError("stale")), broaden)
