from __future__ import annotations

import pytest

from reprobit.classic_repair_authority import (
    ClassicAuthorityRepairError,
    ClassicInterventionEdit,
    ClassicReceiptEdit,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)


def _donor() -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="donor.fixture",
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Provide a private declaration-shape donor.",
        beneficiaries=(
            Scope(
                target="program",
                translation_unit="unit.fixture",
                function="?Function@@YAXXZ",
            ),
        ),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
    )


def _function() -> ClassicRecipeIntervention:
    symbol = "?Function@@YAXXZ"
    return ClassicRecipeIntervention(
        id="function.fixture",
        scope=Scope(
            target="program",
            translation_unit="unit.fixture",
            function=symbol,
        ),
        rationale="Compose one function from the private donor.",
        dependencies=("donor.fixture",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=symbol,
    )


def _receipt() -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof.donor.fixture",
        intervention_id="donor.fixture",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        expected_values={"rendered_sha256": "before"},
    )


def test_receipt_replacement_allows_only_expected_values() -> None:
    before = _receipt()
    after = before.model_copy(update={"expected_values": {"rendered_sha256": "after"}})

    assert ClassicReceiptEdit(before, after).after == after

    changed_status = after.model_copy(update={"status": "freshly measured"})
    with pytest.raises(ClassicAuthorityRepairError, match="outside expected values"):
        ClassicReceiptEdit(before, changed_status)


@pytest.mark.parametrize(
    "update",
    [
        {"parameters": (ClassicField(name="classes", value=2),)},
        {"beneficiaries": ()},
    ],
)
def test_intervention_replacement_allows_current_donor_adjustments(
    update: dict[str, object],
) -> None:
    before = _donor()
    after = before.model_copy(update=update)

    assert ClassicInterventionEdit(before, after).after == after


@pytest.mark.parametrize(
    "update",
    [
        {"dependencies": ("unrelated",)},
        {"rationale": "A replacement must not rewrite review rationale."},
    ],
)
def test_intervention_replacement_rejects_fields_outside_donor_adjustments(
    update: dict[str, object],
) -> None:
    before = _donor()
    after = before.model_copy(update=update)

    with pytest.raises(ClassicAuthorityRepairError, match="outside donor parameters"):
        ClassicInterventionEdit(before, after)


def test_intervention_replacement_rejects_function_parameter_adjustment() -> None:
    before = _function()
    after = before.model_copy(update={"parameters": (ClassicField(name="candidate", value=1),)})

    with pytest.raises(ClassicAuthorityRepairError, match="not a donor adjustment"):
        ClassicInterventionEdit(before, after)


def test_intervention_replacement_revalidates_model_copy_updates() -> None:
    before = _donor()
    invalid = before.model_copy(
        update={
            "beneficiaries": (
                Scope(
                    target="other-program",
                    translation_unit="unit.fixture",
                    function="?Function@@YAXXZ",
                ),
            )
        }
    )

    with pytest.raises(ClassicAuthorityRepairError, match="replacement is invalid"):
        ClassicInterventionEdit(before, invalid)


def test_receipt_replacement_revalidates_model_copy_updates() -> None:
    before = _receipt()
    invalid = before.model_copy(update={"expected_values": {"unsupported": object()}})

    with pytest.raises(ClassicAuthorityRepairError, match="replacement is invalid"):
        ClassicReceiptEdit(before, invalid)
