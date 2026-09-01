from __future__ import annotations

from hashlib import sha256

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirements,
)
from reprobit.coff_format import CoffObject, coff_body
from reprobit.model import Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)

SYMBOL = coff_fixture.TARGET_SYMBOL


def _body(payload: bytes, symbol: str = SYMBOL) -> bytes:
    coff = CoffObject(payload)
    return bytes(coff_body(coff, coff.function_section(symbol)))


def _donor(identifier: str, *beneficiaries: Scope) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program", translation_unit="tu_main"),
        rationale="Exercise retirement of a donor that fresh source no longer needs.",
        beneficiaries=tuple(
            sorted(
                beneficiaries,
                key=lambda item: (
                    item.target,
                    item.translation_unit or "",
                    item.function or "",
                ),
            )
        ),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
    )


def _action(
    identifier: str,
    donor: str,
    symbol: str = SYMBOL,
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program", translation_unit="tu_main", function=symbol),
        rationale="Exercise retirement of an action already emitted by fresh source.",
        dependencies=(donor,),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=symbol,
    )


def _receipt(action: ClassicRecipeIntervention, payload: bytes) -> ClassicProofReceipt:
    assert action.symbol is not None
    body = _body(payload, action.symbol)
    return ClassicProofReceipt(
        id=f"proof_{action.id}",
        intervention_id=action.id,
        family=action.family,
        expected_values={
            "expected_body_length": len(body),
            "expected_body_sha256": sha256(body).hexdigest(),
        },
    )


def test_redundant_action_retirement_removes_its_orphan_donor_and_proofs() -> None:
    seed = coff_fixture.make_coff()
    action = _action("function_old", "donor_old")
    donor = _donor("donor_old", action.scope)
    action_receipt = _receipt(action, seed)
    donor_receipt = ClassicProofReceipt(
        id="proof_donor_old",
        intervention_id=donor.id,
        family=donor.family,
    )

    result = plan_redundant_action_retirements(
        (donor, action),
        (donor_receipt, action_receipt),
        (
            (
                action,
                action_receipt,
                ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
            ),
        ),
    )

    assert [item.before.id for item in result.intervention_edits] == [
        action.id,
        donor.id,
    ]
    assert all(item.after is None for item in result.intervention_edits)
    assert {item.before.id for item in result.receipt_edits} == {
        action_receipt.id,
        donor_receipt.id,
    }
    assert result.removed_donors == (donor.id,)


def test_redundant_action_retirement_keeps_a_shared_donor_and_updates_beneficiaries() -> None:
    seed = coff_fixture.make_coff()
    removed = _action("function_removed", "donor_shared")
    remaining = _action("function_remaining", "donor_shared", "?Other@@YAXXZ")
    donor = _donor("donor_shared", removed.scope, remaining.scope)
    removed_receipt = _receipt(removed, seed)
    remaining_receipt = ClassicProofReceipt(
        id="proof_function_remaining",
        intervention_id=remaining.id,
        family=remaining.family,
    )

    result = plan_redundant_action_retirements(
        (donor, removed, remaining),
        (removed_receipt, remaining_receipt),
        (
            (
                removed,
                removed_receipt,
                ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
            ),
        ),
    )

    donor_edit = next(item for item in result.intervention_edits if item.before.id == donor.id)
    assert donor_edit.after is not None
    assert donor_edit.after.beneficiaries == (remaining.scope,)
    assert result.removed_donors == ()
    assert [item.before.id for item in result.receipt_edits] == [removed_receipt.id]


def test_redundant_action_retirement_does_not_touch_unrelated_orphan_donors() -> None:
    seed = coff_fixture.make_coff()
    action = _action("function_old", "donor_old")
    donor = _donor("donor_old", action.scope)
    unrelated = _donor("donor_unrelated")
    action_receipt = _receipt(action, seed)

    result = plan_redundant_action_retirements(
        (donor, unrelated, action),
        (action_receipt,),
        (
            (
                action,
                action_receipt,
                ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
            ),
        ),
    )

    assert unrelated.id not in {item.before.id for item in result.intervention_edits}


def test_redundant_action_retirement_keeps_a_donor_used_by_another_donor() -> None:
    seed = coff_fixture.make_coff()
    action = _action("function_old", "donor_old")
    donor = _donor("donor_old", action.scope)
    dependent = _donor("donor_dependent").model_copy(update={"dependencies": (donor.id,)})
    action_receipt = _receipt(action, seed)

    result = plan_redundant_action_retirements(
        (donor, dependent, action),
        (action_receipt,),
        (
            (
                action,
                action_receipt,
                ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
            ),
        ),
    )

    donor_edit = next(item for item in result.intervention_edits if item.before.id == donor.id)
    assert donor_edit.after is not None
    assert donor_edit.after.beneficiaries == ()
    assert result.removed_donors == ()


def test_redundant_action_retirement_refuses_a_different_fresh_body() -> None:
    seed = coff_fixture.make_coff()
    donor_object = coff_fixture.make_coff(body=b"\x90" + _body(seed)[1:])
    action = _action("function_old", "donor_old")
    donor = _donor("donor_old", action.scope)
    receipt = _receipt(action, donor_object)

    with pytest.raises(RedundantActionRepairError, match="does not already emit"):
        plan_redundant_action_retirements(
            (donor, action),
            (receipt,),
            (
                (
                    action,
                    receipt,
                    ClassicDispatchMaterials(
                        seed_object=seed,
                        donor_object=donor_object,
                    ),
                ),
            ),
        )


def test_redundant_action_retirements_remove_a_shared_donor_once() -> None:
    seed = coff_fixture.make_coff()
    first = _action("function_first", "donor_shared")
    second = _action(
        "function_second",
        "donor_shared",
        coff_fixture.OTHER_SYMBOL,
    )
    donor = _donor("donor_shared", first.scope, second.scope)
    first_receipt = _receipt(first, seed)
    second_receipt = _receipt(second, seed)
    donor_receipt = ClassicProofReceipt(
        id="proof_donor_shared",
        intervention_id=donor.id,
        family=donor.family,
    )
    materials = ClassicDispatchMaterials(seed_object=seed, donor_object=seed)

    result = plan_redundant_action_retirements(
        (donor, first, second),
        (donor_receipt, first_receipt, second_receipt),
        (
            (first, first_receipt, materials),
            (second, second_receipt, materials),
        ),
    )

    assert [item.before.id for item in result.intervention_edits] == [
        first.id,
        second.id,
        donor.id,
    ]
    assert all(item.after is None for item in result.intervention_edits)
    assert [item.before.id for item in result.intervention_edits if item.before.id == donor.id] == [
        donor.id
    ]
    assert {item.before.id for item in result.receipt_edits} == {
        donor_receipt.id,
        first_receipt.id,
        second_receipt.id,
    }
    assert result.removed_donors == (donor.id,)


def test_redundant_action_retirements_update_a_shared_donor_once_when_still_used() -> None:
    seed = coff_fixture.make_coff()
    first = _action("function_first", "donor_shared")
    second = _action(
        "function_second",
        "donor_shared",
        coff_fixture.OTHER_SYMBOL,
    )
    donor = _donor("donor_shared", first.scope, second.scope)
    dependent = _donor("donor_dependent").model_copy(update={"dependencies": (donor.id,)})
    first_receipt = _receipt(first, seed)
    second_receipt = _receipt(second, seed)
    materials = ClassicDispatchMaterials(seed_object=seed, donor_object=seed)

    result = plan_redundant_action_retirements(
        (donor, dependent, first, second),
        (first_receipt, second_receipt),
        (
            (first, first_receipt, materials),
            (second, second_receipt, materials),
        ),
    )

    donor_edits = [item for item in result.intervention_edits if item.before.id == donor.id]
    assert len(donor_edits) == 1
    assert donor_edits[0].after is not None
    assert donor_edits[0].after.beneficiaries == ()
    assert result.removed_donors == ()


def test_redundant_action_retirements_reject_duplicate_actions() -> None:
    seed = coff_fixture.make_coff()
    action = _action("function_old", "donor_old")
    receipt = _receipt(action, seed)
    materials = ClassicDispatchMaterials(seed_object=seed, donor_object=seed)

    with pytest.raises(RedundantActionRepairError, match="duplicate actions"):
        plan_redundant_action_retirements(
            (action,),
            (receipt,),
            (
                (action, receipt, materials),
                (action, receipt, materials),
            ),
        )


def test_redundant_action_retirements_reject_duplicate_proof_receipts() -> None:
    seed = coff_fixture.make_coff()
    first = _action("function_first", "donor_old")
    second = _action("function_second", "donor_old")
    receipt = _receipt(first, seed)
    materials = ClassicDispatchMaterials(seed_object=seed, donor_object=seed)

    with pytest.raises(RedundantActionRepairError, match="duplicate proof receipts"):
        plan_redundant_action_retirements(
            (first, second),
            (receipt,),
            (
                (first, receipt, materials),
                (second, receipt, materials),
            ),
        )


def test_redundant_action_retirements_require_a_candidate() -> None:
    with pytest.raises(RedundantActionRepairError, match="at least one candidate"):
        plan_redundant_action_retirements((), (), ())
