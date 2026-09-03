from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic_donors import generate_declaration_shape, prepare_donor_compile_request
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_reauthor import (
    describe_reauthorings,
    plan_function_reauthoring,
)
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.coff_format import CoffObject, coff_body
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
)

SOURCE = b"int reprobit_fixture;\n"
SYMBOL = coff_fixture.TARGET_SYMBOL


def _body(payload: bytes) -> bytes:
    obj = CoffObject(payload)
    return bytes(coff_body(obj, obj.function_section(SYMBOL)))


def _donor(identifier: str, functions: int, *beneficiaries: str) -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(1, functions)
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Framework-generated declaration-only compiler-state shape for the fixture.",
        beneficiaries=tuple(
            Scope(target="program", translation_unit="unit.fixture", function=symbol)
            for symbol in beneficiaries
        ),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value)
            for name, value in sorted(
                {
                    "classes": 1,
                    "emission_policy": "non_emitting_declarations_only",
                    "functions": functions,
                    "generated_header_sha256": Digest.from_bytes(generated).value,
                }.items()
            )
        ),
    )


def _receipt(intervention: ClassicRecipeIntervention, **values: object) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=f"proof.{intervention.id}",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values=dict(values),
    )


def _fixture(
    *, goal_donor: str
) -> tuple[
    ClassicRepairRefusal, bytes, bytes, ClassicRecipeIntervention, ClassicRecipeIntervention
]:
    seed = coff_fixture.make_coff()
    retail_body = bytearray(coff_fixture.BODY)
    retail_body[0] = 0x90
    retail = coff_fixture.make_coff(body=bytes(retail_body))
    first = _donor("donor.first", 3, SYMBOL)
    second = _donor("donor.second", 5)
    donors = tuple(
        ClassicPreparedDonor(
            donor,
            prepare_donor_compile_request(
                donor,
                source_path="src/unit.cpp",
                clean_source=SOURCE,
                effective_source=SOURCE,
                receipts=(_receipt(donor),),
            ),
        )
        for donor in (first, second)
    )
    action = ClassicRecipeIntervention(
        id="function.saved",
        scope=Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),
        rationale="Saved equal-body record whose donor no longer emits the retail body.",
        dependencies=("donor.first",),
        family=ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=SYMBOL,
    )
    action_receipt = _receipt(
        action,
        expected_body_sha256=sha256(_body(retail)).hexdigest(),
        expected_seed_length=len(coff_fixture.BODY),
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        donors,
        (action,),
        (),
        (action,),
        (_receipt(first), _receipt(second), action_receipt),
    )
    # donor.first's fresh object no longer carries the goal; the named donor does.
    objects = {"donor.first": seed, "donor.second": seed}
    objects[goal_donor] = retail
    refusal = ClassicRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=action_receipt,
        materials=ClassicDispatchMaterials(seed_object=seed, donor_object=objects["donor.first"]),
        unit=unit,
        reason="fresh donor body no longer matches immutable expected_body_sha256 goal",
        unit_donor_objects=objects,
    )
    return refusal, seed, retail, first, second


def test_reauthors_onto_the_unit_donor_that_carries_the_goal_body() -> None:
    refusal, _seed, _retail, _first, _second = _fixture(goal_donor="donor.second")

    plan = plan_function_reauthoring((refusal,))

    assert plan.skipped == ()
    assert len(plan.reauthorings) == 1
    entry = plan.reauthorings[0]
    assert entry.donor_id == "donor.second"
    assert entry.previous_donor_id == "donor.first"
    assert entry.family == "equal_body_strict"
    assert entry.removed_action_id == "function.saved"
    addition = plan.additions[0]
    assert addition.intervention.dependencies == ("donor.second",)
    assert addition.intervention.family is ClassicRecipeFamily.EQUAL_BODY_STRICT
    assert (
        addition.receipt.expected_values["expected_body_sha256"]
        == (refusal.receipt.expected_values["expected_body_sha256"])
    )
    removed = {edit.before.id: edit.after for edit in plan.intervention_edits}
    # The old record goes; donor.first has no consumer left and is retired; donor.second
    # gains the function as a beneficiary.
    assert removed["function.saved"] is None
    assert removed["donor.first"] is None
    second_after = removed["donor.second"]
    assert second_after is not None
    assert [scope.function for scope in second_after.beneficiaries] == [SYMBOL]
    assert {edit.before.id: edit.after for edit in plan.receipt_edits} == {
        "proof.function.saved": None,
        "proof.donor.first": None,
    }
    assert "was donor.first" in describe_reauthorings(plan.reauthorings)


def test_reauthors_under_a_cheaper_family_on_the_same_donor() -> None:
    refusal, _seed, _retail, _first, _second = _fixture(goal_donor="donor.first")

    plan = plan_function_reauthoring((refusal,))

    assert len(plan.reauthorings) == 1
    entry = plan.reauthorings[0]
    assert entry.donor_id == entry.previous_donor_id == "donor.first"
    assert entry.family == "equal_body_strict"
    # Same donor: only the record is replaced; beneficiaries and consumers are unchanged.
    assert {edit.before.id for edit in plan.intervention_edits} == {"function.saved"}
    assert {edit.before.id for edit in plan.receipt_edits} == {"proof.function.saved"}


def test_refusals_without_a_goal_body_or_a_matching_donor_are_reported_not_guessed() -> None:
    refusal, seed, _retail, _first, _second = _fixture(goal_donor="donor.second")
    no_goal = ClassicRepairRefusal(
        **{
            **{f: getattr(refusal, f) for f in refusal.__slots__},  # type: ignore[attr-defined]
            "receipt": refusal.receipt.model_copy(update={"expected_values": {}}),
        }
    )
    plan = plan_function_reauthoring((no_goal,))
    assert plan.reauthorings == ()
    assert plan.skipped[0][2] == "receipt carries no expected_body_sha256 goal"

    nobody = ClassicRepairRefusal(
        **{
            **{f: getattr(refusal, f) for f in refusal.__slots__},  # type: ignore[attr-defined]
            "unit_donor_objects": {"donor.first": seed, "donor.second": seed},
        }
    )
    plan = plan_function_reauthoring((nobody,))
    assert plan.reauthorings == ()
    assert "no captured donor object carries the goal body" in plan.skipped[0][2]
    assert plan.intervention_edits == () and plan.additions == ()


def test_a_function_is_never_re_seated_onto_another_overlay_donor() -> None:
    refusal, _seed, _retail, _first, second = _fixture(goal_donor="donor.second")
    overlay = second.model_copy(
        update={
            "family": ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
            "parameters": (),
        }
    )
    donors = tuple(
        ClassicPreparedDonor(overlay, item.request)
        if item.intervention.id == "donor.second"
        else item
        for item in refusal.unit.donors
    )
    unit = ClassicPreparedUnit(
        refusal.unit.plan,
        donors,
        refusal.unit.functions,
        refusal.unit.legacy_actions,
        refusal.unit.actions,
        refusal.unit.receipts,
    )
    guarded = ClassicRepairRefusal(
        **{
            **{f: getattr(refusal, f) for f in refusal.__slots__},  # type: ignore[attr-defined]
            "unit": unit,
        }
    )

    plan = plan_function_reauthoring((guarded,))

    assert plan.reauthorings == ()
    assert "no captured donor object carries the goal body" in plan.skipped[0][2]


def test_a_goal_body_no_closed_family_can_host_moves_the_saved_record_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reprobit.classic_repair_reauthor as module
    from reprobit.classic_measured_pin_repair import MeasuredPinRepairError
    from reprobit.discovery_authoring import DiscoveryAuthoringError

    refusal, _seed, _retail, _first, _second = _fixture(goal_donor="donor.second")

    def no_family(**_kwargs: object) -> object:
        raise DiscoveryAuthoringError("seed and donor bodies are no longer the same length")

    monkeypatch.setattr(module, "build_measured_function_record", no_family)
    seen: list[tuple[str, str]] = []

    def repoint(moved: object, receipt: object, materials: object) -> object:
        seen.append((moved.dependencies[0], sha256(materials.donor_object).hexdigest()[:8]))  # type: ignore[attr-defined]
        refreshed = receipt.model_copy(  # type: ignore[attr-defined]
            update={"expected_values": {**receipt.expected_values, "expected_seed_length": 99}}  # type: ignore[attr-defined]
        )
        return SimpleNamespace(receipt=refreshed, changed_keys=("expected_seed_length",))

    monkeypatch.setattr(module, "repair_measured_pins", repoint)

    plan = plan_function_reauthoring((refusal,))

    assert seen == [
        ("donor.second", sha256(refusal.unit_donor_objects["donor.second"]).hexdigest()[:8])
    ]
    (entry,) = plan.reauthorings
    assert entry.addition is None
    assert entry.family == ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT.value
    assert (entry.previous_donor_id, entry.donor_id) == ("donor.first", "donor.second")
    (dependency,) = plan.dependency_edits
    assert dependency.before is refusal.intervention and dependency.donor_id == "donor.second"
    assert plan.additions == ()
    # The saved record is kept: its receipt moves, the retired donor's receipt goes,
    # and the donors' beneficiaries follow the function.
    receipt_edits = {edit.before.id: edit.after for edit in plan.receipt_edits}
    assert set(receipt_edits) == {"proof.function.saved", "proof.donor.first"}
    assert receipt_edits["proof.donor.first"] is None
    assert receipt_edits["proof.function.saved"].expected_values["expected_seed_length"] == 99  # type: ignore[union-attr]
    edited = {edit.before.id: edit.after for edit in plan.intervention_edits}
    assert edited["donor.first"] is None  # no consumer and no beneficiary left
    assert [scope.function for scope in edited["donor.second"].beneficiaries] == [SYMBOL]  # type: ignore[union-attr]
    assert "re-pointed" in describe_reauthorings(plan.reauthorings)

    # A re-point the family refuses is reported, never guessed.
    def refuse(*_args: object) -> object:
        raise MeasuredPinRepairError("seed census changed")

    monkeypatch.setattr(module, "repair_measured_pins", refuse)
    plan = plan_function_reauthoring((refusal,))
    assert plan.reauthorings == () and plan.dependency_edits == ()
    assert "re-point: seed census changed" in plan.skipped[0][2]


def test_repointed_action_drops_the_previous_pairs_debug_delta_only() -> None:
    from reprobit.classic_repair_session import repointed_action

    refusal, _seed, _retail, _first, _second = _fixture(goal_donor="donor.second")
    declared = refusal.intervention.model_copy(
        update={
            "parameters": (
                ClassicField(
                    name="debug_representation_delta",
                    value=[{"kind": "procedure_extent", "record_index": 0}],
                ),
                ClassicField(name="donor_rewriting", value={"kind": "x"}),
            )
        }
    )

    moved = repointed_action(declared, "donor.second")

    assert moved.dependencies == ("donor.second",)
    assert [field.name for field in moved.parameters] == ["donor_rewriting"]
    assert moved.id == declared.id and moved.family is declared.family
    untouched = repointed_action(refusal.intervention, "donor.second")
    assert untouched.parameters == refusal.intervention.parameters
