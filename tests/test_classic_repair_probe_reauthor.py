"""A retune candidate that emits a refused function's retail body is re-authored, not rejected."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture
import test_classic_relational_form_full as relational_fixture

from reprobit.classic_donor_retune_materialization import MaterializedDonorRetuneCandidate
from reprobit.classic_donors import generate_declaration_shape, prepare_donor_compile_request
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
)
from reprobit.classic_repair_probe_candidates import (
    RetunedActionReauthoring,
    retune_authority_edits,
    validate_retuned_actions,
)
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.coff_format import CoffObject, coff_body
from reprobit.execution import StepExecutionReceipt
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


def _donor(functions: int) -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(1, functions)
    return ClassicRecipeIntervention(
        id="donor.saved",
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Framework-generated declaration-only compiler-state shape for the fixture.",
        beneficiaries=(Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),),
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


def _prepared(donor: ClassicRecipeIntervention) -> ClassicPreparedDonor:
    return ClassicPreparedDonor(
        donor,
        prepare_donor_compile_request(
            donor,
            source_path="src/unit.cpp",
            clean_source=SOURCE,
            effective_source=SOURCE,
            receipts=(_receipt(donor),),
        ),
    )


def _output(prepared: ClassicPreparedDonor, object_payload: bytes) -> ClassicDonorProbeOutput:
    request = prepared.request
    digest = Digest.from_bytes(b"step")
    return ClassicDonorProbeOutput(
        prepared.intervention.id,
        "unit.fixture",
        request.build_target,
        request.logical_source,
        "compiler.fixture",
        tuple(
            ClassicDonorProbeInput(path, Digest.from_bytes(payload), len(payload), payload)
            for path, payload in request.logical_outputs.items()
        ),
        Digest.from_bytes(object_payload),
        Digest.from_bytes(b"pdb"),
        object_payload,
        b"pdb",
        StepExecutionReceipt("probe", 0, 1, 0.0, digest, digest),
    )


def _fixture(*, retail_body: bytes):
    seed = coff_fixture.make_coff()
    retail = coff_fixture.make_coff(body=retail_body)
    saved = _donor(3)
    retuned = _donor(5)
    prepared_saved = _prepared(saved)
    action = ClassicRecipeIntervention(
        id="function.saved",
        scope=Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),
        rationale="Saved equal-body record whose donor no longer emits the retail body.",
        dependencies=("donor.saved",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=SYMBOL,
    )
    receipt = _receipt(
        action,
        expected_body_length=len(coff_fixture.BODY),
        expected_body_sha256=sha256(_body(retail)).hexdigest(),
        expected_changed_offsets=[0],
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (prepared_saved,),
        (action,),
        (),
        (action,),
        (_receipt(saved), receipt),
    )
    refusal = ClassicRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
        unit=unit,
        reason="fresh donor body no longer matches immutable expected_body_sha256 goal",
        unit_donor_objects={"donor.saved": seed},
    )
    materialized = MaterializedDonorRetuneCandidate(retuned, _receipt(retuned), 2, ())
    return refusal, prepared_saved, materialized, _output(_prepared(retuned), retail)


def test_a_resized_retail_body_is_re_authored_under_the_cheapest_closed_family() -> None:
    # The candidate emits the retail body, one byte longer than the seed's: the saved
    # equal-length family cannot compose it, same_slot_resize can.
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, output = _fixture(retail_body=retail_body)
    (result,) = validate_retuned_actions((refusal,), prepared, materialized, output)
    assert isinstance(result, RetunedActionReauthoring)
    assert result.action.id == "function.saved"
    assert result.addition.intervention.family is ClassicRecipeFamily.SAME_SLOT_RESIZE
    assert result.addition.intervention.symbol == SYMBOL
    assert result.addition.intervention.dependencies == ("donor.saved",)
    assert result.addition.replaces_intervention_id == "function.saved"
    assert "rejected candidate" not in result.saved_refusal
    interventions, receipts, additions = retune_authority_edits(
        prepared, _receipt(prepared.intervention), (refusal,), materialized, (result,)
    )
    assert interventions[0] == ClassicInterventionEdit(
        prepared.intervention, materialized.intervention
    )
    assert ClassicInterventionEdit(refusal.intervention, None) in interventions
    assert ClassicReceiptEdit(refusal.receipt, None) in receipts
    assert additions == (result.addition,)


@pytest.mark.parametrize("exact", [False, True], ids=["relational-close", "exact"])
def test_auxiliary_retune_uses_the_normalized_cross_tu_goal(exact: bool) -> None:
    symbol = relational_fixture.TARGET_SYMBOL
    seed = relational_fixture.fixture.make_coff(body=relational_fixture.BODY)
    retail_body, _proof = relational_fixture.reversed_image()
    primary_body = relational_fixture.BODY if exact else retail_body
    candidate_body = retail_body if exact else relational_fixture.BODY
    primary_object = relational_fixture.fixture.make_coff(body=primary_body)
    candidate_object = relational_fixture.fixture.make_coff(body=candidate_body)
    beneficiary = (Scope(target="program", translation_unit="unit.fixture", function=symbol),)
    primary = _donor(7).model_copy(update={"id": "donor.primary", "beneficiaries": beneficiary})
    auxiliary = _donor(3).model_copy(update={"beneficiaries": beneficiary})
    retuned = _donor(5).model_copy(update={"beneficiaries": beneficiary})
    prepared_auxiliary = _prepared(auxiliary)
    prepared_retuned = _prepared(retuned)
    action = ClassicRecipeIntervention(
        id="function.cross-tu",
        scope=Scope(target="program", translation_unit="unit.fixture", function=symbol),
        rationale="Saved cross-file resize whose auxiliary donor changed shape.",
        dependencies=(primary.id,),
        family=ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=symbol,
        parameters=(ClassicField(name="complete_donor", value=auxiliary.id),),
    )
    receipt = _receipt(
        action,
        expected_normalized_body_sha256=sha256(retail_body).hexdigest(),
        retail_oracle={
            "address": f"0x{relational_fixture.fixture.RETAIL_ADDRESS:08x}",
            "image": "SAMPLE.DLL",
            "length": len(retail_body),
            "verdict": "MATCH",
        },
        retail_relocations=relational_fixture.fixture.relocation_oracle(seed),
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (_prepared(primary), prepared_auxiliary),
        (action,),
        (),
        (action,),
        (_receipt(primary), _receipt(auxiliary), receipt),
    )
    refusal = ClassicRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(
            seed_object=seed,
            donor_object=primary_object,
            complete_donor_object=seed,
        ),
        unit=unit,
        reason="target donor body/table census changed",
        unit_donor_objects={primary.id: primary_object, auxiliary.id: seed},
        retail_body=retail_body,
    )
    materialized = MaterializedDonorRetuneCandidate(retuned, _receipt(retuned), 2, ())

    (result,) = validate_retuned_actions(
        (refusal,),
        prepared_retuned,
        materialized,
        _output(prepared_retuned, candidate_object),
    )

    assert isinstance(result, RetunedActionReauthoring)
    replacement = result.addition.intervention
    expected_family = (
        ClassicRecipeFamily.EQUAL_BODY_STRICT
        if exact
        else ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING
    )
    assert replacement.family is expected_family
    assert replacement.dependencies == (auxiliary.id,)
    assert result.addition.replaces_intervention_id == action.id
    assert "expected_body_sha256" not in receipt.expected_values
    if not exact:
        assert (
            result.addition.receipt.expected_values["expected_donor_body_sha256"]
            == sha256(relational_fixture.BODY).hexdigest()
        )


def test_retune_reauthoring_retires_orphaned_auxiliary_donors() -> None:
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, output = _fixture(retail_body=retail_body)
    (result,) = validate_retuned_actions((refusal,), prepared, materialized, output)
    assert isinstance(result, RetunedActionReauthoring)
    parameter_donor = _donor(7).model_copy(update={"id": "donor.parameter"})
    receipt_donor = _donor(8).model_copy(update={"id": "donor.receipt"})
    action = refusal.intervention.model_copy(
        update={
            "parameters": (
                ClassicField(
                    name="donor_variants",
                    value=[{"donor": parameter_donor.id}],
                ),
            ),
        }
    )
    receipt = refusal.receipt.model_copy(
        update={
            "expected_values": {
                **refusal.receipt.expected_values,
                "complete_donor": receipt_donor.id,
            }
        }
    )
    unit = replace(
        refusal.unit,
        donors=(*refusal.unit.donors, _prepared(parameter_donor), _prepared(receipt_donor)),
        functions=(action,),
        actions=(action,),
        receipts=(
            *(
                item
                for item in refusal.unit.receipts
                if item.intervention_id != refusal.intervention.id
            ),
            _receipt(parameter_donor),
            _receipt(receipt_donor),
            receipt,
        ),
    )
    refusal = replace(refusal, intervention=action, receipt=receipt, unit=unit)
    result = replace(result, action=action, receipt=receipt)

    interventions, receipts, _additions = retune_authority_edits(
        prepared,
        _receipt(prepared.intervention),
        (refusal,),
        materialized,
        (result,),
    )

    edits = {edit.before.id: edit.after for edit in interventions}
    assert edits[parameter_donor.id] is None
    assert edits[receipt_donor.id] is None
    assert {edit.before.id for edit in receipts} >= {
        f"proof.{parameter_donor.id}",
        f"proof.{receipt_donor.id}",
    }


def _auxiliary_reauthoring_case(
    *, keep_consumer: bool
) -> tuple[
    ClassicPreparedDonor,
    ClassicProofReceipt,
    ClassicRepairRefusal,
    MaterializedDonorRetuneCandidate,
    RetunedActionReauthoring,
]:
    beneficiary_symbols = tuple(sorted((SYMBOL, "?Keeper@@YAXXZ"))) if keep_consumer else (SYMBOL,)
    scopes = tuple(
        Scope(target="program", translation_unit="unit.fixture", function=symbol)
        for symbol in beneficiary_symbols
    )
    saved = _donor(3).model_copy(update={"beneficiaries": scopes})
    retuned = _donor(5).model_copy(update={"beneficiaries": scopes})
    primary = _donor(7).model_copy(
        update={
            "id": "donor.primary",
            "beneficiaries": (
                Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),
            ),
        }
    )
    action = ClassicRecipeIntervention(
        id="function.auxiliary",
        scope=Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),
        rationale="Fixture record using a separately retuned target donor.",
        dependencies=(primary.id,),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=SYMBOL,
        parameters=(ClassicField(name="target_donor", value=saved.id),),
    )
    action_receipt = _receipt(action)
    replacement = action.model_copy(update={"id": "function.reauthored", "parameters": ()})
    replacement_receipt = _receipt(replacement)
    keeper = ClassicRecipeIntervention(
        id="function.keeper",
        scope=Scope(target="program", translation_unit="unit.fixture", function="?Keeper@@YAXXZ"),
        rationale="Fixture consumer retaining the retuned donor.",
        dependencies=(saved.id,),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?Keeper@@YAXXZ",
    )
    functions = (action, keeper) if keep_consumer else (action,)
    donor_receipt = _receipt(saved, expected_functions=3)
    keeper_receipts = (_receipt(keeper),) if keep_consumer else ()
    receipts = (
        donor_receipt,
        _receipt(primary),
        action_receipt,
        *keeper_receipts,
    )
    prepared = _prepared(saved)
    prepared_primary = _prepared(primary)
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (prepared, prepared_primary),
        functions,
        (),
        functions,
        receipts,
    )
    seed = coff_fixture.make_coff()
    refusal = ClassicRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=action_receipt,
        materials=ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
        unit=unit,
        reason="fixture refusal",
        unit_donor_objects={saved.id: seed, primary.id: seed},
    )
    materialized = MaterializedDonorRetuneCandidate(
        retuned,
        _receipt(retuned, expected_functions=5),
        2,
        (),
    )
    result = RetunedActionReauthoring(
        action,
        action_receipt,
        ClassicRecordAddition(
            replacement,
            replacement_receipt,
            replaces_intervention_id=action.id,
        ),
        "fixture refusal",
    )
    return prepared, donor_receipt, refusal, materialized, result


def test_retuned_auxiliary_donor_is_retained_with_one_merged_edit() -> None:
    prepared, donor_receipt, refusal, materialized, result = _auxiliary_reauthoring_case(
        keep_consumer=True
    )

    interventions, receipts, _additions = retune_authority_edits(
        prepared, donor_receipt, (refusal,), materialized, (result,)
    )

    donor_edits = [edit for edit in interventions if edit.before.id == prepared.intervention.id]
    assert len(donor_edits) == 1
    assert donor_edits[0].after is not None
    assert donor_edits[0].after.parameters == materialized.intervention.parameters
    assert [scope.function for scope in donor_edits[0].after.beneficiaries] == ["?Keeper@@YAXXZ"]
    assert [edit.before.id for edit in receipts].count(donor_receipt.id) == 1
    donor_receipt_edit = next(edit for edit in receipts if edit.before.id == donor_receipt.id)
    assert donor_receipt_edit.after == materialized.receipt


def test_orphaned_retuned_auxiliary_discards_the_retune_edits() -> None:
    prepared, donor_receipt, refusal, materialized, result = _auxiliary_reauthoring_case(
        keep_consumer=False
    )

    interventions, receipts, _additions = retune_authority_edits(
        prepared, donor_receipt, (refusal,), materialized, (result,)
    )

    donor_edits = [edit for edit in interventions if edit.before.id == prepared.intervention.id]
    donor_receipt_edits = [edit for edit in receipts if edit.before.id == donor_receipt.id]
    assert donor_edits == [ClassicInterventionEdit(prepared.intervention, None)]
    assert donor_receipt_edits == [ClassicReceiptEdit(donor_receipt, None)]


def test_a_candidate_that_emits_another_body_is_still_rejected() -> None:
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, _output_unused = _fixture(retail_body=retail_body)
    other = coff_fixture.make_coff(body=coff_fixture.BODY[:-1] + b"\xcc" + coff_fixture.BODY[-1:])
    with pytest.raises(MeasuredPinRepairError, match="rejected candidate"):
        validate_retuned_actions((refusal,), prepared, materialized, _output(prepared, other))


def test_retune_does_not_strip_a_source_aware_mosaic_without_its_captured_goal() -> None:
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, output = _fixture(retail_body=retail_body)
    action = refusal.intervention.model_copy(
        update={
            "family": ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
            "parameters": (
                ClassicField(name="instruction_ranges", value=[]),
                ClassicField(name="target_source_refactor", value={"kind": "fixture"}),
            ),
        }
    )
    receipt = refusal.receipt.model_copy(update={"family": action.family})
    unit = replace(
        refusal.unit,
        functions=(action,),
        actions=(action,),
        receipts=tuple(
            receipt if item.intervention_id == action.id else item for item in refusal.unit.receipts
        ),
    )
    guarded = replace(
        refusal,
        intervention=action,
        receipt=receipt,
        unit=unit,
        retail_body=None,
    )

    with pytest.raises(MeasuredPinRepairError, match="rejected candidate"):
        validate_retuned_actions((guarded,), prepared, materialized, output)


def test_edits_refuse_a_re_authoring_that_answers_another_action() -> None:
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, output = _fixture(retail_body=retail_body)
    (result,) = validate_retuned_actions((refusal,), prepared, materialized, output)
    assert isinstance(result, RetunedActionReauthoring)
    stranger = refusal.intervention.model_copy(update={"id": "function.other"})
    with pytest.raises(ValueError, match="does not answer"):
        retune_authority_edits(
            prepared,
            _receipt(prepared.intervention),
            (refusal,),
            materialized,
            (RetunedActionReauthoring(stranger, result.receipt, result.addition, ""),),
        )
