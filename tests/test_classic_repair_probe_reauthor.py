"""A retune candidate that emits a refused function's retail body is re-authored, not rejected."""

from __future__ import annotations

from hashlib import sha256

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic_donor_retune_materialization import MaterializedDonorRetuneCandidate
from reprobit.classic_donors import generate_declaration_shape, prepare_donor_compile_request
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import ClassicInterventionEdit, ClassicReceiptEdit
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


def test_a_candidate_that_emits_another_body_is_still_rejected() -> None:
    retail_body = coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:]
    refusal, prepared, materialized, _output_unused = _fixture(retail_body=retail_body)
    other = coff_fixture.make_coff(body=coff_fixture.BODY[:-1] + b"\xcc" + coff_fixture.BODY[-1:])
    with pytest.raises(MeasuredPinRepairError, match="rejected candidate"):
        validate_retuned_actions((refusal,), prepared, materialized, _output(prepared, other))


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
