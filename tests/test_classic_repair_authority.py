from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.classic_repair_authority import (
    ClassicAuthorityRepairError,
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
    apply_classic_authority_edits,
)
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
    ProjectSpec,
    ProofDocument,
    TargetSpec,
    ToolchainRef,
)
from reprobit.strict_json import canonical_json


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


def _spec() -> ProjectSpec:
    return ProjectSpec(
        schema_version=3,
        project_id="sample",
        state_dir=".reprobit-state",
        toolchain=ToolchainRef(profile="msvc420"),
        build=ProducerGraphBuildAdapter(),
        paths=LogicalPathProfile(source=r"R:\source", build=r"R:\build", toolchain=r"R:\toolchain"),
        targets=(TargetSpec(id="program", artifact="build/program.exe", oracle="o/program.exe"),),
    )


def _shard(tmp_path: Path, spec: ProjectSpec, unit: str) -> tuple[Path, Path]:
    intervention_root = tmp_path / spec.layout.interventions
    proof_root = tmp_path / spec.layout.proofs
    intervention_root.mkdir(parents=True, exist_ok=True)
    proof_root.mkdir(parents=True, exist_ok=True)
    intervention_path = intervention_root / f"{unit}.json"
    proof_path = proof_root / f"{unit}.json"
    intervention_path.write_bytes(
        canonical_json(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id=unit,
                source="src/unit.cpp",
                source_digest=Digest.from_bytes(b"source"),
                build_target="program",
                interventions=(
                    _donor().model_copy(
                        update={
                            "scope": Scope(target="program", translation_unit=unit),
                            "beneficiaries": (
                                Scope(
                                    target="program",
                                    translation_unit=unit,
                                    function="?Function@@YAXXZ",
                                ),
                            ),
                        }
                    ),
                ),
            )
        )
    )
    proof_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id=unit,
                expected_observations=(_receipt(),),
            )
        )
    )
    return intervention_path, proof_path


def test_additions_append_new_function_records_to_their_own_shard(tmp_path: Path) -> None:
    spec = _spec()
    intervention_path, proof_path = _shard(tmp_path, spec, "unit.fixture")
    other_intervention, other_proof = _shard(tmp_path, spec, "unit.other")
    other_before = (other_intervention.read_bytes(), other_proof.read_bytes())
    function = _function()
    receipt = ClassicProofReceipt(
        id="proof.function.fixture",
        intervention_id=function.id,
        family=function.family,
        expected_values={"expected_body_length": 8},
    )

    changed = apply_classic_authority_edits(
        tmp_path, spec, additions=(ClassicRecordAddition(function, receipt),)
    )

    assert changed == (
        f"{spec.layout.interventions}/unit.fixture.json",
        f"{spec.layout.proofs}/unit.fixture.json",
    )
    document = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    assert [item.id for item in document.interventions] == ["donor.fixture", "function.fixture"]
    proofs = ProofDocument.model_validate_json(proof_path.read_bytes())
    assert [item.id for item in proofs.expected_observations] == [
        "proof.donor.fixture",
        "proof.function.fixture",
    ]
    assert (other_intervention.read_bytes(), other_proof.read_bytes()) == other_before

    with pytest.raises(ClassicAuthorityRepairError, match="already exists"):
        apply_classic_authority_edits(
            tmp_path, spec, additions=(ClassicRecordAddition(function, receipt),)
        )
    homeless = function.model_copy(
        update={
            "scope": Scope(
                target="program", translation_unit="unit.missing", function=function.symbol
            )
        }
    )
    with pytest.raises(ClassicAuthorityRepairError, match="without documents"):
        apply_classic_authority_edits(
            tmp_path,
            spec,
            additions=(
                ClassicRecordAddition(
                    homeless, receipt.model_copy(update={"intervention_id": homeless.id})
                ),
            ),
        )


def test_addition_must_carry_its_own_receipt_and_a_unit_scope() -> None:
    with pytest.raises(ClassicAuthorityRepairError, match="does not describe"):
        ClassicRecordAddition(_function(), _receipt())
    # A fresh donor may be added together with the function records it serves.
    added = ClassicRecordAddition(_donor(), _receipt())
    assert added.intervention.role is ClassicRecipeRole.DONOR
    homeless = _function().model_copy(update={"scope": Scope(target="program"), "dependencies": ()})
    with pytest.raises(ClassicAuthorityRepairError, match="names no translation-unit shard"):
        ClassicRecordAddition(
            homeless,
            ClassicProofReceipt(
                id="proof.homeless",
                intervention_id=homeless.id,
                family=homeless.family,
            ),
        )


def test_dependency_edit_drops_only_parameters_bound_to_the_previous_donor() -> None:
    from reprobit.classic_repair_authority import ClassicDependencyEdit
    from reprobit.model import Scope
    from reprobit.schema import (
        ClassicField,
        ClassicRecipeFamily,
        ClassicRecipeIntervention,
        ClassicRecipeRole,
    )

    action = ClassicRecipeIntervention(
        id="fn.move",
        scope=Scope(target="program", translation_unit="unit", function="?f@@YAXXZ"),
        rationale="A rewriting record whose delta described its previous donor.",
        dependencies=("donor.old",),
        family=ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?f@@YAXXZ",
        parameters=(
            ClassicField(
                name="debug_representation_delta",
                value=[{"kind": "procedure_extent", "record_index": 0}],
            ),
            ClassicField(name="donor_rewriting", value={"kind": "donor_fp_bijection_rewriting_v1"}),
        ),
    )

    moved = ClassicDependencyEdit(action, "donor.new", ("debug_representation_delta",)).after
    assert moved.dependencies == ("donor.new",)
    assert [field.name for field in moved.parameters] == ["donor_rewriting"]
    kept = ClassicDependencyEdit(action, "donor.new").after
    assert kept.parameters == action.parameters

    with pytest.raises(Exception, match="not a parameter bound to the previous donor"):
        ClassicDependencyEdit(action, "donor.new", ("donor_rewriting",))
    with pytest.raises(Exception, match="not a parameter bound to the previous donor"):
        ClassicDependencyEdit(
            action.model_copy(update={"parameters": action.parameters[1:]}),
            "donor.new",
            ("debug_representation_delta",),
        )
