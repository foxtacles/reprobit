from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from reprobit.classic_repair_authority import (
    ClassicAuthorityRepairError,
    ClassicInterventionEdit,
    ClassicProjectOverlayEdit,
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


def _project_overlay() -> ClassicRecipeIntervention:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "end", "ctx": "0" * 64, "a": 0},
            "gen": {
                "k": "seq",
                "lines": 3,
                "items": [
                    {
                        "k": "member_probe",
                        "line": 1,
                        "lines": 2,
                        "function_identifier": "Probe",
                    },
                    {"k": "empty_class", "line": 3, "id": "Unused000"},
                ],
            },
        }
    ]
    values = {
        "graph": {"generated_tus": [], "link_admissions": []},
        "outputs": [
            {
                "clean": "1" * 64,
                "effective": "2" * 64,
                "ops": operations,
                "path": "src/unit.cpp",
                "size": 10,
            }
        ],
        "schema": 2,
    }
    return ClassicRecipeIntervention(
        id="project.fixture",
        scope=Scope(target="program"),
        rationale="Render one typed project source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value)  # type: ignore[arg-type]
            for name, value in sorted(values.items())
        ),
    )


def _project_overlay_after(
    before: ClassicRecipeIntervention,
    operations: list[object],
) -> ClassicRecipeIntervention:
    values = {field.name: field.value for field in before.parameters}
    outputs = [dict(item) for item in values["outputs"]]  # type: ignore[union-attr]
    outputs[0]["ops"] = operations
    outputs[0]["effective"] = "3" * 64
    outputs[0]["size"] = 12
    values["outputs"] = outputs
    return ClassicRecipeIntervention.model_validate(
        {
            **before.model_dump(mode="python"),
            "parameters": tuple(
                {"name": name, "value": value} for name, value in sorted(values.items())
            ),
        }
    )


def test_project_overlay_edit_accepts_only_a_trailing_inert_declaration() -> None:
    before = _project_overlay()
    operations = deepcopy(
        next(field.value for field in before.parameters if field.name == "outputs")[0]["ops"]
    )
    sequence = operations[0]["gen"]
    sequence["items"].append({"k": "empty_class", "line": 4, "id": "Unused001"})
    sequence["lines"] = 4
    after = _project_overlay_after(before, operations)

    assert ClassicProjectOverlayEdit(before, after).after == after

    assert ClassicProjectOverlayEdit(after, before).after == before


@pytest.mark.parametrize(
    "change",
    ["helper", "pin-only", "missing-line", "reorder", "non-tail"],
)
def test_project_overlay_edit_rejects_broader_or_unbound_changes(change: str) -> None:
    before = _project_overlay()
    operations = deepcopy(
        next(field.value for field in before.parameters if field.name == "outputs")[0]["ops"]
    )
    sequence = operations[0]["gen"]
    if change == "helper":
        sequence["items"][0]["function_identifier"] = "ChangedProbe"
    elif change == "missing-line":
        sequence["items"].append({"k": "empty_class", "id": "Unused001"})
        sequence["lines"] = 4
    elif change == "reorder":
        sequence["items"] = list(reversed(sequence["items"]))
    elif change == "non-tail":
        sequence["items"].insert(0, {"k": "empty_class", "line": 1, "id": "Unused001"})
        sequence["lines"] = 4
    after = _project_overlay_after(before, operations)

    with pytest.raises(ClassicAuthorityRepairError):
        ClassicProjectOverlayEdit(before, after)


def _receipt() -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof.donor.fixture",
        intervention_id="donor.fixture",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        expected_values={"rendered_sha256": "before"},
    )


def _function_receipt(
    intervention: ClassicRecipeIntervention,
    identifier: str,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=identifier,
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values={"expected_body_length": 8},
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


def test_reauthoring_preserves_the_independent_action_and_receipt_slots(
    tmp_path: Path,
) -> None:
    spec = _spec()
    intervention_path, proof_path = _shard(tmp_path, spec, "unit.fixture")
    before_interventions = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    before_proofs = ProofDocument.model_validate_json(proof_path.read_bytes())
    old = _function().model_copy(update={"id": "function.old"})
    trailing = _function().model_copy(
        update={
            "id": "function.trailing",
            "scope": Scope(
                target="program",
                translation_unit="unit.fixture",
                function="?Trailing@@YAXXZ",
            ),
            "symbol": "?Trailing@@YAXXZ",
        }
    )
    old_receipt = _function_receipt(old, "proof.function.old")
    trailing_receipt = _function_receipt(trailing, "proof.function.trailing")
    intervention_path.write_bytes(
        canonical_json(
            before_interventions.model_copy(
                update={
                    "interventions": (
                        before_interventions.interventions[0],
                        old,
                        trailing,
                    )
                }
            )
        )
    )
    # The old action and receipt deliberately occupy different indices.
    proof_path.write_bytes(
        canonical_json(
            before_proofs.model_copy(
                update={
                    "expected_observations": (
                        trailing_receipt,
                        before_proofs.expected_observations[0],
                        old_receipt,
                    )
                }
            )
        )
    )
    replacement = old.model_copy(update={"id": "function.replacement"})
    replacement_receipt = _function_receipt(replacement, "proof.function.replacement")

    apply_classic_authority_edits(
        tmp_path,
        spec,
        interventions=(ClassicInterventionEdit(old, None),),
        receipts=(ClassicReceiptEdit(old_receipt, None),),
        additions=(
            ClassicRecordAddition(
                replacement,
                replacement_receipt,
                replaces_intervention_id=old.id,
            ),
        ),
    )

    interventions = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    assert [item.id for item in interventions.interventions] == [
        "donor.fixture",
        "function.replacement",
        "function.trailing",
    ]
    proofs = ProofDocument.model_validate_json(proof_path.read_bytes())
    assert [item.id for item in proofs.expected_observations] == [
        "proof.function.trailing",
        "proof.donor.fixture",
        "proof.function.replacement",
    ]


def test_addition_requires_exactly_one_matching_proof_shard(tmp_path: Path) -> None:
    spec = _spec()
    intervention_path, proof_path = _shard(tmp_path, spec, "unit.fixture")
    function = _function()
    receipt = _function_receipt(function, "proof.function.fixture")
    addition = ClassicRecordAddition(function, receipt)

    proof_path.unlink()
    intervention_before = intervention_path.read_bytes()
    with pytest.raises(ClassicAuthorityRepairError, match="without documents"):
        apply_classic_authority_edits(tmp_path, spec, additions=(addition,))
    assert intervention_path.read_bytes() == intervention_before

    proof_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
                expected_observations=(_receipt(),),
            )
        )
    )
    duplicate_path = proof_path.with_name("unit.fixture-copy.json")
    duplicate_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
            )
        )
    )
    before = {path: path.read_bytes() for path in (intervention_path, proof_path, duplicate_path)}
    with pytest.raises(ClassicAuthorityRepairError, match="more than one proof document"):
        apply_classic_authority_edits(tmp_path, spec, additions=(addition,))
    assert {path: path.read_bytes() for path in before} == before


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
