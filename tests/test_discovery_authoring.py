from __future__ import annotations

from hashlib import sha256

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic.composition import compose_equal_body_comdat
from reprobit.classic_donors import (
    generate_declaration_shape,
    merge_candidate_constraints,
    validate_donor_recipe,
)
from reprobit.coff import CoffObject, coff_body
from reprobit.costs import calculate_cost
from reprobit.discovery_authoring import (
    AuthoredClassicRecord,
    DeclarationShapeEqualBodyAuthoring,
    DiscoveryAuthoringError,
    build_declaration_shape_donor,
    build_declaration_shape_equal_body,
    merge_authored_records,
)
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    ProofDocument,
)

TARGET_ID = "program"
TRANSLATION_UNIT_ID = "tu.transform"
BUILD_TARGET = "program"
SYMBOL = coff_fixture.TARGET_SYMBOL


def _objects(*, relocations: tuple[int, ...] = coff_fixture.RELOCATIONS) -> tuple[bytes, bytes]:
    donor_body = bytearray(coff_fixture.BODY)
    donor_body[0] = 0x90
    return (
        coff_fixture.make_coff(),
        coff_fixture.make_coff(body=bytes(donor_body), relocations=relocations),
    )


def _author() -> DeclarationShapeEqualBodyAuthoring:
    seed, donor = _objects()
    return build_declaration_shape_equal_body(
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        build_target=BUILD_TARGET,
        symbol=SYMBOL,
        classes=1,
        functions=3,
        seed_object=seed,
        donor_object=donor,
    )


def test_build_declaration_shape_donor_is_deterministic_and_closed() -> None:
    arguments = {
        "target_id": TARGET_ID,
        "translation_unit_id": TRANSLATION_UNIT_ID,
        "build_target": BUILD_TARGET,
        "classes": 1,
        "functions": 3,
        "beneficiary_symbols": (SYMBOL,),
    }
    record = build_declaration_shape_donor(**arguments)
    provisional = build_declaration_shape_donor(
        **{name: value for name, value in arguments.items() if name != "beneficiary_symbols"}
    )

    assert record == build_declaration_shape_donor(**arguments)
    assert provisional.intervention.beneficiaries == ()
    assert provisional.intervention.id == record.intervention.id
    assert provisional.receipt.id == record.receipt.id
    intervention = record.intervention
    assert intervention.family is ClassicRecipeFamily.DECLARATION_SHAPE
    assert intervention.role is ClassicRecipeRole.DONOR
    assert intervention.scope == Scope(target=TARGET_ID, translation_unit=TRANSLATION_UNIT_ID)
    assert intervention.beneficiaries == (
        Scope(target=TARGET_ID, translation_unit=TRANSLATION_UNIT_ID, function=SYMBOL),
    )
    assert record.receipt.intervention_id == intervention.id
    assert record.receipt.family is intervention.family
    assert record.receipt.expected_values == {}

    parameters = {field.name: field.value for field in intervention.parameters}
    generated = generate_declaration_shape(1, 3)
    generated_digest = sha256(generated).hexdigest()
    assert list(parameters) == sorted(parameters)
    assert parameters == {
        "classes": 1,
        "emission_policy": "non_emitting_declarations_only",
        "functions": 3,
        "generated_header_sha256": generated_digest,
    }
    constraints = merge_candidate_constraints(intervention, record.receipt)
    assert validate_donor_recipe(intervention, constraints).generated_declarations == generated


def test_build_equal_body_pair_has_exact_runtime_replayable_pins() -> None:
    seed, donor = _objects()
    authored = _author()

    assert authored == _author()
    donor_intervention = authored.donor.intervention
    function = authored.function.intervention
    assert donor_intervention.beneficiaries == (function.scope,)
    assert function.family is ClassicRecipeFamily.EQUAL_BODY_STRICT
    assert function.role is ClassicRecipeRole.FUNCTION
    assert function.symbol == SYMBOL
    assert function.dependencies == (donor_intervention.id,)
    assert function.parameters == ()

    expected = authored.function.receipt.expected_values
    donor_body = bytes(coff_body(CoffObject(donor), CoffObject(donor).function_section(SYMBOL)))
    assert expected == {
        "expected_body_length": len(donor_body),
        "expected_body_sha256": sha256(donor_body).hexdigest(),
        "expected_changed_offsets": [0],
    }

    constraints = merge_candidate_constraints(function, authored.function.receipt).materialize()
    composed, _ = compose_equal_body_comdat(
        seed,
        donor,
        {**constraints, "mangled": SYMBOL, "splice_class": "equal_body_strict"},
    )
    assert authored.candidate_object == composed
    assert authored.composition_proof.mangled == SYMBOL
    assert authored.composition_proof.section_number == 1
    assert authored.composition_proof.body_length == len(donor_body)
    assert authored.composition_proof.body_changed_offsets == (0,)
    composed_coff = CoffObject(composed)
    assert bytes(coff_body(composed_coff, composed_coff.function_section(SYMBOL))) == donor_body


def test_build_equal_body_pair_refuses_noop_and_structural_mismatch() -> None:
    seed, donor = _objects()
    common = {
        "target_id": TARGET_ID,
        "translation_unit_id": TRANSLATION_UNIT_ID,
        "build_target": BUILD_TARGET,
        "symbol": SYMBOL,
        "classes": 1,
        "functions": 3,
        "seed_object": seed,
    }
    with pytest.raises(DiscoveryAuthoringError, match="bodies are identical"):
        build_declaration_shape_equal_body(**common, donor_object=seed)

    _, incompatible_donor = _objects(relocations=(coff_fixture.RELOCATIONS[0],))
    with pytest.raises(DiscoveryAuthoringError, match="cannot author strict equal-body"):
        build_declaration_shape_equal_body(**common, donor_object=incompatible_donor)

    with pytest.raises(DiscoveryAuthoringError, match="immutable bytes"):
        build_declaration_shape_equal_body(**common, donor_object=bytearray(donor))  # type: ignore[arg-type]


def test_build_donor_refuses_invalid_campaign_inputs() -> None:
    with pytest.raises(DiscoveryAuthoringError, match="unique"):
        build_declaration_shape_donor(
            target_id=TARGET_ID,
            translation_unit_id=TRANSLATION_UNIT_ID,
            build_target=BUILD_TARGET,
            classes=1,
            functions=3,
            beneficiary_symbols=(SYMBOL, SYMBOL),
        )


def test_merge_authored_records_preserves_shard_metadata_and_refuses_collisions() -> None:
    authored = _author()
    source = b"int transform();\n"
    interventions = InterventionDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        source="src/transform.cpp",
        source_digest=Digest.from_bytes(source),
        build_target=BUILD_TARGET,
    )
    proofs = ProofDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
    )

    merged_interventions, merged_proofs = merge_authored_records(
        interventions,
        proofs,
        authored.records,
    )
    assert interventions.interventions == ()
    assert proofs.expected_observations == ()
    assert merged_interventions.source == interventions.source
    assert merged_interventions.source_digest == interventions.source_digest
    assert merged_interventions.interventions == tuple(
        record.intervention for record in authored.records
    )
    assert merged_proofs.expected_observations == tuple(
        record.receipt for record in authored.records
    )

    with pytest.raises(DiscoveryAuthoringError, match="identifier collision"):
        merge_authored_records(merged_interventions, merged_proofs, authored.records)


def test_merge_authored_records_reuses_one_donor_for_a_second_symbol() -> None:
    first = _author()
    source = b"int transform();\n"
    interventions = InterventionDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        source="src/transform.cpp",
        source_digest=Digest.from_bytes(source),
        build_target=BUILD_TARGET,
    )
    proofs = ProofDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
    )
    first_interventions, first_proofs = merge_authored_records(
        interventions,
        proofs,
        first.records,
    )
    second_donor = build_declaration_shape_donor(
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        build_target=BUILD_TARGET,
        classes=1,
        functions=3,
        beneficiary_symbols=(coff_fixture.OTHER_SYMBOL,),
    )
    second_function = ClassicRecipeIntervention(
        id="discovery.function.second",
        scope=Scope(
            target=TARGET_ID,
            translation_unit=TRANSLATION_UNIT_ID,
            function=coff_fixture.OTHER_SYMBOL,
        ),
        rationale="Strict equal-size COMDAT body selection from one shared private donor.",
        dependencies=(second_donor.intervention.id,),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target=BUILD_TARGET,
        symbol=coff_fixture.OTHER_SYMBOL,
    )
    second_function_record = AuthoredClassicRecord(
        second_function,
        ClassicProofReceipt(
            id="discovery.proof.second",
            intervention_id=second_function.id,
            family=second_function.family,
        ),
    )

    merged_interventions, merged_proofs = merge_authored_records(
        first_interventions,
        first_proofs,
        (second_donor, second_function_record),
    )

    donors = tuple(
        item
        for item in merged_interventions.interventions
        if isinstance(item, ClassicRecipeIntervention) and item.role is ClassicRecipeRole.DONOR
    )
    assert len(donors) == 1
    assert donors[0].id == first.donor.intervention.id == second_donor.intervention.id
    assert donors[0].beneficiaries == tuple(
        sorted(
            (first.function.intervention.scope, second_function.scope),
            key=lambda scope: scope.function or "",
        )
    )
    assert len(merged_interventions.interventions) == 3
    assert len(merged_proofs.expected_observations) == 3
    assert calculate_cost(first_interventions.interventions).project_total == 26
    merged_cost = calculate_cost(merged_interventions.interventions)
    assert merged_cost.project_total == 51
    assert merged_cost.unallocated_shared_cost == 0
    assert len(merged_cost.by_function) == 2
    assert all(item.direct_cost == 25 for item in merged_cost.by_function)
    assert all(
        (item.allocated_shared_cost.numerator, item.allocated_shared_cost.denominator) == (1, 2)
        for item in merged_cost.by_function
    )
    assert all(item.exposure_cost == 1 for item in merged_cost.by_function)


def test_merge_authored_records_refuses_a_conflicting_existing_donor() -> None:
    authored = _author()
    conflicting = authored.donor.intervention.model_copy(
        update={"rationale": "Different declaration donor authority must not share this ID."}
    )
    interventions = InterventionDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        build_target=BUILD_TARGET,
        interventions=(conflicting,),
    )
    proofs = ProofDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        expected_observations=(authored.donor.receipt,),
    )

    with pytest.raises(DiscoveryAuthoringError, match="identifier collision"):
        merge_authored_records(interventions, proofs, (authored.donor,))


def test_merge_authored_records_refuses_nonmatching_shards_and_build_targets() -> None:
    authored = _author()
    interventions = InterventionDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        build_target=BUILD_TARGET,
    )
    wrong_shard = ProofDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id="tu.other",
    )
    with pytest.raises(DiscoveryAuthoringError, match="different shards"):
        merge_authored_records(interventions, wrong_shard, authored.records)

    wrong_target = InterventionDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
        build_target="other",
    )
    proofs = ProofDocument(
        schema_version=3,
        target_id=TARGET_ID,
        translation_unit_id=TRANSLATION_UNIT_ID,
    )
    with pytest.raises(DiscoveryAuthoringError, match="different build target"):
        merge_authored_records(wrong_target, proofs, authored.records)
