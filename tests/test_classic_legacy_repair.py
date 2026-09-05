from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest
import test_classic_simulated_elision_full as fixture
from test_classic_fpo_mosaic_identity import (
    OTHER_SYMBOL as FPO_OTHER_SYMBOL,
)
from test_classic_fpo_mosaic_identity import codeview_stream as fpo_codeview_stream
from test_classic_fpo_mosaic_identity import make_coff as make_fpo_coff

import reprobit.classic_orchestration as orchestration
import reprobit.classic_quarantine as quarantine
import reprobit.classic_repair_probe_candidates as probe_candidates
from reprobit.classic_legacy_repair import (
    LegacyInstallRepair,
    LegacyNoWindowError,
    LegacyOracleMaterial,
    LegacyRepairError,
    capture_legacy_oracle_material,
    plan_legacy_no_window_resolution,
    reauthor_legacy_simulated_elision,
)
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import (
    ClassicAuthorityRepairError,
    ClassicReceiptEdit,
    LegacyInterventionEdit,
    apply_classic_authority_edits,
)
from reprobit.classic_repair_session import LegacyRepairRefusal
from reprobit.coff_format import CoffObject, detailed_relocations
from reprobit.model import ByteRange, Digest, Scope
from reprobit.oracle_pe32 import LegacyInstallError
from reprobit.project_loader import load_project
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    OracleInstallRange,
    ProofDocument,
)
from reprobit.strict_json import canonical_json


def _authority() -> tuple[LegacyOracleInstallIntervention, ClassicProofReceipt]:
    seed = fixture.make_coff()
    donor = fixture.make_coff()
    values = fixture.function_record(seed, donor, fixture.IMAGE)
    values["simulated_elision"] = {
        **values["simulated_elision"],
        "regions": [
            {
                "region_start": 1,
                "region_end": 2,
                "image_start": 1,
                "image_length": 1,
            },
            fixture.region_declaration(),
        ],
    }
    receipt = ClassicProofReceipt(
        id="proof.legacy.fixture",
        intervention_id="legacy.fixture",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
        expected_values=values,
    )
    ranges = (
        OracleInstallRange(
            preimage_range=ByteRange(offset=1, length=1),
            output_range=ByteRange(offset=1, length=1),
            oracle_range=ByteRange(offset=1, length=1),
        ),
        OracleInstallRange(
            preimage_range=ByteRange(offset=fixture.REGION[0], length=2),
            output_range=ByteRange(offset=fixture.REGION[0], length=2),
            oracle_range=ByteRange(offset=fixture.REGION[0], length=2),
        ),
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.fixture",
        scope=Scope(
            target="program",
            translation_unit="unit.fixture",
            function=fixture.TARGET_SYMBOL,
        ),
        rationale="Finite fixture quarantine.",
        dependencies=("donor.fixture",),
        proof_receipt_digest=Digest.from_bytes(canonical_json(receipt)),
        preimage_digest=Digest.from_bytes(fixture.BODY),
        oracle_body_digest=Digest.from_bytes(fixture.IMAGE),
        oracle_target="program",
        oracle_address=fixture.schedule.RETAIL_ADDRESS,
        ranges=ranges,
        byte_count=3,
        maximum_oracle_payload_bytes=len(fixture.IMAGE),
    )
    return action, receipt


def _refreeze(
    action: LegacyOracleInstallIntervention, **updates: object
) -> LegacyOracleInstallIntervention:
    fields = {
        name: getattr(action, name)
        for name in type(action).model_fields
        if name != "allowlist_digest"
    }
    fields.update(updates)
    return LegacyOracleInstallIntervention.freeze(**fields)


def _donor_authority(
    action: LegacyOracleInstallIntervention,
) -> tuple[ClassicRecipeIntervention, ClassicProofReceipt]:
    donor = ClassicRecipeIntervention(
        id=action.dependencies[0],
        scope=Scope(target=action.scope.target, translation_unit=action.scope.translation_unit),
        rationale="Fixture donor.",
        beneficiaries=(action.scope,),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
    )
    return donor, ClassicProofReceipt(
        id="proof.donor.fixture",
        intervention_id=donor.id,
        family=donor.family,
    )


def _relocated_zero_window_authority():
    action, receipt = _authority()
    seed_body = bytes.fromhex("8b0500000000c3")
    donor_body = bytes.fromhex("8b0d00000000c3")
    debug_stream = fpo_codeview_stream(len(seed_body), debug_start=0, debug_end=6)
    seed_object = make_fpo_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, FPO_OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (6, 12)),
    )
    donor_object = make_fpo_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((2, FPO_OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (6, 12)),
    )
    parsed = CoffObject(donor_object)
    row = detailed_relocations(parsed, parsed.function_section(fixture.TARGET_SYMBOL))[0]
    retail_target = 0x12345678
    retail_body = bytearray(donor_body)
    retail_body[2:6] = retail_target.to_bytes(4, "little")
    retail = bytes(retail_body)
    relocation = {
        key: (f"0x{retail_target:08x}" if key == "retail_target" else row[key])
        for key in (
            "addend",
            "offset",
            "retail_target",
            "target",
            "target_section",
            "target_storage",
            "target_type",
            "target_value",
            "type",
        )
    }
    receipt = receipt.model_copy(
        update={
            "expected_values": {
                **receipt.expected_values,
                "expected_body_length": len(retail),
                "expected_body_sha256": sha256(donor_body).hexdigest(),
                "retail_oracle": {
                    "address": f"0x{action.oracle_address:08x}",
                    "image": "PROGRAM.EXE",
                    "length": len(retail),
                    "verdict": "MATCH",
                },
                "retail_relocations": [relocation],
            }
        }
    )
    action = _refreeze(
        action,
        maximum_oracle_payload_bytes=len(retail),
        oracle_body_digest=Digest.from_bytes(donor_body),
        preimage_digest=Digest.from_bytes(donor_body),
        proof_receipt_digest=Digest.from_bytes(canonical_json(receipt)),
    )
    donor, donor_receipt = _donor_authority(action)
    return (
        action,
        receipt,
        donor,
        donor_receipt,
        seed_object,
        donor_object,
        donor_body,
        retail,
    )


def test_reauthor_drops_an_unneeded_old_range_and_strictly_composes() -> None:
    action, receipt = _authority()

    repair = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    )

    assert repair.intervention.id == action.id
    assert repair.intervention.scope == action.scope
    assert repair.intervention.dependencies == action.dependencies
    assert repair.intervention.oracle_target == action.oracle_target
    assert repair.intervention.oracle_address == action.oracle_address
    assert repair.intervention.oracle_body_digest == action.oracle_body_digest
    assert repair.intervention.rationale == action.rationale
    assert repair.intervention.ranges == (
        OracleInstallRange(
            preimage_range=ByteRange(offset=fixture.REGION[0], length=2),
            output_range=ByteRange(offset=fixture.REGION[0], length=2),
            oracle_range=ByteRange(offset=fixture.REGION[0], length=2),
        ),
    )
    assert repair.intervention.byte_count == 2
    assert repair.intervention.maximum_oracle_payload_bytes == len(fixture.IMAGE)
    assert repair.intervention.proof_receipt_digest == Digest.from_bytes(
        canonical_json(repair.receipt)
    )
    assert sha256(repair.output).hexdigest() == fixture.GOLDEN_OBJECT_SHA256


def test_reauthor_reports_a_typed_zero_window_result() -> None:
    action, receipt = _authority()

    with pytest.raises(LegacyNoWindowError, match="none of the saved legacy byte windows"):
        reauthor_legacy_simulated_elision(
            action,
            receipt,
            fixture.make_coff(),
            fixture.make_coff(body=fixture.IMAGE),
            fixture.IMAGE,
        )


def test_legacy_oracle_capture_rejects_bytes_outside_the_saved_digest() -> None:
    action, receipt = _authority()

    class ChangedOracle:
        def read_virtual_address(self, _address, length):
            return b"\x00" * length

    with pytest.raises(LegacyRepairError, match="differs from its pinned body"):
        capture_legacy_oracle_material(action, receipt, ChangedOracle())


def test_legacy_oracle_capture_validates_linked_bytes_in_coff_form() -> None:
    (
        action,
        receipt,
        _donor,
        _donor_receipt,
        _seed_object,
        _donor_object,
        _donor_body,
        linked_retail_body,
    ) = _relocated_zero_window_authority()

    class LinkedOracle:
        def read_virtual_address(self, address, length):
            assert address == action.oracle_address
            assert length == len(linked_retail_body)
            return linked_retail_body

    material = capture_legacy_oracle_material(action, receipt, LinkedOracle())

    assert material.retail_body == linked_retail_body


def test_zero_window_retires_only_when_fresh_source_carries_the_goal() -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)

    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(body=fixture.IMAGE),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )

    assert not plan.replaced
    assert plan.legacy_edit == LegacyInterventionEdit(action, None)
    assert [item.before.id for item in plan.receipt_edits] == [receipt.id, donor_receipt.id]
    assert [(item.before.id, item.after) for item in plan.donor_edits] == [(donor.id, None)]
    assert plan.removed_donors == (donor.id,)


def test_zero_window_replaces_legacy_when_only_current_donor_carries_the_goal() -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)

    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )

    assert plan.replaced
    assert plan.addition is not None
    assert plan.addition.replaces_intervention_id == action.id
    assert plan.addition.intervention.family is ClassicRecipeFamily.EQUAL_BODY_STRICT
    assert plan.addition.intervention.dependencies == action.dependencies
    assert plan.addition.receipt.expected_values["expected_body_sha256"] == (
        action.oracle_body_digest.value
    )
    assert plan.donor_edits == ()
    assert plan.removed_donors == ()
    assert [item.before.id for item in plan.receipt_edits] == [receipt.id]


def test_zero_window_retires_a_relocation_bearing_fresh_seed() -> None:
    (
        action,
        receipt,
        donor,
        donor_receipt,
        _seed_object,
        donor_object,
        _donor_body,
        retail_body,
    ) = _relocated_zero_window_authority()

    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=donor_object,
        donor_object=donor_object,
        retail_body=retail_body,
        build_target="program",
    )

    assert not plan.replaced
    assert plan.legacy_edit == LegacyInterventionEdit(action, None)


def test_zero_window_replaces_with_a_relocation_bearing_current_donor() -> None:
    (
        action,
        receipt,
        donor,
        donor_receipt,
        seed_object,
        donor_object,
        donor_body,
        retail_body,
    ) = _relocated_zero_window_authority()

    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=seed_object,
        donor_object=donor_object,
        retail_body=retail_body,
        build_target="program",
    )

    assert plan.replaced
    assert plan.addition is not None
    assert plan.addition.replaces_intervention_id == action.id
    assert (
        plan.addition.receipt.expected_values["expected_body_sha256"]
        == sha256(donor_body).hexdigest()
    )
    assert plan.addition.receipt.expected_values["expected_body_sha256"] == (
        action.oracle_body_digest.value
    )


def test_zero_window_relocation_equivalence_rejects_unsealed_retail_bytes() -> None:
    (
        action,
        receipt,
        donor,
        donor_receipt,
        _seed_object,
        donor_object,
        _donor_body,
        retail_body,
    ) = _relocated_zero_window_authority()
    changed = bytearray(retail_body)
    changed[0] ^= 1

    with pytest.raises(LegacyRepairError, match="captured retail body differs"):
        plan_legacy_no_window_resolution(
            (action, donor),
            (receipt, donor_receipt),
            intervention=action,
            receipt=receipt,
            seed_object=donor_object,
            donor_object=donor_object,
            retail_body=bytes(changed),
            build_target="program",
        )


def test_zero_window_relocation_equivalence_rejects_a_different_symbol() -> None:
    (
        action,
        receipt,
        donor,
        donor_receipt,
        seed_object,
        _donor_object,
        donor_body,
        retail_body,
    ) = _relocated_zero_window_authority()
    wrong_donor = make_fpo_coff(
        body=donor_body,
        debug_stream=fpo_codeview_stream(len(donor_body), debug_start=0, debug_end=6),
        code_relocations=((2, fixture.TARGET_SYMBOL, 6),),
        line_rows=((0, 11), (6, 12)),
    )

    with pytest.raises(LegacyRepairError, match="neither fresh source nor the current donor"):
        plan_legacy_no_window_resolution(
            (action, donor),
            (receipt, donor_receipt),
            intervention=action,
            receipt=receipt,
            seed_object=seed_object,
            donor_object=wrong_donor,
            retail_body=retail_body,
            build_target="program",
        )


def test_zero_window_refuses_when_neither_fresh_body_carries_the_goal() -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    changed = bytearray(fixture.IMAGE)
    # Change a valid stack displacement outside both saved oracle windows.
    changed[9] = 0x10
    donor_object = fixture.make_coff(body=bytes(changed))

    with pytest.raises(LegacyNoWindowError):
        reauthor_legacy_simulated_elision(
            action,
            receipt,
            fixture.make_coff(),
            donor_object,
            fixture.IMAGE,
        )

    with pytest.raises(LegacyRepairError, match="neither fresh source nor the current donor"):
        plan_legacy_no_window_resolution(
            (action, donor),
            (receipt, donor_receipt),
            intervention=action,
            receipt=receipt,
            seed_object=fixture.make_coff(),
            donor_object=donor_object,
            retail_body=fixture.IMAGE,
            build_target="program",
        )


def test_zero_window_retirement_keeps_a_donor_used_by_another_function() -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    other_scope = Scope(
        target="program",
        translation_unit="unit.fixture",
        function=fixture.OTHER_SYMBOL,
    )
    other = ClassicRecipeIntervention(
        id="function.other",
        scope=other_scope,
        rationale="Fixture consumer.",
        dependencies=(donor.id,),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=fixture.OTHER_SYMBOL,
    )
    other_receipt = ClassicProofReceipt(
        id="proof.function.other",
        intervention_id=other.id,
        family=other.family,
    )
    donor = donor.model_copy(
        update={
            "beneficiaries": tuple(
                sorted((action.scope, other_scope), key=lambda item: item.function or "")
            )
        }
    )

    plan = plan_legacy_no_window_resolution(
        (action, donor, other),
        (receipt, donor_receipt, other_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(body=fixture.IMAGE),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )

    assert plan.removed_donors == ()
    assert len(plan.donor_edits) == 1
    assert plan.donor_edits[0].after is not None
    assert plan.donor_edits[0].after.beneficiaries == (other_scope,)
    assert [item.before.id for item in plan.receipt_edits] == [receipt.id]


def _candidate_refusal(
    baseline: LegacyInstallRepair,
) -> LegacyRepairRefusal:
    action, receipt = _authority()
    return LegacyRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=b"seed", donor_object=b"donor"),
        unit=SimpleNamespace(),
        reason="saved legacy action no longer composes",
        legacy_oracle=LegacyOracleMaterial(fixture.IMAGE, {}),
        baseline_repair=baseline,
    )


def test_retuned_legacy_candidate_must_improve_the_current_safe_cost(monkeypatch) -> None:
    action, receipt = _authority()
    baseline = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    )
    refusal = _candidate_refusal(baseline)
    monkeypatch.setattr(
        probe_candidates,
        "_candidate_materials",
        lambda *_args: refusal.materials,
    )
    worse = LegacyInstallRepair(action, receipt, b"worse")

    for candidate in (baseline, worse):
        monkeypatch.setattr(
            probe_candidates,
            "reauthor_legacy_simulated_elision",
            lambda *_args, result=candidate: result,
        )
        with pytest.raises(MeasuredPinRepairError, match="does not improve current safe cost"):
            probe_candidates.validate_retuned_actions(
                (refusal,),
                SimpleNamespace(),
                SimpleNamespace(),
                SimpleNamespace(),
            )


def test_retuned_legacy_candidate_accepts_a_strictly_better_cost(monkeypatch) -> None:
    action, receipt = _authority()
    baseline = LegacyInstallRepair(action, receipt, b"baseline")
    candidate = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    )
    refusal = _candidate_refusal(baseline)
    monkeypatch.setattr(
        probe_candidates,
        "_candidate_materials",
        lambda *_args: refusal.materials,
    )
    monkeypatch.setattr(
        probe_candidates,
        "reauthor_legacy_simulated_elision",
        lambda *_args: candidate,
    )

    assert probe_candidates.validate_retuned_actions(
        (refusal,),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    ) == (candidate,)
    assert probe_candidates.validate_retuned_actions(
        (replace(refusal, baseline_repair=None),),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    ) == (candidate,)


def test_repair_analysis_releases_preimages_after_a_complete_unit() -> None:
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(b"source"),
        ),
        (),
        (),
        (),
        (),
        (),
    )

    class Recorder:
        def __init__(self):
            self.released = []
            self.donor_objects = []

        def record_unit_donor_objects(self, unit_id, objects):
            self.donor_objects.append((unit_id, dict(objects)))

        def record_action_preimage(self, *_entry):
            raise AssertionError("an empty unit has no action preimages")

        def release_completed_unit_preimages(self, unit_id):
            self.released.append(unit_id)

        def __call__(self, _request):
            raise AssertionError("an empty unit cannot request a measured repair")

        def record_legacy_failure(self, _request):
            raise AssertionError("an empty unit cannot request a legacy repair")

    recorder = Recorder()
    result = orchestration.compose_classic_unit(
        unit,
        seed_object=b"fresh seed",
        donor_materials={},
        seed_source=b"source",
        measured_receipt_repair=recorder,
    )

    assert not result.incomplete
    assert result.output == b"fresh seed"
    assert recorder.released == ["unit.fixture"]
    # The analysis keeps every unit's fresh donor objects for the census.
    assert recorder.donor_objects == [("unit.fixture", {})]


def test_repair_analysis_captures_a_failed_legacy_action_instead_of_aborting(
    monkeypatch,
) -> None:
    action, receipt = _authority()
    donor = ClassicRecipeIntervention(
        id="donor.fixture",
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Fixture donor.",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
    )
    prepared = ClassicPreparedDonor(
        donor,
        SimpleNamespace(logical_outputs={}, carrier_identifiers=frozenset()),
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(b"source"),
        ),
        (prepared,),
        (),
        (action,),
        (action,),
        (receipt,),
    )

    class Recorder:
        def __init__(self):
            self.request = None
            self.preimages = []
            self.released = []

        def record_action_preimage(self, *entry):
            self.preimages.append(entry)

        def release_completed_unit_preimages(self, unit_id):
            self.released.append(unit_id)

        def __call__(self, _request):
            return None

        def record_legacy_failure(self, request):
            self.request = request

    recorder = Recorder()
    monkeypatch.setattr(orchestration, "_require_classic_donor_semantic_material", lambda *_: None)

    def fail(*_args):
        raise LegacyInstallError("saved pins changed")

    monkeypatch.setattr(quarantine, "compose_legacy_simulated_elision", fail)
    result = orchestration.compose_classic_unit(
        unit,
        seed_object=b"fresh seed",
        donor_materials={
            donor.id: SimpleNamespace(intervention=donor, donor_object=b"fresh donor")
        },
        seed_source=b"source",
        legacy_oracles={"program": SimpleNamespace()},
        measured_receipt_repair=recorder,
    )

    assert result.incomplete
    assert result.output == b"fresh seed"
    assert recorder.request.intervention == action
    assert recorder.request.materials.seed_object == b"fresh seed"
    assert recorder.request.materials.donor_object == b"fresh donor"
    assert recorder.preimages == [("unit.fixture", 0, action.id, b"fresh seed")]
    assert recorder.released == []


def test_legacy_authority_edit_rejects_identity_drift_and_new_byte_positions() -> None:
    action, receipt = _authority()
    repaired = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    ).intervention

    assert LegacyInterventionEdit(action, repaired).after == repaired
    with pytest.raises(ClassicAuthorityRepairError, match="identity, scope, dependency, oracle"):
        LegacyInterventionEdit(
            action,
            _refreeze(repaired, rationale="Changed review rationale."),
        )
    moved = OracleInstallRange(
        preimage_range=ByteRange(offset=3, length=1),
        output_range=ByteRange(offset=3, length=1),
        oracle_range=ByteRange(offset=3, length=1),
    )
    with pytest.raises(ClassicAuthorityRepairError, match="broadens its allowlist"):
        LegacyInterventionEdit(
            action,
            _refreeze(repaired, ranges=(moved,), byte_count=1),
        )


def test_legacy_authority_edit_rejects_range_byte_and_payload_growth() -> None:
    action, _receipt = _authority()
    extra = OracleInstallRange(
        preimage_range=ByteRange(offset=6, length=1),
        output_range=ByteRange(offset=6, length=1),
        oracle_range=ByteRange(offset=6, length=1),
    )
    with pytest.raises(ClassicAuthorityRepairError, match="broadens its allowlist"):
        LegacyInterventionEdit(
            action,
            _refreeze(
                action,
                ranges=(*action.ranges, extra),
                byte_count=action.byte_count + 1,
                maximum_oracle_payload_bytes=action.maximum_oracle_payload_bytes + 1,
            ),
        )


def _project_toml(action: LegacyOracleInstallIntervention) -> str:
    return f'''\
schema_version = 3
project_id = "sample"

[build]
kind = "producer-graph"

[toolchain]
profile = "compiler-42"

[paths]
source = 'R:\\src'
build = 'R:\\build'
toolchain = 'R:\\toolchain'

[authenticity]
policy = "allow-quarantine"

[[authenticity.legacy_allowlist]]
intervention_id = "{action.id}"
allowlist_digest = {{ algorithm = "sha256", value = "{action.allowlist_digest.value}" }}
proof_receipt_digest = {{ algorithm = "sha256", value = "{action.proof_receipt_digest.value}" }}
range_count = {len(action.ranges)}
byte_count = {action.byte_count}
maximum_oracle_payload_bytes = {action.maximum_oracle_payload_bytes}

[[targets]]
id = "program"
artifact = "build/program.exe"
oracle = "references/program.exe"
'''


def _formatted_project_toml(action: LegacyOracleInstallIntervention) -> bytes:
    text = _project_toml(action)
    text = text.replace(
        "[[authenticity.legacy_allowlist]]",
        "[[ authenticity . legacy_allowlist ]]   # reviewed legacy entry",
    )
    text = text.replace(
        f'intervention_id = "{action.id}"',
        f"intervention_id    = '{action.id}'   # stable record id",
    )
    text = text.replace(
        f'allowlist_digest = {{ algorithm = "sha256", value = "{action.allowlist_digest.value}" }}',
        "allowlist_digest = {algorithm = 'sha256', "
        f"value = '{action.allowlist_digest.value}'}}   # reviewed ranges",
    )
    text = text.replace(
        'proof_receipt_digest = { algorithm = "sha256", '
        f'value = "{action.proof_receipt_digest.value}" }}',
        "proof_receipt_digest = { algorithm='sha256', "
        f"value='{action.proof_receipt_digest.value}' }} # matching proof",
    )
    text = text.replace(
        f"range_count = {len(action.ranges)}",
        f"range_count = +{len(action.ranges)}   # exact ranges",
    )
    text = text.replace(
        f"byte_count = {action.byte_count}",
        f"byte_count = +{action.byte_count}   # exact bytes",
    )
    text = text.replace(
        f"maximum_oracle_payload_bytes = {action.maximum_oracle_payload_bytes}",
        "maximum_oracle_payload_bytes = 3_0   # reviewed ceiling",
    )
    text = text.replace(
        "\n[[targets]]",
        "\n# Target settings stay beside the target table.\n[[targets]]",
    )
    return text.replace("\n", "\r\n").encode()


def _write_legacy_authority(
    root,
    action: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    donor: ClassicRecipeIntervention,
    donor_receipt: ClassicProofReceipt,
):
    config = root / "reprobit.toml"
    config.write_text(_project_toml(action))
    spec = load_project(config)
    intervention_path = root / spec.layout.interventions / "unit.json"
    proof_path = root / spec.layout.proofs / "unit.json"
    intervention_path.parent.mkdir(parents=True)
    proof_path.parent.mkdir(parents=True)
    intervention_path.write_bytes(
        canonical_json(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
                source="src/unit.cpp",
                source_digest=Digest.from_bytes(b"source"),
                build_target="program",
                interventions=(action, donor),
            )
        )
    )
    proof_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
                expected_observations=(donor_receipt, receipt),
            )
        )
    )
    return spec, config, intervention_path, proof_path


def test_zero_window_replacement_removes_allowlist_and_preserves_record_slots(
    tmp_path,
) -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )
    assert plan.addition is not None
    spec, config, intervention_path, proof_path = _write_legacy_authority(
        tmp_path, action, receipt, donor, donor_receipt
    )

    changed = apply_classic_authority_edits(
        tmp_path,
        spec,
        interventions=plan.donor_edits,
        legacy_interventions=(plan.legacy_edit,),
        receipts=plan.receipt_edits,
        additions=(plan.addition,),
    )

    assert changed == (
        "reprobit.toml",
        f"{spec.layout.interventions}/unit.json",
        f"{spec.layout.proofs}/unit.json",
    )
    assert "[[authenticity.legacy_allowlist]]" not in config.read_text()
    assert load_project(config).authenticity.legacy_allowlist == ()
    interventions = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    assert [item.id for item in interventions.interventions] == [
        plan.addition.intervention.id,
        donor.id,
    ]
    proofs = ProofDocument.model_validate_json(proof_path.read_bytes())
    assert [item.id for item in proofs.expected_observations] == [
        donor_receipt.id,
        plan.addition.receipt.id,
    ]


def test_zero_window_retirement_removes_orphaned_donor_and_allowlist(tmp_path) -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(body=fixture.IMAGE),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )
    spec, config, intervention_path, proof_path = _write_legacy_authority(
        tmp_path, action, receipt, donor, donor_receipt
    )

    apply_classic_authority_edits(
        tmp_path,
        spec,
        interventions=plan.donor_edits,
        legacy_interventions=(plan.legacy_edit,),
        receipts=plan.receipt_edits,
    )

    assert load_project(config).authenticity.legacy_allowlist == ()
    interventions = InterventionDocument.model_validate_json(intervention_path.read_bytes())
    proofs = ProofDocument.model_validate_json(proof_path.read_bytes())
    assert interventions.interventions == ()
    assert proofs.expected_observations == ()


def test_legacy_removal_preserves_crlf_and_adjacent_comments(tmp_path) -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )
    assert plan.addition is not None
    _spec, config, _intervention_path, _proof_path = _write_legacy_authority(
        tmp_path, action, receipt, donor, donor_receipt
    )
    before = _formatted_project_toml(action)
    config.write_bytes(before)
    spec = load_project(config)

    apply_classic_authority_edits(
        tmp_path,
        spec,
        interventions=plan.donor_edits,
        legacy_interventions=(plan.legacy_edit,),
        receipts=plan.receipt_edits,
        additions=(plan.addition,),
    )

    semantic_prefixes = (
        b"[[ authenticity . legacy_allowlist ]]",
        b"intervention_id",
        b"allowlist_digest",
        b"proof_receipt_digest",
        b"range_count",
        b"byte_count",
        b"maximum_oracle_payload_bytes",
    )
    expected = b"".join(
        line
        for line in before.splitlines(keepends=True)
        if not line.lstrip().startswith(semantic_prefixes)
    )
    updated = config.read_bytes()
    assert updated == expected
    assert b"# Target settings stay beside the target table.\r\n[[targets]]" in updated
    assert b"\n" not in updated.replace(b"\r\n", b"")
    assert load_project(config).authenticity.legacy_allowlist == ()


def test_zero_window_dequarantine_is_atomic_when_config_changed(tmp_path) -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    plan = plan_legacy_no_window_resolution(
        (action, donor),
        (receipt, donor_receipt),
        intervention=action,
        receipt=receipt,
        seed_object=fixture.make_coff(),
        donor_object=fixture.make_coff(body=fixture.IMAGE),
        retail_body=fixture.IMAGE,
        build_target="program",
    )
    assert plan.addition is not None
    spec, config, intervention_path, proof_path = _write_legacy_authority(
        tmp_path, action, receipt, donor, donor_receipt
    )
    before = (intervention_path.read_bytes(), proof_path.read_bytes())
    config.write_text(config.read_text().replace("range_count = 2", "range_count = 99"))

    with pytest.raises(ClassicAuthorityRepairError, match="changed before legacy repair"):
        apply_classic_authority_edits(
            tmp_path,
            spec,
            interventions=plan.donor_edits,
            legacy_interventions=(plan.legacy_edit,),
            receipts=plan.receipt_edits,
            additions=(plan.addition,),
        )

    assert (intervention_path.read_bytes(), proof_path.read_bytes()) == before


def test_legacy_removal_requires_its_exact_receipt_edit(tmp_path) -> None:
    action, receipt = _authority()
    donor, donor_receipt = _donor_authority(action)
    spec, config, intervention_path, proof_path = _write_legacy_authority(
        tmp_path, action, receipt, donor, donor_receipt
    )
    before = (
        config.read_bytes(),
        intervention_path.read_bytes(),
        proof_path.read_bytes(),
    )

    with pytest.raises(ClassicAuthorityRepairError, match="needs one matching receipt edit"):
        apply_classic_authority_edits(
            tmp_path,
            spec,
            legacy_interventions=(LegacyInterventionEdit(action, None),),
        )

    assert (
        config.read_bytes(),
        intervention_path.read_bytes(),
        proof_path.read_bytes(),
    ) == before


def test_legacy_action_receipt_and_existing_allowlist_update_atomically(tmp_path) -> None:
    action, receipt = _authority()
    repair = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    )
    config = tmp_path / "reprobit.toml"
    config.write_text(_project_toml(action))
    spec = load_project(config)
    intervention_path = tmp_path / spec.layout.interventions / "unit.json"
    proof_path = tmp_path / spec.layout.proofs / "unit.json"
    intervention_path.parent.mkdir(parents=True)
    proof_path.parent.mkdir(parents=True)
    intervention_path.write_bytes(
        canonical_json(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
                source="src/unit.cpp",
                source_digest=Digest.from_bytes(b"source"),
                build_target="program",
                interventions=(action,),
            )
        )
    )
    proof_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit.fixture",
                expected_observations=(receipt,),
            )
        )
    )

    changed = apply_classic_authority_edits(
        tmp_path,
        spec,
        legacy_interventions=(LegacyInterventionEdit(action, repair.intervention),),
        receipts=(ClassicReceiptEdit(receipt, repair.receipt),),
    )

    assert changed == (
        "reprobit.toml",
        f"{spec.layout.interventions}/unit.json",
        f"{spec.layout.proofs}/unit.json",
    )
    assert config.read_text().count("[[authenticity.legacy_allowlist]]") == 1
    updated = load_project(config).authenticity.legacy_allowlist
    assert len(updated) == 1
    assert updated[0].allowlist_digest == repair.intervention.allowlist_digest
    assert updated[0].proof_receipt_digest == repair.intervention.proof_receipt_digest
    assert updated[0].range_count == 1
    assert updated[0].byte_count == 2


def test_legacy_update_changes_only_values_in_formatted_crlf_toml(tmp_path) -> None:
    action, receipt = _authority()
    repair = reauthor_legacy_simulated_elision(
        action,
        receipt,
        fixture.make_coff(),
        fixture.make_coff(),
        fixture.IMAGE,
    )
    _spec, config, _intervention_path, _proof_path = _write_legacy_authority(
        tmp_path,
        action,
        receipt,
        *_donor_authority(action),
    )
    before = _formatted_project_toml(action)
    config.write_bytes(before)
    spec = load_project(config)

    apply_classic_authority_edits(
        tmp_path,
        spec,
        legacy_interventions=(LegacyInterventionEdit(action, repair.intervention),),
        receipts=(ClassicReceiptEdit(receipt, repair.receipt),),
    )

    expected = before.replace(
        action.allowlist_digest.value.encode(),
        repair.intervention.allowlist_digest.value.encode(),
    )
    expected = expected.replace(
        action.proof_receipt_digest.value.encode(),
        repair.intervention.proof_receipt_digest.value.encode(),
    )
    expected = expected.replace(b"range_count = +2", b"range_count = 1")
    expected = expected.replace(b"byte_count = +3", b"byte_count = 2")
    updated = config.read_bytes()
    assert updated == expected
    assert b"[[ authenticity . legacy_allowlist ]]   # reviewed legacy entry\r\n" in updated
    assert b"intervention_id    = 'legacy.fixture'   # stable record id\r\n" in updated
    assert b"maximum_oracle_payload_bytes = 3_0   # reviewed ceiling\r\n" in updated
    assert b"# Target settings stay beside the target table.\r\n[[targets]]" in updated
    assert b"\n" not in updated.replace(b"\r\n", b"")
    allowlist = load_project(config).authenticity.legacy_allowlist
    assert len(allowlist) == 1
    assert allowlist[0].intervention_id == repair.intervention.id
    assert allowlist[0].allowlist_digest == repair.intervention.allowlist_digest
    assert allowlist[0].proof_receipt_digest == repair.intervention.proof_receipt_digest
    assert allowlist[0].range_count == len(repair.intervention.ranges)
    assert allowlist[0].byte_count == repair.intervention.byte_count
