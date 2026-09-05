from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.classic_repair_session import (
    ClassicReceiptRepair,
    ClassicRepairSession,
    ClassicRepairSessionError,
    apply_classic_receipt_repairs,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
    ProjectSpec,
    ProofDocument,
    TargetSpec,
    ToolchainRef,
)
from reprobit.strict_json import canonical_json


def _receipt(identifier: str, value: int) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=identifier,
        intervention_id=f"function_{identifier}",
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        expected_values={"expected_body_length": value},
    )


def _spec() -> ProjectSpec:
    return ProjectSpec(
        schema_version=3,
        project_id="sample",
        state_dir=".reprobit-state",
        toolchain=ToolchainRef(profile="msvc420"),
        build=ProducerGraphBuildAdapter(),
        paths=LogicalPathProfile(
            source=r"R:\source",
            build=r"R:\build",
            toolchain=r"R:\toolchain",
        ),
        targets=(
            TargetSpec(
                id="program",
                artifact="build/program.exe",
                oracle="oracles/program.exe",
            ),
        ),
    )


def _repair(before: ClassicProofReceipt, after: ClassicProofReceipt) -> ClassicReceiptRepair:
    return ClassicReceiptRepair("tu_main", 0, before, after, ("expected_body_length",))


def test_completed_unit_preimages_do_not_accumulate() -> None:
    session = ClassicRepairSession()

    for index in range(32):
        unit_id = f"unit.{index}"
        session.record_action_preimage(unit_id, 0, f"function.{index}", b"object preimage")
        session.release_completed_unit_preimages(unit_id)

        assert session._unit_action_preimages == {}


def test_apply_classic_receipt_repairs_updates_only_the_matching_proof_document(
    tmp_path: Path,
) -> None:
    spec = _spec()
    proof_root = tmp_path / spec.layout.proofs
    proof_root.mkdir(parents=True)
    first = _receipt("proof_first", 8)
    second = _receipt("proof_second", 12)
    first_path = proof_root / "first.json"
    second_path = proof_root / "second.json"
    first_path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="tu_main",
                expected_observations=(first,),
            )
        )
    )
    second_payload = canonical_json(
        ProofDocument(
            schema_version=3,
            target_id="program",
            translation_unit_id="tu_other",
            expected_observations=(second,),
        )
    )
    second_path.write_bytes(second_payload)
    updated = first.model_copy(update={"expected_values": {"expected_body_length": 9}})

    changed = apply_classic_receipt_repairs(tmp_path, spec, (_repair(first, updated),))

    assert changed == (f"{spec.layout.proofs}/first.json",)
    assert ProofDocument.model_validate_json(first_path.read_bytes()).expected_observations == (
        updated,
    )
    assert second_path.read_bytes() == second_payload


def test_apply_classic_receipt_repairs_refuses_missing_or_changed_receipts(tmp_path: Path) -> None:
    spec = _spec()
    proof_root = tmp_path / spec.layout.proofs
    proof_root.mkdir(parents=True)
    saved = _receipt("proof_saved", 8)
    path = proof_root / "proof.json"
    path.write_bytes(
        canonical_json(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="tu_main",
                expected_observations=(saved,),
            )
        )
    )
    absent = _receipt("proof_absent", 5)
    with pytest.raises(ClassicRepairSessionError, match="absent"):
        apply_classic_receipt_repairs(
            tmp_path,
            spec,
            (
                _repair(
                    absent,
                    absent.model_copy(update={"expected_values": {"expected_body_length": 6}}),
                ),
            ),
        )

    stale = saved.model_copy(update={"expected_values": {"expected_body_length": 7}})
    with pytest.raises(ClassicRepairSessionError, match="changed before"):
        apply_classic_receipt_repairs(
            tmp_path,
            spec,
            (
                _repair(
                    stale,
                    stale.model_copy(update={"expected_values": {"expected_body_length": 6}}),
                ),
            ),
        )


def test_classic_receipt_repair_refuses_broader_or_inaccurate_edits() -> None:
    before = _receipt("proof_saved", 8)
    broadened = before.model_copy(
        update={
            "expected_values": {
                "expected_body_length": 9,
                "unexpected": True,
            }
        }
    )
    with pytest.raises(ClassicRepairSessionError, match="more than expected values"):
        _repair(before, broadened)

    after = before.model_copy(update={"expected_values": {"expected_body_length": 9}})
    with pytest.raises(ClassicRepairSessionError, match="changed-key declaration differs"):
        ClassicReceiptRepair("tu_main", 0, before, after, ("not_the_changed_key",))


def test_classic_receipt_repair_fixture_uses_function_authority() -> None:
    intervention = ClassicRecipeIntervention(
        id="function_proof_saved",
        scope=Scope(target="program", translation_unit="tu_main", function="?f@@YAXXZ"),
        rationale="Keep the fixture aligned with the classic function authority shape.",
        dependencies=("donor",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?f@@YAXXZ",
    )
    assert intervention.id == _receipt("proof_saved", 8).intervention_id


def test_classic_receipt_repair_admits_only_the_debug_delta_as_an_added_pin() -> None:
    before = _receipt("proof_saved", 8)
    with_delta = before.model_copy(
        update={
            "expected_values": {
                "expected_body_length": 8,
                "debug_representation_delta": [{"kind": "procedure_extent"}],
            }
        }
    )

    repair = ClassicReceiptRepair("tu_main", 0, before, with_delta, ("debug_representation_delta",))

    assert repair.changed_keys == ("debug_representation_delta",)
    both = before.model_copy(
        update={
            "expected_values": {
                "expected_body_length": 9,
                "debug_representation_delta": [{"kind": "procedure_extent"}],
            }
        }
    )
    # The declaration is the sorted set of moved keys, the added pin included.
    ClassicReceiptRepair(
        "tu_main", 0, before, both, ("debug_representation_delta", "expected_body_length")
    )
    with pytest.raises(ClassicRepairSessionError, match="changed-key declaration differs"):
        ClassicReceiptRepair(
            "tu_main", 0, before, both, ("expected_body_length", "debug_representation_delta")
        )
    with pytest.raises(ClassicRepairSessionError, match="changed-key declaration differs"):
        ClassicReceiptRepair("tu_main", 0, before, with_delta, ("expected_body_length",))
    other = before.model_copy(
        update={"expected_values": {"expected_body_length": 8, "expected_seed_length": 9}}
    )
    with pytest.raises(ClassicRepairSessionError, match="more than expected values"):
        ClassicReceiptRepair("tu_main", 0, before, other, ("expected_seed_length",))
    dropped = before.model_copy(update={"expected_values": {}})
    with pytest.raises(ClassicRepairSessionError, match="more than expected values"):
        ClassicReceiptRepair("tu_main", 0, before, dropped, ())


def test_the_session_keeps_each_units_fresh_donor_objects_once() -> None:
    from reprobit.classic_repair_dispatch import CapturedDonorObject
    from reprobit.classic_repair_session import ClassicRepairSession, ClassicRepairSessionError

    session = ClassicRepairSession()
    first = {
        "donor.a": CapturedDonorObject("a" * 64, b"aa"),
        "donor.b": CapturedDonorObject("b" * 64, b"bb"),
    }
    session.record_unit_donor_objects("tu.one", first)
    session.record_unit_donor_objects("tu.one", dict(first))

    assert dict(session.unit_donor_objects["tu.one"]) == first
    changed = {"donor.a": CapturedDonorObject("a" * 64, b"x")}
    with pytest.raises(ClassicRepairSessionError, match="conflicting fresh donor objects"):
        session.record_unit_donor_objects("tu.one", changed)
    with pytest.raises(ClassicRepairSessionError, match="malformed"):
        session.record_unit_donor_objects("tu.two", {"donor.a": b"raw"})  # type: ignore[dict-item]
