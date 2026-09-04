from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from typing import cast

import pytest
import test_classic_relational_form_full as fixture
import test_classic_repair_discovery as discovery_fixture

import reprobit.classic_repair_discovery as discovery
from reprobit.classic_donors import prepare_donor_compile_request
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_relational_repair import (
    RelationalRepairError,
    derive_relational_sites,
    reauthor_relational_donor_rewriting,
)
from reprobit.classic_repair_reauthor import plan_function_reauthoring
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.classic_retail_repair import (
    RetailRepairError,
    capture_authenticated_retail_body,
)
from reprobit.coff_format import CoffObject, coff_body
from reprobit.discovery_authoring import build_declaration_shape_donor
from reprobit.model import Digest, Scope
from reprobit.oracle_pe32 import PE32VirtualAddressReader
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
)

SOURCE = b"int relational_repair_fixture;\n"


class _MemoryOracle:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read_virtual_address(self, _address: int, length: int) -> bytes:
        assert length == len(self.body)
        return self.body


def _refusal() -> tuple[ClassicRepairRefusal, bytes, bytes]:
    seed = fixture.fixture.make_coff(body=fixture.BODY)
    retail_body, _proof = fixture.reversed_image()
    donor_record = build_declaration_shape_donor(
        target_id="program",
        translation_unit_id="unit.fixture",
        build_target="program",
        classes=1,
        functions=1,
        beneficiary_symbols=(fixture.TARGET_SYMBOL,),
    )
    prepared = ClassicPreparedDonor(
        donor_record.intervention,
        prepare_donor_compile_request(
            donor_record.intervention,
            source_path="src/unit.cpp",
            clean_source=SOURCE,
            effective_source=SOURCE,
            receipts=(donor_record.receipt,),
        ),
    )
    action = ClassicRecipeIntervention(
        id="function.saved",
        scope=Scope(
            target="program",
            translation_unit="unit.fixture",
            function=fixture.TARGET_SYMBOL,
        ),
        rationale="Saved resize record whose carrier no longer reaches its retail body.",
        dependencies=(donor_record.intervention.id,),
        family=ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=fixture.TARGET_SYMBOL,
    )
    receipt = ClassicProofReceipt(
        id="proof.function.saved",
        intervention_id=action.id,
        family=action.family,
        expected_values={
            "expected_normalized_body_sha256": sha256(retail_body).hexdigest(),
            "retail_oracle": {
                "address": f"0x{fixture.fixture.RETAIL_ADDRESS:08x}",
                "image": "SAMPLE.DLL",
                "length": len(retail_body),
                "verdict": "MATCH",
            },
            "retail_relocations": fixture.fixture.relocation_oracle(seed),
        },
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (prepared,),
        (action,),
        (),
        (action,),
        (donor_record.receipt, receipt),
    )
    return (
        ClassicRepairRefusal(
            unit_id=unit.plan.id,
            action_index=0,
            intervention=action,
            receipt=receipt,
            materials=ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
            unit=unit,
            reason="saved carrier geometry changed",
            unit_donor_objects={donor_record.intervention.id: seed},
            retail_body=retail_body,
        ),
        seed,
        retail_body,
    )


def _body(payload: bytes) -> bytes:
    obj = CoffObject(payload)
    return bytes(coff_body(obj, obj.function_section(fixture.TARGET_SYMBOL)))


def test_derives_ordinary_and_register_direct_mirrors() -> None:
    body = bytes.fromhex("3bc175003bc17c00c3")
    target = bytes.fromhex("3bc8750039c17f00c3")

    sites, proof = derive_relational_sites(body, target)

    assert sites == [
        {
            "branch_offset": 2,
            "compare_offset": 0,
            "expected_rewritten_offsets": [1, 2],
            "image_condition": "ne",
            "reencode": True,
            "seed_condition": "ne",
        },
        {
            "branch_offset": 6,
            "compare_offset": 4,
            "expected_rewritten_offsets": [4, 6],
            "image_condition": "g",
            "seed_condition": "l",
        },
    ]
    assert proof["instruction_count"] == 5
    assert [
        index for index, pair in enumerate(zip(body, target, strict=True)) if pair[0] != pair[1]
    ] == [
        1,
        4,
        6,
    ]


def test_relational_derivation_rejects_uncovered_and_unsafe_changes() -> None:
    body = bytes.fromhex("3bc175003bc17c00c3")
    target = bytearray(bytes.fromhex("3bc8750039c17f00c3"))
    target[-1] = 0xCB
    with pytest.raises(RelationalRepairError, match="uncovered"):
        derive_relational_sites(body, bytes(target))

    unsafe = bytearray(fixture.BODY)
    unsafe[19] = 0x13  # adc reads carry after the mirrored branch
    unsafe_target = bytearray(unsafe)
    unsafe_target[fixture.COMPARE_AT] = 0x39
    unsafe_target[fixture.BRANCH_AT] = 0x7F
    with pytest.raises(RelationalRepairError, match=r"reversal changes.*cf"):
        derive_relational_sites(bytes(unsafe), bytes(unsafe_target))


def test_relational_derivation_rejects_a_relocated_rewrite_byte() -> None:
    body = bytes.fromhex("3bc17501c3c3")
    target = bytes.fromhex("3bc87501c3c3")
    with pytest.raises(RelationalRepairError, match="overlaps a relocation"):
        derive_relational_sites(body, target, ({"offset": 1, "target": "x", "width": 1},))


def test_cross_tu_retail_capture_uses_the_normalized_immutable_goal() -> None:
    refusal, seed, retail_body = _refusal()
    linked_body = fixture.fixture.retail_body_for(retail_body)

    captured = capture_authenticated_retail_body(
        refusal.intervention,
        refusal.receipt,
        cast(PE32VirtualAddressReader, _MemoryOracle(linked_body)),
    )

    assert captured == retail_body
    altered = refusal.receipt.model_copy(
        update={
            "expected_values": {
                **refusal.receipt.expected_values,
                "expected_normalized_body_sha256": "00" * 32,
            }
        }
    )
    with pytest.raises(RetailRepairError, match="immutable body goal"):
        capture_authenticated_retail_body(
            refusal.intervention,
            altered,
            cast(PE32VirtualAddressReader, _MemoryOracle(linked_body)),
        )
    assert _body(seed) == fixture.BODY


def test_authorer_measures_and_dispatches_a_new_donor_rewriting_record() -> None:
    refusal, seed, retail_body = _refusal()
    donor_id = refusal.intervention.dependencies[0]

    authored = reauthor_relational_donor_rewriting(
        refusal.intervention,
        refusal.receipt,
        refusal.materials,
        retail_body,
        donor_id=donor_id,
        donor_object=seed,
    )

    assert authored.intervention.family is ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING
    assert authored.intervention.dependencies == (donor_id,)
    assert authored.measured.changed_keys == ()
    assert _body(authored.measured.candidate.output) == retail_body
    program = authored.intervention.parameters[0].value
    assert isinstance(program, dict) and len(program["relational_sites"]) == 1


def test_saved_donor_and_discovery_paths_share_the_relational_authorer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, _retail_body = _refusal()

    plan = plan_function_reauthoring((refusal,))
    assert plan.skipped == ()
    assert plan.reauthorings[0].family == "retail_exact_donor_rewriting"
    assert plan.additions[0].replaces_intervention_id == refusal.intervention.id

    compiled: list[str] = []
    monkeypatch.setattr(
        discovery,
        "probe_donor_compile_windows",
        discovery_fixture._fake_windows({"default": seed}, compiled),
    )
    result = discovery.probe_carrier_discovery(
        discovery_fixture._Handle(),  # type: ignore[arg-type]
        (replace(refusal, unit_donor_objects={}),),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=1,
        window_size=1,
    )

    assert compiled and result.unresolved == ()
    repair = result.repairs[0]
    assert repair.resolutions[0].family == "retail_exact_donor_rewriting"
    assert any(
        item.replaces_intervention_id == refusal.intervention.id for item in repair.additions
    )
    edits = {item.before.id: item.after for item in repair.intervention_edits}
    assert edits[refusal.intervention.dependencies[0]] is None
