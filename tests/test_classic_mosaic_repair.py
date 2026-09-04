from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import cast

import pytest
from test_classic_fpo_mosaic_identity import LOCAL_RECORD, OTHER_SYMBOL, codeview_stream
from test_classic_instruction_mosaic_full import (
    DONOR_BODY,
    DONOR_RANGE,
    EPILOGUE,
    MOSAIC,
    PROLOGUE,
    SEED_BODY,
    SEED_RANGE,
    STACK_LOAD,
    TARGET_SYMBOL,
    XOR_ZERO,
    carrier,
    make_coff,
    self_permutation,
)

import reprobit.classic_repair_session as repair_session_module
from reprobit import declaration_shapes
from reprobit.classic.composition_fpo_identity import measure_fpo_mosaic_identity
from reprobit.classic.source_proofs import (
    select_source_permutation_window,
    source_overlay_significant_sha256,
)
from reprobit.classic_mosaic_repair import (
    MosaicRepairError,
    capture_instruction_mosaic_retail_body,
    instruction_mosaic_semantics_required,
    reauthor_instruction_mosaic,
)
from reprobit.classic_orchestration import ClassicPreparedUnit, classic_unit_oracle_targets
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_dispatch import ClassicMeasuredReceiptRepairRequest
from reprobit.classic_repair_session import ClassicRepairSession
from reprobit.coff_format import CoffObject, coff_body, detailed_relocations
from reprobit.model import Digest, Scope
from reprobit.msvc_discovery_mosaic import (
    MosaicDonorCandidate,
    MosaicRangeCandidate,
    MosaicSearchBudget,
    mosaic_range_donor_id,
    select_mosaic_ranges,
)
from reprobit.oracle_pe32 import PE32VirtualAddressReader
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
)
from reprobit.strict_json import JsonValue


def _fields(values: dict[str, JsonValue]) -> tuple[ClassicField, ...]:
    return tuple(ClassicField(name=name, value=value) for name, value in sorted(values.items()))


def _donor(
    identifier: str,
    *,
    family: ClassicRecipeFamily = ClassicRecipeFamily.DECLARATION_SHAPE,
    parameters: dict[str, JsonValue] | None = None,
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Fresh declaration-only compiler-state donor for the fixture.",
        family=family,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
        parameters=_fields(parameters or {}),
    )


def _action(
    parameters: dict[str, JsonValue],
    *,
    dependency: str = "donor.primary",
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="function.saved",
        scope=Scope(target="program", translation_unit="unit.fixture", function=TARGET_SYMBOL),
        rationale="Saved bounded instruction mosaic for the fixture.",
        dependencies=(dependency,),
        family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=TARGET_SYMBOL,
        parameters=_fields(parameters),
    )


def _receipt(
    action: ClassicRecipeIntervention,
    body: bytes,
    *,
    pins: dict[str, JsonValue] | None = None,
    relocations: list[JsonValue] | None = None,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof.saved",
        intervention_id=action.id,
        family=action.family,
        expected_values={
            "expected_body_length": len(body),
            "expected_body_sha256": sha256(body).hexdigest(),
            "retail_oracle": {
                "address": "0x00401000",
                "image": "SAMPLE.DLL",
                "length": len(body),
                "verdict": "MATCH",
            },
            "retail_relocations": relocations or [],
            **(pins or {}),
        },
    )


def _fpo_identity(
    seed_bytes: bytes,
    donor_bytes: bytes,
    *,
    name: str,
    source_refactor: bool,
) -> tuple[JsonValue, dict[str, JsonValue]]:
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    identity, pins = measure_fpo_mosaic_identity(
        seed,
        seed.function_section(TARGET_SYMBOL),
        donor,
        donor.function_section(TARGET_SYMBOL),
        receipt_prefix=name,
        source_refactor=source_refactor,
    )
    return cast(JsonValue, identity), cast(dict[str, JsonValue], pins)


def _target_body(object_bytes: bytes) -> bytes:
    value = CoffObject(object_bytes)
    return bytes(coff_body(value, value.function_section(TARGET_SYMBOL)))


def _retail_relocations(object_bytes: bytes) -> list[JsonValue]:
    coff = CoffObject(object_bytes)
    rows = detailed_relocations(coff, coff.function_section(TARGET_SYMBOL))
    return [
        {
            key: cast(JsonValue, "0x00402000" if key == "retail_target" else row[key])
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
        for row in rows
    ]


class _MemoryOracle:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.reads: list[tuple[int, int]] = []

    def read_virtual_address(self, address: int, length: int) -> bytes:
        self.reads.append((address, length))
        return self.body


def test_retail_capture_restores_declared_relocation_addends_and_checks_the_goal() -> None:
    raw = b"\x90\x78\x56\x34\x12\xc3"
    restored = b"\x90\x11\x22\x33\x44\xc3"
    action = _action({"instruction_ranges": []})
    receipt = _receipt(
        action,
        restored,
        relocations=[
            {
                "addend": 0x44332211,
                "offset": 1,
                "retail_target": "0x00402000",
                "target": "_fixture",
                "target_section": 0,
                "target_storage": 2,
                "target_type": 32,
                "target_value": 0,
                "type": 6,
            }
        ],
    )
    memory = _MemoryOracle(raw)

    captured = capture_instruction_mosaic_retail_body(
        action, receipt, cast(PE32VirtualAddressReader, memory)
    )

    assert captured == restored
    assert memory.reads == [(0x00401000, len(restored))]
    altered = receipt.model_copy(
        update={
            "expected_values": {
                **receipt.expected_values,
                "expected_body_sha256": "00" * 32,
            }
        }
    )
    with pytest.raises(MosaicRepairError, match="immutable body goal"):
        capture_instruction_mosaic_retail_body(
            action, altered, cast(PE32VirtualAddressReader, _MemoryOracle(raw))
        )


def test_repair_alone_binds_a_valid_mosaic_target_oracle() -> None:
    action = _action({"instruction_ranges": []})
    receipt = _receipt(action, b"\x90")
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(b"source"),
        ),
        (),
        (action,),
        (),
        (action,),
        (receipt,),
    )

    assert classic_unit_oracle_targets(unit, repair=False) == frozenset()
    assert classic_unit_oracle_targets(unit, repair=True) == frozenset({"program"})

    malformed = receipt.model_copy(
        update={
            "expected_values": {
                **receipt.expected_values,
                "retail_oracle": {
                    **cast(dict[str, JsonValue], receipt.expected_values["retail_oracle"]),
                    "address": "not-an-address",
                },
            }
        }
    )
    assert (
        classic_unit_oracle_targets(
            unit.__class__(
                unit.plan,
                unit.donors,
                unit.functions,
                unit.legacy_actions,
                unit.actions,
                (malformed,),
            ),
            repair=True,
        )
        == frozenset()
    )


def test_first_unit_refusal_captures_only_bounded_mosaic_goals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mosaic = _action({"instruction_ranges": []})
    retail = _receipt(mosaic, b"\x90")
    failed = ClassicRecipeIntervention(
        id="function.other",
        scope=Scope(target="program", translation_unit="unit.fixture", function="?Other@@YAXXZ"),
        rationale="Exercise unit-wide repair-only mosaic capture.",
        dependencies=("donor.primary",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?Other@@YAXXZ",
    )
    failed_receipt = ClassicProofReceipt(
        id="proof.other",
        intervention_id=failed.id,
        family=failed.family,
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(b"source"),
        ),
        (),
        (failed, mosaic),
        (),
        (failed, mosaic),
        (failed_receipt, retail),
    )
    reader = _MemoryOracle(b"\x90")

    def refuse(*_args: object) -> object:
        raise repair_session_module.MeasuredPinRepairError("stale donor")

    monkeypatch.setattr(repair_session_module, "repair_measured_pins", refuse)
    session = ClassicRepairSession()
    session.record_action_preimage(unit.plan.id, 0, failed.id, b"seed")
    result = session(
        ClassicMeasuredReceiptRepairRequest(
            failed,
            failed_receipt,
            ClassicDispatchMaterials(seed_object=b"seed", donor_object=b"donor"),
            RuntimeError("stale donor"),
            unit,
            0,
            {"donor.primary": b"donor"},
            cast(PE32VirtualAddressReader, reader),
        )
    )

    assert result is None
    (refusal,) = session.refusals
    assert refusal.retail_body is None
    assert refusal.unit_retail_bodies == {mosaic.id: b"\x90"}
    assert refusal.action_preimages == {failed.id: b"seed"}
    session.record_action_preimage(unit.plan.id, 1, mosaic.id, b"after failed action")
    with pytest.raises(repair_session_module.ClassicRepairSessionError, match="refused unit"):
        session.release_completed_unit_preimages(unit.plan.id)
    assert session.refusals[0].action_preimages == {failed.id: b"seed"}
    assert reader.reads == [(0x00401000, 1)]


def test_reauthoring_never_replaces_the_saved_retail_goal() -> None:
    seed = make_coff(body=SEED_BODY)
    donor = make_coff(body=DONOR_BODY)
    action = _action({"instruction_ranges": []})
    altered = bytearray(DONOR_BODY)
    altered[0] ^= 1

    with pytest.raises(MosaicRepairError, match="immutable goal"):
        reauthor_instruction_mosaic(
            action,
            _receipt(action, DONOR_BODY),
            ClassicDispatchMaterials(seed_object=seed),
            bytes(altered),
            donor_objects={"donor.primary": donor},
            donor_interventions={"donor.primary": _donor("donor.primary")},
        )


def test_plain_eh_reauthoring_allows_a_valid_debug_tail_difference() -> None:
    donor_debug = bytearray(codeview_stream(len(DONOR_BODY)))
    donor_debug[-5] ^= 1
    raw_seed = make_coff(body=SEED_BODY)
    raw_donor = make_coff(body=DONOR_BODY, debug_stream=bytes(donor_debug))
    assert raw_seed.count(b".debug$F") == raw_donor.count(b".debug$F") == 2
    seed = raw_seed.replace(b".debug$F", b".xdata$x")
    donor = raw_donor.replace(b".debug$F", b".xdata$x")
    action = _action({"instruction_ranges": []})

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, DONOR_BODY),
        ClassicDispatchMaterials(seed_object=seed),
        DONOR_BODY,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    assert _target_body(result.measured.candidate.output) == DONOR_BODY


def test_ordinary_reauthoring_uses_two_named_donors_when_both_are_required() -> None:
    seed_body = PROLOGUE + SEED_RANGE + XOR_ZERO + STACK_LOAD + EPILOGUE
    first_body = PROLOGUE + DONOR_RANGE + XOR_ZERO + STACK_LOAD + EPILOGUE
    second_body = PROLOGUE + SEED_RANGE + STACK_LOAD + XOR_ZERO + EPILOGUE
    target = PROLOGUE + DONOR_RANGE + STACK_LOAD + XOR_ZERO + EPILOGUE
    seed = make_coff(body=seed_body)
    first = make_coff(body=first_body)
    second = make_coff(body=second_body)
    identity, pins = _fpo_identity(seed, first, name="ordinary_fpo_identity", source_refactor=False)
    stale_identity = deepcopy(cast(dict[str, JsonValue], identity))
    cast(dict[str, JsonValue], stale_identity["debug_f"])["section_number"] = 99
    action = _action(
        {
            "instruction_ranges": [],
            "ordinary_fpo_identity": stale_identity,
        }
    )
    receipt = _receipt(action, target, pins=pins)
    donor_actions = {
        "donor.primary": _donor("donor.primary"),
        "donor.secondary": _donor("donor.secondary"),
    }

    result = reauthor_instruction_mosaic(
        action,
        receipt,
        ClassicDispatchMaterials(seed_object=seed),
        target,
        donor_objects={"donor.primary": first, "donor.secondary": second},
        donor_interventions=donor_actions,
    )
    repeated = reauthor_instruction_mosaic(
        action,
        receipt,
        ClassicDispatchMaterials(seed_object=seed),
        target,
        donor_objects={"donor.secondary": second, "donor.primary": first},
        donor_interventions=donor_actions,
    )

    assert result.donor_ids == frozenset({"donor.primary", "donor.secondary"})
    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["ordinary_fpo_identity"] == identity
    assert values["donor_variants"] == [{"donor": "donor.secondary"}]
    assert [item["donor"] for item in values["instruction_ranges"]] == [
        "donor.primary",
        "donor.secondary",
    ]
    assert len(values["instruction_ranges"]) <= 8
    assert _target_body(result.measured.candidate.output) == target
    assert repeated.intervention == result.intervention
    assert repeated.receipt == result.receipt


def test_ordinary_fpo_reauthoring_allows_a_separately_pinned_debug_tail() -> None:
    seed = make_coff(body=SEED_BODY)
    donor_debug = bytearray(codeview_stream(len(DONOR_BODY)))
    donor_debug[-5] ^= 1
    donor = make_coff(body=DONOR_BODY, debug_stream=bytes(donor_debug))
    identity, pins = _fpo_identity(
        seed,
        donor,
        name="ordinary_fpo_identity",
        source_refactor=False,
    )
    action = _action(
        {
            "instruction_ranges": [],
            "ordinary_fpo_identity": identity,
        }
    )

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, DONOR_BODY, pins=pins),
        ClassicDispatchMaterials(seed_object=seed),
        DONOR_BODY,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    assert _target_body(result.measured.candidate.output) == DONOR_BODY


def test_reauthoring_imports_a_complete_instruction_with_an_unchanged_relocation() -> None:
    seed_body = bytes.fromhex("8b0500000000c3")
    donor_body = bytes.fromhex("8b0d00000000c3")
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=6)
    seed = make_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, "?Other@@YAXXZ", 6),),
        line_rows=((0, 11), (6, 12)),
    )
    donor = make_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((2, "?Other@@YAXXZ", 6),),
        line_rows=((0, 11), (6, 12)),
    )
    identity, pins = _fpo_identity(
        seed,
        donor,
        name="ordinary_fpo_identity",
        source_refactor=False,
    )
    action = _action({"instruction_ranges": [], "ordinary_fpo_identity": identity})
    seed_coff = CoffObject(seed)
    relocation = detailed_relocations(seed_coff, seed_coff.function_section(TARGET_SYMBOL))[0]
    retail_relocation: JsonValue = {
        key: cast(JsonValue, "0x00000000" if key == "retail_target" else relocation[key])
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

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, donor_body, pins=pins, relocations=[retail_relocation]),
        ClassicDispatchMaterials(seed_object=seed),
        donor_body,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["instruction_ranges"] == [
        {
            "donor": "donor.primary",
            "donor_instruction_lengths": [6],
            "donor_sha256": sha256(donor_body[:6]).hexdigest(),
            "end": 6,
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "seed_instruction_lengths": [6],
            "seed_sha256": sha256(seed_body[:6]).hexdigest(),
            "start": 0,
        }
    ]
    assert _target_body(result.measured.candidate.output) == donor_body


def test_reauthoring_preserves_permuted_relocations_outside_imported_ranges() -> None:
    seed_body = bytes.fromhex("8b05010000008b0d0200000033c0c3")
    donor_body = bytes.fromhex("8b05020000008b0d0100000033c9c3")
    target_body = seed_body[:12] + donor_body[12:]
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=14)
    seed = make_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, OTHER_SYMBOL, 6), (8, OTHER_SYMBOL, 6)),
        line_rows=((0, 11), (14, 12)),
    ).replace(b".debug$F", b".xdata$x")
    donor = make_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((2, OTHER_SYMBOL, 6), (8, OTHER_SYMBOL, 6)),
        line_rows=((0, 11), (14, 12)),
    ).replace(b".debug$F", b".xdata$x")
    action = _action(
        {
            "instruction_ranges": [],
            "relocation_order": "permuted_outside_ranges",
        }
    )

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, target_body, relocations=_retail_relocations(seed)),
        ClassicDispatchMaterials(seed_object=seed),
        target_body,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["relocation_order"] == "permuted_outside_ranges"
    assert values["instruction_ranges"] == [
        {
            "donor": "donor.primary",
            "donor_instruction_lengths": [2],
            "donor_sha256": sha256(donor_body[12:14]).hexdigest(),
            "end": 14,
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "seed_instruction_lengths": [2],
            "seed_sha256": sha256(seed_body[12:14]).hexdigest(),
            "start": 12,
        }
    ]
    assert _target_body(result.measured.candidate.output) == target_body


def test_reauthoring_rederives_a_contained_relocation_reseat() -> None:
    seed_body = bytes.fromhex("8b05000000008b0d00000000c3")
    donor_body = bytes.fromhex("8b0d000000008b0500000000c3")
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=12)
    seed = make_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (12, 12)),
    ).replace(b".debug$F", b".xdata$x")
    donor = make_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((8, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (12, 12)),
    ).replace(b".debug$F", b".xdata$x")
    action = _action({"instruction_ranges": [{"relocation_reseat": True}]})

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, donor_body, relocations=_retail_relocations(donor)),
        ClassicDispatchMaterials(seed_object=seed),
        donor_body,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["instruction_ranges"] == [
        {
            "donor": "donor.primary",
            "donor_instruction_lengths": [6, 6],
            "donor_relocation_offsets": [8],
            "donor_sha256": sha256(donor_body[:12]).hexdigest(),
            "end": 12,
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "relocation_reseat": True,
            "seed_instruction_lengths": [6, 6],
            "seed_relocation_offsets": [2],
            "seed_sha256": sha256(seed_body[:12]).hexdigest(),
            "start": 0,
        }
    ]
    output = CoffObject(result.measured.candidate.output)
    assert detailed_relocations(output, output.function_section(TARGET_SYMBOL))[0]["offset"] == 8
    assert "expected_output_relocation_sha256" in result.receipt.expected_values
    assert _target_body(result.measured.candidate.output) == donor_body


def test_reauthoring_measures_a_reseated_nonzero_addend_from_the_composed_body() -> None:
    seed_body = bytes.fromhex("8b05112233448b0d00000000c3")
    donor_body = bytes.fromhex("8b0d000000008b0511223344c3")
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=12)
    seed = make_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (12, 12)),
    ).replace(b".debug$F", b".xdata$x")
    donor = make_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((8, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (12, 12)),
    ).replace(b".debug$F", b".xdata$x")
    action = _action({"instruction_ranges": [{"relocation_reseat": True}]})

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, donor_body, relocations=_retail_relocations(donor)),
        ClassicDispatchMaterials(seed_object=seed),
        donor_body,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": _donor("donor.primary")},
    )

    output = CoffObject(result.measured.candidate.output)
    relocation = detailed_relocations(output, output.function_section(TARGET_SYMBOL))[0]
    assert relocation["offset"] == 8
    assert relocation["addend"] == 0x44332211
    assert _target_body(result.measured.candidate.output) == donor_body


def test_reauthoring_does_not_widen_reseat_to_an_unrelated_range() -> None:
    seed_body = bytes.fromhex("8b05000000008b0d0000000033c0c3")
    donor_body = bytes.fromhex("8b0d000000008b050000000033c9c3")
    target_body = seed_body[:12] + donor_body[12:]
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=14)
    seed = make_coff(
        body=seed_body,
        debug_stream=debug_stream,
        code_relocations=((2, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (14, 12)),
    )
    donor = make_coff(
        body=donor_body,
        debug_stream=debug_stream,
        code_relocations=((8, OTHER_SYMBOL, 6),),
        line_rows=((0, 11), (14, 12)),
    )
    action = _action({"instruction_ranges": [{"relocation_reseat": True}]})

    with pytest.raises(MosaicRepairError, match="relocations are incompatible"):
        reauthor_instruction_mosaic(
            action,
            _receipt(action, target_body, relocations=_retail_relocations(seed)),
            ClassicDispatchMaterials(seed_object=seed),
            target_body,
            donor_objects={"donor.primary": donor},
            donor_interventions={"donor.primary": _donor("donor.primary")},
        )


def test_reauthoring_rejects_permuted_relocations_on_a_semantic_mosaic() -> None:
    action = _action(
        {
            "instruction_ranges": [],
            "ordinary_fpo_identity": {},
            "relocation_order": "permuted_outside_ranges",
        }
    )

    with pytest.raises(MosaicRepairError, match="plain single-donor"):
        reauthor_instruction_mosaic(
            action,
            _receipt(action, DONOR_BODY),
            ClassicDispatchMaterials(seed_object=make_coff(body=SEED_BODY)),
            DONOR_BODY,
            donor_objects={"donor.primary": make_coff(body=DONOR_BODY)},
            donor_interventions={"donor.primary": _donor("donor.primary")},
        )


def test_reauthoring_preserves_a_saved_three_donor_nine_range_bound() -> None:
    seed_body = b"\x90" * 18 + b"\xc3"
    target_body = bytes(0x40 if index % 2 == 0 else 0x90 for index in range(18)) + b"\xc3"
    donor_bodies = {
        donor_id: bytes(
            target_body[index] if index % 6 == residue else seed_body[index]
            for index in range(len(seed_body))
        )
        for donor_id, residue in (
            ("donor.one", 0),
            ("donor.two", 2),
            ("donor.three", 4),
        )
    }
    debug_stream = codeview_stream(len(seed_body), debug_start=0, debug_end=len(seed_body) - 1)
    seed = make_coff(body=seed_body, debug_stream=debug_stream)
    donors = {
        donor_id: make_coff(body=body, debug_stream=debug_stream)
        for donor_id, body in donor_bodies.items()
    }
    identity, pins = _fpo_identity(
        seed,
        donors["donor.one"],
        name="ordinary_fpo_identity",
        source_refactor=False,
    )
    saved_ranges: list[JsonValue] = []
    for index in range(0, 18, 2):
        donor_id = ("donor.one", "donor.two", "donor.three")[(index // 2) % 3]
        saved_ranges.append(
            {
                "donor": donor_id,
                "donor_instruction_lengths": [1],
                "donor_sha256": sha256(target_body[index : index + 1]).hexdigest(),
                "end": index + 1,
                "kind": "same_offset_complete_x86_instruction_sequence_v1",
                "seed_instruction_lengths": [1],
                "seed_sha256": sha256(seed_body[index : index + 1]).hexdigest(),
                "start": index,
            }
        )
    action = _action(
        {
            "donor_variants": [{"donor": "donor.three"}, {"donor": "donor.two"}],
            "instruction_ranges": saved_ranges,
            "ordinary_fpo_identity": identity,
        },
        dependency="donor.one",
    )

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, target_body, pins=pins),
        ClassicDispatchMaterials(seed_object=seed),
        target_body,
        donor_objects=donors,
        donor_interventions={donor_id: _donor(donor_id) for donor_id in donors},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert len(cast(list[JsonValue], values["instruction_ranges"])) == 9
    assert values["donor_variants"] == [
        {"donor": "donor.three"},
        {"donor": "donor.two"},
    ]
    assert result.donor_ids == frozenset(donors)
    assert _target_body(result.measured.candidate.output) == target_body


def test_required_mosaic_donor_is_reserved_beyond_the_ranked_candidate_prefix() -> None:
    def candidate(identifier: str, start: int) -> MosaicDonorCandidate:
        body = b"AB"
        item = MosaicRangeCandidate(
            None,
            start,
            start + 1,
            frozenset({start}),
            (1,),
            (1,),
            body,
            identifier,
        )
        return MosaicDonorCandidate(
            None,
            body,
            (item,),
            item.coverage,
            identifier,
        )

    donors = [candidate(f"candidate.{index:03d}", 0) for index in range(64)]
    donors.append(candidate("zz.required", 1))

    selected = select_mosaic_ranges(
        donors,
        frozenset({0, 1}),
        max_candidates_per_symbol=64,
        max_donors=2,
        max_ranges=2,
        budget=MosaicSearchBudget(512),
        required_donor_ids=frozenset({"zz.required"}),
    )

    assert selected is not None
    assert {mosaic_range_donor_id(item) for item in selected} == {
        "candidate.000",
        "zz.required",
    }


def test_saved_self_permutation_is_preserved_and_remeasured() -> None:
    seed = make_coff(body=SEED_BODY)
    donor = make_coff(body=DONOR_BODY)
    seed_coff = CoffObject(seed)
    identity, pins = _fpo_identity(seed, donor, name="ordinary_fpo_identity", source_refactor=False)
    permutation = {
        name: cast(JsonValue, value)
        for name, value in self_permutation(seed_coff).items()
        if not name.startswith("expected_")
    }
    descriptor = carrier()
    donor_action = _donor(
        "donor.primary",
        family=ClassicRecipeFamily.EXTERN_RUN_PAIR,
        parameters={
            "generated_header_sha256": cast(str, descriptor["generated_declarations_sha256"]),
            "header_count": cast(int, descriptor["header_count"]),
            "header_prefix": cast(str, descriptor["header_prefix"]),
            "seat_count": cast(int, descriptor["seat_count"]),
            "seat_prefix": cast(str, descriptor["seat_prefix"]),
            "width": cast(int, descriptor["width"]),
        },
    )
    action = _action(
        {
            "instruction_ranges": [],
            "instruction_self_permutation": cast(JsonValue, permutation),
            "ordinary_fpo_identity": identity,
            "same_function_source_identity": {"carrier": descriptor},
        }
    )

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, MOSAIC, pins=pins),
        ClassicDispatchMaterials(seed_object=seed, seed_source=b"int seed;\n"),
        MOSAIC,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": donor_action},
        donor_sources={"donor.primary": b"int donor;\n"},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["instruction_self_permutation"] == permutation
    assert "same_function_source_identity" in values
    assert (
        result.receipt.expected_values["instruction_self_permutation.expected_changed_offsets"]
        == self_permutation(seed_coff)["expected_changed_offsets"]
    )
    assert _target_body(result.measured.candidate.output) == MOSAIC


@pytest.mark.parametrize(
    ("kind", "shape", "identifiers"),
    [
        (
            "force_included_shape_v1",
            {"classes": 1, "functions": 2},
            ["ClassAaaaaa", "FunctionAaaaaaaa", "FunctionBaaaaaaa"],
        ),
        (
            "force_included_pad_shape_v1",
            {"classes": 1, "functions_per_class": 2},
            ["ClassPad00", "FunctionPad00x00", "FunctionPad00x01"],
        ),
    ],
)
def test_saved_self_permutation_accepts_an_overlay_force_include_carrier(
    kind: str,
    shape: dict[str, JsonValue],
    identifiers: list[str],
) -> None:
    seed = make_coff(body=SEED_BODY)
    donor = make_coff(body=DONOR_BODY)
    seed_coff = CoffObject(seed)
    identity, pins = _fpo_identity(seed, donor, name="ordinary_fpo_identity", source_refactor=False)
    permutation = {
        name: cast(JsonValue, value)
        for name, value in self_permutation(seed_coff).items()
        if not name.startswith("expected_")
    }
    generated = (
        declaration_shapes.generate_shape(1, 2)
        if kind == "force_included_shape_v1"
        else declaration_shapes.generate_pad_shape(1, 2)
    ).encode("ascii")
    descriptor: dict[str, JsonValue] = {
        **shape,
        "generated_declarations_sha256": sha256(generated).hexdigest(),
        "kind": kind,
        "placement": "force_include_v1",
    }
    donor_action = _donor(
        "donor.primary",
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"compiler_state_carrier": descriptor},
    )
    action = _action(
        {
            "instruction_ranges": [],
            "instruction_self_permutation": cast(JsonValue, permutation),
            "ordinary_fpo_identity": identity,
            "same_function_source_identity": {
                "carrier": descriptor,
                "carrier_identifiers": [],
            },
        }
    )

    result = reauthor_instruction_mosaic(
        action,
        _receipt(action, MOSAIC, pins=pins),
        ClassicDispatchMaterials(seed_object=seed, seed_source=b"int seed;\n"),
        MOSAIC,
        donor_objects={"donor.primary": donor},
        donor_interventions={"donor.primary": donor_action},
        donor_sources={"donor.primary": b"int donor;\n"},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["same_function_source_identity"] == {
        "carrier": descriptor,
        "carrier_identifiers": identifiers,
        "effective_source_sha256": sha256(b"int seed;\n").hexdigest(),
        "rendered_source_sha256": sha256(b"int donor;\n").hexdigest(),
        "rendered_source_size": len(b"int donor;\n"),
    }
    assert _target_body(result.measured.candidate.output) == MOSAIC


def _range_pin(data: bytes) -> dict[str, JsonValue]:
    return {
        "baseline_line_count": data.count(b"\n"),
        "baseline_sha256": sha256(data).hexdigest(),
        "baseline_significant_token_sha256": source_overlay_significant_sha256(data),
        "baseline_size": len(data),
    }


def test_source_aware_reauthoring_keeps_its_overlay_bound_proof() -> None:
    seed = make_coff(body=SEED_BODY)
    donor = make_coff(
        body=DONOR_BODY,
        debug_stream=codeview_stream(len(DONOR_BODY), extra=LOCAL_RECORD),
    )
    seed_source = b"// TARGET\nint Read() { return 0; }\n"
    donor_source = b"// TARGET\nint Read() { int value = 0; return value; }\n"
    selector: dict[str, JsonValue] = {
        "kind": "for_initializer_declaration_reseat_v1",
        "selector": "brace_balanced_function_after_marker_v1",
        "start_marker": "// TARGET",
    }
    proof: dict[str, JsonValue] = {
        **selector,
        "donor_range_pin": _range_pin(
            select_source_permutation_window(donor_source, selector, "fixture donor")
        ),
        "operation_ids": ["op.target"],
        "seed_range_pin": _range_pin(
            select_source_permutation_window(seed_source, selector, "fixture seed")
        ),
        "source_owner_mangled": TARGET_SYMBOL,
    }
    identity, pins = _fpo_identity(seed, donor, name="source_fpo_identity", source_refactor=True)
    action = _action(
        {
            "instruction_ranges": [],
            "source_fpo_identity": identity,
            "target_source_refactor": proof,
        },
        dependency="donor.overlay",
    )
    receipt = _receipt(action, DONOR_BODY, pins=pins)
    overlay = _donor("donor.overlay", family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY)

    result = reauthor_instruction_mosaic(
        action,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, seed_source=seed_source),
        DONOR_BODY,
        donor_objects={"donor.overlay": donor},
        donor_interventions={"donor.overlay": overlay},
        donor_sources={"donor.overlay": donor_source},
    )

    values = {field.name: field.value for field in result.intervention.parameters}
    assert values["target_source_refactor"] == proof
    assert values["source_fpo_identity"] == identity
    assert result.intervention.dependencies == ("donor.overlay",)
    assert "donor_variants" not in values
    assert _target_body(result.measured.candidate.output) == DONOR_BODY

    ordinary_donor = overlay.model_copy(update={"family": ClassicRecipeFamily.DECLARATION_SHAPE})
    with pytest.raises(MosaicRepairError, match="source-overlay donor"):
        reauthor_instruction_mosaic(
            action,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, seed_source=seed_source),
            DONOR_BODY,
            donor_objects={"donor.overlay": donor},
            donor_interventions={"donor.overlay": ordinary_donor},
            donor_sources={"donor.overlay": donor_source},
        )


def test_semantic_mosaics_cannot_fall_through_to_equal_body_reauthoring() -> None:
    plain = _action({"instruction_ranges": []})
    source_aware = _action(
        {
            "instruction_ranges": [],
            "target_source_refactor": {"kind": "fixture"},
        }
    )

    assert not instruction_mosaic_semantics_required(plain)
    assert instruction_mosaic_semantics_required(source_aware)
