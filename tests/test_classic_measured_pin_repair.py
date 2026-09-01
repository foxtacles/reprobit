from __future__ import annotations

from hashlib import sha256
from typing import cast

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic import composition_mosaic
from reprobit.classic.measured_pin_repair import (
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
)
from reprobit.coff_format import CoffObject, coff_body, detailed_relocations
from reprobit.model import Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)

SYMBOL = coff_fixture.TARGET_SYMBOL


def _objects() -> tuple[bytes, bytes]:
    donor_body = bytearray(coff_fixture.BODY)
    donor_body[0] = 0x90
    return coff_fixture.make_coff(), coff_fixture.make_coff(body=bytes(donor_body))


def _body(payload: bytes) -> bytes:
    coff = CoffObject(payload)
    return bytes(coff_body(coff, coff.function_section(SYMBOL)))


def _with_named_target_section(payload: bytes, section: int) -> bytes:
    coff = CoffObject(payload)
    symbol_index = next(
        index for index, symbol in coff.symbols.items() if symbol["name"] == coff_fixture.NIL_SYMBOL
    )
    result = bytearray(payload)
    offset = coff.symbol_offset + symbol_index * 18 + 12
    result[offset : offset + 2] = section.to_bytes(2, "little", signed=True)
    return bytes(result)


def _relocation_oracle(payload: bytes, *, section: int) -> list[dict[str, object]]:
    coff = CoffObject(payload)
    primary = coff.function_section(SYMBOL)
    result: list[dict[str, object]] = []
    for row in detailed_relocations(coff, primary):
        result.append(
            {
                "offset": row["offset"],
                "type": row["type"],
                "addend": row["addend"],
                "target": row["target"],
                "target_section": section,
                "target_value": row["target_value"],
                "target_type": row["target_type"],
                "target_storage": row["target_storage"],
                "retail_target": "0x10000000",
            }
        )
    return result


def _intervention(family: ClassicRecipeFamily) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="function.repair",
        scope=Scope(target="program", translation_unit="unit", function=SYMBOL),
        rationale="Exercise conservative measured-pin repair.",
        dependencies=("donor",),
        family=family,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=SYMBOL,
    )


def _receipt(
    intervention: ClassicRecipeIntervention,
    expected_values: dict[str, object],
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof.repair",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values=expected_values,  # type: ignore[arg-type]
        status="saved",
        authenticity="compiler_generated_current_source",
    )


def test_equal_body_repair_refreshes_only_existing_measured_pins_and_replays_dispatch() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.EQUAL_BODY_STRICT)
    donor_digest = sha256(_body(donor)).hexdigest()
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": donor_digest,
            "expected_changed_offsets": [1],
        },
    )

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
    )

    assert result.changed_keys == ("expected_changed_offsets",)
    assert result.receipt.expected_values == {
        "expected_body_length": len(_body(donor)),
        "expected_body_sha256": donor_digest,
        "expected_changed_offsets": [0],
    }
    assert result.receipt.status == receipt.status
    assert result.receipt.authenticity == receipt.authenticity
    assert receipt.expected_values["expected_changed_offsets"] == [1]
    assert _body(result.candidate.output) == _body(donor)


def test_equal_body_repair_never_moves_the_donor_body_goal() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.EQUAL_BODY_STRICT)
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": "0" * 64,
            "expected_changed_offsets": [1],
        },
    )

    with pytest.raises(MeasuredPinRepairError, match="immutable expected_body_sha256"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )

    assert receipt.expected_values["expected_body_sha256"] == "0" * 64


def test_equal_body_repair_requires_ordinary_composer_acceptance() -> None:
    seed, donor = _objects()
    incompatible = coff_fixture.make_coff(body=_body(donor), relocations=(6,))
    intervention = _intervention(ClassicRecipeFamily.EQUAL_BODY_STRICT)
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_changed_offsets": [1],
        },
    )

    with pytest.raises(MeasuredPinRepairError, match="ordinary equal_body_strict candidate"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=incompatible),
        )


def test_measured_pin_repair_refuses_mismatched_or_nonrepinnable_authority() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.EQUAL_BODY_STRICT)
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_changed_offsets": [0],
        },
    )
    mismatched = receipt.model_copy(update={"intervention_id": "function.other"})

    with pytest.raises(MeasuredPinRepairError, match="different intervention"):
        repair_measured_pins(
            intervention,
            mismatched,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )

    unsupported = _intervention(ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION)
    unsupported_receipt = _receipt(
        unsupported,
        {
            "expected_body_sha256": sha256(_body(donor)).hexdigest(),
        },
    )
    with pytest.raises(MeasuredPinRepairError, match="no conservative measured-pin repair"):
        repair_measured_pins(
            unsupported,
            unsupported_receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )


class _RecordingDispatcher:
    def __init__(self, candidate: ClassicCandidate, *, reject: bool = False) -> None:
        self.candidate = candidate
        self.reject = reject
        self.constraints: dict[str, object] | None = None

    def dispatch(
        self,
        _intervention: ClassicRecipeIntervention,
        materials: ClassicDispatchMaterials,
    ) -> ClassicCandidate:
        self.constraints = dict(materials.candidate_constraints or {})
        if self.reject:
            raise ClassicProjectError("source proof no longer holds")
        return self.candidate


def test_source_equal_body_refreshes_seed_and_metadata_but_not_donor_goal() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY)
    donor_digest = sha256(_body(donor)).hexdigest()
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": donor_digest,
            "expected_changed_offsets": [1],
            "expected_code_renames": [[7, "L"]],
            "expected_donor_body_sha256": donor_digest,
            "expected_donor_line_count": 999,
            "expected_donor_metadata_sha256": "1" * 64,
            "expected_seed_body_sha256": "2" * 64,
            "expected_seed_line_count": 999,
            "expected_seed_metadata_sha256": "3" * 64,
        },
    )
    sentinel = cast(ClassicCandidate, object())
    dispatcher = _RecordingDispatcher(sentinel)

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(
            seed_object=seed,
            donor_object=donor,
            seed_source=b"int seed();\n",
            donor_source=b"int donor();\n",
        ),
        dispatcher=cast(ClassicFamilyDispatcher, dispatcher),
    )

    seed_coff = CoffObject(seed)
    donor_coff = CoffObject(donor)
    seed_primary = seed_coff.function_section(SYMBOL)
    donor_primary = donor_coff.function_section(SYMBOL)
    expected = result.receipt.expected_values
    assert set(result.changed_keys) == {
        "expected_changed_offsets",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_seed_body_sha256",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
    }
    assert expected["expected_body_sha256"] == donor_digest
    assert expected["expected_donor_body_sha256"] == donor_digest
    assert expected["expected_seed_body_sha256"] == sha256(_body(seed)).hexdigest()
    assert expected["expected_changed_offsets"] == [0]
    assert expected["expected_seed_metadata_sha256"] == (
        composition_mosaic.instruction_mosaic_metadata_sha256(seed_coff, seed_primary)
    )
    assert expected["expected_donor_metadata_sha256"] == (
        composition_mosaic.instruction_mosaic_metadata_sha256(donor_coff, donor_primary)
    )
    assert expected["expected_code_renames"] == [[7, "L"]]
    assert dispatcher.constraints == expected
    assert result.candidate is sentinel


def test_source_equal_body_requires_matching_donor_pins_and_dispatch_acceptance() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY)
    donor_digest = sha256(_body(donor)).hexdigest()
    mismatched = _receipt(
        intervention,
        {
            "expected_body_sha256": donor_digest,
            "expected_donor_body_sha256": "0" * 64,
        },
    )
    with pytest.raises(MeasuredPinRepairError, match="source-equal-body donor pin differs"):
        repair_measured_pins(
            intervention,
            mismatched,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )

    seed_coff = CoffObject(seed)
    donor_coff = CoffObject(donor)
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": donor_digest,
            "expected_changed_offsets": [1],
            "expected_donor_body_sha256": donor_digest,
            "expected_donor_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
                donor_coff, donor_coff.function_section(SYMBOL)
            ),
            "expected_seed_body_sha256": sha256(_body(seed)).hexdigest(),
            "expected_seed_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
                seed_coff, seed_coff.function_section(SYMBOL)
            ),
        },
    )
    rejecting = _RecordingDispatcher(cast(ClassicCandidate, object()), reject=True)
    with pytest.raises(MeasuredPinRepairError, match="ordinary retail_exact_source_equal_body"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(ClassicFamilyDispatcher, rejecting),
        )


def test_donor_rewriting_refreshes_only_compiler_measurements_around_fixed_donor() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    donor_digest = sha256(_body(donor)).hexdigest()
    receipt = _receipt(
        intervention,
        {
            "expected_body_sha256": "f" * 64,
            "expected_donor_body_sha256": donor_digest,
            "expected_donor_length": 999,
            "expected_donor_line_count": 999,
            "expected_donor_metadata_sha256": "1" * 64,
            "expected_seed_body_sha256": "2" * 64,
            "expected_seed_length": 999,
            "expected_seed_line_count": 999,
            "expected_seed_metadata_sha256": "3" * 64,
            "retail_oracle": {"verdict": "MATCH"},
        },
    )
    sentinel = cast(ClassicCandidate, object())
    dispatcher = _RecordingDispatcher(sentinel)

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        dispatcher=cast(ClassicFamilyDispatcher, dispatcher),
    )

    assert set(result.changed_keys) == {
        "expected_donor_length",
        "expected_donor_line_count",
        "expected_donor_metadata_sha256",
        "expected_seed_body_sha256",
        "expected_seed_length",
        "expected_seed_line_count",
        "expected_seed_metadata_sha256",
    }
    assert result.receipt.expected_values["expected_body_sha256"] == "f" * 64
    assert result.receipt.expected_values["expected_donor_body_sha256"] == donor_digest
    assert result.receipt.expected_values["retail_oracle"] == {"verdict": "MATCH"}
    assert dispatcher.constraints == result.receipt.expected_values
    assert result.candidate is sentinel


def test_donor_rewriting_never_moves_the_donor_body_pin() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": "0" * 64,
            "expected_seed_body_sha256": sha256(_body(seed)).hexdigest(),
        },
    )

    with pytest.raises(MeasuredPinRepairError, match="immutable expected_donor_body_sha256"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )


def test_donor_rewriting_refreshes_only_named_external_section_seats() -> None:
    seed, donor = _objects()
    donor = _with_named_target_section(donor, 4)
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    declared = _relocation_oracle(donor, section=3)
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "retail_relocations": declared,
        },
    )
    sentinel = cast(ClassicCandidate, object())
    dispatcher = _RecordingDispatcher(sentinel)

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        dispatcher=cast(ClassicFamilyDispatcher, dispatcher),
    )

    assert result.changed_keys == ("retail_relocations",)
    refreshed = result.receipt.expected_values["retail_relocations"]
    assert isinstance(refreshed, list)
    assert all(isinstance(row, dict) and row["target_section"] == 4 for row in refreshed)
    assert all(row["target_section"] == 3 for row in declared)
    assert dispatcher.constraints == result.receipt.expected_values
    assert result.candidate is sentinel


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("type", 20),
        ("addend", 1),
        ("target", "?Different@@3HA"),
        ("target_value", 1),
        ("target_type", 32),
        ("target_storage", 3),
    ),
)
def test_donor_rewriting_refuses_broader_relocation_drift_during_seat_refresh(
    field: str,
    replacement: object,
) -> None:
    seed, donor = _objects()
    donor = _with_named_target_section(donor, 4)
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    declared = _relocation_oracle(donor, section=3)
    declared[0][field] = replacement
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "retail_relocations": declared,
        },
    )

    with pytest.raises(MeasuredPinRepairError, match="not an exact named-external seat move"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(
                ClassicFamilyDispatcher,
                _RecordingDispatcher(cast(ClassicCandidate, object())),
            ),
        )


def test_donor_rewriting_does_not_repin_defined_or_undefined_symbol_status() -> None:
    seed, donor = _objects()
    donor = _with_named_target_section(donor, 4)
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "retail_relocations": _relocation_oracle(donor, section=0),
        },
    )

    with pytest.raises(MeasuredPinRepairError, match="not an exact named-external seat move"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(
                ClassicFamilyDispatcher,
                _RecordingDispatcher(cast(ClassicCandidate, object())),
            ),
        )
