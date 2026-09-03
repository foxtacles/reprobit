from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace
from typing import Any, cast

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic import composition_mosaic
from reprobit.classic_measured_pin_repair import (
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
from reprobit.model import Digest, Scope
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


def _divergence_rows(*targets: str) -> list[dict[str, object]]:
    return [
        {
            "offset": 8 * index,
            "width": 4,
            "type": 6,
            "addend": 0,
            "target": target,
            "target_section": 3,
            "target_storage": 6,
            "target_type": 0,
            "target_value": 16 * index,
        }
        for index, target in enumerate(targets)
    ]


def test_donor_rewriting_follows_renumbered_local_labels_in_divergences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reprobit.classic_measured_pin_repair as subject

    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_relocation_divergences": [[1, "$L69582", "$L70311"]],
            "expected_seed_body_sha256": sha256(_body(seed)).hexdigest(),
        },
    )
    rows = {
        "seed": _divergence_rows("__except_list", "$L89484"),
        "donor": _divergence_rows("__except_list", "$L90001"),
    }
    monkeypatch.setattr(
        subject,
        "detailed_relocations",
        lambda obj, _section: rows["seed"] if obj.data == seed else rows["donor"],
    )
    sentinel = cast(ClassicCandidate, object())
    dispatcher = _RecordingDispatcher(sentinel)

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        dispatcher=cast(ClassicFamilyDispatcher, dispatcher),
    )

    assert "expected_relocation_divergences" in result.changed_keys
    assert result.receipt.expected_values["expected_relocation_divergences"] == [
        [1, "$L89484", "$L90001"]
    ]
    assert result.candidate is sentinel


def test_donor_rewriting_refuses_a_divergence_that_is_not_a_local_renumbering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reprobit.classic_measured_pin_repair as subject

    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    receipt = _receipt(
        intervention,
        {
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_relocation_divergences": [[1, "$L69582", "$L70311"]],
        },
    )
    rows = {
        "seed": _divergence_rows("__except_list", "?Other@@YAXXZ"),
        "donor": _divergence_rows("__except_list", "$L70311"),
    }
    monkeypatch.setattr(
        subject,
        "detailed_relocations",
        lambda obj, _section: rows["seed"] if obj.data == seed else rows["donor"],
    )

    with pytest.raises(MeasuredPinRepairError, match="not a compiler-local renumbering"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )


def test_decision_only_family_is_replayed_as_saved_and_accepted_when_it_composes() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION)
    receipt = _receipt(
        intervention,
        {"expected_body_sha256": "f" * 64, "register_bijection": {"kind": "fixed"}},
    )
    sentinel = cast(ClassicCandidate, object())
    dispatcher = _RecordingDispatcher(sentinel)

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        dispatcher=cast(ClassicFamilyDispatcher, dispatcher),
    )

    assert result.receipt is receipt
    assert result.changed_keys == ()
    assert result.candidate is sentinel
    assert dispatcher.constraints == receipt.expected_values


def test_decision_only_family_that_does_not_compose_is_refused_at_validation() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION)
    receipt = _receipt(intervention, {"expected_body_sha256": "f" * 64})

    class _Refusing:
        def dispatch(self, *_args: object, **_kwargs: object) -> ClassicCandidate:
            raise ClassicProjectError("web does not recolour")

    with pytest.raises(MeasuredPinRepairError, match="does not compose") as caught:
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(ClassicFamilyDispatcher, _Refusing()),
        )
    assert caught.value.stage == "ordinary_validation"


def test_reloc_divergent_refreshes_only_seed_and_layout_observations() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT)
    donor_object = CoffObject(donor)
    donor_primary = donor_object.function_section(intervention.symbol or "")
    receipt = _receipt(
        intervention,
        {
            "expected_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_donor_length": donor_primary["raw_size"],
            "expected_donor_section_number": 999,
            "expected_linked_span": (donor_primary["raw_size"] + 15) // 16 * 16,
            "expected_seed_length": 999,
            "retail_oracle": {
                "address": "0x10001000",
                "image": "X.DLL",
                "length": 1,
                "verdict": "MATCH",
            },
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

    assert set(result.changed_keys) == {"expected_donor_section_number", "expected_seed_length"}
    values = result.receipt.expected_values
    assert values["expected_donor_section_number"] == donor_primary["number"]
    assert (
        values["expected_seed_length"]
        == CoffObject(seed).function_section(intervention.symbol or "")["raw_size"]
    )
    assert values["retail_oracle"] == receipt.expected_values["retail_oracle"]
    assert values["expected_body_sha256"] == receipt.expected_values["expected_body_sha256"]
    assert result.candidate is sentinel


def test_reloc_divergent_never_moves_its_donor_body_goal() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT)
    receipt = _receipt(intervention, {"expected_body_sha256": "0" * 64, "expected_seed_length": 1})

    with pytest.raises(MeasuredPinRepairError, match="immutable expected_body_sha256"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        )


def _seat_receipt_values(seed: bytes, donor: bytes) -> dict[str, object]:
    from reprobit.classic_measured_pin_repair import _seat_observations

    return dict(_seat_observations(CoffObject(seed), CoffObject(donor), SYMBOL))


def test_web_recolour_refreshes_seed_witness_observations_but_not_its_decisions() -> None:
    seed = coff_fixture.make_coff()
    donor = coff_fixture.make_coff()  # the witness reproduces the seed body exactly
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR)
    fresh = _seat_receipt_values(seed, donor)
    retail = sha256(_body(seed)).hexdigest()
    stale = {
        "expected_body_length": fresh["expected_body_length"],
        "expected_body_sha256": retail,
        "expected_changed_offsets": [3, 4],
        "expected_closure": [".debug$F", ".debug$S"],
        "expected_comdat_count": fresh["expected_comdat_count"],
        "expected_donor_body_sha256": fresh["expected_donor_body_sha256"],
        "expected_donor_line_count": fresh["expected_donor_line_count"],
        "expected_donor_metadata_sha256": "1" * 64,
        "expected_function_count": fresh["expected_function_count"],
        "expected_relocation_count": fresh["expected_relocation_count"],
        "expected_section_count": fresh["expected_section_count"],
        "expected_section_number": fresh["expected_section_number"],
        "expected_seed_body_sha256": fresh["expected_seed_body_sha256"],
        "expected_seed_line_count": fresh["expected_seed_line_count"],
        "expected_seed_metadata_sha256": "2" * 64,
        "retail_oracle": {
            "address": "0x10000000",
            "image": "X.DLL",
            "length": 1,
            "verdict": "MATCH",
        },
    }
    receipt = _receipt(intervention, stale)

    class _Composing:
        constraints: dict[str, object] | None = None

        def dispatch(self, _intervention: object, materials: ClassicDispatchMaterials) -> Any:
            self.constraints = dict(materials.candidate_constraints or {})
            digest = sha256(seed).hexdigest()
            return ClassicCandidate(seed, {}, Digest(value=digest), {}, {}, {})  # type: ignore[arg-type]

    composer = _Composing()
    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
        dispatcher=cast(ClassicFamilyDispatcher, composer),
    )

    assert result.changed_keys == (
        "expected_donor_metadata_sha256",
        "expected_seed_metadata_sha256",
    )
    values = result.receipt.expected_values
    assert values["expected_seed_metadata_sha256"] == fresh["expected_seed_metadata_sha256"]
    assert values["expected_donor_metadata_sha256"] == fresh["expected_donor_metadata_sha256"]
    assert values["expected_changed_offsets"] == [3, 4]
    assert values["expected_body_sha256"] == retail
    assert composer.constraints is not None
    assert (
        composer.constraints["expected_seed_metadata_sha256"]
        == (fresh["expected_seed_metadata_sha256"])
    )


def test_retail_matching_receipt_refuses_a_composed_body_that_is_not_retail() -> None:
    seed, donor = _objects()
    intervention = _intervention(ClassicRecipeFamily.EQUAL_BODY_STRICT)
    donor_digest = sha256(_body(donor)).hexdigest()
    receipt = _receipt(
        intervention,
        {
            "expected_body_length": len(_body(donor)),
            "expected_body_sha256": donor_digest,
            "expected_changed_offsets": [0],
            "retail_oracle": {
                "address": "0x10000000",
                "image": "X.DLL",
                "length": 1,
                "verdict": "MATCH",
            },
        },
    )

    class _Wrong:
        def dispatch(self, *_args: object, **_kwargs: object) -> Any:
            return ClassicCandidate(seed, {}, Digest.from_bytes(seed), {}, {}, {})  # type: ignore[arg-type]

    with pytest.raises(MeasuredPinRepairError, match="retail-matching") as caught:
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(ClassicFamilyDispatcher, _Wrong()),
        )
    assert caught.value.stage == "ordinary_validation"

    # The ordinary composer installs the donor body, which is the retail body: accepted.
    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
    )
    assert _body(result.candidate.output) == _body(donor)


def test_instruction_mosaic_refreshes_variant_observations_from_captured_objects() -> None:
    seed, donor = _objects()
    variant = coff_fixture.make_coff(body=bytes([0x90]) + coff_fixture.BODY[1:])
    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC)
    fresh = _seat_receipt_values(seed, donor)
    variant_coff = CoffObject(variant)
    variant_primary = variant_coff.function_section(SYMBOL)
    variant_metadata = composition_mosaic.instruction_mosaic_metadata_sha256(
        variant_coff, variant_primary
    )
    receipt = _receipt(
        intervention,
        {
            "donor_variants": [{"donor": "variant"}],
            "donor_variants[0].expected_body_sha256": sha256(_body(variant)).hexdigest(),
            "donor_variants[0].expected_line_count": 99,
            "donor_variants[0].expected_metadata_sha256": "3" * 64,
            "expected_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_donor_body_sha256": sha256(_body(donor)).hexdigest(),
            "expected_seed_body_sha256": "4" * 64,
            "expected_seed_metadata_sha256": "5" * 64,
            "instruction_ranges": [],
        },
    )
    seen: dict[str, object] = {}

    class _Composing:
        def dispatch(self, _intervention: object, materials: ClassicDispatchMaterials) -> Any:
            seen.update(materials.candidate_constraints or {})
            return ClassicCandidate(donor, {}, Digest.from_bytes(donor), {}, {}, {})  # type: ignore[arg-type]

    result = repair_measured_pins(
        intervention,
        receipt,
        ClassicDispatchMaterials(
            seed_object=seed, donor_object=donor, additional_donor_objects={"variant": variant}
        ),
        dispatcher=cast(ClassicFamilyDispatcher, _Composing()),
    )

    assert set(result.changed_keys) == {
        "donor_variants[0].expected_line_count",
        "donor_variants[0].expected_metadata_sha256",
        "expected_seed_body_sha256",
        "expected_seed_metadata_sha256",
    }
    values = result.receipt.expected_values
    assert values["donor_variants[0].expected_metadata_sha256"] == variant_metadata
    assert values["donor_variants[0].expected_line_count"] == variant_primary["line_count"]
    assert values["donor_variants[0].expected_body_sha256"] == sha256(_body(variant)).hexdigest()
    assert values["expected_seed_body_sha256"] == fresh["expected_seed_body_sha256"]
    assert values["expected_donor_body_sha256"] == sha256(_body(donor)).hexdigest()
    assert seen["expected_seed_metadata_sha256"] == fresh["expected_seed_metadata_sha256"]

    with pytest.raises(MeasuredPinRepairError, match="was not captured"):
        repair_measured_pins(
            intervention,
            receipt,
            ClassicDispatchMaterials(seed_object=seed, donor_object=donor),
            dispatcher=cast(ClassicFamilyDispatcher, _Composing()),
        )


def _rows(*items: tuple[int, str, int, int]) -> list[dict[str, Any]]:
    return [
        {
            "offset": offset,
            "type": 20,
            "addend": 0,
            "target": target,
            "target_section": section,
            "target_value": 0,
            "target_type": 32,
            "target_storage": storage,
        }
        for offset, target, section, storage in items
    ]


def test_relocation_seats_follow_a_renumbered_local_in_the_functions_own_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reprobit.classic_measured_pin_repair as module

    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR)
    declared = _rows(
        (4, "?Timer@@YAPAVMxTimer@@XZ", 0, 2),
        (25, "$L80109", 189, 6),
        (40, "_g_pizzaHitSounds$S72827", 12, 3),
    )
    for row in declared:
        row["retail_target"] = "0x10000000"
    receipt = _receipt(
        intervention, {"expected_section_number": 189, "retail_relocations": declared}
    )
    fresh = _rows(
        (4, "?Timer@@YAPAVMxTimer@@XZ", 0, 2),
        (25, "$L80211", 190, 6),
        (40, "_g_pizzaHitSounds$S72830", 12, 3),
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: fresh)
    primary = cast(Any, {"number": 190})

    refreshed = module._named_external_relocation_seats(
        receipt, cast(Any, object()), primary, follow_locals=True
    )
    assert refreshed is not None
    assert refreshed[1]["target"] == "$L80211"  # type: ignore[index]
    assert refreshed[1]["target_section"] == 190  # type: ignore[index]
    # A file static renumbered in place keeps its seat and follows its serial.
    assert refreshed[2]["target"] == "_g_pizzaHitSounds$S72830"  # type: ignore[index]
    assert refreshed[2]["target_section"] == 12  # type: ignore[index]
    assert refreshed[0] == declared[0]  # type: ignore[index]
    assert declared[1]["target"] == "$L80109"

    # A different static under the same seat is not a renumbering.
    other_static = _rows(
        (4, "?Timer@@YAPAVMxTimer@@XZ", 0, 2),
        (25, "$L80211", 190, 6),
        (40, "_g_copDonutSounds$S72830", 12, 3),
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: other_static)
    with pytest.raises(MeasuredPinRepairError, match="not a compiler-serial renumbering"):
        module._named_external_relocation_seats(
            receipt, cast(Any, object()), primary, follow_locals=True
        )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: fresh)

    # Without the follow, and for a moved offset or a foreign section, drift is refused.
    with pytest.raises(MeasuredPinRepairError, match="not an exact named-external"):
        module._named_external_relocation_seats(receipt, cast(Any, object()), primary)
    moved_offset = _rows(
        (4, "?Timer@@YAPAVMxTimer@@XZ", 0, 2),
        (26, "$L80211", 190, 6),
        (40, "_g_pizzaHitSounds$S72830", 12, 3),
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: moved_offset)
    with pytest.raises(MeasuredPinRepairError, match="not an exact named-external"):
        module._named_external_relocation_seats(
            receipt, cast(Any, object()), primary, follow_locals=True
        )
    foreign = _rows(
        (4, "?Timer@@YAPAVMxTimer@@XZ", 0, 2),
        (25, "$L80211", 191, 6),
        (40, "_g_pizzaHitSounds$S72830", 12, 3),
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: foreign)
    with pytest.raises(MeasuredPinRepairError, match="not an exact named-external"):
        module._named_external_relocation_seats(
            receipt, cast(Any, object()), primary, follow_locals=True
        )


def test_code_symbol_references_follow_renumbered_locals_at_unchanged_offsets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import reprobit.classic_measured_pin_repair as module

    intervention = _intervention(ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING)
    declared = [
        [".debug$S", "$L71291", 2235],
        [".debug$S", "$L71291", 2235],
        [".debug$S", "$L71535", 2227],
        [".debug$S", "?Animate@Widget@@UAEXM@Z", 0],
    ]
    receipt = _receipt(intervention, {"donor_rewriting.expected_code_symbol_references": declared})
    donor = SimpleNamespace(
        symbols={
            1: {"name": "$L80001", "section": 7, "value": 2235},
            2: {"name": "$L80002", "section": 7, "value": 2227},
            3: {"name": "?Animate@Widget@@UAEXM@Z", "section": 7, "value": 0},
            4: {"name": "$L80003", "section": 8, "value": 2235},
        }
    )
    primary = cast(Any, {"number": 7})
    monkeypatch.setattr(module, "_comdat_child_closure", lambda *_args: (1, (".debug$S",)))
    monkeypatch.setattr(module, "_comdat_child", lambda *_args: {"number": 9})
    rows = _rows(
        (10, "$L80001", 7, 6),
        (20, "$L80001", 7, 6),
        (30, "$L80002", 7, 6),
        (40, "?Animate@Widget@@UAEXM@Z", 7, 2),
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: rows)

    refreshed = module._renumbered_code_symbol_references(receipt, cast(Any, donor), primary)
    assert refreshed == [
        [".debug$S", "$L80001", 2235],
        [".debug$S", "$L80001", 2235],
        [".debug$S", "$L80002", 2227],
        [".debug$S", "?Animate@Widget@@UAEXM@Z", 0],
    ]
    assert declared[0][1] == "$L71291"

    # A named symbol that vanished, or a local of another kind, is left to the producer.
    other_kind = _rows(
        (10, "$T80001", 7, 6), (30, "$L80002", 7, 6), (40, "?Animate@Widget@@UAEXM@Z", 7, 2)
    )
    monkeypatch.setattr(module, "detailed_relocations", lambda *_args: other_kind)
    donor.symbols[1]["name"] = "$T80001"
    assert module._renumbered_code_symbol_references(receipt, cast(Any, donor), primary) is None


def test_declared_symbol_kind_pairs_file_statics_by_base_name() -> None:
    from reprobit.classic.foundation import declared_symbol_kind, local_symbol_kind

    assert declared_symbol_kind("$L123") == "L" == local_symbol_kind("$L123")
    assert declared_symbol_kind("_g_pizzaHitSounds$S72827") == "S:_g_pizzaHitSounds"
    assert declared_symbol_kind("_g_pizzaHitSounds$S72830") == "S:_g_pizzaHitSounds"
    assert declared_symbol_kind("_g_copDonutSounds$S72830") == "S:_g_copDonutSounds"
    assert local_symbol_kind("_g_pizzaHitSounds$S72827") is None
    assert declared_symbol_kind("?Timer@@YAPAVMxTimer@@XZ") is None
    assert declared_symbol_kind("$S1") is None
    assert declared_symbol_kind("x$Sabc") is None
