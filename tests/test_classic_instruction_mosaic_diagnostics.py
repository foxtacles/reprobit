from __future__ import annotations

import copy

import pytest
from test_classic_instruction_schedule_full import (
    IMAGE,
    TARGET_SYMBOL,
    function_record,
    make_coff,
)

import reprobit.classic.composition as composition
import reprobit.coff_format as coff_format
from reprobit.binary import ByteIdentityError


def _actual_metadata_sha256(payload: bytes) -> str:
    coff = coff_format.CoffObject(payload)
    return composition.instruction_mosaic_metadata_sha256(
        coff,
        coff.function_section(TARGET_SYMBOL),
    )


def _mosaic_record(seed: bytes, donor: bytes) -> dict:
    record = function_record(seed, donor, IMAGE)
    record["splice_class"] = "retail_exact_instruction_mosaic"
    record["expected_line_count"] = record["expected_seed_line_count"]
    record["instruction_ranges"] = [
        {
            "kind": "same_offset_complete_x86_instruction_v1",
            "start": 0,
            "end": 1,
            "seed_sha256": "0" * 64,
            "donor_sha256": "1" * 64,
        }
    ]
    return record


def test_variant_wrapper_reports_expected_and_actual_seed_metadata_sha256() -> None:
    seed = make_coff()
    donor = make_coff()
    record = function_record(seed, donor, IMAGE)
    record["donor_variants"] = [{"donor": "d_variant"}]
    expected = "0" * 64
    actual = _actual_metadata_sha256(seed)
    record["expected_seed_metadata_sha256"] = expected

    with pytest.raises(ByteIdentityError) as caught:
        composition.produce_instruction_mosaic_candidate(
            seed,
            donor,
            record,
            primary_donor_id="d_primary",
        )

    assert str(caught.value) == (
        "instruction-mosaic seed metadata SHA-256 pin mismatch: "
        f"expected {expected}, actual {actual}"
    )


@pytest.mark.parametrize("role", ("seed", "donor"))
def test_core_reports_expected_and_actual_metadata_sha256(role: str) -> None:
    seed = make_coff()
    donor = make_coff()
    record = _mosaic_record(seed, donor)
    expected = "f" * 64
    actual = _actual_metadata_sha256(seed if role == "seed" else donor)
    if role == "seed":
        record["expected_seed_metadata_sha256"] = expected
    else:
        record["expected_seed_metadata_sha256"] = _actual_metadata_sha256(seed)
        record["expected_donor_metadata_sha256"] = expected

    with pytest.raises(ByteIdentityError) as caught:
        composition._produce_instruction_mosaic_candidate_core(
            seed,
            donor,
            copy.deepcopy(record),
            source_permutation=True,
            primary_donor_id="d_primary",
        )

    assert str(caught.value) == (
        f"instruction-mosaic {role} metadata SHA-256 pin mismatch: "
        f"expected {expected}, actual {actual}"
    )
