from __future__ import annotations

from hashlib import sha256

import pytest

import reprobit.classic.composition_same_slot as composition_same_slot
import reprobit.classic.source_proofs as source_proof_algorithms
from reprobit.binary import ByteIdentityError


def _range_pin(data: bytes) -> dict[str, object]:
    return {
        "baseline_sha256": sha256(data).hexdigest(),
        "baseline_size": len(data),
        "baseline_line_count": data.count(b"\n"),
        "baseline_significant_token_sha256": (
            source_proof_algorithms.source_overlay_significant_sha256(data)
        ),
    }


def test_target_source_range_identity_accepts_outside_only_change() -> None:
    selected = b"// target-start\nint target() { return 7; }\n"
    proof = {
        "start_marker": "// target-start",
        "end_marker": "// target-end",
        "range_pin": _range_pin(selected),
    }
    seed = b"int before = 1;\n" + selected + b"// target-end\nint after = 1;\n"
    donor = b"int before = 2;\n" + selected + b"// target-end\nint after = 3;\n"

    detail = source_proof_algorithms.require_target_source_range_identity(
        seed,
        donor,
        proof,
        "target closure",
    )

    assert detail == {
        "target_source_size": len(selected),
        "target_source_sha256": sha256(selected).hexdigest(),
    }


def test_target_source_range_identity_rejects_target_change() -> None:
    selected = b"// target-start\nint target() { return 7; }\n"
    proof = {
        "start_marker": "// target-start",
        "end_marker": "// target-end",
        "range_pin": _range_pin(selected),
    }
    seed = selected + b"// target-end\n"
    donor = selected.replace(b"return 7", b"return 8") + b"// target-end\n"

    with pytest.raises(
        ByteIdentityError,
        match="changes the target source",
    ):
        source_proof_algorithms.require_target_source_range_identity(
            seed,
            donor,
            proof,
            "target closure",
        )


def test_source_target_closure_has_oracle_free_public_producer() -> None:
    assert callable(composition_same_slot.produce_source_target_closure_candidate)
    assert not hasattr(
        composition_same_slot,
        "compose_retail_exact_source_target_closure",
    )
