from __future__ import annotations

from hashlib import sha256

import pytest

from reprobit import classic


def _range_pin(data: bytes) -> dict[str, object]:
    return {
        "baseline_sha256": sha256(data).hexdigest(),
        "baseline_size": len(data),
        "baseline_line_count": data.count(b"\n"),
        "baseline_significant_token_sha256": (
            classic.source_overlay_significant_sha256(data)
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

    detail = classic.require_target_source_range_identity(
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

    with pytest.raises(classic.ByteIdentityError, match="changes the target source"):
        classic.require_target_source_range_identity(
            seed,
            donor,
            proof,
            "target closure",
        )


def test_source_target_closure_has_oracle_free_public_producer() -> None:
    assert callable(classic.produce_source_target_closure_candidate)
    assert not hasattr(classic, "compose_retail_exact_source_target_closure")
