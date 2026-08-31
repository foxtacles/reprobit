from __future__ import annotations

import pytest

from reprobit.binary import ByteIdentityError
from reprobit.classic.ia32 import require_declared_relocation_semantics


def _relocation(target: str = "$L75298") -> dict[str, int | str]:
    return {
        "offset": 12,
        "type": 6,
        "addend": 0,
        "target": target,
        "target_section": 392,
        "target_value": 345,
        "target_type": 0,
        "target_storage": 6,
        "retail_target": "0x10042c09",
    }


@pytest.mark.parametrize(
    ("compiled", "declared"),
    (
        ("$L75298", "$L75299"),
        ("$T75384", "$T75385"),
        ("$done$103", "$done$104"),
    ),
)
def test_declared_relocation_semantics_ignore_only_compiler_local_serials(
    compiled: str,
    declared: str,
) -> None:
    assert require_declared_relocation_semantics(
        [_relocation(compiled)],
        [_relocation(declared)],
        "candidate relocation semantics",
    ) == {
        "semantic_relocation_count": 1,
        "oracle_payload_bytes_read": 0,
    }


@pytest.mark.parametrize(
    ("compiled", "declared"),
    (
        ("$L75298", "$T75298"),
        ("$L75298", "named_symbol"),
        ("named_symbol", "$L75298"),
        ("first_symbol", "second_symbol"),
    ),
)
def test_declared_relocation_semantics_reject_different_symbol_kinds(
    compiled: str,
    declared: str,
) -> None:
    with pytest.raises(ByteIdentityError, match="declared COFF semantics"):
        require_declared_relocation_semantics(
            [_relocation(compiled)],
            [_relocation(declared)],
            "candidate relocation semantics",
        )


@pytest.mark.parametrize(
    ("field", "changed"),
    (
        ("offset", 16),
        ("type", 20),
        ("addend", 4),
        ("target_section", 393),
        ("target_value", 346),
        ("target_type", 32),
        ("target_storage", 3),
    ),
)
def test_declared_relocation_semantics_keep_every_semantic_field_pinned(
    field: str,
    changed: int,
) -> None:
    compiled = _relocation("$L75298")
    declared = _relocation("$L75299")
    compiled[field] = changed

    with pytest.raises(ByteIdentityError, match="declared COFF semantics"):
        require_declared_relocation_semantics(
            [compiled],
            [declared],
            "candidate relocation semantics",
        )
