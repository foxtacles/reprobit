from __future__ import annotations

import pytest

import reprobit.classic.compiler_state_projection as state_projection
from reprobit.classic.compiler_state_foundation import CompilerStateCodePair
from reprobit.classic.relational_projection import derive_equality_compare_reversals
from reprobit.classic.semantic_errors import ClassicSemanticError

_LIST_DTOR_CLEAN = bytes.fromhex(
    "83ec0c56578b41048bf1894424108b088bf93bc8742e8d5704897c24088bc78b3f8b0a8b008901"
    "8b0a8b442408508b10894a04e80000000083c404ff4e083b7c241075d28b460450e800000000c746"
    "040000000083c404c74608000000005f5e83c40cc3"
)
_LIST_DTOR_EFFECTIVE = bytes.fromhex(
    "83ec0c56578b41048bf1894424108b088bf93bc8742e8d5704897c24088bc78b3f8b0a8b008901"
    "8b0a8b442408508b10894a04e80000000083c404ff4e08397c241075d28b460450e800000000c746"
    "040000000083c404c74608000000005f5e83c40cc3"
)


def _delete_relocation(offset: int) -> dict[str, object]:
    return {
        "type": 0x14,
        "target": {
            "kind": "undefined",
            "name": "??3@YAXPAX@Z",
            "value": 0,
            "type": 0x20,
            "storage": 2,
        },
        "addend": "00000000",
        "offset": offset,
    }


def _pair(
    clean: bytes,
    effective: bytes,
    *,
    relocations: tuple[dict[str, object], ...] = (),
) -> CompilerStateCodePair:
    return CompilerStateCodePair(
        owner="toy",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest="3" * 64,
        clean_body=clean,
        effective_body=effective,
        clean_relocations=relocations,
        effective_relocations=relocations,
        eh_control_digest=None,
    )


def test_real_memory_compare_reversal_dispatches_before_web() -> None:
    relocations = (_delete_relocation(52), _delete_relocation(73))
    pair = _pair(
        _LIST_DTOR_CLEAN,
        _LIST_DTOR_EFFECTIVE,
        relocations=relocations,
    )

    proof = state_projection._prove_pair(pair, None)

    assert [step["kind"] for step in proof["steps"]] == ["derived-equality-compare-reversal-v1"]
    step = proof["steps"][0]
    assert step["declaration"] == [
        {
            "compare_offset": 62,
            "branch_offset": 66,
            "seed_condition": "ne",
            "image_condition": "ne",
        }
    ]
    assert step["proof"]["preserved_flags"] == ["zf"]
    assert step["proof"]["changed_flags"] == ["af", "cf", "of", "pf", "sf"]


@pytest.mark.parametrize(
    ("source", "target"),
    [
        # Signed-less consumes flags that operand reversal does not preserve.
        ("3b7c24047c01c3c3", "397c24047c01c3c3"),
        # The conditional branch itself changed.
        ("3b7c24047501c3c3", "397c24047401c3c3"),
        # The branch no longer immediately follows the compare.
        ("3b7c2404907501c3c3", "397c2404907501c3c3"),
        # The fallthrough reads CF after the comparison.
        ("3b7c2404750213c0c3", "397c2404750213c0c3"),
        # A computed transfer prevents a complete target census.
        ("3b7c24047502ffe0c3", "397c24047502ffe0c3"),
    ],
)
def test_derived_equality_compare_reversal_refuses_unsafe_shapes(
    source: str,
    target: str,
) -> None:
    assert (
        derive_equality_compare_reversals(
            bytes.fromhex(source),
            bytes.fromhex(target),
            {},
            frozenset(),
            "fixture",
        )
        is None
    )


def test_derived_equality_compare_reversal_refuses_relocation_overlap() -> None:
    assert (
        derive_equality_compare_reversals(
            bytes.fromhex("3b7c24047501c3c3"),
            bytes.fromhex("397c24047501c3c3"),
            {0: {"width": 1, "target": None}},
            frozenset(),
            "fixture",
        )
        is None
    )


def test_compiler_state_refuses_partial_relational_image_and_reaches_web(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _pair(
        bytes.fromhex("3b7c24047501c3c3"),
        bytes.fromhex("397c2404750190c3"),
    )
    reached_web = False

    def refuse_web(*_args: object, **_kwargs: object) -> None:
        nonlocal reached_web
        reached_web = True
        raise ClassicSemanticError("web fallback reached")

    monkeypatch.setattr(state_projection, "_prove_register_web_recolour", refuse_web)

    with pytest.raises(ClassicSemanticError, match="web fallback reached"):
        state_projection._prove_pair(pair, None)
    assert reached_web
