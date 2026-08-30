from __future__ import annotations

import pytest

import reprobit.classic.compiler_state_projection as state_projection
from reprobit.classic.commutative import derive_commutative_operand_forms
from reprobit.classic.compiler_state_foundation import CompilerStateCodePair
from reprobit.classic.semantic_errors import ClassicSemanticError

_VECTOR4_CLEAN = bytes.fromhex(
    "8b5424085356578b7a048b742410d947048b4604d84804d94708d84808dec1d900d80f"
    "8b5904dec1d9470cd8480cdee1d95b0c8b7a048b5e048b4104d94304d84f08d94704"
    "d84b08dee9d918d907d84b08d903d84f088b4104dee9d95804d903d84f04d907d84b"
    "048b4104dee9d958088b59048b7a048b4604d9470cd808d9400cd80fdec1d803d91b"
    "8b79048b460483c7048b5a04d94004d84b0cd94304d8480cdec1d807d91f8b790483"
    "c7088b4e048b4204d94108d8480cd94008d8490c33c0dec1d807d91f5f5e5bc20800"
)
_VECTOR4_EFFECTIVE = bytes.fromhex(
    "8b5424085356578b7a048b742410d947048b4604d84804d94708d84808dec1d900d80f"
    "8b5904dec1d9470cd8480cdee1d95b0c8b7a048b5e048b4104d94304d84f08d94704"
    "d84b08dee9d918d94308d80fd94708d80b8b4104dee9d95804d94704d80bd94304d8"
    "0f8b4104dee9d958088b59048b7a048b4604d9470cd808d9400cd80fdec1d803d91b"
    "8b79048b460483c7048b5a04d94004d84b0cd94304d8480cdec1d807d91f8b790483"
    "c7088b4e048b4204d94108d8480cd94008d8490c33c0dec1d807d91f5f5e5bc20800"
)
_PARTIAL_VECTOR4 = _VECTOR4_EFFECTIVE[:81] + _VECTOR4_CLEAN[81:]
_PARTIAL_WITH_RESIDUAL = _PARTIAL_VECTOR4[:3] + b"\x0c" + _PARTIAL_VECTOR4[4:]
_FULL_WITH_RESIDUAL = _VECTOR4_EFFECTIVE[:3] + b"\x0c" + _VECTOR4_EFFECTIVE[4:]


def _pair(clean: bytes, effective: bytes) -> CompilerStateCodePair:
    return CompilerStateCodePair(
        owner="?EqualsHamiltonProduct@Vector4@@UAEHABV1@0@Z",
        clean_section_number=290,
        effective_section_number=290,
        topology_digest="d" * 64,
        clean_body=clean,
        effective_body=effective,
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
    )


def test_real_vector4_pair_derives_all_four_exchanges() -> None:
    derived = derive_commutative_operand_forms(
        _VECTOR4_CLEAN,
        _VECTOR4_EFFECTIVE,
        {},
        frozenset(),
        "Vector4 fixture",
    )

    assert derived is not None
    image, sites, proof = derived
    assert image == _VECTOR4_EFFECTIVE
    assert [site["pair_offset"] for site in sites] == [76, 81, 94, 99]
    assert proof["kind"] == "commutative_operand_form_interior_boundary_reseat_v1"
    assert proof["interior_boundary_moves"] == [
        {
            "pair_offset": pair_offset,
            "seed_operator_offset": seed,
            "image_operator_offset": image,
        }
        for pair_offset, seed, image in (
            (76, 78, 79),
            (81, 83, 84),
            (94, 96, 97),
            (99, 101, 102),
        )
    ]


def test_real_vector4_pair_dispatches_before_the_web() -> None:
    proof = state_projection._prove_pair(_pair(_VECTOR4_CLEAN, _VECTOR4_EFFECTIVE), None)

    assert [step["kind"] for step in proof["steps"]] == ["derived-x87-commutative-operand-form-v1"]
    step = proof["steps"][0]
    assert step["debug_authority"] == "effective-compiler-product"
    assert len(step["declaration"]) == 4
    assert len(step["proof"]["interior_boundary_moves"]) == 4


@pytest.mark.parametrize(
    "target",
    [
        # Only the first exchange matches, and an unrelated byte also changed.
        _PARTIAL_WITH_RESIDUAL,
        # All four exchanges match, but an unrelated byte also changed.
        _FULL_WITH_RESIDUAL,
    ],
)
def test_derivation_refuses_partial_or_unrelated_target_images(target: bytes) -> None:
    assert (
        derive_commutative_operand_forms(
            _VECTOR4_CLEAN,
            target,
            {},
            frozenset(),
            "Vector4 fixture",
        )
        is None
    )


def test_derivation_refuses_unequal_target_length() -> None:
    assert (
        derive_commutative_operand_forms(
            _VECTOR4_CLEAN,
            _VECTOR4_EFFECTIVE + b"\x90",
            {},
            frozenset(),
            "Vector4 fixture",
        )
        is None
    )


def test_partial_image_reaches_the_existing_web_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached_web = False

    def refuse_web(*_args: object, **_kwargs: object) -> None:
        nonlocal reached_web
        reached_web = True
        raise ClassicSemanticError("web fallback reached")

    monkeypatch.setattr(state_projection, "_prove_register_web_recolour", refuse_web)

    with pytest.raises(ClassicSemanticError, match="web fallback reached"):
        state_projection._prove_pair(_pair(_VECTOR4_CLEAN, _FULL_WITH_RESIDUAL), None)
    assert reached_web
