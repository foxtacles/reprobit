from __future__ import annotations

import pytest

from reprobit.classic.compiler_state_foundation import CompilerStateCodePair
from reprobit.classic.compiler_state_projection import _prove_pair
from reprobit.classic.semantic_errors import ClassicSemanticError

_LIST_INSERT_CLEAN = bytes.fromhex(
    "5356578bf18b7c24146a148b5f04e80000000083c40485db74078938895804eb05"
    "89008940048947048d78088b480485ff890174148b5424188b0a890f8b5a04895f"
    "048b52088957088b4c2410ff46085f5e5b89018bc1c20c00"
)
_LIST_INSERT_EFFECTIVE = bytes.fromhex(
    "5356578bf18b5c24146a148b7b04e80000000083c40485ff74078918897804eb05"
    "89008940048d78088943048b480485ff890174148b5424188b0a890f8b5a04895f"
    "048b52088957088b4c2410ff46085f5e5b89018bc1c20c00"
)


def _allocation_relocation() -> dict[str, object]:
    return {
        "type": 20,
        "target": {
            "kind": "undefined",
            "name": "??2@YAPAXI@Z",
            "value": 0,
            "type": 32,
            "storage": 2,
        },
        "addend": "00000000",
        "offset": 15,
    }


def _pair(clean: bytes = _LIST_INSERT_CLEAN) -> CompilerStateCodePair:
    relocation = _allocation_relocation()
    return CompilerStateCodePair(
        owner=(
            "?insert@?$list@USampleNode@@"
            "V?$allocator@USampleNode@@@@@@"
            "QAE?AViterator@1@V21@ABUSampleNode@@@Z"
        ),
        clean_section_number=8,
        effective_section_number=8,
        topology_digest="d" * 64,
        clean_body=clean,
        effective_body=_LIST_INSERT_EFFECTIVE,
        clean_relocations=(relocation,),
        effective_relocations=(relocation,),
        eh_control_digest=None,
    )


def test_real_list_insert_composes_existing_bijection_then_schedule() -> None:
    proof = _prove_pair(_pair(), None)

    assert proof["clean_body_digest"] == (
        "e4f14699e047bf9df96fca9bfc62dccd2395e66fbecb756d9223dd313047a30d"
    )
    assert proof["effective_body_digest"] == (
        "364f4539a4b4746a4022cfa748dddd7df34bf40e45f5e2d42737e8c88bd4f692"
    )
    assert proof["moved_relocations"] == []
    assert [step["kind"] for step in proof["steps"]] == [
        "dead-boundary-register-bijection-v1",
        "dependence-dag-schedule-v1",
    ]
    bijection, schedule = proof["steps"]
    assert bijection["mapping"] == {"ebx": "edi", "edi": "ebx"}
    assert bijection["region"] == {"start": 5, "end": 41}
    assert schedule["windows"][0]["start"] == 38
    assert schedule["windows"][0]["end"] == 44
    assert schedule["windows"][0]["target_order"] == [1, 0]
    assert schedule["windows"][0]["dependence_edges"] == []


def test_schedule_derived_bijection_boundary_is_not_a_pattern_override() -> None:
    mutated = bytearray(_LIST_INSERT_CLEAN)
    mutated[6] = 0x74  # mov esi,[esp+0x14], outside the proved EBX/EDI cycle

    with pytest.raises(ClassicSemanticError, match="dependence DAG"):
        _prove_pair(_pair(bytes(mutated)), None)


def test_ordinary_schedule_failure_is_not_misreported_as_missing_gx() -> None:
    pair = CompilerStateCodePair(
        owner="unsafe_ordinary_schedule",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest="d" * 64,
        clean_body=bytes.fromhex("8947048d7808c3"),
        effective_body=bytes.fromhex("8d7808894704c3"),
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
    )

    with pytest.raises(
        ClassicSemanticError,
        match=r"ordinary schedule.*dependence DAG",
    ) as raised:
        _prove_pair(pair, None)
    assert "/GX" not in str(raised.value)


def test_ordinary_push_schedule_failure_is_not_misreported_as_eh() -> None:
    pair = CompilerStateCodePair(
        owner="unsafe_ordinary_push_schedule",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest="d" * 64,
        clean_body=bytes.fromhex("528b45ecc3"),
        effective_body=bytes.fromhex("8b45ec52c3"),
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
    )

    with pytest.raises(
        ClassicSemanticError,
        match=r"ordinary schedule.*dependence DAG",
    ) as raised:
        _prove_pair(pair, None)
    message = str(raised.value)
    assert "/GX" not in message
    assert "EH" not in message
    assert "frame schedule" not in message
