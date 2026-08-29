from __future__ import annotations

from dataclasses import replace

import pytest

from reprobit.classic.compiler_identity import (
    Msvc420CompilerIdentity,
    issue_msvc420_compiler_identity,
)
from reprobit.classic.compiler_state_foundation import (
    CompilerStateCodePair,
    CompilerStateDebugEvidence,
    CompilerStateFpoEvidence,
)
from reprobit.classic.compiler_state_projection import _prove_pair
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.schema import LockedTool, MsvcRelease, ToolchainLock, ToolchainProfileSource

_OWNER = "?Insert@Sample01@@QAEXHW4InsertMode@SampleNode@@@Z"
_INVOKE_ACTION = "?InvokeAction@@YAXW4ActionType@Extra@@ABVEventId@@HPAVSampleEntity@@@Z"

_CLEAN = bytes.fromhex(
    "83ec105356578bf183790c000f85af0100008b5c242483fb01741b83fb020f84e900000083fb03"
    "0f84540100005f5e5b83c410c20800837e0800746e8bcee8000000008b7c2420897c24106a14"
    "895c2418c644241c008b4604894424108d58048b3be80000000083c40485ff740b8b4c240c89"
    "08897804eb05890089400489038b4804890183c00874148d5424108b0a89088b5a048958048b"
    "52088950085fff46085e5b83c410c208008b7c24206a0057a100000000506a04e80000000089"
    "7c2420895c242483c410c6442418018b46048d78048b0f51508bcee8000000008bd089078b4a"
    "04891183c20874148d4c24108b0189028b5904895a048b4908894a085fff46085e5b83c410c2"
    "0800837e08008b7c2420753f8d4c2410897c24108d54240c518bce895c2418c644241c018b46"
    "045052e8000000006a008b0d0000000057516a04e80000000083c4105f5e5b83c410c2080089"
    "7c24108d7c24108d4c240c57895c2418c644241c008b460450518bcee8000000005f5e5b83c4"
    "10c20800837e0800753a8b7c24208d4c24108d54240c518bce897c2414895c2418c644241c01"
    "8b46045052e8000000006a008b0d0000000057516a04e80000000083c4105f5e5b83c410c208"
    "00"
)

_EFFECTIVE = bytes.fromhex(
    "83ec105356578bf183790c000f85af0100008b5c242483fb01741b83fb020f84e900000083fb03"
    "0f84540100005f5e5b83c410c20800837e0800746e8bcee8000000008b7c24208b4604897c24"
    "106a14895c2418894424108d5804c644241c008b3be80000000083c40485ff740b8b4c240c89"
    "08897804eb05890089400489038b4804890183c00874148d5424108b0a89088b5a048958048b"
    "52088950085fff46085e5b83c410c208008b7c24206a0057a100000000506a04e80000000089"
    "7c242083c4108b4604895c24148d7804c6442418018b0f51508bcee8000000008bd089078b4a"
    "04891183c20874148d4c24108b0189028b5904895a048b4908894a085fff46085e5b83c410c2"
    "0800837e08008b7c2420753f8d4c2410897c24108d54240c518bce895c2418c644241c018b46"
    "045052e8000000006a008b0d0000000057516a04e80000000083c4105f5e5b83c410c2080089"
    "7c24108d7c24108d4c240c57895c2418c644241c008b460450518bcee8000000005f5e5b83c4"
    "10c20800837e0800753a8b7c24208d4c24108d54240c518bce897c2414895c2418c644241c01"
    "8b46045052e8000000006a008b0d0000000057516a04e80000000083c4105f5e5b83c410c208"
    "00"
)

_FPO = bytes.fromhex("00000000ca0100000400000002000803")
_DEBUG_S = bytes.fromhex(
    "34000502000000000000000000000000ca01000008000000c1010000000000000000ad2a0010"
    "53616d706c6530313a3a496e736572740b000200f71a1700047468697313000002040000007400"
    "0a705f6f626a65637449641100000208000000eb1a08705f6f7074696f6e02000600"
)

_FPO_RECEIPT = "6738c6ae60b429bea7852712509cbaad574a222aefed7b828153c2c99922ba84"
_DEBUG_RECEIPT = "a97d2e707dc8f9cdbeadf101e3d7c10e72fda8dbdb5382de8861f4a78b254f9b"

_RELOCATION_ROWS = (
    (63, 20, "?DeleteActionWrapper@Sample01@@QAEXXZ"),
    (99, 20, "??2@YAPAXI@Z"),
    (178, 6, "?g_sampleScript@@3PAVEventId@@A"),
    (186, 20, _INVOKE_ACTION),
    (
        219,
        20,
        "?_Buynode@?$list@USampleNode@@V?$allocator@USampleNode@@@@@@"
        "IAEPAU_Node@1@PAU21@0@Z",
    ),
    (
        309,
        20,
        "?insert@?$list@USampleNode@@V?$allocator@USampleNode@@@@@@"
        "QAE?AViterator@1@V21@ABUSampleNode@@@Z",
    ),
    (317, 6, "?g_sampleScript@@3PAVEventId@@A"),
    (326, 20, _INVOKE_ACTION),
    (
        372,
        20,
        "?insert@?$list@USampleNode@@V?$allocator@USampleNode@@@@@@"
        "QAE?AViterator@1@V21@ABUSampleNode@@@Z",
    ),
    (
        425,
        20,
        "?insert@?$list@USampleNode@@V?$allocator@USampleNode@@@@@@"
        "QAE?AViterator@1@V21@ABUSampleNode@@@Z",
    ),
    (433, 6, "?g_sampleScript@@3PAVEventId@@A"),
    (442, 20, _INVOKE_ACTION),
)

_RELOCATIONS = tuple(
    {
        "offset": offset,
        "type": relocation_type,
        "target": {"kind": "undefined", "name": target},
        "addend": "00000000",
    }
    for offset, relocation_type, target in _RELOCATION_ROWS
)


def _compiler_identity() -> Msvc420CompilerIdentity:
    tools = (
        (
            "bin/CL.EXE",
            37_888,
            "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
            ("compiler",),
        ),
        (
            "bin/C1XX.EXE",
            793_088,
            "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
            ("runtime",),
        ),
        (
            "bin/C2.EXE",
            549_888,
            "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
            ("runtime",),
        ),
    )
    identity = issue_msvc420_compiler_identity(
        ToolchainLock(
            schema_version=3,
            adapter="classic-msvc",
            profile="msvc_4_2",
            release=MsvcRelease.V4_2,
            profile_sources=(
                ToolchainProfileSource(
                    repository="https://github.com/archaic-msvc/msvc420.git",
                    revision="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
                    paths=("bin/C1XX.EXE", "bin/C2.EXE", "bin/CL.EXE"),
                ),
            ),
            tools=tuple(
                LockedTool(
                    id=f"compiler-{index}",
                    path=path,
                    size=size,
                    digest=Digest(value=digest),
                    roles=roles,
                )
                for index, (path, size, digest, roles) in enumerate(tools)
            ),
        )
    )
    assert identity is not None
    return identity


def _pair() -> CompilerStateCodePair:
    return CompilerStateCodePair(
        owner=_OWNER,
        clean_section_number=5,
        effective_section_number=5,
        topology_digest="f7e47ed72c5023aedc80b2fc648897ffd351ef451c02821391097c11345d2860",
        clean_body=_CLEAN,
        effective_body=_EFFECTIVE,
        clean_relocations=_RELOCATIONS,
        effective_relocations=_RELOCATIONS,
        eh_control_digest=None,
        fpo_evidence=CompilerStateFpoEvidence(_FPO_RECEIPT, _FPO, _FPO),
        debug_evidence=CompilerStateDebugEvidence(_DEBUG_RECEIPT, _DEBUG_S, _DEBUG_S),
    )


def _replace_byte(body: bytes, offset: int, value: int) -> bytes:
    return body[:offset] + bytes([value]) + body[offset + 1 :]


def _prove(pair: CompilerStateCodePair) -> dict[str, object]:
    return _prove_pair(pair, None, _compiler_identity())


def test_private_stack_object_pair_rejoins_exact_compiler_product() -> None:
    proof = _prove(_pair())

    assert proof["clean_body_digest"] == (
        "451d761e452ad16f3c97640839560f41a2c1833f51d9b251a222976635f917d6"
    )
    assert proof["effective_body_digest"] == (
        "bee3a326b0b276a4f6bfdf275a07ee71fc54ddd77c86e1f6447148e101067538"
    )
    assert proof["body_size"] == 458
    assert proof["relocation_count"] == 12
    assert proof["moved_relocations"] == []

    steps = proof["steps"]
    assert isinstance(steps, list)
    assert [step["kind"] for step in steps] == [
        "dependence-dag-schedule-v1",
        "dependence-dag-schedule-v1",
    ]
    first, second = (step["windows"][0] for step in steps)
    assert (first["start"], first["end"], first["target_order"]) == (
        71,
        96,
        [4, 0, 1, 2, 5, 6, 3],
    )
    assert (second["start"], second["end"], second["target_order"]) == (
        194,
        212,
        [1, 3, 0, 4, 2],
    )
    assert second["stack_adjustments"] == [[0, 197, 36, 20]]

    first_frontier = first["stack_frontier"]
    second_frontier = second["stack_frontier"]
    assert first_frontier["discharged_esp_dependencies"] == []
    assert second_frontier["discharged_esp_dependencies"] == [
        {
            "source_pair": [0, 1],
            "reason": "register_war",
            "stack_instruction": 1,
            "operand_instruction": 0,
            "stack_delta": 16,
            "adjustment": [0, 197, 36, 20],
        }
    ]
    assert [row["source_pair"] for row in first_frontier["discharged_memory_pairs"]] == [
        [0, 4],
        [1, 4],
        [2, 4],
        [3, 4],
    ]
    assert [row["source_pair"] for row in second_frontier["discharged_memory_pairs"]] == [
        [0, 3],
        [2, 3],
    ]

    first_boundary = first_frontier["boundary"]
    second_boundary = second_frontier["boundary"]
    assert first_boundary["frame_floor_from_entry_esp"] == -28
    assert first_boundary["window_entry_esp_from_entry"] == -28
    assert second_boundary["window_entry_esp_from_entry"] == -44
    assert second_boundary["window_exit_esp_from_entry"] == -28
    assert first_boundary["this_copy"] == {
        "kind": "paired-debug-entry-this-copy-v1",
        "entry_register": "ecx",
        "this_register": "esi",
        "definition_offset": 6,
        "encoding": "8bf1",
    }
    assert first_boundary["owner"]["calling_convention_encoding"] == "E"
    assert first_boundary["fpo_receipt_digest"] == _FPO_RECEIPT
    assert first_boundary["debug_receipt_digest"] == _DEBUG_RECEIPT

    first_separations = first_boundary["memory_separations"]
    assert [row["stack_kind"] for row in first_separations] == [
        "explicit-private-stack-cell",
        "implicit-push-seat",
        "explicit-private-stack-cell",
        "explicit-private-stack-cell",
    ]
    assert [row["source_span_from_entry_esp"] for row in first_separations] == [
        [-12, -8],
        [-32, -28],
        [-8, -4],
        [-4, -3],
    ]
    assert [row["target_span_from_entry_esp"] for row in first_separations] == [
        [-12, -8],
        [-32, -28],
        [-8, -4],
        [-4, -3],
    ]
    assert [row["source_span_from_entry_esp"] for row in second_boundary["memory_separations"]] == [
        [-8, -4],
        [-4, -3],
    ]
    assert second_boundary["call_balance"] == [
        {
            "offset": 185,
            "kind": "direct-cdecl-caller-clean",
            "pending_bytes": 16,
            "cleanup_bytes": 0,
            "cdecl_call": {
                "theorem": "msvc420-direct-cdecl-relocation-v1",
                "call_offset": 185,
                "relocation_offset": 186,
                "relocation_width": 4,
                "target": _INVOKE_ACTION,
                "spelling": "msvc-global-or-static-member",
            },
        }
    ]


@pytest.mark.parametrize("missing", ["fpo", "debug"])
def test_private_stack_object_pair_requires_both_paired_debug_children(missing: str) -> None:
    pair = _pair()
    pair = replace(
        pair,
        fpo_evidence=None if missing == "fpo" else pair.fpo_evidence,
        debug_evidence=None if missing == "debug" else pair.debug_evidence,
    )

    with pytest.raises(ClassicSemanticError):
        _prove(pair)


@pytest.mark.parametrize("changed", ["fpo", "debug"])
def test_private_stack_object_pair_requires_identical_paired_child_bodies(
    changed: str,
) -> None:
    pair = _pair()
    assert pair.fpo_evidence is not None and pair.debug_evidence is not None
    fpo = pair.fpo_evidence
    debug = pair.debug_evidence
    if changed == "fpo":
        fpo = replace(fpo, effective_body=_replace_byte(_FPO, 14, 9))
    else:
        debug = replace(debug, effective_body=_replace_byte(_DEBUG_S, 20, 9))
    with pytest.raises(ClassicSemanticError):
        _prove(replace(pair, fpo_evidence=fpo, debug_evidence=debug))


@pytest.mark.parametrize(
    ("fpo", "debug"),
    [
        (
            CompilerStateFpoEvidence("bad", _FPO, _FPO),
            CompilerStateDebugEvidence(_DEBUG_RECEIPT, _DEBUG_S, _DEBUG_S),
        ),
        (
            CompilerStateFpoEvidence(_FPO_RECEIPT, b"\0", b"\0"),
            CompilerStateDebugEvidence(_DEBUG_RECEIPT, _DEBUG_S, _DEBUG_S),
        ),
        (
            CompilerStateFpoEvidence(_FPO_RECEIPT, _FPO, _FPO),
            CompilerStateDebugEvidence("bad", _DEBUG_S, _DEBUG_S),
        ),
        (
            CompilerStateFpoEvidence(_FPO_RECEIPT, _FPO, _FPO),
            CompilerStateDebugEvidence(_DEBUG_RECEIPT, b"\0", b"\0"),
        ),
    ],
)
def test_private_stack_object_pair_rejects_malformed_evidence(
    fpo: CompilerStateFpoEvidence,
    debug: CompilerStateDebugEvidence,
) -> None:
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), fpo_evidence=fpo, debug_evidence=debug))


@pytest.mark.parametrize(
    "owner",
    [
        _OWNER.replace("@@QAE", "@@QAG"),
        _OWNER.replace("?Insert", "?Other"),
    ],
)
def test_private_stack_object_pair_requires_matching_thiscall_owner(owner: str) -> None:
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), owner=owner))


def test_private_stack_object_pair_requires_debug_this_in_prologue_esi() -> None:
    debug = _replace_byte(_DEBUG_S, 60, 24)  # CV register 24 is EDI, not ESI.
    with pytest.raises(ClassicSemanticError):
        _prove(
            replace(
                _pair(),
                debug_evidence=CompilerStateDebugEvidence(_DEBUG_RECEIPT, debug, debug),
            )
        )

    clean = _replace_byte(_CLEAN, 7, 0xF9)  # mov edi, ecx
    effective = _replace_byte(_EFFECTIVE, 7, 0xF9)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), clean_body=clean, effective_body=effective))


@pytest.mark.parametrize(
    "fpo",
    [
        _FPO[:8] + bytes.fromhex("03000000") + _FPO[12:],
        _FPO[:-1] + b"\x43",  # Non-FPO frame kind.
        _FPO[:-1] + b"\x0b",  # Structured-exception flag.
    ],
)
def test_private_stack_object_pair_requires_exact_non_eh_fpo_locals(fpo: bytes) -> None:
    evidence = CompilerStateFpoEvidence(_FPO_RECEIPT, fpo, fpo)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), fpo_evidence=evidence))


def test_private_stack_object_pair_rejects_unreviewed_push_encoding() -> None:
    clean = _replace_byte(_CLEAN, 75, 0x68)
    effective = _replace_byte(_EFFECTIVE, 78, 0x68)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), clean_body=clean, effective_body=effective))


def test_private_stack_object_pair_rejects_segment_overridden_object_address() -> None:
    # Keep the three-byte instruction grid while changing `mov eax,[esi+4]`
    # to `mov eax,fs:[esi]` on both sides of the schedule.
    clean = _CLEAN[:86] + bytes.fromhex("648b06") + _CLEAN[89:]
    effective = _EFFECTIVE[:71] + bytes.fromhex("648b06") + _EFFECTIVE[74:]
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), clean_body=clean, effective_body=effective))


@pytest.mark.parametrize(
    ("side", "offset", "value"),
    [
        ("clean", 197, 32),
        ("effective", 203, 24),
    ],
)
def test_private_stack_object_pair_requires_exact_displacement_rejoin(
    side: str,
    offset: int,
    value: int,
) -> None:
    changes = {
        "clean_body": _replace_byte(_CLEAN, offset, value)
        if side == "clean"
        else _CLEAN,
        "effective_body": _replace_byte(_EFFECTIVE, offset, value)
        if side == "effective"
        else _EFFECTIVE,
    }
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), **changes))
