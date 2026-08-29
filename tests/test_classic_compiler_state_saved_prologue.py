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
    _ImageState,
    _instructions,
    _relocation_parts,
)
from reprobit.classic.compiler_state_projection import _prove_pair
from reprobit.classic.compiler_state_prologue import (
    _try_saved_prologue_web_permutation,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.schema import LockedTool, MsvcRelease, ToolchainLock, ToolchainProfileSource

_OWNER = "?ProcessOne@Demo@@QAEJPAVRouteController@@AAVPoint3@@11@Z"

_CLEAN = bytes.fromhex(
    "83ec0c894c2400538b5c2418568b742418575533ff8da97c21000083ff140f8dd6000000"
    "f68554010000040f85bd0000008b4c241057c744241c000000006a00518bcde800000000"
    "8b44242c8b4c24285051538bcde80000000085c00f85a70000008b859c0100008d4c2418"
    "8d9560010000894424148d44241450518b44243052508bce53e80000000085c08b442414"
    "50754f8b4c241c51568bcde80000000085c0754a8d047f8b4c24108d0487c1e0058dbc08"
    "7c2100008bce57e8000000008b4c241857e80000000068000020418b1f8bcfff533033c0"
    "5d5f5e5b83c40cc21000568bcde80000000085c0742a81c5a001000047e921ffffffb8ff"
    "ffffff5d5f5e5b83c40cc21000b8ffffffff5d5f5e5b83c40cc210008d047f8b4c24108d"
    "0487c1e0058dbc087c2100008bce57e80000000068000020418b1f8bcfff533033c05d5f"
    "5e5b83c40cc21000"
)

_EFFECTIVE = bytes.fromhex(
    "83ec0c894c240053568d997c2100008b742418575533ff8b6c242483ff140f8dd6000000"
    "f68354010000040f85bd0000008b4c241057c744241c000000006a00518bcbe800000000"
    "8b44242c8b4c24285051558bcbe80000000085c00f85a70000008b839c0100008d4c2418"
    "8d9360010000894424148d44241450518b44243052508bce55e80000000085c08b442414"
    "50754f8b4c241c51568bcbe80000000085c0754a8d047f8b4c24108d0487c1e0058dbc08"
    "7c2100008bce57e8000000008b4c241857e80000000068000020418b1f8bcfff533033c0"
    "5d5f5e5b83c40cc21000568bcbe80000000085c0742a81c3a001000047e921ffffffb8ff"
    "ffffff5d5f5e5b83c40cc21000b8ffffffff5d5f5e5b83c40cc210008d047f8b4c24108d"
    "0487c1e0058dbc087c2100008bce57e80000000068000020418b1f8bcfff533033c05d5f"
    "5e5b83c40cc21000"
)

_CLEAN_FPO = bytes.fromhex("000000004c0100000300000004001514")
_EFFECTIVE_FPO = bytes.fromhex("000000004c0100000300000004001714")
_CLEAN_DEBUG = bytes.fromhex(
    "340005020000000000000000000000004c0100001500000043010000000000000000e82a"
    "001044656d6f3a3a50726f636573734f6e650d000002f4ffffffb91b047468697315000002"
    "04000000c0160c705f636f6e74726f6c6c6572130000020800000037160a705f6c6f6361"
    "74696f6e140000020c00000037160b705f646972656374696f6e0d000002100000003716"
    "04705f75701000020074001800096e657874446f6e757416000002f8ffffff40000d617065"
    "78506172616d6574657211000002fcffffffbe1608626f756e6461727902000600"
)
_EFFECTIVE_DEBUG = _CLEAN_DEBUG[:20] + b"\x17" + _CLEAN_DEBUG[21:]

_RELOCATION_ROWS = (
    (68, "?Create@SampleAmmo@@QAEJPAVSampleWorld@@IH@Z"),
    (86, "?CalculateArc@SampleAmmo@@QAEJABVPoint3@@00@Z"),
    (
        134,
        "?FindIntersectionBoundary@RouteController@@QAEJAAVPoint3@@0PAVPointFloat@@"
        "AAPAVRouteBoundary@@AAM@Z",
    ),
    (156, "?Shoot@SampleAmmo@@QAEJPAVRouteController@@PAVRouteBoundary@@M@Z"),
    (188, "?PlaceActor@RouteController@@QAEJPAVRouteActor@@@Z"),
    (198, "?AddActor@RouteBoundary@@QAEJPAVRouteActor@@@Z"),
    (230, "?Shoot@SampleAmmo@@QAEJPAVRouteController@@M@Z"),
    (304, "?PlaceActor@RouteController@@QAEJPAVRouteActor@@@Z"),
)
_RELOCATIONS = tuple(
    {
        "type": 20,
        "target": {
            "kind": "undefined",
            "name": target,
            "value": 0,
            "type": 32,
            "storage": 2,
        },
        "addend": "00000000",
        "offset": offset,
    }
    for offset, target in _RELOCATION_ROWS
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
        clean_section_number=7,
        effective_section_number=7,
        topology_digest="c" * 64,
        clean_body=_CLEAN,
        effective_body=_EFFECTIVE,
        clean_relocations=_RELOCATIONS,
        effective_relocations=_RELOCATIONS,
        eh_control_digest=None,
        fpo_evidence=CompilerStateFpoEvidence("a" * 64, _CLEAN_FPO, _EFFECTIVE_FPO),
        debug_evidence=CompilerStateDebugEvidence("b" * 64, _CLEAN_DEBUG, _EFFECTIVE_DEBUG),
    )


def _prove(pair: CompilerStateCodePair) -> dict[str, object]:
    return _prove_pair(pair, None, _compiler_identity())


def _try_direct(pair: CompilerStateCodePair) -> tuple[_ImageState, dict[str, object]] | None:
    clean_offsets, clean_records = _relocation_parts(
        pair.clean_relocations, "saved-prologue direct clean fixture"
    )
    _effective_offsets, effective_records = _relocation_parts(
        pair.effective_relocations, "saved-prologue direct effective fixture"
    )
    return _try_saved_prologue_web_permutation(
        _ImageState(pair.clean_body, clean_offsets),
        pair,
        _instructions(pair.clean_body, clean_records, "saved-prologue direct clean"),
        _instructions(
            pair.effective_body,
            effective_records,
            "saved-prologue direct effective",
        ),
        clean_records,
        effective_records,
        _compiler_identity(),
    )


def _replace_byte(body: bytes, offset: int, value: int) -> bytes:
    return body[:offset] + bytes([value]) + body[offset + 1 :]


def test_saved_prologue_web_permutation_rejoins_exact_compiler_product() -> None:
    proof = _prove(_pair())

    assert proof["clean_body_digest"] == (
        "8d986d64c7f99e7534d9ed1188d4b5d5333b3408cd917df5160e91230878e952"
    )
    assert proof["effective_body_digest"] == (
        "c4e1c0a387ec2bda1b19d585e061c86ba072398a99cdf354fc0ca4e6a1610282"
    )
    assert proof["body_size"] == 332
    assert proof["relocation_count"] == 8
    assert proof["moved_relocations"] == []
    assert len(proof["steps"]) == 1
    step = proof["steps"][0]
    assert step["kind"] == "msvc-4.20-saved-prologue-web-permutation-v1"
    assert step["window"]["start"] == 7
    assert step["window"]["end"] == 27
    assert step["window"]["target_order"] == [0, 2, 7, 3, 4, 5, 6, 1]
    assert step["window"]["cycle"] == {"ebp": "ebx", "ebx": "ebp"}
    assert step["window"]["stack_adjustments"] == [[1, 11, 24, 36]]
    assert step["window"]["discharged_dependence_edges"] == [
        {
            "source_pair": [5, 7],
            "reason": "saved-register-war-after-web-image",
            "source_register": "ebp",
            "image_register": "ebx",
            "image_save_source_instruction": 0,
        }
    ]
    assert step["paired_metadata"]["codeview"]["debug_start_map"] == [21, 23]
    assert step["rewritten_field_count"] == 12
    assert step["call_observation_count"] == 10
    assert step["reaching_definition_observation_count"] == 93
    assert len(step["epilogues"]) == 4


@pytest.mark.parametrize("missing", ["fpo", "debug"])
def test_saved_prologue_requires_both_paired_children(missing: str) -> None:
    pair = _pair()
    pair = replace(
        pair,
        fpo_evidence=None if missing == "fpo" else pair.fpo_evidence,
        debug_evidence=None if missing == "debug" else pair.debug_evidence,
    )
    with pytest.raises(ClassicSemanticError):
        _prove(pair)


@pytest.mark.parametrize(
    "effective_fpo",
    [
        _replace_byte(_EFFECTIVE_FPO, 8, 4),
        _replace_byte(_EFFECTIVE_FPO, 12, 3),
        _replace_byte(_EFFECTIVE_FPO, 14, 22),
        _replace_byte(_EFFECTIVE_FPO, 15, 0x1C),
        _replace_byte(_EFFECTIVE_FPO, 15, 0x54),
    ],
)
def test_saved_prologue_rejects_unrelated_or_invalid_fpo_changes(
    effective_fpo: bytes,
) -> None:
    pair = _pair()
    assert pair.fpo_evidence is not None
    evidence = replace(pair.fpo_evidence, effective_body=effective_fpo)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(pair, fpo_evidence=evidence))


@pytest.mark.parametrize(
    "effective_fpo",
    [
        _replace_byte(_EFFECTIVE_FPO, 8, 4),
        _replace_byte(_EFFECTIVE_FPO, 14, 22),
        _replace_byte(_EFFECTIVE_FPO, 15, 0x1C),
    ],
)
def test_selected_saved_prologue_never_downgrades_fpo_failure_to_fallthrough(
    effective_fpo: bytes,
) -> None:
    pair = _pair()
    assert pair.fpo_evidence is not None
    evidence = replace(pair.fpo_evidence, effective_body=effective_fpo)

    with pytest.raises(ClassicSemanticError):
        _try_direct(replace(pair, fpo_evidence=evidence))


@pytest.mark.parametrize(
    "effective_debug",
    [
        _replace_byte(_EFFECTIVE_DEBUG, 24, 0x42),
        _replace_byte(_EFFECTIVE_DEBUG, 20, 22),
        _replace_byte(_EFFECTIVE_DEBUG, 64, 25),
        _EFFECTIVE_DEBUG[:-4],
    ],
)
def test_saved_prologue_rejects_unrelated_or_invalid_codeview_changes(
    effective_debug: bytes,
) -> None:
    pair = _pair()
    assert pair.debug_evidence is not None
    evidence = replace(pair.debug_evidence, effective_body=effective_debug)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(pair, debug_evidence=evidence))


def test_saved_prologue_rejects_swapped_compiler_boundaries() -> None:
    pair = _pair()
    assert pair.fpo_evidence is not None and pair.debug_evidence is not None
    fpo = replace(
        pair.fpo_evidence,
        clean_body=_EFFECTIVE_FPO,
        effective_body=_CLEAN_FPO,
    )
    debug = replace(
        pair.debug_evidence,
        clean_body=_EFFECTIVE_DEBUG,
        effective_body=_CLEAN_DEBUG,
    )
    with pytest.raises(ClassicSemanticError):
        _prove(replace(pair, fpo_evidence=fpo, debug_evidence=debug))


def test_saved_prologue_requires_the_matching_thiscall_owner() -> None:
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), owner=_OWNER.replace("?ProcessOne", "?Other")))


def test_saved_prologue_rejects_wrong_stack_rebase() -> None:
    effective = _replace_byte(_EFFECTIVE, 26, 32)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), effective_body=effective))


def test_saved_prologue_rejects_schedule_without_its_atomic_web_cycle() -> None:
    scheduled_window = bytes.fromhex("53568da97c2100008b742418575533ff8b5c2424")
    effective = _CLEAN[:7] + scheduled_window + _CLEAN[27:]
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), effective_body=effective))


def test_saved_prologue_rejects_a_changed_physical_restore() -> None:
    effective = _replace_byte(_EFFECTIVE, 322, 0x5B)
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), effective_body=effective))


def test_saved_prologue_rejects_an_incomplete_downstream_web() -> None:
    effective = _replace_byte(_EFFECTIVE, 37, _CLEAN[37])
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), effective_body=effective))


def test_saved_prologue_rejects_relocation_or_entry_changes() -> None:
    relocation = dict(_RELOCATIONS[0])
    relocation["offset"] = 69
    with pytest.raises(ClassicSemanticError):
        _prove(
            replace(
                _pair(),
                effective_relocations=(relocation, *_RELOCATIONS[1:]),
            )
        )
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), external_entries=(8,)))


def test_saved_prologue_rejects_eh_or_missing_compiler_authority() -> None:
    with pytest.raises(ClassicSemanticError):
        _prove(replace(_pair(), eh_control_digest="d" * 64))
    with pytest.raises(ClassicSemanticError):
        _prove_pair(_pair(), None, None)


def test_unrelated_fpo_boundary_delta_falls_through_to_relational_proof() -> None:
    clean = bytes.fromhex("3b7c24047501c3c3")
    effective = bytes.fromhex("397c24047501c3c3")
    clean_fpo = bytes.fromhex("00000000080000000000000000000410")
    effective_fpo = bytes.fromhex("00000000080000000000000000000610")
    pair = CompilerStateCodePair(
        owner="fixture",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest="c" * 64,
        clean_body=clean,
        effective_body=effective,
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
        fpo_evidence=CompilerStateFpoEvidence(
            "d" * 64,
            clean_fpo,
            effective_fpo,
        ),
        debug_evidence=CompilerStateDebugEvidence("e" * 64, b"clean", b"effective"),
    )

    proof = _prove_pair(pair, None, _compiler_identity())

    assert [step["kind"] for step in proof["steps"]] == ["derived-equality-compare-reversal-v1"]
