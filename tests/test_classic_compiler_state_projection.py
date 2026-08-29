from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import replace

import pytest

import reprobit.classic.compiler_state_projection as state_projection
from reprobit.classic.coff_evidence import (
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
)
from reprobit.classic.coff_projection import (
    _CodeProjectionCertificate,
    _coff_compiler_congruence_trace,
    _coff_semantic_envelope,
    _compiler_state_code_pairs,
    _OrderedArchiveSeedDependency,
    _RuntimeProjectionEquivalence,
)
from reprobit.classic.compiler_identity import (
    Msvc420CompilerIdentity,
    issue_msvc420_compiler_identity,
)
from reprobit.classic.compiler_state_foundation import (
    CompilerStateCodePair,
    CompilerStateCompilerEvidence,
    CompilerStateFpoEvidence,
    _require_relocation_semantics,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.schema import LockedTool, MsvcRelease, ToolchainLock, ToolchainProfileSource
from reprobit.strict_json import canonical_json


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


def _compiler_evidence(*arguments: str) -> CompilerStateCompilerEvidence:
    return CompilerStateCompilerEvidence(
        tool_id="compiler",
        tool_digest="c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
        invocation_digest="2" * 64,
        arguments=arguments,
    )


def _code_pair(
    owner: str,
    *,
    clean_section: int,
    effective_section: int,
) -> CompilerStateCodePair:
    return CompilerStateCodePair(
        owner=owner,
        clean_section_number=clean_section,
        effective_section_number=effective_section,
        topology_digest="3" * 64,
        clean_body=b"\x90\xc3",
        effective_body=b"\x91\xc3",
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
    )


_VECTOR_CLEAN = bytes.fromhex(
    "568b51048b41088bf13bc28bca740783c1043bc175f952e800000000"
    "c7460400000000c746080000000083c404c7460c000000005ec3"
)
_VECTOR_EFFECTIVE = bytes.fromhex(
    "568b41088bf18b49043bc18bd1740783c2043bc275f951e800000000"
    "c7460400000000c746080000000083c404c7460c000000005ec3"
)

_TESTTIMER_PRINT_CLEAN = bytes.fromhex(
    "83ec085356578bf15568000000006800000000e80000000083c4088bf885ff0f84ee000000"
    "680000000033db57e80000000083c408395e147e155368000000005743e80000000083c40c"
    "395e147feb680000000057e800000000c74424180000000083c408837e18007e698b442410"
    "40894424148b461c0faf4424145033db680000000057e80000000083c40c395e147e2733ed"
    "8b46088b5424108b0c2883c504438b049150680000000057e80000000083c40c395e147fdb"
    "680000000057e8000000008b44241c83c408394618894424107f97680000000033db5733ed"
    "e80000000083c408395e147e1f8b461083c304458b4c18fc51680000000057e80000000083"
    "c40c396e147fe157e80000000083c4048bcee8000000005d5f5e5b83c408c3"
)
_TESTTIMER_PRINT_EFFECTIVE = bytes.fromhex(
    "83ec085356578bf15568000000006800000000e80000000083c4088bf885ff0f84ee000000"
    "680000000033db57e80000000083c408395e147e155368000000005743e80000000083c40c"
    "395e147feb680000000057e800000000c74424180000000083c408837e18007e698b442410"
    "40894424148b461c0faf4424145033ed680000000057e80000000083c40c396e147e2733db"
    "8b46088b5424108b0c1883c304458b049150680000000057e80000000083c40c396e147fdb"
    "680000000057e8000000008b44241c83c408394618894424107f97680000000033db5733ed"
    "e80000000083c408395e147e1f8b461083c304458b4c18fc51680000000057e80000000083"
    "c40c396e147fe157e80000000083c4048bcee8000000005d5f5e5b83c408c3"
)


def _fpo_evidence(
    body_size: int,
    *,
    frame: int = 0,
    has_seh: int = 0,
    prolog: int = 9,
    uses_ebp: int = 1,
) -> CompilerStateFpoEvidence:
    packed = 4 | has_seh << 3 | uses_ebp << 4 | frame << 6
    body = struct.pack("<IIIHBB", 0, body_size, 2, 0, prolog, packed)
    return CompilerStateFpoEvidence(
        receipt_digest=Digest.from_bytes(canonical_json({"fixture_fpo": body.hex()})).value,
        clean_body=body,
        effective_body=body,
    )


def _testtimer_print_pair() -> CompilerStateCodePair:
    return CompilerStateCodePair(
        owner="?Print@SampleTimer@@QAEXXZ",
        clean_section_number=28,
        effective_section_number=28,
        topology_digest="3" * 64,
        clean_body=_TESTTIMER_PRINT_CLEAN,
        effective_body=_TESTTIMER_PRINT_EFFECTIVE,
        clean_relocations=(),
        effective_relocations=(),
        eh_control_digest=None,
        fpo_evidence=_fpo_evidence(len(_TESTTIMER_PRINT_CLEAN)),
    )


def _undefined_relocation_statement(
    name: str,
    *,
    offset: int,
    relocation_type: int = 0x14,
    symbol_type: int = 0x20,
) -> dict[str, object]:
    return {
        "type": relocation_type,
        "target": {
            "kind": "undefined",
            "name": name,
            "value": 0,
            "type": symbol_type,
            "storage": 2,
        },
        "addend": "00000000",
        "offset": offset,
    }


def _vector_pair(callee: str = "??3@YAXPAX@Z") -> CompilerStateCodePair:
    relocation = _undefined_relocation_statement(callee, offset=24)
    return CompilerStateCodePair(
        owner="toy_vector_destructor",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest="3" * 64,
        clean_body=_VECTOR_CLEAN,
        effective_body=_VECTOR_EFFECTIVE,
        clean_relocations=(relocation,),
        effective_relocations=(relocation,),
        eh_control_digest=None,
    )


def test_vector_pair_proves_real_schedule_and_atomic_web_path() -> None:
    projection = state_projection.derive_msvc420_compiler_state_projection(
        [_vector_pair()],
        compiler_identity=_compiler_identity(),
        compiler_evidence=_compiler_evidence("/GX"),
    )

    assert projection is not None
    section = projection.proof["sections"][0]
    assert [step["kind"] for step in section["steps"]] == [
        "dependence-dag-schedule-v1",
        "simultaneous-register-web-cycle-v1",
    ]
    web = section["steps"][1]
    assert web["mapping"] == {"ecx": "edx", "edx": "ecx"}
    assert web["call_observation_count"] == 1
    assert isinstance(web["call_observation_digest"], str)


def test_real_testtimer_print_pair_proves_fpo_ebx_ebp_web_cycle() -> None:
    identity = _compiler_identity()
    projection = state_projection.derive_msvc420_compiler_state_projection(
        [_testtimer_print_pair()],
        compiler_identity=identity,
        compiler_evidence=_compiler_evidence("/O2"),
    )
    assert projection is not None
    assert projection.proof["compiler_identity"] == identity.proof_receipt()
    proof = projection.proof["sections"][0]

    assert [step["kind"] for step in proof["steps"]] == [
        "simultaneous-register-web-cycle-v1"
    ]
    web = proof["steps"][0]
    assert web["mapping"] == {"ebp": "ebx", "ebx": "ebp"}
    assert web["rewritten_offsets"] == [126, 142, 147, 157, 159, 161, 181]
    assert web["instruction_count"] == 100
    frame = proof["frame_pointer_free_evidence"]
    assert frame["kind"] == "paired-frame-pointer-free-evidence-v1"
    assert frame["clean_record"]["cbFrame"] == 0
    assert frame["clean_record"]["fHasSEH"] == 0
    assert frame["clean_record"]["fUseBP"] == 1
    assert frame["effective_record"] == frame["clean_record"]


def test_testtimer_ebp_web_requires_paired_fpo_evidence() -> None:
    with pytest.raises(ClassicSemanticError, match="touches a structural register"):
        state_projection._prove_pair(
            replace(_testtimer_print_pair(), fpo_evidence=None),
            None,
        )


@pytest.mark.parametrize(
    "evidence",
    [
        _fpo_evidence(len(_TESTTIMER_PRINT_CLEAN), frame=1),
        _fpo_evidence(len(_TESTTIMER_PRINT_CLEAN), has_seh=1),
        _fpo_evidence(len(_TESTTIMER_PRINT_CLEAN), uses_ebp=0),
    ],
)
def test_testtimer_ebp_web_rejects_non_authorizing_fpo_records(
    evidence: CompilerStateFpoEvidence,
) -> None:
    with pytest.raises(ClassicSemanticError, match="touches a structural register"):
        state_projection._prove_pair(
            replace(_testtimer_print_pair(), fpo_evidence=evidence),
            None,
        )


@pytest.mark.parametrize(
    ("evidence", "message"),
    [
        (
            replace(
                _fpo_evidence(len(_TESTTIMER_PRINT_CLEAN)),
                clean_body=b"\0",
                effective_body=b"\0",
            ),
            "FPO",
        ),
        (
            replace(
                _fpo_evidence(len(_TESTTIMER_PRINT_CLEAN)),
                receipt_digest="unbound",
            ),
            "receipt is malformed",
        ),
    ],
)
def test_testtimer_rejects_malformed_or_unbound_fpo_evidence(
    evidence: CompilerStateFpoEvidence,
    message: str,
) -> None:
    with pytest.raises(ClassicSemanticError, match=message):
        state_projection._prove_pair(
            replace(_testtimer_print_pair(), fpo_evidence=evidence),
            None,
        )


def test_fpo_evidence_rejects_code_that_derives_ebp_from_esp() -> None:
    pair = _testtimer_print_pair()
    clean = b"\x8b\xec" + pair.clean_body
    effective = b"\x8b\xec" + pair.effective_body
    pair = replace(
        pair,
        clean_body=clean,
        effective_body=effective,
        fpo_evidence=_fpo_evidence(len(clean), prolog=11),
    )

    with pytest.raises(ClassicSemanticError, match="touches a structural register"):
        state_projection._prove_pair(pair, None)


def test_non_gx_register_projection_binds_the_locked_compiler_invocation() -> None:
    evidence = _compiler_evidence("/nologo", "/O2")

    projection = state_projection.derive_msvc420_compiler_state_projection(
        [_vector_pair()],
        compiler_identity=_compiler_identity(),
        compiler_evidence=evidence,
    )

    assert projection is not None
    assert projection.proof["exception_mode"] is None
    assert projection.proof["compiler_invocation"] == {
        "tool_id": evidence.tool_id,
        "tool_digest": evidence.tool_digest,
        "invocation_digest": evidence.invocation_digest,
        "arguments_digest": Digest.from_bytes(
            canonical_json(list(evidence.arguments))
        ).value,
    }
    identity_receipt = projection.proof["compiler_identity"]
    assert identity_receipt["target"] == "msvc-4.20-win32-i386"
    assert identity_receipt["receipt_digest"] == (
        _compiler_identity().receipt_digest().model_dump(mode="json")
    )


@pytest.mark.parametrize("identity", [None, object()])
def test_projection_requires_an_issued_compiler_identity(identity: object) -> None:
    with pytest.raises(ClassicSemanticError, match="lacks a validated compiler identity"):
        state_projection.derive_msvc420_compiler_state_projection(
            [_vector_pair()],
            compiler_identity=identity,  # type: ignore[arg-type]
            compiler_evidence=_compiler_evidence("/O2"),
        )


def test_projection_binds_invocation_to_identity_compiler_digest() -> None:
    forged = replace(_compiler_evidence("/O2"), tool_digest="0" * 64)
    with pytest.raises(ClassicSemanticError, match="not bound to the validated compiler"):
        state_projection.derive_msvc420_compiler_state_projection(
            [_vector_pair()],
            compiler_identity=_compiler_identity(),
            compiler_evidence=forged,
        )


@pytest.mark.parametrize(
    "callee",
    [
        "?Method@Thing@@QAEXXZ",  # thiscall observes ECX
        "?Fast@Thing@@YIXXZ",  # fastcall observes ECX and EDX
        "_unknown",  # undecorated calls conservatively observe all caller-saved registers
    ],
)
def test_atomic_web_rejects_calls_that_observe_recoloured_values(callee: str) -> None:
    with pytest.raises(ClassicSemanticError, match="changes a reaching definition"):
        state_projection._prove_pair(
            _vector_pair(callee),
            state_projection._optional_synchronous_exception_mode(_compiler_evidence("/GX")),
        )


def test_pair_rejects_external_entry_in_the_middle_of_an_instruction() -> None:
    pair = replace(_vector_pair(), external_entries=(2,))

    with pytest.raises(ClassicSemanticError, match="non-instruction external entry"):
        state_projection._prove_pair(
            pair,
            state_projection._optional_synchronous_exception_mode(_compiler_evidence("/GX")),
        )


_EH_TOPOLOGY = {
    "characteristics": 0x60001020,
    "comdat_selection": 1,
    "comdat_association": None,
    "alignment": 4,
}
_EH_TOPOLOGY_DIGEST = Digest.from_bytes(canonical_json(_EH_TOPOLOGY)).value
_EH_PROLOGUE = bytes.fromhex(
    "64a100000000"  # mov eax, fs:[__except_list]
    "55"  # push ebp
    "8bec"  # mov ebp, esp
    "6aff"  # push -1
    "6800000000"  # push relocated handler entry
    "50"  # push eax
    "64892500000000"  # mov fs:[__except_list], esp
)


def _eh_relocations(body_size: int, *, allocation_call: bool) -> tuple[dict[str, object], ...]:
    handler = body_size - 1
    values = [
        _undefined_relocation_statement(
            "__except_list", offset=2, relocation_type=6, symbol_type=0
        ),
        {
            "type": 6,
            "target": {
                "kind": "defined",
                "symbol": {
                    "name": "$Lhandler",
                    "type": 0,
                    "storage": 6,
                    "section_symbol": False,
                    "value": handler,
                },
                "section": {"kind": "code", "topology": _EH_TOPOLOGY},
            },
            "addend": "00000000",
            "offset": 12,
        },
        _undefined_relocation_statement(
            "__except_list", offset=20, relocation_type=6, symbol_type=0
        ),
    ]
    if allocation_call:
        values.append(_undefined_relocation_statement("??2@YAPAXI@Z", offset=27))
    return tuple(values)


def _eh_pair(
    clean_suffix: bytes,
    effective_suffix: bytes,
    *,
    allocation_call: bool = False,
    prologue: bytes = _EH_PROLOGUE,
    extra_entries: tuple[int, ...] = (),
) -> CompilerStateCodePair:
    clean = prologue + clean_suffix
    effective = prologue + effective_suffix
    assert len(clean) == len(effective)
    relocations = _eh_relocations(len(clean), allocation_call=allocation_call)
    return CompilerStateCodePair(
        owner="toy_eh_function",
        clean_section_number=1,
        effective_section_number=1,
        topology_digest=_EH_TOPOLOGY_DIGEST,
        clean_body=clean,
        effective_body=effective,
        clean_relocations=relocations,
        effective_relocations=relocations,
        eh_control_digest="4" * 64,
        external_entries=(*extra_entries, len(clean) - 1),
    )


def _gx_mode() -> Mapping[str, object]:
    mode = state_projection._optional_synchronous_exception_mode(_compiler_evidence("/GX"))
    assert mode is not None
    return mode


def test_frame_push_pair_proves_exact_stack_span_disjointness() -> None:
    pair = _eh_pair(
        bytes.fromhex("83ec108b45088b4dec53c3"),
        bytes.fromhex("83ec10538b45088b4decc3"),
    )

    proof = state_projection._prove_pair(pair, _gx_mode())

    assert [step["kind"] for step in proof["steps"]] == [
        "ebp-frame-push-schedule-v1"
    ]
    step = proof["steps"][0]
    assert step["esp_relative_to_ebp"] == -28
    assert step["push_span_relative_to_ebp"] == [-32, -28]
    assert step["discharged_push_memory_edge_count"] == 2


@pytest.mark.parametrize(
    ("pair", "message"),
    [
        (
            _eh_pair(
                bytes.fromhex("83ec108b45088b4de053c3"),
                bytes.fromhex("83ec10538b45088b4de0c3"),
            ),
            "push aliases",
        ),
        (
            _eh_pair(
                bytes.fromhex("83ec108b45088b4dec53c3"),
                bytes.fromhex("83ec10538b45088b4decc3"),
                extra_entries=(27,),
            ),
            "branch or funclet entry",
        ),
        (
            _eh_pair(
                bytes.fromhex("83ec108b45088b4dec53c3"),
                bytes.fromhex("83ec10538b45088b4decc3"),
                prologue=bytes.fromhex(
                    "64a100000000558bec6afe68000000005064892500000000"
                ),
            ),
            "closed MSVC 4.20 EH registration frame",
        ),
    ],
)
def test_frame_push_pair_rejects_alias_entry_and_prologue_mutations(
    pair: CompilerStateCodePair,
    message: str,
) -> None:
    with pytest.raises(ClassicSemanticError, match=message):
        state_projection._prove_pair(pair, _gx_mode())


_ALLOCATION_PREFIX = bytes.fromhex("6a04e80000000083c4048bd8")
_STATE_40 = bytes.fromhex("c745fc40000000")
_STATE_41 = bytes.fromhex("c745fc41000000")
_STATE_42 = bytes.fromhex("c745fc42000000")
_OBJECT_AT_4 = bytes.fromhex("c7430401000000")
_OBJECT_AT_0 = bytes.fromhex("c70302000000")


def _eh_schedule_pair(
    *,
    effective_window: bytes,
    extra_entries: tuple[int, ...] = (),
) -> CompilerStateCodePair:
    clean_window = _OBJECT_AT_4 + _STATE_40 + _STATE_41 + _OBJECT_AT_0 + _STATE_42
    return _eh_pair(
        _ALLOCATION_PREFIX + clean_window + b"\xc3",
        _ALLOCATION_PREFIX + effective_window + b"\xc3",
        allocation_call=True,
        extra_entries=extra_entries,
    )


def test_synchronous_eh_pair_proves_state_schedule_across_fresh_object_memory() -> None:
    pair = _eh_schedule_pair(
        effective_window=_STATE_40 + _STATE_41 + _OBJECT_AT_4 + _OBJECT_AT_0 + _STATE_42
    )

    proof = state_projection._prove_pair(pair, _gx_mode())

    assert [step["kind"] for step in proof["steps"]] == [
        "msvc-synchronous-eh-state-schedule-v1"
    ]
    step = proof["steps"][0]
    assert step["state_values"] == [0x40, 0x41]
    assert step["exception_mode"]["model"] == "msvc-4.20-synchronous-gx"
    assert step["fresh_allocation"]["allocation_target"] == "??2@YAPAXI@Z"


def test_synchronous_eh_pair_still_requires_exact_gx_evidence() -> None:
    pair = _eh_schedule_pair(
        effective_window=_STATE_40 + _STATE_41 + _OBJECT_AT_4 + _OBJECT_AT_0 + _STATE_42
    )

    with pytest.raises(ClassicSemanticError, match="lacks exact synchronous /GX evidence"):
        state_projection._prove_pair(pair, None)


@pytest.mark.parametrize(
    ("pair", "message"),
    [
        (
            _eh_schedule_pair(
                effective_window=(
                    _STATE_41 + _STATE_40 + _OBJECT_AT_4 + _OBJECT_AT_0 + _STATE_42
                )
            ),
            "dependence DAG forbids",
        ),
        (
            _eh_schedule_pair(
                effective_window=(
                    _STATE_40 + _STATE_41 + _OBJECT_AT_4 + _OBJECT_AT_0 + _STATE_42
                ),
                extra_entries=(36,),
            ),
            "control-flow or funclet entry",
        ),
    ],
)
def test_synchronous_eh_pair_rejects_state_order_and_interior_entry(
    pair: CompilerStateCodePair,
    message: str,
) -> None:
    with pytest.raises(ClassicSemanticError, match=message):
        state_projection._prove_pair(pair, _gx_mode())


def test_synchronous_eh_pair_rejects_unproven_allocation_base() -> None:
    pair = _eh_schedule_pair(
        effective_window=_STATE_40 + _STATE_41 + _OBJECT_AT_4 + _OBJECT_AT_0 + _STATE_42
    )
    clean = bytearray(pair.clean_body)
    effective = bytearray(pair.effective_body)
    clean[35] = 0xCB  # mov ebx, ecx instead of the operator-new result in eax
    effective[35] = 0xCB

    with pytest.raises(ClassicSemanticError, match="no definition for its memory base"):
        state_projection._prove_pair(
            replace(pair, clean_body=bytes(clean), effective_body=bytes(effective)),
            _gx_mode(),
        )


@pytest.mark.parametrize("option", ["/GX", "-GX", "/gx", "-gx"])
def test_synchronous_exception_mode_is_derived_from_locked_gx(option: str) -> None:
    evidence = _compiler_evidence("/nologo", option, "/O2")

    mode = state_projection._optional_synchronous_exception_mode(evidence)

    assert mode is not None
    assert mode["model"] == "msvc-4.20-synchronous-gx"
    assert mode["argument"] == option
    assert mode["argument_ordinal"] == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ("/O2",),
        ("/GX", "/GX"),
        ("/GX-",),
        ("-GX-",),
        ("/GX", "/EHa"),
        ("-GX", "-EHsc"),
    ],
)
def test_synchronous_exception_mode_is_absent_for_unrecognized_or_conflicting_options(
    arguments: tuple[str, ...],
) -> None:
    assert (
        state_projection._optional_synchronous_exception_mode(_compiler_evidence(*arguments))
        is None
    )


def test_projection_canonicalizes_pair_order_before_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    visited: list[str] = []

    def prove(
        pair: CompilerStateCodePair,
        _mode: object,
        _identity: object,
    ) -> dict[str, object]:
        visited.append(pair.owner)
        return {"owner": pair.owner, "steps": []}

    monkeypatch.setattr(state_projection, "_prove_pair", prove)
    projection = state_projection.derive_msvc420_compiler_state_projection(
        [
            _code_pair("Zulu", clean_section=2, effective_section=12),
            _code_pair("alpha", clean_section=1, effective_section=11),
        ],
        compiler_identity=_compiler_identity(),
        compiler_evidence=_compiler_evidence("/GX"),
    )

    assert projection is not None
    assert visited == ["alpha", "Zulu"]
    assert [item["owner"] for item in projection.proof["sections"]] == [
        "alpha",
        "Zulu",
    ]


def test_projection_attaches_the_code_owner_to_a_generic_proof_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(
        pair: CompilerStateCodePair,
        mode: Mapping[str, object] | None,
        identity: object,
    ) -> dict[str, object]:
        del pair, mode, identity
        raise ClassicSemanticError("generic proof refusal")

    monkeypatch.setattr(state_projection, "_prove_pair", refuse)

    with pytest.raises(
        ClassicSemanticError,
        match=r"code pair 'named_owner': generic proof refusal",
    ):
        state_projection.derive_msvc420_compiler_state_projection(
            [_code_pair("named_owner", clean_section=1, effective_section=2)],
            compiler_identity=_compiler_identity(),
            compiler_evidence=_compiler_evidence("/GX"),
        )


@pytest.mark.parametrize("duplicate", ["clean", "effective"])
def test_projection_rejects_duplicate_section_certificate_seats(
    duplicate: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        state_projection,
        "_prove_pair",
        lambda pair, mode: {"owner": pair.owner, "steps": []},
    )
    first = _code_pair("first", clean_section=1, effective_section=11)
    second = _code_pair("second", clean_section=2, effective_section=12)
    second = replace(
        second,
        clean_section_number=(1 if duplicate == "clean" else 2),
        effective_section_number=(11 if duplicate == "effective" else 12),
    )

    with pytest.raises(ClassicSemanticError, match=f"{duplicate} section seat"):
        state_projection.derive_msvc420_compiler_state_projection(
            [first, second],
            compiler_identity=_compiler_identity(),
            compiler_evidence=_compiler_evidence("/GX"),
        )


def _symbol(
    index: int,
    name: str,
    *,
    value: int,
    section: int,
    symbol_type: int,
    storage: int,
) -> _CoffSymbol:
    return _CoffSymbol(index, name, value, section, symbol_type, storage, 0, b"")


def _relocation(
    *,
    offset: int,
    target_index: int,
    target: str,
    target_section: int,
    target_value: int,
    target_type: int = 0,
    target_storage: int = 6,
    relocation_type: int = 6,
    addend: int = 0,
) -> _CoffRelocation:
    return _CoffRelocation(
        offset,
        relocation_type,
        target_index,
        target,
        target_section,
        target_value,
        target_type,
        target_storage,
        addend.to_bytes(4, "little", signed=True),
    )


def _section(
    number: int,
    name: str,
    body: bytes,
    *,
    relocations: tuple[_CoffRelocation, ...] = (),
    associated: int | None = None,
    characteristics: int = 0x60001020,
    selection: int | None = 5,
) -> _CoffSection:
    return _CoffSection(
        number,
        name,
        body,
        characteristics,
        (),
        relocations,
        selection,
        associated,
    )


def _section_definition(
    index: int,
    section: _CoffSection,
    *,
    checksum: int = 0,
    reserved: int = 0,
    raw_associated: int | None = None,
) -> _CoffSymbol:
    associated = (section.comdat_associated if raw_associated is None else raw_associated) or 0
    auxiliary = struct.pack(
        "<IHHIHBBH",
        len(section.body),
        len(section.relocations),
        len(section.line_numbers),
        checksum,
        associated & 0xFFFF,
        section.comdat_selection or 0,
        reserved,
        associated >> 16,
    )
    return _CoffSymbol(
        index,
        section.name,
        0,
        section.number,
        0,
        3,
        1,
        auxiliary,
    )


def _ordinal_shifted_paired_object(
    label: str,
    *,
    shifted: bool,
    code_body: bytes,
    control_body: bytes = b"\0\0\0\0",
    control_checksum: int = 0,
    control_reserved: int = 0,
    control_selection: int = 5,
    associate_with_padding: bool = False,
) -> _CoffObject:
    code_number = 2 if shifted else 1
    control_number = code_number + 1
    association = 1 if associate_with_padding else code_number
    code = _section(code_number, ".text$x", code_body)
    control = _section(
        control_number,
        ".xdata$x",
        control_body,
        relocations=(
            _relocation(
                offset=0,
                target_index=3,
                target="$L1",
                target_section=code_number,
                target_value=1,
            ),
        ),
        associated=association,
        characteristics=0x40300040,
        selection=control_selection,
    )
    sections = (
        (
            _section(
                1,
                ".rdata$padding",
                b"padding",
                characteristics=0x40300040,
                selection=None,
            ),
            code,
            control,
        )
        if shifted
        else (code, control)
    )
    return _CoffObject(
        label,
        Digest.from_bytes(label.encode()),
        0,
        sections,
        (
            _section_definition(0, code),
            _symbol(
                2,
                "_owner",
                value=0,
                section=code_number,
                symbol_type=0x20,
                storage=2,
            ),
            _symbol(
                3,
                "$L1",
                value=1,
                section=code_number,
                symbol_type=0,
                storage=6,
            ),
            _section_definition(
                4,
                control,
                checksum=control_checksum,
                reserved=control_reserved,
            ),
        ),
    )


def _paired_object(
    label: str,
    *,
    code_body: bytes,
    code_characteristics: int = 0x60001020,
    control_body: bytes = b"\0\0\0\0",
    entry: int = 1,
    entry_addend: int = 0,
) -> _CoffObject:
    code = _section(
        1,
        ".text$x",
        code_body,
        characteristics=code_characteristics,
    )
    control = _section(
        2,
        ".xdata$x",
        control_body,
        relocations=(
            _relocation(
                offset=0,
                target_index=1,
                target="$L1",
                target_section=1,
                target_value=entry,
                addend=entry_addend,
            ),
        ),
        associated=1,
        characteristics=0x40300040,
    )
    return _CoffObject(
        label,
        Digest.from_bytes(label.encode()),
        0,
        (code, control),
        (
            _symbol(
                0,
                "_owner",
                value=0,
                section=1,
                symbol_type=0x20,
                storage=2,
            ),
            _symbol(
                1,
                "$L1",
                value=entry,
                section=1,
                symbol_type=0,
                storage=6,
            ),
        ),
    )


def _static_serial_target_object(
    label: str,
    *,
    code_body: bytes,
    serial: int,
    direct_static_target: bool = False,
    static_stem: str = "_g_value",
    static_value: int = 4,
    static_storage: int = 3,
    static_type: int = 0,
    duplicate_static_stem: bool = False,
    data_body: bytes = b"abcdefghijkl",
    data_selection: int = 0,
) -> _CoffObject:
    local_name = f"$T{serial}"
    static_name = f"{static_stem}$S{serial}"
    target_index = 2 if direct_static_target else 1
    target_name = static_name if direct_static_target else local_name
    target_value = static_value if direct_static_target else 0
    code = _section(
        1,
        ".text$x",
        code_body,
        relocations=(
            _relocation(
                offset=1,
                target_index=target_index,
                target=target_name,
                target_section=2,
                target_value=target_value,
                target_type=(static_type if direct_static_target else 0),
                target_storage=(static_storage if direct_static_target else 3),
            ),
        ),
    )
    data = _section(
        2,
        ".rdata",
        data_body,
        characteristics=0x40400040,
        selection=data_selection,
    )
    symbols = [
        _symbol(0, "_owner", value=0, section=1, symbol_type=0x20, storage=2),
        _symbol(1, local_name, value=0, section=2, symbol_type=0, storage=3),
        _symbol(
            2,
            static_name,
            value=static_value,
            section=2,
            symbol_type=static_type,
            storage=static_storage,
        ),
    ]
    if duplicate_static_stem:
        symbols.append(
            _symbol(
                3,
                f"{static_stem}$S{serial + 1}",
                value=8,
                section=2,
                symbol_type=0,
                storage=3,
            )
        )
    return _CoffObject(
        label,
        Digest.from_bytes(label.encode()),
        0,
        (code, data),
        tuple(symbols),
    )


def _fpo_paired_object(
    label: str,
    *,
    code_body: bytes,
    fpo_body: bytes | None = None,
    debug_body: bytes = b"symbols",
) -> _CoffObject:
    body = (
        struct.pack("<IIIHBB", 0, len(code_body), 0, 0, 1, 4)
        if fpo_body is None
        else fpo_body
    )
    return _CoffObject(
        label,
        Digest.from_bytes(label.encode()),
        0,
        (
            _section(1, ".text$x", code_body),
            _section(
                2,
                ".debug$F",
                body,
                associated=1,
                characteristics=0x42101040,
            ),
            _section(
                3,
                ".debug$S",
                debug_body,
                associated=1,
                characteristics=0x42101048,
            ),
        ),
        (
            _symbol(
                0,
                "_owner",
                value=0,
                section=1,
                symbol_type=0x20,
                storage=2,
            ),
        ),
    )


def _fpo_vector_coff_pair(*, uses_ebp: int) -> tuple[_CoffObject, _CoffObject]:
    fpo = _fpo_evidence(len(_VECTOR_CLEAN), uses_ebp=uses_ebp).clean_body

    def build(label: str, body: bytes) -> _CoffObject:
        call = _relocation(
            offset=24,
            target_index=1,
            target="??3@YAXPAX@Z",
            target_section=0,
            target_value=0,
            target_type=0x20,
            target_storage=2,
            relocation_type=0x14,
        )
        return _CoffObject(
            label,
            Digest.from_bytes(label.encode()),
            0,
            (
                _section(1, ".text$x", body, relocations=(call,)),
                _section(
                    2,
                    ".debug$F",
                    fpo,
                    associated=1,
                    characteristics=0x42101040,
                ),
                _section(
                    3,
                    ".debug$S",
                    b"symbols",
                    associated=1,
                    characteristics=0x42101048,
                ),
            ),
            (
                _symbol(
                    0,
                    "_owner",
                    value=0,
                    section=1,
                    symbol_type=0x20,
                    storage=2,
                ),
                _symbol(
                    1,
                    "??3@YAXPAX@Z",
                    value=0,
                    section=0,
                    symbol_type=0x20,
                    storage=2,
                ),
            ),
        )

    return build("clean", _VECTOR_CLEAN), build("effective", _VECTOR_EFFECTIVE)


def test_pair_builder_binds_topology_entries_and_exact_eh_control() -> None:
    clean = _paired_object("clean", code_body=b"\x90\xc3")
    effective = _paired_object("effective", code_body=b"\x91\xc3")

    pairs = _compiler_state_code_pairs(
        clean, effective, excluded_effective_sections=frozenset()
    )

    assert len(pairs) == 1
    assert pairs[0].owner == "_owner"
    assert pairs[0].external_entries == (1,)
    assert pairs[0].eh_control_digest is not None


def test_pair_builder_canonicalizes_associated_comdat_section_seats() -> None:
    clean = _ordinal_shifted_paired_object(
        "clean",
        shifted=False,
        code_body=b"\x90\xc3",
    )
    effective = _ordinal_shifted_paired_object(
        "effective",
        shifted=True,
        code_body=b"\x91\xc3",
    )

    pair = _compiler_state_code_pairs(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
    )[0]

    assert pair.clean_section_number == 1
    assert pair.effective_section_number == 2
    assert pair.eh_control_digest is not None


@pytest.mark.parametrize("direct_static_target", [False, True])
def test_pair_builder_canonicalizes_unique_msvc_static_serials(
    direct_static_target: bool,
) -> None:
    clean = _static_serial_target_object(
        "clean",
        code_body=b"\xa1\0\0\0\0\xc3",
        serial=72809,
        direct_static_target=direct_static_target,
    )
    effective = _static_serial_target_object(
        "effective",
        code_body=b"\xa1\0\0\0\0\x90\xc3",
        serial=72830,
        direct_static_target=direct_static_target,
    )

    pair = _compiler_state_code_pairs(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
    )[0]

    _require_relocation_semantics(pair)
    target = pair.clean_relocations[0]["target"]
    assert isinstance(target, dict)
    if direct_static_target:
        assert target["symbol"]["name"] == {"msvc_static_serial_stem": "_g_value"}
    assert pair.clean_relocations[0] == pair.effective_relocations[0]
    certificate = _CodeProjectionCertificate("closed-test-theorem", "4" * 64, True)
    assert _coff_semantic_envelope(
        clean,
        certified_code_sections={1: certificate},
    )["statement"] == _coff_semantic_envelope(
        effective,
        certified_code_sections={1: certificate},
    )["statement"]
    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
        projection_equivalence=_RuntimeProjectionEquivalence(
            equivalent=True,
            byte_equal=False,
            theorem="closed-test-theorem",
            clean_code_certificates={1: certificate},
            effective_code_certificates={1: certificate},
            proof=None,
        ),
    )
    assert "typed-msvc-static-local-serial-alpha-renaming" in trace["allowed_deltas"]


@pytest.mark.parametrize(
    "mutation",
    [
        {"static_stem": "_other_value"},
        {"static_value": 5},
        {"static_storage": 2},
        {"static_type": 0x20},
        {"data_body": b"abcdefghijkX"},
        {"data_selection": 1},
    ],
)
def test_pair_builder_does_not_widen_msvc_static_serial_identity(
    mutation: dict[str, object],
) -> None:
    clean = _static_serial_target_object(
        "clean",
        code_body=b"\xa1\0\0\0\0\xc3",
        serial=72809,
    )
    effective = _static_serial_target_object(
        "effective",
        code_body=b"\xa1\0\0\0\0\x90\xc3",
        serial=72830,
        **mutation,
    )
    pair = _compiler_state_code_pairs(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
    )[0]

    with pytest.raises(ClassicSemanticError, match="changes relocation 0"):
        _require_relocation_semantics(pair)


def test_pair_builder_keeps_an_ambiguous_msvc_static_stem_exact() -> None:
    clean = _static_serial_target_object(
        "clean",
        code_body=b"\xa1\0\0\0\0\xc3",
        serial=72809,
        duplicate_static_stem=True,
    )
    effective = _static_serial_target_object(
        "effective",
        code_body=b"\xa1\0\0\0\0\x90\xc3",
        serial=72830,
        duplicate_static_stem=True,
    )
    pair = _compiler_state_code_pairs(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
    )[0]

    with pytest.raises(ClassicSemanticError, match="changes relocation 0"):
        _require_relocation_semantics(pair)

    unchanged = _static_serial_target_object(
        "unchanged",
        code_body=b"\xa1\0\0\0\0\x90\xc3",
        serial=72809,
        duplicate_static_stem=True,
    )
    exact_pair = _compiler_state_code_pairs(
        clean,
        unchanged,
        excluded_effective_sections=frozenset(),
    )[0]
    _require_relocation_semantics(exact_pair)


def test_pair_builder_rejects_changed_associated_comdat_identity() -> None:
    clean = _ordinal_shifted_paired_object(
        "clean",
        shifted=False,
        code_body=b"\x90\xc3",
    )
    effective = _ordinal_shifted_paired_object(
        "effective",
        shifted=True,
        code_body=b"\x91\xc3",
        associate_with_padding=True,
    )

    with pytest.raises(ClassicSemanticError, match="changes paired EH control"):
        _compiler_state_code_pairs(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"control_checksum": 1},
        {"control_reserved": 1},
        {"control_selection": 4},
        {"control_body": b"\1\0\0\0"},
    ],
)
def test_pair_builder_preserves_associated_comdat_control_evidence(
    mutation: dict[str, object],
) -> None:
    clean = _ordinal_shifted_paired_object(
        "clean",
        shifted=False,
        code_body=b"\x90\xc3",
    )
    effective = _ordinal_shifted_paired_object(
        "effective",
        shifted=True,
        code_body=b"\x91\xc3",
        **mutation,
    )

    with pytest.raises(ClassicSemanticError, match="changes paired EH control"):
        _compiler_state_code_pairs(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
        )


def test_pair_builder_retains_exact_bodies_under_one_paired_child_topology() -> None:
    clean = _fpo_paired_object("clean", code_body=b"\x90\xc3")
    effective = _fpo_paired_object("effective", code_body=b"\x91\xc3")

    pair = _compiler_state_code_pairs(
        clean, effective, excluded_effective_sections=frozenset()
    )[0]

    assert pair.fpo_evidence is not None
    assert pair.fpo_evidence.clean_body == struct.pack("<IIIHBB", 0, 2, 0, 0, 1, 4)
    assert pair.fpo_evidence.effective_body == pair.fpo_evidence.clean_body
    assert len(pair.fpo_evidence.receipt_digest) == 64
    assert pair.debug_evidence is not None
    assert pair.debug_evidence.clean_body == b"symbols"
    assert pair.debug_evidence.effective_body == pair.debug_evidence.clean_body
    assert len(pair.debug_evidence.receipt_digest) == 64

    changed_fpo = struct.pack("<IIIHBB", 0, 2, 0, 0, 2, 4)
    changed = _fpo_paired_object(
        "changed", code_body=b"\x91\xc3", fpo_body=changed_fpo
    )
    changed_pair = _compiler_state_code_pairs(
        clean, changed, excluded_effective_sections=frozenset()
    )[0]
    assert changed_pair.fpo_evidence is not None
    assert changed_pair.fpo_evidence.clean_body != changed_pair.fpo_evidence.effective_body

    changed_debug = _fpo_paired_object(
        "changed-debug", code_body=b"\x91\xc3", debug_body=b"changed"
    )
    changed_debug_pair = _compiler_state_code_pairs(
        clean, changed_debug, excluded_effective_sections=frozenset()
    )[0]
    assert changed_debug_pair.debug_evidence is not None
    assert (
        changed_debug_pair.debug_evidence.clean_body
        != changed_debug_pair.debug_evidence.effective_body
    )


def test_full_coff_non_ebp_projection_accepts_exact_fpo_without_bp_use() -> None:
    clean, effective = _fpo_vector_coff_pair(uses_ebp=0)

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
        compiler_state_identity=_compiler_identity(),
        compiler_state_evidence=_compiler_evidence("/O2"),
        compiler_state_projection_required=True,
    )

    proof = trace["compiler_state_projection_proof"]
    section = proof["sections"][0]
    assert [step["kind"] for step in section["steps"]] == [
        "dependence-dag-schedule-v1",
        "simultaneous-register-web-cycle-v1",
    ]
    assert section["steps"][1]["mapping"] == {"ecx": "edx", "edx": "ecx"}
    assert "frame_pointer_free_evidence" not in section


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"code_characteristics": 0x60001040}, "changes section topology"),
        ({"entry_addend": -1}, "changes external entry offsets"),
        ({"control_body": b"\1\0\0\0"}, "changes paired EH control"),
    ],
)
def test_pair_builder_rejects_changed_topology_entry_or_eh_control(
    mutation: dict[str, object], message: str
) -> None:
    clean = _paired_object("clean", code_body=b"\x90\xc3")
    effective = _paired_object("effective", code_body=b"\x91\xc3", **mutation)

    with pytest.raises(ClassicSemanticError, match=message):
        _compiler_state_code_pairs(clean, effective, excluded_effective_sections=frozenset())


def _relocated_code_object(
    label: str,
    *,
    body: bytes,
    relocation_offset: int,
) -> _CoffObject:
    relocation = _relocation(
        offset=relocation_offset,
        target_index=1,
        target="_callee",
        target_section=0,
        target_value=0,
        target_type=0x20,
        target_storage=2,
        relocation_type=0x14,
    )
    return _CoffObject(
        label,
        Digest.from_bytes(label.encode()),
        0,
        (_section(1, ".text$x", body, relocations=(relocation,)),),
        (
            _symbol(
                0,
                "_owner",
                value=0,
                section=1,
                symbol_type=0x20,
                storage=2,
            ),
            _symbol(
                1,
                "_callee",
                value=0,
                section=0,
                symbol_type=0x20,
                storage=2,
            ),
        ),
    )


def test_code_certificate_rejoins_instruction_image_and_relocation_seat() -> None:
    clean = _relocated_code_object("clean", body=b"\xe8\0\0\0\0\x90\xc3", relocation_offset=1)
    effective = _relocated_code_object(
        "effective", body=b"\x90\xe8\0\0\0\0\xc3", relocation_offset=2
    )
    certificate = _CodeProjectionCertificate("closed-test-theorem", "4" * 64, True)

    assert (
        _coff_semantic_envelope(clean)["statement"]
        != _coff_semantic_envelope(effective)["statement"]
    )
    assert (
        _coff_semantic_envelope(clean, certified_code_sections={1: certificate})["statement"]
        == _coff_semantic_envelope(effective, certified_code_sections={1: certificate})["statement"]
    )


def test_unowned_code_delta_is_not_absorbed_by_compiler_state_pairing() -> None:
    clean = _paired_object("clean", code_body=b"\x90\xc3")
    effective = _paired_object("effective", code_body=b"\x91\xc3")
    clean = replace(
        clean,
        symbols=(
            replace(clean.symbols[0], name="$L0", storage=6, symbol_type=0),
            clean.symbols[1],
        ),
    )
    effective = replace(
        effective,
        symbols=(
            replace(effective.symbols[0], name="$L0", storage=6, symbol_type=0),
            effective.symbols[1],
        ),
    )

    assert (
        _compiler_state_code_pairs(clean, effective, excluded_effective_sections=frozenset())
        == ()
    )
    assert (
        _coff_semantic_envelope(clean)["statement"]
        != _coff_semantic_envelope(effective)["statement"]
    )


def _vector_coff_pair_with_excluded_seed_helper() -> tuple[_CoffObject, _CoffObject]:
    clean_call = _relocation(
        offset=24,
        target_index=1,
        target="??3@YAXPAX@Z",
        target_section=0,
        target_value=0,
        target_type=0x20,
        target_storage=2,
        relocation_type=0x14,
    )
    clean = _CoffObject(
        "clean",
        Digest.from_bytes(b"clean"),
        0,
        (_section(1, ".text$x", _VECTOR_CLEAN, relocations=(clean_call,)),),
        (
            _symbol(0, "_owner", value=0, section=1, symbol_type=0x20, storage=2),
            _symbol(
                1,
                "??3@YAXPAX@Z",
                value=0,
                section=0,
                symbol_type=0x20,
                storage=2,
            ),
        ),
    )
    effective_call = replace(clean_call)
    helper_reference = _relocation(
        offset=1,
        target_index=3,
        target="_seed_data",
        target_section=0,
        target_value=0,
        target_type=0,
        target_storage=2,
        relocation_type=6,
    )
    effective = _CoffObject(
        "effective",
        Digest.from_bytes(b"effective"),
        0,
        (
            _section(1, ".text$x", _VECTOR_EFFECTIVE, relocations=(effective_call,)),
            _section(
                2,
                ".text$seed",
                b"\xa1\0\0\0\0\xc3",
                relocations=(helper_reference,),
            ),
        ),
        (
            _symbol(0, "_owner", value=0, section=1, symbol_type=0x20, storage=2),
            _symbol(
                1,
                "??3@YAXPAX@Z",
                value=0,
                section=0,
                symbol_type=0x20,
                storage=2,
            ),
            _symbol(2, "$Lseed", value=0, section=2, symbol_type=0x20, storage=6),
            _symbol(3, "_seed_data", value=0, section=0, symbol_type=0, storage=2),
        ),
    )
    return clean, effective


def _seed_dependency() -> _OrderedArchiveSeedDependency:
    return _OrderedArchiveSeedDependency(
        helper_identifier="seed_seq",
        helper_symbol="$Lseed",
        helper_section=2,
        policy="reverse_statement_order_msvc_4_20",
        binding_kind="data-dir32",
        name="_seed_data",
        symbol_type=0,
        relocation_offset=1,
        relocation_type=6,
        addend="00000000",
        first_use_ordinal=0,
        undefined_symbol_index=3,
        undefined_row_ordinal=0,
    )


def test_full_coff_trace_merges_seed_row_and_compiler_state_certificates() -> None:
    clean, effective = _vector_coff_pair_with_excluded_seed_helper()

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset({2}),
        ordered_archive_seed_dependencies=(_seed_dependency(),),
        compiler_state_identity=_compiler_identity(),
        compiler_state_evidence=_compiler_evidence("/GX"),
        compiler_state_projection_required=True,
    )

    assert trace["changed_code_section_count"] == 1
    assert trace["allowed_deltas"][-2:] == [
        "typed-ordered-archive-seed-dependency",
        "typed-msvc-4.20-compiler-state-code-image",
    ]
    projection = trace["compiler_state_projection_proof"]
    assert projection["theorem"] == (
        "msvc-4.20-compiler-state-code-image-v1"
    )
    assert projection["compiler_identity"] == _compiler_identity().proof_receipt()


def test_project_overlay_required_gate_proves_register_delta_without_seed_order() -> None:
    clean, effective_with_helper = _vector_coff_pair_with_excluded_seed_helper()
    effective = replace(
        effective_with_helper,
        sections=(effective_with_helper.sections[0],),
        symbols=effective_with_helper.symbols[:2],
    )

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
        compiler_state_identity=_compiler_identity(),
        compiler_state_evidence=_compiler_evidence("/O2"),
        compiler_state_projection_required=True,
    )

    assert trace["allowed_deltas"][-1] == "typed-msvc-4.20-compiler-state-code-image"
    assert trace["compiler_state_projection_proof"]["theorem"] == (
        "msvc-4.20-compiler-state-code-image-v1"
    )


def test_required_gate_does_not_absorb_body_equal_relocation_only_change() -> None:
    body = b"\xe8\0\0\0\0\x90\xc3"
    clean = _relocated_code_object("clean", body=body, relocation_offset=1)
    effective = _relocated_code_object("effective", body=body, relocation_offset=2)

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
            compiler_state_identity=_compiler_identity(),
            compiler_state_evidence=_compiler_evidence("/O2"),
            compiler_state_projection_required=True,
        )


def test_compiler_state_projection_gate_requires_an_exact_boolean() -> None:
    clean, _effective = _vector_coff_pair_with_excluded_seed_helper()

    with pytest.raises(ClassicSemanticError, match="exact boolean"):
        _coff_compiler_congruence_trace(
            clean,
            clean,
            excluded_effective_sections=frozenset(),
            compiler_state_projection_required=1,  # type: ignore[arg-type]
        )


def test_ordered_archive_seed_policy_validation_is_separate_from_code_projection() -> None:
    clean, effective = _vector_coff_pair_with_excluded_seed_helper()

    with pytest.raises(ClassicSemanticError, match=r"exact MSVC 4\.20 policy"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset({2}),
            ordered_archive_seed_dependencies=(
                replace(_seed_dependency(), policy="unsupported"),
            ),
        )


def test_full_coff_trace_requires_compiler_evidence_for_changed_seed_owned_code() -> None:
    clean, effective = _vector_coff_pair_with_excluded_seed_helper()

    with pytest.raises(ClassicSemanticError, match="lacks its locked compiler invocation"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset({2}),
            ordered_archive_seed_dependencies=(_seed_dependency(),),
            compiler_state_identity=_compiler_identity(),
            compiler_state_projection_required=True,
        )


@pytest.mark.parametrize("identity", [None, object()])
def test_full_coff_trace_requires_issued_compiler_identity(identity: object) -> None:
    clean, effective = _vector_coff_pair_with_excluded_seed_helper()

    with pytest.raises(ClassicSemanticError, match="lacks its validated compiler identity"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset({2}),
            ordered_archive_seed_dependencies=(_seed_dependency(),),
            compiler_state_identity=identity,  # type: ignore[arg-type]
            compiler_state_evidence=_compiler_evidence("/GX"),
            compiler_state_projection_required=True,
        )


def test_full_coff_trace_prefers_an_existing_narrow_runtime_projection() -> None:
    clean, effective = _vector_coff_pair_with_excluded_seed_helper()
    other = _CodeProjectionCertificate("other-code-theorem", "5" * 64)
    projection = _RuntimeProjectionEquivalence(
        equivalent=True,
        byte_equal=False,
        theorem="other-code-theorem",
        clean_code_certificates={1: other},
        effective_code_certificates={1: other},
        proof={"theorem": "other-code-theorem"},
    )

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset({2}),
        projection_equivalence=projection,
        ordered_archive_seed_dependencies=(_seed_dependency(),),
        compiler_state_evidence=_compiler_evidence("/GX"),
        compiler_state_projection_required=True,
    )

    assert trace["relational_projection_proof"]["theorem"] == "other-code-theorem"
    assert "compiler_state_projection_proof" not in trace
