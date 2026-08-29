"""Paired frame, debug, prologue, and epilogue evidence for saved-web proofs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypedDict, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.debug import (
    CODEVIEW_END_RECORD_TYPE,
    CODEVIEW_PROCEDURE_RECORD_TYPES,
    parse_codeview_symbol_stream,
    parse_fpo_data,
)
from reprobit.classic.registers import (
    FPO_FRAME_KIND_FPO,
    IA32_GENERAL_REGISTER_NAMES,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

from .compiler_state_foundation import CompilerStateCodePair, _Instruction
from .stack_frontier_foundation import stack_change
from .stack_frontier_object import _thiscall_owner

_NONVOLATILES = ("ebx", "esi", "edi", "ebp")


class _PrologueShape(TypedDict):
    boundary_index: int
    prolog_end: int
    locals_bytes: int
    floor: int
    saves: list[tuple[str, int, int]]


def _require(condition: object, message: str) -> None:
    if not condition:
        raise ClassicSemanticError(message)


def _digest(value: object, label: str) -> str:
    _require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"MSVC 4.20 saved-prologue {label} receipt is malformed",
    )
    assert isinstance(value, str)
    return value


def _fpo_pair(pair: CompilerStateCodePair) -> tuple[dict[str, object], dict[str, object]]:
    evidence = pair.fpo_evidence
    _require(evidence is not None, "MSVC 4.20 saved-prologue proof lacks paired FPO evidence")
    assert evidence is not None
    _digest(evidence.receipt_digest, "FPO")
    _require(
        isinstance(evidence.clean_body, bytes)
        and isinstance(evidence.effective_body, bytes)
        and len(evidence.clean_body) == len(evidence.effective_body) == 16,
        "MSVC 4.20 saved-prologue FPO bodies are malformed",
    )
    _require(
        evidence.clean_body[:14] == evidence.effective_body[:14]
        and evidence.clean_body[15:] == evidence.effective_body[15:]
        and evidence.clean_body[14] != evidence.effective_body[14],
        "MSVC 4.20 saved-prologue FPO pair changes more than cbProlog",
    )
    try:
        clean = parse_fpo_data(evidence.clean_body, expected_proc_size=len(pair.clean_body))
        effective = parse_fpo_data(
            evidence.effective_body, expected_proc_size=len(pair.effective_body)
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    for record in (clean, effective):
        _require(
            record["cbFrame"] == FPO_FRAME_KIND_FPO
            and record["fHasSEH"] == 0
            and record["fUseBP"] == 1
            and record["reserved"] == 0,
            "MSVC 4.20 saved-prologue FPO pair is not frame-pointer-free and non-EH",
        )
    clean_common = {
        key: value
        for key, value in clean.items()
        if key not in {"cbProlog", "raw_sha256"}
    }
    effective_common = {
        key: value for key, value in effective.items() if key not in {"cbProlog", "raw_sha256"}
    }
    _require(
        clean_common == effective_common,
        "MSVC 4.20 saved-prologue FPO pair changes a field other than cbProlog",
    )
    return clean, effective


def _debug_pair(
    pair: CompilerStateCodePair,
    clean_prolog: int,
    effective_prolog: int,
    clean_boundaries: set[int],
    effective_boundaries: set[int],
) -> dict[str, object]:
    evidence = pair.debug_evidence
    _require(
        evidence is not None,
        "MSVC 4.20 saved-prologue proof lacks paired CodeView evidence",
    )
    assert evidence is not None
    receipt = _digest(evidence.receipt_digest, "CodeView")
    clean_body = evidence.clean_body
    effective_body = evidence.effective_body
    _require(
        isinstance(clean_body, bytes)
        and isinstance(effective_body, bytes)
        and len(clean_body) == len(effective_body),
        "MSVC 4.20 saved-prologue CodeView bodies are malformed",
    )
    try:
        clean_records = parse_codeview_symbol_stream(
            clean_body, "MSVC 4.20 saved-prologue clean CodeView"
        )
        effective_records = parse_codeview_symbol_stream(
            effective_body, "MSVC 4.20 saved-prologue effective CodeView"
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error

    def identities(records: Sequence[Mapping[str, object]]) -> list[tuple[object, ...]]:
        return [
            (item["offset"], item["size"], item["type"], item["name"])
            for item in records
        ]

    _require(
        identities(clean_records) == identities(effective_records)
        and bool(clean_records)
        and clean_records[-1]["type"] == CODEVIEW_END_RECORD_TYPE,
        "MSVC 4.20 saved-prologue CodeView record sequence changes",
    )
    procedures = [
        item for item in clean_records if item["type"] in CODEVIEW_PROCEDURE_RECORD_TYPES
    ]
    _require(
        len(procedures) == 1
        and sum(item["type"] == CODEVIEW_END_RECORD_TYPE for item in clean_records) == 1,
        "MSVC 4.20 saved-prologue CodeView is not one closed procedure",
    )
    procedure = procedures[0]
    extent_at = int(procedure["offset"]) + 16
    _require(
        extent_at + 12 <= int(procedure["offset"]) + int(procedure["size"]),
        "MSVC 4.20 saved-prologue CodeView procedure extent is truncated",
    )

    def extent(body: bytes) -> tuple[int, int, int]:
        return tuple(
            int.from_bytes(body[extent_at + offset : extent_at + offset + 4], "little")
            for offset in (0, 4, 8)
        )  # type: ignore[return-value]

    clean_length, clean_start, clean_end = extent(clean_body)
    effective_length, effective_start, effective_end = extent(effective_body)
    _require(
        clean_length == effective_length == len(pair.clean_body) == len(pair.effective_body)
        and clean_end == effective_end
        and 0 <= clean_start <= clean_end <= clean_length
        and 0 <= effective_start <= effective_end <= effective_length,
        "MSVC 4.20 saved-prologue CodeView extent changes outside its debug start",
    )
    allowed = set(range(extent_at + 4, extent_at + 8))
    changed = {
        index
        for index, (clean_byte, effective_byte) in enumerate(
            zip(clean_body, effective_body, strict=True)
        )
        if clean_byte != effective_byte
    }
    _require(
        bool(changed) and changed <= allowed,
        "MSVC 4.20 saved-prologue CodeView changes outside procedure debug_start",
    )
    _require(
        clean_start == clean_prolog
        and effective_start == effective_prolog
        and clean_start in clean_boundaries
        and effective_start in effective_boundaries,
        "MSVC 4.20 saved-prologue FPO and CodeView boundaries disagree",
    )
    try:
        owner = _thiscall_owner(
            pair.owner,
            procedure["name"],
            "MSVC 4.20 saved-prologue owner",
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error
    return {
        "receipt_digest": receipt,
        "clean_stream_digest": Digest.from_bytes(clean_body).value,
        "effective_stream_digest": Digest.from_bytes(effective_body).value,
        "procedure": procedure["name"],
        "code_length": clean_length,
        "debug_end": clean_end,
        "debug_start_map": [clean_start, effective_start],
        "owner": owner,
    }


def _register_push(body: bytes, item: _Instruction) -> str | None:
    start = int(item["offset"])
    opcode = int(item["opcode"])
    if (
        int(item["length"]) == 1
        and opcode in range(0x50, 0x58)
        and body[start] == opcode
    ):
        return IA32_GENERAL_REGISTER_NAMES[opcode - 0x50]
    return None


def _prologue_shape(
    body: bytes,
    instructions: Sequence[_Instruction],
    record: Mapping[str, object],
    context: str,
) -> _PrologueShape:
    prolog_end = cast(int, record["cbProlog"])
    boundary = next(
        (index for index, item in enumerate(instructions) if int(item["offset"]) == prolog_end),
        None,
    )
    _require(boundary is not None and boundary > 0, f"{context} is not an instruction boundary")
    assert boundary is not None
    prologue = list(instructions[:boundary])
    _require(
        int(prologue[-1]["offset"]) + int(prologue[-1]["length"]) == prolog_end
        and all(item["flow"] == "fall" for item in prologue),
        f"{context} is not one linear prologue",
    )
    locals_bytes = cast(int, record["cdwLocals"]) * 4
    first = prologue[0]
    first_raw = body[int(first["offset"]) : int(first["offset"]) + int(first["length"])]
    allocation = (
        len(first_raw) == 3
        and first_raw[:2] == b"\x83\xec"
        and first_raw[2] == locals_bytes
    ) or (
        len(first_raw) == 6
        and first_raw[:2] == b"\x81\xec"
        and int.from_bytes(first_raw[2:], "little") == locals_bytes
    )
    _require(locals_bytes > 0 and allocation, f"{context} lacks its canonical fixed allocation")
    depth = 0
    saves: list[tuple[str, int, int]] = []
    for index, item in enumerate(prologue):
        change = stack_change(body, cast(dict[str, Any], item))
        _require(change is not None, f"{context} has an unknown ESP update")
        assert change is not None
        pushed = _register_push(body, item)
        if index == 0:
            _require(change == -locals_bytes, f"{context} allocation differs from FPO locals")
        elif change < 0:
            _require(
                change == -4
                and pushed in _NONVOLATILES
                and pushed not in {name for name, _index, _offset in saves},
                f"{context} has a non-canonical saved-register push",
            )
            assert pushed is not None
            saves.append((pushed, index, int(item["offset"])))
        else:
            _require(change == 0, f"{context} changes its fixed frame twice")
        depth += change
    _require(
        len(saves) == cast(int, record["cbRegs"])
        and depth == -(locals_bytes + 4 * len(saves)),
        f"{context} saved-register count or frame floor differs from FPO",
    )
    return {
        "boundary_index": boundary,
        "prolog_end": prolog_end,
        "locals_bytes": locals_bytes,
        "floor": depth,
        "saves": saves,
    }


def _epilogues(
    body: bytes,
    instructions: Sequence[_Instruction],
    saved: Sequence[str],
    locals_bytes: int,
    parameter_bytes: int,
    context: str,
) -> list[dict[str, object]]:
    targets = {
        cast(int, item["target"])
        for item in instructions
        if item.get("target") is not None
    }
    receipts: list[dict[str, object]] = []
    for ret_index, ret in enumerate(instructions):
        if ret["flow"] != "ret":
            continue
        needed = len(saved) + 1
        _require(ret_index >= needed, f"{context} return lacks a complete epilogue")
        pops = list(instructions[ret_index - needed : ret_index - 1])
        release = instructions[ret_index - 1]
        expected_pops = list(reversed(saved))
        # POP has the PUSH register encoding plus 8 in its opcode.
        measured_pops = [
            IA32_GENERAL_REGISTER_NAMES[int(item["opcode"]) - 0x58]
            if int(item["length"]) == 1
            and int(item["opcode"]) in range(0x58, 0x60)
            and body[int(item["offset"])] == int(item["opcode"])
            else None
            for item in pops
        ]
        _require(measured_pops == expected_pops, f"{context} return changes restore order")
        release_raw = body[
            int(release["offset"]) : int(release["offset"]) + int(release["length"])
        ]
        expected_release = (
            b"\x83\xc4" + bytes([locals_bytes])
            if locals_bytes <= 0x7F
            else b"\x81\xc4" + locals_bytes.to_bytes(4, "little")
        )
        _require(release_raw == expected_release, f"{context} return changes local release")
        ret_raw = body[int(ret["offset"]) : int(ret["offset"]) + int(ret["length"])]
        expected_ret = (
            b"\xc3"
            if parameter_bytes == 0
            else b"\xc2" + parameter_bytes.to_bytes(2, "little")
        )
        _require(ret_raw == expected_ret, f"{context} return changes parameter cleanup")
        first = int(pops[0]["offset"])
        _require(
            all(
                int(left["offset"]) + int(left["length"]) == int(right["offset"])
                for left, right in zip([*pops, release], [*pops[1:], release, ret], strict=True)
            ),
            f"{context} epilogue is not contiguous",
        )
        _require(
            not any(first < target <= int(ret["offset"]) for target in targets),
            f"{context} has a control-flow entry inside an epilogue",
        )
        receipts.append(
            {
                "start": first,
                "return": int(ret["offset"]),
                "restored": measured_pops,
                "locals_bytes": locals_bytes,
                "parameter_bytes": parameter_bytes,
            }
        )
    _require(bool(receipts), f"{context} has no canonical return")
    return receipts
