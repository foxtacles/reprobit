"""Shared contracts and exact code-image facts for compiler-state projection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypedDict, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.registers import decode_ia32_bijection_body
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.coff import RELOCATION_WIDTHS
from reprobit.model import Digest
from reprobit.strict_json import canonical_json


class _MemoryOperand(TypedDict):
    base: str | None
    index: str | None
    scale: int
    displacement: int
    absolute: bool
    width: int
    read: bool
    write: bool
    unknown: bool


class _Instruction(TypedDict):
    offset: int
    length: int
    opcode: int
    fields: list[tuple[int, int]]
    reads: frozenset[str]
    writes: frozenset[str]
    flow: str
    target: int | None
    frozen: frozenset[str]
    memory: _MemoryOperand | None
    encoding: dict[str, Any] | None
    indirect: bool
    read_atoms: frozenset[Any]
    write_atoms: frozenset[Any]


class _RelocationRecord(TypedDict):
    width: int
    target: str | None
    semantic_digest: str


class _EhFrame(TypedDict):
    base: str
    displacement: int
    width: int
    initial_value: int
    handler_entry: int
    exception_list_target_digest: str
    eh_control_digest: str


class _FreshAllocationEvidence(TypedDict):
    register: str
    definition_offset: int
    allocation_call_offset: int
    allocation_target: str
    allocation_relocation_digest: str


_ScheduleDeclaration = Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CompilerStateFpoEvidence:
    """The two exact FPO children paired by one unchanged section topology."""

    receipt_digest: str
    clean_body: bytes
    effective_body: bytes


@dataclass(frozen=True, slots=True)
class CompilerStateDebugEvidence:
    """The two exact ``.debug$S`` children paired by unchanged topology."""

    receipt_digest: str
    clean_body: bytes
    effective_body: bytes


@dataclass(frozen=True, slots=True)
class CompilerStateCodePair:
    """One retained code section paired independently of raw section ordinals."""

    owner: str
    clean_section_number: int
    effective_section_number: int
    topology_digest: str
    clean_body: bytes
    effective_body: bytes
    clean_relocations: tuple[Mapping[str, object], ...]
    effective_relocations: tuple[Mapping[str, object], ...]
    eh_control_digest: str | None
    external_entries: tuple[int, ...] = ()
    fpo_evidence: CompilerStateFpoEvidence | None = None
    debug_evidence: CompilerStateDebugEvidence | None = None


@dataclass(frozen=True, slots=True)
class CompilerStateCompilerEvidence:
    """Locked compiler identity and raw argv needed by the local /GX theorem."""

    tool_id: str
    tool_digest: str
    invocation_digest: str
    arguments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompilerStateCodeCertificate:
    theorem: str
    digest: str
    covers_relocations: bool = True


@dataclass(frozen=True, slots=True)
class CompilerStateProjection:
    clean_certificates: Mapping[int, CompilerStateCodeCertificate]
    effective_certificates: Mapping[int, CompilerStateCodeCertificate]
    proof: Mapping[str, object]


@dataclass(slots=True)
class _ImageState:
    body: bytes
    relocation_offsets: list[int]


def _relocation_parts(
    values: Sequence[Mapping[str, object]], context: str
) -> tuple[list[int], dict[int, _RelocationRecord]]:
    offsets: list[int] = []
    records: dict[int, _RelocationRecord] = {}
    for ordinal, raw in enumerate(values):
        statement = dict(raw)
        offset = statement.pop("offset", None)
        relocation_type = statement.get("type")
        if not isinstance(offset, int) or not isinstance(relocation_type, int):
            raise ClassicSemanticError(f"{context} relocation {ordinal} is malformed")
        width = RELOCATION_WIDTHS.get(relocation_type)
        if width is None or offset in records:
            raise ClassicSemanticError(
                f"{context} relocation {ordinal} has an unsupported or duplicate seat"
            )
        offsets.append(offset)
        target = statement.get("target")
        target_name: str | None = None
        if isinstance(target, dict):
            if target.get("kind") == "undefined" and isinstance(target.get("name"), str):
                target_name = target["name"]
            elif target.get("kind") == "defined":
                symbol = target.get("symbol")
                if isinstance(symbol, dict) and isinstance(symbol.get("name"), str):
                    target_name = symbol["name"]
        records[offset] = {
            "width": width,
            "target": target_name,
            "semantic_digest": Digest.from_bytes(canonical_json(statement)).value,
        }
    return offsets, records


def _require_relocation_semantics(pair: CompilerStateCodePair) -> None:
    if len(pair.clean_relocations) != len(pair.effective_relocations):
        raise ClassicSemanticError(
            f"MSVC 4.20 compiler-state code pair {pair.owner!r} changes relocation count"
        )
    for ordinal, (clean_raw, effective_raw) in enumerate(
        zip(pair.clean_relocations, pair.effective_relocations, strict=True)
    ):
        clean = dict(clean_raw)
        effective = dict(effective_raw)
        clean.pop("offset", None)
        effective.pop("offset", None)
        if clean != effective:
            raise ClassicSemanticError(
                f"MSVC 4.20 compiler-state code pair {pair.owner!r} changes relocation "
                f"{ordinal} type, target, or addend"
            )


def _relocation_bytes(
    offsets: Sequence[int], records: Mapping[int, _RelocationRecord]
) -> frozenset[int]:
    return frozenset(
        offset + byte for offset in offsets for byte in range(int(records[offset]["width"]))
    )


def _instruction_relocation_observations(
    start: int,
    end: int,
    records: Mapping[int, _RelocationRecord],
) -> list[dict[str, object]]:
    return [
        {
            "field_offset": offset - start,
            "width": record["width"],
            "target": record["target"],
            "semantic_digest": record["semantic_digest"],
        }
        for offset, record in sorted(records.items())
        if start <= offset and offset + int(record["width"]) <= end
    ]


def _instruction_token(
    body: bytes,
    instruction: _Instruction,
    relocation_offsets: Sequence[int],
    relocation_statements: Sequence[Mapping[str, object]],
    *,
    structural: bool,
) -> bytes:
    start = int(instruction["offset"])
    end = start + int(instruction["length"])
    encoded = bytearray(body[start:end])
    seated: list[dict[str, object]] = []
    for ordinal, (offset, raw) in enumerate(
        zip(relocation_offsets, relocation_statements, strict=True)
    ):
        relocation_type = raw.get("type")
        if not isinstance(relocation_type, int):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code relocation type is malformed"
            )
        width = RELOCATION_WIDTHS.get(relocation_type)
        if width is None or offset + width <= start or offset >= end:
            continue
        if not (start <= offset and offset + width <= end):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code relocation straddles an instruction boundary"
            )
        local = offset - start
        encoded[local : local + width] = bytes(width)
        statement = dict(raw)
        statement.pop("offset", None)
        seated.append(
            {
                "ordinal": ordinal,
                "field_offset": local,
                "statement": statement,
            }
        )
    if structural:
        for byte_index, shift in instruction["fields"]:
            local = int(byte_index) - start
            encoded[local] &= ~(7 << int(shift)) & 0xFF
    return canonical_json(
        {
            "encoding": bytes(encoded).hex(),
            "flow": instruction["flow"],
            "relocations": seated,
        }
    )


def _instructions(
    body: bytes, records: Mapping[int, _RelocationRecord], context: str
) -> list[_Instruction]:
    try:
        return cast(
            list[_Instruction],
            list(decode_ia32_bijection_body(body, context, dict(records))),
        )
    except ByteIdentityError as error:
        raise ClassicSemanticError(str(error)) from error


def _tokens(
    body: bytes,
    instructions: Sequence[_Instruction],
    relocation_offsets: Sequence[int],
    relocation_statements: Sequence[Mapping[str, object]],
    *,
    structural: bool,
) -> list[bytes]:
    return [
        _instruction_token(
            body,
            instruction,
            relocation_offsets,
            relocation_statements,
            structural=structural,
        )
        for instruction in instructions
    ]
