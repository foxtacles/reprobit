"""MSVC/i386 COFF function indexing and structural qualification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.coff_format import (
    CoffMetadataIndex,
    CoffObject,
    coff_body,
    coff_mosaic_metadata_digest,
    detailed_relocations,
    require_associated_comdat_compatibility,
    require_mosaic_relocation_compatibility,
    section_definitions,
)
from reprobit.discovery_contracts import (
    CellObservation,
    CompileReceipt,
    DeclarationState,
    DiscoveryError,
    FunctionObservation,
    declaration_state_id,
)
from reprobit.model import Digest
from reprobit.strict_json import JsonValue, canonical_json

_MAX_FUNCTIONS_PER_OBJECT = 4_096


@dataclass(frozen=True, slots=True)
class MsvcFunctionReference:
    """Sealed function bytes and optional COFF semantics for one target."""

    symbol: str
    body: bytes
    object_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if not self.symbol or len(self.symbol) > 2048 or "\0" in self.symbol:
            raise DiscoveryError("MSVC reference symbol is malformed")
        if not self.body:
            raise DiscoveryError(f"MSVC reference body is empty: {self.symbol}")

    @classmethod
    def from_object(cls, object_bytes: bytes, symbol: str) -> MsvcFunctionReference:
        coff = parse_msvc_coff(object_bytes, f"reference {symbol}")
        index = CoffMetadataIndex(coff)
        record = unique_isolated_msvc_function(
            coff,
            symbol,
            f"reference {symbol}",
            index,
        )
        if record is None:
            raise DiscoveryError(f"reference object omits isolated COMDAT {symbol!r}")
        return cls(symbol, record.body, object_bytes)


@dataclass(frozen=True, slots=True)
class MsvcFunctionRecord:
    """One function-symbol span and its section-level COMDAT semantics."""

    symbol: str
    section: dict[str, Any]
    section_offset: int
    end: int
    body: bytes
    selection: int

    @property
    def isolated_primary(self) -> bool:
        return (
            self.section_offset == 0
            and self.end == self.section["raw_size"]
            and bool(self.section["characteristics"] & 0x1000)
            and self.selection not in {0, 5}
        )


@dataclass(frozen=True, slots=True)
class ResolvedMsvcFunctionReference:
    """A declared reference paired with parsed COFF semantics when available."""

    declared: MsvcFunctionReference
    coff: CoffObject | None
    index: CoffMetadataIndex | None
    record: MsvcFunctionRecord | None


def parse_msvc_coff(payload: bytes, context: str) -> CoffObject:
    """Parse one supported i386 COFF object with discovery-specific errors."""

    try:
        return CoffObject(payload)
    except (ByteIdentityError, UnicodeError, ValueError) as exc:
        raise DiscoveryError(f"{context} is not a supported i386 COFF object: {exc}") from exc


def msvc_function_records(
    coff: CoffObject,
    index: CoffMetadataIndex | None = None,
) -> tuple[MsvcFunctionRecord, ...]:
    """Index deterministic function spans across all text sections."""

    definitions = index.definitions if index is not None else section_definitions(coff)
    by_section: dict[int, list[dict[str, Any]]] = {}
    for raw_symbol in coff.symbols.values():
        symbol = raw_symbol
        section_number = symbol["section"]
        if (
            symbol["type"] != 0x20
            or not 0 < section_number <= len(coff.sections)
            or symbol["storage"] not in {2, 3}
        ):
            continue
        section = coff.sections[section_number - 1]
        if (
            not section["name"].startswith(".text")
            or not section["raw_size"]
            or not 0 <= symbol["value"] < section["raw_size"]
        ):
            continue
        by_section.setdefault(section_number, []).append(symbol)

    records: list[MsvcFunctionRecord] = []
    for section_number, symbols in by_section.items():
        section = coff.sections[section_number - 1]
        starts = sorted({cast(int, symbol["value"]) for symbol in symbols})
        ends = dict(pairwise((*starts, cast(int, section["raw_size"]))))
        raw = coff_body(coff, section)
        for symbol in symbols:
            start = cast(int, symbol["value"])
            end = ends[start]
            if end <= start:
                raise DiscoveryError(
                    f"function {symbol['name']!r} has an empty or overlapping COFF span"
                )
            definition = definitions.get(section_number)
            selection = cast(int, definition["selection"]) if definition is not None else 0
            records.append(
                MsvcFunctionRecord(
                    cast(str, symbol["name"]),
                    section,
                    start,
                    end,
                    raw[start:end],
                    selection,
                )
            )
    return tuple(
        sorted(
            records,
            key=lambda item: (
                item.symbol.casefold(),
                item.section["number"],
                item.section_offset,
            ),
        )
    )


def unique_isolated_msvc_function(
    coff: CoffObject,
    symbol: str,
    context: str,
    index: CoffMetadataIndex | None = None,
) -> MsvcFunctionRecord | None:
    """Return one unambiguous isolated primary COMDAT for a symbol."""

    matches = [
        item
        for item in msvc_function_records(coff, index)
        if item.symbol == symbol and item.isolated_primary
    ]
    if len(matches) > 1:
        raise DiscoveryError(f"{context} contains ambiguous definitions of {symbol!r}")
    return matches[0] if matches else None


def _relative_relocations(
    coff: CoffObject,
    record: MsvcFunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> tuple[dict[str, JsonValue], ...]:
    rows: list[dict[str, JsonValue]] = []
    relocations = (
        index.relocations(record.section)
        if index is not None
        else tuple(detailed_relocations(coff, record.section))
    )
    for raw in relocations:
        row = raw
        offset = cast(int, row["offset"])
        width = cast(int, row["width"])
        if offset < record.section_offset or offset + width > record.end:
            continue
        normalized = {
            key: cast(JsonValue, value) for key, value in row.items() if key != "symbol_index"
        }
        normalized["offset"] = offset - record.section_offset
        rows.append(normalized)
    return tuple(rows)


def _line_table(coff: CoffObject, section: Mapping[str, Any]) -> bytes:
    count = cast(int, section["line_count"])
    if not count:
        return b""
    offset = cast(int, section["line_offset"])
    return coff.data[offset : offset + count * 6]


def _function_observation(
    coff: CoffObject,
    record: MsvcFunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> FunctionObservation:
    relocations = _relative_relocations(coff, record, index)
    if record.isolated_primary:
        try:
            metadata = coff_mosaic_metadata_digest(coff, record.section, index=index)
        except ByteIdentityError as exc:
            raise DiscoveryError(
                f"function {record.symbol!r} has malformed COMDAT metadata: {exc}"
            ) from exc
    else:
        metadata = Digest.from_bytes(
            canonical_json(
                {
                    "characteristics": record.section["characteristics"],
                    "line_table": Digest.from_bytes(_line_table(coff, record.section)),
                    "selection": record.selection,
                    "span": (record.section_offset, record.end),
                }
            )
        )
    return FunctionObservation(
        symbol=record.symbol,
        section_number=record.section["number"],
        section_offset=record.section_offset,
        body_size=len(record.body),
        body=Digest.from_bytes(record.body),
        relocation_count=len(relocations),
        relocations=Digest.from_bytes(canonical_json(relocations)),
        line_count=record.section["line_count"],
        metadata=metadata,
        comdat_selection=record.selection,
    )


def _require_primary_structural_pair(
    left: CoffObject,
    left_record: MsvcFunctionRecord,
    right: CoffObject,
    right_record: MsvcFunctionRecord,
    context: str,
    *,
    left_index: CoffMetadataIndex | None = None,
    right_index: CoffMetadataIndex | None = None,
) -> None:
    if not left_record.isolated_primary or not right_record.isolated_primary:
        raise DiscoveryError(f"{context} is not an isolated COMDAT pair")
    if (
        len(left_record.body) != len(right_record.body)
        or left_record.selection != right_record.selection
        or left_record.section["characteristics"] != right_record.section["characteristics"]
    ):
        raise DiscoveryError(f"{context} has incompatible COMDAT structure")
    try:
        require_mosaic_relocation_compatibility(
            left,
            left_record.section,
            right,
            right_record.section,
            context,
            seed_index=left_index,
            donor_index=right_index,
        )
    except ByteIdentityError as exc:
        raise DiscoveryError(f"{context} has incompatible relocations: {exc}") from exc


def require_msvc_structural_pair(
    left: CoffObject,
    left_record: MsvcFunctionRecord,
    right: CoffObject,
    right_record: MsvcFunctionRecord,
    context: str,
    *,
    left_index: CoffMetadataIndex | None = None,
    right_index: CoffMetadataIndex | None = None,
) -> None:
    """Require matching primary and associated COMDAT structure."""

    _require_primary_structural_pair(
        left,
        left_record,
        right,
        right_record,
        context,
        left_index=left_index,
        right_index=right_index,
    )
    try:
        require_associated_comdat_compatibility(
            left,
            left_record.section,
            right,
            right_record.section,
            context,
            left_index=left_index,
            right_index=right_index,
        )
    except ByteIdentityError as exc:
        raise DiscoveryError(
            f"{context} has incompatible associated COMDAT closure: {exc}"
        ) from exc


def msvc_relocation_spans(
    coff: CoffObject,
    record: MsvcFunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> tuple[tuple[int, int], ...]:
    """Return relocation byte spans relative to one function body."""

    return tuple(
        (cast(int, row["offset"]), cast(int, row["offset"]) + cast(int, row["width"]))
        for row in _relative_relocations(coff, record, index)
    )


def _normalized_body(
    coff: CoffObject,
    record: MsvcFunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> bytes:
    body = bytearray(record.body)
    for start, end in msvc_relocation_spans(coff, record, index):
        body[start:end] = b"\0" * (end - start)
    return bytes(body)


def resolve_msvc_reference(
    reference: MsvcFunctionReference,
) -> ResolvedMsvcFunctionReference:
    """Resolve optional full-object semantics for a declared reference."""

    if reference.object_bytes is None:
        return ResolvedMsvcFunctionReference(reference, None, None, None)
    coff = parse_msvc_coff(reference.object_bytes, f"reference {reference.symbol}")
    index = CoffMetadataIndex(coff)
    record = unique_isolated_msvc_function(
        coff,
        reference.symbol,
        f"reference {reference.symbol}",
        index,
    )
    if record is None or len(record.body) != len(reference.body):
        raise DiscoveryError(f"reference COFF geometry differs for {reference.symbol!r}")
    return ResolvedMsvcFunctionReference(reference, coff, index, record)


def compare_msvc_reference(
    reference: ResolvedMsvcFunctionReference,
    candidate: CoffObject,
    candidate_record: MsvcFunctionRecord,
    context: str,
    candidate_index: CoffMetadataIndex | None = None,
) -> tuple[bytes, bytes]:
    """Normalize relocations and compare one candidate to a sealed reference."""

    if len(reference.declared.body) != len(candidate_record.body):
        raise DiscoveryError(f"{context} body size differs")
    candidate_body = _normalized_body(candidate, candidate_record, candidate_index)
    reference_body = bytearray(reference.declared.body)
    if reference.coff is None or reference.record is None:
        if msvc_relocation_spans(candidate, candidate_record, candidate_index):
            raise DiscoveryError(
                f"{context} cannot qualify relocations without reference COFF semantics"
            )
    else:
        require_msvc_structural_pair(
            reference.coff,
            reference.record,
            candidate,
            candidate_record,
            context,
            left_index=reference.index,
            right_index=candidate_index,
        )
        for start, end in msvc_relocation_spans(
            reference.coff,
            reference.record,
            reference.index,
        ):
            reference_body[start:end] = b"\0" * (end - start)
    return candidate_body, bytes(reference_body)


def qualify_msvc_reference_object(
    *,
    reference_object: bytes,
    candidate_object: bytes,
    symbol: str,
) -> None:
    """Require a candidate's normalized primary COMDAT to match a reference.

    This is the small project-authoring boundary used after an exact compiler-lane
    probe. It accepts only full COFF objects: relocated functions cannot be
    qualified from body bytes alone. Associated COMDAT payloads are not compared
    because equal-body composition retains those bytes from the seed object.
    """

    reference = resolve_msvc_reference(MsvcFunctionReference.from_object(reference_object, symbol))
    candidate = parse_msvc_coff(candidate_object, f"candidate {symbol}")
    candidate_index = CoffMetadataIndex(candidate)
    candidate_record = unique_isolated_msvc_function(
        candidate,
        symbol,
        f"candidate {symbol}",
        candidate_index,
    )
    if candidate_record is None:
        raise DiscoveryError(f"candidate object omits isolated COMDAT {symbol!r}")
    if reference.coff is None or reference.record is None:
        raise AssertionError("full reference COFF unexpectedly lost its parsed semantics")
    _require_primary_structural_pair(
        reference.coff,
        reference.record,
        candidate,
        candidate_record,
        f"candidate {symbol}",
        left_index=reference.index,
        right_index=candidate_index,
    )
    candidate_body = _normalized_body(candidate, candidate_record, candidate_index)
    reference_body = _normalized_body(
        reference.coff,
        reference.record,
        reference.index,
    )
    if candidate_body != reference_body:
        raise DiscoveryError(f"candidate body does not match reference for {symbol!r}")


def isolated_msvc_function_symbols(reference_object: bytes) -> tuple[str, ...]:
    """List unambiguous isolated primary COMDAT functions in one reference object."""

    coff = parse_msvc_coff(reference_object, "project grind reference")
    all_records = msvc_function_records(coff, CoffMetadataIndex(coff))
    if len(all_records) > _MAX_FUNCTIONS_PER_OBJECT:
        raise DiscoveryError(
            "project grind reference emits "
            f"{len(all_records)} functions; the per-object limit is "
            f"{_MAX_FUNCTIONS_PER_OBJECT}"
        )
    records = tuple(record for record in all_records if record.isolated_primary)
    counts: dict[str, int] = {}
    for record in records:
        counts[record.symbol] = counts.get(record.symbol, 0) + 1
    return tuple(
        sorted(
            (symbol for symbol, count in counts.items() if count == 1),
            key=lambda item: (item.casefold(), item),
        )
    )


def observe_msvc_discovery_object(
    *,
    cell_id: str,
    state: DeclarationState,
    object_path: Path,
    receipt: CompileReceipt,
) -> CellObservation:
    """Index every qualifying function emitted by one compiler cell."""

    coff = parse_msvc_coff(object_path.read_bytes(), f"discovery cell {cell_id}")
    index = CoffMetadataIndex(coff)
    records = msvc_function_records(coff, index)
    if len(records) > _MAX_FUNCTIONS_PER_OBJECT:
        raise DiscoveryError(
            f"discovery cell {cell_id} emits {len(records)} functions; "
            f"the per-object limit is {_MAX_FUNCTIONS_PER_OBJECT}"
        )
    functions = tuple(_function_observation(coff, item, index) for item in records)
    return CellObservation(
        cell_id=cell_id,
        state_id=declaration_state_id(state),
        state=state,
        object=Digest.from_path(object_path),
        compile=receipt,
        functions=functions,
    )


__all__ = [
    "MsvcFunctionRecord",
    "MsvcFunctionReference",
    "ResolvedMsvcFunctionReference",
    "compare_msvc_reference",
    "isolated_msvc_function_symbols",
    "msvc_function_records",
    "msvc_relocation_spans",
    "observe_msvc_discovery_object",
    "parse_msvc_coff",
    "qualify_msvc_reference_object",
    "require_msvc_structural_pair",
    "resolve_msvc_reference",
    "unique_isolated_msvc_function",
]
