"""MSVC/i386 COFF qualification and bounded intervention search."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import combinations, pairwise
from pathlib import Path
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.coff import (
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
    DiscoveryArtifactPayload,
    DiscoveryArtifactRole,
    DiscoveryError,
    DiscoveryFindingKind,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryProposal,
    FunctionObservation,
    MosaicRangeProposal,
    declaration_state_id,
)
from reprobit.ia32 import supported_ia32_instruction_length
from reprobit.implementation import scoped_package_implementation_digest
from reprobit.model import Digest, Scope
from reprobit.msvc_compile import render_msvc_declaration_state
from reprobit.schema import (
    BinarySurgeryIntervention,
    BinarySurgeryMethod,
    EqualBodyDonorIntervention,
    StateCarrierIntervention,
)
from reprobit.strict_json import JsonValue, canonical_json

_MAX_MOSAIC_BODY_BYTES = 64 * 1024
_MAX_MOSAIC_RANGES_PER_DONOR = 256
_MAX_FUNCTIONS_PER_OBJECT = 4_096
_ANALYSIS_IMPLEMENTATION_PATHS = (
    "binary.py",
    "coff.py",
    "discovery.py",
    "discovery_contracts.py",
    "ia32.py",
    "implementation.py",
    "model.py",
    "msvc_discovery.py",
    "msvc_discovery_analysis.py",
    "schema.py",
    "strict_json.py",
)


def msvc_discovery_analysis_implementation_digest() -> Digest:
    """Bind observations and proposals to the exact installed analyzer."""

    return scoped_package_implementation_digest(_ANALYSIS_IMPLEMENTATION_PATHS)


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
        coff = _parse_coff(object_bytes, f"reference {symbol}")
        index = CoffMetadataIndex(coff)
        record = _unique_isolated_function(
            coff,
            symbol,
            f"reference {symbol}",
            index,
        )
        if record is None:
            raise DiscoveryError(f"reference object omits isolated COMDAT {symbol!r}")
        return cls(symbol, record.body, object_bytes)


@dataclass(frozen=True, slots=True)
class _FunctionRecord:
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
class _ResolvedReference:
    declared: MsvcFunctionReference
    coff: CoffObject | None
    index: CoffMetadataIndex | None
    record: _FunctionRecord | None


@dataclass(frozen=True, slots=True)
class _RangeCandidate:
    product: DiscoveryProduct
    start: int
    end: int
    coverage: frozenset[int]
    seed_lengths: tuple[int, ...]
    donor_lengths: tuple[int, ...]
    donor_body: bytes


@dataclass(frozen=True, slots=True)
class _DonorCandidate:
    product: DiscoveryProduct
    body: bytes
    ranges: tuple[_RangeCandidate, ...]
    coverage: frozenset[int]


@dataclass(slots=True)
class _SymbolAnalysis:
    declared_reference: MsvcFunctionReference
    reference: _ResolvedReference
    seed_coff: CoffObject | None
    seed_index: CoffMetadataIndex | None
    seed_record: _FunctionRecord | None
    seed_normalized: bytes | None
    reference_normalized: bytes | None
    mismatch: frozenset[int]
    seed_instruction_boundaries: frozenset[int] | None
    reference_instruction_boundaries: frozenset[int] | None
    whole_exact: tuple[DiscoveryProduct, CoffObject, _FunctionRecord] | None = None
    private_exact: tuple[DiscoveryProduct, CoffObject, _FunctionRecord] | None = None
    donor_candidates: list[_DonorCandidate] = field(default_factory=list)


@dataclass(slots=True)
class _MosaicBudget:
    limit: int
    used: int = 0

    def spend(self, context: str) -> None:
        self.used += 1
        if self.used > self.limit:
            raise DiscoveryError(
                f"mosaic analysis exceeded max_search_steps {self.limit} while {context}"
            )


def _parse_coff(payload: bytes, context: str) -> CoffObject:
    try:
        return CoffObject(payload)
    except (ByteIdentityError, UnicodeError, ValueError) as exc:
        raise DiscoveryError(f"{context} is not a supported i386 COFF object: {exc}") from exc


def _function_records(
    coff: CoffObject,
    index: CoffMetadataIndex | None = None,
) -> tuple[_FunctionRecord, ...]:
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

    records: list[_FunctionRecord] = []
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
                _FunctionRecord(
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


def _unique_isolated_function(
    coff: CoffObject,
    symbol: str,
    context: str,
    index: CoffMetadataIndex | None = None,
) -> _FunctionRecord | None:
    matches = [
        item
        for item in _function_records(coff, index)
        if item.symbol == symbol and item.isolated_primary
    ]
    if len(matches) > 1:
        raise DiscoveryError(f"{context} contains ambiguous definitions of {symbol!r}")
    return matches[0] if matches else None


def _relative_relocations(
    coff: CoffObject,
    record: _FunctionRecord,
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
            key: cast(JsonValue, value)
            for key, value in row.items()
            if key != "symbol_index"
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
    record: _FunctionRecord,
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


def _require_structural_pair(
    left: CoffObject,
    left_record: _FunctionRecord,
    right: CoffObject,
    right_record: _FunctionRecord,
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
        or left_record.section["characteristics"]
        != right_record.section["characteristics"]
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


def _relocation_spans(
    coff: CoffObject,
    record: _FunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> tuple[tuple[int, int], ...]:
    return tuple(
        (cast(int, row["offset"]), cast(int, row["offset"]) + cast(int, row["width"]))
        for row in _relative_relocations(coff, record, index)
    )


def _normalized_body(
    coff: CoffObject,
    record: _FunctionRecord,
    index: CoffMetadataIndex | None = None,
) -> bytes:
    body = bytearray(record.body)
    for start, end in _relocation_spans(coff, record, index):
        body[start:end] = b"\0" * (end - start)
    return bytes(body)


def _resolve_reference(reference: MsvcFunctionReference) -> _ResolvedReference:
    if reference.object_bytes is None:
        return _ResolvedReference(reference, None, None, None)
    coff = _parse_coff(reference.object_bytes, f"reference {reference.symbol}")
    index = CoffMetadataIndex(coff)
    record = _unique_isolated_function(
        coff,
        reference.symbol,
        f"reference {reference.symbol}",
        index,
    )
    if record is None or len(record.body) != len(reference.body):
        raise DiscoveryError(
            f"reference COFF geometry differs for {reference.symbol!r}"
        )
    return _ResolvedReference(reference, coff, index, record)


def _compare_reference(
    reference: _ResolvedReference,
    candidate: CoffObject,
    candidate_record: _FunctionRecord,
    context: str,
    candidate_index: CoffMetadataIndex | None = None,
) -> tuple[bytes, bytes]:
    if len(reference.declared.body) != len(candidate_record.body):
        raise DiscoveryError(f"{context} body size differs")
    candidate_body = _normalized_body(candidate, candidate_record, candidate_index)
    reference_body = bytearray(reference.declared.body)
    if reference.coff is None or reference.record is None:
        if _relocation_spans(candidate, candidate_record, candidate_index):
            raise DiscoveryError(
                f"{context} cannot qualify relocations without reference COFF semantics"
            )
    else:
        _require_structural_pair(
            reference.coff,
            reference.record,
            candidate,
            candidate_record,
            context,
            left_index=reference.index,
            right_index=candidate_index,
        )
        for start, end in _relocation_spans(
            reference.coff,
            reference.record,
            reference.index,
        ):
            reference_body[start:end] = b"\0" * (end - start)
    return candidate_body, bytes(reference_body)


def _instruction_boundaries(body: bytes, context: str) -> tuple[int, ...]:
    boundaries = [0]
    offset = 0
    while offset < len(body):
        try:
            length = supported_ia32_instruction_length(body[offset:], context)
        except ByteIdentityError as exc:
            raise DiscoveryError(f"{context} contains unsupported IA-32: {exc}") from exc
        offset += length
        if offset > len(body):
            raise DiscoveryError(f"{context} instruction exceeds the function body")
        boundaries.append(offset)
    return tuple(boundaries)


def _instruction_lengths(
    body: bytes,
    start: int,
    end: int,
    context: str,
) -> tuple[int, ...]:
    boundaries = _instruction_boundaries(body[start:end], context)
    return tuple(right - left for left, right in pairwise(boundaries))


def _overlaps_relocation(
    start: int,
    end: int,
    spans: Sequence[tuple[int, int]],
) -> bool:
    return any(start < right and left < end for left, right in spans)


def _mosaic_ranges_for_donor(
    *,
    product: DiscoveryProduct,
    seed_body: bytes,
    donor_body: bytes,
    reference_body: bytes,
    seed_boundaries: frozenset[int],
    reference_boundaries: frozenset[int],
    relocation_spans: Sequence[tuple[int, int]],
    mismatch: frozenset[int],
) -> tuple[_RangeCandidate, ...]:
    try:
        donor_boundaries = set(
            _instruction_boundaries(donor_body, f"{product.observation.cell_id} donor")
        )
    except DiscoveryError:
        return ()
    common = sorted(seed_boundaries & donor_boundaries & reference_boundaries)
    atomic: list[tuple[int, int]] = []
    for start, end in pairwise(common):
        if (
            end - start <= 64
            and donor_body[start:end] == reference_body[start:end]
            and seed_body[start:end] != donor_body[start:end]
            and not _overlaps_relocation(start, end, relocation_spans)
        ):
            atomic.append((start, end))

    merged: list[tuple[int, int]] = []
    for start, end in atomic:
        if merged and merged[-1][1] == start and end - merged[-1][0] <= 64:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    result: list[_RangeCandidate] = []
    for start, end in merged:
        coverage = frozenset(offset for offset in mismatch if start <= offset < end)
        if not coverage:
            continue
        try:
            seed_lengths = _instruction_lengths(
                seed_body,
                start,
                end,
                f"{product.observation.cell_id} seed range",
            )
            donor_lengths = _instruction_lengths(
                donor_body,
                start,
                end,
                f"{product.observation.cell_id} donor range",
            )
        except DiscoveryError:
            continue
        result.append(
            _RangeCandidate(
                product,
                start,
                end,
                coverage,
                seed_lengths,
                donor_lengths,
                donor_body,
            )
        )
        if len(result) > _MAX_MOSAIC_RANGES_PER_DONOR:
            return ()
    return tuple(result)


def _select_ranges(
    donors: Sequence[_DonorCandidate],
    mismatch: frozenset[int],
    max_ranges: int,
    budget: _MosaicBudget,
) -> tuple[_RangeCandidate, ...] | None:
    candidates = tuple(
        sorted(
            (item for donor in donors for item in donor.ranges),
            key=lambda item: (
                item.start,
                -(item.end - item.start),
                item.product.observation.cell_id,
            ),
        )
    )
    mismatch_order = tuple(sorted(mismatch))

    memo: dict[
        tuple[frozenset[int], int, int],
        tuple[_RangeCandidate, ...] | None,
    ] = {}

    def visit(
        covered: frozenset[int],
        previous_end: int,
        remaining: int,
    ) -> tuple[_RangeCandidate, ...] | None:
        key = (covered, previous_end, remaining)
        if key in memo:
            return memo[key]
        budget.spend("selecting instruction ranges")
        if covered == mismatch:
            memo[key] = ()
            return memo[key]
        if remaining == 0:
            memo[key] = None
            return memo[key]
        target = next(offset for offset in mismatch_order if offset not in covered)
        options = (
            item
            for item in candidates
            if item.start >= previous_end
            and item.start <= target < item.end
            and not item.coverage.issubset(covered)
        )
        best: tuple[_RangeCandidate, ...] | None = None
        for item in options:
            suffix = visit(covered | item.coverage, item.end, remaining - 1)
            if suffix is None:
                continue
            found = (item, *suffix)
            score = (
                len(found),
                sum(entry.end - entry.start for entry in found),
                tuple(entry.product.observation.cell_id for entry in found),
            )
            if best is None:
                best = found
            else:
                best_score = (
                    len(best),
                    sum(entry.end - entry.start for entry in best),
                    tuple(entry.product.observation.cell_id for entry in best),
                )
                if score < best_score:
                    best = found
        memo[key] = best
        return best

    return visit(frozenset(), 0, max_ranges)


def _identifier(prefix: str, material: object) -> str:
    digest = hashlib.sha256(canonical_json(material)).hexdigest()
    return f"{prefix}.{digest[:24]}"


def _artifact_id(cell_id: str, role: str, symbol: str) -> str:
    return _identifier("artifact", {"cell": cell_id, "role": role, "symbol": symbol})


def msvc_analysis_authority_digest(
    *,
    compile_authority: Digest,
    references: Mapping[str, MsvcFunctionReference],
    seed_objects: Mapping[str, bytes],
) -> Digest:
    """Bind one analysis campaign to its compiler, references, and seeds."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "compile_authority": compile_authority,
                "references": tuple(
                    {
                        "symbol": symbol,
                        "body": Digest.from_bytes(reference.body),
                        "object": (
                            Digest.from_bytes(reference.object_bytes)
                            if reference.object_bytes is not None
                            else None
                        ),
                    }
                    for symbol, reference in references.items()
                ),
                "seeds": tuple(
                    {
                        "symbol": symbol,
                        "object": Digest.from_bytes(payload),
                    }
                    for symbol, payload in seed_objects.items()
                ),
            }
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

    coff = _parse_coff(object_path.read_bytes(), f"discovery cell {cell_id}")
    index = CoffMetadataIndex(coff)
    records = _function_records(coff, index)
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


def _whole_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: MsvcFunctionReference,
    product: DiscoveryProduct,
) -> DiscoveryProposal:
    state_id = declaration_state_id(product.state)
    scope = Scope(target=plan.target, translation_unit=plan.translation_unit)
    beneficiary = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    carrier = _artifact_id(product.observation.cell_id, "carrier", symbol)
    intervention_id = _identifier(
        "intervention",
        {"campaign": campaign_id, "kind": "state-carrier", "state": state_id, "symbol": symbol},
    )
    rationale = (
        "This declaration combination produced an exact function-body match. "
        "Review the rest of the object file for unintended differences."
    )
    intervention = StateCarrierIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        beneficiaries=(beneficiary,),
        carrier=carrier,
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "whole-body"},
        ),
        kind=DiscoveryFindingKind.WHOLE_BODY,
        scope=scope,
        symbol=symbol,
        state_ids=(state_id,),
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=(carrier,),
        rationale=rationale,
    )


def _private_donor_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: MsvcFunctionReference,
    product: DiscoveryProduct,
) -> DiscoveryProposal:
    state_id = declaration_state_id(product.state)
    scope = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    donor = _artifact_id(product.observation.cell_id, "private-donor", symbol)
    intervention_id = _identifier(
        "intervention",
        {"campaign": campaign_id, "kind": "private-donor", "state": state_id, "symbol": symbol},
    )
    rationale = (
        "This private same-symbol donor has the sealed body and compatible "
        "COMDAT and relocation structure; unrelated donor output is not adopted."
    )
    intervention = EqualBodyDonorIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        donor_artifact=donor,
        donor_symbol=symbol,
        expected_size=len(reference.body),
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "private-donor"},
        ),
        kind=DiscoveryFindingKind.PRIVATE_DONOR,
        scope=scope,
        symbol=symbol,
        state_ids=(state_id,),
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=(donor,),
        rationale=rationale,
    )


def _mosaic_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: MsvcFunctionReference,
    seed_body: bytes,
    ranges: tuple[_RangeCandidate, ...],
) -> DiscoveryProposal:
    scope = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    range_models = tuple(
        MosaicRangeProposal(
            donor_cell_id=item.product.observation.cell_id,
            offset=item.start,
            length=item.end - item.start,
            seed=Digest.from_bytes(seed_body[item.start : item.end]),
            donor=Digest.from_bytes(item.donor_body[item.start : item.end]),
            seed_instruction_lengths=item.seed_lengths,
            donor_instruction_lengths=item.donor_lengths,
        )
        for item in ranges
    )
    donor_products = {
        item.product.observation.cell_id: item.product for item in ranges
    }
    state_ids = tuple(
        sorted(declaration_state_id(item.state) for item in donor_products.values())
    )
    source_artifacts = tuple(
        sorted(
            (
                _identifier(
                    "artifact",
                    {"campaign": campaign_id, "role": "mosaic-seed", "symbol": symbol},
                ),
                *(
                    _artifact_id(cell_id, "mosaic-donor", symbol)
                    for cell_id in donor_products
                ),
            )
        )
    )
    intervention_id = _identifier(
        "intervention",
        {
            "campaign": campaign_id,
            "kind": "instruction-mosaic",
            "states": state_ids,
            "symbol": symbol,
            "ranges": tuple((item.offset, item.length) for item in range_models),
        },
    )
    rationale = (
        "These bounded same-symbol donor ranges cover every remaining byte "
        "difference on complete IA-32 instruction boundaries without relocations."
    )
    intervention = BinarySurgeryIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        method=BinarySurgeryMethod.INSTRUCTION_MOSAIC,
        source_artifacts=source_artifacts,
        output_digest=Digest.from_bytes(reference.body),
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "instruction-mosaic"},
        ),
        kind=DiscoveryFindingKind.INSTRUCTION_MOSAIC,
        scope=scope,
        symbol=symbol,
        state_ids=state_ids,
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=source_artifacts,
        ranges=range_models,
        rationale=rationale,
    )


def build_msvc_discovery_artifacts(
    *,
    source: bytes,
    seed_objects: Mapping[str, bytes],
    campaign_id: str,
    proposals: Sequence[DiscoveryProposal],
    products: Sequence[DiscoveryProduct],
) -> tuple[DiscoveryArtifactPayload, ...]:
    """Return only objects and declaration states named by findings."""

    by_cell = {item.observation.cell_id: item for item in products}
    by_state = {declaration_state_id(item.state): item for item in products}
    if len(by_cell) != len(products) or len(by_state) != len(products):
        raise DiscoveryError("discovery products are not uniquely addressable")
    payloads: dict[str, DiscoveryArtifactPayload] = {}

    def add_candidate(
        *,
        artifact_id: str,
        role: DiscoveryArtifactRole,
        symbol: str,
        product: DiscoveryProduct,
    ) -> None:
        object_bytes = product.object_path.read_bytes()
        if Digest.from_bytes(object_bytes) != product.observation.object:
            raise DiscoveryError(
                f"selected discovery object changed: {product.observation.cell_id}"
            )
        rendered = render_msvc_declaration_state(source, product.state)
        payload = DiscoveryArtifactPayload(
            artifact_id=artifact_id,
            role=role,
            symbol=symbol,
            object_bytes=object_bytes,
            cell_id=product.observation.cell_id,
            state=product.state,
            generated_declarations=rendered.generated_declarations,
        )
        prior = payloads.setdefault(artifact_id, payload)
        if prior != payload:
            raise DiscoveryError(
                f"proposal artifact has conflicting sources: {artifact_id}"
            )

    for proposal in proposals:
        if proposal.campaign_id != campaign_id:
            raise DiscoveryError("proposal artifact belongs to another campaign")
        if proposal.kind is DiscoveryFindingKind.WHOLE_BODY:
            product = by_state.get(proposal.state_ids[0])
            if product is None:
                raise DiscoveryError("whole-body proposal state is unavailable")
            add_candidate(
                artifact_id=proposal.artifact_ids[0],
                role=DiscoveryArtifactRole.STATE_CARRIER,
                symbol=proposal.symbol,
                product=product,
            )
            continue
        if proposal.kind is DiscoveryFindingKind.PRIVATE_DONOR:
            product = by_state.get(proposal.state_ids[0])
            if product is None:
                raise DiscoveryError("private-donor proposal state is unavailable")
            add_candidate(
                artifact_id=proposal.artifact_ids[0],
                role=DiscoveryArtifactRole.PRIVATE_DONOR,
                symbol=proposal.symbol,
                product=product,
            )
            continue
        donor_ids: set[str] = set()
        for item in proposal.ranges:
            product = by_cell.get(item.donor_cell_id)
            if product is None:
                raise DiscoveryError("mosaic proposal donor cell is unavailable")
            artifact_id = _artifact_id(
                item.donor_cell_id,
                "mosaic-donor",
                proposal.symbol,
            )
            donor_ids.add(artifact_id)
            add_candidate(
                artifact_id=artifact_id,
                role=DiscoveryArtifactRole.MOSAIC_DONOR,
                symbol=proposal.symbol,
                product=product,
            )
        seed_ids = set(proposal.artifact_ids) - donor_ids
        seed_bytes = seed_objects.get(proposal.symbol)
        if len(seed_ids) != 1 or seed_bytes is None:
            raise DiscoveryError("mosaic proposal seed artifact is unresolved")
        seed_id = next(iter(seed_ids))
        seed_payload = DiscoveryArtifactPayload(
            artifact_id=seed_id,
            role=DiscoveryArtifactRole.MOSAIC_SEED,
            symbol=proposal.symbol,
            object_bytes=seed_bytes,
        )
        prior = payloads.setdefault(seed_id, seed_payload)
        if prior != seed_payload:
            raise DiscoveryError(f"proposal artifact has conflicting sources: {seed_id}")

    expected = {
        artifact_id for proposal in proposals for artifact_id in proposal.artifact_ids
    }
    if set(payloads) != expected:
        raise DiscoveryError("proposal artifact export is incomplete")
    return tuple(sorted(payloads.values(), key=lambda item: item.artifact_id))


def analyze_msvc_discovery_products(
    *,
    references: Mapping[str, MsvcFunctionReference],
    seed_objects: Mapping[str, bytes],
    campaign_id: str,
    plan: DiscoveryPlan,
    products: Sequence[DiscoveryProduct],
) -> tuple[DiscoveryProposal, ...]:
    """Qualify bounded whole-body, private-donor, and mosaic proposals."""

    selected_symbols = plan.symbols or tuple(references)
    missing = sorted(set(selected_symbols) - set(references))
    if missing:
        raise DiscoveryError(
            "discovery plan names symbols without sealed references: "
            + ", ".join(missing)
        )
    ordered_products = tuple(
        sorted(
            products,
            key=lambda item: (
                canonical_json(item.state),
                item.observation.cell_id,
            ),
        )
    )
    mosaic_budget = _MosaicBudget(plan.mosaic.max_search_steps)
    analyses: dict[str, _SymbolAnalysis] = {}
    for symbol in selected_symbols:
        declared_reference = references[symbol]
        reference = _resolve_reference(declared_reference)
        seed_payload = seed_objects.get(symbol)
        seed_coff: CoffObject | None = None
        seed_index: CoffMetadataIndex | None = None
        seed_record: _FunctionRecord | None = None
        seed_normalized: bytes | None = None
        reference_normalized: bytes | None = None
        if seed_payload is not None:
            seed_coff = _parse_coff(seed_payload, f"seed {symbol}")
            seed_index = CoffMetadataIndex(seed_coff)
            seed_record = _unique_isolated_function(
                seed_coff,
                symbol,
                f"seed {symbol}",
                seed_index,
            )
            if seed_record is None:
                raise DiscoveryError(f"seed object omits isolated COMDAT {symbol!r}")
            seed_normalized, reference_normalized = _compare_reference(
                reference,
                seed_coff,
                seed_record,
                f"seed {symbol}",
                seed_index,
            )
            if seed_normalized == reference_normalized:
                # The admitted seed already has the sealed body; proposing
                # a carrier or donor would be a misleading no-op.
                continue
        mismatch = (
            frozenset(
                index
                for index, (seed_byte, reference_byte) in enumerate(
                    zip(seed_normalized, reference_normalized, strict=True)
                )
                if seed_byte != reference_byte
            )
            if seed_normalized is not None and reference_normalized is not None
            else frozenset()
        )
        seed_boundaries: frozenset[int] | None = None
        reference_boundaries: frozenset[int] | None = None
        if (
            plan.mosaic.enabled
            and seed_normalized is not None
            and reference_normalized is not None
            and mismatch
            and len(reference_normalized) <= _MAX_MOSAIC_BODY_BYTES
        ):
            try:
                seed_boundaries = frozenset(
                    _instruction_boundaries(seed_normalized, f"seed {symbol}")
                )
                reference_boundaries = frozenset(
                    _instruction_boundaries(reference_normalized, f"reference {symbol}")
                )
            except DiscoveryError:
                seed_boundaries = None
                reference_boundaries = None
        analyses[symbol] = _SymbolAnalysis(
            declared_reference,
            reference,
            seed_coff,
            seed_index,
            seed_record,
            seed_normalized,
            reference_normalized,
            mismatch,
            seed_boundaries,
            reference_boundaries,
        )

    # Parse each compiler object at most once, then update every relevant
    # symbol's bounded candidate set from that one object-wide index.
    for product in ordered_products:
        relevant = {
            item.symbol
            for item in product.observation.functions
            if item.symbol in analyses
            and item.section_offset == 0
            and item.comdat_selection not in {0, 5}
            and item.body_size == len(analyses[item.symbol].declared_reference.body)
        }
        if not relevant:
            continue
        coff = _parse_coff(
            product.object_path.read_bytes(),
            f"discovery cell {product.observation.cell_id}",
        )
        coff_index = CoffMetadataIndex(coff)
        records_by_symbol: dict[str, list[_FunctionRecord]] = {}
        for record in _function_records(coff, coff_index):
            if record.symbol in relevant and record.isolated_primary:
                records_by_symbol.setdefault(record.symbol, []).append(record)

        for symbol in sorted(relevant, key=str.casefold):
            analysis = analyses[symbol]
            if analysis.whole_exact is not None and (
                analysis.seed_coff is None or analysis.private_exact is not None
            ):
                continue
            observations = [
                item
                for item in product.observation.functions
                if item.symbol == symbol
                and item.section_offset == 0
                and item.comdat_selection not in {0, 5}
                and item.body_size == len(analysis.declared_reference.body)
            ]
            if not observations:
                continue
            if len(observations) > 1:
                raise DiscoveryError(
                    f"discovery cell {product.observation.cell_id} has ambiguous "
                    f"definitions of {symbol!r}"
                )
            records = records_by_symbol.get(symbol, [])
            if len(records) > 1:
                raise DiscoveryError(
                    f"discovery cell {product.observation.cell_id} has ambiguous "
                    f"isolated COMDATs for {symbol!r}"
                )
            if not records:
                continue
            record = records[0]
            try:
                candidate_body, normalized_reference = _compare_reference(
                    analysis.reference,
                    coff,
                    record,
                    f"candidate {product.observation.cell_id}/{symbol}",
                    coff_index,
                )
            except DiscoveryError:
                continue
            if candidate_body == normalized_reference:
                if analysis.whole_exact is None:
                    analysis.whole_exact = (product, coff, record)
                if analysis.seed_coff is not None and analysis.seed_record is not None:
                    try:
                        _require_structural_pair(
                            analysis.seed_coff,
                            analysis.seed_record,
                            coff,
                            record,
                            f"private donor {product.observation.cell_id}/{symbol}",
                            left_index=analysis.seed_index,
                            right_index=coff_index,
                        )
                    except DiscoveryError:
                        pass
                    else:
                        if analysis.private_exact is None:
                            analysis.private_exact = (product, coff, record)
                continue
            if analysis.whole_exact is not None:
                continue
            if (
                not plan.mosaic.enabled
                or analysis.seed_coff is None
                or analysis.seed_record is None
                or analysis.seed_normalized is None
                or analysis.reference_normalized is None
                or analysis.seed_instruction_boundaries is None
                or analysis.reference_instruction_boundaries is None
                or not analysis.mismatch
                or len(analysis.reference_normalized) > _MAX_MOSAIC_BODY_BYTES
            ):
                continue
            mosaic_budget.spend("qualifying donor candidates")
            try:
                _require_structural_pair(
                    analysis.seed_coff,
                    analysis.seed_record,
                    coff,
                    record,
                    f"mosaic donor {product.observation.cell_id}/{symbol}",
                    left_index=analysis.seed_index,
                    right_index=coff_index,
                )
            except DiscoveryError:
                continue
            spans = tuple(
                sorted(
                    set(
                        _relocation_spans(
                            analysis.seed_coff,
                            analysis.seed_record,
                            analysis.seed_index,
                        )
                    )
                    | set(_relocation_spans(coff, record, coff_index))
                )
            )
            ranges = _mosaic_ranges_for_donor(
                product=product,
                seed_body=analysis.seed_normalized,
                donor_body=candidate_body,
                reference_body=analysis.reference_normalized,
                seed_boundaries=analysis.seed_instruction_boundaries,
                reference_boundaries=analysis.reference_instruction_boundaries,
                relocation_spans=spans,
                mismatch=analysis.mismatch,
            )
            if ranges:
                analysis.donor_candidates.append(
                    _DonorCandidate(
                        product,
                        candidate_body,
                        ranges,
                        frozenset().union(*(item.coverage for item in ranges)),
                    )
                )
                analysis.donor_candidates.sort(
                    key=lambda item: (
                        -len(item.coverage),
                        len(item.ranges),
                        canonical_json(item.product.state),
                        item.product.observation.cell_id,
                    )
                )
                del analysis.donor_candidates[
                    plan.mosaic.max_candidates_per_symbol :
                ]

    proposals: list[DiscoveryProposal] = []
    for symbol in selected_symbols:
        selected_analysis = analyses.get(symbol)
        if selected_analysis is None:
            continue
        if selected_analysis.whole_exact is not None:
            product, _candidate_coff, _candidate_record = (
                selected_analysis.whole_exact
            )
            proposals.append(
                _whole_proposal(
                    campaign_id=campaign_id,
                    plan=plan,
                    symbol=symbol,
                    reference=selected_analysis.declared_reference,
                    product=product,
                )
            )
            if selected_analysis.private_exact is not None:
                private_product, _private_coff, _private_record = (
                    selected_analysis.private_exact
                )
                proposals.append(
                    _private_donor_proposal(
                        campaign_id=campaign_id,
                        plan=plan,
                        symbol=symbol,
                        reference=selected_analysis.declared_reference,
                        product=private_product,
                    )
                )
            continue

        if (
            not plan.mosaic.enabled
            or selected_analysis.seed_normalized is None
            or selected_analysis.reference_normalized is None
            or not selected_analysis.mismatch
        ):
            continue
        selected_analysis.donor_candidates.sort(
            key=lambda item: (
                -len(item.coverage),
                len(item.ranges),
                canonical_json(item.product.state),
                item.product.observation.cell_id,
            )
        )
        donor_candidates = selected_analysis.donor_candidates[
            : plan.mosaic.max_candidates_per_symbol
        ]
        selected: tuple[_RangeCandidate, ...] | None = None
        for donor_count in range(1, plan.mosaic.max_donors + 1):
            for donors in combinations(donor_candidates, donor_count):
                mosaic_budget.spend("combining donor candidates")
                if (
                    frozenset().union(*(item.coverage for item in donors))
                    != selected_analysis.mismatch
                ):
                    continue
                found = _select_ranges(
                    donors,
                    selected_analysis.mismatch,
                    plan.mosaic.max_ranges,
                    mosaic_budget,
                )
                if found is None:
                    continue
                if selected is None or (
                    len(found),
                    sum(item.end - item.start for item in found),
                    tuple(item.product.observation.cell_id for item in found),
                ) < (
                    len(selected),
                    sum(item.end - item.start for item in selected),
                    tuple(item.product.observation.cell_id for item in selected),
                ):
                    selected = found
            if selected is not None:
                break
        if selected is None:
            continue
        composed = bytearray(selected_analysis.seed_normalized)
        for item in selected:
            composed[item.start : item.end] = item.donor_body[item.start : item.end]
        if bytes(composed) != selected_analysis.reference_normalized:
            raise DiscoveryError("selected mosaic ranges do not reproduce the reference")
        proposals.append(
            _mosaic_proposal(
                campaign_id=campaign_id,
                plan=plan,
                symbol=symbol,
                reference=selected_analysis.declared_reference,
                seed_body=(
                    selected_analysis.seed_record.body
                    if selected_analysis.seed_record is not None
                    else selected_analysis.seed_normalized
                ),
                ranges=selected,
            )
        )

    return tuple(sorted(proposals, key=lambda item: item.finding_id))

__all__ = [
    "MsvcFunctionReference",
    "analyze_msvc_discovery_products",
    "build_msvc_discovery_artifacts",
    "msvc_analysis_authority_digest",
    "msvc_discovery_analysis_implementation_digest",
    "observe_msvc_discovery_object",
]
