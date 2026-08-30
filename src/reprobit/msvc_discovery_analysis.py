"""Orchestrate bounded MSVC discovery analysis campaigns."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import reprobit.msvc_discovery_coff as msvc_coff
import reprobit.msvc_discovery_mosaic as mosaic
import reprobit.msvc_discovery_proposals as proposal_builder
from reprobit.coff_format import CoffMetadataIndex, CoffObject
from reprobit.discovery_contracts import (
    DiscoveryError,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryProposal,
    FunctionObservation,
)
from reprobit.implementation import scoped_package_implementation_digest
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

_MAX_MOSAIC_BODY_BYTES = 64 * 1024
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
    "msvc_discovery_coff.py",
    "msvc_discovery_mosaic.py",
    "msvc_discovery_proposals.py",
    "schema.py",
    "strict_json.py",
)


def msvc_discovery_analysis_implementation_digest() -> Digest:
    """Bind observations and proposals to the exact installed analyzer."""

    return scoped_package_implementation_digest(_ANALYSIS_IMPLEMENTATION_PATHS)


@dataclass(slots=True)
class _SymbolAnalysis:
    declared_reference: msvc_coff.MsvcFunctionReference
    reference: msvc_coff.ResolvedMsvcFunctionReference
    seed_coff: CoffObject | None
    seed_index: CoffMetadataIndex | None
    seed_record: msvc_coff.MsvcFunctionRecord | None
    seed_normalized: bytes | None
    reference_normalized: bytes | None
    mismatch: frozenset[int]
    seed_instruction_boundaries: frozenset[int] | None
    reference_instruction_boundaries: frozenset[int] | None
    whole_exact: tuple[DiscoveryProduct, CoffObject, msvc_coff.MsvcFunctionRecord] | None = None
    private_exact: tuple[DiscoveryProduct, CoffObject, msvc_coff.MsvcFunctionRecord] | None = None
    donor_candidates: list[mosaic.MosaicDonorCandidate] = field(default_factory=list)


def msvc_analysis_authority_digest(
    *,
    compile_authority: Digest,
    references: Mapping[str, msvc_coff.MsvcFunctionReference],
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


def _qualifying_observations_by_symbol(
    observations: Sequence[FunctionObservation],
    analyses: Mapping[str, _SymbolAnalysis],
) -> dict[str, tuple[FunctionObservation, ...]]:
    """Index relevant observations in one object-wide pass."""

    indexed: dict[str, list[FunctionObservation]] = {}
    for observation in observations:
        analysis = analyses.get(observation.symbol)
        if (
            analysis is None
            or observation.section_offset != 0
            or observation.comdat_selection in {0, 5}
            or observation.body_size != len(analysis.declared_reference.body)
        ):
            continue
        indexed.setdefault(observation.symbol, []).append(observation)
    return {symbol: tuple(items) for symbol, items in indexed.items()}


def _record_exact_product(
    *,
    product: DiscoveryProduct,
    symbol: str,
    analysis: _SymbolAnalysis,
    coff: CoffObject,
    coff_index: CoffMetadataIndex,
    record: msvc_coff.MsvcFunctionRecord,
) -> None:
    if analysis.whole_exact is None:
        analysis.whole_exact = (product, coff, record)
    if analysis.seed_coff is None or analysis.seed_record is None:
        return
    try:
        msvc_coff.require_msvc_structural_pair(
            analysis.seed_coff,
            analysis.seed_record,
            coff,
            record,
            f"private donor {product.observation.cell_id}/{symbol}",
            left_index=analysis.seed_index,
            right_index=coff_index,
        )
    except DiscoveryError:
        return
    if analysis.private_exact is None:
        analysis.private_exact = (product, coff, record)


def _record_mosaic_product(
    *,
    product: DiscoveryProduct,
    symbol: str,
    analysis: _SymbolAnalysis,
    candidate_body: bytes,
    coff: CoffObject,
    coff_index: CoffMetadataIndex,
    record: msvc_coff.MsvcFunctionRecord,
    plan: DiscoveryPlan,
    mosaic_budget: mosaic.MosaicSearchBudget,
) -> None:
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
        return
    mosaic_budget.spend("qualifying donor candidates")
    try:
        msvc_coff.require_msvc_structural_pair(
            analysis.seed_coff,
            analysis.seed_record,
            coff,
            record,
            f"mosaic donor {product.observation.cell_id}/{symbol}",
            left_index=analysis.seed_index,
            right_index=coff_index,
        )
    except DiscoveryError:
        return
    spans = tuple(
        sorted(
            set(
                msvc_coff.msvc_relocation_spans(
                    analysis.seed_coff,
                    analysis.seed_record,
                    analysis.seed_index,
                )
            )
            | set(msvc_coff.msvc_relocation_spans(coff, record, coff_index))
        )
    )
    ranges = mosaic.mosaic_ranges_for_donor(
        product=product,
        seed_body=analysis.seed_normalized,
        donor_body=candidate_body,
        reference_body=analysis.reference_normalized,
        seed_boundaries=analysis.seed_instruction_boundaries,
        reference_boundaries=analysis.reference_instruction_boundaries,
        relocation_spans=spans,
        mismatch=analysis.mismatch,
    )
    if not ranges:
        return
    analysis.donor_candidates.append(
        mosaic.MosaicDonorCandidate(
            product,
            candidate_body,
            ranges,
            frozenset().union(*(item.coverage for item in ranges)),
        )
    )
    analysis.donor_candidates[:] = mosaic.ranked_mosaic_donors(
        analysis.donor_candidates,
        plan.mosaic.max_candidates_per_symbol,
    )


def _qualify_product_symbol(
    *,
    product: DiscoveryProduct,
    symbol: str,
    analysis: _SymbolAnalysis,
    observations: tuple[FunctionObservation, ...],
    records: Sequence[msvc_coff.MsvcFunctionRecord],
    coff: CoffObject,
    coff_index: CoffMetadataIndex,
    plan: DiscoveryPlan,
    mosaic_budget: mosaic.MosaicSearchBudget,
) -> None:
    """Update one symbol analysis from one already-indexed compiler product."""

    if analysis.whole_exact is not None and (
        analysis.seed_coff is None or analysis.private_exact is not None
    ):
        return
    if len(observations) > 1:
        raise DiscoveryError(
            f"discovery cell {product.observation.cell_id} has ambiguous definitions of {symbol!r}"
        )
    if len(records) > 1:
        raise DiscoveryError(
            f"discovery cell {product.observation.cell_id} has ambiguous "
            f"isolated COMDATs for {symbol!r}"
        )
    if not records:
        return
    record = records[0]
    try:
        candidate_body, normalized_reference = msvc_coff.compare_msvc_reference(
            analysis.reference,
            coff,
            record,
            f"candidate {product.observation.cell_id}/{symbol}",
            coff_index,
        )
    except DiscoveryError:
        return
    if candidate_body == normalized_reference:
        _record_exact_product(
            product=product,
            symbol=symbol,
            analysis=analysis,
            coff=coff,
            coff_index=coff_index,
            record=record,
        )
        return
    if analysis.whole_exact is not None:
        return
    _record_mosaic_product(
        product=product,
        symbol=symbol,
        analysis=analysis,
        candidate_body=candidate_body,
        coff=coff,
        coff_index=coff_index,
        record=record,
        plan=plan,
        mosaic_budget=mosaic_budget,
    )


def _prepare_symbol_analysis(
    *,
    symbol: str,
    declared_reference: msvc_coff.MsvcFunctionReference,
    seed_payload: bytes | None,
    mosaic_enabled: bool,
) -> _SymbolAnalysis | None:
    reference = msvc_coff.resolve_msvc_reference(declared_reference)
    seed_coff: CoffObject | None = None
    seed_index: CoffMetadataIndex | None = None
    seed_record: msvc_coff.MsvcFunctionRecord | None = None
    seed_normalized: bytes | None = None
    reference_normalized: bytes | None = None
    if seed_payload is not None:
        seed_coff = msvc_coff.parse_msvc_coff(seed_payload, f"seed {symbol}")
        seed_index = CoffMetadataIndex(seed_coff)
        seed_record = msvc_coff.unique_isolated_msvc_function(
            seed_coff,
            symbol,
            f"seed {symbol}",
            seed_index,
        )
        if seed_record is None:
            raise DiscoveryError(f"seed object omits isolated COMDAT {symbol!r}")
        seed_normalized, reference_normalized = msvc_coff.compare_msvc_reference(
            reference,
            seed_coff,
            seed_record,
            f"seed {symbol}",
            seed_index,
        )
        if seed_normalized == reference_normalized:
            # The admitted seed already has the sealed body; proposing a carrier
            # or donor would be a misleading no-op.
            return None
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
        mosaic_enabled
        and seed_normalized is not None
        and reference_normalized is not None
        and mismatch
        and len(reference_normalized) <= _MAX_MOSAIC_BODY_BYTES
    ):
        try:
            seed_boundaries = frozenset(
                mosaic.instruction_boundaries(seed_normalized, f"seed {symbol}")
            )
            reference_boundaries = frozenset(
                mosaic.instruction_boundaries(reference_normalized, f"reference {symbol}")
            )
        except DiscoveryError:
            seed_boundaries = None
            reference_boundaries = None
    return _SymbolAnalysis(
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


def _qualify_products(
    *,
    products: Sequence[DiscoveryProduct],
    analyses: Mapping[str, _SymbolAnalysis],
    plan: DiscoveryPlan,
    mosaic_budget: mosaic.MosaicSearchBudget,
) -> None:
    """Parse each compiler object once and update its relevant symbols."""

    for product in products:
        observations_by_symbol = _qualifying_observations_by_symbol(
            product.observation.functions,
            analyses,
        )
        if not observations_by_symbol:
            continue
        coff = msvc_coff.parse_msvc_coff(
            product.object_path.read_bytes(),
            f"discovery cell {product.observation.cell_id}",
        )
        coff_index = CoffMetadataIndex(coff)
        records_by_symbol: dict[str, list[msvc_coff.MsvcFunctionRecord]] = {}
        for record in msvc_coff.msvc_function_records(coff, coff_index):
            if record.symbol in observations_by_symbol and record.isolated_primary:
                records_by_symbol.setdefault(record.symbol, []).append(record)

        for symbol in sorted(observations_by_symbol, key=str.casefold):
            _qualify_product_symbol(
                product=product,
                symbol=symbol,
                analysis=analyses[symbol],
                observations=observations_by_symbol[symbol],
                records=records_by_symbol.get(symbol, ()),
                coff=coff,
                coff_index=coff_index,
                plan=plan,
                mosaic_budget=mosaic_budget,
            )


def _proposals_for_symbol(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    analysis: _SymbolAnalysis,
    mosaic_budget: mosaic.MosaicSearchBudget,
) -> tuple[DiscoveryProposal, ...]:
    if analysis.whole_exact is not None:
        product, _candidate_coff, _candidate_record = analysis.whole_exact
        proposals = [
            proposal_builder.whole_body_proposal(
                campaign_id=campaign_id,
                plan=plan,
                symbol=symbol,
                reference=analysis.declared_reference,
                product=product,
            )
        ]
        if analysis.private_exact is not None:
            private_product, _private_coff, _private_record = analysis.private_exact
            proposals.append(
                proposal_builder.private_donor_proposal(
                    campaign_id=campaign_id,
                    plan=plan,
                    symbol=symbol,
                    reference=analysis.declared_reference,
                    product=private_product,
                )
            )
        return tuple(proposals)

    if (
        not plan.mosaic.enabled
        or analysis.seed_normalized is None
        or analysis.reference_normalized is None
        or not analysis.mismatch
    ):
        return ()
    selected = mosaic.select_mosaic_ranges(
        analysis.donor_candidates,
        analysis.mismatch,
        max_candidates_per_symbol=plan.mosaic.max_candidates_per_symbol,
        max_donors=plan.mosaic.max_donors,
        max_ranges=plan.mosaic.max_ranges,
        budget=mosaic_budget,
    )
    if selected is None:
        return ()
    composed = bytearray(analysis.seed_normalized)
    for item in selected:
        composed[item.start : item.end] = item.donor_body[item.start : item.end]
    if bytes(composed) != analysis.reference_normalized:
        raise DiscoveryError("selected mosaic ranges do not reproduce the reference")
    return (
        proposal_builder.mosaic_proposal(
            campaign_id=campaign_id,
            plan=plan,
            symbol=symbol,
            reference=analysis.declared_reference,
            seed_body=(
                analysis.seed_record.body
                if analysis.seed_record is not None
                else analysis.seed_normalized
            ),
            ranges=selected,
        ),
    )


def analyze_msvc_discovery_products(
    *,
    references: Mapping[str, msvc_coff.MsvcFunctionReference],
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
            "discovery plan names symbols without sealed references: " + ", ".join(missing)
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
    mosaic_budget = mosaic.MosaicSearchBudget(plan.mosaic.max_search_steps)
    analyses: dict[str, _SymbolAnalysis] = {}
    for symbol in selected_symbols:
        analysis = _prepare_symbol_analysis(
            symbol=symbol,
            declared_reference=references[symbol],
            seed_payload=seed_objects.get(symbol),
            mosaic_enabled=plan.mosaic.enabled,
        )
        if analysis is not None:
            analyses[symbol] = analysis

    _qualify_products(
        products=ordered_products,
        analyses=analyses,
        plan=plan,
        mosaic_budget=mosaic_budget,
    )

    proposals: list[DiscoveryProposal] = []
    for symbol in selected_symbols:
        analysis = analyses.get(symbol)
        if analysis is None:
            continue
        proposals.extend(
            _proposals_for_symbol(
                campaign_id=campaign_id,
                plan=plan,
                symbol=symbol,
                analysis=analysis,
                mosaic_budget=mosaic_budget,
            )
        )

    return tuple(sorted(proposals, key=lambda item: item.finding_id))


__all__ = [
    "analyze_msvc_discovery_products",
    "msvc_analysis_authority_digest",
    "msvc_discovery_analysis_implementation_digest",
]
