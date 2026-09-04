"""Bounded IA-32 range discovery and deterministic donor selection."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations, pairwise

from reprobit.binary import ByteIdentityError
from reprobit.discovery_contracts import DiscoveryError, DiscoveryProduct
from reprobit.ia32_decode import supported_ia32_instruction_length
from reprobit.strict_json import canonical_json

_MAX_MOSAIC_RANGES_PER_DONOR = 256


@dataclass(frozen=True, slots=True)
class MosaicRangeCandidate:
    product: DiscoveryProduct | None
    start: int
    end: int
    coverage: frozenset[int]
    seed_lengths: tuple[int, ...]
    donor_lengths: tuple[int, ...]
    donor_body: bytes
    candidate_id: str | None = None


@dataclass(frozen=True, slots=True)
class MosaicDonorCandidate:
    product: DiscoveryProduct | None
    body: bytes
    ranges: tuple[MosaicRangeCandidate, ...]
    coverage: frozenset[int]
    candidate_id: str | None = None


@dataclass(slots=True)
class MosaicSearchBudget:
    limit: int
    used: int = 0

    def spend(self, context: str) -> None:
        self.used += 1
        if self.used > self.limit:
            raise DiscoveryError(
                f"mosaic analysis exceeded max_search_steps {self.limit} while {context}"
            )


def instruction_boundaries(body: bytes, context: str) -> tuple[int, ...]:
    """Return complete supported IA-32 instruction boundaries for one body."""

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
    boundaries = instruction_boundaries(body[start:end], context)
    return tuple(right - left for left, right in pairwise(boundaries))


def _overlaps_excluded_span(
    start: int,
    end: int,
    spans: Sequence[tuple[int, int]],
) -> bool:
    return any(start < right and left < end for left, right in spans)


def mosaic_ranges_for_donor(
    *,
    product: DiscoveryProduct | None,
    seed_body: bytes,
    donor_body: bytes,
    reference_body: bytes,
    seed_boundaries: frozenset[int],
    reference_boundaries: frozenset[int],
    excluded_spans: Sequence[tuple[int, int]],
    mismatch: frozenset[int],
    candidate_id: str | None = None,
) -> tuple[MosaicRangeCandidate, ...]:
    """Find bounded donor ranges aligned across seed, donor, and reference.

    Callers may exclude semantic windows that their eventual composer cannot
    import. Relocation operands need not be excluded when an earlier structural
    gate and the ordinary composer both prove them unchanged.
    """

    if (product is None) == (candidate_id is None):
        raise DiscoveryError("mosaic donor requires exactly one candidate identity")
    if candidate_id is not None:
        label = candidate_id
    else:
        assert product is not None
        label = product.observation.cell_id

    try:
        donor_boundaries = set(instruction_boundaries(donor_body, f"{label} donor"))
    except DiscoveryError:
        return ()
    common = sorted(seed_boundaries & donor_boundaries & reference_boundaries)
    atomic: list[tuple[int, int]] = []
    for start, end in pairwise(common):
        if (
            end - start <= 64
            and donor_body[start:end] == reference_body[start:end]
            and seed_body[start:end] != donor_body[start:end]
            and not _overlaps_excluded_span(start, end, excluded_spans)
        ):
            atomic.append((start, end))

    merged: list[tuple[int, int]] = []
    for start, end in atomic:
        if merged and merged[-1][1] == start and end - merged[-1][0] <= 64:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    result: list[MosaicRangeCandidate] = []
    for start, end in merged:
        coverage = frozenset(offset for offset in mismatch if start <= offset < end)
        if not coverage:
            continue
        try:
            seed_lengths = _instruction_lengths(
                seed_body,
                start,
                end,
                f"{label} seed range",
            )
            donor_lengths = _instruction_lengths(
                donor_body,
                start,
                end,
                f"{label} donor range",
            )
        except DiscoveryError:
            continue
        result.append(
            MosaicRangeCandidate(
                product,
                start,
                end,
                coverage,
                seed_lengths,
                donor_lengths,
                donor_body,
                candidate_id,
            )
        )
        if len(result) > _MAX_MOSAIC_RANGES_PER_DONOR:
            return ()
    return tuple(result)


def ranked_mosaic_donors(
    donors: Sequence[MosaicDonorCandidate],
    limit: int,
) -> tuple[MosaicDonorCandidate, ...]:
    """Return the deterministic retained donor prefix."""

    return tuple(
        sorted(
            donors,
            key=lambda item: (
                -len(item.coverage),
                len(item.ranges),
                canonical_json(item.product.state) if item.product is not None else b"",
                mosaic_donor_id(item),
            ),
        )[:limit]
    )


def mosaic_range_donor_id(item: MosaicRangeCandidate) -> str:
    """Return the stable identity shared by discovery and repair candidates."""

    if item.candidate_id is not None:
        return item.candidate_id
    if item.product is None:
        raise DiscoveryError("mosaic range has no candidate identity")
    return item.product.observation.cell_id


def mosaic_donor_id(item: MosaicDonorCandidate) -> str:
    """Return the stable identity shared by discovery and repair donors."""

    if item.candidate_id is not None:
        return item.candidate_id
    if item.product is None:
        raise DiscoveryError("mosaic donor has no candidate identity")
    return item.product.observation.cell_id


def _select_ranges(
    donors: Sequence[MosaicDonorCandidate],
    mismatch: frozenset[int],
    max_ranges: int,
    budget: MosaicSearchBudget,
) -> tuple[MosaicRangeCandidate, ...] | None:
    candidates = tuple(
        sorted(
            (item for donor in donors for item in donor.ranges),
            key=lambda item: (
                item.start,
                -(item.end - item.start),
                mosaic_range_donor_id(item),
            ),
        )
    )
    mismatch_order = tuple(sorted(mismatch))
    memo: dict[
        tuple[frozenset[int], int, int],
        tuple[MosaicRangeCandidate, ...] | None,
    ] = {}

    def visit(
        covered: frozenset[int],
        previous_end: int,
        remaining: int,
    ) -> tuple[MosaicRangeCandidate, ...] | None:
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
        best: tuple[MosaicRangeCandidate, ...] | None = None
        for item in options:
            suffix = visit(covered | item.coverage, item.end, remaining - 1)
            if suffix is None:
                continue
            found = (item, *suffix)
            if best is None or _range_selection_score(found) < _range_selection_score(best):
                best = found
        memo[key] = best
        return best

    return visit(frozenset(), 0, max_ranges)


def _range_selection_score(
    ranges: tuple[MosaicRangeCandidate, ...],
) -> tuple[int, int, tuple[str, ...]]:
    return (
        len(ranges),
        sum(item.end - item.start for item in ranges),
        tuple(mosaic_range_donor_id(item) for item in ranges),
    )


def select_mosaic_ranges(
    donors: Sequence[MosaicDonorCandidate],
    mismatch: frozenset[int],
    *,
    max_candidates_per_symbol: int,
    max_donors: int,
    max_ranges: int,
    budget: MosaicSearchBudget,
    required_donor_ids: frozenset[str] = frozenset(),
) -> tuple[MosaicRangeCandidate, ...] | None:
    """Select the cheapest deterministic donor/range combination within bounds."""

    if len(required_donor_ids) > max_candidates_per_symbol:
        return None
    ranked = ranked_mosaic_donors(donors, len(donors))
    required_indices = {
        index for index, item in enumerate(ranked) if mosaic_donor_id(item) in required_donor_ids
    }
    if {mosaic_donor_id(ranked[index]) for index in required_indices} != required_donor_ids or len(
        required_indices
    ) != len(required_donor_ids):
        return None
    optional = (index for index in range(len(ranked)) if index not in required_indices)
    retained_indices = required_indices | set(
        tuple(optional)[: max_candidates_per_symbol - len(required_indices)]
    )
    donor_candidates = tuple(item for index, item in enumerate(ranked) if index in retained_indices)
    required_candidates = tuple(
        item for item in donor_candidates if mosaic_donor_id(item) in required_donor_ids
    )
    optional_candidates = tuple(
        item for item in donor_candidates if mosaic_donor_id(item) not in required_donor_ids
    )
    selected: tuple[MosaicRangeCandidate, ...] | None = None
    for donor_count in range(max(1, len(required_candidates)), max_donors + 1):
        for optional_donors in combinations(
            optional_candidates, donor_count - len(required_candidates)
        ):
            budget.spend("combining donor candidates")
            selected_donors = (*required_candidates, *optional_donors)
            if frozenset().union(*(item.coverage for item in selected_donors)) != mismatch:
                continue
            found = _select_ranges(
                selected_donors,
                mismatch,
                max_ranges,
                budget,
            )
            if found is None:
                continue
            if {mosaic_range_donor_id(item) for item in found} != {
                mosaic_donor_id(item) for item in selected_donors
            }:
                # Every declared classic variant must contribute a range.
                continue
            if selected is None or _range_selection_score(found) < _range_selection_score(selected):
                selected = found
        if selected is not None:
            break
    return selected


__all__ = [
    "MosaicDonorCandidate",
    "MosaicRangeCandidate",
    "MosaicSearchBudget",
    "instruction_boundaries",
    "mosaic_donor_id",
    "mosaic_range_donor_id",
    "mosaic_ranges_for_donor",
    "ranked_mosaic_donors",
    "select_mosaic_ranges",
]
