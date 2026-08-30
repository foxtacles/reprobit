"""Bounded IA-32 range discovery and deterministic donor selection."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations, pairwise

from reprobit.binary import ByteIdentityError
from reprobit.discovery_contracts import DiscoveryError, DiscoveryProduct
from reprobit.ia32 import supported_ia32_instruction_length
from reprobit.strict_json import canonical_json

_MAX_MOSAIC_RANGES_PER_DONOR = 256


@dataclass(frozen=True, slots=True)
class MosaicRangeCandidate:
    product: DiscoveryProduct
    start: int
    end: int
    coverage: frozenset[int]
    seed_lengths: tuple[int, ...]
    donor_lengths: tuple[int, ...]
    donor_body: bytes


@dataclass(frozen=True, slots=True)
class MosaicDonorCandidate:
    product: DiscoveryProduct
    body: bytes
    ranges: tuple[MosaicRangeCandidate, ...]
    coverage: frozenset[int]


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


def _overlaps_relocation(
    start: int,
    end: int,
    spans: Sequence[tuple[int, int]],
) -> bool:
    return any(start < right and left < end for left, right in spans)


def mosaic_ranges_for_donor(
    *,
    product: DiscoveryProduct,
    seed_body: bytes,
    donor_body: bytes,
    reference_body: bytes,
    seed_boundaries: frozenset[int],
    reference_boundaries: frozenset[int],
    relocation_spans: Sequence[tuple[int, int]],
    mismatch: frozenset[int],
) -> tuple[MosaicRangeCandidate, ...]:
    """Find bounded donor ranges aligned across seed, donor, and reference."""

    try:
        donor_boundaries = set(
            instruction_boundaries(donor_body, f"{product.observation.cell_id} donor")
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
            MosaicRangeCandidate(
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
                canonical_json(item.product.state),
                item.product.observation.cell_id,
            ),
        )[:limit]
    )


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
                item.product.observation.cell_id,
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
        tuple(item.product.observation.cell_id for item in ranges),
    )


def select_mosaic_ranges(
    donors: Sequence[MosaicDonorCandidate],
    mismatch: frozenset[int],
    *,
    max_candidates_per_symbol: int,
    max_donors: int,
    max_ranges: int,
    budget: MosaicSearchBudget,
) -> tuple[MosaicRangeCandidate, ...] | None:
    """Select the cheapest deterministic donor/range combination within bounds."""

    donor_candidates = ranked_mosaic_donors(donors, max_candidates_per_symbol)
    selected: tuple[MosaicRangeCandidate, ...] | None = None
    for donor_count in range(1, max_donors + 1):
        for selected_donors in combinations(donor_candidates, donor_count):
            budget.spend("combining donor candidates")
            if frozenset().union(*(item.coverage for item in selected_donors)) != mismatch:
                continue
            found = _select_ranges(
                selected_donors,
                mismatch,
                max_ranges,
                budget,
            )
            if found is not None and (
                selected is None or _range_selection_score(found) < _range_selection_score(selected)
            ):
                selected = found
        if selected is not None:
            break
    return selected


__all__ = [
    "MosaicDonorCandidate",
    "MosaicRangeCandidate",
    "MosaicSearchBudget",
    "instruction_boundaries",
    "mosaic_ranges_for_donor",
    "ranked_mosaic_donors",
    "select_mosaic_ranges",
]
