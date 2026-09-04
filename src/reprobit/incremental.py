"""Non-certifying authority and key material for incremental developer builds.

This module never writes committed source, build-plan, intervention, or proof
documents.  It constructs an invocation-local view of current admitted files
so an ordinary edit can be built without pretending that reviewed evidence is
still current.  Certification continues to load the committed authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from reprobit.cache import cache_key
from reprobit.developer_authority import IncrementalAuthorityError
from reprobit.implementation import (
    rehash_scoped_package_import_closure,
    scoped_package_import_closure_receipt,
)
from reprobit.model import Digest
from reprobit.strict_json import JsonValue

_PRODUCER_IMPLEMENTATION_ROOTS = ("reprobit.classic_incremental_execution",)
PRODUCER_CACHE_IMPLEMENTATION_FAMILY = "classic-producer-graph-"
(
    _INITIAL_PRODUCER_IMPLEMENTATION_DIGEST,
    _PRODUCER_IMPLEMENTATION_PATHS,
    _PRODUCER_IMPLEMENTATION_UNRESOLVED_IMPORTS,
) = scoped_package_import_closure_receipt(_PRODUCER_IMPLEMENTATION_ROOTS)


def producer_implementation_digest() -> Digest:
    """Identify only code that can affect warm producer outputs and receipts."""

    return rehash_scoped_package_import_closure(
        _PRODUCER_IMPLEMENTATION_ROOTS,
        _PRODUCER_IMPLEMENTATION_PATHS,
        _PRODUCER_IMPLEMENTATION_UNRESOLVED_IMPORTS,
    )


def revalidate_producer_implementation(expected: Digest) -> None:
    """Fail if output-affecting warm-build code changes during an invocation."""

    if producer_implementation_digest() != expected:
        raise RuntimeError(
            "ReproBit incremental producer implementation changed during execution; rerun the build"
        )


def producer_cache_implementation(
    implementation_digest: Digest | None = None,
) -> str:
    """Bind the cache namespace to output-affecting warm-build code."""

    digest = implementation_digest or producer_implementation_digest()
    return f"{PRODUCER_CACHE_IMPLEMENTATION_FAMILY}v1-{digest.value}"


PRODUCER_IMPLEMENTATION_DIGEST = _INITIAL_PRODUCER_IMPLEMENTATION_DIGEST
PRODUCER_CACHE_IMPLEMENTATION = producer_cache_implementation(PRODUCER_IMPLEMENTATION_DIGEST)


@dataclass(frozen=True, slots=True)
class IncrementalBuildSummary:
    """Stable cache outcome counts for CLI and NDJSON reporting."""

    producer_hits: int
    producer_misses: int
    transform_hits: int
    transform_misses: int
    elapsed_seconds: float
    runtime_init_count: int = 0
    invalidations: tuple[tuple[str, str], ...] = ()
    published_targets: int = 0
    unchanged_targets: int = 0
    published_comparison_pairs: int = 0
    unchanged_comparison_pairs: int = 0

    def __post_init__(self) -> None:
        counts = (
            self.producer_hits,
            self.producer_misses,
            self.transform_hits,
            self.transform_misses,
        )
        if any(item < 0 for item in counts) or self.elapsed_seconds < 0:
            raise ValueError("incremental summary counts and timing cannot be negative")
        if self.runtime_init_count not in {0, 1}:
            raise ValueError("incremental runtime initialization count must be zero or one")
        if any(
            item < 0
            for item in (
                self.published_targets,
                self.unchanged_targets,
                self.published_comparison_pairs,
                self.unchanged_comparison_pairs,
            )
        ):
            raise ValueError("incremental publication counts cannot be negative")
        if self.invalidations != tuple(
            sorted(self.invalidations, key=lambda item: item[0].casefold())
        ) or len({item[0] for item in self.invalidations}) != len(self.invalidations):
            raise ValueError("incremental invalidations must be unique and canonical")

    @property
    def hits(self) -> int:
        return self.producer_hits + self.transform_hits

    @property
    def misses(self) -> int:
        return self.producer_misses + self.transform_misses

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 1.0


def producer_cache_key(material: dict[str, JsonValue]) -> str:
    """Hash a producer key after requiring its complete dependency field set."""

    required = {
        "graph",
        "node",
        "role",
        "toolchain",
        "runtime",
        "argv",
        "cwd",
        "environment",
        "path_profile",
        "direct_inputs",
        "producer_dependencies",
        "recursive_reads",
        "overlay_inputs",
        "generated_inputs",
        "donor_inputs",
        "composition_inputs",
        "transform_inputs",
    }
    missing = required - set(material)
    extra = set(material) - required
    if missing or extra:
        raise IncrementalAuthorityError(
            f"producer cache key material field mismatch; missing={sorted(missing)}, "
            f"extra={sorted(extra)}"
        )
    # cache_key canonicalizes the complete envelope and therefore also
    # validates every nested material value.  Avoid canonicalizing material a
    # second time here: large producer graphs call this once per node.
    return cache_key(
        "producer",
        material,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )


__all__ = [
    "PRODUCER_CACHE_IMPLEMENTATION",
    "PRODUCER_CACHE_IMPLEMENTATION_FAMILY",
    "PRODUCER_IMPLEMENTATION_DIGEST",
    "IncrementalBuildSummary",
    "producer_cache_implementation",
    "producer_cache_key",
    "producer_implementation_digest",
    "revalidate_producer_implementation",
]
