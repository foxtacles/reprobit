"""Conservative VC4.x dependency hints for non-certifying warm builds.

The compiler replay represented here is only a cache invalidation hint.  It is
never exposed as producer provenance.  A malformed trace, changed search
result, ambiguity, or missing authority produces a miss; cold verification
does not import or call this module.
"""

from __future__ import annotations

import ntpath
from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType

from reprobit.cache import CacheLease, CacheRecord, cache_key
from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    MsvcSbrSource,
    MsvcSbrTrace,
    ResolvedInclude,
    SealedIncludeAuthority,
    SealedIncludeIndex,
    index_sealed_include_authority,
    resolve_msvc_include_trace,
)
from reprobit.incremental import (
    PRODUCER_CACHE_IMPLEMENTATION,
    IncrementalAuthorityError,
    producer_cache_key,
)
from reprobit.strict_json import JsonValue, canonical_json


class ClassicCacheHintError(ValueError):
    """A non-certifying compiler dependency hint is malformed."""


def _source_topology_json(sources: tuple[MsvcSbrSource, ...]) -> list[JsonValue]:
    return [
        {
            "raw_path": item.raw_path,
            "parent_index": item.parent_index,
        }
        for item in sources
    ]


def _parse_source_topology(value: object, *, label: str) -> tuple[MsvcSbrSource, ...]:
    if not isinstance(value, list) or not value:
        raise ClassicCacheHintError(f"{label} source topology is invalid")
    parsed: list[MsvcSbrSource] = []
    for index, source in enumerate(value):
        if not isinstance(source, dict) or set(source) != {
            "raw_path",
            "parent_index",
        }:
            raise ClassicCacheHintError(f"{label} source is malformed")
        raw_path = source["raw_path"]
        parent_index = source["parent_index"]
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or "\x00" in raw_path
            or (
                parent_index is not None
                and (
                    not isinstance(parent_index, int)
                    or isinstance(parent_index, bool)
                    or not 0 <= parent_index < index
                )
            )
        ):
            raise ClassicCacheHintError(f"{label} source fields are invalid")
        parsed.append(MsvcSbrSource(raw_path, parent_index))
    return tuple(parsed)


@dataclass(frozen=True, slots=True)
class CompilerDependencyHint:
    """Raw SBR path/parent topology from one discarded diagnostic replay."""

    base_key: str
    working_directory: str
    sources: tuple[MsvcSbrSource, ...]

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "schema": 1,
            "base_key": self.base_key,
            "working_directory": self.working_directory,
            "sources": _source_topology_json(self.sources),
            "certifying": False,
        }

    @classmethod
    def from_record(cls, record: CacheRecord) -> CompilerDependencyHint:
        raw = record.metadata.get("compiler_dependency_hint")
        if not isinstance(raw, dict) or set(raw) != {
            "schema",
            "base_key",
            "working_directory",
            "sources",
            "certifying",
        }:
            raise ClassicCacheHintError("compiler cache record has no valid hint")
        base_key = raw["base_key"]
        working_directory = raw["working_directory"]
        sources = raw["sources"]
        if (
            raw["schema"] != 1
            or raw["certifying"] is not False
            or not isinstance(base_key, str)
            or len(base_key) != 64
            or any(character not in "0123456789abcdef" for character in base_key)
            or not isinstance(working_directory, str)
            or not working_directory
        ):
            raise ClassicCacheHintError("compiler dependency hint identity is invalid")
        parsed = _parse_source_topology(sources, label="compiler dependency hint")
        return cls(base_key, working_directory, parsed)


@dataclass(frozen=True, slots=True)
class CompilerCacheProbe:
    """One current-authority lookup result or conservative miss."""

    key: str | None
    record: CacheRecord | None
    reads: tuple[ResolvedInclude, ...]
    hint: CompilerDependencyHint | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class DonorDependencyTrace:
    """Raw SBR topology from one projected donor's discarded replay."""

    donor_id: str
    working_directory: str
    sources: tuple[MsvcSbrSource, ...]


@dataclass(frozen=True, slots=True)
class DonorTransformDependencyHint:
    """Complete projected-donor trace set for one transformed compiler node."""

    base_key: str
    donors: tuple[DonorDependencyTrace, ...]

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "schema": 1,
            "base_key": self.base_key,
            "donors": [
                {
                    "donor_id": donor.donor_id,
                    "working_directory": donor.working_directory,
                    "sources": _source_topology_json(donor.sources),
                }
                for donor in self.donors
            ],
            "certifying": False,
        }

    @classmethod
    def from_record(cls, record: CacheRecord) -> DonorTransformDependencyHint:
        raw = record.metadata.get("donor_transform_dependency_hint")
        if not isinstance(raw, dict) or set(raw) != {
            "schema",
            "base_key",
            "donors",
            "certifying",
        }:
            raise ClassicCacheHintError("donor-transform cache record has no valid hint")
        base_key = raw["base_key"]
        donors = raw["donors"]
        if (
            raw["schema"] != 1
            or raw["certifying"] is not False
            or not isinstance(base_key, str)
            or len(base_key) != 64
            or any(character not in "0123456789abcdef" for character in base_key)
            or not isinstance(donors, list)
            or not donors
        ):
            raise ClassicCacheHintError("donor-transform dependency hint identity is invalid")
        parsed_donors: list[DonorDependencyTrace] = []
        for donor in donors:
            if not isinstance(donor, dict) or set(donor) != {
                "donor_id",
                "working_directory",
                "sources",
            }:
                raise ClassicCacheHintError("donor-transform dependency hint donor is malformed")
            donor_id = donor["donor_id"]
            working_directory = donor["working_directory"]
            sources = donor["sources"]
            if (
                not isinstance(donor_id, str)
                or not donor_id
                or "\x00" in donor_id
                or not isinstance(working_directory, str)
                or not working_directory
            ):
                raise ClassicCacheHintError(
                    "donor-transform dependency hint donor identity is invalid"
                )
            parsed_sources = _parse_source_topology(
                sources,
                label="donor-transform dependency hint",
            )
            parsed_donors.append(
                DonorDependencyTrace(
                    donor_id,
                    working_directory,
                    parsed_sources,
                )
            )
        result = cls(base_key, tuple(parsed_donors))
        _require_canonical_donor_ids(item.donor_id for item in result.donors)
        return result


@dataclass(frozen=True, slots=True)
class DonorDependencyResolutionContext:
    """Current invocation and sealed namespace for one projected donor."""

    donor_id: str
    expected_working_directory: str
    expected_source: str
    include_directories: tuple[str, ...]
    environment_directories: tuple[str, ...]
    force_includes: tuple[str, ...]
    authority: SealedIncludeAuthority
    mirrored_sources: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class DonorResolvedDependencies:
    """One donor's trace resolved against the current projected namespace."""

    donor_id: str
    reads: tuple[ResolvedInclude, ...]


@dataclass(frozen=True, slots=True)
class DonorTransformCacheProbe:
    """One current-authority projected-transform lookup or conservative miss."""

    key: str | None
    record: CacheRecord | None
    dependencies: tuple[DonorResolvedDependencies, ...]
    hint: DonorTransformDependencyHint | None
    reason: str | None


def _require_canonical_donor_ids(values: Iterable[str]) -> tuple[str, ...]:
    donor_ids = tuple(values)
    if (
        not donor_ids
        or any(not item or "\x00" in item for item in donor_ids)
        or len({item.casefold() for item in donor_ids}) != len(donor_ids)
        or tuple(sorted(donor_ids, key=str.casefold)) != donor_ids
    ):
        raise ClassicCacheHintError("projected donor dependency IDs are not unique and canonical")
    return donor_ids


def compiler_base_key(material: dict[str, JsonValue]) -> str:
    """Hash every non-recursive producer dependency for hint indexing."""

    if material.get("recursive_reads") != []:
        raise IncrementalAuthorityError("compiler base key requires an empty recursive-read field")
    producer_cache_key(material)
    return cache_key(
        "compiler-base",
        material,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )


def _resolved_material(reads: tuple[ResolvedInclude, ...]) -> list[JsonValue]:
    return [
        {
            "raw_path": item.raw_path,
            "logical_path": item.logical_path,
            "digest": item.digest.value,
            "size": item.size,
            "origin": item.origin.value,
            "parent_index": item.parent_index,
        }
        for item in reads
    ]


def compiler_final_key(
    base_material: dict[str, JsonValue],
    reads: tuple[ResolvedInclude, ...],
) -> str:
    """Bind the re-resolved complete recursive read set into a producer key."""

    material = dict(base_material)
    material["recursive_reads"] = _resolved_material(reads)
    return producer_cache_key(material)


def probe_compiler_cache(
    lease: CacheLease,
    *,
    base_key: str,
    base_material: dict[str, JsonValue],
    expected_working_directory: str,
    expected_source: str,
    include_directories: tuple[str, ...],
    environment_directories: tuple[str, ...],
    force_includes: tuple[str, ...],
    authority: SealedIncludeAuthority,
) -> CompilerCacheProbe:
    """Re-resolve a bounded candidate hint set and return only an exact hit."""

    candidate_keys = lease.indexed_record_keys("producer", "compiler-base", base_key)
    if not candidate_keys:
        return CompilerCacheProbe(None, None, (), None, "no prior dependency hint")
    authority_index = index_sealed_include_authority(authority)
    failures: list[str] = []
    best_miss: CompilerCacheProbe | None = None
    for candidate_key in candidate_keys:
        record = lease.lookup("producer", candidate_key)
        if record is None:
            continue
        try:
            hint = CompilerDependencyHint.from_record(record)
            if hint.base_key != base_key:
                raise ClassicCacheHintError("compiler hint base key differs")
            reads = resolve_msvc_include_trace(
                MsvcSbrTrace(hint.working_directory, hint.sources),
                expected_working_directory=expected_working_directory,
                expected_source=expected_source,
                include_directories=include_directories,
                environment_directories=environment_directories,
                force_includes=force_includes,
                authority=authority,
                authority_index=authority_index,
            )
            key = compiler_final_key(base_material, reads)
        except (ClassicCacheHintError, ClassicIncludeTraceError) as exc:
            failures.append(str(exc))
            continue
        # The selected candidate has already passed record/blob validation;
        # reuse it directly when the current recursive key agrees.  Otherwise
        # resolve the recomputed exact key, which also preserves A→B→A reuse
        # even when the matching record appears later in bounded history.
        exact = record if record.key == key else lease.lookup("producer", key)
        if exact is not None:
            return CompilerCacheProbe(key, exact, reads, hint, None)
        if best_miss is None:
            best_miss = CompilerCacheProbe(
                key,
                None,
                reads,
                hint,
                "recursive dependency content changed",
            )
    if best_miss is not None:
        return best_miss
    reason = failures[0] if failures else "dependency hints were unusable"
    return CompilerCacheProbe(None, None, (), None, reason)


def compiler_hint_metadata(
    hint: CompilerDependencyHint,
    *,
    additional: dict[str, JsonValue] | None = None,
) -> MappingProxyType[str, JsonValue]:
    """Create canonical metadata while keeping the hint explicitly noncertifying."""

    values: dict[str, JsonValue] = dict(additional or {})
    if "compiler_dependency_hint" in values:
        raise ClassicCacheHintError("compiler hint metadata field is reserved")
    values["compiler_dependency_hint"] = hint.as_json()
    canonical_json(values)
    return MappingProxyType(values)


def donor_transform_base_key(material: dict[str, JsonValue]) -> str:
    """Hash every non-recursive dependency of one projected transform."""

    if material.get("recursive_reads") != []:
        raise IncrementalAuthorityError(
            "donor-transform base key requires an empty recursive-read field"
        )
    producer_cache_key(material)
    return cache_key(
        "donor-transform-base",
        material,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )


def _donor_context_indexes(
    contexts: tuple[DonorDependencyResolutionContext, ...],
) -> tuple[SealedIncludeIndex, ...]:
    indexes_by_authority: dict[int, SealedIncludeIndex] = {}
    indexes: list[SealedIncludeIndex] = []
    for context in contexts:
        identity = id(context.authority)
        authority_index = indexes_by_authority.get(identity)
        if authority_index is None:
            authority_index = index_sealed_include_authority(context.authority)
            indexes_by_authority[identity] = authority_index
        indexes.append(authority_index)
    return tuple(indexes)


def resolve_donor_transform_dependencies(
    traces: tuple[DonorDependencyTrace, ...],
    contexts: tuple[DonorDependencyResolutionContext, ...],
) -> tuple[DonorResolvedDependencies, ...]:
    """Resolve one complete trace set against current projected namespaces."""

    return _resolve_donor_transform_dependencies(
        traces,
        contexts,
        _donor_context_indexes(contexts),
    )


def _resolve_donor_transform_dependencies(
    traces: tuple[DonorDependencyTrace, ...],
    contexts: tuple[DonorDependencyResolutionContext, ...],
    indexes: tuple[SealedIncludeIndex, ...],
) -> tuple[DonorResolvedDependencies, ...]:
    """Resolve with indexes already bound once for a complete cache probe."""

    trace_ids = _require_canonical_donor_ids(item.donor_id for item in traces)
    context_ids = _require_canonical_donor_ids(item.donor_id for item in contexts)
    if trace_ids != context_ids or len(indexes) != len(contexts):
        raise ClassicCacheHintError(
            "donor-transform dependency hint differs from the current donor universe"
        )
    resolved: list[DonorResolvedDependencies] = []
    for trace, context, authority_index in zip(traces, contexts, indexes, strict=True):
        reads = resolve_msvc_include_trace(
            MsvcSbrTrace(trace.working_directory, trace.sources),
            expected_working_directory=context.expected_working_directory,
            expected_source=context.expected_source,
            include_directories=context.include_directories,
            environment_directories=context.environment_directories,
            force_includes=context.force_includes,
            authority=context.authority,
            authority_index=authority_index,
        )
        for read in reads:
            if read.origin is not IncludeOrigin.DONOR_ARENA:
                continue
            try:
                common = ntpath.commonpath((read.logical_path, context.expected_working_directory))
            except ValueError as exc:
                raise ClassicCacheHintError(
                    "projected donor read leaves its private arena"
                ) from exc
            if ntpath.normcase(common) != ntpath.normcase(context.expected_working_directory):
                raise ClassicCacheHintError("projected donor read leaves its private arena")
        resolved.append(DonorResolvedDependencies(trace.donor_id, reads))
    return tuple(resolved)


def donor_transform_final_key(
    base_material: dict[str, JsonValue],
    dependencies: tuple[DonorResolvedDependencies, ...],
) -> str:
    """Bind each projected donor's current exact recursive reads into its key."""

    _require_canonical_donor_ids(item.donor_id for item in dependencies)
    material = dict(base_material)
    material["recursive_reads"] = [
        {
            "kind": "projected-donor-sbr-v1",
            "donor_id": dependency.donor_id,
            "reads": _resolved_material(dependency.reads),
        }
        for dependency in dependencies
    ]
    return producer_cache_key(material)


def donor_transform_authority_paths(
    contexts: tuple[DonorDependencyResolutionContext, ...],
    dependencies: tuple[DonorResolvedDependencies, ...],
) -> tuple[str, ...]:
    """Map projected mirror reads back to their physical source authorities."""

    context_ids = _require_canonical_donor_ids(item.donor_id for item in contexts)
    dependency_ids = _require_canonical_donor_ids(item.donor_id for item in dependencies)
    if context_ids != dependency_ids:
        raise ClassicCacheHintError(
            "resolved donor dependencies differ from their current contexts"
        )
    logical_paths: dict[str, str] = {}
    for context, dependency in zip(contexts, dependencies, strict=True):
        mirrored = {source.casefold(): original for source, original in context.mirrored_sources}
        if len(mirrored) != len(context.mirrored_sources):
            raise ClassicCacheHintError("donor source-mirror mapping is ambiguous")
        for read in dependency.reads:
            logical = mirrored.get(read.logical_path.casefold())
            if logical is None and read.origin is not IncludeOrigin.DONOR_ARENA:
                logical = read.logical_path
            if logical is not None:
                logical_paths.setdefault(logical.casefold(), logical)
    return tuple(sorted(logical_paths.values(), key=str.casefold))


def probe_donor_transform_cache(
    lease: CacheLease,
    *,
    base_key: str,
    base_material: dict[str, JsonValue],
    contexts: tuple[DonorDependencyResolutionContext, ...],
) -> DonorTransformCacheProbe:
    """Re-resolve bounded projected-donor hints and return only an exact hit."""

    _require_canonical_donor_ids(item.donor_id for item in contexts)
    candidate_keys = lease.indexed_record_keys("producer", "donor-transform-base", base_key)
    if not candidate_keys:
        return DonorTransformCacheProbe(
            None,
            None,
            (),
            None,
            "no prior projected-donor dependency hint",
        )
    authority_indexes = _donor_context_indexes(contexts)
    failures: list[str] = []
    best_miss: DonorTransformCacheProbe | None = None
    for candidate_key in candidate_keys:
        record = lease.lookup("producer", candidate_key)
        if record is None:
            continue
        try:
            hint = DonorTransformDependencyHint.from_record(record)
            if hint.base_key != base_key:
                raise ClassicCacheHintError("donor-transform hint base key differs")
            dependencies = _resolve_donor_transform_dependencies(
                hint.donors,
                contexts,
                authority_indexes,
            )
            key = donor_transform_final_key(base_material, dependencies)
        except (ClassicCacheHintError, ClassicIncludeTraceError) as exc:
            failures.append(str(exc))
            continue
        exact = record if record.key == key else lease.lookup("producer", key)
        if exact is not None:
            return DonorTransformCacheProbe(
                key,
                exact,
                dependencies,
                hint,
                None,
            )
        if best_miss is None:
            best_miss = DonorTransformCacheProbe(
                key,
                None,
                dependencies,
                hint,
                "projected donor dependency content changed",
            )
    if best_miss is not None:
        return best_miss
    reason = failures[0] if failures else "projected donor dependency hints were unusable"
    return DonorTransformCacheProbe(None, None, (), None, reason)


def donor_transform_hint_metadata(
    hint: DonorTransformDependencyHint,
    *,
    additional: dict[str, JsonValue] | None = None,
) -> MappingProxyType[str, JsonValue]:
    """Attach a strict non-certifying projected-donor hint to one record."""

    values: dict[str, JsonValue] = dict(additional or {})
    if "donor_transform_dependency_hint" in values:
        raise ClassicCacheHintError("donor-transform hint metadata field is reserved")
    values["donor_transform_dependency_hint"] = hint.as_json()
    canonical_json(values)
    return MappingProxyType(values)


__all__ = [
    "ClassicCacheHintError",
    "CompilerCacheProbe",
    "CompilerDependencyHint",
    "DonorDependencyResolutionContext",
    "DonorDependencyTrace",
    "DonorResolvedDependencies",
    "DonorTransformCacheProbe",
    "DonorTransformDependencyHint",
    "compiler_base_key",
    "compiler_final_key",
    "compiler_hint_metadata",
    "donor_transform_authority_paths",
    "donor_transform_base_key",
    "donor_transform_final_key",
    "donor_transform_hint_metadata",
    "probe_compiler_cache",
    "probe_donor_transform_cache",
    "resolve_donor_transform_dependencies",
]
