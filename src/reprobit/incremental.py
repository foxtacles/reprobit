"""Non-certifying authority and key material for incremental developer builds.

This module never writes committed source, build-plan, intervention, or proof
documents.  It constructs an invocation-local view of current admitted files
so an ordinary edit can be built without pretending that reviewed evidence is
still current.  Certification continues to load the committed authority.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import MappingProxyType

from reprobit.cache import cache_key
from reprobit.implementation import scoped_package_import_closure_digest
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import producer_graph_accepts_source
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    InterventionDocument,
    ProjectBundle,
    SourceManifestDocument,
    SourceManifestEntry,
    source_manifest_digest,
)
from reprobit.source_lock import SourceLockError, receipt_source_input
from reprobit.strict_json import JsonValue

_PRODUCER_IMPLEMENTATION_ROOTS = ("reprobit.classic_incremental",)


def producer_implementation_digest() -> Digest:
    """Identify only code that can affect warm producer outputs and receipts."""

    return scoped_package_import_closure_digest(_PRODUCER_IMPLEMENTATION_ROOTS)


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
    return f"classic-producer-graph-v1-{digest.value}"


PRODUCER_IMPLEMENTATION_DIGEST = producer_implementation_digest()
PRODUCER_CACHE_IMPLEMENTATION = producer_cache_implementation(PRODUCER_IMPLEMENTATION_DIGEST)


class IncrementalAuthorityError(ValueError):
    """Current worktree bytes cannot safely use reviewed build transformations."""


@dataclass(frozen=True, slots=True)
class DeveloperAuthority:
    """Invocation-local source authority for one non-certifying build."""

    bundle: ProjectBundle
    changed_paths: tuple[str, ...]
    changed_translation_units: tuple[str, ...]
    protected_sources: MappingProxyType[str, tuple[str, ...]]


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

    def __post_init__(self) -> None:
        counts = (
            self.producer_hits,
            self.producer_misses,
            self.transform_hits,
            self.transform_misses,
        )
        if any(item < 0 for item in counts) or self.elapsed_seconds < 0:
            raise ValueError("incremental summary counts and timing cannot be negative")
        if self.runtime_init_count < 0:
            raise ValueError("incremental runtime initialization count cannot be negative")
        if self.published_targets < 0 or self.unchanged_targets < 0:
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


def _intervention_ids(document: InterventionDocument) -> tuple[str, ...]:
    return tuple(sorted((item.id for item in document.interventions), key=str.casefold))


def _overlay_clean_owners(bundle: ProjectBundle) -> dict[str, tuple[str, ...]]:
    owners: dict[str, list[str]] = {}
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            continue
        values = {item.name: item.value for item in intervention.parameters}
        outputs = values.get("outputs")
        if not isinstance(outputs, list):
            raise IncrementalAuthorityError(
                f"source-overlay authority {intervention.id!r} is malformed"
            )
        for raw in outputs:
            path = raw.get("path") if isinstance(raw, dict) else None
            if not isinstance(path, str):
                raise IncrementalAuthorityError(
                    f"source-overlay authority {intervention.id!r} has a malformed output"
                )
            assert isinstance(raw, dict)
            if "clean" in raw:
                owners.setdefault(path.casefold(), []).append(intervention.id)
    return {path: tuple(sorted(values, key=str.casefold)) for path, values in owners.items()}


def current_worktree_authority(
    committed: ProjectBundle,
    project_root: Path,
) -> DeveloperAuthority:
    """Build an ephemeral source/plan view without repinning reviewed evidence.

    Existing admitted paths may change.  Path additions/deletions, archive
    authorities, source-overlay clean inputs, and translation units with actual
    interventions remain review boundaries and fail with an affected-id
    diagnostic.  An intervention-free TU may receive an ephemeral digest for
    this invocation only.
    """

    root = project_root.resolve(strict=True)
    if root != Path(committed.root).resolve(strict=True):
        raise IncrementalAuthorityError(
            "developer authority project root differs from the loaded project"
        )
    manifest = committed.source_manifest
    plan = committed.build_plan
    graph = committed.producer_graph
    if manifest is None or plan is None or graph is None:
        raise IncrementalAuthorityError(
            "incremental producer builds require source, build-plan, and graph authority"
        )
    entries: list[SourceManifestEntry] = []
    changed: list[str] = []
    old_by_path = {item.path.casefold(): item for item in manifest.entries}
    for entry in manifest.entries:
        try:
            size, digest, _ = receipt_source_input(root, entry.path)
        except SourceLockError as exc:
            raise IncrementalAuthorityError(
                f"incremental build cannot change the admitted path topology: {entry.path!r}: {exc}"
            ) from exc
        entries.append(SourceManifestEntry(path=entry.path, size=size, digest=digest))
        if size != entry.size or digest != entry.digest:
            changed.append(entry.path)
    ephemeral_manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=tuple(entries),
    )
    if not producer_graph_accepts_source(
        graph,
        paths=(item.path for item in ephemeral_manifest.entries),
    ):
        raise IncrementalAuthorityError(
            "committed producer graph does not admit the current source-path topology"
        )

    changed_folded = {item.casefold() for item in changed}
    fixed_archives = {
        item.source.casefold(): f"quarantine archive {item.identity!r}" for item in plan.archives
    }
    fixed_archives.update(
        {
            item.path.casefold(): f"project SDK archive {item.path!r}"
            for item in plan.project_sdk_libraries
        }
    )
    for path in sorted(changed_folded.intersection(fixed_archives)):
        raise IncrementalAuthorityError(
            f"current-worktree edit changes fixed {fixed_archives[path]}; "
            "refresh reviewed authority before building"
        )

    overlay_owners = _overlay_clean_owners(committed)
    for path in sorted(changed_folded.intersection(overlay_owners)):
        display = old_by_path[path].path
        raise IncrementalAuthorityError(
            f"current-worktree edit {display!r} invalidates reviewed source-overlay "
            f"intervention(s): {', '.join(overlay_owners[path])}"
        )

    documents_by_unit = {
        item.translation_unit_id: item
        for item in committed.intervention_documents
        if item.translation_unit_id is not None
    }
    changed_units: list[str] = []
    protected_sources: dict[str, tuple[str, ...]] = {}
    new_units = []
    updated_documents: list[InterventionDocument] = []
    updated_by_id: dict[str, InterventionDocument] = {}
    current_entries = {item.path.casefold(): item for item in ephemeral_manifest.entries}
    for unit in plan.translation_units:
        document = documents_by_unit.get(unit.id)
        if document is None:
            raise IncrementalAuthorityError(
                f"translation unit {unit.id!r} lacks an intervention shard"
            )
        intervention_ids = _intervention_ids(document)
        if intervention_ids:
            protected_sources[unit.source.casefold()] = intervention_ids
        if unit.source.casefold() not in changed_folded:
            new_units.append(unit)
            continue
        if intervention_ids:
            raise IncrementalAuthorityError(
                f"current-worktree edit {unit.source!r} invalidates reviewed "
                f"intervention(s): {', '.join(intervention_ids)}"
            )
        current_entry = current_entries.get(unit.source.casefold())
        if current_entry is None:
            raise IncrementalAuthorityError(
                f"translation unit {unit.id!r} is outside current source authority"
            )
        changed_units.append(unit.id)
        updated_unit = unit.model_copy(update={"source_digest": current_entry.digest})
        new_units.append(updated_unit)
        updated_by_id[unit.id] = document.model_copy(update={"source_digest": current_entry.digest})

    for document in committed.intervention_documents:
        if document.translation_unit_id in updated_by_id:
            updated_documents.append(updated_by_id[document.translation_unit_id])
        else:
            updated_documents.append(document)
    ephemeral_plan = plan.model_copy(
        update={
            "source_manifest_digest": source_manifest_digest(ephemeral_manifest),
            "translation_units": tuple(new_units),
        }
    )
    try:
        bundle = ProjectBundle(
            root=committed.root,
            spec=committed.spec,
            toolchain_lock=committed.toolchain_lock,
            source_manifest=ephemeral_manifest,
            build_plan=ephemeral_plan,
            producer_graph=graph,
            intervention_documents=tuple(updated_documents),
            proof_documents=committed.proof_documents,
            oracle_documents=committed.oracle_documents,
        )
    except ValueError as exc:
        raise IncrementalAuthorityError(
            f"current-worktree authority is internally inconsistent: {exc}"
        ) from exc
    return DeveloperAuthority(
        bundle,
        tuple(changed),
        tuple(sorted(changed_units, key=str.casefold)),
        MappingProxyType(protected_sources),
    )


def require_fresh_protected_recursive_inputs(
    authority: DeveloperAuthority,
    *,
    translation_unit_id: str,
    source: str,
    recursive_logical_paths: Iterable[str],
) -> None:
    """Reject stale reviewed transforms after discovering changed TU inputs.

    Direct TU edits are rejected while the developer authority is created.
    Header closure is only known after a conservative compiler-hint replay, so
    this second boundary must run before any reviewed composition/transform is
    restored or applied.
    """

    intervention_ids = authority.protected_sources.get(source.casefold())
    if not intervention_ids:
        return
    source_root = normalize_logical_path(authority.bundle.spec.paths.source)
    prefix = f"{source_root}\\"
    changed = {item.casefold(): item for item in authority.changed_paths}
    affected: dict[str, str] = {}
    for raw_path in recursive_logical_paths:
        logical = normalize_logical_path(raw_path)
        if not logical.casefold().startswith(prefix.casefold()):
            continue
        relative = PureWindowsPath(logical[len(prefix) :]).as_posix()
        display = changed.get(relative.casefold())
        if display is not None:
            affected[display.casefold()] = display
    if not affected:
        return
    paths = ", ".join(repr(item) for item in sorted(affected.values(), key=str.casefold))
    raise IncrementalAuthorityError(
        f"current-worktree recursive input edit(s) {paths} affect protected "
        f"translation unit {translation_unit_id!r} and invalidate reviewed "
        f"intervention(s): {', '.join(intervention_ids)}"
    )


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
    "PRODUCER_IMPLEMENTATION_DIGEST",
    "DeveloperAuthority",
    "IncrementalAuthorityError",
    "IncrementalBuildSummary",
    "current_worktree_authority",
    "producer_cache_implementation",
    "producer_cache_key",
    "producer_implementation_digest",
    "require_fresh_protected_recursive_inputs",
    "revalidate_producer_implementation",
]
