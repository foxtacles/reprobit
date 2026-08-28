"""Non-certifying incremental execution for classic producer graphs.

This module is intentionally absent from cold verification.  It plans cache
keys from the current physical authority, restores into a fresh run staging
tree, and constructs the classic logical workspace/backend only after the
first cache miss.
"""

from __future__ import annotations

import ntpath
import os
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from functools import partial
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock
from time import monotonic
from types import MappingProxyType
from typing import cast

from reprobit import classic
from reprobit.assets import runtime_asset_path
from reprobit.backends import ExecutionBackend, PosixWineBackend
from reprobit.cache import CacheLease, CacheOutput, IncrementalCache
from reprobit.classic_cache import (
    ClassicCacheHintError,
    CompilerDependencyHint,
    DonorDependencyResolutionContext,
    DonorDependencyTrace,
    DonorResolvedDependencies,
    DonorTransformDependencyHint,
    compiler_base_key,
    compiler_hint_metadata,
    donor_transform_authority_paths,
    donor_transform_base_key,
    donor_transform_final_key,
    donor_transform_hint_metadata,
    probe_compiler_cache,
    probe_donor_transform_cache,
    resolve_donor_transform_dependencies,
)
from reprobit.classic_cache import (
    compiler_final_key as compiler_cache_final_key,
)
from reprobit.classic_donors import DonorIncludeProjection
from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    SealedIncludeAuthority,
    SealedIncludeFile,
    resolve_msvc_include_trace,
)
from reprobit.classic_link_closure import (
    MissingDirectiveInputsError,
    audit_classic_link_directives,
    link_directive_closure_material,
    module_definition_material,
    parse_classic_module_definition,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    classic_compiler_translation_unit_authority,
    classic_rdata_repack_graph_authority,
    classic_terminal_pipeline_authority,
    prepare_classic_units,
)
from reprobit.classic_project import ClassicProjectError, _overlay_dialect
from reprobit.classic_resources import scan_msvc_resource_dependencies
from reprobit.classic_runtime import (
    ClassicProducerGraphPreparedRun,
    _classic_producer_environment,
    _ClassicWarmCompilerTransformResult,
    _graph_role_bindings,
    _graph_system_library_map,
    _toolchain_tree_files,
    prepare_classic_producer_graph_run,
)
from reprobit.engine import BuildExecutionReceipt, FileReceipt
from reprobit.implementation import (
    package_implementation_digest,
    revalidate_package_implementation,
)
from reprobit.incremental import (
    PRODUCER_CACHE_IMPLEMENTATION,
    DeveloperAuthority,
    IncrementalBuildSummary,
    producer_cache_key,
    require_fresh_protected_recursive_inputs,
)
from reprobit.incremental_executor import (
    CacheProbeDecision,
    IncrementalDAGExecutor,
    IncrementalNode,
    IncrementalPhase,
    IncrementalProgress,
    NodeOutcome,
    PreparedNodeInputs,
    ReceiptBoundInput,
)
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path
from reprobit.process import CancellationToken
from reprobit.producer_graph import (
    ProducerNode,
    ProducerRole,
    materialize_argument,
    producer_graph_digest,
)
from reprobit.progress import ProgressKind
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProducerGraphBuildAdapter,
    ProjectBundle,
)
from reprobit.secure_paths import (
    SecureFileSnapshot,
    SecurePathError,
    atomic_publish_new_relative,
    atomic_publish_new_relative_from_stream,
    atomic_publish_relative_if_current,
    canonical_system_path,
    digest_relative_file,
    hold_relative_file_set,
    read_relative_file,
    remove_published_relative,
    windows_attributes_are_basic_restorable,
)
from reprobit.state import AdvisoryFileLock
from reprobit.strict_json import JsonValue, canonical_json
from reprobit.toolchains import ClassicMSVCToolchain, ToolchainLock


class ClassicIncrementalError(RuntimeError):
    """The non-certifying classic warm build cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class ClassicIncrementalResult:
    receipt: BuildExecutionReceipt
    summary: IncrementalBuildSummary


@dataclass(frozen=True, slots=True)
class _TargetPublication:
    target_id: str
    relative: str
    payload: bytes
    staged: SecureFileSnapshot
    prior_payload: bytes | None
    prior: SecureFileSnapshot | None


@dataclass(slots=True)
class _CompilerState:
    base_key: str
    base_material: dict[str, JsonValue]
    final_key: str | None = None
    hint: CompilerDependencyHint | None = None
    replay_failure: str | None = None
    physical_inputs: tuple[Path, ...] = ()


@dataclass(slots=True)
class _TransformState:
    base_key: str
    base_material: dict[str, JsonValue]
    final_key: str | None = None
    hint: DonorTransformDependencyHint | None = None
    replay_failure: str | None = None
    physical_inputs: tuple[Path, ...] = ()


def _json(value: object) -> JsonValue:
    canonical_json(value)
    return cast(JsonValue, value)


def _logical_join(root: str, relative: str) -> str:
    return normalize_logical_path(root.rstrip("\\/") + "\\" + relative.replace("/", "\\"))


def _secure_location(path: Path) -> tuple[Path, str]:
    absolute = canonical_system_path(path)
    if not absolute.anchor or len(absolute.parts) < 2:
        raise ClassicIncrementalError(f"warm input has no secure location: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


@contextmanager
def _target_publication_transaction(state_root: Path) -> Iterator[None]:
    """Serialize one complete warm target-set compare-and-swap interval."""

    marker = b"reprobit-warm-target-publication-v1\n"
    relative = "warm-target-publication.lock"
    try:
        snapshot = atomic_publish_new_relative(state_root, relative, marker)
    except SecurePathError as publication_error:
        try:
            payload, snapshot = read_relative_file(state_root, relative)
        except SecurePathError as read_error:
            raise ClassicIncrementalError(
                "warm target publication lock is unsafe"
            ) from read_error
        if payload != marker:
            raise ClassicIncrementalError(
                "warm target publication lock is invalid"
            ) from publication_error
    try:
        lock = AdvisoryFileLock(snapshot.path, create=False)
    except OSError as exc:
        raise ClassicIncrementalError(
            "warm target publication lock cannot be opened safely"
        ) from exc
    with lock:
        payload, named = read_relative_file(state_root, relative)
        held = os.fstat(lock.stream.fileno())
        if payload != marker or (
            named.device,
            named.inode,
            named.size,
            named.mtime_ns,
            named.mode,
            named.ctime_ns,
        ) != (
            held.st_dev,
            held.st_ino,
            held.st_size,
            held.st_mtime_ns,
            held.st_mode,
            held.st_ctime_ns,
        ):
            raise ClassicIncrementalError(
                "warm target publication lock changed while acquiring it"
            )
        yield


def _snapshot(path: Path) -> SecureFileSnapshot:
    root, relative = _secure_location(path)
    try:
        return digest_relative_file(root, relative)
    except SecurePathError as exc:
        raise ClassicIncrementalError(
            f"warm input is absent, redirected, or unstable: {path}"
        ) from exc


def _payload(path: Path) -> tuple[bytes, SecureFileSnapshot]:
    root, relative = _secure_location(path)
    try:
        return read_relative_file(root, relative)
    except SecurePathError as exc:
        raise ClassicIncrementalError(
            f"warm input is absent, redirected, or unstable: {path}"
        ) from exc


class _PhysicalInputCensus:
    """Exact physical receipts sampled while planning one warm invocation."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: dict[Path, SecureFileSnapshot] = {}

    def _record(self, snapshot: SecureFileSnapshot) -> SecureFileSnapshot:
        path = snapshot.path.resolve(strict=True)
        with self._lock:
            previous = self._entries.setdefault(path, snapshot)
        if previous != snapshot:
            raise ClassicIncrementalError(
                f"warm physical input changed while planning: {path}"
            )
        return snapshot

    def snapshot(self, path: Path) -> SecureFileSnapshot:
        return self._record(_snapshot(path))

    def payload(self, path: Path) -> tuple[bytes, SecureFileSnapshot]:
        payload, snapshot = _payload(path)
        return payload, self._record(snapshot)

    def sampled_path(self, path: Path) -> Path:
        snapshot = self.snapshot(path)
        return snapshot.path.resolve(strict=True)

    def known_path(self, path: Path) -> Path | None:
        canonical = Path(os.path.abspath(path)).resolve(strict=False)
        with self._lock:
            return canonical if canonical in self._entries else None

    def paths(self) -> tuple[Path, ...]:
        with self._lock:
            return tuple(sorted(self._entries, key=str))

    def validate(self, paths: Sequence[Path]) -> None:
        selected = {Path(os.path.abspath(path)).resolve(strict=False) for path in paths}
        with self._lock:
            expected = {path: self._entries.get(path) for path in selected}
        missing = tuple(
            sorted((path for path, value in expected.items() if value is None), key=str)
        )
        if missing:
            raise ClassicIncrementalError(
                "warm input census omitted sampled path(s): "
                + ", ".join(str(path) for path in missing)
            )
        for path in sorted(selected, key=str):
            prior = expected[path]
            assert prior is not None
            current = _snapshot(path)
            if current != prior:
                raise ClassicIncrementalError(
                    f"warm sampled physical input changed before cache publication: {path}"
                )

    def validate_all(self) -> None:
        with self._lock:
            paths = tuple(self._entries)
        self.validate(paths)


def _receipt(reference: str, logical_path: str, snapshot: SecureFileSnapshot) -> JsonValue:
    return _json(
        {
            "reference": reference,
            "logical_path": logical_path,
            "digest": snapshot.digest.value,
            "size": snapshot.size,
        }
    )


def _dependency_material(dependencies: Mapping[str, NodeOutcome]) -> list[JsonValue]:
    return [
        _json(
            {
                "node": node_id,
                "key": outcome.key,
                "outputs": [
                    {
                        "name": item.name,
                        "digest": item.digest,
                        "size": item.size,
                        "executable": item.executable,
                    }
                    for item in outcome.record.outputs
                ],
            }
        )
        for node_id, outcome in sorted(dependencies.items(), key=lambda item: item[0].casefold())
    ]


def _runtime_material(
    backend: ExecutionBackend,
    compiler_transport: Path | None,
    resource_transport: Path | None,
    *,
    snapshot: Callable[[Path], SecureFileSnapshot] = _snapshot,
) -> JsonValue:
    programs: list[JsonValue] = []
    for label, raw in (
        ("compiler_transport", compiler_transport),
        ("resource_transport", resource_transport),
    ):
        if raw is None:
            continue
        path = raw.expanduser().resolve(strict=True)
        programs.append(_receipt(label, str(path), snapshot(path)))
    for label in ("wine_pin", "wineserver_pin"):
        pin = getattr(backend, label, None)
        if pin is None:
            continue
        receipt = snapshot(pin.path)
        if receipt.size != pin.size or receipt.digest.value != pin.sha256:
            raise ClassicIncrementalError(f"resolved backend {label} changed")
        programs.append(_receipt(label, str(pin.path), receipt))
    proxy = runtime_asset_path("ReproBitPathProxy.sh")
    proxy_receipt = snapshot(proxy)
    programs.append(
        _json(
            {
                "role": "runtime-path-proxy-template",
                "digest": proxy_receipt.digest.value,
                "size": proxy_receipt.size,
            }
        )
    )
    return _json(
        {
            "backend": backend.identifier,
            "capabilities": asdict(backend.capabilities),
            "programs": programs,
        }
    )


def _render_sources(
    bundle: ProjectBundle,
    project_root: Path,
    *,
    read_payload: Callable[[Path], tuple[bytes, SecureFileSnapshot]] = _payload,
) -> tuple[
    Mapping[str, bytes],
    Mapping[str, bytes],
    Mapping[str, JsonValue],
    frozenset[str],
    frozenset[str],
]:
    manifest = bundle.source_manifest
    if manifest is None:
        raise ClassicIncrementalError("warm producer graph lacks a source manifest")
    clean: dict[str, bytes] = {}
    for entry in manifest.entries:
        path = project_root.joinpath(*PurePosixPath(entry.path).parts)
        source_payload, snapshot = read_payload(path)
        if snapshot.digest != entry.digest or snapshot.size != entry.size:
            raise ClassicIncrementalError(
                f"current source authority changed during warm planning: {entry.path!r}"
            )
        clean[entry.path] = source_payload
    effective = dict(clean)
    declarations: dict[str, JsonValue] = {}
    generated_translation_units: set[str] = set()
    generated_outputs: set[str] = set()
    try:
        from reprobit.classic_overlay import render_classic_overlay

        for intervention in bundle.interventions:
            if not isinstance(intervention, ClassicRecipeIntervention) or (
                intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
            ):
                continue
            values = {item.name: item.value for item in intervention.parameters}
            outputs = values.get("outputs")
            graph = values.get("graph")
            schema = values.get("schema")
            if not isinstance(outputs, list) or not isinstance(graph, dict) or schema != 2:
                raise ClassicIncrementalError(f"source-overlay {intervention.id!r} is malformed")
            clean_inputs: dict[str, bytes] = {}
            for raw in outputs:
                if not isinstance(raw, dict):
                    raise ClassicIncrementalError(
                        f"source-overlay {intervention.id!r} has a malformed output"
                    )
                overlay_path = raw.get("path")
                if not isinstance(overlay_path, str) or overlay_path in declarations:
                    raise ClassicIncrementalError(
                        f"source-overlay {intervention.id!r} repeats an output"
                    )
                if "clean" in raw:
                    clean_payload = clean.get(overlay_path)
                    if clean_payload is None:
                        raise ClassicIncrementalError(
                            f"source-overlay clean input is absent: {overlay_path!r}"
                        )
                    clean_inputs[overlay_path] = clean_payload
                else:
                    generated_outputs.add(overlay_path.casefold())
                declarations[overlay_path] = _json(
                    {
                        "intervention": intervention.id,
                        "declaration": raw,
                    }
                )
            rendered = render_classic_overlay(
                {"schema": schema, "outputs": outputs, "graph": graph},
                clean_inputs,
                dialect=_overlay_dialect(bundle),  # type: ignore[arg-type]
            )
            for raw in outputs:
                assert isinstance(raw, dict)
                overlay_path = cast(str, raw["path"])
                payload = rendered.outputs[overlay_path]
                if raw.get("effective") != Digest.from_bytes(payload).value or raw.get(
                    "size"
                ) != len(payload):
                    raise ClassicIncrementalError(
                        f"rendered source-overlay output changed: {overlay_path!r}"
                    )
                effective[overlay_path] = payload
            raw_generated = graph.get("generated_tus", [])
            if not isinstance(raw_generated, list):
                raise ClassicIncrementalError("source-overlay generated_tus is malformed")
            for raw in raw_generated:
                generated_path = raw.get("path") if isinstance(raw, dict) else None
                if not isinstance(generated_path, str) or generated_path not in effective:
                    raise ClassicIncrementalError(
                        "source-overlay generated TU lacks rendered bytes"
                    )
                generated_translation_units.add(generated_path.casefold())
    except ValueError as exc:
        raise ClassicIncrementalError(f"cannot render warm source authority: {exc}") from exc
    return (
        MappingProxyType(clean),
        MappingProxyType(effective),
        MappingProxyType(declarations),
        frozenset(generated_translation_units),
        frozenset(generated_outputs),
    )


def _include_authorities(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    toolchain_root: Path,
    effective_sources: Mapping[str, bytes],
    deferred_outputs: frozenset[str],
    snapshot: Callable[[Path], SecureFileSnapshot] = _snapshot,
) -> tuple[
    SealedIncludeAuthority,
    SealedIncludeAuthority,
    Mapping[str, Path],
    Mapping[str, bytes],
]:
    source_root = normalize_logical_path(bundle.spec.paths.source)
    toolchain_logical_root = normalize_logical_path(bundle.spec.paths.toolchain)
    roots = tuple(sorted((source_root, toolchain_logical_root), key=str.casefold))
    source_files: list[SealedIncludeFile] = []
    payloads: dict[str, bytes] = {}
    physical: dict[str, Path] = {}
    for relative, payload in sorted(effective_sources.items(), key=lambda item: item[0].casefold()):
        logical = _logical_join(source_root, relative)
        source_files.append(
            SealedIncludeFile(
                logical,
                Digest.from_bytes(payload),
                len(payload),
                IncludeOrigin.PROJECT_SOURCE,
            )
        )
        payloads[logical] = payload
        physical[logical.casefold()] = project_root.joinpath(*PurePosixPath(relative).parts)

    toolchain_paths = {
        toolchain_root.joinpath(*PurePosixPath(item.path).parts).resolve(strict=True)
        for item in (*bundle.toolchain_lock.tools, *bundle.toolchain_lock.runtime_files)
    }
    toolchain_paths.update(_toolchain_tree_files(bundle, toolchain_root))
    toolchain_files: list[SealedIncludeFile] = []
    for path in sorted(toolchain_paths, key=lambda item: str(item).casefold()):
        relative = path.relative_to(toolchain_root).as_posix()
        logical = _logical_join(toolchain_logical_root, relative)
        receipt = snapshot(path)
        toolchain_files.append(
            SealedIncludeFile(
                logical,
                receipt.digest,
                receipt.size,
                IncludeOrigin.TOOLCHAIN_TREE,
            )
        )
        physical[logical.casefold()] = path

    generated = tuple(
        sorted((*source_files, *toolchain_files), key=lambda item: item.logical_path.casefold())
    )
    ordinary = tuple(
        item
        for item in generated
        if not (
            item.origin is IncludeOrigin.PROJECT_SOURCE
            and PureWindowsPath(item.logical_path)
            .relative_to(PureWindowsPath(source_root))
            .as_posix()
            .casefold()
            in deferred_outputs
        )
    )
    return (
        SealedIncludeAuthority(roots, ordinary),
        SealedIncludeAuthority(roots, generated),
        MappingProxyType(physical),
        MappingProxyType(payloads),
    )


def _warm_cache_environment(
    installation: ClassicMSVCToolchain,
    *,
    build_root: str,
    posix_wine: bool,
) -> Mapping[str, str]:
    """Return one lane-stable producer environment for cache-key material."""

    values = _classic_producer_environment(
        installation,
        temp_directory=_logical_join(build_root, ".reprobit-tmp/$LANE"),
    )
    if posix_wine:
        path_keys = [key for key in values if key.casefold() == "path"]
        if len(path_keys) != 1:
            raise ClassicIncrementalError("warm Wine environment lacks one PATH")
        values["WINEPATH"] = values.pop(path_keys[0])
    return MappingProxyType(dict(sorted(values.items(), key=lambda item: item[0].casefold())))


def _compiler_parameters(
    node: ProducerNode,
    *,
    bundle: ProjectBundle,
    compiler_logical: str,
    environment: Mapping[str, str],
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    arguments = tuple(
        materialize_argument(
            value,
            source_root=bundle.spec.paths.source,
            build_root=bundle.spec.paths.build,
            toolchain_root=bundle.spec.paths.toolchain,
        )
        for value in node.arguments
    )
    parsed = classic.validate_compile_arguments([compiler_logical, *arguments])
    source = cast(str, parsed["source_token"])
    include_directories = tuple(
        cast(tuple[int, str, bool], item)[1]
        for item in cast(Sequence[object], parsed["include_paths"])
    )
    force_includes = tuple(
        cast(tuple[int, str, bool], item)[1]
        for item in cast(Sequence[object], parsed["force_includes"])
    )
    include_environment = tuple(item for item in environment["INCLUDE"].split(";") if item)
    return source, bundle.spec.paths.build, include_directories, include_environment, force_includes


def _logical_absolute(value: str, *, working_directory: str) -> str:
    raw = value.replace("/", "\\")
    drive, _tail = ntpath.splitdrive(raw)
    if raw.startswith("\\\\") or value.startswith("/"):
        raise ClassicIncrementalError(f"donor compiler path is not a DOS path: {value!r}")
    if drive:
        candidate = raw
    elif raw.startswith("\\"):
        candidate = PureWindowsPath(working_directory).drive + raw
    else:
        candidate = ntpath.join(working_directory, raw)
    return normalize_logical_path(ntpath.normpath(candidate))


def _logical_relative(path: str, *, root: str) -> str | None:
    try:
        common = ntpath.commonpath((path, root))
    except ValueError:
        return None
    if ntpath.normcase(common) != ntpath.normcase(root):
        return None
    relative = ntpath.relpath(path, root)
    if relative == ".":
        return ""
    if relative.startswith(".."):
        return None
    return PureWindowsPath(relative).as_posix()


def _projected_donor_resolution_contexts(
    unit: ClassicPreparedUnit,
    *,
    compiler_nodes: Mapping[str, ProducerNode],
    compiler_sources: Mapping[str, str],
    node_arguments: Callable[[ProducerNode], tuple[str, ...]],
    source_root: str,
    build_root: str,
    environment: Mapping[str, str],
    authority: SealedIncludeAuthority,
) -> tuple[DonorDependencyResolutionContext, ...]:
    """Reconstruct exact projected donor reads without materializing a runtime."""

    projected = tuple(
        sorted(
            (
                donor
                for donor in unit.donors
                if donor.request.compiler_additions.include_projection
                is not DonorIncludeProjection.NONE
            ),
            key=lambda item: item.intervention.id.casefold(),
        )
    )
    if not projected:
        return ()
    normalized_source_root = normalize_logical_path(source_root)
    normalized_build_root = normalize_logical_path(build_root)
    environment_directories = tuple(
        item for item in environment["INCLUDE"].split(";") if item
    )
    contexts: list[DonorDependencyResolutionContext] = []
    for donor in projected:
        request = donor.request
        if request.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} is not a source overlay"
            )
        source_path = PurePosixPath(request.logical_source)
        if (
            source_path.is_absolute()
            or not source_path.parts
            or any(part in {"", ".", ".."} for part in source_path.parts)
        ):
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} source path is unsafe"
            )
        legacy_path = PurePosixPath(request.legacy_recipe_id)
        if (
            legacy_path.is_absolute()
            or len(legacy_path.parts) != 1
            or any(part in {"", ".", ".."} for part in legacy_path.parts)
        ):
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} legacy ID is unsafe"
            )
        matches: list[tuple[ProducerNode, dict[str, object]]] = []
        for node_id, node in compiler_nodes.items():
            if compiler_sources[node_id].casefold() != request.logical_source.casefold():
                continue
            try:
                parsed = classic.validate_compile_arguments(list(node_arguments(node)))
            except Exception as exc:
                raise ClassicIncrementalError(
                    f"projected donor compiler lane {node_id!r} is invalid: {exc}"
                ) from exc
            definitions = {
                cast(tuple[int, str, bool], item)[1]
                for item in cast(Sequence[object], parsed["definitions"])
            }
            if request.compiler_additions.required_define in definitions:
                matches.append((node, parsed))
        if len(matches) != 1:
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} has {len(matches)} "
                "committed compiler lanes"
            )
        _record_node, parsed = matches[0]
        parent = source_path.parent.as_posix()
        expected_directories = ["inc"]
        expected_directories.append(
            "inc/source" if parent == "." else f"inc/source/{parent}"
        )
        if tuple(expected_directories) != request.compiler_additions.include_directories:
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} include layout differs"
            )
        force_includes = request.compiler_additions.force_includes
        if (
            any(item != "run.h" for item in force_includes)
            or len(force_includes) > 1
            or request.staged_source != "s.cpp"
            or "s.cpp" not in request.files
            or bool(force_includes) != ("run.h" in request.files)
        ):
            raise ClassicIncrementalError(
                f"projected donor {donor.intervention.id!r} staging layout differs"
            )

        marker_stem = (
            f"composed-{unit.plan.build_target}-{unit.plan.source.replace('/', '_')}"
        )
        donor_root = PureWindowsPath(normalized_build_root).parent / "donors"
        arena = normalize_logical_path(
            str(donor_root / f"{marker_stem}-{request.legacy_recipe_id}")
        )
        record_source = _logical_join(normalized_source_root, request.logical_source)
        private_includes = [
            _logical_join(arena, "inc"),
            _logical_join(
                arena,
                "inc/source" if parent == "." else f"inc/source/{parent}",
            ),
            normalize_logical_path(str(PureWindowsPath(record_source).parent)),
        ]
        include_directories = list(private_includes)
        for item in cast(Sequence[object], parsed["include_paths"]):
            raw = cast(tuple[int, str, bool], item)[1]
            visible = _logical_absolute(raw, working_directory=normalized_build_root)
            relative = _logical_relative(visible, root=normalized_source_root)
            if relative is not None:
                include_directories.append(
                    _logical_join(
                        arena,
                        "inc/source" if not relative else f"inc/source/{relative}",
                    )
                )
            include_directories.append(raw)

        arena_files: dict[str, SealedIncludeFile] = {}
        mirrored_sources: dict[str, tuple[str, str]] = {}
        for item in authority.files:
            if item.origin is not IncludeOrigin.PROJECT_SOURCE:
                continue
            relative = _logical_relative(item.logical_path, root=normalized_source_root)
            if relative is None:
                raise ClassicIncrementalError(
                    f"projected donor source authority is outside its root: {item.logical_path!r}"
                )
            mirrored = _logical_join(arena, f"inc/source/{relative}")
            arena_files[mirrored.casefold()] = SealedIncludeFile(
                mirrored,
                item.digest,
                item.size,
                IncludeOrigin.DONOR_ARENA,
            )
            mirrored_sources[mirrored.casefold()] = (mirrored, item.logical_path)
        for relative, payload in request.files.items():
            path = PurePosixPath(relative)
            if (
                path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise ClassicIncrementalError(
                    f"projected donor {donor.intervention.id!r} input path is unsafe"
                )
            logical = _logical_join(arena, path.as_posix())
            folded = logical.casefold()
            existing = arena_files.get(folded)
            if existing is not None and existing.logical_path != logical:
                raise ClassicIncrementalError(
                    f"projected donor {donor.intervention.id!r} has a DOS path collision"
                )
            arena_files[folded] = SealedIncludeFile(
                logical,
                Digest.from_bytes(payload),
                len(payload),
                IncludeOrigin.DONOR_ARENA,
            )
            mirrored_sources.pop(folded, None)
        donor_authority = SealedIncludeAuthority(
            tuple(sorted((*authority.logical_roots, arena), key=str.casefold)),
            tuple(
                sorted(
                    (*authority.files, *arena_files.values()),
                    key=lambda item: item.logical_path.casefold(),
                )
            ),
        )
        original_force_includes = tuple(
            cast(tuple[int, str, bool], item)[1]
            for item in cast(Sequence[object], parsed["force_includes"])
        )
        contexts.append(
            DonorDependencyResolutionContext(
                donor.intervention.id,
                arena,
                _logical_join(arena, "s.cpp"),
                tuple(include_directories),
                environment_directories,
                (*original_force_includes, *force_includes),
                donor_authority,
                tuple(sorted(mirrored_sources.values(), key=lambda item: item[0].casefold())),
            )
        )
    return tuple(contexts)


def _warm_link_control_references(
    linker: ProducerNode,
    graph_nodes: Sequence[ProducerNode],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if linker.role is not ProducerRole.LINKER or linker.target_id is None:
        raise ClassicIncrementalError("warm link-control audit requires one linker node")
    by_id = {node.id: node for node in graph_nodes}
    if len(by_id) != len(graph_nodes) or linker.id not in by_id:
        raise ClassicIncrementalError("warm link-control graph is incomplete or ambiguous")
    ancestors: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in ancestors:
            return
        node = by_id.get(node_id)
        if node is None:
            raise ClassicIncrementalError(
                f"warm link-control dependency is absent: {node_id!r}"
            )
        ancestors.add(node_id)
        for dependency in node.depends_on:
            visit(dependency)

    visit(linker.id)
    collected_object_refs: list[str] = []
    for node_id in sorted(ancestors, key=str.casefold):
        node = by_id[node_id]
        if node.role is not ProducerRole.COMPILER:
            continue
        current_object_refs = tuple(
            reference
            for reference in node.outputs
            if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold() == ".obj"
        )
        if len(current_object_refs) != 1:
            raise ClassicIncrementalError(
                f"compiler {node_id!r} lacks one directive-audited OBJ"
            )
        collected_object_refs.append(current_object_refs[0])
    archive_refs = tuple(
        sorted(
            {
                reference
                for node_id in ancestors
                for reference in (*by_id[node_id].inputs, *by_id[node_id].directive_inputs)
                if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold()
                in {".lib", ".a"}
            },
            key=str.casefold,
        )
    )
    definition_refs = tuple(
        reference
        for reference in linker.inputs
        if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold() == ".def"
    )
    if len(definition_refs) > 1:
        raise ClassicIncrementalError(
            f"target {linker.target_id!r} names more than one DEF input"
        )
    return tuple(collected_object_refs), archive_refs, definition_refs


def _warm_link_control_material(
    linker: ProducerNode,
    graph_nodes: Sequence[ProducerNode],
    *,
    payload_for_reference: Callable[[str], bytes],
) -> JsonValue:
    """Audit and serialize the exact hidden linker-control closure.

    This is deliberately the same parser and canonical serialization used by
    cold execution.  It runs before a linker cache lookup, including on an
    otherwise all-hit build, so restored objects cannot introduce an
    undeclared DEFAULTLIB/DISALLOWLIB/DEF control.
    """

    object_refs, archive_refs, definition_refs = _warm_link_control_references(
        linker,
        graph_nodes,
    )
    object_inputs = {
        reference: payload_for_reference(reference) for reference in object_refs
    }
    archive_inputs = {
        reference: payload_for_reference(reference) for reference in archive_refs
    }
    try:
        closure = audit_classic_link_directives(
            object_inputs=object_inputs,
            archive_inputs=archive_inputs,
            declared_archive_refs=archive_refs,
            linker_arguments=linker.arguments,
        )
    except MissingDirectiveInputsError as exc:
        suggestions = " ".join(
            f"--directive-input {linker.target_id}={library}" for library in exc.libraries
        )
        raise ClassicIncrementalError(
            f"target {linker.target_id!r} lacks committed DEFAULTLIB edges; "
            f"rerun `rbit graph extract ... {suggestions}`"
        ) from exc
    except Exception as exc:
        raise ClassicIncrementalError(
            f"target {linker.target_id!r} linker-control closure failed: {exc}"
        ) from exc
    definition = None
    if definition_refs:
        try:
            definition = parse_classic_module_definition(
                payload_for_reference(definition_refs[0]),
                label=definition_refs[0],
            )
        except Exception as exc:
            raise ClassicIncrementalError(
                f"target {linker.target_id!r} DEF closure failed: {exc}"
            ) from exc
    return _json(
        {
            "schema": 1,
            "target_id": linker.target_id,
            "linker_node": linker.id,
            "directives": link_directive_closure_material(closure),
            "module_definition": module_definition_material(definition),
        }
    )


def _base_material(
    *,
    bundle: ProjectBundle,
    graph_digest: str,
    node_identity: JsonValue,
    role: str,
    toolchain: JsonValue,
    runtime: JsonValue,
    argv: Sequence[str],
    environment: Mapping[str, str],
    direct_inputs: Sequence[JsonValue],
    dependencies: Mapping[str, NodeOutcome],
    recursive_reads: Sequence[JsonValue],
    overlay_inputs: Sequence[JsonValue] = (),
    generated_inputs: Sequence[JsonValue] = (),
    donor_inputs: Sequence[JsonValue] = (),
    composition_inputs: Sequence[JsonValue] = (),
    transform_inputs: Sequence[JsonValue] = (),
) -> dict[str, JsonValue]:
    graph = bundle.producer_graph
    if graph is None:
        raise ClassicIncrementalError("warm build has no producer graph")
    return {
        "graph": graph_digest,
        "node": node_identity,
        "role": role,
        "toolchain": toolchain,
        "runtime": runtime,
        "argv": _json(list(argv)),
        "cwd": normalize_logical_path(bundle.spec.paths.build),
        "environment": _json(dict(environment)),
        "path_profile": _json(
            {
                "id": graph.path_profile_id,
                "source": normalize_logical_path(bundle.spec.paths.source),
                "build": normalize_logical_path(bundle.spec.paths.build),
                "toolchain": normalize_logical_path(bundle.spec.paths.toolchain),
            }
        ),
        "direct_inputs": _json(list(direct_inputs)),
        "producer_dependencies": _json(_dependency_material(dependencies)),
        "recursive_reads": _json(list(recursive_reads)),
        "overlay_inputs": _json(list(overlay_inputs)),
        "generated_inputs": _json(list(generated_inputs)),
        "donor_inputs": _json(list(donor_inputs)),
        "composition_inputs": _json(list(composition_inputs)),
        "transform_inputs": _json(list(transform_inputs)),
    }


class _WarmRuntime:
    def __init__(
        self,
        prepared: ClassicProducerGraphPreparedRun,
        *,
        staging_root: Path,
        project_root: Path,
        oracle_paths: Mapping[str, Path],
        oracle_snapshots: Mapping[str, SecureFileSnapshot],
    ) -> None:
        self.prepared = prepared
        self.project_root = project_root
        self.oracle_paths = oracle_paths
        self.oracle_snapshots = oracle_snapshots
        self._oracle_stack = ExitStack()
        self._oracle_lock = Lock()
        self._oracles_bound = False
        self._closed = False
        prepared.executor.bind_warm_staging_root(staging_root)

    @property
    def initialized_lane_count(self) -> int:
        return self.prepared.initialized_lane_count

    def ensure_oracles(self) -> None:
        with self._oracle_lock:
            if self._oracles_bound:
                return
            stack = ExitStack()
            try:
                from reprobit.legacy import bind_pe32_oracle
                from reprobit.verify import seal_file_oracle

                capabilities = {}
                for target_id, path in sorted(
                    self.oracle_paths.items(), key=lambda item: item[0].casefold()
                ):
                    sealed = stack.enter_context(seal_file_oracle(path))
                    digest, size = sealed._digest_receipt()
                    expected = self.oracle_snapshots[target_id]
                    if digest != expected.digest.value or size != expected.size:
                        raise ClassicIncrementalError(
                            f"warm legacy oracle changed after key planning: {target_id!r}"
                        )
                    capabilities[target_id] = bind_pe32_oracle(sealed)
                self.prepared.executor.bind_legacy_oracles(capabilities)
            except BaseException:
                stack.close()
                raise
            self._oracle_stack = stack.pop_all()
            self._oracles_bound = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.prepared.close()
        finally:
            self._oracle_stack.close()


def execute_classic_incremental_build(
    authority: DeveloperAuthority,
    *,
    project_root: Path,
    session_root: Path,
    state_root: Path,
    toolchain_root: Path,
    backend: ExecutionBackend,
    jobs: int,
    compiler_transport: Path | None = None,
    resource_transport: Path | None = None,
    initialization_timeout: float = 600.0,
    compile_timeout: float = 600.0,
    link_timeout: float = 900.0,
    cleanup_timeout: float = 10.0,
    progress: IncrementalProgress | None = None,
) -> ClassicIncrementalResult:
    """Execute one current-worktree producer graph with conservative reuse."""

    started = monotonic()
    bundle = authority.bundle
    graph = bundle.producer_graph
    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter) or graph is None:
        raise ClassicIncrementalError("warm classic execution requires a producer graph")
    if jobs < 1:
        raise ClassicIncrementalError("warm build jobs must be positive")
    try:
        rdata_graph_authority = classic_rdata_repack_graph_authority(bundle, graph)
    except ClassicProjectError as exc:
        raise ClassicIncrementalError(str(exc)) from exc
    rdata_material_by_object = {
        object_identity: (
            _json(
                {
                    "intervention": intervention.model_dump(mode="json"),
                    "proof": receipt.model_dump(mode="json"),
                }
            ),
        )
        for object_identity, (intervention, receipt, _values) in rdata_graph_authority.items()
    }
    graph_digest_value = producer_graph_digest(graph).value
    implementation_receipt = package_implementation_digest()
    project_root = project_root.resolve(strict=True)
    toolchain_root = toolchain_root.resolve(strict=True)
    census = _PhysicalInputCensus()
    session_root.mkdir(parents=True, exist_ok=False)
    staging_root = session_root / "staging"
    staging_root.mkdir()
    planner_build_root = session_root / "planner-build"
    planner_build_root.mkdir()

    installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile,
        toolchain_root,
        logical_root=bundle.spec.paths.toolchain,
    )
    runtime_lock = ToolchainLock.from_schema_v3(bundle.toolchain_lock)
    installation.doctor(runtime_lock).require_ok()
    _role_tool_ids, role_relatives = _graph_role_bindings(bundle, installation)
    role_logical = {
        role: installation.logical_path(relative) for role, relative in role_relatives.items()
    }
    environment = _warm_cache_environment(
        installation,
        build_root=bundle.spec.paths.build,
        posix_wine=isinstance(backend, PosixWineBackend),
    )
    toolchain_material = _json(bundle.toolchain_lock.model_dump(mode="json"))
    runtime_material = _runtime_material(
        backend,
        compiler_transport,
        resource_transport,
        snapshot=census.snapshot,
    )
    runtime_input_paths = census.paths()
    (
        clean_sources,
        effective_sources,
        overlay_by_path,
        generated_paths,
        _cleanless_outputs,
    ) = _render_sources(bundle, project_root, read_payload=census.payload)
    ordinary_authority, generated_authority, physical_by_logical, source_payloads = (
        _include_authorities(
            bundle,
            project_root=project_root,
            toolchain_root=toolchain_root,
            effective_sources=effective_sources,
            # Cleanless overlay headers are installed in the ordinary epoch.
            # Only the explicit generated-TU/carrier set is deferred behind
            # the ordinary producer barrier, matching the cold runtime.
            deferred_outputs=generated_paths,
            snapshot=census.snapshot,
        )
    )
    system_libraries = _graph_system_library_map(
        bundle,
        graph,
        installation,
        effective_root=project_root,
        build_root=planner_build_root,
    )
    units = prepare_classic_units(
        bundle,
        clean_sources=clean_sources,
        effective_sources=effective_sources,
        overlay_dialect=_overlay_dialect(bundle),
    )
    units_by_id: dict[str, ClassicPreparedUnit] = {}
    for unit in units:
        if unit.plan.id in units_by_id:
            raise ClassicIncrementalError(
                f"warm build repeats prepared translation unit {unit.plan.id!r}"
            )
        units_by_id[unit.plan.id] = unit
    try:
        planned_compilers = classic_compiler_translation_unit_authority(bundle, graph)
    except ClassicProjectError as exc:
        raise ClassicIncrementalError(str(exc)) from exc
    documents_by_unit = {
        document.translation_unit_id: document
        for document in bundle.intervention_documents
        if document.translation_unit_id is not None
    }

    source_root = normalize_logical_path(bundle.spec.paths.source)
    toolchain_logical_root = normalize_logical_path(bundle.spec.paths.toolchain)
    authority_by_epoch = {
        False: ordinary_authority,
        True: generated_authority,
    }
    authority_files = {
        generated: {item.logical_path.casefold(): item for item in current.files}
        for generated, current in authority_by_epoch.items()
    }
    oracle_snapshots: dict[str, SecureFileSnapshot] = {}
    oracle_paths: dict[str, Path] = {}
    legacy_target_ids = {action.oracle_target for unit in units for action in unit.legacy_actions}
    for target in bundle.spec.targets:
        if target.id not in legacy_target_ids:
            continue
        path = project_root.joinpath(*PurePosixPath(target.oracle).parts)
        oracle_paths[target.id] = path
        oracle_snapshots[target.id] = census.snapshot(path)
    if set(oracle_paths) != legacy_target_ids:
        raise ClassicIncrementalError(
            "warm legacy transform names unknown oracle targets: "
            f"{sorted(legacy_target_ids - set(oracle_paths))}"
        )

    graph_output_owner = {
        reference.casefold(): node.id for node in graph.nodes for reference in node.outputs
    }
    compiler_nodes = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    compiler_sources: dict[str, str] = {}
    generated_nodes: set[str] = set()
    for node_id, node in compiler_nodes.items():
        sources = tuple(
            reference.removeprefix("source/")
            for reference in node.inputs
            if reference.startswith("source/")
            and PurePosixPath(reference).suffix.casefold() in {".c", ".cc", ".cpp", ".cxx"}
        )
        if len(sources) != 1:
            raise ClassicIncrementalError(
                f"compiler node {node_id!r} lacks one translation-unit source"
            )
        compiler_sources[node_id] = sources[0]
        if sources[0].casefold() in generated_paths:
            generated_nodes.add(node_id)
    compiler_units: dict[str, ClassicPreparedUnit] = {}
    for node_id, plan in planned_compilers.items():
        prepared_unit = units_by_id.get(plan.id)
        if prepared_unit is None or prepared_unit.plan != plan:
            raise ClassicIncrementalError(
                f"warm prepared translation unit differs from build plan: {plan.id!r}"
            )
        compiler_units[node_id] = prepared_unit

    output_paths: dict[str, Mapping[str, Path]] = {}
    for node in graph.nodes:
        directory = staging_root / "nodes" / node.id
        output_paths[node.id] = MappingProxyType(
            {
                reference: directory / f"{index:03d}-{PurePosixPath(reference).name}"
                for index, reference in enumerate(node.outputs)
            }
        )
    transform_ids = {node_id: f"transform.{node_id}" for node_id in compiler_units}
    transform_paths = {
        node_id: MappingProxyType(
            {
                reference: staging_root
                / "transforms"
                / node_id
                / f"{index:03d}-{PurePosixPath(reference).name}"
                for index, reference in enumerate(node.outputs)
            }
        )
        for node_id, node in compiler_nodes.items()
        if node_id in compiler_units
    }
    effective_owner = dict(graph_output_owner)
    for node_id, node in compiler_nodes.items():
        if node_id not in transform_ids:
            continue
        for reference in node.outputs:
            effective_owner[reference.casefold()] = transform_ids[node_id]

    def staged_reference_inputs(
        consumer_id: str,
        references: Sequence[str],
        *,
        owners_by_reference: Mapping[str, str] = effective_owner,
    ) -> tuple[
        Mapping[str, Path],
        Callable[
            [CacheLease, Mapping[str, NodeOutcome]], PreparedNodeInputs
        ]
        | None,
    ]:
        selected = tuple(
            sorted(
                {reference for reference in references if reference.startswith("build/")},
                key=str.casefold,
            )
        )
        if not selected:
            return MappingProxyType({}), None
        values = MappingProxyType(
            {
                reference: staging_root
                / "inputs"
                / consumer_id
                / f"{index:03d}-{PurePosixPath(reference).name}"
                for index, reference in enumerate(selected)
            }
        )
        owners: dict[str, str] = {}
        for reference in selected:
            owner = owners_by_reference.get(reference.casefold())
            if owner is None:
                raise ClassicIncrementalError(
                    f"warm input {reference!r} has no graph output owner"
                )
            owners[reference] = owner

        def materialize(
            lease: CacheLease,
            outcomes: Mapping[str, NodeOutcome],
        ) -> PreparedNodeInputs:
            grouped: dict[str, dict[str, Path]] = {}
            for reference, destination in values.items():
                owner = owners[reference]
                if owner not in outcomes:
                    raise ClassicIncrementalError(
                        f"warm input {reference!r} owner {owner!r} is incomplete"
                    )
                grouped.setdefault(owner, {})[reference] = destination
            entries: dict[str, ReceiptBoundInput] = {}
            for owner, destinations in sorted(grouped.items(), key=lambda item: item[0]):
                outcome = outcomes[owner]
                snapshots = lease.restore_selected(
                    outcome.record,
                    destinations,
                    allowed_root=staging_root,
                )
                receipts = {item.name: item for item in outcome.record.outputs}
                for reference in destinations:
                    entries[reference] = ReceiptBoundInput(
                        receipts[reference],
                        snapshots[reference],
                    )
            return PreparedNodeInputs(MappingProxyType(entries))

        return values, materialize

    effective_sources_by_path = {
        path.casefold(): payload for path, payload in effective_sources.items()
    }

    def reference_payload(
        reference: str,
        *,
        immutable_build_inputs: Mapping[str, Path] | None = None,
    ) -> bytes:
        kind, relative = reference.split("/", 1)
        if kind == "build":
            if immutable_build_inputs is None or reference not in immutable_build_inputs:
                raise ClassicIncrementalError(
                    f"warm build input {reference!r} lacks an immutable predecessor view"
                )
            build_payload, _receipt_value = _payload(immutable_build_inputs[reference])
            return build_payload
        if kind in {"source", "quarantine-archive"}:
            source_payload = effective_sources_by_path.get(relative.casefold())
            if source_payload is None:
                raise ClassicIncrementalError(
                    f"warm linker input is outside effective source authority: {reference!r}"
                )
            return source_payload
        if kind == "toolchain":
            toolchain_payload, _receipt_value = census.payload(
                toolchain_root.joinpath(*PurePosixPath(relative).parts)
            )
            return toolchain_payload
        if kind == "system-library":
            path = system_libraries.get(reference)
            if path is None:
                raise ClassicIncrementalError(
                    f"warm system library is unresolved: {reference!r}"
                )
            system_payload, _receipt_value = census.payload(path)
            return system_payload
        raise ClassicIncrementalError(
            f"warm linker input has an unsupported kind: {reference!r}"
        )

    def direct_inputs(node: ProducerNode, *, generated: bool) -> list[JsonValue]:
        values: list[JsonValue] = []
        files = authority_files[generated]
        for reference in (*node.inputs, *node.directive_inputs):
            if reference.startswith("build/"):
                continue
            kind, relative = reference.split("/", 1)
            if kind in {"source", "quarantine-archive"}:
                logical = _logical_join(source_root, relative)
                item = files.get(logical.casefold())
                if item is None:
                    raise ClassicIncrementalError(
                        f"warm direct input is outside source authority: {reference!r}"
                    )
                values.append(
                    _json(
                        {
                            "reference": reference,
                            "logical_path": item.logical_path,
                            "digest": item.digest.value,
                            "size": item.size,
                        }
                    )
                )
            elif kind == "toolchain":
                logical = _logical_join(toolchain_logical_root, relative)
                item = files.get(logical.casefold())
                if item is None:
                    raise ClassicIncrementalError(
                        f"warm direct input is outside toolchain authority: {reference!r}"
                    )
                values.append(
                    _json(
                        {
                            "reference": reference,
                            "logical_path": item.logical_path,
                            "digest": item.digest.value,
                            "size": item.size,
                        }
                    )
                )
            elif kind == "system-library":
                path = system_libraries.get(reference)
                if path is None:
                    raise ClassicIncrementalError(
                        f"warm system library is unresolved: {reference!r}"
                    )
                values.append(_receipt(reference, str(path), census.snapshot(path)))
            else:
                raise ClassicIncrementalError(
                    f"warm direct input has an unsupported kind: {reference!r}"
                )
        return values

    def sampled_reference_path(reference: str) -> Path | None:
        if reference.startswith("build/"):
            return None
        kind, relative = reference.split("/", 1)
        if kind in {"source", "quarantine-archive"}:
            resolved = project_root.joinpath(*PurePosixPath(relative).parts)
        elif kind == "toolchain":
            resolved = toolchain_root.joinpath(*PurePosixPath(relative).parts)
        elif kind == "system-library":
            system_path = system_libraries.get(reference)
            if system_path is None:
                raise ClassicIncrementalError(
                    f"warm system library is unresolved: {reference!r}"
                )
            resolved = system_path
        else:
            return None
        return census.known_path(resolved)

    def recursive_sampled_paths(logical_paths: Sequence[str]) -> tuple[Path, ...]:
        paths: set[Path] = set()
        for logical_path in logical_paths:
            physical = physical_by_logical.get(logical_path.casefold())
            if physical is None:
                raise ClassicIncrementalError(
                    f"warm recursive input lacks a physical authority: {logical_path!r}"
                )
            sampled = census.known_path(physical)
            if sampled is not None:
                paths.add(sampled)
        return tuple(sorted(paths, key=str))

    def verify_before_store(runtime: _WarmRuntime, paths: Sequence[Path]) -> None:
        # Global producer-readable namespace authority is held by the runtime
        # and verified once when it closes, before any staged record name is
        # published.  Per-node checks stay deliberately scoped to physical
        # inputs sampled for this node so N misses do not rehash the complete
        # authority N times.
        del runtime
        census.validate(paths)

    def node_arguments(node: ProducerNode) -> tuple[str, ...]:
        return (
            role_logical[node.role],
            *(
                materialize_argument(
                    value,
                    source_root=bundle.spec.paths.source,
                    build_root=bundle.spec.paths.build,
                    toolchain_root=bundle.spec.paths.toolchain,
                )
                for value in node.arguments
            ),
        )

    runtime_holder: dict[str, _WarmRuntime] = {}
    runtime_lock_guard = Lock()

    def runtime_factory() -> _WarmRuntime:
        with runtime_lock_guard:
            existing = runtime_holder.get("runtime")
            if existing is not None:
                return existing
            prepared = prepare_classic_producer_graph_run(
                bundle,
                project_root=project_root,
                session_root=session_root / "classic",
                toolchain_root=toolchain_root,
                backend=backend,
                jobs=jobs,
                compiler_transport=compiler_transport,
                resource_transport=resource_transport,
                initialization_timeout=initialization_timeout,
                compile_timeout=compile_timeout,
                link_timeout=link_timeout,
                cleanup_timeout=cleanup_timeout,
            )
            try:
                runtime = _WarmRuntime(
                    prepared,
                    staging_root=staging_root,
                    project_root=project_root,
                    oracle_paths=MappingProxyType(oracle_paths),
                    oracle_snapshots=MappingProxyType(oracle_snapshots),
                )
            except BaseException:
                prepared.close()
                raise
            runtime_holder["runtime"] = runtime
            return runtime

    compiler_states: dict[str, _CompilerState] = {}
    transform_states: dict[str, _TransformState] = {}
    nodes: list[IncrementalNode[_WarmRuntime]] = []
    ordinary_barrier = tuple(
        sorted(
            (
                *(
                    transform_ids.get(node_id, node_id)
                    for node_id in compiler_nodes
                    if node_id not in generated_nodes
                ),
                *(node.id for node in graph.nodes if node.role is ProducerRole.RESOURCE),
            ),
            key=str.casefold,
        )
    )

    for node in graph.nodes:
        generated = node.id in generated_nodes
        graph_dependencies = tuple(
            sorted(
                (transform_ids.get(dependency, dependency) for dependency in node.depends_on),
                key=str.casefold,
            )
        )
        order_only: tuple[str, ...] = ()
        if generated:
            added = tuple(
                dependency
                for dependency in ordinary_barrier
                if dependency not in graph_dependencies
            )
            graph_dependencies = tuple(sorted((*graph_dependencies, *added), key=str.casefold))
            order_only = tuple(sorted(added, key=str.casefold))
        arguments = node_arguments(node)
        direct = direct_inputs(node, generated=generated)
        sampled_inputs = {
            path
            for reference in (*node.inputs, *node.directive_inputs)
            for path in (sampled_reference_path(reference),)
            if path is not None
        }
        role_path = census.known_path(
            toolchain_root.joinpath(*PurePosixPath(role_relatives[node.role]).parts)
        )
        if role_path is not None:
            sampled_inputs.add(role_path)
        sampled_inputs.update(runtime_input_paths)
        overlay_inputs = tuple(
            overlay_by_path[path]
            for path in sorted(overlay_by_path, key=str.casefold)
            if path.casefold()
            in {
                reference.removeprefix("source/").casefold()
                for reference in node.inputs
                if reference.startswith("source/")
            }
        )
        generated_inputs = tuple(
            overlay_by_path[path]
            for path in sorted(overlay_by_path, key=str.casefold)
            if generated and path.casefold() in generated_paths
        )

        if node.role is ProducerRole.COMPILER:
            source, cwd, include_dirs, env_dirs, force_includes = _compiler_parameters(
                node,
                bundle=bundle,
                compiler_logical=role_logical[ProducerRole.COMPILER],
                environment=environment,
            )

            def compiler_material(
                dependencies: Mapping[str, NodeOutcome],
                *,
                current_node: ProducerNode = node,
                current_direct: tuple[JsonValue, ...] = tuple(direct),
                current_overlay: tuple[JsonValue, ...] = overlay_inputs,
                current_generated: tuple[JsonValue, ...] = generated_inputs,
                current_arguments: tuple[str, ...] = arguments,
            ) -> dict[str, JsonValue]:
                return _base_material(
                    bundle=bundle,
                    graph_digest=graph_digest_value,
                    node_identity=_json(current_node.model_dump(mode="json")),
                    role=current_node.role.value,
                    toolchain=toolchain_material,
                    runtime=runtime_material,
                    argv=current_arguments,
                    environment=environment,
                    direct_inputs=current_direct,
                    dependencies=dependencies,
                    recursive_reads=(),
                    overlay_inputs=current_overlay,
                    generated_inputs=current_generated,
                )

            empty_material = compiler_material(MappingProxyType({}))
            base_key = compiler_base_key(empty_material)
            state = _CompilerState(
                base_key,
                empty_material,
                physical_inputs=tuple(sorted(sampled_inputs, key=str)),
            )
            compiler_states[node.id] = state
            selected_authority = authority_by_epoch[generated]
            source_relative = compiler_sources[node.id]
            selected_compiler_unit = compiler_units.get(node.id)
            translation_unit_id = (
                selected_compiler_unit.plan.id
                if selected_compiler_unit is not None
                else node.id
            )

            def compiler_probe(
                lease: CacheLease,
                dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: _CompilerState = state,
                current_authority: SealedIncludeAuthority = selected_authority,
                current_source: str = source,
                current_cwd: str = cwd,
                current_include_dirs: tuple[str, ...] = include_dirs,
                current_env_dirs: tuple[str, ...] = env_dirs,
                current_force_includes: tuple[str, ...] = force_includes,
                current_translation_unit_id: str = translation_unit_id,
                current_source_relative: str = source_relative,
                current_material: Callable[
                    [Mapping[str, NodeOutcome]], dict[str, JsonValue]
                ] = compiler_material,
            ) -> CacheProbeDecision:
                material = current_material(dependencies)
                current_state.base_material = material
                current_state.base_key = compiler_base_key(material)
                probe = probe_compiler_cache(
                    lease,
                    base_key=current_state.base_key,
                    base_material=material,
                    expected_working_directory=current_cwd,
                    expected_source=current_source,
                    include_directories=current_include_dirs,
                    environment_directories=current_env_dirs,
                    force_includes=current_force_includes,
                    authority=current_authority,
                )
                if probe.reads:
                    current_state.physical_inputs = tuple(
                        sorted(
                            {
                                *current_state.physical_inputs,
                                *recursive_sampled_paths(
                                    tuple(item.logical_path for item in probe.reads)
                                ),
                            },
                            key=str,
                        )
                    )
                    require_fresh_protected_recursive_inputs(
                        authority,
                        translation_unit_id=current_translation_unit_id,
                        source=current_source_relative,
                        recursive_logical_paths=(item.logical_path for item in probe.reads),
                    )
                current_state.hint = probe.hint
                current_state.final_key = probe.key
                return CacheProbeDecision(
                    probe.key,
                    probe.record,
                    probe.reason,
                )

            _compiler_inputs, compiler_input_materializer = staged_reference_inputs(
                node.id,
                node.inputs,
            )

            def compiler_action(
                runtime: _WarmRuntime,
                cancellation: CancellationToken,
                prepared_inputs: PreparedNodeInputs,
                *,
                current_node: ProducerNode = node,
                current_outputs: Mapping[str, Path] = output_paths[node.id],
                current_state: _CompilerState = state,
                current_authority: SealedIncludeAuthority = selected_authority,
                current_source: str = source,
                current_cwd: str = cwd,
                current_include_dirs: tuple[str, ...] = include_dirs,
                current_env_dirs: tuple[str, ...] = env_dirs,
                current_force_includes: tuple[str, ...] = force_includes,
                current_translation_unit_id: str = translation_unit_id,
                current_source_relative: str = source_relative,
            ) -> None:
                runtime.prepared.executor.execute_warm_graph_node(
                    current_node.id,
                    inputs=prepared_inputs,
                    outputs=current_outputs,
                    cancellation=cancellation,
                )
                replay = runtime.prepared.executor.replay_warm_compiler_dependencies(
                    current_node.id,
                    cancellation=cancellation,
                )
                if replay.trace is None:
                    assert replay.reason is not None
                    current_state.replay_failure = replay.reason
                else:
                    try:
                        reads = resolve_msvc_include_trace(
                            replay.trace,
                            expected_working_directory=current_cwd,
                            expected_source=current_source,
                            include_directories=current_include_dirs,
                            environment_directories=current_env_dirs,
                            force_includes=current_force_includes,
                            authority=current_authority,
                        )
                    except ClassicIncludeTraceError as exc:
                        current_state.replay_failure = str(exc)
                    else:
                        current_state.physical_inputs = tuple(
                            sorted(
                                {
                                    *current_state.physical_inputs,
                                    *recursive_sampled_paths(
                                        tuple(item.logical_path for item in reads)
                                    ),
                                },
                                key=str,
                            )
                        )
                        require_fresh_protected_recursive_inputs(
                            authority,
                            translation_unit_id=current_translation_unit_id,
                            source=current_source_relative,
                            recursive_logical_paths=(item.logical_path for item in reads),
                        )
                        current_state.hint = CompilerDependencyHint(
                            current_state.base_key,
                            replay.trace.working_directory,
                            replay.trace.sources,
                        )
                        current_state.final_key = compiler_cache_final_key(
                            current_state.base_material, reads
                        )
                if current_state.replay_failure is not None:
                    if (
                        current_source_relative.casefold() in authority.protected_sources
                        and authority.changed_paths
                    ):
                        interventions = authority.protected_sources[
                            current_source_relative.casefold()
                        ]
                        raise ClassicIncrementalError(
                            "cannot revalidate recursive inputs for protected "
                            f"translation unit {current_translation_unit_id!r}: "
                            f"{current_state.replay_failure}; affected reviewed "
                            f"intervention(s): {', '.join(interventions)}"
                        )
                    fallback = dict(current_state.base_material)
                    fallback["recursive_reads"] = _json(
                        [
                            {
                                "unusable_dependency_replay": current_state.replay_failure,
                                "invocation": uuid.uuid4().hex,
                            }
                        ]
                    )
                    current_state.final_key = producer_cache_key(fallback)
                    current_state.hint = None

            def compiler_final_key_factory(
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: _CompilerState = state,
            ) -> str:
                if current_state.final_key is None:
                    raise ClassicIncrementalError(
                        "compiler action omitted its final dependency key"
                    )
                return current_state.final_key

            def compiler_metadata(
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: _CompilerState = state,
                current_node: ProducerNode = node,
            ) -> Mapping[str, JsonValue]:
                additional: dict[str, JsonValue] = {
                    "node_id": current_node.id,
                    "certifying": False,
                }
                if current_state.replay_failure is not None:
                    additional["dependency_replay_failure"] = current_state.replay_failure
                if current_state.hint is None:
                    return MappingProxyType(additional)
                return compiler_hint_metadata(
                    current_state.hint,
                    additional=additional,
                )

            def compiler_key_factory(
                dependencies: Mapping[str, NodeOutcome],
                *,
                current: Callable[
                    [Mapping[str, NodeOutcome]], dict[str, JsonValue]
                ] = compiler_material,
            ) -> str:
                return compiler_base_key(current(dependencies))

            def compiler_pre_store(
                runtime: _WarmRuntime,
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: _CompilerState = state,
            ) -> None:
                verify_before_store(runtime, current_state.physical_inputs)

            nodes.append(
                IncrementalNode(
                    id=node.id,
                    domain="producer",
                    depends_on=graph_dependencies,
                    outputs=output_paths[node.id],
                    key=compiler_key_factory,
                    execute=compiler_action,
                    metadata=compiler_metadata,
                    pre_store=compiler_pre_store,
                    materialize_inputs=compiler_input_materializer,
                    final_key=compiler_final_key_factory,
                    probe=compiler_probe,
                    order_only=order_only,
                )
            )
        else:
            recursive_reads: tuple[JsonValue, ...] = ()
            if node.role is ProducerRole.RESOURCE:
                current_authority = ordinary_authority
                arguments_without_tool = arguments[1:]
                include_directories: list[str] = []
                index = 0
                while index < len(arguments_without_tool) - 1:
                    value = arguments_without_tool[index]
                    folded = value.casefold()
                    if folded in {"/i", "-i"}:
                        include_directories.append(arguments_without_tool[index + 1])
                        index += 2
                        continue
                    if folded.startswith(("/i", "-i")) and len(value) > 2:
                        include_directories.append(value[2:])
                    index += 1
                source_refs = tuple(
                    reference
                    for reference in node.inputs
                    if reference.startswith("source/")
                    and PurePosixPath(reference).suffix.casefold() == ".rc"
                )
                if len(source_refs) != 1:
                    raise ClassicIncrementalError(f"resource node {node.id!r} lacks one RC source")
                payloads: dict[str, bytes] = {}
                for item in current_authority.files:
                    payload = source_payloads.get(item.logical_path)
                    if payload is None:
                        physical = physical_by_logical.get(item.logical_path.casefold())
                        if physical is None:
                            raise ClassicIncrementalError(
                                f"resource authority lacks bytes for {item.logical_path!r}"
                            )
                        payload, snapshot = census.payload(physical)
                        if snapshot.digest != item.digest or snapshot.size != item.size:
                            raise ClassicIncrementalError(
                                f"resource authority changed: {item.logical_path!r}"
                            )
                    payloads[item.logical_path] = payload
                resource_receipt = scan_msvc_resource_dependencies(
                    source_path=_logical_join(source_root, source_refs[0].removeprefix("source/")),
                    include_directories=tuple(include_directories),
                    environment_directories=tuple(environment["INCLUDE"].split(";")),
                    authority=current_authority,
                    payloads=MappingProxyType(payloads),
                )
                recursive_reads = tuple(
                    _json(
                        {
                            "logical_path": item.logical_path,
                            "digest": item.digest.value,
                            "size": item.size,
                            "origin": item.origin.value,
                            "kind": item.kind.value,
                            "parent_path": item.parent_path,
                        }
                    )
                    for item in resource_receipt.reads
                )
                sampled_inputs.update(
                    recursive_sampled_paths(
                        tuple(item.logical_path for item in resource_receipt.reads)
                    )
                )

            link_references: tuple[str, ...] = ()
            if node.role is ProducerRole.LINKER:
                link_reference_groups = _warm_link_control_references(node, graph.nodes)
                link_references = tuple(
                    reference
                    for group in link_reference_groups
                    for reference in group
                )
            staged_inputs, producer_input_materializer = staged_reference_inputs(
                node.id,
                (*node.inputs, *link_references),
            )

            def producer_material(
                dependencies: Mapping[str, NodeOutcome],
                *,
                current_node: ProducerNode = node,
                current_direct: tuple[JsonValue, ...] = tuple(direct),
                current_recursive: tuple[JsonValue, ...] = recursive_reads,
                current_overlay: tuple[JsonValue, ...] = overlay_inputs,
                current_arguments: tuple[str, ...] = arguments,
                current_immutable_inputs: Mapping[str, Path] = staged_inputs,
            ) -> dict[str, JsonValue]:
                link_controls = (
                    (_warm_link_control_material(
                        current_node,
                        graph.nodes,
                        payload_for_reference=partial(
                            reference_payload,
                            immutable_build_inputs=current_immutable_inputs,
                        ),
                    ),)
                    if current_node.role is ProducerRole.LINKER
                    else ()
                )
                return _base_material(
                    bundle=bundle,
                    graph_digest=graph_digest_value,
                    node_identity=_json(current_node.model_dump(mode="json")),
                    role=current_node.role.value,
                    toolchain=toolchain_material,
                    runtime=runtime_material,
                    argv=current_arguments,
                    environment=environment,
                    direct_inputs=current_direct,
                    dependencies=dependencies,
                    recursive_reads=current_recursive,
                    overlay_inputs=current_overlay,
                    composition_inputs=link_controls,
                )

            def producer_action(
                runtime: _WarmRuntime,
                cancellation: CancellationToken,
                prepared_inputs: PreparedNodeInputs,
                *,
                current_node: ProducerNode = node,
                current_outputs: Mapping[str, Path] = output_paths[node.id],
            ) -> None:
                runtime.prepared.executor.execute_warm_graph_node(
                    current_node.id,
                    inputs=prepared_inputs,
                    outputs=current_outputs,
                    cancellation=cancellation,
                )

            def producer_key_factory(
                dependencies: Mapping[str, NodeOutcome],
                *,
                current: Callable[
                    [Mapping[str, NodeOutcome]], dict[str, JsonValue]
                ] = producer_material,
            ) -> str:
                return producer_cache_key(current(dependencies))

            def producer_metadata(
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current: ProducerNode = node,
            ) -> Mapping[str, JsonValue]:
                return MappingProxyType({"node_id": current.id, "certifying": False})

            def producer_pre_store(
                runtime: _WarmRuntime,
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_paths: tuple[Path, ...] = tuple(
                    sorted(sampled_inputs, key=str)
                ),
            ) -> None:
                verify_before_store(runtime, current_paths)

            nodes.append(
                IncrementalNode(
                    id=node.id,
                    domain="producer",
                    depends_on=graph_dependencies,
                    outputs=output_paths[node.id],
                    key=producer_key_factory,
                    execute=producer_action,
                    metadata=producer_metadata,
                    pre_store=producer_pre_store,
                    materialize_inputs=producer_input_materializer,
                    materialize_before_probe=node.role is ProducerRole.LINKER,
                    order_only=order_only,
                )
            )

    all_overlay_inputs = tuple(
        overlay_by_path[path] for path in sorted(overlay_by_path, key=str.casefold)
    )
    for compiler_id, transform_unit in compiler_units.items():
        compiler_node = compiler_nodes[compiler_id]
        selected_transform_document = documents_by_unit.get(transform_unit.plan.id)
        if selected_transform_document is None:
            raise ClassicIncrementalError(
                f"warm transform lacks intervention shard for {transform_unit.plan.id!r}"
            )
        transform_document = selected_transform_document
        intervention_ids = {item.id for item in transform_document.interventions}
        proofs = tuple(
            _json(receipt.model_dump(mode="json"))
            for proof in bundle.proof_documents
            for receipt in proof.expected_observations
            if receipt.intervention_id in intervention_ids
        )
        donor_inputs = tuple(
            _json(
                {
                    "intervention": donor.intervention.model_dump(mode="json"),
                    "request": {
                        "intervention_id": donor.request.receipt.intervention_id,
                        "family": donor.request.receipt.family.value,
                        "constraints_digest": donor.request.receipt.constraints_digest.value,
                        "input_digests": dict(donor.request.receipt.input_digests),
                        "output_digests": dict(donor.request.receipt.output_digests),
                        "compiler_additions_digest": (
                            donor.request.receipt.compiler_additions_digest.value
                        ),
                        "rendering_digest": donor.request.receipt.rendering_digest.value,
                    },
                    "files": {
                        path: Digest.from_bytes(payload).value
                        for path, payload in sorted(
                            donor.request.files.items(), key=lambda item: item[0].casefold()
                        )
                    },
                }
            )
            for donor in transform_unit.donors
        )
        legacy_targets = tuple(
            sorted(
                {action.oracle_target for action in transform_unit.legacy_actions},
                key=str.casefold,
            )
        )
        oracle_inputs = tuple(
            _receipt(
                f"oracle/{target_id}",
                str(oracle_paths[target_id]),
                oracle_snapshots[target_id],
            )
            for target_id in legacy_targets
        )
        transform_sampled_paths = tuple(
            sorted(
                (
                    path
                    for target_id in legacy_targets
                    for path in (census.known_path(oracle_paths[target_id]),)
                    if path is not None
                ),
                key=str,
            )
        )
        raw_outputs = output_paths[compiler_id]
        transformed_outputs = transform_paths[compiler_id]
        transform_id = transform_ids[compiler_id]
        transform_contexts = _projected_donor_resolution_contexts(
            transform_unit,
            compiler_nodes=compiler_nodes,
            compiler_sources=compiler_sources,
            node_arguments=node_arguments,
            source_root=source_root,
            build_root=bundle.spec.paths.build,
            environment=environment,
            authority=authority_by_epoch[compiler_id in generated_nodes],
        )
        object_refs = tuple(
            reference
            for reference in compiler_node.outputs
            if PurePosixPath(reference).suffix.casefold() == ".obj"
        )
        if len(object_refs) != 1:
            raise ClassicIncrementalError(
                f"warm compiler transform {compiler_id!r} lacks one object output"
            )
        object_value = object_refs[0].removeprefix("build/")
        selected_rdata_inputs = rdata_material_by_object.get(
            object_value.casefold(), ()
        )
        _transform_inputs, transform_input_materializer = staged_reference_inputs(
            transform_id,
            tuple(raw_outputs),
            owners_by_reference=graph_output_owner,
        )

        def transform_material(
            dependencies: Mapping[str, NodeOutcome],
            *,
            current_id: str = compiler_id,
            current_node: ProducerNode = compiler_node,
            current_unit: ClassicPreparedUnit = transform_unit,
            current_document: object = transform_document.model_dump(mode="json"),
            current_proofs: tuple[JsonValue, ...] = proofs,
            current_donors: tuple[JsonValue, ...] = donor_inputs,
            current_oracles: tuple[JsonValue, ...] = oracle_inputs,
            current_rdata: tuple[JsonValue, ...] = selected_rdata_inputs,
        ) -> dict[str, JsonValue]:
            return _base_material(
                bundle=bundle,
                graph_digest=graph_digest_value,
                node_identity=_json(
                    {
                        "id": transform_ids[current_id],
                        "compiler_node": current_node.model_dump(mode="json"),
                        "translation_unit": current_unit.plan.model_dump(mode="json"),
                    }
                ),
                role="compiler-transform",
                toolchain=toolchain_material,
                runtime=runtime_material,
                argv=("internal:classic-tu-transform",),
                environment=environment,
                direct_inputs=current_oracles,
                dependencies=dependencies,
                recursive_reads=(),
                overlay_inputs=all_overlay_inputs,
                donor_inputs=current_donors,
                composition_inputs=(_json(current_document), *current_proofs),
                transform_inputs=(
                    *( _json(item.model_dump(mode="json")) for item in current_unit.actions),
                    *current_rdata,
                ),
            )

        transform_state: _TransformState | None = None
        if transform_contexts:
            empty_material = transform_material(MappingProxyType({}))
            transform_state = _TransformState(
                donor_transform_base_key(empty_material),
                empty_material,
                physical_inputs=transform_sampled_paths,
            )
            transform_states[transform_id] = transform_state

        def transform_probe(
            lease: CacheLease,
            dependencies: Mapping[str, NodeOutcome],
            *,
            current_state: _TransformState | None = transform_state,
            current_contexts: tuple[
                DonorDependencyResolutionContext, ...
            ] = transform_contexts,
            current_unit: ClassicPreparedUnit = transform_unit,
            current_material: Callable[
                [Mapping[str, NodeOutcome]], dict[str, JsonValue]
            ] = transform_material,
        ) -> CacheProbeDecision:
            if current_state is None:
                raise ClassicIncrementalError(
                    "projected transform probe lacks mutable dependency state"
                )
            material = current_material(dependencies)
            current_state.base_material = material
            current_state.base_key = donor_transform_base_key(material)
            probe = probe_donor_transform_cache(
                lease,
                base_key=current_state.base_key,
                base_material=material,
                contexts=current_contexts,
            )
            if probe.dependencies:
                logical_paths = donor_transform_authority_paths(
                    current_contexts,
                    probe.dependencies,
                )
                current_state.physical_inputs = tuple(
                    sorted(
                        {
                            *current_state.physical_inputs,
                            *recursive_sampled_paths(logical_paths),
                        },
                        key=str,
                    )
                )
                require_fresh_protected_recursive_inputs(
                    authority,
                    translation_unit_id=current_unit.plan.id,
                    source=current_unit.plan.source,
                    recursive_logical_paths=logical_paths,
                )
            current_state.hint = probe.hint
            current_state.final_key = probe.key
            return CacheProbeDecision(probe.key, probe.record, probe.reason)

        def transform_action(
            runtime: _WarmRuntime,
            cancellation: CancellationToken,
            prepared_inputs: PreparedNodeInputs,
            *,
            current_id: str = compiler_id,
            current_outputs: Mapping[str, Path] = transformed_outputs,
            needs_oracle: bool = bool(legacy_targets),
            current_state: _TransformState | None = transform_state,
            current_contexts: tuple[
                DonorDependencyResolutionContext, ...
            ] = transform_contexts,
            current_unit: ClassicPreparedUnit = transform_unit,
        ) -> None:
            if needs_oracle:
                runtime.ensure_oracles()
            result = runtime.prepared.executor.execute_warm_compiler_transform(
                current_id,
                inputs=prepared_inputs,
                outputs=current_outputs,
                cancellation=cancellation,
            )
            if current_state is None:
                return
            if not isinstance(result, _ClassicWarmCompilerTransformResult):
                raise ClassicIncrementalError(
                    "warm compiler transform omitted its donor dependency result"
                )
            replays = tuple(
                sorted(
                    result.donor_dependencies,
                    key=lambda item: item.donor_id.casefold(),
                )
            )
            expected_ids = tuple(item.donor_id for item in current_contexts)
            replay_ids = tuple(item.donor_id for item in replays)
            if replay_ids != expected_ids:
                current_state.replay_failure = (
                    "runtime projected-donor universe differs from the planner"
                )
            else:
                traces: list[DonorDependencyTrace] = []
                runtime_dependencies: list[DonorResolvedDependencies] = []
                for replay in replays:
                    if replay.trace is None:
                        assert replay.reason is not None
                        current_state.replay_failure = replay.reason
                        break
                    traces.append(
                        DonorDependencyTrace(
                            replay.donor_id,
                            replay.trace.working_directory,
                            replay.trace.sources,
                        )
                    )
                    runtime_dependencies.append(
                        DonorResolvedDependencies(replay.donor_id, replay.reads)
                    )
                if current_state.replay_failure is None:
                    trace_tuple = tuple(traces)
                    try:
                        resolved = resolve_donor_transform_dependencies(
                            trace_tuple,
                            current_contexts,
                        )
                    except (ClassicCacheHintError, ClassicIncludeTraceError) as exc:
                        current_state.replay_failure = str(exc)
                    else:
                        if resolved != tuple(runtime_dependencies):
                            current_state.replay_failure = (
                                "runtime projected-donor reads differ from planner resolution"
                            )
                        else:
                            logical_paths = donor_transform_authority_paths(
                                current_contexts,
                                resolved,
                            )
                            current_state.physical_inputs = tuple(
                                sorted(
                                    {
                                        *current_state.physical_inputs,
                                        *recursive_sampled_paths(logical_paths),
                                    },
                                    key=str,
                                )
                            )
                            require_fresh_protected_recursive_inputs(
                                authority,
                                translation_unit_id=current_unit.plan.id,
                                source=current_unit.plan.source,
                                recursive_logical_paths=logical_paths,
                            )
                            current_state.hint = DonorTransformDependencyHint(
                                current_state.base_key,
                                trace_tuple,
                            )
                            current_state.final_key = donor_transform_final_key(
                                current_state.base_material,
                                resolved,
                            )
            if current_state.replay_failure is not None:
                if (
                    current_unit.plan.source.casefold() in authority.protected_sources
                    and authority.changed_paths
                ):
                    interventions = authority.protected_sources[
                        current_unit.plan.source.casefold()
                    ]
                    raise ClassicIncrementalError(
                        "cannot revalidate projected donor inputs for protected "
                        f"translation unit {current_unit.plan.id!r}: "
                        f"{current_state.replay_failure}; affected reviewed "
                        f"intervention(s): {', '.join(interventions)}"
                    )
                fallback = dict(current_state.base_material)
                fallback["recursive_reads"] = _json(
                    [
                        {
                            "unusable_donor_dependency_replay": (
                                current_state.replay_failure
                            ),
                            "invocation": uuid.uuid4().hex,
                        }
                    ]
                )
                current_state.final_key = producer_cache_key(fallback)
                current_state.hint = None

        def transform_key_factory(
            dependencies: Mapping[str, NodeOutcome],
            *,
            current: Callable[
                [Mapping[str, NodeOutcome]], dict[str, JsonValue]
            ] = transform_material,
            current_state: _TransformState | None = transform_state,
        ) -> str:
            material = current(dependencies)
            return (
                donor_transform_base_key(material)
                if current_state is not None
                else producer_cache_key(material)
            )

        def transform_final_key_factory(
            _dependencies: Mapping[str, NodeOutcome],
            *,
            current_state: _TransformState | None = transform_state,
        ) -> str:
            if current_state is None:
                raise ClassicIncrementalError(
                    "projected transform final key lacks dependency state"
                )
            if current_state.final_key is None:
                raise ClassicIncrementalError(
                    "compiler transform omitted its final donor dependency key"
                )
            return current_state.final_key

        def transform_metadata(
            _dependencies: Mapping[str, NodeOutcome],
            *,
            current: str = transform_id,
            current_state: _TransformState | None = transform_state,
        ) -> Mapping[str, JsonValue]:
            additional: dict[str, JsonValue] = {
                "node_id": current,
                "certifying": False,
            }
            if current_state is None:
                return MappingProxyType(additional)
            if current_state.replay_failure is not None:
                additional["donor_dependency_replay_failure"] = (
                    current_state.replay_failure
                )
            if current_state.hint is None:
                return MappingProxyType(additional)
            return donor_transform_hint_metadata(
                current_state.hint,
                additional=additional,
            )

        def transform_pre_store(
            runtime: _WarmRuntime,
            _dependencies: Mapping[str, NodeOutcome],
            *,
            current_paths: tuple[Path, ...] = transform_sampled_paths,
            current_state: _TransformState | None = transform_state,
        ) -> None:
            verify_before_store(
                runtime,
                current_state.physical_inputs
                if current_state is not None
                else current_paths,
            )

        nodes.append(
            IncrementalNode(
                id=transform_id,
                domain="producer",
                depends_on=(compiler_id,),
                outputs=transformed_outputs,
                key=transform_key_factory,
                execute=transform_action,
                metadata=transform_metadata,
                pre_store=transform_pre_store,
                materialize_inputs=transform_input_materializer,
                phase=IncrementalPhase.TRANSFORM,
                final_key=(
                    transform_final_key_factory
                    if transform_state is not None
                    else None
                ),
                probe=transform_probe if transform_state is not None else None,
            )
        )

    terminal_nodes: dict[str, str] = {}
    terminal_paths: dict[str, Path] = {}
    targets_by_id = {item.id: item for item in bundle.spec.targets}
    for linker in (node for node in graph.nodes if node.role is ProducerRole.LINKER):
        assert linker.target_id is not None
        target_id = linker.target_id
        target = targets_by_id[target_id]
        primary = tuple(
            reference
            for reference in linker.outputs
            if PurePosixPath(reference).suffix.casefold()
            == PurePosixPath(target.artifact).suffix.casefold()
        )
        if len(primary) != 1:
            raise ClassicIncrementalError(f"linker {linker.id!r} lacks one target image output")
        terminal_id = f"terminal.{target_id}"
        terminal_path = staging_root / "terminal" / target_id / "artifact"
        terminal_nodes[target_id] = terminal_id
        terminal_paths[target_id] = terminal_path
        _terminal_inputs, terminal_input_materializer = staged_reference_inputs(
            terminal_id,
            primary,
        )
        quarantine = tuple(direct_inputs(linker, generated=bool(generated_nodes)))
        terminal_authority = tuple(
            _json(
                {
                    "intervention": intervention.model_dump(mode="json"),
                    "proof": receipt.model_dump(mode="json"),
                }
            )
            for intervention, receipt in classic_terminal_pipeline_authority(
                bundle,
                target_id=target_id,
            )
        )

        def terminal_material(
            dependencies: Mapping[str, NodeOutcome],
            *,
            current_linker: ProducerNode = linker,
            current_target: str = target_id,
            current_quarantine: tuple[JsonValue, ...] = quarantine,
            current_interventions: tuple[JsonValue, ...] = terminal_authority,
        ) -> dict[str, JsonValue]:
            return _base_material(
                bundle=bundle,
                graph_digest=graph_digest_value,
                node_identity=_json(
                    {
                        "id": f"terminal.{current_target}",
                        "linker": current_linker.model_dump(mode="json"),
                    }
                ),
                role="terminal-transform",
                toolchain=toolchain_material,
                runtime=runtime_material,
                argv=("internal:classic-terminal-pipeline", current_target),
                environment=environment,
                direct_inputs=current_quarantine,
                dependencies=dependencies,
                recursive_reads=(),
                composition_inputs=(_json(bundle.spec.authenticity.model_dump(mode="json")),),
                transform_inputs=current_interventions,
            )

        def terminal_action(
            runtime: _WarmRuntime,
            _cancellation: CancellationToken,
            prepared_inputs: PreparedNodeInputs,
            *,
            current_target: str = target_id,
            current_output: Path = terminal_path,
        ) -> None:
            runtime.prepared.executor.execute_warm_terminal(
                current_target,
                inputs=prepared_inputs,
                destination=current_output,
            )

        def terminal_key_factory(
            dependencies: Mapping[str, NodeOutcome],
            *,
            current: Callable[
                [Mapping[str, NodeOutcome]], dict[str, JsonValue]
            ] = terminal_material,
        ) -> str:
            return producer_cache_key(current(dependencies))

        def terminal_metadata(
            _dependencies: Mapping[str, NodeOutcome],
            *,
            current: str = terminal_id,
        ) -> Mapping[str, JsonValue]:
            return MappingProxyType({"node_id": current, "certifying": False})

        def terminal_pre_store(
            runtime: _WarmRuntime,
            _dependencies: Mapping[str, NodeOutcome],
        ) -> None:
            verify_before_store(runtime, ())

        nodes.append(
            IncrementalNode(
                id=terminal_id,
                domain="producer",
                depends_on=(linker.id,),
                outputs=MappingProxyType({"artifact": terminal_path}),
                key=terminal_key_factory,
                execute=terminal_action,
                metadata=terminal_metadata,
                pre_store=terminal_pre_store,
                materialize_inputs=terminal_input_materializer,
                phase=IncrementalPhase.TRANSFORM,
            )
        )

    cache = IncrementalCache(
        state_root,
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )

    def lane_count() -> int:
        runtime = runtime_holder.get("runtime")
        return runtime.initialized_lane_count if runtime is not None else 0

    def before_record_publication() -> None:
        # This is the single complete invocation census at the cache trust
        # boundary.  Node hooks validate only their exact sampled closure;
        # editable-install code/asset drift is checked once after the runtime
        # namespace closes and before any record name becomes reusable.
        census.validate_all()
        revalidate_package_implementation(implementation_receipt)

    executor_progress: IncrementalProgress | None
    if progress is not None:

        def report_executor_progress(
            kind: ProgressKind,
            completed: int,
            total: int,
            phase: str,
            node_id: str,
            reason: str | None,
        ) -> None:
            progress(kind, completed, total + 1, phase, node_id, reason)

        executor_progress = report_executor_progress
    else:
        executor_progress = None

    execution = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=session_root,
        runtime_factory=runtime_factory,
        runtime_close=lambda runtime: runtime.close(),
        max_workers=jobs,
        progress=executor_progress,
        runtime_init_count=lane_count,
        before_publish=before_record_publication,
    ).execute(tuple(nodes))

    # Only complete, re-resolvable compiler traces enter bounded base history.
    with cache.lease() as lease:
        for node_id, compiler_state in compiler_states.items():
            outcome = execution.outcomes[node_id]
            # A hit is already present in this bounded recency index.  Rewriting
            # it on every no-change build adds mutable cache traffic without
            # improving lookup quality.
            if (
                outcome.cache_hit
                or compiler_state.hint is None
                or compiler_state.replay_failure is not None
            ):
                continue
            lease.index_record(
                "producer",
                "compiler-base",
                compiler_state.base_key,
                outcome.record,
            )
        for node_id, transform_state_value in transform_states.items():
            outcome = execution.outcomes[node_id]
            if (
                outcome.cache_hit
                or transform_state_value.hint is None
                or transform_state_value.replay_failure is not None
            ):
                continue
            lease.index_record(
                "producer",
                "donor-transform-base",
                transform_state_value.base_key,
                outcome.record,
            )

    invalidations = dict(execution.summary.invalidations)
    for node_id, compiler_state in compiler_states.items():
        if compiler_state.replay_failure is not None:
            invalidations[node_id] = (
                "dependency replay unusable; compiler result was not indexed or reusable: "
                + compiler_state.replay_failure
            )
    for node_id, transform_state_value in transform_states.items():
        if transform_state_value.replay_failure is not None:
            invalidations[node_id] = (
                "projected donor dependency replay unusable; transform result was "
                "not indexed or reusable: "
                + transform_state_value.replay_failure
            )
    summary = replace(
        execution.summary,
        invalidations=tuple(sorted(invalidations.items(), key=lambda item: item[0].casefold())),
    )

    # The mutable staging workspace is transport only.  Re-materialize each
    # terminal artifact from its immutable record into a fresh publication
    # seat, and bind the subsequent target payload to that exact receipt.
    publication_root = session_root / "publication"
    publication_root.mkdir()
    immutable_terminals: dict[str, tuple[Path, CacheOutput]] = {}
    with cache.lease() as lease:
        for target in bundle.spec.targets:
            terminal_id = terminal_nodes[target.id]
            record = execution.outcomes[terminal_id].record
            outputs_by_name = {item.name: item for item in record.outputs}
            if set(outputs_by_name) != {"artifact"}:
                raise ClassicIncrementalError(
                    f"warm terminal {target.id!r} record has an invalid output set"
                )
            destination = publication_root / target.id / "artifact"
            restored_outputs = lease.restore_selected(
                record,
                {"artifact": destination},
                allowed_root=session_root,
            )
            expected = outputs_by_name["artifact"]
            received = restored_outputs["artifact"]
            if (
                received.digest.value != expected.digest
                or received.size != expected.size
                or bool(received.mode & stat.S_IXUSR) != expected.executable
            ):
                raise ClassicIncrementalError(
                    f"warm terminal {target.id!r} restore differs from its cache receipt"
                )
            immutable_terminals[target.id] = (destination, expected)

    committed: list[tuple[_TargetPublication, SecureFileSnapshot]] = []
    published_targets: list[tuple[_TargetPublication, SecureFileSnapshot]] = []
    unchanged_target_count = 0
    result: ClassicIncrementalResult | None = None
    # Snapshot, compare, publish, and finally reseal the complete target set
    # beneath one cooperating-run transaction lock.  Each replacement also
    # checks its exact preimage immediately before commit, so an uncoordinated
    # replacement observed during the interval fails closed and survives.
    with _target_publication_transaction(state_root):
        census.validate_all()
        prepared_publications: list[_TargetPublication] = []
        for target in bundle.spec.targets:
            staged, expected_terminal = immutable_terminals[target.id]
            payload, staged_snapshot = _payload(staged)
            if (
                staged_snapshot.digest.value != expected_terminal.digest
                or staged_snapshot.size != expected_terminal.size
                or bool(staged_snapshot.mode & stat.S_IXUSR)
                != expected_terminal.executable
            ):
                raise ClassicIncrementalError(
                    f"warm terminal {target.id!r} changed after immutable restore"
                )
            target_path = project_root.joinpath(*PurePosixPath(target.artifact).parts)
            prior_payload: bytes | None = None
            prior_snapshot: SecureFileSnapshot | None = None
            if os.path.lexists(target_path):
                try:
                    prior_payload, prior_snapshot = read_relative_file(
                        project_root,
                        target.artifact,
                    )
                except SecurePathError as exc:
                    raise ClassicIncrementalError(
                        f"warm target {target.id!r} prior publication is unsafe: {exc}"
                    ) from exc
                if (
                    os.name == "posix"
                    and prior_snapshot is not None
                    and stat.S_IMODE(prior_snapshot.mode) & ~0o777
                ):
                    raise ClassicIncrementalError(
                        f"warm target {target.id!r} has unsupported special mode bits"
                    )
                if os.name == "nt" and not windows_attributes_are_basic_restorable(
                    prior_snapshot.windows_attributes
                ):
                    raise ClassicIncrementalError(
                        f"warm target {target.id!r} has non-restorable Windows attributes"
                    )
            prepared_publications.append(
                _TargetPublication(
                    target.id,
                    target.artifact,
                    payload,
                    staged_snapshot,
                    prior_payload,
                    prior_snapshot,
                )
            )

        try:
            for publication in prepared_publications:
                prior_metadata_matches = publication.prior is not None and (
                    (
                        os.name == "posix"
                        and stat.S_IMODE(publication.prior.mode)
                        == stat.S_IMODE(publication.staged.mode)
                    )
                    or (
                        os.name == "nt"
                        and publication.prior.windows_attributes
                        == publication.staged.windows_attributes
                    )
                )
                if publication.prior_payload == publication.payload and prior_metadata_matches:
                    current_payload, published = read_relative_file(
                        project_root,
                        publication.relative,
                    )
                    if current_payload != publication.payload or published != publication.prior:
                        raise ClassicIncrementalError(
                            f"warm target {publication.target_id!r} changed before "
                            "no-op publication"
                        )
                    unchanged_target_count += 1
                else:
                    published = atomic_publish_relative_if_current(
                        project_root,
                        publication.relative,
                        publication.payload,
                        expected=publication.prior,
                        mode=(
                            stat.S_IMODE(publication.staged.mode)
                            if os.name == "posix"
                            else None
                        ),
                        windows_attributes=(
                            publication.staged.windows_attributes
                            if os.name == "nt"
                            else None
                        ),
                    )
                    committed.append((publication, published))
                published_targets.append((publication, published))
                if (
                    published.digest != publication.staged.digest
                    or published.size != publication.staged.size
                    or (
                        os.name == "posix"
                        and stat.S_IMODE(published.mode)
                        != stat.S_IMODE(publication.staged.mode)
                    )
                    or (
                        os.name == "nt"
                        and published.windows_attributes
                        != publication.staged.windows_attributes
                    )
                ):
                    raise ClassicIncrementalError(
                        f"warm target {publication.target_id!r} changed during publication"
                    )
            expected_targets = {
                publication.relative: published
                for publication, published in published_targets
            }
            with hold_relative_file_set(project_root, expected_targets) as held_targets:
                committed = [
                    (publication, held_targets[publication.relative])
                    for publication, _published in committed
                ]
                published_targets = [
                    (publication, held_targets[publication.relative])
                    for publication, _published in published_targets
                ]
                outputs = tuple(
                    sorted(
                        (
                            FileReceipt(
                                published.path,
                                published.digest,
                                published.size,
                                True,
                                terminal_nodes[publication.target_id],
                                published.device,
                                published.inode,
                            )
                            for publication, published in published_targets
                        ),
                        key=lambda item: str(item.path),
                    )
                )
                result = ClassicIncrementalResult(
                    BuildExecutionReceipt(False, (), outputs, ()),
                    summary,
                )
        except BaseException as publication_error:
            rollback_errors: list[str] = []
            for publication, published in reversed(committed):
                try:
                    removed = remove_published_relative(
                        project_root,
                        publication.relative,
                        expected=published,
                    )
                    if not removed or publication.prior_payload is None:
                        continue
                    if os.name == "posix":
                        assert publication.prior is not None
                        restored = atomic_publish_new_relative_from_stream(
                            project_root,
                            publication.relative,
                            BytesIO(publication.prior_payload),
                            mode=stat.S_IMODE(publication.prior.mode),
                            expected_digest=publication.prior.digest,
                            expected_size=publication.prior.size,
                        )
                    else:
                        assert publication.prior is not None
                        restored = atomic_publish_new_relative_from_stream(
                            project_root,
                            publication.relative,
                            BytesIO(publication.prior_payload),
                            windows_attributes=publication.prior.windows_attributes,
                            expected_digest=publication.prior.digest,
                            expected_size=publication.prior.size,
                        )
                    if publication.prior is None or (
                        restored.digest != publication.prior.digest
                        or restored.size != publication.prior.size
                        or (
                            os.name == "posix"
                            and stat.S_IMODE(restored.mode)
                            != stat.S_IMODE(publication.prior.mode)
                        )
                        or (
                            os.name == "nt"
                            and restored.windows_attributes
                            != publication.prior.windows_attributes
                        )
                    ):
                        raise ClassicIncrementalError(
                            "warm target rollback changed prior bytes: "
                            f"{publication.target_id!r}"
                        )
                except BaseException as rollback_error:
                    rollback_errors.append(
                        f"{publication.target_id}: {rollback_error}"
                    )
            if rollback_errors:
                publication_error.add_note(
                    "warm target rollback also failed: " + "; ".join(rollback_errors)
                )
            if isinstance(publication_error, ClassicIncrementalError):
                raise
            raise ClassicIncrementalError(
                f"warm target set could not be published safely: {publication_error}"
            ) from publication_error

    if result is None:
        raise ClassicIncrementalError("warm target set produced no receipt")
    summary = replace(
        summary,
        elapsed_seconds=monotonic() - started,
        published_targets=len(published_targets) - unchanged_target_count,
        unchanged_targets=unchanged_target_count,
    )
    result = replace(result, summary=summary)
    if progress is not None:
        progress(
            ProgressKind.UNIT_FINISHED,
            len(nodes) + 2,
            len(nodes) + 2,
            "publication",
            "target-set",
            None,
        )
    return result


__all__ = [
    "ClassicIncrementalError",
    "ClassicIncrementalResult",
    "execute_classic_incremental_build",
]
