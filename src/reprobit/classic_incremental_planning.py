"""Capture immutable authority and graph layout for classic incremental builds."""

from __future__ import annotations

import ntpath
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock
from types import MappingProxyType
from typing import cast

from reprobit.assets import runtime_asset_path
from reprobit.backends import ExecutionBackend, PosixWineBackend
from reprobit.classic.arguments import validate_compile_arguments
from reprobit.classic_cache import DonorDependencyResolutionContext
from reprobit.classic_donors import (
    DonorIncludeProjection,
    donor_requires_dependency_tracking,
)
from reprobit.classic_includes import IncludeOrigin, SealedIncludeAuthority, SealedIncludeFile
from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    ClassicIncrementalPlan,
    PhysicalInputCensus,
    input_receipt,
    json_value,
    logical_join,
    read_payload,
    snapshot_file,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    classic_compiler_translation_unit_authority,
    classic_rdata_repack_graph_authority,
    prepare_classic_units,
)
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_environment import (
    _classic_producer_environment,
    _toolchain_tree_files,
)
from reprobit.classic_runtime_graph import (
    _graph_role_bindings,
    _graph_system_library_map,
)
from reprobit.incremental import (
    PRODUCER_IMPLEMENTATION_DIGEST,
    DeveloperAuthority,
    revalidate_producer_implementation,
)
from reprobit.incremental_executor import IncrementalProgress
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import (
    ProducerNode,
    ProducerRole,
    materialize_argument,
    producer_graph_digest,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    classic_analysis_pdb_paths,
)
from reprobit.secure_paths import SecureFileSnapshot
from reprobit.strict_json import JsonValue
from reprobit.toolchains import ClassicMSVCToolchain


def _runtime_material(
    backend: ExecutionBackend,
    compiler_transport: Path | None,
    resource_transport: Path | None,
    *,
    snapshot: Callable[[Path], SecureFileSnapshot] = snapshot_file,
) -> JsonValue:
    programs: list[JsonValue] = []
    for label, raw in (
        ("compiler_transport", compiler_transport),
        ("resource_transport", resource_transport),
    ):
        if raw is None:
            continue
        path = raw.expanduser().resolve(strict=True)
        programs.append(input_receipt(label, str(path), snapshot(path)))
    for label in ("wine_pin", "wineserver_pin"):
        pin = getattr(backend, label, None)
        if pin is None:
            continue
        receipt = snapshot(pin.path)
        if receipt.size != pin.size or receipt.digest.value != pin.sha256:
            raise ClassicIncrementalError(f"resolved backend {label} changed")
        programs.append(input_receipt(label, str(pin.path), receipt))
    proxy = runtime_asset_path("ReproBitPathProxy.sh")
    proxy_receipt = snapshot(proxy)
    programs.append(
        json_value(
            {
                "role": "runtime-path-proxy-template",
                "digest": proxy_receipt.digest.value,
                "size": proxy_receipt.size,
            }
        )
    )
    return json_value(
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
    read_payload: Callable[[Path], tuple[bytes, SecureFileSnapshot]] = read_payload,
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
                declarations[overlay_path] = json_value(
                    {
                        "intervention": intervention.id,
                        "declaration": raw,
                    }
                )
            rendered = render_classic_overlay(
                {"schema": schema, "outputs": outputs, "graph": graph},
                clean_inputs,
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
    snapshot: Callable[[Path], SecureFileSnapshot] = snapshot_file,
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
        logical = logical_join(source_root, relative)
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
        logical = logical_join(toolchain_logical_root, relative)
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
        temp_directory=logical_join(build_root, ".reprobit-tmp/$LANE"),
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
    parsed = validate_compile_arguments([compiler_logical, *arguments])
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


def _donor_dependency_resolution_contexts(
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
    """Reconstruct exact dependency-tracked donor reads without a runtime."""

    tracked = tuple(
        sorted(
            (
                donor
                for donor in unit.donors
                if donor_requires_dependency_tracking(
                    donor.request,
                    owning_build_target=unit.plan.build_target,
                    owning_logical_source=unit.plan.source,
                )
            ),
            key=lambda item: item.intervention.id.casefold(),
        )
    )
    if not tracked:
        return ()
    normalized_source_root = normalize_logical_path(source_root)
    normalized_build_root = normalize_logical_path(build_root)
    environment_directories = tuple(item for item in environment["INCLUDE"].split(";") if item)
    contexts: list[DonorDependencyResolutionContext] = []
    for donor in tracked:
        request = donor.request
        is_overlay = request.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
        mirror_active = (
            request.compiler_additions.include_projection is not DonorIncludeProjection.NONE
        )
        if mirror_active and not is_overlay:
            raise ClassicIncrementalError(
                f"dependency-tracked donor {donor.intervention.id!r} requests a source "
                "mirror without being a source overlay"
            )
        source_path = PurePosixPath(request.logical_source)
        if (
            source_path.is_absolute()
            or not source_path.parts
            or any(part in {"", ".", ".."} for part in source_path.parts)
        ):
            raise ClassicIncrementalError(
                f"dependency-tracked donor {donor.intervention.id!r} source path is unsafe"
            )
        compiler_seat = PurePosixPath(request.compiler_seat)
        if (
            compiler_seat.is_absolute()
            or len(compiler_seat.parts) != 1
            or any(part in {"", ".", ".."} for part in compiler_seat.parts)
        ):
            raise ClassicIncrementalError(
                f"dependency-tracked donor {donor.intervention.id!r} compiler seat is unsafe"
            )
        matches: list[tuple[ProducerNode, dict[str, object]]] = []
        for node_id, node in compiler_nodes.items():
            if (
                compiler_sources[node_id].casefold()
                != request.logical_source.casefold()
                or node.owner != request.build_target
            ):
                continue
            try:
                parsed = validate_compile_arguments(list(node_arguments(node)))
            except Exception as exc:
                raise ClassicIncrementalError(
                    f"donor compiler lane {node_id!r} is invalid: {exc}"
                ) from exc
            matches.append((node, parsed))
        if len(matches) != 1:
            raise ClassicIncrementalError(
                f"dependency-tracked donor {donor.intervention.id!r} has {len(matches)} "
                "committed compiler lanes for its target/source identity: "
                f"{request.build_target}/{request.logical_source}"
            )
        _record_node, parsed = matches[0]
        parent = source_path.parent.as_posix()
        expected_directories: list[str] = []
        if is_overlay:
            expected_directories.append("inc")
            if mirror_active:
                expected_directories.append(
                    "inc/source" if parent == "." else f"inc/source/{parent}"
                )
        if tuple(expected_directories) != request.compiler_additions.include_directories:
            raise ClassicIncrementalError(
                f"dependency-tracked donor {donor.intervention.id!r} include layout differs"
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
                f"dependency-tracked donor {donor.intervention.id!r} staging layout differs"
            )

        marker_stem = f"composed-{unit.plan.build_target}-{unit.plan.source.replace('/', '_')}"
        donor_root = PureWindowsPath(normalized_build_root).parent / "donors"
        arena = normalize_logical_path(
            str(donor_root / f"{marker_stem}-{request.compiler_seat}")
        )
        record_source = logical_join(normalized_source_root, request.logical_source)
        private_includes: list[str] = []
        if is_overlay:
            private_includes.append(logical_join(arena, "inc"))
            if mirror_active:
                private_includes.append(
                    logical_join(
                        arena,
                        "inc/source" if parent == "." else f"inc/source/{parent}",
                    )
                )
        private_includes.append(
            normalize_logical_path(str(PureWindowsPath(record_source).parent))
        )
        include_directories = list(private_includes)
        for item in cast(Sequence[object], parsed["include_paths"]):
            raw = cast(tuple[int, str, bool], item)[1]
            if mirror_active:
                visible = _logical_absolute(raw, working_directory=normalized_build_root)
                relative = _logical_relative(visible, root=normalized_source_root)
                if relative is not None:
                    include_directories.append(
                        logical_join(
                            arena,
                            "inc/source" if not relative else f"inc/source/{relative}",
                        )
                    )
            include_directories.append(raw)

        arena_files: dict[str, SealedIncludeFile] = {}
        mirrored_sources: dict[str, tuple[str, str]] = {}
        if mirror_active:
            for item in authority.files:
                if item.origin is not IncludeOrigin.PROJECT_SOURCE:
                    continue
                relative = _logical_relative(item.logical_path, root=normalized_source_root)
                if relative is None:
                    raise ClassicIncrementalError(
                        "dependency-tracked donor source authority is outside its root: "
                        f"{item.logical_path!r}"
                    )
                mirrored = logical_join(arena, f"inc/source/{relative}")
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
                    f"dependency-tracked donor {donor.intervention.id!r} input path is unsafe"
                )
            logical = logical_join(arena, path.as_posix())
            folded = logical.casefold()
            existing = arena_files.get(folded)
            if existing is not None and existing.logical_path != logical:
                raise ClassicIncrementalError(
                    f"dependency-tracked donor {donor.intervention.id!r} has a DOS path collision"
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
                logical_join(arena, "s.cpp"),
                tuple(include_directories),
                environment_directories,
                (*original_force_includes, *force_includes),
                donor_authority,
                tuple(sorted(mirrored_sources.values(), key=lambda item: item[0].casefold())),
            )
        )
    return tuple(contexts)


def prepare_classic_incremental_plan(
    authority: DeveloperAuthority,
    *,
    started: float,
    project_root: Path,
    session_root: Path,
    state_root: Path,
    toolchain_root: Path,
    backend: ExecutionBackend,
    jobs: int,
    compiler_transport: Path | None,
    resource_transport: Path | None,
    initialization_timeout: float,
    compile_timeout: float,
    link_timeout: float,
    cleanup_timeout: float,
    progress: IncrementalProgress | None,
) -> ClassicIncrementalPlan:
    implementation_receipt = PRODUCER_IMPLEMENTATION_DIGEST
    revalidate_producer_implementation(implementation_receipt)
    bundle = authority.bundle
    graph = bundle.producer_graph
    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter) or graph is None:
        raise ClassicIncrementalError("warm classic execution requires a producer graph")
    if jobs < 1:
        raise ClassicIncrementalError("warm build jobs must be positive")
    if bundle.build_plan is None:
        analysis_link_options: tuple[str, ...] = ()
    else:
        analysis_link_options = bundle.build_plan.analysis_link_options
    if analysis_link_options not in {(), ("/DEBUG",)}:
        raise ClassicIncrementalError("warm analysis-link options are not closed")
    try:
        analysis_pdb_relatives = dict(classic_analysis_pdb_paths(bundle))
    except ValueError as exc:
        raise ClassicIncrementalError(
            f"warm analysis PDB output policy is malformed: {exc}"
        ) from exc
    if bool(analysis_pdb_relatives) != bool(analysis_link_options):
        raise ClassicIncrementalError("warm analysis PDB output set differs from policy")
    try:
        rdata_graph_authority = classic_rdata_repack_graph_authority(bundle, graph)
    except ClassicProjectError as exc:
        raise ClassicIncrementalError(str(exc)) from exc
    rdata_material_by_object = {
        object_identity: (
            json_value(
                {
                    "intervention": intervention.model_dump(mode="json"),
                    "proof": receipt.model_dump(mode="json"),
                }
            ),
        )
        for object_identity, (intervention, receipt, _values) in rdata_graph_authority.items()
    }
    graph_digest_value = producer_graph_digest(graph).value
    project_root = project_root.resolve(strict=True)
    toolchain_root = toolchain_root.resolve(strict=True)
    census = PhysicalInputCensus()
    session_root.mkdir(parents=True, exist_ok=False)
    staging_root = session_root / "staging"
    staging_root.mkdir()
    planner_build_root = session_root / "planner-build"
    planner_build_root.mkdir()
    installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile, toolchain_root, logical_root=bundle.spec.paths.toolchain
    )
    toolchain_lock = bundle.toolchain_lock
    installation.doctor(toolchain_lock).require_ok()
    _role_tool_ids, role_relatives = _graph_role_bindings(bundle, installation)
    role_logical = {
        role: installation.logical_path(relative) for role, relative in role_relatives.items()
    }
    environment = _warm_cache_environment(
        installation,
        build_root=bundle.spec.paths.build,
        posix_wine=isinstance(backend, PosixWineBackend),
    )
    toolchain_material = json_value(bundle.toolchain_lock.model_dump(mode="json"))
    runtime_material = _runtime_material(
        backend, compiler_transport, resource_transport, snapshot=census.snapshot
    )
    runtime_input_paths = census.paths()
    clean_sources, effective_sources, overlay_by_path, generated_paths, _cleanless_outputs = (
        _render_sources(bundle, project_root, read_payload=census.payload)
    )
    ordinary_authority, generated_authority, physical_by_logical, source_payloads = (
        _include_authorities(
            bundle,
            project_root=project_root,
            toolchain_root=toolchain_root,
            effective_sources=effective_sources,
            deferred_outputs=generated_paths,
            snapshot=census.snapshot,
        )
    )
    system_libraries = _graph_system_library_map(
        bundle, graph, installation, effective_root=project_root, build_root=planner_build_root
    )
    units = prepare_classic_units(
        bundle,
        clean_sources=clean_sources,
        effective_sources=effective_sources,
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
    authority_by_epoch = {False: ordinary_authority, True: generated_authority}
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
            + f"{sorted(legacy_target_ids - set(oracle_paths))}"
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
    for node_id, unit_plan in planned_compilers.items():
        prepared_unit = units_by_id.get(unit_plan.id)
        if prepared_unit is None or prepared_unit.plan != unit_plan:
            raise ClassicIncrementalError(
                f"warm prepared translation unit differs from build plan: {unit_plan.id!r}"
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
    return ClassicIncrementalPlan(
        started=started,
        authority=authority,
        bundle=bundle,
        graph=graph,
        project_root=project_root,
        session_root=session_root,
        state_root=state_root,
        toolchain_root=toolchain_root,
        backend=backend,
        jobs=jobs,
        compiler_transport=compiler_transport,
        resource_transport=resource_transport,
        initialization_timeout=initialization_timeout,
        compile_timeout=compile_timeout,
        link_timeout=link_timeout,
        cleanup_timeout=cleanup_timeout,
        progress=progress,
        census=census,
        staging_root=staging_root,
        graph_digest=graph_digest_value,
        implementation_receipt=implementation_receipt,
        role_relatives=role_relatives,
        role_logical=role_logical,
        environment=environment,
        toolchain_material=toolchain_material,
        runtime_material=runtime_material,
        runtime_input_paths=runtime_input_paths,
        effective_sources=effective_sources,
        effective_sources_by_path=MappingProxyType(
            {path.casefold(): payload for path, payload in effective_sources.items()}
        ),
        overlay_by_path=overlay_by_path,
        generated_paths=generated_paths,
        ordinary_authority=ordinary_authority,
        authority_by_epoch=MappingProxyType(authority_by_epoch),
        authority_files=MappingProxyType(
            {key: MappingProxyType(value) for key, value in authority_files.items()}
        ),
        physical_by_logical=physical_by_logical,
        source_payloads=source_payloads,
        system_libraries=system_libraries,
        units=tuple(units),
        documents_by_unit=MappingProxyType(documents_by_unit),
        source_root=source_root,
        toolchain_logical_root=toolchain_logical_root,
        oracle_snapshots=MappingProxyType(oracle_snapshots),
        oracle_paths=MappingProxyType(oracle_paths),
        graph_output_owner=MappingProxyType(graph_output_owner),
        compiler_nodes=MappingProxyType(compiler_nodes),
        compiler_sources=MappingProxyType(compiler_sources),
        generated_nodes=frozenset(generated_nodes),
        compiler_units=MappingProxyType(compiler_units),
        output_paths=MappingProxyType(output_paths),
        transform_ids=MappingProxyType(transform_ids),
        transform_paths=MappingProxyType(transform_paths),
        effective_owner=MappingProxyType(effective_owner),
        ordinary_barrier=ordinary_barrier,
        rdata_material_by_object=MappingProxyType(rdata_material_by_object),
        analysis_link_options=analysis_link_options,
        analysis_pdb_relatives=MappingProxyType(analysis_pdb_relatives),
        runtime_holder={},
        runtime_lock=Lock(),
        compiler_states={},
        transform_states={},
        nodes=[],
        terminal_nodes={},
        terminal_paths={},
        primary_link_outputs={},
        analysis_nodes={},
    )
