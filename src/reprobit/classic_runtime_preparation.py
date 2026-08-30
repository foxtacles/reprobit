"""Preparation of one direct classic producer-graph execution."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from reprobit.backends import (
    BackendError,
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
)
from reprobit.build import BuildPlan
from reprobit.classic.semantic_contracts import CleanSourceInput, ProjectOverlaySourcePair
from reprobit.classic.source_overlay import plan_project_overlay_compiler_epochs
from reprobit.classic_orchestration import (
    classic_rdata_repack_graph_authority,
    prepare_classic_units,
)
from reprobit.classic_project import (
    ClassicProjectError,
    InterventionWitness,
    materialize_effective_workspace,
)
from reprobit.classic_runtime import (
    ClassicProducerGraphBuildExecutor,
    ClassicProducerGraphRuntimeEvidenceProvider,
)
from reprobit.classic_runtime_donor import ClassicDonorComposition
from reprobit.classic_runtime_environment import (
    _admitted_host_wrapper,
    _install_path_proxies,
    _install_pinned_wine_alias,
    _locked_wrapper_runtime_files,
    _logical_join,
    _materialize_direct_logical_workspace,
    _prepare_execution_lanes,
    _project_locked_toolchain,
    _toolchain_include_reader_payloads,
)
from reprobit.classic_runtime_files import _safe_relative
from reprobit.classic_runtime_graph import (
    _graph_compile_records,
    _graph_role_bindings,
    _graph_system_library_map,
    _graph_targets,
)
from reprobit.classic_runtime_overlay import ClassicOverlayEpochs
from reprobit.classic_runtime_probe import ClassicProbeExecution
from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
    ClassicProgressCallback,
    ClassicProgressReporter,
)
from reprobit.classic_runtime_warm import ClassicWarmExecution
from reprobit.model import Digest
from reprobit.producer_graph import ProducerRole, read_producer_graph
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProducerGraphBuildAdapter,
    ProjectBundle,
)
from reprobit.toolchains import ClassicMSVCToolchain


@dataclass(frozen=True, slots=True)
class _OverlayEpochPlan:
    """Sealed project-overlay inputs split across their compiler epochs."""

    effective_outputs: Mapping[str, bytes]
    project_source_pairs: tuple[ProjectOverlaySourcePair, ...]
    generated_inputs: frozenset[str]
    carrier_input_seals: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class ClassicProducerGraphPreparedRun:
    executor: ClassicProducerGraphBuildExecutor
    producer: ClassicProducerExecution
    warm: ClassicWarmExecution
    probes: ClassicProbeExecution
    donors: ClassicDonorComposition
    evidence_provider: ClassicProducerGraphRuntimeEvidenceProvider
    plan: BuildPlan
    intervention_witnesses: tuple[InterventionWitness, ...]

    def close(self) -> None:
        try:
            self.warm.close()
        finally:
            self.producer.close()


def _classic_progress_total(
    bundle: ProjectBundle,
    *,
    graph_node_count: int,
    resource_node_count: int,
    audit_node_count: int,
    has_overlay: bool,
    donor_count: int,
    unit_count: int,
    target_count: int,
    analysis_enabled: bool,
    generated_translation_units: bool,
) -> int:
    rdata_count = sum(
        1
        for intervention in bundle.interventions
        if isinstance(intervention, ClassicRecipeIntervention)
        and isinstance(
            {item.name: item.value for item in intervention.parameters}.get("rdata_pool_repack"),
            dict,
        )
    )
    return (
        graph_node_count
        + resource_node_count
        + (audit_node_count if has_overlay else 0)
        + (6 if has_overlay and audit_node_count else 4 if has_overlay else 1)
        + 2 * donor_count
        + unit_count
        + rdata_count
        + 2 * target_count
        + (2 * target_count if analysis_enabled else 0)
        + (1 if generated_translation_units else 0)
        + 1
    )


def _capture_and_restore_overlay_outputs(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    effective_root: Path,
) -> _OverlayEpochPlan:
    """Capture effective bytes, then restore the ordinary compiler epoch.

    Every output without a clean preimage is deliberately absent when this
    function returns.  The executor materializes those sealed bytes only after
    all ordinary compiler/resource nodes have completed.
    """

    outputs: dict[str, bytes] = {}
    source_pairs: list[ProjectOverlaySourcePair] = []
    generated_inputs: set[str] = set()
    carrier_input_seals: dict[str, tuple[str, ...]] = {}
    folded_outputs: set[str] = set()
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            continue
        values = {item.name: item.value for item in intervention.parameters}
        declarations = values.get("outputs")
        graph = values.get("graph")
        if not isinstance(declarations, list) or not isinstance(graph, dict):
            raise ClassicProjectError("source-overlay declaration is malformed")
        raw_generated = graph.get("generated_tus")
        if not isinstance(raw_generated, list):
            raise ClassicProjectError("source-overlay generated-TU graph is malformed")
        carrier_paths: list[str] = []
        for raw in raw_generated:
            path = raw.get("path") if isinstance(raw, dict) else None
            if not isinstance(path, str):
                raise ClassicProjectError("source-overlay generated TU is malformed")
            carrier_paths.append(_safe_relative(path))
        intervention_generated: set[str] = set()
        for raw in declarations:
            path = raw.get("path") if isinstance(raw, dict) else None
            if not isinstance(path, str):
                raise ClassicProjectError("source-overlay output is malformed")
            assert isinstance(raw, dict)
            relative = _safe_relative(path)
            if relative.casefold() in folded_outputs:
                raise ClassicProjectError("source-overlay output paths overlap")
            folded_outputs.add(relative.casefold())
            output_path = effective_root.joinpath(*PurePosixPath(relative).parts)
            if output_path.is_symlink() or not output_path.is_file():
                raise ClassicProjectError(f"rendered source-overlay output is absent: {relative!r}")
            effective_payload = output_path.read_bytes()
            effective_digest = raw.get("effective")
            effective_size = raw.get("size")
            if (
                not isinstance(effective_digest, str)
                or effective_digest != Digest.from_bytes(effective_payload).value
                or not isinstance(effective_size, int)
                or isinstance(effective_size, bool)
                or effective_size != len(effective_payload)
            ):
                raise ClassicProjectError(f"rendered source-overlay output changed: {relative!r}")
            outputs[relative] = effective_payload
            clean_digest = raw.get("clean")
            if clean_digest is None:
                clean_payload = None
                intervention_generated.add(relative)
                generated_inputs.add(relative)
            else:
                if not isinstance(clean_digest, str):
                    raise ClassicProjectError(
                        f"source-overlay clean digest is malformed: {relative!r}"
                    )
                clean_path = project_root.joinpath(*PurePosixPath(relative).parts)
                if clean_path.is_symlink() or not clean_path.is_file():
                    raise ClassicProjectError(
                        f"ordinary source-overlay clean input is absent: {relative!r}"
                    )
                clean_payload = clean_path.read_bytes()
                if Digest.from_bytes(clean_payload).value != clean_digest:
                    raise ClassicProjectError(
                        f"ordinary source-overlay clean input changed: {relative!r}"
                    )
            source_pairs.append(
                ProjectOverlaySourcePair(relative, clean_payload, effective_payload)
            )
        generated_folded = {item.casefold() for item in intervention_generated}
        seal = tuple(sorted(intervention_generated, key=str.casefold))
        for carrier_path in carrier_paths:
            if carrier_path.casefold() not in generated_folded:
                raise ClassicProjectError(
                    f"source-overlay carrier is not a generated output: {carrier_path!r}"
                )
            if carrier_path.casefold() in {item.casefold() for item in carrier_input_seals}:
                raise ClassicProjectError(f"source-overlay carrier paths overlap: {carrier_path!r}")
            carrier_input_seals[carrier_path] = seal
    generated_folded = {item.casefold() for item in generated_inputs}
    pairs_by_path = {item.path: item for item in source_pairs}
    for relative in outputs:
        destination = effective_root.joinpath(*PurePosixPath(relative).parts)
        if relative.casefold() in generated_folded:
            if destination.is_symlink() or not destination.is_file():
                raise ClassicProjectError(
                    f"generated source-overlay output is absent: {relative!r}"
                )
            destination.unlink()
            continue
        clean_payload = pairs_by_path[relative].clean_payload
        if clean_payload is None:
            raise AssertionError("ordinary source-overlay pair lacks a clean payload")
        destination.write_bytes(clean_payload)
    return _OverlayEpochPlan(
        MappingProxyType(outputs),
        tuple(sorted(source_pairs, key=lambda item: item.path.casefold())),
        frozenset(generated_inputs),
        MappingProxyType(carrier_input_seals),
    )


def prepare_classic_producer_graph_run(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    session_root: Path,
    toolchain_root: Path,
    backend: ExecutionBackend,
    jobs: int,
    compiler_transport: Path | None = None,
    resource_transport: Path | None = None,
    initialization_timeout: float = 600.0,
    compile_timeout: float = 600.0,
    link_timeout: float = 900.0,
    cleanup_timeout: float = 10.0,
    progress: ClassicProgressCallback | None = None,
) -> ClassicProducerGraphPreparedRun:
    """Prepare a cold, direct execution of the committed producer graph."""

    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise ClassicProjectError("classic graph execution requires the producer-graph adapter")
    graph = bundle.producer_graph
    if graph is not None:
        classic_rdata_repack_graph_authority(bundle, graph)
    if isinstance(backend, NativeWindowsBackend):
        try:
            backend.doctor(execute_probe=True).require_ok()
        except BackendError as exc:
            raise ClassicProjectError(f"native Windows backend is unavailable: {exc}") from exc
    if graph is None:
        raise ClassicProjectError(
            "classic authenticity execution requires a committed producer graph"
        )
    if bundle.build_plan is None or bundle.source_manifest is None:
        raise ClassicProjectError("classic graph execution requires source and build plans")
    analysis_link_options = bundle.build_plan.analysis_link_options
    if jobs < 1 or min(initialization_timeout, compile_timeout, link_timeout, cleanup_timeout) <= 0:
        raise ClassicProjectError("classic execution limits must be positive")
    project_root = project_root.resolve(strict=True)
    session_root = session_root.resolve(strict=False)
    try:
        session_root.relative_to(project_root)
    except ValueError as exc:
        raise ClassicProjectError("classic session must remain beneath project root") from exc
    if session_root.exists() and any(session_root.iterdir()):
        raise ClassicProjectError(f"classic session is not empty: {session_root}")
    session_root.mkdir(parents=True, exist_ok=True)
    (session_root / "logs").mkdir()

    graph_path = project_root.joinpath(*PurePosixPath(bundle.spec.layout.producer_graph).parts)
    if (
        graph_path.is_symlink()
        or not graph_path.is_file()
        or (read_producer_graph(graph_path) != graph)
    ):
        raise ClassicProjectError("committed producer graph changed after project load")
    admitted_toolchain_root = toolchain_root.resolve(strict=True)
    logical_workspace = _materialize_direct_logical_workspace(
        bundle,
        session_root=session_root,
        toolchain_root=admitted_toolchain_root,
    )
    # Donor compilers need a private writable seat on the mapped logical
    # drive, but creating a new sibling after a source lease is acquired would
    # mutate that lease's held ancestor.  Establish the container before any
    # readable namespace exists; individual arenas mutate only this dedicated
    # producer-writable directory.
    donor_root = logical_workspace.build_root.parent / "donors"
    donor_root.mkdir(parents=True, exist_ok=False)
    effective_root = logical_workspace.effective_root
    build_root = logical_workspace.build_root
    overlay_interventions = materialize_effective_workspace(
        bundle,
        project_root,
        effective_root,
    )
    overlay_epoch = _capture_and_restore_overlay_outputs(
        bundle,
        project_root=project_root,
        effective_root=effective_root,
    )
    overlay_effective_outputs = overlay_epoch.effective_outputs
    source_installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile,
        admitted_toolchain_root,
        logical_root=bundle.spec.paths.toolchain,
    )
    toolchain_lock = bundle.toolchain_lock
    source_installation.doctor(toolchain_lock).require_ok()
    original_toolchain_inputs = _project_locked_toolchain(
        bundle,
        source_root=source_installation.root,
        destination=logical_workspace.toolchain_entry,
    )
    installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile,
        logical_workspace.toolchain_entry,
        logical_root=bundle.spec.paths.toolchain,
    )
    installation.doctor(toolchain_lock).require_ok()
    role_tool_ids, role_relatives = _graph_role_bindings(bundle, installation)

    wrapper_files: tuple[Path, ...] = ()
    proxy_files: tuple[Path, ...] = ()
    proxy_template: Path | None = None
    frontend_environment: Mapping[str, str] = MappingProxyType({})
    role_commands: dict[ProducerRole, Path] = {
        role: Path(_logical_join(bundle.spec.paths.toolchain, relative))
        for role, relative in role_relatives.items()
    }
    host_programs: list[Path] = []
    transport: Path | None = None
    wine_alias: Path | None = None
    if isinstance(backend, PosixWineBackend):
        if compiler_transport is None or resource_transport is None:
            raise ClassicProjectError(
                "POSIX classic execution requires explicit compiler and RC transport selectors"
            )
        real_compiler = _admitted_host_wrapper(
            compiler_transport,
            toolchain_root=source_installation.root,
            label="compiler transport selector",
        )
        real_rc = _admitted_host_wrapper(
            resource_transport,
            toolchain_root=source_installation.root,
            label="RC transport selector",
        )
        if real_compiler.parent != real_rc.parent:
            raise ClassicProjectError("compiler and RC selectors must share one transport")
        real_linker = _admitted_host_wrapper(
            real_compiler.parent / "link",
            toolchain_root=source_installation.root,
            label="linker transport selector",
        )
        real_librarian = _admitted_host_wrapper(
            real_compiler.parent / "lib",
            toolchain_root=source_installation.root,
            label="librarian transport selector",
        )
        transport = _admitted_host_wrapper(
            real_compiler.parent / "wine-msvc.sh",
            toolchain_root=source_installation.root,
            label="Wine MSVC transport",
        )
        if os.path.lexists(transport.parent / "msvctricks.exe"):
            raise ClassicProjectError(
                "wine-msvc transports with host-path msvctricks require a typed adapter"
            )
        wrapper_files = _locked_wrapper_runtime_files(
            bundle,
            (real_compiler, real_rc, real_linker, real_librarian, transport),
            toolchain_root=source_installation.root,
        )
        proxies, proxy_template = _install_path_proxies(session_root)
        role_commands = {
            ProducerRole.COMPILER: proxies["cl"],
            ProducerRole.RESOURCE: proxies["rc"],
            ProducerRole.LIBRARIAN: proxies["lib"],
            ProducerRole.LINKER: proxies["link"],
        }
        proxy_files = tuple(proxies.values())
        frontend_environment = MappingProxyType(
            {
                "REPROBIT_WINE_MSVC_TRANSPORT": str(transport),
                "REPROBIT_LOGICAL_CL": installation.logical_path(
                    role_relatives[ProducerRole.COMPILER]
                ),
                "REPROBIT_LOGICAL_RC": installation.logical_path(
                    role_relatives[ProducerRole.RESOURCE]
                ),
                "REPROBIT_LOGICAL_LINK": installation.logical_path(
                    role_relatives[ProducerRole.LINKER]
                ),
                "REPROBIT_LOGICAL_LIB": installation.logical_path(
                    role_relatives[ProducerRole.LIBRARIAN]
                ),
            }
        )
        if backend.wine_pin is None or backend.wineserver_pin is None:
            raise ClassicProjectError("POSIX classic execution requires resolved Wine programs")
        wine_alias = _install_pinned_wine_alias(session_root, backend.wine_pin.path)
        proxy_files = (*proxy_files, wine_alias)
        host_programs.extend((backend.wine_pin.path, backend.wineserver_pin.path, transport))
    else:
        if compiler_transport is not None or resource_transport is not None:
            raise ClassicProjectError(
                "native Windows execution does not accept POSIX transport selectors"
            )

    clean_sources = {
        entry.path: (project_root / entry.path).read_bytes()
        for entry in bundle.source_manifest.entries
    }
    compiler_epoch_plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        overlay_epoch.project_source_pairs,
        (
            tuple(
                CleanSourceInput(path, payload)
                for path, payload in sorted(
                    clean_sources.items(), key=lambda item: item[0].casefold()
                )
            )
            if overlay_interventions
            else ()
        ),
        secondary_reader_payloads=(
            _toolchain_include_reader_payloads(bundle, source_installation.root)
            if overlay_interventions
            else {}
        ),
    )
    effective_sources = {
        entry.path: (effective_root / entry.path).read_bytes()
        for entry in bundle.source_manifest.entries
    }
    effective_sources.update(overlay_effective_outputs)
    units = prepare_classic_units(
        bundle,
        clean_sources=clean_sources,
        effective_sources=effective_sources,
    )
    compile_records = _graph_compile_records(
        bundle,
        graph,
        effective_root=effective_root,
        build_root=build_root,
        toolchain_root=installation.root,
        compiler_command=role_commands[ProducerRole.COMPILER],
        generated_translation_units=frozenset(overlay_epoch.carrier_input_seals),
    )
    targets = _graph_targets(
        bundle,
        graph,
        effective_root=effective_root,
        build_root=build_root,
        toolchain_root=installation.root,
    )
    system_library_map = _graph_system_library_map(
        bundle,
        graph,
        installation,
        effective_root=effective_root,
        build_root=build_root,
    )
    authority_inputs: list[Path] = [
        graph_path,
        *proxy_files,
        *system_library_map.values(),
        *original_toolchain_inputs,
    ]
    if proxy_template is not None:
        authority_inputs.append(proxy_template)
    if isinstance(backend, PosixWineBackend):
        assert backend.wine_pin is not None and backend.wineserver_pin is not None
        authority_inputs.extend((backend.wine_pin.path, backend.wineserver_pin.path))

    lane_pool = _prepare_execution_lanes(
        bundle,
        installation=installation,
        backend=backend,
        logical_workspace=logical_workspace,
        session_root=session_root,
        role_commands=role_commands,
        host_programs=host_programs,
        frontend_environment=frontend_environment,
        jobs=jobs,
        initialization_timeout=initialization_timeout,
        cleanup_timeout=cleanup_timeout,
        wine_alias=wine_alias,
    )
    try:
        reporter = ClassicProgressReporter(
            _classic_progress_total(
                bundle,
                graph_node_count=len(graph.nodes),
                resource_node_count=sum(
                    1 for node in graph.nodes if node.role is ProducerRole.RESOURCE
                ),
                audit_node_count=len(compiler_epoch_plan.audit_node_ids),
                has_overlay=bool(overlay_interventions),
                donor_count=sum(len(unit.donors) for unit in units),
                unit_count=len(units),
                target_count=len(targets),
                analysis_enabled=bool(analysis_link_options),
                generated_translation_units=bool(overlay_epoch.carrier_input_seals),
            ),
            progress,
        )
        producer = ClassicProducerExecution(
            bundle=bundle,
            session_root=session_root,
            build_root=build_root,
            effective_root=effective_root,
            toolchain_root=installation.root,
            graph=graph,
            role_commands=role_commands,
            role_tool_ids=role_tool_ids,
            wrapper_runtime_files=wrapper_files,
            authority_inputs=authority_inputs,
            analysis_link_options=analysis_link_options,
            lane_pool=lane_pool,
            jobs=jobs,
            compile_timeout=compile_timeout,
            link_timeout=link_timeout,
            progress=reporter,
        )
        overlay = ClassicOverlayEpochs(
            bundle=bundle,
            effective_root=effective_root,
            build_root=build_root,
            graph=graph,
            targets=targets,
            overlay_witnesses=overlay_interventions,
            overlay_effective_outputs=overlay_effective_outputs,
            project_source_pairs=overlay_epoch.project_source_pairs,
            compiler_epoch_plan=compiler_epoch_plan,
            generated_inputs=overlay_epoch.generated_inputs,
            carrier_input_seals=overlay_epoch.carrier_input_seals,
            system_libraries=system_library_map,
            producer=producer,
            progress=reporter,
        )
        donors = ClassicDonorComposition(
            bundle=bundle,
            session_root=session_root,
            build_root=build_root,
            effective_root=effective_root,
            graph=graph,
            compile_records=compile_records,
            units=units,
            overlay_effective_outputs=overlay_effective_outputs,
            producer=producer,
            progress=reporter,
            compile_timeout=compile_timeout,
        )
        warm = ClassicWarmExecution(
            bundle=bundle,
            project_root=project_root,
            session_root=session_root,
            build_root=build_root,
            effective_root=effective_root,
            graph=graph,
            targets=targets,
            compile_records=compile_records,
            units=units,
            producer=producer,
            overlay=overlay,
            donors=donors,
        )
        probes = ClassicProbeExecution(
            graph=graph,
            units=units,
            producer=producer,
            overlay=overlay,
            donors=donors,
            warm=warm,
        )
        evidence_provider = ClassicProducerGraphRuntimeEvidenceProvider(
            bundle,
            project_root,
            reporter,
        )
        executor = ClassicProducerGraphBuildExecutor(
            bundle=bundle,
            project_root=project_root,
            session_root=session_root,
            build_root=build_root,
            effective_root=effective_root,
            toolchain_root=installation.root,
            graph=graph,
            role_tool_ids=role_tool_ids,
            wrapper_runtime_files=wrapper_files,
            authority_inputs=authority_inputs,
            targets=targets,
            compile_records=compile_records,
            units=units,
            overlay_witnesses=overlay_interventions,
            system_libraries=system_library_map,
            analysis_link_options=analysis_link_options,
            producer=producer,
            overlay=overlay,
            donors=donors,
            evidence_provider=evidence_provider,
            progress=reporter,
        )
        return ClassicProducerGraphPreparedRun(
            executor=executor,
            producer=producer,
            warm=warm,
            probes=probes,
            donors=donors,
            evidence_provider=evidence_provider,
            plan=BuildPlan(()),
            intervention_witnesses=tuple(overlay_interventions),
        )
    except BaseException as original:
        try:
            lane_pool.close()
        except BaseException as error:
            original.add_note(f"classic runtime cleanup also failed: {error}")
        raise


__all__ = [
    "ClassicProducerGraphPreparedRun",
    "prepare_classic_producer_graph_run",
]
