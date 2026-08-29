"""Named classic incremental DAG node-construction phases."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from functools import partial
from pathlib import Path, PurePosixPath
from types import MappingProxyType

import reprobit.classic_incremental_context as warm_context
from reprobit.cache import CacheLease
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
from reprobit.classic_cache import compiler_final_key as compiler_cache_final_key
from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    SealedIncludeAuthority,
    resolve_msvc_include_trace,
)
from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    ClassicIncrementalPlan,
    CompilerState,
    TransformState,
    WarmRuntime,
    input_receipt,
    json_value,
    logical_join,
)
from reprobit.classic_incremental_keys import (
    _warm_link_control_references,
)
from reprobit.classic_incremental_keys import (
    compiler_material as build_compiler_material,
)
from reprobit.classic_incremental_keys import (
    producer_material as build_producer_material,
)
from reprobit.classic_incremental_keys import (
    transform_material as build_transform_material,
)
from reprobit.classic_incremental_planning import (
    _compiler_parameters,
    _projected_donor_resolution_contexts,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
)
from reprobit.classic_resources import scan_msvc_resource_dependencies
from reprobit.classic_runtime_developer import ClassicWarmCompilerTransformResult
from reprobit.incremental import producer_cache_key, require_fresh_protected_recursive_inputs
from reprobit.incremental_executor import (
    CacheProbeDecision,
    IncrementalNode,
    IncrementalPhase,
    NodeOutcome,
    PreparedNodeInputs,
)
from reprobit.model import Digest
from reprobit.process import CancellationToken
from reprobit.producer_graph import ProducerNode, ProducerRole
from reprobit.strict_json import JsonValue


def add_producer_nodes(plan: ClassicIncrementalPlan) -> None:
    authority = plan.authority
    authority_by_epoch = plan.authority_by_epoch
    bundle = plan.bundle
    census = plan.census
    compiler_sources = plan.compiler_sources
    compiler_states = plan.compiler_states
    compiler_units = plan.compiler_units
    environment = plan.environment
    generated_nodes = plan.generated_nodes
    generated_paths = plan.generated_paths
    graph = plan.graph
    nodes = plan.nodes
    ordinary_authority = plan.ordinary_authority
    ordinary_barrier = plan.ordinary_barrier
    output_paths = plan.output_paths
    overlay_by_path = plan.overlay_by_path
    physical_by_logical = plan.physical_by_logical
    role_logical = plan.role_logical
    role_relatives = plan.role_relatives
    runtime_input_paths = plan.runtime_input_paths
    source_payloads = plan.source_payloads
    source_root = plan.source_root
    toolchain_root = plan.toolchain_root
    transform_ids = plan.transform_ids
    direct_inputs = partial(warm_context.direct_inputs, plan)
    node_arguments = partial(warm_context.node_arguments, plan)
    recursive_sampled_paths = partial(warm_context.recursive_sampled_paths, plan)
    sampled_reference_path = partial(warm_context.sampled_reference_path, plan)
    staged_reference_inputs = partial(warm_context.staged_reference_inputs, plan)
    verify_before_store = partial(warm_context.verify_before_store, plan)
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
                return build_compiler_material(
                    plan,
                    current_node,
                    direct=current_direct,
                    overlay_inputs=current_overlay,
                    generated_inputs=current_generated,
                    arguments=current_arguments,
                    dependencies=dependencies,
                )

            empty_material = compiler_material(MappingProxyType({}))
            base_key = compiler_base_key(empty_material)
            state = CompilerState(
                base_key,
                empty_material,
                physical_inputs=tuple(sorted(sampled_inputs, key=str)),
            )
            compiler_states[node.id] = state
            selected_authority = authority_by_epoch[generated]
            source_relative = compiler_sources[node.id]
            selected_compiler_unit = compiler_units.get(node.id)
            translation_unit_id = (
                selected_compiler_unit.plan.id if selected_compiler_unit is not None else node.id
            )

            def compiler_probe(
                lease: CacheLease,
                dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: CompilerState = state,
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
                runtime: WarmRuntime,
                cancellation: CancellationToken,
                prepared_inputs: PreparedNodeInputs,
                *,
                current_node: ProducerNode = node,
                current_outputs: Mapping[str, Path] = output_paths[node.id],
                current_state: CompilerState = state,
                current_authority: SealedIncludeAuthority = selected_authority,
                current_source: str = source,
                current_cwd: str = cwd,
                current_include_dirs: tuple[str, ...] = include_dirs,
                current_env_dirs: tuple[str, ...] = env_dirs,
                current_force_includes: tuple[str, ...] = force_includes,
                current_translation_unit_id: str = translation_unit_id,
                current_source_relative: str = source_relative,
            ) -> None:
                runtime.prepared.developer.execute_warm_graph_node(
                    current_node.id,
                    inputs=prepared_inputs,
                    outputs=current_outputs,
                    cancellation=cancellation,
                )
                replay = runtime.prepared.developer.replay_warm_compiler_dependencies(
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
                    fallback["recursive_reads"] = json_value(
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
                current_state: CompilerState = state,
            ) -> str:
                if current_state.final_key is None:
                    raise ClassicIncrementalError(
                        "compiler action omitted its final dependency key"
                    )
                return current_state.final_key

            def compiler_metadata(
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: CompilerState = state,
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
                runtime: WarmRuntime,
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_state: CompilerState = state,
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
                    source_path=logical_join(source_root, source_refs[0].removeprefix("source/")),
                    include_directories=tuple(include_directories),
                    environment_directories=tuple(environment["INCLUDE"].split(";")),
                    authority=current_authority,
                    payloads=MappingProxyType(payloads),
                )
                recursive_reads = tuple(
                    json_value(
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
                    reference for group in link_reference_groups for reference in group
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
                return build_producer_material(
                    plan,
                    current_node,
                    direct=current_direct,
                    recursive_reads=current_recursive,
                    overlay_inputs=current_overlay,
                    arguments=current_arguments,
                    immutable_inputs=current_immutable_inputs,
                    dependencies=dependencies,
                )

            def producer_action(
                runtime: WarmRuntime,
                cancellation: CancellationToken,
                prepared_inputs: PreparedNodeInputs,
                *,
                current_node: ProducerNode = node,
                current_outputs: Mapping[str, Path] = output_paths[node.id],
            ) -> None:
                runtime.prepared.developer.execute_warm_graph_node(
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
                runtime: WarmRuntime,
                _dependencies: Mapping[str, NodeOutcome],
                *,
                current_paths: tuple[Path, ...] = tuple(sorted(sampled_inputs, key=str)),
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


def add_transform_nodes(plan: ClassicIncrementalPlan) -> None:
    authority = plan.authority
    authority_by_epoch = plan.authority_by_epoch
    bundle = plan.bundle
    census = plan.census
    compiler_nodes = plan.compiler_nodes
    compiler_sources = plan.compiler_sources
    compiler_units = plan.compiler_units
    documents_by_unit = plan.documents_by_unit
    environment = plan.environment
    generated_nodes = plan.generated_nodes
    graph_output_owner = plan.graph_output_owner
    nodes = plan.nodes
    oracle_paths = plan.oracle_paths
    oracle_snapshots = plan.oracle_snapshots
    output_paths = plan.output_paths
    overlay_by_path = plan.overlay_by_path
    rdata_material_by_object = plan.rdata_material_by_object
    source_root = plan.source_root
    transform_ids = plan.transform_ids
    transform_paths = plan.transform_paths
    transform_states = plan.transform_states
    node_arguments = partial(warm_context.node_arguments, plan)
    recursive_sampled_paths = partial(warm_context.recursive_sampled_paths, plan)
    staged_reference_inputs = partial(warm_context.staged_reference_inputs, plan)
    verify_before_store = partial(warm_context.verify_before_store, plan)
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
            json_value(receipt.model_dump(mode="json"))
            for proof in bundle.proof_documents
            for receipt in proof.expected_observations
            if receipt.intervention_id in intervention_ids
        )
        donor_inputs = tuple(
            json_value(
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
            input_receipt(
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
        selected_rdata_inputs = rdata_material_by_object.get(object_value.casefold(), ())
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
            return build_transform_material(
                plan,
                current_id,
                current_node,
                current_unit,
                document=current_document,
                proofs=current_proofs,
                donor_inputs=current_donors,
                oracle_inputs=current_oracles,
                rdata_inputs=current_rdata,
                overlay_inputs=all_overlay_inputs,
                dependencies=dependencies,
            )

        transform_state: TransformState | None = None
        if transform_contexts:
            empty_material = transform_material(MappingProxyType({}))
            transform_state = TransformState(
                donor_transform_base_key(empty_material),
                empty_material,
                physical_inputs=transform_sampled_paths,
            )
            transform_states[transform_id] = transform_state

        def transform_probe(
            lease: CacheLease,
            dependencies: Mapping[str, NodeOutcome],
            *,
            current_state: TransformState | None = transform_state,
            current_contexts: tuple[DonorDependencyResolutionContext, ...] = transform_contexts,
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
            runtime: WarmRuntime,
            cancellation: CancellationToken,
            prepared_inputs: PreparedNodeInputs,
            *,
            current_id: str = compiler_id,
            current_outputs: Mapping[str, Path] = transformed_outputs,
            current_state: TransformState | None = transform_state,
            current_contexts: tuple[DonorDependencyResolutionContext, ...] = transform_contexts,
            current_unit: ClassicPreparedUnit = transform_unit,
        ) -> None:
            result = runtime.prepared.developer.execute_warm_compiler_transform(
                current_id,
                inputs=prepared_inputs,
                outputs=current_outputs,
                cancellation=cancellation,
            )
            if current_state is None:
                return
            if not isinstance(result, ClassicWarmCompilerTransformResult):
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
                    interventions = authority.protected_sources[current_unit.plan.source.casefold()]
                    raise ClassicIncrementalError(
                        "cannot revalidate projected donor inputs for protected "
                        f"translation unit {current_unit.plan.id!r}: "
                        f"{current_state.replay_failure}; affected reviewed "
                        f"intervention(s): {', '.join(interventions)}"
                    )
                fallback = dict(current_state.base_material)
                fallback["recursive_reads"] = json_value(
                    [
                        {
                            "unusable_donor_dependency_replay": (current_state.replay_failure),
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
            current_state: TransformState | None = transform_state,
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
            current_state: TransformState | None = transform_state,
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
            current_state: TransformState | None = transform_state,
        ) -> Mapping[str, JsonValue]:
            additional: dict[str, JsonValue] = {
                "node_id": current,
                "certifying": False,
            }
            if current_state is None:
                return MappingProxyType(additional)
            if current_state.replay_failure is not None:
                additional["donor_dependency_replay_failure"] = current_state.replay_failure
            if current_state.hint is None:
                return MappingProxyType(additional)
            return donor_transform_hint_metadata(
                current_state.hint,
                additional=additional,
            )

        def transform_pre_store(
            runtime: WarmRuntime,
            _dependencies: Mapping[str, NodeOutcome],
            *,
            current_paths: tuple[Path, ...] = transform_sampled_paths,
            current_state: TransformState | None = transform_state,
        ) -> None:
            verify_before_store(
                runtime,
                current_state.physical_inputs if current_state is not None else current_paths,
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
                final_key=(transform_final_key_factory if transform_state is not None else None),
                probe=transform_probe if transform_state is not None else None,
            )
        )
