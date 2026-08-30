"""Terminal publication and analysis-link DAG node construction."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import partial
from pathlib import Path, PurePosixPath
from types import MappingProxyType

import reprobit.classic_incremental_context as warm_context
from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    ClassicIncrementalPlan,
    WarmRuntime,
    json_value,
    logical_join,
)
from reprobit.classic_incremental_keys import (
    _warm_analysis_link_material,
)
from reprobit.classic_incremental_keys import (
    analysis_material as build_analysis_material,
)
from reprobit.classic_incremental_keys import (
    terminal_material as build_terminal_material,
)
from reprobit.classic_orchestration import classic_terminal_pipeline_authority
from reprobit.incremental import producer_cache_key
from reprobit.incremental_executor import (
    IncrementalNode,
    IncrementalPhase,
    NodeOutcome,
    PreparedNodeInputs,
)
from reprobit.process import CancellationToken
from reprobit.producer_graph import ProducerNode, ProducerRole
from reprobit.strict_json import JsonValue


def add_terminal_nodes(plan: ClassicIncrementalPlan) -> None:
    bundle = plan.bundle
    generated_nodes = plan.generated_nodes
    graph = plan.graph
    nodes = plan.nodes
    staging_root = plan.staging_root
    terminal_nodes = plan.terminal_nodes
    terminal_paths = plan.terminal_paths
    primary_link_outputs = plan.primary_link_outputs
    direct_inputs = partial(warm_context.direct_inputs, plan)
    staged_reference_inputs = partial(warm_context.staged_reference_inputs, plan)
    verify_before_store = partial(warm_context.verify_before_store, plan)
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
        primary_link_outputs[target_id] = primary[0]
        _terminal_inputs, terminal_input_materializer = staged_reference_inputs(
            terminal_id,
            primary,
        )
        quarantine = tuple(direct_inputs(linker, generated=bool(generated_nodes)))
        terminal_authority = tuple(
            json_value(
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
            return build_terminal_material(
                plan,
                current_linker,
                current_target,
                quarantine=current_quarantine,
                interventions=current_interventions,
                dependencies=dependencies,
            )

        def terminal_action(
            runtime: WarmRuntime,
            _cancellation: CancellationToken,
            prepared_inputs: PreparedNodeInputs,
            *,
            current_target: str = target_id,
            current_output: Path = terminal_path,
        ) -> None:
            runtime.prepared.warm.execute_warm_terminal(
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
            runtime: WarmRuntime,
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


def add_analysis_nodes(plan: ClassicIncrementalPlan) -> None:
    if not plan.analysis_link_options:
        return
    analysis_link_options = plan.analysis_link_options
    analysis_nodes = plan.analysis_nodes
    bundle = plan.bundle
    graph = plan.graph
    nodes = plan.nodes
    primary_link_outputs = plan.primary_link_outputs
    staging_root = plan.staging_root
    terminal_nodes = plan.terminal_nodes
    node_arguments = partial(warm_context.node_arguments, plan)
    staged_reference_inputs = partial(warm_context.staged_reference_inputs, plan)
    verify_before_store = partial(warm_context.verify_before_store, plan)

    terminal_barrier = tuple(sorted(terminal_nodes.values(), key=str.casefold))
    prior_analysis_id: str | None = None
    linkers = tuple(
        sorted(
            (node for node in graph.nodes if node.role is ProducerRole.LINKER),
            key=lambda item: item.target_id.casefold() if item.target_id else "",
        )
    )
    for linker in linkers:
        assert linker.target_id is not None
        target_id = linker.target_id
        terminal_id = terminal_nodes[target_id]
        analysis_id = f"analysis-link.{target_id}"
        current_paths = MappingProxyType(
            {
                "image": staging_root / "analysis" / target_id / "image",
                "pdb": staging_root / "analysis" / target_id / "pdb",
            }
        )
        analysis_nodes[target_id] = analysis_id
        arguments = node_arguments(linker)[1:]
        exact_logical_image = logical_join(
            bundle.spec.paths.build,
            primary_link_outputs[target_id].removeprefix("build/"),
        )
        authority_statement = _warm_analysis_link_material(
            linker,
            arguments=arguments,
            exact_logical_image=exact_logical_image,
            added_options=analysis_link_options,
        )
        _analysis_inputs, analysis_input_materializer = staged_reference_inputs(
            analysis_id,
            linker.inputs,
        )
        order_only_dependencies = {item for item in terminal_barrier if item != terminal_id}
        if prior_analysis_id is not None:
            order_only_dependencies.add(prior_analysis_id)
        order_only = tuple(sorted(order_only_dependencies, key=str.casefold))
        dependencies = tuple(
            sorted(
                {linker.id, terminal_id, *order_only_dependencies},
                key=str.casefold,
            )
        )

        def analysis_material(
            dependency_outcomes: Mapping[str, NodeOutcome],
            *,
            current_id: str = analysis_id,
            current_linker: ProducerNode = linker,
            current_target: str = target_id,
            current_authority: JsonValue = authority_statement,
        ) -> dict[str, JsonValue]:
            return build_analysis_material(
                plan,
                current_id,
                current_linker,
                current_target,
                current_authority,
                dependencies=dependency_outcomes,
            )

        def analysis_action(
            runtime: WarmRuntime,
            cancellation: CancellationToken,
            prepared_inputs: PreparedNodeInputs,
            *,
            current_target: str = target_id,
            current_outputs: Mapping[str, Path] = current_paths,
        ) -> None:
            runtime.prepared.warm.execute_warm_analysis_link(
                current_target,
                inputs=prepared_inputs,
                outputs=current_outputs,
                cancellation=cancellation,
            )

        def analysis_key_factory(
            dependency_outcomes: Mapping[str, NodeOutcome],
            *,
            current: Callable[
                [Mapping[str, NodeOutcome]], dict[str, JsonValue]
            ] = analysis_material,
        ) -> str:
            return producer_cache_key(current(dependency_outcomes))

        def analysis_metadata(
            _dependency_outcomes: Mapping[str, NodeOutcome],
            *,
            current_id: str = analysis_id,
            current_target: str = target_id,
        ) -> Mapping[str, JsonValue]:
            return MappingProxyType(
                {
                    "node_id": current_id,
                    "target_id": current_target,
                    "certifying": False,
                    "analysis_only": True,
                }
            )

        def analysis_pre_store(
            runtime: WarmRuntime,
            _dependency_outcomes: Mapping[str, NodeOutcome],
        ) -> None:
            verify_before_store(runtime, ())

        nodes.append(
            IncrementalNode(
                id=analysis_id,
                domain="producer",
                depends_on=dependencies,
                outputs=current_paths,
                key=analysis_key_factory,
                execute=analysis_action,
                metadata=analysis_metadata,
                pre_store=analysis_pre_store,
                materialize_inputs=analysis_input_materializer,
                phase=IncrementalPhase.TRANSFORM,
                order_only=order_only,
            )
        )
        prior_analysis_id = analysis_id
