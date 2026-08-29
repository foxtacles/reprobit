"""Auditable cache-key material builders for classic incremental node roles."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from functools import partial
from pathlib import Path

from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    ClassicIncrementalPlan,
    json_value,
    reference_payload,
)
from reprobit.classic_link_closure import (
    ClassicLinkClosureError,
    MissingDirectiveInputsError,
    audit_classic_link_directives,
    direct_terminal_link_control_references,
    link_directive_closure_material,
    module_definition_material,
    parse_classic_module_definition,
)
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.incremental_executor import NodeOutcome
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import ProducerNode, ProducerRole
from reprobit.schema import ProjectBundle
from reprobit.strict_json import JsonValue


def dependency_material(dependencies: Mapping[str, NodeOutcome]) -> list[JsonValue]:
    return [
        json_value(
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


def _warm_link_control_references(
    linker: ProducerNode,
    graph_nodes: Sequence[ProducerNode],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if linker.role is not ProducerRole.LINKER or linker.target_id is None:
        raise ClassicIncrementalError("warm link-control audit requires one linker node")
    by_id = {node.id: node for node in graph_nodes}
    if len(by_id) != len(graph_nodes) or by_id.get(linker.id) != linker:
        raise ClassicIncrementalError("warm link-control graph is incomplete or ambiguous")
    try:
        references = direct_terminal_link_control_references(linker)
    except ClassicLinkClosureError as exc:
        raise ClassicIncrementalError(str(exc)) from exc
    return references.objects, references.archives, references.definitions


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
    object_inputs = {reference: payload_for_reference(reference) for reference in object_refs}
    archive_inputs = {reference: payload_for_reference(reference) for reference in archive_refs}
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
    return json_value(
        {
            "schema": 1,
            "target_id": linker.target_id,
            "linker_node": linker.id,
            "directives": link_directive_closure_material(closure),
            "module_definition": module_definition_material(definition),
        }
    )


def _warm_analysis_link_material(
    linker: ProducerNode,
    *,
    arguments: Sequence[str],
    exact_logical_image: str,
    added_options: tuple[str, ...],
) -> JsonValue:
    """Validate and serialize the closed warm `/DEBUG` relink authority."""

    if (
        linker.role is not ProducerRole.LINKER
        or linker.target_id is None
        or added_options != ("/DEBUG",)
    ):
        raise ClassicIncrementalError("warm analysis relink lacks closed linker authority")
    counts = {"out": 0, "pdb": 0, "implib": 0, "map": 0}
    incremental_no_count = 0
    original_out: str | None = None
    for argument in arguments:
        folded = argument.casefold()
        if folded in {"/debug", "-debug"} or folded.startswith(("/debug:", "-debug:")):
            raise ClassicIncrementalError(
                f"exact linker {linker.id!r} already contains an analysis debug option"
            )
        if folded.startswith(("/incremental:", "-incremental:")):
            if folded not in {"/incremental:no", "-incremental:no"}:
                raise ClassicIncrementalError(
                    f"warm analysis relink {linker.id!r} admits incremental linker state"
                )
            incremental_no_count += 1
        for name, prefixes in (
            ("out", ("/out:", "-out:")),
            ("pdb", ("/pdb:", "-pdb:")),
            ("implib", ("/implib:", "-implib:")),
            ("map", ("/map:", "-map:")),
        ):
            prefix = next((item for item in prefixes if folded.startswith(item)), None)
            if prefix is None:
                continue
            if len(argument) == len(prefix) or "\x00" in argument:
                raise ClassicIncrementalError(
                    f"warm analysis relink {linker.id!r} has a malformed /{name.upper()} control"
                )
            counts[name] += 1
            if name == "out":
                original_out = argument[len(prefix) :]
            break
    if counts["out"] != 1 or counts["pdb"] != 1:
        raise ClassicIncrementalError(
            f"warm analysis relink {linker.id!r} requires one /OUT and one /PDB"
        )
    if incremental_no_count != 1:
        raise ClassicIncrementalError(
            f"warm analysis relink {linker.id!r} requires one /INCREMENTAL:NO"
        )
    if counts["implib"] > 1 or counts["map"] > 1 or original_out is None:
        raise ClassicIncrementalError(
            f"warm analysis relink {linker.id!r} repeats a secondary output control"
        )
    try:
        received_out = normalize_logical_path(original_out.replace("/", "\\"))
        expected_out = normalize_logical_path(exact_logical_image)
    except ValueError as exc:
        raise ClassicIncrementalError(
            f"warm analysis relink {linker.id!r} has an invalid /OUT control"
        ) from exc
    if received_out.casefold() != expected_out.casefold():
        raise ClassicIncrementalError(
            f"warm analysis relink {linker.id!r} /OUT differs from its exact target"
        )
    return json_value(
        {
            "schema": 1,
            "kind": "classic-analysis-link-v1",
            "target_id": linker.target_id,
            "linker_node": linker.id,
            "exact_image": expected_out,
            "added_options": list(added_options),
            "isolated_outputs": ["image", "pdb"],
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
        "argv": json_value(list(argv)),
        "cwd": normalize_logical_path(bundle.spec.paths.build),
        "environment": json_value(dict(environment)),
        "path_profile": json_value(
            {
                "id": graph.path_profile_id,
                "source": normalize_logical_path(bundle.spec.paths.source),
                "build": normalize_logical_path(bundle.spec.paths.build),
                "toolchain": normalize_logical_path(bundle.spec.paths.toolchain),
            }
        ),
        "direct_inputs": json_value(list(direct_inputs)),
        "producer_dependencies": json_value(dependency_material(dependencies)),
        "recursive_reads": json_value(list(recursive_reads)),
        "overlay_inputs": json_value(list(overlay_inputs)),
        "generated_inputs": json_value(list(generated_inputs)),
        "donor_inputs": json_value(list(donor_inputs)),
        "composition_inputs": json_value(list(composition_inputs)),
        "transform_inputs": json_value(list(transform_inputs)),
    }


def compiler_material(
    plan: ClassicIncrementalPlan,
    node: ProducerNode,
    *,
    direct: Sequence[JsonValue],
    overlay_inputs: Sequence[JsonValue],
    generated_inputs: Sequence[JsonValue],
    arguments: Sequence[str],
    dependencies: Mapping[str, NodeOutcome],
) -> dict[str, JsonValue]:
    return _base_material(
        bundle=plan.bundle,
        graph_digest=plan.graph_digest,
        node_identity=json_value(node.model_dump(mode="json")),
        role=node.role.value,
        toolchain=plan.toolchain_material,
        runtime=plan.runtime_material,
        argv=arguments,
        environment=plan.environment,
        direct_inputs=direct,
        dependencies=dependencies,
        recursive_reads=(),
        overlay_inputs=overlay_inputs,
        generated_inputs=generated_inputs,
    )


def producer_material(
    plan: ClassicIncrementalPlan,
    node: ProducerNode,
    *,
    direct: Sequence[JsonValue],
    recursive_reads: Sequence[JsonValue],
    overlay_inputs: Sequence[JsonValue],
    arguments: Sequence[str],
    immutable_inputs: Mapping[str, Path],
    dependencies: Mapping[str, NodeOutcome],
) -> dict[str, JsonValue]:
    link_controls = (
        (
            _warm_link_control_material(
                node,
                plan.graph.nodes,
                payload_for_reference=partial(
                    reference_payload,
                    plan,
                    immutable_build_inputs=immutable_inputs,
                ),
            ),
        )
        if node.role is ProducerRole.LINKER
        else ()
    )
    return _base_material(
        bundle=plan.bundle,
        graph_digest=plan.graph_digest,
        node_identity=json_value(node.model_dump(mode="json")),
        role=node.role.value,
        toolchain=plan.toolchain_material,
        runtime=plan.runtime_material,
        argv=arguments,
        environment=plan.environment,
        direct_inputs=direct,
        dependencies=dependencies,
        recursive_reads=recursive_reads,
        overlay_inputs=overlay_inputs,
        composition_inputs=link_controls,
    )


def transform_material(
    plan: ClassicIncrementalPlan,
    compiler_id: str,
    node: ProducerNode,
    unit: ClassicPreparedUnit,
    *,
    document: object,
    proofs: Sequence[JsonValue],
    donor_inputs: Sequence[JsonValue],
    oracle_inputs: Sequence[JsonValue],
    rdata_inputs: Sequence[JsonValue],
    overlay_inputs: Sequence[JsonValue],
    dependencies: Mapping[str, NodeOutcome],
) -> dict[str, JsonValue]:
    return _base_material(
        bundle=plan.bundle,
        graph_digest=plan.graph_digest,
        node_identity=json_value(
            {
                "id": plan.transform_ids[compiler_id],
                "compiler_node": node.model_dump(mode="json"),
                "translation_unit": unit.plan.model_dump(mode="json"),
            }
        ),
        role="compiler-transform",
        toolchain=plan.toolchain_material,
        runtime=plan.runtime_material,
        argv=("internal:classic-tu-transform",),
        environment=plan.environment,
        direct_inputs=oracle_inputs,
        dependencies=dependencies,
        recursive_reads=(),
        overlay_inputs=overlay_inputs,
        donor_inputs=donor_inputs,
        composition_inputs=(json_value(document), *proofs),
        transform_inputs=(
            *(json_value(item.model_dump(mode="json")) for item in unit.actions),
            *rdata_inputs,
        ),
    )


def terminal_material(
    plan: ClassicIncrementalPlan,
    linker: ProducerNode,
    target_id: str,
    *,
    quarantine: Sequence[JsonValue],
    interventions: Sequence[JsonValue],
    dependencies: Mapping[str, NodeOutcome],
) -> dict[str, JsonValue]:
    return _base_material(
        bundle=plan.bundle,
        graph_digest=plan.graph_digest,
        node_identity=json_value(
            {
                "id": f"terminal.{target_id}",
                "linker": linker.model_dump(mode="json"),
            }
        ),
        role="terminal-transform",
        toolchain=plan.toolchain_material,
        runtime=plan.runtime_material,
        argv=("internal:classic-terminal-pipeline", target_id),
        environment=plan.environment,
        direct_inputs=quarantine,
        dependencies=dependencies,
        recursive_reads=(),
        composition_inputs=(json_value(plan.bundle.spec.authenticity.model_dump(mode="json")),),
        transform_inputs=interventions,
    )


def analysis_material(
    plan: ClassicIncrementalPlan,
    node_id: str,
    linker: ProducerNode,
    target_id: str,
    authority: JsonValue,
    *,
    dependencies: Mapping[str, NodeOutcome],
) -> dict[str, JsonValue]:
    return _base_material(
        bundle=plan.bundle,
        graph_digest=plan.graph_digest,
        node_identity=json_value(
            {
                "id": node_id,
                "target_id": target_id,
                "linker": linker.model_dump(mode="json"),
            }
        ),
        role="analysis-link",
        toolchain=plan.toolchain_material,
        runtime=plan.runtime_material,
        argv=("internal:classic-analysis-link-v1", *plan.analysis_link_options),
        environment=plan.environment,
        direct_inputs=(),
        dependencies=dependencies,
        recursive_reads=(),
        composition_inputs=(authority,),
    )
