"""Project-neutral planning and composition for migrated classic MSVC builds.

This module owns the seam between typed schema-v3 shards and the low-level
COFF/PE producers.  It deliberately does not know how a consumer names its
CMake targets and never receives an image oracle.  A build adapter supplies
fresh compiler products; the functions here validate the complete declaration
graph, render private donor inputs, compose translation units, and apply the
candidate-only terminal pipeline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from reprobit.classic_donors import (
    DonorCompileRequest,
    DonorSourceError,
    matching_candidate_constraints,
    prepare_donor_compile_request,
)
from reprobit.classic_project import (
    ClassicCandidate,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
    InterventionWitness,
)
from reprobit.classic_semantics import (
    ClassicSemanticError,
    DonorSemanticUse,
    issue_classic_donor_semantics,
)
from reprobit.model import Digest, SemanticProof
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
    LegacyOracleInstallIntervention,
    ProjectBundle,
)
from reprobit.strict_json import canonical_json

if TYPE_CHECKING:
    from reprobit.legacy import PE32VirtualAddressReader


@dataclass(frozen=True, slots=True)
class ClassicPreparedDonor:
    intervention: ClassicRecipeIntervention
    request: DonorCompileRequest


@dataclass(frozen=True, slots=True)
class ClassicPreparedUnit:
    plan: ClassicTranslationUnitPlan
    donors: tuple[ClassicPreparedDonor, ...]
    functions: tuple[ClassicRecipeIntervention, ...]
    legacy_actions: tuple[LegacyOracleInstallIntervention, ...]
    actions: tuple[ClassicRecipeIntervention | LegacyOracleInstallIntervention, ...]
    receipts: tuple[ClassicProofReceipt, ...]


@dataclass(frozen=True, slots=True)
class ClassicUnitComposition:
    output: bytes
    witnesses: tuple[InterventionWitness, ...]
    group_order_evidence: Digest | None = None
    donor_semantic_proofs: Mapping[str, SemanticProof] = MappingProxyType({})
    donor_semantic_uses: Mapping[str, tuple[DonorSemanticUse, ...]] = MappingProxyType(
        {}
    )


@dataclass(frozen=True, slots=True)
class ClassicTerminalComposition:
    output: bytes
    witnesses: tuple[InterventionWitness, ...]


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    return {field.name: field.value for field in intervention.parameters}


def _receipt_index(bundle: ProjectBundle) -> tuple[ClassicProofReceipt, ...]:
    return tuple(
        receipt
        for document in bundle.proof_documents
        for receipt in document.expected_observations
    )


def _temporary_classic_legacy_action_authority(
    bundle: ProjectBundle,
) -> Mapping[str, tuple[LegacyOracleInstallIntervention, ...]]:
    """Validate and group the one-off classic oracle bridge by planned TU."""

    action_documents = tuple(
        (
            document,
            tuple(
                item
                for item in document.interventions
                if isinstance(item, LegacyOracleInstallIntervention)
            ),
        )
        for document in bundle.intervention_documents
        if any(
            isinstance(item, LegacyOracleInstallIntervention)
            for item in document.interventions
        )
    )
    if not action_documents:
        return MappingProxyType({})
    plan = bundle.build_plan
    if plan is None:
        raise ClassicProjectError(
            "temporary classic legacy-action authority requires a build plan"
        )
    planned_units = {unit.id: unit for unit in plan.translation_units}
    grouped: dict[str, list[LegacyOracleInstallIntervention]] = {}
    for document, actions in action_documents:
        unit_id = document.translation_unit_id
        if unit_id is None or unit_id not in planned_units:
            raise ClassicProjectError(
                f"legacy action {actions[0].id!r} is outside a planned "
                "translation-unit shard"
            )
        unit = planned_units[unit_id]
        donors = {
            item.id
            for item in document.interventions
            if isinstance(item, ClassicRecipeIntervention)
            and item.role is ClassicRecipeRole.DONOR
        }
        for action in actions:
            if action.scope.translation_unit != unit_id or action.scope.function is None:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} must have exact function and "
                    "translation-unit scope"
                )
            if document.target_id != unit.target_id or action.scope.target != unit.target_id:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} target differs from its planned "
                    "translation-unit shard"
                )
            if action.oracle_target != action.scope.target:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} oracle target differs from its scope"
                )
            if len(action.dependencies) != 1:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} requires exactly one donor dependency"
                )
            dependency = action.dependencies[0]
            if dependency not in donors:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} dependency {dependency!r} is not a "
                    "donor in its translation-unit shard"
                )
            grouped.setdefault(unit_id, []).append(action)
    return MappingProxyType(
        {
            unit_id: tuple(actions)
            for unit_id, actions in sorted(grouped.items())
        }
    )


_COMPILER_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})


def _compiler_source(node: ProducerNode) -> str:
    sources = tuple(
        reference.removeprefix("source/")
        for reference in node.inputs
        if reference.startswith("source/")
        and PurePosixPath(reference).suffix.casefold() in _COMPILER_SOURCE_SUFFIXES
    )
    if len(sources) != 1:
        raise ClassicProjectError(
            f"compiler node {node.id!r} lacks one translation-unit source"
        )
    return sources[0]


def _compiler_terminal_consumer_targets(
    graph: ProducerGraphDocument,
) -> Mapping[str, frozenset[str]]:
    """Map compiler nodes to terminal targets reached through actual build inputs."""

    output_owners: dict[str, ProducerNode] = {}
    consumers: dict[str, set[str]] = {
        node.id: set()
        for node in graph.nodes
        if node.role is ProducerRole.COMPILER
    }
    for node in graph.nodes:
        for reference in node.outputs:
            identity = reference.casefold()
            if identity in output_owners:
                raise ClassicProjectError(
                    f"producer graph repeats output authority for {reference!r}"
                )
            output_owners[identity] = node

    def visit(node: ProducerNode, *, target_id: str, visited: set[str]) -> None:
        if node.id in visited:
            return
        visited.add(node.id)
        for reference in node.inputs:
            if not reference.startswith("build/"):
                continue
            producer = output_owners.get(reference.casefold())
            if producer is None:
                continue
            if producer.role is ProducerRole.COMPILER:
                consumers[producer.id].add(target_id)
            elif producer.role is not ProducerRole.LINKER:
                visit(producer, target_id=target_id, visited=visited)

    for linker in (node for node in graph.nodes if node.role is ProducerRole.LINKER):
        if linker.target_id is None:
            raise ClassicProjectError(f"linker {linker.id!r} lacks a target identity")
        visit(linker, target_id=linker.target_id, visited=set())
    return MappingProxyType(
        {
            node_id: frozenset(target_ids)
            for node_id, target_ids in consumers.items()
        }
    )


def classic_compiler_translation_unit_authority(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
) -> Mapping[str, ClassicTranslationUnitPlan]:
    """Bind every planned target/source identity to one graph compiler node."""

    plan = bundle.build_plan
    if plan is None:
        raise ClassicProjectError("classic compiler authority requires a build plan")
    planned_by_identity: dict[tuple[str, str], ClassicTranslationUnitPlan] = {}
    for unit in plan.translation_units:
        identity = (unit.build_target.casefold(), unit.source.casefold())
        if identity in planned_by_identity:
            raise ClassicProjectError(
                "build plan repeats one target/source compile identity: "
                f"{unit.build_target}/{unit.source}"
            )
        planned_by_identity[identity] = unit

    compilers_by_identity: dict[tuple[str, str], list[ProducerNode]] = {}
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        identity = (node.owner.casefold(), _compiler_source(node).casefold())
        compilers_by_identity.setdefault(identity, []).append(node)

    consumers = _compiler_terminal_consumer_targets(graph)
    result: dict[str, ClassicTranslationUnitPlan] = {}
    for identity, unit in planned_by_identity.items():
        matches = compilers_by_identity.get(identity, [])
        if len(matches) != 1:
            raise ClassicProjectError(
                "build-plan translation unit has no unique graph compiler lane: "
                f"{unit.build_target}/{unit.source}"
            )
        compiler = matches[0]
        actual_targets = consumers[compiler.id]
        expected_targets = frozenset({unit.target_id})
        if actual_targets != expected_targets:
            raise ClassicProjectError(
                "build-plan translation-unit compiler terminal consumers differ: "
                f"unit={unit.id!r}, compiler={compiler.id!r}, "
                f"declared={unit.target_id!r}, actual={sorted(actual_targets)!r}"
            )
        result[compiler.id] = unit
    return MappingProxyType(result)


def _receipt_mentions_rdata_selector(receipt: ClassicProofReceipt) -> bool:
    root = "rdata_pool_repack"
    return any(
        path == root or path.startswith(f"{root}.") or path.startswith(f"{root}[")
        for path in receipt.expected_values
    )


def _rdata_repack_materialization(
    intervention: ClassicRecipeIntervention,
    receipts: Sequence[ClassicProofReceipt],
) -> tuple[ClassicProofReceipt, Mapping[str, object], str] | None:
    raw_values = _parameters(intervention)
    raw_present = "rdata_pool_repack" in raw_values
    matching_receipts = tuple(
        receipt for receipt in receipts if receipt.intervention_id == intervention.id
    )
    if not raw_present and not any(
        _receipt_mentions_rdata_selector(receipt) for receipt in matching_receipts
    ):
        return None
    try:
        values = matching_candidate_constraints(intervention, receipts).materialize()
    except DonorSourceError as exc:
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} has invalid proof constraints: {exc}"
        ) from exc
    materialized_present = "rdata_pool_repack" in values
    if raw_present != materialized_present:
        raise ClassicProjectError(
            f"proof receipt cannot introduce or remove the rdata repack selector for "
            f"{intervention.id!r}"
        )
    if intervention.family is not ClassicRecipeFamily.IMAGE_BINARY_REPACK or (
        intervention.role is not ClassicRecipeRole.PROJECT
    ):
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} must be a project image-binary-repack recipe"
        )
    if set(values) != {"rdata_pool_repack"}:
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} declaration is not closed"
        )
    raw_declaration = raw_values.get("rdata_pool_repack")
    declaration = values.get("rdata_pool_repack")
    if not isinstance(raw_declaration, dict) or not isinstance(declaration, dict):
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} has an invalid selector"
        )
    if declaration.get("schema") != "rdata_pool_repack_v1":
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} has an unsupported selector schema"
        )
    raw_object = raw_declaration.get("object")
    object_path = declaration.get("object")
    if not isinstance(raw_object, str) or not raw_object or (
        not isinstance(object_path, str) or not object_path
    ):
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} has an invalid object path"
        )
    if raw_object != object_path:
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} proof changes its selected object"
        )
    if len(matching_receipts) != 1:
        # The materializer normally closes this condition.  Keep the returned
        # receipt identity explicit rather than relying on a lossy dictionary.
        raise ClassicProjectError(
            f"rdata repack {intervention.id!r} lacks one proof receipt"
        )
    return matching_receipts[0], MappingProxyType(dict(values)), object_path


def classic_terminal_pipeline_authority(
    bundle: ProjectBundle,
    *,
    target_id: str,
) -> tuple[tuple[ClassicRecipeIntervention, ClassicProofReceipt], ...]:
    """Select the exact declarations and proof receipts consumed post-link."""

    receipts = {item.intervention_id: item for item in _receipt_index(bundle)}
    selected = tuple(
        sorted(
            (
                item
                for item in bundle.interventions
                if isinstance(item, ClassicRecipeIntervention)
                and item.role is ClassicRecipeRole.PROJECT
                and item.scope.target == target_id
                and item.family
                in {
                    ClassicRecipeFamily.IMAGE_LINK_ORDER,
                    ClassicRecipeFamily.IMAGE_METADATA,
                    ClassicRecipeFamily.IMAGE_BINARY_REPACK,
                }
                and "rdata_pool_repack" not in _parameters(item)
            ),
            key=lambda item: (
                {
                    ClassicRecipeFamily.IMAGE_METADATA: 0,
                    ClassicRecipeFamily.IMAGE_LINK_ORDER: 1,
                    ClassicRecipeFamily.IMAGE_BINARY_REPACK: 2,
                }[item.family],
                item.id,
            ),
        )
    )
    result: list[tuple[ClassicRecipeIntervention, ClassicProofReceipt]] = []
    for intervention in selected:
        receipt = receipts.get(intervention.id)
        if receipt is None:
            raise ClassicProjectError(
                f"terminal intervention {intervention.id!r} lacks one proof receipt"
            )
        # Materialization is the same proof/declaration compatibility gate the
        # actual transform consumes.  Planning therefore cannot key a stale
        # or malformed proof and defer the failure until after a cache hit.
        matching_candidate_constraints(intervention, tuple(receipts.values())).materialize()
        result.append((intervention, receipt))
    return tuple(result)


def classic_rdata_repack_authority(
    bundle: ProjectBundle,
    *,
    target_id: str,
    object_path: str,
) -> tuple[ClassicRecipeIntervention, ClassicProofReceipt, Mapping[str, object]] | None:
    """Select one exact pre-link object repack declaration and proof receipt."""

    receipt_values = _receipt_index(bundle)
    matches: list[
        tuple[ClassicRecipeIntervention, ClassicProofReceipt, Mapping[str, object]]
    ] = []
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.scope.target != target_id
        ):
            continue
        materialized = _rdata_repack_materialization(intervention, receipt_values)
        if materialized is None:
            continue
        receipt, values, selected_object = materialized
        if selected_object != object_path:
            continue
        matches.append((intervention, receipt, values))
    if not matches:
        return None
    if len(matches) != 1:
        raise ClassicProjectError(f"multiple rdata repacks name {object_path!r}")
    return matches[0]


def classic_rdata_repack_graph_authority(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
) -> Mapping[
    str,
    tuple[ClassicRecipeIntervention, ClassicProofReceipt, Mapping[str, object]],
]:
    """Close the one-repack-per-produced-object authority for all targets."""

    by_id = {node.id: node for node in graph.nodes}
    if len(by_id) != len(graph.nodes):
        raise ClassicProjectError("producer graph repeats a node identity")
    produced_objects: dict[str, dict[str, tuple[ProducerNode, str]]] = {}
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        for reference in node.outputs:
            if not reference.startswith("build/") or not reference.casefold().endswith(".obj"):
                continue
            object_path = reference.removeprefix("build/")
            produced_objects.setdefault(object_path.casefold(), {})[node.id] = (
                node,
                object_path,
            )
    compiler_consumers = _compiler_terminal_consumer_targets(graph)

    receipt_values = _receipt_index(bundle)
    selected: dict[
        str,
        list[
            tuple[
                ClassicRecipeIntervention,
                ClassicProofReceipt,
                Mapping[str, object],
            ]
        ],
    ] = {}
    for intervention in sorted(
        (
            item
            for item in bundle.interventions
            if isinstance(item, ClassicRecipeIntervention)
        ),
        key=lambda item: item.id,
    ):
        materialized = _rdata_repack_materialization(intervention, receipt_values)
        if materialized is None:
            continue
        receipt, values, object_path = materialized
        object_identity = object_path.casefold()
        producers = produced_objects.get(object_identity, {})
        if not producers:
            raise ClassicProjectError(
                f"rdata repack {intervention.id!r} names an unproduced object: "
                f"{object_path!r}"
            )
        canonical_object = next(iter(producers.values()))[1]
        if object_path != canonical_object:
            raise ClassicProjectError(
                f"rdata repack {intervention.id!r} must use the graph's exact object "
                f"spelling {canonical_object!r}, not {object_path!r}"
            )
        target_id = intervention.scope.target
        consumer_targets = frozenset(
            consumer_target
            for producer, _canonical_path in producers.values()
            for consumer_target in compiler_consumers[producer.id]
        )
        if target_id not in consumer_targets:
            raise ClassicProjectError(
                f"rdata repack {intervention.id!r} targets {canonical_object!r}, "
                f"which target {target_id!r} does not consume"
            )
        selected.setdefault(object_identity, []).append(
            (intervention, receipt, values)
        )

    result: dict[
        str,
        tuple[ClassicRecipeIntervention, ClassicProofReceipt, Mapping[str, object]],
    ] = {}
    selected_producers: dict[str, ProducerNode] = {}
    for object_identity, matches in sorted(selected.items()):
        producers = produced_objects[object_identity]
        canonical_object = next(iter(producers.values()))[1]
        if len(matches) != 1:
            identities = ", ".join(repr(item[0].id) for item in matches)
            raise ClassicProjectError(
                f"multiple rdata repacks name {canonical_object!r}: "
                f"{identities}"
            )
        if len(producers) != 1:
            identities = ", ".join(repr(node_id) for node_id in sorted(producers))
            raise ClassicProjectError(
                f"rdata repack object {canonical_object!r} has multiple producing "
                f"compiler nodes: {identities}"
            )
        producer = next(iter(producers.values()))[0]
        intervention = matches[0][0]
        consumer_targets = compiler_consumers[producer.id]
        if consumer_targets != frozenset({intervention.scope.target}):
            raise ClassicProjectError(
                f"rdata repack {intervention.id!r} terminal consumers differ for "
                f"{canonical_object!r}: declared={intervention.scope.target!r}, "
                f"actual={sorted(consumer_targets)!r}"
            )
        object_outputs = tuple(
            reference
            for reference in producer.outputs
            if reference.startswith("build/")
            and reference.casefold().endswith(".obj")
        )
        pdb_outputs = tuple(
            reference
            for reference in producer.outputs
            if reference.startswith("build/")
            and reference.casefold().endswith(".pdb")
        )
        if len(object_outputs) != 1 or len(pdb_outputs) != 1:
            raise ClassicProjectError(
                f"rdata repack compiler {producer.id!r} must publish exactly one "
                "object and one PDB"
            )
        selected_producers[object_identity] = producer
        result[object_identity] = matches[0]

    compiler_units = classic_compiler_translation_unit_authority(bundle, graph)
    for object_identity, producer in selected_producers.items():
        if producer.id in compiler_units:
            continue
        canonical_object = produced_objects[object_identity][producer.id][1]
        raise ClassicProjectError(
            f"rdata repack object {canonical_object!r} has no prepared "
            "translation-unit compiler lane"
        )
    return MappingProxyType(result)


def _canonical_overlay_operations(
    bundle: ProjectBundle,
) -> Mapping[str, tuple[Mapping[str, object], ...]]:
    result: dict[str, tuple[Mapping[str, object], ...]] = {}
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            continue
        outputs = _parameters(intervention).get("outputs")
        if not isinstance(outputs, list):
            raise ClassicProjectError("source-overlay outputs are malformed")
        for raw in outputs:
            if not isinstance(raw, dict):
                raise ClassicProjectError("source-overlay output is malformed")
            path = raw.get("path")
            operations = raw.get("ops")
            if not isinstance(path, str) or not isinstance(operations, list) or (
                any(not isinstance(item, dict) for item in operations)
            ):
                raise ClassicProjectError("source-overlay operation list is malformed")
            if path in result:
                raise ClassicProjectError(f"source-overlay output repeats {path!r}")
            result[path] = tuple(operations)
    return MappingProxyType(result)


def _donor_source(
    intervention: ClassicRecipeIntervention,
    receipts: Sequence[ClassicProofReceipt],
    owning_source: str,
) -> str:
    values = matching_candidate_constraints(intervention, receipts).materialize()
    value = values.get("donor_source", owning_source)
    if not isinstance(value, str) or not value:
        raise ClassicProjectError(
            f"donor {intervention.id!r} has an invalid source declaration"
        )
    return value


def prepare_classic_units(
    bundle: ProjectBundle,
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    overlay_dialect: object | None = None,
) -> tuple[ClassicPreparedUnit, ...]:
    """Close every TU shard and render all private donor compile requests."""

    if bundle.build_plan is None:
        raise ClassicProjectError("classic orchestration requires a build plan")
    legacy_actions = _temporary_classic_legacy_action_authority(bundle)
    receipts = _receipt_index(bundle)
    documents = {
        document.translation_unit_id: document
        for document in bundle.intervention_documents
        if document.translation_unit_id is not None
    }
    canonical_operations = _canonical_overlay_operations(bundle)
    prepared: list[ClassicPreparedUnit] = []
    for plan in bundle.build_plan.translation_units:
        document = documents.get(plan.id)
        if document is None or document.source != plan.source:
            raise ClassicProjectError(f"translation-unit shard is absent: {plan.id!r}")
        unit_interventions = tuple(document.interventions)
        donors = tuple(
            item
            for item in unit_interventions
            if isinstance(item, ClassicRecipeIntervention)
            and item.role is ClassicRecipeRole.DONOR
        )
        functions = tuple(
            item
            for item in unit_interventions
            if isinstance(item, ClassicRecipeIntervention)
            and item.role is ClassicRecipeRole.FUNCTION
        )
        legacy = legacy_actions.get(plan.id, ())
        actions = tuple(
            item
            for item in unit_interventions
            if isinstance(item, LegacyOracleInstallIntervention)
            or (
                isinstance(item, ClassicRecipeIntervention)
                and item.role is ClassicRecipeRole.FUNCTION
            )
        )
        admitted_ids = {item.id for item in donors}
        for function in (*functions, *legacy):
            unknown = set(function.dependencies) - admitted_ids
            if unknown:
                raise ClassicProjectError(
                    f"function {function.id!r} has non-donor dependencies: {sorted(unknown)}"
                )
            if not function.dependencies:
                raise ClassicProjectError(
                    f"function {function.id!r} has no fresh donor dependency"
                )
        rendered_donors: list[ClassicPreparedDonor] = []
        for donor in donors:
            logical_source = _donor_source(donor, receipts, plan.source)
            clean = clean_sources.get(logical_source)
            effective = effective_sources.get(logical_source)
            if clean is None or effective is None:
                raise ClassicProjectError(
                    f"donor {donor.id!r} source is outside source authority: "
                    f"{logical_source!r}"
                )
            operation_replay = canonical_operations.get(logical_source)
            overlay_clean_inputs: Mapping[str, bytes] | None = None
            if donor.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
                renderings = _parameters(donor).get("renderings")
                if not isinstance(renderings, list) or not renderings:
                    raise ClassicProjectError(
                        f"overlay donor {donor.id!r} has no rendering paths"
                    )
                selected: dict[str, bytes] = {}
                for raw_rendering in renderings:
                    if not isinstance(raw_rendering, dict) or not isinstance(
                        raw_rendering.get("path"), str
                    ):
                        raise ClassicProjectError(
                            f"overlay donor {donor.id!r} rendering is malformed"
                        )
                    rendering_path = cast(str, raw_rendering["path"])
                    payload = clean_sources.get(rendering_path)
                    if payload is None:
                        raise ClassicProjectError(
                            f"overlay donor clean input is absent: {rendering_path!r}"
                        )
                    selected[rendering_path] = payload
                overlay_clean_inputs = selected
            kwargs: dict[str, Any] = {}
            if overlay_dialect is not None:
                kwargs["overlay_dialect"] = overlay_dialect
            try:
                request = prepare_donor_compile_request(
                    donor,
                    source_path=logical_source,
                    clean_source=clean,
                    effective_source=effective,
                    receipts=receipts,
                    clean_sources=overlay_clean_inputs,
                    canonical_overlay_operations=operation_replay
                    if _parameters(donor).get("canonical_overlay_replay") is not None
                    else None,
                    **kwargs,
                )
            except ValueError as exc:
                raise ClassicProjectError(
                    f"cannot prepare donor {donor.id!r}: {exc}"
                ) from exc
            rendered_donors.append(ClassicPreparedDonor(donor, request))
        unit_receipts = tuple(
            item
            for item in receipts
            if item.intervention_id in {entry.id for entry in unit_interventions}
        )
        prepared.append(
            ClassicPreparedUnit(
                plan,
                tuple(rendered_donors),
                functions,
                legacy,
                actions,
                unit_receipts,
            )
        )
    return tuple(prepared)


def _legacy_donor_index(unit: ClassicPreparedUnit) -> Mapping[str, str]:
    result: dict[str, str] = {}
    for donor in unit.donors:
        legacy_id = _parameters(donor.intervention).get("legacy_recipe_id")
        if isinstance(legacy_id, str):
            if legacy_id in result:
                raise ClassicProjectError(f"legacy donor identity repeats: {legacy_id!r}")
            result[legacy_id] = donor.intervention.id
    return MappingProxyType(result)


def _named_donor_id(
    values: Mapping[str, object],
    name: str,
    legacy_ids: Mapping[str, str],
) -> str | None:
    legacy_id = values.get(name)
    if legacy_id is None:
        return None
    if not isinstance(legacy_id, str) or legacy_id not in legacy_ids:
        raise ClassicProjectError(f"function names an unknown {name}: {legacy_id!r}")
    return legacy_ids[legacy_id]


def compose_classic_unit(
    unit: ClassicPreparedUnit,
    *,
    seed_object: bytes,
    donor_objects: Mapping[str, bytes],
    donor_compile_statements: Mapping[str, Mapping[str, object]],
    seed_source: bytes,
    legacy_oracles: Mapping[str, PE32VirtualAddressReader] | None = None,
) -> ClassicUnitComposition:
    """Compose one independently compiled TU without access to image-oracle bytes."""

    from reprobit import classic

    if not isinstance(seed_object, bytes) or not isinstance(seed_source, bytes):
        raise ClassicProjectError("classic unit inputs must be immutable bytes")
    expected_donors = {item.intervention.id for item in unit.donors}
    if set(donor_objects) != expected_donors:
        missing = sorted(expected_donors - set(donor_objects))
        extra = sorted(set(donor_objects) - expected_donors)
        raise ClassicProjectError(
            f"fresh donor-object universe differs; missing={missing}, extra={extra}"
        )
    if set(donor_compile_statements) != expected_donors:
        missing = sorted(expected_donors - set(donor_compile_statements))
        extra = sorted(set(donor_compile_statements) - expected_donors)
        raise ClassicProjectError(
            f"donor compile-statement universe differs; missing={missing}, extra={extra}"
        )
    donor_sources = {
        item.intervention.id: item.request.logical_outputs.get(unit.plan.source)
        for item in unit.donors
    }
    legacy_ids = _legacy_donor_index(unit)
    output = seed_object
    witnesses: list[InterventionWitness] = []
    donor_uses: dict[str, list[DonorSemanticUse]] = {
        donor_id: [] for donor_id in expected_donors
    }
    quarantined_uses: dict[str, dict[str, Digest]] = {
        donor_id: {} for donor_id in expected_donors
    }
    dispatcher = ClassicFamilyDispatcher()
    for action in unit.actions:
        if isinstance(action, LegacyOracleInstallIntervention):
            if legacy_oracles is None or action.oracle_target not in legacy_oracles:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} lacks its sealed oracle capability"
                )
            matches = [
                item for item in unit.receipts if item.intervention_id == action.id
            ]
            if len(matches) != 1:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} requires one proof receipt"
                )
            if len(action.dependencies) != 1:
                raise ClassicProjectError(
                    f"legacy action {action.id!r} requires one fresh donor"
                )
            from reprobit.classic_legacy import compose_legacy_simulated_elision

            result = compose_legacy_simulated_elision(
                action,
                matches[0],
                output,
                donor_objects[action.dependencies[0]],
                legacy_oracles[action.oracle_target],
            )
            output = result.output
            for donor_id in action.dependencies:
                quarantined_uses[donor_id][action.id] = result.evidence_digest
            witnesses.append(
                InterventionWitness(
                    action.id,
                    action.scope.target,
                    result.evidence_digest,
                    legacy_oracle_install=True,
                )
            )
            continue
        function = action
        values = matching_candidate_constraints(function, unit.receipts).materialize()
        primary_id = function.dependencies[0]
        primary = donor_objects[primary_id]
        target_donor_id = _named_donor_id(values, "target_donor", legacy_ids)
        complete_donor_id = _named_donor_id(values, "complete_donor", legacy_ids)
        instruction_donor_id = _named_donor_id(
            values, "instruction_donor", legacy_ids
        )
        function_donor_inputs = {
            primary_id: f"dependency:{primary_id}",
        }
        for named_donor_id, input_name in (
            (target_donor_id, "target_donor_object"),
            (complete_donor_id, "complete_donor_object"),
            (instruction_donor_id, "instruction_donor_object"),
        ):
            if named_donor_id is not None:
                function_donor_inputs.setdefault(named_donor_id, input_name)
        additional: dict[str, bytes] = {}
        variants = values.get("donor_variants", [])
        if isinstance(variants, list):
            for item in variants:
                if not isinstance(item, dict) or not isinstance(item.get("donor"), str):
                    raise ClassicProjectError("donor variant declaration is malformed")
                legacy_id = cast(str, item["donor"])
                resolved_donor_id = legacy_ids.get(legacy_id)
                if resolved_donor_id is None:
                    raise ClassicProjectError(f"donor variant is unknown: {legacy_id!r}")
                additional[legacy_id] = donor_objects[resolved_donor_id]
                function_donor_inputs.setdefault(
                    resolved_donor_id, f"additional_donor:{legacy_id}"
                )
        request = next(
            item.request for item in unit.donors if item.intervention.id == primary_id
        )
        try:
            candidate = dispatcher.dispatch(
                function,
                ClassicDispatchMaterials(
                    seed_object=output,
                    donor_object=primary,
                    target_donor_object=(
                        donor_objects[target_donor_id]
                        if target_donor_id is not None
                        else primary
                    ),
                    complete_donor_object=(
                        donor_objects[complete_donor_id]
                        if complete_donor_id is not None
                        else None
                    ),
                    instruction_donor_object=(
                        donor_objects[instruction_donor_id]
                        if instruction_donor_id is not None
                        else None
                    ),
                    seed_source=seed_source,
                    donor_source=donor_sources.get(primary_id),
                    target_donor_source=donor_sources.get(
                        target_donor_id if target_donor_id is not None else primary_id
                    ),
                    instruction_donor_source=(
                        donor_sources.get(instruction_donor_id)
                        if instruction_donor_id is not None
                        else None
                    ),
                    additional_donor_objects=additional,
                    shape_identifiers=request.carrier_identifiers,
                    candidate_constraints=values,
                ),
            )
        except Exception as exc:
            raise ClassicProjectError(
                f"classic action {function.id!r} "
                f"({function.family.value}, {function.symbol!r}) failed: {exc}"
            ) from exc
        output = candidate.output
        for donor_id, input_name in sorted(function_donor_inputs.items()):
            donor_uses[donor_id].append(
                DonorSemanticUse(
                    intervention_id=function.id,
                    proof=candidate.semantic_proof,
                    input_statement=candidate.semantic_input_statement,
                    output_statement=candidate.semantic_output_statement,
                    input_name=input_name,
                )
            )
        witnesses.append(
            InterventionWitness(
                function.id,
                function.scope.target,
                candidate.evidence_digest,
                semantic_proof=candidate.semantic_proof,
                semantic_input_statement=candidate.semantic_input_statement,
                semantic_output_statement=candidate.semantic_output_statement,
            )
        )
    group_evidence: Digest | None = None
    if unit.plan.group_order is not None:
        raw_orders = unit.plan.group_order
        if not isinstance(raw_orders, list) or not raw_orders:
            raise ClassicProjectError("group-order declaration is malformed")
        orders = raw_orders if isinstance(raw_orders[0], list) else [raw_orders]
        proofs: list[Mapping[str, object]] = []
        for order in orders:
            if not isinstance(order, list):
                raise ClassicProjectError("group-order list is malformed")
            if unit.plan.mode == "swap_comdat_group_order":
                output, proof = classic.compose_swap_comdat_group_order(
                    output, {"group_order": order}
                )
            elif unit.plan.mode in {
                "restore_comdat_group_order",
                "compose_equal_body_comdat",
            }:
                output, proof = classic.compose_restore_comdat_group_order(
                    output, {"group_order": order}
                )
            else:
                raise ClassicProjectError(
                    f"unsupported group-order mode: {unit.plan.mode!r}"
                )
            proofs.append(proof)
        group_evidence = Digest.from_bytes(canonical_json(proofs))
    donor_semantic_proofs: dict[str, SemanticProof] = {}
    for prepared in unit.donors:
        donor_id = prepared.intervention.id
        try:
            validation = issue_classic_donor_semantics(
                prepared.intervention,
                donor_object=donor_objects[donor_id],
                source_inputs=prepared.request.files,
                compiler_statement=donor_compile_statements[donor_id],
                downstream_uses=donor_uses[donor_id],
                quarantined_consumers=quarantined_uses[donor_id],
            )
        except ClassicSemanticError as exc:
            raise ClassicProjectError(
                f"classic donor semantic validator rejected {donor_id!r}: {exc}"
            ) from exc
        donor_semantic_proofs[donor_id] = validation.proof
    return ClassicUnitComposition(
        output,
        tuple(witnesses),
        group_evidence,
        MappingProxyType(donor_semantic_proofs),
        MappingProxyType(
            {
                donor_id: tuple(uses)
                for donor_id, uses in sorted(donor_uses.items())
            }
        ),
    )


def apply_classic_terminal_pipeline(
    bundle: ProjectBundle,
    *,
    target_id: str,
    candidate: bytes,
) -> ClassicTerminalComposition:
    """Apply postlink candidate-only transforms in one deterministic order."""

    if not isinstance(candidate, bytes):
        raise ClassicProjectError("terminal candidate must be immutable bytes")
    receipts = _receipt_index(bundle)
    interventions = tuple(
        item for item, _receipt in classic_terminal_pipeline_authority(bundle, target_id=target_id)
    )
    output = candidate
    witnesses: list[InterventionWitness] = []
    dispatcher = ClassicFamilyDispatcher()
    for intervention in interventions:
        constraints = matching_candidate_constraints(
            intervention, receipts
        ).materialize()
        result = dispatcher.dispatch_project(
            intervention,
            output,
            candidate_constraints=constraints,
        )
        output = result.output
        witnesses.append(
            InterventionWitness(
                intervention.id,
                target_id,
                result.evidence_digest,
                semantic_proof=result.semantic_proof,
                semantic_input_statement=result.semantic_input_statement,
                semantic_output_statement=result.semantic_output_statement,
            )
        )
    return ClassicTerminalComposition(output, tuple(witnesses))


def classic_rdata_repack(
    bundle: ProjectBundle,
    *,
    target_id: str,
    object_path: str,
    candidate: bytes,
) -> tuple[ClassicCandidate, InterventionWitness] | None:
    """Apply the one pre-link object repack declared for an exact object seat."""

    authority = classic_rdata_repack_authority(
        bundle,
        target_id=target_id,
        object_path=object_path,
    )
    if authority is None:
        return None
    intervention, _receipt, values = authority
    result = ClassicFamilyDispatcher().dispatch_project(
        intervention,
        candidate,
        candidate_constraints=values,
    )
    return result, InterventionWitness(
        intervention.id,
        target_id,
        result.evidence_digest,
        semantic_proof=result.semantic_proof,
        semantic_input_statement=result.semantic_input_statement,
        semantic_output_statement=result.semantic_output_statement,
    )


__all__ = [
    "ClassicPreparedDonor",
    "ClassicPreparedUnit",
    "ClassicTerminalComposition",
    "ClassicUnitComposition",
    "apply_classic_terminal_pipeline",
    "classic_compiler_translation_unit_authority",
    "classic_rdata_repack",
    "classic_rdata_repack_authority",
    "classic_rdata_repack_graph_authority",
    "classic_terminal_pipeline_authority",
    "compose_classic_unit",
    "prepare_classic_units",
]
