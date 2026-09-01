"""Project-overlay semantic ancestry proofs for classic source overlays.

Source rendering is not a semantic proof.  This module admits an overlay only
when current-run evidence establishes a closed source theorem, compiler-input
congruence, and a strict COFF/link projection for every effective primary
input.  Donor-only renderings remain private.  Generated intervention units
are closed section by section: duplicate COMDATs must lose by proven LINK
order, unique COMDATs must be dead under /OPT:REF, and the one intentional
constant-pool data shape is sealed byte for byte.

The validator is intentionally conservative.  Unknown COFF constructs and
incomplete link closures are errors, never best-effort evidence.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from reprobit.classic.coff_evidence import (
    _CoffObject,
)
from reprobit.classic.coff_projection import _CrtPullLinkerDependency, _OrderedArchiveSeedDependency
from reprobit.classic.compiler_epoch import (
    _compiler_namespace_member_wire,
    _compiler_namespace_toolchain_readers,
    _project_compiler_audit_trace,
)
from reprobit.classic.linker_identity import (
    issue_msvc420_linker_identity,
)
from reprobit.classic.semantic_contracts import (
    SOURCE_OVERLAY_OBLIGATIONS,
    SOURCE_OVERLAY_VALIDATOR_DIGEST,
    SOURCE_OVERLAY_VALIDATOR_ID,
    CleanSourceInput,
    CompilerProduct,
    DonorSemanticLane,
    EffectiveOverlayReceipt,
    OverlaySemanticSnapshot,
    OverlaySemanticValidation,
    PrimarySourceOrigin,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
    SemanticValidatorContract,
    SourceInputReceipt,
    TargetLinkClosure,
    _donor_input_is_authorized,
    _issue_semantic_proof,
    _statement_named_digest,
    _statement_payload_digest,
    semantic_proof_matches,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import (
    _ancestor_compilers,
    _clean_source_authority,
    _compiler_epoch_wire,
    _compiler_semantic_sources,
    _compiler_shape,
    _graph_archives,
    _overlay_declaration,
    _overlay_interventions,
    _OverlaySourceValidation,
    _unique,
    _validate_project_overlay_sources,
)
from reprobit.classic.source_overlay_claims import _relative
from reprobit.model import Digest, SemanticProof
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    linker_input_sequence,
    producer_graph_digest,
    toolchain_document_digest,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ProjectBundle,
)
from reprobit.strict_json import canonical_json

from .project_overlay_archives import _overlay_lane_input_is_authorized, _OverlayOutputOwner
from .project_overlay_carriers import _carrier_isolation_trace
from .project_overlay_helpers import _helper_isolation_trace


def overlay_semantic_run_binding(
    graph: ProducerGraphDocument, snapshot: OverlaySemanticSnapshot
) -> Digest:
    """Recompute the executor's immutable semantic-snapshot binding.

    This is ancestry integrity, not a logic theorem: it prevents a caller from
    swapping an OBJ, source epoch, or archive after the current-run receipts
    were sealed.  Logic equivalence is established separately by the source
    and COFF theorems.
    """

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "producer_graph": producer_graph_digest(graph).model_dump(mode="json"),
                "primary_sources": [
                    {
                        "path": item.path,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                        "origin": item.origin.value,
                    }
                    for item in snapshot.primary_sources
                ],
                "compiler_products": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                        "generated_inputs": list(item.generated_inputs),
                        "compiler_invocation": (
                            _compiler_epoch_wire(item.compiler_invocation)
                            if item.compiler_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.compiler_products
                ],
                "project_source_pairs": [
                    {
                        "path": item.path,
                        "clean_digest": (
                            Digest.from_bytes(item.clean_payload).model_dump(mode="json")
                            if item.clean_payload is not None
                            else None
                        ),
                        "clean_size": (
                            len(item.clean_payload) if item.clean_payload is not None else None
                        ),
                        "effective_digest": Digest.from_bytes(item.effective_payload).model_dump(
                            mode="json"
                        ),
                        "effective_size": len(item.effective_payload),
                    }
                    for item in snapshot.project_source_pairs
                ],
                "counterfactual_compiler_audits": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.counterfactual_payload).model_dump(
                            mode="json"
                        ),
                        "size": len(item.counterfactual_payload),
                        "counterfactual_invocation": (
                            _compiler_epoch_wire(item.counterfactual_invocation)
                            if item.counterfactual_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.counterfactual_compiler_audits
                ],
                "counterfactual_namespace_id": snapshot.counterfactual_namespace_id,
                "clean_source_inputs": [
                    {
                        "path": item.path,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                    }
                    for item in snapshot.clean_source_inputs
                ],
                "compiler_namespaces": [
                    {
                        "namespace_id": item.namespace_id,
                        "namespace_digest": item.namespace_digest.model_dump(mode="json"),
                        "input_evidence_kind": item.input_evidence_kind.value,
                        "members": [
                            _compiler_namespace_member_wire(member) for member in item.members
                        ],
                    }
                    for item in snapshot.compiler_namespaces
                ],
                "archives": [
                    {
                        "target": closure.target_id,
                        "values": [
                            {
                                "reference": archive.archive_ref,
                                "digest": Digest.from_bytes(archive.payload).model_dump(
                                    mode="json"
                                ),
                                "size": len(archive.payload),
                            }
                            for archive in closure.archives
                        ],
                    }
                    for closure in snapshot.link_closures
                ],
            }
        )
    )


def prove_source_overlay_semantics(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    snapshot: OverlaySemanticSnapshot,
    *,
    semantic_contracts: Mapping[ClassicRecipeFamily, SemanticValidatorContract],
) -> OverlaySemanticValidation:
    """Prove every source-overlay intervention in one current-run snapshot.

    This function performs no I/O.  The classic executor must build the
    snapshot from immutable bytes while the private logical-path runtime is
    still sealed.
    """

    if graph.toolchain_lock_digest != toolchain_document_digest(bundle.toolchain_lock):
        raise ClassicSemanticError("producer graph differs from the locked toolchain identity")
    if snapshot.run_binding != overlay_semantic_run_binding(graph, snapshot):
        raise ClassicSemanticError("semantic snapshot differs from its run binding")

    overlays = _overlay_interventions(bundle)
    if not overlays:
        return OverlaySemanticValidation(MappingProxyType({}), MappingProxyType({}))
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicSemanticError("source-overlay proof requires a complete source manifest")

    primary = _unique(snapshot.primary_sources, lambda item: item.path, "primary source")
    effective = _unique(snapshot.effective_outputs, lambda item: item.path, "effective output")
    products = _unique(snapshot.compiler_products, lambda item: item.node_id, "compiler product")
    closures = _unique(snapshot.link_closures, lambda item: item.target_id, "link closure")
    source_pairs = _unique(
        snapshot.project_source_pairs, lambda item: item.path, "project overlay source pair"
    )
    counterfactual_audits = _unique(
        snapshot.counterfactual_compiler_audits,
        lambda item: item.node_id,
        "declaration-counterfactual compiler audit",
    )
    manifest_by_path = {item.path.casefold(): item for item in manifest.entries}
    interventions = {item.id: item for item in bundle.interventions}
    certified_primary = any(
        item.origin is PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
        for item in snapshot.primary_sources
    )
    certified_evidence = bool(
        snapshot.project_source_pairs
        or snapshot.counterfactual_compiler_audits
        or snapshot.counterfactual_namespace_id is not None
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    )
    if certified_primary != certified_evidence:
        raise ClassicSemanticError(
            "certified project-overlay origin and counterfactual evidence must appear together"
        )
    if certified_primary:
        if (
            not isinstance(snapshot.counterfactual_namespace_id, str)
            or not snapshot.counterfactual_namespace_id
        ):
            raise ClassicSemanticError(
                "certified project overlay lacks its counterfactual namespace identity"
            )
    elif snapshot.counterfactual_namespace_id is not None:
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot name a counterfactual namespace"
        )

    graph_compilers = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    if set(products) != {item.casefold() for item in graph_compilers}:
        raise ClassicSemanticError("compiler products do not exactly cover the producer graph")
    for raw_product in products.values():
        product = raw_product
        if not isinstance(product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        source_ref, object_ref = _compiler_shape(graph_compilers[product.node_id])
        if product.source_ref != source_ref or product.object_ref != object_ref:
            raise ClassicSemanticError(
                f"compiler product {product.node_id!r} differs from committed graph paths"
            )
        if not product.payload:
            raise ClassicSemanticError(f"compiler product {product.node_id!r} is empty")

    all_output_paths: set[str] = set()
    all_generated_paths: set[str] = set()
    all_generated_inputs: set[str] = set()
    carrier_input_seals: dict[str, tuple[str, ...]] = {}
    output_owner: dict[str, _OverlayOutputOwner] = {}
    declaration_by_id: dict[
        str,
        tuple[
            dict[str, dict[str, object]],
            frozenset[str],
            frozenset[str],
        ],
    ] = {}
    for overlay in overlays:
        overlay_declaration = _overlay_declaration(overlay)
        declaration_by_id[overlay.id] = overlay_declaration
        paths, generated, generated_inputs = overlay_declaration
        overlap = {item.casefold() for item in paths} & {
            item.casefold() for item in all_output_paths
        }
        if overlap:
            raise ClassicSemanticError(f"overlay outputs overlap: {sorted(overlap)}")
        all_output_paths.update(paths)
        all_generated_paths.update(generated)
        all_generated_inputs.update(generated_inputs)
        generated_seal = tuple(sorted(generated_inputs, key=str.casefold))
        for carrier_path in generated:
            carrier_input_seals[carrier_path.casefold()] = generated_seal
        output_owner.update(
            {
                path.casefold(): _OverlayOutputOwner(
                    overlay.id,
                    overlay.scope.target,
                    path in generated_inputs,
                )
                for path in paths
            }
        )

    clean_sources: dict[str, CleanSourceInput] = {}
    semantic_clean_sources: dict[str, CleanSourceInput] = {}
    source_validation: _OverlaySourceValidation | None = None
    if certified_primary:
        if set(source_pairs) != {path.casefold() for path in all_output_paths}:
            missing = sorted({path.casefold() for path in all_output_paths} - set(source_pairs))
            extra = sorted(set(source_pairs) - {path.casefold() for path in all_output_paths})
            raise ClassicSemanticError(
                f"project overlay source-pair universe differs; missing={missing}, extra={extra}"
            )
        clean_sources = _clean_source_authority(bundle, snapshot)
        semantic_clean_sources = _compiler_semantic_sources(clean_sources)
        for overlay in overlays:
            outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
            for path, declaration in outputs.items():
                raw_pair = source_pairs[path.casefold()]
                if not isinstance(raw_pair, ProjectOverlaySourcePair) or raw_pair.path != path:
                    raise ClassicSemanticError(f"project overlay source pair changed: {path!r}")
                if (
                    Digest.from_bytes(raw_pair.effective_payload).value != declaration["effective"]
                    or len(raw_pair.effective_payload) != declaration["size"]
                ):
                    raise ClassicSemanticError(
                        f"project overlay effective source changed: {path!r}"
                    )
                if path in generated_inputs:
                    if raw_pair.clean_payload is not None:
                        raise ClassicSemanticError(
                            f"generated overlay source has a clean preimage: {path!r}"
                        )
                else:
                    clean = clean_sources.get(path.casefold())
                    if (
                        clean is None
                        or raw_pair.clean_payload != clean.payload
                        or declaration.get("clean") != Digest.from_bytes(clean.payload).value
                    ):
                        raise ClassicSemanticError(
                            f"project overlay clean preimage changed: {path!r}"
                        )
        source_validation = _validate_project_overlay_sources(
            overlays=overlays,
            graph=graph,
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=semantic_clean_sources,
            declaration_by_id=declaration_by_id,
            secondary_reader_payloads=_compiler_namespace_toolchain_readers(
                bundle, snapshot.compiler_namespaces
            ),
        )
    elif (
        source_pairs
        or counterfactual_audits
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    ):
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot carry project-overlay epoch evidence"
        )

    expected_primary = set(manifest_by_path) | {item.casefold() for item in all_generated_inputs}
    if set(primary) != expected_primary:
        missing = sorted(expected_primary - set(primary))
        extra = sorted(set(primary) - expected_primary)
        raise ClassicSemanticError(
            f"primary source seat is not closed; missing={missing}, extra={extra}"
        )
    if set(effective) != {item.casefold() for item in all_output_paths}:
        raise ClassicSemanticError("effective output receipts do not exactly cover overlays")

    for folded, raw_receipt in primary.items():
        receipt = raw_receipt
        if not isinstance(receipt, SourceInputReceipt):
            raise AssertionError("primary source index has an invalid value")
        _relative(receipt.path, label="primary source path")
        if receipt.size < 0:
            raise ClassicSemanticError(f"primary source {receipt.path!r} has invalid size")
        manifest_entry = manifest_by_path.get(folded)
        declared_output = next(
            (
                declaration
                for outputs, _generated, _inputs in declaration_by_id.values()
                for path, declaration in outputs.items()
                if path.casefold() == folded
            ),
            None,
        )
        if manifest_entry is not None:
            if certified_primary and declared_output is not None:
                if (
                    receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    or receipt.digest.value != declared_output["effective"]
                    or receipt.size != declared_output["size"]
                ):
                    raise ClassicSemanticError(
                        f"primary source {receipt.path!r} is not a certified project overlay"
                    )
            elif receipt.origin is not PrimarySourceOrigin.CLEAN_MANIFEST or (
                receipt.digest != manifest_entry.digest or receipt.size != manifest_entry.size
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not the clean manifest input"
                )
        elif receipt.path in all_generated_paths:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier TU"
                )
        elif certified_primary and receipt.path in all_generated_inputs:
            if (
                receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                or not isinstance(declared_output, dict)
                or receipt.digest.value != declared_output["effective"]
                or receipt.size != declared_output["size"]
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a certified generated header"
                )
        elif receipt.path in all_generated_inputs:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier input"
                )
        else:
            raise ClassicSemanticError(
                f"primary source {receipt.path!r} is an unclassified effective input"
            )

    for overlay in overlays:
        outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
        for path, output_declaration in outputs.items():
            effective_receipt = effective[path.casefold()]
            if (
                effective_receipt.digest.value != output_declaration["effective"]
                or effective_receipt.size != output_declaration["size"]
            ):
                raise ClassicSemanticError(f"effective overlay output changed: {path!r}")
            clean_value = output_declaration.get("clean")
            manifest_entry = manifest_by_path.get(path.casefold())
            if path in generated_inputs:
                primary_receipt = primary[path.casefold()]
                if not isinstance(primary_receipt, SourceInputReceipt):
                    raise AssertionError("carrier source index has an invalid value")
                expected_origin = (
                    PrimarySourceOrigin.GENERATED_CARRIER
                    if path in all_generated_paths
                    else PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    if certified_primary
                    else PrimarySourceOrigin.GENERATED_CARRIER
                )
                if (
                    primary_receipt.origin is not expected_origin
                    or primary_receipt.digest != effective_receipt.digest
                    or primary_receipt.size != effective_receipt.size
                ):
                    raise ClassicSemanticError(f"generated carrier changed: {path!r}")
            elif manifest_entry is None or clean_value != manifest_entry.digest.value:
                raise ClassicSemanticError(
                    f"ordinary overlay {path!r} lacks its exact clean manifest preimage"
                )

    compiler_by_source: dict[str, list[CompilerProduct]] = defaultdict(list)
    for raw_product in products.values():
        if not isinstance(raw_product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        kind, relative = raw_product.source_ref.split("/", 1)
        if kind != "source":
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} reads a non-source primary input"
            )
        source_receipt = primary.get(relative.casefold())
        if source_receipt is None:
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} source is absent from primary seal"
            )
        normalized_generated_inputs = tuple(
            _relative(item, label="compiler generated-input path")
            for item in raw_product.generated_inputs
        )
        if normalized_generated_inputs != tuple(
            sorted(set(normalized_generated_inputs), key=str.casefold)
        ):
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} generated-input seal is not canonical"
            )
        expected_generated_inputs = carrier_input_seals.get(relative.casefold())
        if expected_generated_inputs is None:
            expected_generated_inputs = (
                tuple(sorted(source_validation.generated_headers, key=str.casefold))
                if source_validation is not None
                else ()
            )
        if normalized_generated_inputs != expected_generated_inputs:
            if relative.casefold() in carrier_input_seals:
                raise ClassicSemanticError(
                    f"carrier compiler {raw_product.node_id!r} lacks its exact generated epoch"
                )
            raise ClassicSemanticError(
                f"ordinary compiler {raw_product.node_id!r} has the wrong generated-header epoch"
            )
        compiler_by_source[relative.casefold()].append(raw_product)

    counterfactual_objects: dict[str, _CoffObject] = {}
    effective_objects: dict[str, _CoffObject] = {}
    helper_sections: dict[str, frozenset[int]] = {}
    crt_pull_dependencies: dict[str, tuple[_CrtPullLinkerDependency, ...]] = {}
    ordered_archive_seed_dependencies: dict[str, tuple[_OrderedArchiveSeedDependency, ...]] = {}
    compiler_audit_trace: list[dict[str, object]] = []
    compiler_namespace_trace: list[dict[str, object]] = []
    if source_validation is not None:
        (
            counterfactual_objects,
            effective_objects,
            helper_sections,
            crt_pull_dependencies,
            ordered_archive_seed_dependencies,
            compiler_audit_trace,
            compiler_namespace_trace,
        ) = _project_compiler_audit_trace(
            bundle=bundle,
            graph=graph,
            products={
                value.node_id.casefold(): value
                for value in products.values()
                if isinstance(value, CompilerProduct)
            },
            audits={
                value.node_id.casefold(): value
                for value in counterfactual_audits.values()
                if isinstance(value, ProjectOverlayCounterfactualAudit)
            },
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=clean_sources,
            generated_tus=frozenset(all_generated_paths),
            source_validation=source_validation,
            namespace_evidences=snapshot.compiler_namespaces,
            counterfactual_namespace_id=(
                snapshot.counterfactual_namespace_id
                if isinstance(snapshot.counterfactual_namespace_id, str)
                else ""
            ),
        )

    lanes_by_overlay: dict[
        str,
        list[tuple[DonorSemanticLane, tuple[EffectiveOverlayReceipt, ...]]],
    ] = defaultdict(list)
    for lane in snapshot.donor_lanes:
        if (
            tuple(
                sorted(
                    lane.overlay_inputs,
                    key=lambda item: (item.path.casefold(), item.digest.value),
                )
            )
            != lane.overlay_inputs
        ):
            raise ClassicSemanticError(
                f"donor lane {lane.donor_intervention_id!r} inputs are not canonical"
            )
        donor = interventions.get(lane.donor_intervention_id)
        consumer = interventions.get(lane.consumer_intervention_id)
        if not isinstance(donor, ClassicRecipeIntervention) or (
            donor.role is not ClassicRecipeRole.DONOR
        ):
            raise ClassicSemanticError(
                f"donor lane names invalid intervention {lane.donor_intervention_id!r}"
            )
        if not isinstance(consumer, ClassicRecipeIntervention) or (
            consumer.role is not ClassicRecipeRole.FUNCTION
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {lane.consumer_intervention_id!r} is invalid"
            )
        if donor.scope.target != lane.target_id or consumer.scope.target != lane.target_id:
            raise ClassicSemanticError("donor lane crosses target boundaries")
        raw_statement_consumer = lane.consumer_input_statement.get("intervention")
        if not isinstance(raw_statement_consumer, Mapping):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} statement omits its intervention"
            )
        try:
            statement_consumer = ClassicRecipeIntervention.model_validate_json(
                canonical_json(raw_statement_consumer)
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} intervention is malformed"
            ) from exc
        if statement_consumer != consumer or not _donor_input_is_authorized(
            donor,
            consumer,
            lane.consumer_input_statement,
            input_name=lane.input_name,
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} uses an unauthorized candidate input"
            )
        contract = semantic_contracts.get(consumer.family)
        if contract is None or not semantic_proof_matches(
            lane.semantic_proof, consumer.family, contract
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} lacks a registered semantic proof"
            )
        expected_input = Digest.from_bytes(canonical_json(lane.consumer_input_statement))
        expected_output = Digest.from_bytes(canonical_json(lane.consumer_output_statement))
        if lane.semantic_proof.input_statement_digest != expected_input or (
            lane.semantic_proof.output_statement_digest != expected_output
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} proof statements changed"
            )
        if (
            _statement_payload_digest(
                lane.consumer_input_statement,
                name=lane.input_name,
            )
            != lane.donor_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} is not bound to its donor object"
            )
        if (
            _statement_named_digest(lane.consumer_input_statement, "seed", "digest")
            != lane.seed_object_digest
            or _statement_named_digest(lane.consumer_output_statement, "candidate", "digest")
            != lane.candidate_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} object lineage changed"
            )
        inputs_by_overlay: dict[str, list[EffectiveOverlayReceipt]] = defaultdict(list)
        for item in lane.overlay_inputs:
            lane_receipt = effective.get(item.path.casefold())
            if lane_receipt != item:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} names an unsealed overlay input {item.path!r}"
                )
            owner = output_owner.get(item.path.casefold())
            if owner is None:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} names an ownerless overlay input {item.path!r}"
                )
            if not _overlay_lane_input_is_authorized(
                owner,
                lane.target_id,
                certified_project_overlay=source_validation is not None,
            ):
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} consumes a cross-target "
                    "generated or uncertified overlay"
                )
            inputs_by_overlay[owner.intervention_id].append(item)
        for overlay_id, owned_inputs in inputs_by_overlay.items():
            lanes_by_overlay[overlay_id].append((lane, tuple(owned_inputs)))

    overlay_traces: dict[str, object] = {}
    proofs: dict[str, SemanticProof] = {}
    source_contract = _SourceOverlayContract()
    graph_linkers: dict[str, ProducerNode] = {
        node.target_id.casefold(): node
        for node in graph.nodes
        if node.role is ProducerRole.LINKER and node.target_id is not None
    }
    for overlay in overlays:
        outputs, generated, generated_inputs = declaration_by_id[overlay.id]
        closure_value = closures.get(overlay.scope.target.casefold())
        if not isinstance(closure_value, TargetLinkClosure):
            raise ClassicSemanticError(
                f"overlay target {overlay.scope.target!r} lacks a complete link closure"
            )
        graph_compiler_ids = _ancestor_compilers(graph, overlay.scope.target)
        if closure_value.compiler_node_ids != tuple(sorted(graph_compiler_ids, key=str.casefold)):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} compiler closure differs from graph"
            )
        if closure_value.archive_refs != _graph_archives(graph, overlay.scope.target):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} archive closure differs from graph"
            )
        terminal_linker = graph_linkers.get(overlay.scope.target.casefold())
        if terminal_linker is None:
            raise ClassicSemanticError(
                f"overlay target {overlay.scope.target!r} lacks its terminal linker"
            )
        carrier_node_ids: set[str] = set()
        carrier_generator_kinds: dict[str, tuple[str, ...]] = {}
        for path in generated:
            candidates = compiler_by_source.get(path.casefold(), [])
            if len(candidates) != 1:
                raise ClassicSemanticError(
                    f"generated carrier {path!r} has {len(candidates)} compiler products"
                )
            node_id = candidates[0].node_id
            carrier_node_ids.add(node_id)
            declaration = outputs[path]
            operations = declaration.get("ops")
            if not isinstance(operations, list):
                raise ClassicSemanticError(f"generated carrier {path!r} omits its operations")
            generator_kinds: list[str] = []
            for operation in operations:
                generator = operation.get("gen") if isinstance(operation, dict) else None
                generator_kind = generator.get("k") if isinstance(generator, dict) else None
                if not isinstance(generator_kind, str) or not generator_kind:
                    raise ClassicSemanticError(
                        f"generated carrier {path!r} has an unclassified generator"
                    )
                generator_kinds.append(generator_kind)
            carrier_generator_kinds[node_id] = tuple(generator_kinds)
        carrier_trace = _carrier_isolation_trace(
            target=closure_value,
            linker_arguments=terminal_linker.arguments,
            linker_inputs=linker_input_sequence(terminal_linker),
            linker_identity=issue_msvc420_linker_identity(bundle.toolchain_lock),
            products={
                key: value for key, value in products.items() if isinstance(value, CompilerProduct)
            },
            carrier_node_ids=frozenset(carrier_node_ids),
            carrier_generator_kinds=carrier_generator_kinds,
        )
        helper_trace = (
            _helper_isolation_trace(
                target=closure_value,
                linker_inputs=linker_input_sequence(terminal_linker),
                products={
                    value.node_id: value
                    for value in products.values()
                    if isinstance(value, CompilerProduct)
                },
                counterfactual_objects=counterfactual_objects,
                effective_objects=effective_objects,
                helper_sections=helper_sections,
                crt_pull_dependencies=crt_pull_dependencies,
                ordered_archive_seed_dependencies=ordered_archive_seed_dependencies,
            )
            if source_validation is not None
            else {
                "target": overlay.scope.target,
                "helper_objects": [],
                "unique_unreferenced_definitions": [],
                "crt_pull_archive_provider_candidates": [],
                "ordered_archive_seed_dependencies": [],
            }
        )
        lanes = sorted(
            lanes_by_overlay.get(overlay.id, []),
            key=lambda item: (
                item[0].target_id.casefold(),
                item[0].donor_intervention_id,
                item[0].consumer_intervention_id,
                item[0].input_name,
            ),
        )
        ordinary = set(outputs) - set(generated_inputs)
        used = {
            item.path
            for _lane, owned_inputs in lanes
            for item in owned_inputs
            if item.path in ordinary
        }
        # Ordinary outputs that do not enter any donor lane are harmlessly
        # discarded: the exact primary seat check above proves their effective
        # bytes are absent from every primary compiler input.
        discarded = [] if certified_primary else sorted(ordinary - used)
        trace = {
            "schema": 1,
            "run_binding": snapshot.run_binding.model_dump(mode="json"),
            "overlay_intervention": overlay.model_dump(mode="json"),
            "producer_graph_digest": producer_graph_digest(graph).model_dump(mode="json"),
            "primary_source_seal": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "origin": item.origin.value,
                }
                for item in sorted(snapshot.primary_sources, key=lambda item: item.path.casefold())
            ],
            "effective_outputs": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "disposition": (
                        "generated-carrier-tu"
                        if item.path in generated
                        else "certified-project-primary"
                        if certified_primary
                        else "generated-carrier-input"
                        if item.path in generated_inputs
                        else "certified-donor"
                        if item.path in used
                        else "discarded"
                    ),
                }
                for item in sorted(
                    (
                        value
                        for key, value in effective.items()
                        if key in {path.casefold() for path in outputs}
                        and isinstance(value, EffectiveOverlayReceipt)
                    ),
                    key=lambda item: item.path.casefold(),
                )
            ],
            "carrier_compile_epoch": {
                "generated_inputs": sorted(generated_inputs, key=str.casefold),
                "carrier_compilers": sorted(carrier_node_ids, key=str.casefold),
                "ordinary_generated_inputs": (
                    sorted(source_validation.generated_headers, key=str.casefold)
                    if source_validation is not None
                    else []
                ),
            },
            "project_overlay_epoch": {
                "enabled": source_validation is not None,
                "compiler_namespaces": compiler_namespace_trace,
                "compiler_audits": compiler_audit_trace,
                "source_validation": (
                    source_validation.traces.get(overlay.id)
                    if source_validation is not None
                    else None
                ),
            },
            "donor_lanes": [
                {
                    "target": lane.target_id,
                    "donor": lane.donor_intervention_id,
                    "consumer": lane.consumer_intervention_id,
                    "input_name": lane.input_name,
                    "overlay_inputs": [
                        {
                            "path": item.path,
                            "digest": item.digest.model_dump(mode="json"),
                            "size": item.size,
                        }
                        for item in owned_inputs
                    ],
                    "consumer_proof": lane.semantic_proof.evidence_digest.value,
                    "input_statement": lane.semantic_proof.input_statement_digest.value,
                }
                for lane, owned_inputs in lanes
            ],
            "discarded_outputs": discarded,
            "carrier_isolation": carrier_trace,
            "project_helper_isolation": helper_trace,
        }
        input_statement = {
            "schema": 1,
            "intervention": overlay.model_dump(mode="json"),
            "clean_manifest": {
                item.path: item.digest.model_dump(mode="json") for item in manifest.entries
            },
            "effective_outputs": {
                path: {
                    "digest": declaration["effective"],
                    "size": declaration["size"],
                }
                for path, declaration in outputs.items()
            },
        }
        proof = _issue_semantic_proof(
            family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
            contract=source_contract,
            input_statement=input_statement,
            output_statement=trace,
        )
        proofs[overlay.id] = proof
        overlay_traces[overlay.id] = trace
    return OverlaySemanticValidation(MappingProxyType(proofs), MappingProxyType(overlay_traces))


@dataclass(frozen=True, slots=True)
class _SourceOverlayContract:
    validator_id: str = SOURCE_OVERLAY_VALIDATOR_ID
    validator_digest: Digest = SOURCE_OVERLAY_VALIDATOR_DIGEST
    obligations: tuple[str, ...] = SOURCE_OVERLAY_OBLIGATIONS


__all__ = [
    "overlay_semantic_run_binding",
    "prove_source_overlay_semantics",
]
