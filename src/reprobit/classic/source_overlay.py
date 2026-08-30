"""Source-level overlay claims and deterministic compiler-epoch planning."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import TypeVar

from reprobit.classic.link_topology import (
    ClassicLinkTopologyError,
    terminal_link_input_topology,
)
from reprobit.classic.overlay_declarations import (
    _DECLARATION_GENERATORS,
    _declaration_odr_analysis,
    _DeclarationFact,
    _odr_conflict_summary,
)
from reprobit.classic.overlay_types import ClassicOverlayOutputReceipt
from reprobit.classic.semantic_contracts import (
    CleanSourceInput,
    CompilerEpochInvocation,
    OverlaySemanticSnapshot,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlaySourcePair,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay_claims import (
    _CPP_SOURCE_SUFFIXES,
    _FUNCTION_CLAIM_GENERATORS,
    _HEADER_SUFFIXES,
    _SOURCE_SUFFIXES,
    _UNREACHABLE_HELPER_GENERATORS,
    _claim_key,
    _parse_semantic_claims,
    _preprocessor_mutations,
    _relative,
    _require_declaration_seat,
    _reserved_cpp_identifier,
    _sparse_source_reader_fallbacks,
    _token_texts,
    _validate_declaration_leaf,
    _validate_function_leaf,
    _validate_include_leaf,
    _validate_unreachable_helper_leaf,
)
from reprobit.classic_overlay_document import (
    render_classic_overlay,
    render_classic_overlay_leaf_subset,
)
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import ClassicRecipeFamily, ClassicRecipeIntervention, ProjectBundle
from reprobit.toolchains import ToolchainError
from reprobit.toolchains import profile as toolchain_profile

_OBJECT_SUFFIXES = frozenset({".obj", ".o"})

_Item = TypeVar("_Item")


def _unique(items: Sequence[_Item], key: Callable[[_Item], str], label: str) -> dict[str, _Item]:
    result: dict[str, _Item] = {}
    for item in items:
        item_key = str(key(item)).casefold()
        if item_key in result:
            raise ClassicSemanticError(f"{label} repeats {key(item)!r}")
        result[item_key] = item
    return result


def _compiler_epoch_wire(value: CompilerEpochInvocation) -> dict[str, object]:
    return {
        "input_evidence_kind": value.input_evidence_kind.value,
        "tool_id": value.tool_id,
        "tool_digest": value.tool_digest.model_dump(mode="json"),
        "arguments": list(value.arguments),
        "working_directory": value.working_directory,
        "environment_digest": value.environment_digest.model_dump(mode="json"),
        "path_profile_digest": value.path_profile_digest.model_dump(mode="json"),
        "invocation_digest": value.invocation_digest.model_dump(mode="json"),
        "namespace_id": value.namespace_id,
        "namespace_digest": value.namespace_digest.model_dump(mode="json"),
        "namespace_count": value.namespace_count,
    }


def _overlay_interventions(
    bundle: ProjectBundle,
) -> tuple[ClassicRecipeIntervention, ...]:
    return tuple(
        item
        for item in bundle.interventions
        if isinstance(item, ClassicRecipeIntervention)
        and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
    )


def _overlay_declaration(
    intervention: ClassicRecipeIntervention,
) -> tuple[
    dict[str, dict[str, object]],
    frozenset[str],
    frozenset[str],
]:
    values = {item.name: item.value for item in intervention.parameters}
    if (
        set(values)
        not in (
            {"graph", "outputs", "schema"},
            {"graph", "outputs", "schema", "semantic_claims"},
        )
        or values["schema"] != 2
    ):
        raise ClassicSemanticError(f"overlay {intervention.id!r} declaration is not closed")
    graph = values["graph"]
    outputs = values["outputs"]
    if not isinstance(graph, dict) or set(graph) != {"generated_tus", "link_admissions"}:
        raise ClassicSemanticError(f"overlay {intervention.id!r} graph is malformed")
    if graph["link_admissions"] != [] or not isinstance(graph["generated_tus"], list):
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} has unsupported direct link admissions"
        )
    generated: set[str] = set()
    for item in graph["generated_tus"]:
        path_value = item.get("path") if isinstance(item, dict) else None
        if not isinstance(path_value, str):
            raise ClassicSemanticError(f"overlay {intervention.id!r} carrier is malformed")
        generated.add(_relative(path_value, label="generated carrier path"))
    if not isinstance(outputs, list):
        raise ClassicSemanticError(f"overlay {intervention.id!r} outputs are malformed")
    result: dict[str, dict[str, object]] = {}
    for item in outputs:
        if not isinstance(item, dict):
            raise ClassicSemanticError(f"overlay {intervention.id!r} output is malformed")
        path_value = item.get("path")
        if not isinstance(path_value, str):
            raise ClassicSemanticError(f"overlay {intervention.id!r} output is malformed")
        path = _relative(path_value, label="overlay output path")
        if path.casefold() in {key.casefold() for key in result}:
            raise ClassicSemanticError(f"overlay {intervention.id!r} repeats {path!r}")
        effective = item.get("effective")
        size = item.get("size")
        if not isinstance(effective, str) or re.fullmatch(r"[0-9a-f]{64}", effective) is None:
            raise ClassicSemanticError(f"overlay {intervention.id!r} has an invalid digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ClassicSemanticError(f"overlay {intervention.id!r} has an invalid size")
        result[path] = {str(key): value for key, value in item.items()}
    generated_inputs = {path for path, declaration in result.items() if "clean" not in declaration}
    if generated_inputs and not generated:
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} generated inputs have no carrier TU"
        )
    if not generated.issubset(generated_inputs):
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} carrier TUs are not generated outputs"
        )
    for path in generated_inputs:
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix in _SOURCE_SUFFIXES:
            if path not in generated:
                raise ClassicSemanticError(
                    f"overlay {intervention.id!r} generated source is not a carrier TU: {path!r}"
                )
        elif suffix not in _HEADER_SUFFIXES:
            raise ClassicSemanticError(
                f"overlay {intervention.id!r} has unsupported generated input {path!r}"
            )
    return result, frozenset(generated), frozenset(generated_inputs)


def _compiler_shape(node: ProducerNode) -> tuple[str, str]:
    source_refs = [
        item
        for item in node.inputs
        if PurePosixPath(item.split("/", 1)[-1]).suffix.casefold() in _SOURCE_SUFFIXES
    ]
    object_refs = [
        item
        for item in node.outputs
        if PurePosixPath(item.split("/", 1)[-1]).suffix.casefold() in _OBJECT_SUFFIXES
    ]
    if len(source_refs) != 1 or len(object_refs) != 1:
        raise ClassicSemanticError(
            f"compiler node {node.id!r} does not have one source and one object"
        )
    return source_refs[0], object_refs[0]


def _ancestor_compilers(graph: ProducerGraphDocument, target_id: str) -> frozenset[str]:
    try:
        topology = terminal_link_input_topology(graph, target_id)
    except ClassicLinkTopologyError as exc:
        raise ClassicSemanticError(str(exc)) from exc
    return frozenset(topology.compiler_node_ids)


def _graph_archives(graph: ProducerGraphDocument, target_id: str) -> tuple[str, ...]:
    try:
        return terminal_link_input_topology(graph, target_id).archive_refs
    except ClassicLinkTopologyError as exc:
        raise ClassicSemanticError(str(exc)) from exc


def _receipt_trace(receipt: ClassicOverlayOutputReceipt) -> dict[str, object]:
    return {
        "path": receipt.path,
        "input_digest": receipt.input_digest,
        "input_size": receipt.input_size,
        "output_digest": receipt.output_digest,
        "output_size": receipt.output_size,
        "operations": [
            {
                "operation_id": operation.operation_id,
                "action": operation.action,
                "fragment_digest": operation.fragment_digest,
                "fragment_size": operation.fragment_size,
                "removed_digest": operation.removed_digest,
                "removed_size": operation.removed_size,
                "anchors": [
                    {
                        "role": anchor.role,
                        "context_digest": anchor.context_digest,
                        "token_boundary": anchor.token_boundary,
                        "byte_offset": anchor.byte_offset,
                    }
                    for anchor in operation.anchors
                ],
            }
            for operation in receipt.operations
        ],
    }


def _overlay_source_trace(
    *,
    receipts: Sequence[ClassicOverlayOutputReceipt],
    operation_census: Mapping[str, int],
    semantic_claim_count: int,
    unused_typedefs: Sequence[dict[str, object]],
    extended_declaration_line_seats: set[tuple[str, str, str, str, bool]],
) -> dict[str, object]:
    """Build the canonical per-overlay source-language evidence trace."""

    return {
        "render_receipts": [
            _receipt_trace(item) for item in sorted(receipts, key=lambda item: item.path.casefold())
        ],
        "operation_census": dict(sorted(operation_census.items())),
        "semantic_claim_count": semantic_claim_count,
        "unused_typedefs": sorted(
            unused_typedefs,
            key=lambda item: (str(item["source_path"]).casefold(), str(item["identifier"])),
        ),
        "extended_global_declaration_line_seats": [
            {
                "theorem": (
                    "compiler-projected-global-declaration-line-seat-v1"
                    if projection_required
                    else "comment-separated-preprocessor-declaration-line-seat-v1"
                ),
                "source_path": path,
                "operation": operation,
                "generator": kind,
                "predecessor": predecessor,
                "runtime_projection_required": projection_required,
            }
            for path, operation, kind, predecessor, projection_required in sorted(
                extended_declaration_line_seats,
                key=lambda item: (
                    item[0].casefold(),
                    item[1].casefold(),
                    item[2],
                    item[3],
                    item[4],
                ),
            )
        ],
    }


_GENERATED_CARRIER_GENERATORS = frozenset(
    {"call_supplier", "const_pool", "reloc_ring", "template_supplier"}
)


@dataclass(frozen=True, slots=True)
class _OverlaySourceValidation:
    traces: Mapping[str, object]
    compiler_epoch_plan: ProjectOverlayCompilerEpochPlan
    generated_headers: frozenset[str]
    logical_headers: frozenset[str]
    unused_typedef_sources: frozenset[str]
    projection_sources: frozenset[str]
    projection_all: bool
    helper_identifiers: frozenset[str]
    helpers_by_source: Mapping[str, tuple[str, ...]]
    crt_pull_helpers_by_source: Mapping[str, tuple[str, ...]]
    ordered_archive_seed_helpers_by_source: Mapping[str, tuple[tuple[str, str], ...]]
    global_declaration_identifiers: frozenset[str]
    macro_sensitive_identifiers: frozenset[str]
    intrinsic_macro_mutations: frozenset[tuple[str, str, str]]


def _overlay_document(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    values = {item.name: item.value for item in intervention.parameters}
    return {
        "schema": values.get("schema"),
        "outputs": values.get("outputs"),
        "graph": values.get("graph"),
    }


def _generator_leaves(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, dict) or not isinstance(value.get("k"), str):
        raise ClassicSemanticError("source-overlay generator is malformed")
    normalized = {str(key): item for key, item in value.items()}
    if normalized["k"] != "seq":
        return (normalized,)
    raw_items = normalized.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ClassicSemanticError("source-overlay sequence is empty")
    result: list[dict[str, object]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            raise ClassicSemanticError("source-overlay sequence item is malformed")
        child = {str(key): item for key, item in raw_item.items() if key != "line"}
        result.extend(_generator_leaves(child))
    return tuple(result)


def _clean_source_authority(
    bundle: ProjectBundle,
    snapshot: OverlaySemanticSnapshot,
) -> dict[str, CleanSourceInput]:
    manifest = bundle.source_manifest
    if manifest is None:
        raise ClassicSemanticError("clean source authority has no manifest")
    inputs = _unique(snapshot.clean_source_inputs, lambda item: item.path, "clean source input")
    expected = {item.path.casefold(): item for item in manifest.entries}
    if set(inputs) != set(expected):
        missing = sorted(set(expected) - set(inputs))
        extra = sorted(set(inputs) - set(expected))
        raise ClassicSemanticError(
            f"clean source input census differs; missing={missing}, extra={extra}"
        )
    for folded, value in inputs.items():
        if not isinstance(value, CleanSourceInput) or type(value.payload) is not bytes:
            raise ClassicSemanticError("clean source input is not immutable bytes")
        entry = expected[folded]
        if (
            value.path != entry.path
            or len(value.payload) != entry.size
            or Digest.from_bytes(value.payload) != entry.digest
        ):
            raise ClassicSemanticError(f"clean source input changed: {value.path!r}")
    return {folded: value for folded, value in inputs.items()}


def _compiler_semantic_sources(
    clean_sources: Mapping[str, CleanSourceInput],
) -> dict[str, CleanSourceInput]:
    """Keep full source authority separate from C/C++ language analysis."""

    return {
        key: value
        for key, value in clean_sources.items()
        if PurePosixPath(value.path).suffix.casefold() in _CPP_SOURCE_SUFFIXES
    }


def _token_census(payloads: Iterable[bytes]) -> dict[str, int]:
    census: dict[str, int] = defaultdict(int)
    for payload in payloads:
        for token in _token_texts(payload):
            census[token] += 1
    return census


_LeafKey = tuple[str, str, int]
_RenderContext = tuple[dict[str, object], Mapping[str, bytes]]


def _validate_declaration_project_closure(
    *,
    declaration_facts: Mapping[str, Sequence[_DeclarationFact]],
    declaration_seat_failures: set[tuple[str, str, str, str]],
    declaration_origin_identifiers: set[str],
    token_census: Mapping[str, int],
    ordinary_effective_token_census: Mapping[str, int],
    declaration_fragment_token_census: Mapping[str, int],
) -> dict[str, object]:
    """Close project-wide ODR, seat, and fragment-origin obligations."""

    declaration_odr, odr_conflicts = _declaration_odr_analysis(declaration_facts)
    if declaration_seat_failures or odr_conflicts:
        blocked_paths = sorted(
            {path for path, _operation, _kind, _reason in declaration_seat_failures}
            | {
                str(conflict[key])
                for conflict in odr_conflicts
                for key in ("left_source", "right_source")
            },
            key=str.casefold,
        )
        seat_trace = [
            {
                "path": path,
                "operation": operation,
                "generator": kind,
                "reason": reason,
            }
            for path, operation, kind, reason in sorted(declaration_seat_failures)
        ]
        odr_summary = _odr_conflict_summary(odr_conflicts) if odr_conflicts else "none"
        raise ClassicSemanticError(
            "project overlay declaration theorem is quarantined; "
            f"blocked_paths={blocked_paths}, seat_failures={seat_trace}, "
            f"odr_conflicts={odr_summary}"
        )

    origin_failures = [
        {
            "identifier": identifier,
            "clean_occurrences": token_census.get(identifier, 0),
            "ordinary_effective_occurrences": ordinary_effective_token_census.get(identifier, 0),
            "declaration_fragment_occurrences": declaration_fragment_token_census.get(
                identifier, 0
            ),
        }
        for identifier in sorted(declaration_origin_identifiers)
        if token_census.get(identifier, 0) != 0
        or declaration_fragment_token_census.get(identifier, 0) == 0
        or ordinary_effective_token_census.get(identifier, 0)
        != declaration_fragment_token_census.get(identifier, 0)
    ]
    if origin_failures:
        raise ClassicSemanticError(
            "source-overlay declaration identifier escapes its closed fragment family: "
            f"{origin_failures}"
        )
    return declaration_odr


@dataclass(frozen=True, slots=True)
class _CounterfactualLeafClosure:
    selected_leaves: frozenset[_LeafKey]
    selected_generated_header_includes: frozenset[_LeafKey]
    projection_sources: frozenset[str]


def _close_counterfactual_leaves(
    *,
    declaration_identifier_leaves: Mapping[str, set[_LeafKey]],
    selected_leaves: set[_LeafKey],
    leaf_paths: Mapping[_LeafKey, str],
    generated_headers: frozenset[str],
    pending_generated_header_includes: Mapping[_LeafKey, str],
    projection_sources: set[str],
) -> _CounterfactualLeafClosure:
    """Close declaration families and same-overlay generated-header includes."""

    selected = set(selected_leaves)
    projections = set(projection_sources)
    changed = True
    while changed:
        changed = False
        for family_leaves in declaration_identifier_leaves.values():
            if family_leaves.issubset(selected):
                continue
            newly_blocked = family_leaves & selected
            if not newly_blocked:
                continue
            selected.difference_update(newly_blocked)
            projections.update(leaf_paths[key].casefold() for key in family_leaves)
            changed = True

    generated_header_leaves: dict[str, set[_LeafKey]] = defaultdict(set)
    for leaf_key, path in leaf_paths.items():
        if path in generated_headers:
            generated_header_leaves[path.casefold()].add(leaf_key)
    selected_includes: set[_LeafKey] = set()
    for leaf_key, target in pending_generated_header_includes.items():
        target_leaves = generated_header_leaves.get(target.casefold(), set())
        if target_leaves and target_leaves.issubset(selected):
            selected.add(leaf_key)
            selected_includes.add(leaf_key)
        else:
            projections.add(leaf_paths[leaf_key].casefold())
    return _CounterfactualLeafClosure(
        frozenset(selected),
        frozenset(selected_includes),
        frozenset(projections),
    )


def _render_declaration_counterfactuals(
    *,
    overlays: Sequence[ClassicRecipeIntervention],
    render_contexts: Mapping[str, _RenderContext],
    selected_leaves: frozenset[_LeafKey],
    generated_tu_folded: set[str],
) -> tuple[dict[str, bytes], dict[str, tuple[tuple[str, int], ...]]]:
    """Render the exact closed declaration leaf subset for every overlay."""

    declaration_outputs: dict[str, bytes] = {}
    declaration_leaf_keys: dict[str, tuple[tuple[str, int], ...]] = {}
    for overlay in overlays:
        document, context_clean_inputs = render_contexts[overlay.id]
        selected_keys = frozenset(
            (operation_id, leaf_index)
            for overlay_id, operation_id, leaf_index in selected_leaves
            if overlay_id == overlay.id
        )
        try:
            counterfactual = render_classic_overlay_leaf_subset(
                document,
                context_clean_inputs,
                selected_keys,
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} declaration counterfactual cannot be derived: {exc}"
            ) from exc
        declaration_leaf_keys[overlay.id] = tuple(sorted(selected_keys))
        for path, payload in counterfactual.outputs.items():
            if path.casefold() in generated_tu_folded:
                continue
            if path in declaration_outputs:
                raise ClassicSemanticError(
                    f"declaration counterfactual output is owned more than once: {path!r}"
                )
            declaration_outputs[path] = payload
    return declaration_outputs, declaration_leaf_keys


def _plan_counterfactual_compilers(
    *,
    graph: ProducerGraphDocument,
    strict_paths: set[str],
    generated_tu_folded: set[str],
    compiler_nodes_by_source: Mapping[str, Sequence[ProducerNode]],
    projection_sources: frozenset[str],
    projection_all: bool,
    declaration_outputs: Mapping[str, bytes],
    declaration_leaf_keys: Mapping[str, tuple[tuple[str, int], ...]],
    reader_closure_fallbacks: tuple[str, ...],
) -> ProjectOverlayCompilerEpochPlan:
    """Select the exact ordinary compiler audit and projection node sets."""

    ordinary_compilers: dict[str, ProducerNode] = {}
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_ref, _object_ref = _compiler_shape(node)
        relative = source_ref.removeprefix("source/")
        if relative.casefold() not in generated_tu_folded:
            ordinary_compilers[node.id] = node
    audit_node_ids: set[str] = set()
    projection_node_ids: set[str] = set()
    projection_header = False
    for folded_path in sorted(strict_paths):
        suffix = PurePosixPath(folded_path).suffix.casefold()
        if suffix in _HEADER_SUFFIXES:
            owners = set(ordinary_compilers)
            projection_header = projection_header or folded_path in projection_sources
        elif suffix in _SOURCE_SUFFIXES:
            owners = (
                set(ordinary_compilers)
                if reader_closure_fallbacks
                else {
                    node.id
                    for node in compiler_nodes_by_source.get(folded_path, ())
                    if node.id in ordinary_compilers
                }
            )
            if not owners:
                raise ClassicSemanticError(
                    f"source-overlay semantic delta has no compiler owner: {folded_path!r}"
                )
        else:
            raise ClassicSemanticError(
                f"source-overlay semantic delta has an unsupported source kind: {folded_path!r}"
            )
        if not owners:
            raise ClassicSemanticError(
                f"source-overlay semantic delta has no ordinary compiler reader: {folded_path!r}"
            )
        audit_node_ids.update(owners)
        if folded_path in projection_sources:
            projection_node_ids.update(owners)
    if projection_all or projection_header:
        projection_node_ids.update(audit_node_ids)
    return ProjectOverlayCompilerEpochPlan(
        MappingProxyType(
            dict(sorted(declaration_outputs.items(), key=lambda item: item[0].casefold()))
        ),
        frozenset(audit_node_ids),
        frozenset(projection_node_ids),
        MappingProxyType(
            dict(sorted(declaration_leaf_keys.items(), key=lambda item: item[0].casefold()))
        ),
        reader_closure_fallbacks,
    )


def _attach_counterfactual_traces(
    *,
    traces: Mapping[str, object],
    declaration_odr: Mapping[str, object],
    compiler_epoch_plan: ProjectOverlayCompilerEpochPlan,
    pending_generated_header_includes: Mapping[_LeafKey, str],
    selected_generated_header_includes: frozenset[_LeafKey],
) -> None:
    """Append canonical project-closure evidence to each per-overlay trace."""

    for trace in traces.values():
        if not isinstance(trace, dict):
            raise AssertionError("source validation trace is not mutable")
        trace["global_declaration_odr"] = declaration_odr
    for overlay_id, trace in traces.items():
        if not isinstance(trace, dict):
            raise AssertionError("source validation trace is not mutable")
        trace["declaration_counterfactual"] = {
            "theorem": "derived-closed-declaration-family-counterfactual-v1",
            "selected_leaf_keys": [
                {"operation_id": operation_id, "leaf_index": leaf_index}
                for operation_id, leaf_index in compiler_epoch_plan.declaration_leaf_keys[
                    overlay_id
                ]
            ],
            "closed_generated_header_includes": [
                {
                    "operation_id": operation_id,
                    "leaf_index": leaf_index,
                    "logical_header": pending_generated_header_includes[
                        (selected_overlay_id, operation_id, leaf_index)
                    ],
                }
                for selected_overlay_id, operation_id, leaf_index in sorted(
                    selected_generated_header_includes
                )
                if selected_overlay_id == overlay_id
            ],
            "audit_node_ids": sorted(compiler_epoch_plan.audit_node_ids, key=str.casefold),
            "runtime_projection_node_ids": sorted(
                compiler_epoch_plan.runtime_projection_node_ids,
                key=str.casefold,
            ),
            "reader_closure_fallbacks": list(compiler_epoch_plan.reader_closure_fallbacks),
        }


def _validate_project_overlay_sources(
    *,
    overlays: Sequence[ClassicRecipeIntervention],
    graph: ProducerGraphDocument,
    source_pairs: Mapping[str, ProjectOverlaySourcePair],
    clean_sources: Mapping[str, CleanSourceInput],
    declaration_by_id: Mapping[
        str,
        tuple[dict[str, dict[str, object]], frozenset[str], frozenset[str]],
    ],
    secondary_reader_payloads: Mapping[str, bytes] | None,
) -> _OverlaySourceValidation:
    """Prove project-agnostic source theorems selected by the closed grammar."""

    generated_tus = frozenset(
        path for overlay in overlays for path in declaration_by_id[overlay.id][1]
    )
    generated_tu_folded = {path.casefold() for path in generated_tus}
    no_clean = frozenset(path for overlay in overlays for path in declaration_by_id[overlay.id][2])
    generated_headers = no_clean - generated_tus
    token_census = _token_census(source.payload for source in clean_sources.values())
    effective_sources = {
        source.path.casefold(): source.payload for source in clean_sources.values()
    }
    effective_sources.update(
        {pair.path.casefold(): pair.effective_payload for pair in source_pairs.values()}
    )
    effective_token_census = _token_census(effective_sources.values())
    ordinary_effective_token_census = _token_census(
        payload for path, payload in effective_sources.items() if path not in generated_tu_folded
    )
    preprocessor_mutations = _preprocessor_mutations(clean_sources)
    introduced: set[str] = set()
    declaration_origin_identifiers: set[str] = set()
    exclusive_declaration_identifiers: set[str] = set()
    declaration_facts: dict[str, list[_DeclarationFact]] = defaultdict(list)
    declaration_seat_failures: set[tuple[str, str, str, str]] = set()
    introduced_locals: set[tuple[str, str, str]] = set()
    helper_identifiers: set[str] = set()
    helpers_by_source: dict[str, list[str]] = defaultdict(list)
    crt_pull_helpers_by_source: dict[str, list[str]] = defaultdict(list)
    ordered_archive_seed_helpers_by_source: dict[str, list[tuple[str, str]]] = defaultdict(list)
    macro_sensitive_identifiers: set[str] = set()
    intrinsic_macro_mutations: set[tuple[str, str, str]] = set()
    logical_headers: set[str] = set()
    unused_typedef_sources: set[str] = set()
    projection_sources: set[str] = set()
    projection_all = False
    traces: dict[str, object] = {}
    render_contexts: dict[str, _RenderContext] = {}
    all_counterfactual_leaves: set[tuple[str, str, int]] = set()
    selected_counterfactual_leaves: set[tuple[str, str, int]] = set()
    compiler_replay_paths: set[str] = set()
    leaf_paths: dict[tuple[str, str, int], str] = {}
    declaration_identifier_leaves: dict[str, set[tuple[str, str, int]]] = defaultdict(set)
    declaration_fragment_token_census: dict[str, int] = defaultdict(int)
    pending_generated_header_includes: dict[tuple[str, str, int], str] = {}
    compiler_nodes_by_source: dict[str, list[ProducerNode]] = defaultdict(list)
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_ref, _object_ref = _compiler_shape(node)
        kind, relative = source_ref.split("/", 1)
        if kind == "source":
            compiler_nodes_by_source[relative.casefold()].append(node)
    graph_targets = tuple(
        sorted(
            (
                str(node.target_id)
                for node in graph.nodes
                if node.role is ProducerRole.LINKER and node.target_id is not None
            ),
            key=str.casefold,
        )
    )
    targets_by_compiler: dict[str, set[str]] = defaultdict(set)
    for target_id in graph_targets:
        for node_id in _ancestor_compilers(graph, target_id):
            targets_by_compiler[node_id].add(target_id)
    authority_paths = {source.path.casefold(): source.path for source in clean_sources.values()}
    authority_paths.update(
        {
            pair.path.casefold(): pair.path
            for pair in source_pairs.values()
            if pair.clean_payload is None
        }
    )

    for overlay in overlays:
        outputs, _generated, _generated_inputs = declaration_by_id[overlay.id]
        owned_generated_headers = {path.casefold() for path in outputs if path in generated_headers}
        claims = _parse_semantic_claims(overlay)
        clean_inputs = {
            path: pair.clean_payload
            for path in outputs
            if (pair := source_pairs.get(path.casefold())) is not None
            and pair.clean_payload is not None
        }
        if set(clean_inputs) != {
            path for path, declaration in outputs.items() if "clean" in declaration
        }:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} lacks immutable clean render inputs"
            )
        document = _overlay_document(overlay)
        render_clean_inputs = {
            path: payload for path, payload in clean_inputs.items() if isinstance(payload, bytes)
        }
        try:
            rendered = render_classic_overlay(document, render_clean_inputs)
        except ValueError as exc:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} cannot be re-rendered from clean authority: {exc}"
            ) from exc
        if set(rendered.outputs) != set(outputs):
            raise ClassicSemanticError(f"overlay {overlay.id!r} render universe changed")
        render_contexts[overlay.id] = (document, render_clean_inputs)
        for path, payload in rendered.outputs.items():
            pair = source_pairs.get(path.casefold())
            if not isinstance(pair, ProjectOverlaySourcePair) or pair.effective_payload != payload:
                raise ClassicSemanticError(f"project overlay rendering changed: {path!r}")

        receipt_by_path = {item.path: item for item in rendered.receipts}
        consumed_claims: set[str] = set()
        operation_census: dict[str, int] = defaultdict(int)
        literal_aliases: dict[tuple[str, str, str, str], dict[str, list[int]]] = defaultdict(
            lambda: {"definition": [], "use": []}
        )
        assert_insertions: list[tuple[str, frozenset[str]]] = []
        assert_deletions: list[tuple[str, str]] = []
        unused_typedefs: list[dict[str, object]] = []
        extended_declaration_line_seats: set[tuple[str, str, str, str, bool]] = set()
        for path, declaration in outputs.items():
            raw_operations = declaration.get("ops")
            if not isinstance(raw_operations, list):
                raise ClassicSemanticError(f"source-overlay operations are malformed: {path}")
            receipt = receipt_by_path[path]
            if len(raw_operations) != len(receipt.operations):
                raise ClassicSemanticError(f"source-overlay receipt is incomplete: {path}")
            pair = source_pairs[path.casefold()]
            clean_payload = pair.clean_payload
            clean_tokens = () if clean_payload is None else _token_texts(clean_payload)
            line_sensitive = "__LINE__" in clean_tokens or any(
                clean_tokens[index : index + 2] == ("#", "line")
                for index in range(len(clean_tokens) - 1)
            )
            is_carrier_tu = path in generated_tus
            is_generated_header = path in generated_headers
            source_compilers = compiler_nodes_by_source.get(path.casefold(), [])
            declaration_targets = frozenset(
                target
                for node in source_compilers
                for target in targets_by_compiler.get(node.id, set())
            )
            if not source_compilers:
                # Header exposure is narrowed later by exact compiler namespace
                # receipts.  The source-only theorem deliberately uses every
                # target as its fail-closed over-approximation.
                declaration_targets = frozenset(graph_targets)
            for raw_operation, operation_receipt in zip(
                raw_operations, receipt.operations, strict=True
            ):
                if not isinstance(raw_operation, dict) or not isinstance(
                    raw_operation.get("op"), str
                ):
                    raise ClassicSemanticError(f"source-overlay operation is malformed: {path}")
                action = raw_operation["op"]
                leaves = _generator_leaves(raw_operation.get("gen"))
                anchor_offsets = tuple(anchor.byte_offset for anchor in operation_receipt.anchors)
                if action in {"replace", "delete"} and operation_receipt.removed_digest is None:
                    raise ClassicSemanticError(
                        f"destructive operation lacks removed-byte evidence: {path}"
                    )
                if line_sensitive:
                    raise ClassicSemanticError(
                        f"source-overlay operation changes line-sensitive input {path!r}"
                    )
                if is_carrier_tu:
                    if action != "append" or any(
                        leaf["k"] not in _GENERATED_CARRIER_GENERATORS for leaf in leaves
                    ):
                        raise ClassicSemanticError(
                            f"generated carrier {path!r} uses an ordinary source operation"
                        )
                    continue
                if is_generated_header and (
                    action != "append" or len(leaves) != 1 or leaves[0]["k"] != "record_header"
                ):
                    raise ClassicSemanticError(f"generated header {path!r} is not declaration-only")
                if clean_payload is not None and action == "append":
                    raise ClassicSemanticError(
                        f"clean-backed source overlay {path!r} appends a new owner"
                    )
                for leaf_index, leaf in enumerate(leaves):
                    kind = str(leaf["k"])
                    leaf_key = (overlay.id, operation_receipt.operation_id, leaf_index)
                    all_counterfactual_leaves.add(leaf_key)
                    leaf_paths[leaf_key] = path
                    operation_census[kind] += 1
                    claim_key = _claim_key(operation_receipt.operation_id, leaf_index)
                    claim = claims.get(claim_key)
                    if kind in _DECLARATION_GENERATORS | {"record_header"}:
                        if claim is not None or action not in {"insert", "append"}:
                            raise ClassicSemanticError(
                                f"declaration generator {kind!r} has an invalid claim or seat"
                            )
                        declaration_delta = _validate_declaration_leaf(
                            leaf=leaf,
                            kind=kind,
                            action=action,
                            path=path,
                            operation_id=operation_receipt.operation_id,
                            clean_payload=clean_payload,
                            anchor_offsets=anchor_offsets,
                            declaration_targets=declaration_targets,
                            token_census=token_census,
                            effective_token_census=effective_token_census,
                            preprocessor_mutations=preprocessor_mutations,
                            introduced=introduced,
                            exclusive_declaration_identifiers=(exclusive_declaration_identifiers),
                            helper_identifiers=helper_identifiers,
                        )
                        declaration_seat_failures.update(declaration_delta.seat_failures)
                        if declaration_delta.extended_line_seat is not None:
                            extended_declaration_line_seats.add(
                                declaration_delta.extended_line_seat
                            )
                        if declaration_delta.projection_required:
                            projection_sources.add(path.casefold())
                        if declaration_delta.unused_typedef_source:
                            unused_typedef_sources.add(path.casefold())
                        unused_typedefs.extend(declaration_delta.unused_typedefs)
                        for fact in declaration_delta.facts:
                            declaration_facts[fact.identifier].append(fact)
                        guard = declaration_delta.guard
                        if guard is not None:
                            exclusive_declaration_identifiers.add(guard)
                            introduced.add(guard)
                            intrinsic_macro_mutations.add((path.casefold(), "define", guard))
                        introduced.update(declaration_delta.declared)
                        declaration_origin_identifiers.update(declaration_delta.declared)
                        if guard is not None:
                            declaration_origin_identifiers.add(guard)
                        declaration_family_identifiers = declaration_delta.declared + (
                            (guard,) if guard is not None else ()
                        )
                        for identifier in declaration_family_identifiers:
                            declaration_identifier_leaves[identifier].add(leaf_key)
                        for identifier in declaration_delta.declared:
                            declaration_fragment_token_census[identifier] += 1
                        if guard is not None:
                            declaration_fragment_token_census[guard] += 2
                        macro_sensitive_identifiers.update(
                            declaration_delta.macro_sensitive_identifiers
                        )
                        if not declaration_delta.projection_required:
                            selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "lines":
                        if claim is not None:
                            raise ClassicSemanticError("layout-only generator cannot carry a claim")
                        if action in {"insert", "append"}:
                            selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "cond":
                        if (
                            claim is not None
                            or action != "insert"
                            or leaf.get("branch_policy") != "typed_declarations_only"
                        ):
                            raise ClassicSemanticError("conditional declaration seat is unsafe")
                        if clean_payload is not None:
                            _require_declaration_seat(
                                clean_payload,
                                min(anchor_offsets),
                                operation=operation_receipt.operation_id,
                            )
                        selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "size_asserts":
                        if claim is not None or action != "insert":
                            raise ClassicSemanticError("compile-time assertion seat is unsafe")
                        if clean_payload is None or not anchor_offsets:
                            raise ClassicSemanticError("compile-time assertion lacks a source seat")
                        _require_declaration_seat(
                            clean_payload,
                            min(anchor_offsets),
                            operation=operation_receipt.operation_id,
                        )
                        projection_sources.add(path.casefold())
                        continue
                    if kind in {"include", "include_seat"}:
                        include_delta = _validate_include_leaf(
                            kind=kind,
                            leaf=leaf,
                            action=action,
                            claim=claim,
                            path=path,
                            operation_id=operation_receipt.operation_id,
                            clean_payload=clean_payload,
                            anchor_offsets=anchor_offsets,
                            source_compilers=source_compilers,
                            authority_paths=authority_paths,
                        )
                        if include_delta.consumes_claim:
                            consumed_claims.add(claim_key)
                        logical_headers.add(include_delta.logical_path)
                        if include_delta.logical_path.casefold() in owned_generated_headers:
                            pending_generated_header_includes[leaf_key] = include_delta.logical_path
                        else:
                            projection_sources.add(path.casefold())
                        continue
                    if kind in _FUNCTION_CLAIM_GENERATORS:
                        function_delta = _validate_function_leaf(
                            kind=kind,
                            leaf=leaf,
                            action=action,
                            claim=claim,
                            path=path,
                            operation_receipt=operation_receipt,
                            leaf_index=leaf_index,
                            clean_payload=clean_payload,
                            source_compilers=source_compilers,
                            authority_paths=authority_paths,
                            clean_sources=clean_sources,
                            preprocessor_mutations=preprocessor_mutations,
                            introduced_locals=introduced_locals,
                        )
                        consumed_claims.add(claim_key)
                        compiler_replay_paths.add(path.casefold())
                        introduced_locals.update(function_delta.introduced_locals)
                        macro_sensitive_identifiers.update(
                            function_delta.macro_sensitive_identifiers
                        )
                        if function_delta.counterfactual_policy == "project":
                            projection_sources.add(path.casefold())
                        else:
                            selected_counterfactual_leaves.add(leaf_key)
                        if function_delta.literal_alias_event is not None:
                            event = function_delta.literal_alias_event
                            literal_aliases[event.key][event.role].append(event.offset)
                        if function_delta.assert_insertion is not None:
                            assert_insertions.append(function_delta.assert_insertion)
                        if function_delta.assert_deletion is not None:
                            assert_deletions.append(function_delta.assert_deletion)
                        continue
                    if kind in _UNREACHABLE_HELPER_GENERATORS:
                        helper_delta = _validate_unreachable_helper_leaf(
                            kind=kind,
                            leaf=leaf,
                            action=action,
                            claim=claim,
                            path=path,
                            clean_payload=clean_payload,
                            anchor_offsets=anchor_offsets,
                            token_census=token_census,
                            introduced=introduced,
                        )
                        helper = helper_delta.identifier
                        introduced.add(helper)
                        macro_sensitive_identifiers.add(helper)
                        helper_identifiers.add(helper)
                        helpers_by_source[path.casefold()].append(helper)
                        if helper_delta.crt_pull:
                            crt_pull_helpers_by_source[path.casefold()].append(helper)
                        if helper_delta.ordered_archive_seed_policy is not None:
                            ordered_archive_seed_helpers_by_source[path.casefold()].append(
                                (helper, helper_delta.ordered_archive_seed_policy)
                            )
                        if helper_delta.projection_required:
                            projection_sources.add(path.casefold())
                        continue
                    raise ClassicSemanticError(
                        f"source-overlay generator has no semantic theorem: {kind!r}"
                    )
        if any(
            len(values["definition"]) != 1
            or len(values["use"]) != 1
            or values["definition"][0] >= values["use"][0]
            for values in literal_aliases.values()
        ):
            raise ClassicSemanticError("literal alias does not form one closed definition/use pair")
        if assert_insertions:
            if len(assert_insertions) != 1:
                raise ClassicSemanticError("assert reseat has no unique carrier")
            authentic, restored = assert_insertions[0]
            deleted = {
                condition for function, condition in assert_deletions if function == authentic
            }
            if deleted != set(restored) or len(deleted) != len(assert_deletions):
                raise ClassicSemanticError("assert reseat deletion closure differs")
        elif assert_deletions:
            raise ClassicSemanticError("assert deletions have no carrier insertion")
        if consumed_claims != set(claims):
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} has unused or missing semantic claims"
            )
        traces[overlay.id] = _overlay_source_trace(
            receipts=rendered.receipts,
            operation_census=operation_census,
            semantic_claim_count=len(claims),
            unused_typedefs=unused_typedefs,
            extended_declaration_line_seats=extended_declaration_line_seats,
        )
    declaration_odr = _validate_declaration_project_closure(
        declaration_facts=declaration_facts,
        declaration_seat_failures=declaration_seat_failures,
        declaration_origin_identifiers=declaration_origin_identifiers,
        token_census=token_census,
        ordinary_effective_token_census=ordinary_effective_token_census,
        declaration_fragment_token_census=declaration_fragment_token_census,
    )
    leaf_closure = _close_counterfactual_leaves(
        declaration_identifier_leaves=declaration_identifier_leaves,
        selected_leaves=selected_counterfactual_leaves,
        leaf_paths=leaf_paths,
        generated_headers=generated_headers,
        pending_generated_header_includes=pending_generated_header_includes,
        projection_sources=projection_sources,
    )
    projection_sources.update(leaf_closure.projection_sources)
    declaration_outputs, declaration_leaf_keys = _render_declaration_counterfactuals(
        overlays=overlays,
        render_contexts=render_contexts,
        selected_leaves=leaf_closure.selected_leaves,
        generated_tu_folded=generated_tu_folded,
    )
    strict_paths = {
        leaf_paths[key].casefold()
        for key in all_counterfactual_leaves - leaf_closure.selected_leaves
    } | compiler_replay_paths
    reader_closure_fallbacks: tuple[str, ...]
    if secondary_reader_payloads is None:
        reader_closure_fallbacks = ("toolchain-include-namespace-unavailable",)
    else:
        reader_payloads = dict(effective_sources)
        reader_payloads.update(secondary_reader_payloads)
        reader_closure_fallbacks = _sparse_source_reader_fallbacks(
            graph=graph,
            effective_sources=reader_payloads,
            strict_paths=frozenset(strict_paths),
        )
    compiler_epoch_plan = _plan_counterfactual_compilers(
        graph=graph,
        strict_paths=strict_paths,
        generated_tu_folded=generated_tu_folded,
        compiler_nodes_by_source=compiler_nodes_by_source,
        projection_sources=leaf_closure.projection_sources,
        projection_all=projection_all,
        declaration_outputs=declaration_outputs,
        declaration_leaf_keys=declaration_leaf_keys,
        reader_closure_fallbacks=reader_closure_fallbacks,
    )
    _attach_counterfactual_traces(
        traces=traces,
        declaration_odr=declaration_odr,
        compiler_epoch_plan=compiler_epoch_plan,
        pending_generated_header_includes=pending_generated_header_includes,
        selected_generated_header_includes=(leaf_closure.selected_generated_header_includes),
    )
    reserved_identifiers = sorted(
        identifier
        for identifier in macro_sensitive_identifiers
        if _reserved_cpp_identifier(identifier)
    )
    if reserved_identifiers:
        raise ClassicSemanticError(
            "source-overlay identifiers enter the implementation-reserved namespace: "
            f"{reserved_identifiers}"
        )
    return _OverlaySourceValidation(
        MappingProxyType(traces),
        compiler_epoch_plan,
        generated_headers,
        frozenset(logical_headers),
        frozenset(unused_typedef_sources),
        frozenset(projection_sources),
        projection_all,
        frozenset(helper_identifiers),
        MappingProxyType(
            {path: tuple(identifiers) for path, identifiers in sorted(helpers_by_source.items())}
        ),
        MappingProxyType(
            {
                path: tuple(identifiers)
                for path, identifiers in sorted(crt_pull_helpers_by_source.items())
            }
        ),
        MappingProxyType(
            {
                path: tuple(helpers)
                for path, helpers in sorted(ordered_archive_seed_helpers_by_source.items())
            }
        ),
        frozenset(declaration_origin_identifiers),
        frozenset(macro_sensitive_identifiers),
        frozenset(intrinsic_macro_mutations),
    )


def _derive_project_overlay_compiler_epoch(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    source_pairs: Sequence[ProjectOverlaySourcePair],
    clean_source_inputs: Sequence[CleanSourceInput],
    *,
    secondary_reader_payloads: Mapping[str, bytes] | None = None,
) -> tuple[
    ProjectOverlayCompilerEpochPlan,
    _OverlaySourceValidation | None,
    frozenset[str],
]:
    """Derive and validate the declaration counterfactual execution theorem.

    The optional validation is absent only when the project has no overlay.
    Generated carrier paths are returned separately because they never belong
    to the ordinary sparse-audit universe.
    """

    overlays = _overlay_interventions(bundle)
    if not overlays:
        if source_pairs or clean_source_inputs:
            raise ClassicSemanticError(
                "compiler epoch planning received source evidence without a project overlay"
            )
        return (
            ProjectOverlayCompilerEpochPlan(
                MappingProxyType({}),
                frozenset(),
                frozenset(),
                MappingProxyType({}),
            ),
            None,
            frozenset(),
        )
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicSemanticError(
            "project-overlay compiler epoch planning requires a complete source manifest"
        )
    clean_sources = _unique(clean_source_inputs, lambda item: item.path, "clean source input")
    manifest_by_path = {item.path.casefold(): item for item in manifest.entries}
    if set(clean_sources) != set(manifest_by_path):
        missing = sorted(set(manifest_by_path) - set(clean_sources))
        extra = sorted(set(clean_sources) - set(manifest_by_path))
        raise ClassicSemanticError(
            f"clean source authority differs during compiler epoch planning; "
            f"missing={missing}, extra={extra}"
        )
    for folded, source in clean_sources.items():
        if not isinstance(source, CleanSourceInput):
            raise ClassicSemanticError("clean source authority contains an invalid record")
        entry = manifest_by_path[folded]
        if (
            source.path != entry.path
            or len(source.payload) != entry.size
            or Digest.from_bytes(source.payload) != entry.digest
        ):
            raise ClassicSemanticError(
                f"clean source authority changed during compiler epoch planning: {source.path!r}"
            )

    declaration_by_id: dict[
        str,
        tuple[dict[str, dict[str, object]], frozenset[str], frozenset[str]],
    ] = {}
    output_paths: set[str] = set()
    for overlay in overlays:
        declaration = _overlay_declaration(overlay)
        declaration_by_id[overlay.id] = declaration
        outputs, _generated, _generated_inputs = declaration
        folded_outputs = {path.casefold() for path in outputs}
        overlap = folded_outputs & output_paths
        if overlap:
            raise ClassicSemanticError(
                f"project-overlay compiler epoch outputs overlap: {sorted(overlap)}"
            )
        output_paths.update(folded_outputs)

    pairs = _unique(source_pairs, lambda item: item.path, "project overlay source pair")
    if set(pairs) != output_paths:
        missing = sorted(output_paths - set(pairs))
        extra = sorted(set(pairs) - output_paths)
        raise ClassicSemanticError(
            f"project-overlay compiler epoch source pairs differ; missing={missing}, extra={extra}"
        )
    for overlay in overlays:
        outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
        for path, output_declaration in outputs.items():
            pair = pairs[path.casefold()]
            if not isinstance(pair, ProjectOverlaySourcePair) or pair.path != path:
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch source pair changed: {path!r}"
                )
            if (
                Digest.from_bytes(pair.effective_payload).value != output_declaration["effective"]
                or len(pair.effective_payload) != output_declaration["size"]
            ):
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch effective source changed: {path!r}"
                )
            if path in generated_inputs:
                if pair.clean_payload is not None:
                    raise ClassicSemanticError(
                        f"generated compiler epoch source has a clean preimage: {path!r}"
                    )
                continue
            clean = clean_sources.get(path.casefold())
            if (
                not isinstance(clean, CleanSourceInput)
                or pair.clean_payload != clean.payload
                or output_declaration.get("clean") != Digest.from_bytes(clean.payload).value
            ):
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch clean source changed: {path!r}"
                )

    validation = _validate_project_overlay_sources(
        overlays=overlays,
        graph=graph,
        source_pairs={
            key: value
            for key, value in pairs.items()
            if isinstance(value, ProjectOverlaySourcePair)
        },
        clean_sources=_compiler_semantic_sources(
            {
                key: value
                for key, value in clean_sources.items()
                if isinstance(value, CleanSourceInput)
            }
        ),
        declaration_by_id=declaration_by_id,
        secondary_reader_payloads=(
            None
            if _toolchain_include_roots(bundle) and not secondary_reader_payloads
            else (secondary_reader_payloads or {})
        ),
    )
    generated_tus = frozenset(
        path
        for _outputs, generated, _generated_inputs in declaration_by_id.values()
        for path in generated
    )
    return validation.compiler_epoch_plan, validation, generated_tus


def plan_project_overlay_compiler_epochs(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    source_pairs: Sequence[ProjectOverlaySourcePair],
    clean_source_inputs: Sequence[CleanSourceInput],
    *,
    secondary_reader_payloads: Mapping[str, bytes] | None = None,
) -> ProjectOverlayCompilerEpochPlan:
    """Derive the declaration counterfactual and its exact sparse audit set.

    Runtime uses this pure planner to decide which compiler nodes to execute.
    Semantic validation invokes the same theorem independently and rejects any
    missing or extra runtime evidence; the returned bytes are therefore a
    derived execution plan, not caller-supplied proof authority.
    """

    plan, _validation, _generated_tus = _derive_project_overlay_compiler_epoch(
        bundle,
        graph,
        source_pairs,
        clean_source_inputs,
        secondary_reader_payloads=secondary_reader_payloads,
    )
    return plan


def _toolchain_include_roots(bundle: ProjectBundle) -> tuple[str, ...]:
    """Return the exact locked trees that can supply preprocessor inputs."""

    try:
        roots = set(toolchain_profile(bundle.toolchain_lock.profile).include_roots)
    except ToolchainError:
        roots = set()
    roots.update(
        tree.path
        for tree in bundle.toolchain_lock.input_trees
        if "include" in {part.casefold() for part in PurePosixPath(tree.path).parts}
    )
    return tuple(sorted(roots, key=str.casefold))


__all__ = ["plan_project_overlay_compiler_epochs"]
