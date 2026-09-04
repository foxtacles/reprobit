"""Semantic boundary for donor-private source refactors.

The classic overlay renderer proves *what bytes* a typed operation produced.
This module proves the smaller, complementary claim needed before those bytes
may influence a composed object:

* the six source refactors used by the current project are bound to one
  source-aware consumer and to the declarations that make the rewrite
  logic-equivalent; and
* the two dead-local carrier forms are kept in the weaker, honest category of
  donor-private compiler state.  They are structurally inert local work, but
  are not promoted to a whole-program source-equivalence claim.

There is deliberately no general C++ rewriting language here.  A new refactor
kind needs a new closed proof rule and tests.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from reprobit.classic.overlay_types import (
    ClassicOverlayOutputReceipt,
)
from reprobit.classic.source_proofs import (
    require_target_source_refactor_identity,
    select_source_permutation_window,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicRecipeIntervention,
)
from reprobit.strict_json import canonical_json

from .source_refactor_semantics_entropy import (
    _prove_entropy_only_rendering,
    _prove_true_refactor_entropy,
)
from .source_refactor_semantics_lifts import (
    _prove_capture,
    _prove_constructor_lift,
    _prove_private_state,
)
from .source_refactor_semantics_loops import (
    _prove_fixed_fill,
    _prove_for_initializer,
    _prove_inclusive,
    _prove_shuffle,
)
from .source_refactor_semantics_schema import (
    _PRIVATE_STATE_KINDS,
    _TRUE_REFACTOR_KINDS,
    SourceRefactorSemanticError,
    SourceRefactorSemanticProof,
    _array,
    _keys,
    _need,
    _object,
    _operations,
    _parameters,
    _receipt_index,
    _safe_nonsemantic_operations,
    _semantic_operations,
)


def validate_donor_source_semantics(
    donor: ClassicRecipeIntervention,
    consumers: Sequence[ClassicRecipeIntervention],
    *,
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    rendered_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str] = frozenset(),
    overlay_receipts: Sequence[ClassicOverlayOutputReceipt] = (),
) -> SourceRefactorSemanticProof | None:
    """Validate the closed semantic claim of one rendered overlay donor.

    Declaration-only donors return ``None``.  Any donor carrying one of the
    admitted source mutation generators must have exactly one reviewed
    consumer.  Unknown future refactor kinds are not inferred here: they must
    add an explicit rule before being admitted.
    """

    if donor.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return None
    _need(donor.role is ClassicRecipeRole.DONOR, "source semantics require a donor")
    parameters = _parameters(donor)
    operations = _operations(parameters)
    semantic_operations = _semantic_operations(operations)
    if not semantic_operations:
        _prove_entropy_only_rendering(
            operations,
            owning_source=owning_source,
            clean_sources=clean_sources,
            rendered_sources=rendered_sources,
        )
        return None
    receipts = _receipt_index(overlay_receipts)
    _need(bool(receipts), "source-mutating donor lacks overlay operation receipts")
    for operation in semantic_operations:
        operation_id = operation.operation_id
        _need(operation_id is not None, "source-mutating operation lacks an id")
        _need(
            (operation.path, operation_id) in receipts,
            f"source refactor operation {operation_id!r} lacks a receipt",
        )
    _need(len(consumers) == 1, "source-mutating donor must have exactly one consumer")
    consumer = consumers[0]
    _need(
        consumer.role is ClassicRecipeRole.FUNCTION and donor.id in consumer.dependencies,
        "source-mutating donor consumer binding differs",
    )
    consumer_parameters = _parameters(consumer)
    kinds = {
        cast(str, leaf.get("k"))
        for operation in semantic_operations
        for leaf in operation.leaves
        if leaf.get("k") != "member_sig"
    }
    if kinds <= _PRIVATE_STATE_KINDS:
        _need(
            "target_source_refactor" not in consumer_parameters,
            "private compiler-state donor is mislabeled as a target refactor",
        )
        return _prove_private_state(
            donor=donor,
            operations=operations,
            semantic_operations=semantic_operations,
            owning_source=owning_source,
            clean_sources=clean_sources,
            rendered_sources=rendered_sources,
        )

    _need(
        not kinds.intersection(_PRIVATE_STATE_KINDS),
        "source refactor mixes private compiler-state operations",
    )
    _need(len(kinds) == 1 and kinds <= _TRUE_REFACTOR_KINDS, "source refactor kind set differs")
    proof = _object(
        consumer_parameters.get("target_source_refactor"), "target source refactor proof"
    )
    proof_kind = proof.get("kind")
    expected_kind = {
        "for_initializer_declaration_reseat_v1": "for_init_decl",
        "fixed_array_fill_loop_v1": "fixed_array_fill",
        "fixed_array_shuffle_pointer_countdown_v1": "fixed_array_shuffle_countdown",
        "inclusive_extent_assignment_v1": "inclusive_extent",
        "constructor_allocation_lift_v1": "ctor_alloc_lift",
        "captured_pointer_tail_return_v1": "capture_tail",
    }.get(cast(str, proof_kind))
    _need(
        expected_kind is not None and kinds == {expected_kind},
        "source refactor proof kind differs from its generator",
    )
    common_keys = {
        "kind",
        "selector",
        "start_marker",
        "source_owner_mangled",
        "seed_range_pin",
        "donor_range_pin",
        "operation_ids",
    }
    additions = {
        "fixed_array_fill_loop_v1": {"array_declaration"},
        "fixed_array_shuffle_pointer_countdown_v1": {"semantic_witness"},
        "inclusive_extent_assignment_v1": {"semantic_witness"},
        "constructor_allocation_lift_v1": {"semantic_witness", "constructor_signature"},
    }.get(cast(str, proof_kind), set())
    _keys(proof, common_keys | additions, "target source refactor proof")
    _need(
        proof["selector"] == "brace_balanced_function_after_marker_v1",
        "target source refactor selector differs",
    )
    _need(
        proof["source_owner_mangled"] == consumer.symbol,
        "target source refactor owner differs from its consumer",
    )
    operation_ids = _array(proof["operation_ids"], "target source refactor operation ids")
    _need(
        bool(operation_ids)
        and len(operation_ids) == len(set(operation_ids))
        and all(isinstance(item, str) for item in operation_ids),
        "target source refactor operation ids differ",
    )
    actual_ids = [operation.operation_id for operation in semantic_operations]
    _need(
        None not in actual_ids and set(actual_ids) == set(operation_ids),
        "target source refactor operation set is incomplete",
    )
    expected_counts = {
        "for_init_decl": 1,
        "fixed_array_fill": 1,
        "fixed_array_shuffle_countdown": 1,
        "inclusive_extent": 1,
        "capture_tail": 5,
        "ctor_alloc_lift": 4,
    }
    _need(
        len(semantic_operations) == expected_counts[cast(str, expected_kind)],
        "target source refactor operation count differs",
    )
    _safe_nonsemantic_operations(operations, frozenset(map(id, semantic_operations)), owning_source)
    _need(
        owning_source in clean_sources and owning_source in rendered_sources,
        "source refactor owning-TU bytes are absent",
    )
    clean_unit = clean_sources[owning_source]
    donor_unit = rendered_sources[owning_source]
    try:
        require_target_source_refactor_identity(
            clean_unit,
            donor_unit,
            proof,
            f"donor {donor.id} source refactor",
        )
        clean_target = select_source_permutation_window(
            clean_unit, proof, f"donor {donor.id} clean target"
        )
        donor_target = select_source_permutation_window(
            donor_unit, proof, f"donor {donor.id} donor target"
        )
    except ValueError as exc:
        raise SourceRefactorSemanticError(str(exc)) from exc
    target_start = clean_unit.index(clean_target)
    target_end = target_start + len(clean_target)
    _prove_true_refactor_entropy(
        operations=operations,
        semantic_operations=semantic_operations,
        owning_source=owning_source,
        clean_sources=clean_sources,
        receipts=receipts,
        target_start=target_start,
        target_end=target_end,
    )
    clean_positions: dict[str, int] = {}
    for operation in semantic_operations:
        _need(
            operation.path == owning_source
            or (
                expected_kind == "ctor_alloc_lift" and operation.leaves[0].get("k") == "member_sig"
            ),
            "source refactor operation leaves its owning TU",
        )
        operation_id = cast(str, operation.operation_id)
        receipt = receipts.get((operation.path, operation_id))
        _need(receipt is not None, f"source refactor operation {operation_id!r} lacks a receipt")
        assert receipt is not None
        receipt_anchors = receipt.anchors
        _need(bool(receipt_anchors), f"source refactor operation {operation_id!r} has no anchor")
        start = receipt_anchors[0].byte_offset
        if operation.path == owning_source:
            end = receipt_anchors[-1].byte_offset
            definition_seat = expected_kind == "ctor_alloc_lift" and (
                operation.leaves[0].get("role") == "constructor_body"
                or (
                    operation.leaves[0].get("k") == "member_sig"
                    and operation.leaves[0].get("form") == "qualified_definition_header"
                )
            )
            if definition_seat:
                _need(
                    start == end and start <= target_start,
                    f"source refactor operation {operation_id!r} has the wrong definition seat",
                )
            else:
                _need(
                    target_start <= start <= end <= target_end,
                    f"source refactor operation {operation_id!r} leaves its target",
                )
            clean_positions[operation_id] = start
    primary_generators = [
        operation.leaves[0]
        for operation in semantic_operations
        if operation.leaves[0].get("k") == expected_kind
    ]
    if expected_kind == "for_init_decl":
        _prove_for_initializer(clean_target, donor_target, primary_generators[0])
    elif expected_kind == "fixed_array_fill":
        _prove_fixed_fill(
            clean_sources=clean_sources,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "fixed_array_shuffle_countdown":
        _need(
            consumer.family
            in {
                ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
                ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY,
            }
            and isinstance(consumer_parameters.get("source_fpo_identity"), Mapping)
            and "ordinary_fpo_identity" not in consumer_parameters,
            "fixed-array shuffle lacks its isolated source-FPO consumer",
        )
        _prove_shuffle(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "inclusive_extent":
        _prove_inclusive(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "capture_tail":
        _prove_capture(
            clean_target,
            donor_target,
            clean_unit,
            semantic_operations,
            clean_positions,
        )
    else:
        _need(
            consumer.family is ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
            "allocation lift lacks its retail-exact divergent consumer",
        )
        _prove_constructor_lift(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            donor_unit=donor_unit,
            proof=proof,
            consumer_parameters=consumer_parameters,
            semantic_operations=semantic_operations,
            rendered_sources=rendered_sources,
        )
    statement = {
        "intervention": donor.id,
        "consumer": consumer.id,
        "classification": "logic_equivalent_target_source_refactor_v1",
        "generator_kinds": sorted(kinds),
        "operation_ids": sorted(cast(list[str], operation_ids)),
    }
    return SourceRefactorSemanticProof(
        donor.id,
        "logic_equivalent_target_source_refactor_v1",
        tuple(sorted(kinds)),
        tuple(sorted(cast(list[str], operation_ids))),
        Digest.from_bytes(canonical_json(statement)),
    )


__all__ = [
    "validate_donor_source_semantics",
]
