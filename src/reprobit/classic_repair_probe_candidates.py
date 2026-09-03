"""Pure candidate preparation and composition checks for classic repair probes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from reprobit.classic.source_refactor_semantics import validate_donor_source_semantics
from reprobit.classic_donor_retune_candidates import DonorRetuneCandidate
from reprobit.classic_donor_retune_materialization import (
    MaterializedDonorRetuneCandidate,
    materialize_donor_retune_candidate,
)
from reprobit.classic_donors import matching_candidate_constraints, prepare_donor_compile_request
from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepair,
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_orchestration import (
    ClassicPreparedDonor,
    ClassicPreparedUnit,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import ClassicInterventionEdit, ClassicReceiptEdit
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.classic_runtime_probe import ClassicDonorProbeOutput
from reprobit.schema import ClassicProofReceipt, ClassicRecipeFamily, ClassicRecipeIntervention


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    return {item.name: item.value for item in intervention.parameters}


def _overlay_inputs(
    donor: ClassicPreparedDonor,
    clean_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]],
) -> tuple[Mapping[str, bytes] | None, Sequence[Mapping[str, object]] | None]:
    if donor.intervention.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return None, None
    selected: dict[str, bytes] = {}
    for path in donor.request.logical_outputs:
        payload = clean_sources.get(path)
        if payload is None:
            raise ValueError(f"authenticated clean source is absent: {path!r}")
        selected[path] = payload
    replay = _parameters(donor.intervention).get("canonical_overlay_replay")
    operations = canonical_overlay_operations.get(donor.request.logical_source)
    if replay is None:
        operations = None
    elif operations is None:
        raise ValueError(f"canonical overlay replay is absent for {donor.request.logical_source!r}")
    return selected, operations


def _candidate_receipts(
    unit: ClassicPreparedUnit,
    before: ClassicProofReceipt,
    after: ClassicProofReceipt,
) -> tuple[ClassicProofReceipt, ...]:
    return tuple(after if item.id == before.id else item for item in unit.receipts)


def prepare_retune_candidate(
    unit: ClassicPreparedUnit,
    donor: ClassicPreparedDonor,
    donor_receipt: ClassicProofReceipt,
    candidate: DonorRetuneCandidate,
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]],
) -> tuple[MaterializedDonorRetuneCandidate, ClassicPreparedDonor]:
    """Materialize and semantically close one nearby donor authority state."""

    clean_inputs, operations = _overlay_inputs(
        donor,
        clean_sources,
        canonical_overlay_operations,
    )
    materialized = materialize_donor_retune_candidate(
        candidate,
        donor_receipt,
        clean_sources=clean_inputs,
        canonical_overlay_operations=operations,
    )
    source_path = donor.request.logical_source
    clean_source = clean_sources.get(source_path)
    effective_source = effective_sources.get(source_path)
    if clean_source is None or effective_source is None:
        raise ValueError(f"authenticated clean/effective source is absent: {source_path!r}")
    request = prepare_donor_compile_request(
        materialized.intervention,
        source_path=source_path,
        clean_source=clean_source,
        effective_source=effective_source,
        receipts=_candidate_receipts(unit, donor_receipt, materialized.receipt),
        clean_sources=clean_inputs,
        canonical_overlay_operations=operations,
    )
    consumers = tuple(
        function for function in unit.functions if donor.intervention.id in function.dependencies
    )
    validate_donor_source_semantics(
        materialized.intervention,
        consumers,
        owning_source=unit.plan.source,
        clean_sources=clean_sources,
        rendered_sources=request.logical_outputs,
        overlaid_paths=frozenset(canonical_overlay_operations),
        overlay_receipts=request.overlay_receipts,
    )
    return materialized, ClassicPreparedDonor(materialized.intervention, request)


def clone_retune_probe_unit(
    unit: ClassicPreparedUnit,
    donor: ClassicPreparedDonor,
    probe_id: str,
) -> ClassicPreparedUnit:
    """Give a prepared candidate a diagnostic-only unique identity."""

    intervention = donor.intervention.model_copy(update={"id": probe_id})
    compile_receipt = replace(donor.request.receipt, intervention_id=probe_id)
    request = replace(donor.request, intervention_id=probe_id, receipt=compile_receipt)
    return replace(
        unit,
        donors=(ClassicPreparedDonor(intervention, request),),
        functions=(),
        legacy_actions=(),
        actions=(),
        receipts=(),
    )


def same_donor_compile_input(
    first: ClassicPreparedDonor,
    second: ClassicPreparedDonor,
) -> bool:
    """Return whether two authorities produce the identical private compiler request."""

    left = first.request
    right = second.request
    return (
        left.compiler_seat == right.compiler_seat
        and left.family is right.family
        and left.build_target == right.build_target
        and left.logical_source == right.logical_source
        and left.staged_source == right.staged_source
        and left.files == right.files
        and left.logical_outputs == right.logical_outputs
        and left.compiler_additions == right.compiler_additions
        and left.carrier_identifiers == right.carrier_identifiers
    )


def _rendered_source(
    donor: ClassicPreparedDonor,
    output: ClassicDonorProbeOutput,
) -> bytes:
    expected = donor.request.logical_outputs
    observed = {item.logical_path: item.payload for item in output.rendered_inputs}
    if observed != expected:
        raise ValueError(f"donor probe {output.donor_id!r} returned different rendered inputs")
    source = observed.get(donor.request.logical_source)
    if source is None:
        raise ValueError(f"donor probe {output.donor_id!r} omitted its logical source")
    return source


def _candidate_materials(
    failure: ClassicRepairRefusal,
    donor: ClassicPreparedDonor,
    materialized: MaterializedDonorRetuneCandidate,
    output: ClassicDonorProbeOutput,
) -> ClassicDispatchMaterials:
    action = failure.intervention
    donor_id = materialized.intervention.id
    if not action.dependencies or action.dependencies[0] != donor_id:
        raise ValueError(
            f"action {action.id!r} does not name retuned donor {donor_id!r} as primary"
        )
    values = matching_candidate_constraints(action, (failure.receipt,)).materialize()
    target_id = values.get("target_donor")
    complete_id = values.get("complete_donor")
    instruction_id = values.get("instruction_donor")
    rendered_source = _rendered_source(donor, output)
    additional = dict(failure.materials.additional_donor_objects)
    if donor_id in additional:
        additional[donor_id] = output.object_payload
    return replace(
        failure.materials,
        donor_object=output.object_payload,
        target_donor_object=(
            output.object_payload
            if target_id in {None, donor_id}
            else failure.materials.target_donor_object
        ),
        complete_donor_object=(
            output.object_payload
            if complete_id == donor_id
            else failure.materials.complete_donor_object
        ),
        instruction_donor_object=(
            output.object_payload
            if instruction_id == donor_id
            else failure.materials.instruction_donor_object
        ),
        donor_source=rendered_source,
        target_donor_source=(
            rendered_source
            if target_id in {None, donor_id}
            else failure.materials.target_donor_source
        ),
        instruction_donor_source=(
            rendered_source
            if instruction_id == donor_id
            else failure.materials.instruction_donor_source
        ),
        additional_donor_objects=additional,
        shape_identifiers=donor.request.carrier_identifiers,
    )


def _consumer_refusal(
    unit: ClassicPreparedUnit,
    consumer: ClassicRecipeIntervention,
    template: ClassicRepairRefusal,
) -> ClassicRepairRefusal:
    """Describe a currently composing consumer of the retuned donor as a pseudo-refusal.

    Its materials are rebuilt the way the unit composition builds them, from the
    fresh donor objects captured with the sibling failure, so the candidate is
    validated against every function the donor serves and not only against the
    ones that happened to fail.
    """

    receipts = [item for item in unit.receipts if item.intervention_id == consumer.id]
    if len(receipts) != 1:
        raise ValueError(f"consumer {consumer.id!r} requires one proof receipt")
    receipt = receipts[0]
    objects = template.unit_donor_objects
    values = matching_candidate_constraints(consumer, (receipt,)).materialize()
    primary_id = consumer.dependencies[0]
    if primary_id not in objects:
        raise ValueError(f"consumer {consumer.id!r} donor object {primary_id!r} was not captured")

    def named(key: str) -> bytes | None:
        donor_id = values.get(key)
        if donor_id is None:
            return None
        if not isinstance(donor_id, str) or donor_id not in objects:
            raise ValueError(f"consumer {consumer.id!r} names an uncaptured {key}: {donor_id!r}")
        return objects[donor_id]

    additional: dict[str, bytes] = {}
    variants = values.get("donor_variants", [])
    if isinstance(variants, list):
        for item in variants:
            donor_id = item.get("donor") if isinstance(item, dict) else None
            if not isinstance(donor_id, str) or donor_id not in objects:
                raise ValueError(f"consumer {consumer.id!r} names an uncaptured donor variant")
            additional[donor_id] = objects[donor_id]
    sources = {
        item.intervention.id: item.request.logical_outputs.get(unit.plan.source)
        for item in unit.donors
    }
    target_id = values.get("target_donor")
    instruction_id = values.get("instruction_donor")
    materials = replace(
        template.materials,
        donor_object=objects[primary_id],
        target_donor_object=named("target_donor") if target_id is not None else objects[primary_id],
        complete_donor_object=named("complete_donor"),
        instruction_donor_object=named("instruction_donor"),
        donor_source=sources.get(primary_id),
        target_donor_source=sources.get(target_id if isinstance(target_id, str) else primary_id),
        instruction_donor_source=(
            sources.get(instruction_id) if isinstance(instruction_id, str) else None
        ),
        additional_donor_objects=additional,
        candidate_constraints=values,
    )
    return replace(template, intervention=consumer, receipt=receipt, materials=materials)


def other_consumers(
    unit: ClassicPreparedUnit,
    donor_id: str,
    failures: Sequence[ClassicRepairRefusal],
) -> tuple[ClassicRepairRefusal, ...]:
    """Pseudo-refusals for the donor's consumers that are not among the captured failures."""

    if not failures or not failures[0].unit_donor_objects:
        return ()
    failed = {item.intervention.id for item in failures}
    return tuple(
        _consumer_refusal(unit, function, failures[0])
        for function in unit.functions
        if donor_id in function.dependencies and function.id not in failed
    )


def validate_retuned_actions(
    failures: Sequence[ClassicRepairRefusal],
    donor: ClassicPreparedDonor,
    materialized: MaterializedDonorRetuneCandidate,
    output: ClassicDonorProbeOutput,
) -> tuple[MeasuredPinRepair, ...]:
    """Replay the ordinary composer for every captured consumer failure.

    Callers pass the captured failures followed by the donor's other consumers
    (see :func:`other_consumers`), so a candidate that would break a function
    the donor still serves is refused rather than traded for the failing one.
    """

    repaired: list[MeasuredPinRepair] = []
    for failure in failures:
        try:
            repaired.append(
                repair_measured_pins(
                    failure.intervention,
                    failure.receipt,
                    _candidate_materials(failure, donor, materialized, output),
                )
            )
        except MeasuredPinRepairError as exc:
            raise MeasuredPinRepairError(
                f"action {failure.intervention.id!r} rejected candidate: {exc}",
                stage=exc.stage,
            ) from exc
        except ValueError as exc:
            raise MeasuredPinRepairError(
                f"action {failure.intervention.id!r} rejected candidate: {exc}"
            ) from exc
    return tuple(repaired)


def retune_authority_edits(
    donor_before: ClassicPreparedDonor,
    donor_receipt: ClassicProofReceipt,
    failures: Sequence[ClassicRepairRefusal],
    materialized: MaterializedDonorRetuneCandidate,
    repaired: Sequence[MeasuredPinRepair],
) -> tuple[tuple[ClassicInterventionEdit, ...], tuple[ClassicReceiptEdit, ...]]:
    """Build exact typed edits after ordinary candidate admission."""

    intervention_edits = (
        ClassicInterventionEdit(donor_before.intervention, materialized.intervention),
    )
    receipts: dict[str, ClassicReceiptEdit] = {}
    if materialized.receipt != donor_receipt:
        receipts[donor_receipt.id] = ClassicReceiptEdit(donor_receipt, materialized.receipt)
    for failure, result in zip(failures, repaired, strict=True):
        if result.receipt == failure.receipt:
            continue
        edit = ClassicReceiptEdit(failure.receipt, result.receipt)
        previous = receipts.get(edit.before.id)
        if previous is not None and previous != edit:
            raise ValueError(f"receipt {edit.before.id!r} produced conflicting repairs")
        receipts[edit.before.id] = edit
    return intervention_edits, tuple(receipts[key] for key in sorted(receipts, key=str.casefold))


__all__ = [
    "clone_retune_probe_unit",
    "other_consumers",
    "prepare_retune_candidate",
    "retune_authority_edits",
    "same_donor_compile_input",
    "validate_retuned_actions",
]
