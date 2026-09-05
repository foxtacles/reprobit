"""Pure candidate preparation and composition checks for classic repair probes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import TYPE_CHECKING

from reprobit.classic.source_refactor_semantics import validate_donor_source_semantics
from reprobit.classic_donor_retune_candidates import DonorRetuneCandidate
from reprobit.classic_donor_retune_materialization import (
    MaterializedDonorRetuneCandidate,
    materialize_donor_retune_candidate,
)
from reprobit.classic_donor_usage import beneficiary_keys, donor_after_usage
from reprobit.classic_donors import matching_candidate_constraints, prepare_donor_compile_request
from reprobit.classic_legacy_repair import (
    LegacyInstallRepair,
    LegacyRepairError,
    reauthor_legacy_simulated_elision,
)
from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepair,
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_mosaic_repair import (
    MosaicRepairError,
    instruction_mosaic_semantics_required,
    reauthor_instruction_mosaic,
)
from reprobit.classic_orchestration import (
    ClassicPreparedDonor,
    ClassicPreparedUnit,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_relational_repair import (
    RelationalRepairError,
    reauthor_relational_donor_rewriting,
)
from reprobit.classic_repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
)
from reprobit.classic_repair_session import ClassicRepairRefusal, RepairRefusal
from reprobit.classic_retail_repair import RetailRepairError, retail_body_goal_digest
from reprobit.classic_runtime_probe import ClassicDonorProbeOutput
from reprobit.coff_format import CoffObject, coff_body
from reprobit.discovery_authoring import (
    REAUTHORABLE_FAMILIES,
    DiscoveryAuthoringError,
    build_measured_function_record,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    LegacyOracleInstallIntervention,
    classic_function_donor_ids,
)

if TYPE_CHECKING:
    from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession


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
    overlay_render_session: ClassicOverlayRenderSession | None = None,
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
        overlay_render_session=overlay_render_session,
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
        overlay_render_session=overlay_render_session,
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
    failure: RepairRefusal,
    donor: ClassicPreparedDonor,
    materialized: MaterializedDonorRetuneCandidate,
    output: ClassicDonorProbeOutput,
) -> ClassicDispatchMaterials:
    action = failure.intervention
    donor_id = materialized.intervention.id
    if isinstance(action, LegacyOracleInstallIntervention):
        if not action.dependencies or action.dependencies[0] != donor_id:
            raise ValueError(
                f"legacy action {action.id!r} does not name retuned donor {donor_id!r} as primary"
            )
        rendered_source = _rendered_source(donor, output)
        return replace(
            failure.materials,
            donor_object=output.object_payload,
            target_donor_object=output.object_payload,
            donor_source=rendered_source,
            target_donor_source=rendered_source,
            shape_identifiers=donor.request.carrier_identifiers,
        )
    if donor_id not in classic_function_donor_ids(action, failure.receipt):
        raise ValueError(f"action {action.id!r} does not name retuned donor {donor_id!r}")
    rendered_source = _rendered_source(donor, output)
    primary_retuned = action.dependencies[0] == donor_id
    values = matching_candidate_constraints(action, (failure.receipt,)).materialize()
    target_id = values.get("target_donor")
    complete_id = values.get("complete_donor")
    instruction_id = values.get("instruction_donor")
    target_retuned = target_id == donor_id or (target_id is None and primary_retuned)
    additional = dict(failure.materials.additional_donor_objects)
    if donor_id in additional:
        additional[donor_id] = output.object_payload
    return replace(
        failure.materials,
        donor_object=(output.object_payload if primary_retuned else failure.materials.donor_object),
        target_donor_object=(
            output.object_payload if target_retuned else failure.materials.target_donor_object
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
        donor_source=(rendered_source if primary_retuned else failure.materials.donor_source),
        target_donor_source=(
            rendered_source if target_retuned else failure.materials.target_donor_source
        ),
        instruction_donor_source=(
            rendered_source
            if instruction_id == donor_id
            else failure.materials.instruction_donor_source
        ),
        additional_donor_objects=additional,
        shape_identifiers=(
            donor.request.carrier_identifiers
            if primary_retuned
            else failure.materials.shape_identifiers
        ),
    )


def _consumer_refusal(
    unit: ClassicPreparedUnit,
    consumer: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    template: RepairRefusal,
) -> ClassicRepairRefusal:
    """Describe a currently composing consumer of the retuned donor as a pseudo-refusal.

    Its materials are rebuilt the way the unit composition builds them, from the
    fresh donor objects captured with the sibling failure, so the candidate is
    validated against every function the donor serves and not only against the
    ones that happened to fail.
    """

    objects = template.unit_donor_objects
    seed_object = template.action_preimages.get(consumer.id)
    if seed_object is None:
        raise ValueError(f"consumer {consumer.id!r} has no captured composition preimage")
    action_indices = tuple(
        index for index, action in enumerate(unit.actions) if action.id == consumer.id
    )
    if len(action_indices) != 1:
        raise ValueError(f"consumer {consumer.id!r} requires one action position")
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
    prepared = {item.intervention.id: item for item in unit.donors}
    primary = prepared.get(primary_id)
    if primary is None:
        raise ValueError(f"consumer {consumer.id!r} primary donor {primary_id!r} was not prepared")
    sources = {
        donor_id: item.request.logical_outputs.get(unit.plan.source)
        for donor_id, item in prepared.items()
    }
    target_id = values.get("target_donor")
    instruction_id = values.get("instruction_donor")
    materials = replace(
        template.materials,
        seed_object=seed_object,
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
        shape_identifiers=primary.request.carrier_identifiers,
        candidate_constraints=values,
    )
    return ClassicRepairRefusal(
        unit_id=template.unit_id,
        action_index=action_indices[0],
        intervention=consumer,
        receipt=receipt,
        materials=materials,
        unit=unit,
        reason=template.reason,
        unit_donor_objects=template.unit_donor_objects,
        retail_body=template.unit_retail_bodies.get(consumer.id),
        unit_retail_bodies=template.unit_retail_bodies,
        action_preimages=template.action_preimages,
    )


def other_consumers(
    unit: ClassicPreparedUnit,
    donor_id: str,
    failures: Sequence[RepairRefusal],
) -> tuple[ClassicRepairRefusal, ...]:
    """Pseudo-refusals for the donor's consumers that are not among the captured failures."""

    if not failures:
        return ()
    failed = {item.intervention.id for item in failures}
    earliest_failure = min(item.action_index for item in failures)
    action_positions: dict[str, int] = {}
    for index, action in enumerate(unit.actions):
        if action.id in action_positions:
            raise ValueError(f"unit repeats action {action.id!r}")
        action_positions[action.id] = index
    uncaptured_legacy: list[str] = []
    for action in unit.legacy_actions:
        if donor_id not in action.dependencies or action.id in failed:
            continue
        position = action_positions.get(action.id)
        if position is None:
            raise ValueError(f"legacy consumer {action.id!r} has no action position")
        if position < earliest_failure:
            uncaptured_legacy.append(action.id)
    if uncaptured_legacy:
        raise ValueError(f"donor {donor_id!r} has uncaptured legacy consumers: {uncaptured_legacy}")
    if not failures[0].unit_donor_objects:
        return ()
    consumers: list[ClassicRepairRefusal] = []
    for function in unit.functions:
        if function.id in failed:
            continue
        position = action_positions.get(function.id)
        if position is None:
            raise ValueError(f"consumer {function.id!r} has no action position")
        if position >= earliest_failure:
            continue
        receipts = tuple(item for item in unit.receipts if item.intervention_id == function.id)
        if len(receipts) != 1:
            raise ValueError(f"consumer {function.id!r} requires one proof receipt")
        receipt = receipts[0]
        if donor_id not in classic_function_donor_ids(function, receipt):
            continue
        consumers.append(_consumer_refusal(unit, function, receipt, failures[0]))
    return tuple(consumers)


@dataclass(frozen=True, slots=True)
class RetunedActionReauthoring:
    """A consumer the retuned donor serves under a new record instead of its saved one.

    The candidate either emits the consumer's retail body or reaches it through
    a proved relational rewrite, but the saved family cannot compose that state.
    The saved record and receipt are replaced by the cheapest closed proof.
    """

    action: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    addition: ClassicRecordAddition
    saved_refusal: str


def _goal_body_digest(
    action: ClassicRecipeIntervention, receipt: ClassicProofReceipt
) -> str | None:
    try:
        return retail_body_goal_digest(action, receipt)
    except RetailRepairError:
        return None


def _reauthor_retuned_action(
    failure: RepairRefusal,
    materials: ClassicDispatchMaterials,
    saved_refusal: MeasuredPinRepairError,
    donor: ClassicPreparedDonor,
    materialized: MaterializedDonorRetuneCandidate,
    output: ClassicDonorProbeOutput,
) -> RetunedActionReauthoring | None:
    """Re-author a refused consumer when a closed proof reaches its retail body."""

    action = failure.intervention
    if (
        not isinstance(action, ClassicRecipeIntervention)
        or action.role is not ClassicRecipeRole.FUNCTION
        or action.symbol is None
        or not action.dependencies
        or not isinstance(materials.seed_object, bytes)
    ):
        return None
    if (
        isinstance(failure, ClassicRepairRefusal)
        and action.family is ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC
        and failure.retail_body is not None
    ):
        donor_id = donor.intervention.id
        donor_objects = dict(failure.unit_donor_objects)
        donor_objects[donor_id] = output.object_payload
        donor_interventions = {
            item.intervention.id: (
                materialized.intervention if item.intervention.id == donor_id else item.intervention
            )
            for item in failure.unit.donors
        }
        donor_sources = {
            item.intervention.id: (
                _rendered_source(donor, output)
                if item.intervention.id == donor_id
                else item.request.logical_outputs.get(failure.unit.plan.source)
            )
            for item in failure.unit.donors
        }
        donor_shapes = {
            item.intervention.id: (
                donor.request.carrier_identifiers
                if item.intervention.id == donor_id
                else item.request.carrier_identifiers
            )
            for item in failure.unit.donors
        }
        try:
            mosaic = reauthor_instruction_mosaic(
                action,
                failure.receipt,
                materials,
                failure.retail_body,
                donor_objects=donor_objects,
                donor_interventions=donor_interventions,
                donor_sources=donor_sources,
                donor_shape_identifiers=donor_shapes,
            )
        except MosaicRepairError:
            if instruction_mosaic_semantics_required(action):
                return None
        else:
            return RetunedActionReauthoring(
                action,
                failure.receipt,
                ClassicRecordAddition(
                    mosaic.intervention,
                    mosaic.receipt,
                    replaces_intervention_id=action.id,
                ),
                str(saved_refusal),
            )
    if instruction_mosaic_semantics_required(action):
        return None
    if isinstance(failure, ClassicRepairRefusal) and failure.retail_body is not None:
        try:
            relational = reauthor_relational_donor_rewriting(
                action,
                failure.receipt,
                materials,
                failure.retail_body,
                donor_id=donor.intervention.id,
                donor_object=output.object_payload,
                donor_source=_rendered_source(donor, output),
                shape_identifiers=donor.request.carrier_identifiers,
            )
        except RelationalRepairError:
            pass
        else:
            return RetunedActionReauthoring(
                action,
                failure.receipt,
                ClassicRecordAddition(
                    relational.intervention,
                    relational.receipt,
                    replaces_intervention_id=action.id,
                ),
                str(saved_refusal),
            )
    goal = _goal_body_digest(action, failure.receipt)
    if goal is None:
        return None
    try:
        candidate = CoffObject(output.object_payload)
        body = coff_body(candidate, candidate.function_section(action.symbol))
    except Exception:
        return None
    if sha256(bytes(body)).hexdigest() != goal:
        return None
    for family in REAUTHORABLE_FAMILIES:
        try:
            record = build_measured_function_record(
                target_id=action.scope.target,
                translation_unit_id=failure.unit_id,
                build_target=action.build_target,
                symbol=action.symbol,
                family=family,
                donor_id=donor.intervention.id,
                seed_object=materials.seed_object,
                donor_object=output.object_payload,
            )
        except DiscoveryAuthoringError:
            continue
        return RetunedActionReauthoring(
            action,
            failure.receipt,
            ClassicRecordAddition(
                record.intervention,
                record.receipt,
                replaces_intervention_id=action.id,
            ),
            str(saved_refusal),
        )
    return None


def validate_retuned_actions(
    failures: Sequence[RepairRefusal],
    donor: ClassicPreparedDonor,
    materialized: MaterializedDonorRetuneCandidate,
    output: ClassicDonorProbeOutput,
) -> tuple[MeasuredPinRepair | RetunedActionReauthoring | LegacyInstallRepair, ...]:
    """Replay the ordinary composer for every captured consumer failure.

    Callers pass the captured failures followed by the donor's other consumers
    (see :func:`other_consumers`), so a candidate that would break a function
    the donor still serves is refused rather than traded for the failing one.
    A consumer whose saved family refuses the candidate is re-authored when the
    candidate either emits its retail body or reaches it through a closed
    relational proof (:class:`RetunedActionReauthoring`).
    """

    repaired: list[MeasuredPinRepair | RetunedActionReauthoring | LegacyInstallRepair] = []
    for failure in failures:
        try:
            materials = _candidate_materials(failure, donor, materialized, output)
        except ValueError as exc:
            raise MeasuredPinRepairError(
                f"action {failure.intervention.id!r} rejected candidate: {exc}"
            ) from exc
        if isinstance(failure.intervention, LegacyOracleInstallIntervention):
            if failure.legacy_oracle is None or materials.donor_object is None:
                raise MeasuredPinRepairError(
                    f"action {failure.intervention.id!r} lacks its captured legacy oracle"
                )
            baseline = failure.baseline_repair
            try:
                candidate = reauthor_legacy_simulated_elision(
                    failure.intervention,
                    failure.receipt,
                    materials.seed_object,
                    materials.donor_object,
                    failure.legacy_oracle.retail_body,
                    failure.legacy_oracle.auxiliary_bodies,
                )
            except LegacyRepairError as exc:
                raise MeasuredPinRepairError(
                    f"action {failure.intervention.id!r} rejected candidate: {exc}",
                    stage="ordinary_validation",
                ) from exc
            if baseline is not None:
                candidate_cost = (
                    candidate.intervention.byte_count,
                    len(candidate.intervention.ranges),
                )
                baseline_cost = (
                    baseline.intervention.byte_count,
                    len(baseline.intervention.ranges),
                )
                if candidate_cost >= baseline_cost:
                    raise MeasuredPinRepairError(
                        f"action {failure.intervention.id!r} rejected candidate: legacy "
                        f"authority cost {candidate_cost} does not improve current safe cost "
                        f"{baseline_cost}",
                        stage="ordinary_validation",
                    )
            repaired.append(candidate)
            continue
        try:
            repaired.append(repair_measured_pins(failure.intervention, failure.receipt, materials))
        except MeasuredPinRepairError as exc:
            reauthored = _reauthor_retuned_action(
                failure, materials, exc, donor, materialized, output
            )
            if reauthored is None:
                raise MeasuredPinRepairError(
                    f"action {failure.intervention.id!r} rejected candidate: {exc}",
                    stage=exc.stage,
                ) from exc
            repaired.append(reauthored)
        except ValueError as exc:
            raise MeasuredPinRepairError(
                f"action {failure.intervention.id!r} rejected candidate: {exc}"
            ) from exc
    return tuple(repaired)


def retune_authority_edits(
    donor_before: ClassicPreparedDonor,
    donor_receipt: ClassicProofReceipt,
    failures: Sequence[RepairRefusal],
    materialized: MaterializedDonorRetuneCandidate,
    repaired: Sequence[MeasuredPinRepair | RetunedActionReauthoring | LegacyInstallRepair],
) -> tuple[
    tuple[ClassicInterventionEdit, ...],
    tuple[ClassicReceiptEdit, ...],
    tuple[ClassicRecordAddition, ...],
]:
    """Build exact typed edits after ordinary candidate admission.

    A re-authored consumer removes its saved record and receipt and adds the
    new record.  Its primary donor still names the same beneficiary; auxiliary
    donors that the replacement no longer uses are reconciled too.
    """

    retuned_id = donor_before.intervention.id
    intervention_edits: dict[str, ClassicInterventionEdit] = {
        retuned_id: ClassicInterventionEdit(donor_before.intervention, materialized.intervention),
    }
    receipts: dict[str, ClassicReceiptEdit] = {}
    additions: list[ClassicRecordAddition] = []
    beneficiary_state: dict[
        str,
        tuple[
            ClassicRecipeIntervention,
            set[tuple[str, str, str]],
            set[str],
        ],
    ] = {}

    def record_intervention(edit: ClassicInterventionEdit) -> None:
        previous = intervention_edits.get(edit.before.id)
        if previous is not None and previous != edit:
            raise ValueError(f"intervention {edit.before.id!r} produced conflicting repairs")
        intervention_edits[edit.before.id] = edit

    def record_receipt(edit: ClassicReceiptEdit) -> None:
        previous = receipts.get(edit.before.id)
        if previous is not None and previous != edit:
            raise ValueError(f"receipt {edit.before.id!r} produced conflicting repairs")
        receipts[edit.before.id] = edit

    def consumer_donors(
        unit: ClassicPreparedUnit,
        consumer: ClassicRecipeIntervention | LegacyOracleInstallIntervention,
    ) -> frozenset[str]:
        if (
            isinstance(consumer, ClassicRecipeIntervention)
            and consumer.role is ClassicRecipeRole.FUNCTION
        ):
            matches = tuple(item for item in unit.receipts if item.intervention_id == consumer.id)
            if len(matches) != 1:
                raise ValueError(f"consumer {consumer.id!r} requires one proof receipt")
            return classic_function_donor_ids(consumer, matches[0])
        return frozenset(consumer.dependencies)

    if materialized.receipt != donor_receipt:
        record_receipt(ClassicReceiptEdit(donor_receipt, materialized.receipt))
    for failure, result in zip(failures, repaired, strict=True):
        if isinstance(result, LegacyInstallRepair):
            if result.intervention.id != failure.intervention.id:
                raise ValueError(
                    f"legacy re-authoring of {result.intervention.id!r} does not answer "
                    f"{failure.intervention.id!r}"
                )
            # Save the donor first.  The next analysis pass re-authors the
            # existing legacy action from the now-current compiler object.
            continue
        if isinstance(result, RetunedActionReauthoring):
            if result.action.id != failure.intervention.id:
                raise ValueError(
                    f"re-authoring of {result.action.id!r} does not answer "
                    f"{failure.intervention.id!r}"
                )
            record_intervention(ClassicInterventionEdit(result.action, None))
            edit = ClassicReceiptEdit(result.receipt, None)
            additions.append(result.addition)
            before_donors = classic_function_donor_ids(result.action, result.receipt)
            after_donors = classic_function_donor_ids(
                result.addition.intervention,
                result.addition.receipt,
            )
            changed_donors = before_donors ^ after_donors
            unit_donors = {item.intervention.id: item.intervention for item in failure.unit.donors}
            unknown = changed_donors - unit_donors.keys()
            if unknown:
                raise ValueError(
                    f"function {result.action.id!r} names donors outside its prepared unit: "
                    f"{sorted(unknown)}"
                )
            key = (
                result.action.scope.target,
                result.action.scope.translation_unit or "",
                result.action.scope.function or "",
            )
            for donor_id in unit_donors:
                if donor_id not in changed_donors:
                    continue
                saved = unit_donors[donor_id]
                state = beneficiary_state.setdefault(
                    donor_id,
                    (
                        saved,
                        beneficiary_keys(saved),
                        {
                            consumer.id
                            for consumer in (
                                *failure.unit.actions,
                                *(item.intervention for item in failure.unit.donors),
                            )
                            if donor_id in consumer_donors(failure.unit, consumer)
                        },
                    ),
                )
                if state[0] != saved:
                    raise ValueError(f"donor {donor_id!r} has conflicting prepared authority")
                _saved, beneficiaries, consumers = state
                if donor_id in before_donors:
                    beneficiaries.discard(key)
                    consumers.discard(result.action.id)
                if donor_id in after_donors:
                    beneficiaries.add(key)
                    consumers.add(result.addition.intervention.id)
        else:
            if result.receipt == failure.receipt:
                continue
            edit = ClassicReceiptEdit(failure.receipt, result.receipt)
        record_receipt(edit)
    unit_receipts = {
        item.intervention_id: item for failure in failures for item in failure.unit.receipts
    }
    for donor_id, (saved, beneficiaries, consumers) in beneficiary_state.items():
        after = donor_after_usage(saved, beneficiaries, consumers)
        if after is saved:
            continue
        if after is None:
            if donor_id == retuned_id:
                if saved != donor_before.intervention:
                    raise ValueError(
                        f"retuned donor {donor_id!r} differs from its prepared authority"
                    )
                intervention_edits[donor_id] = ClassicInterventionEdit(
                    donor_before.intervention, None
                )
            else:
                record_intervention(ClassicInterventionEdit(saved, None))
            orphan_receipt = unit_receipts.get(donor_id)
            if donor_id == retuned_id and orphan_receipt is None:
                raise ValueError(f"retuned donor {donor_id!r} has no proof receipt")
            if orphan_receipt is not None:
                edit = ClassicReceiptEdit(orphan_receipt, None)
                if donor_id == retuned_id:
                    if orphan_receipt != donor_receipt:
                        raise ValueError(
                            f"retuned donor {donor_id!r} has conflicting proof authority"
                        )
                    receipts[edit.before.id] = edit
                else:
                    record_receipt(edit)
            continue
        if donor_id == retuned_id:
            if saved != donor_before.intervention:
                raise ValueError(f"retuned donor {donor_id!r} differs from its prepared authority")
            intervention_edits[donor_id] = ClassicInterventionEdit(
                donor_before.intervention,
                materialized.intervention.model_copy(update={"beneficiaries": after.beneficiaries}),
            )
        else:
            record_intervention(ClassicInterventionEdit(saved, after))
    added_ids = [item.intervention.id for item in additions]
    if len(set(added_ids)) != len(added_ids):
        raise ValueError("re-authored records repeat an identifier")
    return (
        tuple(intervention_edits.values()),
        tuple(receipts[key] for key in sorted(receipts, key=str.casefold)),
        tuple(additions),
    )


__all__ = [
    "RetunedActionReauthoring",
    "clone_retune_probe_unit",
    "other_consumers",
    "prepare_retune_candidate",
    "retune_authority_edits",
    "same_donor_compile_input",
    "validate_retuned_actions",
]
