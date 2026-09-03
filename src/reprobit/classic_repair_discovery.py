"""Carrier-state discovery inside repair.

When a translation unit's saved donors cannot be retuned any further, the
functions they served are not lost: a fresh declaration-only carrier state may
emit the body a record needs.  This probe compiles new declaration shapes for
such a unit -- states none of its donors renders yet -- and inspects every
compiled object against every refused function of the unit:

* a body equal to the record's immutable ``expected_body_sha256`` goal lets the
  function be re-authored onto the new donor with the cheapest closed
  equal-body family the composer proves;
* a body equal to a rewriting record's pinned ``expected_donor_body_sha256``
  lets the saved record move onto the new donor unchanged, its donor-side
  measurements refreshed by the ordinary measured-pin repair.

Nothing here reads a reference image; the accepted objects become ordinary
donor records whose fresh compile and cold proof still decide everything.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256

from reprobit.classic_donors import (
    DonorSourceError,
    generate_declaration_shape,
    generate_forward_run,
    merge_candidate_constraints,
    prepare_donor_compile_request,
    validate_donor_recipe,
)
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError, repair_measured_pins
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_repair_authority import (
    ClassicDependencyEdit,
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
)
from reprobit.classic_repair_probe_cache import (
    ClassicDonorCompileOutcome,
    ClassicDonorCompileRefusal,
)
from reprobit.classic_repair_probe_candidates import clone_retune_probe_unit
from reprobit.classic_repair_probe_execution import (
    ClassicDonorCompileCache,
    probe_donor_compile_windows,
)
from reprobit.classic_repair_session import (
    ClassicRepairRefusal,
    dropped_move_parameters,
    repoint_refusal_materials,
    repointed_action,
)
from reprobit.classic_runtime_probe import (
    ClassicDonorProbeOutput,
    ClassicDonorProbeProgress,
    ClassicProbeExecution,
)
from reprobit.coff_format import CoffObject, coff_body
from reprobit.discovery_authoring import (
    REAUTHORABLE_FAMILIES,
    DiscoveryAuthoringError,
    build_declaration_shape_donor,
    build_measured_function_record,
)
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import canonical_json

DEFAULT_DISCOVERY_CANDIDATES = 64
# Every declaration shape (505) plus forward declaration runs of 1..500 declarations
# at each of the three placements (1500): the closed carrier states discovery may try.
MAX_DISCOVERY_CANDIDATES = 2005
DEFAULT_DISCOVERY_WINDOW = 8
_FORWARD_RUN_PREFIX = "RbDsc"
_FORWARD_RUN_WIDTH = 3
_FORWARD_RUN_PLACEMENTS = ("suffix", "prefix", "after_includes")
_FORWARD_RUN_RATIONALE = (
    "Framework-generated declaration-only compiler-state carrier rendered with the translation "
    "unit; it contributes no code, data, strings, vtables, or linker directives."
)


class ClassicDiscoveryProbeError(RuntimeError):
    """The discovery request is inconsistent with the captured refusals."""


@dataclass(frozen=True, slots=True)
class ClassicDiscoveryResolution:
    """How one refused function was settled by a discovered carrier state."""

    action_id: str
    symbol: str
    donor_id: str
    how: str  # "reauthor" or "repoint"
    family: str


@dataclass(frozen=True, slots=True)
class ClassicDiscoveryRepair:
    """Typed authority changes for one translation unit."""

    unit_id: str
    resolutions: tuple[ClassicDiscoveryResolution, ...]
    additions: tuple[ClassicRecordAddition, ...]
    intervention_edits: tuple[ClassicInterventionEdit, ...]
    receipt_edits: tuple[ClassicReceiptEdit, ...]
    dependency_edits: tuple[ClassicDependencyEdit, ...]


@dataclass(frozen=True, slots=True)
class ClassicDiscoveryResult:
    repairs: tuple[ClassicDiscoveryRepair, ...]
    unresolved: tuple[tuple[str, str, str], ...]
    """``(unit_id, action_id, reason)`` for refusals no compiled state settled."""
    compiled_candidates: int
    tried_states: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Per unit, the generated-header digests of every shape this probe compiled."""


@dataclass(slots=True)
class _UnitWork:
    unit: ClassicPreparedUnit
    refusals: list[ClassicRepairRefusal]
    attempts: list[tuple[str, ClassicRecipeIntervention, ClassicPreparedDonor]]
    resolved: dict[str, tuple[ClassicDiscoveryResolution, object]]
    kept_donors: dict[str, ClassicRecipeIntervention]
    reasons: dict[str, str]
    receipts: dict[str, ClassicProofReceipt] = field(default_factory=dict)
    identities: dict[str, str] = field(default_factory=dict)


def _shape_states() -> list[tuple[int, int]]:
    states = [(c, f) for c in range(1, 11) for f in range(c, 10 * c + 1)]
    states.sort(key=lambda item: (item[0] + item[1], item[0]))
    return states


def _carrier_states() -> list[tuple[str, tuple[int, int] | tuple[str, int]]]:
    """Every discovery state cheapest-first: shapes, then forward runs by count."""

    states: list[tuple[str, tuple[int, int] | tuple[str, int]]] = [
        ("shape", shape) for shape in _shape_states()
    ]
    for count in range(1, 501):
        for placement in _FORWARD_RUN_PLACEMENTS:
            states.append(("forward_run", (placement, count)))
    return states


def _state_identity(kind: str, generated: bytes, placement: str = "") -> str:
    """One string naming a carrier state: family, placement and generated-header digest."""

    return f"{kind}:{placement}:{Digest.from_bytes(generated).value}"


def _forward_run_donor(
    unit: ClassicPreparedUnit, placement: str, count: int
) -> tuple[ClassicRecipeIntervention, ClassicProofReceipt]:
    generated = generate_forward_run(_FORWARD_RUN_PREFIX, count, _FORWARD_RUN_WIDTH)
    parameters: dict[str, object] = {
        "count": count,
        "emission_policy": "non_emitting_declarations_only",
        "generated_header_sha256": Digest.from_bytes(generated).value,
        "placement": placement,
        "prefix": _FORWARD_RUN_PREFIX,
        "width": _FORWARD_RUN_WIDTH,
    }
    donor_id = (
        "discovery.donor."
        + Digest.from_bytes(
            canonical_json(
                {
                    "build_target": unit.plan.build_target,
                    "family": ClassicRecipeFamily.FORWARD_DECLARATION_RUN.value,
                    "parameters": parameters,
                    "target_id": unit.plan.target_id,
                    "translation_unit_id": unit.plan.id,
                }
            )
        ).value[:16]
    )
    intervention = ClassicRecipeIntervention(
        id=donor_id,
        scope=Scope(target=unit.plan.target_id, translation_unit=unit.plan.id),
        rationale=_FORWARD_RUN_RATIONALE,
        family=ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
        role=ClassicRecipeRole.DONOR,
        build_target=unit.plan.build_target,
        parameters=tuple(
            ClassicField(name=name, value=value)  # type: ignore[arg-type]
            for name, value in sorted(parameters.items())
        ),
    )
    receipt = ClassicProofReceipt(
        id="discovery.proof." + Digest.from_bytes(canonical_json({"donor": donor_id})).value[:16],
        intervention_id=donor_id,
        family=ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
    )
    validate_donor_recipe(intervention, merge_candidate_constraints(intervention, receipt))
    return intervention, receipt


def _existing_state_identities(unit: ClassicPreparedUnit) -> set[str]:
    """Identities of the carrier states the unit's saved donors already render."""

    identities: set[str] = set()
    for item in unit.donors:
        values = {parameter.name: parameter.value for parameter in item.intervention.parameters}
        digest = values.get("generated_header_sha256")
        if not isinstance(digest, str):
            continue
        if item.intervention.family is ClassicRecipeFamily.DECLARATION_SHAPE:
            identities.add(f"shape::{digest}")
        elif item.intervention.family is ClassicRecipeFamily.FORWARD_DECLARATION_RUN:
            identities.add(f"forward_run:{values.get('placement')}:{digest}")
        else:
            identities.add(f"{item.intervention.family.value}::{digest}")
    return identities


def _body_digest(payload: bytes, symbol: str) -> str | None:
    try:
        obj = CoffObject(payload)
        return sha256(bytes(coff_body(obj, obj.function_section(symbol)))).hexdigest()
    except Exception:
        return None


def _digest_pin(receipt: ClassicProofReceipt, key: str) -> str | None:
    value = receipt.expected_values.get(key)
    return value if isinstance(value, str) and len(value) == 64 else None


def _group_units(
    refusals: Sequence[ClassicRepairRefusal],
) -> dict[str, _UnitWork]:
    work: dict[str, _UnitWork] = {}
    for refusal in refusals:
        action = refusal.intervention
        if action.role is not ClassicRecipeRole.FUNCTION or not action.dependencies:
            raise ClassicDiscoveryProbeError(
                f"discovery refusal {action.id!r} is not a classic function with a primary donor"
            )
        entry = work.setdefault(refusal.unit_id, _UnitWork(refusal.unit, [], [], {}, {}, {}))
        if entry.unit != refusal.unit:
            raise ClassicDiscoveryProbeError(
                f"discovery refusals for {refusal.unit_id!r} disagree about prepared TU authority"
            )
        entry.refusals.append(refusal)
    return work


def _prepare_attempts(
    work: Mapping[str, _UnitWork],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    per_unit: int,
    tried_states: Mapping[str, frozenset[str]] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Build candidate donors per unit; return (probe_id, unit_id) in fair order.

    Shapes another donor of the unit already renders, and shapes this command
    already compiled for the unit (``tried_states``), are skipped.
    """

    ordinal = 0
    per_unit_ids: dict[str, list[str]] = {}
    for unit_id, entry in sorted(work.items(), key=lambda item: item[0].casefold()):
        unit = entry.unit
        source = unit.plan.source
        clean = clean_sources.get(source)
        effective = effective_sources.get(source)
        if clean is None or effective is None:
            raise ClassicDiscoveryProbeError(f"authenticated source is absent: {source!r}")
        taken = _existing_state_identities(unit) | set(
            (tried_states or {}).get(unit_id, frozenset())
        )
        # Two states can render the same private compiler inputs (a forward run
        # placed after the includes of a source without any, say); one arena is
        # one candidate, so the later state is skipped rather than compiled twice.
        seats = {item.request.compiler_seat.casefold() for item in unit.donors}
        ids: list[str] = []
        for kind, state in _carrier_states():
            if len(ids) >= per_unit:
                break
            try:
                if kind == "shape":
                    classes, functions = int(state[0]), int(state[1])
                    identity = _state_identity(kind, generate_declaration_shape(classes, functions))
                    if identity in taken:
                        continue
                    record = build_declaration_shape_donor(
                        target_id=unit.plan.target_id,
                        translation_unit_id=unit.plan.id,
                        build_target=unit.plan.build_target,
                        classes=classes,
                        functions=functions,
                    )
                    intervention, receipt = record.intervention, record.receipt
                else:
                    placement, count = str(state[0]), int(state[1])
                    identity = _state_identity(
                        kind,
                        generate_forward_run(_FORWARD_RUN_PREFIX, count, _FORWARD_RUN_WIDTH),
                        placement,
                    )
                    if identity in taken:
                        continue
                    intervention, receipt = _forward_run_donor(unit, placement, count)
                request = prepare_donor_compile_request(
                    intervention,
                    source_path=source,
                    clean_source=clean,
                    effective_source=effective,
                    receipts=(receipt,),
                )
            except (DiscoveryAuthoringError, DonorSourceError, ValueError) as exc:
                entry.reasons.setdefault("preparation", str(exc))
                continue
            seat = request.compiler_seat.casefold()
            if seat in seats:
                continue
            seats.add(seat)
            probe_id = f"discovery_probe_{ordinal:04d}"
            ordinal += 1
            entry.attempts.append(
                (probe_id, intervention, ClassicPreparedDonor(intervention, request))
            )
            entry.receipts[intervention.id] = receipt
            entry.identities[probe_id] = identity
            ids.append(probe_id)
        per_unit_ids[unit_id] = ids
    order: list[tuple[str, str]] = []
    longest = max((len(ids) for ids in per_unit_ids.values()), default=0)
    for index in range(longest):
        for unit_id in sorted(per_unit_ids, key=str.casefold):
            ids = per_unit_ids[unit_id]
            if index < len(ids):
                order.append((ids[index], unit_id))
    return tuple(order)


def _try_resolve(
    entry: _UnitWork,
    refusal: ClassicRepairRefusal,
    donor: ClassicRecipeIntervention,
    payload: bytes,
) -> tuple[ClassicDiscoveryResolution, object] | None:
    action = refusal.intervention
    symbol = action.symbol or ""
    body = _body_digest(payload, symbol)
    if body is None:
        return None
    goal = _digest_pin(refusal.receipt, "expected_body_sha256")
    # A rewriting witness pins its donor body; a cross-file resize pins the body of
    # the same-file target donor its primary dependency names.
    donor_goal = _digest_pin(refusal.receipt, "expected_donor_body_sha256") or _digest_pin(
        refusal.receipt, "expected_target_donor_body_sha256"
    )
    if goal is not None and body == goal:
        for family in REAUTHORABLE_FAMILIES:
            try:
                record = build_measured_function_record(
                    target_id=action.scope.target,
                    translation_unit_id=refusal.unit_id,
                    build_target=action.build_target,
                    symbol=symbol,
                    family=family,
                    donor_id=donor.id,
                    seed_object=refusal.materials.seed_object,
                    donor_object=payload,
                )
            except DiscoveryAuthoringError as exc:
                entry.reasons[action.id] = f"{family.value}: {exc}"
                continue
            return (
                ClassicDiscoveryResolution(action.id, symbol, donor.id, "reauthor", family.value),
                ClassicRecordAddition(record.intervention, record.receipt),
            )
    # The record's own family may still compose from the new donor: a body that
    # is the goal but that no closed equal-body family can host (the seed changed
    # length, say), or a rewriting witness body, moves the saved record over.
    if (goal is not None and body == goal) or (
        donor_goal is not None and donor_goal != goal and body == donor_goal
    ):
        moved = repointed_action(action, donor.id)
        try:
            repaired = repair_measured_pins(
                moved,
                refusal.receipt,
                repoint_refusal_materials(refusal, donor.id, payload),
            )
        except MeasuredPinRepairError as exc:
            entry.reasons[action.id] = f"re-point onto {donor.id}: {exc}"
            return None
        return (
            ClassicDiscoveryResolution(action.id, symbol, donor.id, "repoint", action.family.value),
            (repaired.receipt, moved),
        )
    return None


def _unit_repair(entry: _UnitWork) -> ClassicDiscoveryRepair | None:
    if not entry.resolved:
        return None
    unit = entry.unit
    target_id = unit.plan.target_id
    receipts = {item.intervention_id: item for item in unit.receipts}
    donor_beneficiaries: dict[str, set[str]] = {donor_id: set() for donor_id in entry.kept_donors}
    saved_donors = {item.intervention.id: item.intervention for item in unit.donors}
    saved_beneficiaries = {
        donor_id: {scope.function or "" for scope in saved.beneficiaries}
        for donor_id, saved in saved_donors.items()
    }
    consumers = {
        donor_id: {f.id for f in unit.functions if donor_id in f.dependencies}
        for donor_id in saved_donors
    }
    additions: list[ClassicRecordAddition] = []
    intervention_edits: list[ClassicInterventionEdit] = []
    receipt_edits: list[ClassicReceiptEdit] = []
    dependency_edits: list[ClassicDependencyEdit] = []
    resolutions: list[ClassicDiscoveryResolution] = []
    for refusal in entry.refusals:
        action = refusal.intervention
        settled = entry.resolved.get(action.id)
        if settled is None:
            continue
        resolution, product = settled
        resolutions.append(resolution)
        previous = action.dependencies[0]
        symbol = action.symbol or ""
        donor_beneficiaries[resolution.donor_id].add(symbol)
        if resolution.how == "reauthor":
            assert isinstance(product, ClassicRecordAddition)
            additions.append(product)
            intervention_edits.append(ClassicInterventionEdit(action, None))
            old_receipt = receipts.get(action.id)
            if old_receipt is None:
                raise ClassicDiscoveryProbeError(f"refused action {action.id!r} has no receipt")
            receipt_edits.append(ClassicReceiptEdit(old_receipt, None))
            consumers[previous].discard(action.id)
        else:
            assert isinstance(product, tuple)
            repaired_receipt, _moved = product
            assert isinstance(repaired_receipt, ClassicProofReceipt)
            dependency_edits.append(
                ClassicDependencyEdit(action, resolution.donor_id, dropped_move_parameters(action))
            )
            if repaired_receipt != refusal.receipt:
                receipt_edits.append(ClassicReceiptEdit(refusal.receipt, repaired_receipt))
            consumers[previous].discard(action.id)
        saved_beneficiaries[previous].discard(symbol)
    for donor_id, donor in entry.kept_donors.items():
        scopes = tuple(
            Scope(target=target_id, translation_unit=unit.plan.id, function=symbol)
            for symbol in sorted(donor_beneficiaries[donor_id])
        )
        receipt = entry.receipts.get(donor_id)
        if receipt is None:
            raise ClassicDiscoveryProbeError(f"discovered donor {donor_id!r} lost its receipt")
        additions.append(
            ClassicRecordAddition(donor.model_copy(update={"beneficiaries": scopes}), receipt)
        )
    for donor_id, saved in saved_donors.items():
        before = {scope.function or "" for scope in saved.beneficiaries}
        if saved_beneficiaries[donor_id] == before:
            continue
        if not consumers[donor_id] and not saved_beneficiaries[donor_id]:
            intervention_edits.append(ClassicInterventionEdit(saved, None))
            donor_receipt = receipts.get(donor_id)
            if donor_receipt is not None:
                receipt_edits.append(ClassicReceiptEdit(donor_receipt, None))
            continue
        scopes = tuple(
            Scope(target=target_id, translation_unit=unit.plan.id, function=symbol)
            for symbol in sorted(saved_beneficiaries[donor_id])
        )
        intervention_edits.append(
            ClassicInterventionEdit(saved, saved.model_copy(update={"beneficiaries": scopes}))
        )
    return ClassicDiscoveryRepair(
        unit.plan.id,
        tuple(resolutions),
        tuple(additions),
        tuple(intervention_edits),
        tuple(receipt_edits),
        tuple(dependency_edits),
    )


def probe_carrier_discovery(
    probes: ClassicProbeExecution,
    refusals: Sequence[ClassicRepairRefusal],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    per_unit: int = DEFAULT_DISCOVERY_CANDIDATES,
    candidate_budget: int = MAX_DISCOVERY_CANDIDATES,
    window_size: int = DEFAULT_DISCOVERY_WINDOW,
    progress: ClassicDonorProbeProgress | None = None,
    tried_states: Mapping[str, frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
) -> ClassicDiscoveryResult:
    """Compile fresh carrier states per unit until every refusal is settled or bounded out.

    ``tried_states`` carries the shapes earlier rounds of the same command compiled
    for each unit; they are not compiled again.  The result reports every shape
    compiled now so the caller can extend that memory.
    """

    if type(per_unit) is not int or not 1 <= per_unit <= MAX_DISCOVERY_CANDIDATES:
        raise ClassicDiscoveryProbeError(
            f"per_unit must be an integer from 1 to {MAX_DISCOVERY_CANDIDATES}"
        )
    try:
        work = _group_units(refusals)
        if not work:
            return ClassicDiscoveryResult((), (), 0)
        order = _prepare_attempts(
            work,
            clean_sources=clean_sources,
            effective_sources=effective_sources,
            per_unit=per_unit,
            tried_states=tried_states,
        )
        attempts = {
            probe_id: (unit_id, donor, prepared)
            for unit_id, entry in work.items()
            for probe_id, donor, prepared in entry.attempts
        }
        if not attempts:
            unprepared = tuple(
                (unit_id, refusal.intervention.id, entry.reasons.get("preparation", "no state"))
                for unit_id, entry in work.items()
                for refusal in entry.refusals
            )
            if probes.producer.is_open:
                probes.close()
            return ClassicDiscoveryResult((), unprepared, 0)
        budget = min(candidate_budget, len(order))
        order = order[:budget]

        def windows() -> Iterable[tuple[str, ...]]:
            pending = [probe_id for probe_id, _unit_id in order]
            while pending:
                window = tuple(
                    probe_id
                    for probe_id in pending[:window_size]
                    if any(
                        refusal.intervention.id not in work[attempts[probe_id][0]].resolved
                        for refusal in work[attempts[probe_id][0]].refusals
                    )
                )
                pending = pending[window_size:]
                if window:
                    yield window

        def evaluate(outcomes: tuple[ClassicDonorCompileOutcome, ...]) -> bool:
            for outcome in outcomes:
                unit_id, donor, _prepared = attempts[outcome.donor_id]
                entry = work[unit_id]
                if isinstance(outcome, ClassicDonorCompileRefusal):
                    entry.reasons.setdefault("compilation", outcome.reason)
                    continue
                if not isinstance(outcome, ClassicDonorProbeOutput):
                    raise ClassicDiscoveryProbeError("discovery probe returned an invalid outcome")
                for refusal in entry.refusals:
                    if refusal.intervention.id in entry.resolved:
                        continue
                    settled = _try_resolve(entry, refusal, donor, outcome.object_payload)
                    if settled is not None:
                        entry.resolved[refusal.intervention.id] = settled
                        entry.kept_donors.setdefault(donor.id, donor)
            return all(
                refusal.intervention.id in entry.resolved
                for entry in work.values()
                for refusal in entry.refusals
            )

        units = tuple(
            clone_retune_probe_unit(work[unit_id].unit, prepared, probe_id)
            for probe_id, (unit_id, _donor, prepared) in attempts.items()
            if probe_id in {item[0] for item in order}
        )
        outcomes = probe_donor_compile_windows(
            probes,
            units,
            windows(),
            evaluate=evaluate,
            progress=progress,
            planned_candidates=len(order),
            cache=compile_cache,
        )
    except BaseException as original:
        try:
            if probes.producer.is_open:
                probes.close()
        except BaseException as cleanup_error:
            original.add_note(f"classic discovery cleanup also failed: {cleanup_error}")
        raise
    if probes.producer.is_open:
        probes.close()
    compiled_ids = {outcome.donor_id for outcome in outcomes}
    tried: dict[str, set[str]] = {}
    for probe_id, (unit_id, _donor, _prepared) in attempts.items():
        if probe_id in compiled_ids:
            tried.setdefault(unit_id, set()).add(work[unit_id].identities[probe_id])
    repairs: list[ClassicDiscoveryRepair] = []
    unresolved: list[tuple[str, str, str]] = []
    for unit_id, entry in sorted(work.items(), key=lambda item: item[0].casefold()):
        repair = _unit_repair(entry)
        if repair is not None:
            repairs.append(repair)
        for refusal in entry.refusals:
            if refusal.intervention.id not in entry.resolved:
                unresolved.append(
                    (
                        unit_id,
                        refusal.intervention.id,
                        entry.reasons.get(refusal.intervention.id)
                        or entry.reasons.get("compilation")
                        or "no compiled declaration shape carried the record's body",
                    )
                )
    return ClassicDiscoveryResult(
        tuple(repairs),
        tuple(unresolved),
        len(outcomes),
        {unit_id: frozenset(values) for unit_id, values in tried.items()},
    )


__all__ = [
    "DEFAULT_DISCOVERY_CANDIDATES",
    "MAX_DISCOVERY_CANDIDATES",
    "ClassicDiscoveryProbeError",
    "ClassicDiscoveryRepair",
    "ClassicDiscoveryResolution",
    "ClassicDiscoveryResult",
    "probe_carrier_discovery",
]
