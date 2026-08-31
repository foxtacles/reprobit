"""Bounded, non-certifying donor retuning for classic repair.

The service in this module consumes one already-prepared probe runtime.  It
renders every nearby donor candidate first, compiles the complete batch once,
and then admits only candidates accepted by the ordinary function composer.
It never issues runtime evidence or retries a whole project build.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from reprobit.classic.donor_retune_candidates import (
    DEFAULT_RETUNE_CANDIDATES,
    MAX_RETUNE_RADIUS,
    DonorRetuneChange,
    DonorRetuneError,
    enumerate_donor_retune_candidates,
)
from reprobit.classic.donor_retune_materialization import (
    MaterializedDonorRetuneCandidate,
)
from reprobit.classic.measured_pin_repair import MeasuredPinRepairError
from reprobit.classic.repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
)
from reprobit.classic.repair_probe_candidates import (
    clone_retune_probe_unit,
    prepare_retune_candidate,
    retune_authority_edits,
    same_donor_compile_input,
    validate_retuned_actions,
)
from reprobit.classic.repair_probe_execution import (
    ClassicDonorCompileOutcome,
    ClassicDonorCompileRefusal,
    probe_donor_compile_windows,
)
from reprobit.classic.repair_session import ClassicRepairRefusal
from reprobit.classic_donors import DonorSourceError
from reprobit.classic_orchestration import (
    ClassicPreparedDonor,
    ClassicPreparedUnit,
)
from reprobit.classic_runtime_probe import (
    ClassicDonorProbeOutput,
    ClassicDonorProbeProgress,
    ClassicProbeExecution,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeRole,
)

DEFAULT_RETUNE_PROBE_WINDOW = 8
MAX_RETUNE_PROBE_WINDOW = 16


class ClassicDonorRetuneProbeError(RuntimeError):
    """The requested repair probe is ambiguous or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneAttemptRefusal:
    """Why one bounded candidate was not eligible or did not compose."""

    distance: int
    changes: tuple[DonorRetuneChange, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneRepair:
    """Typed authority edits for one ordinarily validated donor retune."""

    unit_id: str
    donor_id: str
    action_ids: tuple[str, ...]
    distance: int
    changes: tuple[DonorRetuneChange, ...]
    intervention_edits: tuple[ClassicInterventionEdit, ...]
    receipt_edits: tuple[ClassicReceiptEdit, ...]
    attempts: int


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneRefusal:
    """A donor group for which no bounded candidate restored composition."""

    unit_id: str
    donor_id: str
    action_ids: tuple[str, ...]
    reason: str
    attempts: tuple[ClassicDonorRetuneAttemptRefusal, ...] = ()


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneProbeResult:
    """Complete deterministic result of one candidate batch."""

    repairs: tuple[ClassicDonorRetuneRepair, ...]
    refusals: tuple[ClassicDonorRetuneRefusal, ...]
    compiled_candidates: int


@dataclass(slots=True)
class _RepairGroup:
    unit: ClassicPreparedUnit
    donor: ClassicPreparedDonor
    donor_receipt: ClassicProofReceipt
    failures: tuple[ClassicRepairRefusal, ...]
    setup_refusals: list[ClassicDonorRetuneAttemptRefusal]

    @property
    def key(self) -> tuple[str, str]:
        return self.unit.plan.id, self.donor.intervention.id

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(item.intervention.id for item in self.failures)


@dataclass(frozen=True, slots=True)
class _PreparedAttempt:
    group_key: tuple[str, str]
    materialized: MaterializedDonorRetuneCandidate
    donor: ClassicPreparedDonor
    probe_id: str


def _one_donor(
    unit: ClassicPreparedUnit,
    donor_id: str,
) -> tuple[ClassicPreparedDonor, ClassicProofReceipt]:
    donors = tuple(item for item in unit.donors if item.intervention.id == donor_id)
    receipts = tuple(item for item in unit.receipts if item.intervention_id == donor_id)
    if len(donors) != 1 or len(receipts) != 1:
        raise ClassicDonorRetuneProbeError(
            f"classic donor {donor_id!r} requires one prepared request and one proof receipt"
        )
    return donors[0], receipts[0]


def _group_failures(refusals: Sequence[ClassicRepairRefusal]) -> tuple[_RepairGroup, ...]:
    grouped: dict[tuple[str, str], list[ClassicRepairRefusal]] = {}
    for refusal in refusals:
        action = refusal.intervention
        if action.role is not ClassicRecipeRole.FUNCTION or not action.dependencies:
            raise ClassicDonorRetuneProbeError(
                f"repair refusal {action.id!r} is not a classic function with a primary donor"
            )
        unit = refusal.unit
        if unit.plan.id != refusal.unit_id or action not in unit.actions:
            raise ClassicDonorRetuneProbeError(
                f"repair refusal {action.id!r} differs from its prepared TU authority"
            )
        donor_id = action.dependencies[0]
        grouped.setdefault((unit.plan.id, donor_id), []).append(refusal)

    result: list[_RepairGroup] = []
    for key in sorted(grouped, key=lambda item: (item[0].casefold(), item[1].casefold())):
        failures = tuple(
            sorted(
                grouped[key],
                key=lambda item: (item.action_index, item.intervention.id.casefold()),
            )
        )
        action_ids = [item.intervention.id for item in failures]
        if len(action_ids) != len(set(action_ids)):
            raise ClassicDonorRetuneProbeError(
                f"classic donor repair repeats failed actions: {action_ids}"
            )
        unit = failures[0].unit
        if any(item.unit != unit for item in failures[1:]):
            raise ClassicDonorRetuneProbeError(
                f"classic donor {key[1]!r} failures disagree about prepared TU authority"
            )
        donor, donor_receipt = _one_donor(unit, key[1])
        result.append(_RepairGroup(unit, donor, donor_receipt, failures, []))
    return tuple(result)


def _candidate_windows(
    attempts: tuple[_PreparedAttempt, ...],
    selected: Mapping[tuple[str, str], ClassicDonorRetuneRepair],
    *,
    window_size: int,
) -> Iterable[tuple[str, ...]]:
    """Yield fair lazy windows, dropping groups as soon as they are selected."""

    emitted: set[str] = set()
    for distance in sorted({item.materialized.distance for item in attempts}):
        by_group: dict[tuple[str, str], deque[str]] = {}
        for item in attempts:
            if item.materialized.distance == distance:
                queue = by_group.setdefault(item.group_key, deque())
                if item.probe_id not in queue:
                    queue.append(item.probe_id)
        group_keys = tuple(
            sorted(by_group, key=lambda item: (item[0].casefold(), item[1].casefold()))
        )
        while True:
            window: list[str] = []
            while len(window) < window_size:
                added = False
                for group_key in group_keys:
                    if group_key in selected:
                        continue
                    queue = by_group[group_key]
                    while queue and queue[0] in emitted:
                        queue.popleft()
                    if not queue:
                        continue
                    probe_id = queue.popleft()
                    emitted.add(probe_id)
                    window.append(probe_id)
                    added = True
                    if len(window) == window_size:
                        break
                if not added:
                    break
            if not window:
                break
            yield tuple(window)


def _probe_bounded_donor_retunes(
    probes: ClassicProbeExecution,
    refusals: Sequence[ClassicRepairRefusal],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
    radius: int = MAX_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
    window_size: int = DEFAULT_RETUNE_PROBE_WINDOW,
    progress: ClassicDonorProbeProgress | None = None,
) -> ClassicDonorRetuneProbeResult:
    """Compile deterministic distance tiers and select ordinarily valid retunes.

    Failed actions are grouped by translation unit and primary donor.  A
    candidate is selected only if the ordinary measured-pin repair/composer
    accepts every *captured* failed action in its group; callers must still
    continue the TU to expose later actions.  Candidate enumeration remains
    bounded by ``radius`` and ``limit`` per donor.  Nearby distance tiers run
    first in small windows, and outer tiers are requested only after cheaper
    candidates fail.  The supplied non-certifying probe runtime is consumed.
    """

    if type(window_size) is not int or not 1 <= window_size <= MAX_RETUNE_PROBE_WINDOW:
        raise ClassicDonorRetuneProbeError(
            f"window_size must be an integer from 1 to {MAX_RETUNE_PROBE_WINDOW}"
        )
    groups = _group_failures(refusals)
    if not groups:
        return ClassicDonorRetuneProbeResult((), (), 0)
    canonical = canonical_overlay_operations or {}
    by_key = {group.key: group for group in groups}
    attempts: list[_PreparedAttempt] = []
    compiler_seats: dict[tuple[str, str, str], _PreparedAttempt] = {}
    for group in groups:
        try:
            candidates = enumerate_donor_retune_candidates(
                group.donor.intervention,
                radius=radius,
                limit=limit,
            )
        except DonorRetuneError as exc:
            group.setup_refusals.append(ClassicDonorRetuneAttemptRefusal(0, (), str(exc)))
            continue
        for candidate in candidates:
            try:
                materialized, donor = prepare_retune_candidate(
                    group.unit,
                    group.donor,
                    group.donor_receipt,
                    candidate,
                    clean_sources=clean_sources,
                    effective_sources=effective_sources,
                    canonical_overlay_operations=canonical,
                )
            except (
                ClassicDonorRetuneProbeError,
                DonorRetuneError,
                DonorSourceError,
                ValueError,
            ) as exc:
                group.setup_refusals.append(
                    ClassicDonorRetuneAttemptRefusal(
                        candidate.distance,
                        candidate.changes,
                        f"candidate preparation failed: {exc}",
                    )
                )
                continue
            compiler_seat = (
                group.unit.plan.build_target.casefold(),
                group.unit.plan.source.casefold(),
                donor.request.compiler_seat.casefold(),
            )
            previous = compiler_seats.get(compiler_seat)
            if previous is not None:
                if (
                    previous.materialized.distance != materialized.distance
                    or not same_donor_compile_input(previous.donor, donor)
                ):
                    group.setup_refusals.append(
                        ClassicDonorRetuneAttemptRefusal(
                            candidate.distance,
                            candidate.changes,
                            "candidate compiler arena collides with a different bounded input",
                        )
                    )
                    continue
                probe_id = previous.probe_id
            else:
                probe_id = f"repair_probe_{len(compiler_seats):04d}"
            attempt = _PreparedAttempt(group.key, materialized, donor, probe_id)
            compiler_seats.setdefault(compiler_seat, attempt)
            attempts.append(attempt)

    if not attempts:
        unavailable = tuple(
            ClassicDonorRetuneRefusal(
                group.unit.plan.id,
                group.donor.intervention.id,
                group.action_ids,
                (
                    "donor family has no bounded retune candidates"
                    if not group.setup_refusals
                    else "no bounded donor candidate could be prepared"
                ),
                tuple(group.setup_refusals),
            )
            for group in groups
        )
        return ClassicDonorRetuneProbeResult((), unavailable, 0)

    attempt_tuple = tuple(attempts)
    attempts_by_id: dict[str, list[_PreparedAttempt]] = {}
    for attempt in attempt_tuple:
        attempts_by_id.setdefault(attempt.probe_id, []).append(attempt)
    rejected = {group.key: list(group.setup_refusals) for group in groups}
    compiled = {group.key: 0 for group in groups}
    selected: dict[tuple[str, str], ClassicDonorRetuneRepair] = {}
    compilable_groups = {item.group_key for item in attempt_tuple}

    def evaluate(outcomes: tuple[ClassicDonorCompileOutcome, ...]) -> bool:
        for outcome in outcomes:
            if not isinstance(outcome, (ClassicDonorProbeOutput, ClassicDonorCompileRefusal)):
                raise ClassicDonorRetuneProbeError(
                    "donor repair probe returned an invalid candidate outcome"
                )
            matching_attempts = attempts_by_id.get(outcome.donor_id)
            if matching_attempts is None:
                raise ClassicDonorRetuneProbeError(
                    f"donor repair probe returned unknown candidate {outcome.donor_id!r}"
                )
            for attempt in matching_attempts:
                group = by_key[attempt.group_key]
                compiled[group.key] += 1
                if group.key in selected:
                    continue
                if isinstance(outcome, ClassicDonorCompileRefusal):
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            f"candidate compiler rejected input: {outcome.reason}",
                        )
                    )
                    continue
                try:
                    repaired = validate_retuned_actions(
                        group.failures,
                        attempt.donor,
                        attempt.materialized,
                        outcome,
                    )
                    intervention_edits, receipt_edits = retune_authority_edits(
                        group.donor,
                        group.donor_receipt,
                        group.failures,
                        attempt.materialized,
                        repaired,
                    )
                except MeasuredPinRepairError as exc:
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            str(exc),
                        )
                    )
                    continue
                selected[group.key] = ClassicDonorRetuneRepair(
                    group.unit.plan.id,
                    group.donor.intervention.id,
                    group.action_ids,
                    attempt.materialized.distance,
                    attempt.materialized.changes,
                    intervention_edits,
                    receipt_edits,
                    len(rejected[group.key]) + 1,
                )
        return compilable_groups <= set(selected)

    canonical_attempts = tuple(values[0] for values in attempts_by_id.values())
    units = tuple(
        clone_retune_probe_unit(by_key[item.group_key].unit, item.donor, item.probe_id)
        for item in canonical_attempts
    )
    outcomes = probe_donor_compile_windows(
        probes,
        units,
        _candidate_windows(attempt_tuple, selected, window_size=window_size),
        evaluate=evaluate,
        progress=progress,
        planned_candidates=len(canonical_attempts),
    )

    repairs: list[ClassicDonorRetuneRepair] = []
    refusals_out: list[ClassicDonorRetuneRefusal] = []
    for group in groups:
        repair = selected.get(group.key)
        if repair is not None:
            repairs.append(repair)
            continue
        refusals_out.append(
            ClassicDonorRetuneRefusal(
                group.unit.plan.id,
                group.donor.intervention.id,
                group.action_ids,
                f"none of {compiled[group.key]} compiled candidates restored composition",
                tuple(rejected[group.key]),
            )
        )
    return ClassicDonorRetuneProbeResult(
        tuple(repairs),
        tuple(refusals_out),
        len(outcomes),
    )


def probe_bounded_donor_retunes(
    probes: ClassicProbeExecution,
    refusals: Sequence[ClassicRepairRefusal],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
    radius: int = MAX_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
    window_size: int = DEFAULT_RETUNE_PROBE_WINDOW,
    progress: ClassicDonorProbeProgress | None = None,
) -> ClassicDonorRetuneProbeResult:
    """Consume one prepared runtime while attempting bounded donor retunes."""

    try:
        result = _probe_bounded_donor_retunes(
            probes,
            refusals,
            clean_sources=clean_sources,
            effective_sources=effective_sources,
            canonical_overlay_operations=canonical_overlay_operations,
            radius=radius,
            limit=limit,
            window_size=window_size,
            progress=progress,
        )
    except BaseException as original:
        try:
            if probes.producer.is_open:
                probes.close()
        except BaseException as cleanup_error:
            original.add_note(f"classic donor retune cleanup also failed: {cleanup_error}")
        raise
    if probes.producer.is_open:
        probes.close()
    return result


__all__ = [
    "DEFAULT_RETUNE_PROBE_WINDOW",
    "MAX_RETUNE_PROBE_WINDOW",
    "ClassicDonorRetuneAttemptRefusal",
    "ClassicDonorRetuneProbeError",
    "ClassicDonorRetuneProbeResult",
    "ClassicDonorRetuneRefusal",
    "ClassicDonorRetuneRepair",
    "probe_bounded_donor_retunes",
]
