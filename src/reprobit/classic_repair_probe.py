"""Bounded, non-certifying donor retuning for classic repair.

The service in this module consumes one already-prepared probe runtime.  It
renders every nearby donor candidate first, compiles the complete batch once,
and then admits only candidates accepted by the ordinary function composer.
It never issues runtime evidence or retries a whole project build.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession
from reprobit.classic_donor_retune_candidates import (
    DEFAULT_REPAIR_RETUNE_RADIUS,
    DEFAULT_RETUNE_CANDIDATES,
    DonorRetuneChange,
    DonorRetuneError,
    enumerate_donor_retune_candidates,
)
from reprobit.classic_donor_retune_materialization import (
    MaterializedDonorRetuneCandidate,
)
from reprobit.classic_donors import DonorSourceError
from reprobit.classic_measured_pin_repair import MeasuredPinRepairError
from reprobit.classic_orchestration import (
    ClassicPreparedDonor,
    ClassicPreparedUnit,
)
from reprobit.classic_repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
)
from reprobit.classic_repair_probe_cache import (
    ClassicDonorCompileOutcome,
    ClassicDonorCompileRefusal,
)
from reprobit.classic_repair_probe_candidates import (
    clone_retune_probe_unit,
    other_consumers,
    prepare_retune_candidate,
    retune_authority_edits,
    same_donor_compile_input,
    validate_retuned_actions,
)
from reprobit.classic_repair_probe_execution import (
    ClassicDonorCompileCache,
    ClassicDonorSourceSeal,
    probe_donor_compile_windows,
)
from reprobit.classic_repair_session import ClassicRepairRefusal, RepairRefusal
from reprobit.classic_runtime_probe import (
    ClassicDonorProbeOutput,
    ClassicDonorProbeProgress,
    ClassicProbeExecution,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    LegacyOracleInstallIntervention,
    classic_function_donor_ids,
)
from reprobit.strict_json import canonical_json

DEFAULT_RETUNE_PROBE_WINDOW = 8
MAX_RETUNE_PROBE_WINDOW = 16
DEFAULT_RETUNE_PROBE_CANDIDATES = 256
MAX_RETUNE_PROBE_CANDIDATES = 65536


class ClassicDonorRetuneProbeError(RuntimeError):
    """The requested repair probe is ambiguous or internally inconsistent."""


ClassicDonorRetuneAttemptStage = Literal[
    "preparation",
    "compilation",
    "measurement",
    "ordinary_validation",
]

_ATTEMPT_STAGE_RANK: dict[ClassicDonorRetuneAttemptStage, int] = {
    "preparation": 0,
    "compilation": 1,
    "measurement": 2,
    "ordinary_validation": 3,
}


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneAttemptRefusal:
    """Why one bounded candidate was not eligible or did not compose."""

    distance: int
    changes: tuple[DonorRetuneChange, ...]
    stage: ClassicDonorRetuneAttemptStage
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
    compiler_seat: str = ""
    abandoned_state: str = ""
    """Canonical parameters of the donor state this repair moves away from."""
    move_signature: str = ""
    """Family and knob deltas of the accepted move; see :func:`_move_signature`."""
    additions: tuple[ClassicRecordAddition, ...] = ()
    """Records re-authored onto the retuned donor because their saved family refused the state."""


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneRefusal:
    """A donor group for which no bounded candidate restored composition."""

    unit_id: str
    donor_id: str
    action_ids: tuple[str, ...]
    compiled_candidates: int
    reason: str
    attempts: tuple[ClassicDonorRetuneAttemptRefusal, ...] = ()
    exhausted: bool = False
    """Every bounded candidate of this donor was tried; nothing was left untried by budget."""

    @property
    def best_attempt(self) -> ClassicDonorRetuneAttemptRefusal | None:
        """Return the candidate that reached the strongest deterministic check."""

        if not self.attempts:
            return None
        _index, attempt = min(
            enumerate(self.attempts),
            key=lambda item: (
                -_ATTEMPT_STAGE_RANK[item[1].stage],
                item[1].distance,
                item[0],
            ),
        )
        return attempt


@dataclass(frozen=True, slots=True)
class ClassicDonorRetuneProbeResult:
    """Complete deterministic result of one candidate batch."""

    repairs: tuple[ClassicDonorRetuneRepair, ...]
    refusals: tuple[ClassicDonorRetuneRefusal, ...]
    compiled_candidates: int

    @property
    def best_refusal(self) -> ClassicDonorRetuneRefusal | None:
        """Return the refusal with the most useful deterministic candidate result."""

        if not self.refusals:
            return None

        def key(item: tuple[int, ClassicDonorRetuneRefusal]) -> tuple[int, int, int]:
            index, refusal = item
            attempt = refusal.best_attempt
            if attempt is None:
                return (1, 0, index)
            return (
                -_ATTEMPT_STAGE_RANK[attempt.stage],
                attempt.distance,
                index,
            )

        _index, refusal = min(enumerate(self.refusals), key=key)
        return refusal


@dataclass(slots=True)
class _RepairGroup:
    unit: ClassicPreparedUnit
    donor: ClassicPreparedDonor
    donor_receipt: ClassicProofReceipt
    failures: tuple[RepairRefusal, ...]
    setup_refusals: list[ClassicDonorRetuneAttemptRefusal]
    consumers: tuple[ClassicRepairRefusal, ...] = ()
    """The donor's currently composing consumers, validated with every candidate."""
    donor_rank: int = 0
    """Primary donors sort before canonical auxiliary alternatives."""

    @property
    def key(self) -> tuple[str, str]:
        return self.unit.plan.id, self.donor.intervention.id

    @property
    def validated(self) -> tuple[RepairRefusal, ...]:
        return (*self.failures, *self.consumers)

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(item.intervention.id for item in self.failures)


@dataclass(frozen=True, slots=True)
class _PreparedAttempt:
    group_key: tuple[str, str]
    materialized: MaterializedDonorRetuneCandidate
    donor: ClassicPreparedDonor
    probe_id: str
    donor_rank: int = 0


def _move_signature(family: str, changes: Iterable[DonorRetuneChange]) -> str:
    """Name a retune move by its family and knob deltas, independent of the donor.

    A shared-header edit disturbs every translation unit the same way, so the
    move that restored one donor (``functions +1`` of a declaration shape, say)
    is the best first guess for every other donor of that family.  Item indices
    and derived changes are left out; an empty string names no move.
    """

    knobs: list[str] = []
    for change in changes:
        if change.kind == "insert":
            try:
                operation = json.loads(str(change.after))
                placement = str(operation["anchor"]["at"])
                count = int(operation["gen"]["lines"])
            except (KeyError, TypeError, ValueError):
                continue
            knobs.append(f"insert.{placement}+{count}")
            continue
        if change.kind != "knob":
            continue
        key = next((str(part) for part in reversed(change.path) if isinstance(part, str)), "")
        if "members" in change.path:
            key = f"members.{key}"
        if isinstance(change.before, int) and isinstance(change.after, int):
            knobs.append(f"{key}{change.after - change.before:+d}")
        else:
            knobs.append(f"{key}={change.after}")
    if not knobs:
        return ""
    return f"{family}|" + ",".join(sorted(knobs))


def _parameter_payload(intervention: ClassicRecipeIntervention) -> str:
    """Canonical text of a donor's parameters, the identity of one carrier state."""

    payload = canonical_json([[field.name, field.value] for field in intervention.parameters])
    return payload.decode()


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


def _retunable_donor_ids(refusal: RepairRefusal) -> tuple[str, ...]:
    """Return the primary donor followed by canonical auxiliary alternatives."""

    action = refusal.intervention
    if not action.dependencies:
        return ()
    primary = action.dependencies[0]
    if isinstance(action, LegacyOracleInstallIntervention):
        return (primary,)
    try:
        donor_ids = classic_function_donor_ids(action, refusal.receipt)
    except ValueError as exc:
        raise ClassicDonorRetuneProbeError(
            f"repair refusal {action.id!r} has an invalid donor graph: {exc}"
        ) from exc
    return (
        primary,
        *sorted(donor_ids - {primary}, key=lambda item: (item.casefold(), item)),
    )


def _group_failures(
    refusals: Sequence[RepairRefusal],
    *,
    excluded_groups: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[_RepairGroup, ...]:
    grouped: dict[tuple[str, str], list[RepairRefusal]] = {}
    donor_ranks: dict[tuple[str, str], int] = {}
    for refusal in refusals:
        action = refusal.intervention
        if (
            not isinstance(action, LegacyOracleInstallIntervention)
            and action.role is not ClassicRecipeRole.FUNCTION
        ) or not action.dependencies:
            raise ClassicDonorRetuneProbeError(
                f"repair refusal {action.id!r} has no retunable primary donor"
            )
        unit = refusal.unit
        if unit.plan.id != refusal.unit_id or action not in unit.actions:
            raise ClassicDonorRetuneProbeError(
                f"repair refusal {action.id!r} differs from its prepared TU authority"
            )
        for donor_rank, donor_id in enumerate(_retunable_donor_ids(refusal)):
            key = (unit.plan.id, donor_id)
            if key in excluded_groups:
                continue
            grouped.setdefault(key, []).append(refusal)
            donor_ranks[key] = min(donor_rank, donor_ranks.get(key, donor_rank))

    result: list[_RepairGroup] = []
    for key in sorted(
        grouped,
        key=lambda item: (
            item[0].casefold(),
            donor_ranks[item],
            item[1].casefold(),
            item[1],
        ),
    ):
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
        try:
            consumers = other_consumers(unit, key[1], failures)
        except ValueError as exc:
            raise ClassicDonorRetuneProbeError(
                f"classic donor {key[1]!r} consumers cannot be described: {exc}"
            ) from exc
        result.append(
            _RepairGroup(
                unit,
                donor,
                donor_receipt,
                failures,
                [],
                consumers,
                donor_ranks[key],
            )
        )
    return tuple(result)


def _occupying_donor(group: _RepairGroup, compiler_seat: str) -> str | None:
    """The other donor of the unit whose saved state already renders ``compiler_seat``."""

    for item in group.unit.donors:
        if item.intervention.id == group.donor.intervention.id:
            continue
        if item.request.compiler_seat.casefold() == compiler_seat.casefold():
            return item.intervention.id
    return None


def _selected_seat_owner(
    selected: Mapping[tuple[str, str], ClassicDonorRetuneRepair],
    groups: Mapping[tuple[str, str], _RepairGroup],
    attempt: _PreparedAttempt,
) -> str | None:
    """The donor of the same unit whose already-selected retune renders this seat."""

    unit_id = groups[attempt.group_key].unit.plan.id
    seat = attempt.donor.request.compiler_seat.casefold()
    for key, repair in selected.items():
        if (
            key != attempt.group_key
            and repair.unit_id == unit_id
            and repair.compiler_seat.casefold() == seat
        ):
            return repair.donor_id
    return None


def _group_action_keys(group: _RepairGroup) -> frozenset[tuple[str, str]]:
    """Identify every action whose saved composition a proposal would change."""

    return frozenset((group.unit.plan.id, item.intervention.id) for item in group.validated)


def _selected_action_owner(
    selected: Mapping[tuple[str, str], ClassicDonorRetuneRepair],
    groups: Mapping[tuple[str, str], _RepairGroup],
    group: _RepairGroup,
) -> str | None:
    """Return a selected donor whose proposal overlaps this group's actions."""

    claimed = _group_action_keys(group)
    for key in selected:
        if claimed & _group_action_keys(groups[key]):
            return groups[key].donor.intervention.id
    return None


def _candidate_windows(
    attempts: tuple[_PreparedAttempt, ...],
    selected: Mapping[tuple[str, str], ClassicDonorRetuneRepair],
    *,
    window_size: int,
    candidate_budget: int,
    signatures: Mapping[str, str] | None = None,
    deferred: set[tuple[str, str]] | None = None,
) -> Iterable[tuple[str, ...]]:
    """Yield fair lazy windows, dropping groups as soon as they are selected.

    Nearby distance tiers come first and every group gets a fair share of each
    window.  Whenever a group has been selected, candidates of the still-open
    groups that repeat the accepted move (same ``signatures`` value) are
    promoted ahead of the tier walk: the move that just restored one donor is
    the most likely to restore the others after the same source edit.
    """

    emitted: set[str] = set()
    deferred_groups = deferred if deferred is not None else set()
    remaining = candidate_budget
    ordered = sorted(
        attempts,
        key=lambda item: (
            item.materialized.distance,
            item.group_key[0].casefold(),
            item.donor_rank,
            item.group_key[1].casefold(),
            item.probe_id,
        ),
    )

    def promoted(limit: int) -> list[str]:
        if not signatures or limit <= 0:
            return []
        wanted = {getattr(repair, "move_signature", "") for repair in selected.values()} - {""}
        if not wanted:
            return []
        chosen: list[str] = []
        for item in ordered:
            if len(chosen) == limit:
                break
            if (
                item.group_key in selected
                or item.group_key in deferred_groups
                or item.probe_id in emitted
            ):
                continue
            if signatures.get(item.probe_id) in wanted:
                chosen.append(item.probe_id)
                emitted.add(item.probe_id)
        return chosen

    for distance in sorted({item.materialized.distance for item in attempts}):
        by_group: dict[tuple[str, str], deque[str]] = {}
        for item in attempts:
            if item.materialized.distance == distance:
                queue = by_group.setdefault(item.group_key, deque())
                if item.probe_id not in queue:
                    queue.append(item.probe_id)
        donor_ranks = {
            item.group_key: item.donor_rank
            for item in attempts
            if item.materialized.distance == distance
        }
        group_keys = tuple(
            sorted(
                by_group,
                key=lambda item: (
                    item[0].casefold(),
                    donor_ranks[item],
                    item[1].casefold(),
                    item[1],
                ),
            )
        )
        while remaining:
            window: list[str] = promoted(min(window_size, remaining))
            while len(window) < min(window_size, remaining):
                added = False
                for group_key in group_keys:
                    if group_key in selected or group_key in deferred_groups:
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
            remaining -= len(window)
            yield tuple(window)


def _probe_bounded_donor_retunes(
    probes: ClassicProbeExecution,
    refusals: Sequence[RepairRefusal],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
    radius: int = DEFAULT_REPAIR_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
    window_size: int = DEFAULT_RETUNE_PROBE_WINDOW,
    candidate_budget: int = DEFAULT_RETUNE_PROBE_CANDIDATES,
    progress: ClassicDonorProbeProgress | None = None,
    abandoned_states: Mapping[tuple[str, str], frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
    excluded_groups: frozenset[tuple[str, str]] = frozenset(),
    close_runtime: bool = True,
    materialize_source_epoch: bool = True,
    source_seal: ClassicDonorSourceSeal | None = None,
    namespace_id: str = "noncertifying-donor-repair-probe",
) -> ClassicDonorRetuneProbeResult:
    """Compile deterministic distance tiers and select ordinarily valid retunes.

    ``abandoned_states`` maps ``(unit_id, donor_id)`` to canonical parameter
    payloads this command already saved and moved away from; a candidate that
    would return to one is refused, so two consumers cannot trade a donor back
    and forth between rounds.

    Failed actions are grouped by translation unit and each donor they use,
    with the primary donor tried before canonical auxiliary alternatives.
    ``excluded_groups`` can defer already-exhausted ``(unit_id, donor_id)``
    pairs without hiding the same failure from another donor.  A candidate is
    selected only if the ordinary measured-pin repair/composer accepts every
    *captured* failed action in its group; callers must still continue the TU
    to expose later actions.  Candidate enumeration remains bounded by
    ``radius`` and ``limit`` per donor.  Nearby distance tiers run first in
    small windows, and outer tiers are requested only after cheaper candidates
    fail.  The supplied non-certifying probe runtime is consumed.
    """

    if type(window_size) is not int or not 1 <= window_size <= MAX_RETUNE_PROBE_WINDOW:
        raise ClassicDonorRetuneProbeError(
            f"window_size must be an integer from 1 to {MAX_RETUNE_PROBE_WINDOW}"
        )
    if (
        type(candidate_budget) is not int
        or not 1 <= candidate_budget <= MAX_RETUNE_PROBE_CANDIDATES
    ):
        raise ClassicDonorRetuneProbeError(
            f"candidate_budget must be an integer from 1 to {MAX_RETUNE_PROBE_CANDIDATES}"
        )
    groups = _group_failures(refusals, excluded_groups=excluded_groups)
    if not groups:
        return ClassicDonorRetuneProbeResult((), (), 0)
    canonical = canonical_overlay_operations or {}
    by_key = {group.key: group for group in groups}
    attempts: list[_PreparedAttempt] = []
    compiler_seats: dict[tuple[str, str, str], _PreparedAttempt] = {}
    signatures: dict[str, str] = {}
    with ClassicOverlayRenderSession() as overlay_render_session:
        for group in groups:
            try:
                candidates = enumerate_donor_retune_candidates(
                    group.donor.intervention,
                    radius=radius,
                    limit=limit,
                    carrier_sources=clean_sources,
                )
            except DonorRetuneError as exc:
                group.setup_refusals.append(
                    ClassicDonorRetuneAttemptRefusal(0, (), "preparation", str(exc))
                )
                continue
            forbidden = (abandoned_states or {}).get(group.key, frozenset())
            for candidate in candidates:
                if forbidden and _parameter_payload(candidate.intervention) in forbidden:
                    group.setup_refusals.append(
                        ClassicDonorRetuneAttemptRefusal(
                            candidate.distance,
                            candidate.changes,
                            "preparation",
                            "candidate returns to a donor state this command already saved and "
                            "abandoned",
                        )
                    )
                    continue
                try:
                    materialized, donor = prepare_retune_candidate(
                        group.unit,
                        group.donor,
                        group.donor_receipt,
                        candidate,
                        clean_sources=clean_sources,
                        effective_sources=effective_sources,
                        canonical_overlay_operations=canonical,
                        overlay_render_session=overlay_render_session,
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
                            "preparation",
                            f"candidate preparation failed: {exc}",
                        )
                    )
                    continue
                occupant = _occupying_donor(group, donor.request.compiler_seat)
                if occupant is not None:
                    group.setup_refusals.append(
                        ClassicDonorRetuneAttemptRefusal(
                            candidate.distance,
                            candidate.changes,
                            "preparation",
                            "candidate renders the same declarations as donor "
                            f"{occupant!r} of this translation unit and would share its "
                            "compiler arena",
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
                                "preparation",
                                "candidate compiler arena collides with a different bounded input",
                            )
                        )
                        continue
                    probe_id = previous.probe_id
                else:
                    probe_id = f"repair_probe_{len(compiler_seats):04d}"
                attempt = _PreparedAttempt(
                    group.key,
                    materialized,
                    donor,
                    probe_id,
                    group.donor_rank,
                )
                compiler_seats.setdefault(compiler_seat, attempt)
                attempts.append(attempt)
                signatures.setdefault(
                    probe_id,
                    _move_signature(group.donor.intervention.family.value, materialized.changes),
                )

    if not attempts:
        unavailable = tuple(
            ClassicDonorRetuneRefusal(
                group.unit.plan.id,
                group.donor.intervention.id,
                group.action_ids,
                0,
                (
                    "donor family has no bounded retune candidates"
                    if not group.setup_refusals
                    else "no bounded donor candidate could be prepared"
                ),
                tuple(group.setup_refusals),
                exhausted=True,
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
    deferred: set[tuple[str, str]] = set()
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
                            "compilation",
                            f"candidate compiler rejected input: {outcome.reason}",
                        )
                    )
                    continue
                overlap = _selected_action_owner(selected, by_key, group)
                if overlap is not None:
                    deferred.add(group.key)
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            "ordinary_validation",
                            "candidate was deferred because the selected repair for donor "
                            f"{overlap!r} changes the same function record",
                        )
                    )
                    continue
                taken = _selected_seat_owner(selected, by_key, attempt)
                if taken is not None:
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            "ordinary_validation",
                            "candidate renders the same declarations as the retune already "
                            f"selected for donor {taken!r} of this translation unit",
                        )
                    )
                    continue
                try:
                    repaired = validate_retuned_actions(
                        group.validated,
                        attempt.donor,
                        attempt.materialized,
                        outcome,
                    )
                    intervention_edits, receipt_edits, additions = retune_authority_edits(
                        group.donor,
                        group.donor_receipt,
                        group.validated,
                        attempt.materialized,
                        repaired,
                    )
                except MeasuredPinRepairError as exc:
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            exc.stage,
                            str(exc),
                        )
                    )
                    continue
                except ValueError as exc:
                    rejected[group.key].append(
                        ClassicDonorRetuneAttemptRefusal(
                            attempt.materialized.distance,
                            attempt.materialized.changes,
                            "ordinary_validation",
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
                    attempt.donor.request.compiler_seat,
                    _parameter_payload(group.donor.intervention),
                    _move_signature(
                        group.donor.intervention.family.value,
                        attempt.materialized.changes,
                    ),
                    additions,
                )
                for other_key in compilable_groups - set(selected):
                    if _selected_action_owner(selected, by_key, by_key[other_key]) is not None:
                        deferred.add(other_key)
        return compilable_groups <= (set(selected) | deferred)

    canonical_attempts = tuple(values[0] for values in attempts_by_id.values())
    units = tuple(
        clone_retune_probe_unit(by_key[item.group_key].unit, item.donor, item.probe_id)
        for item in canonical_attempts
    )
    compiled_probe_ids = probe_donor_compile_windows(
        probes,
        units,
        _candidate_windows(
            attempt_tuple,
            selected,
            window_size=window_size,
            candidate_budget=candidate_budget,
            signatures=signatures,
            deferred=deferred,
        ),
        evaluate=evaluate,
        progress=progress,
        planned_candidates=min(len(canonical_attempts), candidate_budget),
        cache=compile_cache,
        close_runtime=close_runtime,
        materialize_source_epoch=materialize_source_epoch,
        source_seal=source_seal,
        namespace_id=namespace_id,
    )
    compiled_probe_id_set = set(compiled_probe_ids)

    repairs: list[ClassicDonorRetuneRepair] = []
    refusals_out: list[ClassicDonorRetuneRefusal] = []
    for group in groups:
        repair = selected.get(group.key)
        if repair is not None:
            repairs.append(repair)
            continue
        choice_count = compiled[group.key]
        choices = f"{choice_count} compiler choice" + ("" if choice_count == 1 else "s")
        untried = {
            attempt.probe_id for attempt in attempt_tuple if attempt.group_key == group.key
        } - compiled_probe_id_set
        if group.key in deferred:
            reason = "donor repair was deferred because another selected repair overlaps it"
        elif len(compiled_probe_ids) >= candidate_budget and untried:
            reason = (
                "remaining command-wide donor-candidate budget was exhausted after "
                f"testing {choices} for this donor"
            )
        else:
            reason = f"none of {choices} restored the expected output"
        refusals_out.append(
            ClassicDonorRetuneRefusal(
                group.unit.plan.id,
                group.donor.intervention.id,
                group.action_ids,
                compiled[group.key],
                reason,
                tuple(rejected[group.key]),
                exhausted=group.key not in deferred and not untried,
            )
        )
    return ClassicDonorRetuneProbeResult(
        tuple(repairs),
        tuple(refusals_out),
        len(compiled_probe_ids),
    )


def probe_bounded_donor_retunes(
    probes: ClassicProbeExecution,
    refusals: Sequence[RepairRefusal],
    *,
    clean_sources: Mapping[str, bytes],
    effective_sources: Mapping[str, bytes],
    canonical_overlay_operations: Mapping[str, Sequence[Mapping[str, object]]] | None = None,
    radius: int = DEFAULT_REPAIR_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
    window_size: int = DEFAULT_RETUNE_PROBE_WINDOW,
    candidate_budget: int = DEFAULT_RETUNE_PROBE_CANDIDATES,
    progress: ClassicDonorProbeProgress | None = None,
    abandoned_states: Mapping[tuple[str, str], frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
    excluded_groups: frozenset[tuple[str, str]] = frozenset(),
    close_runtime: bool = True,
    materialize_source_epoch: bool = True,
    source_seal: ClassicDonorSourceSeal | None = None,
    namespace_id: str = "noncertifying-donor-repair-probe",
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
            candidate_budget=candidate_budget,
            progress=progress,
            abandoned_states=abandoned_states,
            compile_cache=compile_cache,
            excluded_groups=excluded_groups,
            close_runtime=close_runtime,
            materialize_source_epoch=materialize_source_epoch,
            source_seal=source_seal,
            namespace_id=namespace_id,
        )
    except BaseException as original:
        try:
            if probes.producer.is_open:
                probes.close()
        except BaseException as cleanup_error:
            original.add_note(f"classic donor retune cleanup also failed: {cleanup_error}")
        raise
    if close_runtime and probes.producer.is_open:
        probes.close()
    return result


__all__ = [
    "DEFAULT_RETUNE_PROBE_CANDIDATES",
    "DEFAULT_RETUNE_PROBE_WINDOW",
    "MAX_RETUNE_PROBE_CANDIDATES",
    "MAX_RETUNE_PROBE_WINDOW",
    "ClassicDonorRetuneAttemptRefusal",
    "ClassicDonorRetuneAttemptStage",
    "ClassicDonorRetuneProbeError",
    "ClassicDonorRetuneProbeResult",
    "ClassicDonorRetuneRefusal",
    "ClassicDonorRetuneRepair",
    "probe_bounded_donor_retunes",
]
