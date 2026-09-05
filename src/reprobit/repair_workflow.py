"""Bounded classic authority repair for one private staged project.

One repair attempt stages the sealed project, refreshes its source records,
repairs saved build guidance through bounded warm analysis passes, proves
every target from scratch, and publishes the verified result atomically.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_legacy_repair import (
    LegacyInstallRepair,
    LegacyNoWindowError,
    LegacyNoWindowResolution,
    LegacyRepairError,
    plan_legacy_no_window_resolution,
    reauthor_legacy_simulated_elision,
)
from reprobit.classic_link_layout_repair import (
    ClassicLinkLayoutHint,
    derive_classic_link_layout_hint,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirements,
)
from reprobit.classic_repair_authority import (
    ClassicReceiptEdit,
    LegacyInterventionEdit,
    apply_classic_authority_edits,
)
from reprobit.classic_repair_dispatch import CapturedDonorObject
from reprobit.classic_repair_probe import (
    ClassicDonorRetuneRefusal,
)
from reprobit.classic_repair_probe_cache import (
    ClassicDonorCompileStore,
    probe_store_directory,
)
from reprobit.classic_repair_reauthor import (
    ClassicReauthorError,
    plan_function_reauthoring,
)
from reprobit.classic_repair_session import (
    ClassicReceiptRepair,
    ClassicRepairSession,
    LegacyRepairRefusal,
    RepairRefusal,
    apply_classic_receipt_repairs,
)
from reprobit.cli_output import count_phrase
from reprobit.composition_ledger import (
    COMPOSED_BODY_LEDGER_RELATIVE,
    ComposedBodyLedger,
    ObsoleteLedgerError,
    read_ledger,
)
from reprobit.intervention_metadata import ClassicRecipeFamily, ClassicRecipeRole
from reprobit.model import AuthenticityPolicy
from reprobit.producer_graph import producer_graph_digest
from reprobit.project_execution import (
    BuildRequest,
    ExecutionProgress,
    ProjectExecutionOptions,
    RepairAnalysisOptions,
    VerifyRequest,
    VerifyResult,
    execute_build,
)
from reprobit.project_loader import load_project_tree
from reprobit.repair import (
    RepairCandidate,
    RepairError,
    RepairOutputSnapshot,
    RepairSnapshot,
    capture_repair_record_postimages,
    collect_repair_candidate,
    publish_repair_candidate,
    stage_repair_project,
)
from reprobit.repair_census import RepairCensusEntry, plan_repair_census
from reprobit.repair_donor_analysis import (
    ClassicRepairProbeSession,
    RepairProbeOptions,
    apply_classic_discovery_repairs,
    apply_classic_donor_repairs,
    apply_classic_project_overlay_repair,
    probe_classic_carrier_discovery,
    probe_classic_donor_repairs,
    probe_classic_project_overlay_repairs,
)
from reprobit.repair_unit_admission import (
    TranslationUnitAdmissionError,
    apply_translation_unit_admissions,
    plan_translation_unit_admissions,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    LegacyOracleInstallIntervention,
    ProjectBundle,
    ProjectSpec,
    classic_debug_companion_paths,
    classic_function_donor_ids,
)
from reprobit.search_limits import (
    DEFAULT_DISCOVERY_CANDIDATES,
    DEFAULT_REPAIR_RETUNE_RADIUS,
    DEFAULT_RETUNE_CANDIDATES,
    MAX_REPAIR_ADJUSTMENT_ROUNDS,
    MAX_REPAIR_CANDIDATES,
)
from reprobit.source_lock import receipt_source_input
from reprobit.source_lock_workflow import apply_source_lock, plan_source_lock
from reprobit.source_regeneration import (
    RegenerationPlan,
    SourceRegenerationError,
    apply_source_regeneration,
    plan_source_regeneration,
)
from reprobit.staged_project import StagedProject
from reprobit.state import KeepWorkspace
from reprobit.strict_json import canonical_json
from reprobit.transactions import TransactionResult


@dataclass(frozen=True, slots=True)
class RepairWorkflowOptions:
    """Execution and bounded-search choices for one automatic repair."""

    execution: ProjectExecutionOptions
    policy: AuthenticityPolicy | None = None
    retune_radius: int = DEFAULT_REPAIR_RETUNE_RADIUS
    retune_candidates: int = DEFAULT_RETUNE_CANDIDATES
    candidate_limit: int = MAX_REPAIR_CANDIDATES
    adjustment_rounds: int = MAX_REPAIR_ADJUSTMENT_ROUNDS
    discovery_candidates: int = DEFAULT_DISCOVERY_CANDIDATES

    def probes(self, project: Path) -> RepairProbeOptions:
        return RepairProbeOptions(
            project=project,
            execution=self.execution,
            retune_radius=self.retune_radius,
            retune_candidates=self.retune_candidates,
            discovery_candidates=self.discovery_candidates,
        )


class RepairWorkflowError(RuntimeError):
    """A bounded repair could not restore ordinary classic composition."""

    def __init__(
        self,
        message: str,
        *,
        diagnostic: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


def _consume_candidate_budget(
    compiled: int,
    used: int,
    *,
    limit: int,
    search: str,
) -> int:
    """Add one search result without trusting it past the remaining command budget."""

    remaining = limit - compiled
    if not 0 <= used <= remaining:
        raise RepairWorkflowError(f"{search} exceeded its remaining command-wide candidate budget")
    return compiled + used


@dataclass(frozen=True, slots=True)
class RepairWorkflowResult:
    """Human-sized accounting for a completed staged repair."""

    changed_records: tuple[str, ...]
    affected_units: tuple[str, ...]
    measured_checks: int
    retired_actions: int
    removed_donors: int
    donor_retunes: int
    compiled_candidates: int
    passes: int
    reauthored_actions: int = 0
    discovered_actions: int = 0
    replayed_candidates: int = 0
    """Candidates settled from earlier compiles of the same seat instead of compiling."""
    admitted_units: int = 0
    """Translation units the ledger census added to the build plan for unrecorded fallout."""
    source_retunes: int = 0
    """Project source layouts adjusted after their dual compiler-epoch check."""
    adjustment_rounds: int = 0
    """Saved-guidance adjustment rounds consumed by this workflow run."""


@dataclass(slots=True)
class RepairSessionState:
    """Mutable accounting and loop guards for one bounded repair run."""

    adjustment_limit: int
    candidate_limit: int
    changed_records: set[str] = field(default_factory=set)
    affected_units: set[str] = field(default_factory=set)
    measured_checks: int = 0
    retired_actions: int = 0
    removed_donors: int = 0
    donor_retunes: int = 0
    reauthored_actions: int = 0
    discovered_actions: int = 0
    admitted_units: int = 0
    source_retunes: int = 0
    compiled_candidates: int = 0
    adjustment_rounds: int = 0
    seen_authority: set[str] = field(default_factory=set)
    exhausted_groups: set[tuple[str, str]] = field(default_factory=set)
    abandoned_states: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    discovered_shapes: dict[str, set[str]] = field(default_factory=dict)
    captured_donor_objects: dict[str, dict[str, CapturedDonorObject]] = field(default_factory=dict)
    """Per unit, the fresh donor objects of its last fresh composition in this run."""
    initial_function_actions: int | None = None
    pass_number: int = 0
    last_outcome: str | None = None

    def require_adjustment_round(self) -> None:
        if self.adjustment_rounds >= self.adjustment_limit:
            raise RepairWorkflowError(
                "automatic repair reached its limit of "
                f"{self.adjustment_limit} saved-guidance adjustment rounds"
            )

    def consume_candidates(self, used: int, *, search: str) -> None:
        self.compiled_candidates = _consume_candidate_budget(
            self.compiled_candidates,
            used,
            limit=self.candidate_limit,
            search=search,
        )

    def begin_pass(self, bundle: ProjectBundle) -> None:
        self.pass_number += 1
        if self.initial_function_actions is None:
            self.initial_function_actions = sum(
                isinstance(item, LegacyOracleInstallIntervention)
                or getattr(item, "role", None) is ClassicRecipeRole.FUNCTION
                for item in bundle.interventions
            )
        maximum_analyses = self.initial_function_actions + self.adjustment_limit + 1
        if self.pass_number > maximum_analyses:
            raise RepairWorkflowError("automatic repair exceeded its monotonic analysis bound")
        fingerprint = _authority_fingerprint(bundle)
        if fingerprint in self.seen_authority:
            raise RepairWorkflowError(
                "automatic repair reached a previously checked saved-guidance state"
            )
        self.seen_authority.add(fingerprint)

    def result(self, compile_cache: ClassicDonorCompileStore) -> RepairWorkflowResult:
        return RepairWorkflowResult(
            changed_records=tuple(
                sorted(self.changed_records, key=lambda item: (item.casefold(), item))
            ),
            affected_units=tuple(sorted(self.affected_units, key=str.casefold)),
            measured_checks=self.measured_checks,
            retired_actions=self.retired_actions,
            removed_donors=self.removed_donors,
            donor_retunes=self.donor_retunes,
            compiled_candidates=self.compiled_candidates,
            passes=self.pass_number,
            reauthored_actions=self.reauthored_actions,
            discovered_actions=self.discovered_actions,
            replayed_candidates=compile_cache.memory_hits + compile_cache.disk_hits,
            admitted_units=self.admitted_units,
            source_retunes=self.source_retunes,
            adjustment_rounds=self.adjustment_rounds,
        )

    def record_transition(
        self,
        changed: Sequence[str],
        *,
        empty_error: str,
        outcome: str,
        consume_round: bool = True,
    ) -> None:
        """Record one proven authority mutation and its next-pass explanation."""

        if not changed:
            raise RepairWorkflowError(empty_error)
        self.changed_records.update(changed)
        if consume_round:
            self.adjustment_rounds += 1
        self.last_outcome = outcome


class RepairAnalysisError(RuntimeError):
    """A non-certifying analysis failed outside a recorded repair seat."""


@dataclass(frozen=True, slots=True)
class RepairAnalysisResult:
    """Measured and structural fallout from one bounded incremental pass."""

    completed: bool
    measured_repairs: tuple[ClassicReceiptRepair, ...]
    structural_refusals: tuple[RepairRefusal, ...]
    seed_objects: Mapping[str, SeedObject] = field(default_factory=lambda: MappingProxyType({}))
    unit_donor_objects: Mapping[str, Mapping[str, CapturedDonorObject]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    """Per translation unit, the fresh donor objects the pass composed with."""


def analyze_classic_repair(
    options: RepairWorkflowOptions,
    progress: ExecutionProgress,
    *,
    staged_root: Path,
    cache_root: Path | None = None,
    progress_description: str = "checking affected source files",
    seed_census: bool = False,
) -> RepairAnalysisResult:
    """Run one warm analysis and distinguish repair fallout from fatal failure.

    With ``seed_census`` the analysis also compiles every translation unit and
    returns each fresh object so the caller can census unrecorded fallout.
    """

    session = ClassicRepairSession()
    try:
        result = execute_build(
            BuildRequest(
                project=staged_root,
                execution=options.execution,
                keep_workspace=KeepWorkspace.NEVER,
                cache_root=cache_root,
                repair_analysis=RepairAnalysisOptions(session, seed_census),
                progress_description=progress_description,
            ),
            progress,
        )
    except Exception as exc:
        raise RepairAnalysisError(f"repair analysis failed: {exc}") from exc
    refusals = session.refusals
    cutoffs: dict[str, int] = {}
    for refusal in refusals:
        cutoffs[refusal.unit_id] = min(
            refusal.action_index,
            cutoffs.get(refusal.unit_id, refusal.action_index),
        )
    repairs = tuple(
        repair
        for repair in session.repairs
        if repair.action_index <= cutoffs.get(repair.unit_id, repair.action_index)
    )
    refusals = tuple(
        refusal for refusal in refusals if refusal.action_index <= cutoffs[refusal.unit_id]
    )
    return RepairAnalysisResult(
        not refusals,
        repairs,
        refusals,
        result.seed_objects,
        session.unit_donor_objects,
    )


def _listed_census(entries: Sequence[RepairCensusEntry], limit: int = 8) -> str:
    listed = ", ".join(f"{entry.source}:{entry.symbol}" for entry in entries[:limit])
    more = len(entries) - limit
    return listed + (f" and {more} more" if more > 0 else "")


def _composed_body_ledger(cache_root: Path) -> ComposedBodyLedger | None:
    """The last accepted verify's composed-body ledger of this state directory, if any."""

    path = cache_root.joinpath(*COMPOSED_BODY_LEDGER_RELATIVE)
    if not path.is_file():
        return None
    try:
        return read_ledger(path)
    except ObsoleteLedgerError:
        return None  # Independent cold verification refreshes optional derived data.
    except (OSError, ValueError) as exc:
        raise RepairWorkflowError(f"saved repair data at {path} is unreadable: {exc}") from exc


def _ledger_for_bundle(
    ledger: ComposedBodyLedger | None,
    bundle: ProjectBundle,
) -> ComposedBodyLedger | None:
    """Use accepted composed-body evidence only for the graph that produced it."""

    if ledger is None:
        return None
    graph = bundle.producer_graph
    if graph is None:
        return None
    return ledger if ledger.graph_digest == producer_graph_digest(graph).value else None


def _classic_receipts(bundle: ProjectBundle) -> tuple[ClassicProofReceipt, ...]:
    return tuple(
        receipt
        for document in bundle.proof_documents
        for receipt in document.expected_observations
        if isinstance(receipt, ClassicProofReceipt)
    )


def _authority_fingerprint(bundle: ProjectBundle) -> str:
    payload = {
        "interventions": [
            document.model_dump(mode="json") for document in bundle.intervention_documents
        ],
        "proofs": [document.model_dump(mode="json") for document in bundle.proof_documents],
    }
    return sha256(canonical_json(payload)).hexdigest()


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _probe_refusal_error(
    refusal: ClassicDonorRetuneRefusal,
    unresolved: tuple[tuple[str, str, str], ...] = (),
) -> RepairWorkflowError:
    attempts = refusal.compiled_candidates
    choice = "choice" if attempts == 1 else "choices"
    lines = [
        "Automatic repair could not prove a safe result for affected build "
        f"`{refusal.unit_id}` after testing {attempts} nearby compiler {choice}."
    ]
    discovery_note = next(
        (reason for unit_id, _action, reason in unresolved if unit_id == refusal.unit_id), None
    )
    if discovery_note:
        lines.append(f"Fresh compiler choices did not help: {_one_line(discovery_note)}")
    best = refusal.best_attempt
    best_document: dict[str, object] | None = None
    if best is not None:
        visible_changes = tuple(change for change in best.changes if change.kind == "knob")
        if visible_changes:
            rendered = "; ".join(
                f"`{change.path[-1]}` {change.before} -> {change.after}"
                for change in visible_changes
            )
            lines.append(f"Closest compiler choice tried: {rendered}.")
        lines.append(f"Why it was rejected: {_one_line(best.reason)}")
        best_document = {
            "distance": best.distance,
            "stage": best.stage,
            "reason": best.reason,
            "changes": [
                {
                    "path": list(change.path),
                    "before": change.before,
                    "after": change.after,
                    "kind": change.kind,
                }
                for change in best.changes
            ],
        }
    else:
        lines.append(f"Why it was rejected: {_one_line(refusal.reason)}")
    return RepairWorkflowError(
        " ".join(lines),
        diagnostic={
            "unit_id": refusal.unit_id,
            "donor_id": refusal.donor_id,
            "action_ids": list(refusal.action_ids),
            "candidates_tried": refusal.compiled_candidates,
            "reason": refusal.reason,
            "best_candidate": best_document,
        },
    )


def _donor_group_keys(refusal: RepairRefusal) -> tuple[tuple[str, str], ...]:
    """Return every retunable donor key, with the primary donor first."""

    action = refusal.intervention
    dependencies = action.dependencies
    if not dependencies:
        return ()
    primary = dependencies[0]
    if isinstance(action, LegacyOracleInstallIntervention):
        donor_ids = frozenset({primary})
    elif isinstance(action, ClassicRecipeIntervention):
        donor_ids = classic_function_donor_ids(action, refusal.receipt)
    else:
        # Small workflow doubles and future non-classic refusal types can only
        # express the dependency graph they carry directly.
        donor_ids = frozenset(dependencies)
    ordered = (primary, *sorted(donor_ids - {primary}, key=lambda item: (item.casefold(), item)))
    return tuple((refusal.unit_id, donor_id) for donor_id in ordered)


def _publish_legacy_fallbacks(
    root: Path,
    spec: ProjectSpec,
    fallbacks: Sequence[tuple[LegacyRepairRefusal, LegacyInstallRepair]],
) -> tuple[str, ...]:
    """Atomically save current-donor legacy repairs after retunes find no improvement."""

    return apply_classic_authority_edits(
        root,
        spec,
        legacy_interventions=tuple(
            LegacyInterventionEdit(refusal.intervention, repair.intervention)
            for refusal, repair in fallbacks
        ),
        receipts=tuple(
            ClassicReceiptEdit(refusal.receipt, repair.receipt) for refusal, repair in fallbacks
        ),
    )


def _publish_legacy_no_window_resolution(
    root: Path,
    spec: ProjectSpec,
    resolution: LegacyNoWindowResolution,
) -> tuple[str, ...]:
    """Atomically remove a quarantine and optionally replace its record in place."""

    return apply_classic_authority_edits(
        root,
        spec,
        interventions=resolution.donor_edits,
        legacy_interventions=(resolution.legacy_edit,),
        receipts=resolution.receipt_edits,
        additions=(() if resolution.addition is None else (resolution.addition,)),
    )


@dataclass(frozen=True, slots=True)
class _RepairContext:
    """Inputs shared by the ordered repair stages of one private attempt."""

    options: RepairWorkflowOptions
    progress: ExecutionProgress
    staged_root: Path
    spec: ProjectSpec
    cache_root: Path
    state: RepairSessionState
    compile_cache: ClassicDonorCompileStore
    probe_options: RepairProbeOptions
    settle_target_ids: frozenset[str]
    link_layout_hint: ClassicLinkLayoutHint | None


@dataclass(frozen=True, slots=True)
class _LegacyFallout:
    refusals: tuple[RepairRefusal, ...]
    fallbacks: tuple[tuple[LegacyRepairRefusal, LegacyInstallRepair], ...]
    failures: tuple[str, ...]
    no_window_resolution: LegacyNoWindowResolution | None


@dataclass(frozen=True, slots=True)
class _RetirementOutcome:
    changed: bool
    failures: tuple[str, ...]


def _analyze_repair_pass(
    context: _RepairContext,
    ledger: ComposedBodyLedger | None,
) -> RepairAnalysisResult:
    """Measure the current guidance, then census remaining functions when needed."""

    options = context.options
    progress = context.progress
    staged_root = context.staged_root
    cache_root = context.cache_root
    state = context.state
    settle_target_ids = context.settle_target_ids

    if settle_target_ids:
        progress_description = (
            f"repair pass {state.pass_number}: checking a remaining link layout mismatch"
        )
    else:
        progress_description = f"repair pass {state.pass_number}: checking affected source files"
    if state.last_outcome is not None and settle_target_ids:
        progress_description = (
            "repair pass "
            f"{state.pass_number}: checking the link layout again ({state.last_outcome})"
        )
    elif state.last_outcome is not None:
        progress_description = (
            f"repair pass {state.pass_number}: checking again ({state.last_outcome})"
        )
    analysis = analyze_classic_repair(
        options,
        progress,
        staged_root=staged_root,
        cache_root=cache_root,
        progress_description=progress_description,
        seed_census=False,
    )
    # The first analysis of a pass is the one that composes changed units
    # fresh; the census analysis that may follow replays them from the cache.
    _remember_donor_objects(state, analysis)
    if not analysis.measured_repairs and analysis.completed and ledger is not None:
        analysis = analyze_classic_repair(
            options,
            progress,
            staged_root=staged_root,
            cache_root=cache_root,
            progress_description=(
                f"repair pass {state.pass_number}: checking remaining source files"
            ),
            seed_census=True,
        )
        _remember_donor_objects(state, analysis)
    state.affected_units.update(item.unit_id for item in analysis.measured_repairs)
    state.affected_units.update(item.unit_id for item in analysis.structural_refusals)
    return analysis


def _remember_donor_objects(state: RepairSessionState, analysis: RepairAnalysisResult) -> None:
    """Carry each unit's freshly composed donor objects to later passes of this run.

    A later analysis replays an unchanged unit from the warm cache and composes
    nothing, so the objects the census hosts fallout on come from the last pass
    that composed the unit; each object stays bound to its donor recipe.
    """

    for unit_id, objects in getattr(analysis, "unit_donor_objects", {}).items():
        if objects:
            state.captured_donor_objects[unit_id] = dict(objects)


def _repair_measured_checks(
    context: _RepairContext,
    analysis: RepairAnalysisResult,
) -> bool:
    """Refresh measured checks before attempting any structural repair."""

    staged_root = context.staged_root
    spec = context.spec
    state = context.state

    if analysis.measured_repairs:
        state.require_adjustment_round()
        changed = apply_classic_receipt_repairs(
            staged_root,
            spec,
            analysis.measured_repairs,
        )
        state.measured_checks += len(analysis.measured_repairs)
        state.record_transition(
            changed,
            empty_error="measured repair reported success without changing saved guidance",
            outcome="refreshed " + count_phrase(len(analysis.measured_repairs), "saved check"),
        )
        return True
    return False


def _repair_unrecorded_functions(
    context: _RepairContext,
    bundle: ProjectBundle,
    ledger: ComposedBodyLedger | None,
    analysis: RepairAnalysisResult,
) -> bool:
    """Admit and discover fallout absent from the saved function records."""

    progress = context.progress
    staged_root = context.staged_root
    spec = context.spec
    state = context.state
    compile_cache = context.compile_cache
    probe_options = context.probe_options
    candidate_limit = context.state.candidate_limit

    if ledger is not None:
        census = plan_repair_census(
            bundle,
            ledger,
            getattr(analysis, "seed_objects", None) or {},
            captured_donor_objects=state.captured_donor_objects,
        )
        if census.missing:
            raise RepairWorkflowError(
                "the edit removed functions used by the last accepted build: "
                + _listed_census(census.missing)
            )
        if census.unplanned:
            # Fallout in a unit the plan never listed: admit the unit (plan
            # entry plus empty shards) so the next pass can record it.
            state.require_adjustment_round()
            try:
                admitted = plan_translation_unit_admissions(bundle, census.unplanned)
                changed = apply_translation_unit_admissions(staged_root, spec, admitted)
            except TranslationUnitAdmissionError as exc:
                raise RepairWorkflowError(
                    "automatic repair could not add saved guidance for newly affected "
                    f"source files ({_listed_census(census.unplanned)}): " + _one_line(exc)
                ) from exc
            state.admitted_units += len(admitted)
            state.record_transition(
                changed,
                empty_error=(
                    "source-file admission reported success without changing saved guidance"
                ),
                outcome="added " + count_phrase(len(admitted), "affected source build"),
            )
            return True
        if census.refusals:
            state.require_adjustment_round()
            remaining_candidates = candidate_limit - state.compiled_candidates
            if remaining_candidates <= 0:
                raise RepairWorkflowError(
                    "automatic repair reached --candidate-limit "
                    f"after testing {candidate_limit} repair choices"
                )
            state.affected_units.update(item.unit_id for item in census.refusals)
            discovery = probe_classic_carrier_discovery(
                probe_options,
                progress,
                census.refusals,
                candidate_budget=remaining_candidates,
                tried_states={
                    key: frozenset(value) for key, value in state.discovered_shapes.items()
                },
                compile_cache=compile_cache,
            )
            state.consume_candidates(
                discovery.compiled_candidates,
                search="newly affected function discovery",
            )
            for unit_id, digests in getattr(discovery, "tried_states", {}).items():
                state.discovered_shapes.setdefault(unit_id, set()).update(digests)
            if not discovery.repairs:
                unresolved = ", ".join(
                    f"{unit_id} {action_id}: {reason}"
                    for unit_id, action_id, reason in discovery.unresolved[:8]
                )
                raise RepairWorkflowError(
                    "automatic repair could not restore newly affected functions: "
                    + (unresolved or "no carrier state settled it")
                )
            changed = apply_classic_discovery_repairs(staged_root, spec, discovery.repairs)
            resolved = sum(len(item.resolutions) for item in discovery.repairs)
            state.discovered_actions += resolved
            state.record_transition(
                changed,
                empty_error=("new-function check reported success without changing saved guidance"),
                outcome="added " + count_phrase(resolved, "function repair"),
            )
            return True
    return False


def _repair_source_layout(
    context: _RepairContext,
    bundle: ProjectBundle,
) -> bool:
    """Try the bounded source-layout stage after function composition is settled."""

    progress = context.progress
    staged_root = context.staged_root
    spec = context.spec
    state = context.state
    probe_options = context.probe_options
    settle_target_ids = context.settle_target_ids
    link_layout_hint = context.link_layout_hint
    candidate_limit = context.state.candidate_limit

    if any(
        isinstance(item, ClassicRecipeIntervention)
        and item.role is ClassicRecipeRole.PROJECT
        and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        for item in bundle.interventions
    ):
        remaining_candidates = max(0, candidate_limit - state.compiled_candidates)
        source_result = probe_classic_project_overlay_repairs(
            probe_options,
            progress,
            candidate_budget=remaining_candidates,
            settle_target_ids=settle_target_ids,
            link_layout_hint=link_layout_hint,
        )
        state.consume_candidates(
            source_result.compiled_candidates,
            search="source-layout repair",
        )
        if source_result.repair is not None:
            state.require_adjustment_round()
            changed = apply_classic_project_overlay_repair(
                staged_root,
                spec,
                source_result.repair,
            )
            if not changed:
                raise RepairWorkflowError(
                    "source-layout repair reported success without changing saved guidance"
                )
            try:
                regeneration = plan_source_regeneration(staged_root)
                apply_source_regeneration(staged_root, regeneration)
            except SourceRegenerationError as exc:
                raise RepairWorkflowError(
                    "source-layout repair could not refresh its saved output checks: "
                    + _one_line(exc)
                ) from exc
            state.source_retunes += 1
            state.record_transition(
                (*changed, *regeneration.changed_documents),
                empty_error=(
                    "source-layout regeneration reported success without changing saved guidance"
                ),
                outcome="adjusted one source layout",
            )
            return True
        if source_result.checked and source_result.reason is not None:
            if source_result.exhausted:
                raise RepairWorkflowError(
                    "automatic repair reached --candidate-limit "
                    f"after testing {candidate_limit} repair choices"
                )
            raise RepairWorkflowError(
                "automatic repair could not find a safe source layout for "
                f"{source_result.source_path or 'an affected source'}: "
                + _one_line(source_result.reason)
            )
    return False


def _prepare_legacy_fallout(
    context: _RepairContext,
    bundle: ProjectBundle,
    analysis: RepairAnalysisResult,
    receipts: tuple[ClassicProofReceipt, ...],
) -> _LegacyFallout:
    """Capture legacy fallback evidence before donor searches alter its source."""

    unavailable_legacy = [
        refusal
        for refusal in analysis.structural_refusals
        if isinstance(refusal.intervention, LegacyOracleInstallIntervention)
        and (refusal.legacy_oracle is None or refusal.materials.donor_object is None)
    ]
    if unavailable_legacy:
        detail = next(
            (
                refusal.reason
                if refusal.legacy_oracle is None
                else "fresh donor material is unavailable"
            )
            for refusal in unavailable_legacy
        )
        raise RepairWorkflowError(
            "automatic repair cannot inspect the saved legacy oracle before donor search: "
            + _one_line(detail)
        )

    structural_refusals: list[RepairRefusal] = []
    legacy_fallbacks: list[tuple[LegacyRepairRefusal, LegacyInstallRepair]] = []
    legacy_failures: list[str] = []
    no_window_resolution: LegacyNoWindowResolution | None = None
    for refusal in analysis.structural_refusals:
        if not isinstance(refusal.intervention, LegacyOracleInstallIntervention):
            structural_refusals.append(refusal)
            continue
        assert refusal.legacy_oracle is not None
        assert refusal.materials.donor_object is not None
        try:
            repaired = reauthor_legacy_simulated_elision(
                refusal.intervention,
                refusal.receipt,
                refusal.materials.seed_object,
                refusal.materials.donor_object,
                refusal.legacy_oracle.retail_body,
                refusal.legacy_oracle.auxiliary_bodies,
            )
        except LegacyNoWindowError:
            try:
                no_window_resolution = plan_legacy_no_window_resolution(
                    bundle.interventions,
                    receipts,
                    intervention=refusal.intervention,
                    receipt=refusal.receipt,
                    seed_object=refusal.materials.seed_object,
                    donor_object=refusal.materials.donor_object,
                    retail_body=refusal.legacy_oracle.retail_body,
                    build_target=refusal.unit.plan.build_target,
                )
            except LegacyRepairError as exc:
                legacy_failures.append(str(exc))
                structural_refusals.append(refusal)
                continue
            else:
                break
        except (LegacyRepairError, RuntimeError, ValueError) as exc:
            legacy_failures.append(str(exc))
            structural_refusals.append(refusal)
            continue
        with_baseline = replace(refusal, baseline_repair=repaired)
        structural_refusals.append(with_baseline)
        legacy_fallbacks.append((with_baseline, repaired))
    return _LegacyFallout(
        tuple(structural_refusals),
        tuple(legacy_fallbacks),
        tuple(legacy_failures),
        no_window_resolution,
    )


def _resolve_obsolete_quarantine(
    context: _RepairContext,
    bundle: ProjectBundle,
    no_window_resolution: LegacyNoWindowResolution | None,
) -> bool:
    """Remove or replace an obsolete quarantine using the already proven plan."""

    staged_root = context.staged_root
    state = context.state

    if no_window_resolution is not None:
        state.require_adjustment_round()
        changed = _publish_legacy_no_window_resolution(
            staged_root,
            bundle.spec,
            no_window_resolution,
        )
        state.removed_donors += len(no_window_resolution.removed_donors)
        if no_window_resolution.replaced:
            state.reauthored_actions += 1
            outcome = "replaced 1 obsolete quarantine record"
        else:
            state.retired_actions += 1
            outcome = "removed 1 obsolete quarantine record"
        state.record_transition(
            changed,
            empty_error="legacy dequarantine reported success without changing saved guidance",
            outcome=outcome,
        )
        return True
    return False


def _retire_redundant_adjustments(
    context: _RepairContext,
    bundle: ProjectBundle,
    current_refusals: tuple[RepairRefusal, ...],
    receipts: tuple[ClassicProofReceipt, ...],
) -> _RetirementOutcome:
    """Retire proven redundant adjustments without consuming a search round."""

    staged_root = context.staged_root
    spec = context.spec
    state = context.state

    retirement_failures: list[str] = []
    retirement_candidates: list[
        tuple[
            ClassicRecipeIntervention,
            ClassicProofReceipt,
            ClassicDispatchMaterials,
        ]
    ] = []
    for refusal in current_refusals:
        if isinstance(refusal.intervention, LegacyOracleInstallIntervention):
            continue
        candidate = (refusal.intervention, refusal.receipt, refusal.materials)
        try:
            plan_redundant_action_retirements(
                bundle.interventions,
                receipts,
                (candidate,),
            )
        except RedundantActionRepairError as exc:
            retirement_failures.append(str(exc))
            continue
        retirement_candidates.append(candidate)

    if retirement_candidates:
        try:
            plan = plan_redundant_action_retirements(
                bundle.interventions,
                receipts,
                tuple(retirement_candidates),
            )
        except RedundantActionRepairError as exc:
            raise RepairWorkflowError(
                "automatic repair could not combine its proven obsolete adjustments: "
                + _one_line(exc)
            ) from exc
        changed = apply_classic_authority_edits(
            staged_root,
            spec,
            interventions=plan.intervention_edits,
            receipts=plan.receipt_edits,
        )
        state.retired_actions += len(retirement_candidates)
        state.removed_donors += len(plan.removed_donors)
        state.record_transition(
            changed,
            empty_error=(
                "redundant-action retirement reported success without changing saved guidance"
            ),
            outcome="removed "
            + count_phrase(len(retirement_candidates), "obsolete function record"),
            consume_round=False,
        )
        return _RetirementOutcome(True, tuple(retirement_failures))
    return _RetirementOutcome(False, tuple(retirement_failures))


def _reauthor_existing_functions(
    context: _RepairContext,
    current_refusals: tuple[RepairRefusal, ...],
) -> bool:
    """Prefer bodies already emitted by available donors before compiling more."""

    staged_root = context.staged_root
    spec = context.spec
    state = context.state

    # Before compiling anything: a refused function whose goal body another
    # donor of its unit (or its own donor, under a cheaper family) already
    # emits is re-authored onto that donor from the captured fresh objects.
    try:
        reauthor_plan = plan_function_reauthoring(
            tuple(
                item
                for item in current_refusals
                if not isinstance(item.intervention, LegacyOracleInstallIntervention)
            )
        )
    except ClassicReauthorError as exc:
        raise RepairWorkflowError(
            "automatic repair could not plan function re-authoring: " + _one_line(exc)
        ) from exc
    if reauthor_plan.reauthorings:
        state.require_adjustment_round()
        changed = apply_classic_authority_edits(
            staged_root,
            spec,
            interventions=reauthor_plan.intervention_edits,
            receipts=reauthor_plan.receipt_edits,
            additions=reauthor_plan.additions,
            dependencies=reauthor_plan.dependency_edits,
        )
        state.reauthored_actions += len(reauthor_plan.reauthorings)
        state.record_transition(
            changed,
            empty_error=("function re-authoring reported success without changing saved guidance"),
            outcome="updated " + count_phrase(len(reauthor_plan.reauthorings), "function record"),
        )
        return True
    return False


def _repair_donor_fallout(
    context: _RepairContext,
    bundle: ProjectBundle,
    current_refusals: tuple[RepairRefusal, ...],
    legacy_fallbacks: tuple[tuple[LegacyRepairRefusal, LegacyInstallRepair], ...],
) -> bool:
    """Retune donors, discover carriers, then use a proven legacy fallback."""

    progress = context.progress
    staged_root = context.staged_root
    spec = context.spec
    state = context.state
    compile_cache = context.compile_cache
    probe_options = context.probe_options
    candidate_limit = context.state.candidate_limit

    donor_refusals = tuple(
        refusal
        for refusal in current_refusals
        if (
            isinstance(refusal.intervention, LegacyOracleInstallIntervention)
            or refusal.intervention.role is ClassicRecipeRole.FUNCTION
        )
        and refusal.intervention.dependencies
    )
    if donor_refusals:
        state.require_adjustment_round()
        remaining_candidates = candidate_limit - state.compiled_candidates
        if remaining_candidates <= 0:
            if legacy_fallbacks:
                changed = _publish_legacy_fallbacks(staged_root, bundle.spec, legacy_fallbacks)
                state.reauthored_actions += len(legacy_fallbacks)
                state.record_transition(
                    changed,
                    empty_error=(
                        "legacy re-authoring reported success without changing saved guidance"
                    ),
                    outcome="narrowed " + count_phrase(len(legacy_fallbacks), "quarantine record"),
                )
                return True
            raise RepairWorkflowError(
                "automatic repair reached --candidate-limit "
                f"after testing {candidate_limit} repair choices"
            )
        active_group_keys = frozenset(
            key for refusal in donor_refusals for key in _donor_group_keys(refusal)
        )
        deferred_group_keys = frozenset(state.exhausted_groups & active_group_keys)
        excluded_group_keys = (
            deferred_group_keys if active_group_keys - deferred_group_keys else frozenset()
        )
        frozen_abandoned = {key: frozenset(value) for key, value in state.abandoned_states.items()}
        discovery_refusals = tuple(
            item
            for item in donor_refusals
            if not isinstance(item.intervention, LegacyOracleInstallIntervention)
        )
        donor_discovery = None
        unresolved_discovery: tuple[tuple[str, str, str], ...] = ()
        with ClassicRepairProbeSession(probe_options, progress) as probe_session:
            probe = probe_classic_donor_repairs(
                probe_options,
                progress,
                donor_refusals,
                candidate_budget=remaining_candidates,
                abandoned_states=frozen_abandoned,
                compile_cache=compile_cache,
                excluded_groups=excluded_group_keys,
                session=probe_session,
            )
            state.consume_candidates(
                probe.compiled_candidates,
                search="donor repair",
            )
            state.exhausted_groups.update(
                (refusal.unit_id, refusal.donor_id)
                for refusal in probe.refusals
                if getattr(refusal, "exhausted", False)
            )
            if not probe.repairs and excluded_group_keys:
                # Nothing fresh settled: give the deferred groups their final attempt.
                remaining_candidates = candidate_limit - state.compiled_candidates
                if remaining_candidates > 0:
                    probe = probe_classic_donor_repairs(
                        probe_options,
                        progress,
                        donor_refusals,
                        candidate_budget=remaining_candidates,
                        abandoned_states=frozen_abandoned,
                        compile_cache=compile_cache,
                        session=probe_session,
                    )
                    state.consume_candidates(
                        probe.compiled_candidates,
                        search="donor repair",
                    )
                    state.exhausted_groups.update(
                        (refusal.unit_id, refusal.donor_id)
                        for refusal in probe.refusals
                        if getattr(refusal, "exhausted", False)
                    )
            if not probe.repairs and discovery_refusals:
                remaining_candidates = candidate_limit - state.compiled_candidates
                donor_discovery = probe_classic_carrier_discovery(
                    probe_options,
                    progress,
                    discovery_refusals,
                    candidate_budget=remaining_candidates,
                    tried_states={
                        key: frozenset(value) for key, value in state.discovered_shapes.items()
                    },
                    compile_cache=compile_cache,
                    session=probe_session,
                )
                state.consume_candidates(
                    donor_discovery.compiled_candidates,
                    search="carrier discovery",
                )
                unresolved_discovery = donor_discovery.unresolved
                for unit_id, digests in getattr(donor_discovery, "tried_states", {}).items():
                    state.discovered_shapes.setdefault(unit_id, set()).update(digests)
        # The runtime is closed before any authority mutation below.
        if probe.repairs:
            changed = apply_classic_donor_repairs(staged_root, spec, probe.repairs)
            for repair in probe.repairs:
                if getattr(repair, "abandoned_state", ""):
                    state.abandoned_states.setdefault((repair.unit_id, repair.donor_id), set()).add(
                        repair.abandoned_state
                    )
            state.donor_retunes += len(probe.repairs)
            state.record_transition(
                changed,
                empty_error="donor repair reported success without changing saved guidance",
                outcome="adjusted " + count_phrase(len(probe.repairs), "compiler choice"),
            )
            return True
        if donor_discovery is not None and donor_discovery.repairs:
            changed = apply_classic_discovery_repairs(staged_root, spec, donor_discovery.repairs)
            resolved = sum(len(item.resolutions) for item in donor_discovery.repairs)
            state.discovered_actions += resolved
            state.record_transition(
                changed,
                empty_error=("carrier discovery reported success without changing saved guidance"),
                outcome="added " + count_phrase(resolved, "function repair"),
            )
            return True
        if legacy_fallbacks:
            changed = _publish_legacy_fallbacks(staged_root, bundle.spec, legacy_fallbacks)
            state.reauthored_actions += len(legacy_fallbacks)
            state.record_transition(
                changed,
                empty_error=(
                    "legacy re-authoring reported success without changing saved guidance"
                ),
                outcome="narrowed " + count_phrase(len(legacy_fallbacks), "quarantine record"),
            )
            return True
        if probe.best_refusal is not None:
            raise _probe_refusal_error(
                probe.best_refusal,
                unresolved_discovery,
            )
    return False


def repair_classic_records(
    options: RepairWorkflowOptions,
    progress: ExecutionProgress,
    *,
    staged_root: Path,
    spec: ProjectSpec,
    cache_root: Path,
    settle_target_ids: frozenset[str] = frozenset(),
    link_layout_hint: ClassicLinkLayoutHint | None = None,
) -> RepairWorkflowResult:
    """Run the ordered repair stages until a fresh analysis finds no fallout."""

    state = RepairSessionState(options.adjustment_rounds, options.candidate_limit)
    compile_cache = ClassicDonorCompileStore(probe_store_directory(cache_root))
    context = _RepairContext(
        options,
        progress,
        staged_root,
        spec,
        cache_root,
        state,
        compile_cache,
        options.probes(staged_root),
        settle_target_ids,
        link_layout_hint,
    )
    saved_ledger = _composed_body_ledger(cache_root)
    while True:
        bundle = load_project_tree(staged_root)
        state.begin_pass(bundle)
        ledger = _ledger_for_bundle(saved_ledger, bundle)
        analysis = _analyze_repair_pass(context, ledger)
        if _repair_measured_checks(context, analysis):
            continue
        if analysis.completed:
            if _repair_unrecorded_functions(context, bundle, ledger, analysis):
                continue
            if _repair_source_layout(context, bundle):
                continue
            return state.result(compile_cache)

        receipts = _classic_receipts(bundle)
        legacy = _prepare_legacy_fallout(context, bundle, analysis, receipts)
        if _resolve_obsolete_quarantine(context, bundle, legacy.no_window_resolution):
            continue
        retirement = _retire_redundant_adjustments(context, bundle, legacy.refusals, receipts)
        if retirement.changed:
            continue
        if _reauthor_existing_functions(context, legacy.refusals):
            continue
        if _repair_donor_fallout(context, bundle, legacy.refusals, legacy.fallbacks):
            continue
        reasons = (
            *(item.reason for item in legacy.refusals),
            *legacy.failures,
            *retirement.failures,
        )
        detail = next((_one_line(reason) for reason in reasons if reason), "unknown fallout")
        raise RepairWorkflowError("automatic repair could not find a safe adjustment: " + detail)


class RepairRecords(Protocol):
    def __call__(
        self,
        options: RepairWorkflowOptions,
        progress: ExecutionProgress,
        *,
        staged_root: Path,
        spec: ProjectSpec,
        cache_root: Path,
        settle_target_ids: frozenset[str] = frozenset(),
        link_layout_hint: ClassicLinkLayoutHint | None = None,
    ) -> RepairWorkflowResult: ...


VerifyProject = Callable[[VerifyRequest, ExecutionProgress], VerifyResult]


@dataclass(frozen=True, slots=True)
class RepairAttemptResult:
    candidate: RepairCandidate
    transaction: TransactionResult
    regeneration: RegenerationPlan
    workflow: RepairWorkflowResult
    staged: StagedProject
    cleanup_warning: str | None = None


class RepairAttemptFailure(RuntimeError):
    """Expected candidate failure with the phase and retained workspace attached."""

    def __init__(self, error: Exception, *, phase: str, staged: StagedProject) -> None:
        super().__init__(str(error))
        self.error = error
        self.phase = phase
        self.staged = staged


def _merge_cleanup_warnings(*warnings: str | None) -> str | None:
    parts = tuple(warning for warning in warnings if warning)
    return "; ".join(parts) if parts else None


def _merge_workflow_results(
    first: RepairWorkflowResult,
    second: RepairWorkflowResult,
) -> RepairWorkflowResult:
    """Combine accounting from consecutive private repair passes."""

    return RepairWorkflowResult(
        changed_records=tuple(
            sorted(
                {*first.changed_records, *second.changed_records},
                key=lambda item: (item.casefold(), item),
            )
        ),
        affected_units=tuple(
            sorted({*first.affected_units, *second.affected_units}, key=str.casefold)
        ),
        measured_checks=first.measured_checks + second.measured_checks,
        retired_actions=first.retired_actions + second.retired_actions,
        removed_donors=first.removed_donors + second.removed_donors,
        donor_retunes=first.donor_retunes + second.donor_retunes,
        compiled_candidates=first.compiled_candidates + second.compiled_candidates,
        passes=first.passes + second.passes,
        reauthored_actions=first.reauthored_actions + second.reauthored_actions,
        discovered_actions=first.discovered_actions + second.discovered_actions,
        replayed_candidates=first.replayed_candidates + second.replayed_candidates,
        admitted_units=first.admitted_units + second.admitted_units,
        source_retunes=first.source_retunes + second.source_retunes,
        adjustment_rounds=first.adjustment_rounds + second.adjustment_rounds,
    )


def _cold_mismatch_targets(
    verified: VerifyResult,
) -> frozenset[str]:
    """Return target IDs eligible for one evidence-driven layout retry."""

    report = verified.engine.report
    if not (
        report.verdict.cold and report.verdict.logic_certified and not report.verdict.byte_exact
    ):
        return frozenset()
    return frozenset(target.id for target in report.targets if not target.byte_exact)


def _cold_link_layout_hint(
    staged_root: Path,
    target_ids: frozenset[str],
    candidate_outputs: Mapping[str, bytes],
) -> ClassicLinkLayoutHint | None:
    """Derive one transient compiler-layout objective from a failed cold proof."""

    try:
        bundle = load_project_tree(staged_root)
        graph = bundle.producer_graph
        if graph is None:
            return None
        targets = {target.id: target for target in bundle.spec.targets}
        companions = {item.target_id: item for item in classic_debug_companion_paths(bundle)}
        for target_id in sorted(target_ids, key=str.casefold):
            target = targets.get(target_id)
            companion = companions.get(target_id)
            if target is None or companion is None:
                continue
            candidate_image = candidate_outputs.get(target.artifact)
            debug_image = candidate_outputs.get(companion.image)
            pdb = candidate_outputs.get(companion.pdb)
            if candidate_image is None or debug_image is None or pdb is None:
                continue
            _size, _digest, oracle_image = receipt_source_input(
                staged_root,
                target.oracle,
                capture=True,
            )
            if oracle_image is None:
                raise AssertionError("captured source receipt has no payload")
            hint = derive_classic_link_layout_hint(
                bundle,
                graph,
                target_id=target_id,
                candidate_image=candidate_image,
                oracle_image=oracle_image,
                debug_image=debug_image,
                pdb=pdb,
            )
            if hint is not None:
                return hint
    except (OSError, ValueError):
        return None
    return None


def execute_repair_attempt(
    options: RepairWorkflowOptions,
    progress: ExecutionProgress,
    *,
    snapshot: RepairSnapshot,
    selected_paths: tuple[str, ...],
    cache_root: Path,
    candidate_report_directory: str,
    final_report_directory: str,
    report_preimages: tuple[RepairOutputSnapshot, ...],
    keep: KeepWorkspace,
    verify_project: VerifyProject,
    repair_records: RepairRecords,
) -> RepairAttemptResult:
    """Run, prove, and publish one candidate or raise an expected typed failure."""

    staged = stage_repair_project(snapshot, keep=keep)
    phase = "preparing a private repair workspace"
    published = False
    result: RepairAttemptResult | None = None
    try:
        with staged as staged_root:
            phase = "refreshing saved source records"
            try:
                regeneration = plan_source_regeneration(
                    staged_root,
                    clean_preimage_root=snapshot.root,
                )
                apply_source_regeneration(staged_root, regeneration)
            except SourceRegenerationError as exc:
                raise RepairError(f"mechanical source repair refused: {exc}") from exc

            source_lock = plan_source_lock(
                staged_root,
                selected_paths,
                progress,
                seal=True,
            )
            apply_source_lock(
                source_lock,
                invalidate_producer_graph=False,
            )

            phase = "repairing saved build guidance"
            candidate_limit = options.candidate_limit
            adjustment_limit = options.adjustment_rounds
            verify_request = VerifyRequest(
                project=staged_root,
                execution=options.execution,
                policy=options.policy,
                report_directory=candidate_report_directory,
                keep_workspace=KeepWorkspace.NEVER,
            )
            workflow = repair_records(
                options,
                progress,
                staged_root=staged_root,
                spec=snapshot.spec,
                cache_root=cache_root,
                settle_target_ids=frozenset(),
                link_layout_hint=None,
            )
            _consume_candidate_budget(
                0,
                workflow.compiled_candidates,
                limit=candidate_limit,
                search="automatic repair",
            )
            if not 0 <= workflow.adjustment_rounds <= adjustment_limit:
                raise RepairWorkflowError(
                    "automatic repair exceeded its command-wide adjustment-round budget"
                )

            while True:
                authorized_records = {
                    snapshot.spec.layout.source_manifest,
                    snapshot.spec.layout.build_plan,
                    snapshot.spec.layout.producer_graph,
                    *regeneration.changed_documents,
                    *workflow.changed_records,
                }
                record_postimages = capture_repair_record_postimages(
                    snapshot,
                    staged_root,
                    authorized_records,
                )

                phase = "proving every target from scratch"
                verified = verify_project(verify_request, progress)
                if verified.accepted:
                    break

                phase = "checking the private from-scratch result"
                # A failed verifier may write outputs and reports, but it may not
                # alter any sealed input or authorized record.  Reuse the final
                # collection boundary to prove that before another repair pass.
                try:
                    failed_candidate = collect_repair_candidate(
                        snapshot,
                        staged_root,
                        report_directory=candidate_report_directory,
                        verified=verified,
                        record_postimages=record_postimages,
                    )
                    target_ids = _cold_mismatch_targets(
                        verified,
                    )
                    link_layout_hint = _cold_link_layout_hint(
                        staged_root,
                        target_ids,
                        failed_candidate.outputs,
                    )
                except RepairError as exc:
                    raise RepairError(
                        "candidate output did not satisfy exact verification and the committed "
                        f"authenticity policy; {_one_line(exc)}"
                    ) from exc
                if not target_ids:
                    raise RepairError(
                        "candidate output did not satisfy exact verification and the committed "
                        "authenticity policy"
                    )

                remaining_candidates = candidate_limit - workflow.compiled_candidates
                if remaining_candidates <= 0:
                    raise RepairWorkflowError(
                        "from-scratch verification found link layout fallout after repair "
                        "reached --candidate-limit"
                    )
                remaining_rounds = adjustment_limit - workflow.adjustment_rounds
                if remaining_rounds <= 0:
                    raise RepairWorkflowError(
                        "from-scratch verification found link layout fallout after repair "
                        "reached its saved-guidance adjustment-round limit"
                    )

                phase = "settling link layout for the affected targets"
                followup_options = replace(
                    options,
                    candidate_limit=remaining_candidates,
                    adjustment_rounds=remaining_rounds,
                )
                followup = repair_records(
                    followup_options,
                    progress,
                    staged_root=staged_root,
                    spec=snapshot.spec,
                    cache_root=cache_root,
                    settle_target_ids=target_ids,
                    link_layout_hint=link_layout_hint,
                )
                _consume_candidate_budget(
                    workflow.compiled_candidates,
                    followup.compiled_candidates,
                    limit=candidate_limit,
                    search="link layout repair",
                )
                if not 0 <= followup.adjustment_rounds <= remaining_rounds:
                    raise RepairWorkflowError(
                        "link layout repair exceeded its remaining command-wide "
                        "adjustment-round budget"
                    )
                if followup.source_retunes < 1 or not followup.changed_records:
                    raise RepairWorkflowError(
                        "from-scratch verification found link layout fallout, but no safe "
                        "automatic source adjustment settled it"
                    )
                workflow = _merge_workflow_results(workflow, followup)

            phase = "collecting the verified repair result"
            candidate = collect_repair_candidate(
                snapshot,
                staged_root,
                report_directory=candidate_report_directory,
                verified=verified,
                record_postimages=record_postimages,
            )
            phase = "publishing the verified repair result"
            transaction = publish_repair_candidate(
                snapshot,
                candidate,
                report_directory=final_report_directory,
                report_preimages=report_preimages,
            )
            published = True
            result = RepairAttemptResult(
                candidate,
                transaction,
                regeneration,
                workflow,
                staged,
                transaction.cleanup_warning,
            )
    except KeyboardInterrupt:
        if published and result is not None:
            return replace(
                result,
                cleanup_warning=_merge_cleanup_warnings(
                    result.cleanup_warning,
                    "private workspace cleanup was interrupted",
                ),
            )
        raise
    except Exception as error:
        if published and result is not None:
            return replace(
                result,
                cleanup_warning=_merge_cleanup_warnings(
                    result.cleanup_warning,
                    str(error),
                ),
            )
        raise RepairAttemptFailure(error, phase=phase, staged=staged) from error
    assert result is not None
    return result


__all__ = [
    "RepairAnalysisError",
    "RepairAnalysisResult",
    "RepairAttemptFailure",
    "RepairAttemptResult",
    "RepairRecords",
    "RepairWorkflowError",
    "RepairWorkflowOptions",
    "RepairWorkflowResult",
    "VerifyProject",
    "analyze_classic_repair",
    "execute_repair_attempt",
    "repair_classic_records",
]
