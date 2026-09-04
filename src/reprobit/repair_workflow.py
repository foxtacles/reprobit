"""Bounded classic authority repair for one private staged project.

One repair attempt stages the sealed project, refreshes its source records,
repairs saved build guidance through bounded warm analysis passes, proves
every target from scratch, and publishes the verified result atomically.
"""

from __future__ import annotations

import argparse
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
from reprobit.classic_repair_probe import (
    DEFAULT_RETUNE_PROBE_CANDIDATES,
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
from reprobit.cli_build import command_build
from reprobit.cli_output import CLIOutput, count_phrase
from reprobit.cli_project import command_source_lock
from reprobit.composition_ledger import (
    COMPOSED_BODY_LEDGER_RELATIVE,
    ComposedBodyLedger,
    read_ledger,
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
from reprobit.report_io import read_report_json
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    LegacyOracleInstallIntervention,
    ProjectBundle,
    ProjectSpec,
    classic_debug_companion_paths,
    classic_function_donor_ids,
)
from reprobit.source_lock import receipt_source_input
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

MAX_REPAIR_ADJUSTMENT_ROUNDS = 24
MAX_REPAIR_DONOR_CANDIDATES = DEFAULT_RETUNE_PROBE_CANDIDATES


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


def _repair_limit(args: argparse.Namespace, name: str, default: int) -> int:
    """Resolve one optional CLI repair bound while preserving its default."""

    return getattr(args, name, None) or default


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


class RepairAnalysisError(RuntimeError):
    """A non-certifying analysis failed outside a recorded repair seat."""


@dataclass(frozen=True, slots=True)
class RepairAnalysisResult:
    """Measured and structural fallout from one bounded incremental pass."""

    completed: bool
    measured_repairs: tuple[ClassicReceiptRepair, ...]
    structural_refusals: tuple[RepairRefusal, ...]
    seed_objects: Mapping[str, SeedObject] = field(default_factory=lambda: MappingProxyType({}))


def analyze_classic_repair(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    cache_root: Path | None = None,
    progress_description: str = "checking affected source files",
    seed_census: bool = False,
) -> RepairAnalysisResult:
    """Run one warm analysis and distinguish repair fallout from fatal failure.

    With ``seed_census`` the analysis also compiles every translation unit and
    returns each fresh object so the caller can census unrecorded fallout.
    """

    session = ClassicRepairSession()
    values = vars(args).copy()
    values.update(
        cold=False,
        keep_workspace=KeepWorkspace.NEVER.value,
        _classic_measured_receipt_repair=session,
        _classic_repair_analysis_only=True,
        _classic_seed_census=seed_census,
        _incremental_cache_root=cache_root,
        _incremental_progress_description=progress_description,
    )
    try:
        status = command_build(argparse.Namespace(**values), output)
    except Exception as exc:
        raise RepairAnalysisError(f"repair analysis failed: {exc}") from exc
    if status != 0:
        raise RepairAnalysisError(f"repair analysis returned failure status {status}")
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
        session.seed_objects,
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
    except (OSError, ValueError) as exc:
        raise RepairWorkflowError(f"saved repair data at {path} is unreadable: {exc}") from exc


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


def repair_classic_records(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    staged_root: Path,
    spec: ProjectSpec,
    cache_root: Path,
    settle_target_ids: frozenset[str] = frozenset(),
    link_layout_hint: ClassicLinkLayoutHint | None = None,
) -> RepairWorkflowResult:
    """Repair measured, redundant, then nearby-donor fallout until composition is clean.

    ``args.adjustment_rounds`` and ``args.donor_candidates`` raise the default
    round and command-wide donor-candidate limits for large shared-header
    repairs; the search stays bounded by whatever the command line declares.
    """

    adjustment_limit = _repair_limit(args, "adjustment_rounds", MAX_REPAIR_ADJUSTMENT_ROUNDS)
    candidate_limit = _repair_limit(args, "donor_candidates", MAX_REPAIR_DONOR_CANDIDATES)
    changed_records: set[str] = set()
    affected_units: set[str] = set()
    measured_checks = 0
    retired_actions = 0
    removed_donors = 0
    donor_retunes = 0
    reauthored_actions = 0
    discovered_actions = 0
    admitted_units = 0
    source_retunes = 0
    compiled_candidates = 0
    seen_authority: set[str] = set()
    adjustment_rounds = 0
    initial_function_actions: int | None = None
    pass_number = 0
    last_outcome: str | None = None
    # Donor groups whose complete bounded candidate set already failed once in this
    # command.  Their saved state has not changed, so they are deferred until every
    # other group is settled and then given one final attempt, instead of burning
    # the same thousands of compiles in every round.
    exhausted_groups: set[tuple[str, str]] = set()
    # Donor states this command saved and then moved away from; a later round
    # must not return a donor to one of them (two consumers would otherwise
    # trade it back and forth until the fingerprint guard stops the run).
    abandoned_states: dict[tuple[str, str], set[str]] = {}
    # Carrier states discovery already compiled per unit in this command.
    discovered_shapes: dict[str, set[str]] = {}
    # Donor compiles are pure functions of their seat and compile epoch: never
    # compile one twice, in this command or in a later one.
    compile_cache = ClassicDonorCompileStore(probe_store_directory(cache_root))
    # The composed-body ledger of the last accepted verify, when this state
    # directory holds one, lets every clean pass census unrecorded fallout: a
    # function without a saved record whose fresh seed body left the body the
    # linker selected at verify time would change the image just like a
    # refused record does, so it is discovered and recorded before the repair
    # reports success.
    ledger = _composed_body_ledger(cache_root)

    while True:
        pass_number += 1
        bundle = load_project_tree(staged_root)
        if initial_function_actions is None:
            initial_function_actions = sum(
                isinstance(item, LegacyOracleInstallIntervention)
                or getattr(item, "role", None) is ClassicRecipeRole.FUNCTION
                for item in bundle.interventions
            )
        maximum_analyses = initial_function_actions + adjustment_limit + 1
        if pass_number > maximum_analyses:
            raise RepairWorkflowError("automatic repair exceeded its monotonic analysis bound")
        fingerprint = _authority_fingerprint(bundle)
        if fingerprint in seen_authority:
            raise RepairWorkflowError(
                "automatic repair reached a previously checked saved-guidance state"
            )
        seen_authority.add(fingerprint)
        if settle_target_ids:
            progress_description = (
                f"repair pass {pass_number}: checking a remaining link layout mismatch"
            )
        else:
            progress_description = f"repair pass {pass_number}: checking affected source files"
        if last_outcome is not None and settle_target_ids:
            progress_description = (
                f"repair pass {pass_number}: checking the link layout again ({last_outcome})"
            )
        elif last_outcome is not None:
            progress_description = f"repair pass {pass_number}: checking again ({last_outcome})"
        analysis = analyze_classic_repair(
            args,
            output,
            cache_root=cache_root,
            progress_description=progress_description,
            seed_census=ledger is not None,
        )
        affected_units.update(item.unit_id for item in analysis.measured_repairs)
        affected_units.update(item.unit_id for item in analysis.structural_refusals)

        if analysis.measured_repairs:
            if adjustment_rounds >= adjustment_limit:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{adjustment_limit} saved-guidance adjustment rounds"
                )
            changed = apply_classic_receipt_repairs(
                staged_root,
                spec,
                analysis.measured_repairs,
            )
            if not changed:
                raise RepairWorkflowError(
                    "measured repair reported success without changing saved guidance"
                )
            changed_records.update(changed)
            measured_checks += len(analysis.measured_repairs)
            adjustment_rounds += 1
            last_outcome = "refreshed " + count_phrase(
                len(analysis.measured_repairs),
                "saved check",
            )
            continue

        if analysis.completed:
            if ledger is not None:
                census = plan_repair_census(
                    bundle, ledger, getattr(analysis, "seed_objects", None) or {}
                )
                if census.missing:
                    raise RepairWorkflowError(
                        "the edit removed functions used by the last accepted build: "
                        + _listed_census(census.missing)
                    )
                if census.unplanned:
                    # Fallout in a unit the plan never listed: admit the unit (plan
                    # entry plus empty shards) so the next pass can record it.
                    if adjustment_rounds >= adjustment_limit:
                        raise RepairWorkflowError(
                            "automatic repair reached its limit of "
                            f"{adjustment_limit} saved-guidance adjustment rounds"
                        )
                    try:
                        admitted = plan_translation_unit_admissions(bundle, census.unplanned)
                        changed = apply_translation_unit_admissions(staged_root, spec, admitted)
                    except TranslationUnitAdmissionError as exc:
                        raise RepairWorkflowError(
                            "automatic repair could not add saved guidance for newly affected "
                            f"source files ({_listed_census(census.unplanned)}): " + _one_line(exc)
                        ) from exc
                    if not changed:
                        raise RepairWorkflowError(
                            "source-file admission reported success without changing saved guidance"
                        )
                    changed_records.update(changed)
                    admitted_units += len(admitted)
                    adjustment_rounds += 1
                    last_outcome = "added " + count_phrase(
                        len(admitted),
                        "affected source build",
                    )
                    continue
                if census.refusals:
                    if adjustment_rounds >= adjustment_limit:
                        raise RepairWorkflowError(
                            "automatic repair reached its limit of "
                            f"{adjustment_limit} saved-guidance adjustment rounds"
                        )
                    remaining_candidates = candidate_limit - compiled_candidates
                    if remaining_candidates <= 0:
                        raise RepairWorkflowError(
                            "automatic repair exhausted the command-wide --donor-candidates "
                            f"limit after testing {candidate_limit} repair choices"
                        )
                    affected_units.update(item.unit_id for item in census.refusals)
                    discovery = probe_classic_carrier_discovery(
                        args,
                        output,
                        census.refusals,
                        candidate_budget=remaining_candidates,
                        tried_states={
                            key: frozenset(value) for key, value in discovered_shapes.items()
                        },
                        compile_cache=compile_cache,
                    )
                    compiled_candidates = _consume_candidate_budget(
                        compiled_candidates,
                        discovery.compiled_candidates,
                        limit=candidate_limit,
                        search="newly affected function discovery",
                    )
                    for unit_id, digests in getattr(discovery, "tried_states", {}).items():
                        discovered_shapes.setdefault(unit_id, set()).update(digests)
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
                    if not changed:
                        raise RepairWorkflowError(
                            "new-function check reported success without changing saved guidance"
                        )
                    changed_records.update(changed)
                    resolved = sum(len(item.resolutions) for item in discovery.repairs)
                    discovered_actions += resolved
                    adjustment_rounds += 1
                    last_outcome = "added " + count_phrase(
                        resolved,
                        "function repair",
                    )
                    continue
            if any(
                isinstance(item, ClassicRecipeIntervention)
                and item.role is ClassicRecipeRole.PROJECT
                and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
                for item in bundle.interventions
            ):
                remaining_candidates = max(0, candidate_limit - compiled_candidates)
                source_result = probe_classic_project_overlay_repairs(
                    args,
                    output,
                    candidate_budget=remaining_candidates,
                    settle_target_ids=settle_target_ids,
                    link_layout_hint=link_layout_hint,
                )
                compiled_candidates = _consume_candidate_budget(
                    compiled_candidates,
                    source_result.compiled_candidates,
                    limit=candidate_limit,
                    search="source-layout repair",
                )
                if source_result.repair is not None:
                    if adjustment_rounds >= adjustment_limit:
                        raise RepairWorkflowError(
                            "automatic repair reached its limit of "
                            f"{adjustment_limit} saved-guidance adjustment rounds"
                        )
                    changed = apply_classic_project_overlay_repair(
                        staged_root,
                        spec,
                        source_result.repair,
                    )
                    if not changed:
                        raise RepairWorkflowError(
                            "source-layout repair reported success without changing saved guidance"
                        )
                    changed_records.update(changed)
                    try:
                        regeneration = plan_source_regeneration(staged_root)
                        apply_source_regeneration(staged_root, regeneration)
                    except SourceRegenerationError as exc:
                        raise RepairWorkflowError(
                            "source-layout repair could not refresh its saved output checks: "
                            + _one_line(exc)
                        ) from exc
                    changed_records.update(regeneration.changed_documents)
                    source_retunes += 1
                    adjustment_rounds += 1
                    last_outcome = "adjusted one source layout"
                    continue
                if source_result.checked and source_result.reason is not None:
                    if source_result.exhausted:
                        raise RepairWorkflowError(
                            "automatic repair exhausted the command-wide --donor-candidates "
                            f"limit after testing {candidate_limit} repair choices"
                        )
                    raise RepairWorkflowError(
                        "automatic repair could not find a safe source layout for "
                        f"{source_result.source_path or 'an affected source'}: "
                        + _one_line(source_result.reason)
                    )
            return RepairWorkflowResult(
                changed_records=tuple(
                    sorted(changed_records, key=lambda item: (item.casefold(), item))
                ),
                affected_units=tuple(sorted(affected_units, key=str.casefold)),
                measured_checks=measured_checks,
                retired_actions=retired_actions,
                removed_donors=removed_donors,
                donor_retunes=donor_retunes,
                compiled_candidates=compiled_candidates,
                passes=pass_number,
                reauthored_actions=reauthored_actions,
                discovered_actions=discovered_actions,
                replayed_candidates=compile_cache.memory_hits + compile_cache.disk_hits,
                admitted_units=admitted_units,
                source_retunes=source_retunes,
                adjustment_rounds=adjustment_rounds,
            )

        receipts = _classic_receipts(bundle)
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
                else:
                    break
            except (LegacyRepairError, RuntimeError, ValueError) as exc:
                legacy_failures.append(str(exc))
                structural_refusals.append(refusal)
                continue
            with_baseline = replace(refusal, baseline_repair=repaired)
            structural_refusals.append(with_baseline)
            legacy_fallbacks.append((with_baseline, repaired))
        if no_window_resolution is not None:
            if adjustment_rounds >= adjustment_limit:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{adjustment_limit} saved-guidance adjustment rounds"
                )
            changed = _publish_legacy_no_window_resolution(
                staged_root,
                bundle.spec,
                no_window_resolution,
            )
            if not changed:
                raise RepairWorkflowError(
                    "legacy dequarantine reported success without changing saved guidance"
                )
            changed_records.update(changed)
            removed_donors += len(no_window_resolution.removed_donors)
            if no_window_resolution.replaced:
                reauthored_actions += 1
                last_outcome = "replaced 1 obsolete quarantine record"
            else:
                retired_actions += 1
                last_outcome = "removed 1 obsolete quarantine record"
            adjustment_rounds += 1
            continue
        current_refusals = tuple(structural_refusals)

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
            if not changed:
                raise RepairWorkflowError(
                    "redundant-action retirement reported success without changing saved guidance"
                )
            changed_records.update(changed)
            retired_actions += len(retirement_candidates)
            removed_donors += len(plan.removed_donors)
            last_outcome = "removed " + count_phrase(
                len(retirement_candidates),
                "obsolete function record",
            )
            continue

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
            if adjustment_rounds >= adjustment_limit:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{adjustment_limit} saved-guidance adjustment rounds"
                )
            changed = apply_classic_authority_edits(
                staged_root,
                spec,
                interventions=reauthor_plan.intervention_edits,
                receipts=reauthor_plan.receipt_edits,
                additions=reauthor_plan.additions,
                dependencies=reauthor_plan.dependency_edits,
            )
            if not changed:
                raise RepairWorkflowError(
                    "function re-authoring reported success without changing saved guidance"
                )
            changed_records.update(changed)
            reauthored_actions += len(reauthor_plan.reauthorings)
            adjustment_rounds += 1
            last_outcome = "updated " + count_phrase(
                len(reauthor_plan.reauthorings),
                "function record",
            )
            continue

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
            if adjustment_rounds >= adjustment_limit:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{adjustment_limit} saved-guidance adjustment rounds"
                )
            remaining_candidates = candidate_limit - compiled_candidates
            if remaining_candidates <= 0:
                if legacy_fallbacks:
                    changed = _publish_legacy_fallbacks(staged_root, bundle.spec, legacy_fallbacks)
                    if not changed:
                        raise RepairWorkflowError(
                            "legacy re-authoring reported success without changing saved guidance"
                        )
                    changed_records.update(changed)
                    reauthored_actions += len(legacy_fallbacks)
                    adjustment_rounds += 1
                    last_outcome = "narrowed " + count_phrase(
                        len(legacy_fallbacks),
                        "quarantine record",
                    )
                    continue
                raise RepairWorkflowError(
                    "automatic repair exhausted the command-wide --donor-candidates "
                    f"limit after testing {candidate_limit} repair choices"
                )
            active_group_keys = frozenset(
                key for refusal in donor_refusals for key in _donor_group_keys(refusal)
            )
            deferred_group_keys = frozenset(exhausted_groups & active_group_keys)
            excluded_group_keys = (
                deferred_group_keys if active_group_keys - deferred_group_keys else frozenset()
            )
            frozen_abandoned = {key: frozenset(value) for key, value in abandoned_states.items()}
            probe = probe_classic_donor_repairs(
                args,
                output,
                donor_refusals,
                candidate_budget=remaining_candidates,
                abandoned_states=frozen_abandoned,
                compile_cache=compile_cache,
                excluded_groups=excluded_group_keys,
            )
            compiled_candidates = _consume_candidate_budget(
                compiled_candidates,
                probe.compiled_candidates,
                limit=candidate_limit,
                search="donor repair",
            )
            exhausted_groups.update(
                (refusal.unit_id, refusal.donor_id)
                for refusal in probe.refusals
                if getattr(refusal, "exhausted", False)
            )
            if not probe.repairs and excluded_group_keys:
                # Nothing fresh could be settled: give the deferred groups their final attempt.
                remaining_candidates = candidate_limit - compiled_candidates
                if remaining_candidates > 0:
                    probe = probe_classic_donor_repairs(
                        args,
                        output,
                        donor_refusals,
                        candidate_budget=remaining_candidates,
                        abandoned_states=frozen_abandoned,
                        compile_cache=compile_cache,
                    )
                    compiled_candidates = _consume_candidate_budget(
                        compiled_candidates,
                        probe.compiled_candidates,
                        limit=candidate_limit,
                        search="donor repair",
                    )
                    exhausted_groups.update(
                        (refusal.unit_id, refusal.donor_id)
                        for refusal in probe.refusals
                        if getattr(refusal, "exhausted", False)
                    )
            if probe.repairs:
                changed = apply_classic_donor_repairs(staged_root, spec, probe.repairs)
                if not changed:
                    raise RepairWorkflowError(
                        "donor repair reported success without changing saved guidance"
                    )
                changed_records.update(changed)
                for repair in probe.repairs:
                    if getattr(repair, "abandoned_state", ""):
                        abandoned_states.setdefault((repair.unit_id, repair.donor_id), set()).add(
                            repair.abandoned_state
                        )
                donor_retunes += len(probe.repairs)
                adjustment_rounds += 1
                last_outcome = "adjusted " + count_phrase(
                    len(probe.repairs),
                    "compiler choice",
                )
                continue
            # No saved donor can be retuned: compile fresh carrier states for the
            # affected units and accept any that carries a refused record's body.
            remaining_candidates = candidate_limit - compiled_candidates
            discovery_refusals = tuple(
                item
                for item in donor_refusals
                if not isinstance(item.intervention, LegacyOracleInstallIntervention)
            )
            unresolved_discovery: tuple[tuple[str, str, str], ...] = ()
            if discovery_refusals:
                discovery = probe_classic_carrier_discovery(
                    args,
                    output,
                    discovery_refusals,
                    candidate_budget=remaining_candidates,
                    tried_states={
                        key: frozenset(value) for key, value in discovered_shapes.items()
                    },
                    compile_cache=compile_cache,
                )
                compiled_candidates = _consume_candidate_budget(
                    compiled_candidates,
                    discovery.compiled_candidates,
                    limit=candidate_limit,
                    search="carrier discovery",
                )
                unresolved_discovery = discovery.unresolved
                for unit_id, digests in getattr(discovery, "tried_states", {}).items():
                    discovered_shapes.setdefault(unit_id, set()).update(digests)
                if discovery.repairs:
                    changed = apply_classic_discovery_repairs(staged_root, spec, discovery.repairs)
                    if not changed:
                        raise RepairWorkflowError(
                            "carrier discovery reported success without changing saved guidance"
                        )
                    changed_records.update(changed)
                    resolved = sum(len(item.resolutions) for item in discovery.repairs)
                    discovered_actions += resolved
                    adjustment_rounds += 1
                    last_outcome = "added " + count_phrase(
                        resolved,
                        "function repair",
                    )
                    continue
            if legacy_fallbacks:
                changed = _publish_legacy_fallbacks(staged_root, bundle.spec, legacy_fallbacks)
                if not changed:
                    raise RepairWorkflowError(
                        "legacy re-authoring reported success without changing saved guidance"
                    )
                changed_records.update(changed)
                reauthored_actions += len(legacy_fallbacks)
                adjustment_rounds += 1
                last_outcome = "narrowed " + count_phrase(
                    len(legacy_fallbacks),
                    "quarantine record",
                )
                continue
            if probe.best_refusal is not None:
                raise _probe_refusal_error(
                    probe.best_refusal,
                    unresolved_discovery,
                )
            probe_reasons: list[str] = []
        else:
            probe_reasons = []

        reasons = [
            *(item.reason for item in current_refusals),
            *legacy_failures,
            *retirement_failures,
            *probe_reasons,
        ]
        detail = next((" ".join(reason.split()) for reason in reasons if reason), "unknown fallout")
        raise RepairWorkflowError("automatic repair could not find a safe adjustment: " + detail)


class RepairRecords(Protocol):
    def __call__(
        self,
        args: argparse.Namespace,
        output: CLIOutput,
        *,
        staged_root: Path,
        spec: ProjectSpec,
        cache_root: Path,
        settle_target_ids: frozenset[str] = frozenset(),
        link_layout_hint: ClassicLinkLayoutHint | None = None,
    ) -> RepairWorkflowResult: ...


VerifyCommand = Callable[[argparse.Namespace, CLIOutput], int]


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


def _candidate_args(
    args: argparse.Namespace, staged_root: Path, report_directory: str
) -> argparse.Namespace:
    values = vars(args).copy()
    values.update(
        project=str(staged_root),
        report_dir=report_directory,
        action_receipt=None,
        action_nonce=None,
        keep_workspace=KeepWorkspace.NEVER.value,
    )
    return argparse.Namespace(**values)


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
    staged_root: Path,
    report_directory: str,
) -> frozenset[str]:
    """Return target IDs eligible for one evidence-driven layout retry."""

    try:
        report = read_report_json(staged_root / report_directory / "report.json")
    except ValueError as exc:
        raise RepairError(f"private verification produced an invalid report: {exc}") from exc
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


def _link_settlement_args(
    args: argparse.Namespace,
    *,
    candidate_budget: int,
    adjustment_rounds: int,
) -> argparse.Namespace:
    values = vars(args).copy()
    values.update(
        donor_candidates=candidate_budget,
        adjustment_rounds=adjustment_rounds,
    )
    return argparse.Namespace(**values)


def execute_repair_attempt(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    snapshot: RepairSnapshot,
    selected_paths: tuple[str, ...],
    cache_root: Path,
    candidate_report_directory: str,
    final_report_directory: str,
    report_preimages: tuple[RepairOutputSnapshot, ...],
    keep: KeepWorkspace,
    verify_command: VerifyCommand,
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

            command_source_lock(
                argparse.Namespace(
                    project=str(staged_root),
                    path=list(selected_paths),
                    invalidate_producer_graph=False,
                ),
                output,
            )

            phase = "repairing saved build guidance"
            candidate_args = _candidate_args(args, staged_root, candidate_report_directory)
            candidate_limit = _repair_limit(
                candidate_args,
                "donor_candidates",
                MAX_REPAIR_DONOR_CANDIDATES,
            )
            adjustment_limit = _repair_limit(
                candidate_args,
                "adjustment_rounds",
                MAX_REPAIR_ADJUSTMENT_ROUNDS,
            )
            workflow = repair_records(
                candidate_args,
                output,
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
                status = verify_command(candidate_args, output)
                if status == 0:
                    break
                if status != 1:
                    raise RepairError(
                        "candidate output did not satisfy exact verification and the committed "
                        "authenticity policy"
                    )

                phase = "checking the private from-scratch result"
                # A failed verifier may write outputs and reports, but it may not
                # alter any sealed input or authorized record.  Reuse the final
                # collection boundary to prove that before another repair pass.
                try:
                    failed_candidate = collect_repair_candidate(
                        snapshot,
                        staged_root,
                        report_directory=candidate_report_directory,
                        record_postimages=record_postimages,
                    )
                    target_ids = _cold_mismatch_targets(
                        staged_root,
                        candidate_report_directory,
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
                        "exhausted the command-wide --donor-candidates limit"
                    )
                remaining_rounds = adjustment_limit - workflow.adjustment_rounds
                if remaining_rounds <= 0:
                    raise RepairWorkflowError(
                        "from-scratch verification found link layout fallout after repair "
                        "reached its saved-guidance adjustment-round limit"
                    )

                phase = "settling link layout for the affected targets"
                candidate_args = _link_settlement_args(
                    candidate_args,
                    candidate_budget=remaining_candidates,
                    adjustment_rounds=remaining_rounds,
                )
                followup = repair_records(
                    candidate_args,
                    output,
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
            )
    except KeyboardInterrupt:
        raise
    except Exception as error:
        if published and result is not None:
            return replace(result, cleanup_warning=str(error))
        raise RepairAttemptFailure(error, phase=phase, staged=staged) from error
    assert result is not None
    return result


__all__ = [
    "MAX_REPAIR_ADJUSTMENT_ROUNDS",
    "MAX_REPAIR_DONOR_CANDIDATES",
    "RepairAnalysisError",
    "RepairAnalysisResult",
    "RepairAttemptFailure",
    "RepairAttemptResult",
    "RepairRecords",
    "RepairWorkflowError",
    "RepairWorkflowResult",
    "VerifyCommand",
    "analyze_classic_repair",
    "execute_repair_attempt",
    "repair_classic_records",
]
