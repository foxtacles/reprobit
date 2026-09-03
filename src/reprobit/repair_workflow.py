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
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirements,
)
from reprobit.classic_repair_authority import apply_classic_authority_edits
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
    ClassicRepairRefusal,
    ClassicRepairSession,
    apply_classic_receipt_repairs,
)
from reprobit.cli_build import COMPOSED_BODY_LEDGER_RELATIVE, command_build
from reprobit.cli_output import CLIOutput
from reprobit.cli_project import command_source_lock
from reprobit.composition_ledger import ComposedBodyLedger, read_ledger
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
    probe_classic_carrier_discovery,
    probe_classic_donor_repairs,
)
from reprobit.repair_unit_admission import (
    TranslationUnitAdmissionError,
    apply_translation_unit_admissions,
    plan_translation_unit_admissions,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ProjectBundle,
    ProjectSpec,
)
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


class RepairAnalysisError(RuntimeError):
    """A non-certifying analysis failed outside a recorded repair seat."""


@dataclass(frozen=True, slots=True)
class RepairAnalysisResult:
    """Measured and structural fallout from one bounded incremental pass."""

    completed: bool
    measured_repairs: tuple[ClassicReceiptRepair, ...]
    structural_refusals: tuple[ClassicRepairRefusal, ...]
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
    return RepairAnalysisResult(
        not session.refusals,
        session.repairs,
        session.refusals,
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
        raise RepairWorkflowError(f"composed-body ledger {path} is unreadable: {exc}") from exc


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
    setting = "setting" if attempts == 1 else "settings"
    lines = [
        f"No safe automatic repair restored `{refusal.unit_id}` after testing "
        f"{attempts} nearby compiler {setting}."
    ]
    discovery_note = next(
        (reason for unit_id, _action, reason in unresolved if unit_id == refusal.unit_id), None
    )
    if discovery_note:
        lines.append(f"Fresh declaration shapes did not help either: {_one_line(discovery_note)}")
    best = refusal.best_attempt
    best_document: dict[str, object] | None = None
    if best is not None:
        visible_changes = tuple(change for change in best.changes if change.kind == "knob")
        if visible_changes:
            rendered = "; ".join(
                f"`{change.path[-1]}` {change.before} -> {change.after}"
                for change in visible_changes
            )
            lines.append(f"Closest technical candidate: {rendered}.")
        lines.append(f"Technical reason it was refused: {_one_line(best.reason)}")
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
        lines.append(f"Technical reason it was refused: {_one_line(refusal.reason)}")
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


def _donor_group_key(refusal: ClassicRepairRefusal) -> tuple[str, str]:
    dependencies = refusal.intervention.dependencies
    return (refusal.unit_id, dependencies[0] if dependencies else "")


def repair_classic_records(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    staged_root: Path,
    spec: ProjectSpec,
    cache_root: Path,
) -> RepairWorkflowResult:
    """Repair measured, redundant, then nearby-donor fallout until composition is clean.

    ``args.adjustment_rounds`` and ``args.donor_candidates`` raise the default
    round and command-wide donor-candidate limits for large shared-header
    repairs; the search stays bounded by whatever the command line declares.
    """

    adjustment_limit = getattr(args, "adjustment_rounds", None) or MAX_REPAIR_ADJUSTMENT_ROUNDS
    candidate_limit = getattr(args, "donor_candidates", None) or MAX_REPAIR_DONOR_CANDIDATES
    changed_records: set[str] = set()
    affected_units: set[str] = set()
    measured_checks = 0
    retired_actions = 0
    removed_donors = 0
    donor_retunes = 0
    reauthored_actions = 0
    discovered_actions = 0
    admitted_units = 0
    compiled_candidates = 0
    seen_authority: set[str] = set()
    adjustment_rounds = 0
    initial_function_actions: int | None = None
    pass_number = 0
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
                getattr(item, "role", None) is ClassicRecipeRole.FUNCTION
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
        analysis = analyze_classic_repair(
            args,
            output,
            cache_root=cache_root,
            progress_description=f"checking affected source files (pass {pass_number})",
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
            continue

        if analysis.completed:
            if ledger is not None:
                census = plan_repair_census(
                    bundle, ledger, getattr(analysis, "seed_objects", None) or {}
                )
                if census.missing:
                    raise RepairWorkflowError(
                        "verified functions no longer defined by their fresh object: "
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
                            "automatic repair could not admit the translation units with "
                            f"unrecorded fallout ({_listed_census(census.unplanned)}): "
                            + _one_line(exc)
                        ) from exc
                    if not changed:
                        raise RepairWorkflowError(
                            "translation-unit admission reported success without changing "
                            "saved guidance"
                        )
                    changed_records.update(changed)
                    admitted_units += len(admitted)
                    adjustment_rounds += 1
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
                            "automatic repair exhausted its command-wide budget of "
                            f"{candidate_limit} donor candidates"
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
                    compiled_candidates += discovery.compiled_candidates
                    for unit_id, digests in getattr(discovery, "tried_states", {}).items():
                        discovered_shapes.setdefault(unit_id, set()).update(digests)
                    if not discovery.repairs:
                        unresolved = ", ".join(
                            f"{unit_id} {action_id}: {reason}"
                            for unit_id, action_id, reason in discovery.unresolved[:8]
                        )
                        raise RepairWorkflowError(
                            "automatic repair could not record unrecorded fallout: "
                            + (unresolved or "no carrier state settled it")
                        )
                    changed = apply_classic_discovery_repairs(staged_root, spec, discovery.repairs)
                    if not changed:
                        raise RepairWorkflowError(
                            "unrecorded-fallout census reported success without changing "
                            "saved guidance"
                        )
                    changed_records.update(changed)
                    discovered_actions += sum(len(item.resolutions) for item in discovery.repairs)
                    adjustment_rounds += 1
                    continue
            return RepairWorkflowResult(
                tuple(sorted(changed_records, key=lambda item: (item.casefold(), item))),
                tuple(sorted(affected_units, key=str.casefold)),
                measured_checks,
                retired_actions,
                removed_donors,
                donor_retunes,
                compiled_candidates,
                pass_number,
                reauthored_actions,
                discovered_actions,
                compile_cache.memory_hits + compile_cache.disk_hits,
                admitted_units,
            )

        receipts = _classic_receipts(bundle)
        retirement_failures: list[str] = []
        retirement_candidates: list[
            tuple[
                ClassicRecipeIntervention,
                ClassicProofReceipt,
                ClassicDispatchMaterials,
            ]
        ] = []
        for refusal in analysis.structural_refusals:
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
            continue

        # Before compiling anything: a refused function whose goal body another
        # donor of its unit (or its own donor, under a cheaper family) already
        # emits is re-authored onto that donor from the captured fresh objects.
        try:
            reauthor_plan = plan_function_reauthoring(analysis.structural_refusals)
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
            continue

        donor_refusals = tuple(
            refusal
            for refusal in analysis.structural_refusals
            if refusal.intervention.role is ClassicRecipeRole.FUNCTION
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
                raise RepairWorkflowError(
                    "automatic repair exhausted its command-wide budget of "
                    f"{candidate_limit} donor candidates"
                )
            fresh_refusals = tuple(
                refusal
                for refusal in donor_refusals
                if _donor_group_key(refusal) not in exhausted_groups
            )
            frozen_abandoned = {key: frozenset(value) for key, value in abandoned_states.items()}
            probe = probe_classic_donor_repairs(
                args,
                output,
                fresh_refusals or donor_refusals,
                candidate_budget=remaining_candidates,
                abandoned_states=frozen_abandoned,
                compile_cache=compile_cache,
            )
            if not 0 <= probe.compiled_candidates <= remaining_candidates:
                raise RepairWorkflowError(
                    "donor repair exceeded its remaining command-wide candidate budget"
                )
            compiled_candidates += probe.compiled_candidates
            exhausted_groups.update(
                (refusal.unit_id, refusal.donor_id)
                for refusal in probe.refusals
                if getattr(refusal, "exhausted", False)
            )
            if not probe.repairs and fresh_refusals and len(fresh_refusals) < len(donor_refusals):
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
                    if not 0 <= probe.compiled_candidates <= remaining_candidates:
                        raise RepairWorkflowError(
                            "donor repair exceeded its remaining command-wide candidate budget"
                        )
                    compiled_candidates += probe.compiled_candidates
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
                continue
            # No saved donor can be retuned: compile fresh carrier states for the
            # affected units and accept any that carries a refused record's body.
            remaining_candidates = candidate_limit - compiled_candidates
            discovery = probe_classic_carrier_discovery(
                args,
                output,
                donor_refusals,
                candidate_budget=remaining_candidates,
                tried_states={key: frozenset(value) for key, value in discovered_shapes.items()},
                compile_cache=compile_cache,
            )
            compiled_candidates += discovery.compiled_candidates
            for unit_id, digests in getattr(discovery, "tried_states", {}).items():
                discovered_shapes.setdefault(unit_id, set()).update(digests)
            if discovery.repairs:
                changed = apply_classic_discovery_repairs(staged_root, spec, discovery.repairs)
                if not changed:
                    raise RepairWorkflowError(
                        "carrier discovery reported success without changing saved guidance"
                    )
                changed_records.update(changed)
                discovered_actions += sum(len(item.resolutions) for item in discovery.repairs)
                adjustment_rounds += 1
                continue
            if probe.best_refusal is not None:
                raise _probe_refusal_error(probe.best_refusal, discovery.unresolved)
            probe_reasons: list[str] = []
        else:
            probe_reasons = []

        reasons = [
            *(item.reason for item in analysis.structural_refusals),
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
                regeneration = plan_source_regeneration(staged_root)
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
            workflow = repair_records(
                candidate_args,
                output,
                staged_root=staged_root,
                spec=snapshot.spec,
                cache_root=cache_root,
            )
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
            if status != 0:
                raise RepairError(
                    "candidate output did not satisfy exact verification and the committed "
                    "authenticity policy"
                )

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
