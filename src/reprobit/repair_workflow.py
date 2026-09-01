"""Bounded classic authority repair for one private staged project.

One repair attempt stages the sealed project, refreshes its source records,
repairs saved build guidance through bounded warm analysis passes, proves
every target from scratch, and publishes the verified result atomically.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Protocol

from reprobit.classic.redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirements,
)
from reprobit.classic.repair_authority import apply_classic_authority_edits
from reprobit.classic.repair_probe import (
    MAX_RETUNE_PROBE_CANDIDATES,
    ClassicDonorRetuneRefusal,
)
from reprobit.classic.repair_session import (
    ClassicReceiptRepair,
    ClassicRepairRefusal,
    ClassicRepairSession,
    apply_classic_receipt_repairs,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.cli_build import command_build
from reprobit.cli_output import CLIOutput
from reprobit.cli_project import command_source_lock
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
from reprobit.repair_donor_analysis import (
    apply_classic_donor_repairs,
    probe_classic_donor_repairs,
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
MAX_REPAIR_DONOR_CANDIDATES = MAX_RETUNE_PROBE_CANDIDATES


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


class RepairAnalysisError(RuntimeError):
    """A non-certifying analysis failed outside a recorded repair seat."""


@dataclass(frozen=True, slots=True)
class RepairAnalysisResult:
    """Measured and structural fallout from one bounded incremental pass."""

    completed: bool
    measured_repairs: tuple[ClassicReceiptRepair, ...]
    structural_refusals: tuple[ClassicRepairRefusal, ...]


def analyze_classic_repair(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    cache_root: Path | None = None,
    progress_description: str = "checking affected source files",
) -> RepairAnalysisResult:
    """Run one warm analysis and distinguish repair fallout from fatal failure."""

    session = ClassicRepairSession()
    values = vars(args).copy()
    values.update(
        cold=False,
        keep_workspace=KeepWorkspace.NEVER.value,
        _classic_measured_receipt_repair=session,
        _classic_repair_analysis_only=True,
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
    )


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


def _probe_refusal_error(refusal: ClassicDonorRetuneRefusal) -> RepairWorkflowError:
    attempts = refusal.compiled_candidates
    setting = "setting" if attempts == 1 else "settings"
    lines = [
        f"No safe automatic repair restored `{refusal.unit_id}` after testing "
        f"{attempts} nearby compiler {setting}."
    ]
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


def repair_classic_records(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    staged_root: Path,
    spec: ProjectSpec,
    cache_root: Path,
) -> RepairWorkflowResult:
    """Repair measured, redundant, then nearby-donor fallout until composition is clean."""

    changed_records: set[str] = set()
    affected_units: set[str] = set()
    measured_checks = 0
    retired_actions = 0
    removed_donors = 0
    donor_retunes = 0
    compiled_candidates = 0
    seen_authority: set[str] = set()
    adjustment_rounds = 0
    initial_function_actions: int | None = None
    pass_number = 0

    while True:
        pass_number += 1
        bundle = load_project_tree(staged_root)
        if initial_function_actions is None:
            initial_function_actions = sum(
                getattr(item, "role", None) is ClassicRecipeRole.FUNCTION
                for item in bundle.interventions
            )
        maximum_analyses = initial_function_actions + MAX_REPAIR_ADJUSTMENT_ROUNDS + 1
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
        )
        affected_units.update(item.unit_id for item in analysis.measured_repairs)
        affected_units.update(item.unit_id for item in analysis.structural_refusals)

        if analysis.measured_repairs:
            if adjustment_rounds >= MAX_REPAIR_ADJUSTMENT_ROUNDS:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{MAX_REPAIR_ADJUSTMENT_ROUNDS} saved-guidance adjustment rounds"
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
            return RepairWorkflowResult(
                tuple(sorted(changed_records, key=lambda item: (item.casefold(), item))),
                tuple(sorted(affected_units, key=str.casefold)),
                measured_checks,
                retired_actions,
                removed_donors,
                donor_retunes,
                compiled_candidates,
                pass_number,
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

        donor_refusals = tuple(
            refusal
            for refusal in analysis.structural_refusals
            if refusal.intervention.role is ClassicRecipeRole.FUNCTION
            and refusal.intervention.dependencies
        )
        if donor_refusals:
            if adjustment_rounds >= MAX_REPAIR_ADJUSTMENT_ROUNDS:
                raise RepairWorkflowError(
                    "automatic repair reached its limit of "
                    f"{MAX_REPAIR_ADJUSTMENT_ROUNDS} saved-guidance adjustment rounds"
                )
            remaining_candidates = MAX_REPAIR_DONOR_CANDIDATES - compiled_candidates
            if remaining_candidates <= 0:
                raise RepairWorkflowError(
                    "automatic repair exhausted its command-wide budget of "
                    f"{MAX_REPAIR_DONOR_CANDIDATES} donor candidates"
                )
            probe = probe_classic_donor_repairs(
                args,
                output,
                donor_refusals,
                candidate_budget=remaining_candidates,
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
                donor_retunes += len(probe.repairs)
                adjustment_rounds += 1
                continue
            if probe.best_refusal is not None:
                raise _probe_refusal_error(probe.best_refusal)
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
