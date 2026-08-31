"""Bounded classic authority repair for one private staged project."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from reprobit.classic.redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirements,
)
from reprobit.classic.repair_authority import apply_classic_authority_edits
from reprobit.classic.repair_probe import (
    MAX_RETUNE_PROBE_CANDIDATES,
    ClassicDonorRetuneRefusal,
)
from reprobit.classic.repair_session import apply_classic_receipt_repairs
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.cli_output import CLIOutput
from reprobit.project_loader import load_project_tree
from reprobit.repair_analysis import analyze_classic_repair
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
from reprobit.strict_json import canonical_json

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
        f"No safe adjustment restored `{refusal.unit_id}` after trying {attempts} donor {setting}."
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
            lines.append(f"Closest useful candidate: {rendered}.")
        lines.append(f"Why it was refused: {_one_line(best.reason)}")
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
        lines.append(f"Why it was refused: {_one_line(refusal.reason)}")
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


__all__ = [
    "MAX_REPAIR_ADJUSTMENT_ROUNDS",
    "MAX_REPAIR_DONOR_CANDIDATES",
    "RepairWorkflowError",
    "RepairWorkflowResult",
    "repair_classic_records",
]
