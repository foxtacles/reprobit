"""Bounded classic authority repair for one private staged project."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from reprobit.classic.redundant_action_repair import (
    RedundantActionRepairError,
    plan_redundant_action_retirement,
)
from reprobit.classic.repair_authority import apply_classic_authority_edits
from reprobit.classic.repair_session import apply_classic_receipt_repairs
from reprobit.cli_output import CLIOutput
from reprobit.project_loader import load_project_tree
from reprobit.repair_analysis import analyze_classic_repair
from reprobit.repair_donor_analysis import (
    apply_classic_donor_repairs,
    probe_classic_donor_repairs,
)
from reprobit.schema import ClassicProofReceipt, ClassicRecipeRole, ProjectBundle, ProjectSpec
from reprobit.strict_json import canonical_json

MAX_REPAIR_PASSES = 24


class RepairWorkflowError(RuntimeError):
    """A bounded repair could not restore ordinary classic composition."""


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

    for pass_number in range(1, MAX_REPAIR_PASSES + 1):
        bundle = load_project_tree(staged_root, verify_source_authority=False)
        fingerprint = _authority_fingerprint(bundle)
        if fingerprint in seen_authority:
            raise RepairWorkflowError(
                "automatic repair reached a previously checked saved-guidance state"
            )
        seen_authority.add(fingerprint)
        analysis = analyze_classic_repair(args, output, cache_root=cache_root)
        affected_units.update(item.unit_id for item in analysis.measured_repairs)
        affected_units.update(item.unit_id for item in analysis.structural_refusals)

        if analysis.measured_repairs:
            changed_records.update(
                apply_classic_receipt_repairs(
                    staged_root,
                    spec,
                    analysis.measured_repairs,
                )
            )
            measured_checks += len(analysis.measured_repairs)
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
        retired = False
        for refusal in analysis.structural_refusals:
            try:
                plan = plan_redundant_action_retirement(
                    bundle.interventions,
                    receipts,
                    refusal.intervention,
                    refusal.receipt,
                    refusal.materials,
                )
            except RedundantActionRepairError as exc:
                retirement_failures.append(str(exc))
                continue
            changed_records.update(
                apply_classic_authority_edits(
                    staged_root,
                    spec,
                    interventions=plan.intervention_edits,
                    receipts=plan.receipt_edits,
                )
            )
            retired_actions += 1
            removed_donors += len(plan.removed_donors)
            retired = True
            break
        if retired:
            continue

        donor_refusals = tuple(
            refusal
            for refusal in analysis.structural_refusals
            if refusal.intervention.role is ClassicRecipeRole.FUNCTION
            and refusal.intervention.dependencies
        )
        if donor_refusals:
            probe = probe_classic_donor_repairs(args, output, donor_refusals)
            compiled_candidates += probe.compiled_candidates
            if probe.repairs:
                changed_records.update(
                    apply_classic_donor_repairs(staged_root, spec, probe.repairs)
                )
                donor_retunes += len(probe.repairs)
                continue
            probe_reasons = [item.reason for item in probe.refusals]
        else:
            probe_reasons = []

        reasons = [
            *(item.reason for item in analysis.structural_refusals),
            *retirement_failures,
            *probe_reasons,
        ]
        detail = next((" ".join(reason.split()) for reason in reasons if reason), "unknown fallout")
        raise RepairWorkflowError(
            "automatic repair could not find a bounded, ordinarily validated adjustment: "
            + detail
        )

    raise RepairWorkflowError(
        f"automatic repair did not converge after {MAX_REPAIR_PASSES} bounded passes"
    )


__all__ = [
    "MAX_REPAIR_PASSES",
    "RepairWorkflowError",
    "RepairWorkflowResult",
    "repair_classic_records",
]
