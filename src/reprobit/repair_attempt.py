"""One private repair attempt, including verification and atomic publication."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from reprobit.cli_output import CLIOutput
from reprobit.cli_project import command_source_lock
from reprobit.repair import (
    RepairCandidate,
    RepairError,
    RepairOutputSnapshot,
    RepairSnapshot,
    StagedRepairProject,
    capture_repair_record_postimages,
    collect_repair_candidate,
    publish_repair_candidate,
)
from reprobit.repair_workflow import RepairWorkflowResult
from reprobit.schema import ProjectSpec
from reprobit.source_regeneration import (
    RegenerationPlan,
    SourceRegenerationError,
    apply_source_regeneration,
    plan_source_regeneration,
)
from reprobit.state import KeepWorkspace
from reprobit.transactions import TransactionResult


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
    staged: StagedRepairProject
    cleanup_warning: str | None = None


class RepairAttemptFailure(RuntimeError):
    """Expected candidate failure with the phase and retained workspace attached."""

    def __init__(self, error: Exception, *, phase: str, staged: StagedRepairProject) -> None:
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

    staged = StagedRepairProject(snapshot, keep=keep)
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
    "RepairAttemptFailure",
    "RepairAttemptResult",
    "execute_repair_attempt",
]
