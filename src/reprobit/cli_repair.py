"""One-command repair of deterministic source fallout with exact verification."""

from __future__ import annotations

import argparse
from io import StringIO
from pathlib import Path

from reprobit.cli_build import command_verify
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError, project_root, safe_project_path
from reprobit.cli_project import command_source_lock
from reprobit.repair import (
    RepairError,
    StagedRepairProject,
    capture_repair_report_preimages,
    capture_repair_snapshot,
    collect_repair_candidate,
    publish_repair_candidate,
)
from reprobit.source_regeneration import (
    SourceRegenerationError,
    apply_source_regeneration,
    plan_source_regeneration,
)
from reprobit.state import KeepWorkspace

_CANDIDATE_REPORT_DIRECTORY = ".reprobit-repair/reports"


class _CandidateOutput(CLIOutput):
    """Relay progress while withholding provisional candidate verdicts."""

    def emit(
        self,
        event: str,
        message: str,
        *,
        diagnostic: bool = False,
        **fields: object,
    ) -> None:
        del event, message, diagnostic, fields


def _candidate_output(output: CLIOutput) -> CLIOutput:
    return _CandidateOutput(
        output_format=output.output_format,
        stdout=output.stdout if output.output_format == "ndjson" else StringIO(),
        stderr=output.stderr,
        heartbeat_seconds=output.heartbeat_seconds,
    )


def _candidate_args(args: argparse.Namespace, staged_root: Path) -> argparse.Namespace:
    values = vars(args).copy()
    values.update(
        project=str(staged_root),
        report_dir=_CANDIDATE_REPORT_DIRECTORY,
        action_receipt=None,
        action_nonce=None,
    )
    return argparse.Namespace(**values)


def command_repair(args: argparse.Namespace, output: CLIOutput) -> int:
    """Repair in private, prove every target, then publish once."""

    root = project_root(args.project)
    try:
        snapshot = capture_repair_snapshot(root)
    except RepairError as exc:
        raise CLIError(str(exc)) from exc
    admitted_paths = tuple(entry.path for entry in snapshot.source_manifest.entries)
    final_report_directory = (
        safe_project_path(root, args.report_dir).relative_to(root).as_posix()
        if args.report_dir
        else (Path(snapshot.spec.state_dir) / "reports").as_posix()
    )
    try:
        report_preimages = capture_repair_report_preimages(snapshot, final_report_directory)
    except RepairError as exc:
        raise CLIError(str(exc)) from exc
    candidate_output = _candidate_output(output)
    staged = StagedRepairProject(snapshot, keep=KeepWorkspace(args.keep_workspace))
    published = False
    cleanup_warning: str | None = None

    try:
        with staged as staged_root:
            try:
                regeneration_plan = plan_source_regeneration(staged_root)
                apply_source_regeneration(staged_root, regeneration_plan)
            except SourceRegenerationError as exc:
                raise RepairError(f"mechanical source repair refused: {exc}") from exc

            lock_args = argparse.Namespace(
                project=str(staged_root),
                path=list(admitted_paths),
                invalidate_producer_graph=False,
            )
            command_source_lock(lock_args, candidate_output)

            verification_status = command_verify(
                _candidate_args(args, staged_root),
                candidate_output,
            )
            if verification_status != 0:
                raise RepairError(
                    "candidate output did not satisfy exact verification and the committed "
                    "authenticity policy"
                )

            candidate = collect_repair_candidate(
                snapshot,
                staged_root,
                report_directory=_CANDIDATE_REPORT_DIRECTORY,
            )
            transaction = publish_repair_candidate(
                snapshot,
                candidate,
                report_directory=final_report_directory,
                report_preimages=report_preimages,
            )
            published = True
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        if published:
            cleanup_warning = str(exc)
        else:
            retained = staged.retained_path
            retained_report = retained / "project" / _CANDIDATE_REPORT_DIRECTORY / "report.html"
            if retained_report.is_file():
                retained_line = f" Review: {retained_report}."
            elif retained.is_dir():
                retained_line = f" Diagnostics: {retained}."
            else:
                retained_line = ""
            raise CLIError(
                "repair stopped; your source edits were kept and saved project records "
                f"were not changed.{retained_line} Cause: {exc}\nTry: rbit clean {root}"
            ) from exc

    changed_records = len(candidate.records)
    report_html = root / final_report_directory / "report.html"
    output.emit(
        "repair_complete",
        (
            f"Repair complete: updated {changed_records} saved project file(s) and "
            f"verified every target exactly\nReport: {report_html}"
        ),
        project=root,
        refreshed_checks=len(regeneration_plan.changes),
        changed_records=sorted(candidate.records),
        source_inputs=len(admitted_paths),
        exact=True,
        transaction_id=transaction.transaction_id,
        report_html=report_html,
        report_json=report_html.with_suffix(".json"),
        cleanup_warning=cleanup_warning,
    )
    if cleanup_warning is not None:
        output.emit(
            "repair_cleanup_warning",
            (
                "Repair was published and verified, but its private workspace could not "
                f"be cleaned automatically: {cleanup_warning}\nTry: rbit clean {root}"
            ),
            diagnostic=True,
            project=root,
            workspace=staged.retained_path,
        )
    elif staged.retained_path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful repair workspace: {staged.retained_path}",
            path=staged.retained_path,
            outcome="succeeded",
            diagnostic=True,
        )
    return 0


__all__ = ["command_repair"]
