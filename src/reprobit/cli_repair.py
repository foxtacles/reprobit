"""One-command repair of deterministic source fallout with exact verification."""

from __future__ import annotations

import argparse
from io import StringIO
from pathlib import Path

from reprobit.classic_donor_retune_candidates import (
    MAX_RETUNE_CANDIDATES,
    MAX_RETUNE_RADIUS,
)
from reprobit.classic_repair_discovery import MAX_DISCOVERY_CANDIDATES
from reprobit.classic_repair_probe import MAX_RETUNE_PROBE_CANDIDATES
from reprobit.cli_build import command_verify
from reprobit.cli_output import CLIOutput, count_phrase, human_command
from reprobit.cli_paths import CLIError, project_root, safe_project_path
from reprobit.cli_state import state_root
from reprobit.repair import (
    RepairError,
    capture_repair_report_preimages,
    capture_repair_snapshot,
)
from reprobit.repair_workflow import (
    RepairAttemptFailure,
    RepairWorkflowError,
    execute_repair_attempt,
    repair_classic_records,
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


_SEARCH_BOUNDS = (
    ("retune_radius", "--retune-radius", MAX_RETUNE_RADIUS),
    ("retune_candidates", "--retune-candidates", MAX_RETUNE_CANDIDATES),
    ("donor_candidates", "--donor-candidates", MAX_RETUNE_PROBE_CANDIDATES),
    ("adjustment_rounds", "--adjustment-rounds", None),
    ("discovery_candidates", "--discovery-candidates", MAX_DISCOVERY_CANDIDATES),
)


def _check_search_bounds(args: argparse.Namespace) -> None:
    for attribute, option, maximum in _SEARCH_BOUNDS:
        value = getattr(args, attribute, None)
        if value is None:
            continue
        if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
            ceiling = f" and at most {maximum}" if maximum is not None else ""
            raise CLIError(f"{option} must be at least 1{ceiling}")


def command_repair(args: argparse.Namespace, output: CLIOutput) -> int:
    """Repair in private, prove every target, then publish once."""

    _check_search_bounds(args)
    root = project_root(args.project)
    entrypoint = root / "reprobit.toml"
    if entrypoint.is_symlink() or not entrypoint.is_file():
        next_command = human_command(("rbit", "init", root))
        raise CLIError(f"no ReproBit project found at {entrypoint}\nNext: {next_command}")
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
    cache_root = state_root(root, snapshot.spec)
    try:
        result = execute_repair_attempt(
            args,
            candidate_output,
            snapshot=snapshot,
            selected_paths=admitted_paths,
            cache_root=cache_root,
            candidate_report_directory=_CANDIDATE_REPORT_DIRECTORY,
            final_report_directory=final_report_directory,
            report_preimages=report_preimages,
            keep=KeepWorkspace(args.keep_workspace),
            verify_command=command_verify,
            repair_records=repair_classic_records,
        )
    except RepairAttemptFailure as failure:
        failure_error = failure.error
        phase = failure.phase
        staged = failure.staged
        if (
            output.output_format == "ndjson"
            and isinstance(failure_error, RepairWorkflowError)
            and failure_error.diagnostic is not None
        ):
            output.emit(
                "repair_refused",
                str(failure_error),
                diagnostic=True,
                phase=phase,
                **failure_error.diagnostic,
            )
        retained = staged.retained_path
        retained_report = retained / "project" / _CANDIDATE_REPORT_DIRECTORY / "report.html"
        if retained_report.is_file():
            retained_line = f"\nReview: {retained_report}"
        elif retained.is_dir():
            retained_line = f"\nDiagnostics: {retained}"
        else:
            retained_line = ""
        cause = " ".join(str(failure_error).split())
        if staged.root is not None:
            cause = cause.replace(str(staged.root), "the private repair workspace")
        cleanup_line = (
            f"\nCleanup when finished: {human_command(('rbit', 'clean', root))}"
            if retained.is_dir()
            else ""
        )
        raise CLIError(
            f"Repair stopped while {phase}. Your source edits are untouched; "
            "ReproBit did not publish its staged project records or outputs."
            f"\nDetails: {cause}{retained_line}"
            f"{cleanup_line}"
        ) from failure_error

    candidate = result.candidate
    transaction = result.transaction
    regeneration_plan = result.regeneration
    repair_result = result.workflow
    staged = result.staged
    cleanup_warning = result.cleanup_warning

    changed_records = len(candidate.records)
    report_html = root / final_report_directory / "report.html"
    if changed_records:
        guidance_changed = any(
            (
                regeneration_plan.changes,
                repair_result.measured_checks,
                repair_result.retired_actions,
                repair_result.donor_retunes,
                repair_result.reauthored_actions,
                repair_result.discovered_actions,
            )
        )
        completion_lines = [
            "Repair complete: "
            f"{count_phrase(changed_records, 'saved project file')} updated; "
            "every target matches exactly."
        ]
        if guidance_changed:
            if repair_result.affected_units:
                affected_count = len(repair_result.affected_units)
                guidance_owner = "its" if affected_count == 1 else "their"
                completion_lines.append(
                    "Repaired "
                    + count_phrase(
                        affected_count,
                        "affected source file",
                    )
                    + f" and refreshed {guidance_owner} saved guidance."
                )
            else:
                completion_lines.append("Refreshed saved source guidance.")
        if repair_result.reauthored_actions:
            completion_lines.append(
                "Re-authored "
                + count_phrase(repair_result.reauthored_actions, "function record")
                + " from donors the affected source files already had."
            )
        if repair_result.discovered_actions:
            completion_lines.append(
                "Settled "
                + count_phrase(repair_result.discovered_actions, "function record")
                + " on freshly discovered declaration shapes."
            )
        if repair_result.compiled_candidates:
            tested = (
                "Tested "
                f"{count_phrase(repair_result.compiled_candidates, 'nearby compiler setting')}"
            )
            replayed = repair_result.replayed_candidates
            if replayed:
                tested += f" ({count_phrase(replayed, 'replayed from an earlier compile')})"
            completion_lines.append(tested + ".")
        completion_lines.append(f"Report: {report_html}")
        completion_message = "\n".join(completion_lines)
    else:
        completion_message = (
            f"Nothing needed repair; every target still matches exactly\nReport: {report_html}"
        )
    output.emit(
        "repair_complete",
        completion_message,
        project=root,
        refreshed_checks=len(regeneration_plan.changes),
        repaired_translation_units=len(repair_result.affected_units),
        measured_checks=repair_result.measured_checks,
        retired_actions=repair_result.retired_actions,
        removed_donors=repair_result.removed_donors,
        donor_retunes=repair_result.donor_retunes,
        reauthored_actions=repair_result.reauthored_actions,
        discovered_actions=repair_result.discovered_actions,
        donor_candidates=repair_result.compiled_candidates,
        replayed_candidates=repair_result.replayed_candidates,
        repair_passes=repair_result.passes,
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
