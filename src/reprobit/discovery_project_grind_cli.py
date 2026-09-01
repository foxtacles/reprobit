"""CLI and report publication for the bounded project-wide grind."""

from __future__ import annotations

import argparse
import os
import posixpath
from pathlib import Path, PurePosixPath
from typing import cast

from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import (
    CLIError,
    canonical_project_relative,
    project_root,
    relative_output,
    safe_project_path,
)
from reprobit.discovery_grind import (
    DonorProgress,
    ProjectGrindCallbacks,
    ProjectGrindResult,
)
from reprobit.discovery_grind_report import (
    GrindReportCommands,
    GrindReportLayout,
    grind_approval_argv,
    publish_grind_outcome,
    render_cold_verification,
)
from reprobit.discovery_project import ProjectGrindPlan
from reprobit.discovery_project_grind import (
    MAX_PROJECT_GRIND_SYMBOLS,
    ProjectAutoGrindResult,
    ProjectGrindArtifacts,
    ProjectGrindWorkItem,
    ProjectReferenceAssignment,
    project_auto_grind_summary,
    run_project_auto_grind,
)
from reprobit.discovery_project_grind_report import render_project_auto_grind_report_html
from reprobit.project_loader import load_project
from reprobit.state import report_publication_lease
from reprobit.strict_json import JsonValue, canonical_json
from reprobit.transactions import CASTransaction


def _project_reference_assignments(
    values: list[str],
) -> tuple[ProjectReferenceAssignment, ...]:
    assignments: list[ProjectReferenceAssignment] = []
    for value in values:
        translation_unit, separator, reference = value.partition("=")
        if (
            not separator
            or not translation_unit
            or not reference
            or "=" in reference
            or "\0" in translation_unit
        ):
            raise CLIError("--reference-object must use the exact TU=PROJECT_PATH form")
        assignments.append(
            ProjectReferenceAssignment(
                translation_unit,
                canonical_project_relative(reference, label="reference object"),
            )
        )
    return tuple(assignments)


def _campaign_callbacks(
    callbacks: ProjectGrindCallbacks,
    *,
    reuse_across_symbols: bool,
) -> ProjectGrindCallbacks:
    """Reuse immutable compiler probes within one read-only project campaign."""

    if not reuse_across_symbols:
        return callbacks

    seed_cache: dict[str, bytes] = {}
    donor_cache: dict[frozenset[str], dict[str, bytes]] = {}

    def probe_seed(staged_root: Path, node_id: str) -> bytes:
        payload = seed_cache.get(node_id)
        if payload is None:
            payload = callbacks.probe_seed(staged_root, node_id)
            seed_cache[node_id] = payload
        return payload

    def probe_donors(
        staged_root: Path,
        donor_ids: tuple[str, ...],
        progress: DonorProgress | None,
    ) -> dict[str, bytes]:
        key = frozenset(donor_ids)
        cached = donor_cache.get(key)
        if cached is None:
            compiled = callbacks.probe_donors(staged_root, donor_ids, progress)
            cached = dict(compiled)
            donor_cache[key] = cached
        else:
            if callable(progress):
                for completed, donor_id in enumerate(donor_ids, start=1):
                    progress(completed, len(donor_ids), donor_id)
        return {donor_id: cached[donor_id] for donor_id in donor_ids}

    return ProjectGrindCallbacks(
        probe_seed=probe_seed,
        probe_donors=probe_donors,
        cold_verify=callbacks.cold_verify,
    )


def _campaign_argv(
    root: Path,
    args: argparse.Namespace,
    *,
    acceptance: str | None = None,
) -> tuple[str, ...]:
    values = [
        "rbit",
        "discover",
        "grind",
        str(root),
        "--max-symbols",
        str(args.max_symbols),
    ]
    for value in args.reference_object:
        values.extend(("--reference-object", value))
    if acceptance is not None:
        values.append(acceptance)
    return tuple(values)


def project_state_root(root: Path) -> Path:
    """Resolve the project-owned state directory that holds reports and leases."""

    return safe_project_path(root, load_project(root).state_dir)


def _project_report_directory(state_root: Path) -> Path:
    return state_root / "reports/grind/project"


def _owned_numbered_report_outputs(root: Path, directory: Path) -> tuple[Path, ...]:
    """Return the bounded filenames owned by project-wide grind reports."""

    paths: list[Path] = []
    for index in range(1, MAX_PROJECT_GRIND_SYMBOLS + 1):
        stem = f"{index:03d}"
        paths.extend(
            (
                relative_output(root, str(directory / "plans" / f"{stem}-plan.json")),
                relative_output(root, str(directory / "outcomes" / f"{stem}-decision.html")),
                relative_output(root, str(directory / "cold" / f"{stem}-verification.json")),
                relative_output(root, str(directory / "cold" / f"{stem}-verification.html")),
            )
        )
    return tuple(paths)


def _publish_project_grind_outcome(
    root: Path,
    state_root: Path,
    index: int,
    item: ProjectGrindWorkItem,
    plan: ProjectGrindPlan,
    result: ProjectGrindResult,
    *,
    verify_argv: tuple[str, ...],
) -> ProjectGrindArtifacts:
    """Atomically publish one detailed result before the next symbol runs."""

    directory = _project_report_directory(state_root)
    stem = f"{index:03d}"
    plan_output = relative_output(root, str(directory / "plans" / f"{stem}-plan.json"))
    plan_relative = PurePosixPath(plan_output.as_posix()).as_posix()
    layout = GrindReportLayout(
        report=directory / "outcomes" / f"{stem}-decision.html",
        cold_json=directory / "cold" / f"{stem}-verification.json",
        cold_html=directory / "cold" / f"{stem}-verification.html",
    )
    extra_files = {plan_output: canonical_json(plan)}
    solution = result.solution
    cold_files = render_cold_verification(root, layout, solution) if solution is not None else {}
    publication = publish_grind_outcome(
        root,
        state_root,
        layout,
        result,
        plan_relative=plan_relative,
        commands=GrindReportCommands(
            approval=human_command(grind_approval_argv(root, plan_relative, exact=result.exact)),
            verify=human_command(verify_argv),
            proceed=human_command(("rbit", "discover", "grind", root)),
        ),
        cold_files=cold_files,
        extra_files=extra_files,
    )
    return ProjectGrindArtifacts(
        plan=plan_output.as_posix(),
        decision_report=publication.report.as_posix(),
        cold_verification_json=(
            publication.cold_json.as_posix() if publication.cold_json is not None else None
        ),
        cold_verification_html=(
            publication.cold_html.as_posix() if publication.cold_html is not None else None
        ),
    )


def _relative_report_link(directory: Path | PurePosixPath, relative: str) -> str:
    return posixpath.relpath(relative, start=directory.as_posix())


def _project_grind_reports(
    root: Path,
    state_root: Path,
    result: ProjectAutoGrindResult,
    *,
    exact_approval_argv: tuple[str, ...],
    progress_approval_argv: tuple[str, ...],
    continue_argv: tuple[str, ...],
    verify_argv: tuple[str, ...],
) -> tuple[Path, Path, str, tuple[Path, ...], tuple[Path, ...]]:
    directory = _project_report_directory(state_root)
    directory_relative = relative_output(root, str(directory))
    desired_json = directory / "report.json"
    desired_html = directory / "report.html"
    decision_paths: list[Path] = []
    plan_paths: list[Path] = []
    decision_links: list[str | None] = []
    artifact_rows: list[dict[str, JsonValue]] = []
    for outcome in result.outcomes:
        artifacts = outcome.artifacts
        if artifacts is None:
            plan_relative = None
            decision_link = None
            cold_json_link = None
            cold_html_link = None
        else:
            plan_relative = artifacts.plan
            plan_paths.append(root / Path(*PurePosixPath(artifacts.plan).parts))
            decision_paths.append(root / Path(*PurePosixPath(artifacts.decision_report).parts))
            decision_link = _relative_report_link(
                directory_relative,
                artifacts.decision_report,
            )
            cold_json_link = (
                _relative_report_link(
                    PurePosixPath(artifacts.decision_report).parent,
                    artifacts.cold_verification_json,
                )
                if artifacts.cold_verification_json is not None
                else None
            )
            cold_html_link = (
                _relative_report_link(
                    PurePosixPath(artifacts.decision_report).parent,
                    artifacts.cold_verification_html,
                )
                if artifacts.cold_verification_html is not None
                else None
            )
        decision_links.append(decision_link)
        artifact_rows.append(
            {
                "target": outcome.item.target_id,
                "translation_unit": outcome.item.translation_unit_id,
                "symbol": outcome.item.symbol,
                "plan": plan_relative,
                "decision_report": decision_link,
                "cold_verification_json": cold_json_link,
                "cold_verification_html": cold_html_link,
            }
        )

    if result.exact and not result.accepted:
        next_kind = "approve"
        next_argv = exact_approval_argv
        next_label = "Repeat fresh proofs and save the passing adjustments"
    elif result.qualified and not result.accepted:
        next_kind = "save_progress"
        next_argv = progress_approval_argv
        next_label = "Save the locally proven adjustments without claiming an exact project"
    elif result.published:
        if result.exact:
            next_kind = "verify"
            next_argv = verify_argv
            next_label = "Verify the exact saved project again from scratch"
        else:
            next_kind = "continue"
            next_argv = continue_argv
            next_label = "Continue with the next bounded project pass"
    else:
        next_kind = None
        next_argv = ()
        next_label = None
    next_command = human_command(next_argv) if next_argv else None

    summary = dict(project_auto_grind_summary(result))
    outcome_rows = cast(list[dict[str, JsonValue]], summary["outcomes"])
    for row, artifact_metadata in zip(outcome_rows, artifact_rows, strict=True):
        row.update(artifact_metadata)
    summary["next_step"] = (
        {
            "kind": next_kind,
            "argv": list(next_argv),
            "command": next_command,
        }
        if next_kind is not None and next_command is not None
        else None
    )
    files = {
        relative_output(root, str(desired_json)): canonical_json(summary),
        relative_output(root, str(desired_html)): render_project_auto_grind_report_html(
            result,
            outcome_reports=tuple(decision_links),
            summary_json=desired_json.name,
            next_step_label=next_label,
            next_step_command=next_command,
        ).encode("utf-8"),
    }
    with report_publication_lease(state_root):
        transaction = CASTransaction(root)
        retained = set(files)
        for outcome in result.outcomes:
            artifacts = outcome.artifacts
            if artifacts is None:
                continue
            for value in (
                artifacts.plan,
                artifacts.decision_report,
                artifacts.cold_verification_json,
                artifacts.cold_verification_html,
            ):
                if value is not None:
                    retained.add(Path(*PurePosixPath(value).parts))
        for owned in _owned_numbered_report_outputs(root, directory):
            if owned not in retained and os.path.lexists(root / owned):
                transaction.delete(owned)
        for relative, payload in files.items():
            transaction.write(relative, payload)
        transaction_id = transaction.commit().transaction_id
    return (
        desired_json,
        desired_html,
        transaction_id,
        tuple(decision_paths),
        tuple(plan_paths),
    )


def command_discover_project_grind(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    callbacks: ProjectGrindCallbacks,
) -> int:
    """Run the bounded project-wide low-hanging-fruit search."""

    root = project_root(args.project)
    accept_progress = getattr(args, "accept_progress", False)
    assignments = _project_reference_assignments(args.reference_object)
    state_root = project_state_root(root)
    report_directory = _project_report_directory(state_root)
    verify_argv = ("rbit", "verify", str(root))
    outcome_report_warnings: list[tuple[ProjectGrindWorkItem, str, str]] = []

    def finalize_outcome(
        index: int,
        item: ProjectGrindWorkItem,
        plan: ProjectGrindPlan,
        result: ProjectGrindResult,
    ) -> ProjectGrindArtifacts | None:
        try:
            return _publish_project_grind_outcome(
                root,
                state_root,
                index,
                item,
                plan,
                result,
                verify_argv=verify_argv,
            )
        except Exception as exc:
            # Reports are diagnostics, never authority.  Preserve a completed
            # search (and any already-published intervention) and keep going.
            outcome_report_warnings.append((item, type(exc).__name__, str(exc)))
            return None

    with output.producer_activity(
        "Finding and proving low-cost adjustments across the project"
    ) as progress:
        result = run_project_auto_grind(
            root,
            reference_assignments=assignments,
            max_symbols=args.max_symbols,
            accept_exact=args.accept_exact,
            accept_progress=accept_progress,
            # Preview runs leave authority unchanged, so equal compiler probes are
            # immutable across symbols. Accepted runs can publish after each symbol;
            # compile each later item against that newly updated project state.
            callbacks=_campaign_callbacks(
                callbacks,
                reuse_across_symbols=not (args.accept_exact or accept_progress),
            ),
            progress=progress,
            finalize_outcome=finalize_outcome,
        )

    exact_approval_argv = _campaign_argv(root, args, acceptance="--accept-exact")
    progress_approval_argv = _campaign_argv(root, args, acceptance="--accept-progress")
    continue_argv = _campaign_argv(root, args)
    report_json: Path | None = None
    report_html: Path | None = None
    decision_reports: tuple[Path, ...] = ()
    persisted_plans: tuple[Path, ...] = ()
    report_transaction_id: str | None = None
    report_warnings: list[str] = []
    desired_report = report_directory / "report.html"
    for item, error_type, error_message in outcome_report_warnings:
        warning = f"{item.translation_unit_id}/{item.symbol}: {error_type}: {error_message}"
        report_warnings.append(warning)
        output.emit(
            "discovery_project_grind_report_warning",
            "A function search finished, but its detailed review report could not be "
            "written. The remaining searches will continue, and any already-saved proven "
            "records remain unchanged.",
            project=root,
            report=desired_report,
            translation_unit=item.translation_unit_id,
            symbol=item.symbol,
            error_type=error_type,
            error=error_message,
            nonfatal=True,
        )
    try:
        (
            report_json,
            report_html,
            report_transaction_id,
            decision_reports,
            persisted_plans,
        ) = _project_grind_reports(
            root,
            state_root,
            result,
            exact_approval_argv=exact_approval_argv,
            progress_approval_argv=progress_approval_argv,
            continue_argv=continue_argv,
            verify_argv=verify_argv,
        )
    except Exception as exc:
        report_warnings.append(f"campaign index: {type(exc).__name__}: {exc}")
        output.emit(
            "discovery_project_grind_report_warning",
            "The bounded project search finished, but its review report could not be "
            "written. Any already-saved proven records remain unchanged.",
            project=root,
            report=desired_report,
            error_type=type(exc).__name__,
            error=str(exc),
            nonfatal=True,
        )
    report_warning = "; ".join(report_warnings) or None

    report_line = (
        f"Report: {report_html}"
        if report_html is not None
        else "Report: unavailable (see the nonfatal warning above)"
    )
    published_exact = sum(outcome.published and outcome.exact for outcome in result.outcomes)
    published_progress = result.published - published_exact
    if not result.outcomes:
        message = (
            "No eligible project functions were available for the bounded grind.\n"
            "Add a reference object named for a translation-unit id or source stem, or use "
            "--reference-object TU=PATH.\n"
            f"{report_line}"
        )
    elif result.published:
        if published_exact:
            message = (
                f"Saved {result.published} locally proven adjustment"
                f"{'s' if result.published != 1 else ''}; the final cold build matched every "
                "target exactly.\n"
                "Earlier adjustments in this pass were admitted only as local progress; the "
                "exact final build is the project certification gate.\n"
                f"{report_line}\n"
                f"Next: {human_command(verify_argv)}"
            )
        else:
            message = (
                f"Saved {published_progress} locally proven adjustment"
                f"{'s' if published_progress != 1 else ''} from {len(result.outcomes)} bounded "
                "function searches.\n"
                "Each saved function matches its project-owned reference object and passed its "
                "logic checks. The complete project is still not exact, so no project "
                "certification was issued.\n"
                f"{report_line}\n"
                f"Next: {human_command(continue_argv)}"
            )
    elif result.exact:
        message = (
            f"Found {result.exact} freshly verified exact adjustment"
            f"{'s' if result.exact != 1 else ''} across {len(result.outcomes)} bounded "
            "function searches. Project files stayed unchanged.\n"
            "This is a low-hanging-fruit pass, not a complete solver. Review the report, then "
            "rerun the same fresh proofs and save passing results with:\n"
            f"{human_command(exact_approval_argv)}\n"
            f"{report_line}"
        )
    elif result.qualified:
        message = (
            f"Found {result.qualified} locally proven adjustment"
            f"{'s' if result.qualified != 1 else ''} across {len(result.outcomes)} bounded "
            "function searches. Project files stayed unchanged.\n"
            "These functions match their project-owned reference objects and passed their "
            "logic checks, but the complete project does not match yet. Review the report, "
            "then save this bounded progress without claiming project certification with:\n"
            f"{human_command(progress_approval_argv)}\n"
            f"{report_line}"
        )
    else:
        message = (
            f"Tried {len(result.outcomes)} bounded project function"
            f"{'s' if len(result.outcomes) != 1 else ''}; no safe local adjustment was proven. "
            "Project files stayed unchanged.\n"
            "The grind intentionally stops short of an exhaustive solver.\n"
            f"{report_line}"
        )
    if result.exact and not result.accepted:
        next_argv = exact_approval_argv
    elif result.qualified and not result.accepted:
        next_argv = progress_approval_argv
    elif published_exact:
        next_argv = verify_argv
    elif result.published:
        next_argv = continue_argv
    else:
        next_argv = ()
    output.emit(
        "discovery_project_grind_complete",
        message,
        project=root,
        project_wide=True,
        accepted=result.accepted,
        accept_mode=(
            "progress" if accept_progress else ("exact" if args.accept_exact else "preview")
        ),
        eligible_units=result.campaign.eligible_units,
        reference_objects=result.campaign.reference_objects,
        discovered_symbols=result.campaign.discovered_symbols,
        attempted_symbols=len(result.outcomes),
        truncated_symbols=result.campaign.truncated_symbols,
        locally_qualified_symbols=result.qualified,
        exact_symbols=result.exact,
        published_symbols=result.published,
        published_progress_symbols=published_progress,
        max_symbols=args.max_symbols,
        report_json=report_json,
        report_html=report_html,
        decision_reports=decision_reports,
        persisted_plans=persisted_plans,
        report_transaction_id=report_transaction_id,
        report_warning=report_warning,
        approval_argv=(
            exact_approval_argv
            if result.exact and not result.accepted
            else (progress_approval_argv if result.qualified and not result.accepted else ())
        ),
        verify_argv=verify_argv,
        next_argv=next_argv,
        next_command=human_command(next_argv) if next_argv else None,
        outcomes=[
            {
                "target": outcome.item.target_id,
                "translation_unit": outcome.item.translation_unit_id,
                "symbol": outcome.item.symbol,
                "reference_object": outcome.item.reference_object,
                "locally_qualified": outcome.locally_qualified,
                "exact": outcome.exact,
                "published": outcome.published,
                "added_cost": outcome.added_cost,
            }
            for outcome in result.outcomes
        ],
        skips=[
            {
                "translation_unit": skip.translation_unit_id,
                "reference_object": skip.reference_object,
                "symbol": skip.symbol,
                "reason": skip.reason,
            }
            for skip in result.campaign.skips
        ],
    )
    if args.accept_exact:
        return 0 if any(outcome.published and outcome.exact for outcome in result.outcomes) else 1
    if accept_progress:
        return 0 if result.published else 1
    return 0 if result.qualified else 1


__all__ = ["command_discover_project_grind", "project_state_root"]
