"""Human-first CLI adapter for authenticated project grind runs."""

from __future__ import annotations

import argparse
import io
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import CLIError, project_root, relative_output, safe_project_path
from reprobit.discovery_contracts import InclusiveRange, enumerate_declaration_states
from reprobit.discovery_grind import (
    ColdTrialEvidence,
    ProjectGrindCallbacks,
    run_project_grind,
)
from reprobit.discovery_grind_report import render_grind_report_html
from reprobit.discovery_project import ProjectGrindPlan
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project, load_project_tree
from reprobit.report_io import (
    read_report_json,
    render_report_html,
)
from reprobit.state import KeepWorkspace
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

if TYPE_CHECKING:
    from reprobit.classic_runtime_preparation import ClassicProducerGraphPreparedRun
    from reprobit.schema import ProjectBundle


PrepareRun = Callable[..., "ClassicProducerGraphPreparedRun"]
VerifyCommand = Callable[[argparse.Namespace, CLIOutput], int]


def _canonical_project_relative(value: str, *, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\0" in value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CLIError(f"{label} must be a canonical project-relative path")
    return value


def command_discover_grind_init(args: argparse.Namespace, output: CLIOutput) -> int:
    """Create the compact project-aware plan used by the automatic grind."""

    root = project_root(args.project)
    bundle = load_project_tree(root)
    if bundle.build_plan is None:
        raise CLIError("discover init requires a committed ReproBit build plan")
    source = _canonical_project_relative(args.source, label="source")
    matches = tuple(
        unit
        for unit in bundle.build_plan.translation_units
        if unit.source.casefold() == source.casefold()
        and (args.translation_unit is None or unit.id == args.translation_unit)
    )
    if not matches:
        detail = (
            f" for translation unit `{args.translation_unit}`"
            if args.translation_unit is not None
            else ""
        )
        raise CLIError(f"the build plan has no `{source}` compiler lane{detail}")
    if len(matches) != 1:
        choices = ", ".join(f"`{unit.id}`" for unit in matches)
        raise CLIError(
            f"`{source}` has several compiler lanes ({choices}); choose one with --translation-unit"
        )
    unit = matches[0]
    plan = ProjectGrindPlan(
        reference_object=_canonical_project_relative(
            args.reference,
            label="reference object",
        ),
        target=unit.target_id,
        translation_unit=unit.id,
        symbol=args.symbol,
        classes=InclusiveRange(start=1, stop=4),
        functions=InclusiveRange(start=10, stop=10),
    )
    reference = safe_project_path(root, plan.reference_object)
    if reference.is_symlink() or not reference.is_file():
        raise CLIError(f"reference object is unavailable: {reference}")
    destination = relative_output(root, args.plan)
    if destination.suffix.casefold() != ".json":
        raise CLIError("project discovery plan must end in .json")
    transaction = CASTransaction(root)
    transaction.write(destination, canonical_json(plan), expected_sha256=None)
    result = transaction.commit()
    states = len(enumerate_declaration_states(plan.plan))
    next_command = human_command(
        ("rbit", "discover", "grind", root, "--plan", destination.as_posix())
    )
    output.emit(
        "discovery_grind_plan_created",
        f"Created a {states}-state grind plan at `{root / destination}`.\n"
        f"Selected `{unit.id}` from `{source}` for `{args.symbol}`.\n"
        "No compiler was run and no intervention authority changed.\n"
        f"Next: {next_command}",
        project=root,
        plan=root / destination,
        target=unit.target_id,
        translation_unit=unit.id,
        source=source,
        symbol=args.symbol,
        reference=plan.reference_object,
        states=states,
        transaction_id=result.transaction_id,
        next_command=next_command,
        next_argv=("rbit", "discover", "grind", str(root), "--plan", destination.as_posix()),
    )
    return 0


def _private_session(staged_root: Path, label: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f".reprobit-grind-{label}-", dir=staged_root))


def _prepare_probe(
    args: argparse.Namespace,
    *,
    staged_root: Path,
    label: str,
    prepare_run: PrepareRun,
) -> tuple[ClassicProducerGraphPreparedRun, Path]:
    bundle: ProjectBundle = load_project_tree(staged_root)
    session = _private_session(staged_root, label)

    def quiet_progress(
        completed: int,
        total: int,
        phase: str,
        node_id: str,
        kind: ProgressKind,
        reason: str | None,
    ) -> None:
        del completed, total, phase, node_id, kind, reason

    try:
        prepared = prepare_run(
            args,
            bundle,
            project_root=staged_root,
            session_root=session,
            progress=quiet_progress,
        )
    except BaseException:
        shutil.rmtree(session, ignore_errors=True)
        raise
    return prepared, session


def _probe_seed(
    args: argparse.Namespace,
    *,
    staged_root: Path,
    node_id: str,
    prepare_run: PrepareRun,
) -> bytes:
    prepared, session = _prepare_probe(
        args,
        staged_root=staged_root,
        label="seed",
        prepare_run=prepare_run,
    )
    try:
        outputs = prepared.probes.probe_compiler_nodes(
            (node_id,),
            source_epoch="effective",
        )
        if len(outputs) != 1 or outputs[0].node_id != node_id:
            raise RuntimeError("seed compiler probe returned a different producer node")
        return outputs[0].object_payload
    finally:
        prepared.close()
        shutil.rmtree(session, ignore_errors=True)


def _probe_donors(
    args: argparse.Namespace,
    *,
    staged_root: Path,
    donor_ids: tuple[str, ...],
    progress: Callable[[int, int, str], None] | None,
    prepare_run: PrepareRun,
) -> dict[str, bytes]:
    prepared, session = _prepare_probe(
        args,
        staged_root=staged_root,
        label="donors",
        prepare_run=prepare_run,
    )
    try:
        outputs = prepared.probes.probe_donor_compilers(
            donor_ids,
            progress=progress,
        )
        return {item.donor_id: item.object_payload for item in outputs}
    finally:
        prepared.close()
        shutil.rmtree(session, ignore_errors=True)


def _cold_trial(
    args: argparse.Namespace,
    *,
    staged_root: Path,
    verify_command: VerifyCommand,
) -> ColdTrialEvidence:
    report_relative = ".reprobit-grind-trial-report"
    values: dict[str, Any] = dict(vars(args))
    values.update(
        {
            "project": str(staged_root),
            "policy": None,
            "report_dir": report_relative,
            "action_receipt": None,
            "action_nonce": None,
            "keep_workspace": KeepWorkspace.NEVER.value,
        }
    )
    sink = io.StringIO()
    status = verify_command(
        argparse.Namespace(**values),
        CLIOutput("text", sink, sink),
    )
    report = read_report_json(staged_root / report_relative / "report.json")
    return ColdTrialEvidence(accepted=status == 0, report=report)


def _grind_callbacks(
    args: argparse.Namespace,
    *,
    prepare_run: PrepareRun,
    verify_command: VerifyCommand,
) -> ProjectGrindCallbacks:
    return ProjectGrindCallbacks(
        probe_seed=lambda staged, node: _probe_seed(
            args,
            staged_root=staged,
            node_id=node,
            prepare_run=prepare_run,
        ),
        probe_donors=lambda staged, donors, progress: _probe_donors(
            args,
            staged_root=staged,
            donor_ids=donors,
            progress=progress,
            prepare_run=prepare_run,
        ),
        cold_verify=lambda staged: _cold_trial(
            args,
            staged_root=staged,
            verify_command=verify_command,
        ),
    )


def command_discover_grind(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    prepare_run: PrepareRun,
    verify_command: VerifyCommand,
) -> int:
    """Run the public bounded auto-solve workflow."""

    if getattr(args, "project_wide", False):
        from reprobit.discovery_project_grind_cli import command_discover_project_grind

        return command_discover_project_grind(
            args,
            output,
            callbacks=_grind_callbacks(
                args,
                prepare_run=prepare_run,
                verify_command=verify_command,
            ),
        )
    if getattr(args, "reference_object", ()):
        raise CLIError("--reference-object requires --project-wide")

    root = project_root(args.project)
    report_directory = safe_project_path(root, load_project(root).state_dir) / "reports" / "grind"
    with output.producer_activity("Finding and proving a low-cost exact intervention") as progress:
        result = run_project_grind(
            root,
            plan_relative=args.plan,
            accept_exact=args.accept_exact,
            callbacks=_grind_callbacks(
                args,
                prepare_run=prepare_run,
                verify_command=verify_command,
            ),
            progress=progress,
        )

    solution = result.solution
    desired_grind_report = report_directory / "report.html"
    desired_cold_json = report_directory / "cold-verification.json"
    desired_cold_html = report_directory / "cold-verification.html"
    grind_report_html: Path | None = None
    cold_report_json: Path | None = None
    cold_report_html: Path | None = None
    report_transaction_id: str | None = None
    report_warnings: list[str] = []
    report_approval_command = human_command(
        (
            "rbit",
            "discover",
            "grind",
            root,
            "--plan",
            args.plan,
            "--accept-exact",
        )
    )
    report_verify_command = human_command(("rbit", "verify", root))

    def warn_report(artifact: str, path: Path, exc: Exception) -> None:
        warning = f"{artifact}: {type(exc).__name__}: {exc}"
        report_warnings.append(warning)
        project_status = (
            "The already-saved project records remain unchanged."
            if result.published
            else "Project files remain unchanged."
        )
        output.emit(
            "discovery_grind_report_warning",
            f"The grind outcome is complete, but {artifact} could not be written. {project_status}",
            project=root,
            published=result.published,
            artifact=artifact,
            report=path,
            error_type=type(exc).__name__,
            error=str(exc),
            nonfatal=True,
        )

    cold_files: dict[Path, bytes] = {}
    if solution is not None:
        try:
            cold_files = {
                relative_output(root, str(desired_cold_json)): canonical_json(solution.report),
                relative_output(root, str(desired_cold_html)): render_report_html(
                    solution.report,
                    canonical_json_href=desired_cold_json.name,
                ).encode("utf-8"),
            }
        except Exception as exc:
            warn_report("the cold verification report", desired_cold_html, exc)

    try:
        files = {
            relative_output(root, str(desired_grind_report)): render_grind_report_html(
                result,
                plan_relative=args.plan,
                cold_report_html=(desired_cold_html.name if cold_files else None),
                cold_report_json=(desired_cold_json.name if cold_files else None),
                approval_command=report_approval_command,
                verify_command=report_verify_command,
            ).encode("utf-8")
        }
        files.update(cold_files)
        transaction = CASTransaction(root)
        for relative, payload in files.items():
            transaction.write(relative, payload)
        report_transaction_id = transaction.commit().transaction_id
        grind_report_html = desired_grind_report
        if cold_files:
            cold_report_json = desired_cold_json
            cold_report_html = desired_cold_html
    except Exception as exc:
        warn_report("the grind review report", desired_grind_report, exc)

    report_warning = "; ".join(report_warnings) or None

    grind_report_line = (
        f"Grind report: `{grind_report_html}`"
        if grind_report_html is not None
        else "Grind report: unavailable (see the nonfatal warning above)"
    )
    cold_report_line = (
        f"Cold verification: `{cold_report_html}`"
        if cold_report_html is not None
        else "Cold verification report: unavailable"
    )

    if solution is None:
        reasons = Counter(item.reason for item in result.rejections)
        common = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:3]
        reason_summary = ""
        if common:
            reason_summary = "\nMost common reasons:\n" + "\n".join(
                f"- {reason} ({count} state{'s' if count != 1 else ''})" for reason, count in common
            )
        message = (
            f"No exact solution was found in {result.states} bounded declaration states.\n"
            "No project files changed. Widen `reprobit/discovery.json` "
            f"deliberately if these bounds are too small.{reason_summary}\n"
            f"{grind_report_line}"
        )
    elif result.published:
        classes, functions = (solution.state.parameter(name) for name in ("classes", "functions"))
        intervention_file, proof_file = solution.authority_files
        saved_summary = (
            "ReproBit saved 1 function intervention, reused the matching shared donor, "
            "and updated its cost assignment"
            if solution.reused_donor
            else "ReproBit saved 2 intervention records and their matching proof records"
        )
        review_command = human_command(("git", "diff", "--", intervention_file, proof_file))
        verify_command_text = human_command(("rbit", "verify", root))
        message = (
            f"Exact solution saved for `{solution.symbol}`: "
            f"`classes={classes}`, `functions={functions}`.\n"
            "A fresh build matched every target byte for byte, and both required logic "
            f"checks passed. {saved_summary} in one safe update.\n"
            f"Changed: `{intervention_file}`, `{proof_file}`\n"
            f"Added cost: {solution.added_cost} relative points.\n"
            f"{grind_report_line}\n"
            f"{cold_report_line}\n"
            f"Review: {review_command}\n"
            f"Next: {verify_command_text}"
        )
    else:
        classes, functions = (solution.state.parameter(name) for name in ("classes", "functions"))
        approval_command = human_command(
            (
                "rbit",
                "discover",
                "grind",
                root,
                "--plan",
                args.plan,
                "--accept-exact",
            )
        )
        reuse_line = (
            "Approval will save 1 function intervention, reuse the matching shared donor, "
            "and update its cost assignment.\n"
            if solution.reused_donor
            else "Approval will save 2 intervention records and their matching proof records.\n"
        )
        message = (
            f"Exact solution found for `{solution.symbol}`: "
            f"`classes={classes}`, `functions={functions}`.\n"
            "A fresh build matched every target byte for byte, and both required logic "
            "checks passed. Only review reports were written; project files stayed unchanged.\n"
            f"{reuse_line}"
            f"Added cost if approved: {solution.added_cost} relative points.\n"
            f"{grind_report_line}\n"
            f"{cold_report_line}\n"
            "Approval always performs a fresh proof run before publishing:\n"
            f"{approval_command}"
        )

    output.emit(
        "discovery_grind_complete",
        message,
        project=root,
        exact=result.exact,
        published=result.published,
        states=result.states,
        compiler_trials=result.compiler_trials,
        qualified_candidates=result.qualified_candidates,
        cold_trials=result.cold_trials,
        added_interventions=(
            solution.added_interventions if solution is not None and result.published else 0
        ),
        proposed_interventions=(solution.added_interventions if solution is not None else 0),
        reused_donor=solution.reused_donor if solution is not None else False,
        added_cost=solution.added_cost if solution is not None else 0,
        symbol=solution.symbol if solution is not None else None,
        declaration_state=solution.state if solution is not None else None,
        donor_id=solution.donor_id if solution is not None else None,
        function_id=solution.function_id if solution is not None else None,
        authority_files=solution.authority_files if solution is not None else (),
        transaction_id=result.transaction_id,
        report_run_id=solution.report.run_id if solution is not None else None,
        grind_report_html=grind_report_html,
        cold_verification_report_json=cold_report_json,
        cold_verification_report_html=cold_report_html,
        report_transaction_id=report_transaction_id,
        report_warning=report_warning,
        approval_argv=(
            "rbit",
            "discover",
            "grind",
            str(root),
            "--plan",
            args.plan,
            "--accept-exact",
        )
        if solution is not None and not result.published
        else (),
        rejections=[
            {
                "state_id": item.state_id,
                "stage": item.stage,
                "reason": item.reason,
            }
            for item in result.rejections
        ],
    )
    return 0 if solution is not None else 1


__all__ = ["command_discover_grind", "command_discover_grind_init"]
