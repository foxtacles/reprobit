"""Human-first CLI adapter for authenticated project grind runs."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from reprobit.cli_build import execution_options_from_cli
from reprobit.cli_environment import resolve_classic_execution_inputs
from reprobit.cli_output import CLIOutput, NextStep, human_command, next_step_fields
from reprobit.cli_paths import (
    CLIError,
    canonical_project_relative,
    project_root,
    relative_output,
    safe_project_path,
)
from reprobit.discovery_contracts import enumerate_declaration_states
from reprobit.discovery_grind import (
    ColdTrialEvidence,
    ProjectGrindCallbacks,
    require_single_acceptance,
    run_project_grind,
)
from reprobit.discovery_grind_report import (
    GrindReportCommands,
    GrindReportLayout,
    grind_approval_argv,
    publish_grind_outcome,
    render_cold_verification,
)
from reprobit.discovery_project import (
    DEFAULT_GRIND_CLASSES,
    DEFAULT_GRIND_FUNCTIONS,
    ProjectGrindPlan,
)
from reprobit.discovery_project_grind_cli import project_state_root
from reprobit.progress import ProgressKind
from reprobit.project_execution import (
    NULL_EXECUTION_PROGRESS,
    ProjectExecutionOptions,
    VerifyRequest,
    execute_verify,
    prepare_producer_graph_run,
)
from reprobit.project_loader import load_project_tree
from reprobit.state import KeepWorkspace
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

if TYPE_CHECKING:
    from reprobit.classic_runtime_preparation import ClassicProducerGraphPreparedRun
    from reprobit.schema import ProjectBundle


def command_discover_grind_init(args: argparse.Namespace, output: CLIOutput) -> int:
    """Create the compact project-aware plan used by the automatic grind."""

    root = project_root(args.project)
    bundle = load_project_tree(root)
    if bundle.build_plan is None:
        raise CLIError("discover init requires a committed ReproBit build plan")
    source = canonical_project_relative(args.source, label="source")
    matches = tuple(
        unit
        for unit in bundle.build_plan.translation_units
        if unit.source.casefold() == source.casefold()
        and (args.translation_unit is None or unit.id == args.translation_unit)
    )
    if not matches:
        detail = (
            f" for translation unit '{args.translation_unit}'"
            if args.translation_unit is not None
            else ""
        )
        raise CLIError(f"the build plan has no '{source}' compiler lane{detail}")
    if len(matches) != 1:
        choices = ", ".join(f"'{unit.id}'" for unit in matches)
        raise CLIError(
            f"'{source}' has several compiler lanes ({choices}); choose one with --translation-unit"
        )
    unit = matches[0]
    plan = ProjectGrindPlan(
        reference_object=canonical_project_relative(
            args.reference,
            label="reference object",
        ),
        target=unit.target_id,
        translation_unit=unit.id,
        symbol=args.symbol,
        classes=DEFAULT_GRIND_CLASSES,
        functions=DEFAULT_GRIND_FUNCTIONS,
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
    next_step = NextStep(
        ("rbit", "discover", "grind", root, "--expert-plan", destination.as_posix())
    )
    output.emit(
        "discovery_grind_plan_created",
        f"Created a {states}-state grind plan at {root / destination}.\n"
        f"Selected '{unit.id}' from '{source}' for '{args.symbol}'.\n"
        "No compiler was run and no intervention authority changed.\n"
        f"Next: {next_step.command}",
        project=root,
        plan=root / destination,
        target=unit.target_id,
        translation_unit=unit.id,
        source=source,
        symbol=args.symbol,
        reference=plan.reference_object,
        states=states,
        transaction_id=result.transaction_id,
        **next_step.fields(),
    )
    return 0


def _private_session(staged_root: Path, label: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f".reprobit-grind-{label}-", dir=staged_root))


def _prepare_probe(
    options: ProjectExecutionOptions,
    *,
    staged_root: Path,
    label: str,
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
        execution = resolve_classic_execution_inputs(
            profile=bundle.spec.toolchain.profile,
            explicit_toolchain_root=options.toolchain_root,
            backend=options.backend,
            compiler_transport=options.compiler_transport,
            resource_transport=options.resource_transport,
        )
        prepared = prepare_producer_graph_run(
            options,
            bundle,
            project_root=staged_root,
            session_root=session,
            execution=execution,
            progress=quiet_progress,
        )
    except BaseException:
        shutil.rmtree(session, ignore_errors=True)
        raise
    return prepared, session


def _probe_seed(
    options: ProjectExecutionOptions,
    *,
    staged_root: Path,
    node_id: str,
) -> bytes:
    prepared, session = _prepare_probe(
        options,
        staged_root=staged_root,
        label="seed",
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
    options: ProjectExecutionOptions,
    *,
    staged_root: Path,
    donor_ids: tuple[str, ...],
    progress: Callable[[int, int, str], None] | None,
) -> dict[str, bytes]:
    prepared, session = _prepare_probe(
        options,
        staged_root=staged_root,
        label="donors",
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
    options: ProjectExecutionOptions,
    *,
    staged_root: Path,
) -> ColdTrialEvidence:
    report_relative = ".reprobit-grind-trial-report"
    verified = execute_verify(
        VerifyRequest(
            project=staged_root,
            execution=options,
            report_directory=report_relative,
            keep_workspace=KeepWorkspace.NEVER,
        ),
        NULL_EXECUTION_PROGRESS,
    )
    return ColdTrialEvidence(accepted=verified.accepted, report=verified.engine.report)


def _grind_callbacks(
    options: ProjectExecutionOptions,
) -> ProjectGrindCallbacks:
    return ProjectGrindCallbacks(
        probe_seed=lambda staged, node: _probe_seed(
            options,
            staged_root=staged,
            node_id=node,
        ),
        probe_donors=lambda staged, donors, progress: _probe_donors(
            options,
            staged_root=staged,
            donor_ids=donors,
            progress=progress,
        ),
        cold_verify=lambda staged: _cold_trial(
            options,
            staged_root=staged,
        ),
    )


def command_discover_grind(
    args: argparse.Namespace,
    output: CLIOutput,
) -> int:
    """Run the public bounded auto-solve workflow."""

    accept_progress = getattr(args, "accept_progress", False)
    require_single_acceptance(
        args.accept_exact,
        accept_progress,
        error=CLIError,
        message="choose either --accept-exact or --accept-progress, not both",
    )
    execution = execution_options_from_cli(args)
    if args.plan is None:
        from reprobit.discovery_project_grind_cli import command_discover_project_grind

        return command_discover_project_grind(
            args,
            output,
            callbacks=_grind_callbacks(execution),
        )
    if getattr(args, "reference_object", ()):
        raise CLIError("--reference-object belongs to the default project-wide grind")
    if getattr(args, "max_symbols", 8) != 8:
        raise CLIError("--max-symbols belongs to the default project-wide grind")

    root = project_root(args.project)
    state_root = project_state_root(root)
    report_directory = state_root / "reports" / "grind"
    with output.producer_activity("finding and proving a low-cost adjustment") as progress:
        result = run_project_grind(
            root,
            plan_relative=args.plan,
            accept_exact=args.accept_exact,
            accept_progress=accept_progress,
            callbacks=_grind_callbacks(execution),
            progress=progress,
        )

    solution = result.solution
    layout = GrindReportLayout(
        report=report_directory / "report.html",
        cold_json=report_directory / "cold-verification.json",
        cold_html=report_directory / "cold-verification.html",
    )
    grind_report_html: Path | None = None
    cold_report_json: Path | None = None
    cold_report_html: Path | None = None
    report_transaction_id: str | None = None
    report_warnings: list[str] = []
    approval_argv = grind_approval_argv(root, args.plan, exact=result.exact)
    report_approval_command = human_command(approval_argv)
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
            diagnostic=True,
        )

    cold_files: dict[Path, bytes] = {}
    if solution is not None:
        try:
            cold_files = render_cold_verification(root, layout, solution)
        except Exception as exc:
            warn_report("the cold verification report", layout.cold_html, exc)

    try:
        publication = publish_grind_outcome(
            root,
            state_root,
            layout,
            result,
            plan_relative=args.plan,
            commands=GrindReportCommands(
                approval=report_approval_command,
                verify=report_verify_command,
                proceed=human_command(("rbit", "discover", "grind", root)),
            ),
            cold_files=cold_files,
        )
        report_transaction_id = publication.transaction_id
        grind_report_html = layout.report
        if cold_files:
            cold_report_json = layout.cold_json
            cold_report_html = layout.cold_html
    except Exception as exc:
        warn_report("the grind review report", layout.report, exc)

    report_warning = "; ".join(report_warnings) or None

    grind_report_line = (
        f"Grind report: {grind_report_html}"
        if grind_report_html is not None
        else "Grind report: unavailable (see the nonfatal warning above)"
    )
    cold_report_line = (
        f"Fresh verification: {cold_report_html}"
        if cold_report_html is not None
        else "Fresh verification report: unavailable"
    )

    if solution is None:
        next_step = None
        reasons = Counter(item.reason for item in result.rejections)
        common = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:3]
        reason_summary = ""
        if common:
            reason_summary = "\nMost common reasons:\n" + "\n".join(
                f"- {reason} ({count} state{'s' if count != 1 else ''})" for reason, count in common
            )
        message = (
            f"No safe local adjustment was found in {result.states} bounded declaration states.\n"
            "No project files changed. Widen reprobit/discovery.json "
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
        outcome_label = "Exact solution" if result.exact else "Local progress"
        verdict_line = (
            "A fresh build matched every target byte for byte, and both required logic "
            "checks passed."
            if result.exact
            else (
                "The function matched its project-owned reference object and both required logic "
                "checks passed. The complete project is not exact, so this is not project "
                "certification."
            )
        )
        next_step = NextStep(
            ("rbit", "verify", root) if result.exact else ("rbit", "discover", "grind", root)
        )
        message = (
            f"{outcome_label} saved for '{solution.symbol}': "
            f"classes={classes}, functions={functions}.\n"
            f"{verdict_line} {saved_summary} in one safe update.\n"
            f"Changed: {intervention_file}, {proof_file}\n"
            f"Added cost: {solution.added_cost} relative points.\n"
            f"{grind_report_line}\n"
            f"{cold_report_line}\n"
            f"Review: {review_command}\n"
            f"Next: {next_step.command}"
        )
    else:
        next_step = NextStep(approval_argv)
        classes, functions = (solution.state.parameter(name) for name in ("classes", "functions"))
        reuse_line = (
            "Approval will save 1 function intervention, reuse the matching shared donor, "
            "and update its cost assignment.\n"
            if solution.reused_donor
            else "Approval will save 2 intervention records and their matching proof records.\n"
        )
        outcome_label = "Exact solution" if result.exact else "Local progress"
        verdict_line = (
            "A fresh build matched every target byte for byte, and both required logic "
            "checks passed."
            if result.exact
            else (
                "The function matched its project-owned reference object and both required logic "
                "checks passed, but the complete project does not match yet."
            )
        )
        message = (
            f"{outcome_label} found for '{solution.symbol}': "
            f"classes={classes}, functions={functions}.\n"
            f"{verdict_line} Only review reports were written; project files stayed unchanged.\n"
            f"{reuse_line}"
            f"Added cost if approved: {solution.added_cost} relative points.\n"
            f"{grind_report_line}\n"
            f"{cold_report_line}\n"
            "Approval always performs a fresh proof run before publishing:\n"
            f"{report_approval_command}"
        )

    output.emit(
        "discovery_grind_complete",
        message,
        project=root,
        exact=result.exact,
        locally_qualified=result.locally_qualified,
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
        approval_argv=(approval_argv if solution is not None and not result.published else ()),
        rejections=[
            {
                "state_id": item.state_id,
                "stage": item.stage,
                "reason": item.reason,
            }
            for item in result.rejections
        ],
        **next_step_fields(next_step),
    )
    if args.accept_exact:
        return 0 if result.published and result.exact else 1
    if accept_progress:
        return 0 if result.published else 1
    return 0 if solution is not None else 1


__all__ = ["command_discover_grind", "command_discover_grind_init"]
