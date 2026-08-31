"""CLI orchestration for incremental builds and exact verification."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reprobit.build import BuildPlan, BuildStep
from reprobit.cli_environment import selected_backend
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError, project_root, resolve_program, safe_project_path
from reprobit.cli_state import state_root
from reprobit.model import AuthenticityPolicy
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project_tree
from reprobit.schema import (
    CommandBuildAdapter,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
)
from reprobit.state import KeepWorkspace, RunArena

if TYPE_CHECKING:
    from reprobit.classic_runtime_preparation import ClassicProducerGraphPreparedRun
    from reprobit.cli_environment import ClassicExecutionInputs


def _host_environment(programs: Sequence[str], temporary: Path) -> tuple[tuple[str, str], ...]:
    directories = [str(Path(item).parent) for item in programs]
    directories.extend(os.defpath.split(os.pathsep))
    values = {
        "PATH": os.pathsep.join(dict.fromkeys(directories)),
        "LANG": "C",
        "LC_ALL": "C",
        "TMP": str(temporary),
        "TEMP": str(temporary),
    }
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        values["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return tuple(sorted(values.items()))


def _runtime_plan(
    spec: ProjectSpec,
    root: Path,
    temporary: Path,
) -> BuildPlan:
    outputs = tuple(str(safe_project_path(root, target.artifact)) for target in spec.targets)
    if not isinstance(spec.build, CommandBuildAdapter):
        raise CLIError(f"unsupported build adapter: {type(spec.build).__name__}")
    declared = (*spec.build.configure, *spec.build.build)
    steps: list[BuildStep] = []
    for index, command in enumerate(declared):
        cwd = safe_project_path(root, command.cwd)
        program = resolve_program(command.argv[0], cwd)
        step = BuildStep(
            id=f"command.{index:04d}",
            argv=(program, *command.argv[1:]),
            cwd=str(cwd),
            depends_on=(steps[-1].id,) if steps else (),
            outputs=outputs if index == len(declared) - 1 else (),
            environment=_host_environment((program,), temporary),
            timeout_seconds=command.timeout_seconds,
        )
        steps.append(step)
    return BuildPlan(tuple(steps))


def prepare_producer_graph_run(
    args: argparse.Namespace,
    bundle: ProjectBundle,
    *,
    project_root: Path,
    session_root: Path,
    execution: ClassicExecutionInputs,
    progress: Callable[[int, int, str, str, ProgressKind, str | None], None],
) -> ClassicProducerGraphPreparedRun:
    """Prepare the closed built-in direct runtime from CLI authority."""

    from reprobit.classic_runtime_preparation import prepare_classic_producer_graph_run

    def relay_progress(
        completed: int,
        total: int,
        phase: str,
        node_id: str,
        kind: str,
        reason: str | None,
    ) -> None:
        progress(completed, total, phase, node_id, ProgressKind(kind), reason)

    return prepare_classic_producer_graph_run(
        bundle,
        project_root=project_root,
        session_root=session_root,
        toolchain_root=execution.toolchain_root,
        backend=execution.backend,
        jobs=args.jobs,
        compiler_transport=execution.compiler_transport,
        resource_transport=execution.resource_transport,
        initialization_timeout=args.initialization_timeout,
        compile_timeout=args.compile_timeout,
        link_timeout=args.link_timeout,
        cleanup_timeout=args.cleanup_timeout,
        progress=relay_progress,
        measured_receipt_repair=getattr(args, "_classic_measured_receipt_repair", None),
    )


def _quarantine_oracle_targets(bundle: ProjectBundle) -> frozenset[str]:
    """Return the classic quarantine path's exact oracle capability set."""

    from reprobit.classic_orchestration import (
        _classic_quarantine_action_authority,
    )

    actions_by_unit = _classic_quarantine_action_authority(bundle)
    return frozenset(
        action.oracle_target for actions in actions_by_unit.values() for action in actions
    )


def command_build(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.engine import BuildPlanExecutor

    root = project_root(args.project)
    with output.activity("checking the project files", phase="validate"):
        if args.cold:
            # Cold developer builds retain the exact committed source pins and
            # stay wholly outside the incremental cache implementation.
            bundle = load_project_tree(root)
            developer_authority = None
        else:
            committed = load_project_tree(root, verify_source_authority=False)
            if isinstance(committed.spec.build, ProducerGraphBuildAdapter):
                # This invocation-local view is created before state/cache or
                # runtime work. It never rewrites committed authority.
                from reprobit.incremental import current_worktree_authority

                developer_authority = current_worktree_authority(committed, root)
                bundle = developer_authority.bundle
            else:
                # Non-producer adapters have no dependency-aware warm authority.
                # Preserve their existing strict source validation.
                bundle = load_project_tree(root)
                developer_authority = None
    execution = None
    if isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        from reprobit.cli_environment import resolve_classic_execution_inputs

        execution = resolve_classic_execution_inputs(
            profile=bundle.spec.toolchain.profile,
            explicit_toolchain_root=args.toolchain_root,
            backend=selected_backend(args),
            compiler_transport=args.compiler_transport,
            resource_transport=args.resource_transport,
        )
    state = state_root(root, bundle.spec)
    cache_override = getattr(args, "_incremental_cache_root", None)
    cache_state = (
        Path(cache_override).resolve(strict=True)
        if cache_override is not None
        else state
    )
    if not cache_state.is_dir():
        raise CLIError("incremental cache root is not a directory")
    required = tuple(safe_project_path(root, item.artifact) for item in bundle.spec.targets)
    arena = RunArena(
        state,
        kind="build",
        keep=KeepWorkspace(args.keep_workspace),
    )
    try:
        with arena:
            run_root = arena.path
            if isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
                assert execution is not None
                if args.cold:
                    with output.producer_activity("building from scratch") as progress:
                        prepared = prepare_producer_graph_run(
                            args,
                            bundle,
                            project_root=root,
                            session_root=run_root / "classic",
                            execution=execution,
                            progress=progress,
                        )
                        with ExitStack() as stack:
                            stack.callback(prepared.close)
                            from reprobit.oracle_pe32 import bind_pe32_oracle
                            from reprobit.verify import seal_file_oracle

                            quarantine_targets = _quarantine_oracle_targets(bundle)
                            prepared.donors.bind_legacy_oracles(
                                {
                                    target.id: bind_pe32_oracle(
                                        stack.enter_context(
                                            seal_file_oracle(safe_project_path(root, target.oracle))
                                        )
                                    )
                                    for target in bundle.spec.targets
                                    if target.id in quarantine_targets
                                }
                            )
                            receipt = prepared.executor.execute(
                                prepared.plan,
                                cold=True,
                                required_outputs=required,
                            )
                    incremental_summary = None
                else:
                    assert developer_authority is not None
                    from reprobit.classic_incremental import (
                        execute_classic_incremental_build,
                    )

                    progress_description = getattr(
                        args,
                        "_incremental_progress_description",
                        "rebuilding changed steps and reusing unchanged work",
                    )
                    with output.producer_activity(progress_description) as progress:

                        def incremental_progress(
                            kind: str,
                            completed: int,
                            total: int,
                            phase: str,
                            node_id: str,
                            reason: str | None,
                        ) -> None:
                            progress(
                                completed,
                                total,
                                phase,
                                node_id,
                                ProgressKind(kind),
                                reason,
                            )

                        incremental = execute_classic_incremental_build(
                            developer_authority,
                            project_root=root,
                            session_root=run_root / "incremental",
                            state_root=cache_state,
                            toolchain_root=execution.toolchain_root,
                            backend=execution.backend,
                            jobs=args.jobs,
                            compiler_transport=execution.compiler_transport,
                            resource_transport=execution.resource_transport,
                            initialization_timeout=args.initialization_timeout,
                            compile_timeout=args.compile_timeout,
                            link_timeout=args.link_timeout,
                            cleanup_timeout=args.cleanup_timeout,
                            progress=incremental_progress,
                            measured_receipt_repair=getattr(
                                args,
                                "_classic_measured_receipt_repair",
                                None,
                            ),
                            repair_analysis=bool(
                                getattr(args, "_classic_repair_analysis_only", False)
                            ),
                        )
                    receipt = incremental.receipt
                    incremental_summary = incremental.summary
            else:
                temporary = run_root / "host-tmp"
                temporary.mkdir()
                plan = _runtime_plan(bundle.spec, root, temporary)
                with output.activity("executing build plan", phase="execute"):
                    receipt = BuildPlanExecutor(
                        run_root=run_root / "tasks",
                        max_workers=args.jobs,
                    ).execute(plan, cold=args.cold, required_outputs=required)
                incremental_summary = None
    except BaseException:
        if arena.path.is_dir():
            output.emit(
                "workspace_retained",
                f"retained failed build workspace: {arena.path}",
                path=arena.path,
                outcome="failed",
                diagnostic=True,
            )
            output.emit(
                "workspace_gc_hint",
                f"remove retained workspaces when finished: rbit clean {root}",
                project=root,
                diagnostic=True,
            )
        raise
    if arena.path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful build workspace: {arena.path}",
            path=arena.path,
            outcome="succeeded",
            diagnostic=True,
        )
    if incremental_summary is not None:
        output.incremental_summary(incremental_summary)
        completion_message = (
            "Build complete: "
            f"{incremental_summary.hits + incremental_summary.misses} step(s), "
            f"{len(receipt.outputs)} output(s)"
        )
        completion_fields: dict[str, Any] = {
            "nodes": incremental_summary.hits + incremental_summary.misses,
            "hits": incremental_summary.hits,
            "misses": incremental_summary.misses,
        }
    else:
        completion_message = (
            f"Build complete: {len(receipt.steps)} step(s), {len(receipt.outputs)} output(s)"
        )
        completion_fields = {"steps": len(receipt.steps)}
    output.emit(
        "build_complete",
        completion_message,
        cold=receipt.cold,
        **completion_fields,
        outputs=[
            {"path": item.path, "sha256": item.digest.value, "size": item.size}
            for item in receipt.outputs
        ],
    )
    return 0


def command_verify(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.engine import (
        EngineRequest,
        ReportDestinations,
        ReproductionEngine,
    )
    from reprobit.execution import TargetOracle
    from reprobit.verify import seal_file_oracle

    if getattr(args, "_classic_measured_receipt_repair", None) is not None:
        raise CLIError("exact verification refuses provisional measured receipt repairs")
    root = project_root(args.project)
    with output.activity("checking the project files", phase="validate"):
        bundle = load_project_tree(root)
    requested_policy = (
        AuthenticityPolicy(args.policy)
        if args.policy is not None
        else bundle.spec.authenticity.policy
    )
    if (
        requested_policy is AuthenticityPolicy.ALLOW_QUARANTINE
        and bundle.spec.authenticity.policy is AuthenticityPolicy.CLEAN
    ):
        raise CLIError("requested authenticity policy would broaden the committed clean policy")
    if isinstance(bundle.spec.build, CommandBuildAdapter):
        raise CLIError(
            "cold verification refuses command adapters without declared input/output receipts"
        )
    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise CLIError(f"unsupported certification adapter: {type(bundle.spec.build).__name__}")
    from reprobit.cli_environment import resolve_classic_execution_inputs

    execution = resolve_classic_execution_inputs(
        profile=bundle.spec.toolchain.profile,
        explicit_toolchain_root=args.toolchain_root,
        backend=selected_backend(args),
        compiler_transport=args.compiler_transport,
        resource_transport=args.resource_transport,
    )
    state = state_root(root, bundle.spec)
    if args.report_dir:
        report_directory = safe_project_path(root, args.report_dir)
        report_json = report_directory / "report.json"
        report_html = report_directory / "report.html"
    else:
        report_json = state / "reports" / "report.json"
        report_html = state / "reports" / "report.html"
    if (args.action_receipt is None) != (args.action_nonce is None):
        raise CLIError("--action-receipt and --action-nonce must be supplied together")
    action_receipt = (
        Path(args.action_receipt).expanduser().resolve(strict=False)
        if args.action_receipt is not None
        else None
    )
    arena = RunArena(
        state,
        kind="verify",
        keep=KeepWorkspace(args.keep_workspace),
    )
    try:
        with arena:
            run_root = arena.path
            with output.producer_activity(
                "building from scratch and checking the exact output"
            ) as progress:
                prepared = prepare_producer_graph_run(
                    args,
                    bundle,
                    project_root=root,
                    session_root=run_root / "classic",
                    execution=execution,
                    progress=progress,
                )
                with ExitStack() as stack:
                    stack.callback(prepared.close)
                    oracles = tuple(
                        TargetOracle(
                            target.id,
                            stack.enter_context(
                                seal_file_oracle(safe_project_path(root, target.oracle))
                            ),
                        )
                        for target in bundle.spec.targets
                    )
                    from reprobit.oracle_pe32 import bind_pe32_oracle

                    quarantine_targets = _quarantine_oracle_targets(bundle)
                    prepared.donors.bind_legacy_oracles(
                        {
                            oracle.target_id: bind_pe32_oracle(oracle.capability)
                            for oracle in oracles
                            if oracle.target_id in quarantine_targets
                        }
                    )
                    request = EngineRequest(
                        bundle=bundle,
                        build_plan=prepared.plan,
                        project_root=root,
                        run_root=run_root,
                        oracles=oracles,
                        jobs=args.jobs,
                        cold=True,
                        reports=ReportDestinations(json=report_json, html=report_html),
                        evidence_providers=(prepared.evidence_provider,),
                        build_executor=prepared.executor,
                    )
                    result = ReproductionEngine().run(request)
        if action_receipt is not None and args.action_nonce is not None:
            from reprobit.action_summary import publish_action_completion

            publish_action_completion(
                result.report,
                report_path=report_json,
                html_path=report_html,
                receipt_path=action_receipt,
                nonce=args.action_nonce,
            )
    except BaseException:
        if arena.path.is_dir():
            output.emit(
                "workspace_retained",
                f"retained failed verification workspace: {arena.path}",
                path=arena.path,
                outcome="failed",
                diagnostic=True,
            )
            output.emit(
                "workspace_gc_hint",
                f"remove retained workspaces when finished: rbit clean {root}",
                project=root,
                diagnostic=True,
            )
        raise
    if arena.path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful verification workspace: {arena.path}",
            path=arena.path,
            outcome="succeeded",
            diagnostic=True,
        )
    accepted = result.accepts(requested_policy)
    exact_targets = sum(item.comparison.byte_exact for item in result.targets)
    quarantine_actions = len(result.verdict.quarantines)
    quarantine_bytes = sum(item.byte_count for item in result.verdict.quarantines)
    if accepted:
        message_lines = [
            f"Verification passed: {exact_targets}/{len(result.targets)} targets are byte-identical"
        ]
        if result.verdict.clean:
            message_lines.append("Authenticity: clean; every required claim passed")
        elif result.verdict.quarantined:
            message_lines.append(
                "Authenticity: accepted with "
                f"{quarantine_actions} disclosed exception(s) covering "
                f"{quarantine_bytes} bytes"
            )
        message_lines.extend(
            (
                f"Intervention cost: {result.report.costs.project_total:,} relative points",
                f"Report: {report_html}",
            )
        )
    else:
        message_lines = [
            "Verification did not satisfy the authenticity policy",
            f"Byte identity: {exact_targets}/{len(result.targets)} targets exact",
            f"Report: {report_html}",
        ]
    output.emit(
        "verification",
        "\n".join(message_lines),
        verdict=result.verdict,
        policy=requested_policy,
        accepted=accepted,
        origin_integrity=result.evidence.origin_integrity,
        report_json=report_json,
        report_html=report_html,
        total_cost=result.report.costs.project_total,
        targets=len(result.targets),
        exact_targets=exact_targets,
        quarantine_actions=quarantine_actions,
        quarantine_bytes=quarantine_bytes,
    )
    return 0 if accepted else 1


__all__ = ["command_build", "command_verify", "prepare_producer_graph_run"]
