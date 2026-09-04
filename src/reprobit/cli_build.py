"""CLI orchestration for incremental builds and exact verification."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from reprobit.cli_environment import selected_backend
from reprobit.cli_output import CLIOutput, bounded_items, count_phrase, human_command
from reprobit.cli_paths import (
    project_root,
)
from reprobit.model import AuthenticityPolicy
from reprobit.project_execution import (
    NULL_EXECUTION_PROGRESS as NULL_EXECUTION_PROGRESS,
)
from reprobit.project_execution import (
    BuildRequest as BuildRequest,
)
from reprobit.project_execution import (
    BuildResult as BuildResult,
)
from reprobit.project_execution import (
    ExecutionProgress as ExecutionProgress,
)
from reprobit.project_execution import (
    LedgerPublication as LedgerPublication,
)
from reprobit.project_execution import (
    NullExecutionProgress as NullExecutionProgress,
)
from reprobit.project_execution import (
    ProducerProgress as ProducerProgress,
)
from reprobit.project_execution import (
    ProjectExecutionOptions as ProjectExecutionOptions,
)
from reprobit.project_execution import (
    RepairAnalysisOptions as RepairAnalysisOptions,
)
from reprobit.project_execution import (
    VerifyRequest as VerifyRequest,
)
from reprobit.project_execution import (
    VerifyResult as VerifyResult,
)
from reprobit.project_execution import (
    WorkspaceObserver as WorkspaceObserver,
)
from reprobit.project_execution import (
    execute_build as execute_build,
)
from reprobit.project_execution import (
    execute_verify as execute_verify,
)
from reprobit.project_execution import (
    prepare_producer_graph_run as prepare_producer_graph_run,
)
from reprobit.state import KeepWorkspace


def execution_options_from_cli(args: argparse.Namespace) -> ProjectExecutionOptions:
    """Translate parsed CLI fields once at the command boundary."""

    return ProjectExecutionOptions(
        jobs=args.jobs,
        backend=selected_backend(args),
        toolchain_root=args.toolchain_root,
        compiler_transport=args.compiler_transport,
        resource_transport=args.resource_transport,
        initialization_timeout=args.initialization_timeout,
        compile_timeout=args.compile_timeout,
        link_timeout=args.link_timeout,
        cleanup_timeout=args.cleanup_timeout,
    )


def _project_relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _workspace_observer(output: CLIOutput, project: Path) -> WorkspaceObserver:
    def observe(kind: str, path: Path, outcome: str) -> None:
        adjective = "failed" if outcome == "failed" else "successful"
        output.emit(
            "workspace_retained",
            f"retained {adjective} {kind} workspace: {path}",
            path=path,
            outcome=outcome,
            diagnostic=True,
        )
        if outcome == "failed":
            output.emit(
                "workspace_gc_hint",
                "remove retained workspaces when finished: "
                f"{human_command(('rbit', 'clean', project))}",
                project=project,
                diagnostic=True,
            )

    return observe


def _emit_build_result(output: CLIOutput, result: BuildResult) -> None:
    receipt = result.receipt
    incremental_summary = result.incremental_summary
    if incremental_summary is not None:
        output.incremental_summary(incremental_summary)
        completion_message = (
            "Build complete: "
            f"{count_phrase(incremental_summary.hits + incremental_summary.misses, 'step')}, "
            f"{count_phrase(len(receipt.outputs), 'output')}"
        )
        completion_fields: dict[str, Any] = {
            "nodes": incremental_summary.hits + incremental_summary.misses,
            "hits": incremental_summary.hits,
            "misses": incremental_summary.misses,
        }
    else:
        completion_message = (
            f"Build complete: {count_phrase(len(receipt.steps), 'step')}, "
            f"{count_phrase(len(receipt.outputs), 'output')}"
        )
        completion_fields = {"steps": len(receipt.steps)}
    if output.output_format == "text":
        visible_outputs, hidden_outputs = bounded_items(receipt.outputs)
        completion_message += "".join(
            f"\n  {_project_relative(result.project, item.path)} ({item.size:,} bytes)"
            for item in visible_outputs
        )
        if hidden_outputs:
            completion_message += f"\n  ... and {hidden_outputs} more outputs"
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


def command_build(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    result = execute_build(
        BuildRequest(
            project=root,
            execution=execution_options_from_cli(args),
            cold=args.cold,
            keep_workspace=KeepWorkspace(args.keep_workspace),
        ),
        output,
        workspace_observer=_workspace_observer(output, root),
    )
    _emit_build_result(output, result)
    return 0


def _emit_verify_result(output: CLIOutput, verified: VerifyResult) -> None:
    result = verified.engine
    requested_policy = verified.policy
    report_json = verified.report_json
    report_html = verified.report_html
    accepted = verified.accepted
    if verified.ledger is not None:
        ledger_fields = (
            {"functions": verified.ledger.functions}
            if verified.ledger.functions is not None
            else {}
        )
        output.emit(
            "composed_body_ledger",
            verified.ledger.message,
            path=verified.ledger.path,
            outcome=verified.ledger.outcome,
            diagnostic=True,
            **ledger_fields,
        )
    exact_targets = sum(item.comparison.byte_exact for item in result.targets)
    target_results = {item.target_id: item.comparison.byte_exact for item in result.targets}
    different_targets = tuple(target for target, exact in target_results.items() if not exact)
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
                f"{count_phrase(quarantine_actions, 'disclosed exception')} covering "
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
        ]
        if different_targets:
            visible, hidden = bounded_items(different_targets)
            summary = ", ".join(visible)
            if hidden:
                summary += f", ... and {hidden} more"
            message_lines.append(f"Different: {summary}")
        message_lines.append(f"Report: {report_html}")
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
        target_results=target_results,
        quarantine_actions=quarantine_actions,
        quarantine_bytes=quarantine_bytes,
    )


def command_verify(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    verified = execute_verify(
        VerifyRequest(
            project=root,
            execution=execution_options_from_cli(args),
            policy=AuthenticityPolicy(args.policy) if args.policy is not None else None,
            report_directory=args.report_dir,
            action_receipt=(Path(args.action_receipt) if args.action_receipt is not None else None),
            action_nonce=args.action_nonce,
            keep_workspace=KeepWorkspace(args.keep_workspace),
        ),
        output,
        workspace_observer=_workspace_observer(output, root),
    )
    _emit_verify_result(output, verified)
    return 0 if verified.accepted else 1


__all__ = ["command_build", "command_verify", "execution_options_from_cli"]
