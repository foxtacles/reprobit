"""CLI orchestration for incremental builds and exact verification."""

from __future__ import annotations

import argparse
import math
import os
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, cast

from reprobit.backends import ExecutionBackend
from reprobit.build import BuildPlan, BuildStep
from reprobit.cli_environment import selected_backend
from reprobit.cli_output import CLIOutput, bounded_items, count_phrase, human_command
from reprobit.cli_paths import (
    CLIError,
    project_root,
    report_output_conflict,
    resolve_program,
    safe_project_path,
)
from reprobit.cli_state import state_root
from reprobit.composition_ledger import (
    COMPOSED_BODY_LEDGER_RELATIVE,
    ComposedBodyLedger,
    write_ledger,
)
from reprobit.engine import EngineResult
from reprobit.execution import BuildExecutionReceipt
from reprobit.incremental import IncrementalBuildSummary
from reprobit.model import AuthenticityPolicy
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project_tree
from reprobit.schema import (
    CommandBuildAdapter,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
)
from reprobit.state import KeepWorkspace, RunArena, report_publication_lease

if TYPE_CHECKING:
    from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession
    from reprobit.classic_incremental_context import SeedObject
    from reprobit.classic_repair_dispatch import ClassicMeasuredReceiptRepair
    from reprobit.classic_runtime_preparation import ClassicProducerGraphPreparedRun
    from reprobit.cli_environment import ClassicExecutionInputs
    from reprobit.toolchains import ToolchainDoctorReport


ProducerProgress = Callable[[int, int, str, str, ProgressKind, str | None], None]
WorkspaceObserver = Callable[[str, Path, str], None]


class ExecutionProgress(Protocol):
    """Progress surface shared by CLI and quiet internal workflows."""

    def activity(
        self,
        description: str,
        *,
        phase: str = "work",
    ) -> AbstractContextManager[Callable[[str], None]]: ...

    def producer_activity(
        self,
        description: str,
    ) -> AbstractContextManager[ProducerProgress]: ...


class NullExecutionProgress:
    """Discard progress for internal trial runs that have no user-facing step."""

    @contextmanager
    def activity(
        self,
        description: str,
        *,
        phase: str = "work",
    ) -> Iterator[Callable[[str], None]]:
        del description, phase

        def update(message: str) -> None:
            del message

        yield update

    @contextmanager
    def producer_activity(self, description: str) -> Iterator[ProducerProgress]:
        del description

        def update(
            completed: int,
            total: int,
            phase: str,
            node_id: str,
            kind: ProgressKind,
            reason: str | None,
        ) -> None:
            del completed, total, phase, node_id, kind, reason

        yield update


NULL_EXECUTION_PROGRESS = NullExecutionProgress()


@dataclass(frozen=True, slots=True)
class ProjectExecutionOptions:
    """Host and deadline choices needed to run a project."""

    jobs: int
    backend: ExecutionBackend
    toolchain_root: str | os.PathLike[str] | None = None
    compiler_transport: str | os.PathLike[str] | None = None
    resource_transport: str | os.PathLike[str] | None = None
    initialization_timeout: float = 600.0
    compile_timeout: float = 600.0
    link_timeout: float = 900.0
    cleanup_timeout: float = 10.0

    def __post_init__(self) -> None:
        if self.jobs < 1:
            raise ValueError("jobs must be at least one")
        if any(
            not math.isfinite(value) or value <= 0
            for value in (
                self.initialization_timeout,
                self.compile_timeout,
                self.link_timeout,
                self.cleanup_timeout,
            )
        ):
            raise ValueError("execution timeouts must be finite and positive")


@dataclass(frozen=True, slots=True)
class RepairAnalysisOptions:
    """Explicit non-certifying hooks used only by automatic repair analysis."""

    receipt_repair: ClassicMeasuredReceiptRepair
    seed_census: bool = False


@dataclass(frozen=True, slots=True)
class BuildRequest:
    project: Path
    execution: ProjectExecutionOptions
    cold: bool = False
    keep_workspace: KeepWorkspace = KeepWorkspace.ON_FAILURE
    cache_root: Path | None = None
    repair_analysis: RepairAnalysisOptions | None = None
    progress_description: str = "rebuilding changed steps and reusing unchanged work"


@dataclass(frozen=True, slots=True)
class BuildResult:
    project: Path
    receipt: BuildExecutionReceipt
    incremental_summary: IncrementalBuildSummary | None
    seed_objects: Mapping[str, SeedObject]
    retained_workspace: Path | None


@dataclass(frozen=True, slots=True)
class VerifyRequest:
    project: Path
    execution: ProjectExecutionOptions
    policy: AuthenticityPolicy | None = None
    report_directory: str | os.PathLike[str] | None = None
    action_receipt: Path | None = None
    action_nonce: str | None = None
    keep_workspace: KeepWorkspace = KeepWorkspace.ON_FAILURE
    source_toolchain_report: ToolchainDoctorReport | None = None


@dataclass(frozen=True, slots=True)
class LedgerPublication:
    path: Path
    outcome: str
    message: str
    functions: int | None = None
    payload: bytes | None = None


@dataclass(frozen=True, slots=True)
class VerifyResult:
    project: Path
    engine: EngineResult
    policy: AuthenticityPolicy
    report_json: Path
    report_html: Path
    report_json_payload: bytes
    report_html_payload: bytes
    ledger: LedgerPublication | None
    retained_workspace: Path | None

    @property
    def accepted(self) -> bool:
        return self.engine.accepts(self.policy)


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


def _overlay_render_session() -> ClassicOverlayRenderSession:
    """Create the one overlay render session shared by a build or verify run.

    Project loading renders every source overlay to validate source authority
    and the effective workspace renders them again; sharing one bounded session
    lets the second render reuse the first one's token indexes and anchors.
    """

    from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession

    return ClassicOverlayRenderSession()


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
    options: ProjectExecutionOptions,
    bundle: ProjectBundle,
    *,
    project_root: Path,
    session_root: Path,
    execution: ClassicExecutionInputs,
    progress: ProducerProgress,
    receipt_repair: ClassicMeasuredReceiptRepair | None = None,
    source_toolchain_report: ToolchainDoctorReport | None = None,
    overlay_render_session: ClassicOverlayRenderSession | None = None,
) -> ClassicProducerGraphPreparedRun:
    """Prepare the closed built-in direct runtime from explicit run options."""

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
        jobs=options.jobs,
        compiler_transport=execution.compiler_transport,
        resource_transport=execution.resource_transport,
        initialization_timeout=options.initialization_timeout,
        compile_timeout=options.compile_timeout,
        link_timeout=options.link_timeout,
        cleanup_timeout=options.cleanup_timeout,
        progress=relay_progress,
        measured_receipt_repair=receipt_repair,
        source_toolchain_report=source_toolchain_report,
        overlay_render_session=overlay_render_session,
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


def _repair_oracle_targets(
    prepared: ClassicProducerGraphPreparedRun,
) -> frozenset[str]:
    """Return the extra sealed readers required only during repair analysis."""

    from reprobit.classic_orchestration import classic_unit_oracle_targets

    return frozenset().union(
        *(classic_unit_oracle_targets(unit, repair=True) for unit in prepared.donors.units)
    )


def _project_relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _check_report_outputs(
    root: Path,
    bundle: ProjectBundle,
    outputs: Sequence[tuple[str, Path]],
) -> None:
    """Keep user-selected reports away from project inputs and authority."""

    if bundle.source_manifest is None:
        raise CLIError("verification requires a locked source manifest")
    conflict = report_output_conflict(
        root,
        bundle.spec,
        outputs,
        source_paths=(entry.path for entry in bundle.source_manifest.entries),
    )
    if conflict is not None:
        raise CLIError(conflict)


def execute_build(
    request: BuildRequest,
    progress: ExecutionProgress = NULL_EXECUTION_PROGRESS,
    *,
    workspace_observer: WorkspaceObserver | None = None,
) -> BuildResult:
    """Build from explicit application inputs without rendering a CLI result."""

    with _overlay_render_session() as overlay_session:
        return _execute_build(
            request,
            progress,
            overlay_session=overlay_session,
            workspace_observer=workspace_observer,
        )


def _execute_build(
    request: BuildRequest,
    progress: ExecutionProgress,
    *,
    overlay_session: ClassicOverlayRenderSession,
    workspace_observer: WorkspaceObserver | None,
) -> BuildResult:
    from reprobit.engine import BuildPlanExecutor

    root = project_root(os.fspath(request.project))
    with progress.activity("checking the project files", phase="validate"):
        if request.cold:
            # Cold developer builds retain the exact committed source pins and
            # stay wholly outside the incremental cache implementation.
            bundle = load_project_tree(root, overlay_render_session=overlay_session)
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
            explicit_toolchain_root=request.execution.toolchain_root,
            backend=request.execution.backend,
            compiler_transport=request.execution.compiler_transport,
            resource_transport=request.execution.resource_transport,
        )
    state = state_root(root, bundle.spec)
    cache_state = (
        request.cache_root.resolve(strict=True) if request.cache_root is not None else state
    )
    if not cache_state.is_dir():
        raise CLIError("incremental cache root is not a directory")
    required = tuple(safe_project_path(root, item.artifact) for item in bundle.spec.targets)
    arena = RunArena(
        state,
        kind="build",
        keep=request.keep_workspace,
    )
    seed_objects: Mapping[str, SeedObject] = MappingProxyType({})
    try:
        with arena:
            run_root = arena.path
            if isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
                assert execution is not None
                if request.cold:
                    with progress.producer_activity("building from scratch") as report_progress:
                        prepared = prepare_producer_graph_run(
                            request.execution,
                            bundle,
                            project_root=root,
                            session_root=run_root / "classic",
                            execution=execution,
                            progress=report_progress,
                            receipt_repair=(
                                request.repair_analysis.receipt_repair
                                if request.repair_analysis is not None
                                else None
                            ),
                            overlay_render_session=overlay_session,
                        )
                        # The effective workspace is rendered; release the
                        # retained indexes before the producers start.
                        overlay_session.close()
                        with ExitStack() as stack:
                            stack.callback(prepared.close)
                            from reprobit.oracle_pe32 import bind_pe32_oracle
                            from reprobit.verify import seal_file_oracle

                            repair = request.repair_analysis
                            oracle_targets = (
                                _repair_oracle_targets(prepared)
                                if repair is not None
                                else _quarantine_oracle_targets(bundle)
                            )
                            prepared.donors.bind_legacy_oracles(
                                {
                                    target.id: bind_pe32_oracle(
                                        stack.enter_context(
                                            seal_file_oracle(safe_project_path(root, target.oracle))
                                        )
                                    )
                                    for target in bundle.spec.targets
                                    if target.id in oracle_targets
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
                    from reprobit.classic_incremental_execution import (
                        execute_classic_incremental_build,
                    )

                    with progress.producer_activity(
                        request.progress_description
                    ) as report_progress:

                        def incremental_progress(
                            kind: str,
                            completed: int,
                            total: int,
                            phase: str,
                            node_id: str,
                            reason: str | None,
                        ) -> None:
                            report_progress(
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
                            jobs=request.execution.jobs,
                            compiler_transport=execution.compiler_transport,
                            resource_transport=execution.resource_transport,
                            initialization_timeout=request.execution.initialization_timeout,
                            compile_timeout=request.execution.compile_timeout,
                            link_timeout=request.execution.link_timeout,
                            cleanup_timeout=request.execution.cleanup_timeout,
                            progress=incremental_progress,
                            measured_receipt_repair=(
                                request.repair_analysis.receipt_repair
                                if request.repair_analysis is not None
                                else None
                            ),
                            repair_analysis=request.repair_analysis is not None,
                            seed_census=(
                                request.repair_analysis.seed_census
                                if request.repair_analysis is not None
                                else False
                            ),
                            overlay_render_session=overlay_session,
                        )
                    receipt = incremental.receipt
                    incremental_summary = incremental.summary
                    seed_objects = incremental.seed_objects
            else:
                temporary = run_root / "host-tmp"
                temporary.mkdir()
                plan = _runtime_plan(bundle.spec, root, temporary)
                with progress.activity("executing build plan", phase="execute"):
                    receipt = BuildPlanExecutor(
                        run_root=run_root / "tasks",
                        max_workers=request.execution.jobs,
                    ).execute(plan, cold=request.cold, required_outputs=required)
                incremental_summary = None
    except BaseException:
        if arena.path.is_dir() and workspace_observer is not None:
            workspace_observer("build", arena.path, "failed")
        raise
    retained_workspace = arena.path if arena.path.is_dir() else None
    if retained_workspace is not None and workspace_observer is not None:
        workspace_observer("build", retained_workspace, "succeeded")
    return BuildResult(
        project=root,
        receipt=receipt,
        incremental_summary=incremental_summary,
        seed_objects=seed_objects,
        retained_workspace=retained_workspace,
    )


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


def _composed_body_ledger(run: object) -> tuple[ComposedBodyLedger | None, str | None]:
    """Read the verified function bodies back from the run; never fail the verify over it."""

    from reprobit.composition_ledger_runtime import FinishedRun, ledger_from_run

    try:
        return ledger_from_run(cast(FinishedRun, run)), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _publish_composed_body_ledger(
    state: Path,
    ledger: ComposedBodyLedger | None,
    error: str | None,
) -> LedgerPublication:
    """Record an accepted verification's selected function bodies for later repairs."""

    path = state.joinpath(*COMPOSED_BODY_LEDGER_RELATIVE)
    failure = error or (
        "current verification did not provide function bodies" if ledger is None else None
    )
    payload: bytes | None = None
    removed_stale = False
    removal_error: OSError | None = None
    with report_publication_lease(state):
        if (
            ledger is not None
            and os.path.lexists(path.parent)
            and (path.parent.is_symlink() or not path.parent.is_dir())
        ):
            failure = f"saved repair data directory is not a regular directory: {path.parent}"
        elif ledger is not None:
            try:
                payload = write_ledger(path, ledger)
            except OSError as exc:
                failure = str(exc)
            else:
                failure = None
        if failure is not None and os.path.lexists(path):
            try:
                if path.parent.is_symlink() or path.is_symlink() or not path.is_file():
                    raise OSError(f"saved repair data is not a regular file: {path}")
                path.unlink()
                removed_stale = True
            except OSError as exc:
                removal_error = exc
    if failure is not None:
        message = f"verified function bodies were not recorded: {failure}"
        if removed_stale:
            message += "; removed the older saved repair data"
        elif removal_error is not None:
            message += f"; older saved repair data could not be removed: {removal_error}"
        return LedgerPublication(path, "skipped", message)
    assert ledger is not None
    assert payload is not None
    functions = sum(len(target.functions) for target in ledger.targets.values())
    return LedgerPublication(
        path,
        "succeeded",
        f"recorded {functions} verified function bodies for later repairs: {path}",
        functions,
        payload,
    )


def execute_verify(
    request: VerifyRequest,
    progress: ExecutionProgress = NULL_EXECUTION_PROGRESS,
    *,
    workspace_observer: WorkspaceObserver | None = None,
) -> VerifyResult:
    """Verify from explicit application inputs without rendering a CLI result."""

    with _overlay_render_session() as overlay_session:
        return _execute_verify(
            request,
            progress,
            overlay_session=overlay_session,
            workspace_observer=workspace_observer,
        )


def _execute_verify(
    request: VerifyRequest,
    progress: ExecutionProgress,
    *,
    overlay_session: ClassicOverlayRenderSession,
    workspace_observer: WorkspaceObserver | None,
) -> VerifyResult:
    from reprobit.engine import (
        EngineRequest,
        ReportDestinations,
        ReproductionEngine,
    )
    from reprobit.execution import TargetOracle
    from reprobit.verify import seal_file_oracle

    root = project_root(os.fspath(request.project))
    with progress.activity("checking the project files", phase="validate"):
        bundle = load_project_tree(root, overlay_render_session=overlay_session)
    requested_policy = (
        request.policy if request.policy is not None else bundle.spec.authenticity.policy
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
        explicit_toolchain_root=request.execution.toolchain_root,
        backend=request.execution.backend,
        compiler_transport=request.execution.compiler_transport,
        resource_transport=request.execution.resource_transport,
    )
    state = state_root(root, bundle.spec)
    if request.report_directory:
        report_directory = safe_project_path(root, os.fspath(request.report_directory))
        report_json = report_directory / "report.json"
        report_html = report_directory / "report.html"
    else:
        report_json = state / "reports" / "report.json"
        report_html = state / "reports" / "report.html"
    if (request.action_receipt is None) != (request.action_nonce is None):
        raise CLIError("--action-receipt and --action-nonce must be supplied together")
    action_receipt = (
        request.action_receipt.expanduser().resolve(strict=False)
        if request.action_receipt is not None
        else None
    )
    report_outputs = [("JSON report", report_json), ("HTML report", report_html)]
    if action_receipt is not None:
        report_outputs.append(("action receipt", action_receipt))
    _check_report_outputs(root, bundle, report_outputs)
    arena = RunArena(
        state,
        kind="verify",
        keep=request.keep_workspace,
    )
    try:
        with arena:
            run_root = arena.path
            with progress.producer_activity(
                "building from scratch and checking the exact output"
            ) as report_progress:
                prepared = prepare_producer_graph_run(
                    request.execution,
                    bundle,
                    project_root=root,
                    session_root=run_root / "classic",
                    execution=execution,
                    progress=report_progress,
                    source_toolchain_report=request.source_toolchain_report,
                    overlay_render_session=overlay_session,
                )
                # The effective workspace is rendered; release the retained
                # indexes before the producers start.
                overlay_session.close()
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

                    oracle_targets = _quarantine_oracle_targets(bundle)
                    prepared.donors.bind_legacy_oracles(
                        {
                            oracle.target_id: bind_pe32_oracle(oracle.capability)
                            for oracle in oracles
                            if oracle.target_id in oracle_targets
                        }
                    )
                    engine_request = EngineRequest(
                        bundle=bundle,
                        build_plan=prepared.plan,
                        project_root=root,
                        run_root=run_root,
                        oracles=oracles,
                        jobs=request.execution.jobs,
                        cold=True,
                        reports=ReportDestinations(json=report_json, html=report_html),
                        evidence_providers=(prepared.evidence_provider,),
                        build_executor=prepared.executor,
                    )
                    result = ReproductionEngine().run(engine_request)
                    ledger, ledger_error = _composed_body_ledger(prepared.executor)
        if action_receipt is not None and request.action_nonce is not None:
            from reprobit.action_summary import publish_action_completion

            publish_action_completion(
                result.report,
                report_path=report_json,
                html_path=report_html,
                receipt_path=action_receipt,
                nonce=request.action_nonce,
            )
    except BaseException:
        if arena.path.is_dir() and workspace_observer is not None:
            workspace_observer("verification", arena.path, "failed")
        raise
    retained_workspace = arena.path if arena.path.is_dir() else None
    if retained_workspace is not None and workspace_observer is not None:
        workspace_observer("verification", retained_workspace, "succeeded")
    accepted = result.accepts(requested_policy)
    ledger_publication = (
        _publish_composed_body_ledger(state, ledger, ledger_error) if accepted else None
    )
    try:
        report_json_payload = result.report_payloads[report_json]
        report_html_payload = result.report_payloads[report_html]
    except KeyError as exc:
        raise CLIError(f"verification omitted its published report bytes: {exc.args[0]}") from exc
    return VerifyResult(
        project=root,
        engine=result,
        policy=requested_policy,
        report_json=report_json,
        report_html=report_html,
        report_json_payload=report_json_payload,
        report_html_payload=report_html_payload,
        ledger=ledger_publication,
        retained_workspace=retained_workspace,
    )


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


__all__ = [
    "NULL_EXECUTION_PROGRESS",
    "BuildRequest",
    "BuildResult",
    "ExecutionProgress",
    "NullExecutionProgress",
    "ProjectExecutionOptions",
    "RepairAnalysisOptions",
    "VerifyRequest",
    "VerifyResult",
    "command_build",
    "command_verify",
    "execute_build",
    "execute_verify",
    "execution_options_from_cli",
    "prepare_producer_graph_run",
]
