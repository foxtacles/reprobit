"""Human-first orchestration for importing an ordinary CMake project."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from reprobit.backends import ExecutionBackend, NativeWindowsBackend, backend_for_host
from reprobit.cli_environment import resolve_classic_execution_inputs
from reprobit.cli_output import CLIOutput, NextStep, count_phrase, next_step_fields
from reprobit.cli_paths import (
    CLIError,
    project_root,
    real_directory,
    resolve_program,
    safe_project_path,
)
from reprobit.cli_state import state_root
from reprobit.cmake_configure import configure_cmake_project
from reprobit.cmake_graph import CMakeGraphResult, record_cmake_graph
from reprobit.cmake_import import (
    CMakeScaffold,
    rollback_cmake_scaffold,
    scaffold_cmake_authority,
)
from reprobit.cmake_refresh import (
    CMakeRefreshResult,
    capture_cmake_refresh_candidate,
    capture_cmake_refresh_snapshot,
    collect_cmake_refresh_evidence,
    prepare_cmake_refresh_authority,
    publish_cmake_refresh,
    restore_compatible_translation_unit_authority,
    stage_cmake_refresh,
)
from reprobit.msvc42_provision import (
    ProvisionError,
    verify_msvc42_cmake_frontend,
)
from reprobit.producer_graph import CMakeImportRecipe, read_producer_graph
from reprobit.project_execution import (
    ProjectExecutionOptions,
    VerifyRequest,
    VerifyResult,
    execute_verify,
)
from reprobit.project_loader import load_project, load_project_tree
from reprobit.project_readiness import inspect_project_readiness
from reprobit.schema import ProducerGraphBuildAdapter, ProjectBundle, SchemaError
from reprobit.secure_path_contracts import is_redirected_metadata
from reprobit.source_authority import SourceInputMismatch
from reprobit.source_lock_workflow import (
    apply_source_lock,
    cmake_reimport_guidance,
    plan_source_lock,
)
from reprobit.state import KeepWorkspace, RunArena
from reprobit.toolchains import (
    MSVC_42,
    ClassicMSVCToolchain,
    ToolchainDoctorReport,
    validate_toolchain_installation,
)


def _configure_and_record(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    root: Path,
    bundle: ProjectBundle,
    workspace: Path,
    toolchain_root: Path,
    installation: ClassicMSVCToolchain,
    cmake: Path,
    compiler_transport: Path,
    resource_transport: Path,
    generator: str,
    make_program: Path | None,
    derive_translation_units: bool,
) -> CMakeGraphResult:
    with output.activity("configuring the CMake project", phase="configure"):
        configured = configure_cmake_project(
            bundle,
            project_root=root,
            workspace_root=workspace,
            toolchain_root=toolchain_root,
            cmake=cmake,
            compiler_transport=_absolute_file(compiler_transport),
            resource_transport=_absolute_file(resource_transport),
            configuration=args.configuration,
            timeout_seconds=args.timeout,
            defer_project_plan=True,
            generator=generator,
            make_program=make_program,
            cmake_defines=args.cmake_define,
        )
    # CMake ran outside ReproBit's process. Authenticate the source installation
    # again before its recorded commands become project authority.
    source_toolchain_report = installation.doctor(bundle.toolchain_lock)
    source_toolchain_report.require_ok()
    with output.activity(
        "recording the direct compiler and linker steps",
        phase="graph-import",
    ):
        result = record_cmake_graph(
            project_root=root,
            configured_build_root=configured.configured_build_root,
            effective_source_root=configured.effective_source_root,
            expected_effective_source_digest=configured.effective_source_digest,
            toolchain_root=toolchain_root,
            target_plan=configured.target_plan,
            cmake=args.cmake,
            configuration=args.configuration,
            timeout_seconds=args.timeout,
            cmake_defines=args.cmake_define,
            directive_inputs=args.directive_input,
            derive_translation_units=derive_translation_units,
        )
    return replace(result, source_toolchain_report=source_toolchain_report)


def _absolute_file(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise CLIError(f"execution transport is not a regular file: {resolved}")
    return resolved


def _resolve_import_recipe(args: argparse.Namespace, *, root: Path, refresh: bool) -> None:
    """Fill omitted graph-affecting options from the recorded import recipe."""

    if args.clear_cmake_defines and not refresh:
        raise CLIError("--clear-cmake-defines requires --refresh")
    if args.clear_directive_inputs and not refresh:
        raise CLIError("--clear-directive-inputs requires --refresh")
    saved: CMakeImportRecipe | None = CMakeImportRecipe()
    if refresh:
        spec = load_project(root)
        graph_path = safe_project_path(root, spec.layout.producer_graph)
        saved = read_producer_graph(graph_path).import_recipe
        if saved is None:
            raise CLIError(cmake_reimport_guidance(root))
    assert saved is not None
    args.cmake = saved.cmake if args.cmake is None else args.cmake
    args.configuration = saved.configuration if args.configuration is None else args.configuration
    args.timeout = saved.timeout_seconds if args.timeout is None else args.timeout
    args.cmake_define = (
        []
        if args.clear_cmake_defines
        else list(saved.cmake_defines if args.cmake_define is None else args.cmake_define)
    )
    args.directive_input = (
        []
        if args.clear_directive_inputs
        else list(saved.directive_inputs if args.directive_input is None else args.directive_input)
    )


def _plain_directory(path: Path) -> bool:
    """Return whether ``path`` is one ordinary directory, not a redirect."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not is_redirected_metadata(metadata)


@contextmanager
def _cmake_import_workspace(arena: RunArena, *, short: bool) -> Iterator[Path]:
    """Seat legacy NMake in a short real tree while state owns retention."""

    if not short:
        yield arena.path / "cmake"
        return

    workspace = arena.create_cmake_workspace()
    if not workspace.is_absolute() or not _plain_directory(workspace):
        raise CLIError(f"temporary CMake workspace is not a real directory: {workspace}")
    succeeded = False
    try:
        yield workspace
        succeeded = True
    finally:
        active_error = sys.exception()
        cleanup_errors: list[BaseException] = []
        retain = arena.keep is KeepWorkspace.ALWAYS or (
            arena.keep is KeepWorkspace.ON_FAILURE and not succeeded
        )
        if retain:
            try:
                if not _plain_directory(workspace):
                    raise CLIError("temporary CMake workspace changed type before retention")
                shutil.copytree(workspace, arena.path / "cmake", symlinks=True)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            if not _plain_directory(workspace):
                raise CLIError("temporary CMake workspace changed type before cleanup")
            arena.remove_cmake_workspace(workspace)
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            if active_error is not None:
                for cleanup_error in cleanup_errors:
                    active_error.add_note(
                        f"temporary CMake workspace cleanup failed: {cleanup_error}"
                    )
            else:
                failure = CLIError("temporary CMake workspace cleanup failed")
                for cleanup_error in cleanup_errors:
                    failure.add_note(str(cleanup_error))
                raise failure


def _verify_refreshed_project(
    root: Path,
    output: CLIOutput,
    *,
    jobs: int,
    backend: ExecutionBackend,
    toolchain_root: Path,
    compiler_transport: Path,
    resource_transport: Path,
    source_toolchain_report: ToolchainDoctorReport | None = None,
) -> VerifyResult:
    verified = execute_verify(
        VerifyRequest(
            project=root,
            execution=ProjectExecutionOptions(
                jobs=jobs,
                backend=backend,
                toolchain_root=toolchain_root,
                compiler_transport=compiler_transport,
                resource_transport=resource_transport,
            ),
            keep_workspace=KeepWorkspace.NEVER,
            source_toolchain_report=source_toolchain_report,
        ),
        output,
    )
    if not verified.accepted:
        raise CLIError("the refreshed CMake build did not reproduce every reference exactly")
    return verified


def _command_cmake_refresh(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    root: Path,
    toolchain_root: Path,
    installation: ClassicMSVCToolchain,
    toolchain_report: ToolchainDoctorReport | None,
    jobs: int,
    backend: ExecutionBackend,
    cmake: Path,
    compiler_transport: Path,
    resource_transport: Path,
    generator: str,
    make_program: Path | None,
) -> int:
    if args.target:
        raise CLIError("--target is only used by the first CMake import")

    source_plan = plan_source_lock(
        root,
        args.path,
        output,
        reconcile_translation_units=True,
    )
    snapshot = capture_cmake_refresh_snapshot(source_plan)
    staged = stage_cmake_refresh(snapshot, keep=KeepWorkspace(args.keep_workspace))
    published = False
    cleanup_warning: str | None = None
    graph_result: CMakeGraphResult | None = None
    refreshed: CMakeRefreshResult | None = None
    try:
        with staged as staged_root:
            staged_source_plan = plan_source_lock(
                staged_root,
                tuple(entry.path for entry in source_plan.document.entries),
                output,
                seal=True,
                reconcile_translation_units=True,
            )
            apply_source_lock(
                staged_source_plan,
                invalidate_producer_graph=True,
                reconcile_translation_units=True,
                replace_producer_graph=True,
            )
            saved_units = prepare_cmake_refresh_authority(staged_root)
            bundle = load_project_tree(staged_root, include_producer_graph=False)
            validate_toolchain_installation(
                installation,
                bundle.toolchain_lock,
                previous=toolchain_report,
            ).require_ok()
            with _cmake_import_workspace(
                staged.arena,
                short=generator == "NMake Makefiles",
            ) as workspace:
                graph_result = _configure_and_record(
                    args,
                    output,
                    root=staged_root,
                    bundle=bundle,
                    workspace=workspace,
                    toolchain_root=toolchain_root,
                    installation=installation,
                    cmake=cmake,
                    compiler_transport=compiler_transport,
                    resource_transport=resource_transport,
                    generator=generator,
                    make_program=make_program,
                    derive_translation_units=True,
                )
                if graph_result.skipped_translation_units:
                    raise CLIError(
                        "CMake refresh found compiler steps that do not map to one project "
                        "source and target"
                    )
                (
                    preserved,
                    reset,
                    added,
                    retired,
                ) = restore_compatible_translation_unit_authority(staged_root, saved_units)
                candidate = capture_cmake_refresh_candidate(
                    snapshot,
                    staged_root,
                    saved_translation_units=saved_units,
                )
                with output.activity(
                    "proving the refreshed build from scratch",
                    phase="verify",
                ):
                    verified = _verify_refreshed_project(
                        staged_root,
                        output,
                        jobs=jobs,
                        backend=backend,
                        toolchain_root=toolchain_root,
                        compiler_transport=compiler_transport,
                        resource_transport=resource_transport,
                        source_toolchain_report=graph_result.source_toolchain_report,
                    )
                evidence = collect_cmake_refresh_evidence(
                    snapshot,
                    staged_root,
                    candidate=candidate,
                    verified=verified,
                )
                refreshed = publish_cmake_refresh(
                    snapshot,
                    candidate=candidate,
                    evidence=evidence,
                    preserved_translation_units=preserved,
                    reset_translation_units=reset,
                    added_translation_units=added,
                    retired_translation_units=retired,
                )
                published = True
                cleanup_warning = refreshed.transaction.cleanup_warning
    except BaseException as error:
        if published:
            workspace_warning = (
                "private workspace cleanup was interrupted"
                if isinstance(error, KeyboardInterrupt)
                else "private workspace cleanup failed: "
                + (" ".join(str(error).split()) or type(error).__name__)
            )
            cleanup_warning = "; ".join(
                warning for warning in (cleanup_warning, workspace_warning) if warning
            )
        else:
            if staged.retained_path.is_dir():
                output.emit(
                    "workspace_retained",
                    f"retained failed CMake refresh workspace: {staged.retained_path}",
                    path=staged.retained_path,
                    outcome="failed",
                    diagnostic=True,
                )
            raise

    if staged.retained_path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful CMake refresh workspace: {staged.retained_path}",
            path=staged.retained_path,
            outcome="succeeded",
            diagnostic=True,
        )
    assert published and graph_result is not None and refreshed is not None
    message = (
        "CMake refresh complete and verified from scratch: "
        f"{count_phrase(refreshed.preserved_translation_units, 'TU')} kept, "
        f"{refreshed.reset_translation_units} reset, "
        f"{refreshed.added_translation_units} added, "
        f"{refreshed.retired_translation_units} retired"
        f"\nReport: {refreshed.report_html}"
    )
    if cleanup_warning is not None:
        message += f"\nWarning: {cleanup_warning}"
    output.emit(
        "cmake_refreshed",
        message,
        nodes=len(graph_result.graph.nodes),
        preserved_translation_units=refreshed.preserved_translation_units,
        reset_translation_units=refreshed.reset_translation_units,
        added_translation_units=refreshed.added_translation_units,
        retired_translation_units=refreshed.retired_translation_units,
        source_manifest=snapshot.spec.layout.source_manifest,
        build_plan=snapshot.spec.layout.build_plan,
        producer_graph=snapshot.spec.layout.producer_graph,
        transaction_id=refreshed.transaction.transaction_id,
        cold_verified=True,
        outputs=refreshed.outputs,
        report_json=refreshed.report_json,
        report_html=refreshed.report_html,
        cleanup_warning=cleanup_warning,
        **next_step_fields(None),
    )
    return 0


def command_cmake_import(args: argparse.Namespace, output: CLIOutput) -> int:
    """Scaffold, configure, and record one ordinary CMake project."""

    root = project_root(args.project)
    if args.path and not args.refresh:
        raise CLIError("--path requires --refresh")
    if args.refresh and args.target:
        raise CLIError("--target is only used by the first CMake import")
    spec = load_project(root)
    if not isinstance(spec.build, ProducerGraphBuildAdapter):
        raise CLIError("CMake import requires a producer-graph project")
    _resolve_import_recipe(args, root=root, refresh=args.refresh)
    readiness = inspect_project_readiness(
        root,
        check_local_environment=True,
        local_toolchain_root=args.toolchain_root,
    )
    import_prerequisites = {
        "local_toolchain",
        "toolchain_lock",
        "references",
    }
    if not args.refresh:
        import_prerequisites.add("source_manifest")
    blocker = next(
        (item for item in readiness.items if item.id in import_prerequisites and not item.ready),
        None,
    )
    if blocker is not None:
        blocker_guidance = blocker.next_command or blocker.detail
        raise CLIError(
            "CMake import is not ready: "
            f"{blocker.label}: {blocker.detail}\nNext: {blocker_guidance}"
        )
    backend = backend_for_host()
    execution = resolve_classic_execution_inputs(
        profile=spec.toolchain.profile,
        explicit_toolchain_root=args.toolchain_root,
        backend=backend,
        compiler_transport=args.compiler_transport,
        resource_transport=args.resource_transport,
    )
    toolchain_root = real_directory(execution.toolchain_root, label="toolchain root")
    installation = ClassicMSVCToolchain(spec.toolchain.profile, toolchain_root)
    compiler_transport = execution.compiler_transport
    resource_transport = execution.resource_transport
    if isinstance(backend, NativeWindowsBackend) and compiler_transport is None:
        compiler_transport = installation.host_path(installation.profile.compiler)
        resource_transport = installation.host_path(installation.profile.resource_compiler)
    if compiler_transport is None or resource_transport is None:
        raise CLIError("compiler and resource transports could not be resolved")

    generator = "Unix Makefiles"
    make_program: Path | None = None
    if isinstance(backend, NativeWindowsBackend):
        if spec.toolchain.profile != MSVC_42:
            raise CLIError(
                "native CMake import currently supports authenticated NMake only "
                "for the msvc_4_2 profile"
            )
        generator = "NMake Makefiles"
        make_program = installation.host_path("bin/NMAKE.EXE")
        message_file = installation.host_path("bin/NMAKE.ERR")
        if any(path.is_symlink() or not path.is_file() for path in (make_program, message_file)):
            raise CLIError(
                "native CMake import needs NMAKE from the current authenticated compiler "
                "bundle; provision it to a fresh destination with rbit toolchain provision"
            )
        try:
            verify_msvc42_cmake_frontend(toolchain_root)
        except ProvisionError as error:
            raise CLIError(
                "native CMake import refused a changed NMake frontend; "
                "provision the compiler to a fresh destination"
            ) from error

    cmake = Path(resolve_program(args.cmake, root))
    if args.refresh:
        return _command_cmake_refresh(
            args,
            output,
            root=root,
            toolchain_root=toolchain_root,
            installation=installation,
            toolchain_report=readiness.toolchain_report,
            jobs=args.jobs,
            backend=backend,
            cmake=cmake,
            compiler_transport=compiler_transport,
            resource_transport=resource_transport,
            generator=generator,
            make_program=make_program,
        )
    scaffold = CMakeScaffold({}, None)
    graph_path = safe_project_path(root, spec.layout.producer_graph)
    arena: RunArena | None = None
    try:
        with output.activity("preparing a reviewable CMake build plan", phase="import"):
            scaffold = scaffold_cmake_authority(root, spec, args.target)
            try:
                bundle = load_project_tree(root, include_producer_graph=False)
            except SchemaError as error:
                if scaffold.transaction_id is not None and isinstance(
                    error.__cause__, SourceInputMismatch
                ):
                    next_step = NextStep(("rbit", "source", "preview", root))
                    raise CLIError(
                        "Source inputs changed after they were locked; review and lock them "
                        f"again before the first CMake import. {error.__cause__.detail}\n"
                        f"Next: {next_step.command}"
                    ) from error
                raise
            validate_toolchain_installation(
                installation,
                bundle.toolchain_lock,
                previous=readiness.toolchain_report,
            ).require_ok()
            if bundle.build_plan is None:
                raise CLIError("CMake import could not create or load its build plan")
        state = state_root(root, spec)
        arena = RunArena(
            state,
            kind="import",
            keep=KeepWorkspace(args.keep_workspace),
        )
        with arena:
            with _cmake_import_workspace(
                arena,
                short=generator == "NMake Makefiles",
            ) as workspace:
                graph_result = _configure_and_record(
                    args,
                    output,
                    root=root,
                    bundle=bundle,
                    workspace=workspace,
                    toolchain_root=toolchain_root,
                    installation=installation,
                    cmake=cmake,
                    compiler_transport=compiler_transport,
                    resource_transport=resource_transport,
                    generator=generator,
                    make_program=make_program,
                    derive_translation_units=not bundle.build_plan.translation_units,
                )
            output.emit(
                "producer_graph_extracted",
                f"committed {count_phrase(len(graph_result.graph.nodes), 'direct producer')} "
                f"to {graph_result.output}",
                output=graph_result.output,
                extractor=graph_result.graph.extractor,
                nodes=len(graph_result.graph.nodes),
                roles=graph_result.role_counts,
                graph_digest=graph_result.graph_digest.value,
                transaction_id=graph_result.transaction_id,
                translation_units=graph_result.translation_units,
                skipped_translation_units=graph_result.skipped_translation_units,
                certification_runtime="direct-locked-producers",
            )
    except BaseException as error:
        if arena is not None and arena.path.is_dir():
            output.emit(
                "workspace_retained",
                f"retained failed CMake import workspace: {arena.path}",
                path=arena.path,
                outcome="failed",
                diagnostic=True,
            )
        if scaffold.files and not os.path.lexists(graph_path):
            try:
                rollback_cmake_scaffold(root, scaffold)
            except Exception as rollback_error:
                error.add_note(f"CMake scaffold rollback also failed: {rollback_error}")
        raise

    if arena is not None and arena.path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful CMake import workspace: {arena.path}",
            path=arena.path,
            outcome="succeeded",
            diagnostic=True,
        )

    final = load_project_tree(root)
    assert final.producer_graph is not None
    assert final.build_plan is not None
    next_step = NextStep(("rbit", "build", root))
    output.emit(
        "cmake_imported",
        "CMake import complete: "
        f"{count_phrase(len(final.producer_graph.nodes), 'build step')} and "
        f"{count_phrase(len(final.build_plan.translation_units), 'TU')} recorded"
        f"\nNext: {next_step.command}",
        build_plan=safe_project_path(root, spec.layout.build_plan),
        producer_graph=graph_path,
        scaffold_transaction_id=scaffold.transaction_id,
        nodes=len(final.producer_graph.nodes),
        translation_units=len(final.build_plan.translation_units),
        **next_step.fields(),
    )
    return 0


__all__ = ["command_cmake_import"]
