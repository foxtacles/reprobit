"""Human-first orchestration for importing an ordinary CMake project."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from reprobit.backends import NativeWindowsBackend, backend_for_host
from reprobit.cli_environment import resolve_classic_execution_inputs
from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import CLIError, project_root, resolve_program, safe_project_path
from reprobit.cmake_configure import configure_cmake_project
from reprobit.cmake_graph import record_cmake_graph
from reprobit.cmake_import import (
    CMakeScaffold,
    rollback_cmake_scaffold,
    scaffold_cmake_authority,
)
from reprobit.msvc42_provision import (
    ProvisionError,
    verify_msvc42_cmake_frontend,
)
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import ProducerGraphBuildAdapter
from reprobit.state import KeepWorkspace, RunArena
from reprobit.toolchains import MSVC_42, ClassicMSVCToolchain

_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


def _real_directory(value: str | os.PathLike[str], *, label: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise CLIError(f"{label} is not an existing real directory: {candidate}")
    return candidate.resolve(strict=True)


def _absolute_file(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise CLIError(f"execution transport is not a regular file: {resolved}")
    return resolved


def _import_state_root(root: Path, relative: str) -> Path:
    lexical = root.joinpath(*PurePosixPath(relative.replace("\\", "/")).parts)
    if lexical.is_symlink():
        raise CLIError(f"state directory is a symlink: {lexical}")
    state = safe_project_path(root, relative)
    state.mkdir(parents=True, exist_ok=True)
    return state


def _plain_directory(path: Path) -> bool:
    """Return whether ``path`` is one ordinary directory, not a redirect."""

    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not int(getattr(metadata, "st_reparse_tag", 0))
        and not (int(getattr(metadata, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT)
    )


@contextmanager
def _cmake_import_workspace(arena: RunArena, *, short: bool) -> Iterator[Path]:
    """Seat legacy NMake in a short real tree while state owns retention."""

    if not short:
        yield arena.path / "cmake"
        return

    workspace = Path(tempfile.mkdtemp(prefix="rbit-cmake-"))
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
            shutil.rmtree(workspace)
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


def command_cmake_import(args: argparse.Namespace, output: CLIOutput) -> int:
    """Scaffold, configure, and record one ordinary CMake project."""

    root = project_root(args.project)
    spec = load_project(root)
    if not isinstance(spec.build, ProducerGraphBuildAdapter):
        raise CLIError("CMake import requires a producer-graph project")
    backend = backend_for_host()
    execution = resolve_classic_execution_inputs(
        profile=spec.toolchain.profile,
        explicit_toolchain_root=args.toolchain_root,
        backend=backend,
        compiler_transport=args.compiler_transport,
        resource_transport=args.resource_transport,
    )
    toolchain_root = _real_directory(execution.toolchain_root, label="toolchain root")
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
                "bundle; provision it to a fresh destination with `rbit toolchain provision`"
            )
        try:
            verify_msvc42_cmake_frontend(toolchain_root)
        except ProvisionError as error:
            raise CLIError(
                "native CMake import refused a changed NMake frontend; "
                "provision the compiler to a fresh destination"
            ) from error

    cmake = Path(resolve_program(args.cmake, root))
    scaffold = CMakeScaffold({}, None)
    graph_path = safe_project_path(root, spec.layout.producer_graph)
    arena: RunArena | None = None
    try:
        with output.activity("preparing a reviewable CMake build plan", phase="import"):
            scaffold = scaffold_cmake_authority(root, spec, args.target)
            bundle = load_project_tree(root, include_producer_graph=False)
            installation.doctor(bundle.toolchain_lock).require_ok()
            if bundle.build_plan is None:
                raise CLIError("CMake import could not create or load its build plan")
        state = _import_state_root(root, spec.state_dir)
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
                    )
                with output.activity(
                    "recording the direct compiler and linker steps",
                    phase="graph-import",
                ):
                    graph_result = record_cmake_graph(
                        project_root=root,
                        configured_build_root=configured.configured_build_root,
                        effective_source_root=configured.effective_source_root,
                        expected_effective_source_digest=configured.effective_source_digest,
                        toolchain_root=toolchain_root,
                        target_plan=configured.target_plan,
                        directive_inputs=args.directive_input,
                        derive_translation_units=not bundle.build_plan.translation_units,
                    )
            output.emit(
                "producer_graph_extracted",
                f"committed {len(graph_result.graph.nodes)} direct producer(s) "
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
    next_command = human_command(("rbit", "build", root))
    output.emit(
        "cmake_imported",
        f"CMake import complete: {len(final.producer_graph.nodes)} build step(s) and "
        f"{len(final.build_plan.translation_units)} TU(s) recorded\nNext: {next_command}",
        build_plan=safe_project_path(root, spec.layout.build_plan),
        producer_graph=graph_path,
        scaffold_transaction_id=scaffold.transaction_id,
        nodes=len(final.producer_graph.nodes),
        translation_units=len(final.build_plan.translation_units),
        next_command=next_command,
    )
    return 0


__all__ = ["command_cmake_import"]
