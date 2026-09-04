"""Discarded compiler replays shared by cached and cold developer builds."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, cast

from reprobit.classic.arguments import validate_compile_arguments
from reprobit.classic_includes import MsvcSbrTrace, parse_msvc_sbr
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_environment import _run
from reprobit.classic_runtime_files import _secure_remove_regular
from reprobit.process import CancellationToken, CommandFailed, ProcessSupervisor
from reprobit.producer_graph import ProducerNode, ProducerRole, materialize_argument
from reprobit.schema import ProjectBundle

if TYPE_CHECKING:
    from reprobit.classic_runtime_producer import ClassicProducerExecution


def _erase_dependency_replay_arena(arena: Path, *, replay_root: Path) -> None:
    """Erase every regular discard output and its exact run-private arena."""

    arena = Path(os.path.abspath(arena))
    replay_root = Path(os.path.abspath(replay_root))
    if arena.parent != replay_root or arena.is_symlink() or not arena.is_dir():
        raise ClassicProjectError(f"classic dependency replay arena is redirected: {arena}")
    try:
        entries = tuple(arena.iterdir())
    except OSError as exc:
        raise ClassicProjectError(
            f"classic dependency replay arena cannot be enumerated: {arena}"
        ) from exc
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise ClassicProjectError(
                f"classic dependency replay produced a non-regular discard entry: {entry}"
            )
        _secure_remove_regular(entry)
    try:
        arena.rmdir()
    except OSError as exc:
        raise ClassicProjectError(
            f"classic dependency replay arena could not be erased: {arena}"
        ) from exc


@dataclass(frozen=True, slots=True)
class ClassicCompilerDependencyReplay:
    """Dependency-only result from a discarded `/Fr` compiler invocation."""

    trace: MsvcSbrTrace | None
    reason: str | None

    def __post_init__(self) -> None:
        if (self.trace is None) == (self.reason is None):
            raise ClassicProjectError("classic compiler replay requires exactly one result state")


def replay_compiler_dependencies(
    producer: ClassicProducerExecution,
    supervisor: ProcessSupervisor,
    node: ProducerNode,
    *,
    cancellation: CancellationToken,
) -> ClassicCompilerDependencyReplay:
    """Run and discard one `/Fr` invocation for developer dependency checks.

    This replay never supplies build artifacts or certifying provenance.
    """

    if node.role is not ProducerRole.COMPILER:
        raise ClassicProjectError("dependency replay requires a compiler node")
    replay_root = producer.build_root / ".reprobit-warm-replay"
    replay_root.mkdir(exist_ok=True)
    arena = replay_root / sha256(node.id.encode("utf-8")).hexdigest()[:20]
    arena.mkdir(exist_ok=False)
    try:
        object_path = arena / "discard.obj"
        pdb_path = arena / "discard.pdb"
        sbr_path = arena / "dependencies.sbr"
        object_logical = producer.logical_for_host_path(object_path)
        pdb_logical = producer.logical_for_host_path(pdb_path)
        sbr_logical = producer.logical_for_host_path(sbr_path)
        arguments: list[str] = []
        object_count = 0
        pdb_count = 0
        for argument in producer.node_arguments(node):
            folded = argument.casefold()
            if folded.startswith(("/fr", "-fr")):
                return ClassicCompilerDependencyReplay(
                    None, "committed compiler argv already contains /Fr"
                )
            if folded.startswith(("/fo", "-fo")):
                arguments.append(f"/Fo{object_logical}")
                object_count += 1
            elif folded.startswith(("/fd", "-fd")):
                arguments.append(f"/Fd{pdb_logical}")
                pdb_count += 1
            else:
                arguments.append(argument)
        if object_count != 1 or pdb_count != 1:
            return ClassicCompilerDependencyReplay(
                None, "compiler replay could not isolate exactly one OBJ/PDB pair"
            )
        arguments.append(f"/Fr{sbr_logical}")
        lane = producer.lane_pool.acquire()
        try:
            try:
                result, _spec = _run(
                    supervisor,
                    (str(producer.role_commands[ProducerRole.COMPILER]), *arguments),
                    cwd=producer.producer_cwd(lane, producer.build_root),
                    environment=lane.environment,
                    timeout=producer.compile_timeout,
                    log=(
                        producer.session_root / "logs" / "warm-dependency-replay" / f"{node.id}.log"
                    ),
                    cancellation=cancellation,
                    windows_lineage_planner=(lane.windows_lineage_planner),
                )
            except CommandFailed as exc:
                cancellation.raise_if_cancelled()
                return ClassicCompilerDependencyReplay(
                    None, f"discarded compiler replay failed: {exc}"
                )
        finally:
            producer.lane_pool.release(lane)
        if not result.succeeded:
            return ClassicCompilerDependencyReplay(
                None,
                f"discarded compiler replay returned {result.returncode}: {result.output_tail}",
            )
        try:
            actual_sbr = producer.compiler_companion_output(sbr_path)
            trace = parse_msvc_sbr(actual_sbr.read_bytes())
        except (OSError, ValueError) as exc:
            return ClassicCompilerDependencyReplay(
                None, f"discarded compiler replay trace is unusable: {exc}"
            )
        # The replay OBJ/PDB are deliberately neither registered nor
        # returned.  Their different bytes can never substitute for the
        # normal invocation.
        return ClassicCompilerDependencyReplay(trace, None)
    finally:
        _erase_dependency_replay_arena(arena, replay_root=replay_root)


def compiler_include_parameters(
    node: ProducerNode,
    *,
    bundle: ProjectBundle,
    compiler_logical: str,
    environment: Mapping[str, str],
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    arguments = tuple(
        materialize_argument(
            value,
            source_root=bundle.spec.paths.source,
            build_root=bundle.spec.paths.build,
            toolchain_root=bundle.spec.paths.toolchain,
        )
        for value in node.arguments
    )
    parsed = validate_compile_arguments([compiler_logical, *arguments])
    source = cast(str, parsed["source_token"])
    include_directories = tuple(
        cast(tuple[int, str, bool], item)[1]
        for item in cast(Sequence[object], parsed["include_paths"])
    )
    force_includes = tuple(
        cast(tuple[int, str, bool], item)[1]
        for item in cast(Sequence[object], parsed["force_includes"])
    )
    include_environment = tuple(item for item in environment["INCLUDE"].split(";") if item)
    return source, bundle.spec.paths.build, include_directories, include_environment, force_includes
