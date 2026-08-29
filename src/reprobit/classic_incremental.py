"""Non-certifying incremental execution for classic producer graphs.

Warm execution captures immutable physical authority, assembles explicit DAG
phases, and initializes the classic runtime only after the first cache miss.
Cold verification never imports this module.
"""

from __future__ import annotations

from pathlib import Path
from time import monotonic

from reprobit.backends import ExecutionBackend
from reprobit.classic_incremental_context import ClassicIncrementalResult
from reprobit.classic_incremental_execution import execute_classic_incremental_plan
from reprobit.classic_incremental_nodes import (
    add_producer_nodes,
    add_transform_nodes,
)
from reprobit.classic_incremental_planning import prepare_classic_incremental_plan
from reprobit.classic_incremental_targets import add_analysis_nodes, add_terminal_nodes
from reprobit.incremental import DeveloperAuthority
from reprobit.incremental_executor import IncrementalProgress


def execute_classic_incremental_build(
    authority: DeveloperAuthority,
    *,
    project_root: Path,
    session_root: Path,
    state_root: Path,
    toolchain_root: Path,
    backend: ExecutionBackend,
    jobs: int,
    compiler_transport: Path | None = None,
    resource_transport: Path | None = None,
    initialization_timeout: float = 600.0,
    compile_timeout: float = 600.0,
    link_timeout: float = 900.0,
    cleanup_timeout: float = 10.0,
    progress: IncrementalProgress | None = None,
) -> ClassicIncrementalResult:
    """Execute one current-worktree producer graph with conservative reuse."""

    plan = prepare_classic_incremental_plan(
        authority,
        started=monotonic(),
        project_root=project_root,
        session_root=session_root,
        state_root=state_root,
        toolchain_root=toolchain_root,
        backend=backend,
        jobs=jobs,
        compiler_transport=compiler_transport,
        resource_transport=resource_transport,
        initialization_timeout=initialization_timeout,
        compile_timeout=compile_timeout,
        link_timeout=link_timeout,
        cleanup_timeout=cleanup_timeout,
        progress=progress,
    )
    add_producer_nodes(plan)
    add_transform_nodes(plan)
    add_terminal_nodes(plan)
    add_analysis_nodes(plan)
    return execute_classic_incremental_plan(plan)


__all__ = ["execute_classic_incremental_build"]
