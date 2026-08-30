"""CLI commands for local run workspaces and the reusable cache."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import CLIError, project_root, safe_project_path
from reprobit.project_loader import load_project
from reprobit.schema import ProjectSpec
from reprobit.state import StateStore, human_bytes


def state_path(root: Path, spec: ProjectSpec) -> Path:
    """Resolve an existing or prospective project state directory safely."""

    lexical = root.joinpath(*PurePosixPath(spec.state_dir.replace("\\", "/")).parts)
    if lexical.is_symlink():
        raise CLIError(f"state directory is a symlink: {lexical}")
    return safe_project_path(root, spec.state_dir)


def state_root(root: Path, spec: ProjectSpec) -> Path:
    """Resolve and create the project state directory."""

    state = state_path(root, spec)
    state.mkdir(parents=True, exist_ok=True)
    return state


def command_state_status(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    spec = load_project(root)
    state = state_path(root, spec)
    with output.activity("inspecting local ReproBit state", phase="state"):
        status = StateStore(state, create=False).status()
    active = sum(item.active for item in status.runs)
    retained = len(status.runs) - active
    lines = [
        f"state: {human_bytes(status.total_bytes)} in {status.total_files} file(s)",
        f"  runs: {len(status.runs)} ({active} active, {retained} retained), "
        f"{human_bytes(status.run_bytes)}",
        f"  cache: {status.cache_records} record(s), {status.cache_blobs} blob(s), "
        f"{human_bytes(status.cache_bytes)}",
        f"  cache leases: {status.cache_active_leases} active, {status.cache_stale_leases} stale",
    ]
    output.emit(
        "state_status",
        "\n".join(lines),
        root=status.root,
        total_bytes=status.total_bytes,
        total_files=status.total_files,
        run_bytes=status.run_bytes,
        run_files=status.run_files,
        cache_bytes=status.cache_bytes,
        cache_files=status.cache_files,
        cache_records=status.cache_records,
        cache_blobs=status.cache_blobs,
        cache_active_leases=status.cache_active_leases,
        cache_stale_leases=status.cache_stale_leases,
        runs=[
            {
                "path": item.path,
                "kind": item.kind,
                "active": item.active,
                "outcome": item.outcome,
                "bytes": item.bytes,
                "files": item.files,
                "modified_ns": item.modified_ns,
            }
            for item in status.runs
        ],
    )
    return 0


def command_clean(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    spec = load_project(root)
    state = state_path(root, spec)
    age_hours = args.older_than_hours if args.older_than_hours is not None else 0.0
    age_seconds = age_hours * 3600.0
    store = StateStore(state, create=False)
    description = (
        "checking how much local build state can be removed"
        if args.preview
        else (
            "removing inactive build workspaces and selected cache data"
            if args.cache
            else "removing inactive build workspaces"
        )
    )
    with output.activity(description, phase="cleanup"):
        result = store.gc(
            older_than_seconds=age_seconds,
            dry_run=args.preview,
            include_cache=args.cache,
        )
    if args.preview:
        next_argv: list[str | Path] = ["rbit", "clean", root]
        if args.older_than_hours is not None:
            next_argv.extend(("--older-than-hours", f"{age_hours:g}"))
        if args.cache:
            next_argv.append("--cache")
        next_command = human_command(next_argv)
        if not args.cache:
            cache_summary = "The reusable incremental cache will be kept."
        elif result.cache_active_leases:
            cache_summary = (
                "Cache cleanup is currently skipped because "
                f"{result.cache_active_leases} active build(s) are using it."
            )
        else:
            cache_summary = (
                f"The selection includes {result.cache_removed_records} cache record(s) "
                f"and {result.cache_removed_blobs} unreferenced blob(s); "
                f"{result.cache_skipped_recent_records} recent cache record(s) will be kept."
            )
        output.emit(
            "cleanup_preview",
            f"Clean preview: {human_bytes(result.reclaimed_bytes)} can be freed. "
            f"Selected {len(result.removed)} inactive workspace(s). {cache_summary} "
            f"Run {next_command} to perform this cleanup.",
            candidates=result.removed,
            cache_requested=args.cache,
            cache_records=result.cache_removed_records,
            cache_blobs=result.cache_removed_blobs,
            active_cache_leases=result.cache_active_leases,
            reclaimable_bytes=result.reclaimed_bytes,
            older_than_hours=age_hours,
            next_command=next_command,
            next_argv=next_argv,
        )
        return 0
    if not args.cache:
        cache_summary = "The reusable incremental cache was kept."
    elif result.cache_active_leases:
        cache_summary = (
            "Cache cleanup was skipped because "
            f"{result.cache_active_leases} active build(s) are using it."
        )
    else:
        cache_summary = (
            f"Removed {result.cache_removed_records} cache record(s) and "
            f"{result.cache_removed_blobs} unreferenced blob(s); kept "
            f"{result.cache_skipped_recent_records} recent cache record(s)."
        )
    output.emit(
        "cleanup",
        f"Freed {human_bytes(result.reclaimed_bytes)}. "
        f"Removed {len(result.removed)} inactive workspace(s). {cache_summary} "
        f"Kept {len(result.skipped_active)} active and "
        f"{len(result.skipped_recent)} recent workspace(s).",
        removed=result.removed,
        reclaimed_bytes=result.reclaimed_bytes,
        skipped_active=result.skipped_active,
        skipped_recent=result.skipped_recent,
        cache_requested=args.cache,
        cache_records=result.cache_removed_records,
        cache_blobs=result.cache_removed_blobs,
        active_cache_leases=result.cache_active_leases,
        skipped_recent_cache_records=result.cache_skipped_recent_records,
        older_than_hours=age_hours,
    )
    return 0


__all__ = ["command_clean", "command_state_status", "state_path", "state_root"]
