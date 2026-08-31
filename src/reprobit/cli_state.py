"""CLI commands for local run workspaces and the reusable cache."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

from reprobit.cli_output import CLIOutput, count_phrase, human_command
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
    from reprobit.incremental import (
        PRODUCER_CACHE_IMPLEMENTATION,
        PRODUCER_CACHE_IMPLEMENTATION_FAMILY,
    )

    root = project_root(args.project)
    spec = load_project(root)
    state = state_path(root, spec)
    with output.activity("inspecting local ReproBit state", phase="state"):
        status = StateStore(state, create=False).status(
            cache_implementation=PRODUCER_CACHE_IMPLEMENTATION,
            cache_implementation_family=PRODUCER_CACHE_IMPLEMENTATION_FAMILY,
        )
    active = sum(item.active for item in status.runs)
    retained = len(status.runs) - active
    lines = [
        f"state: {human_bytes(status.total_bytes)} in {count_phrase(status.total_files, 'file')}",
        f"  runs: {len(status.runs)} ({active} active, {retained} retained), "
        f"{human_bytes(status.run_bytes)}",
        f"  cache: {count_phrase(status.cache_records, 'record')}, "
        f"{count_phrase(status.cache_blobs, 'blob')}, "
        f"{human_bytes(status.cache_bytes)}",
        f"  cache leases: {status.cache_active_leases} active, {status.cache_stale_leases} stale",
        f"  reports: {status.report_files} managed "
        f"{'file' if status.report_files == 1 else 'files'}, "
        f"{human_bytes(status.report_bytes)}",
    ]
    if status.cache_current_records or status.cache_obsolete_records:
        lines.insert(
            4,
            "  incremental build records: "
            f"{status.cache_current_records} current, "
            f"{status.cache_obsolete_records} obsolete",
        )
    if status.cache_obsolete_records:
        lines.insert(
            5,
            "  preview workspace + obsolete cache cleanup: "
            f"{human_command(('rbit', 'clean', root, '--obsolete-cache', '--preview'))}",
        )
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
        cache_current_records=status.cache_current_records,
        cache_obsolete_records=status.cache_obsolete_records,
        report_bytes=status.report_bytes,
        report_files=status.report_files,
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
    from reprobit.incremental import (
        PRODUCER_CACHE_IMPLEMENTATION,
        PRODUCER_CACHE_IMPLEMENTATION_FAMILY,
    )

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
            "removing inactive build workspaces and selected local data"
            if args.cache or args.obsolete_cache or args.reports
            else "removing inactive build workspaces"
        )
    )
    with output.activity(description, phase="cleanup"):
        result = store.gc(
            older_than_seconds=age_seconds,
            dry_run=args.preview,
            include_cache=args.cache,
            include_reports=args.reports,
            obsolete_cache_implementation=(
                PRODUCER_CACHE_IMPLEMENTATION if args.obsolete_cache else None
            ),
            obsolete_cache_implementation_family=(
                PRODUCER_CACHE_IMPLEMENTATION_FAMILY if args.obsolete_cache else None
            ),
        )
    if args.preview:
        next_argv: list[str | Path] = ["rbit", "clean", root]
        if args.older_than_hours is not None:
            next_argv.extend(("--older-than-hours", f"{age_hours:g}"))
        if args.cache:
            next_argv.append("--cache")
        if args.obsolete_cache:
            next_argv.append("--obsolete-cache")
        if args.reports:
            next_argv.append("--reports")
        has_selection = bool(
            result.removed
            or result.cache_removed_records
            or result.cache_removed_blobs
            or result.reports_removed
        )
        next_command = human_command(next_argv) if has_selection else None
        if not args.cache and not args.obsolete_cache:
            cache_summary = "The reusable incremental cache will be kept."
        elif result.cache_active_leases:
            build_verb = "is" if result.cache_active_leases == 1 else "are"
            cache_summary = (
                "Cache cleanup is currently skipped because "
                f"{count_phrase(result.cache_active_leases, 'active build')} "
                f"{build_verb} using it."
            )
        elif args.obsolete_cache:
            cache_summary = (
                "The selection includes "
                f"{count_phrase(result.cache_removed_records, 'obsolete cache record')} and "
                f"{count_phrase(result.cache_removed_blobs, 'unreferenced blob')}; "
                "the current cache will be kept"
                + (
                    ", along with "
                    f"{count_phrase(result.cache_skipped_recent_records, 'recent obsolete record')}"
                    "."
                    if result.cache_skipped_recent_records
                    else "."
                )
            )
        else:
            cache_summary = (
                "The selection includes "
                f"{count_phrase(result.cache_removed_records, 'cache record')} "
                f"and {count_phrase(result.cache_removed_blobs, 'unreferenced blob')}; "
                f"{count_phrase(result.cache_skipped_recent_records, 'recent cache record')} "
                "will be kept."
            )
        report_summary = (
            f"The selection includes {result.report_files} managed report "
            f"{'file' if result.report_files == 1 else 'files'}."
            if args.reports
            else "Saved reports will be kept."
        )
        next_step = (
            f"Run {next_command} to perform this cleanup."
            if next_command is not None
            else "Nothing to remove."
        )
        output.emit(
            "cleanup_preview",
            f"Clean preview: {human_bytes(result.reclaimed_bytes)} can be freed. "
            f"Selected {count_phrase(len(result.removed), 'inactive workspace')}. "
            f"{cache_summary} "
            f"{report_summary} "
            f"{next_step}",
            candidates=result.removed,
            cache_requested=args.cache or args.obsolete_cache,
            obsolete_cache_requested=args.obsolete_cache,
            cache_records=result.cache_removed_records,
            cache_blobs=result.cache_removed_blobs,
            active_cache_leases=result.cache_active_leases,
            reports_requested=args.reports,
            report_files=result.report_files,
            report_bytes=result.report_bytes,
            reports=result.reports_removed,
            reclaimable_bytes=result.reclaimed_bytes,
            older_than_hours=age_hours,
            next_command=next_command,
            next_argv=next_argv if next_command is not None else (),
        )
        return 0
    if not args.cache and not args.obsolete_cache:
        cache_summary = "The reusable incremental cache was kept."
    elif result.cache_active_leases:
        build_verb = "is" if result.cache_active_leases == 1 else "are"
        cache_summary = (
            "Cache cleanup was skipped because "
            f"{count_phrase(result.cache_active_leases, 'active build')} "
            f"{build_verb} using it."
        )
    elif args.obsolete_cache:
        cache_summary = (
            f"Removed {count_phrase(result.cache_removed_records, 'obsolete cache record')} "
            f"and {count_phrase(result.cache_removed_blobs, 'unreferenced blob')}; "
            "kept the current cache"
            + (
                " and "
                f"{count_phrase(result.cache_skipped_recent_records, 'recent obsolete record')}"
                "."
                if result.cache_skipped_recent_records
                else "."
            )
        )
    else:
        cache_summary = (
            f"Removed {count_phrase(result.cache_removed_records, 'cache record')} and "
            f"{count_phrase(result.cache_removed_blobs, 'unreferenced blob')}; kept "
            f"{count_phrase(result.cache_skipped_recent_records, 'recent cache record')}."
        )
    report_summary = (
        f"Removed {result.report_files} managed report "
        f"{'file' if result.report_files == 1 else 'files'}."
        if args.reports
        else "Saved reports were kept."
    )
    output.emit(
        "cleanup",
        f"Freed {human_bytes(result.reclaimed_bytes)}. "
        f"Removed {count_phrase(len(result.removed), 'inactive workspace')}. "
        f"{cache_summary} "
        f"{report_summary} "
        f"Kept {count_phrase(len(result.skipped_active), 'active workspace')} and "
        f"{count_phrase(len(result.skipped_recent), 'recent workspace')}.",
        removed=result.removed,
        reclaimed_bytes=result.reclaimed_bytes,
        skipped_active=result.skipped_active,
        skipped_recent=result.skipped_recent,
        cache_requested=args.cache or args.obsolete_cache,
        obsolete_cache_requested=args.obsolete_cache,
        cache_records=result.cache_removed_records,
        cache_blobs=result.cache_removed_blobs,
        active_cache_leases=result.cache_active_leases,
        skipped_recent_cache_records=result.cache_skipped_recent_records,
        reports_requested=args.reports,
        report_files=result.report_files,
        report_bytes=result.report_bytes,
        reports=result.reports_removed,
        older_than_hours=age_hours,
    )
    return 0


__all__ = ["command_clean", "command_state_status", "state_path", "state_root"]
