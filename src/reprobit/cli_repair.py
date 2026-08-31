"""One-command repair of deterministic source fallout with exact verification."""

from __future__ import annotations

import argparse
from pathlib import Path

from reprobit.cli_build import command_verify
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError, project_root, safe_project_path
from reprobit.cli_project import command_source_lock
from reprobit.project_loader import load_project
from reprobit.schema import SourceManifestDocument
from reprobit.source_regeneration import apply_source_regeneration, plan_source_regeneration
from reprobit.transactions import CASTransaction, TransactionError, sha256_bytes, sha256_file


def _read_manifest(root: Path, relative: str) -> SourceManifestDocument:
    path = safe_project_path(root, relative)
    if not path.is_file():
        raise CLIError("repair needs an existing source lock; run rbit setup first")
    return SourceManifestDocument.model_validate_json(path.read_bytes())


def _snapshot_files(root: Path, paths: set[str]) -> dict[str, bytes | None]:
    snapshot: dict[str, bytes | None] = {}
    for relative in sorted(paths):
        path = safe_project_path(root, relative)
        snapshot[relative] = path.read_bytes() if path.is_file() else None
    return snapshot


def _preimages(root: Path, paths: set[str]) -> dict[str, str | None]:
    preimages: dict[str, str | None] = {}
    for relative in sorted(paths):
        path = safe_project_path(root, relative)
        preimages[relative] = sha256_file(path) if path.is_file() else None
    return preimages


def _restore_files(
    root: Path,
    originals: dict[str, bytes | None],
    expected: dict[str, str | None],
) -> tuple[str, ...]:
    changed = tuple(
        relative
        for relative, original in originals.items()
        if (None if original is None else sha256_bytes(original)) != expected[relative]
    )
    if not changed:
        return ()
    transaction = CASTransaction(root)
    for relative in changed:
        original = originals[relative]
        if original is None:
            transaction.delete(relative, expected_sha256=expected[relative])
        else:
            transaction.write(relative, original, expected_sha256=expected[relative])
    transaction.commit()
    return changed


def command_repair(args: argparse.Namespace, output: CLIOutput) -> int:
    """Refresh deterministic source authority, then prove every target exactly."""

    root = project_root(args.project)
    spec = load_project(root)
    manifest = _read_manifest(root, spec.layout.source_manifest)
    if not manifest.complete:
        raise CLIError("repair needs a complete source lock; run rbit source lock first")
    admitted_paths = tuple(entry.path for entry in manifest.entries)

    plan = plan_source_regeneration(root)
    watched_paths = set(plan.changed_documents)
    watched_paths.update((spec.layout.source_manifest, spec.layout.build_plan))
    originals = _snapshot_files(root, watched_paths)
    rollback_preimages = _preimages(root, watched_paths)

    try:
        regeneration = apply_source_regeneration(root, plan)
        if regeneration is not None:
            rollback_preimages = _preimages(root, watched_paths)
        lock_args = argparse.Namespace(
            project=str(root),
            path=list(admitted_paths),
            invalidate_producer_graph=False,
        )
        command_source_lock(lock_args, output)
        rollback_preimages = _preimages(root, watched_paths)
        verification_status = command_verify(args, output)
        if verification_status != 0:
            raise CLIError("candidate output did not pass exact verification")
    except KeyboardInterrupt:
        _restore_files(root, originals, rollback_preimages)
        raise
    except Exception as exc:
        try:
            restored = _restore_files(root, originals, rollback_preimages)
        except TransactionError as rollback_error:
            raise CLIError(
                "repair stopped and could not restore project records because they changed "
                f"concurrently: {rollback_error}"
            ) from exc
        detail = (
            f"; restored {len(restored)} project file(s) to their pre-repair state"
            if restored
            else "; no project records were changed"
        )
        raise CLIError(f"repair did not pass exact verification{detail}: {exc}") from exc

    output.emit(
        "repair_complete",
        (
            f"Repair complete: refreshed {len(plan.changes)} saved source check(s) and "
            "verified every target exactly"
        ),
        refreshed_checks=len(plan.changes),
        changed_documents=list(plan.changed_documents),
        source_inputs=len(admitted_paths),
        exact=True,
    )
    return 0


__all__ = ["command_repair"]
