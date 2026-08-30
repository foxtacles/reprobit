"""CLI boundary for the removable one-off schema migration."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError, project_root
from reprobit.model import Digest
from reprobit.project_loader import validate_project_files
from reprobit.schema import ProjectBundle
from reprobit.transactions import CASTransaction


def _existing_schema_additions(
    root: Path,
    candidate: ProjectBundle,
    generated: set[str],
) -> list[Path]:
    """Report existing schema paths that this one-off conversion does not own."""

    layout = candidate.spec.layout
    directories = (
        Path(layout.interventions),
        Path(layout.interventions) / "tus",
        Path(layout.proofs),
        Path(layout.proofs) / "tus",
        Path(layout.oracles),
    )
    additions: list[Path] = []
    for relative_directory in directories:
        directory = root.joinpath(*relative_directory.parts)
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise CLIError(f"migration-managed schema directory is unsafe: {directory}")
        for path in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
            if path.suffix.casefold() != ".json":
                continue
            relative = relative_directory / path.name
            if relative.as_posix() in generated:
                continue
            additions.append(relative)
    return additions


def _producer_graph_reconciliation(
    root: Path,
    candidate: ProjectBundle,
) -> tuple[tuple[Path, str] | None, Path | None]:
    """Invalidate a derived graph only when it cannot bind the migrated tree."""

    relative = Path(candidate.spec.layout.producer_graph)
    path = root.joinpath(*relative.parts)
    if not path.exists():
        return None, None
    if path.is_symlink() or not path.is_file():
        raise CLIError(f"migration-managed producer graph path is unsafe: {path}")
    try:
        from reprobit.producer_graph import read_producer_graph

        graph = read_producer_graph(path)
        ProjectBundle(
            root=str(root),
            spec=candidate.spec,
            toolchain_lock=candidate.toolchain_lock,
            source_manifest=candidate.source_manifest,
            build_plan=candidate.build_plan,
            producer_graph=graph,
            intervention_documents=candidate.intervention_documents,
            proof_documents=candidate.proof_documents,
            oracle_documents=candidate.oracle_documents,
        )
    except (OSError, ValueError, ValidationError):
        return (relative, "producer graph bindings differ from migrated authority"), None
    return None, relative


def command_manifest_migrate(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.migration import migration_output

    source = Path(args.source).expanduser().resolve(strict=True)
    semantic_claims = (
        Path(args.semantic_claims).expanduser().resolve(strict=True)
        if args.semantic_claims is not None
        else None
    )
    with output.activity("converting and validating schema-v2 manifest"):
        result = migration_output(source, semantic_claims_path=semantic_claims)
        candidate = validate_project_files(result.files)
    root = project_root(args.project_root)
    generated_paths = {item.as_posix() for item in result.files}
    existing_additions = _existing_schema_additions(
        root,
        candidate,
        generated_paths,
    )
    graph_removal, preserved_graph = _producer_graph_reconciliation(
        root,
        candidate,
    )
    managed_removals = [] if graph_removal is None else [graph_removal]
    output.emit(
        "migration_preview",
        f"migration produces {len(result.files)} files, "
        f"{result.intervention_count} interventions, {result.proof_count} proofs, "
        f"and {len(managed_removals)} managed removal(s)",
        source=source,
        source_sha256=result.source_sha256,
        semantic_claims=semantic_claims,
        files=len(result.files),
        interventions=result.intervention_count,
        proofs=result.proof_count,
        managed_removals=len(managed_removals),
        preserved_schema_additions=len(existing_additions),
        apply=args.apply,
    )
    for relative, data in sorted(result.files.items(), key=lambda item: item[0].as_posix()):
        output.emit(
            "migration_file",
            f"  {relative.as_posix()} ({len(data)} bytes)",
            path=relative.as_posix(),
            size=len(data),
        )
    for removal_path, reason in managed_removals:
        output.emit(
            "migration_remove",
            f"  remove {removal_path.as_posix()} ({reason})",
            path=removal_path.as_posix(),
            reason=reason,
        )
    for addition_path in existing_additions:
        output.emit(
            "migration_preserve",
            f"  preserve {addition_path.as_posix()} (outside this one-off conversion)",
            path=addition_path.as_posix(),
            reason="existing schema addition is not owned by this conversion",
        )
    if not args.apply:
        return 0
    manifest = candidate.source_manifest
    assert manifest is not None
    from reprobit.source_lock import receipt_source_input

    source_preconditions: list[tuple[str, str]] = []
    for entry in manifest.entries:
        if entry.path in generated_paths:
            generated = result.files[PurePosixPath(entry.path)]
            if len(generated) != entry.size or Digest.from_bytes(generated) != entry.digest:
                raise CLIError(
                    "migration would overwrite an admitted source with different bytes: "
                    f"{entry.path!r}"
                )
            continue
        size, digest, _ = receipt_source_input(root, entry.path)
        if size != entry.size or digest != entry.digest:
            raise CLIError(f"migration source authority differs at apply time: {entry.path!r}")
        source_preconditions.append((entry.path, entry.digest.value))
    transaction = CASTransaction(root)
    for relative, data in sorted(result.files.items(), key=lambda item: item[0].as_posix()):
        transaction.write(Path(*relative.parts), data)
    for removal_path, _reason in managed_removals:
        transaction.delete(removal_path)
    if preserved_graph is not None:
        transaction.assert_unchanged(preserved_graph)
    for source_relative, source_digest_value in source_preconditions:
        transaction.assert_unchanged(
            source_relative,
            expected_sha256=source_digest_value,
        )
    committed = transaction.commit()
    output.emit(
        "migration_applied",
        f"applied migration transaction {committed.transaction_id}",
        transaction_id=committed.transaction_id,
        changed_paths=committed.changed_paths,
        removed_paths=[path.as_posix() for path, _reason in managed_removals],
        preserved_schema_additions=[path.as_posix() for path in existing_additions],
    )
    return 0


__all__ = ["command_manifest_migrate"]
