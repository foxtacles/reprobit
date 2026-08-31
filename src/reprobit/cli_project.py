"""CLI commands for project creation, source authority, and inspection."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reprobit.authority_snapshot import (
    AuthoritySnapshotError,
    assert_json_authority_unchanged,
    capture_file_preimage,
    capture_json_authority_directories,
)
from reprobit.cli_output import CLIOutput, human_command
from reprobit.cli_paths import CLIError, project_root, relative_output, safe_project_path
from reprobit.costs import CostBreakdown, InterventionCost, calculate_cost
from reprobit.model import Digest
from reprobit.producer_graph import producer_graph_accepts_source
from reprobit.project_loader import load_project, load_project_tree
from reprobit.report_html_format import cost_class_label, human_label
from reprobit.schema import (
    BuildPlanDocument,
    ClassicRecipeIntervention,
    Intervention,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
    ProjectSpec,
    SourceManifestDocument,
    TargetSpec,
    ToolchainRef,
    source_manifest_digest,
)
from reprobit.strict_json import canonical_json, strict_load
from reprobit.transactions import CASTransaction


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _count_phrase(count: int, singular: str, plural: str | None = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _render_initial_project(spec: ProjectSpec) -> bytes:
    assert isinstance(spec.build, ProducerGraphBuildAdapter)
    target = spec.targets[0]
    lines = [
        "schema_version = 3",
        f"project_id = {_toml_string(spec.project_id)}",
        f"state_dir = {_toml_string(spec.state_dir)}",
        "",
        "[build]",
        'kind = "producer-graph"',
        "",
        "[toolchain]",
        'adapter = "classic-msvc"',
        f"profile = {_toml_string(spec.toolchain.profile)}",
        f"lock_file = {_toml_string(spec.toolchain.lock_file)}",
        "",
        "[paths]",
        f"id = {_toml_string(spec.paths.id)}",
        f"source = {_toml_string(spec.paths.source)}",
        f"build = {_toml_string(spec.paths.build)}",
        f"toolchain = {_toml_string(spec.paths.toolchain)}",
        "",
        "[verifier]",
        'kind = "literal"',
        "",
        "[authenticity]",
        'policy = "clean"',
        "",
        "[[targets]]",
        f"id = {_toml_string(target.id)}",
        f"artifact = {_toml_string(target.artifact)}",
        f"oracle = {_toml_string(target.oracle)}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _derived_project_id(root: Path) -> str:
    """Derive a stable, schema-safe default from a project directory name."""

    value = re.sub(r"[^a-z0-9._-]+", "-", root.name.casefold()).strip("._-")
    if not value:
        return "project"
    if not value[0].isalpha():
        value = f"project-{value}"
    return value[:128].rstrip("._-") or "project"


def command_init(args: argparse.Namespace, output: CLIOutput) -> int:
    root = Path(args.path).expanduser().resolve(strict=False)
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise CLIError(f"initialization target is not a real directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    artifact = args.artifact or f"build/{args.target}.exe"
    oracle = args.oracle or f"reference/{args.target}.exe"
    spec = ProjectSpec(
        schema_version=3,
        project_id=args.project_id or _derived_project_id(root),
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile=args.profile),
        paths=LogicalPathProfile(
            source=args.logical_source,
            build=args.logical_build,
            toolchain=args.logical_toolchain,
        ),
        targets=(TargetSpec(id=args.target, artifact=artifact, oracle=oracle),),
    )
    project_data = _render_initial_project(spec)
    initial_manifest = SourceManifestDocument(
        schema_version=3,
        # Initialization has not reviewed any project inputs yet. A certifying
        # manifest only becomes complete through ``rbit source lock``.
        complete=False,
        entries=(),
    )
    transaction = CASTransaction(root)
    transaction.write("reprobit.toml", project_data, expected_sha256=None)
    transaction.write(
        spec.layout.source_manifest,
        canonical_json(initial_manifest),
        expected_sha256=None,
    )
    result = transaction.commit()
    next_command = human_command(("rbit", "setup", root))
    output.emit(
        "initialized",
        f"Created ReproBit project {spec.project_id!r} at {root}\nNext: {next_command}",
        project_root=root,
        project_id=spec.project_id,
        changed_paths=result.changed_paths,
        next_command=next_command,
    )
    return 0


def _explicit_source_paths(root: Path, values: Sequence[str]) -> tuple[str, ...]:
    paths: list[str] = []
    for value in values:
        relative = relative_output(root, value)
        candidate = root / relative
        if candidate.is_symlink() or not candidate.exists():
            raise CLIError(f"source lock input is absent or redirected: {relative}")
        if candidate.is_file():
            paths.append(relative.as_posix())
            continue
        for child in sorted(candidate.rglob("*"), key=lambda item: item.as_posix()):
            if child.is_symlink():
                raise CLIError(f"source lock tree contains a symlink: {child}")
            if child.is_file():
                paths.append(child.relative_to(root).as_posix())
    return tuple(paths)


def _build_source_document(
    root: Path,
    spec: ProjectSpec,
    values: Sequence[str],
    output: CLIOutput,
) -> SourceManifestDocument:
    from reprobit.source_lock import SourceLockError, build_source_manifest, git_tracked_paths

    if values:
        paths = _explicit_source_paths(root, values)
    else:
        try:
            paths = git_tracked_paths(root)
        except SourceLockError as exc:
            if str(exc) == "the project has no tracked source inputs":
                detail = "Git has no tracked project files"
            else:
                detail = "Git could not inspect this directory as a worktree"
            raise CLIError(
                f"cannot select project source automatically: {detail}. "
                "Make sure Git is installed, then run git init and git add as needed. "
                "Alternatively, repeat --path PATH to name the complete source input set "
                "explicitly."
            ) from exc
    with output.activity("checking the project source files"):
        return build_source_manifest(root, paths, spec=spec, complete=True)


def _load_source_manifest(path: Path) -> SourceManifestDocument:
    return SourceManifestDocument.model_validate_json(canonical_json(strict_load(path)))


def _load_build_plan(path: Path) -> BuildPlanDocument:
    return BuildPlanDocument.model_validate_json(canonical_json(strict_load(path)))


def _source_changes(
    before: SourceManifestDocument,
    after: SourceManifestDocument,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[dict[str, Any], ...]]:
    old = {item.path: item for item in before.entries}
    new = {item.path: item for item in after.entries}
    added = tuple(sorted(set(new) - set(old), key=lambda item: (item.casefold(), item)))
    removed = tuple(sorted(set(old) - set(new), key=lambda item: (item.casefold(), item)))
    changed = tuple(
        {
            "path": path,
            "before_digest": old[path].digest.value,
            "after_digest": new[path].digest.value,
            "before_size": old[path].size,
            "after_size": new[path].size,
        }
        for path in sorted(set(old) & set(new), key=lambda item: (item.casefold(), item))
        if old[path].digest != new[path].digest or old[path].size != new[path].size
    )
    return added, removed, changed


def _inspect_candidate_source_authority(
    root: Path,
    spec: ProjectSpec,
    document: SourceManifestDocument,
    document_digest: Digest,
) -> tuple[BuildPlanDocument | None, Any | None]:
    build_plan_path = safe_project_path(root, spec.layout.build_plan)
    intervention_root = safe_project_path(root, spec.layout.interventions)
    if not build_plan_path.is_file() and not any(intervention_root.rglob("*.json")):
        return None, None
    plan = (
        _load_build_plan(build_plan_path).model_copy(
            update={"source_manifest_digest": document_digest}
        )
        if build_plan_path.is_file()
        else None
    )
    bundle = load_project_tree(
        root,
        verify_source_authority=False,
        include_producer_graph=False,
        source_manifest_override=document,
        build_plan_override=plan,
    )
    from reprobit.source_authority import inspect_source_authority

    return plan, inspect_source_authority(
        bundle,
        root,
        source_manifest=document,
        build_plan=plan,
        preflight_classic_recipes=True,
    )


def _stale_tu_fields(report: Any | None) -> tuple[dict[str, Any], ...]:
    if report is None:
        return ()
    return tuple(
        {
            "translation_unit_id": item.translation_unit_id,
            "source": item.source,
            "expected_digest": item.expected_digest,
            "actual_digest": item.actual_digest,
        }
        for item in report.stale_translation_units
    )


def _declared_overlay_outputs(root: Path, spec: ProjectSpec) -> tuple[str, ...]:
    """Read source-overlay output paths without requiring their stale pins to verify."""

    outputs: set[str] = set()
    directory = safe_project_path(root, spec.layout.interventions)
    if not directory.is_dir():
        return ()
    for path in sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()):
        document = strict_load(path)
        if not isinstance(document, dict):
            continue
        raw_interventions: Any = document.get("interventions")
        if not isinstance(raw_interventions, list):
            continue
        for intervention in raw_interventions:
            if not isinstance(intervention, dict) or intervention.get("family") != (
                "source_overlay_graph"
            ):
                continue
            raw_parameters: Any = intervention.get("parameters")
            if not isinstance(raw_parameters, list):
                continue
            parameters: dict[str, Any] = {}
            for field in raw_parameters:
                if isinstance(field, dict) and isinstance(field.get("name"), str):
                    parameters[field["name"]] = field.get("value")
            declarations = parameters.get("outputs")
            if not isinstance(declarations, list):
                continue
            for declaration in declarations:
                if isinstance(declaration, dict) and isinstance(declaration.get("path"), str):
                    outputs.add(declaration["path"])
    return tuple(sorted(outputs, key=lambda item: (item.casefold(), item)))


def _source_preview_message(
    *,
    added: Sequence[str],
    removed: Sequence[str],
    changed: Sequence[Mapping[str, Any]],
    entries: int,
    graph_invalidation_required: bool,
    membership_transition_blocked: bool,
    authority_checked: bool,
    authority_error: str | None,
    stale_units: Sequence[Mapping[str, Any]],
) -> str:
    if not added and not removed and not changed:
        lines = [f"Source files are up to date; {entries} selected input(s)."]
    else:
        lines = [
            f"Source preview: +{len(added)} -{len(removed)} ~{len(changed)}; "
            f"{entries} selected input(s)"
        ]
    if added:
        lines.append("  add: " + ", ".join(added))
    if removed:
        lines.append("  remove: " + ", ".join(removed))
    if changed:
        lines.append("  change: " + ", ".join(str(item["path"]) for item in changed))
    if graph_invalidation_required:
        graph_detail = (
            "update needed, but these source changes cannot be locked safely yet"
            if membership_transition_blocked
            else "update required after locking these source changes"
        )
        lines.append(f"  build graph: {graph_detail}")
    if authority_error is not None:
        label = (
            "  saved records still name the previous source-file list: "
            if added or removed
            else "  project records need repair: "
        )
        lines.append(label + authority_error)
    elif stale_units:
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in stale_units
        )
        label = (
            "  saved records still name the previous source-file list for: "
            if added or removed
            else "  project records need repair for: "
        )
        lines.append(label + rendered)
    elif not authority_checked:
        lines.append("  no build plan or saved source-derived records to check")
    else:
        lines.append("  reviewed source-derived records remain valid")
    return "\n".join(lines)


def _source_selection_command(
    action: str,
    root: Path,
    paths: Sequence[str],
    *,
    invalidate_graph: bool = False,
) -> str:
    arguments: list[str | Path] = ["rbit", "source", action, "--project", root]
    for path in paths:
        arguments.extend(("--path", path))
    if invalidate_graph:
        arguments.append("--invalidate-producer-graph")
    return human_command(arguments)


def _blocked_source_membership_guidance() -> str:
    return (
        "\nNo safe automatic next step is available: ReproBit cannot yet reconcile "
        "a change to which files the project builds without risking saved interventions. "
        "Restore the previous source-file list for now; the guided CMake update for this "
        "case is not supported yet."
    )


def command_source_preview(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    spec = load_project(root)
    document = _build_source_document(root, spec, args.path, output)
    document_digest = source_manifest_digest(document)
    current = _load_source_manifest(safe_project_path(root, spec.layout.source_manifest))
    current_digest = source_manifest_digest(current)
    added, removed, changed = _source_changes(current, document)

    producer_graph_path = safe_project_path(root, spec.layout.producer_graph)
    authority_error: str | None = None
    plan: BuildPlanDocument | None = None
    report: Any | None = None
    try:
        plan, report = _inspect_candidate_source_authority(root, spec, document, document_digest)
    except ValueError as exc:
        from reprobit.source_authority import SourceAuthorityError

        if not isinstance(exc, SourceAuthorityError):
            raise
        authority_error = str(exc)
    graph_invalidation_required = False
    checked_overlay_outputs: tuple[str, ...] = ()
    if producer_graph_path.is_file():
        from reprobit.producer_graph import read_producer_graph

        checked_overlay_outputs = (
            report.overlay_outputs if report is not None else _declared_overlay_outputs(root, spec)
        )
        graph_invalidation_required = not producer_graph_accepts_source(
            read_producer_graph(producer_graph_path),
            paths=(item.path for item in document.entries),
            overlay_outputs=checked_overlay_outputs,
        )
    stale_units = _stale_tu_fields(report)
    source_changed = document_digest != current_digest
    next_command: str | None = None
    membership_changed = bool(added or removed)
    membership_transition_blocked = membership_changed and bool(authority_error or stale_units)
    if not membership_transition_blocked:
        if authority_error is not None or stale_units:
            next_command = human_command(("rbit", "repair", root))
        elif source_changed or graph_invalidation_required:
            next_command = _source_selection_command(
                "lock",
                root,
                args.path,
                invalidate_graph=graph_invalidation_required,
            )
    message = _source_preview_message(
        added=added,
        removed=removed,
        changed=changed,
        entries=len(document.entries),
        graph_invalidation_required=graph_invalidation_required,
        membership_transition_blocked=membership_transition_blocked,
        authority_checked=report is not None,
        authority_error=authority_error,
        stale_units=stale_units,
    )
    if membership_transition_blocked:
        message += _blocked_source_membership_guidance()
    if next_command is not None:
        message += f"\nNext: {next_command}"
    cmake_import_command = (
        human_command(("rbit", "import", "cmake", root))
        if graph_invalidation_required and not membership_transition_blocked
        else None
    )
    if cmake_import_command is not None:
        message += (
            "\nThen refresh the recorded CMake build because one of its inputs changed: "
            f"{cmake_import_command}"
        )
    output.emit(
        "source_preview",
        message,
        before_source_manifest_digest=current_digest.value,
        after_source_manifest_digest=document_digest.value,
        entries=len(document.entries),
        added=added,
        removed=removed,
        changed=changed,
        unchanged=len(document.entries) - len(added) - len(changed),
        producer_graph_invalidation_required=graph_invalidation_required,
        checked_overlay_outputs=checked_overlay_outputs,
        authority_checked=report is not None,
        classic_preflight_checked=plan is not None and report is not None,
        stale_translation_units=stale_units,
        repair_required=bool(authority_error or stale_units),
        authority_error=authority_error,
        membership_transition_blocked=membership_transition_blocked,
        cmake_import_command=cmake_import_command,
        up_to_date=(
            not source_changed
            and not graph_invalidation_required
            and authority_error is None
            and not stale_units
        ),
        next_command=next_command,
    )
    return 0


def command_source_lock(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    try:
        config_preimage = capture_file_preimage(root, "reprobit.toml", required=True)
        spec = load_project(root)
        if capture_file_preimage(root, "reprobit.toml", required=True) != config_preimage:
            raise AuthoritySnapshotError("reprobit.toml changed while source lock was starting")
        control_preimages = {
            relative: capture_file_preimage(root, relative)
            for relative in (
                spec.toolchain.lock_file,
                spec.layout.source_manifest,
                spec.layout.build_plan,
                spec.layout.producer_graph,
            )
        }
        authority_snapshot = capture_json_authority_directories(
            root,
            (
                spec.layout.interventions,
                spec.layout.proofs,
                spec.layout.oracles,
            ),
        )
    except AuthoritySnapshotError as exc:
        raise CLIError(f"cannot seal source-lock inputs: {exc}") from exc
    document = _build_source_document(root, spec, args.path, output)
    document_digest = source_manifest_digest(document)
    current = _load_source_manifest(safe_project_path(root, spec.layout.source_manifest))
    added, removed, _changed = _source_changes(current, document)
    membership_changed = bool(added or removed)

    producer_graph_path = safe_project_path(root, spec.layout.producer_graph)
    graph_invalidated = False
    graph_present = producer_graph_path.is_file()
    graph = None
    if graph_present:
        from reprobit.producer_graph import read_producer_graph

        graph = read_producer_graph(producer_graph_path)
        graph_invalidated = not producer_graph_accepts_source(
            graph,
            paths=(item.path for item in document.entries),
            overlay_outputs=_declared_overlay_outputs(root, spec),
        )

    plan: BuildPlanDocument | None = None
    report: Any | None = None
    try:
        plan, report = _inspect_candidate_source_authority(root, spec, document, document_digest)
    except ValueError as exc:
        from reprobit.source_authority import SourceAuthorityError

        if not isinstance(exc, SourceAuthorityError):
            raise
        if membership_changed:
            raise CLIError(
                "source lock refused because saved records still name the previous "
                f"source-file list: {exc}" + _blocked_source_membership_guidance()
            ) from exc
        repair_hint = human_command(("rbit", "repair", root))
        raise CLIError(
            "source lock refused because reviewed source-derived authority must be "
            f"repaired: {exc}\nTry: {repair_hint}"
        ) from exc
    stale_units = _stale_tu_fields(report)
    if stale_units:
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in stale_units
        )
        if membership_changed:
            raise CLIError(
                "source lock refused because saved translation-unit records still name "
                f"the previous source-file list: {rendered}" + _blocked_source_membership_guidance()
            )
        repair_hint = human_command(("rbit", "repair", root))
        raise CLIError(
            "source lock refused because effective translation-unit bytes changed; "
            "repair the affected intervention and proof records instead of repinning "
            f"them: {rendered}\nTry: {repair_hint}"
        )

    if graph is not None:
        graph_invalidated = not producer_graph_accepts_source(
            graph,
            paths=(item.path for item in document.entries),
            overlay_outputs=(report.overlay_outputs if report is not None else ()),
        )
        if graph_invalidated:
            if not args.invalidate_producer_graph:
                retry_hint = _source_selection_command(
                    "lock",
                    root,
                    args.path,
                    invalidate_graph=True,
                )
                raise CLIError(
                    "the selected source files removed an input used by the recorded build; "
                    f"first run: {retry_hint}\n"
                    "Then refresh the CMake build records: "
                    f"{human_command(('rbit', 'import', 'cmake', root))}"
                )
            graph_invalidated = True

    transaction = CASTransaction(root)
    transaction.write(
        spec.layout.source_manifest,
        canonical_json(document),
        expected_sha256=control_preimages[spec.layout.source_manifest],
    )
    if plan is not None:
        transaction.write(
            spec.layout.build_plan,
            canonical_json(plan),
            expected_sha256=control_preimages[spec.layout.build_plan],
        )
    else:
        transaction.assert_unchanged(
            spec.layout.build_plan,
            expected_sha256=control_preimages[spec.layout.build_plan],
        )
    if graph_invalidated:
        transaction.delete(
            spec.layout.producer_graph,
            expected_sha256=control_preimages[spec.layout.producer_graph],
        )
    elif graph_present:
        transaction.assert_unchanged(
            spec.layout.producer_graph,
            expected_sha256=control_preimages[spec.layout.producer_graph],
        )
    else:
        transaction.assert_unchanged(spec.layout.producer_graph, expected_sha256=None)
    transaction.assert_unchanged("reprobit.toml", expected_sha256=config_preimage)
    transaction.assert_unchanged(
        spec.toolchain.lock_file,
        expected_sha256=control_preimages[spec.toolchain.lock_file],
    )
    assert_json_authority_unchanged(transaction, authority_snapshot)
    claimed_paths = {
        "reprobit.toml",
        spec.toolchain.lock_file,
        spec.layout.source_manifest,
        spec.layout.build_plan,
        spec.layout.producer_graph,
        *(
            relative
            for directory in authority_snapshot
            for relative, _digest in directory.file_digests
        ),
    }
    for entry in document.entries:
        if entry.path not in claimed_paths:
            transaction.assert_unchanged(entry.path, expected_sha256=entry.digest.value)
    result = transaction.commit()
    cmake_import_command = (
        human_command(("rbit", "import", "cmake", root))
        if graph_invalidated or not graph_present
        else None
    )
    next_command = cmake_import_command or human_command(("rbit", "status", root))
    message = f"locked {len(document.entries)} project source input(s)"
    message += f"\nNext: {next_command}"
    output.emit(
        "source_locked",
        message,
        output=spec.layout.source_manifest,
        entries=len(document.entries),
        source_manifest_digest=document_digest.value,
        producer_graph_invalidated=graph_invalidated,
        next_command=next_command,
        transaction_id=result.transaction_id,
    )
    return 0


def command_source_regenerate(args: argparse.Namespace, output: CLIOutput) -> int:
    """Regenerate mechanical source-derived pins after admitted source edits."""

    from reprobit.source_regeneration import (
        SourceRegenerationError,
        apply_source_regeneration,
        plan_source_regeneration,
    )

    root = project_root(args.project)
    try:
        plan = plan_source_regeneration(root)
    except SourceRegenerationError as exc:
        raise CLIError(f"source regeneration refused: {exc}") from exc
    rendered_changes = [
        {
            "document": change.document,
            "location": change.location,
            "before": change.before,
            "after": change.after,
        }
        for change in plan.changes
    ]
    if not plan.changes:
        output.emit(
            "source_regenerated",
            "No source-record updates are needed; saved records already match current files.",
            applied=False,
            changes=rendered_changes,
            documents=[],
        )
        return 0
    counts_by_document: dict[str, int] = {}
    for change in plan.changes:
        counts_by_document[change.document] = counts_by_document.get(change.document, 0) + 1
    if args.apply:
        summary = (
            f"Saved source records refreshed: {_count_phrase(len(plan.changes), 'update')} saved "
            f"across {_count_phrase(len(plan.changed_documents), 'project file')}"
        )
    else:
        summary = (
            f"Source-record preview: {_count_phrase(len(plan.changes), 'update')} would be saved "
            f"across {_count_phrase(len(plan.changed_documents), 'project file')}"
        )
    lines = [summary]
    visible_documents = sorted(counts_by_document)[:8]
    for document in visible_documents:
        lines.append(f"  {document}: {_count_phrase(counts_by_document[document], 'check')}")
    hidden_documents = len(counts_by_document) - len(visible_documents)
    if hidden_documents:
        lines.append(f"  ...and {_count_phrase(hidden_documents, 'more project file')}")
    if args.apply:
        try:
            transaction = apply_source_regeneration(root, plan)
        except SourceRegenerationError as exc:
            raise CLIError(f"source regeneration refused: {exc}") from exc
        if transaction is None:
            raise AssertionError("source regeneration applied an empty plan")
        next_command = human_command(("rbit", "repair", root))
        lines.append(f"Next: {next_command}")
        output.emit(
            "source_regenerated",
            "\n".join(lines),
            applied=True,
            changes=rendered_changes,
            documents=list(plan.changed_documents),
            transaction_id=transaction.transaction_id,
            next_command=next_command,
        )
        return 0
    lines.append("Preview only: no project files changed. Add --apply to save these updates.")
    output.emit(
        "source_regenerated",
        "\n".join(lines),
        applied=False,
        changes=rendered_changes,
        documents=list(plan.changed_documents),
    )
    return 0


def command_source_export(args: argparse.Namespace, output: CLIOutput) -> int:
    """Materialize the reviewed effective source view used by producers."""

    from reprobit.source_export import refresh_effective_source_export

    root = project_root(args.project)
    safe_project_path(root, args.destination)
    candidate = Path(args.destination.replace("\\", "/"))
    destination = Path(os.path.abspath(candidate if candidate.is_absolute() else root / candidate))
    with output.activity("preparing the effective source view", phase="source"):
        bundle = load_project_tree(root)
        witnesses = refresh_effective_source_export(bundle, root, destination)
    output.emit(
        "source_exported",
        f"Effective source view ready: {destination}",
        path=destination,
        interventions=len(witnesses),
    )
    return 0


def command_validate(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    with output.activity("checking every saved project file", phase="validate"):
        bundle = load_project_tree(root, verify_source_authority=False)
        from reprobit.source_authority import validate_source_authority

        validate_source_authority(bundle, root, preflight_classic_recipes=True)
        if (
            isinstance(bundle.spec.build, ProducerGraphBuildAdapter)
            and bundle.producer_graph is None
        ):
            raise CLIError(
                "producer-graph project has no committed graph; run rbit import cmake "
                "before validation"
            )
    output.emit(
        "validated",
        f"validated {bundle.spec.project_id}: {len(bundle.spec.targets)} target(s), "
        f"{len(bundle.interventions)} intervention(s)",
        project_id=bundle.spec.project_id,
        targets=len(bundle.spec.targets),
        interventions=len(bundle.interventions),
        proofs=sum(len(item.expected_observations) for item in bundle.proof_documents),
    )
    return 0


def _scope_text(scope: Any) -> str:
    values = [scope.target]
    if scope.translation_unit is not None:
        values.append(scope.translation_unit)
    if scope.function is not None:
        values.append(scope.function)
    return "/".join(values)


def _human_intervention_label(item: Intervention) -> str:
    if isinstance(item, ClassicRecipeIntervention):
        return f"{human_label(item.family.value).capitalize()} adjustment"
    return human_label(item.kind)


def _human_intervention_detail(item: Intervention, cost: InterventionCost) -> str:
    units = ", ".join(
        f"{human_label(unit.kind.value)}: {unit.count} x {unit.unit_cost} = {unit.cost}"
        for unit in cost.units
    )
    dependencies = ", ".join(item.dependencies) or "none"
    beneficiaries = ", ".join(_scope_text(scope) for scope in item.beneficiaries) or "none"
    return "\n".join(
        (
            f"{item.id}: {_human_intervention_label(item)}, cost={cost.cost}, "
            f"scope={_scope_text(item.scope)}",
            f"  cost class: {cost_class_label(cost.cost_class)}",
            f"  typed units: {units}",
            f"  dependencies: {dependencies}",
            f"  shared beneficiaries: {beneficiaries}",
            f"  rationale: {item.rationale}",
        )
    )


def _human_cost_breakdown(result: CostBreakdown) -> str:
    attributed = result.project_total - result.unallocated_shared_cost
    lines = [
        f"project intervention cost: {result.project_total} relative points "
        f"(model v{result.model_version})",
        f"function attribution: {attributed} attributed + "
        f"{result.unallocated_shared_cost} remaining at target/TU scope "
        f"= {result.project_total}",
    ]
    if result.by_target:
        lines.append("by target (same project total):")
        lines.extend(
            f"  {item.target}: {item.cost} (interventions={item.interventions}, units={item.units})"
            for item in result.by_target
        )
    if result.by_class:
        lines.append("by class (same project total):")
        lines.extend(
            f"  {cost_class_label(item.cost_class)}: {item.cost} "
            f"(interventions={item.interventions}, units={item.units})"
            for item in result.by_class
        )
    return "\n".join(lines)


def command_explain(args: argparse.Namespace, output: CLIOutput) -> int:
    bundle = load_project_tree(project_root(args.project), verify_source_authority=False)
    costs = {
        item.intervention_id: item for item in calculate_cost(bundle.interventions).interventions
    }
    selected = tuple(
        item
        for item in bundle.interventions
        if args.intervention is None or item.id == args.intervention
    )
    if args.intervention is not None and not selected:
        raise CLIError(f"unknown intervention: {args.intervention}")
    for item in selected:
        cost = costs[item.id]
        summary = (
            f"{item.id}: {_human_intervention_label(item)}, cost={cost.cost}, "
            f"scope={_scope_text(item.scope)}"
        )
        output.emit(
            "intervention",
            (
                _human_intervention_detail(item, cost)
                if args.intervention is not None and output.output_format == "text"
                else summary
            ),
            id=item.id,
            kind=item.kind,
            cost=cost.cost,
            cost_class=cost.cost_class.value,
            units=cost.units,
            scope=item.scope,
            rationale=item.rationale,
            dependencies=item.dependencies,
            beneficiaries=item.beneficiaries,
        )
    return 0


def command_cost(args: argparse.Namespace, output: CLIOutput) -> int:
    bundle = load_project_tree(project_root(args.project), verify_source_authority=False)
    result = calculate_cost(bundle.interventions)
    output.emit(
        "cost",
        (
            _human_cost_breakdown(result)
            if output.output_format == "text"
            else (
                f"project intervention cost: {result.project_total} relative points "
                f"(model v{result.model_version})"
            )
        ),
        breakdown=result,
    )
    return 0


def command_status(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.project_readiness import (
        inspect_project_readiness,
        render_project_readiness,
    )

    root = project_root(args.project)
    readiness = inspect_project_readiness(root)
    output.emit(
        "project_readiness",
        render_project_readiness(readiness, include_ready=args.all),
        ready=readiness.ready,
        completed=readiness.completed,
        total=len(readiness.items),
        next_command=readiness.next_command,
        checks=[
            {
                "id": item.id,
                "label": item.label,
                "ready": item.ready,
                "detail": item.detail,
                "next_command": item.next_command,
            }
            for item in readiness.items
        ],
    )
    return 0 if readiness.ready else 1


def command_report(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.report_io import read_report_json, write_report_html

    source = Path(args.input).expanduser().resolve(strict=True)
    destination = (
        Path(args.html).expanduser().resolve(strict=False)
        if args.html
        else source.with_suffix(".html")
    )
    report = read_report_json(source)
    write_report_html(report, destination, canonical_json_path=source)
    output.emit(
        "report_written",
        f"wrote self-contained report to {destination}",
        input=source,
        html=destination,
        clean=report.verdict.clean,
        total_cost=report.costs.project_total,
    )
    return 0


__all__ = [
    "command_cost",
    "command_explain",
    "command_init",
    "command_report",
    "command_source_export",
    "command_source_lock",
    "command_source_preview",
    "command_status",
    "command_validate",
]
