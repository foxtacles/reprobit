"""CLI commands for project creation, source authority, and inspection."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from reprobit.authority_snapshot import (
    AuthoritySnapshotError,
    JsonAuthorityDirectorySnapshot,
    assert_json_authority_unchanged,
    capture_file_preimage,
    capture_json_authority_directories,
)
from reprobit.cli_output import (
    CLIOutput,
    NextStep,
    bounded_items,
    count_phrase,
    human_command,
    next_step_fields,
)
from reprobit.cli_paths import (
    CLIError,
    paths_alias,
    paths_overlap,
    project_root,
    protected_project_paths,
    relative_output,
    safe_project_path,
)
from reprobit.costs import CostBreakdown, InterventionCost, calculate_cost
from reprobit.model import Digest
from reprobit.producer_graph import (
    CMakeImportRecipe,
    producer_graph_accepts_source,
    read_producer_graph,
)
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
from reprobit.transactions import CASTransaction, TransactionResult

if TYPE_CHECKING:
    from reprobit.source_authority import SourceAuthorityReport


class ActivityProgress(Protocol):
    """The progress surface needed while selecting project source files."""

    def activity(
        self,
        description: str,
        *,
        phase: str = "work",
    ) -> AbstractContextManager[Callable[[str], None]]: ...


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_initial_project(spec: ProjectSpec) -> bytes:
    assert isinstance(spec.build, ProducerGraphBuildAdapter)
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
    ]
    for target in spec.targets:
        lines.extend(
            (
                "[[targets]]",
                f"id = {_toml_string(target.id)}",
                f"artifact = {_toml_string(target.artifact)}",
                f"oracle = {_toml_string(target.oracle)}",
                "",
            )
        )
    return "\n".join(lines).encode("utf-8")


def _derived_project_id(root: Path) -> str:
    """Derive a stable, schema-safe default from a project directory name."""

    value = re.sub(r"[^a-z0-9._-]+", "-", root.name.casefold()).strip("._-")
    if not value:
        return "project"
    if not value[0].isalpha():
        value = f"project-{value}"
    return value[:128].rstrip("._-") or "project"


def _init_path_overrides(
    values: Sequence[str] | None,
    *,
    option: str,
    target_ids: tuple[str, ...],
) -> dict[str, str]:
    """Parse one plain single-target path or repeatable TARGET=PATH mappings."""

    if not values:
        return {}
    if len(target_ids) == 1 and len(values) == 1:
        target_id, separator, path = values[0].partition("=")
        if not separator:
            return {target_ids[0]: values[0]}
        if target_id not in target_ids:
            raise CLIError(f"{option} names unknown target {target_id!r}")
        if not path or "=" in path:
            raise CLIError(f"{option} must use TARGET=PROJECT_PATH")
        return {target_id: path}

    overrides: dict[str, str] = {}
    for value in values:
        target_id, separator, path = value.partition("=")
        if not separator or not target_id or not path or "=" in path:
            raise CLIError(
                f"{option} must use TARGET=PROJECT_PATH when initializing multiple targets"
            )
        if target_id not in target_ids:
            raise CLIError(f"{option} names unknown target {target_id!r}")
        if target_id in overrides:
            raise CLIError(f"{option} repeats target {target_id!r}")
        overrides[target_id] = path
    return overrides


_LOCAL_STATE_IGNORES = (b"/.reprobit-state/", b"/.reprobit-transactions/")


def _updated_gitignore(root: Path) -> bytes | None:
    """Add only ReproBit's root-local state entries while preserving project text."""

    path = root / ".gitignore"
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CLIError(f"cannot safely update redirected or non-file ignore list: {path}")
    current = path.read_bytes() if path.is_file() else b""
    existing = set(current.splitlines())
    missing = tuple(entry for entry in _LOCAL_STATE_IGNORES if entry not in existing)
    if not missing:
        return None
    separator = b"" if not current or current.endswith(b"\n") else b"\n"
    return current + separator + b"\n".join(missing) + b"\n"


def command_init(args: argparse.Namespace, output: CLIOutput) -> int:
    root = Path(args.project).expanduser().resolve(strict=False)
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise CLIError(f"initialization target is not a real directory: {root}")
    target_ids = tuple(args.target or ("program",))
    if len({target.casefold() for target in target_ids}) != len(target_ids):
        raise CLIError("--target names must be unique under DOS case folding")
    artifact_overrides = _init_path_overrides(
        args.artifact,
        option="--artifact",
        target_ids=target_ids,
    )
    oracle_overrides = _init_path_overrides(
        args.oracle,
        option="--oracle",
        target_ids=target_ids,
    )
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
        targets=tuple(
            TargetSpec(
                id=target_id,
                artifact=artifact_overrides.get(target_id, f"build/{target_id}.exe"),
                oracle=oracle_overrides.get(target_id, f"reference/{target_id}.exe"),
            )
            for target_id in target_ids
        ),
    )
    project_data = _render_initial_project(spec)
    initial_manifest = SourceManifestDocument(
        schema_version=3,
        # Initialization has not reviewed any project inputs yet. A certifying
        # manifest only becomes complete through ``rbit source lock``.
        complete=False,
        entries=(),
    )
    root.mkdir(parents=True, exist_ok=True)
    transaction = CASTransaction(root)
    transaction.write("reprobit.toml", project_data, expected_sha256=None)
    transaction.write(
        spec.layout.source_manifest,
        canonical_json(initial_manifest),
        expected_sha256=None,
    )
    gitignore = _updated_gitignore(root)
    if gitignore is not None:
        transaction.write(".gitignore", gitignore)
    result = transaction.commit()
    next_step = NextStep(("rbit", "setup", root))
    output.emit(
        "initialized",
        f"Created ReproBit project {spec.project_id!r} at {root}\nNext: {next_step.command}",
        project_root=root,
        project_id=spec.project_id,
        changed_paths=result.changed_paths,
        **next_step.fields(),
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
    output: ActivityProgress,
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
    *,
    preflight_classic_recipes: bool = True,
) -> tuple[BuildPlanDocument | None, SourceAuthorityReport | None]:
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
        preflight_classic_recipes=preflight_classic_recipes,
    )


def _stale_tu_fields(report: SourceAuthorityReport | None) -> tuple[dict[str, Any], ...]:
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
    def concise(values: Sequence[str]) -> str:
        visible, hidden = bounded_items(values)
        rendered = ", ".join(visible)
        return rendered + (f", ... and {hidden} more" if hidden else "")

    if not added and not removed and not changed:
        lines = [f"Source files are up to date; {count_phrase(entries, 'selected input')}."]
    else:
        lines = [
            f"Source preview: +{len(added)} -{len(removed)} ~{len(changed)}; "
            f"{count_phrase(entries, 'selected input')}"
        ]
    if added:
        lines.append("  add: " + concise(added))
    if removed:
        lines.append("  remove: " + concise(removed))
    if changed:
        lines.append("  change: " + concise(tuple(str(item["path"]) for item in changed)))
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
        visible_units, hidden_units = bounded_items(stale_units)
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in visible_units
        )
        if hidden_units:
            rendered += f", ... and {hidden_units} more"
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


def _source_selection_step(
    action: str,
    root: Path,
    paths: Sequence[str],
    *,
    invalidate_graph: bool = False,
) -> NextStep:
    arguments: list[str | Path] = ["rbit", "source", action, root]
    for path in paths:
        arguments.extend(("--path", path))
    if invalidate_graph:
        arguments.append("--invalidate-producer-graph")
    return NextStep(arguments)


def _recorded_cmake_recipe(root: Path) -> CMakeImportRecipe | None:
    spec = load_project(root)
    return read_producer_graph(safe_project_path(root, spec.layout.producer_graph)).import_recipe


def cmake_reimport_guidance(root: Path) -> str:
    """Explain the one safe migration for a graph without replayable import options."""

    return (
        "Automatic CMake refresh needs the original import options and will not guess them. "
        f"Re-run {human_command(('rbit', 'import', 'cmake', root))} once with those "
        "options before refreshing."
    )


def _cmake_refresh_step(
    root: Path,
    paths: Sequence[str],
    *,
    recipe: CMakeImportRecipe | None = None,
) -> NextStep:
    arguments: list[str | Path] = ["rbit", "import", "cmake", root, "--refresh"]
    for path in paths:
        arguments.extend(("--path", path))
    recipe = _recorded_cmake_recipe(root) if recipe is None else recipe
    if recipe is None:
        raise CLIError(cmake_reimport_guidance(root))
    arguments.extend(("--cmake", recipe.cmake))
    arguments.extend(("--configuration", recipe.configuration))
    arguments.extend(("--timeout", str(recipe.timeout_seconds)))
    for declaration in recipe.cmake_defines:
        arguments.extend(("--cmake-define", declaration))
    for declaration in recipe.directive_inputs:
        arguments.extend(("--directive-input", declaration))
    return NextStep(arguments)


def _blocked_source_membership_guidance() -> str:
    return (
        "\nNo safe automatic next step is available because the saved build records "
        "cannot be matched unambiguously to this source selection. Review the listed "
        "project records before trying again."
    )


@dataclass(frozen=True, slots=True)
class SourceLockPlan:
    """One inspected source selection and, when sealed, its commit preconditions."""

    root: Path
    spec: ProjectSpec
    selected_paths: tuple[str, ...]
    document: SourceManifestDocument
    current: SourceManifestDocument
    document_digest: Digest
    current_digest: Digest
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[dict[str, Any], ...]
    build_plan: BuildPlanDocument | None
    authority_report: SourceAuthorityReport | None
    authority_error: str | None
    stale_units: tuple[dict[str, Any], ...]
    graph_present: bool
    graph_invalidation_required: bool
    checked_overlay_outputs: tuple[str, ...]
    config_preimage: str | None = None
    control_preimages: dict[str, str | None] | None = None
    authority_snapshot: tuple[JsonAuthorityDirectorySnapshot, ...] | None = None

    @property
    def membership_changed(self) -> bool:
        return bool(self.added or self.removed)

    @property
    def source_changed(self) -> bool:
        return self.document_digest != self.current_digest


def plan_source_lock(
    root: Path,
    paths: Sequence[str],
    output: ActivityProgress,
    *,
    seal: bool = False,
    reconcile_translation_units: bool = False,
) -> SourceLockPlan:
    """Inspect one source selection; optionally seal everything needed to apply it."""

    project = root.resolve(strict=True)
    config_preimage: str | None = None
    control_preimages: dict[str, str | None] | None = None
    authority_snapshot: tuple[JsonAuthorityDirectorySnapshot, ...] | None = None
    try:
        if seal:
            config_preimage = capture_file_preimage(project, "reprobit.toml", required=True)
        spec = load_project(project)
        if seal:
            if capture_file_preimage(project, "reprobit.toml", required=True) != config_preimage:
                raise AuthoritySnapshotError("reprobit.toml changed while source lock was starting")
            control_preimages = {
                relative: capture_file_preimage(project, relative)
                for relative in (
                    spec.toolchain.lock_file,
                    spec.layout.source_manifest,
                    spec.layout.build_plan,
                    spec.layout.producer_graph,
                )
            }
            authority_snapshot = capture_json_authority_directories(
                project,
                (
                    spec.layout.interventions,
                    spec.layout.proofs,
                    spec.layout.oracles,
                ),
            )
    except AuthoritySnapshotError as exc:
        raise CLIError(f"cannot seal source-lock inputs: {exc}") from exc

    document = _build_source_document(project, spec, paths, output)
    document_digest = source_manifest_digest(document)
    current = _load_source_manifest(safe_project_path(project, spec.layout.source_manifest))
    current_digest = source_manifest_digest(current)
    added, removed, changed = _source_changes(current, document)

    authority_error: str | None = None
    build_plan: BuildPlanDocument | None = None
    report: SourceAuthorityReport | None = None
    try:
        build_plan, report = _inspect_candidate_source_authority(
            project,
            spec,
            document,
            document_digest,
            preflight_classic_recipes=not reconcile_translation_units,
        )
    except ValueError as exc:
        from reprobit.source_authority import SourceAuthorityError

        if not isinstance(exc, SourceAuthorityError):
            raise
        authority_error = str(exc)

    graph_path = safe_project_path(project, spec.layout.producer_graph)
    graph_present = graph_path.is_file()
    checked_overlay_outputs: tuple[str, ...] = ()
    graph_invalidation_required = False
    if graph_present:
        from reprobit.producer_graph import read_producer_graph

        checked_overlay_outputs = (
            report.overlay_outputs
            if report is not None
            else _declared_overlay_outputs(project, spec)
        )
        graph_invalidation_required = not producer_graph_accepts_source(
            read_producer_graph(graph_path),
            paths=(item.path for item in document.entries),
            overlay_outputs=checked_overlay_outputs,
        )

    return SourceLockPlan(
        root=project,
        spec=spec,
        selected_paths=tuple(paths),
        document=document,
        current=current,
        document_digest=document_digest,
        current_digest=current_digest,
        added=added,
        removed=removed,
        changed=changed,
        build_plan=build_plan,
        authority_report=report,
        authority_error=authority_error,
        stale_units=_stale_tu_fields(report),
        graph_present=graph_present,
        graph_invalidation_required=graph_invalidation_required,
        checked_overlay_outputs=checked_overlay_outputs,
        config_preimage=config_preimage,
        control_preimages=control_preimages,
        authority_snapshot=authority_snapshot,
    )


def apply_source_lock(
    plan: SourceLockPlan,
    *,
    invalidate_producer_graph: bool,
    reconcile_translation_units: bool = False,
    replace_producer_graph: bool = False,
) -> TransactionResult:
    """Apply one sealed plan without re-running CLI orchestration."""

    if (
        plan.config_preimage is None
        or plan.control_preimages is None
        or plan.authority_snapshot is None
    ):
        raise CLIError("source-lock plan was not sealed for publication")

    if plan.authority_error is not None:
        if plan.membership_changed:
            raise CLIError(
                "source lock refused because saved records still name the previous "
                f"source-file list: {plan.authority_error}" + _blocked_source_membership_guidance()
            )
        repair_hint = human_command(("rbit", "repair", plan.root))
        raise CLIError(
            "source lock refused because reviewed source-derived authority must be "
            f"repaired: {plan.authority_error}\nTry: {repair_hint}"
        )
    if plan.stale_units and not (plan.membership_changed and reconcile_translation_units):
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in plan.stale_units
        )
        if plan.membership_changed:
            if plan.graph_present and plan.build_plan is not None:
                refresh_hint = _cmake_refresh_step(plan.root, plan.selected_paths).command
                raise CLIError(
                    "source lock cannot replace translation-unit records on its own: "
                    f"{rendered}\nUse: {refresh_hint}"
                )
            raise CLIError(
                "source lock refused because saved translation-unit records still name "
                f"the previous source-file list: {rendered}" + _blocked_source_membership_guidance()
            )
        repair_hint = human_command(("rbit", "repair", plan.root))
        raise CLIError(
            "source lock refused because effective translation-unit bytes changed; "
            "repair the affected intervention and proof records instead of repinning "
            f"them: {rendered}\nTry: {repair_hint}"
        )
    graph_will_be_removed = plan.graph_invalidation_required or (
        replace_producer_graph and plan.graph_present
    )
    if graph_will_be_removed and not invalidate_producer_graph:
        if plan.graph_present and plan.build_plan is not None:
            refresh_hint = _cmake_refresh_step(plan.root, plan.selected_paths).command
            raise CLIError(
                "the selected source files require new CMake build records; "
                f"refresh them together with the source lock: {refresh_hint}"
            )
        retry_hint = _source_selection_step(
            "lock",
            plan.root,
            plan.selected_paths,
            invalidate_graph=True,
        ).command
        raise CLIError(
            "the selected source files removed an input used by the recorded build; "
            f"lock them and remove that obsolete graph: {retry_hint}\n"
            f"Then record a new build: {human_command(('rbit', 'import', 'cmake', plan.root))}"
        )

    spec = plan.spec
    preimages = plan.control_preimages
    transaction = CASTransaction(plan.root)
    transaction.write(
        spec.layout.source_manifest,
        canonical_json(plan.document),
        expected_sha256=preimages[spec.layout.source_manifest],
    )
    if plan.build_plan is not None:
        transaction.write(
            spec.layout.build_plan,
            canonical_json(plan.build_plan),
            expected_sha256=preimages[spec.layout.build_plan],
        )
    else:
        transaction.assert_unchanged(
            spec.layout.build_plan,
            expected_sha256=preimages[spec.layout.build_plan],
        )
    if graph_will_be_removed:
        transaction.delete(
            spec.layout.producer_graph,
            expected_sha256=preimages[spec.layout.producer_graph],
        )
    else:
        transaction.assert_unchanged(
            spec.layout.producer_graph,
            expected_sha256=preimages[spec.layout.producer_graph],
        )
    transaction.assert_unchanged("reprobit.toml", expected_sha256=plan.config_preimage)
    transaction.assert_unchanged(
        spec.toolchain.lock_file,
        expected_sha256=preimages[spec.toolchain.lock_file],
    )
    assert_json_authority_unchanged(transaction, plan.authority_snapshot)
    claimed_paths = {
        "reprobit.toml",
        spec.toolchain.lock_file,
        spec.layout.source_manifest,
        spec.layout.build_plan,
        spec.layout.producer_graph,
        *(
            relative
            for directory in plan.authority_snapshot
            for relative, _digest in directory.file_digests
        ),
    }
    for entry in plan.document.entries:
        if entry.path not in claimed_paths:
            transaction.assert_unchanged(entry.path, expected_sha256=entry.digest.value)
    return transaction.commit()


def command_source_preview(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    plan = plan_source_lock(root, args.path, output)
    document = plan.document
    added, removed, changed = plan.added, plan.removed, plan.changed
    next_step: NextStep | None = None
    recipe = _recorded_cmake_recipe(root) if plan.graph_present else None
    cmake_refresh_available = bool(
        (plan.membership_changed or plan.graph_invalidation_required)
        and plan.authority_error is None
        and plan.graph_present
        and plan.build_plan is not None
        and recipe is not None
    )
    cmake_recipe_missing = bool(
        (plan.membership_changed or plan.graph_invalidation_required)
        and plan.graph_present
        and plan.build_plan is not None
        and recipe is None
    )
    membership_transition_blocked = plan.membership_changed and bool(
        plan.authority_error or (plan.stale_units and not cmake_refresh_available)
    )
    if not membership_transition_blocked:
        if cmake_refresh_available:
            next_step = _cmake_refresh_step(root, args.path, recipe=recipe)
        elif plan.authority_error is not None or plan.stale_units:
            next_step = NextStep(("rbit", "repair", root))
        elif plan.source_changed:
            next_step = _source_selection_step(
                "lock",
                root,
                args.path,
            )
    message = _source_preview_message(
        added=added,
        removed=removed,
        changed=changed,
        entries=len(document.entries),
        graph_invalidation_required=plan.graph_invalidation_required,
        membership_transition_blocked=membership_transition_blocked,
        authority_checked=plan.authority_report is not None,
        authority_error=plan.authority_error,
        stale_units=plan.stale_units,
    )
    if membership_transition_blocked:
        message += (
            "\n" + cmake_reimport_guidance(root)
            if cmake_recipe_missing
            else _blocked_source_membership_guidance()
        )
    if next_step is not None:
        message += f"\nNext: {next_step.command}"
    cmake_import_step = next_step if cmake_refresh_available else None
    output.emit(
        "source_preview",
        message,
        before_source_manifest_digest=plan.current_digest.value,
        after_source_manifest_digest=plan.document_digest.value,
        entries=len(document.entries),
        added=added,
        removed=removed,
        changed=changed,
        unchanged=len(document.entries) - len(added) - len(changed),
        producer_graph_invalidation_required=plan.graph_invalidation_required,
        checked_overlay_outputs=plan.checked_overlay_outputs,
        authority_checked=plan.authority_report is not None,
        classic_preflight_checked=plan.build_plan is not None and plan.authority_report is not None,
        stale_translation_units=plan.stale_units,
        repair_required=bool(
            plan.authority_error or (plan.stale_units and not cmake_refresh_available)
        ),
        authority_error=plan.authority_error,
        membership_transition_blocked=membership_transition_blocked,
        cmake_refresh_required=cmake_refresh_available,
        cmake_import_command=(None if cmake_import_step is None else cmake_import_step.command),
        up_to_date=(
            not plan.source_changed
            and not plan.graph_invalidation_required
            and plan.authority_error is None
            and not plan.stale_units
        ),
        **next_step_fields(next_step),
    )
    return 0


def command_source_lock(args: argparse.Namespace, output: CLIOutput) -> int:
    root = project_root(args.project)
    plan = plan_source_lock(root, args.path, output, seal=True)
    result = apply_source_lock(
        plan,
        invalidate_producer_graph=args.invalidate_producer_graph,
    )
    from reprobit.project_readiness import inspect_project_readiness

    readiness = inspect_project_readiness(root, check_local_environment=True)
    next_instruction = readiness.next_instruction
    message = f"locked {count_phrase(len(plan.document.entries), 'project source input')}"
    if next_instruction is not None:
        message += f"\nNext: {next_instruction}"
    output.emit(
        "source_locked",
        message,
        output=plan.spec.layout.source_manifest,
        entries=len(plan.document.entries),
        source_manifest_digest=plan.document_digest.value,
        producer_graph_invalidated=plan.graph_invalidation_required,
        next_instruction=next_instruction,
        transaction_id=result.transaction_id,
        **next_step_fields(readiness.next),
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
            **next_step_fields(None),
        )
        return 0
    counts_by_document: dict[str, int] = {}
    for change in plan.changes:
        counts_by_document[change.document] = counts_by_document.get(change.document, 0) + 1
    if args.apply:
        summary = (
            f"Saved source records refreshed: {count_phrase(len(plan.changes), 'update')} saved "
            f"across {count_phrase(len(plan.changed_documents), 'project file')}"
        )
    else:
        summary = (
            f"Source-record preview: {count_phrase(len(plan.changes), 'update')} would be saved "
            f"across {count_phrase(len(plan.changed_documents), 'project file')}"
        )
    lines = [summary]
    visible_documents = sorted(counts_by_document)[:8]
    for document in visible_documents:
        lines.append(f"  {document}: {count_phrase(counts_by_document[document], 'check')}")
    hidden_documents = len(counts_by_document) - len(visible_documents)
    if hidden_documents:
        lines.append(f"  ...and {count_phrase(hidden_documents, 'more project file')}")
    if args.apply:
        try:
            transaction = apply_source_regeneration(root, plan)
        except SourceRegenerationError as exc:
            raise CLIError(f"source regeneration refused: {exc}") from exc
        if transaction is None:
            raise AssertionError("source regeneration applied an empty plan")
        next_step = NextStep(("rbit", "repair", root))
        lines.append(f"Next: {next_step.command}")
        output.emit(
            "source_regenerated",
            "\n".join(lines),
            applied=True,
            changes=rendered_changes,
            documents=list(plan.changed_documents),
            transaction_id=transaction.transaction_id,
            **next_step.fields(),
        )
        return 0
    lines.append("Preview only: no project files changed. Add --apply to save these updates.")
    output.emit(
        "source_regenerated",
        "\n".join(lines),
        applied=False,
        changes=rendered_changes,
        documents=list(plan.changed_documents),
        **next_step_fields(None),
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
        if bundle.source_manifest is None:
            raise CLIError("source export requires a locked source manifest")
        for label, protected in protected_project_paths(
            root,
            bundle.spec,
            source_paths=(entry.path for entry in bundle.source_manifest.entries),
        ):
            if paths_overlap(destination, protected):
                raise CLIError(f"source export destination overlaps {label}: {protected}")
        result = refresh_effective_source_export(bundle, root, destination)
    message = f"Effective source view ready: {destination}"
    if result.cleanup_warning is not None:
        message += f"\nWarning: {result.cleanup_warning}"
    output.emit(
        "source_exported",
        message,
        path=destination,
        interventions=len(result.witnesses),
        cleanup_warning=result.cleanup_warning,
        preserved_paths=result.preserved_paths,
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
        f"validated {bundle.spec.project_id}: "
        f"{count_phrase(len(bundle.spec.targets), 'target')}, "
        f"{count_phrase(len(bundle.interventions), 'intervention')}",
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
        f"(cost model v{result.model_version}, see docs/costs.md)",
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
        known = ", ".join(item.id for item in bundle.interventions) or "none saved"
        raise CLIError(f"unknown intervention: {args.intervention} (known: {known})")
    if args.intervention is None and not selected:
        output.emit("intervention_summary", "No saved interventions.", interventions=0)
        return 0
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
    if args.intervention is None and selected and output.output_format == "text":
        output.emit(
            "hint",
            "hint: rbit explain --intervention ID shows one intervention in full",
            diagnostic=True,
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
                f"(cost model v{result.model_version})"
            )
        ),
        breakdown=result,
    )
    if output.output_format == "text" and bundle.interventions:
        output.emit(
            "hint",
            "hint: rbit explain lists each intervention; --intervention ID shows one in full",
            diagnostic=True,
        )
    return 0


def command_status(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.project_readiness import (
        inspect_project_readiness,
        render_project_readiness,
    )

    root = project_root(args.project)
    readiness = inspect_project_readiness(root, check_local_environment=True)
    output.emit(
        "project_readiness",
        render_project_readiness(readiness, include_ready=args.all),
        ready=readiness.ready,
        completed=readiness.completed,
        total=len(readiness.items),
        next_instruction=readiness.next_instruction,
        **next_step_fields(readiness.next),
        checks=[
            {
                "id": item.id,
                "label": item.label,
                "ready": item.ready,
                "detail": item.detail,
                "next_command": item.next_command,
                "next_argv": item.next_argv,
            }
            for item in readiness.items
        ],
    )
    return 0 if readiness.ready else 1


def command_report(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.report_io import read_report_json, write_report_html

    source = Path(args.input).expanduser().resolve(strict=False)
    if not source.is_file():
        raise CLIError(f"report input is not an existing file: {source}")
    destination = (
        Path(args.html).expanduser().resolve(strict=False)
        if args.html
        else source.with_suffix(".html")
    )
    if paths_alias(source, destination):
        raise CLIError("report HTML output must differ from its canonical JSON input")
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
    "SourceLockPlan",
    "apply_source_lock",
    "cmake_reimport_guidance",
    "command_cost",
    "command_explain",
    "command_init",
    "command_report",
    "command_source_export",
    "command_source_lock",
    "command_source_preview",
    "command_status",
    "command_validate",
    "plan_source_lock",
]
