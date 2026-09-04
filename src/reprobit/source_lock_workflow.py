"""Source selection, authority inspection, and atomic source-lock publication."""

from __future__ import annotations

from collections.abc import Callable, Sequence
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
    NextStep,
    human_command,
)
from reprobit.cli_paths import (
    CLIError,
    relative_output,
    safe_project_path,
)
from reprobit.model import Digest
from reprobit.producer_graph import (
    CMakeImportRecipe,
    producer_graph_accepts_source,
    read_producer_graph,
)
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import (
    BuildPlanDocument,
    ProjectSpec,
    SourceManifestDocument,
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


__all__ = ["SourceLockPlan", "apply_source_lock", "cmake_reimport_guidance", "plan_source_lock"]
