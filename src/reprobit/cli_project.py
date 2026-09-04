"""CLI commands for project creation, source authority, and inspection."""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reprobit.cli_output import (
    CLIOutput,
    NextStep,
    bounded_items,
    count_phrase,
    next_step_fields,
)
from reprobit.cli_paths import (
    CLIError,
    paths_alias,
    paths_overlap,
    project_root,
    protected_project_paths,
    safe_project_path,
)
from reprobit.costs import CostBreakdown, InterventionCost, calculate_cost
from reprobit.intervention_metadata import classic_recipe_family_label
from reprobit.project_loader import load_project_tree
from reprobit.report_html_format import cost_class_label, human_label
from reprobit.schema import (
    ClassicRecipeIntervention,
    Intervention,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
    ProjectSpec,
    SourceManifestDocument,
    TargetSpec,
    ToolchainRef,
)
from reprobit.source_lock_workflow import (
    ActivityProgress as ActivityProgress,
)
from reprobit.source_lock_workflow import (
    SourceLockPlan as SourceLockPlan,
)
from reprobit.source_lock_workflow import (
    _blocked_source_membership_guidance,
    _cmake_refresh_step,
    _recorded_cmake_recipe,
    _source_selection_step,
)
from reprobit.source_lock_workflow import (
    apply_source_lock as apply_source_lock,
)
from reprobit.source_lock_workflow import (
    cmake_reimport_guidance as cmake_reimport_guidance,
)
from reprobit.source_lock_workflow import (
    plan_source_lock as plan_source_lock,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction


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
        return classic_recipe_family_label(item.family)
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
