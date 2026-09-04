"""Bounded project-wide front end for the existing per-symbol grind engine."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reprobit.classic_orchestration import classic_compiler_translation_unit_authority
from reprobit.classic_project import ClassicProjectError
from reprobit.discovery_contracts import enumerate_declaration_states
from reprobit.discovery_grind import (
    GrindProgress,
    ProjectGrindCallbacks,
    ProjectGrindResult,
    require_single_acceptance,
    run_project_grind,
)
from reprobit.discovery_project import (
    DEFAULT_GRIND_CLASSES,
    DEFAULT_GRIND_FUNCTIONS,
    ProjectGrindPlan,
    discovery_state_root,
)
from reprobit.model import Digest
from reprobit.msvc_discovery_coff import isolated_msvc_function_symbols
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import (
    ClassicRecipeIntervention,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    ProjectBundle,
)
from reprobit.secure_path_contracts import SecurePathError, canonical_relative_path
from reprobit.state import KeepWorkspace, RunArena
from reprobit.strict_json import JsonValue, canonical_json

_MAX_REFERENCE_ENTRIES = 4_096
_MAX_REFERENCE_OBJECTS = 64
MAX_PROJECT_GRIND_SYMBOLS = 64


class ProjectAutoGrindError(RuntimeError):
    """A project-wide grind request is unsafe, ambiguous, or unbounded."""


@dataclass(frozen=True, slots=True)
class ProjectReferenceAssignment:
    translation_unit_id: str
    reference_object: str


@dataclass(frozen=True, slots=True)
class ProjectGrindWorkItem:
    target_id: str
    translation_unit_id: str
    symbol: str
    reference_object: str


@dataclass(frozen=True, slots=True)
class ProjectGrindSkip:
    translation_unit_id: str | None
    reference_object: str | None
    symbol: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ProjectGrindCampaign:
    project_id: str
    eligible_units: int
    reference_objects: int
    discovered_symbols: int
    truncated_symbols: int
    items: tuple[ProjectGrindWorkItem, ...]
    skips: tuple[ProjectGrindSkip, ...]


@dataclass(frozen=True, slots=True)
class ProjectGrindArtifacts:
    """Project-relative diagnostic paths published for one completed symbol."""

    plan: str
    decision_report: str
    cold_verification_json: str | None
    cold_verification_html: str | None


@dataclass(frozen=True, slots=True)
class ProjectGrindOutcome:
    """Compact campaign result that never retains a full cold verification report."""

    item: ProjectGrindWorkItem
    exact: bool
    published: bool
    states: int
    compiler_trials: int
    qualified_candidates: int
    cold_trials: int
    added_cost: int
    transaction_id: str | None
    cold_report_run_id: Digest | None
    artifacts: ProjectGrindArtifacts | None = None
    locally_qualified: bool = False


ProjectGrindOutcomeFinalizer = Callable[
    [int, ProjectGrindWorkItem, ProjectGrindPlan, ProjectGrindResult],
    ProjectGrindArtifacts | None,
]


@dataclass(frozen=True, slots=True)
class ProjectAutoGrindResult:
    campaign: ProjectGrindCampaign
    outcomes: tuple[ProjectGrindOutcome, ...]
    accepted: bool
    accept_progress: bool = False

    @property
    def exact(self) -> int:
        return sum(outcome.exact for outcome in self.outcomes)

    @property
    def qualified(self) -> int:
        return sum(outcome.locally_qualified or outcome.exact for outcome in self.outcomes)

    @property
    def published(self) -> int:
        return sum(outcome.published for outcome in self.outcomes)


@dataclass(frozen=True, slots=True)
class _EligibleUnit:
    unit: ClassicTranslationUnitPlan
    interventions: InterventionDocument


def _portable_relative(value: str, *, label: str) -> str:
    try:
        canonical_relative_path(value)
    except SecurePathError:
        raise ProjectAutoGrindError(f"{label} must be a canonical project-relative path") from None
    return value


def _reference_path(root: Path, relative: str) -> Path:
    relative = _portable_relative(relative, label="reference object")
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise ProjectAutoGrindError(f"reference object is unavailable: {relative!r}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProjectAutoGrindError(f"reference object escapes the project: {relative!r}") from exc
    return resolved


def _eligible_units(bundle: ProjectBundle) -> tuple[_EligibleUnit, ...]:
    if bundle.build_plan is None or bundle.producer_graph is None:
        raise ProjectAutoGrindError("project-wide grind requires a committed producer graph")
    try:
        compiler_authority = classic_compiler_translation_unit_authority(
            bundle,
            bundle.producer_graph,
        )
    except ClassicProjectError as exc:
        raise ProjectAutoGrindError(f"project compiler authority is invalid: {exc}") from exc
    compiler_counts = Counter(unit.id for unit in compiler_authority.values())
    interventions = {
        document.translation_unit_id: document
        for document in bundle.intervention_documents
        if document.translation_unit_id is not None
    }
    proof_counts = Counter(
        document.translation_unit_id
        for document in bundle.proof_documents
        if document.translation_unit_id is not None
    )
    return tuple(
        _EligibleUnit(unit, interventions[unit.id])
        for unit in bundle.build_plan.translation_units
        if compiler_counts[unit.id] == 1 and unit.id in interventions and proof_counts[unit.id] == 1
    )


def _scan_reference_objects(root: Path) -> tuple[str, ...]:
    directory = root / "reference"
    if not directory.exists():
        return ()
    if directory.is_symlink() or not directory.is_dir():
        raise ProjectAutoGrindError("reference must be a real project directory")
    objects: list[str] = []
    for count, path in enumerate(directory.rglob("*"), start=1):
        if count > _MAX_REFERENCE_ENTRIES:
            raise ProjectAutoGrindError(
                "project-wide grind inspects at most "
                f"{_MAX_REFERENCE_ENTRIES} entries beneath reference"
            )
        if path.is_symlink():
            raise ProjectAutoGrindError("reference object directory contains a redirected entry")
        if path.is_file() and path.suffix.casefold() == ".obj":
            objects.append(PurePosixPath(path.relative_to(root).as_posix()).as_posix())
            if len(objects) > _MAX_REFERENCE_OBJECTS:
                raise ProjectAutoGrindError(
                    f"project-wide grind accepts at most {_MAX_REFERENCE_OBJECTS} reference objects"
                )
    return tuple(sorted(objects, key=lambda item: (item.casefold(), item)))


def _reference_assignments(
    root: Path,
    units: tuple[_EligibleUnit, ...],
    assignments: tuple[ProjectReferenceAssignment, ...],
) -> tuple[dict[str, str], tuple[ProjectGrindSkip, ...]]:
    by_id = {item.unit.id.casefold(): item for item in units}
    skips: list[ProjectGrindSkip] = []
    if assignments:
        explicit: dict[str, str] = {}
        for assignment in assignments:
            unit = by_id.get(assignment.translation_unit_id.casefold())
            if unit is None or unit.unit.id != assignment.translation_unit_id:
                raise ProjectAutoGrindError(
                    "--reference-object names an ineligible or unknown translation unit: "
                    f"{assignment.translation_unit_id!r}"
                )
            if unit.unit.id in explicit:
                raise ProjectAutoGrindError(
                    f"translation unit has more than one explicit reference: {unit.unit.id!r}"
                )
            _reference_path(root, assignment.reference_object)
            explicit[unit.unit.id] = assignment.reference_object
        for eligible in units:
            if eligible.unit.id not in explicit:
                skips.append(
                    ProjectGrindSkip(
                        eligible.unit.id,
                        None,
                        None,
                        "no reference object was assigned",
                    )
                )
        return explicit, tuple(skips)

    objects = _scan_reference_objects(root)
    if len(objects) == 1 and len(units) == 1:
        return {units[0].unit.id: objects[0]}, ()
    candidates: dict[str, list[str]] = {item.unit.id: [] for item in units}
    matched_objects: set[str] = set()
    for reference in objects:
        stem = PurePosixPath(reference).stem.casefold()
        matched_units = tuple(
            item
            for item in units
            if item.unit.id.casefold() == stem
            or PurePosixPath(item.unit.source).stem.casefold() == stem
        )
        if len(matched_units) == 1:
            candidates[matched_units[0].unit.id].append(reference)
            matched_objects.add(reference)
        elif len(matched_units) > 1:
            skips.append(
                ProjectGrindSkip(
                    None,
                    reference,
                    None,
                    "reference name matches more than one translation unit; use "
                    "--reference-object TU=PATH",
                )
            )
            matched_objects.add(reference)
    inferred: dict[str, str] = {}
    for eligible in units:
        unit_references = candidates[eligible.unit.id]
        if len(unit_references) == 1:
            inferred[eligible.unit.id] = unit_references[0]
        elif not unit_references:
            skips.append(
                ProjectGrindSkip(
                    eligible.unit.id,
                    None,
                    None,
                    "no reference object matched the translation-unit id or source stem",
                )
            )
        else:
            skips.append(
                ProjectGrindSkip(
                    eligible.unit.id,
                    None,
                    None,
                    "several reference objects matched; use --reference-object TU=PATH",
                )
            )
    for reference in objects:
        if reference not in matched_objects:
            skips.append(
                ProjectGrindSkip(
                    None,
                    reference,
                    None,
                    "reference name did not match a translation-unit id or source stem",
                )
            )
    return inferred, tuple(skips)


def _existing_function_symbols(document: InterventionDocument) -> frozenset[str]:
    return frozenset(
        intervention.scope.function
        for intervention in document.interventions
        if isinstance(
            intervention,
            (ClassicRecipeIntervention, LegacyOracleInstallIntervention),
        )
        and intervention.scope.function is not None
    )


def enumerate_project_grind_campaign(
    project_root: Path,
    *,
    reference_assignments: tuple[ProjectReferenceAssignment, ...] = (),
    max_symbols: int = 8,
) -> ProjectGrindCampaign:
    """Enumerate a deterministic, bounded set of low-cost per-symbol searches."""

    if not 1 <= max_symbols <= MAX_PROJECT_GRIND_SYMBOLS:
        raise ProjectAutoGrindError(
            f"project-wide grind max symbols must be between 1 and {MAX_PROJECT_GRIND_SYMBOLS}"
        )
    root = project_root.resolve(strict=True)
    bundle = load_project_tree(root)
    units = _eligible_units(bundle)
    references, assignment_skips = _reference_assignments(
        root,
        units,
        reference_assignments,
    )
    skips = list(assignment_skips)
    items_by_unit: list[tuple[ProjectGrindWorkItem, ...]] = []
    discovered_symbols = 0
    by_id = {item.unit.id: item for item in units}
    for unit_id, reference in sorted(references.items(), key=lambda item: item[0].casefold()):
        eligible = by_id[unit_id]
        try:
            symbols = isolated_msvc_function_symbols(_reference_path(root, reference).read_bytes())
        except Exception as exc:
            skips.append(
                ProjectGrindSkip(
                    unit_id,
                    reference,
                    None,
                    f"reference object could not be inspected: {exc}",
                )
            )
            continue
        existing = _existing_function_symbols(eligible.interventions)
        available = tuple(
            sorted(
                (symbol for symbol in symbols if symbol not in existing),
                key=lambda item: (item.casefold(), item),
            )
        )
        discovered_symbols += len(available)
        items_by_unit.append(
            tuple(
                ProjectGrindWorkItem(
                    eligible.unit.target_id,
                    unit_id,
                    symbol,
                    reference,
                )
                for symbol in available
            )
        )
        if not available:
            skips.append(
                ProjectGrindSkip(
                    unit_id,
                    reference,
                    None,
                    "reference contains no unclaimed isolated COMDAT functions",
                )
            )
    # Take one function from each TU before returning to the first.  A small
    # global budget therefore samples the project instead of being consumed by
    # whichever translation unit sorts first.
    items = tuple(
        unit_items[index]
        for index in range(max((len(unit_items) for unit_items in items_by_unit), default=0))
        for unit_items in items_by_unit
        if index < len(unit_items)
    )
    truncated = max(0, len(items) - max_symbols)
    return ProjectGrindCampaign(
        project_id=bundle.spec.project_id,
        eligible_units=len(units),
        reference_objects=len(references),
        discovered_symbols=discovered_symbols,
        truncated_symbols=truncated,
        items=items[:max_symbols],
        skips=tuple(skips),
    )


def project_grind_plan(item: ProjectGrindWorkItem) -> ProjectGrindPlan:
    """Return the persisted bounded plan for one campaign work item."""

    return ProjectGrindPlan(
        reference_object=item.reference_object,
        target=item.target_id,
        translation_unit=item.translation_unit_id,
        symbol=item.symbol,
        classes=DEFAULT_GRIND_CLASSES,
        functions=DEFAULT_GRIND_FUNCTIONS,
    )


def _reference_preflight_message(campaign: ProjectGrindCampaign) -> str:
    paired = campaign.reference_objects
    missing = max(0, campaign.eligible_units - paired)
    return (
        f"Reference preflight: {paired} of {campaign.eligible_units} eligible compiler "
        f"steps paired; {missing} missing; {len(campaign.items)} bounded "
        f"function{'s' if len(campaign.items) != 1 else ''} selected"
    )


def _compact_outcome(
    item: ProjectGrindWorkItem,
    result: ProjectGrindResult,
    artifacts: ProjectGrindArtifacts | None,
) -> ProjectGrindOutcome:
    solution = result.solution
    return ProjectGrindOutcome(
        item=item,
        exact=result.exact,
        published=result.published,
        states=result.states,
        compiler_trials=result.compiler_trials,
        qualified_candidates=result.qualified_candidates,
        cold_trials=result.cold_trials,
        added_cost=solution.added_cost if solution is not None else 0,
        transaction_id=result.transaction_id,
        cold_report_run_id=(solution.report.run_id if solution is not None else None),
        artifacts=artifacts,
        locally_qualified=result.locally_qualified,
    )


def run_project_auto_grind(
    project_root: Path,
    *,
    callbacks: ProjectGrindCallbacks,
    reference_assignments: tuple[ProjectReferenceAssignment, ...] = (),
    max_symbols: int = 8,
    accept_exact: bool = False,
    accept_progress: bool = False,
    progress: GrindProgress | None = None,
    finalize_outcome: ProjectGrindOutcomeFinalizer | None = None,
) -> ProjectAutoGrindResult:
    """Run the bounded grind independently for each eligible function.

    Accepted progress is monotonic in a deliberately local sense: every saved
    result adds one previously unhandled function whose compiler-produced body
    matches its project-owned reference object and whose semantic proof passed
    in a cold run.  It never claims that the complete project is exact.
    """

    require_single_acceptance(accept_exact, accept_progress, error=ProjectAutoGrindError)

    root = project_root.resolve(strict=True)
    campaign = enumerate_project_grind_campaign(
        root,
        reference_assignments=reference_assignments,
        max_symbols=max_symbols,
    )
    state_dir = load_project(root).state_dir
    plans = tuple(project_grind_plan(item) for item in campaign.items)
    item_totals = tuple(2 + 3 * len(enumerate_declaration_states(plan.plan)) for plan in plans)
    total = 2 + sum(item_totals)
    completed = 0
    if progress is not None:
        progress(
            completed,
            total,
            "discovery-enumerate",
            _reference_preflight_message(campaign),
            ProgressKind.PHASE_STARTED,
            None,
        )
    completed += 1
    if progress is not None:
        progress(
            completed,
            total,
            "discovery-enumerate",
            "Project discovery scope sealed",
            ProgressKind.UNIT_FINISHED,
            None,
        )

    outcomes: list[ProjectGrindOutcome] = []
    with RunArena(
        discovery_state_root(root, state_dir),
        kind="grind",
        keep=KeepWorkspace.NEVER,
    ) as arena:
        plan_path = arena.path / "plan.json"
        plan_relative = PurePosixPath(plan_path.relative_to(root).as_posix()).as_posix()
        for index, (item, plan, item_total) in enumerate(
            zip(
                campaign.items,
                plans,
                item_totals,
                strict=True,
            ),
            start=1,
        ):
            plan_path.write_bytes(canonical_json(plan))
            item_start = completed

            def item_progress(
                item_completed: int,
                reported_total: int,
                phase: str,
                detail: str,
                kind: ProgressKind,
                reason: str | None,
                *,
                current: ProjectGrindWorkItem = item,
                expected_total: int = item_total,
                offset: int = item_start,
            ) -> None:
                if reported_total != expected_total:
                    raise ProjectAutoGrindError(
                        "per-symbol grind progress differs from its bounded plan"
                    )
                if progress is not None:
                    progress(
                        offset + item_completed,
                        total,
                        phase,
                        f"{current.translation_unit_id} · {current.symbol} · {detail}",
                        kind,
                        reason,
                    )

            detailed_result = run_project_grind(
                root,
                callbacks=callbacks,
                plan_relative=plan_relative,
                accept_exact=accept_exact,
                accept_progress=accept_progress,
                progress=item_progress,
            )
            project_is_exact = detailed_result.exact
            artifacts = (
                finalize_outcome(index, item, plan, detailed_result)
                if finalize_outcome is not None
                else None
            )
            outcomes.append(_compact_outcome(item, detailed_result, artifacts))
            # A cold report can be tens of MiB.  Do not carry the detailed
            # per-symbol result into the next campaign iteration.
            del detailed_result
            completed += item_total
            if project_is_exact:
                remaining = sum(item_totals[index:])
                if remaining and progress is not None:
                    progress(
                        completed + remaining,
                        total,
                        "grind-skip",
                        "Project is exact; remaining function searches are unnecessary",
                        ProgressKind.UNIT_FINISHED,
                        None,
                    )
                completed += remaining
                break

    if completed + 1 != total:
        raise AssertionError("project grind progress differs from its bounded campaign")
    if progress is not None:
        progress(
            total,
            total,
            "grind-finalize",
            "Project-wide bounded search complete",
            ProgressKind.UNIT_FINISHED,
            None,
        )
    compact_outcomes = tuple(outcomes)
    return ProjectAutoGrindResult(
        campaign,
        compact_outcomes,
        any(outcome.published for outcome in compact_outcomes),
        accept_progress,
    )


def project_auto_grind_summary(result: ProjectAutoGrindResult) -> Mapping[str, JsonValue]:
    """Return compact canonical report data without duplicating cold reports."""

    return {
        "schema_version": 1,
        "project_id": result.campaign.project_id,
        "eligible_units": result.campaign.eligible_units,
        "reference_objects": result.campaign.reference_objects,
        "discovered_symbols": result.campaign.discovered_symbols,
        "attempted_symbols": len(result.outcomes),
        "truncated_symbols": result.campaign.truncated_symbols,
        "locally_qualified_symbols": result.qualified,
        "exact_symbols": result.exact,
        "published_symbols": result.published,
        "accepted": result.accepted,
        "accept_progress": result.accept_progress,
        "outcomes": [
            {
                "target": outcome.item.target_id,
                "translation_unit": outcome.item.translation_unit_id,
                "symbol": outcome.item.symbol,
                "reference_object": outcome.item.reference_object,
                "locally_qualified": outcome.locally_qualified,
                "exact": outcome.exact,
                "published": outcome.published,
                "states": outcome.states,
                "qualified_candidates": outcome.qualified_candidates,
                "cold_trials": outcome.cold_trials,
                "added_cost": outcome.added_cost,
                "transaction_id": outcome.transaction_id,
                "cold_report_run_id": (
                    outcome.cold_report_run_id.model_dump(mode="json")
                    if outcome.cold_report_run_id is not None
                    else None
                ),
            }
            for outcome in result.outcomes
        ],
        "skips": [
            {
                "translation_unit": skip.translation_unit_id,
                "reference_object": skip.reference_object,
                "symbol": skip.symbol,
                "reason": skip.reason,
            }
            for skip in result.campaign.skips
        ],
    }


__all__ = [
    "MAX_PROJECT_GRIND_SYMBOLS",
    "ProjectAutoGrindError",
    "ProjectAutoGrindResult",
    "ProjectGrindArtifacts",
    "ProjectGrindCampaign",
    "ProjectGrindOutcome",
    "ProjectGrindOutcomeFinalizer",
    "ProjectGrindSkip",
    "ProjectGrindWorkItem",
    "ProjectReferenceAssignment",
    "enumerate_project_grind_campaign",
    "project_auto_grind_summary",
    "project_grind_plan",
    "run_project_auto_grind",
]
