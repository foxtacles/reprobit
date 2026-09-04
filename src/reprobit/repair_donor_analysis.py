"""Bounded donor repair against one private, non-certifying classic runtime."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from reprobit.classic_donor_retune_candidates import (
    DEFAULT_REPAIR_RETUNE_RADIUS,
    DEFAULT_RETUNE_CANDIDATES,
)
from reprobit.classic_link_layout_repair import ClassicLinkLayoutHint
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    canonical_overlay_operations,
)
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_project_overlay_repair import (
    ClassicProjectOverlayRepair,
    ClassicProjectOverlayRepairResult,
    probe_project_overlay_repair,
)
from reprobit.classic_repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    apply_classic_authority_edits,
)
from reprobit.classic_repair_discovery import (
    DEFAULT_DISCOVERY_CANDIDATES,
    ClassicDiscoveryRepair,
    ClassicDiscoveryResult,
    probe_carrier_discovery,
)
from reprobit.classic_repair_probe import (
    DEFAULT_RETUNE_PROBE_CANDIDATES,
    ClassicDonorRetuneProbeResult,
    ClassicDonorRetuneRepair,
    probe_bounded_donor_retunes,
)
from reprobit.classic_repair_probe_execution import (
    ClassicDonorCompileCache,
    ClassicDonorSourceSeal,
    prepare_donor_probe_source_epoch,
)
from reprobit.classic_repair_session import ClassicRepairRefusal, RepairRefusal
from reprobit.classic_runtime_probe import ClassicDonorProbeProgress, ClassicProbeExecution
from reprobit.cli_build import (
    ExecutionProgress,
    ProjectExecutionOptions,
    prepare_producer_graph_run,
)
from reprobit.cli_environment import resolve_classic_execution_inputs
from reprobit.cli_state import state_root
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project_tree
from reprobit.schema import ProjectBundle, ProjectSpec
from reprobit.state import KeepWorkspace, RunArena

if TYPE_CHECKING:
    from reprobit.classic_runtime_preparation import ClassicProducerGraphPreparedRun

_ProbeResult = TypeVar("_ProbeResult", ClassicDonorRetuneProbeResult, ClassicDiscoveryResult)


@dataclass(frozen=True, slots=True)
class RepairProbeOptions:
    """Project, runtime, and bounded search choices for private repair probes."""

    project: Path
    execution: ProjectExecutionOptions
    retune_radius: int = DEFAULT_REPAIR_RETUNE_RADIUS
    retune_candidates: int = DEFAULT_RETUNE_CANDIDATES
    discovery_candidates: int = DEFAULT_DISCOVERY_CANDIDATES


class ClassicRepairProbeSession:
    """Reuse one private probe runtime until the caller changes project authority."""

    def __init__(self, options: RepairProbeOptions, progress: ExecutionProgress) -> None:
        self._options = options
        self._progress = progress
        self._root: Path | None = None
        self._bundle: ProjectBundle | None = None
        self._operations: Mapping[str, Sequence[Mapping[str, object]]] | None = None
        self._arena: RunArena | None = None
        self._prepared: ClassicProducerGraphPreparedRun | None = None
        self._clean_sources: dict[str, bytes] | None = None
        self._effective_sources: dict[str, bytes] | None = None
        self._source_seal: ClassicDonorSourceSeal | None = None
        self._wave = 0

    def __enter__(self) -> ClassicRepairProbeSession:
        return self

    def __exit__(self, error_type: object, error: object, traceback: object) -> Literal[False]:
        del error_type, traceback
        if error is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException as cleanup_error:
                if isinstance(error, BaseException):
                    error.add_note(f"classic donor repair cleanup also failed: {cleanup_error}")
        return False

    def _prepare(self, kind: str) -> bool:
        if self._prepared is not None:
            if not self._prepared.producer.is_open:
                raise ClassicProjectError("classic repair probe session is already closed")
            return False
        root = self._options.project
        bundle = load_project_tree(root)
        arena = RunArena(
            state_root(root, bundle.spec),
            kind=kind,
            keep=KeepWorkspace.NEVER,
        )
        arena.__enter__()
        prepared: ClassicProducerGraphPreparedRun | None = None
        try:
            with self._progress.activity(
                "preparing the repair search",
                phase="repair-probe-prepare",
            ):
                execution = resolve_classic_execution_inputs(
                    profile=bundle.spec.toolchain.profile,
                    explicit_toolchain_root=self._options.execution.toolchain_root,
                    backend=self._options.execution.backend,
                    compiler_transport=self._options.execution.compiler_transport,
                    resource_transport=self._options.execution.resource_transport,
                )
                prepared = prepare_producer_graph_run(
                    self._options.execution,
                    bundle,
                    project_root=root,
                    session_root=arena.path / "classic",
                    execution=execution,
                    progress=_ignore_preparation_progress,
                )
            prepared.producer.begin_developer()
            source_seal = prepare_donor_probe_source_epoch(prepared.probes)
            clean, effective = _source_payloads(
                root,
                bundle,
                effective_root=prepared.probes.effective_root,
                overlay_outputs=prepared.donors.overlay_effective_outputs,
            )
        except BaseException as original:
            if prepared is not None and prepared.producer.is_open:
                try:
                    prepared.close()
                except BaseException as cleanup_error:
                    original.add_note(f"classic donor repair cleanup also failed: {cleanup_error}")
            try:
                arena.__exit__(type(original), original, original.__traceback__)
            except BaseException as cleanup_error:
                original.add_note(f"classic repair arena cleanup also failed: {cleanup_error}")
            raise
        assert prepared is not None
        self._root = root
        self._bundle = bundle
        self._operations = canonical_overlay_operations(bundle)
        self._arena = arena
        self._prepared = prepared
        self._clean_sources = clean
        self._effective_sources = effective
        self._source_seal = source_seal
        return True

    def probe(
        self,
        refusals: tuple[RepairRefusal, ...],
        *,
        kind: str,
        activity: str,
        run: Callable[
            [
                ClassicProbeExecution,
                tuple[RepairRefusal, ...],
                Mapping[str, bytes],
                Mapping[str, bytes],
                Mapping[str, Sequence[Mapping[str, object]]],
                ClassicDonorProbeProgress,
                ClassicDonorSourceSeal,
                str,
            ],
            _ProbeResult,
        ],
    ) -> _ProbeResult:
        fresh = self._prepare(kind)
        assert self._root is not None
        assert self._bundle is not None
        assert self._operations is not None
        assert self._prepared is not None
        assert self._clean_sources is not None
        assert self._effective_sources is not None
        assert self._source_seal is not None
        if not fresh:
            current_clean, current_effective = _source_payloads(
                self._root,
                self._bundle,
                effective_root=self._prepared.probes.effective_root,
                overlay_outputs=self._prepared.donors.overlay_effective_outputs,
            )
            if current_clean != self._clean_sources or current_effective != self._effective_sources:
                raise ClassicProjectError("classic repair probe source authority changed")
        bound_refusals = _bind_refusals_to_probe_units(
            refusals,
            self._prepared.probes.units,
        )
        self._wave += 1
        namespace_id = f"noncertifying-donor-repair-probe.{self._wave:04d}"
        with self._progress.producer_activity(activity) as progress:

            def report_candidate(completed: int, total: int, donor_id: str) -> None:
                progress(
                    completed,
                    total,
                    "repair-probe",
                    donor_id,
                    ProgressKind.UNIT_FINISHED,
                    None,
                )

            result = run(
                self._prepared.probes,
                bound_refusals,
                self._clean_sources,
                self._effective_sources,
                self._operations,
                report_candidate,
                self._source_seal,
                namespace_id,
            )
        return result

    def close(self) -> None:
        prepared = self._prepared
        arena = self._arena
        self._prepared = None
        self._arena = None
        cleanup_error: BaseException | None = None
        try:
            if prepared is not None and prepared.producer.is_open:
                prepared.close()
        except BaseException as error:
            cleanup_error = error
        try:
            if arena is not None:
                arena.__exit__(None, None, None)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
            else:
                cleanup_error.add_note(f"classic repair arena cleanup also failed: {error}")
        if cleanup_error is not None:
            raise cleanup_error


def _ignore_preparation_progress(
    completed: int,
    total: int,
    phase: str,
    node_id: str,
    kind: ProgressKind,
    reason: str | None,
) -> None:
    del completed, total, phase, node_id, kind, reason


def _source_payloads(
    root: Path,
    bundle: ProjectBundle,
    *,
    effective_root: Path,
    overlay_outputs: Mapping[str, bytes],
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    manifest = bundle.source_manifest
    if manifest is None:
        raise ClassicProjectError("classic donor repair requires committed source authority")
    clean = {
        entry.path: root.joinpath(*PurePosixPath(entry.path).parts).read_bytes()
        for entry in manifest.entries
    }
    effective = {
        entry.path: effective_root.joinpath(*PurePosixPath(entry.path).parts).read_bytes()
        for entry in manifest.entries
    }
    effective.update(overlay_outputs)
    return clean, effective


def _bind_refusals_to_probe_units(
    refusals: Sequence[RepairRefusal],
    units: Sequence[ClassicPreparedUnit],
) -> tuple[RepairRefusal, ...]:
    """Bind captured fallout to freshly prepared, identical TU authority."""

    by_id: dict[str, ClassicPreparedUnit] = {}
    for unit in units:
        unit_id = unit.plan.id
        if unit_id in by_id:
            raise ClassicProjectError(
                f"classic donor repair prepared translation unit {unit_id!r} more than once"
            )
        by_id[unit_id] = unit

    bound: list[RepairRefusal] = []
    for refusal in refusals:
        fresh = by_id.get(refusal.unit_id)
        if fresh is None:
            raise ClassicProjectError(
                "classic donor repair cannot find freshly prepared translation unit "
                f"{refusal.unit_id!r}"
            )
        if isinstance(refusal, ClassicRepairRefusal) and refusal.synthetic:
            # A census entry carries a placeholder unit: it binds to the fresh
            # authority of its translation unit by id alone, and has no saved
            # action or receipt to match.
            if refusal.unit.plan.id != refusal.unit_id or fresh.plan.id != refusal.unit_id:
                raise ClassicProjectError(
                    "classic census entry does not name its freshly prepared translation "
                    f"unit {refusal.unit_id!r}"
                )
            bound.append(replace(refusal, unit=fresh))
            continue
        if refusal.unit.plan.id != refusal.unit_id or refusal.unit != fresh:
            # Prepared units contain canonical logical paths and byte payloads. Physical
            # run roots live on ClassicProbeExecution, so there are no ephemeral unit
            # fields to normalize or ignore here.
            raise ClassicProjectError(
                "classic donor repair analysis no longer matches freshly prepared "
                f"translation unit {refusal.unit_id!r}"
            )
        if (
            refusal.action_index < 0
            or refusal.action_index >= len(fresh.actions)
            or fresh.actions[refusal.action_index] != refusal.intervention
        ):
            raise ClassicProjectError(
                "classic donor repair refusal does not match its freshly prepared action "
                f"in translation unit {refusal.unit_id!r}"
            )
        matching_receipts = tuple(
            receipt
            for receipt in fresh.receipts
            if receipt.intervention_id == refusal.intervention.id
        )
        if matching_receipts != (refusal.receipt,):
            raise ClassicProjectError(
                "classic donor repair refusal does not match its freshly prepared receipt "
                f"in translation unit {refusal.unit_id!r}"
            )
        bound.append(replace(refusal, unit=fresh))
    return tuple(bound)


def probe_classic_donor_repairs(
    options: RepairProbeOptions,
    progress: ExecutionProgress,
    refusals: tuple[RepairRefusal, ...],
    *,
    candidate_budget: int = DEFAULT_RETUNE_PROBE_CANDIDATES,
    abandoned_states: Mapping[tuple[str, str], frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
    excluded_groups: frozenset[tuple[str, str]] = frozenset(),
    session: ClassicRepairProbeSession | None = None,
) -> ClassicDonorRetuneProbeResult:
    """Search bounded donor retunes without issuing evidence or publishing authority.

    The explicit radius and per-donor limit may widen the bounded search; the
    command-wide candidate budget still caps total compilation.
    """

    if not refusals:
        return ClassicDonorRetuneProbeResult((), (), 0)
    radius = options.retune_radius
    limit = options.retune_candidates

    def run(
        probes: ClassicProbeExecution,
        bound: tuple[RepairRefusal, ...],
        clean: Mapping[str, bytes],
        effective: Mapping[str, bytes],
        operations: Mapping[str, Sequence[Mapping[str, object]]],
        progress: ClassicDonorProbeProgress,
        source_seal: ClassicDonorSourceSeal,
        namespace_id: str,
    ) -> ClassicDonorRetuneProbeResult:
        return probe_bounded_donor_retunes(
            probes,
            bound,
            clean_sources=clean,
            effective_sources=effective,
            canonical_overlay_operations=operations,
            radius=radius,
            limit=limit,
            candidate_budget=candidate_budget,
            progress=progress,
            abandoned_states=abandoned_states,
            compile_cache=compile_cache,
            excluded_groups=excluded_groups,
            close_runtime=False,
            materialize_source_epoch=False,
            source_seal=source_seal,
            namespace_id=namespace_id,
        )

    return _probe_with_runtime(
        options,
        progress,
        refusals,
        kind="repairprobe",
        activity="trying nearby compiler choices (the shown total is an upper bound)",
        run=run,
        session=session,
    )


def probe_classic_carrier_discovery(
    options: RepairProbeOptions,
    progress: ExecutionProgress,
    refusals: tuple[ClassicRepairRefusal, ...],
    *,
    candidate_budget: int,
    tried_states: Mapping[str, frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
    session: ClassicRepairProbeSession | None = None,
) -> ClassicDiscoveryResult:
    """Compile fresh carrier states for units whose donors cannot be retuned further.

    The per-unit option bounds shapes tried per unit; the command-wide
    ``candidate_budget`` still caps the total.
    """

    if not refusals or candidate_budget < 1:
        return ClassicDiscoveryResult((), (), 0)
    per_unit = options.discovery_candidates

    def run(
        probes: ClassicProbeExecution,
        bound: tuple[RepairRefusal, ...],
        clean: Mapping[str, bytes],
        effective: Mapping[str, bytes],
        _operations: Mapping[str, Sequence[Mapping[str, object]]],
        progress: ClassicDonorProbeProgress,
        source_seal: ClassicDonorSourceSeal,
        namespace_id: str,
    ) -> ClassicDiscoveryResult:
        if any(not isinstance(item, ClassicRepairRefusal) for item in bound):
            raise ClassicProjectError("carrier discovery cannot replace a legacy action")
        return probe_carrier_discovery(
            probes,
            cast(tuple[ClassicRepairRefusal, ...], bound),
            clean_sources=clean,
            effective_sources=effective,
            per_unit=per_unit,
            candidate_budget=candidate_budget,
            progress=progress,
            tried_states=tried_states,
            compile_cache=compile_cache,
            close_runtime=False,
            materialize_source_epoch=False,
            source_seal=source_seal,
            namespace_id=namespace_id,
        )

    return _probe_with_runtime(
        options,
        progress,
        refusals,
        kind="discoveryprobe",
        activity="trying fresh compiler choices (the shown total is an upper bound)",
        run=run,
        session=session,
    )


def probe_classic_project_overlay_repairs(
    options: RepairProbeOptions,
    progress: ExecutionProgress,
    *,
    candidate_budget: int,
    settle_target_ids: frozenset[str] = frozenset(),
    link_layout_hint: ClassicLinkLayoutHint | None = None,
) -> ClassicProjectOverlayRepairResult:
    """Check the dual source epoch and try bounded inert layout adjustments."""

    root = options.project
    bundle = load_project_tree(root)
    arena = RunArena(
        state_root(root, bundle.spec),
        kind="sourceprobe",
        keep=KeepWorkspace.NEVER,
    )
    with arena:
        with progress.activity(
            "preparing the source-layout check",
            phase="repair-source-prepare",
        ):
            execution = resolve_classic_execution_inputs(
                profile=bundle.spec.toolchain.profile,
                explicit_toolchain_root=options.execution.toolchain_root,
                backend=options.execution.backend,
                compiler_transport=options.execution.compiler_transport,
                resource_transport=options.execution.resource_transport,
            )
            prepared = prepare_producer_graph_run(
                options.execution,
                bundle,
                project_root=root,
                session_root=arena.path / "classic",
                execution=execution,
                progress=_ignore_preparation_progress,
            )
        clean_sources = {
            entry.path: root.joinpath(*PurePosixPath(entry.path).parts).read_bytes()
            for entry in (bundle.source_manifest.entries if bundle.source_manifest else ())
        }
        try:
            with progress.producer_activity(
                "checking nearby source layouts (the shown total is an upper bound)"
            ) as report_progress:

                def report_candidate(completed: int, total: int, candidate_id: str) -> None:
                    report_progress(
                        completed,
                        total,
                        "repair-source-probe",
                        candidate_id,
                        ProgressKind.UNIT_FINISHED,
                        None,
                    )

                result = probe_project_overlay_repair(
                    prepared.probes,
                    bundle,
                    clean_sources=clean_sources,
                    candidate_budget=candidate_budget,
                    radius=options.retune_radius,
                    candidate_limit=options.retune_candidates,
                    settle_target_ids=settle_target_ids,
                    link_layout_hint=link_layout_hint,
                    progress=report_candidate,
                )
        except BaseException as original:
            if prepared.producer.is_open:
                try:
                    prepared.close()
                except BaseException as cleanup_error:
                    original.add_note(
                        f"classic source-layout repair cleanup also failed: {cleanup_error}"
                    )
            raise
        if prepared.producer.is_open:
            prepared.close()
        return result


def _probe_with_runtime(
    options: RepairProbeOptions,
    progress: ExecutionProgress,
    refusals: tuple[RepairRefusal, ...],
    *,
    kind: str,
    activity: str,
    run: Callable[
        [
            ClassicProbeExecution,
            tuple[RepairRefusal, ...],
            Mapping[str, bytes],
            Mapping[str, bytes],
            Mapping[str, Sequence[Mapping[str, object]]],
            ClassicDonorProbeProgress,
            ClassicDonorSourceSeal,
            str,
        ],
        _ProbeResult,
    ],
    session: ClassicRepairProbeSession | None = None,
) -> _ProbeResult:
    """Run one probe, optionally sharing its private runtime with later probes."""

    if session is not None:
        return session.probe(refusals, kind=kind, activity=activity, run=run)
    with ClassicRepairProbeSession(options, progress) as owned:
        return owned.probe(refusals, kind=kind, activity=activity, run=run)


def apply_classic_discovery_repairs(
    root: Path,
    spec: ProjectSpec,
    repairs: Sequence[ClassicDiscoveryRepair],
) -> tuple[str, ...]:
    """Apply discovered-carrier repairs (new donors, re-authored and re-pointed records) at once."""

    repair_tuple = tuple(repairs)
    if not repair_tuple:
        return ()
    return apply_classic_authority_edits(
        root,
        spec,
        interventions=tuple(e for r in repair_tuple for e in r.intervention_edits),
        receipts=tuple(e for r in repair_tuple for e in r.receipt_edits),
        additions=tuple(a for r in repair_tuple for a in r.additions),
        dependencies=tuple(d for r in repair_tuple for d in r.dependency_edits),
    )


def apply_classic_donor_repairs(
    root: Path,
    spec: ProjectSpec,
    repairs: Sequence[ClassicDonorRetuneRepair],
) -> tuple[str, ...]:
    """Apply successful typed donor-retune edits as one authority transaction."""

    repair_tuple = tuple(repairs)
    if not repair_tuple:
        return ()
    interventions: tuple[ClassicInterventionEdit, ...] = tuple(
        edit for repair in repair_tuple for edit in repair.intervention_edits
    )
    receipts: tuple[ClassicReceiptEdit, ...] = tuple(
        edit for repair in repair_tuple for edit in repair.receipt_edits
    )
    return apply_classic_authority_edits(
        root,
        spec,
        interventions=interventions,
        receipts=receipts,
        additions=tuple(item for repair in repair_tuple for item in repair.additions),
    )


def apply_classic_project_overlay_repair(
    root: Path,
    spec: ProjectSpec,
    repair: ClassicProjectOverlayRepair,
) -> tuple[str, ...]:
    """Publish one compiler-proven source-layout edit through typed CAS."""

    return apply_classic_authority_edits(
        root,
        spec,
        project_overlays=(repair.edit,),
    )


__all__ = [
    "RepairProbeOptions",
    "apply_classic_discovery_repairs",
    "apply_classic_donor_repairs",
    "apply_classic_project_overlay_repair",
    "probe_classic_carrier_discovery",
    "probe_classic_donor_repairs",
    "probe_classic_project_overlay_repairs",
]
