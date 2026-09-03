"""Bounded donor repair against one private, non-certifying classic runtime."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import TypeVar

from reprobit.classic_donor_retune_candidates import (
    DEFAULT_REPAIR_RETUNE_RADIUS,
    DEFAULT_RETUNE_CANDIDATES,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    canonical_overlay_operations,
)
from reprobit.classic_project import ClassicProjectError
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
from reprobit.classic_repair_probe_execution import ClassicDonorCompileCache
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.classic_runtime_probe import ClassicDonorProbeProgress, ClassicProbeExecution
from reprobit.cli_build import prepare_producer_graph_run
from reprobit.cli_environment import (
    resolve_classic_execution_inputs,
    selected_backend,
)
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import project_root
from reprobit.cli_state import state_root
from reprobit.progress import ProgressKind
from reprobit.project_loader import load_project_tree
from reprobit.schema import ProjectBundle, ProjectSpec
from reprobit.state import KeepWorkspace, RunArena

_ProbeResult = TypeVar("_ProbeResult", ClassicDonorRetuneProbeResult, ClassicDiscoveryResult)


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
    refusals: Sequence[ClassicRepairRefusal],
    units: Sequence[ClassicPreparedUnit],
) -> tuple[ClassicRepairRefusal, ...]:
    """Bind captured fallout to freshly prepared, identical TU authority."""

    by_id: dict[str, ClassicPreparedUnit] = {}
    for unit in units:
        unit_id = unit.plan.id
        if unit_id in by_id:
            raise ClassicProjectError(
                f"classic donor repair prepared translation unit {unit_id!r} more than once"
            )
        by_id[unit_id] = unit

    bound: list[ClassicRepairRefusal] = []
    for refusal in refusals:
        fresh = by_id.get(refusal.unit_id)
        if fresh is None:
            raise ClassicProjectError(
                "classic donor repair cannot find freshly prepared translation unit "
                f"{refusal.unit_id!r}"
            )
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
    args: argparse.Namespace,
    output: CLIOutput,
    refusals: tuple[ClassicRepairRefusal, ...],
    *,
    candidate_budget: int = DEFAULT_RETUNE_PROBE_CANDIDATES,
    abandoned_states: Mapping[tuple[str, str], frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
) -> ClassicDonorRetuneProbeResult:
    """Search bounded donor retunes without issuing evidence or publishing authority.

    ``args.retune_radius`` and ``args.retune_candidates`` (per donor) widen the
    bounded search when the command line asks for it; their defaults are the
    probe's own.
    """

    if not refusals:
        return ClassicDonorRetuneProbeResult((), (), 0)
    radius = getattr(args, "retune_radius", None) or DEFAULT_REPAIR_RETUNE_RADIUS
    limit = getattr(args, "retune_candidates", None) or DEFAULT_RETUNE_CANDIDATES

    def run(
        probes: ClassicProbeExecution,
        bound: tuple[ClassicRepairRefusal, ...],
        clean: Mapping[str, bytes],
        effective: Mapping[str, bytes],
        operations: Mapping[str, Sequence[Mapping[str, object]]],
        progress: ClassicDonorProbeProgress,
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
        )

    return _probe_with_runtime(
        args,
        output,
        refusals,
        kind="repairprobe",
        activity="trying nearby donor settings (the shown total is an upper bound)",
        run=run,
    )


def probe_classic_carrier_discovery(
    args: argparse.Namespace,
    output: CLIOutput,
    refusals: tuple[ClassicRepairRefusal, ...],
    *,
    candidate_budget: int,
    tried_states: Mapping[str, frozenset[str]] | None = None,
    compile_cache: ClassicDonorCompileCache | None = None,
) -> ClassicDiscoveryResult:
    """Compile fresh carrier states for units whose donors cannot be retuned further.

    ``args.discovery_candidates`` bounds the shapes tried per unit; the
    command-wide ``candidate_budget`` still caps the total.
    """

    if not refusals or candidate_budget < 1:
        return ClassicDiscoveryResult((), (), 0)
    per_unit = getattr(args, "discovery_candidates", None) or DEFAULT_DISCOVERY_CANDIDATES

    def run(
        probes: ClassicProbeExecution,
        bound: tuple[ClassicRepairRefusal, ...],
        clean: Mapping[str, bytes],
        effective: Mapping[str, bytes],
        _operations: Mapping[str, Sequence[Mapping[str, object]]],
        progress: ClassicDonorProbeProgress,
    ) -> ClassicDiscoveryResult:
        return probe_carrier_discovery(
            probes,
            bound,
            clean_sources=clean,
            effective_sources=effective,
            per_unit=per_unit,
            candidate_budget=candidate_budget,
            progress=progress,
            tried_states=tried_states,
            compile_cache=compile_cache,
        )

    return _probe_with_runtime(
        args,
        output,
        refusals,
        kind="discoveryprobe",
        activity="trying fresh carrier states (the shown total is an upper bound)",
        run=run,
    )


def _probe_with_runtime(
    args: argparse.Namespace,
    output: CLIOutput,
    refusals: tuple[ClassicRepairRefusal, ...],
    *,
    kind: str,
    activity: str,
    run: Callable[
        [
            ClassicProbeExecution,
            tuple[ClassicRepairRefusal, ...],
            Mapping[str, bytes],
            Mapping[str, bytes],
            Mapping[str, Sequence[Mapping[str, object]]],
            ClassicDonorProbeProgress,
        ],
        _ProbeResult,
    ],
) -> _ProbeResult:
    """Prepare one non-certifying probe runtime, bind the refusals to it, and run ``run``."""

    root = project_root(args.project)
    bundle = load_project_tree(root)
    operations = canonical_overlay_operations(bundle)
    arena = RunArena(
        state_root(root, bundle.spec),
        kind=kind,
        keep=KeepWorkspace.NEVER,
    )
    with arena:
        with output.activity(
            "preparing a safe donor search",
            phase="repair-probe-prepare",
        ):
            execution = resolve_classic_execution_inputs(
                profile=bundle.spec.toolchain.profile,
                explicit_toolchain_root=args.toolchain_root,
                backend=selected_backend(args),
                compiler_transport=args.compiler_transport,
                resource_transport=args.resource_transport,
            )
            prepared = prepare_producer_graph_run(
                args,
                bundle,
                project_root=root,
                session_root=arena.path / "classic",
                execution=execution,
                progress=_ignore_preparation_progress,
            )

        try:
            bound_refusals = _bind_refusals_to_probe_units(
                refusals,
                prepared.probes.units,
            )
            clean_sources, effective_sources = _source_payloads(
                root,
                bundle,
                effective_root=prepared.probes.effective_root,
                overlay_outputs=prepared.donors.overlay_effective_outputs,
            )
            with output.producer_activity(activity) as progress:

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
                    prepared.probes,
                    bound_refusals,
                    clean_sources,
                    effective_sources,
                    operations,
                    report_candidate,
                )
        except BaseException as original:
            if prepared.producer.is_open:
                try:
                    prepared.close()
                except BaseException as cleanup_error:
                    original.add_note(f"classic donor repair cleanup also failed: {cleanup_error}")
            raise
        # Current probes close their runtime when they consume it. Checking the
        # live producer is the durable contract: it also covers no-candidate
        # results and future probes that choose to leave cleanup to this owner.
        if prepared.producer.is_open:
            prepared.close()
        return result


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
    )


__all__ = [
    "apply_classic_discovery_repairs",
    "apply_classic_donor_repairs",
    "probe_classic_carrier_discovery",
    "probe_classic_donor_repairs",
]
