"""Execute, account for, and publish one prepared classic incremental plan."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import replace
from functools import partial
from pathlib import Path
from time import monotonic
from types import MappingProxyType

import reprobit.classic_incremental_context as warm_context
from reprobit.cache import CacheOutput, IncrementalCache
from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    ClassicIncrementalPlan,
    ClassicIncrementalResult,
    read_payload,
)
from reprobit.classic_publication import (
    ClassicPublicationError,
    ClassicPublicationRequest,
    publish_classic_output_set,
)
from reprobit.execution import BuildExecutionReceipt, FileReceipt
from reprobit.incremental import (
    producer_cache_implementation,
    revalidate_producer_implementation,
)
from reprobit.incremental_executor import (
    IncrementalDAGExecutor,
    IncrementalProgress,
    IncrementalProgressEventKind,
)


def execute_classic_incremental_plan(
    plan: ClassicIncrementalPlan,
) -> ClassicIncrementalResult:
    analysis_nodes = plan.analysis_nodes
    analysis_pdb_relatives = plan.analysis_pdb_relatives
    bundle = plan.bundle
    census = plan.census
    compiler_states = plan.compiler_states
    implementation_receipt = plan.implementation_receipt
    jobs = plan.jobs
    nodes = plan.nodes
    progress = plan.progress
    project_root = plan.project_root
    runtime_holder = plan.runtime_holder
    session_root = plan.session_root
    started = plan.started
    state_root = plan.state_root
    terminal_nodes = plan.terminal_nodes
    transform_states = plan.transform_states
    runtime_factory = partial(warm_context.runtime_factory, plan)
    cache = IncrementalCache(
        state_root,
        implementation=producer_cache_implementation(implementation_receipt),
    )

    def runtime_count() -> int:
        runtime = runtime_holder.get("runtime")
        return runtime.initialized_runtime_count if runtime is not None else 0

    def before_record_publication() -> None:
        # This is the single complete invocation census at the cache trust
        # boundary.  Node hooks validate only their exact sampled closure;
        # editable-install code/asset drift is checked once after the runtime
        # namespace closes and before any record name becomes reusable.
        census.validate_all()
        revalidate_producer_implementation(implementation_receipt)

    executor_progress: IncrementalProgress | None
    if progress is not None:

        def report_executor_progress(
            kind: IncrementalProgressEventKind,
            completed: int,
            total: int,
            phase: str,
            node_id: str,
            reason: str | None,
        ) -> None:
            progress(kind, completed, total + 1, phase, node_id, reason)

        executor_progress = report_executor_progress
    else:
        executor_progress = None

    execution = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=session_root,
        runtime_factory=runtime_factory,
        runtime_close=lambda runtime: runtime.close(),
        max_workers=jobs,
        progress=executor_progress,
        runtime_init_count=runtime_count,
        before_publish=before_record_publication,
    ).execute(tuple(nodes))

    # Only complete, re-resolvable compiler traces enter bounded base history.
    with cache.lease() as lease:
        for node_id, compiler_state in compiler_states.items():
            outcome = execution.outcomes[node_id]
            # A hit is already present in this bounded recency index.  Rewriting
            # it on every no-change build adds mutable cache traffic without
            # improving lookup quality.
            if (
                outcome.cache_hit
                or compiler_state.hint is None
                or compiler_state.replay_failure is not None
            ):
                continue
            lease.index_record(
                "producer",
                "compiler-base",
                compiler_state.base_key,
                outcome.record,
            )
        for node_id, transform_state_value in transform_states.items():
            outcome = execution.outcomes[node_id]
            if (
                outcome.cache_hit
                or transform_state_value.hint is None
                or transform_state_value.replay_failure is not None
            ):
                continue
            lease.index_record(
                "producer",
                "donor-transform-base",
                transform_state_value.base_key,
                outcome.record,
            )

    invalidations = dict(execution.summary.invalidations)
    for node_id, compiler_state in compiler_states.items():
        if compiler_state.replay_failure is not None:
            invalidations[node_id] = (
                "dependency replay unusable; compiler result was not indexed or reusable: "
                + compiler_state.replay_failure
            )
    for node_id, transform_state_value in transform_states.items():
        if transform_state_value.replay_failure is not None:
            invalidations[node_id] = (
                "projected donor dependency replay unusable; transform result was "
                "not indexed or reusable: " + transform_state_value.replay_failure
            )
    summary = replace(
        execution.summary,
        invalidations=tuple(sorted(invalidations.items(), key=lambda item: item[0].casefold())),
    )

    # The mutable staging workspace is transport only.  Re-materialize each
    # terminal artifact from its immutable record into a fresh publication
    # seat, and bind the subsequent target payload to that exact receipt.
    publication_root = session_root / "publication"
    publication_root.mkdir()
    immutable_terminals: dict[str, tuple[Path, CacheOutput]] = {}
    immutable_analysis: dict[str, Mapping[str, tuple[Path, CacheOutput]]] = {}
    with cache.lease() as lease:
        for target in bundle.spec.targets:
            terminal_id = terminal_nodes[target.id]
            record = execution.outcomes[terminal_id].record
            outputs_by_name = {item.name: item for item in record.outputs}
            if set(outputs_by_name) != {"artifact"}:
                raise ClassicIncrementalError(
                    f"warm terminal {target.id!r} record has an invalid output set"
                )
            destination = publication_root / target.id / "artifact"
            restored_outputs = lease.restore_selected(
                record,
                {"artifact": destination},
                allowed_root=session_root,
            )
            expected = outputs_by_name["artifact"]
            received = restored_outputs["artifact"]
            if (
                received.digest.value != expected.digest
                or received.size != expected.size
                or bool(received.mode & stat.S_IXUSR) != expected.executable
            ):
                raise ClassicIncrementalError(
                    f"warm terminal {target.id!r} restore differs from its cache receipt"
                )
            immutable_terminals[target.id] = (destination, expected)
            selected_analysis_id = analysis_nodes.get(target.id)
            if selected_analysis_id is None:
                continue
            analysis_record = execution.outcomes[selected_analysis_id].record
            analysis_outputs = {item.name: item for item in analysis_record.outputs}
            if set(analysis_outputs) != {"image", "pdb"}:
                raise ClassicIncrementalError(
                    f"warm analysis relink {target.id!r} record has an invalid output set"
                )
            destinations = {
                "image": publication_root / target.id / "analysis-image",
                "pdb": publication_root / target.id / "analysis-pdb",
            }
            restored_analysis = lease.restore_selected(
                analysis_record,
                destinations,
                allowed_root=session_root,
            )
            received_analysis: dict[str, tuple[Path, CacheOutput]] = {}
            for name, destination in destinations.items():
                expected_analysis = analysis_outputs[name]
                received = restored_analysis[name]
                if (
                    expected_analysis.size == 0
                    or received.digest.value != expected_analysis.digest
                    or received.size != expected_analysis.size
                    or bool(received.mode & stat.S_IXUSR) != expected_analysis.executable
                ):
                    raise ClassicIncrementalError(
                        f"warm analysis relink {target.id!r} {name} restore differs "
                        "from its cache receipt"
                    )
                received_analysis[name] = (destination, expected_analysis)
            immutable_analysis[target.id] = MappingProxyType(received_analysis)

    publication_requests: list[ClassicPublicationRequest] = []

    def publication_request(
        *,
        target_id: str,
        kind: str,
        producer_node_id: str,
        relative: str,
        staged: Path,
        expected: CacheOutput,
    ) -> ClassicPublicationRequest:
        payload, staged_snapshot = read_payload(staged)
        if (
            staged_snapshot.digest.value != expected.digest
            or staged_snapshot.size != expected.size
            or bool(staged_snapshot.mode & stat.S_IXUSR) != expected.executable
        ):
            raise ClassicIncrementalError(
                f"warm {kind} {target_id!r} changed after immutable restore"
            )
        return ClassicPublicationRequest(
            owner_id=target_id,
            kind=kind,
            producer_step=producer_node_id,
            relative=relative,
            payload=payload,
            mode=stat.S_IMODE(staged_snapshot.mode) if os.name == "posix" else None,
            windows_attributes=(staged_snapshot.windows_attributes if os.name == "nt" else None),
        )

    for target in bundle.spec.targets:
        staged, expected_terminal = immutable_terminals[target.id]
        publication_requests.append(
            publication_request(
                target_id=target.id,
                kind="target",
                producer_node_id=terminal_nodes[target.id],
                relative=target.artifact,
                staged=staged,
                expected=expected_terminal,
            )
        )
        if target.id in immutable_analysis:
            analysis_pdb, expected_pdb = immutable_analysis[target.id]["pdb"]
            publication_requests.append(
                publication_request(
                    target_id=target.id,
                    kind="analysis PDB",
                    producer_node_id=analysis_nodes[target.id],
                    relative=analysis_pdb_relatives[target.id],
                    staged=analysis_pdb,
                    expected=expected_pdb,
                )
            )

    def before_target_publication() -> None:
        census.validate_all()
        if execution.summary.misses == 0:
            # Misses revalidate the installed implementation immediately
            # before publishing new cache records.  An all-hit run has no
            # cache publication boundary, so retain that fail-closed check
            # once here without rehashing every restored workspace output.
            revalidate_producer_implementation(implementation_receipt)

    try:
        with publish_classic_output_set(
            project_root,
            state_root,
            publication_requests,
            before_commit=before_target_publication,
        ) as published_outputs:
            unchanged_target_count = sum(
                item.request.kind == "target" and not item.changed for item in published_outputs
            )
            outputs = tuple(
                sorted(
                    (
                        FileReceipt(
                            item.snapshot.path,
                            item.snapshot.digest,
                            item.snapshot.size,
                            True,
                            item.request.producer_step,
                            item.snapshot.device,
                            item.snapshot.inode,
                        )
                        for item in published_outputs
                    ),
                    key=lambda item: str(item.path),
                )
            )
            result = ClassicIncrementalResult(
                BuildExecutionReceipt(False, (), outputs, ()),
                summary,
            )
    except ClassicPublicationError as exc:
        raise ClassicIncrementalError(
            f"warm target set could not be published safely: {exc}"
        ) from exc

    if result is None:
        raise ClassicIncrementalError("warm target set produced no receipt")
    summary = replace(
        summary,
        elapsed_seconds=monotonic() - started,
        published_targets=(
            sum(item.request.kind == "target" for item in published_outputs)
            - unchanged_target_count
        ),
        unchanged_targets=unchanged_target_count,
    )
    result = replace(result, summary=summary)
    if progress is not None:
        progress(
            "unit_finished",
            len(nodes) + 2,
            len(nodes) + 2,
            "publication",
            "target-set",
            None,
        )
    return result
