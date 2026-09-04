"""Generic dependency-aware executor for non-certifying warm builds."""

from __future__ import annotations

import os
import stat
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Generic, Literal, TypeAlias, TypeVar

from reprobit.cache import CacheLease, CacheOutput, CacheRecord, IncrementalCache
from reprobit.dag_queue import DependencyQueue
from reprobit.incremental import IncrementalBuildSummary
from reprobit.process import CancellationToken
from reprobit.secure_path_contracts import (
    SecureFileSnapshot,
    SecurePathError,
)
from reprobit.secure_paths import digest_relative_file
from reprobit.strict_json import JsonValue


class IncrementalExecutionError(RuntimeError):
    """A warm DAG is unsafe, incomplete, or failed during execution."""


RuntimeT = TypeVar("RuntimeT")


@dataclass(frozen=True, slots=True)
class NodeOutcome:
    """One completed warm node and its immutable output receipt."""

    node_id: str
    key: str
    record: CacheRecord
    cache_hit: bool
    publishable: bool = True


@dataclass(frozen=True, slots=True)
class NodeKeyDecision:
    """A final key plus an optional reason why a prior generation is stale."""

    key: str | None
    invalidation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CacheProbeDecision:
    """A selected, already-validated record or one conservative miss."""

    key: str | None
    record: CacheRecord | None
    invalidation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ReceiptBoundInput:
    """One private dependency copy bound to its immutable cache receipt."""

    output: CacheOutput
    snapshot: SecureFileSnapshot


@dataclass(frozen=True, slots=True)
class PreparedNodeInputs:
    """Immutable dependency view passed to trusted node execution code."""

    entries: Mapping[str, ReceiptBoundInput]


NodeKeyFactory = Callable[[Mapping[str, NodeOutcome]], str | NodeKeyDecision]
NodeCacheProbe = Callable[[CacheLease, Mapping[str, NodeOutcome]], CacheProbeDecision]
NodeAction = Callable[[RuntimeT, CancellationToken, PreparedNodeInputs], None]
NodePreStore = Callable[[RuntimeT, Mapping[str, NodeOutcome]], None]
NodeInputMaterializer = Callable[[CacheLease, Mapping[str, NodeOutcome]], PreparedNodeInputs]
IncrementalProgressEventKind: TypeAlias = Literal[
    "cache_hit",
    "cache_miss",
    "unit_finished",
]
IncrementalProgress = Callable[
    [IncrementalProgressEventKind, int, int, str, str, str | None],
    None,
]


class IncrementalPhase(StrEnum):
    """Closed accounting class for warm work."""

    PRODUCER = "producer"
    TRANSFORM = "transform"


@dataclass(frozen=True, slots=True)
class IncrementalNode(Generic[RuntimeT]):
    """One cacheable DAG node with fresh-workspace destinations."""

    id: str
    domain: str
    depends_on: tuple[str, ...]
    outputs: Mapping[str, Path]
    key: NodeKeyFactory
    execute: NodeAction[RuntimeT]
    metadata: Callable[[Mapping[str, NodeOutcome]], Mapping[str, JsonValue]]
    pre_store: NodePreStore[RuntimeT] | None = None
    materialize_inputs: NodeInputMaterializer | None = None
    materialize_before_probe: bool = False
    final_key: NodeKeyFactory | None = None
    probe: NodeCacheProbe | None = None
    phase: IncrementalPhase = IncrementalPhase.PRODUCER
    order_only: tuple[str, ...] = ()
    publish_result: Callable[[], bool] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.phase, IncrementalPhase):
            raise IncrementalExecutionError(f"incremental node {self.id!r} has an invalid phase")
        if self.order_only != tuple(sorted(set(self.order_only), key=str.casefold)):
            raise IncrementalExecutionError(
                f"incremental node {self.id!r} has noncanonical order-only dependencies"
            )
        if self.materialize_before_probe and self.materialize_inputs is None:
            raise IncrementalExecutionError(
                f"incremental node {self.id!r} requests probe inputs without a materializer"
            )


class _LazyRuntime(Generic[RuntimeT]):
    def __init__(
        self,
        factory: Callable[[], RuntimeT],
        close: Callable[[RuntimeT], None],
    ) -> None:
        self._factory = factory
        self._close = close
        self._value: RuntimeT | None = None
        self._error: BaseException | None = None
        self._lock = Lock()
        self.created = False
        self.closed = False

    @staticmethod
    def _construction_failure(error: Exception) -> IncrementalExecutionError:
        return IncrementalExecutionError(f"incremental runtime construction failed: {error}")

    def get(self) -> RuntimeT:
        with self._lock:
            if self._error is not None:
                if isinstance(self._error, Exception):
                    raise self._construction_failure(self._error) from self._error
                raise self._error
            if self._value is None:
                try:
                    self._value = self._factory()
                    self.created = True
                except BaseException as exc:
                    self._error = exc
                    if isinstance(exc, Exception):
                        raise self._construction_failure(exc) from exc
                    raise
            return self._value

    def close(self) -> None:
        with self._lock:
            value = self._value
            if value is None or self.closed:
                return
            self.closed = True
        self._close(value)


@dataclass(frozen=True, slots=True)
class IncrementalExecutionResult(Generic[RuntimeT]):
    outcomes: Mapping[str, NodeOutcome]
    summary: IncrementalBuildSummary
    runtime_created: bool


class IncrementalDAGExecutor(Generic[RuntimeT]):
    """Reuse valid nodes and lazily create a runtime for cache misses only.

    Receipt-only consumers can disable ``materialize_cache_hits``. Their hits
    still receive full content validation; explicit input materializers supply
    private copies when needed. The default preserves standalone callers that
    consume the declared workspace outputs after execution.
    """

    def __init__(
        self,
        *,
        cache: IncrementalCache,
        workspace_root: Path,
        runtime_factory: Callable[[], RuntimeT],
        runtime_close: Callable[[RuntimeT], None],
        max_workers: int,
        progress: IncrementalProgress | None = None,
        runtime_init_count: Callable[[], int] | None = None,
        before_publish: Callable[[], None] | None = None,
        materialize_cache_hits: bool = True,
    ) -> None:
        if max_workers < 1:
            raise IncrementalExecutionError("incremental worker count must be positive")
        self.cache = cache
        self.workspace_alias_root = Path(os.path.abspath(workspace_root))
        self.workspace_root = workspace_root.resolve(strict=True)
        self.runtime_factory = runtime_factory
        self.runtime_close = runtime_close
        self.max_workers = max_workers
        self.progress = progress
        self.runtime_init_count = runtime_init_count
        self.before_publish = before_publish
        self.materialize_cache_hits = materialize_cache_hits

    def execute(
        self,
        nodes: Sequence[IncrementalNode[RuntimeT]],
    ) -> IncrementalExecutionResult[RuntimeT]:
        started = time.monotonic()
        by_id = {item.id: item for item in nodes}
        if len(by_id) != len(nodes) or not nodes:
            raise IncrementalExecutionError("incremental nodes must be non-empty and unique")
        for node in nodes:
            unknown = set(node.depends_on) - set(by_id)
            invalid_ordering = set(node.order_only) - set(node.depends_on)
            if unknown or invalid_ordering or node.id in node.depends_on:
                raise IncrementalExecutionError(
                    f"incremental node {node.id!r} has invalid dependencies: "
                    f"unknown={sorted(unknown)}, order_only={sorted(invalid_ordering)}"
                )
            if set(node.depends_on) - set(node.order_only) and node.materialize_inputs is None:
                raise IncrementalExecutionError(
                    f"incremental node {node.id!r} has data dependencies but no "
                    "receipt-bound input materializer"
                )
        data_consumers = {
            dependency
            for node in nodes
            for dependency in set(node.depends_on) - set(node.order_only)
        }
        output_owners: dict[str, tuple[str, str]] = {}
        canonical_outputs: dict[str, Mapping[str, Path]] = {}
        for node in nodes:
            if not node.outputs:
                raise IncrementalExecutionError(f"incremental node {node.id!r} has no outputs")
            normalized: dict[str, Path] = {}
            for name, output in node.outputs.items():
                if not output.is_absolute():
                    raise IncrementalExecutionError(f"incremental output is not absolute: {output}")
                if ".." in output.parts:
                    raise IncrementalExecutionError(
                        f"incremental output is not canonical: {output}"
                    )
                lexical = Path(os.path.abspath(output))
                try:
                    relative = lexical.relative_to(self.workspace_alias_root)
                    lexical_parent = self.workspace_alias_root
                except ValueError:
                    try:
                        relative = lexical.relative_to(self.workspace_root)
                        lexical_parent = self.workspace_root
                    except ValueError as exc:
                        raise IncrementalExecutionError(
                            f"incremental output escapes workspace: {output}"
                        ) from exc
                if self.workspace_alias_root.resolve(strict=True) != self.workspace_root:
                    raise IncrementalExecutionError(
                        "incremental workspace alias changed after initialization"
                    )
                parent = lexical_parent
                for component in relative.parts[:-1]:
                    parent /= component
                    if os.path.lexists(parent) and (parent.is_symlink() or not parent.is_dir()):
                        raise IncrementalExecutionError(
                            f"incremental output parent is redirected: {parent}"
                        )
                canonical = self.workspace_root / relative
                physical_key = os.fspath(canonical).casefold()
                previous = output_owners.setdefault(physical_key, (node.id, name))
                if previous != (node.id, name):
                    raise IncrementalExecutionError(
                        f"incremental output {output} aliases {previous[0]!r}/{previous[1]!r}"
                    )
                if not name:
                    raise IncrementalExecutionError("incremental output name is empty")
                normalized[name] = canonical
            canonical_outputs[node.id] = MappingProxyType(normalized)

        lazy = _LazyRuntime(self.runtime_factory, self.runtime_close)
        cancellation = CancellationToken()
        outcomes: dict[str, NodeOutcome] = {}
        try:
            ready_queue = DependencyQueue({node.id: node.depends_on for node in nodes})
        except ValueError as exc:
            raise IncrementalExecutionError(
                f"incremental graph cannot make progress: {exc}"
            ) from exc
        progress_count = 0
        progress_total = len(nodes) + 1
        progress_lock = Lock()
        producer_hits = 0
        producer_misses = 0
        transform_hits = 0
        transform_misses = 0
        invalidations: list[tuple[str, str]] = []
        staged_records: list[tuple[IncrementalNode[RuntimeT], CacheRecord]] = []
        staged_lock = Lock()

        def announce(
            kind: IncrementalProgressEventKind,
            node: IncrementalNode[RuntimeT],
            reason: str | None,
            *,
            complete: bool,
        ) -> None:
            nonlocal progress_count
            with progress_lock:
                if complete:
                    progress_count += 1
                if self.progress is not None:
                    self.progress(
                        kind,
                        progress_count,
                        progress_total,
                        node.phase.value,
                        node.id,
                        reason,
                    )

        execution_error: BaseException | None = None
        runtime_closed = False
        try:
            with self.cache.lease() as lease:

                def run(
                    node: IncrementalNode[RuntimeT],
                    snapshot: Mapping[str, NodeOutcome],
                ) -> NodeOutcome:
                    cancellation.raise_if_cancelled()
                    dependencies = MappingProxyType(
                        {
                            dependency: snapshot[dependency]
                            for dependency in node.depends_on
                            if dependency not in node.order_only
                        }
                    )
                    dependencies_publishable = all(
                        outcome.publishable for outcome in dependencies.values()
                    )
                    prepared_inputs: PreparedNodeInputs | None = None
                    if node.materialize_before_probe:
                        assert node.materialize_inputs is not None
                        prepared_inputs = node.materialize_inputs(lease, snapshot)
                    if node.probe is not None:
                        probe = node.probe(lease, dependencies)
                        key = probe.key
                        reason = probe.invalidation_reason
                        record = probe.record
                        if record is not None and (
                            key is None
                            or record.key != key
                            or record.domain != node.domain
                            or record.implementation != self.cache.implementation
                        ):
                            raise IncrementalExecutionError(
                                f"node {node.id!r} probe returned a record from "
                                "a different cache identity"
                            )
                        if not dependencies_publishable:
                            record = None
                            reason = "provisional dependency requires fresh execution"
                    else:
                        decision = node.key(dependencies)
                        if isinstance(decision, NodeKeyDecision):
                            key = decision.key
                            reason = decision.invalidation_reason
                        else:
                            key = decision
                            reason = None
                        record = (
                            lease.lookup(node.domain, key)
                            if key is not None and dependencies_publishable
                            else None
                        )
                        if not dependencies_publishable:
                            reason = "provisional dependency requires fresh execution"
                    if record is not None:
                        assert key is not None
                        if self.materialize_cache_hits:
                            lease.restore(
                                record,
                                canonical_outputs[node.id],
                                allowed_root=self.workspace_root,
                            )
                        else:
                            if {item.name for item in record.outputs} != set(node.outputs):
                                raise IncrementalExecutionError(
                                    f"node {node.id!r} cache hit differs from its output set"
                                )
                            lease.validate_record(record)
                        announce(
                            "cache_hit",
                            node,
                            None,
                            complete=True,
                        )
                        return NodeOutcome(node.id, key, record, True)
                    if reason:
                        with progress_lock:
                            invalidations.append((node.id, reason))
                    # A typed miss is useful immediately, but discovery is
                    # not completion: the producer, publication, and
                    # integrity checks still remain.
                    announce(
                        "cache_miss",
                        node,
                        reason,
                        complete=False,
                    )
                    data_dependencies = set(node.depends_on) - set(node.order_only)
                    if data_dependencies:
                        assert node.materialize_inputs is not None
                        if prepared_inputs is None:
                            prepared_inputs = node.materialize_inputs(lease, snapshot)
                    elif prepared_inputs is None:
                        prepared_inputs = PreparedNodeInputs(MappingProxyType({}))
                    runtime = lazy.get()
                    cancellation.raise_if_cancelled()
                    assert prepared_inputs is not None
                    node.execute(runtime, cancellation, prepared_inputs)
                    cancellation.raise_if_cancelled()
                    if node.final_key is not None:
                        final_decision = node.final_key(dependencies)
                        final_key = (
                            final_decision.key
                            if isinstance(final_decision, NodeKeyDecision)
                            else final_decision
                        )
                    else:
                        final_key = key
                    if final_key is None:
                        raise IncrementalExecutionError(
                            f"node {node.id!r} did not produce a final cache key"
                        )
                    for name, output in canonical_outputs[node.id].items():
                        if output.is_symlink() or not output.is_file():
                            raise IncrementalExecutionError(
                                f"node {node.id!r} omitted output {name!r}: {output}"
                            )
                    if node.pre_store is not None:
                        node.pre_store(runtime, dependencies)
                    metadata = dict(node.metadata(dependencies))
                    publish_result = dependencies_publishable and (
                        node.publish_result is None or node.publish_result()
                    )
                    staged_key = (
                        final_key
                        if publish_result
                        else sha256(
                            (f"provisional\0{node.id}\0{final_key}\0{uuid.uuid4().hex}").encode()
                        ).hexdigest()
                    )
                    if publish_result or node.id in data_consumers:
                        staged = lease.stage_record(
                            node.domain,
                            staged_key,
                            canonical_outputs[node.id],
                            metadata=metadata,
                        )
                    else:
                        staged = lease.snapshot_record(
                            node.domain,
                            staged_key,
                            canonical_outputs[node.id],
                            metadata=metadata,
                        )
                    if publish_result:
                        with staged_lock:
                            staged_records.append((node, staged))
                    announce(
                        "unit_finished",
                        node,
                        None,
                        complete=True,
                    )
                    return NodeOutcome(
                        node.id,
                        staged_key,
                        staged,
                        False,
                        publish_result,
                    )

                with ThreadPoolExecutor(max_workers=min(self.max_workers, len(nodes))) as pool:
                    running: dict[Future[NodeOutcome], IncrementalNode[RuntimeT]] = {}
                    try:
                        while ready_queue:
                            for node_id in ready_queue.take_ready(self.max_workers - len(running)):
                                node = by_id[node_id]
                                snapshot = MappingProxyType(dict(outcomes))
                                running[pool.submit(run, node, snapshot)] = node
                            done, _pending = wait(running, return_when=FIRST_COMPLETED)
                            for future in sorted(
                                done, key=lambda item: running[item].id.casefold()
                            ):
                                node = running.pop(future)
                                try:
                                    outcome = future.result()
                                except Exception as exc:
                                    raise IncrementalExecutionError(
                                        f"incremental node {node.id!r} failed: {exc}"
                                    ) from exc
                                outcomes[node.id] = outcome
                                if node.phase is IncrementalPhase.TRANSFORM:
                                    if outcome.cache_hit:
                                        transform_hits += 1
                                    else:
                                        transform_misses += 1
                                elif outcome.cache_hit:
                                    producer_hits += 1
                                else:
                                    producer_misses += 1
                                ready_queue.finish(node.id)
                    except BaseException:
                        cancellation.cancel("incremental sibling failed")
                        for future in running:
                            future.cancel()
                        raise
                # Blobs are immutable and may safely converge during
                # execution, but record names remain unpublished until every
                # producer-readable namespace closes cleanly.  A failed close
                # therefore leaves only unreferenced blobs for GC, never a
                # reusable record from a failed invocation.
                lazy.close()
                runtime_closed = True
                transient_nodes = tuple(
                    by_id[node_id]
                    for node_id, outcome in outcomes.items()
                    if not outcome.publishable and node_id not in data_consumers
                )
                if staged_records or transient_nodes:
                    if staged_records and self.before_publish is not None:
                        self.before_publish()
                    # Re-seal the complete outcome set before publishing any
                    # records.  A transient-only run re-seals just its leaf
                    # outputs because no later node can consume or mutate them.
                    validation_nodes = nodes if staged_records else transient_nodes
                    validation_boundary = "publication" if staged_records else "final validation"
                    for node in sorted(validation_nodes, key=lambda item: item.id.casefold()):
                        outcome = outcomes[node.id]
                        expected = {item.name: item for item in outcome.record.outputs}
                        if set(expected) != set(canonical_outputs[node.id]):
                            raise IncrementalExecutionError(
                                f"node {node.id!r} outcome differs from its output set"
                            )
                        if outcome.cache_hit and not self.materialize_cache_hits:
                            # Lazy hits have no mutable producer workspace copy. Recheck their
                            # immutable bytes before any descendant record becomes reusable.
                            lease.validate_record(outcome.record)
                            continue
                        for name, output in canonical_outputs[node.id].items():
                            output_relative = output.relative_to(self.workspace_root).as_posix()
                            try:
                                received = digest_relative_file(
                                    self.workspace_root,
                                    output_relative,
                                )
                            except SecurePathError as exc:
                                raise IncrementalExecutionError(
                                    f"node {node.id!r} output {name!r} changed before "
                                    f"{validation_boundary}"
                                ) from exc
                            receipt = expected[name]
                            if (
                                received.digest.value != receipt.digest
                                or received.size != receipt.size
                                or bool(received.mode & stat.S_IXUSR) != receipt.executable
                            ):
                                raise IncrementalExecutionError(
                                    f"node {node.id!r} output {name!r} changed before "
                                    f"{validation_boundary}"
                                )
                    for node, staged in sorted(
                        staged_records,
                        key=lambda item: item[0].id.casefold(),
                    ):
                        published = lease.publish_record(staged)
                        prior = outcomes[node.id]
                        outcomes[node.id] = NodeOutcome(
                            prior.node_id,
                            prior.key,
                            published,
                            False,
                            prior.publishable,
                        )
            with progress_lock:
                if progress_count != len(nodes):
                    raise IncrementalExecutionError(
                        "incremental node progress accounting is incomplete"
                    )
                progress_count += 1
                if self.progress is not None:
                    self.progress(
                        "unit_finished",
                        progress_count,
                        progress_total,
                        "publication",
                        "cache-record-set",
                        None,
                    )
        except BaseException as exc:
            execution_error = exc
            raise
        finally:
            if not runtime_closed:
                try:
                    lazy.close()
                except BaseException as close_error:
                    if execution_error is not None:
                        execution_error.add_note(
                            f"incremental runtime cleanup also failed: {close_error}"
                        )
                    else:
                        raise

        if progress_count != progress_total:
            raise IncrementalExecutionError("incremental progress accounting is incomplete")
        summary = IncrementalBuildSummary(
            producer_hits=producer_hits,
            producer_misses=producer_misses,
            transform_hits=transform_hits,
            transform_misses=transform_misses,
            elapsed_seconds=time.monotonic() - started,
            runtime_init_count=(
                self.runtime_init_count()
                if self.runtime_init_count is not None
                else int(lazy.created)
            ),
            invalidations=tuple(sorted(invalidations, key=lambda item: item[0].casefold())),
        )
        return IncrementalExecutionResult(
            MappingProxyType(outcomes),
            summary,
            lazy.created,
        )


__all__ = [
    "CacheProbeDecision",
    "IncrementalDAGExecutor",
    "IncrementalExecutionError",
    "IncrementalExecutionResult",
    "IncrementalNode",
    "IncrementalPhase",
    "IncrementalProgress",
    "IncrementalProgressEventKind",
    "NodeAction",
    "NodeCacheProbe",
    "NodeInputMaterializer",
    "NodeKeyDecision",
    "NodeKeyFactory",
    "NodeOutcome",
    "PreparedNodeInputs",
    "ReceiptBoundInput",
]
