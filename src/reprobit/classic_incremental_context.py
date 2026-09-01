"""Typed state and immutable-input helpers for classic incremental builds."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Lock
from types import MappingProxyType
from typing import cast

from reprobit.backends import ExecutionBackend
from reprobit.cache import CacheLease
from reprobit.classic_cache import (
    CompilerDependencyHint,
    DonorTransformDependencyHint,
)
from reprobit.classic_includes import SealedIncludeAuthority, SealedIncludeFile
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_repair_dispatch import ClassicMeasuredReceiptRepair
from reprobit.classic_runtime_preparation import (
    ClassicProducerGraphPreparedRun,
    prepare_classic_producer_graph_run,
)
from reprobit.execution import BuildExecutionReceipt
from reprobit.incremental import DeveloperAuthority, IncrementalBuildSummary
from reprobit.incremental_executor import (
    IncrementalNode,
    IncrementalProgress,
    NodeOutcome,
    PreparedNodeInputs,
    ReceiptBoundInput,
)
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    materialize_argument,
)
from reprobit.schema import ClassicDebugCompanionPaths, InterventionDocument, ProjectBundle
from reprobit.secure_path_contracts import (
    SecureFileSnapshot,
    SecurePathError,
    canonical_system_path,
)
from reprobit.secure_paths import (
    digest_relative_file,
    read_relative_file,
    stat_relative_file,
)
from reprobit.strict_json import JsonValue, canonical_json


class ClassicIncrementalError(RuntimeError):
    """The non-certifying classic warm build cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class ClassicIncrementalResult:
    receipt: BuildExecutionReceipt
    summary: IncrementalBuildSummary


@dataclass(slots=True)
class CompilerState:
    base_key: str
    base_material: dict[str, JsonValue]
    final_key: str | None = None
    hint: CompilerDependencyHint | None = None
    replay_failure: str | None = None
    physical_inputs: tuple[Path, ...] = ()


@dataclass(slots=True)
class TransformState:
    base_key: str
    base_material: dict[str, JsonValue]
    final_key: str | None = None
    hint: DonorTransformDependencyHint | None = None
    replay_failure: str | None = None
    physical_inputs: tuple[Path, ...] = ()


def json_value(value: object) -> JsonValue:
    canonical_json(value)
    return cast(JsonValue, value)


def logical_join(root: str, relative: str) -> str:
    return normalize_logical_path(root.rstrip("\\/") + "\\" + relative.replace("/", "\\"))


def secure_location(path: Path) -> tuple[Path, str]:
    absolute = canonical_system_path(path)
    if not absolute.anchor or len(absolute.parts) < 2:
        raise ClassicIncrementalError(f"warm input has no secure location: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def snapshot_file(path: Path) -> SecureFileSnapshot:
    root, relative = secure_location(path)
    try:
        return digest_relative_file(root, relative)
    except SecurePathError as exc:
        raise ClassicIncrementalError(
            f"warm input is absent, redirected, or unstable: {path}"
        ) from exc


def read_payload(path: Path) -> tuple[bytes, SecureFileSnapshot]:
    root, relative = secure_location(path)
    try:
        return read_relative_file(root, relative)
    except SecurePathError as exc:
        raise ClassicIncrementalError(
            f"warm input is absent, redirected, or unstable: {path}"
        ) from exc


SNAPSHOT_IDENTITY_FIELDS = (
    "device",
    "inode",
    "size",
    "mtime_ns",
    "ctime_ns",
    "mode",
    "windows_file_id",
    "windows_attributes",
)
"""Every identity attribute a sampled snapshot carries besides its content digest."""


def snapshot_identity_is_exact(recorded: SecureFileSnapshot, current: object) -> bool:
    """Return whether ``current`` proves the file behind ``recorded`` unchanged.

    ``current`` is the held identity observed for the same path just now.  It
    proves the sample exact only when it names the same path and carries every
    attribute in :data:`SNAPSHOT_IDENTITY_FIELDS` with the recorded value.  A
    missing attribute or any difference means the content must be hashed
    again; the identity alone never stands in for a hash it cannot vouch for.
    """

    if getattr(current, "path", None) != recorded.path:
        return False
    for name in SNAPSHOT_IDENTITY_FIELDS:
        try:
            observed = getattr(current, name)
        except AttributeError:
            return False
        if observed is None or observed != getattr(recorded, name):
            return False
    return True


class PhysicalInputCensus:
    """Exact physical receipts sampled while planning one warm invocation.

    The first sample of a path hashes it through a held, no-follow ancestor
    chain.  Later samples and the pre-publication checks re-observe the held
    identity of the same path (device, inode, size, both timestamps, mode and
    the Windows file id) and reuse the recorded receipt only when every one of
    those attributes still matches; otherwise the file is hashed again and any
    difference is rejected exactly as a first sample would be.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: dict[Path, SecureFileSnapshot] = {}

    def _record(self, snapshot: SecureFileSnapshot) -> SecureFileSnapshot:
        path = snapshot.path.resolve(strict=True)
        with self._lock:
            previous = self._entries.setdefault(path, snapshot)
        if previous != snapshot:
            raise ClassicIncrementalError(f"warm physical input changed while planning: {path}")
        return snapshot

    @staticmethod
    def _still_exact(recorded: SecureFileSnapshot, path: Path) -> bool:
        """Re-observe ``path`` through the held chain and compare its identity.

        Any failure to observe the identity reports ``False`` so the caller
        falls back to a full hash, whose own error names the actual problem.
        """

        try:
            root, relative = secure_location(path)
            current = stat_relative_file(root, relative)
        except (ClassicIncrementalError, SecurePathError):
            return False
        return snapshot_identity_is_exact(recorded, current)

    def _exact_sample(self, path: Path) -> SecureFileSnapshot | None:
        """Return the recorded receipt for ``path`` when its identity is still exact."""

        key = canonical_system_path(path)
        with self._lock:
            recorded = self._entries.get(key)
        if recorded is None or not self._still_exact(recorded, key):
            return None
        return recorded

    def snapshot(self, path: Path) -> SecureFileSnapshot:
        exact = self._exact_sample(path)
        if exact is not None:
            return exact
        return self._record(snapshot_file(path))

    def payload(self, path: Path) -> tuple[bytes, SecureFileSnapshot]:
        payload, snapshot = read_payload(path)
        return payload, self._record(snapshot)

    def sampled_path(self, path: Path) -> Path:
        snapshot = self.snapshot(path)
        return snapshot.path.resolve(strict=True)

    def known_path(self, path: Path) -> Path | None:
        received = Path(path)
        if received.is_absolute():
            with self._lock:
                exact = self._entries.get(received)
            if exact is not None:
                return exact.path
        canonical = received.resolve(strict=False)
        with self._lock:
            return canonical if canonical in self._entries else None

    def paths(self) -> tuple[Path, ...]:
        with self._lock:
            return tuple(sorted(self._entries, key=str))

    def validate(self, paths: Sequence[Path]) -> None:
        selected = {Path(path).resolve(strict=False) for path in paths}
        with self._lock:
            expected = {path: self._entries.get(path) for path in selected}
        missing = tuple(
            sorted((path for path, value in expected.items() if value is None), key=str)
        )
        if missing:
            raise ClassicIncrementalError(
                "warm input census omitted sampled path(s): "
                + ", ".join(str(path) for path in missing)
            )
        for path in sorted(selected, key=str):
            prior = expected[path]
            assert prior is not None
            if self._still_exact(prior, path):
                continue
            current = snapshot_file(path)
            if current != prior:
                raise ClassicIncrementalError(
                    f"warm sampled physical input changed before cache publication: {path}"
                )

    def validate_all(self) -> None:
        with self._lock:
            paths = tuple(self._entries)
        self.validate(paths)


def input_receipt(
    reference: str,
    logical_path: str,
    snapshot: SecureFileSnapshot,
) -> JsonValue:
    return json_value(
        {
            "reference": reference,
            "logical_path": logical_path,
            "digest": snapshot.digest.value,
            "size": snapshot.size,
        }
    )


class WarmRuntime:
    def __init__(
        self,
        prepared: ClassicProducerGraphPreparedRun,
        *,
        staging_root: Path,
        project_root: Path,
        oracle_paths: Mapping[str, Path],
        oracle_snapshots: Mapping[str, SecureFileSnapshot],
    ) -> None:
        self.prepared = prepared
        self.project_root = project_root
        self.oracle_paths = oracle_paths
        self.oracle_snapshots = oracle_snapshots
        self._oracle_stack = ExitStack()
        self._oracle_lock = Lock()
        self._oracles_bound = False
        self._closed = False
        prepared.warm.bind_warm_staging_root(staging_root)

    @property
    def initialized_runtime_count(self) -> int:
        return self.prepared.producer.initialized_runtime_count

    def ensure_oracles(self) -> None:
        with self._oracle_lock:
            if self._oracles_bound:
                return
            stack = ExitStack()
            try:
                from reprobit.oracle_pe32 import bind_pe32_oracle
                from reprobit.verify import seal_file_oracle

                capabilities = {}
                for target_id, path in sorted(
                    self.oracle_paths.items(), key=lambda item: item[0].casefold()
                ):
                    sealed = stack.enter_context(seal_file_oracle(path))
                    digest, size = sealed._digest_receipt()
                    expected = self.oracle_snapshots[target_id]
                    if digest != expected.digest.value or size != expected.size:
                        raise ClassicIncrementalError(
                            f"warm legacy oracle changed after key planning: {target_id!r}"
                        )
                    capabilities[target_id] = bind_pe32_oracle(sealed)
                self.prepared.donors.bind_legacy_oracles(capabilities)
            except BaseException:
                stack.close()
                raise
            self._oracle_stack = stack.pop_all()
            self._oracles_bound = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.prepared.close()
        finally:
            self._oracle_stack.close()


@dataclass(slots=True)
class ClassicIncrementalPlan:
    """All captured authority and mutable assembly state for one warm build."""

    started: float
    authority: DeveloperAuthority
    bundle: ProjectBundle
    graph: ProducerGraphDocument
    project_root: Path
    session_root: Path
    state_root: Path
    toolchain_root: Path
    backend: ExecutionBackend
    jobs: int
    compiler_transport: Path | None
    resource_transport: Path | None
    initialization_timeout: float
    compile_timeout: float
    link_timeout: float
    cleanup_timeout: float
    progress: IncrementalProgress | None
    measured_receipt_repair: ClassicMeasuredReceiptRepair | None
    census: PhysicalInputCensus
    staging_root: Path
    graph_digest: str
    implementation_receipt: Digest
    role_relatives: Mapping[ProducerRole, str]
    role_logical: Mapping[ProducerRole, str]
    environment: Mapping[str, str]
    toolchain_material: JsonValue
    runtime_material: JsonValue
    runtime_input_paths: tuple[Path, ...]
    effective_sources: Mapping[str, bytes]
    effective_sources_by_path: Mapping[str, bytes]
    overlay_by_path: Mapping[str, JsonValue]
    generated_paths: frozenset[str]
    ordinary_authority: SealedIncludeAuthority
    authority_by_epoch: Mapping[bool, SealedIncludeAuthority]
    authority_files: Mapping[bool, Mapping[str, SealedIncludeFile]]
    physical_by_logical: Mapping[str, Path]
    source_payloads: Mapping[str, bytes]
    system_libraries: Mapping[str, Path]
    units: tuple[ClassicPreparedUnit, ...]
    documents_by_unit: Mapping[str, InterventionDocument]
    source_root: str
    toolchain_logical_root: str
    oracle_snapshots: Mapping[str, SecureFileSnapshot]
    oracle_paths: Mapping[str, Path]
    graph_output_owner: Mapping[str, str]
    compiler_nodes: Mapping[str, ProducerNode]
    compiler_sources: Mapping[str, str]
    generated_nodes: frozenset[str]
    compiler_units: Mapping[str, ClassicPreparedUnit]
    output_paths: Mapping[str, Mapping[str, Path]]
    transform_ids: Mapping[str, str]
    transform_paths: Mapping[str, Mapping[str, Path]]
    effective_owner: Mapping[str, str]
    ordinary_barrier: tuple[str, ...]
    rdata_material_by_object: Mapping[str, tuple[JsonValue, ...]]
    analysis_link_options: tuple[str, ...]
    debug_companion_paths: Mapping[str, ClassicDebugCompanionPaths]
    runtime_holder: dict[str, WarmRuntime]
    runtime_lock: Lock
    compiler_states: dict[str, CompilerState]
    transform_states: dict[str, TransformState]
    nodes: list[IncrementalNode[WarmRuntime]]
    terminal_nodes: dict[str, str]
    terminal_paths: dict[str, Path]
    primary_link_outputs: dict[str, str]
    analysis_nodes: dict[str, str]


def staged_reference_inputs(
    plan: ClassicIncrementalPlan,
    consumer_id: str,
    references: Sequence[str],
    *,
    owners_by_reference: Mapping[str, str] | None = None,
) -> tuple[
    Mapping[str, Path],
    Callable[[CacheLease, Mapping[str, NodeOutcome]], PreparedNodeInputs] | None,
]:
    """Plan immutable receipt-bound restores for one consumer."""

    owners_by_reference = owners_by_reference or plan.effective_owner
    selected = tuple(
        sorted(
            {reference for reference in references if reference.startswith("build/")},
            key=str.casefold,
        )
    )
    if not selected:
        return MappingProxyType({}), None
    values = MappingProxyType(
        {
            reference: plan.staging_root
            / "inputs"
            / consumer_id
            / f"{index:03d}-{PurePosixPath(reference).name}"
            for index, reference in enumerate(selected)
        }
    )
    owners: dict[str, str] = {}
    for reference in selected:
        owner = owners_by_reference.get(reference.casefold())
        if owner is None:
            raise ClassicIncrementalError(f"warm input {reference!r} has no graph output owner")
        owners[reference] = owner

    def materialize(
        lease: CacheLease,
        outcomes: Mapping[str, NodeOutcome],
    ) -> PreparedNodeInputs:
        grouped: dict[str, dict[str, Path]] = {}
        for reference, destination in values.items():
            owner = owners[reference]
            if owner not in outcomes:
                raise ClassicIncrementalError(
                    f"warm input {reference!r} owner {owner!r} is incomplete"
                )
            grouped.setdefault(owner, {})[reference] = destination
        entries: dict[str, ReceiptBoundInput] = {}
        for owner, destinations in sorted(grouped.items(), key=lambda item: item[0]):
            outcome = outcomes[owner]
            snapshots = lease.restore_selected(
                outcome.record,
                destinations,
                allowed_root=plan.staging_root,
            )
            receipts = {item.name: item for item in outcome.record.outputs}
            for reference in destinations:
                entries[reference] = ReceiptBoundInput(
                    receipts[reference],
                    snapshots[reference],
                )
        return PreparedNodeInputs(MappingProxyType(entries))

    return values, materialize


def reference_payload(
    plan: ClassicIncrementalPlan,
    reference: str,
    *,
    immutable_build_inputs: Mapping[str, Path] | None = None,
) -> bytes:
    """Read one key-authority payload, never a mutable predecessor path."""

    kind, relative = reference.split("/", 1)
    if kind == "build":
        if immutable_build_inputs is None or reference not in immutable_build_inputs:
            raise ClassicIncrementalError(
                f"warm build input {reference!r} lacks an immutable predecessor view"
            )
        build_payload, _receipt_value = read_payload(immutable_build_inputs[reference])
        return build_payload
    if kind in {"source", "quarantine-archive"}:
        source_payload = plan.effective_sources_by_path.get(relative.casefold())
        if source_payload is None:
            raise ClassicIncrementalError(
                f"warm linker input is outside effective source authority: {reference!r}"
            )
        return source_payload
    if kind == "toolchain":
        toolchain_payload, _receipt_value = plan.census.payload(
            plan.toolchain_root.joinpath(*PurePosixPath(relative).parts)
        )
        return toolchain_payload
    if kind == "system-library":
        path = plan.system_libraries.get(reference)
        if path is None:
            raise ClassicIncrementalError(f"warm system library is unresolved: {reference!r}")
        system_payload, _receipt_value = plan.census.payload(path)
        return system_payload
    raise ClassicIncrementalError(f"warm linker input has an unsupported kind: {reference!r}")


def direct_inputs(
    plan: ClassicIncrementalPlan,
    node: ProducerNode,
    *,
    generated: bool,
) -> list[JsonValue]:
    values: list[JsonValue] = []
    files = plan.authority_files[generated]
    for reference in (*node.inputs, *node.directive_inputs):
        if reference.startswith("build/"):
            continue
        kind, relative = reference.split("/", 1)
        if kind in {"source", "quarantine-archive"}:
            logical = logical_join(plan.source_root, relative)
            item = files.get(logical.casefold())
            if item is None:
                raise ClassicIncrementalError(
                    f"warm direct input is outside source authority: {reference!r}"
                )
            values.append(
                json_value(
                    {
                        "reference": reference,
                        "logical_path": item.logical_path,
                        "digest": item.digest.value,
                        "size": item.size,
                    }
                )
            )
        elif kind == "toolchain":
            logical = logical_join(plan.toolchain_logical_root, relative)
            item = files.get(logical.casefold())
            if item is None:
                raise ClassicIncrementalError(
                    f"warm direct input is outside toolchain authority: {reference!r}"
                )
            values.append(
                json_value(
                    {
                        "reference": reference,
                        "logical_path": item.logical_path,
                        "digest": item.digest.value,
                        "size": item.size,
                    }
                )
            )
        elif kind == "system-library":
            path = plan.system_libraries.get(reference)
            if path is None:
                raise ClassicIncrementalError(f"warm system library is unresolved: {reference!r}")
            values.append(input_receipt(reference, str(path), plan.census.snapshot(path)))
        else:
            raise ClassicIncrementalError(
                f"warm direct input has an unsupported kind: {reference!r}"
            )
    return values


def sampled_reference_path(
    plan: ClassicIncrementalPlan,
    reference: str,
) -> Path | None:
    if reference.startswith("build/"):
        return None
    kind, relative = reference.split("/", 1)
    if kind in {"source", "quarantine-archive"}:
        resolved = plan.project_root.joinpath(*PurePosixPath(relative).parts)
    elif kind == "toolchain":
        resolved = plan.toolchain_root.joinpath(*PurePosixPath(relative).parts)
    elif kind == "system-library":
        system_path = plan.system_libraries.get(reference)
        if system_path is None:
            raise ClassicIncrementalError(f"warm system library is unresolved: {reference!r}")
        resolved = system_path
    else:
        return None
    return plan.census.known_path(resolved)


def recursive_sampled_paths(
    plan: ClassicIncrementalPlan,
    logical_paths: Sequence[str],
) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for logical_path in logical_paths:
        physical = plan.physical_by_logical.get(logical_path.casefold())
        if physical is None:
            raise ClassicIncrementalError(
                f"warm recursive input lacks a physical authority: {logical_path!r}"
            )
        sampled = plan.census.known_path(physical)
        if sampled is not None:
            paths.add(sampled)
    return tuple(sorted(paths, key=str))


def verify_before_store(
    plan: ClassicIncrementalPlan,
    runtime: WarmRuntime,
    paths: Sequence[Path],
) -> None:
    # The runtime verifies the global producer namespace before any record is
    # published. Per-node checks stay scoped to that node's sampled inputs.
    del runtime
    plan.census.validate(paths)


def node_arguments(
    plan: ClassicIncrementalPlan,
    node: ProducerNode,
) -> tuple[str, ...]:
    return (
        plan.role_logical[node.role],
        *(
            materialize_argument(
                value,
                source_root=plan.bundle.spec.paths.source,
                build_root=plan.bundle.spec.paths.build,
                toolchain_root=plan.bundle.spec.paths.toolchain,
            )
            for value in node.arguments
        ),
    )


def runtime_factory(plan: ClassicIncrementalPlan) -> WarmRuntime:
    with plan.runtime_lock:
        existing = plan.runtime_holder.get("runtime")
        if existing is not None:
            return existing
        prepared = prepare_classic_producer_graph_run(
            plan.bundle,
            project_root=plan.project_root,
            session_root=plan.session_root / "classic",
            toolchain_root=plan.toolchain_root,
            backend=plan.backend,
            jobs=plan.jobs,
            compiler_transport=plan.compiler_transport,
            resource_transport=plan.resource_transport,
            initialization_timeout=plan.initialization_timeout,
            compile_timeout=plan.compile_timeout,
            link_timeout=plan.link_timeout,
            cleanup_timeout=plan.cleanup_timeout,
            measured_receipt_repair=plan.measured_receipt_repair,
        )
        runtime: WarmRuntime | None = None
        try:
            runtime = WarmRuntime(
                prepared,
                staging_root=plan.staging_root,
                project_root=plan.project_root,
                oracle_paths=plan.oracle_paths,
                oracle_snapshots=plan.oracle_snapshots,
            )
            # Donor transforms share one composition and may run in any DAG
            # order.  Bind the complete planned capability set before the
            # runtime becomes visible to any node, so an unrelated donor
            # compile cannot make later oracle binding impossible.
            runtime.ensure_oracles()
        except BaseException:
            if runtime is None:
                prepared.close()
            else:
                runtime.close()
            raise
        plan.runtime_holder["runtime"] = runtime
        return runtime


__all__ = [
    "SNAPSHOT_IDENTITY_FIELDS",
    "ClassicIncrementalError",
    "ClassicIncrementalPlan",
    "ClassicIncrementalResult",
    "CompilerState",
    "PhysicalInputCensus",
    "TransformState",
    "WarmRuntime",
    "direct_inputs",
    "input_receipt",
    "json_value",
    "logical_join",
    "node_arguments",
    "read_payload",
    "recursive_sampled_paths",
    "reference_payload",
    "runtime_factory",
    "sampled_reference_path",
    "snapshot_file",
    "snapshot_identity_is_exact",
    "staged_reference_inputs",
    "verify_before_store",
]
