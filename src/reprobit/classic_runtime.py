"""Direct producer-graph execution for migrated classic MSVC projects.

CMake is a migration-time graph extractor only.  A certifying run consumes the
committed :mod:`reprobit.producer_graph` document and directly invokes every
locked compiler, resource compiler, librarian, and linker node.  Project CMake
code and generated build-system programs are never executed here.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Condition, Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from reprobit import classic
from reprobit.assets import runtime_asset_path
from reprobit.backends import (
    BackendError,
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
    WorkerSandbox,
)
from reprobit.build import BuildPlan
from reprobit.classic_donors import DonorCompileRequest, DonorIncludeProjection
from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    MsvcSbrTrace,
    ResolvedInclude,
    SealedIncludeAuthority,
    SealedIncludeFile,
    parse_msvc_sbr,
    resolve_msvc_include_trace,
)
from reprobit.classic_link_closure import (
    ClassicLinkDirectiveClosure,
    MissingDirectiveInputsError,
    ModuleDefinitionReceipt,
    audit_classic_link_directives,
    link_directive_closure_material,
    module_definition_material,
    parse_classic_module_definition,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    apply_classic_terminal_pipeline,
    classic_rdata_repack,
    classic_rdata_repack_graph_authority,
    compose_classic_unit,
    prepare_classic_units,
)
from reprobit.classic_project import (
    ClassicProjectError,
    InterventionWitness,
    _effective_source_seal,
    _overlay_dialect,
    materialize_effective_workspace,
)
from reprobit.classic_resources import (
    ResourceDependencyReceipt,
    scan_msvc_resource_dependencies,
)
from reprobit.classic_semantics import (
    CLASSIC_SEMANTIC_CONTRACTS,
    ArchiveInput,
    ClassicSemanticError,
    CleanSourceInput,
    CompilerEpochInvocation,
    CompilerInputEvidenceKind,
    CompilerNamespaceEvidence,
    CompilerProduct,
    CompilerSourceRead,
    DonorSemanticLane,
    EffectiveOverlayReceipt,
    OverlaySemanticSnapshot,
    PrimarySourceOrigin,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
    SourceInputReceipt,
    TargetLinkClosure,
    classic_compiler_path_profile_digest,
    compiler_epoch_invocation_digest,
    compiler_namespace_evidence_digest,
    overlay_semantic_run_binding,
    plan_project_overlay_compiler_epochs,
    prove_source_overlay_semantics,
    validate_project_overlay_compiler_epoch,
)
from reprobit.engine import (
    BuildExecutionReceipt,
    FileReceipt,
    ProducerAttestation,
    ProducerKind,
    RuntimeEvidence,
    RuntimeEvidenceContext,
    StepExecutionReceipt,
    classic_semantic_obligation_name,
)
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    Certificate,
    Digest,
    ProofObligation,
    ProvenanceKind,
    ProvenanceNode,
    SemanticArtifactClaim,
    SemanticProof,
)
from reprobit.native_device_map import NativeDeviceMapLease
from reprobit.paths import (
    MaterializedSkeleton,
    logical_relative_to,
    normalize_logical_path,
)
from reprobit.process import (
    CancellationToken,
    CommandSpec,
    ProcessResult,
    ProcessSupervisor,
    WindowsLineagePlanner,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    materialize_argument,
    materialize_reference,
    producer_graph_digest,
    read_producer_graph,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    project_sdk_archive_authorities,
)
from reprobit.sealed_namespace import (
    NamespaceFile,
    NamespaceTree,
    SealedNamespaceFile,
    SealedNamespaceLease,
    SealedNamespaceSnapshot,
)
from reprobit.secure_paths import (
    SecureFileIdentity,
    SecureFileSnapshot,
    SecurePathError,
    atomic_copy_new_relative,
    atomic_publish_relative,
    canonical_system_path,
    digest_relative_file,
    hold_relative_file_set,
    remove_regular_relative,
    reseal_relative_file,
    stat_relative_file,
)
from reprobit.strict_json import canonical_json
from reprobit.toolchains import ClassicMSVCToolchain, ToolchainLock
from reprobit.toolchains import profile as toolchain_profile

if TYPE_CHECKING:
    from reprobit.incremental_executor import PreparedNodeInputs, ReceiptBoundInput
    from reprobit.legacy import PE32VirtualAddressReader


ClassicProgressCallback = Callable[[int, int, str, str], None]


class _ProgressReporter:
    """Serialize stable producer progress events across executor workers."""

    def __init__(self, total: int, callback: ClassicProgressCallback | None) -> None:
        if total < 0:
            raise ClassicProjectError("classic progress total cannot be negative")
        self.total = total
        self.callback = callback
        self.completed = 0
        self._lock = Lock()

    def emit(self, phase: str, node_id: str) -> None:
        with self._lock:
            self.completed += 1
            if self.completed > self.total:
                raise ClassicProjectError("classic progress exceeded its declared total")
            if self.callback is not None:
                self.callback(self.completed, self.total, phase, node_id)


@dataclass(frozen=True, slots=True)
class _ExecutionLane:
    """One producer environment and its optional Windows lineage plan."""

    id: str
    environment: Mapping[str, str]
    worker: WorkerSandbox
    windows_lineage_planner: WindowsLineagePlanner | None = None


class _LazyExecutionLanePool:
    """Grow isolated producer lanes only when concurrent work needs them.

    Constructing a prepared run is metadata-only with respect to the backend:
    no Wine prefix, wineserver, or native logical-drive binding exists until a
    producer actually acquires a lane.  A single miss therefore creates one
    lane, while concurrent cold work may grow the pool up to ``maximum``.
    """

    def __init__(
        self,
        *,
        maximum: int,
        create: Callable[[int], _ExecutionLane],
        close_created: Callable[[], None],
        compiler_environment_digest: Digest,
    ) -> None:
        if maximum < 1:
            raise ClassicProjectError("classic execution requires at least one lane")
        self.maximum = maximum
        self.compiler_environment_digest = compiler_environment_digest
        self._create = create
        self._close_created = close_created
        self._condition = Condition()
        self._available: list[_ExecutionLane] = []
        self._all: list[_ExecutionLane] = []
        self._borrowed: set[int] = set()
        self._creating = 0
        self._next_index = 0
        self._failure: BaseException | None = None
        self._closing = False
        self._closed = False

    @property
    def created_count(self) -> int:
        with self._condition:
            return len(self._all)

    @property
    def lanes(self) -> tuple[_ExecutionLane, ...]:
        with self._condition:
            return tuple(self._all)

    def acquire(self) -> _ExecutionLane:
        index: int | None = None
        with self._condition:
            while index is None:
                if self._closed or self._closing:
                    raise ClassicProjectError("classic execution lane pool is closed")
                if self._failure is not None:
                    raise ClassicProjectError(
                        "classic execution lane initialization previously failed"
                    ) from self._failure
                if self._available:
                    lane = self._available.pop()
                    self._borrowed.add(id(lane))
                    return lane
                if len(self._all) + self._creating < self.maximum:
                    index = self._next_index
                    self._next_index += 1
                    self._creating += 1
                    break
                self._condition.wait()
        try:
            lane = self._create(index)
            received_digest = _compiler_environment_digest(lane.environment)
            if received_digest != self.compiler_environment_digest:
                raise ClassicProjectError(
                    "classic compiler lane exposes a different frontend environment"
                )
        except BaseException as exc:
            with self._condition:
                self._creating -= 1
                if self._failure is None:
                    self._failure = exc
                self._condition.notify_all()
            raise
        with self._condition:
            self._creating -= 1
            self._all.append(lane)
            if self._closing or self._closed or self._failure is not None:
                self._condition.notify_all()
                raise ClassicProjectError(
                    "classic execution lane pool closed during initialization"
                )
            self._borrowed.add(id(lane))
            self._condition.notify_all()
            return lane

    def release(self, lane: _ExecutionLane) -> None:
        with self._condition:
            if not any(item is lane for item in self._all) or id(lane) not in self._borrowed:
                raise ClassicProjectError("classic execution returned an unknown lane")
            self._borrowed.remove(id(lane))
            if not self._closing and not self._closed and self._failure is None:
                self._available.append(lane)
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closing = True
            if self._borrowed or self._creating:
                self._closing = False
                raise ClassicProjectError(
                    "classic execution lane pool closed while lanes were active"
                )
            self._closed = True
            self._available.clear()
            self._condition.notify_all()
        self._close_created()


@dataclass(frozen=True, slots=True)
class ClassicProducerTarget:
    target_id: str
    build_target: str
    output: Path
    pdb: Path | None
    link_node_id: str = ""


@dataclass(frozen=True, slots=True)
class ClassicCompilerProbeOutput:
    """Raw output of one non-certifying exact committed-node compiler probe."""

    node_id: str
    source_reference: str
    object_reference: str
    pdb_reference: str
    object_path: Path
    pdb_path: Path
    object_digest: Digest
    pdb_digest: Digest
    object_payload: bytes
    pdb_payload: bytes
    step: StepExecutionReceipt


@dataclass(frozen=True, slots=True)
class ClassicDonorProbeInput:
    """One immutable logical rendered input returned by a donor probe."""

    logical_path: str
    digest: Digest
    size: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class ClassicDonorProbeOutput:
    """Raw output of one non-certifying prepared-donor compiler probe."""

    donor_id: str
    translation_unit_id: str
    build_target: str
    source_reference: str
    producer_node_id: str
    rendered_inputs: tuple[ClassicDonorProbeInput, ...]
    object_digest: Digest
    pdb_digest: Digest
    object_payload: bytes
    pdb_payload: bytes
    step: StepExecutionReceipt


@dataclass(frozen=True, slots=True)
class _CompileRecord:
    node_id: str
    directory: Path
    source: Path
    object_path: Path
    pdb_path: Path
    arguments: tuple[str, ...]
    build_target: str


@dataclass(frozen=True, slots=True)
class _DonorCompilerInvocation:
    """Private result shared by cold composition and bounded diagnostics."""

    record: _CompileRecord
    object_path: Path
    pdb_path: Path
    object_payload: bytes
    pdb_payload: bytes
    result: ProcessResult
    spec: CommandSpec
    namespace: SealedNamespaceSnapshot
    step_id: str
    dependency_replay: _ClassicWarmDonorDependencyReplay | None = None


@dataclass(frozen=True, slots=True)
class _OverlayEpochPlan:
    """Sealed project-overlay inputs split across their compiler epochs."""

    effective_outputs: Mapping[str, bytes]
    project_source_pairs: tuple[ProjectOverlaySourcePair, ...]
    generated_inputs: frozenset[str]
    carrier_input_seals: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class _ResourceDependencyAudit:
    """One static, closed recursive-read proof for a resource compiler node."""

    step: StepExecutionReceipt
    receipt: ResourceDependencyReceipt


def _project_overlay_resource_reader_closure(
    *,
    source_root: str,
    source_pairs: Sequence[ProjectOverlaySourcePair],
    graph: ProducerGraphDocument,
    receipts: Mapping[str, ResourceDependencyReceipt],
) -> dict[str, object]:
    """Prove that RC's exact recursive-read closure excludes overlay outputs."""

    expected_nodes = {node.id for node in graph.nodes if node.role is ProducerRole.RESOURCE}
    if set(receipts) != expected_nodes:
        missing = sorted(expected_nodes - set(receipts), key=str.casefold)
        extra = sorted(set(receipts) - expected_nodes, key=str.casefold)
        raise ClassicProjectError(
            "project-overlay resource reader closure differs from the producer graph; "
            f"missing={missing}, extra={extra}"
        )
    overlay_logical_paths = {
        _logical_join(source_root, pair.path).casefold(): pair.path for pair in source_pairs
    }
    overlay_reads = tuple(
        sorted(
            (
                node_id,
                overlay_logical_paths[read.logical_path.casefold()],
                read.kind.value,
            )
            for node_id, receipt in receipts.items()
            for read in receipt.reads
            if read.logical_path.casefold() in overlay_logical_paths
        )
    )
    if overlay_reads:
        raise ClassicProjectError(
            "project-overlay source is also a resource-compiler input; sparse compiler "
            f"semantics do not admit this secondary reader: {overlay_reads}"
        )
    return {
        "schema": 1,
        "resource_nodes": sorted(receipts, key=str.casefold),
        "resource_read_count": sum(len(receipt.reads) for receipt in receipts.values()),
        "overlay_resource_reads": [],
    }


@dataclass(frozen=True, slots=True)
class _ClassicWarmCompilerReplay:
    """Dependency-only result from a discarded `/Fr` compiler invocation."""

    trace: MsvcSbrTrace | None
    reason: str | None

    def __post_init__(self) -> None:
        if (self.trace is None) == (self.reason is None):
            raise ClassicProjectError(
                "classic warm compiler replay requires exactly one result state"
            )


@dataclass(frozen=True, slots=True)
class _ClassicWarmDonorDependencyReplay:
    """Non-certifying dependency result from one projected donor replay."""

    donor_id: str
    trace: MsvcSbrTrace | None
    reads: tuple[ResolvedInclude, ...]
    reason: str | None

    def __post_init__(self) -> None:
        if not self.donor_id or (
            self.trace is None
        ) == (self.reason is None) or (self.trace is None and self.reads):
            raise ClassicProjectError(
                "classic warm donor replay requires exactly one complete result state"
            )


@dataclass(frozen=True, slots=True)
class _ClassicWarmCompilerTransformResult:
    """Warm transform receipts plus discarded projected-donor diagnostics."""

    steps: tuple[StepExecutionReceipt, ...]
    donor_dependencies: tuple[_ClassicWarmDonorDependencyReplay, ...]


@dataclass(frozen=True, slots=True)
class _DirectLogicalWorkspace:
    """Run-private source/build/toolchain seats for a committed producer graph."""

    root: Path
    drive_letter: str
    effective_root: Path
    build_root: Path
    toolchain_entry: Path
    materialized: MaterializedSkeleton


@dataclass(frozen=True, slots=True)
class ClassicProducedImage:
    target_id: str
    raw_path: Path
    final_path: Path
    link_step_id: str
    linker_tool_id: str
    witnesses: tuple[InterventionWitness, ...]
    final_snapshot: SecureFileSnapshot


@dataclass(frozen=True, slots=True)
class ClassicProducerRead:
    """One sealed file visible to a compiler or read by a resource producer."""

    logical_path: str
    physical_path: Path
    digest: Digest
    size: int
    origin: IncludeOrigin
    parent_index: int | None
    parent_path: str | None
    kind: str
    payload: bytes | None = None


@dataclass(frozen=True, slots=True)
class ClassicProducerReadReceipt:
    """Closed readable-input set for one producer execution."""

    node_id: str
    step_id: str
    role: ProducerRole
    epoch: str
    reads: tuple[ClassicProducerRead, ...]
    coverage: str = "recursive-read-v1"
    namespace_id: str | None = None
    namespace_digest: Digest | None = None
    namespace_count: int | None = None


@dataclass(frozen=True, slots=True)
class ClassicCompilerNamespaceReceipt:
    """One shared complete namespace plus physical ancestry leaves."""

    evidence: CompilerNamespaceEvidence
    reads: tuple[ClassicProducerRead, ...]


@dataclass(frozen=True, slots=True)
class ClassicCapturedProducerOutput:
    """Immutable content receipt captured before a later in-place transform."""

    node_id: str
    step_id: str
    role: ProducerRole
    reference: str
    logical_path: str
    digest: Digest
    size: int


@dataclass(frozen=True, slots=True)
class ClassicDonorOutputReceipt:
    """Private compiler object consumed only by certified composition."""

    intervention_id: str
    node_id: str
    step_id: str
    logical_path: str
    digest: Digest
    size: int


@dataclass(frozen=True, slots=True)
class ClassicProducerGraphExecutionRecord:
    images: tuple[ClassicProducedImage, ...]
    witnesses: tuple[InterventionWitness, ...]
    producer_reads: tuple[ClassicProducerReadReceipt, ...] = ()
    compiler_outputs: tuple[ClassicCapturedProducerOutput, ...] = ()
    donor_outputs: tuple[ClassicDonorOutputReceipt, ...] = ()
    compiler_namespaces: tuple[ClassicCompilerNamespaceReceipt, ...] = ()


class ClassicProducerGraphRuntimeEvidenceProvider:
    """Issue evidence only after the paired executor has completed this run."""

    name = "classic-msvc-producer-graph-v1"

    def __init__(self, executor: ClassicProducerGraphBuildExecutor) -> None:
        self._executor = executor

    def issue(self, context: RuntimeEvidenceContext) -> RuntimeEvidence:
        """Assemble a forward producer DAG from the paired execution record."""

        self._executor.reseal_published_targets()
        return _ClassicEvidenceAssembler(self._executor, context).assemble()


def _evidence_identifier(prefix: str, *material: object) -> str:
    suffix = Digest.from_bytes(canonical_json(material)).value[:24]
    return f"{prefix}.{suffix}"


def _statement_has_receipt(statement: object, digest: Digest, size: int) -> bool:
    if isinstance(statement, Mapping):
        raw_digest = statement.get("digest")
        if statement.get("size") == size:
            try:
                if Digest.model_validate(raw_digest) == digest:
                    return True
            except ValueError:
                pass
        return any(_statement_has_receipt(value, digest, size) for value in statement.values())
    if isinstance(statement, list):
        return any(_statement_has_receipt(value, digest, size) for value in statement)
    return False


def _statement_candidate_receipt(statement: object) -> tuple[Digest, int] | None:
    if not isinstance(statement, Mapping):
        return None
    candidate = statement.get("candidate")
    if not isinstance(candidate, Mapping):
        return None
    size = candidate.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ClassicProjectError("semantic candidate size is malformed")
    try:
        digest = Digest.model_validate(candidate.get("digest"))
    except ValueError as exc:
        raise ClassicProjectError("semantic candidate digest is malformed") from exc
    return digest, size


class _ClassicEvidenceAssembler:
    """Translate one closed classic execution into its causal proof DAG."""

    def __init__(
        self,
        executor: ClassicProducerGraphBuildExecutor,
        context: RuntimeEvidenceContext,
    ) -> None:
        record = executor.record
        if record is None:
            raise ClassicProjectError("classic producer-graph evidence requested before execution")
        self.executor = executor
        self.context = context
        self.record = record
        self.project_root = Path(context.bundle.root).resolve(strict=False)
        self.output_receipts = {
            item.path.resolve(strict=False): item for item in context.build.outputs
        }
        self.input_receipts = {
            item.path.resolve(strict=False): item for item in context.build.inputs
        }
        self.steps = {item.step_id: item for item in context.build.steps}
        self.locked = {
            item.id: item
            for item in (
                *context.bundle.toolchain_lock.tools,
                *context.bundle.toolchain_lock.runtime_files,
            )
        }
        self.nodes = {item.id: item for item in executor.graph.nodes}
        self.interventions = {item.id: item for item in context.bundle.interventions}
        self.witnesses = {item.intervention_id: item for item in record.witnesses}
        if set(self.witnesses) != set(self.interventions):
            missing = sorted(set(self.interventions) - set(self.witnesses))
            extra = sorted(set(self.witnesses) - set(self.interventions))
            raise ClassicProjectError(
                f"runtime witnesses differ from interventions; missing={missing}, extra={extra}"
            )
        self.artifacts: dict[str, Artifact] = {}
        self.provenance: dict[str, ProvenanceNode] = {}
        self.terminal_node: dict[str, str] = {}
        self.producers: list[ProducerAttestation] = []
        self.certificates: dict[str, Certificate] = {}
        self.current_by_reference: dict[str, str] = {}
        self.leaf_by_content: dict[tuple[str, str, int, str], str] = {}
        self.reads_by_node: dict[str, list[ClassicProducerReadReceipt]] = {}
        for receipt in record.producer_reads:
            self.reads_by_node.setdefault(receipt.node_id, []).append(receipt)
        namespace_rows = {
            item.evidence.namespace_id.casefold(): item for item in record.compiler_namespaces
        }
        if len(namespace_rows) != len(record.compiler_namespaces):
            raise ClassicProjectError("runtime repeats a compiler namespace receipt")
        self.compiler_namespaces = namespace_rows
        self.namespace_artifacts: dict[str, str] = {}
        self.overlay_outputs = self._overlay_output_owners()
        self.overlay_artifacts: dict[str, set[str]] = {
            item_id: set() for item_id in self._overlay_intervention_ids()
        }

    def assemble(self) -> RuntimeEvidence:
        self._add_compiler_and_resource_outputs()
        self._bind_overlay_certificates()
        self._add_donor_outputs()
        self._apply_translation_unit_transforms()
        self._apply_object_repack_transforms()
        self._add_role_outputs(ProducerRole.LIBRARIAN)
        self._add_role_outputs(ProducerRole.LINKER)
        self._publish_targets()
        if set(self.certificates) != set(self.interventions):
            missing = sorted(set(self.interventions) - set(self.certificates))
            extra = sorted(set(self.certificates) - set(self.interventions))
            raise ClassicProjectError(
                f"evidence certificates differ from interventions; missing={missing}, extra={extra}"
            )
        return RuntimeEvidence(
            provider_id=ClassicProducerGraphRuntimeEvidenceProvider.name,
            run_binding=self.context.run_binding,
            artifacts=tuple(self.artifacts.values()),
            provenance=tuple(self.provenance.values()),
            certificates=tuple(self.certificates.values()),
            producers=tuple(self.producers),
        )

    def _overlay_intervention_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    item.id
                    for item in self.interventions.values()
                    if isinstance(item, ClassicRecipeIntervention)
                    and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
                ),
                key=str.casefold,
            )
        )

    def _overlay_output_owners(self) -> dict[str, str]:
        owners: dict[str, str] = {}
        for intervention in self.interventions.values():
            if not isinstance(intervention, ClassicRecipeIntervention) or (
                intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
            ):
                continue
            values = {item.name: item.value for item in intervention.parameters}
            outputs = values.get("outputs")
            if not isinstance(outputs, list):
                raise ClassicProjectError("source-overlay outputs are malformed")
            for declaration in outputs:
                path = declaration.get("path") if isinstance(declaration, dict) else None
                if not isinstance(path, str):
                    raise ClassicProjectError("source-overlay output path is malformed")
                folded = _safe_relative(path).casefold()
                if folded in owners:
                    raise ClassicProjectError("source-overlay evidence paths overlap")
                owners[folded] = intervention.id
        return owners

    def _add_artifact(
        self,
        artifact: Artifact,
        *,
        kind: ProvenanceKind,
        operation: str,
        origin: ArtifactOrigin,
        parent_artifacts: Sequence[str] = (),
        intervention_id: str | None = None,
        certificate_ids: Sequence[str] = (),
    ) -> str:
        if artifact.id in self.artifacts:
            if self.artifacts[artifact.id] != artifact:
                raise ClassicProjectError("evidence artifact identity collision")
            return artifact.id
        parent_ids = tuple(parent_artifacts)
        provenance_id = _evidence_identifier("provenance", artifact.id, operation)
        if provenance_id in self.provenance:
            raise ClassicProjectError("evidence provenance identity collision")
        self.artifacts[artifact.id] = artifact
        self.provenance[provenance_id] = ProvenanceNode(
            id=provenance_id,
            kind=kind,
            operation=operation,
            origin=origin,
            parents=tuple(self.terminal_node[item] for item in parent_ids),
            artifact_id=artifact.id,
            intervention_id=intervention_id,
            certificate_ids=tuple(certificate_ids),
        )
        self.terminal_node[artifact.id] = provenance_id
        return artifact.id

    def _leaf_artifact(
        self,
        *,
        path: Path,
        logical_path: str,
        digest: Digest,
        size: int,
        kind: ArtifactKind,
        origin: ArtifactOrigin,
        first_party: bool,
    ) -> str:
        key = (logical_path, digest.value, size, kind.value)
        existing = self.leaf_by_content.get(key)
        if existing is not None:
            return existing
        artifact_id = _evidence_identifier("artifact", "leaf", *key)
        provenance_kind = {
            ArtifactKind.SOURCE: ProvenanceKind.SOURCE,
            ArtifactKind.TOOLCHAIN: ProvenanceKind.TOOLCHAIN,
        }.get(kind, ProvenanceKind.EXTERNAL)
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=kind,
                logical_path=logical_path,
                digest=digest,
                size=size,
                origin=origin,
                first_party=first_party,
                receipt_path=str(path.resolve(strict=False)),
            ),
            kind=provenance_kind,
            operation={
                ProvenanceKind.SOURCE: "sealed_source",
                ProvenanceKind.TOOLCHAIN: "locked_toolchain",
                ProvenanceKind.EXTERNAL: "sealed_external",
            }[provenance_kind],
            origin=origin,
        )
        self.leaf_by_content[key] = artifact_id
        return artifact_id

    def _source_read_artifact(self, read: ClassicProducerRead) -> str:
        path = read.physical_path.resolve(strict=False)
        if read.origin is IncludeOrigin.TOOLCHAIN_TREE:
            return self._leaf_artifact(
                path=path,
                logical_path=read.logical_path,
                digest=read.digest,
                size=read.size,
                kind=ArtifactKind.TOOLCHAIN,
                origin=ArtifactOrigin.FRESH_SEED,
                first_party=True,
            )
        if read.origin is IncludeOrigin.DONOR_ARENA:
            return self._leaf_artifact(
                path=path,
                logical_path=read.logical_path,
                digest=read.digest,
                size=read.size,
                kind=ArtifactKind.SOURCE,
                origin=ArtifactOrigin.FRESH_DONOR,
                first_party=True,
            )
        input_receipt = self.input_receipts.get(path)
        if input_receipt is not None and (
            input_receipt.digest == read.digest and input_receipt.size == read.size
        ):
            return self._leaf_artifact(
                path=path,
                logical_path=read.logical_path,
                digest=read.digest,
                size=read.size,
                kind=ArtifactKind.SOURCE,
                origin=ArtifactOrigin.FRESH_SEED,
                first_party=True,
            )
        try:
            relative = path.relative_to(self.executor.effective_root).as_posix()
        except ValueError as exc:
            raise ClassicProjectError("project read escapes its effective source seat") from exc
        owner = self.overlay_outputs.get(relative.casefold())
        if owner is None:
            raise ClassicProjectError(
                f"unreceipted producer read lacks source-overlay authority: {relative!r}"
            )
        parents: list[str] = []
        if input_receipt is not None:
            parents.append(
                self._leaf_artifact(
                    path=path,
                    logical_path=read.logical_path,
                    digest=input_receipt.digest,
                    size=input_receipt.size,
                    kind=ArtifactKind.SOURCE,
                    origin=ArtifactOrigin.FRESH_SEED,
                    first_party=True,
                )
            )
        else:
            parents.extend(self._clean_source_authority())
        artifact_id = _evidence_identifier(
            "artifact", "effective-source", relative, read.digest, read.size
        )
        certificate_id = _evidence_identifier("certificate", owner)
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=ArtifactKind.SOURCE,
                logical_path=read.logical_path,
                digest=read.digest,
                size=read.size,
                origin=ArtifactOrigin.COMPOSED,
                inputs=tuple(parents),
            ),
            kind=ProvenanceKind.INTERVENTION,
            operation="source_overlay",
            origin=ArtifactOrigin.COMPOSED,
            parent_artifacts=parents,
            intervention_id=owner,
            certificate_ids=(certificate_id,),
        )
        self.overlay_artifacts[owner].add(artifact_id)
        return artifact_id

    def _compiler_namespace_artifact(self, namespace_id: str) -> str:
        folded = namespace_id.casefold()
        existing = self.namespace_artifacts.get(folded)
        if existing is not None:
            return existing
        receipt = self.compiler_namespaces.get(folded)
        if receipt is None or receipt.evidence.namespace_id != namespace_id:
            raise ClassicProjectError(f"compiler namespace receipt is absent: {namespace_id!r}")
        evidence = receipt.evidence
        wire = canonical_json(
            {
                "schema": 1,
                "namespace_id": evidence.namespace_id,
                "input_evidence_kind": evidence.input_evidence_kind.value,
                "members": [
                    {
                        "reference": item.reference,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                        "parent_index": item.parent_index,
                    }
                    for item in evidence.members
                ],
            }
        )
        if Digest.from_bytes(wire) != evidence.namespace_digest or len(receipt.reads) != len(
            evidence.members
        ):
            raise ClassicProjectError(f"compiler namespace evidence changed: {namespace_id!r}")
        parents = tuple(dict.fromkeys(self._source_read_artifact(item) for item in receipt.reads))
        artifact_id = _evidence_identifier(
            "artifact", "compiler-namespace", evidence.namespace_id, evidence.namespace_digest
        )
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=ArtifactKind.RECEIPT,
                logical_path=(f".reprobit/compiler-namespaces/{evidence.namespace_id}.json"),
                digest=evidence.namespace_digest,
                size=len(wire),
                origin=ArtifactOrigin.FRESH_SEED,
                inputs=parents,
            ),
            kind=ProvenanceKind.PRODUCER,
            operation="sealed_compiler_namespace",
            origin=ArtifactOrigin.FRESH_SEED,
            parent_artifacts=parents,
        )
        self.namespace_artifacts[folded] = artifact_id
        return artifact_id

    def _clean_source_authority(self) -> tuple[str, ...]:
        result = []
        effective = self.executor.effective_root.resolve(strict=False)
        for receipt in sorted(self.input_receipts.values(), key=lambda item: str(item.path)):
            try:
                receipt.path.resolve(strict=False).relative_to(effective)
            except ValueError:
                continue
            result.append(
                self._leaf_artifact(
                    path=receipt.path,
                    logical_path=self.executor._logical_for_host_path(receipt.path),
                    digest=receipt.digest,
                    size=receipt.size,
                    kind=ArtifactKind.SOURCE,
                    origin=ArtifactOrigin.FRESH_SEED,
                    first_party=True,
                )
            )
        if not result:
            raise ClassicProjectError("generated source has no clean source authority")
        return tuple(result)

    def _tool_artifact(self, role: ProducerRole) -> str:
        tool_id = self.executor.role_tool_ids[role]
        tool = self.locked.get(tool_id)
        if tool is None:
            raise ClassicProjectError(f"producer role {role.value!r} names an unlocked tool")
        path = self.executor.toolchain_root.joinpath(*PurePosixPath(tool.path).parts).resolve(
            strict=False
        )
        receipt = self.input_receipts.get(path)
        if (
            receipt is None
            or receipt.digest != tool.digest
            or (tool.size is not None and receipt.size != tool.size)
        ):
            raise ClassicProjectError(
                f"locked producer tool lacks its build input receipt: {tool_id!r}"
            )
        return self._leaf_artifact(
            path=path,
            logical_path=self.executor._logical_for_host_path(path),
            digest=tool.digest,
            size=receipt.size,
            kind=ArtifactKind.TOOLCHAIN,
            origin=ArtifactOrigin.FRESH_SEED,
            first_party=True,
        )

    def _read_inputs(self, node: ProducerNode) -> tuple[str, ...]:
        admitted = [
            item
            for item in self.reads_by_node.get(node.id, [])
            if item.role is node.role and item.epoch in {"effective", "generated"}
        ]
        if len(admitted) != 1:
            raise ClassicProjectError(
                f"producer {node.id!r} has {len(admitted)} effective read closures"
            )
        receipt = admitted[0]
        if node.role is ProducerRole.COMPILER:
            if (
                receipt.namespace_id is None
                or receipt.namespace_digest is None
                or receipt.namespace_count is None
            ):
                raise ClassicProjectError(f"compiler {node.id!r} lacks shared namespace identity")
            namespace = self.compiler_namespaces.get(receipt.namespace_id.casefold())
            if namespace is None or (
                namespace.evidence.namespace_digest != receipt.namespace_digest
                or len(namespace.evidence.members) != receipt.namespace_count
            ):
                raise ClassicProjectError(f"compiler {node.id!r} namespace receipt changed")
            return (self._compiler_namespace_artifact(receipt.namespace_id),)
        return tuple(dict.fromkeys(self._source_read_artifact(item) for item in receipt.reads))

    def _reference_artifact(self, reference: str) -> str:
        if reference.startswith("build/"):
            artifact_id = self.current_by_reference.get(reference.casefold())
            if artifact_id is None:
                raise ClassicProjectError(f"producer input precedes its artifact: {reference!r}")
            return artifact_id
        if reference.startswith("system-library/"):
            path = self.executor._archive_path(reference)
            kind = ArtifactKind.EXTERNAL
            origin = ArtifactOrigin.EXTERNAL
            first_party = False
        else:
            resolved = self.executor._reference(reference)
            if resolved is None:
                raise ClassicProjectError(f"producer input is unresolved: {reference!r}")
            path = resolved
            if reference.startswith("toolchain/"):
                kind = ArtifactKind.TOOLCHAIN
                origin = ArtifactOrigin.FRESH_SEED
                first_party = True
            elif reference.startswith("source/"):
                kind = ArtifactKind.SOURCE
                origin = ArtifactOrigin.FRESH_SEED
                first_party = True
            else:
                kind = ArtifactKind.EXTERNAL
                origin = ArtifactOrigin.EXTERNAL
                first_party = False
        receipt = self.input_receipts.get(path.resolve(strict=False))
        if receipt is None:
            raise ClassicProjectError(f"producer input lacks a sealed build receipt: {reference!r}")
        return self._leaf_artifact(
            path=path,
            logical_path=reference,
            digest=receipt.digest,
            size=receipt.size,
            kind=kind,
            origin=origin,
            first_party=first_party,
        )

    def _node_inputs(self, node: ProducerNode) -> tuple[str, ...]:
        values: list[str] = [self._tool_artifact(node.role)]
        if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}:
            values.extend(self._read_inputs(node))
        else:
            values.extend(
                self._reference_artifact(item) for item in (*node.inputs, *node.directive_inputs)
            )
        return tuple(dict.fromkeys(values))

    def _artifact_kind(self, reference: str) -> ArtifactKind:
        suffix = PurePosixPath(reference).suffix.casefold()
        return {
            ".obj": ArtifactKind.OBJECT,
            ".o": ArtifactKind.OBJECT,
            ".pdb": ArtifactKind.PDB,
            ".res": ArtifactKind.RESOURCE,
            ".lib": ArtifactKind.ARCHIVE,
            ".exe": ArtifactKind.IMAGE,
            ".dll": ArtifactKind.IMAGE,
        }.get(suffix, ArtifactKind.GENERATED)

    def _project_logical_path(self, path: Path) -> str:
        try:
            return path.resolve(strict=False).relative_to(self.project_root).as_posix()
        except ValueError as exc:
            raise ClassicProjectError("producer output escapes the project root") from exc

    def _add_produced_artifact(
        self,
        *,
        node: ProducerNode,
        reference: str,
        digest: Digest,
        size: int,
        step_id: str,
        inputs: Sequence[str],
        captured: bool,
        logical_path: str | None = None,
    ) -> str:
        tool_id = self.executor.role_tool_ids[node.role]
        tool = self.locked[tool_id]
        path = self.executor._reference(reference)
        if path is None:
            raise ClassicProjectError("producer output reference is not materializable")
        artifact_id = _evidence_identifier("artifact", "producer", node.id, reference, digest, size)
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=self._artifact_kind(reference),
                logical_path=logical_path or self._project_logical_path(path),
                digest=digest,
                size=size,
                origin=ArtifactOrigin.FRESH_SEED,
                producer=tool_id,
                inputs=tuple(inputs),
                receipt_path=str(path.resolve(strict=False)),
            ),
            kind=ProvenanceKind.PRODUCER,
            operation={
                ProducerRole.COMPILER: "compile",
                ProducerRole.RESOURCE: "resource_compile",
                ProducerRole.LIBRARIAN: "archive",
                ProducerRole.LINKER: "link",
            }[node.role],
            origin=ArtifactOrigin.FRESH_SEED,
            parent_artifacts=inputs,
        )
        self.producers.append(
            ProducerAttestation(
                id=_evidence_identifier("producer", artifact_id, step_id),
                artifact_id=artifact_id,
                step_id=step_id,
                producer_kind={
                    ProducerRole.COMPILER: ProducerKind.COMPILER,
                    ProducerRole.RESOURCE: ProducerKind.RESOURCE,
                    ProducerRole.LIBRARIAN: ProducerKind.LIBRARIAN,
                    ProducerRole.LINKER: ProducerKind.LINKER,
                }[node.role],
                tool_id=tool_id,
                tool_digest=tool.digest,
                artifact_digest=digest,
                artifact_size=size,
                captured_before_overwrite=captured,
            )
        )
        return artifact_id

    def _add_compiler_and_resource_outputs(self) -> None:
        captures = {item.reference.casefold(): item for item in self.record.compiler_outputs}
        for node in self.executor.graph.nodes:
            if node.role is ProducerRole.COMPILER:
                inputs = self._node_inputs(node)
                for reference in node.outputs:
                    captured = captures.get(reference.casefold())
                    if captured is None or captured.node_id != node.id:
                        raise ClassicProjectError(
                            f"compiler output lacks its raw capture: {reference!r}"
                        )
                    path = self.executor._reference(reference)
                    assert path is not None
                    final = self.output_receipts.get(path.resolve(strict=False))
                    overwritten = final is None or (
                        final.digest != captured.digest
                        or final.size != captured.size
                        or final.producer_step != node.id
                    )
                    artifact_id = self._add_produced_artifact(
                        node=node,
                        reference=reference,
                        digest=captured.digest,
                        size=captured.size,
                        step_id=captured.step_id,
                        inputs=inputs,
                        captured=overwritten,
                    )
                    self.current_by_reference[reference.casefold()] = artifact_id
            elif node.role is ProducerRole.RESOURCE:
                self._add_node_final_outputs(node)

    def _add_node_final_outputs(self, node: ProducerNode) -> None:
        inputs = self._node_inputs(node)
        for reference in node.outputs:
            path = self.executor._reference(reference)
            if path is None:
                raise ClassicProjectError("producer output is not a file")
            receipt = self.output_receipts.get(path.resolve(strict=False))
            if receipt is None or receipt.producer_step != node.id:
                raise ClassicProjectError(f"producer output lacks its final receipt: {reference!r}")
            artifact_id = self._add_produced_artifact(
                node=node,
                reference=reference,
                digest=receipt.digest,
                size=receipt.size,
                step_id=node.id,
                inputs=inputs,
                captured=False,
            )
            self.current_by_reference[reference.casefold()] = artifact_id

    def _add_role_outputs(self, role: ProducerRole) -> None:
        pending = {node.id: node for node in self.executor.graph.nodes if node.role is role}
        while pending:
            progressed = False
            for node_id, node in tuple(pending.items()):
                if any(
                    reference.startswith("build/")
                    and reference.casefold() not in self.current_by_reference
                    for reference in node.inputs
                ):
                    continue
                self._add_node_final_outputs(node)
                del pending[node_id]
                progressed = True
            if not progressed:
                raise ClassicProjectError(f"{role.value} evidence graph cannot resolve its inputs")

    def _semantic_claims(
        self,
        proof: SemanticProof,
        artifact_ids: Sequence[str],
    ) -> tuple[SemanticArtifactClaim, ...]:
        claims: list[SemanticArtifactClaim] = []
        for artifact_id in artifact_ids:
            artifact = self.artifacts[artifact_id]
            if _statement_has_receipt(proof.output_statement, artifact.digest, artifact.size):
                relation: Literal["input", "output"] = "output"
            elif _statement_has_receipt(proof.input_statement, artifact.digest, artifact.size):
                relation = "input"
            else:
                continue
            claims.append(
                SemanticArtifactClaim(
                    artifact_id=artifact_id,
                    relation=relation,
                    digest=artifact.digest,
                    size=artifact.size,
                )
            )
        if not claims:
            raise ClassicProjectError("semantic proof has no matching artifact receipt")
        return tuple(
            sorted(
                claims,
                key=lambda item: (
                    item.relation,
                    item.artifact_id,
                    item.digest.value,
                    item.size,
                ),
            )
        )

    def _add_certificate(
        self,
        witness: InterventionWitness,
        artifact_ids: Sequence[str],
    ) -> str:
        intervention = self.interventions[witness.intervention_id]
        certificate_id = _evidence_identifier("certificate", witness.intervention_id)
        if witness.intervention_id in self.certificates:
            raise ClassicProjectError("runtime witness was certified more than once")
        execution_name = (
            "quarantined_oracle_install" if witness.legacy_oracle_install else "fresh_execution"
        )
        obligations = [
            ProofObligation(
                name=execution_name,
                passed=True,
                evidence_digest=Digest.from_bytes(
                    canonical_json(
                        {
                            "run": self.context.run_binding,
                            "obligation": execution_name,
                            "intervention": intervention,
                            "witness": witness.evidence_digest,
                        }
                    )
                ),
            )
        ]
        semantic_proofs: tuple[SemanticProof, ...] = ()
        if witness.semantic_proof is not None:
            if not isinstance(intervention, ClassicRecipeIntervention) or (
                witness.semantic_proof.family != intervention.family.value
            ):
                raise ClassicProjectError("semantic proof family differs from intervention")
            obligations.append(
                ProofObligation(
                    name=classic_semantic_obligation_name(intervention.family),
                    passed=True,
                    evidence_digest=witness.semantic_proof.evidence_digest,
                )
            )
            semantic_payload = witness.semantic_proof.model_dump(mode="python")
            semantic_payload["artifact_claims"] = self._semantic_claims(
                witness.semantic_proof, artifact_ids
            )
            semantic_proofs = (SemanticProof.model_validate(semantic_payload),)
        self.certificates[witness.intervention_id] = Certificate(
            id=certificate_id,
            intervention_id=witness.intervention_id,
            obligations=tuple(sorted(obligations, key=lambda item: item.name)),
            artifact_ids=tuple(sorted(set(artifact_ids))),
            semantic_proofs=semantic_proofs,
        )
        return certificate_id

    def _attach_certificate(self, artifact_id: str, certificate_id: str) -> None:
        node_id = self.terminal_node[artifact_id]
        node = self.provenance[node_id]
        self.provenance[node_id] = node.model_copy(
            update={"certificate_ids": tuple(sorted({*node.certificate_ids, certificate_id}))}
        )

    def _bind_overlay_certificates(self) -> None:
        compiler_objects = {
            item.reference.casefold(): self.current_by_reference[item.reference.casefold()]
            for item in self.record.compiler_outputs
            if self._artifact_kind(item.reference) is ArtifactKind.OBJECT
        }
        for intervention_id in self._overlay_intervention_ids():
            witness = self.witnesses[intervention_id]
            proof = witness.semantic_proof
            if proof is None or not isinstance(proof.output_statement, Mapping):
                raise ClassicProjectError("source-overlay proof omits its output statement")
            epoch = proof.output_statement.get("project_overlay_epoch")
            audits = epoch.get("compiler_audits") if isinstance(epoch, Mapping) else None
            if not isinstance(audits, list):
                raise ClassicProjectError("source-overlay proof omits compiler audits")
            object_ids: list[str] = []
            for row in audits:
                reference = row.get("object_ref") if isinstance(row, Mapping) else None
                if not isinstance(reference, str):
                    raise ClassicProjectError("source-overlay compiler audit is malformed")
                artifact_id = compiler_objects.get(reference.casefold())
                if artifact_id is None:
                    raise ClassicProjectError(
                        f"source-overlay audit names an unknown object: {reference!r}"
                    )
                object_ids.append(artifact_id)
            artifact_ids = tuple(
                dict.fromkeys([*sorted(self.overlay_artifacts[intervention_id]), *object_ids])
            )
            certificate_id = self._add_certificate(witness, artifact_ids)
            for artifact_id in artifact_ids:
                self._attach_certificate(artifact_id, certificate_id)

    def _add_donor_outputs(self) -> None:
        for donor in self.record.donor_outputs:
            node = self.nodes.get(donor.node_id)
            if node is None or node.role is not ProducerRole.COMPILER:
                raise ClassicProjectError("private donor names an invalid compiler node")
            reads = [
                item
                for item in self.reads_by_node.get(donor.node_id, [])
                if item.epoch == f"donor:{donor.intervention_id}"
            ]
            if len(reads) != 1:
                raise ClassicProjectError("private donor lacks its recursive read receipt")
            read_receipt = reads[0]
            if read_receipt.namespace_id is None:
                raise ClassicProjectError("private donor lacks its shared namespace receipt")
            inputs = tuple(
                dict.fromkeys(
                    [
                        self._tool_artifact(ProducerRole.COMPILER),
                        self._compiler_namespace_artifact(read_receipt.namespace_id),
                        *(self._source_read_artifact(item) for item in read_receipt.reads),
                    ]
                )
            )
            synthetic_reference = f"build/private-donors/{donor.intervention_id}.obj"
            artifact_id = self._add_produced_artifact(
                node=node,
                reference=synthetic_reference,
                digest=donor.digest,
                size=donor.size,
                step_id=donor.step_id,
                inputs=inputs,
                captured=True,
                logical_path=f".reprobit/private-donors/{donor.intervention_id}.obj",
            )
            witness = self.witnesses[donor.intervention_id]
            certificate_id = self._add_certificate(witness, (artifact_id,))
            self._attach_certificate(artifact_id, certificate_id)

    def _stage_artifact(
        self,
        *,
        witness: InterventionWitness,
        current_id: str,
        logical_path: str,
        additional_inputs: Sequence[str] = (),
        fallback_receipt: FileReceipt | None = None,
    ) -> str:
        proof = witness.semantic_proof
        candidate = (
            _statement_candidate_receipt(proof.output_statement) if proof is not None else None
        )
        if candidate is None:
            if fallback_receipt is None:
                raise ClassicProjectError(
                    f"intervention {witness.intervention_id!r} lacks an output receipt"
                )
            digest, size = fallback_receipt.digest, fallback_receipt.size
        else:
            digest, size = candidate
        inputs = tuple(dict.fromkeys((current_id, *additional_inputs)))
        artifact_id = _evidence_identifier(
            "artifact", "transform", witness.intervention_id, digest, size
        )
        certificate_id = _evidence_identifier("certificate", witness.intervention_id)
        intervention = self.interventions[witness.intervention_id]
        family = getattr(intervention, "family", None)
        metadata = family is ClassicRecipeFamily.IMAGE_METADATA
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=self.artifacts[current_id].kind,
                logical_path=logical_path,
                digest=digest,
                size=size,
                origin=ArtifactOrigin.COMPOSED,
                inputs=inputs,
                receipt_path=(
                    str(fallback_receipt.path)
                    if fallback_receipt is not None
                    else self.artifacts[current_id].receipt_path
                ),
            ),
            kind=(
                ProvenanceKind.ORACLE_INSTALL
                if witness.legacy_oracle_install
                else (
                    ProvenanceKind.METADATA_TRANSFORM if metadata else ProvenanceKind.INTERVENTION
                )
            ),
            operation=(
                "oracle_install"
                if witness.legacy_oracle_install
                else ("metadata_transform" if metadata else "classic_transform")
            ),
            origin=(
                ArtifactOrigin.ORACLE if witness.legacy_oracle_install else ArtifactOrigin.COMPOSED
            ),
            parent_artifacts=inputs,
            intervention_id=witness.intervention_id,
            certificate_ids=(certificate_id,),
        )
        self._add_certificate(witness, (artifact_id,))
        return artifact_id

    def _semantic_input_artifacts(self, witness: InterventionWitness) -> tuple[str, ...]:
        proof = witness.semantic_proof
        if proof is None:
            return ()
        matches = [
            artifact.id
            for artifact in self.artifacts.values()
            if _statement_has_receipt(proof.input_statement, artifact.digest, artifact.size)
        ]
        return tuple(sorted(matches))

    def _apply_translation_unit_transforms(self) -> None:
        for unit in sorted(self.executor.units, key=lambda item: item.plan.id.casefold()):
            record = self.executor._record_for_unit(unit)
            node = self.nodes[record.node_id]
            _, object_reference = self.executor._compiler_product_refs(node)
            current = self.current_by_reference[object_reference.casefold()]
            for action in unit.actions:
                witness = self.witnesses[action.id]
                current = self._stage_artifact(
                    witness=witness,
                    current_id=current,
                    logical_path=self.artifacts[current].logical_path,
                    additional_inputs=self._semantic_input_artifacts(witness),
                )
            path = self.executor._reference(object_reference)
            assert path is not None
            receipt = self.output_receipts[path.resolve(strict=False)]
            if self.artifacts[current].digest != receipt.digest or (
                self.artifacts[current].size != receipt.size
            ):
                raise ClassicProjectError(
                    f"semantic object stages differ from the final output: {object_reference!r}"
                )
            self.current_by_reference[object_reference.casefold()] = current

    def _apply_object_repack_transforms(self) -> None:
        for intervention in sorted(
            self.interventions.values(), key=lambda item: item.id.casefold()
        ):
            if not isinstance(intervention, ClassicRecipeIntervention):
                continue
            values = {item.name: item.value for item in intervention.parameters}
            declaration = values.get("rdata_pool_repack")
            if not isinstance(declaration, dict):
                continue
            value = declaration.get("object")
            if not isinstance(value, str):
                raise ClassicProjectError("rdata object declaration is malformed")
            reference = f"build/{_safe_relative(value)}"
            current = self.current_by_reference.get(reference.casefold())
            if current is None:
                raise ClassicProjectError("rdata object has no compiler ancestry")
            path = self.executor._reference(reference)
            assert path is not None
            receipt = self.output_receipts[path.resolve(strict=False)]
            transformed = self._stage_artifact(
                witness=self.witnesses[intervention.id],
                current_id=current,
                logical_path=self.artifacts[current].logical_path,
                additional_inputs=self._semantic_input_artifacts(self.witnesses[intervention.id]),
                fallback_receipt=receipt,
            )
            if self.artifacts[transformed].digest != receipt.digest or (
                self.artifacts[transformed].size != receipt.size
            ):
                raise ClassicProjectError("rdata semantic output differs from final object")
            self.current_by_reference[reference.casefold()] = transformed

    def _publish_targets(self) -> None:
        specs = {item.id: item for item in self.context.bundle.spec.targets}

        def is_raw_output(reference: str, raw_path: Path) -> bool:
            path = self.executor._reference(reference)
            return path is not None and path.resolve(strict=False) == raw_path.resolve(strict=False)

        link_outputs = {
            item.raw_path.resolve(strict=False): self.current_by_reference[
                next(
                    reference.casefold()
                    for node in self.executor.graph.nodes
                    if node.id == item.link_step_id
                    for reference in node.outputs
                    if is_raw_output(reference, item.raw_path)
                )
            ]
            for item in self.record.images
        }
        for image in sorted(self.record.images, key=lambda item: item.target_id):
            current = link_outputs[image.raw_path.resolve(strict=False)]
            final_receipt = self.output_receipts.get(image.final_path.resolve(strict=False))
            if final_receipt is None:
                raise ClassicProjectError("published target lacks its final build receipt")
            for witness in image.witnesses:
                current = self._stage_artifact(
                    witness=witness,
                    current_id=current,
                    logical_path=specs[image.target_id].artifact,
                    additional_inputs=self._semantic_input_artifacts(witness),
                    fallback_receipt=final_receipt,
                )
            if image.witnesses:
                if self.artifacts[current].digest != final_receipt.digest or (
                    self.artifacts[current].size != final_receipt.size
                ):
                    raise ClassicProjectError(
                        "terminal semantic output differs from published target"
                    )
            else:
                linked = self.artifacts[current]
                if linked.digest != final_receipt.digest or (linked.size != final_receipt.size):
                    raise ClassicProjectError(
                        "linked image differs from its published target receipt"
                    )
                if linked.logical_path == specs[image.target_id].artifact:
                    continue
                artifact_id = _evidence_identifier(
                    "artifact",
                    "published-target",
                    image.target_id,
                    final_receipt.digest,
                    final_receipt.size,
                )
                self._add_artifact(
                    Artifact(
                        id=artifact_id,
                        kind=ArtifactKind.IMAGE,
                        logical_path=specs[image.target_id].artifact,
                        digest=final_receipt.digest,
                        size=final_receipt.size,
                        origin=ArtifactOrigin.COMPOSED,
                        inputs=(current,),
                        receipt_path=str(image.final_path.resolve(strict=False)),
                    ),
                    kind=ProvenanceKind.PRODUCER,
                    operation="publish",
                    origin=ArtifactOrigin.COMPOSED,
                    parent_artifacts=(current,),
                )


def _digest_path(path: Path) -> Digest:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return Digest(value=digest.hexdigest())


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _secure_copy_new(
    source: Path,
    destination: Path,
    *,
    expected: ReceiptBoundInput | None = None,
) -> SecureFileSnapshot:
    """Copy one run-private file without following or replacing path entries."""

    source = canonical_system_path(source)
    destination = canonical_system_path(destination)
    if not source.anchor or not destination.anchor:
        raise ClassicProjectError("classic warm copy requires absolute paths")
    source_root = Path(source.anchor)
    destination_root = Path(destination.anchor)
    source_relative = PurePosixPath(*source.parts[1:]).as_posix()
    destination_relative = PurePosixPath(*destination.parts[1:]).as_posix()
    try:
        source_identity = stat_relative_file(source_root, source_relative)
        expected_identity = source_identity
        expected_digest: Digest | None = None
        expected_size: int | None = None
        executable = bool(source_identity.mode & stat.S_IXUSR)
        if expected is not None:
            if canonical_system_path(expected.snapshot.path) != source:
                raise ClassicProjectError(
                    "classic warm dependency path differs from its receipt-bound view"
                )
            expected_identity = SecureFileIdentity(
                expected.snapshot.path,
                expected.snapshot.size,
                expected.snapshot.device,
                expected.snapshot.inode,
                expected.snapshot.mtime_ns,
                expected.snapshot.mode,
                expected.snapshot.ctime_ns,
                expected.snapshot.windows_file_id,
                expected.snapshot.windows_attributes,
            )
            expected_digest = Digest(value=expected.output.digest)
            expected_size = expected.output.size
            executable = expected.output.executable
        received = atomic_copy_new_relative(
            source_root,
            source_relative,
            destination_root,
            destination_relative,
            executable=executable,
            expected_digest=expected_digest,
            expected_size=expected_size,
            expected_source=expected_identity,
        )
        if expected is not None and (
            received.digest.value != expected.output.digest
            or received.size != expected.output.size
            or bool(received.mode & stat.S_IXUSR) != expected.output.executable
        ):
            raise ClassicProjectError(
                "classic warm dependency copy differs from its cache receipt"
            )
        return received
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(
            f"classic warm copy could not safely publish {destination}: {exc}"
        ) from exc


def _secure_remove_regular(path: Path) -> None:
    """Remove one exact run-private regular file without following parents."""

    path = Path(os.path.abspath(path))
    if not path.anchor:
        raise ClassicProjectError("classic warm erasure requires an absolute path")
    root = Path(path.anchor)
    relative = PurePosixPath(*path.parts[1:]).as_posix()
    try:
        removed = remove_regular_relative(root, relative)
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(
            f"classic warm output could not be erased safely: {path}: {exc}"
        ) from exc
    if not removed:
        raise ClassicProjectError(f"classic warm output disappeared before erasure: {path}")


def _runtime_authority_label(path: Path) -> str:
    """Give one external authority a stable full-path namespace identity."""

    canonical = Path(os.path.abspath(path)).resolve(strict=True)
    return "runtime-authority:" + canonical.as_posix()


def _erase_warm_replay_arena(arena: Path, *, replay_root: Path) -> None:
    """Erase every regular discard output and its exact run-private arena."""

    arena = Path(os.path.abspath(arena))
    replay_root = Path(os.path.abspath(replay_root))
    if arena.parent != replay_root or arena.is_symlink() or not arena.is_dir():
        raise ClassicProjectError(f"classic warm replay arena is redirected: {arena}")
    try:
        entries = tuple(arena.iterdir())
    except OSError as exc:
        raise ClassicProjectError(
            f"classic warm replay arena cannot be enumerated: {arena}"
        ) from exc
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise ClassicProjectError(
                f"classic warm replay produced a non-regular discard entry: {entry}"
            )
        _secure_remove_regular(entry)
    try:
        arena.rmdir()
    except OSError as exc:
        raise ClassicProjectError(
            f"classic warm replay arena could not be erased: {arena}"
        ) from exc


def _erase_donor_dependency_outputs(paths: Sequence[Path]) -> None:
    """Erase exact case-insensitive replay outputs without touching donor bytes."""

    for path in paths:
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise ClassicProjectError(
                f"donor dependency output parent is absent or redirected: {parent}"
            )
        matches = tuple(
            item for item in parent.iterdir() if item.name.casefold() == path.name.casefold()
        )
        if len(matches) > 1:
            raise ClassicProjectError(
                f"donor dependency output has {len(matches)} physical aliases: {path}"
            )
        if not matches:
            continue
        actual = matches[0]
        if actual.is_symlink() or not actual.is_file():
            raise ClassicProjectError(
                f"donor dependency output is not a regular file: {actual}"
            )
        _secure_remove_regular(actual)


def _receipt(path: Path, *, fresh: bool, producer_step: str | None) -> FileReceipt:
    if path.is_symlink() or not path.is_file():
        raise ClassicProjectError(f"classic output is absent or redirected: {path}")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ClassicProjectError(f"classic output is not regular: {path}")
    digest = _digest_path(path)
    after = path.stat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ClassicProjectError(f"classic output changed while receipted: {path}")
    return FileReceipt(
        path.resolve(strict=True),
        digest,
        after.st_size,
        fresh,
        producer_step,
        after.st_dev,
        after.st_ino,
    )


def _tree_file_seal(root: Path) -> Mapping[Path, tuple[int, Digest]]:
    """Snapshot regular files beneath a producer-writable seat."""

    sealed: dict[Path, tuple[int, Digest]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_symlink():
            raise ClassicProjectError(f"producer build tree contains a symlink: {path}")
        if path.is_file():
            resolved = path.resolve(strict=True)
            sealed[resolved] = (path.stat().st_size, _digest_path(path))
    return MappingProxyType(sealed)


def _require_declared_tree_writes(
    before: Mapping[Path, tuple[int, Digest]],
    *,
    root: Path,
    allowed_outputs: Iterable[Path],
    phase: str,
) -> None:
    """Reject residual producer writes outside the committed output set."""

    after = _tree_file_seal(root)
    changed = {path for path in set(before) | set(after) if before.get(path) != after.get(path)}
    allowed = {path.resolve(strict=False) for path in allowed_outputs}
    unexpected = sorted(changed - allowed, key=str)
    if unexpected:
        raise ClassicProjectError(
            f"{phase} wrote undeclared build-tree files: "
            + ", ".join(str(path) for path in unexpected[:12])
        )


def _require_unchanged_tree(
    before: Mapping[Path, tuple[int, Digest]], *, root: Path, label: str
) -> None:
    """Require a complete read-only seat to retain exact membership and bytes."""

    after = _tree_file_seal(root)
    changed = sorted(
        (path for path in set(before) | set(after) if before.get(path) != after.get(path)),
        key=str,
    )
    if changed:
        raise ClassicProjectError(
            f"{label} changed during execution: " + ", ".join(str(path) for path in changed[:12])
        )


def _semantic_statement_digest(statement: Mapping[str, object], *components: str) -> Digest:
    current: object = statement
    for component in components:
        if not isinstance(current, Mapping):
            raise ClassicProjectError("classic semantic statement path is malformed")
        current = current.get(component)
    try:
        return Digest.model_validate(current)
    except ValueError as exc:
        raise ClassicProjectError("classic semantic statement digest is malformed") from exc


def _command_digest(argv: Sequence[str], cwd: Path, environment: Mapping[str, str]) -> Digest:
    return Digest.from_bytes(
        canonical_json(
            {
                "argv": list(argv),
                "cwd": str(cwd),
                "environment": dict(sorted(environment.items())),
            }
        )
    )


def _step_receipt(step_id: str, result: ProcessResult, spec: CommandSpec) -> StepExecutionReceipt:
    return StepExecutionReceipt(
        step_id,
        result.returncode,
        result.attempts,
        result.duration_seconds,
        Digest.from_bytes(result.output),
        _command_digest(result.argv, spec.cwd, spec.environment_mapping),
    )


def _internal_step(step_id: str, material: object, duration: float) -> StepExecutionReceipt:
    digest = Digest.from_bytes(canonical_json(material))
    return StepExecutionReceipt(step_id, 0, 1, duration, digest, digest)


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ClassicProjectError(f"unsafe discovered project path: {value!r}")
    return path.as_posix()


def _logical_relative_parts(value: str, *, drive_letter: str) -> tuple[str, ...]:
    normalized = normalize_logical_path(value)
    path = PureWindowsPath(normalized)
    if path.drive.rstrip(":").upper() != drive_letter:
        raise ClassicProjectError(f"logical path {value!r} is outside drive {drive_letter}:")
    return tuple(path.parts[1:])


def _logical_join(root: str, relative: str) -> str:
    suffix = "\\".join(PurePosixPath(relative).parts)
    return normalize_logical_path(root.rstrip("\\") + "\\" + suffix)


def _compiler_read_reference(
    logical_path: str,
    *,
    source_root: str,
    toolchain_root: str,
) -> str:
    """Convert one sealed DOS compiler read into a portable authority reference."""

    path = PureWindowsPath(normalize_logical_path(logical_path))
    for authority, raw_root in (
        ("source", source_root),
        ("toolchain", toolchain_root),
    ):
        root = PureWindowsPath(normalize_logical_path(raw_root))
        if len(path.parts) <= len(root.parts) or tuple(
            item.casefold() for item in path.parts[: len(root.parts)]
        ) != tuple(item.casefold() for item in root.parts):
            continue
        relative = PurePosixPath(*path.parts[len(root.parts) :]).as_posix()
        return f"{authority}/{relative}"
    raise ClassicProjectError(f"compiler read leaves source/toolchain authority: {logical_path!r}")


_CLASSIC_TOOLCHAIN_ENVIRONMENT_VARIABLES = ("PATH", "INCLUDE", "LIB", "LIBPATH")


def _rooted_toolchain_environment(
    environment: Mapping[str, str],
    *,
    logical_toolchain_root: str,
) -> dict[str, str]:
    """Render the rooted path spelling in the classic producer contract."""

    root = normalize_logical_path(logical_toolchain_root)
    rendered = dict(environment)
    folded = [key.casefold() for key in rendered]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("classic environment repeats a case-insensitive key")
    keys = {key.casefold(): key for key in rendered}
    for name in _CLASSIC_TOOLCHAIN_ENVIRONMENT_VARIABLES:
        key = keys.get(name.casefold())
        if key is None:
            raise ClassicProjectError(f"classic producer environment lacks one {name}")
        parts = tuple(rendered[key].split(";"))
        if not parts or any(not item for item in parts):
            raise ClassicProjectError(f"classic producer environment {name} is malformed")
        rooted: list[str] = []
        for item in parts:
            try:
                canonical = normalize_logical_path(item)
                if canonical != item:
                    raise ValueError("path presentation is not canonical")
                logical_relative_to(canonical, root)
            except Exception as exc:
                raise ClassicProjectError(
                    f"classic producer environment {name} leaves the toolchain root"
                ) from exc
            rooted.append(canonical[2:])
        rendered[key] = ";".join(rooted)
    return rendered


def _classic_producer_environment(
    installation: ClassicMSVCToolchain,
    *,
    temp_directory: str,
) -> dict[str, str]:
    environment = installation.default_environment(temp_directory=temp_directory)
    environment["LIBPATH"] = environment["LIB"]
    return _rooted_toolchain_environment(
        environment,
        logical_toolchain_root=installation.logical_root,
    )


def _compiler_environment_path_material(value: str) -> dict[str, str]:
    if value.startswith("\\") and not value.startswith("\\\\"):
        canonical = normalize_logical_path("Z:" + value)
        if canonical[2:] != value:
            raise ValueError("rooted path presentation is not canonical")
        return {
            "kind": "rooted-no-drive",
            "presentation": value,
        }
    canonical = normalize_logical_path(value)
    if canonical != value:
        raise ValueError("drive-absolute path presentation is not canonical")
    return {
        "kind": "drive-absolute",
        "presentation": value,
    }


def _compiler_environment_digest(environment: Mapping[str, str]) -> Digest:
    """Validate and bind exact frontend-visible toolchain path presentations."""

    variables: dict[str, tuple[dict[str, str], ...]] = {}
    for name in ("INCLUDE", "LIB", "LIBPATH", "WINEPATH"):
        matches = [value for key, value in environment.items() if key.casefold() == name.casefold()]
        if len(matches) > 1 or (name != "WINEPATH" and len(matches) != 1):
            raise ClassicProjectError(f"compiler environment does not uniquely bind {name}")
        if not matches:
            variables[name] = ()
            continue
        parts = tuple(matches[0].split(";"))
        if not parts or any(not item for item in parts):
            raise ClassicProjectError(f"compiler environment {name} is malformed")
        try:
            variables[name] = tuple(_compiler_environment_path_material(item) for item in parts)
        except Exception as exc:
            raise ClassicProjectError(
                f"compiler environment {name} leaves the logical path profile"
            ) from exc
    override_matches = [
        value
        for key, value in environment.items()
        if key.casefold() == "winedlloverrides"
    ]
    if len(override_matches) > 1 or any(
        not value or "\0" in value for value in override_matches
    ):
        raise ClassicProjectError("compiler environment does not uniquely bind DLL overrides")
    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 3,
                "dll_overrides": override_matches[0] if override_matches else None,
                "variables": {name: list(values) for name, values in variables.items()},
            }
        )
    )


def _materialize_direct_logical_workspace(
    bundle: ProjectBundle,
    *,
    session_root: Path,
    toolchain_root: Path,
) -> _DirectLogicalWorkspace:
    """Materialize only seats named by the committed producer graph.

    Runtime authenticity never runs project CMake, so no host CMake runtime or
    probe tree is projected into the producer-visible drive.
    """

    declared = tuple(
        normalize_logical_path(value)
        for value in (
            bundle.spec.paths.source,
            bundle.spec.paths.build,
            bundle.spec.paths.toolchain,
        )
    )
    drives = {PureWindowsPath(value).drive.rstrip(":").upper() for value in declared}
    if len(drives) != 1:
        raise ClassicProjectError("classic logical seats must share one DOS drive")
    drive_letter = drives.pop()
    folded = tuple(value.casefold().rstrip("\\") for value in declared)
    for index, left in enumerate(folded):
        for right in folded[index + 1 :]:
            if left == right or left.startswith(right + "\\") or right.startswith(left + "\\"):
                raise ClassicProjectError("classic logical seats overlap")
    root = session_root / "logical-drive"

    def host_path(logical: str) -> Path:
        return root.joinpath(*_logical_relative_parts(logical, drive_letter=drive_letter))

    # The direct executor projects the finite locked toolchain closure into
    # this real drive tree below.  Mapping the caller's entire installation
    # would expose unpinned siblings to producer/source-controlled paths.
    toolchain_root.resolve(strict=True)
    root.mkdir(parents=True, exist_ok=False)
    materialized = MaterializedSkeleton(root.resolve(strict=True), drive_letter, ())
    return _DirectLogicalWorkspace(
        root=root,
        drive_letter=drive_letter,
        effective_root=host_path(declared[0]),
        build_root=host_path(declared[1]),
        toolchain_entry=host_path(declared[2]),
        materialized=materialized,
    )


def _project_locked_toolchain(
    bundle: ProjectBundle,
    *,
    source_root: Path,
    destination: Path,
) -> tuple[Path, ...]:
    """Copy only lock-admitted producer/runtime/tree files into the DOS seat."""

    source_root = source_root.resolve(strict=True)
    if destination.exists():
        raise ClassicProjectError("locked toolchain projection destination already exists")
    destination.mkdir(parents=True)
    relatives: set[PurePosixPath] = {
        PurePosixPath(item.path)
        for item in (
            *bundle.toolchain_lock.tools,
            *bundle.toolchain_lock.runtime_files,
        )
    }
    for tree in bundle.toolchain_lock.input_trees:
        relative_root = PurePosixPath(tree.path)
        physical_root = source_root.joinpath(*relative_root.parts)
        if physical_root.is_symlink() or not physical_root.is_dir():
            raise ClassicProjectError(
                f"locked toolchain input tree is absent or redirected: {tree.path!r}"
            )
        for child in physical_root.rglob("*"):
            if child.is_symlink():
                raise ClassicProjectError(
                    f"locked toolchain input tree contains a symlink: {child}"
                )
            if child.is_file():
                relatives.add(relative_root / child.relative_to(physical_root).as_posix())
    folded = [relative.as_posix().casefold() for relative in relatives]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("locked toolchain closure has DOS-case collisions")
    originals: list[Path] = []
    for relative in sorted(relatives, key=lambda item: item.as_posix().casefold()):
        source = source_root.joinpath(*relative.parts)
        if source.is_symlink() or not source.is_file():
            raise ClassicProjectError(
                f"locked toolchain file is absent or redirected: {relative.as_posix()!r}"
            )
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
        if target.is_symlink() or _digest_path(target) != _digest_path(source):
            raise ClassicProjectError(
                f"locked toolchain projection differs: {relative.as_posix()!r}"
            )
        originals.append(source.resolve(strict=True))
    return tuple(originals)


def _install_path_proxies(
    session_root: Path,
) -> tuple[Mapping[str, Path], Path]:
    template = runtime_asset_path("ReproBitPathProxy.sh")
    if template.is_symlink() or not template.is_file():
        raise ClassicProjectError("classic path-proxy template is absent or redirected")
    proxy_root = session_root / "path-proxies"
    proxy_root.mkdir()
    proxies: dict[str, Path] = {}
    for name in ("cl", "rc", "link", "lib"):
        destination = proxy_root / name
        shutil.copyfile(template, destination)
        destination.chmod(stat.S_IRUSR | stat.S_IXUSR)
        proxies[name] = destination
    return MappingProxyType(proxies), template


def _install_pinned_wine_alias(session_root: Path, wine: Path) -> Path:
    """Give an opaque transport's ``command -v wine`` one exact pinned result."""

    wine = wine.resolve(strict=True)
    if wine.is_symlink() or not wine.is_file():
        raise ClassicProjectError("pinned Wine executable is absent or redirected")
    alias_root = session_root / "host-tool-aliases"
    alias_root.mkdir(exist_ok=False)
    alias = alias_root / "wine"
    alias.write_text(
        "#!/bin/sh\nexec " + shlex.quote(str(wine)) + ' "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    alias.chmod(stat.S_IRUSR | stat.S_IXUSR)
    return alias.resolve(strict=True)


def _close_unbound_wine_worker(backend: PosixWineBackend, worker: WorkerSandbox) -> None:
    """Reap one initialized worker that never reached logical-drive binding."""

    try:
        backend.terminate_worker_server(worker)
    finally:
        backend.scrub_worker_drive_mappings(worker)


def _prepare_execution_lanes(
    bundle: ProjectBundle,
    *,
    installation: ClassicMSVCToolchain,
    backend: ExecutionBackend,
    logical_workspace: _DirectLogicalWorkspace,
    session_root: Path,
    role_commands: Mapping[ProducerRole, Path],
    host_programs: Sequence[Path],
    frontend_environment: Mapping[str, str],
    jobs: int,
    initialization_timeout: float,
    cleanup_timeout: float,
    wine_alias: Path | None,
) -> _LazyExecutionLanePool:
    """Describe a lazy producer-lane pool without initializing its backend."""

    if jobs < 1 or min(initialization_timeout, cleanup_timeout) <= 0:
        raise ClassicProjectError("classic execution lane limits must be positive")
    # Runtime-authority files trust and seal their containing-directory anchor;
    # paths above it are identity-held but deliberately ignore unrelated
    # sibling churn.  Create the lazy worker container before any namespace
    # lease is acquired so a lane never mutates an ancestor of a readable
    # session authority after that authority has been sealed.
    backend_workers_root = session_root / "backend-workers"
    backend_workers_root.mkdir(exist_ok=False)
    temporary_root = logical_workspace.build_root / ".reprobit-tmp"
    temporary_root.mkdir(parents=True, exist_ok=False)
    binding_lock = Lock()
    bindings: list[tuple[WorkerSandbox, ExitStack]] = []
    native_worker: WorkerSandbox | None = None
    native_lineage_planner: WindowsLineagePlanner | None = None

    def producer_environment(lane_id: str) -> dict[str, str]:
        logical_temporary = _logical_join(bundle.spec.paths.build, f".reprobit-tmp/{lane_id}")
        return _classic_producer_environment(
            installation,
            temp_directory=logical_temporary,
        )

    digest_environment = producer_environment("lane-0000")
    if isinstance(backend, PosixWineBackend):
        path_values = [
            value for key, value in digest_environment.items() if key.casefold() == "path"
        ]
        if len(path_values) != 1:
            raise ClassicProjectError("classic Wine environment lacks one PATH")
        digest_environment["WINEPATH"] = path_values[0]
        overrides = ";".join(
            f"{library}={mode}" for library, mode in installation.profile.wine_dll_overrides
        )
        if overrides:
            digest_environment["WINEDLLOVERRIDES"] = overrides
    compiler_environment_digest = _compiler_environment_digest(digest_environment)

    def bind_worker(
        worker: WorkerSandbox,
    ) -> tuple[ExitStack, WindowsLineagePlanner | None]:
        stack = ExitStack()
        try:
            binding = stack.enter_context(
                backend.bind_skeleton(worker, logical_workspace.materialized)
            )
            if isinstance(backend, PosixWineBackend):
                backend.verify_worker_drive_mappings(
                    worker, logical_drive=logical_workspace.drive_letter
                )
            lineage_planner: WindowsLineagePlanner | None = None
            if isinstance(backend, NativeWindowsBackend):
                if not isinstance(binding, NativeDeviceMapLease):
                    raise ClassicProjectError(
                        "native Windows backend returned an unrecognized logical-drive lease"
                    )
                lineage_planner = binding
            return stack, lineage_planner
        except BaseException:
            stack.close()
            raise

    def create(index: int) -> _ExecutionLane:
        nonlocal native_lineage_planner, native_worker
        lane_id = f"lane-{index:04d}"
        worker: WorkerSandbox
        stack: ExitStack | None = None
        attempted_initialization = False
        if isinstance(backend, PosixWineBackend):
            worker = backend.create_worker(backend_workers_root, f"producer-graph-{index:04d}")
            try:
                attempted_initialization = True
                backend.initialize_worker_prefix(
                    worker,
                    timeout_seconds=min(initialization_timeout, 300),
                )
                stack, lineage_planner = bind_worker(worker)
                if lineage_planner is not None:
                    raise ClassicProjectError(
                        "POSIX backend unexpectedly returned a Windows lineage planner"
                    )
            except BaseException as original:
                cleanup_error: BaseException | None = None
                try:
                    if stack is not None:
                        _close_backend_runtime(
                            backend,
                            worker,
                            stack,
                            logical_drive=logical_workspace.drive_letter,
                            timeout_seconds=cleanup_timeout,
                        )
                    elif attempted_initialization:
                        _close_unbound_wine_worker(backend, worker)
                except BaseException as exc:
                    cleanup_error = exc
                if cleanup_error is not None:
                    original.add_note(
                        f"classic lane initialization cleanup also failed: {cleanup_error}"
                    )
                raise
            assert stack is not None
            with binding_lock:
                bindings.append((worker, stack))
        else:
            with binding_lock:
                if native_worker is None:
                    candidate = backend.create_worker(backend_workers_root, "producer-graph")
                    candidate_stack, candidate_planner = bind_worker(candidate)
                    if isinstance(backend, NativeWindowsBackend) and (
                        candidate_planner is None
                    ):
                        raise ClassicProjectError(
                            "native Windows lane lacks a fresh-LUID lineage planner"
                        )
                    native_worker = candidate
                    native_lineage_planner = candidate_planner
                    bindings.append((candidate, candidate_stack))
                worker = native_worker

        physical_temporary = temporary_root / lane_id
        try:
            physical_temporary.mkdir()
            windows_environment = producer_environment(lane_id)
            environment = _host_environment((*host_programs, *role_commands.values()))
            if isinstance(backend, PosixWineBackend):
                environment.update(
                    backend.worker_environment(
                        worker,
                        windows_environment=windows_environment,
                        dll_overrides=installation.profile.wine_dll_overrides,
                    )
                )
                environment.update(
                    {
                        **frontend_environment,
                        "REPROBIT_PHYSICAL_DRIVE_ROOT": str(logical_workspace.root),
                        "REPROBIT_LOGICAL_DRIVE_ROOT": (f"{logical_workspace.drive_letter}:"),
                        "REPROBIT_PHYSICAL_TOOLCHAIN_ROOT": str(installation.root),
                        "REPROBIT_LOGICAL_TOOLCHAIN_ROOT": (
                            bundle.spec.paths.toolchain.replace("\\", "/")
                        ),
                    }
                )
                if wine_alias is None:
                    raise ClassicProjectError("POSIX execution omitted the pinned Wine alias")
                environment["PATH"] = os.pathsep.join((str(wine_alias.parent), environment["PATH"]))
            else:
                windows_environment["PATH"] = os.pathsep.join(
                    (windows_environment["PATH"], environment["PATH"])
                )
                environment.update(windows_environment)
            return _ExecutionLane(
                lane_id,
                MappingProxyType(environment),
                worker,
                native_lineage_planner,
            )
        except BaseException:
            # The binding is owned by close_created.  The pool records this
            # failure and prepare/execution cleanup closes every created lease.
            raise

    def close_created() -> None:
        error: BaseException | None = None
        with binding_lock:
            owned = tuple(reversed(bindings))
            bindings.clear()
        for worker, stack in owned:
            try:
                _close_backend_runtime(
                    backend,
                    worker,
                    stack,
                    logical_drive=logical_workspace.drive_letter,
                    timeout_seconds=cleanup_timeout,
                )
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    return _LazyExecutionLanePool(
        maximum=jobs,
        create=create,
        close_created=close_created,
        compiler_environment_digest=compiler_environment_digest,
    )


def _close_backend_runtime(
    backend: ExecutionBackend,
    worker: WorkerSandbox,
    stack: ExitStack,
    *,
    logical_drive: str,
    timeout_seconds: float = 10.0,
) -> None:
    if timeout_seconds <= 0:
        raise ClassicProjectError("classic runtime cleanup timeout must be positive")
    try:
        if isinstance(backend, PosixWineBackend):
            try:
                # Certification fails if Wine exposed any additional host
                # drive while producers were live.
                backend.verify_worker_drive_mappings(
                    worker,
                    logical_drive=logical_drive,
                )
                backend.complete_worker_drive_mapping_lifetime(worker)
            finally:
                # Even a failed certification must stop and reap the private
                # server before mappings are unbound and scrubbed.
                backend.terminate_worker_server(worker, timeout_seconds=timeout_seconds)
    finally:
        try:
            stack.close()
        finally:
            if isinstance(backend, PosixWineBackend):
                backend.scrub_worker_drive_mappings(worker)


def _tool_with_role(bundle: ProjectBundle, role: str) -> tuple[str, str]:
    matches = [item for item in bundle.toolchain_lock.tools if role in item.roles]
    if len(matches) != 1:
        raise ClassicProjectError(f"toolchain lock does not uniquely bind role {role!r}")
    return matches[0].id, matches[0].path


def _admitted_host_wrapper(path: Path, *, toolchain_root: Path, label: str) -> Path:
    """Admit an explicitly selected local MSVC transport frontend.

    Canonical toolchain locks identify the Microsoft producers separately from
    their POSIX transport.  Each executed transport sibling is admitted below
    only when the toolchain lock also seals that exact regular file.
    """

    resolved = path.expanduser().resolve(strict=True)
    root = toolchain_root.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ClassicProjectError(f"{label} must be inside the admitted toolchain root") from exc
    if path.is_symlink() or resolved.is_symlink() or not resolved.is_file():
        raise ClassicProjectError(f"{label} must be a regular non-symlink file")
    if not os.access(resolved, os.X_OK):
        raise ClassicProjectError(f"{label} is not executable: {resolved}")
    return resolved


def _locked_wrapper_runtime_files(
    bundle: ProjectBundle,
    wrappers: Sequence[Path],
    *,
    toolchain_root: Path,
) -> tuple[Path, ...]:
    """Admit only the explicitly selected, lock-pinned POSIX transport closure."""

    root = toolchain_root.resolve(strict=True)
    receipts = {
        item.path.replace("\\", "/").casefold(): item
        for item in bundle.toolchain_lock.runtime_files
    }
    admitted: list[Path] = []
    for wrapper in wrappers:
        resolved = wrapper.resolve(strict=True)
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ClassicProjectError("transport file escapes the locked toolchain") from exc
        receipt = receipts.get(relative.casefold())
        if receipt is None:
            raise ClassicProjectError(f"POSIX transport file is not runtime-pinned: {relative!r}")
        if (
            resolved.is_symlink()
            or not resolved.is_file()
            or (receipt.size is not None and receipt.size != resolved.stat().st_size)
            or receipt.digest != _digest_path(resolved)
        ):
            raise ClassicProjectError(
                f"POSIX transport file differs from its runtime pin: {relative!r}"
            )
        admitted.append(resolved)
    folded = [path.as_posix().casefold() for path in admitted]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("POSIX transport closure repeats a file")
    return tuple(admitted)


def _toolchain_tree_files(bundle: ProjectBundle, root: Path) -> tuple[Path, ...]:
    """Expand locked portable input-tree membership into immutable run inputs."""

    files: set[Path] = set()
    admitted_root = root.resolve(strict=True)
    for tree in bundle.toolchain_lock.input_trees:
        tree_root = admitted_root.joinpath(*PurePosixPath(tree.path).parts)
        if tree_root.is_symlink() or not tree_root.is_dir():
            raise ClassicProjectError(f"locked toolchain tree is absent: {tree.path!r}")
        for child in tree_root.rglob("*"):
            if child.is_symlink():
                raise ClassicProjectError(
                    f"locked toolchain tree contains a runtime symlink: {child}"
                )
            if child.is_file():
                files.add(child.resolve(strict=True))
    return tuple(sorted(files, key=str))


def _toolchain_include_reader_payloads(
    bundle: ProjectBundle,
    root: Path,
) -> Mapping[str, bytes]:
    """Read the locked toolchain trees that can feed the preprocessor."""

    include_roots = {
        path.casefold().rstrip("/")
        for path in toolchain_profile(bundle.toolchain_lock.profile).include_roots
    }
    include_roots.update(
        tree.path.casefold().rstrip("/")
        for tree in bundle.toolchain_lock.input_trees
        if "include" in {part.casefold() for part in PurePosixPath(tree.path).parts}
    )
    admitted_root = root.resolve(strict=True)
    payloads: dict[str, bytes] = {}
    for path in _toolchain_tree_files(bundle, admitted_root):
        relative = path.relative_to(admitted_root).as_posix()
        if not any(
            relative.casefold().startswith(include_root + "/")
            for include_root in include_roots
        ):
            continue
        payloads[f"toolchain/{relative}"] = path.read_bytes()
    return MappingProxyType(payloads)


def _host_environment(programs: Sequence[Path]) -> dict[str, str]:
    path = os.pathsep.join(
        dict.fromkeys([*(str(item.parent) for item in programs), *os.defpath.split(os.pathsep)])
    )
    values = {"PATH": path, "LANG": "C", "LC_ALL": "C"}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        values["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return values


def _run(
    supervisor: ProcessSupervisor,
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    log: Path,
    cancellation: CancellationToken | None = None,
    windows_lineage_planner: WindowsLineagePlanner | None = None,
) -> tuple[ProcessResult, CommandSpec]:
    spec = CommandSpec.create(
        argv,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout,
        log_path=log,
    )
    return (
        supervisor.run(
            spec,
            cancellation=cancellation,
            windows_lineage_planner=windows_lineage_planner,
        ),
        spec,
    )


class ClassicProducerGraphBuildExecutor:
    """Execute one committed classic producer graph without a build system."""

    def __init__(
        self,
        *,
        bundle: ProjectBundle,
        project_root: Path,
        session_root: Path,
        build_root: Path,
        effective_root: Path,
        toolchain_root: Path,
        graph: ProducerGraphDocument,
        role_commands: Mapping[ProducerRole, Path],
        role_tool_ids: Mapping[ProducerRole, str],
        wrapper_runtime_files: Sequence[Path],
        authority_inputs: Sequence[Path],
        targets: Sequence[ClassicProducerTarget],
        compile_records: Sequence[_CompileRecord],
        units: Sequence[ClassicPreparedUnit],
        overlay_witnesses: Sequence[InterventionWitness],
        overlay_effective_outputs: Mapping[str, bytes],
        project_source_pairs: Sequence[ProjectOverlaySourcePair],
        compiler_epoch_plan: ProjectOverlayCompilerEpochPlan,
        generated_inputs: frozenset[str],
        carrier_input_seals: Mapping[str, tuple[str, ...]],
        system_libraries: Mapping[str, Path],
        lane_pool: _LazyExecutionLanePool,
        jobs: int,
        compile_timeout: float,
        link_timeout: float,
        progress: ClassicProgressCallback | None = None,
    ) -> None:
        if set(role_commands) != set(ProducerRole) or set(role_tool_ids) != set(ProducerRole):
            raise ClassicProjectError("producer graph does not bind every locked role")
        self.bundle = bundle
        self.project_root = project_root
        self.session_root = session_root
        self.build_root = build_root
        self.effective_root = effective_root
        self.toolchain_root = toolchain_root
        logical_source_parts = _logical_relative_parts(
            bundle.spec.paths.source,
            drive_letter=PureWindowsPath(bundle.spec.paths.source).drive.rstrip(":").upper(),
        )
        logical_drive_root = self.effective_root
        for _ in logical_source_parts:
            logical_drive_root = logical_drive_root.parent
        self._logical_drive_root = logical_drive_root.resolve(strict=True)
        self._logical_drive_letter = (
            PureWindowsPath(bundle.spec.paths.source).drive.rstrip(":").upper()
        )
        for physical, logical in (
            (self.effective_root, bundle.spec.paths.source),
            (self.build_root, bundle.spec.paths.build),
            (self.toolchain_root, bundle.spec.paths.toolchain),
        ):
            expected = self._logical_drive_root.joinpath(
                *_logical_relative_parts(
                    logical,
                    drive_letter=self._logical_drive_letter,
                )
            )
            if physical.resolve(strict=True) != expected.resolve(strict=True):
                raise ClassicProjectError(
                    "classic physical seat differs from its logical drive projection"
                )
        self.graph = graph
        self.role_commands = MappingProxyType(dict(role_commands))
        self.role_tool_ids = MappingProxyType(dict(role_tool_ids))
        self.wrapper_runtime_files = tuple(wrapper_runtime_files)
        self.authority_inputs = tuple(authority_inputs)
        namespace_authority: dict[Path, NamespaceFile] = {}
        for raw in (
            *self.wrapper_runtime_files,
            *self.authority_inputs,
            *self.role_commands.values(),
        ):
            path = raw.resolve(strict=True)
            if path.is_symlink() or not path.is_file():
                raise ClassicProjectError(
                    f"classic runtime authority is absent or redirected: {path}"
                )
            if any(
                _path_is_within(path, root) for root in (self.effective_root, self.toolchain_root)
            ):
                continue
            namespace_authority[path] = NamespaceFile(
                _runtime_authority_label(path),
                path,
                # The containing directory is the explicitly admitted trust
                # anchor.  The lease still holds and rechecks every ancestor
                # by identity and seals this anchor's ctime, so swaps of the
                # authority or its parent fail.  Unrelated sibling churn in a
                # home/volume ancestor cannot invalidate the producer.
                path.parent,
            )
        self._namespace_authority_files = tuple(
            namespace_authority[path]
            for path in sorted(namespace_authority, key=lambda item: str(item).casefold())
        )
        self.targets = tuple(targets)
        self.compile_records = tuple(compile_records)
        self.units = tuple(units)
        self.overlay_witnesses = tuple(overlay_witnesses)
        self.overlay_effective_outputs = MappingProxyType(dict(overlay_effective_outputs))
        self.project_source_pairs = tuple(project_source_pairs)
        self.compiler_epoch_plan = compiler_epoch_plan
        self.generated_inputs = generated_inputs
        self.carrier_input_seals = MappingProxyType(dict(carrier_input_seals))
        generated_nodes: dict[str, tuple[str, ...]] = {}
        carrier_sources = {
            path.casefold(): inputs for path, inputs in self.carrier_input_seals.items()
        }
        seen_carriers: set[str] = set()
        for node in graph.nodes:
            if node.role is not ProducerRole.COMPILER:
                continue
            source_ref, _ = self._compiler_product_refs(node)
            if not source_ref.startswith("source/"):
                continue
            relative = source_ref.removeprefix("source/")
            seal = carrier_sources.get(relative.casefold())
            if seal is None:
                continue
            if relative.casefold() in seen_carriers:
                raise ClassicProjectError(
                    f"generated carrier {relative!r} has more than one compiler node"
                )
            seen_carriers.add(relative.casefold())
            generated_nodes[node.id] = seal
        if seen_carriers != set(carrier_sources):
            missing = sorted(set(carrier_sources) - seen_carriers)
            raise ClassicProjectError(
                f"generated carriers lack committed compiler nodes: {missing}"
            )
        self.generated_node_inputs = MappingProxyType(generated_nodes)
        pair_paths = [item.path.casefold() for item in self.project_source_pairs]
        if len(pair_paths) != len(set(pair_paths)):
            raise ClassicProjectError("project-overlay source pairs overlap")
        if set(pair_paths) != {path.casefold() for path in self.overlay_effective_outputs}:
            raise ClassicProjectError("project-overlay source pairs differ from rendered outputs")
        generated_pair_paths = {
            item.path.casefold() for item in self.project_source_pairs if item.clean_payload is None
        }
        if generated_pair_paths != {path.casefold() for path in self.generated_inputs}:
            raise ClassicProjectError(
                "project-overlay generated source pairs differ from no-clean outputs"
            )
        for item in self.project_source_pairs:
            effective = self.overlay_effective_outputs.get(item.path)
            if effective != item.effective_payload:
                raise ClassicProjectError(f"project-overlay source pair changed: {item.path!r}")
        self.generated_translation_units = frozenset(self.carrier_input_seals)
        if not {item.casefold() for item in self.generated_translation_units}.issubset(
            {item.casefold() for item in self.generated_inputs}
        ):
            raise ClassicProjectError(
                "generated translation units are not no-clean overlay outputs"
            )
        generated_tu_folded = {item.casefold() for item in self.generated_translation_units}
        self.ordinary_generated_inputs = tuple(
            sorted(
                (
                    item
                    for item in self.generated_inputs
                    if item.casefold() not in generated_tu_folded
                ),
                key=str.casefold,
            )
        )
        ordinary_compiler_ids = {
            node.id
            for node in graph.nodes
            if node.role is ProducerRole.COMPILER and node.id not in self.generated_node_inputs
        }
        if (
            not isinstance(self.compiler_epoch_plan, ProjectOverlayCompilerEpochPlan)
            or not self.compiler_epoch_plan.audit_node_ids.issubset(ordinary_compiler_ids)
            or not self.compiler_epoch_plan.runtime_projection_node_ids.issubset(
                self.compiler_epoch_plan.audit_node_ids
            )
        ):
            raise ClassicProjectError("project-overlay compiler epoch plan is invalid")
        expected_counterfactual_outputs = {
            item.path.casefold()
            for item in self.project_source_pairs
            if item.path.casefold() not in generated_tu_folded
        }
        if {
            path.casefold() for path in self.compiler_epoch_plan.declaration_outputs
        } != expected_counterfactual_outputs or any(
            type(payload) is not bytes
            for payload in self.compiler_epoch_plan.declaration_outputs.values()
        ):
            raise ClassicProjectError(
                "project-overlay declaration counterfactual output universe differs"
            )
        if not self.compiler_epoch_plan.audit_node_ids:
            effective_by_path = {
                item.path: item.effective_payload
                for item in self.project_source_pairs
                if item.path.casefold() not in generated_tu_folded
            }
            if dict(self.compiler_epoch_plan.declaration_outputs) != effective_by_path:
                raise ClassicProjectError(
                    "zero-audit counterfactual differs from the effective source epoch"
                )
        self.system_libraries = MappingProxyType(dict(system_libraries))
        self._semantic_lock = Lock()
        self._evidence_lock = Lock()
        self._output_lock = Lock()
        self._physical_outputs: dict[Path, Path] = {}
        self._donor_semantic_lanes: list[DonorSemanticLane] = []
        self._counterfactual_compiler_audits: tuple[
            ProjectOverlayCounterfactualAudit, ...
        ] = ()
        self._counterfactual_namespace_id: str | None = None
        self._clean_source_inputs: tuple[CleanSourceInput, ...] = ()
        self._effective_compiler_products: tuple[CompilerProduct, ...] = ()
        self._producer_reads: list[ClassicProducerReadReceipt] = []
        self._resource_dependency_receipts: dict[str, ResourceDependencyReceipt] = {}
        self._captured_compiler_outputs: tuple[ClassicCapturedProducerOutput, ...] = ()
        self._donor_outputs: list[ClassicDonorOutputReceipt] = []
        self._link_directive_closures: Mapping[str, ClassicLinkDirectiveClosure] = MappingProxyType(
            {}
        )
        self._module_definition_receipts: Mapping[str, ModuleDefinitionReceipt] = MappingProxyType(
            {}
        )
        self._donor_include_authority: SealedIncludeAuthority | None = None
        self._namespace_payload_intern: dict[tuple[str, int], bytes] = {}
        self._compiler_namespaces: dict[str, ClassicCompilerNamespaceReceipt] = {}
        self._active_compiler_namespace_id: str | None = None
        if lane_pool.maximum != jobs:
            raise ClassicProjectError("classic execution lane capacity differs from the job limit")
        self._lane_pool = lane_pool
        self._compiler_environment_digest = lane_pool.compiler_environment_digest
        self._compiler_path_profile_digest = classic_compiler_path_profile_digest(bundle, graph)
        self.jobs = jobs
        self.compile_timeout = compile_timeout
        self.link_timeout = link_timeout
        self._runtime_open = True
        self._warm_lock = Lock()
        self._warm_stack: ExitStack | None = None
        self._warm_supervisor: ProcessSupervisor | None = None
        self._warm_authority_namespace: SealedNamespaceLease | None = None
        self._warm_source_namespace: SealedNamespaceLease | None = None
        self._warm_include_authority: SealedIncludeAuthority | None = None
        self._warm_compiler_namespace_id: str | None = None
        self._warm_source_seal: Mapping[Path, tuple[int, Digest]] | None = None
        self._warm_generated_epoch = False
        self._warm_staging_root: Path | None = None
        rdata_count = sum(
            1
            for intervention in bundle.interventions
            if isinstance(intervention, ClassicRecipeIntervention)
            and isinstance(
                {item.name: item.value for item in intervention.parameters}.get(
                    "rdata_pool_repack"
                ),
                dict,
            )
        )
        total = (
            len(graph.nodes)
            + sum(1 for node in graph.nodes if node.role is ProducerRole.RESOURCE)
            + (
                len(self.compiler_epoch_plan.audit_node_ids)
                if self.overlay_witnesses
                else 0
            )
            + (
                6
                if self.overlay_witnesses and self.compiler_epoch_plan.audit_node_ids
                else 4
                if self.overlay_witnesses
                else 1
            )
            + 2 * sum(len(unit.donors) for unit in self.units)
            + len(self.units)
            + rdata_count
            + 2 * len(self.targets)
            + (1 if self.generated_translation_units else 0)
            + 1  # complete validation, execution-record construction, and runtime close
        )
        self._progress = _ProgressReporter(total, progress)
        self.record: ClassicProducerGraphExecutionRecord | None = None
        self._legacy_oracles: Mapping[str, PE32VirtualAddressReader] = MappingProxyType({})

    def _close_runtime(self) -> None:
        if not self._runtime_open:
            return
        self._runtime_open = False
        # A few narrow migration diagnostics construct an executor shell with
        # ``object.__new__`` so they can exercise the probe contract without a
        # backend.  Treat an absent warm session exactly like one that was
        # never opened; production instances always initialize these fields.
        warm_stack = getattr(self, "_warm_stack", None)
        self._warm_stack = None
        self._warm_supervisor = None
        self._warm_authority_namespace = None
        self._warm_source_namespace = None
        self._warm_include_authority = None
        self._warm_compiler_namespace_id = None
        self._warm_source_seal = None
        self._warm_staging_root = None
        try:
            if warm_stack is not None:
                warm_stack.close()
        finally:
            self._lane_pool.close()

    def close(self) -> None:
        """Release the bound logical drive when execution will not consume it."""

        self._close_runtime()

    @property
    def initialized_lane_count(self) -> int:
        """Number of backend lanes materialized by actual producer demand."""

        return self._lane_pool.created_count

    def _warm_node(self, node_id: str) -> ProducerNode:
        matches = tuple(node for node in self.graph.nodes if node.id == node_id)
        if len(matches) != 1:
            raise ClassicProjectError(f"classic warm execution names an unknown node: {node_id!r}")
        return matches[0]

    def bind_warm_staging_root(self, root: Path) -> None:
        """Bind the independent run-private destination for cacheable outputs."""

        if self.record is not None or not self._runtime_open or self._warm_staging_root:
            raise ClassicProjectError("classic warm staging is already bound or used")
        lexical = Path(os.path.abspath(root))
        if lexical.is_symlink() or not lexical.is_dir():
            raise ClassicProjectError(
                f"classic warm staging root is absent or redirected: {lexical}"
            )
        resolved = lexical.resolve(strict=True)
        try:
            resolved.relative_to(self.project_root.resolve(strict=True))
        except ValueError as exc:
            raise ClassicProjectError(
                "classic warm staging root must remain beneath the project"
            ) from exc
        self._warm_staging_root = resolved

    def _warm_epoch(
        self,
        *,
        generated: bool | None,
    ) -> tuple[ProcessSupervisor, SealedIncludeAuthority, str, str]:
        """Open or advance the non-certifying warm producer source epoch."""

        with self._warm_lock:
            if self.record is not None or not self._runtime_open:
                raise ClassicProjectError("classic warm execution requires one unused prepared run")
            if self._warm_stack is None:
                stack = ExitStack()
                try:
                    source_seal = _tree_file_seal(self.effective_root)
                    if self.overlay_witnesses:
                        _, source_seal = self._materialize_certified_project_overlay_epoch(
                            source_seal
                        )
                    supervisor = stack.enter_context(ProcessSupervisor())
                    authority = stack.enter_context(self._authority_namespace_lease())
                    source = stack.enter_context(self._source_namespace_lease())
                    namespace = self._capture_compiler_namespace(
                        "noncertifying-warm-effective",
                        source=source.snapshot,
                        authority=authority.snapshot,
                    )
                    include_authority = self._include_authority()
                except BaseException:
                    stack.close()
                    raise
                self._warm_stack = stack
                self._warm_supervisor = supervisor
                self._warm_authority_namespace = authority
                self._warm_source_namespace = source
                self._warm_include_authority = include_authority
                self._warm_compiler_namespace_id = namespace.evidence.namespace_id
                self._warm_source_seal = source_seal
                self._donor_include_authority = include_authority
                self._active_compiler_namespace_id = namespace.evidence.namespace_id

            if generated is True and not self._warm_generated_epoch:
                if not self.generated_translation_units:
                    raise ClassicProjectError(
                        "classic warm execution requested an empty generated epoch"
                    )
                assert self._warm_stack is not None
                assert self._warm_authority_namespace is not None
                assert self._warm_source_namespace is not None
                assert self._warm_source_seal is not None
                self._warm_source_namespace.close()
                _, generated_seal = self._materialize_generated_input_epoch(self._warm_source_seal)
                source = self._warm_stack.enter_context(self._source_namespace_lease())
                namespace = self._capture_compiler_namespace(
                    "noncertifying-warm-generated",
                    source=source.snapshot,
                    authority=self._warm_authority_namespace.snapshot,
                )
                include_authority = self._include_authority()
                self._warm_source_namespace = source
                self._warm_include_authority = include_authority
                self._warm_compiler_namespace_id = namespace.evidence.namespace_id
                self._warm_source_seal = generated_seal
                self._warm_generated_epoch = True
                self._donor_include_authority = include_authority
                self._active_compiler_namespace_id = namespace.evidence.namespace_id
            elif generated is False and self._warm_generated_epoch:
                raise ClassicProjectError(
                    "classic warm execution cannot return to the ordinary source epoch"
                )

            assert self._warm_supervisor is not None
            assert self._warm_include_authority is not None
            assert self._warm_compiler_namespace_id is not None
            return (
                self._warm_supervisor,
                self._warm_include_authority,
                self._warm_compiler_namespace_id,
                "generated" if self._warm_generated_epoch else "effective",
            )

    def _materialize_warm_inputs(self, inputs: PreparedNodeInputs) -> None:
        """Copy exact cache-receipted dependencies into the logical seat."""

        # Sibling ready nodes may consume the same restored archive/object.  A
        # single materialization lock makes the absence check + exclusive copy
        # converge to one physical file; later consumers verify exact bytes.
        with self._warm_lock:
            for reference, bound in sorted(
                inputs.entries.items(), key=lambda item: item[0].casefold()
            ):
                if not reference.startswith("build/"):
                    raise ClassicProjectError(
                        f"classic warm input is not a build reference: {reference!r}"
                    )
                destination = self._reference(reference)
                if destination is None:
                    raise ClassicProjectError(
                        f"classic warm input is not materializable: {reference!r}"
                    )
                source = bound.snapshot.path
                self._require_regular(source, label="classic warm staged input")
                if os.path.lexists(destination):
                    self._require_regular(destination, label="classic warm logical input")
                    destination_root = Path(canonical_system_path(destination).anchor)
                    destination_relative = PurePosixPath(
                        *canonical_system_path(destination).parts[1:]
                    ).as_posix()
                    received = digest_relative_file(
                        destination_root, destination_relative
                    )
                    if (
                        received.digest.value != bound.output.digest
                        or received.size != bound.output.size
                        or bool(received.mode & stat.S_IXUSR) != bound.output.executable
                    ):
                        raise ClassicProjectError(
                            f"classic warm logical input conflicts with {reference!r}"
                        )
                    physical = destination.resolve(strict=True)
                else:
                    physical = _secure_copy_new(
                        source, destination, expected=bound
                    ).path.resolve(strict=True)
                declared = destination.resolve(strict=False)
                with self._output_lock:
                    previous = self._physical_outputs.setdefault(declared, physical)
                    if previous != physical:
                        raise ClassicProjectError(
                            f"classic warm input aliases another physical output: {reference!r}"
                        )

    def verify_warm_authority(self) -> None:
        """Revalidate active readable namespaces before a warm cache store."""

        with self._warm_lock:
            if self.record is not None or not self._runtime_open:
                raise ClassicProjectError("classic warm authority is no longer active")
            if self._warm_authority_namespace is None or self._warm_source_namespace is None:
                raise ClassicProjectError("classic warm authority was not initialized")
            self._warm_authority_namespace.verify()
            self._warm_source_namespace.verify()

    def _copy_warm_outputs(
        self,
        node: ProducerNode,
        destinations: Mapping[str, Path],
    ) -> None:
        if set(destinations) != set(node.outputs):
            raise ClassicProjectError(
                f"classic warm node {node.id!r} staging outputs differ from its graph"
            )
        physical = self._node_outputs(node)
        if len(physical) != len(node.outputs):
            raise ClassicProjectError(f"classic warm node {node.id!r} omitted a physical output")
        for reference, source in zip(node.outputs, physical, strict=True):
            destination = destinations[reference]
            if self._warm_staging_root is None:
                raise ClassicProjectError("classic warm staging root is not bound")
            try:
                Path(os.path.abspath(destination)).relative_to(self._warm_staging_root)
            except ValueError as exc:
                raise ClassicProjectError(
                    f"classic warm staging output escapes its run: {destination}"
                ) from exc
            _secure_copy_new(source, destination)

    def execute_warm_graph_node(
        self,
        node_id: str,
        *,
        inputs: PreparedNodeInputs,
        outputs: Mapping[str, Path],
        cancellation: CancellationToken,
    ) -> tuple[StepExecutionReceipt, ...]:
        """Execute one cache-missing committed producer into warm staging."""

        node = self._warm_node(node_id)
        expected_inputs = {reference for reference in node.inputs if reference.startswith("build/")}
        if set(inputs.entries) != expected_inputs:
            raise ClassicProjectError(
                f"classic warm node {node.id!r} staged dependencies differ from its graph"
            )
        supervisor, include_authority, namespace_id, epoch = self._warm_epoch(
            generated=(
                node.id in self.generated_node_inputs
                if node.role is ProducerRole.COMPILER
                else False
                if node.role is ProducerRole.RESOURCE
                else None
            )
        )
        self._materialize_warm_inputs(inputs)
        receipts = self._run_node(
            supervisor,
            node,
            cancellation,
            receipt_step_id=f"warm.{node.id}",
            log_namespace="warm-producers",
            include_authority=(
                include_authority
                if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
                else None
            ),
            include_trace_epoch=(
                f"warm-{epoch}"
                if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
                else None
            ),
            compiler_namespace_id=(namespace_id if node.role is ProducerRole.COMPILER else None),
        )
        self._copy_warm_outputs(node, outputs)
        if node.role is ProducerRole.COMPILER:
            declared = self._declared_node_outputs(node)
            physical = self._node_outputs(node)
            for path in physical:
                _secure_remove_regular(path)
            with self._output_lock:
                for path in declared:
                    self._physical_outputs.pop(path, None)
        return receipts

    def _warm_unit(self, compiler_node_id: str) -> ClassicPreparedUnit:
        records = tuple(
            record for record in self.compile_records if record.node_id == compiler_node_id
        )
        if len(records) != 1:
            raise ClassicProjectError(
                f"classic warm compiler node {compiler_node_id!r} lacks one compile record"
            )
        record = records[0]
        matches = tuple(
            unit
            for unit in self.units
            if unit.plan.build_target == record.build_target
            and (self.effective_root / unit.plan.source).resolve(strict=True) == record.source
        )
        if len(matches) != 1:
            raise ClassicProjectError(
                f"classic warm compiler node {compiler_node_id!r} lacks one prepared TU"
            )
        return matches[0]

    def execute_warm_compiler_transform(
        self,
        compiler_node_id: str,
        *,
        inputs: PreparedNodeInputs,
        outputs: Mapping[str, Path],
        cancellation: CancellationToken,
    ) -> _ClassicWarmCompilerTransformResult:
        """Apply one TU's reviewed composition and object transforms."""

        node = self._warm_node(compiler_node_id)
        if node.role is not ProducerRole.COMPILER or set(inputs.entries) != set(node.outputs):
            raise ClassicProjectError(
                f"classic warm transform {compiler_node_id!r} has invalid raw inputs"
            )
        supervisor, _authority, _namespace_id, _epoch = self._warm_epoch(
            generated=node.id in self.generated_node_inputs
        )
        self._materialize_warm_inputs(inputs)
        unit = self._warm_unit(compiler_node_id)
        donor_dependencies: list[_ClassicWarmDonorDependencyReplay] = []
        record, steps, _witnesses = self._compose_unit(
            supervisor,
            unit,
            cancellation,
            dependency_replays=donor_dependencies,
        )
        object_path = record.object_path.resolve(strict=True)
        for intervention in self.bundle.interventions:
            if not isinstance(intervention, ClassicRecipeIntervention):
                continue
            values = {item.name: item.value for item in intervention.parameters}
            declaration = values.get("rdata_pool_repack")
            if not isinstance(declaration, dict):
                continue
            object_value = declaration.get("object")
            if not isinstance(object_value, str):
                raise ClassicProjectError("rdata repack object path is malformed")
            selected = self.build_root.joinpath(
                *PurePosixPath(_safe_relative(object_value)).parts
            ).resolve(strict=False)
            if str(selected).casefold() != str(object_path).casefold():
                continue
            applied = classic_rdata_repack(
                self.bundle,
                target_id=intervention.scope.target,
                object_path=object_value,
                candidate=object_path.read_bytes(),
            )
            if applied is None:
                raise ClassicProjectError("rdata repack declaration was not selected")
            result, _witness = applied
            temporary = object_path.with_name(f".{object_path.name}.warm-rdata-{intervention.id}")
            with temporary.open("xb") as stream:
                stream.write(result.output)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, object_path)
            steps.append(
                _internal_step(
                    f"warm.rdata.{intervention.id}",
                    {
                        "object": object_value,
                        "output": Digest.from_bytes(result.output).model_dump(mode="json"),
                    },
                    0.0,
                )
            )
        self._copy_warm_outputs(node, outputs)
        return _ClassicWarmCompilerTransformResult(
            tuple(steps),
            tuple(sorted(donor_dependencies, key=lambda item: item.donor_id.casefold())),
        )

    def replay_warm_compiler_dependencies(
        self,
        compiler_node_id: str,
        *,
        cancellation: CancellationToken,
    ) -> _ClassicWarmCompilerReplay:
        """Run and discard one `/Fr` invocation used only as a cache hint."""

        node = self._warm_node(compiler_node_id)
        if node.role is not ProducerRole.COMPILER:
            raise ClassicProjectError("classic warm dependency replay requires a compiler node")
        supervisor, _authority, _namespace_id, _epoch = self._warm_epoch(
            generated=node.id in self.generated_node_inputs
        )
        replay_root = self.build_root / ".reprobit-warm-replay"
        replay_root.mkdir(exist_ok=True)
        arena = replay_root / sha256(node.id.encode("utf-8")).hexdigest()[:20]
        arena.mkdir(exist_ok=False)
        try:
            object_path = arena / "discard.obj"
            pdb_path = arena / "discard.pdb"
            sbr_path = arena / "dependencies.sbr"
            object_logical = self._logical_for_host_path(object_path)
            pdb_logical = self._logical_for_host_path(pdb_path)
            sbr_logical = self._logical_for_host_path(sbr_path)
            arguments: list[str] = []
            object_count = 0
            pdb_count = 0
            for argument in self._node_arguments(node):
                folded = argument.casefold()
                if folded.startswith(("/fr", "-fr")):
                    return _ClassicWarmCompilerReplay(
                        None, "committed compiler argv already contains /Fr"
                    )
                if folded.startswith(("/fo", "-fo")):
                    arguments.append(f"/Fo{object_logical}")
                    object_count += 1
                elif folded.startswith(("/fd", "-fd")):
                    arguments.append(f"/Fd{pdb_logical}")
                    pdb_count += 1
                else:
                    arguments.append(argument)
            if object_count != 1 or pdb_count != 1:
                return _ClassicWarmCompilerReplay(
                    None, "compiler replay could not isolate exactly one OBJ/PDB pair"
                )
            arguments.append(f"/Fr{sbr_logical}")
            lane = self._lane_pool.acquire()
            try:
                try:
                    result, _spec = _run(
                        supervisor,
                        (str(self.role_commands[ProducerRole.COMPILER]), *arguments),
                        cwd=self._producer_cwd(lane, self.build_root),
                        environment=lane.environment,
                        timeout=self.compile_timeout,
                        log=(
                            self.session_root / "logs" / "warm-dependency-replay" / f"{node.id}.log"
                        ),
                        cancellation=cancellation,
                        windows_lineage_planner=(
                            lane.windows_lineage_planner
                        ),
                    )
                except Exception as exc:
                    cancellation.raise_if_cancelled()
                    return _ClassicWarmCompilerReplay(
                        None, f"discarded compiler replay failed: {exc}"
                    )
            finally:
                self._lane_pool.release(lane)
            if not result.succeeded:
                return _ClassicWarmCompilerReplay(
                    None,
                    f"discarded compiler replay returned {result.returncode}: {result.output_tail}",
                )
            try:
                actual_sbr = self._compiler_companion_output(sbr_path)
                trace = parse_msvc_sbr(actual_sbr.read_bytes())
            except (OSError, ValueError) as exc:
                return _ClassicWarmCompilerReplay(
                    None, f"discarded compiler replay trace is unusable: {exc}"
                )
            # The replay OBJ/PDB are deliberately neither registered nor
            # returned.  Their different bytes can never substitute for the
            # normal invocation.
            return _ClassicWarmCompilerReplay(trace, None)
        finally:
            _erase_warm_replay_arena(arena, replay_root=replay_root)

    def execute_warm_terminal(
        self,
        target_id: str,
        *,
        inputs: PreparedNodeInputs,
        destination: Path,
    ) -> SecureFileSnapshot:
        """Apply one target's terminal transforms into run-private staging."""

        targets = tuple(target for target in self.targets if target.target_id == target_id)
        if len(targets) != 1:
            raise ClassicProjectError(
                f"classic warm terminal names an unknown target: {target_id!r}"
            )
        target = targets[0]
        node = self._warm_node(target.link_node_id)
        primary = tuple(
            reference
            for reference in node.outputs
            if Path(reference).suffix.casefold()
            == Path(
                self.bundle.spec.targets[
                    next(
                        index
                        for index, item in enumerate(self.bundle.spec.targets)
                        if item.id == target_id
                    )
                ].artifact
            ).suffix.casefold()
        )
        if len(primary) != 1:
            raise ClassicProjectError(
                f"classic warm terminal {target_id!r} lacks one primary linker output"
            )
        if set(inputs.entries) != {primary[0]}:
            raise ClassicProjectError(
                f"classic warm terminal {target_id!r} has invalid linker input"
            )
        self._warm_epoch(generated=None)
        self._materialize_warm_inputs(inputs)
        self._require_regular(target.output, label="classic warm linked image")
        terminal = apply_classic_terminal_pipeline(
            self.bundle,
            target_id=target_id,
            candidate=target.output.read_bytes(),
        )
        try:
            if self._warm_staging_root is None:
                raise ClassicProjectError("classic warm staging root is not bound")
            relative = Path(os.path.abspath(destination)).relative_to(self._warm_staging_root)
            return atomic_publish_relative(
                self._warm_staging_root,
                PurePosixPath(*relative.parts).as_posix(),
                terminal.output,
            )
        except (OSError, SecurePathError, ValueError) as exc:
            raise ClassicProjectError(
                f"classic warm terminal could not stage {target_id!r}: {exc}"
            ) from exc

    def probe_compiler_nodes(
        self,
        node_ids: Sequence[str],
        *,
        source_epoch: Literal["clean", "effective"] = "effective",
    ) -> tuple[ClassicCompilerProbeOutput, ...]:
        """Run a bounded non-certifying exact-node compiler probe.

        This migration diagnostic invokes only the selected committed compiler
        nodes at the normal logical source/build/toolchain seats.  It holds the
        same complete readable-namespace leases as a cold run, returns the raw
        OBJ/PDB bytes, and always closes the backend lifetime before returning.
        No runtime evidence, semantic proof, target, or public report is issued.
        The prepared run is consumed and cannot subsequently execute normally.
        """

        if self.record is not None or not self._runtime_open:
            raise ClassicProjectError("classic compiler probe requires one unused prepared run")
        if source_epoch not in {"clean", "effective"}:
            raise ClassicProjectError("classic compiler probe source epoch is invalid")
        requested = tuple(node_ids)
        if not requested or len(requested) != len(set(requested)):
            raise ClassicProjectError("classic compiler probe requires unique selected node IDs")
        by_id = {node.id: node for node in self.graph.nodes}
        unknown = sorted(set(requested) - set(by_id), key=str.casefold)
        if unknown:
            raise ClassicProjectError(f"classic compiler probe names unknown nodes: {unknown}")
        selected = tuple(by_id[node_id] for node_id in requested)
        if any(
            node.role is not ProducerRole.COMPILER or node.id in self.generated_node_inputs
            for node in selected
        ):
            raise ClassicProjectError(
                "classic compiler probe admits only ordinary committed compiler nodes"
            )
        selected_ids = set(requested)
        external_dependencies = {
            dependency
            for node in selected
            for dependency in node.depends_on
            if dependency not in selected_ids
        }
        if external_dependencies:
            raise ClassicProjectError(
                "classic compiler probe omits required producer dependencies: "
                + ", ".join(sorted(external_dependencies, key=str.casefold))
            )

        try:
            source_before = _tree_file_seal(self.effective_root)
            if source_epoch == "effective" and self.overlay_witnesses:
                self._materialize_certified_project_overlay_epoch(source_before)
            elif source_epoch == "clean" and self.overlay_witnesses:
                # Preparation deliberately leaves every clean-backed output at
                # its manifest bytes and every generated output absent.
                _require_unchanged_tree(
                    source_before,
                    root=self.effective_root,
                    label="clean compiler probe source epoch",
                )
            build_before = _tree_file_seal(self.build_root)
        except BaseException as original:
            try:
                self._close_runtime()
            except BaseException as cleanup_error:
                original.add_note(f"classic compiler probe cleanup also failed: {cleanup_error}")
            raise
        receipts: list[StepExecutionReceipt] = []
        try:
            with ExitStack() as stack, ProcessSupervisor() as supervisor:
                authority = stack.enter_context(self._authority_namespace_lease())
                source = stack.enter_context(self._source_namespace_lease())
                namespace = self._capture_compiler_namespace(
                    f"noncertifying-probe-{source_epoch}",
                    source=source.snapshot,
                    authority=authority.snapshot,
                )
                completed: set[str] = set()
                output_steps: dict[Path, str] = {}
                receipts.extend(
                    self._run_graph_nodes(
                        supervisor,
                        selected,
                        completed=completed,
                        output_steps=output_steps,
                        cancellation=CancellationToken(),
                        step_id_prefix="probe.",
                        progress_phase="compiler-probe",
                        log_namespace="compiler-probe",
                        include_authority=self._include_authority(),
                        include_trace_epoch=f"probe-{source_epoch}",
                        compiler_namespace_id=namespace.evidence.namespace_id,
                    )
                )
                if completed != selected_ids:
                    raise ClassicProjectError("classic compiler probe execution was incomplete")
            _require_declared_tree_writes(
                build_before,
                root=self.build_root,
                allowed_outputs=(path for node in selected for path in self._node_outputs(node)),
                phase="classic compiler probe",
            )
            producer_steps = {
                receipt.step_id: receipt
                for receipt in receipts
                if receipt.step_id.startswith("probe.")
            }
            outputs: list[ClassicCompilerProbeOutput] = []
            for node in selected:
                source_ref, object_ref = self._compiler_product_refs(node)
                pdb_refs = tuple(
                    reference
                    for reference in node.outputs
                    if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold() == ".pdb"
                )
                if len(pdb_refs) != 1:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} lacks one PDB output"
                    )
                object_declared = self._reference(object_ref)
                pdb_declared = self._reference(pdb_refs[0])
                if object_declared is None or pdb_declared is None:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} output is not materializable"
                    )
                with self._output_lock:
                    object_path = self._physical_outputs.get(object_declared)
                    pdb_path = self._physical_outputs.get(pdb_declared)
                if object_path is None or pdb_path is None:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} lacks physical outputs"
                    )
                self._require_regular(object_path, label="compiler probe OBJ")
                self._require_regular(pdb_path, label="compiler probe PDB")
                object_payload = object_path.read_bytes()
                pdb_payload = pdb_path.read_bytes()
                step = producer_steps.get(f"probe.{node.id}")
                if step is None:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} lacks an execution receipt"
                    )
                outputs.append(
                    ClassicCompilerProbeOutput(
                        node.id,
                        source_ref,
                        object_ref,
                        pdb_refs[0],
                        object_path,
                        pdb_path,
                        Digest.from_bytes(object_payload),
                        Digest.from_bytes(pdb_payload),
                        object_payload,
                        pdb_payload,
                        step,
                    )
                )
            return tuple(outputs)
        finally:
            self._close_runtime()

    def probe_donor_compilers(
        self,
        donor_ids: Sequence[str],
    ) -> tuple[ClassicDonorProbeOutput, ...]:
        """Run exact prepared private-donor compilers as a consumed diagnostic.

        The caller may select only donor requests already rendered by the
        committed project plan.  Each request is invoked through its owning
        compiler node's command and the normal locked execution lane.  Raw
        products and immutable rendered inputs are returned solely for
        migration diagnosis; no evidence, proof, cache entry, or report is
        issued.  The prepared run is consumed and its backend is closed on
        success and failure.
        """

        if self.record is not None or not self._runtime_open:
            raise ClassicProjectError("classic donor probe requires one unused prepared run")

        try:
            requested = tuple(donor_ids)
            if not requested or len(requested) != len(set(requested)):
                raise ClassicProjectError(
                    "classic donor probe requires unique selected donor IDs"
                )
            prepared: dict[str, tuple[ClassicPreparedUnit, int]] = {}
            for unit in self.units:
                for donor_index, donor in enumerate(unit.donors):
                    donor_id = donor.intervention.id
                    if donor_id in prepared:
                        raise ClassicProjectError(
                            f"classic prepared donor ID is ambiguous: {donor_id!r}"
                        )
                    prepared[donor_id] = (unit, donor_index)
            unknown = sorted(set(requested) - set(prepared), key=str.casefold)
            if unknown:
                raise ClassicProjectError(
                    f"classic donor probe names unknown prepared donors: {unknown}"
                )

            source_seal = _tree_file_seal(self.effective_root)
            if self.overlay_witnesses:
                _, source_seal = self._materialize_certified_project_overlay_epoch(
                    source_seal
                )
                if self.generated_translation_units:
                    _, source_seal = self._materialize_generated_input_epoch(source_seal)
            _require_unchanged_tree(
                source_seal,
                root=self.effective_root,
                label="donor compiler probe source epoch",
            )

            outputs: list[ClassicDonorProbeOutput] = []
            with ExitStack() as stack, ProcessSupervisor() as supervisor:
                authority = stack.enter_context(self._authority_namespace_lease())
                source = stack.enter_context(self._source_namespace_lease())
                namespace = self._capture_compiler_namespace(
                    "noncertifying-donor-probe",
                    source=source.snapshot,
                    authority=authority.snapshot,
                )
                self._active_compiler_namespace_id = namespace.evidence.namespace_id
                cancellation = CancellationToken()
                for ordinal, donor_id in enumerate(requested):
                    unit, donor_index = prepared[donor_id]
                    donor = unit.donors[donor_index]
                    invocation = self._invoke_donor_compiler(
                        supervisor,
                        unit,
                        donor_index,
                        cancellation,
                        step_id=f"probe.donor.{ordinal:04d}.{donor_id}",
                    )
                    rendered_inputs = tuple(
                        ClassicDonorProbeInput(
                            logical_path,
                            Digest.from_bytes(payload),
                            len(payload),
                            payload,
                        )
                        for logical_path, payload in sorted(
                            donor.request.logical_outputs.items(),
                            key=lambda item: item[0].casefold(),
                        )
                    )
                    if not rendered_inputs:
                        raise ClassicProjectError(
                            f"classic donor {donor_id!r} lacks logical rendered inputs"
                        )
                    outputs.append(
                        ClassicDonorProbeOutput(
                            donor_id,
                            unit.plan.id,
                            donor.request.build_target,
                            donor.request.logical_source,
                            invocation.record.node_id,
                            rendered_inputs,
                            Digest.from_bytes(invocation.object_payload),
                            Digest.from_bytes(invocation.pdb_payload),
                            invocation.object_payload,
                            invocation.pdb_payload,
                            _step_receipt(
                                invocation.step_id,
                                invocation.result,
                                invocation.spec,
                            ),
                        )
                    )
            _require_unchanged_tree(
                source_seal,
                root=self.effective_root,
                label="donor compiler probe source epoch",
            )
        except BaseException as original:
            try:
                self._close_runtime()
            except BaseException as cleanup_error:
                original.add_note(f"classic donor probe cleanup also failed: {cleanup_error}")
            raise
        self._close_runtime()
        return tuple(outputs)

    def bind_legacy_oracles(self, oracles: Mapping[str, PE32VirtualAddressReader]) -> None:
        """Install opaque VA readers after CLI oracle sealing and before execution."""

        if self.record is not None or self._legacy_oracles:
            raise ClassicProjectError("legacy oracle capabilities are already bound or used")
        required = {item.oracle_target for unit in self.units for item in unit.legacy_actions}
        if set(oracles) != required:
            raise ClassicProjectError(
                "legacy oracle capability set differs; "
                f"missing={sorted(required - set(oracles))}, "
                f"extra={sorted(set(oracles) - required)}"
            )
        self._legacy_oracles = MappingProxyType(
            {target_id: oracles[target_id] for target_id in sorted(required)}
        )

    def _reference(self, value: str) -> Path | None:
        return materialize_reference(
            value,
            source_root=self.effective_root,
            build_root=self.build_root,
            toolchain_root=self.toolchain_root,
        )

    def _node_arguments(self, node: ProducerNode) -> tuple[str, ...]:
        return tuple(
            materialize_argument(
                value,
                source_root=self.bundle.spec.paths.source,
                build_root=self.bundle.spec.paths.build,
                toolchain_root=self.bundle.spec.paths.toolchain,
            )
            for value in node.arguments
        )

    def _logical_for_host_path(self, path: Path) -> str:
        """Map one run-private physical path into the committed DOS drive."""

        resolved = path.resolve(strict=False)
        try:
            relative = resolved.relative_to(self._logical_drive_root)
        except ValueError as exc:
            raise ClassicProjectError(f"compiler path escapes the logical drive: {path}") from exc
        if not relative.parts:
            return normalize_logical_path(f"{self._logical_drive_letter}:\\")
        return normalize_logical_path(
            f"{self._logical_drive_letter}:\\" + "\\".join(relative.parts)
        )

    def _producer_cwd(self, lane: _ExecutionLane, physical: Path) -> Path:
        """Present the mapped DOS cwd to native producers, not its host backing path."""

        if lane.windows_lineage_planner is None:
            return physical
        if os.name != "nt":
            raise ClassicProjectError(
                "suspended native producer admission is unavailable off Windows"
            )
        return Path(self._logical_for_host_path(physical))

    def _compiler_visible_path(self, value: str) -> str:
        """Normalize either an admitted DOS path or a run-private host path."""

        windows = PureWindowsPath(value.replace("/", "\\"))
        if windows.drive:
            return normalize_logical_path(str(windows))
        path = Path(value)
        if not path.is_absolute():
            raise ClassicProjectError(f"compiler dependency path lacks a closed root: {value!r}")
        return self._logical_for_host_path(path)

    def _host_for_logical_path(self, value: str) -> Path:
        """Resolve one committed DOS path only inside the materialized drive."""

        normalized = normalize_logical_path(value.replace("/", "\\"))
        parts = _logical_relative_parts(
            normalized,
            drive_letter=self._logical_drive_letter,
        )
        path = self._logical_drive_root.joinpath(*parts)
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(self._logical_drive_root)
        except ValueError as exc:
            raise ClassicProjectError(
                f"logical producer read escapes the materialized drive: {value!r}"
            ) from exc
        self._require_regular(resolved, label="logical producer read")
        return resolved

    def _authority_namespace_lease(self) -> SealedNamespaceLease:
        """Hold the projected toolchain and every host transport authority."""

        return SealedNamespaceLease(
            trees=(
                NamespaceTree(
                    "toolchain",
                    self.toolchain_root,
                    self._logical_drive_root,
                ),
            ),
            files=self._namespace_authority_files,
            retain_payload_labels=("toolchain",),
        )

    def _source_namespace_lease(self) -> SealedNamespaceLease:
        """Hold one immutable project-source epoch at its logical seat."""

        return SealedNamespaceLease(
            trees=(
                NamespaceTree(
                    "source",
                    self.effective_root,
                    self._logical_drive_root,
                ),
            ),
            retain_payload_labels=("source",),
        )

    def _intern_namespace_payload(self, item: SealedNamespaceFile) -> bytes:
        payload = item.payload
        if payload is None:
            raise ClassicProjectError(f"compiler namespace omitted retained bytes: {item.path}")
        key = (item.digest.value, item.size)
        existing = self._namespace_payload_intern.get(key)
        if existing is not None:
            if existing != payload:
                raise ClassicProjectError("namespace payload digest collision")
            return existing
        self._namespace_payload_intern[key] = payload
        return payload

    def _capture_compiler_namespace(
        self,
        namespace_id: str,
        *,
        source: SealedNamespaceSnapshot,
        authority: SealedNamespaceSnapshot,
    ) -> ClassicCompilerNamespaceReceipt:
        """Capture one shared complete readable namespace over-approximation."""

        if namespace_id in self._compiler_namespaces:
            raise ClassicProjectError(
                f"compiler namespace ID is already captured: {namespace_id!r}"
            )

        values: list[ClassicProducerRead] = []
        for label, snapshot, root, origin in (
            (
                "source",
                source,
                self.effective_root,
                IncludeOrigin.PROJECT_SOURCE,
            ),
            (
                "toolchain",
                authority,
                self.toolchain_root,
                IncludeOrigin.TOOLCHAIN_TREE,
            ),
        ):
            for item in snapshot.files_for(label):
                expected = root.joinpath(*PurePosixPath(item.relative_path).parts)
                if item.path.resolve(strict=True) != expected.resolve(strict=True):
                    raise ClassicProjectError(
                        f"compiler {label} namespace path changed: {item.relative_path!r}"
                    )
                values.append(
                    ClassicProducerRead(
                        self._logical_for_host_path(item.path),
                        item.path,
                        item.digest,
                        item.size,
                        origin,
                        None,
                        None,
                        "complete-readable-namespace",
                        self._intern_namespace_payload(item),
                    )
                )
        folded = [item.logical_path.casefold() for item in values]
        if len(folded) != len(set(folded)):
            raise ClassicProjectError("compiler readable namespace has a DOS-case collision")
        reads = tuple(sorted(values, key=lambda item: item.logical_path.casefold()))
        members = tuple(
            CompilerSourceRead(
                _compiler_read_reference(
                    item.logical_path,
                    source_root=self.bundle.spec.paths.source,
                    toolchain_root=self.bundle.spec.paths.toolchain,
                ),
                item.digest,
                item.size,
                item.parent_index,
                cast(bytes, item.payload),
            )
            for item in reads
        )
        evidence = CompilerNamespaceEvidence(
            namespace_id,
            Digest(value="0" * 64),
            members,
            CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE,
        )
        evidence = replace(
            evidence,
            namespace_digest=compiler_namespace_evidence_digest(evidence),
        )
        receipt = ClassicCompilerNamespaceReceipt(evidence, reads)
        self._compiler_namespaces[namespace_id] = receipt
        return receipt

    def _compiler_epoch_invocation(
        self, node: ProducerNode, *, epoch: str
    ) -> CompilerEpochInvocation:
        """Freeze one compiler-visible invocation and its recursive source reads."""

        if node.role is not ProducerRole.COMPILER:
            raise ClassicProjectError(f"producer {node.id!r} is not a compiler invocation")
        with self._evidence_lock:
            matches = tuple(
                item
                for item in self._producer_reads
                if item.node_id == node.id
                and item.role is ProducerRole.COMPILER
                and item.epoch == epoch
            )
        if len(matches) != 1:
            raise ClassicProjectError(
                f"compiler {node.id!r} has {len(matches)} {epoch!r} read receipts"
            )
        receipt = matches[0]
        namespace_id = receipt.namespace_id
        if namespace_id is None:
            raise ClassicProjectError(
                f"compiler {node.id!r} {epoch} lacks shared namespace identity"
            )
        namespace = self._compiler_namespaces.get(namespace_id)
        if namespace is None or (
            receipt.namespace_digest != namespace.evidence.namespace_digest
            or receipt.namespace_count != len(namespace.evidence.members)
        ):
            raise ClassicProjectError(f"compiler {node.id!r} {epoch} namespace receipt changed")
        tool_id = self.role_tool_ids[ProducerRole.COMPILER]
        tools = [item for item in self.bundle.toolchain_lock.tools if item.id == tool_id]
        if len(tools) != 1:
            raise ClassicProjectError("compiler epoch does not bind exactly one locked compiler")
        invocation = CompilerEpochInvocation(
            tool_id,
            tools[0].digest,
            node.arguments,
            self.bundle.spec.paths.build,
            self._compiler_environment_digest,
            self._compiler_path_profile_digest,
            Digest(value="0" * 64),
            namespace.evidence.namespace_id,
            namespace.evidence.namespace_digest,
            len(namespace.evidence.members),
            CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE,
        )
        return replace(
            invocation,
            invocation_digest=compiler_epoch_invocation_digest(invocation),
        )

    @staticmethod
    def _sealed_include_file(
        *,
        path: Path,
        physical_root: Path,
        logical_root: str,
        origin: IncludeOrigin,
        sealed: tuple[int, Digest] | None = None,
    ) -> SealedIncludeFile:
        if path.is_symlink() or not path.is_file():
            raise ClassicProjectError(
                f"sealed include authority file is absent or redirected: {path}"
            )
        try:
            relative = path.resolve(strict=True).relative_to(physical_root.resolve(strict=True))
        except ValueError as exc:
            raise ClassicProjectError(
                f"sealed include authority file escapes its root: {path}"
            ) from exc
        size, digest = sealed or (path.stat().st_size, _digest_path(path))
        if path.stat().st_size != size or _digest_path(path) != digest:
            raise ClassicProjectError(
                f"sealed include authority file changed while indexed: {path}"
            )
        logical_path = _logical_join(logical_root, relative.as_posix())
        return SealedIncludeFile(logical_path, digest, size, origin)

    def _include_authority(self) -> SealedIncludeAuthority:
        """Seal the current project epoch and locked toolchain header trees."""

        source_seal = _tree_file_seal(self.effective_root)
        files = [
            self._sealed_include_file(
                path=path,
                physical_root=self.effective_root,
                logical_root=self.bundle.spec.paths.source,
                origin=IncludeOrigin.PROJECT_SOURCE,
                sealed=receipt,
            )
            for path, receipt in source_seal.items()
        ]
        files.extend(
            self._sealed_include_file(
                path=path,
                physical_root=self.toolchain_root,
                logical_root=self.bundle.spec.paths.toolchain,
                origin=IncludeOrigin.TOOLCHAIN_TREE,
            )
            for path in _toolchain_tree_files(self.bundle, self.toolchain_root)
        )
        roots = tuple(
            sorted(
                (
                    normalize_logical_path(self.bundle.spec.paths.source),
                    normalize_logical_path(self.bundle.spec.paths.toolchain),
                ),
                key=str.casefold,
            )
        )
        return SealedIncludeAuthority(
            roots,
            tuple(sorted(files, key=lambda item: item.logical_path.casefold())),
        )

    def _donor_authority(
        self,
        base: SealedIncludeAuthority,
        *,
        arena: Path,
        arena_seal: Mapping[Path, tuple[int, Digest]],
    ) -> SealedIncludeAuthority:
        """Extend the immutable project/toolchain authority by one donor arena."""

        logical_arena = self._logical_for_host_path(arena)
        donor_files = tuple(
            self._sealed_include_file(
                path=path,
                physical_root=arena,
                logical_root=logical_arena,
                origin=IncludeOrigin.DONOR_ARENA,
                sealed=receipt,
            )
            for path, receipt in arena_seal.items()
        )
        return SealedIncludeAuthority(
            tuple(sorted((*base.logical_roots, logical_arena), key=str.casefold)),
            tuple(
                sorted(
                    (*base.files, *donor_files),
                    key=lambda item: item.logical_path.casefold(),
                )
            ),
        )

    @staticmethod
    def _include_environment_directories(
        environment: Mapping[str, str],
    ) -> tuple[str, ...]:
        matches = [value for key, value in environment.items() if key.casefold() == "include"]
        if len(matches) != 1 or not matches[0]:
            raise ClassicProjectError("compiler environment does not uniquely declare INCLUDE")
        values = tuple(matches[0].split(";"))
        if any(not value for value in values):
            raise ClassicProjectError("compiler INCLUDE contains an empty search root")
        return values

    def _include_payloads(self, authority: SealedIncludeAuthority) -> Mapping[str, bytes]:
        payloads: dict[str, bytes] = {}
        for item in authority.files:
            path = self._host_for_logical_path(item.logical_path)
            payload = path.read_bytes()
            if len(payload) != item.size or Digest.from_bytes(payload) != item.digest:
                raise ClassicProjectError(
                    f"sealed include input changed before dependency scan: {item.logical_path!r}"
                )
            payloads[item.logical_path] = payload
        return MappingProxyType(payloads)

    def _resource_dependency_audit(
        self,
        node: ProducerNode,
        *,
        command: Sequence[str],
        lane: _ExecutionLane,
        authority: SealedIncludeAuthority,
        epoch: str,
    ) -> _ResourceDependencyAudit:
        """Statically close every RC include and file-backed resource operand."""

        started = time.monotonic()
        arguments = tuple(command[1:])
        include_directories: list[str] = []
        index = 0
        while index < len(arguments) - 1:
            value = arguments[index]
            folded = value.casefold()
            if folded in {"/i", "-i"}:
                if index + 1 >= len(arguments) - 1:
                    raise ClassicProjectError(
                        f"resource node {node.id!r} has an incomplete include option"
                    )
                include_directories.append(self._compiler_visible_path(arguments[index + 1]))
                index += 2
                continue
            if folded.startswith(("/i", "-i")) and len(value) > 2:
                include_directories.append(self._compiler_visible_path(value[2:]))
            index += 1
        source_refs = tuple(
            value
            for value in node.inputs
            if value.startswith("source/") and PurePosixPath(value).suffix.casefold() == ".rc"
        )
        if len(source_refs) != 1:
            raise ClassicProjectError(f"resource node {node.id!r} lacks one committed RC source")
        source_path = self._compiler_visible_path(arguments[-1])
        expected_source = _logical_join(
            self.bundle.spec.paths.source,
            source_refs[0].removeprefix("source/"),
        )
        if source_path.casefold() != expected_source.casefold():
            raise ClassicProjectError(
                f"resource node {node.id!r} source argument differs from its edge"
            )
        receipt = scan_msvc_resource_dependencies(
            source_path=source_path,
            include_directories=tuple(include_directories),
            environment_directories=self._include_environment_directories(lane.environment),
            authority=authority,
            payloads=self._include_payloads(authority),
        )
        step_id = f"resource-dependencies.{epoch}.{node.id}"
        step = _internal_step(
            step_id,
            {
                "schema": 1,
                "producer_node": node.id,
                "source": receipt.source_path,
                "reads": [
                    {
                        "logical_path": item.logical_path,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                        "origin": item.origin.value,
                        "kind": item.kind.value,
                        "parent_path": item.parent_path,
                    }
                    for item in receipt.reads
                ],
            },
            time.monotonic() - started,
        )
        read_receipt = ClassicProducerReadReceipt(
            node.id,
            step.step_id,
            ProducerRole.RESOURCE,
            epoch,
            tuple(
                ClassicProducerRead(
                    item.logical_path,
                    self._host_for_logical_path(item.logical_path),
                    item.digest,
                    item.size,
                    item.origin,
                    None,
                    item.parent_path,
                    item.kind.value,
                )
                for item in receipt.reads
            ),
        )
        with self._evidence_lock:
            if node.id in self._resource_dependency_receipts:
                raise ClassicProjectError(
                    f"resource node {node.id!r} repeated its dependency receipt"
                )
            self._resource_dependency_receipts[node.id] = receipt
            self._producer_reads.append(read_receipt)
        return _ResourceDependencyAudit(step, receipt)

    def _declared_node_outputs(self, node: ProducerNode) -> tuple[Path, ...]:
        outputs = tuple(self._reference(value) for value in node.outputs)
        if any(path is None for path in outputs):
            raise ClassicProjectError(f"producer {node.id!r} has a non-file output")
        return cast(tuple[Path, ...], outputs)

    def _node_outputs(self, node: ProducerNode) -> tuple[Path, ...]:
        declared = self._declared_node_outputs(node)
        with self._output_lock:
            return tuple(self._physical_outputs.get(path, path) for path in declared)

    @staticmethod
    def _compiler_companion_output(path: Path) -> Path:
        """Resolve one exact DOS-case-insensitive PDB companion on the host.

        MSPDB41 lowercases some newly created basenames even when ``/Fd`` uses
        source-preserving case.  The producer graph and compiler argument are
        DOS paths, so case is not semantic, but the POSIX build seat can be
        case-sensitive.  Admit exactly one same-parent, case-fold-equal regular
        file and reject aliases or any broader write.
        """

        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise ClassicProjectError(
                f"compiler companion output parent is absent or redirected: {parent}"
            )
        matches = tuple(
            item for item in parent.iterdir() if item.name.casefold() == path.name.casefold()
        )
        if len(matches) != 1:
            raise ClassicProjectError(
                f"compiler companion output has {len(matches)} physical aliases: {path}"
            )
        actual = matches[0]
        if actual.is_symlink() or not actual.is_file():
            raise ClassicProjectError(
                f"compiler companion output is absent or redirected: {actual}"
            )
        return actual.resolve(strict=True)

    def _ancestor_node_ids(self, target_id: str) -> frozenset[str]:
        by_id = {node.id: node for node in self.graph.nodes}
        terminal = [
            node
            for node in self.graph.nodes
            if node.role is ProducerRole.LINKER and node.target_id == target_id
        ]
        if len(terminal) != 1:
            raise ClassicProjectError(f"target {target_id!r} has no unique graph linker")
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            node = by_id.get(node_id)
            if node is None:
                raise ClassicProjectError(f"producer graph dependency is absent: {node_id!r}")
            visited.add(node_id)
            for dependency in node.depends_on:
                visit(dependency)

        visit(terminal[0].id)
        return frozenset(visited)

    @staticmethod
    def _compiler_product_refs(node: ProducerNode) -> tuple[str, str]:
        source_suffixes = {".c", ".cc", ".cpp", ".cxx"}
        sources = tuple(
            value
            for value in node.inputs
            if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() in source_suffixes
        )
        objects = tuple(
            value
            for value in node.outputs
            if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() in {".obj", ".o"}
        )
        if len(sources) != 1 or len(objects) != 1:
            raise ClassicProjectError(
                f"compiler node {node.id!r} lacks one source/object semantic edge"
            )
        return sources[0], objects[0]

    def _primary_source_receipts(self) -> tuple[SourceInputReceipt, ...]:
        manifest = self.bundle.source_manifest
        if manifest is None or not manifest.complete:
            raise ClassicProjectError("overlay semantics require a complete source manifest")
        receipts: list[SourceInputReceipt] = []
        expected: set[str] = set()
        pairs = {item.path.casefold(): item for item in self.project_source_pairs}
        for entry in manifest.entries:
            path = self.effective_root.joinpath(*PurePosixPath(entry.path).parts)
            self._require_regular(path, label="primary compiler source")
            payload = path.read_bytes()
            pair = pairs.get(entry.path.casefold())
            if pair is None:
                digest = entry.digest
                size = entry.size
                origin = PrimarySourceOrigin.CLEAN_MANIFEST
            else:
                if pair.clean_payload is None:
                    raise ClassicProjectError(
                        f"manifest source has no project-overlay clean preimage: {entry.path!r}"
                    )
                digest = Digest.from_bytes(pair.effective_payload)
                size = len(pair.effective_payload)
                origin = PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
            if Digest.from_bytes(payload) != digest or len(payload) != size:
                raise ClassicProjectError(
                    f"primary compiler source differs from its epoch: {entry.path!r}"
                )
            expected.add(entry.path.casefold())
            receipts.append(
                SourceInputReceipt(
                    entry.path,
                    digest,
                    size,
                    origin,
                )
            )
        for relative in self.ordinary_generated_inputs:
            pair = pairs.get(relative.casefold())
            if pair is None or pair.clean_payload is not None:
                raise ClassicProjectError(
                    f"generated header lacks its no-clean source pair: {relative!r}"
                )
            path = self.effective_root.joinpath(*PurePosixPath(relative).parts)
            self._require_regular(path, label="certified project-overlay header")
            payload = path.read_bytes()
            if payload != pair.effective_payload:
                raise ClassicProjectError(f"certified project-overlay header changed: {relative!r}")
            expected.add(relative.casefold())
            receipts.append(
                SourceInputReceipt(
                    relative,
                    Digest.from_bytes(payload),
                    len(payload),
                    PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY,
                )
            )
        for relative in sorted(self.generated_translation_units, key=str.casefold):
            path = self.effective_root.joinpath(*PurePosixPath(relative).parts)
            self._require_regular(path, label="generated carrier source")
            payload = path.read_bytes()
            expected.add(relative.casefold())
            receipts.append(
                SourceInputReceipt(
                    relative,
                    Digest.from_bytes(payload),
                    len(payload),
                    PrimarySourceOrigin.GENERATED_CARRIER,
                )
            )
        actual = {
            relative.casefold() for relative, _, _ in _effective_source_seal(self.effective_root)
        }
        if actual != expected:
            raise ClassicProjectError(
                "primary compiler source seat contains undeclared effective outputs"
            )
        return tuple(sorted(receipts, key=lambda item: item.path.casefold()))

    def _compiler_products(self) -> tuple[CompilerProduct, ...]:
        expected = {node.id for node in self.graph.nodes if node.role is ProducerRole.COMPILER}
        if {item.node_id for item in self._effective_compiler_products} != expected:
            raise ClassicProjectError(
                "raw effective compiler-product capture differs from the producer graph"
            )
        return self._effective_compiler_products

    def _capture_clean_source_inputs(
        self,
        source_seal: Mapping[Path, tuple[int, Digest]],
    ) -> StepExecutionReceipt:
        """Freeze the complete immutable source authority without compiling it."""

        started = time.monotonic()
        _require_unchanged_tree(
            source_seal,
            root=self.effective_root,
            label="clean project-overlay source authority",
        )
        manifest = self.bundle.source_manifest
        if manifest is None or not manifest.complete:
            raise ClassicProjectError(
                "project-overlay source capture requires a complete source manifest"
            )
        clean_inputs: list[CleanSourceInput] = []
        expected_source_seal: list[tuple[str, int, str]] = []
        for entry in manifest.entries:
            path = self.effective_root.joinpath(*PurePosixPath(entry.path).parts)
            self._require_regular(path, label="clean project-overlay source")
            payload = path.read_bytes()
            if Digest.from_bytes(payload) != entry.digest or len(payload) != entry.size:
                raise ClassicProjectError(
                    f"clean project-overlay source changed: {entry.path!r}"
                )
            clean_inputs.append(CleanSourceInput(entry.path, payload))
            expected_source_seal.append((entry.path, entry.size, entry.digest.value))
        if tuple(
            sorted(expected_source_seal, key=lambda item: item[0].casefold())
        ) != _effective_source_seal(self.effective_root):
            raise ClassicProjectError(
                "clean project-overlay source seat differs from the complete manifest"
            )
        self._clean_source_inputs = tuple(
            sorted(clean_inputs, key=lambda item: item.path.casefold())
        )
        step_id = "source.clean-authority-capture"
        receipt = _internal_step(
            step_id,
            {
                "schema": 1,
                "source_manifest_count": len(self._clean_source_inputs),
                "source_seal": [
                    {"path": path, "size": size, "digest": digest}
                    for path, size, digest in _effective_source_seal(self.effective_root)
                ],
            },
            time.monotonic() - started,
        )
        self._progress.emit("source-epoch", step_id)
        return receipt

    def _run_counterfactual_compiler_audit(
        self,
        supervisor: ProcessSupervisor,
        nodes: Sequence[ProducerNode],
        *,
        source_seal: Mapping[Path, tuple[int, Digest]],
        cancellation: CancellationToken,
        compiler_namespace_id: str,
    ) -> list[StepExecutionReceipt]:
        """Compile exactly the planned semantic-delta nodes, then erase them.

        The audit runs at the exact committed source/build/toolchain seats.  Its
        raw object bytes are retained only in immutable semantic statements;
        every graph-declared OBJ/PDB is removed before the effective graph is
        allowed to execute.
        """

        if not self.overlay_witnesses:
            raise ClassicProjectError(
                "counterfactual compiler audit requires a project overlay"
            )
        expected = set(self.compiler_epoch_plan.audit_node_ids)
        if {node.id for node in nodes} != expected or any(
            node.role is not ProducerRole.COMPILER for node in nodes
        ):
            raise ClassicProjectError(
                "counterfactual compiler audit differs from its derived sparse plan"
            )
        outside_dependencies = {
            dependency
            for node in nodes
            for dependency in node.depends_on
            if dependency not in expected
        }
        if outside_dependencies:
            raise ClassicProjectError(
                "counterfactual compiler audit depends on non-audit producer nodes: "
                + ", ".join(sorted(outside_dependencies, key=str.casefold))
            )
        _require_unchanged_tree(
            source_seal,
            root=self.effective_root,
            label="declaration-counterfactual compiler epoch",
        )
        build_seal = _tree_file_seal(self.build_root)
        completed: set[str] = set()
        output_steps: dict[Path, str] = {}
        receipts = self._run_graph_nodes(
            supervisor,
            nodes,
            completed=completed,
            output_steps=output_steps,
            cancellation=cancellation,
            step_id_prefix="audit.counterfactual.",
            progress_phase="counterfactual-audit",
            log_namespace="counterfactual-audit",
            include_authority=self._include_authority(),
            include_trace_epoch="declaration-counterfactual",
            compiler_namespace_id=compiler_namespace_id,
        )
        if completed != expected:
            raise ClassicProjectError("counterfactual compiler audit execution was incomplete")
        _require_declared_tree_writes(
            build_seal,
            root=self.build_root,
            allowed_outputs=(path for node in nodes for path in self._node_outputs(node)),
            phase="counterfactual compiler audit",
        )
        _require_unchanged_tree(
            source_seal,
            root=self.effective_root,
            label="declaration-counterfactual compiler epoch",
        )

        started = time.monotonic()
        audits: list[ProjectOverlayCounterfactualAudit] = []
        output_material: list[dict[str, object]] = []
        declared_universe: set[Path] = set()
        physical_universe: set[Path] = set()
        for node in sorted(nodes, key=lambda item: item.id.casefold()):
            source_ref, object_ref = self._compiler_product_refs(node)
            declared_outputs = self._declared_node_outputs(node)
            if any(
                path.suffix.casefold() not in {".obj", ".o", ".pdb"} for path in declared_outputs
            ):
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} declares a non-OBJ/PDB output"
                )
            declared_object = self._reference(object_ref)
            if declared_object is None:
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} object is unresolved"
                )
            with self._output_lock:
                physical_outputs = {
                    declared: self._physical_outputs.get(declared) for declared in declared_outputs
                }
            if any(actual is None for actual in physical_outputs.values()):
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} lacks its physical-output receipt"
                )
            actual_object = physical_outputs.get(declared_object)
            if actual_object is None:
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} lacks its object output"
                )
            self._require_regular(
                actual_object,
                label=f"counterfactual compiler audit object {node.id!r}",
            )
            object_payload = actual_object.read_bytes()
            audits.append(
                ProjectOverlayCounterfactualAudit(
                    node.id,
                    source_ref,
                    object_ref,
                    object_payload,
                    self._compiler_epoch_invocation(
                        node, epoch="declaration-counterfactual"
                    ),
                )
            )
            node_outputs: list[dict[str, object]] = []
            for reference, declared in zip(node.outputs, declared_outputs, strict=True):
                actual = physical_outputs[declared]
                if actual is None:
                    raise AssertionError("physical compiler output was not narrowed")
                self._require_regular(
                    actual,
                    label=f"counterfactual compiler audit output {node.id!r}",
                )
                try:
                    actual.relative_to(self.build_root.resolve(strict=True))
                except ValueError as exc:
                    raise ClassicProjectError(
                        f"counterfactual compiler audit output escapes the build seat: {actual}"
                    ) from exc
                payload = actual.read_bytes()
                node_outputs.append(
                    {
                        "reference": reference,
                        "digest": Digest.from_bytes(payload).model_dump(mode="json"),
                        "size": len(payload),
                    }
                )
                declared_universe.add(declared)
                physical_universe.add(actual)
            output_material.append(
                {
                    "node_id": node.id,
                    "step_id": f"audit.counterfactual.{node.id}",
                    "source_ref": source_ref,
                    "outputs": node_outputs,
                }
            )
        if len(physical_universe) != len(declared_universe):
            raise ClassicProjectError("counterfactual compiler audit aliases physical outputs")
        with self._output_lock:
            if set(self._physical_outputs) != declared_universe:
                raise ClassicProjectError(
                    "counterfactual compiler audit physical-output registry is not isolated"
                )
        for path in sorted(physical_universe, key=str):
            self._require_regular(path, label="counterfactual compiler audit erase target")
            path.unlink()
        for declared in sorted(declared_universe, key=str):
            with self._output_lock:
                actual = self._physical_outputs.pop(declared, None)
            if actual is None:
                raise ClassicProjectError(
                    "counterfactual compiler audit output disappeared from its registry"
                )
            if os.path.lexists(actual) or (
                declared.parent.is_dir()
                and any(
                    item.name.casefold() == declared.name.casefold()
                    for item in declared.parent.iterdir()
                )
            ):
                raise ClassicProjectError(
                    f"counterfactual compiler audit output survived erasure: {declared}"
                )
        with self._output_lock:
            if self._physical_outputs:
                raise ClassicProjectError(
                    "counterfactual compiler audit left stale physical-output registrations"
                )
        _require_unchanged_tree(
            build_seal,
            root=self.build_root,
            label="counterfactual compiler audit erasure",
        )
        self._counterfactual_compiler_audits = tuple(
            sorted(audits, key=lambda item: item.node_id.casefold())
        )
        step_id = "source.counterfactual-compiler-audit-capture"
        receipts.append(
            _internal_step(
                step_id,
                {
                    "schema": 1,
                    "producer_graph": producer_graph_digest(self.graph).model_dump(mode="json"),
                    "counterfactual_source_seal": [
                        {"path": path, "size": size, "digest": digest}
                        for path, size, digest in _effective_source_seal(self.effective_root)
                    ],
                    "compiler_outputs": output_material,
                    "erased_declared_outputs": sorted(
                        (reference for node in nodes for reference in node.outputs),
                        key=str.casefold,
                    ),
                },
                time.monotonic() - started,
            )
        )
        self._progress.emit("source-epoch", step_id)
        return receipts

    def _install_project_overlay_source(
        self,
        *,
        relative: str,
        expected_payload: bytes | None,
        payload: bytes,
        epoch: str,
    ) -> tuple[Path, bool]:
        """Install one exact source transition beneath the sealed source root."""

        destination = self.effective_root.joinpath(*PurePosixPath(relative).parts)
        if expected_payload is None:
            if os.path.lexists(destination):
                raise ClassicProjectError(
                    f"{epoch} source already exists without a preimage: {relative!r}"
                )
        else:
            self._require_regular(destination, label=f"{epoch} source preimage")
            if destination.read_bytes() != expected_payload:
                raise ClassicProjectError(f"{epoch} source preimage changed: {relative!r}")
            if expected_payload == payload:
                return destination, False
        parent = destination.parent
        lineage: list[Path] = []
        while parent != self.effective_root:
            lineage.append(parent)
            parent = parent.parent
        if parent != self.effective_root:
            raise ClassicProjectError(f"{epoch} source escapes its seat: {relative!r}")
        for directory in reversed(lineage):
            if os.path.lexists(directory) and (
                directory.is_symlink() or not directory.is_dir()
            ):
                raise ClassicProjectError(
                    f"{epoch} source parent is redirected: {relative!r}"
                )
            directory.mkdir(exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.reprobit-{epoch}")
        if os.path.lexists(temporary):
            raise ClassicProjectError(f"{epoch} temporary path already exists: {temporary}")
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        self._require_regular(destination, label=f"{epoch} installed source")
        if destination.read_bytes() != payload:
            raise ClassicProjectError(f"{epoch} source changed after install: {relative!r}")
        return destination, True

    def _materialize_project_overlay_counterfactual_epoch(
        self,
        clean_source_seal: Mapping[Path, tuple[int, Digest]],
    ) -> tuple[StepExecutionReceipt, Mapping[Path, tuple[int, Digest]]]:
        """Install the pure derived declaration/layout counterfactual."""

        if not self.compiler_epoch_plan.audit_node_ids:
            raise ClassicProjectError("empty compiler audit plan has no physical counterfactual")
        _require_unchanged_tree(
            clean_source_seal,
            root=self.effective_root,
            label="clean project-overlay source authority",
        )
        started = time.monotonic()
        pairs = {item.path.casefold(): item for item in self.project_source_pairs}
        destinations: list[Path] = []
        outputs: list[dict[str, object]] = []
        before = _effective_source_seal(self.effective_root)
        for relative, payload in self.compiler_epoch_plan.declaration_outputs.items():
            pair = pairs.get(relative.casefold())
            if pair is None or relative.casefold() in {
                item.casefold() for item in self.generated_translation_units
            }:
                raise ClassicProjectError(
                    f"counterfactual source is not an ordinary overlay output: {relative!r}"
                )
            destination, written = self._install_project_overlay_source(
                relative=relative,
                expected_payload=pair.clean_payload,
                payload=payload,
                epoch="declaration-counterfactual",
            )
            if written:
                destinations.append(destination)
            outputs.append(
                {
                    "path": relative,
                    "digest": Digest.from_bytes(payload).model_dump(mode="json"),
                    "size": len(payload),
                    "written": written,
                }
            )
        _require_declared_tree_writes(
            clean_source_seal,
            root=self.effective_root,
            allowed_outputs=destinations,
            phase="declaration-counterfactual source epoch",
        )
        step_id = "source.declaration-counterfactual-epoch"
        receipt = _internal_step(
            step_id,
            {
                "schema": 1,
                "before": [
                    {"path": path, "size": size, "digest": digest}
                    for path, size, digest in before
                ],
                "after": [
                    {"path": path, "size": size, "digest": digest}
                    for path, size, digest in _effective_source_seal(self.effective_root)
                ],
                "outputs": outputs,
                "audit_node_ids": sorted(
                    self.compiler_epoch_plan.audit_node_ids,
                    key=str.casefold,
                ),
            },
            time.monotonic() - started,
        )
        self._progress.emit("source-epoch", step_id)
        return receipt, _tree_file_seal(self.effective_root)

    def _materialize_certified_project_overlay_epoch(
        self,
        source_seal: Mapping[Path, tuple[int, Digest]],
        *,
        preimage: Literal["clean", "counterfactual"] = "clean",
    ) -> tuple[StepExecutionReceipt, Mapping[Path, tuple[int, Digest]]]:
        """Install exactly the certified ordinary effective source epoch."""

        if not self.overlay_witnesses or not self.project_source_pairs:
            raise ClassicProjectError(
                "certified project-overlay epoch requires rendered project outputs"
            )
        _require_unchanged_tree(
            source_seal,
            root=self.effective_root,
            label=f"{preimage} project-overlay compiler epoch",
        )
        started = time.monotonic()
        generated_tus = {item.casefold() for item in self.generated_translation_units}
        destinations: list[Path] = []
        declarations: list[dict[str, object]] = []
        before_relative = _effective_source_seal(self.effective_root)
        for pair in sorted(self.project_source_pairs, key=lambda item: item.path.casefold()):
            relative = _safe_relative(pair.path)
            destination = self.effective_root.joinpath(*PurePosixPath(relative).parts)
            deferred = relative.casefold() in generated_tus
            if pair.clean_payload is None and deferred:
                if os.path.lexists(destination):
                    raise ClassicProjectError(
                        f"generated carrier was visible before its epoch: {relative!r}"
                    )
                declarations.append(
                    {
                        "path": relative,
                        "clean": None,
                        "effective": Digest.from_bytes(pair.effective_payload).model_dump(
                            mode="json"
                        ),
                        "size": len(pair.effective_payload),
                        "written": False,
                    }
                )
                continue
            if preimage == "counterfactual":
                expected_payload = self.compiler_epoch_plan.declaration_outputs.get(relative)
                if expected_payload is None:
                    raise ClassicProjectError(
                        f"counterfactual source preimage is absent: {relative!r}"
                    )
            else:
                expected_payload = pair.clean_payload
            destination, written = self._install_project_overlay_source(
                relative=relative,
                expected_payload=expected_payload,
                payload=pair.effective_payload,
                epoch="certified-project-overlay",
            )
            if written:
                destinations.append(destination)
            declarations.append(
                {
                    "path": relative,
                    "preimage": (
                        Digest.from_bytes(expected_payload).model_dump(mode="json")
                        if expected_payload is not None
                        else None
                    ),
                    "effective": Digest.from_bytes(pair.effective_payload).model_dump(mode="json"),
                    "size": len(pair.effective_payload),
                    "written": written,
                }
            )
        _require_declared_tree_writes(
            source_seal,
            root=self.effective_root,
            allowed_outputs=destinations,
            phase="certified project-overlay source epoch",
        )
        after_relative = _effective_source_seal(self.effective_root)
        step_id = "source.certified-project-overlay-epoch"
        receipt = _internal_step(
            step_id,
            {
                "schema": 1,
                "before": [
                    {"path": path, "size": size, "digest": digest}
                    for path, size, digest in before_relative
                ],
                "after": [
                    {"path": path, "size": size, "digest": digest}
                    for path, size, digest in after_relative
                ],
                "outputs": declarations,
                "preimage_epoch": preimage,
                "ordinary_generated_inputs": list(self.ordinary_generated_inputs),
                "deferred_generated_translation_units": sorted(
                    self.generated_translation_units, key=str.casefold
                ),
            },
            time.monotonic() - started,
        )
        self._progress.emit("source-epoch", step_id)
        return receipt, _tree_file_seal(self.effective_root)

    def _capture_effective_compiler_products(self) -> StepExecutionReceipt:
        """Freeze raw effective CL outputs before candidate composition mutates them."""

        started = time.monotonic()
        products: list[CompilerProduct] = []
        captured_outputs: list[ClassicCapturedProducerOutput] = []
        material: list[dict[str, object]] = []
        ordinary_visibility = self.ordinary_generated_inputs
        for node in sorted(self.graph.nodes, key=lambda item: item.id.casefold()):
            if node.role is not ProducerRole.COMPILER:
                continue
            source_ref, object_ref = self._compiler_product_refs(node)
            declared_object = self._reference(object_ref)
            if declared_object is None:
                raise ClassicProjectError("compiler semantic output is not a file")
            with self._output_lock:
                object_path = self._physical_outputs.get(declared_object)
            if object_path is None:
                raise ClassicProjectError(f"compiler {node.id!r} lacks a physical object receipt")
            self._require_regular(object_path, label="raw effective compiler object")
            payload = object_path.read_bytes()
            generated_inputs = self.generated_node_inputs.get(node.id, ordinary_visibility)
            compiler_invocation = self._compiler_epoch_invocation(
                node,
                epoch=(
                    "generated" if node.id in self.generated_node_inputs else "effective"
                ),
            )
            product = CompilerProduct(
                node.id,
                source_ref,
                object_ref,
                payload,
                generated_inputs,
                compiler_invocation,
            )
            products.append(product)
            node_output_material: list[dict[str, object]] = []
            declared_outputs = self._declared_node_outputs(node)
            for reference, declared in zip(node.outputs, declared_outputs, strict=True):
                if not reference.startswith("build/"):
                    raise ClassicProjectError(
                        f"compiler {node.id!r} has a non-build output reference"
                    )
                with self._output_lock:
                    physical_output = self._physical_outputs.get(declared)
                if physical_output is None:
                    raise ClassicProjectError(
                        f"compiler {node.id!r} lacks an output capture receipt"
                    )
                self._require_regular(physical_output, label="raw compiler output capture")
                output_payload = physical_output.read_bytes()
                logical_path = _logical_join(
                    self.bundle.spec.paths.build,
                    reference.removeprefix("build/"),
                )
                captured_outputs.append(
                    ClassicCapturedProducerOutput(
                        node.id,
                        node.id,
                        ProducerRole.COMPILER,
                        reference,
                        logical_path,
                        Digest.from_bytes(output_payload),
                        len(output_payload),
                    )
                )
                node_output_material.append(
                    {
                        "reference": reference,
                        "logical_path": logical_path,
                        "digest": Digest.from_bytes(output_payload).model_dump(mode="json"),
                        "size": len(output_payload),
                    }
                )
            material.append(
                {
                    "node_id": node.id,
                    "source_ref": source_ref,
                    "object_ref": object_ref,
                    "digest": Digest.from_bytes(payload).model_dump(mode="json"),
                    "size": len(payload),
                    "generated_inputs": list(generated_inputs),
                    "outputs": node_output_material,
                }
            )
        self._effective_compiler_products = tuple(products)
        self._captured_compiler_outputs = tuple(captured_outputs)
        step_id = "source.effective-compiler-product-capture"
        receipt = _internal_step(
            step_id,
            {
                "schema": 1,
                "producer_graph": producer_graph_digest(self.graph).model_dump(mode="json"),
                "products": material,
            },
            time.monotonic() - started,
        )
        self._progress.emit("source-epoch", step_id)
        return receipt

    def _materialize_generated_input_epoch(
        self,
        ordinary_source_seal: Mapping[Path, tuple[int, Digest]],
    ) -> tuple[StepExecutionReceipt, Mapping[Path, tuple[int, Digest]]]:
        """Install the sealed carrier inputs after ordinary producers finish."""

        if not self.generated_translation_units:
            raise ClassicProjectError("generated-input epoch is empty")
        _require_unchanged_tree(
            ordinary_source_seal,
            root=self.effective_root,
            label="ordinary compiler source epoch",
        )
        started = time.monotonic()
        destinations: list[Path] = []
        declarations: list[Mapping[str, object]] = []
        for relative in sorted(self.generated_translation_units, key=str.casefold):
            payload = self.overlay_effective_outputs.get(relative)
            if payload is None:
                raise ClassicProjectError(
                    f"generated input lacks captured overlay bytes: {relative!r}"
                )
            destination = self.effective_root.joinpath(
                *PurePosixPath(_safe_relative(relative)).parts
            )
            if os.path.lexists(destination):
                raise ClassicProjectError(
                    f"generated input was visible during the ordinary epoch: {relative!r}"
                )
            parent = destination.parent
            lineage: list[Path] = []
            while parent != self.effective_root:
                lineage.append(parent)
                parent = parent.parent
            if parent != self.effective_root:
                raise ClassicProjectError(
                    f"generated input escapes the effective source seat: {relative!r}"
                )
            for directory in reversed(lineage):
                if os.path.lexists(directory) and (
                    directory.is_symlink() or not directory.is_dir()
                ):
                    raise ClassicProjectError(f"generated input parent is redirected: {relative!r}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(payload)
            self._require_regular(destination, label="generated compiler input")
            if destination.read_bytes() != payload:
                raise ClassicProjectError(
                    f"generated compiler input changed while installed: {relative!r}"
                )
            destinations.append(destination)
            declarations.append(
                {
                    "path": relative,
                    "digest": Digest.from_bytes(payload).model_dump(mode="json"),
                    "size": len(payload),
                }
            )
        _require_declared_tree_writes(
            ordinary_source_seal,
            root=self.effective_root,
            allowed_outputs=destinations,
            phase="generated-input epoch",
        )
        step_id = "source.generated-input-epoch"
        receipt = _internal_step(
            step_id,
            {
                "schema": 1,
                "generated_translation_units": declarations,
                "ordinary_generated_inputs": list(self.ordinary_generated_inputs),
                "carrier_input_seals": {
                    path: list(inputs)
                    for path, inputs in sorted(
                        self.carrier_input_seals.items(),
                        key=lambda item: item[0].casefold(),
                    )
                },
            },
            time.monotonic() - started,
        )
        self._progress.emit("source-epoch", step_id)
        return receipt, _tree_file_seal(self.effective_root)

    def _archive_path(self, reference: str) -> Path:
        if reference.startswith("system-library/"):
            path = self.system_libraries.get(reference)
        else:
            path = self._reference(reference)
        if path is None:
            raise ClassicProjectError(f"semantic archive reference is unresolved: {reference!r}")
        self._require_regular(path, label=f"semantic archive {reference!r}")
        return path

    def _audit_link_controls(
        self,
        targets: Sequence[ClassicProducerTarget] | None = None,
    ) -> tuple[StepExecutionReceipt, ...]:
        """Close each selected target's hidden controls before its LINK wave."""

        by_id = {node.id: node for node in self.graph.nodes}
        all_compilers = {node.id for node in self.graph.nodes if node.role is ProducerRole.COMPILER}
        target_by_id = {target.target_id: target for target in self.targets}
        all_target_ids = set(target_by_id)
        if len(target_by_id) != len(self.targets):
            raise ClassicProjectError("classic targets repeat a target identity")
        closures = dict(self._link_directive_closures)
        definitions = dict(self._module_definition_receipts)
        if not set(closures).issubset(all_target_ids) or not set(definitions).issubset(closures):
            raise ClassicProjectError("linker-control audit state differs from classic targets")
        selected = self.targets if targets is None else tuple(targets)
        selected_ids = tuple(target.target_id for target in selected)
        if not selected_ids or len(selected_ids) != len(set(selected_ids)):
            raise ClassicProjectError(
                "linker-control audit requires one or more unique target identities"
            )
        unknown = sorted(set(selected_ids) - all_target_ids, key=str.casefold)
        if unknown:
            raise ClassicProjectError(f"linker-control audit names unknown targets: {unknown}")
        for target in selected:
            if target != target_by_id[target.target_id]:
                raise ClassicProjectError(
                    f"linker-control audit target {target.target_id!r} differs from authority"
                )
        repeated = sorted(set(selected_ids).intersection(closures), key=str.casefold)
        if repeated:
            raise ClassicProjectError(f"linker-control targets were already audited: {repeated}")
        steps: list[StepExecutionReceipt] = []
        for target in selected:
            started = time.monotonic()
            ancestors = self._ancestor_node_ids(target.target_id)
            compiler_ids = tuple(
                sorted(
                    (
                        node_id
                        for node_id in ancestors
                        if by_id[node_id].role is ProducerRole.COMPILER
                    ),
                    key=str.casefold,
                )
            )
            object_inputs: dict[str, bytes] = {}
            for node_id in compiler_ids:
                node = by_id[node_id]
                object_refs = tuple(
                    reference
                    for reference in node.outputs
                    if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold() == ".obj"
                )
                if len(object_refs) != 1:
                    raise ClassicProjectError(
                        f"compiler {node_id!r} lacks one directive-audited OBJ"
                    )
                path = self._reference(object_refs[0])
                if path is None:
                    raise ClassicProjectError("compiler OBJ is not materializable")
                self._require_regular(path, label=f"directive input {object_refs[0]!r}")
                object_inputs[object_refs[0]] = path.read_bytes()
            archive_refs = tuple(
                sorted(
                    {
                        value
                        for node_id in ancestors
                        for value in (
                            *by_id[node_id].inputs,
                            *by_id[node_id].directive_inputs,
                        )
                        if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold()
                        in {".lib", ".a"}
                    },
                    key=str.casefold,
                )
            )
            archive_inputs = {
                reference: self._archive_path(reference).read_bytes() for reference in archive_refs
            }
            terminal = by_id[target.link_node_id]
            try:
                closure = audit_classic_link_directives(
                    object_inputs=object_inputs,
                    archive_inputs=archive_inputs,
                    declared_archive_refs=archive_refs,
                    linker_arguments=terminal.arguments,
                )
            except MissingDirectiveInputsError as exc:
                suggestions = " ".join(
                    f"--directive-input {target.target_id}={library}" for library in exc.libraries
                )
                raise ClassicProjectError(
                    f"target {target.target_id!r} lacks committed DEFAULTLIB edges; "
                    f"rerun `rbit graph extract ... {suggestions}`"
                ) from exc
            except Exception as exc:
                raise ClassicProjectError(
                    f"target {target.target_id!r} linker-control closure failed: {exc}"
                ) from exc

            definition_refs = tuple(
                value
                for value in terminal.inputs
                if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() == ".def"
            )
            if len(definition_refs) > 1:
                raise ClassicProjectError(
                    f"target {target.target_id!r} names more than one DEF input"
                )
            definition: ModuleDefinitionReceipt | None = None
            if definition_refs:
                path = self._reference(definition_refs[0])
                if path is None:
                    raise ClassicProjectError("module-definition input is unresolved")
                self._require_regular(path, label="module-definition input")
                try:
                    definition = parse_classic_module_definition(
                        path.read_bytes(), label=definition_refs[0]
                    )
                except Exception as exc:
                    raise ClassicProjectError(
                        f"target {target.target_id!r} DEF closure failed: {exc}"
                    ) from exc
                definitions[target.target_id] = definition
            closures[target.target_id] = closure
            step_id = f"link-controls.{target.target_id}"
            steps.append(
                _internal_step(
                    step_id,
                    {
                        "schema": 1,
                        "target_id": target.target_id,
                        "linker_node": terminal.id,
                        "directives": link_directive_closure_material(closure),
                        "module_definition": module_definition_material(definition),
                    },
                    time.monotonic() - started,
                )
            )
        if set(closures) == all_target_ids:
            audited_compilers = {
                node_id
                for target_id in all_target_ids
                for node_id in self._ancestor_node_ids(target_id)
                if by_id[node_id].role is ProducerRole.COMPILER
            }
            if audited_compilers != all_compilers:
                missing = sorted(all_compilers - audited_compilers, key=str.casefold)
                raise ClassicProjectError(
                    f"compiler outputs lack terminal linker-control ancestry: {missing}"
                )
        self._link_directive_closures = MappingProxyType(closures)
        self._module_definition_receipts = MappingProxyType(definitions)
        for step in steps:
            self._progress.emit("link-controls", step.step_id)
        return tuple(steps)

    def _link_root_symbols(self, node: ProducerNode) -> tuple[str, ...]:
        roots: set[str] = set()
        explicit_entry = False
        no_entry = False
        for argument in node.arguments:
            folded = argument.casefold()
            if folded.startswith(("/entry:", "-entry:")):
                roots.add(argument.split(":", 1)[1])
                explicit_entry = True
            elif folded.startswith(("/export:", "-export:")):
                declaration = argument.split(":", 1)[1].split(",", 1)[0]
                roots.add(declaration.split("=", 1)[-1])
            elif folded in {"/noentry", "-noentry"}:
                no_entry = True
        if explicit_entry and no_entry:
            raise ClassicProjectError("linker declares both /ENTRY and /NOENTRY")
        if not explicit_entry and not no_entry:
            output_suffixes = {
                PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() for value in node.outputs
            }
            is_dll = (
                any(argument.casefold() in {"/dll", "-dll"} for argument in node.arguments)
                or ".dll" in output_suffixes
            )
            if is_dll:
                roots.add("__DllMainCRTStartup@12")
            else:
                # The selected CRT startup depends on subsystem and source-level
                # entry spelling.  Keeping the complete closed MSVC 4.x set is a
                # conservative reachability root for carrier isolation.
                roots.update(
                    {
                        "_mainCRTStartup",
                        "_WinMainCRTStartup",
                        "_wmainCRTStartup",
                        "_wWinMainCRTStartup",
                    }
                )
        target_id = node.target_id
        if target_id is None:
            raise ClassicProjectError("linker root closure lacks a target identity")
        directive_closure = self._link_directive_closures.get(target_id)
        if directive_closure is None:
            raise ClassicProjectError(f"target {target_id!r} lacks a current linker-control audit")
        roots.update(directive_closure.include_symbols)
        roots.update(directive_closure.export_symbols)
        definition = self._module_definition_receipts.get(target_id)
        if definition is not None:
            roots.update(definition.exports)
        if any(not value or "\0" in value for value in roots):
            raise ClassicProjectError("linker root-symbol declaration is malformed")
        return tuple(sorted(roots, key=str.casefold))

    def _target_link_closures(self) -> tuple[TargetLinkClosure, ...]:
        by_id = {node.id: node for node in self.graph.nodes}
        closures: list[TargetLinkClosure] = []
        for target in self.targets:
            ancestors = self._ancestor_node_ids(target.target_id)
            compiler_ids = tuple(
                sorted(
                    (
                        node_id
                        for node_id in ancestors
                        if by_id[node_id].role is ProducerRole.COMPILER
                    ),
                    key=str.casefold,
                )
            )
            archive_refs = tuple(
                sorted(
                    {
                        value
                        for node_id in ancestors
                        for value in (
                            *by_id[node_id].inputs,
                            *by_id[node_id].directive_inputs,
                        )
                        if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold()
                        in {".lib", ".a"}
                    },
                    key=str.casefold,
                )
            )
            archives = tuple(
                ArchiveInput(reference, self._archive_path(reference).read_bytes())
                for reference in archive_refs
            )
            terminal = by_id[target.link_node_id]
            closures.append(
                TargetLinkClosure(
                    target.target_id,
                    compiler_ids,
                    archive_refs,
                    archives,
                    self._link_root_symbols(terminal),
                )
            )
        return tuple(sorted(closures, key=lambda item: item.target_id.casefold()))

    def _semantic_compiler_namespaces(
        self,
        compiler_products: Sequence[CompilerProduct],
    ) -> tuple[CompilerNamespaceEvidence, ...]:
        semantic_namespace_ids = {
            invocation.namespace_id
            for audit in self._counterfactual_compiler_audits
            for invocation in (audit.counterfactual_invocation,)
            if isinstance(invocation, CompilerEpochInvocation)
        }
        semantic_namespace_ids.update(
            product.compiler_invocation.namespace_id
            for product in compiler_products
            if isinstance(product.compiler_invocation, CompilerEpochInvocation)
        )
        if not isinstance(self._counterfactual_namespace_id, str):
            raise ClassicProjectError(
                "project-overlay proof lacks its counterfactual namespace"
            )
        semantic_namespace_ids.add(self._counterfactual_namespace_id)
        missing = semantic_namespace_ids - set(self._compiler_namespaces)
        if missing:
            raise ClassicProjectError(
                "project-overlay proof lacks compiler namespaces: "
                + ", ".join(sorted(missing, key=str.casefold))
            )
        return tuple(
            self._compiler_namespaces[namespace_id].evidence
            for namespace_id in sorted(semantic_namespace_ids, key=str.casefold)
        )

    def _validate_project_overlay_compiler_epoch(self) -> StepExecutionReceipt:
        """Reject compiler-epoch divergence before any candidate composition."""

        started = time.monotonic()
        compiler_products = self._compiler_products()
        compiler_namespaces = self._semantic_compiler_namespaces(compiler_products)
        with self._evidence_lock:
            resource_receipts = dict(self._resource_dependency_receipts)
        reader_trace = _project_overlay_resource_reader_closure(
            source_root=self.bundle.spec.paths.source,
            source_pairs=self.project_source_pairs,
            graph=self.graph,
            receipts=resource_receipts,
        )
        try:
            semantic_trace = validate_project_overlay_compiler_epoch(
                self.bundle,
                self.graph,
                compiler_products=compiler_products,
                project_source_pairs=self.project_source_pairs,
                counterfactual_compiler_audits=self._counterfactual_compiler_audits,
                counterfactual_namespace_id=cast(str, self._counterfactual_namespace_id),
                clean_source_inputs=self._clean_source_inputs,
                compiler_namespaces=compiler_namespaces,
            )
        except ClassicSemanticError as exc:
            raise ClassicProjectError(
                f"project-overlay compiler epoch preflight failed: {exc}"
            ) from exc
        trace = dict(semantic_trace)
        trace["secondary_reader_closure"] = reader_trace
        step_id = "source.compiler-epoch-preflight"
        receipt = _internal_step(step_id, trace, time.monotonic() - started)
        self._progress.emit("validate", step_id)
        return receipt

    def _apply_overlay_semantic_proofs(self, witnesses: list[InterventionWitness]) -> None:
        if not self.overlay_witnesses:
            return
        primary_sources = self._primary_source_receipts()
        effective_outputs = tuple(
            EffectiveOverlayReceipt(
                path,
                Digest.from_bytes(payload),
                len(payload),
            )
            for path, payload in sorted(
                self.overlay_effective_outputs.items(),
                key=lambda item: item[0].casefold(),
            )
        )
        compiler_products = self._compiler_products()
        source_pairs = tuple(
            sorted(self.project_source_pairs, key=lambda item: item.path.casefold())
        )
        counterfactual_compiler_audits = self._counterfactual_compiler_audits
        clean_source_inputs = self._clean_source_inputs
        compiler_namespaces = self._semantic_compiler_namespaces(compiler_products)
        link_closures = self._target_link_closures()
        with self._semantic_lock:
            donor_lanes = tuple(
                sorted(
                    self._donor_semantic_lanes,
                    key=lambda item: (
                        item.target_id.casefold(),
                        item.donor_intervention_id.casefold(),
                        item.consumer_intervention_id.casefold(),
                    ),
                )
            )
        snapshot = OverlaySemanticSnapshot(
            run_binding=Digest(value="0" * 64),
            primary_sources=primary_sources,
            effective_outputs=effective_outputs,
            compiler_products=compiler_products,
            donor_lanes=donor_lanes,
            link_closures=link_closures,
            project_source_pairs=source_pairs,
            counterfactual_compiler_audits=counterfactual_compiler_audits,
            counterfactual_namespace_id=self._counterfactual_namespace_id,
            clean_source_inputs=clean_source_inputs,
            compiler_namespaces=compiler_namespaces,
        )
        snapshot = replace(
            snapshot,
            run_binding=overlay_semantic_run_binding(self.graph, snapshot),
        )
        validation = prove_source_overlay_semantics(
            self.bundle,
            self.graph,
            snapshot,
            semantic_contracts=CLASSIC_SEMANTIC_CONTRACTS,
        )
        expected = {item.intervention_id for item in self.overlay_witnesses}
        if set(validation.proofs) != expected:
            raise ClassicProjectError("source-overlay semantic proof universe differs")
        for index, witness in enumerate(witnesses):
            proof = validation.proofs.get(witness.intervention_id)
            if proof is not None:
                witnesses[index] = replace(witness, semantic_proof=proof)

    @staticmethod
    def _require_regular(path: Path, *, label: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise ClassicProjectError(f"{label} is absent or redirected: {path}")

    def _run_node(
        self,
        supervisor: ProcessSupervisor,
        node: ProducerNode,
        cancellation: CancellationToken,
        *,
        receipt_step_id: str | None = None,
        log_namespace: str = "producers",
        include_authority: SealedIncludeAuthority | None = None,
        include_trace_epoch: str | None = None,
        compiler_namespace_id: str | None = None,
    ) -> tuple[StepExecutionReceipt, ...]:
        for value in (*node.inputs, *node.directive_inputs):
            path = self._reference(value)
            if path is not None:
                self._require_regular(path, label=f"producer {node.id!r} input")
        declared_outputs = self._declared_node_outputs(node)
        for path in declared_outputs:
            companion_exists = (
                node.role is ProducerRole.COMPILER
                and path.suffix.casefold() == ".pdb"
                and path.parent.is_dir()
                and any(
                    item.name.casefold() == path.name.casefold() for item in path.parent.iterdir()
                )
            )
            if os.path.lexists(path) or companion_exists:
                raise ClassicProjectError(f"producer {node.id!r} output already exists: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)
        command = (
            str(self.role_commands[node.role]),
            *self._node_arguments(node),
        )
        timeout = min(
            float(node.timeout_seconds),
            (
                self.compile_timeout
                if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
                else self.link_timeout
            ),
        )
        lane = self._lane_pool.acquire()
        try:
            resource_audit: _ResourceDependencyAudit | None = None
            if node.role is ProducerRole.RESOURCE:
                if include_authority is None or include_trace_epoch is None:
                    raise ClassicProjectError(
                        f"resource node {node.id!r} lacks recursive-read authority"
                    )
                resource_audit = self._resource_dependency_audit(
                    node,
                    command=command,
                    lane=lane,
                    authority=include_authority,
                    epoch=include_trace_epoch,
                )
            result, spec = _run(
                supervisor,
                command,
                cwd=self._producer_cwd(lane, self.build_root),
                environment=lane.environment,
                timeout=timeout,
                log=self.session_root / "logs" / log_namespace / f"{node.id}.log",
                cancellation=cancellation,
                windows_lineage_planner=lane.windows_lineage_planner,
            )
            if node.role is ProducerRole.COMPILER and (
                compiler_namespace_id is None or include_trace_epoch is None
            ):
                raise ClassicProjectError(
                    f"compiler node {node.id!r} lacks a sealed readable namespace"
                )
        finally:
            self._lane_pool.release(lane)
        physical_outputs: dict[Path, Path] = {}
        for path in declared_outputs:
            if node.role is ProducerRole.COMPILER and path.suffix.casefold() == ".pdb":
                actual = self._compiler_companion_output(path)
            else:
                self._require_regular(path, label=f"producer {node.id!r} output")
                actual = path.resolve(strict=True)
            physical_outputs[path] = actual
        if len(set(physical_outputs.values())) != len(physical_outputs):
            raise ClassicProjectError(f"producer {node.id!r} aliases two declared outputs")
        with self._output_lock:
            overlap = set(physical_outputs.values()).intersection(self._physical_outputs.values())
            if overlap:
                raise ClassicProjectError(
                    f"producer {node.id!r} reuses another node's physical output"
                )
            self._physical_outputs.update(physical_outputs)
        producer_receipt = _step_receipt(receipt_step_id or node.id, result, spec)
        auxiliary: list[StepExecutionReceipt] = []
        if node.role is ProducerRole.COMPILER:
            assert compiler_namespace_id is not None
            assert include_trace_epoch is not None
            namespace = self._compiler_namespaces.get(compiler_namespace_id)
            if namespace is None:
                raise ClassicProjectError(f"compiler node {node.id!r} names an unknown namespace")
            with self._evidence_lock:
                self._producer_reads.append(
                    ClassicProducerReadReceipt(
                        node.id,
                        producer_receipt.step_id,
                        ProducerRole.COMPILER,
                        include_trace_epoch,
                        (),
                        "complete-readable-namespace-v1",
                        namespace.evidence.namespace_id,
                        namespace.evidence.namespace_digest,
                        len(namespace.evidence.members),
                    )
                )
        if resource_audit is not None:
            auxiliary.append(resource_audit.step)
        return producer_receipt, *auxiliary

    def _run_graph_nodes(
        self,
        supervisor: ProcessSupervisor,
        nodes: Sequence[ProducerNode],
        *,
        completed: set[str],
        output_steps: dict[Path, str],
        cancellation: CancellationToken,
        step_id_prefix: str = "",
        progress_phase: str | None = None,
        log_namespace: str = "producers",
        include_authority: SealedIncludeAuthority | None = None,
        include_trace_epoch: str | None = None,
        compiler_namespace_id: str | None = None,
    ) -> list[StepExecutionReceipt]:
        pending = {node.id: node for node in nodes}
        receipts: list[StepExecutionReceipt] = []
        while pending:
            ready = tuple(
                node
                for node in sorted(pending.values(), key=lambda item: item.id.casefold())
                if set(node.depends_on).issubset(completed)
            )
            if not ready:
                waiting = {
                    node.id: sorted(set(node.depends_on) - completed) for node in pending.values()
                }
                raise ClassicProjectError(f"producer graph phase cannot make progress: {waiting}")
            with ThreadPoolExecutor(max_workers=min(self.jobs, len(ready))) as pool:
                futures = {
                    pool.submit(
                        self._run_node,
                        supervisor,
                        node,
                        cancellation,
                        receipt_step_id=f"{step_id_prefix}{node.id}",
                        log_namespace=log_namespace,
                        include_authority=include_authority,
                        include_trace_epoch=include_trace_epoch,
                        compiler_namespace_id=compiler_namespace_id,
                    ): node
                    for node in ready
                }
                try:
                    for future in as_completed(futures):
                        node = futures[future]
                        try:
                            node_receipts = future.result()
                        except Exception as exc:
                            raise ClassicProjectError(
                                f"producer node {node.id!r} failed: {exc}"
                            ) from exc
                        producer_receipt = node_receipts[0]
                        receipts.extend(node_receipts)
                        for path in self._node_outputs(node):
                            output_steps[path.resolve(strict=False)] = producer_receipt.step_id
                        self._progress.emit(
                            progress_phase
                            or {
                                ProducerRole.COMPILER: "compile",
                                ProducerRole.RESOURCE: "resource",
                                ProducerRole.LIBRARIAN: "librarian",
                                ProducerRole.LINKER: "link",
                            }[node.role],
                            producer_receipt.step_id,
                        )
                        for include_receipt in node_receipts[1:]:
                            self._progress.emit(
                                "resource-dependencies",
                                include_receipt.step_id,
                            )
                except BaseException:
                    cancellation.cancel("classic producer graph sibling failed")
                    supervisor.cancel_all()
                    for future in futures:
                        future.cancel()
                    raise
            for node in ready:
                completed.add(node.id)
                del pending[node.id]
        return receipts

    def _run_linker_waves(
        self,
        supervisor: ProcessSupervisor,
        linkers: Sequence[ProducerNode],
        *,
        completed: set[str],
        output_steps: dict[Path, str],
        cancellation: CancellationToken,
    ) -> list[StepExecutionReceipt]:
        """Audit and run terminal linkers in dependency-ready waves."""

        pending = {node.id: node for node in linkers}
        if len(pending) != len(linkers) or any(
            node.role is not ProducerRole.LINKER for node in linkers
        ):
            raise ClassicProjectError("linker phase contains invalid producer nodes")
        target_by_linker = {target.link_node_id: target for target in self.targets}
        if len(target_by_linker) != len(self.targets) or set(target_by_linker) != set(pending):
            raise ClassicProjectError("linker phase differs from classic target authority")

        receipts: list[StepExecutionReceipt] = []
        while pending:
            ready = tuple(
                node
                for node in sorted(pending.values(), key=lambda item: item.id.casefold())
                if set(node.depends_on).issubset(completed)
            )
            if not ready:
                waiting = {
                    node.id: sorted(set(node.depends_on) - completed)
                    for node in pending.values()
                }
                raise ClassicProjectError(
                    f"linker graph phase cannot make progress: {waiting}"
                )
            wave_seal = _tree_file_seal(self.build_root)
            receipts.extend(
                self._audit_link_controls(
                    tuple(target_by_linker[node.id] for node in ready)
                )
            )
            receipts.extend(
                self._run_graph_nodes(
                    supervisor,
                    ready,
                    completed=completed,
                    output_steps=output_steps,
                    cancellation=cancellation,
                )
            )
            _require_declared_tree_writes(
                wave_seal,
                root=self.build_root,
                allowed_outputs=(path for node in ready for path in self._node_outputs(node)),
                phase="linker wave",
            )
            for node in ready:
                del pending[node.id]
        return receipts

    def _record_for_unit(self, unit: ClassicPreparedUnit) -> _CompileRecord:
        source = (self.effective_root / unit.plan.source).resolve(strict=True)
        matches = [
            item
            for item in self.compile_records
            if item.source == source and item.build_target == unit.plan.build_target
        ]
        if len(matches) != 1:
            raise ClassicProjectError(
                f"TU {unit.plan.id!r} has {len(matches)} committed compile lanes"
            )
        return matches[0]

    def _record_for_donor(self, unit: ClassicPreparedUnit, donor_index: int) -> _CompileRecord:
        donor = unit.donors[donor_index]
        source = (self.effective_root / donor.request.logical_source).resolve(strict=True)
        required_define = donor.request.compiler_additions.required_define
        matches: list[_CompileRecord] = []
        for item in self.compile_records:
            if item.source != source:
                continue
            parsed = classic.validate_compile_arguments(list(item.arguments))
            definitions = {definition[1] for definition in parsed["definitions"]}
            if required_define in definitions:
                matches.append(item)
        if len(matches) != 1:
            raise ClassicProjectError(
                f"donor {donor.intervention.id!r} has {len(matches)} committed compile "
                f"lanes for required define {required_define!r}"
            )
        return matches[0]

    def _donor_compiler_command(
        self,
        record: _CompileRecord,
        request: DonorCompileRequest,
        arena: Path,
    ) -> tuple[str, ...]:
        """Rebuild the proven legacy donor argv without changing visible paths."""

        arguments = list(record.arguments)
        try:
            parsed = classic.validate_compile_arguments(arguments)
        except Exception as exc:
            raise ClassicProjectError("donor compile lane arguments are invalid") from exc
        source_index = len(arguments) - 1
        object_index = cast(tuple[int, str, bool], parsed["Fo"])[0]
        pdb_index = cast(tuple[int, str, bool], parsed["Fd"])[0]
        if len({source_index, object_index, pdb_index}) != 3:
            raise ClassicProjectError("donor compile lane path seats are ambiguous")
        include_entries = tuple(
            cast(tuple[int, str, bool], item) for item in parsed["include_paths"]
        )
        if not include_entries:
            raise ClassicProjectError("donor compile lane requires project include options")
        include_by_index = {
            index: (value, separate) for index, value, separate in include_entries
        }
        if len(include_by_index) != len(include_entries):
            raise ClassicProjectError("donor compile lane include seats are ambiguous")
        first_include = min(include_by_index)

        is_overlay = request.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
        projection = request.compiler_additions.include_projection
        mirror_active = projection is not DonorIncludeProjection.NONE
        source_parent = self._logical_for_host_path(record.source.parent)
        private_includes: list[str]
        if is_overlay:
            parent = PurePosixPath(request.logical_source).parent.as_posix()
            expected_directories = ["inc"]
            private_includes = [f"/I{self._logical_for_host_path(arena / 'inc')}"]
            if mirror_active:
                mirror_parent = arena / "inc" / "source"
                if parent != ".":
                    mirror_parent = mirror_parent.joinpath(*PurePosixPath(parent).parts)
                expected_directories.append(
                    "inc/source" if parent == "." else f"inc/source/{parent}"
                )
                private_includes.append(f"/I{self._logical_for_host_path(mirror_parent)}")
            private_includes.append(f"/I{source_parent}")
            if tuple(expected_directories) != request.compiler_additions.include_directories:
                raise ClassicProjectError("donor overlay include layout differs")
        else:
            if request.compiler_additions.include_directories:
                raise ClassicProjectError("ordinary donor declares private include directories")
            if projection is not DonorIncludeProjection.NONE:
                raise ClassicProjectError("ordinary donor requests a source mirror")
            private_includes = [f"/I{source_parent}"]

        force_includes = request.compiler_additions.force_includes
        if any(item != "run.h" for item in force_includes) or len(force_includes) > 1:
            raise ClassicProjectError("donor force-include layout differs")
        if request.staged_source != "s.cpp" or "s.cpp" not in request.files:
            raise ClassicProjectError("donor source staging layout differs")
        if bool(force_includes) != ("run.h" in request.files):
            raise ClassicProjectError("donor force-include payload differs")

        command: list[str] = []
        for index, token in enumerate(arguments):
            if index == first_include:
                command.extend(private_includes)
            include_entry = include_by_index.get(index)
            if mirror_active and include_entry is not None:
                include_value, separate = include_entry
                visible = self._compiler_visible_path(include_value)
                include_path = self._logical_drive_root.joinpath(
                    *_logical_relative_parts(
                        visible,
                        drive_letter=self._logical_drive_letter,
                    )
                )
                if include_path.is_symlink() or not include_path.is_dir():
                    raise ClassicProjectError(
                        f"donor compile include root is absent or redirected: {visible!r}"
                    )
                include_path = include_path.resolve(strict=True)
                try:
                    relative = include_path.relative_to(self.effective_root.resolve(strict=True))
                except ValueError:
                    pass
                else:
                    mirrored = arena / "inc" / "source" / relative
                    if separate:
                        command.extend((token, self._logical_for_host_path(mirrored)))
                    else:
                        command.append(f"{token[:2]}{self._logical_for_host_path(mirrored)}")
            if index == object_index:
                command.extend(f"/FI{relative}" for relative in force_includes)
                command.append("/Foo.obj")
            elif index == pdb_index:
                command.append("/Fdo.pdb")
            elif index == source_index:
                command.append("s.cpp")
            else:
                command.append(token)
        return tuple(command)

    def _replay_projected_donor_dependencies(
        self,
        supervisor: ProcessSupervisor,
        *,
        donor_id: str,
        command: tuple[str, ...],
        arena: Path,
        arena_seal: Mapping[Path, tuple[int, Digest]],
        lane: _ExecutionLane,
        timeout: float,
        step_id: str,
        cancellation: CancellationToken,
    ) -> _ClassicWarmDonorDependencyReplay:
        """Run one discarded `/Fr` command without changing canonical outputs."""

        diagnostic_object = arena / ".reprobit-donor-dependencies.obj"
        diagnostic_pdb = arena / ".reprobit-donor-dependencies.pdb"
        diagnostic_sbr = arena / ".reprobit-donor-dependencies.sbr"
        outputs = (diagnostic_object, diagnostic_pdb, diagnostic_sbr)
        try:
            try:
                parsed = classic.validate_compile_arguments(list(command))
            except Exception as exc:
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"canonical donor argv cannot be replayed: {exc}",
                )
            if any(
                argument.casefold().startswith(("/fr", "-fr"))
                for argument in command[1:-1]
            ):
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    "canonical donor argv already contains /Fr",
                )
            object_index = cast(tuple[int, str, bool], parsed["Fo"])[0]
            pdb_index = cast(tuple[int, str, bool], parsed["Fd"])[0]
            arguments = list(command)
            arguments[object_index] = (
                f"/Fo{self._logical_for_host_path(diagnostic_object)}"
            )
            arguments[pdb_index] = f"/Fd{self._logical_for_host_path(diagnostic_pdb)}"
            arguments.insert(
                len(arguments) - 1,
                f"/Fr{self._logical_for_host_path(diagnostic_sbr)}",
            )
            try:
                result, _spec = _run(
                    supervisor,
                    tuple(arguments),
                    cwd=self._producer_cwd(lane, arena),
                    environment=lane.environment,
                    timeout=timeout,
                    log=(
                        self.session_root
                        / "logs"
                        / "donor-dependencies"
                        / f"{step_id}.log"
                    ),
                    cancellation=cancellation,
                    windows_lineage_planner=lane.windows_lineage_planner,
                )
            except Exception as exc:
                cancellation.raise_if_cancelled()
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency replay failed: {exc}",
                )
            if not result.succeeded:
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    "discarded donor dependency replay returned "
                    f"{result.returncode}: {result.output_tail}",
                )
            try:
                actual_sbr = self._compiler_companion_output(diagnostic_sbr)
                trace = parse_msvc_sbr(actual_sbr.read_bytes())
            except (ClassicProjectError, OSError, ValueError) as exc:
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency trace is unusable: {exc}",
                )
            base_authority = self._donor_include_authority
            if base_authority is None:
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    "discarded donor dependency replay lacks an active include authority",
                )
            try:
                authority = self._donor_authority(
                    base_authority,
                    arena=arena,
                    arena_seal=arena_seal,
                )
                working_directory = self._logical_for_host_path(arena)
                source = _logical_join(working_directory, cast(str, parsed["source_token"]))
                reads = resolve_msvc_include_trace(
                    trace,
                    expected_working_directory=working_directory,
                    expected_source=source,
                    include_directories=tuple(
                        cast(tuple[int, str, bool], item)[1]
                        for item in cast(Sequence[object], parsed["include_paths"])
                    ),
                    environment_directories=self._include_environment_directories(
                        lane.environment
                    ),
                    force_includes=tuple(
                        cast(tuple[int, str, bool], item)[1]
                        for item in cast(Sequence[object], parsed["force_includes"])
                    ),
                    authority=authority,
                )
            except (ClassicIncludeTraceError, ClassicProjectError, ValueError) as exc:
                return _ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency trace cannot be resolved: {exc}",
                )
            return _ClassicWarmDonorDependencyReplay(donor_id, trace, reads, None)
        finally:
            _erase_donor_dependency_outputs(outputs)

    def _invoke_donor_compiler(
        self,
        supervisor: ProcessSupervisor,
        unit: ClassicPreparedUnit,
        donor_index: int,
        cancellation: CancellationToken,
        *,
        step_id: str,
        capture_dependencies: bool = False,
    ) -> _DonorCompilerInvocation:
        """Run the one normal private donor lane without issuing evidence."""

        donor = unit.donors[donor_index]
        record = self._record_for_donor(unit, donor_index)
        marker_stem = f"composed-{unit.plan.build_target}-{unit.plan.source.replace('/', '_')}"
        donor_root = self.build_root.parent / "donors"
        if donor_root.is_symlink() or not donor_root.is_dir():
            raise ClassicProjectError("classic donor arena root is absent or redirected")
        legacy_recipe_id = _safe_relative(donor.request.legacy_recipe_id)
        if len(PurePosixPath(legacy_recipe_id).parts) != 1:
            raise ClassicProjectError("classic donor legacy recipe ID is not one path component")
        arena = donor_root / f"{marker_stem}-{legacy_recipe_id}"
        arena.mkdir(exist_ok=False)
        if donor.request.compiler_additions.include_projection is not DonorIncludeProjection.NONE:
            shutil.copytree(self.effective_root, arena / "inc" / "source")
        elif donor.request.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
            (arena / "inc").mkdir()
        for relative, payload in donor.request.files.items():
            path = arena.joinpath(*PurePosixPath(_safe_relative(relative)).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        parsed = classic.validate_compile_arguments(list(record.arguments))
        definitions = {item[1] for item in parsed["definitions"]}
        required_define = donor.request.compiler_additions.required_define
        if required_define not in definitions:
            raise ClassicProjectError(
                f"donor {donor.intervention.id!r} compile lane lacks {required_define!r}"
            )
        donor_object = arena / "o.obj"
        donor_pdb = arena / "o.pdb"
        command = self._donor_compiler_command(record, donor.request, arena)
        before = _tree_file_seal(arena)
        include_root = arena / "inc"
        namespace_files: list[Path] = []
        for relative in donor.request.files:
            path = arena.joinpath(*PurePosixPath(_safe_relative(relative)).parts)
            if include_root.is_dir() and _path_is_within(path, include_root):
                continue
            namespace_files.append(path)
        held_files = MappingProxyType(
            {
                path.relative_to(arena).as_posix(): digest_relative_file(
                    arena,
                    path.relative_to(arena).as_posix(),
                )
                for path in namespace_files
            }
        )
        timeout = min(
            self.compile_timeout,
            float(
                next(node.timeout_seconds for node in self.graph.nodes if node.id == record.node_id)
            ),
        )
        lane = self._lane_pool.acquire()
        donor_namespace_snapshot: SealedNamespaceSnapshot
        dependency_replay: _ClassicWarmDonorDependencyReplay | None = None
        try:
            with ExitStack() as stack:
                held = stack.enter_context(hold_relative_file_set(arena, held_files))
                include_namespace = (
                    stack.enter_context(
                        SealedNamespaceLease(
                            trees=(NamespaceTree("donor-arena", include_root, include_root),),
                        )
                    )
                    if include_root.is_dir()
                    else None
                )
                result, spec = _run(
                    supervisor,
                    command,
                    cwd=self._producer_cwd(lane, arena),
                    environment=lane.environment,
                    timeout=timeout,
                    log=self.session_root / "logs" / "donors" / f"{step_id}.log",
                    cancellation=cancellation,
                    windows_lineage_planner=lane.windows_lineage_planner,
                )
                if capture_dependencies and (
                    donor.request.compiler_additions.include_projection
                    is not DonorIncludeProjection.NONE
                ):
                    self._require_regular(
                        donor_object,
                        label=f"donor {donor.intervention.id!r} canonical object",
                    )
                    self._require_regular(
                        donor_pdb,
                        label=f"donor {donor.intervention.id!r} canonical PDB",
                    )
                    canonical_object = donor_object.read_bytes()
                    canonical_pdb = donor_pdb.read_bytes()
                    dependency_replay = self._replay_projected_donor_dependencies(
                        supervisor,
                        donor_id=donor.intervention.id,
                        command=command,
                        arena=arena,
                        arena_seal=before,
                        lane=lane,
                        timeout=timeout,
                        step_id=step_id,
                        cancellation=cancellation,
                    )
                    if (
                        donor_object.read_bytes() != canonical_object
                        or donor_pdb.read_bytes() != canonical_pdb
                    ):
                        raise ClassicProjectError(
                            "discarded donor dependency replay changed canonical OBJ/PDB bytes"
                        )
                standalone = tuple(
                    SealedNamespaceFile(
                        "donor-arena",
                        relative,
                        snapshot.path,
                        snapshot.digest,
                        snapshot.size,
                    )
                    for relative, snapshot in held.items()
                )
                include_files = (
                    include_namespace.snapshot.files if include_namespace is not None else ()
                )
                donor_namespace_snapshot = SealedNamespaceSnapshot(
                    tuple(
                        sorted(
                            (*standalone, *include_files),
                            key=lambda item: (
                                item.label.casefold(),
                                item.relative_path.casefold(),
                            ),
                        )
                    )
                )
        finally:
            self._lane_pool.release(lane)
        self._require_regular(donor_object, label=f"donor {donor.intervention.id!r} object")
        self._require_regular(donor_pdb, label=f"donor {donor.intervention.id!r} PDB")
        _require_declared_tree_writes(
            before,
            root=arena,
            allowed_outputs=(donor_object, donor_pdb),
            phase=f"donor {donor.intervention.id!r}",
        )
        object_payload = donor_object.read_bytes()
        pdb_payload = donor_pdb.read_bytes()
        return _DonorCompilerInvocation(
            record,
            donor_object,
            donor_pdb,
            object_payload,
            pdb_payload,
            result,
            spec,
            donor_namespace_snapshot,
            step_id,
            dependency_replay,
        )

    def _compile_donor(
        self,
        supervisor: ProcessSupervisor,
        unit: ClassicPreparedUnit,
        donor_index: int,
        cancellation: CancellationToken,
        *,
        dependency_replays: list[_ClassicWarmDonorDependencyReplay] | None = None,
    ) -> tuple[
        str,
        bytes,
        tuple[StepExecutionReceipt, ...],
        Mapping[str, object],
        InterventionWitness,
    ]:
        donor = unit.donors[donor_index]
        invocation = self._invoke_donor_compiler(
            supervisor,
            unit,
            donor_index,
            cancellation,
            step_id=f"donor.{unit.plan.id}.{donor_index:04d}",
            capture_dependencies=dependency_replays is not None,
        )
        projected = (
            donor.request.compiler_additions.include_projection
            is not DonorIncludeProjection.NONE
        )
        if dependency_replays is not None and projected:
            if invocation.dependency_replay is None:
                raise ClassicProjectError(
                    f"projected donor {donor.intervention.id!r} omitted its warm replay"
                )
            dependency_replays.append(invocation.dependency_replay)
        elif invocation.dependency_replay is not None:
            raise ClassicProjectError(
                f"donor {donor.intervention.id!r} produced an unexpected warm replay"
            )
        record = invocation.record
        donor_object = invocation.object_path
        payload = invocation.object_payload
        result = invocation.result
        spec = invocation.spec
        donor_namespace = invocation.namespace
        step_id = invocation.step_id
        donor_evidence = Digest.from_bytes(
            canonical_json(
                {
                    "intervention_id": donor.request.receipt.intervention_id,
                    "family": donor.request.receipt.family,
                    "constraints_digest": donor.request.receipt.constraints_digest,
                    "input_digests": dict(donor.request.receipt.input_digests),
                    "output_digests": dict(donor.request.receipt.output_digests),
                    "compiler_additions_digest": (donor.request.receipt.compiler_additions_digest),
                    "rendering_digest": donor.request.receipt.rendering_digest,
                    "producer_node": record.node_id,
                    "fresh_object_sha256": sha256(payload).hexdigest(),
                }
            )
        )
        step_receipt = _step_receipt(step_id, result, spec)
        namespace_step = _internal_step(
            f"compiler-namespace.{step_id}",
            {
                "schema": 1,
                "coverage": "complete-readable-namespace-v1",
                "producer_node": record.node_id,
                "files": [
                    {
                        "label": item.label,
                        "path": item.relative_path,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                    }
                    for item in donor_namespace.files
                ],
            },
            0.0,
        )
        step_receipts = (step_receipt, namespace_step)
        shared_namespace_id = self._active_compiler_namespace_id
        if shared_namespace_id is None:
            raise ClassicProjectError("donor compiler namespace is not active")
        shared_namespace = self._compiler_namespaces.get(shared_namespace_id)
        if shared_namespace is None:
            raise ClassicProjectError("donor compiler namespace receipt is absent")
        donor_reads = tuple(
            ClassicProducerRead(
                self._logical_for_host_path(item.path),
                item.path,
                item.digest,
                item.size,
                IncludeOrigin.DONOR_ARENA,
                None,
                None,
                "complete-readable-namespace",
            )
            for item in donor_namespace.files
        )
        with self._evidence_lock:
            self._producer_reads.append(
                ClassicProducerReadReceipt(
                    record.node_id,
                    step_id,
                    ProducerRole.COMPILER,
                    f"donor:{donor.intervention.id}",
                    donor_reads,
                    "complete-readable-namespace-v1",
                    shared_namespace.evidence.namespace_id,
                    shared_namespace.evidence.namespace_digest,
                    len(shared_namespace.evidence.members),
                )
            )
        donor_output_receipt = ClassicDonorOutputReceipt(
            donor.intervention.id,
            record.node_id,
            step_id,
            self._logical_for_host_path(donor_object),
            Digest.from_bytes(payload),
            len(payload),
        )
        with self._evidence_lock:
            self._donor_outputs.append(donor_output_receipt)
        compile_statement: Mapping[str, object] = MappingProxyType(
            {
                "schema": 1,
                "producer_node": record.node_id,
                "step": {
                    "step_id": step_receipt.step_id,
                    "returncode": step_receipt.returncode,
                    "attempts": step_receipt.attempts,
                    "output_digest": step_receipt.output_digest.model_dump(mode="json"),
                    "command_digest": step_receipt.command_digest.model_dump(mode="json"),
                },
                "request_receipt": {
                    "intervention_id": donor.request.receipt.intervention_id,
                    "family": donor.request.receipt.family.value,
                    "constraints_digest": donor.request.receipt.constraints_digest.model_dump(
                        mode="json"
                    ),
                    "input_digests": dict(donor.request.receipt.input_digests),
                    "output_digests": dict(donor.request.receipt.output_digests),
                    "compiler_additions_digest": (
                        donor.request.receipt.compiler_additions_digest.model_dump(mode="json")
                    ),
                    "rendering_digest": donor.request.receipt.rendering_digest.model_dump(
                        mode="json"
                    ),
                },
                "object_digest": Digest.from_bytes(payload).model_dump(mode="json"),
                "object_size": len(payload),
                "input_namespace": {
                    "step_id": namespace_step.step_id,
                    "evidence_digest": namespace_step.output_digest.model_dump(mode="json"),
                    "file_count": len(donor_namespace.files),
                },
            }
        )
        self._progress.emit("donor-compile", step_id)
        self._progress.emit("input-namespace", namespace_step.step_id)
        return (
            donor.intervention.id,
            payload,
            step_receipts,
            compile_statement,
            InterventionWitness(
                donor.intervention.id,
                donor.intervention.scope.target,
                donor_evidence,
            ),
        )

    def _compose_unit(
        self,
        supervisor: ProcessSupervisor,
        unit: ClassicPreparedUnit,
        cancellation: CancellationToken,
        *,
        dependency_replays: list[_ClassicWarmDonorDependencyReplay] | None = None,
    ) -> tuple[_CompileRecord, list[StepExecutionReceipt], list[InterventionWitness]]:
        record = self._record_for_unit(unit)
        self._require_regular(record.object_path, label=f"seed object for {unit.plan.id!r}")
        if record.pdb_path.is_symlink():
            raise ClassicProjectError(f"seed PDB is redirected: {record.pdb_path}")
        seed = record.object_path.read_bytes()
        steps: list[StepExecutionReceipt] = []
        donor_witnesses: list[InterventionWitness] = []
        donor_objects: dict[str, bytes] = {}
        donor_compile_statements: dict[str, Mapping[str, object]] = {}
        for donor_index in range(len(unit.donors)):
            donor_id, payload, receipts, compile_statement, witness = self._compile_donor(
                supervisor,
                unit,
                donor_index,
                cancellation,
                dependency_replays=dependency_replays,
            )
            donor_objects[donor_id] = payload
            donor_compile_statements[donor_id] = compile_statement
            steps.extend(receipts)
            donor_witnesses.append(witness)
        started = time.monotonic()
        composition = compose_classic_unit(
            unit,
            seed_object=seed,
            donor_objects=donor_objects,
            donor_compile_statements=donor_compile_statements,
            seed_source=record.source.read_bytes(),
            legacy_oracles=self._legacy_oracles,
        )
        donor_witnesses = [
            replace(
                witness,
                semantic_proof=composition.donor_semantic_proofs[witness.intervention_id],
            )
            for witness in donor_witnesses
        ]
        donor_by_id = {prepared.intervention.id: prepared for prepared in unit.donors}
        function_witnesses = {
            witness.intervention_id: witness
            for witness in composition.witnesses
            if witness.intervention_id in {item.id for item in unit.functions}
        }
        semantic_lanes: list[DonorSemanticLane] = []
        for function in unit.functions:
            function_witness = function_witnesses.get(function.id)
            if (
                function_witness is None
                or function_witness.semantic_proof is None
                or (
                    function_witness.semantic_input_statement is None
                    or function_witness.semantic_output_statement is None
                )
            ):
                raise ClassicProjectError(
                    f"function {function.id!r} omitted its typed semantic statements"
                )
        functions_by_id = {function.id: function for function in unit.functions}
        if not set(composition.donor_semantic_uses).issubset(donor_by_id):
            raise ClassicProjectError("composition donor-use universe names an uncompiled donor")
        for donor_id, uses in composition.donor_semantic_uses.items():
            prepared = donor_by_id[donor_id]
            request = prepared.request
            overlay_inputs = tuple(
                sorted(
                    (
                        EffectiveOverlayReceipt(
                            path,
                            Digest.from_bytes(payload),
                            len(payload),
                        )
                        for path, payload in self.overlay_effective_outputs.items()
                        if request.receipt.input_digests.get(f"effective:{path}")
                        == Digest.from_bytes(payload).value
                        or request.logical_outputs.get(path) == payload
                    ),
                    key=lambda item: (item.path.casefold(), item.digest.value),
                )
            )
            if not overlay_inputs:
                continue
            for use in uses:
                consumer = functions_by_id.get(use.intervention_id)
                if consumer is None:
                    raise ClassicProjectError(
                        f"donor {donor_id!r} names unknown semantic consumer "
                        f"{use.intervention_id!r}"
                    )
                semantic_lanes.append(
                    DonorSemanticLane(
                        consumer.scope.target,
                        donor_id,
                        consumer.id,
                        overlay_inputs,
                        _semantic_statement_digest(use.input_statement, "seed", "digest"),
                        Digest.from_bytes(donor_objects[donor_id]),
                        _semantic_statement_digest(
                            use.output_statement,
                            "candidate",
                            "digest",
                        ),
                        use.input_statement,
                        use.output_statement,
                        use.proof,
                        input_name=use.input_name,
                    )
                )
        with self._semantic_lock:
            self._donor_semantic_lanes.extend(semantic_lanes)
        temporary = record.object_path.with_name(
            f".{record.object_path.name}.reprobit-{unit.plan.id}"
        )
        temporary.write_bytes(composition.output)
        os.replace(temporary, record.object_path)
        steps.append(
            _internal_step(
                f"compose.{unit.plan.id}",
                {
                    "producer_node": record.node_id,
                    "unit": unit.plan.model_dump(mode="json"),
                    "output": sha256(composition.output).hexdigest(),
                    "witnesses": [item.evidence_digest.value for item in composition.witnesses],
                    "group_order": (
                        composition.group_order_evidence.value
                        if composition.group_order_evidence is not None
                        else None
                    ),
                },
                time.monotonic() - started,
            )
        )
        self._progress.emit("compose", f"compose.{unit.plan.id}")
        return record, steps, [*donor_witnesses, *composition.witnesses]

    def execute(
        self,
        plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: Iterable[Path] = (),
    ) -> BuildExecutionReceipt:
        try:
            receipt = self._execute(plan, cold=cold, required_outputs=required_outputs)
        except BaseException as original:
            try:
                self._close_runtime()
            except BaseException as cleanup_error:
                original.add_note(f"classic runtime cleanup also failed: {cleanup_error}")
            raise
        else:
            self._close_runtime()
        self.reseal_published_targets()
        self._progress.emit("validation", "execution-record")
        if self._progress.completed != self._progress.total:
            raise ClassicProjectError(
                "classic progress did not cover every successful execution step"
            )
        return receipt

    def reseal_published_targets(self) -> None:
        """Require every public target to retain its publication identity/content."""

        record = self.record
        if record is None:
            raise ClassicProjectError(
                "classic targets cannot be resealed before successful execution"
            )
        artifacts = {target.id: target.artifact for target in self.bundle.spec.targets}
        for image in record.images:
            artifact = artifacts.get(image.target_id)
            if artifact is None:
                raise ClassicProjectError(
                    f"published target {image.target_id!r} is no longer declared"
                )
            try:
                reseal_relative_file(
                    self.project_root,
                    artifact,
                    expected=image.final_snapshot,
                )
            except SecurePathError as exc:
                raise ClassicProjectError(
                    f"published target {image.target_id!r} changed before report commit"
                ) from exc

    def _execute(
        self,
        plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: Iterable[Path] = (),
    ) -> BuildExecutionReceipt:
        if plan.steps or plan.link_admissions:
            raise ClassicProjectError(
                "classic producer-graph executor accepts only its sealed adapter plan"
            )
        if not cold:
            raise ClassicProjectError("classic authenticity execution must be cold")
        required = {path.resolve(strict=False) for path in required_outputs}
        expected = {
            (self.project_root / target.artifact).resolve(strict=False)
            for target in self.bundle.spec.targets
        }
        if required != expected:
            raise ClassicProjectError("engine required-output set differs from classic targets")
        graph_outputs = {
            path.resolve(strict=False)
            for node in self.graph.nodes
            for path in self._declared_node_outputs(node)
        }
        preexisting = [path for path in sorted(graph_outputs) if os.path.lexists(path)]
        if preexisting:
            raise ClassicProjectError(
                "cold classic execution found preexisting outputs: "
                + ", ".join(str(path) for path in preexisting[:12])
            )

        input_paths = [
            self.effective_root / relative
            for relative, _, _ in _effective_source_seal(self.effective_root)
        ]
        input_paths.extend(
            self.toolchain_root.joinpath(*PurePosixPath(item.path).parts)
            for item in (
                *self.bundle.toolchain_lock.tools,
                *self.bundle.toolchain_lock.runtime_files,
            )
        )
        input_paths.extend(_toolchain_tree_files(self.bundle, self.toolchain_root))
        input_paths.extend(self.wrapper_runtime_files)
        input_paths.extend(self.authority_inputs)
        inputs = tuple(
            _receipt(path, fresh=False, producer_step=None)
            for path in sorted(set(input_paths), key=str)
        )
        source_tree_before = _tree_file_seal(self.effective_root)
        toolchain_tree_before = _tree_file_seal(self.toolchain_root)

        steps: list[StepExecutionReceipt] = []
        witnesses = list(self.overlay_witnesses)
        completed: set[str] = set()
        output_steps: dict[Path, str] = {}
        cancellation = CancellationToken()
        counterfactual_compilers = tuple(
            node
            for node in self.graph.nodes
            if node.role is ProducerRole.COMPILER
            and node.id in self.compiler_epoch_plan.audit_node_ids
        )
        ordinary = tuple(
            node
            for node in self.graph.nodes
            if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
            and node.id not in self.generated_node_inputs
        )
        generated = tuple(
            node
            for node in self.graph.nodes
            if node.role is ProducerRole.COMPILER and node.id in self.generated_node_inputs
        )
        librarians = tuple(node for node in self.graph.nodes if node.role is ProducerRole.LIBRARIAN)
        linkers = tuple(node for node in self.graph.nodes if node.role is ProducerRole.LINKER)
        if len(ordinary) + len(generated) + len(librarians) + len(linkers) != len(self.graph.nodes):
            raise ClassicProjectError("producer graph contains an unsupported role")
        with ExitStack() as namespace_stack, ProcessSupervisor() as supervisor:
            authority_namespace = namespace_stack.enter_context(self._authority_namespace_lease())
            effective_ordinary_source_seal = source_tree_before
            if self.overlay_witnesses:
                steps.append(self._capture_clean_source_inputs(source_tree_before))
                effective_preimage: Literal["clean", "counterfactual"] = "clean"
                if counterfactual_compilers:
                    counterfactual_step, counterfactual_source_seal = (
                        self._materialize_project_overlay_counterfactual_epoch(
                            source_tree_before
                        )
                    )
                    steps.append(counterfactual_step)
                    counterfactual_source_namespace = namespace_stack.enter_context(
                        self._source_namespace_lease()
                    )
                    counterfactual_namespace = self._capture_compiler_namespace(
                        "declaration-counterfactual-epoch",
                        source=counterfactual_source_namespace.snapshot,
                        authority=authority_namespace.snapshot,
                    )
                    self._counterfactual_namespace_id = (
                        counterfactual_namespace.evidence.namespace_id
                    )
                    steps.extend(
                        self._run_counterfactual_compiler_audit(
                            supervisor,
                            counterfactual_compilers,
                            source_seal=counterfactual_source_seal,
                            cancellation=cancellation,
                            compiler_namespace_id=(
                                counterfactual_namespace.evidence.namespace_id
                            ),
                        )
                    )
                    counterfactual_source_namespace.close()
                    effective_ordinary_source_seal = counterfactual_source_seal
                    effective_preimage = "counterfactual"
                overlay_step, effective_ordinary_source_seal = (
                    self._materialize_certified_project_overlay_epoch(
                        effective_ordinary_source_seal,
                        preimage=effective_preimage,
                    )
                )
                steps.append(overlay_step)
            ordinary_source_namespace = namespace_stack.enter_context(
                self._source_namespace_lease()
            )
            ordinary_namespace = self._capture_compiler_namespace(
                "effective-project-epoch",
                source=ordinary_source_namespace.snapshot,
                authority=authority_namespace.snapshot,
            )
            if self.overlay_witnesses and not counterfactual_compilers:
                self._counterfactual_namespace_id = ordinary_namespace.evidence.namespace_id
            ordinary_include_authority = self._include_authority()
            ordinary_seal = _tree_file_seal(self.build_root)
            steps.extend(
                self._run_graph_nodes(
                    supervisor,
                    ordinary,
                    completed=completed,
                    output_steps=output_steps,
                    cancellation=cancellation,
                    include_authority=ordinary_include_authority,
                    include_trace_epoch="effective",
                    compiler_namespace_id=ordinary_namespace.evidence.namespace_id,
                )
            )
            _require_declared_tree_writes(
                ordinary_seal,
                root=self.build_root,
                allowed_outputs=(path for node in ordinary for path in self._node_outputs(node)),
                phase="ordinary compiler/resource phase",
            )
            _require_unchanged_tree(
                effective_ordinary_source_seal,
                root=self.effective_root,
                label="certified project-overlay compiler epoch",
            )
            source_tree_after_generation = effective_ordinary_source_seal
            if self.generated_translation_units:
                ordinary_source_namespace.close()
                generated_step, source_tree_after_generation = (
                    self._materialize_generated_input_epoch(effective_ordinary_source_seal)
                )
                steps.append(generated_step)
                generated_include_authority = self._include_authority()
                generated_source_namespace = namespace_stack.enter_context(
                    self._source_namespace_lease()
                )
                generated_namespace = self._capture_compiler_namespace(
                    "generated-project-epoch",
                    source=generated_source_namespace.snapshot,
                    authority=authority_namespace.snapshot,
                )
            else:
                generated_include_authority = ordinary_include_authority
                generated_namespace = ordinary_namespace
            if bool(generated) != bool(self.generated_translation_units):
                raise ClassicProjectError(
                    "generated compiler epoch differs from overlay input authority"
                )
            generated_seal = _tree_file_seal(self.build_root)
            steps.extend(
                self._run_graph_nodes(
                    supervisor,
                    generated,
                    completed=completed,
                    output_steps=output_steps,
                    cancellation=cancellation,
                    include_authority=generated_include_authority,
                    include_trace_epoch="generated",
                    compiler_namespace_id=generated_namespace.evidence.namespace_id,
                )
            )
            _require_declared_tree_writes(
                generated_seal,
                root=self.build_root,
                allowed_outputs=(path for node in generated for path in self._node_outputs(node)),
                phase="generated compiler phase",
            )
            steps.append(self._capture_effective_compiler_products())
            if self.overlay_witnesses:
                steps.append(self._validate_project_overlay_compiler_epoch())
            self._donor_include_authority = generated_include_authority
            self._active_compiler_namespace_id = generated_namespace.evidence.namespace_id
            composition_seal = _tree_file_seal(self.build_root)
            with ThreadPoolExecutor(max_workers=min(self.jobs, max(1, len(self.units)))) as pool:
                futures = {
                    pool.submit(self._compose_unit, supervisor, unit, cancellation): unit
                    for unit in self.units
                }
                try:
                    for future in as_completed(futures):
                        unit = futures[future]
                        try:
                            record, unit_steps, unit_witnesses = future.result()
                        except Exception as exc:
                            raise ClassicProjectError(
                                f"classic TU {unit.plan.id!r} composition failed: {exc}"
                            ) from exc
                        steps.extend(unit_steps)
                        witnesses.extend(unit_witnesses)
                        output_steps[record.object_path.resolve(strict=False)] = (
                            f"compose.{unit.plan.id}"
                        )
                except BaseException:
                    cancellation.cancel("classic composition sibling failed")
                    supervisor.cancel_all()
                    for future in futures:
                        future.cancel()
                    raise
            _require_declared_tree_writes(
                composition_seal,
                root=self.build_root,
                allowed_outputs=(self._record_for_unit(unit).object_path for unit in self.units),
                phase="composition phase",
            )

            rdata_seal = _tree_file_seal(self.build_root)
            rdata_outputs: list[Path] = []
            declared_graph_outputs = {path.casefold(): path for path in map(str, graph_outputs)}
            for intervention in self.bundle.interventions:
                if not isinstance(intervention, ClassicRecipeIntervention):
                    continue
                values = {item.name: item.value for item in intervention.parameters}
                declaration = values.get("rdata_pool_repack")
                if not isinstance(declaration, dict):
                    continue
                object_value = declaration.get("object")
                if not isinstance(object_value, str):
                    raise ClassicProjectError("rdata repack object path is malformed")
                object_path = self.build_root.joinpath(
                    *PurePosixPath(_safe_relative(object_value)).parts
                ).resolve(strict=False)
                if str(object_path).casefold() not in declared_graph_outputs:
                    raise ClassicProjectError(
                        "rdata repack object is not a committed producer output"
                    )
                self._require_regular(object_path, label="rdata repack object")
                started = time.monotonic()
                applied = classic_rdata_repack(
                    self.bundle,
                    target_id=intervention.scope.target,
                    object_path=object_value,
                    candidate=object_path.read_bytes(),
                )
                if applied is None:
                    raise ClassicProjectError("rdata repack declaration was not selected")
                result, witness = applied
                object_path.write_bytes(result.output)
                witnesses.append(witness)
                step_id = f"rdata.{intervention.id}"
                steps.append(
                    _internal_step(
                        step_id,
                        {"proof": result.proof, "object": object_value},
                        time.monotonic() - started,
                    )
                )
                output_steps[object_path] = step_id
                rdata_outputs.append(object_path)
                self._progress.emit("object-transform", step_id)

            _require_declared_tree_writes(
                rdata_seal,
                root=self.build_root,
                allowed_outputs=rdata_outputs,
                phase="object-transform phase",
            )

            librarian_seal = _tree_file_seal(self.build_root)
            steps.extend(
                self._run_graph_nodes(
                    supervisor,
                    librarians,
                    completed=completed,
                    output_steps=output_steps,
                    cancellation=cancellation,
                )
            )
            _require_declared_tree_writes(
                librarian_seal,
                root=self.build_root,
                allowed_outputs=(path for node in librarians for path in self._node_outputs(node)),
                phase="librarian phase",
            )

            steps.extend(
                self._run_linker_waves(
                    supervisor,
                    linkers,
                    completed=completed,
                    output_steps=output_steps,
                    cancellation=cancellation,
                )
            )
            self._apply_overlay_semantic_proofs(witnesses)
        if completed != {node.id for node in self.graph.nodes}:
            raise ClassicProjectError("producer graph execution was incomplete")

        images: list[ClassicProducedImage] = []
        target_specs = {item.id: item for item in self.bundle.spec.targets}
        for target in self.targets:
            self._require_regular(target.output, label=f"linked target {target.target_id!r}")
            started = time.monotonic()
            terminal = apply_classic_terminal_pipeline(
                self.bundle,
                target_id=target.target_id,
                candidate=target.output.read_bytes(),
            )
            logical_artifact = target_specs[target.target_id].artifact
            try:
                final_snapshot = atomic_publish_relative(
                    self.project_root,
                    logical_artifact,
                    terminal.output,
                )
            except SecurePathError as exc:
                raise ClassicProjectError(
                    f"target {target.target_id!r} could not be published safely: {exc}"
                ) from exc
            final_path = final_snapshot.path
            steps.append(
                _internal_step(
                    f"publish.{target.target_id}",
                    {
                        "link_node": target.link_node_id,
                        "raw": _digest_path(target.output),
                        "final": sha256(terminal.output).hexdigest(),
                        "witnesses": [item.evidence_digest.value for item in terminal.witnesses],
                    },
                    time.monotonic() - started,
                )
            )
            witnesses.extend(terminal.witnesses)
            images.append(
                ClassicProducedImage(
                    target.target_id,
                    target.output,
                    final_path,
                    target.link_node_id,
                    self.role_tool_ids[ProducerRole.LINKER],
                    terminal.witnesses,
                    final_snapshot,
                )
            )
            self._progress.emit("terminal", f"publish.{target.target_id}")

        physical_graph_outputs = {
            path.resolve(strict=True)
            for node in self.graph.nodes
            for path in self._node_outputs(node)
        }
        if len(physical_graph_outputs) != sum(len(node.outputs) for node in self.graph.nodes):
            raise ClassicProjectError("producer graph aliases physical outputs")
        output_receipts = [
            _receipt(
                path,
                fresh=True,
                producer_step=output_steps.get(path.resolve(strict=False)),
            )
            for path in sorted(physical_graph_outputs, key=str)
        ]
        output_receipts.extend(
            _receipt(path, fresh=True, producer_step=None) for path in sorted(expected, key=str)
        )
        output_receipts_by_path = {
            item.path.resolve(strict=False): item for item in output_receipts
        }
        for image in images:
            receipt = output_receipts_by_path.get(image.final_path.resolve(strict=False))
            snapshot = image.final_snapshot
            if receipt is None or (
                receipt.digest != snapshot.digest
                or receipt.size != snapshot.size
                or receipt.device != snapshot.device
                or receipt.inode != snapshot.inode
            ):
                raise ClassicProjectError(
                    f"published target {image.target_id!r} receipt differs from its "
                    "atomic publication"
                )
        mutable_clean_inputs = {
            self.effective_root.joinpath(*PurePosixPath(item.path).parts).resolve(
                strict=False
            ): item
            for item in self.project_source_pairs
            if item.clean_payload is not None
        }
        for input_receipt in inputs:
            source_pair = mutable_clean_inputs.get(input_receipt.path.resolve(strict=False))
            if source_pair is not None:
                clean_payload = source_pair.clean_payload
                if clean_payload is None:
                    raise AssertionError("mutable source pair was not narrowed")
                if input_receipt.digest != Digest.from_bytes(
                    clean_payload
                ) or input_receipt.size != len(clean_payload):
                    raise ClassicProjectError(
                        f"classic clean audit input receipt differs: {input_receipt.path}"
                    )
                continue
            after_receipt = _receipt(input_receipt.path, fresh=False, producer_step=None)
            if (
                input_receipt.digest != after_receipt.digest
                or input_receipt.size != after_receipt.size
                or input_receipt.device != after_receipt.device
                or input_receipt.inode != after_receipt.inode
            ):
                raise ClassicProjectError(
                    f"classic input changed during execution: {input_receipt.path}"
                )
        _require_unchanged_tree(
            source_tree_after_generation,
            root=self.effective_root,
            label="effective source authority",
        )
        _require_unchanged_tree(
            toolchain_tree_before,
            root=self.toolchain_root,
            label="locked toolchain projection",
        )
        if self._progress.completed != self._progress.total - 1:
            raise ClassicProjectError(
                "classic progress did not cover every pre-finalization execution step"
            )
        witness_ids = [item.intervention_id for item in witnesses]
        if len(witness_ids) != len(set(witness_ids)):
            raise ClassicProjectError("classic runtime emitted duplicate intervention witnesses")
        expected_compiler_outputs = {
            reference.casefold()
            for node in self.graph.nodes
            if node.role is ProducerRole.COMPILER
            for reference in node.outputs
        }
        actual_compiler_outputs = {
            item.reference.casefold() for item in self._captured_compiler_outputs
        }
        if actual_compiler_outputs != expected_compiler_outputs:
            raise ClassicProjectError("raw compiler output capture differs from the producer graph")
        expected_donors = {donor.intervention.id for unit in self.units for donor in unit.donors}
        if (
            len(self._donor_outputs) != len(expected_donors)
            or {item.intervention_id for item in self._donor_outputs} != expected_donors
        ):
            raise ClassicProjectError(
                "private donor output capture differs from prepared donor lanes"
            )
        self.record = ClassicProducerGraphExecutionRecord(
            tuple(images),
            tuple(witnesses),
            tuple(
                sorted(
                    self._producer_reads,
                    key=lambda item: (
                        item.role.value,
                        item.node_id.casefold(),
                        item.epoch.casefold(),
                        item.step_id.casefold(),
                    ),
                )
            ),
            tuple(
                sorted(
                    self._captured_compiler_outputs,
                    key=lambda item: (
                        item.node_id.casefold(),
                        item.reference.casefold(),
                    ),
                )
            ),
            tuple(
                sorted(
                    self._donor_outputs,
                    key=lambda item: item.intervention_id.casefold(),
                )
            ),
            tuple(
                self._compiler_namespaces[key]
                for key in sorted(self._compiler_namespaces, key=str.casefold)
            ),
        )
        return BuildExecutionReceipt(
            True,
            inputs,
            tuple(sorted(output_receipts, key=lambda item: str(item.path))),
            tuple(sorted(steps, key=lambda item: item.step_id)),
        )


@dataclass(frozen=True, slots=True)
class ClassicProducerGraphPreparedRun:
    executor: ClassicProducerGraphBuildExecutor
    evidence_provider: ClassicProducerGraphRuntimeEvidenceProvider
    plan: BuildPlan
    intervention_witnesses: tuple[InterventionWitness, ...]

    @property
    def initialized_lane_count(self) -> int:
        return self.executor.initialized_lane_count

    def probe_compiler_nodes(
        self,
        node_ids: Sequence[str],
        *,
        source_epoch: Literal["clean", "effective"] = "effective",
    ) -> tuple[ClassicCompilerProbeOutput, ...]:
        return self.executor.probe_compiler_nodes(
            node_ids,
            source_epoch=source_epoch,
        )

    def probe_donor_compilers(
        self,
        donor_ids: Sequence[str],
    ) -> tuple[ClassicDonorProbeOutput, ...]:
        return self.executor.probe_donor_compilers(donor_ids)

    def close(self) -> None:
        self.executor.close()


def _graph_role_bindings(
    bundle: ProjectBundle,
    installation: ClassicMSVCToolchain,
) -> tuple[Mapping[ProducerRole, str], Mapping[ProducerRole, str]]:
    expected = {
        ProducerRole.COMPILER: ("compiler", installation.profile.compiler),
        ProducerRole.RESOURCE: (
            "resource-compiler",
            installation.profile.resource_compiler,
        ),
        ProducerRole.LIBRARIAN: ("librarian", installation.profile.librarian),
        ProducerRole.LINKER: ("linker", installation.profile.linker),
    }
    identifiers: dict[ProducerRole, str] = {}
    relatives: dict[ProducerRole, str] = {}
    for producer_role, (lock_role, profile_relative) in expected.items():
        tool_id, relative = _tool_with_role(bundle, lock_role)
        if relative.casefold() != profile_relative.casefold():
            raise ClassicProjectError(
                f"locked {lock_role!r} role differs from the selected profile producer"
            )
        identifiers[producer_role] = tool_id
        relatives[producer_role] = relative
    return MappingProxyType(identifiers), MappingProxyType(relatives)


def _graph_compile_records(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    effective_root: Path,
    build_root: Path,
    toolchain_root: Path,
    compiler_command: Path,
    generated_translation_units: frozenset[str] = frozenset(),
) -> tuple[_CompileRecord, ...]:
    generated_folded = {item.casefold() for item in generated_translation_units}
    records: list[_CompileRecord] = []
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_refs = tuple(value for value in node.inputs if value.startswith("source/"))
        if len(source_refs) != 1:
            raise ClassicProjectError(f"compiler node {node.id!r} must name one source input")
        outputs = {
            value: materialize_reference(
                value,
                source_root=effective_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            )
            for value in node.outputs
        }
        objects = tuple(
            path
            for reference, path in outputs.items()
            if reference.casefold().endswith(".obj") and path is not None
        )
        pdbs = tuple(
            path
            for reference, path in outputs.items()
            if reference.casefold().endswith(".pdb") and path is not None
        )
        if len(objects) != 1 or len(pdbs) != 1:
            raise ClassicProjectError(f"compiler node {node.id!r} must declare one OBJ and one PDB")
        arguments = (
            str(compiler_command),
            *(
                materialize_argument(
                    value,
                    source_root=bundle.spec.paths.source,
                    build_root=bundle.spec.paths.build,
                    toolchain_root=bundle.spec.paths.toolchain,
                )
                for value in node.arguments
            ),
        )
        try:
            parsed = classic.validate_compile_arguments(list(arguments))
        except Exception as exc:
            raise ClassicProjectError(
                f"compiler node {node.id!r} has unsafe arguments: {exc}"
            ) from exc
        source_relative = source_refs[0].removeprefix("source/")
        expected_source = _logical_join(bundle.spec.paths.source, source_relative)
        if normalize_logical_path(parsed["source_token"].replace("/", "\\")) != expected_source:
            raise ClassicProjectError(
                f"compiler node {node.id!r} source argument differs from its input"
            )
        object_relative = next(
            value.removeprefix("build/")
            for value in node.outputs
            if value.casefold().endswith(".obj")
        )
        pdb_relative = next(
            value.removeprefix("build/")
            for value in node.outputs
            if value.casefold().endswith(".pdb")
        )
        if normalize_logical_path(parsed["Fo"][1].replace("/", "\\")) != _logical_join(
            bundle.spec.paths.build, object_relative
        ) or normalize_logical_path(parsed["Fd"][1].replace("/", "\\")) != _logical_join(
            bundle.spec.paths.build, pdb_relative
        ):
            raise ClassicProjectError(
                f"compiler node {node.id!r} output arguments differ from its outputs"
            )
        source_path = cast(
            Path,
            materialize_reference(
                source_refs[0],
                source_root=effective_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            ),
        )
        if source_relative.casefold() in generated_folded:
            if os.path.lexists(source_path):
                raise ClassicProjectError(
                    f"generated compiler source is present before its epoch: {source_relative!r}"
                )
            resolved_source = source_path.resolve(strict=False)
        else:
            if source_path.is_symlink() or not source_path.is_file():
                raise ClassicProjectError(
                    f"ordinary compiler source is absent or redirected: {source_relative!r}"
                )
            resolved_source = source_path.resolve(strict=True)
        records.append(
            _CompileRecord(
                node_id=node.id,
                directory=build_root,
                source=resolved_source,
                object_path=objects[0].resolve(strict=False),
                pdb_path=pdbs[0].resolve(strict=False),
                arguments=arguments,
                build_target=node.owner,
            )
        )
    identities = [
        (record.build_target.casefold(), record.source.as_posix().casefold()) for record in records
    ]
    if len(identities) != len(set(identities)):
        raise ClassicProjectError("producer graph repeats target/source compile identity")
    return tuple(records)


def _graph_targets(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    effective_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> tuple[ClassicProducerTarget, ...]:
    gates = {
        gate.target_id: gate.build_target
        for gate in bundle.build_plan.target_gates  # type: ignore[union-attr]
    }
    specs = {target.id: target for target in bundle.spec.targets}
    targets: list[ClassicProducerTarget] = []
    for node in graph.nodes:
        if node.target_id is None:
            continue
        target_id = node.target_id
        if node.role is not ProducerRole.LINKER or node.owner != gates.get(target_id):
            raise ClassicProjectError(
                f"terminal node {node.id!r} differs from target-gate authority"
            )
        suffix = Path(specs[target_id].artifact).suffix.casefold()
        primary_refs = tuple(
            reference for reference in node.outputs if Path(reference).suffix.casefold() == suffix
        )
        if primary_refs != (specs[target_id].artifact,):
            raise ClassicProjectError(
                f"terminal node {node.id!r} primary output differs from target artifact"
            )
        candidates = tuple(
            path
            for reference in primary_refs
            for path in (
                materialize_reference(
                    reference,
                    source_root=effective_root,
                    build_root=build_root,
                    toolchain_root=toolchain_root,
                ),
            )
            if path is not None
        )
        if not suffix or len(candidates) != 1:
            raise ClassicProjectError(
                f"terminal node {node.id!r} does not identify one primary image output"
            )
        pdbs = tuple(
            path
            for reference in node.outputs
            if reference.casefold().endswith(".pdb")
            for path in (
                materialize_reference(
                    reference,
                    source_root=effective_root,
                    build_root=build_root,
                    toolchain_root=toolchain_root,
                ),
            )
            if path is not None
        )
        if len(pdbs) > 1:
            raise ClassicProjectError(f"terminal node {node.id!r} repeats PDB outputs")
        targets.append(
            ClassicProducerTarget(
                target_id=target_id,
                build_target=node.owner,
                output=candidates[0].resolve(strict=False),
                pdb=pdbs[0].resolve(strict=False) if pdbs else None,
                link_node_id=node.id,
            )
        )
    if {target.target_id for target in targets} != set(specs):
        raise ClassicProjectError("producer graph does not exactly cover project targets")
    return tuple(sorted(targets, key=lambda item: item.target_id.casefold()))


def _graph_system_library_map(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    installation: ClassicMSVCToolchain,
    *,
    effective_root: Path,
    build_root: Path,
) -> Mapping[str, Path]:
    if bundle.build_plan is None or bundle.source_manifest is None:
        raise ClassicProjectError(
            "system-library resolution requires source and build-plan authority"
        )
    sdk_authorities = {
        item.path.casefold(): item for item in project_sdk_archive_authorities(bundle.build_plan)
    }
    manifest_entries = {item.path.casefold(): item for item in bundle.source_manifest.entries}
    result: dict[str, Path] = {}
    roots = {
        "${SOURCE}": effective_root,
        "${BUILD}": build_root,
        "${TOOLCHAIN}": installation.root,
    }
    for node in graph.nodes:
        names = sorted(
            value.removeprefix("system-library/").casefold()
            for value in (*node.inputs, *node.directive_inputs)
            if value.startswith("system-library/")
        )
        if not names:
            continue
        search_roots: list[tuple[Path, Literal["source", "build", "toolchain"]]] = []
        for argument in node.arguments:
            if not argument.casefold().startswith(("/libpath:", "-libpath:")):
                continue
            raw = argument.split(":", 1)[1]
            matched = False
            for marker, root in roots.items():
                if raw == marker or raw.startswith(marker + "/"):
                    search_relative = raw.removeprefix(marker).removeprefix("/")
                    origin = cast(
                        Literal["source", "build", "toolchain"],
                        {
                            "${SOURCE}": "source",
                            "${BUILD}": "build",
                            "${TOOLCHAIN}": "toolchain",
                        }[marker],
                    )
                    search_roots.append(
                        (
                            root.joinpath(*PurePosixPath(search_relative).parts).resolve(
                                strict=True
                            ),
                            origin,
                        )
                    )
                    matched = True
                    break
            if not matched:
                raise ClassicProjectError(
                    f"producer {node.id!r} has an unseated library search path"
                )
        for relative in installation.profile.library_roots:
            search_roots.append((installation.host_path(relative), "toolchain"))
        for root, _origin in search_roots:
            if root.is_symlink() or not root.is_dir():
                raise ClassicProjectError(f"toolchain library root is absent or redirected: {root}")
        for name in names:
            selected: Path | None = None
            selected_origin: Literal["source", "build", "toolchain"] | None = None
            for root, origin in search_roots:
                matches = tuple(
                    child.resolve(strict=True)
                    for child in root.iterdir()
                    if child.is_file() and not child.is_symlink() and child.name.casefold() == name
                )
                if len(matches) > 1:
                    raise ClassicProjectError(f"system library {name!r} is ambiguous within {root}")
                if matches:
                    selected = matches[0]
                    selected_origin = origin
                    break
            if selected is None:
                raise ClassicProjectError(
                    f"system library {name!r} is absent from producer search roots"
                )
            if selected_origin == "build":
                raise ClassicProjectError(
                    f"system library {name!r} resolves through the build seat; "
                    "declare the produced build archive edge explicitly"
                )
            if selected_origin == "source":
                try:
                    sdk_relative = selected.relative_to(effective_root.resolve(strict=True))
                except ValueError as exc:
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} escaped its seat"
                    ) from exc
                logical_path = PurePosixPath(*sdk_relative.parts).as_posix()
                authority = sdk_authorities.get(logical_path.casefold())
                entry = manifest_entries.get(logical_path.casefold())
                if authority is None or entry is None:
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} lacks exact "
                        f"project SDK authority for {logical_path!r}"
                    )
                payload = selected.read_bytes()
                digest = Digest.from_bytes(payload)
                if (
                    len(payload) != entry.size
                    or digest != entry.digest
                    or digest.value != authority.sha256
                ):
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} differs from "
                        f"its project SDK/source-manifest pin"
                    )
            reference = f"system-library/{name}"
            previous = result.setdefault(reference, selected)
            if previous != selected:
                raise ClassicProjectError(
                    f"system library {name!r} resolves differently across producer nodes"
                )
    return MappingProxyType(dict(sorted(result.items(), key=lambda item: item[0].casefold())))


def _graph_system_library_inputs(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    installation: ClassicMSVCToolchain,
    *,
    effective_root: Path,
    build_root: Path,
) -> tuple[Path, ...]:
    """Compatibility view of the exact reference-to-library map."""

    return tuple(
        _graph_system_library_map(
            bundle,
            graph,
            installation,
            effective_root=effective_root,
            build_root=build_root,
        ).values()
    )


def _capture_and_restore_overlay_outputs(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    effective_root: Path,
) -> _OverlayEpochPlan:
    """Capture effective bytes, then restore the ordinary compiler epoch.

    Every output without a clean preimage is deliberately absent when this
    function returns.  The executor materializes those sealed bytes only after
    all ordinary compiler/resource nodes have completed.
    """

    outputs: dict[str, bytes] = {}
    source_pairs: list[ProjectOverlaySourcePair] = []
    generated_inputs: set[str] = set()
    carrier_input_seals: dict[str, tuple[str, ...]] = {}
    folded_outputs: set[str] = set()
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention) or (
            intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            continue
        values = {item.name: item.value for item in intervention.parameters}
        declarations = values.get("outputs")
        graph = values.get("graph")
        if not isinstance(declarations, list) or not isinstance(graph, dict):
            raise ClassicProjectError("source-overlay declaration is malformed")
        raw_generated = graph.get("generated_tus")
        if not isinstance(raw_generated, list):
            raise ClassicProjectError("source-overlay generated-TU graph is malformed")
        carrier_paths: list[str] = []
        for raw in raw_generated:
            path = raw.get("path") if isinstance(raw, dict) else None
            if not isinstance(path, str):
                raise ClassicProjectError("source-overlay generated TU is malformed")
            carrier_paths.append(_safe_relative(path))
        intervention_generated: set[str] = set()
        for raw in declarations:
            path = raw.get("path") if isinstance(raw, dict) else None
            if not isinstance(path, str):
                raise ClassicProjectError("source-overlay output is malformed")
            assert isinstance(raw, dict)
            relative = _safe_relative(path)
            if relative.casefold() in folded_outputs:
                raise ClassicProjectError("source-overlay output paths overlap")
            folded_outputs.add(relative.casefold())
            output_path = effective_root.joinpath(*PurePosixPath(relative).parts)
            if output_path.is_symlink() or not output_path.is_file():
                raise ClassicProjectError(f"rendered source-overlay output is absent: {relative!r}")
            effective_payload = output_path.read_bytes()
            effective_digest = raw.get("effective")
            effective_size = raw.get("size")
            if (
                not isinstance(effective_digest, str)
                or effective_digest != Digest.from_bytes(effective_payload).value
                or not isinstance(effective_size, int)
                or isinstance(effective_size, bool)
                or effective_size != len(effective_payload)
            ):
                raise ClassicProjectError(f"rendered source-overlay output changed: {relative!r}")
            outputs[relative] = effective_payload
            clean_digest = raw.get("clean")
            if clean_digest is None:
                clean_payload = None
                intervention_generated.add(relative)
                generated_inputs.add(relative)
            else:
                if not isinstance(clean_digest, str):
                    raise ClassicProjectError(
                        f"source-overlay clean digest is malformed: {relative!r}"
                    )
                clean_path = project_root.joinpath(*PurePosixPath(relative).parts)
                if clean_path.is_symlink() or not clean_path.is_file():
                    raise ClassicProjectError(
                        f"ordinary source-overlay clean input is absent: {relative!r}"
                    )
                clean_payload = clean_path.read_bytes()
                if Digest.from_bytes(clean_payload).value != clean_digest:
                    raise ClassicProjectError(
                        f"ordinary source-overlay clean input changed: {relative!r}"
                    )
            source_pairs.append(
                ProjectOverlaySourcePair(relative, clean_payload, effective_payload)
            )
        generated_folded = {item.casefold() for item in intervention_generated}
        seal = tuple(sorted(intervention_generated, key=str.casefold))
        for carrier_path in carrier_paths:
            if carrier_path.casefold() not in generated_folded:
                raise ClassicProjectError(
                    f"source-overlay carrier is not a generated output: {carrier_path!r}"
                )
            if carrier_path.casefold() in {item.casefold() for item in carrier_input_seals}:
                raise ClassicProjectError(f"source-overlay carrier paths overlap: {carrier_path!r}")
            carrier_input_seals[carrier_path] = seal
    generated_folded = {item.casefold() for item in generated_inputs}
    pairs_by_path = {item.path: item for item in source_pairs}
    for relative in outputs:
        destination = effective_root.joinpath(*PurePosixPath(relative).parts)
        if relative.casefold() in generated_folded:
            if destination.is_symlink() or not destination.is_file():
                raise ClassicProjectError(
                    f"generated source-overlay output is absent: {relative!r}"
                )
            destination.unlink()
            continue
        clean_payload = pairs_by_path[relative].clean_payload
        if clean_payload is None:
            raise AssertionError("ordinary source-overlay pair lacks a clean payload")
        destination.write_bytes(clean_payload)
    return _OverlayEpochPlan(
        MappingProxyType(outputs),
        tuple(sorted(source_pairs, key=lambda item: item.path.casefold())),
        frozenset(generated_inputs),
        MappingProxyType(carrier_input_seals),
    )


def prepare_classic_producer_graph_run(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    session_root: Path,
    toolchain_root: Path,
    backend: ExecutionBackend,
    jobs: int,
    compiler_transport: Path | None = None,
    resource_transport: Path | None = None,
    initialization_timeout: float = 600.0,
    compile_timeout: float = 600.0,
    link_timeout: float = 900.0,
    cleanup_timeout: float = 10.0,
    progress: ClassicProgressCallback | None = None,
) -> ClassicProducerGraphPreparedRun:
    """Prepare a cold, direct execution of the committed producer graph."""

    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise ClassicProjectError("classic graph execution requires the producer-graph adapter")
    graph = bundle.producer_graph
    if graph is not None:
        classic_rdata_repack_graph_authority(bundle, graph)
    if isinstance(backend, NativeWindowsBackend):
        try:
            backend.doctor(execute_probe=True).require_ok()
        except BackendError as exc:
            raise ClassicProjectError(
                f"native Windows backend is unavailable: {exc}"
            ) from exc
    if graph is None:
        raise ClassicProjectError(
            "classic authenticity execution requires a committed producer graph"
        )
    if bundle.build_plan is None or bundle.source_manifest is None:
        raise ClassicProjectError("classic graph execution requires source and build plans")
    if jobs < 1 or min(initialization_timeout, compile_timeout, link_timeout, cleanup_timeout) <= 0:
        raise ClassicProjectError("classic execution limits must be positive")
    project_root = project_root.resolve(strict=True)
    session_root = session_root.resolve(strict=False)
    try:
        session_root.relative_to(project_root)
    except ValueError as exc:
        raise ClassicProjectError("classic session must remain beneath project root") from exc
    if session_root.exists() and any(session_root.iterdir()):
        raise ClassicProjectError(f"classic session is not empty: {session_root}")
    session_root.mkdir(parents=True, exist_ok=True)
    (session_root / "logs").mkdir()

    graph_path = project_root.joinpath(*PurePosixPath(bundle.spec.layout.producer_graph).parts)
    if (
        graph_path.is_symlink()
        or not graph_path.is_file()
        or (read_producer_graph(graph_path) != graph)
    ):
        raise ClassicProjectError("committed producer graph changed after project load")
    admitted_toolchain_root = toolchain_root.resolve(strict=True)
    logical_workspace = _materialize_direct_logical_workspace(
        bundle,
        session_root=session_root,
        toolchain_root=admitted_toolchain_root,
    )
    # Donor compilers need a private writable seat on the mapped logical
    # drive, but creating a new sibling after a source lease is acquired would
    # mutate that lease's held ancestor.  Establish the container before any
    # readable namespace exists; individual arenas mutate only this dedicated
    # producer-writable directory.
    donor_root = logical_workspace.build_root.parent / "donors"
    donor_root.mkdir(parents=True, exist_ok=False)
    effective_root = logical_workspace.effective_root
    build_root = logical_workspace.build_root
    overlay_interventions = materialize_effective_workspace(
        bundle,
        project_root,
        effective_root,
    )
    overlay_epoch = _capture_and_restore_overlay_outputs(
        bundle,
        project_root=project_root,
        effective_root=effective_root,
    )
    overlay_effective_outputs = overlay_epoch.effective_outputs
    source_installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile,
        admitted_toolchain_root,
        logical_root=bundle.spec.paths.toolchain,
    )
    runtime_lock = ToolchainLock.from_schema_v3(bundle.toolchain_lock)
    source_installation.doctor(runtime_lock).require_ok()
    original_toolchain_inputs = _project_locked_toolchain(
        bundle,
        source_root=source_installation.root,
        destination=logical_workspace.toolchain_entry,
    )
    installation = ClassicMSVCToolchain(
        bundle.spec.toolchain.profile,
        logical_workspace.toolchain_entry,
        logical_root=bundle.spec.paths.toolchain,
    )
    installation.doctor(runtime_lock).require_ok()
    role_tool_ids, role_relatives = _graph_role_bindings(bundle, installation)

    wrapper_files: tuple[Path, ...] = ()
    proxy_files: tuple[Path, ...] = ()
    proxy_template: Path | None = None
    frontend_environment: Mapping[str, str] = MappingProxyType({})
    role_commands: dict[ProducerRole, Path] = {
        role: Path(_logical_join(bundle.spec.paths.toolchain, relative))
        for role, relative in role_relatives.items()
    }
    host_programs: list[Path] = []
    transport: Path | None = None
    wine_alias: Path | None = None
    if isinstance(backend, PosixWineBackend):
        if compiler_transport is None or resource_transport is None:
            raise ClassicProjectError(
                "POSIX classic execution requires explicit compiler and RC transport selectors"
            )
        real_compiler = _admitted_host_wrapper(
            compiler_transport,
            toolchain_root=source_installation.root,
            label="compiler transport selector",
        )
        real_rc = _admitted_host_wrapper(
            resource_transport,
            toolchain_root=source_installation.root,
            label="RC transport selector",
        )
        if real_compiler.parent != real_rc.parent:
            raise ClassicProjectError("compiler and RC selectors must share one transport")
        real_linker = _admitted_host_wrapper(
            real_compiler.parent / "link",
            toolchain_root=source_installation.root,
            label="linker transport selector",
        )
        real_librarian = _admitted_host_wrapper(
            real_compiler.parent / "lib",
            toolchain_root=source_installation.root,
            label="librarian transport selector",
        )
        transport = _admitted_host_wrapper(
            real_compiler.parent / "wine-msvc.sh",
            toolchain_root=source_installation.root,
            label="Wine MSVC transport",
        )
        if os.path.lexists(transport.parent / "msvctricks.exe"):
            raise ClassicProjectError(
                "wine-msvc transports with host-path msvctricks require a typed adapter"
            )
        wrapper_files = _locked_wrapper_runtime_files(
            bundle,
            (real_compiler, real_rc, real_linker, real_librarian, transport),
            toolchain_root=source_installation.root,
        )
        proxies, proxy_template = _install_path_proxies(session_root)
        role_commands = {
            ProducerRole.COMPILER: proxies["cl"],
            ProducerRole.RESOURCE: proxies["rc"],
            ProducerRole.LIBRARIAN: proxies["lib"],
            ProducerRole.LINKER: proxies["link"],
        }
        proxy_files = tuple(proxies.values())
        frontend_environment = MappingProxyType(
            {
                "REPROBIT_WINE_MSVC_TRANSPORT": str(transport),
                "REPROBIT_LOGICAL_CL": installation.logical_path(
                    role_relatives[ProducerRole.COMPILER]
                ),
                "REPROBIT_LOGICAL_RC": installation.logical_path(
                    role_relatives[ProducerRole.RESOURCE]
                ),
                "REPROBIT_LOGICAL_LINK": installation.logical_path(
                    role_relatives[ProducerRole.LINKER]
                ),
                "REPROBIT_LOGICAL_LIB": installation.logical_path(
                    role_relatives[ProducerRole.LIBRARIAN]
                ),
            }
        )
        if backend.wine_pin is None or backend.wineserver_pin is None:
            raise ClassicProjectError("POSIX classic execution requires resolved Wine programs")
        wine_alias = _install_pinned_wine_alias(session_root, backend.wine_pin.path)
        proxy_files = (*proxy_files, wine_alias)
        host_programs.extend((backend.wine_pin.path, backend.wineserver_pin.path, transport))
    else:
        if compiler_transport is not None or resource_transport is not None:
            raise ClassicProjectError(
                "native Windows execution does not accept POSIX transport selectors"
            )

    clean_sources = {
        entry.path: (project_root / entry.path).read_bytes()
        for entry in bundle.source_manifest.entries
    }
    compiler_epoch_plan = plan_project_overlay_compiler_epochs(
        bundle,
        graph,
        overlay_epoch.project_source_pairs,
        (
            tuple(
                CleanSourceInput(path, payload)
                for path, payload in sorted(
                    clean_sources.items(), key=lambda item: item[0].casefold()
                )
            )
            if overlay_interventions
            else ()
        ),
        secondary_reader_payloads=(
            _toolchain_include_reader_payloads(bundle, source_installation.root)
            if overlay_interventions
            else {}
        ),
    )
    effective_sources = {
        entry.path: (effective_root / entry.path).read_bytes()
        for entry in bundle.source_manifest.entries
    }
    effective_sources.update(overlay_effective_outputs)
    units = prepare_classic_units(
        bundle,
        clean_sources=clean_sources,
        effective_sources=effective_sources,
        overlay_dialect=_overlay_dialect(bundle),
    )
    compile_records = _graph_compile_records(
        bundle,
        graph,
        effective_root=effective_root,
        build_root=build_root,
        toolchain_root=installation.root,
        compiler_command=role_commands[ProducerRole.COMPILER],
        generated_translation_units=frozenset(overlay_epoch.carrier_input_seals),
    )
    targets = _graph_targets(
        bundle,
        graph,
        effective_root=effective_root,
        build_root=build_root,
        toolchain_root=installation.root,
    )
    system_library_map = _graph_system_library_map(
        bundle,
        graph,
        installation,
        effective_root=effective_root,
        build_root=build_root,
    )
    authority_inputs: list[Path] = [
        graph_path,
        *proxy_files,
        *system_library_map.values(),
        *original_toolchain_inputs,
    ]
    if proxy_template is not None:
        authority_inputs.append(proxy_template)
    if isinstance(backend, PosixWineBackend):
        assert backend.wine_pin is not None and backend.wineserver_pin is not None
        authority_inputs.extend((backend.wine_pin.path, backend.wineserver_pin.path))

    lane_pool = _prepare_execution_lanes(
        bundle,
        installation=installation,
        backend=backend,
        logical_workspace=logical_workspace,
        session_root=session_root,
        role_commands=role_commands,
        host_programs=host_programs,
        frontend_environment=frontend_environment,
        jobs=jobs,
        initialization_timeout=initialization_timeout,
        cleanup_timeout=cleanup_timeout,
        wine_alias=wine_alias,
    )
    try:
        executor = ClassicProducerGraphBuildExecutor(
            bundle=bundle,
            project_root=project_root,
            session_root=session_root,
            build_root=build_root,
            effective_root=effective_root,
            toolchain_root=installation.root,
            graph=graph,
            role_commands=role_commands,
            role_tool_ids=role_tool_ids,
            wrapper_runtime_files=wrapper_files,
            authority_inputs=authority_inputs,
            targets=targets,
            compile_records=compile_records,
            units=units,
            overlay_witnesses=overlay_interventions,
            overlay_effective_outputs=overlay_effective_outputs,
            project_source_pairs=overlay_epoch.project_source_pairs,
            compiler_epoch_plan=compiler_epoch_plan,
            generated_inputs=overlay_epoch.generated_inputs,
            carrier_input_seals=overlay_epoch.carrier_input_seals,
            system_libraries=system_library_map,
            lane_pool=lane_pool,
            jobs=jobs,
            compile_timeout=compile_timeout,
            link_timeout=link_timeout,
            progress=progress,
        )
        return ClassicProducerGraphPreparedRun(
            executor=executor,
            evidence_provider=ClassicProducerGraphRuntimeEvidenceProvider(executor),
            plan=BuildPlan(()),
            intervention_witnesses=tuple(overlay_interventions),
        )
    except BaseException as original:
        try:
            lane_pool.close()
        except BaseException as error:
            original.add_note(f"classic runtime cleanup also failed: {error}")
        raise


__all__ = [
    "ClassicCompilerProbeOutput",
    "ClassicDonorProbeInput",
    "ClassicDonorProbeOutput",
    "ClassicProducedImage",
    "ClassicProducerGraphBuildExecutor",
    "ClassicProducerGraphExecutionRecord",
    "ClassicProducerGraphPreparedRun",
    "ClassicProducerGraphRuntimeEvidenceProvider",
    "ClassicProducerTarget",
    "ClassicProgressCallback",
    "prepare_classic_producer_graph_run",
]
