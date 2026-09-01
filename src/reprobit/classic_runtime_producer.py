"""Direct producer authority and process execution for classic builds."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock
from types import MappingProxyType
from typing import Literal, cast

from reprobit.classic.compiler_epoch import (
    classic_compiler_path_profile_digest,
    compiler_epoch_invocation_digest,
    compiler_namespace_evidence_digest,
)
from reprobit.classic.semantic_contracts import (
    CompilerEpochInvocation,
    CompilerInputEvidenceKind,
    CompilerNamespaceEvidence,
    CompilerSourceRead,
)
from reprobit.classic_execution_records import (
    ClassicCompilerNamespaceReceipt,
    ClassicProducerRead,
    ClassicProducerReadReceipt,
)
from reprobit.classic_includes import (
    IncludeOrigin,
    SealedIncludeAuthority,
    SealedIncludeFile,
)
from reprobit.classic_project import (
    ClassicProjectError,
)
from reprobit.classic_resources import (
    ResourceDependencyReceipt,
    scan_msvc_resource_dependencies,
)
from reprobit.classic_runtime_environment import (
    _ExecutionLane,
    _LazyExecutionLanePool,
    _logical_join,
    _logical_relative_parts,
    _run,
    _toolchain_tree_files,
)
from reprobit.classic_runtime_files import (
    _digest_path,
    _path_is_within,
    _require_declared_tree_writes,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
    ClassicProducerTarget,
)
from reprobit.classic_runtime_receipts import (
    _internal_step,
    _step_receipt,
)
from reprobit.execution import StepExecutionReceipt
from reprobit.model import Digest
from reprobit.paths import (
    normalize_logical_path,
)
from reprobit.process import (
    CancellationToken,
    CommandSpec,
    ProcessResult,
    ProcessSupervisor,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    materialize_argument,
    materialize_reference,
)
from reprobit.schema import (
    ProjectBundle,
)
from reprobit.sealed_namespace import (
    NamespaceFile,
    NamespaceTree,
    SealedNamespaceFile,
    SealedNamespaceLease,
    SealedNamespaceSnapshot,
)

ClassicProgressEventKind = Literal[
    "unit_finished",
    "phase_started",
    "phase_finished",
    "phase_failed",
    "heartbeat",
]
ClassicProgressCallback = Callable[
    [int, int, str, str, ClassicProgressEventKind, str | None],
    None,
]


class ClassicProgressReporter:
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
                self.callback(
                    self.completed,
                    self.total,
                    phase,
                    node_id,
                    "unit_finished",
                    None,
                )

    def activity(
        self,
        kind: ClassicProgressEventKind,
        phase: str,
        message: str,
        reason: str | None = None,
    ) -> None:
        """Report a named non-counted sub-phase at the current unit position."""

        if kind not in {
            "phase_started",
            "phase_finished",
            "phase_failed",
            "heartbeat",
        }:
            raise ClassicProjectError(f"invalid classic progress activity: {kind}")
        with self._lock:
            if self.callback is not None:
                self.callback(
                    self.completed,
                    self.total,
                    phase,
                    message,
                    kind,
                    reason,
                )


@dataclass(frozen=True, slots=True)
class _ResourceDependencyAudit:
    """One static, closed recursive-read proof for a resource compiler node."""

    step: StepExecutionReceipt
    receipt: ResourceDependencyReceipt


@dataclass(frozen=True, slots=True)
class ClassicAnalysisLinkPlan:
    """One closed relink whose image remains private to the current run."""

    target_id: str
    node_id: str
    arguments: tuple[str, ...]
    arena: Path
    image: Path
    pdb: Path
    allowed_outputs: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class ClassicAnalysisLinkExecution:
    """Validated private image/PDB pair from one analysis relink."""

    plan: ClassicAnalysisLinkPlan
    result: ProcessResult
    spec: CommandSpec
    private_files: tuple[Path, ...]
    image: Path
    pdb: Path


def _runtime_authority_label(path: Path) -> str:
    """Give one external authority a stable full-path namespace identity."""

    canonical = Path(os.path.abspath(path)).resolve(strict=True)
    return "runtime-authority:" + canonical.as_posix()


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


class ClassicProducerExecution:
    """Own direct producer authority, process execution, outputs, and read evidence."""

    def __init__(
        self,
        *,
        bundle: ProjectBundle,
        session_root: Path,
        build_root: Path,
        effective_root: Path,
        toolchain_root: Path,
        graph: ProducerGraphDocument,
        role_commands: Mapping[ProducerRole, Path],
        role_tool_ids: Mapping[ProducerRole, str],
        wrapper_runtime_files: Sequence[Path],
        authority_inputs: Sequence[Path],
        analysis_link_options: Sequence[str],
        lane_pool: _LazyExecutionLanePool,
        jobs: int,
        compile_timeout: float,
        link_timeout: float,
        progress: ClassicProgressReporter,
    ) -> None:
        if set(role_commands) != set(ProducerRole) or set(role_tool_ids) != set(ProducerRole):
            raise ClassicProjectError("producer graph does not bind every locked role")
        self.bundle = bundle
        self.session_root = session_root
        self.build_root = build_root
        self.effective_root = effective_root
        self.toolchain_root = toolchain_root
        logical_source_parts = _logical_relative_parts(
            bundle.spec.paths.source,
            drive_letter=PureWindowsPath(bundle.spec.paths.source).drive.rstrip(":").upper(),
        )
        logical_drive_root = effective_root
        for _ in logical_source_parts:
            logical_drive_root = logical_drive_root.parent
        self._logical_drive_root = logical_drive_root.resolve(strict=True)
        self._logical_drive_letter = (
            PureWindowsPath(bundle.spec.paths.source).drive.rstrip(":").upper()
        )
        for physical, logical in (
            (effective_root, bundle.spec.paths.source),
            (build_root, bundle.spec.paths.build),
            (toolchain_root, bundle.spec.paths.toolchain),
        ):
            expected = self._logical_drive_root.joinpath(
                *_logical_relative_parts(logical, drive_letter=self._logical_drive_letter)
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
        ):
            path = raw.resolve(strict=True)
            if path.is_symlink() or not path.is_file():
                raise ClassicProjectError(
                    f"classic runtime authority is absent or redirected: {path}"
                )
            if any(_path_is_within(path, root) for root in (effective_root, toolchain_root)):
                continue
            namespace_authority[path] = NamespaceFile(
                _runtime_authority_label(path),
                path,
                path.parent,
            )
        self._namespace_authority_files = tuple(
            namespace_authority[path]
            for path in sorted(namespace_authority, key=lambda item: str(item).casefold())
        )
        self.analysis_link_options = tuple(analysis_link_options)
        if self.analysis_link_options not in {(), ("/DEBUG",)}:
            raise ClassicProjectError("classic analysis-link options are not closed")
        if lane_pool.maximum != jobs:
            raise ClassicProjectError("classic execution lane capacity differs from the job limit")
        self._lane_pool = lane_pool
        self._compiler_environment_digest = lane_pool.compiler_environment_digest
        self._compiler_path_profile_digest = classic_compiler_path_profile_digest(bundle, graph)
        self.jobs = jobs
        self.compile_timeout = compile_timeout
        self.link_timeout = link_timeout
        self._progress = progress
        self._runtime_open = True
        self._mode: Literal["certifying", "developer"] | None = None
        self._output_lock = Lock()
        self._evidence_lock = Lock()
        self._physical_outputs: dict[Path, Path] = {}
        self._producer_reads: list[ClassicProducerReadReceipt] = []
        # Compiler read receipts indexed by (node id, epoch) as they arrive, so
        # freezing one epoch's invocation does not rescan every receipt.
        self._compiler_reads: dict[tuple[str, str], list[ClassicProducerReadReceipt]] = {}
        self._resource_dependency_receipts: dict[str, ResourceDependencyReceipt] = {}
        self._namespace_payload_intern: dict[tuple[str, int], bytes] = {}
        self._compiler_namespaces: dict[str, ClassicCompilerNamespaceReceipt] = {}

    def begin_certifying(self) -> None:
        self._claim_mode("certifying")

    def begin_developer(self) -> None:
        self._claim_mode("developer")

    def _claim_mode(self, mode: Literal["certifying", "developer"]) -> None:
        if not self._runtime_open:
            raise ClassicProjectError("classic producer runtime is closed")
        if self._mode is None:
            self._mode = mode
        elif self._mode != mode:
            raise ClassicProjectError(
                "classic prepared run cannot mix certifying and developer execution"
            )

    @property
    def is_open(self) -> bool:
        return self._runtime_open

    @property
    def initialized_runtime_count(self) -> int:
        """Report whether this run started its single shared backend runtime."""

        return int(self._lane_pool.created_count > 0)

    @property
    def logical_drive_root(self) -> Path:
        return self._logical_drive_root

    @property
    def logical_drive_letter(self) -> str:
        return self._logical_drive_letter

    @property
    def lane_pool(self) -> _LazyExecutionLanePool:
        return self._lane_pool

    def close(self) -> None:
        if not self._runtime_open:
            return
        self._runtime_open = False
        self._lane_pool.close()

    def producer_reads(self) -> tuple[ClassicProducerReadReceipt, ...]:
        with self._evidence_lock:
            return tuple(self._producer_reads)

    def _record_producer_read(self, receipt: ClassicProducerReadReceipt) -> None:
        """Append one read receipt; the caller holds the evidence lock."""

        self._producer_reads.append(receipt)
        if receipt.role is ProducerRole.COMPILER:
            self._compiler_reads.setdefault((receipt.node_id, receipt.epoch), []).append(receipt)

    def resource_dependency_receipts(self) -> Mapping[str, ResourceDependencyReceipt]:
        with self._evidence_lock:
            return MappingProxyType(dict(self._resource_dependency_receipts))

    def compiler_namespaces(self) -> Mapping[str, ClassicCompilerNamespaceReceipt]:
        return MappingProxyType(dict(self._compiler_namespaces))

    def bind_cached_output(self, declared: Path, physical: Path) -> None:
        with self._output_lock:
            previous = self._physical_outputs.setdefault(declared, physical)
            if previous != physical:
                raise ClassicProjectError(
                    f"classic cached output aliases another physical output: {declared}"
                )

    def clear_output(self, declared: Path) -> Path | None:
        with self._output_lock:
            return self._physical_outputs.pop(declared, None)

    def registered_outputs(self) -> Mapping[Path, Path]:
        with self._output_lock:
            return MappingProxyType(dict(self._physical_outputs))

    def reference(self, value: str) -> Path | None:
        return materialize_reference(
            value,
            source_root=self.effective_root,
            build_root=self.build_root,
            toolchain_root=self.toolchain_root,
        )

    def node_arguments(self, node: ProducerNode) -> tuple[str, ...]:
        return tuple(
            materialize_argument(
                value,
                source_root=self.bundle.spec.paths.source,
                build_root=self.bundle.spec.paths.build,
                toolchain_root=self.bundle.spec.paths.toolchain,
            )
            for value in node.arguments
        )

    def logical_for_host_path(self, path: Path) -> str:
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

    def producer_cwd(self, lane: _ExecutionLane, physical: Path) -> Path:
        """Present the mapped DOS cwd to native producers, not its host backing path."""

        if lane.windows_lineage_planner is None:
            return physical
        if os.name != "nt":
            raise ClassicProjectError(
                "suspended native producer admission is unavailable off Windows"
            )
        return Path(self.logical_for_host_path(physical))

    def compiler_visible_path(self, value: str) -> str:
        """Normalize either an admitted DOS path or a run-private host path."""

        windows = PureWindowsPath(value.replace("/", "\\"))
        if windows.drive:
            return normalize_logical_path(str(windows))
        path = Path(value)
        if not path.is_absolute():
            raise ClassicProjectError(f"compiler dependency path lacks a closed root: {value!r}")
        return self.logical_for_host_path(path)

    def host_for_logical_path(self, value: str) -> Path:
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
        self.require_regular(resolved, label="logical producer read")
        return resolved

    def authority_namespace_lease(self) -> SealedNamespaceLease:
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

    def source_namespace_lease(self) -> SealedNamespaceLease:
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

    def capture_compiler_namespace(
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
                        self.logical_for_host_path(item.path),
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

    def compiler_epoch_invocation(
        self, node: ProducerNode, *, epoch: str
    ) -> CompilerEpochInvocation:
        """Freeze one compiler-visible invocation and its recursive source reads."""

        if node.role is not ProducerRole.COMPILER:
            raise ClassicProjectError(f"producer {node.id!r} is not a compiler invocation")
        with self._evidence_lock:
            matches = tuple(self._compiler_reads.get((node.id, epoch), ()))
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

    def include_authority(self) -> SealedIncludeAuthority:
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

    def donor_authority(
        self,
        base: SealedIncludeAuthority,
        *,
        arena: Path,
        arena_seal: Mapping[Path, tuple[int, Digest]],
    ) -> SealedIncludeAuthority:
        """Extend the immutable project/toolchain authority by one donor arena."""

        logical_arena = self.logical_for_host_path(arena)
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
    def include_environment_directories(
        environment: Mapping[str, str],
    ) -> tuple[str, ...]:
        matches = [value for key, value in environment.items() if key.casefold() == "include"]
        if len(matches) != 1 or not matches[0]:
            raise ClassicProjectError("compiler environment does not uniquely declare INCLUDE")
        values = tuple(matches[0].split(";"))
        if any(not value for value in values):
            raise ClassicProjectError("compiler INCLUDE contains an empty search root")
        return values

    def include_payloads(self, authority: SealedIncludeAuthority) -> Mapping[str, bytes]:
        payloads: dict[str, bytes] = {}
        for item in authority.files:
            path = self.host_for_logical_path(item.logical_path)
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
                include_directories.append(self.compiler_visible_path(arguments[index + 1]))
                index += 2
                continue
            if folded.startswith(("/i", "-i")) and len(value) > 2:
                include_directories.append(self.compiler_visible_path(value[2:]))
            index += 1
        source_refs = tuple(
            value
            for value in node.inputs
            if value.startswith("source/") and PurePosixPath(value).suffix.casefold() == ".rc"
        )
        if len(source_refs) != 1:
            raise ClassicProjectError(f"resource node {node.id!r} lacks one committed RC source")
        source_path = self.compiler_visible_path(arguments[-1])
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
            environment_directories=self.include_environment_directories(lane.environment),
            authority=authority,
            payloads=self.include_payloads(authority),
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
                    self.host_for_logical_path(item.logical_path),
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
            self._record_producer_read(read_receipt)
        return _ResourceDependencyAudit(step, receipt)

    def declared_outputs(self, node: ProducerNode) -> tuple[Path, ...]:
        outputs = tuple(self.reference(value) for value in node.outputs)
        if any(path is None for path in outputs):
            raise ClassicProjectError(f"producer {node.id!r} has a non-file output")
        return cast(tuple[Path, ...], outputs)

    def node_outputs(self, node: ProducerNode) -> tuple[Path, ...]:
        declared = self.declared_outputs(node)
        with self._output_lock:
            return tuple(self._physical_outputs.get(path, path) for path in declared)

    @staticmethod
    def compiler_companion_output(path: Path) -> Path:
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

    @staticmethod
    def require_regular(path: Path, *, label: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise ClassicProjectError(f"{label} is absent or redirected: {path}")

    def run_node(
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
            path = self.reference(value)
            if path is not None:
                self.require_regular(path, label=f"producer {node.id!r} input")
        declared_outputs = self.declared_outputs(node)
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
            *self.node_arguments(node),
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
                cwd=self.producer_cwd(lane, self.build_root),
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
                actual = self.compiler_companion_output(path)
            else:
                self.require_regular(path, label=f"producer {node.id!r} output")
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
                self._record_producer_read(
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

    def run_graph_nodes(
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
                        self.run_node,
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
                        for path in self.node_outputs(node):
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

    def _analysis_link_plan(
        self,
        target: ClassicProducerTarget,
        node: ProducerNode,
    ) -> ClassicAnalysisLinkPlan:
        """Derive one private `/DEBUG` relink from an exact terminal command."""

        if self.analysis_link_options != ("/DEBUG",):
            raise ClassicProjectError("classic analysis relink lacks its closed /DEBUG authority")
        if (
            node.role is not ProducerRole.LINKER
            or node.id != target.link_node_id
            or node.target_id != target.target_id
            or target.pdb is not None
        ):
            raise ClassicProjectError(
                f"analysis relink target {target.target_id!r} differs from exact-link authority"
            )
        arena = self.build_root / ".reprobit-analysis" / target.target_id
        image = arena / target.output.name
        pdb = arena / f"{target.output.stem}.PDB"
        implementation_library = arena / f"{target.output.stem}.lib"
        export_file = implementation_library.with_suffix(".exp")
        map_file = arena / f"{target.output.stem}.map"
        logical_image = self.logical_for_host_path(image)
        logical_pdb = self.logical_for_host_path(pdb)
        logical_implementation_library = self.logical_for_host_path(implementation_library)
        logical_map = self.logical_for_host_path(map_file)

        rewritten: list[str] = []
        counts = {"out": 0, "pdb": 0, "implib": 0, "map": 0}
        incremental_no_count = 0
        for argument in self.node_arguments(node):
            folded = argument.casefold()
            if folded in {"/debug", "-debug"} or folded.startswith(("/debug:", "-debug:")):
                raise ClassicProjectError(
                    f"exact linker {node.id!r} already contains an analysis-only debug option"
                )
            if folded.startswith(("/incremental:", "-incremental:")):
                if folded not in {"/incremental:no", "-incremental:no"}:
                    raise ClassicProjectError(
                        f"analysis relink {node.id!r} does not admit incremental linker state"
                    )
                incremental_no_count += 1
            replacement: tuple[str, str, str] | None = None
            for name, prefixes, value in (
                ("out", ("/out:", "-out:"), logical_image),
                ("pdb", ("/pdb:", "-pdb:"), logical_pdb),
                (
                    "implib",
                    ("/implib:", "-implib:"),
                    logical_implementation_library,
                ),
                ("map", ("/map:", "-map:"), logical_map),
            ):
                prefix = next((item for item in prefixes if folded.startswith(item)), None)
                if prefix is not None:
                    replacement = name, prefix, value
                    break
            if replacement is None:
                rewritten.append(argument)
                continue
            name, prefix, value = replacement
            if len(argument) == len(prefix) or "\x00" in argument:
                raise ClassicProjectError(
                    f"analysis relink {node.id!r} has a malformed /{name.upper()} control"
                )
            counts[name] += 1
            rewritten.append(argument[: len(prefix)] + value)

        if counts["out"] != 1 or counts["pdb"] != 1:
            raise ClassicProjectError(
                f"analysis relink {node.id!r} requires exactly one /OUT and one /PDB control"
            )
        if counts["implib"] > 1 or counts["map"] > 1:
            raise ClassicProjectError(
                f"analysis relink {node.id!r} repeats a secondary linker output control"
            )
        if incremental_no_count != 1:
            raise ClassicProjectError(
                f"analysis relink {node.id!r} requires exactly one /INCREMENTAL:NO control"
            )
        try:
            exact_logical = normalize_logical_path(self.logical_for_host_path(target.output))
            original_out = next(
                argument.split(":", 1)[1]
                for argument in self.node_arguments(node)
                if argument.casefold().startswith(("/out:", "-out:"))
            )
            original_logical = normalize_logical_path(original_out.replace("/", "\\"))
        except (StopIteration, ValueError) as exc:
            raise ClassicProjectError(
                f"analysis relink {node.id!r} has an invalid exact image control"
            ) from exc
        if original_logical.casefold() != exact_logical.casefold():
            raise ClassicProjectError(
                f"analysis relink {node.id!r} /OUT differs from its exact target"
            )

        allowed = [image, pdb]
        if counts["implib"]:
            allowed.extend((implementation_library, export_file))
        if counts["map"]:
            allowed.append(map_file)
        folded_allowed = [str(path).casefold() for path in allowed]
        if len(folded_allowed) != len(set(folded_allowed)):
            raise ClassicProjectError(f"analysis relink {node.id!r} aliases private output paths")
        return ClassicAnalysisLinkPlan(
            target.target_id,
            node.id,
            (*rewritten, *self.analysis_link_options),
            arena,
            image,
            pdb,
            tuple(allowed),
        )

    def execute_private_analysis_link(
        self,
        supervisor: ProcessSupervisor,
        target: ClassicProducerTarget,
        node: ProducerNode,
        cancellation: CancellationToken,
        *,
        log_namespace: str,
    ) -> ClassicAnalysisLinkExecution:
        """Execute and validate one isolated image/PDB pair without publishing."""

        plan = self._analysis_link_plan(target, node)
        if os.path.lexists(plan.arena):
            raise ClassicProjectError(
                f"analysis relink arena already exists for {target.target_id!r}"
            )
        build_seal = _tree_file_seal(self.build_root)
        parent = plan.arena.parent
        if parent.is_symlink():
            raise ClassicProjectError("analysis relink root is redirected")
        parent.mkdir(parents=True, exist_ok=True)
        plan.arena.mkdir(exist_ok=False)

        lane = self._lane_pool.acquire()
        try:
            result, spec = _run(
                supervisor,
                (str(self.role_commands[ProducerRole.LINKER]), *plan.arguments),
                cwd=self.producer_cwd(lane, self.build_root),
                environment=lane.environment,
                timeout=min(float(node.timeout_seconds), self.link_timeout),
                log=self.session_root / "logs" / log_namespace / f"{target.target_id}.log",
                cancellation=cancellation,
                windows_lineage_planner=lane.windows_lineage_planner,
            )
        finally:
            self._lane_pool.release(lane)

        private_files = tuple(_tree_file_seal(plan.arena))
        arena = plan.arena.resolve(strict=True)
        if any(path.parent != arena for path in private_files):
            raise ClassicProjectError(
                f"analysis relink {node.id!r} created a nested private output"
            )
        by_folded: dict[str, Path] = {}
        for path in private_files:
            folded = str(path).casefold()
            if folded in by_folded:
                raise ClassicProjectError(
                    f"analysis relink {node.id!r} created case-fold output aliases"
                )
            by_folded[folded] = path
        allowed = {str(path.resolve(strict=False)).casefold() for path in plan.allowed_outputs}
        unexpected = sorted(set(by_folded) - allowed)
        image = by_folded.get(str(plan.image.resolve(strict=False)).casefold())
        pdb = by_folded.get(str(plan.pdb.resolve(strict=False)).casefold())
        pdb_files = tuple(path for path in private_files if path.suffix.casefold() == ".pdb")
        if unexpected or image is None or pdb is None or len(pdb_files) != 1:
            raise ClassicProjectError(
                f"analysis relink {node.id!r} did not produce its closed image/PDB pair"
            )
        if image.stat().st_size == 0 or pdb.stat().st_size == 0:
            raise ClassicProjectError(f"analysis relink {node.id!r} produced an empty image or PDB")
        _require_declared_tree_writes(
            build_seal,
            root=self.build_root,
            allowed_outputs=private_files,
            phase=f"analysis relink {target.target_id!r}",
        )
        return ClassicAnalysisLinkExecution(
            plan,
            result,
            spec,
            private_files,
            image,
            pdb,
        )


__all__ = [
    "ClassicAnalysisLinkExecution",
    "ClassicAnalysisLinkPlan",
    "ClassicProducerExecution",
    "ClassicProgressCallback",
    "ClassicProgressEventKind",
    "ClassicProgressReporter",
]
