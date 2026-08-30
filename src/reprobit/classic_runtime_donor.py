"""Private donor compilation and reviewed translation-unit composition."""

from __future__ import annotations

import os
import shutil
import time
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path, PurePosixPath
from threading import Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from reprobit.classic.arguments import validate_compile_arguments
from reprobit.classic.semantic_contracts import (
    _CLASSIC_SEMANTIC_ISSUER,
    DonorSemanticLane,
    EffectiveOverlayReceipt,
    _ClassicDonorSemanticMaterial,
)
from reprobit.classic_donors import (
    DonorCompileRequest,
    DonorIncludeProjection,
    donor_requires_dependency_tracking,
)
from reprobit.classic_execution_records import (
    ClassicActiveCompilerEpoch,
    ClassicDonorOutputReceipt,
    ClassicObjectTransformReceipt,
    ClassicProducerRead,
    ClassicProducerReadReceipt,
)
from reprobit.classic_includes import (
    ClassicIncludeTraceError,
    IncludeOrigin,
    MsvcSbrTrace,
    ResolvedInclude,
    parse_msvc_sbr,
    resolve_msvc_include_trace,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    compose_classic_unit,
)
from reprobit.classic_project import (
    ClassicProjectError,
    InterventionWitness,
)
from reprobit.classic_runtime_environment import (
    _ExecutionLane,
    _logical_join,
    _logical_relative_parts,
    _run,
)
from reprobit.classic_runtime_files import (
    _path_is_within,
    _require_declared_tree_writes,
    _safe_relative,
    _secure_remove_regular,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
    ClassicCompileRecord,
    classic_compiler_product_refs,
)
from reprobit.execution import (
    StepExecutionReceipt,
)
from reprobit.model import Digest
from reprobit.process import (
    CancellationToken,
    CommandFailed,
    CommandSpec,
    ProcessResult,
    ProcessSupervisor,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerRole,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ProjectBundle,
)
from reprobit.sealed_namespace import (
    NamespaceTree,
    SealedNamespaceFile,
    SealedNamespaceLease,
    SealedNamespaceSnapshot,
)
from reprobit.secure_paths import (
    digest_relative_file,
    hold_relative_file_set,
)
from reprobit.strict_json import canonical_json

if TYPE_CHECKING:
    from reprobit.oracle_pe32 import PE32VirtualAddressReader


from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
    ClassicProgressReporter,
)
from reprobit.classic_runtime_receipts import (
    _internal_step,
    _step_receipt,
)


@dataclass(frozen=True, slots=True)
class _DonorCompilerInvocation:
    """Private result shared by cold composition and bounded diagnostics."""

    record: ClassicCompileRecord
    object_path: Path
    pdb_path: Path
    object_payload: bytes
    pdb_payload: bytes
    result: ProcessResult
    spec: CommandSpec
    namespace: SealedNamespaceSnapshot
    step_id: str
    dependency_replay: ClassicWarmDonorDependencyReplay | None = None


@dataclass(frozen=True, slots=True)
class ClassicWarmDonorDependencyReplay:
    """Non-certifying dependency result from one tracked donor replay."""

    donor_id: str
    trace: MsvcSbrTrace | None
    reads: tuple[ResolvedInclude, ...]
    reason: str | None

    def __post_init__(self) -> None:
        if (
            not self.donor_id
            or (self.trace is None) == (self.reason is None)
            or (self.trace is None and self.reads)
        ):
            raise ClassicProjectError(
                "classic warm donor replay requires exactly one complete result state"
            )


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
            raise ClassicProjectError(f"donor dependency output is not a regular file: {actual}")
        _secure_remove_regular(actual)


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


class ClassicDonorComposition:
    """Own private donor compilation, composition, and donor evidence."""

    def __init__(
        self,
        *,
        bundle: ProjectBundle,
        session_root: Path,
        build_root: Path,
        effective_root: Path,
        graph: ProducerGraphDocument,
        compile_records: Sequence[ClassicCompileRecord],
        units: Sequence[ClassicPreparedUnit],
        overlay_effective_outputs: Mapping[str, bytes],
        producer: ClassicProducerExecution,
        progress: ClassicProgressReporter,
        compile_timeout: float,
    ) -> None:
        self.bundle = bundle
        self.session_root = session_root
        self.build_root = build_root
        self.effective_root = effective_root
        self.graph = graph
        self.compile_records = tuple(compile_records)
        self.units = tuple(units)
        self.overlay_effective_outputs = MappingProxyType(dict(overlay_effective_outputs))
        self.producer = producer
        self._progress = progress
        self.compile_timeout = compile_timeout
        self._evidence_lock = Lock()
        self._semantic_lock = Lock()
        self._producer_reads: list[ClassicProducerReadReceipt] = []
        self._donor_outputs: list[ClassicDonorOutputReceipt] = []
        self._object_transforms: list[ClassicObjectTransformReceipt] = []
        self._donor_semantic_lanes: list[DonorSemanticLane] = []
        self._legacy_oracles: Mapping[str, PE32VirtualAddressReader] = MappingProxyType({})
        self._started = False

    def producer_reads(self) -> tuple[ClassicProducerReadReceipt, ...]:
        with self._evidence_lock:
            return tuple(self._producer_reads)

    def donor_outputs(self) -> tuple[ClassicDonorOutputReceipt, ...]:
        with self._evidence_lock:
            return tuple(self._donor_outputs)

    def object_transforms(self) -> tuple[ClassicObjectTransformReceipt, ...]:
        with self._evidence_lock:
            return tuple(self._object_transforms)

    def semantic_lanes(self) -> tuple[DonorSemanticLane, ...]:
        with self._semantic_lock:
            return tuple(self._donor_semantic_lanes)

    def bind_legacy_oracles(self, oracles: Mapping[str, PE32VirtualAddressReader]) -> None:
        """Install opaque VA readers after CLI oracle sealing and before execution."""

        if self._started or self._legacy_oracles:
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

    def record_for_unit(self, unit: ClassicPreparedUnit) -> ClassicCompileRecord:
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

    def record_for_donor(self, unit: ClassicPreparedUnit, donor_index: int) -> ClassicCompileRecord:
        donor = unit.donors[donor_index]
        source = (self.effective_root / donor.request.logical_source).resolve(strict=True)
        matches = [
            item
            for item in self.compile_records
            if item.source == source and item.build_target == donor.request.build_target
        ]
        if len(matches) != 1:
            raise ClassicProjectError(
                f"donor {donor.intervention.id!r} has {len(matches)} committed compile "
                "lanes for its target/source identity: "
                f"{donor.request.build_target}/{donor.request.logical_source}"
            )
        return matches[0]

    def _donor_compiler_command(
        self,
        record: ClassicCompileRecord,
        request: DonorCompileRequest,
        arena: Path,
    ) -> tuple[str, ...]:
        """Rebuild the committed donor compiler argv with private path seats."""

        arguments = list(record.arguments)
        try:
            parsed = validate_compile_arguments(arguments)
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
        include_by_index = {index: (value, separate) for index, value, separate in include_entries}
        if len(include_by_index) != len(include_entries):
            raise ClassicProjectError("donor compile lane include seats are ambiguous")
        first_include = min(include_by_index)

        is_overlay = request.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
        projection = request.compiler_additions.include_projection
        mirror_active = projection is not DonorIncludeProjection.NONE
        source_parent = self.producer.logical_for_host_path(record.source.parent)
        private_includes: list[str]
        if is_overlay:
            parent = PurePosixPath(request.logical_source).parent.as_posix()
            expected_directories = ["inc"]
            private_includes = [f"/I{self.producer.logical_for_host_path(arena / 'inc')}"]
            if mirror_active:
                mirror_parent = arena / "inc" / "source"
                if parent != ".":
                    mirror_parent = mirror_parent.joinpath(*PurePosixPath(parent).parts)
                expected_directories.append(
                    "inc/source" if parent == "." else f"inc/source/{parent}"
                )
                private_includes.append(f"/I{self.producer.logical_for_host_path(mirror_parent)}")
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
                visible = self.producer.compiler_visible_path(include_value)
                include_path = self.producer._logical_drive_root.joinpath(
                    *_logical_relative_parts(
                        visible,
                        drive_letter=self.producer._logical_drive_letter,
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
                        command.extend((token, self.producer.logical_for_host_path(mirrored)))
                    else:
                        command.append(
                            f"{token[:2]}{self.producer.logical_for_host_path(mirrored)}"
                        )
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

    def _replay_donor_dependencies(
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
        compiler_epoch: ClassicActiveCompilerEpoch,
    ) -> ClassicWarmDonorDependencyReplay:
        """Run one discarded `/Fr` command without changing canonical outputs."""

        diagnostic_object = arena / ".reprobit-donor-dependencies.obj"
        diagnostic_pdb = arena / ".reprobit-donor-dependencies.pdb"
        diagnostic_sbr = arena / ".reprobit-donor-dependencies.sbr"
        outputs = (diagnostic_object, diagnostic_pdb, diagnostic_sbr)
        try:
            try:
                parsed = validate_compile_arguments(list(command))
            except Exception as exc:
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"canonical donor argv cannot be replayed: {exc}",
                )
            if any(argument.casefold().startswith(("/fr", "-fr")) for argument in command[1:-1]):
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    "canonical donor argv already contains /Fr",
                )
            object_index = cast(tuple[int, str, bool], parsed["Fo"])[0]
            pdb_index = cast(tuple[int, str, bool], parsed["Fd"])[0]
            arguments = list(command)
            arguments[object_index] = f"/Fo{self.producer.logical_for_host_path(diagnostic_object)}"
            arguments[pdb_index] = f"/Fd{self.producer.logical_for_host_path(diagnostic_pdb)}"
            arguments.insert(
                len(arguments) - 1,
                f"/Fr{self.producer.logical_for_host_path(diagnostic_sbr)}",
            )
            try:
                result, _spec = _run(
                    supervisor,
                    tuple(arguments),
                    cwd=self.producer.producer_cwd(lane, arena),
                    environment=lane.environment,
                    timeout=timeout,
                    log=(self.session_root / "logs" / "donor-dependencies" / f"{step_id}.log"),
                    cancellation=cancellation,
                    windows_lineage_planner=lane.windows_lineage_planner,
                )
            except CommandFailed as exc:
                cancellation.raise_if_cancelled()
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency replay failed: {exc}",
                )
            if not result.succeeded:
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    "discarded donor dependency replay returned "
                    f"{result.returncode}: {result.output_tail}",
                )
            try:
                actual_sbr = self.producer.compiler_companion_output(diagnostic_sbr)
                trace = parse_msvc_sbr(actual_sbr.read_bytes())
            except (ClassicProjectError, OSError, ValueError) as exc:
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency trace is unusable: {exc}",
                )
            try:
                authority = self.producer.donor_authority(
                    compiler_epoch.include_authority,
                    arena=arena,
                    arena_seal=arena_seal,
                )
                working_directory = self.producer.logical_for_host_path(arena)
                source = _logical_join(working_directory, cast(str, parsed["source_token"]))
                reads = resolve_msvc_include_trace(
                    trace,
                    expected_working_directory=working_directory,
                    expected_source=source,
                    include_directories=tuple(
                        cast(tuple[int, str, bool], item)[1]
                        for item in cast(Sequence[object], parsed["include_paths"])
                    ),
                    environment_directories=self.producer.include_environment_directories(
                        lane.environment
                    ),
                    force_includes=tuple(
                        cast(tuple[int, str, bool], item)[1]
                        for item in cast(Sequence[object], parsed["force_includes"])
                    ),
                    authority=authority,
                )
            except (ClassicIncludeTraceError, ClassicProjectError, ValueError) as exc:
                return ClassicWarmDonorDependencyReplay(
                    donor_id,
                    None,
                    (),
                    f"discarded donor dependency trace cannot be resolved: {exc}",
                )
            return ClassicWarmDonorDependencyReplay(donor_id, trace, reads, None)
        finally:
            _erase_donor_dependency_outputs(outputs)

    def invoke_donor_compiler(
        self,
        supervisor: ProcessSupervisor,
        unit: ClassicPreparedUnit,
        donor_index: int,
        cancellation: CancellationToken,
        *,
        step_id: str,
        compiler_epoch: ClassicActiveCompilerEpoch,
        capture_dependencies: bool = False,
    ) -> _DonorCompilerInvocation:
        """Run the one normal private donor lane without issuing evidence."""

        self._started = True
        donor = unit.donors[donor_index]
        record = self.record_for_donor(unit, donor_index)
        marker_stem = f"composed-{unit.plan.build_target}-{unit.plan.source.replace('/', '_')}"
        donor_root = self.build_root.parent / "donors"
        if donor_root.is_symlink() or not donor_root.is_dir():
            raise ClassicProjectError("classic donor arena root is absent or redirected")
        compiler_seat = _safe_relative(donor.request.compiler_seat)
        if len(PurePosixPath(compiler_seat).parts) != 1:
            raise ClassicProjectError("classic donor compiler seat is not one path component")
        arena = donor_root / f"{marker_stem}-{compiler_seat}"
        arena.mkdir(exist_ok=False)
        if donor.request.compiler_additions.include_projection is not DonorIncludeProjection.NONE:
            shutil.copytree(self.effective_root, arena / "inc" / "source")
        elif donor.request.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
            (arena / "inc").mkdir()
        for relative, payload in donor.request.files.items():
            path = arena.joinpath(*PurePosixPath(_safe_relative(relative)).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
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
        lane = self.producer.lane_pool.acquire()
        donor_namespace_snapshot: SealedNamespaceSnapshot
        dependency_replay: ClassicWarmDonorDependencyReplay | None = None
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
                    cwd=self.producer.producer_cwd(lane, arena),
                    environment=lane.environment,
                    timeout=timeout,
                    log=self.session_root / "logs" / "donors" / f"{step_id}.log",
                    cancellation=cancellation,
                    windows_lineage_planner=lane.windows_lineage_planner,
                )
                dependency_tracked = donor_requires_dependency_tracking(
                    donor.request,
                    owning_build_target=unit.plan.build_target,
                    owning_logical_source=unit.plan.source,
                )
                if capture_dependencies and dependency_tracked:
                    self.producer.require_regular(
                        donor_object,
                        label=f"donor {donor.intervention.id!r} canonical object",
                    )
                    self.producer.require_regular(
                        donor_pdb,
                        label=f"donor {donor.intervention.id!r} canonical PDB",
                    )
                    canonical_object = donor_object.read_bytes()
                    canonical_pdb = donor_pdb.read_bytes()
                    dependency_replay = self._replay_donor_dependencies(
                        supervisor,
                        donor_id=donor.intervention.id,
                        command=command,
                        arena=arena,
                        arena_seal=before,
                        lane=lane,
                        timeout=timeout,
                        step_id=step_id,
                        cancellation=cancellation,
                        compiler_epoch=compiler_epoch,
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
            self.producer.lane_pool.release(lane)
        self.producer.require_regular(donor_object, label=f"donor {donor.intervention.id!r} object")
        self.producer.require_regular(donor_pdb, label=f"donor {donor.intervention.id!r} PDB")
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
        compiler_epoch: ClassicActiveCompilerEpoch,
        dependency_replays: list[ClassicWarmDonorDependencyReplay] | None = None,
    ) -> tuple[
        _ClassicDonorSemanticMaterial,
        tuple[StepExecutionReceipt, ...],
        InterventionWitness,
    ]:
        donor = unit.donors[donor_index]
        invocation = self.invoke_donor_compiler(
            supervisor,
            unit,
            donor_index,
            cancellation,
            step_id=f"donor.{unit.plan.id}.{donor_index:04d}",
            compiler_epoch=compiler_epoch,
            capture_dependencies=dependency_replays is not None,
        )
        dependency_tracked = donor_requires_dependency_tracking(
            donor.request,
            owning_build_target=unit.plan.build_target,
            owning_logical_source=unit.plan.source,
        )
        if dependency_replays is not None and dependency_tracked:
            if invocation.dependency_replay is None:
                raise ClassicProjectError(
                    f"dependency-tracked donor {donor.intervention.id!r} omitted its warm replay"
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
        shared_namespace_id = compiler_epoch.namespace_id
        shared_namespace = self.producer.compiler_namespaces().get(shared_namespace_id)
        if shared_namespace is None:
            raise ClassicProjectError("donor compiler namespace receipt is absent")
        donor_reads = tuple(
            ClassicProducerRead(
                self.producer.logical_for_host_path(item.path),
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
            self.producer.logical_for_host_path(donor_object),
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
        semantic_material = _ClassicDonorSemanticMaterial(
            intervention=donor.intervention,
            donor_object=payload,
            source_inputs=donor.request.files,
            compiler_statement=compile_statement,
            _issuer=_CLASSIC_SEMANTIC_ISSUER,
        )
        self._progress.emit("donor-compile", step_id)
        self._progress.emit("input-namespace", namespace_step.step_id)
        return (
            semantic_material,
            step_receipts,
            InterventionWitness(
                donor.intervention.id,
                donor.intervention.scope.target,
                donor_evidence,
            ),
        )

    def compose_unit(
        self,
        supervisor: ProcessSupervisor,
        unit: ClassicPreparedUnit,
        cancellation: CancellationToken,
        *,
        compiler_epoch: ClassicActiveCompilerEpoch,
        dependency_replays: list[ClassicWarmDonorDependencyReplay] | None = None,
    ) -> tuple[ClassicCompileRecord, list[StepExecutionReceipt], list[InterventionWitness]]:
        record = self.record_for_unit(unit)
        self.producer.require_regular(record.object_path, label=f"seed object for {unit.plan.id!r}")
        if record.pdb_path.is_symlink():
            raise ClassicProjectError(f"seed PDB is redirected: {record.pdb_path}")
        seed = record.object_path.read_bytes()
        steps: list[StepExecutionReceipt] = []
        donor_witnesses: list[InterventionWitness] = []
        donor_materials: dict[str, _ClassicDonorSemanticMaterial] = {}
        for donor_index in range(len(unit.donors)):
            material, receipts, witness = self._compile_donor(
                supervisor,
                unit,
                donor_index,
                cancellation,
                compiler_epoch=compiler_epoch,
                dependency_replays=dependency_replays,
            )
            donor_id = material.intervention.id
            if donor_id in donor_materials:
                raise ClassicProjectError(f"compiled donor identity repeats: {donor_id!r}")
            donor_materials[donor_id] = material
            steps.extend(receipts)
            donor_witnesses.append(witness)
        started = time.monotonic()
        composition = compose_classic_unit(
            unit,
            seed_object=seed,
            donor_materials=donor_materials,
            seed_source=record.source.read_bytes(),
            legacy_oracles=self._legacy_oracles,
        )
        object_transform: ClassicObjectTransformReceipt | None = None
        if composition.group_order_evidence is not None:
            if (
                unit.plan.group_order is None
                or composition.group_order_input_digest is None
                or composition.group_order_input_size is None
            ):
                raise ClassicProjectError("group-order composition receipt is incomplete")
            operation = unit.plan.group_order.operation
            compiler_node = next(
                (item for item in self.graph.nodes if item.id == record.node_id),
                None,
            )
            if compiler_node is None:
                raise ClassicProjectError("group-order unit lacks its compiler node")
            _source_reference, object_reference = classic_compiler_product_refs(compiler_node)
            object_transform = ClassicObjectTransformReceipt(
                unit.plan.id,
                object_reference,
                f"compose.{unit.plan.id}",
                operation,
                composition.group_order_input_digest,
                composition.group_order_input_size,
                Digest.from_bytes(composition.output),
                len(composition.output),
                composition.group_order_evidence,
            )
        elif unit.plan.group_order is not None:
            raise ClassicProjectError("group-order composition omitted its receipt")
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
                        Digest.from_bytes(donor_materials[donor_id].donor_object),
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
        if object_transform is not None:
            with self._evidence_lock:
                self._object_transforms.append(object_transform)
        self._progress.emit("compose", f"compose.{unit.plan.id}")
        return record, steps, [*donor_witnesses, *composition.witnesses]


__all__ = [
    "ClassicDonorComposition",
    "ClassicWarmDonorDependencyReplay",
]
