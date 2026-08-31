"""Warm incremental execution for classic producer graphs."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import TYPE_CHECKING

from reprobit.binary import ByteIdentityError
from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
from reprobit.classic_includes import (
    MsvcSbrTrace,
    parse_msvc_sbr,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    apply_classic_terminal_pipeline,
    classic_rdata_repack,
)
from reprobit.classic_project import (
    ClassicProjectError,
)
from reprobit.classic_runtime_environment import (
    _run,
)
from reprobit.classic_runtime_files import (
    _safe_relative,
    _secure_remove_regular,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
    ClassicCompileRecord,
    ClassicProducerTarget,
)
from reprobit.execution import (
    StepExecutionReceipt,
)
from reprobit.model import Digest
from reprobit.msvc42_debug_companion import stabilize_msvc42_debug_companion
from reprobit.process import (
    CancellationToken,
    CommandFailed,
    ProcessSupervisor,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
)
from reprobit.schema import (
    ClassicRecipeIntervention,
    ProjectBundle,
)
from reprobit.sealed_namespace import (
    SealedNamespaceLease,
)
from reprobit.secure_path_contracts import (
    SecureFileIdentity,
    SecureFileSnapshot,
    SecurePathError,
    canonical_system_path,
)
from reprobit.secure_paths import (
    atomic_copy_new_relative,
    atomic_publish_new_relative,
    atomic_publish_relative,
    digest_relative_file,
    read_relative_file,
    stat_relative_file,
)

if TYPE_CHECKING:
    from reprobit.incremental_executor import PreparedNodeInputs, ReceiptBoundInput


from reprobit.classic_runtime_donor import (
    ClassicDonorComposition,
    ClassicWarmDonorDependencyReplay,
)
from reprobit.classic_runtime_overlay import ClassicOverlayEpochs
from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
)
from reprobit.classic_runtime_receipts import (
    _internal_step,
    _step_receipt,
)


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
            raise ClassicProjectError("classic warm dependency copy differs from its cache receipt")
        return received
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(
            f"classic warm copy could not safely publish {destination}: {exc}"
        ) from exc


def _secure_read_bytes(path: Path) -> bytes:
    """Read one absolute run-private file without following path redirects."""

    absolute = canonical_system_path(path)
    if not absolute.anchor:
        raise ClassicProjectError("classic warm read requires an absolute path")
    root = Path(absolute.anchor)
    relative = PurePosixPath(*absolute.parts[1:]).as_posix()
    try:
        payload, _snapshot = read_relative_file(root, relative)
        return payload
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(f"classic warm read is unsafe for {absolute}: {exc}") from exc


def _secure_publish_new_bytes(payload: bytes, destination: Path) -> SecureFileSnapshot:
    """Create one canonical warm output without a mutable temporary file."""

    absolute = canonical_system_path(destination)
    if not absolute.anchor:
        raise ClassicProjectError("classic warm publication requires an absolute path")
    root = Path(absolute.anchor)
    relative = PurePosixPath(*absolute.parts[1:]).as_posix()
    try:
        return atomic_publish_new_relative(root, relative, payload)
    except (OSError, SecurePathError) as exc:
        raise ClassicProjectError(
            f"classic warm bytes could not safely publish {absolute}: {exc}"
        ) from exc


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


@dataclass(frozen=True, slots=True)
class ClassicWarmCompilerReplay:
    """Dependency-only result from a discarded `/Fr` compiler invocation."""

    trace: MsvcSbrTrace | None
    reason: str | None

    def __post_init__(self) -> None:
        if (self.trace is None) == (self.reason is None):
            raise ClassicProjectError(
                "classic warm compiler replay requires exactly one result state"
            )


@dataclass(frozen=True, slots=True)
class ClassicWarmCompilerTransformResult:
    """Warm transform receipts plus discarded projected-donor diagnostics."""

    steps: tuple[StepExecutionReceipt, ...]
    donor_dependencies: tuple[ClassicWarmDonorDependencyReplay, ...]
    provisional_repair: bool = False


class ClassicWarmExecution:
    """Own cacheable warm execution within one prepared producer runtime."""

    def __init__(
        self,
        *,
        bundle: ProjectBundle,
        project_root: Path,
        session_root: Path,
        build_root: Path,
        effective_root: Path,
        graph: ProducerGraphDocument,
        targets: Sequence[ClassicProducerTarget],
        compile_records: Sequence[ClassicCompileRecord],
        units: Sequence[ClassicPreparedUnit],
        producer: ClassicProducerExecution,
        overlay: ClassicOverlayEpochs,
        donors: ClassicDonorComposition,
    ) -> None:
        self.bundle = bundle
        self.project_root = project_root
        self.session_root = session_root
        self.build_root = build_root
        self.effective_root = effective_root
        self.graph = graph
        self.targets = tuple(targets)
        self.compile_records = tuple(compile_records)
        self.units = tuple(units)
        self.producer = producer
        self.overlay = overlay
        self.donors = donors
        self._warm_lock = Lock()
        self._warm_stack: ExitStack | None = None
        self._warm_supervisor: ProcessSupervisor | None = None
        self._warm_authority_namespace: SealedNamespaceLease | None = None
        self._warm_source_namespace: SealedNamespaceLease | None = None
        self._warm_active_epoch: ClassicActiveCompilerEpoch | None = None
        self._warm_staging_root: Path | None = None

    def close(self) -> None:
        warm_stack = self._warm_stack
        self._warm_stack = None
        self._warm_supervisor = None
        self._warm_authority_namespace = None
        self._warm_source_namespace = None
        self._warm_active_epoch = None
        self._warm_staging_root = None
        if warm_stack is not None:
            warm_stack.close()

    def _warm_node(self, node_id: str) -> ProducerNode:
        matches = tuple(node for node in self.graph.nodes if node.id == node_id)
        if len(matches) != 1:
            raise ClassicProjectError(f"classic warm execution names an unknown node: {node_id!r}")
        return matches[0]

    def bind_warm_staging_root(self, root: Path) -> None:
        """Bind the independent run-private destination for cacheable outputs."""

        if not self.producer.is_open or self._warm_staging_root:
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
    ) -> tuple[ProcessSupervisor, ClassicActiveCompilerEpoch]:
        """Open or advance the non-certifying warm producer source epoch."""

        with self._warm_lock:
            self.producer.begin_developer()
            if not self.producer.is_open:
                raise ClassicProjectError("classic warm execution requires one unused prepared run")
            if self._warm_stack is None:
                stack = ExitStack()
                try:
                    source_seal = _tree_file_seal(self.effective_root)
                    if self.overlay.overlay_witnesses:
                        _, source_seal = self.overlay.materialize_certified_project_overlay_epoch(
                            source_seal
                        )
                    supervisor = stack.enter_context(ProcessSupervisor())
                    authority = stack.enter_context(self.producer.authority_namespace_lease())
                    source = stack.enter_context(self.producer.source_namespace_lease())
                    namespace = self.producer.capture_compiler_namespace(
                        "noncertifying-warm-effective",
                        source=source.snapshot,
                        authority=authority.snapshot,
                    )
                    include_authority = self.producer.include_authority()
                except BaseException:
                    stack.close()
                    raise
                self._warm_stack = stack
                self._warm_supervisor = supervisor
                self._warm_authority_namespace = authority
                self._warm_source_namespace = source
                self._warm_active_epoch = ClassicActiveCompilerEpoch(
                    namespace.evidence.namespace_id,
                    include_authority,
                    source_seal,
                    False,
                )

            assert self._warm_active_epoch is not None
            if generated is True and not self._warm_active_epoch.generated:
                if not self.overlay.generated_translation_units:
                    raise ClassicProjectError(
                        "classic warm execution requested an empty generated epoch"
                    )
                assert self._warm_stack is not None
                assert self._warm_authority_namespace is not None
                assert self._warm_source_namespace is not None
                self._warm_source_namespace.close()
                _, generated_seal = self.overlay.materialize_generated_input_epoch(
                    self._warm_active_epoch.source_seal
                )
                source = self._warm_stack.enter_context(self.producer.source_namespace_lease())
                namespace = self.producer.capture_compiler_namespace(
                    "noncertifying-warm-generated",
                    source=source.snapshot,
                    authority=self._warm_authority_namespace.snapshot,
                )
                include_authority = self.producer.include_authority()
                self._warm_source_namespace = source
                self._warm_active_epoch = ClassicActiveCompilerEpoch(
                    namespace.evidence.namespace_id,
                    include_authority,
                    generated_seal,
                    True,
                )
            elif generated is False and self._warm_active_epoch.generated:
                raise ClassicProjectError(
                    "classic warm execution cannot return to the ordinary source epoch"
                )

            assert self._warm_supervisor is not None
            return self._warm_supervisor, self._warm_active_epoch

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
                destination = self.producer.reference(reference)
                if destination is None:
                    raise ClassicProjectError(
                        f"classic warm input is not materializable: {reference!r}"
                    )
                source = bound.snapshot.path
                self.producer.require_regular(source, label="classic warm staged input")
                if os.path.lexists(destination):
                    self.producer.require_regular(destination, label="classic warm logical input")
                    destination_root = Path(canonical_system_path(destination).anchor)
                    destination_relative = PurePosixPath(
                        *canonical_system_path(destination).parts[1:]
                    ).as_posix()
                    received = digest_relative_file(destination_root, destination_relative)
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
                    physical = _secure_copy_new(source, destination, expected=bound).path.resolve(
                        strict=True
                    )
                declared = destination.resolve(strict=False)
                self.producer.bind_cached_output(declared, physical)

    def verify_warm_authority(self) -> None:
        """Revalidate active readable namespaces before a warm cache store."""

        with self._warm_lock:
            if not self.producer.is_open:
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
        physical = self.producer.node_outputs(node)
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
        supervisor, active_epoch = self._warm_epoch(
            generated=(
                node.id in self.overlay.generated_node_inputs
                if node.role is ProducerRole.COMPILER
                else False
                if node.role is ProducerRole.RESOURCE
                else None
            )
        )
        self._materialize_warm_inputs(inputs)
        receipts = self.producer.run_node(
            supervisor,
            node,
            cancellation,
            receipt_step_id=f"warm.{node.id}",
            log_namespace="warm-producers",
            include_authority=(
                active_epoch.include_authority
                if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
                else None
            ),
            include_trace_epoch=(
                f"warm-{'generated' if active_epoch.generated else 'effective'}"
                if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
                else None
            ),
            compiler_namespace_id=(
                active_epoch.namespace_id if node.role is ProducerRole.COMPILER else None
            ),
        )
        self._copy_warm_outputs(node, outputs)
        if node.role is ProducerRole.COMPILER:
            declared = self.producer.declared_outputs(node)
            physical = self.producer.node_outputs(node)
            for path in physical:
                _secure_remove_regular(path)
            for path in declared:
                self.producer.clear_output(path)
        return receipts

    def execute_warm_analysis_link(
        self,
        target_id: str,
        *,
        inputs: PreparedNodeInputs,
        outputs: Mapping[str, Path],
        certified_image: Path,
        cancellation: CancellationToken,
    ) -> StepExecutionReceipt:
        """Run one cache-missing analysis relink into paired warm outputs."""

        targets = tuple(target for target in self.targets if target.target_id == target_id)
        if len(targets) != 1:
            raise ClassicProjectError(
                f"classic warm analysis relink names an unknown target: {target_id!r}"
            )
        target = targets[0]
        node = self._warm_node(target.link_node_id)
        expected_inputs = {reference for reference in node.inputs if reference.startswith("build/")}
        if set(inputs.entries) != expected_inputs or set(outputs) != {"image", "pdb"}:
            raise ClassicProjectError(
                f"classic warm analysis relink {target_id!r} has an invalid input/output pair"
            )
        supervisor, _active_epoch = self._warm_epoch(generated=None)
        self._materialize_warm_inputs(inputs)
        step_id = f"warm.analysis-link.{target_id}"
        execution = self.producer.execute_private_analysis_link(
            supervisor,
            target,
            node,
            cancellation,
            log_namespace="warm-analysis-link",
        )
        try:
            try:
                stabilized = stabilize_msvc42_debug_companion(
                    _secure_read_bytes(certified_image),
                    _secure_read_bytes(execution.image),
                    _secure_read_bytes(execution.pdb),
                    expected_pdb_path=self.producer.logical_for_host_path(execution.plan.pdb),
                )
            except ByteIdentityError as exc:
                raise ClassicProjectError(
                    f"warm analysis relink {target_id!r} is not a valid MSVC 4.2 "
                    f"debug companion: {exc}"
                ) from exc
            for name, payload in (("image", stabilized.image), ("pdb", stabilized.pdb)):
                destination = outputs[name]
                if self._warm_staging_root is None:
                    raise ClassicProjectError("classic warm staging root is not bound")
                try:
                    Path(os.path.abspath(destination)).relative_to(self._warm_staging_root)
                except ValueError as exc:
                    raise ClassicProjectError(
                        f"classic warm analysis output escapes its run: {destination}"
                    ) from exc
                _secure_publish_new_bytes(payload, destination)
        finally:
            for path in execution.private_files:
                if os.path.lexists(path):
                    _secure_remove_regular(path)
            execution.plan.arena.rmdir()
        return _step_receipt(step_id, execution.result, execution.spec)

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
    ) -> ClassicWarmCompilerTransformResult:
        """Apply one TU's reviewed composition and object transforms."""

        node = self._warm_node(compiler_node_id)
        if node.role is not ProducerRole.COMPILER or set(inputs.entries) != set(node.outputs):
            raise ClassicProjectError(
                f"classic warm transform {compiler_node_id!r} has invalid raw inputs"
            )
        supervisor, active_epoch = self._warm_epoch(
            generated=node.id in self.overlay.generated_node_inputs
        )
        self._materialize_warm_inputs(inputs)
        unit = self._warm_unit(compiler_node_id)
        donor_dependencies: list[ClassicWarmDonorDependencyReplay] = []
        record, steps, _witnesses, provisional_repair = self.donors.compose_unit(
            supervisor,
            unit,
            cancellation,
            compiler_epoch=active_epoch,
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
        return ClassicWarmCompilerTransformResult(
            tuple(steps),
            tuple(sorted(donor_dependencies, key=lambda item: item.donor_id.casefold())),
            provisional_repair,
        )

    def replay_warm_compiler_dependencies(
        self,
        compiler_node_id: str,
        *,
        cancellation: CancellationToken,
    ) -> ClassicWarmCompilerReplay:
        """Run and discard one `/Fr` invocation used only as a cache hint."""

        node = self._warm_node(compiler_node_id)
        if node.role is not ProducerRole.COMPILER:
            raise ClassicProjectError("classic warm dependency replay requires a compiler node")
        supervisor, _active_epoch = self._warm_epoch(
            generated=node.id in self.overlay.generated_node_inputs
        )
        replay_root = self.build_root / ".reprobit-warm-replay"
        replay_root.mkdir(exist_ok=True)
        arena = replay_root / sha256(node.id.encode("utf-8")).hexdigest()[:20]
        arena.mkdir(exist_ok=False)
        try:
            object_path = arena / "discard.obj"
            pdb_path = arena / "discard.pdb"
            sbr_path = arena / "dependencies.sbr"
            object_logical = self.producer.logical_for_host_path(object_path)
            pdb_logical = self.producer.logical_for_host_path(pdb_path)
            sbr_logical = self.producer.logical_for_host_path(sbr_path)
            arguments: list[str] = []
            object_count = 0
            pdb_count = 0
            for argument in self.producer.node_arguments(node):
                folded = argument.casefold()
                if folded.startswith(("/fr", "-fr")):
                    return ClassicWarmCompilerReplay(
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
                return ClassicWarmCompilerReplay(
                    None, "compiler replay could not isolate exactly one OBJ/PDB pair"
                )
            arguments.append(f"/Fr{sbr_logical}")
            lane = self.producer.lane_pool.acquire()
            try:
                try:
                    result, _spec = _run(
                        supervisor,
                        (str(self.producer.role_commands[ProducerRole.COMPILER]), *arguments),
                        cwd=self.producer.producer_cwd(lane, self.build_root),
                        environment=lane.environment,
                        timeout=self.producer.compile_timeout,
                        log=(
                            self.session_root / "logs" / "warm-dependency-replay" / f"{node.id}.log"
                        ),
                        cancellation=cancellation,
                        windows_lineage_planner=(lane.windows_lineage_planner),
                    )
                except CommandFailed as exc:
                    cancellation.raise_if_cancelled()
                    return ClassicWarmCompilerReplay(
                        None, f"discarded compiler replay failed: {exc}"
                    )
            finally:
                self.producer.lane_pool.release(lane)
            if not result.succeeded:
                return ClassicWarmCompilerReplay(
                    None,
                    f"discarded compiler replay returned {result.returncode}: {result.output_tail}",
                )
            try:
                actual_sbr = self.producer.compiler_companion_output(sbr_path)
                trace = parse_msvc_sbr(actual_sbr.read_bytes())
            except (OSError, ValueError) as exc:
                return ClassicWarmCompilerReplay(
                    None, f"discarded compiler replay trace is unusable: {exc}"
                )
            # The replay OBJ/PDB are deliberately neither registered nor
            # returned.  Their different bytes can never substitute for the
            # normal invocation.
            return ClassicWarmCompilerReplay(trace, None)
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
        self.producer.require_regular(target.output, label="classic warm linked image")
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


__all__ = [
    "ClassicWarmCompilerReplay",
    "ClassicWarmCompilerTransformResult",
    "ClassicWarmExecution",
]
