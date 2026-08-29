"""Warm incremental execution and non-certifying classic probes."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import TYPE_CHECKING, Literal

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
from reprobit.classic_runtime_graph import (
    ClassicCompileRecord,
    ClassicProducerTarget,
    classic_compiler_product_refs,
)
from reprobit.execution import (
    StepExecutionReceipt,
)
from reprobit.model import Digest
from reprobit.process import (
    CancellationToken,
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
from reprobit.secure_paths import (
    SecureFileSnapshot,
    SecurePathError,
    atomic_publish_relative,
    canonical_system_path,
    digest_relative_file,
)

if TYPE_CHECKING:
    from reprobit.incremental_executor import PreparedNodeInputs


from reprobit.classic_runtime_donor import (
    ClassicDonorComposition,
    ClassicWarmDonorDependencyReplay,
)
from reprobit.classic_runtime_overlay import (
    ClassicActiveCompilerEpoch,
    ClassicOverlayEpochs,
)
from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
    _erase_warm_replay_arena,
    _internal_step,
    _require_declared_tree_writes,
    _require_unchanged_tree,
    _safe_relative,
    _secure_copy_new,
    _secure_remove_regular,
    _step_receipt,
    _tree_file_seal,
)


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


class ClassicDeveloperExecution:
    """Own non-certifying warm execution and bounded compiler probes."""

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

    def close_all(self) -> None:
        try:
            self.close()
        finally:
            self.producer.close()

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
            for name, source in (("image", execution.image), ("pdb", execution.pdb)):
                destination = outputs[name]
                if self._warm_staging_root is None:
                    raise ClassicProjectError("classic warm staging root is not bound")
                try:
                    Path(os.path.abspath(destination)).relative_to(self._warm_staging_root)
                except ValueError as exc:
                    raise ClassicProjectError(
                        f"classic warm analysis output escapes its run: {destination}"
                    ) from exc
                _secure_copy_new(source, destination)
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
        record, steps, _witnesses = self.donors.compose_unit(
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
                except Exception as exc:
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

        if not self.producer.is_open:
            raise ClassicProjectError("classic compiler probe requires one unused prepared run")
        self.producer.begin_developer()
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
            node.role is not ProducerRole.COMPILER or node.id in self.overlay.generated_node_inputs
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
            if source_epoch == "effective" and self.overlay.overlay_witnesses:
                self.overlay.materialize_certified_project_overlay_epoch(source_before)
            elif source_epoch == "clean" and self.overlay.overlay_witnesses:
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
                self.close_all()
            except BaseException as cleanup_error:
                original.add_note(f"classic compiler probe cleanup also failed: {cleanup_error}")
            raise
        receipts: list[StepExecutionReceipt] = []
        try:
            with ExitStack() as stack, ProcessSupervisor() as supervisor:
                authority = stack.enter_context(self.producer.authority_namespace_lease())
                source = stack.enter_context(self.producer.source_namespace_lease())
                namespace = self.producer.capture_compiler_namespace(
                    f"noncertifying-probe-{source_epoch}",
                    source=source.snapshot,
                    authority=authority.snapshot,
                )
                completed: set[str] = set()
                output_steps: dict[Path, str] = {}
                receipts.extend(
                    self.producer.run_graph_nodes(
                        supervisor,
                        selected,
                        completed=completed,
                        output_steps=output_steps,
                        cancellation=CancellationToken(),
                        step_id_prefix="probe.",
                        progress_phase="compiler-probe",
                        log_namespace="compiler-probe",
                        include_authority=self.producer.include_authority(),
                        include_trace_epoch=f"probe-{source_epoch}",
                        compiler_namespace_id=namespace.evidence.namespace_id,
                    )
                )
                if completed != selected_ids:
                    raise ClassicProjectError("classic compiler probe execution was incomplete")
            _require_declared_tree_writes(
                build_before,
                root=self.build_root,
                allowed_outputs=(
                    path for node in selected for path in self.producer.node_outputs(node)
                ),
                phase="classic compiler probe",
            )
            producer_steps = {
                receipt.step_id: receipt
                for receipt in receipts
                if receipt.step_id.startswith("probe.")
            }
            outputs: list[ClassicCompilerProbeOutput] = []
            for node in selected:
                source_ref, object_ref = classic_compiler_product_refs(node)
                pdb_refs = tuple(
                    reference
                    for reference in node.outputs
                    if PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold() == ".pdb"
                )
                if len(pdb_refs) != 1:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} lacks one PDB output"
                    )
                object_declared = self.producer.reference(object_ref)
                pdb_declared = self.producer.reference(pdb_refs[0])
                if object_declared is None or pdb_declared is None:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} output is not materializable"
                    )
                registered_outputs = self.producer.registered_outputs()
                object_path = registered_outputs.get(object_declared)
                pdb_path = registered_outputs.get(pdb_declared)
                if object_path is None or pdb_path is None:
                    raise ClassicProjectError(
                        f"compiler probe node {node.id!r} lacks physical outputs"
                    )
                self.producer.require_regular(object_path, label="compiler probe OBJ")
                self.producer.require_regular(pdb_path, label="compiler probe PDB")
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
            self.close_all()

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

        if not self.producer.is_open:
            raise ClassicProjectError("classic donor probe requires one unused prepared run")
        self.producer.begin_developer()

        try:
            requested = tuple(donor_ids)
            if not requested or len(requested) != len(set(requested)):
                raise ClassicProjectError("classic donor probe requires unique selected donor IDs")
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
            if self.overlay.overlay_witnesses:
                _, source_seal = self.overlay.materialize_certified_project_overlay_epoch(
                    source_seal
                )
                if self.overlay.generated_translation_units:
                    _, source_seal = self.overlay.materialize_generated_input_epoch(source_seal)
            _require_unchanged_tree(
                source_seal,
                root=self.effective_root,
                label="donor compiler probe source epoch",
            )

            outputs: list[ClassicDonorProbeOutput] = []
            with ExitStack() as stack, ProcessSupervisor() as supervisor:
                authority = stack.enter_context(self.producer.authority_namespace_lease())
                source = stack.enter_context(self.producer.source_namespace_lease())
                namespace = self.producer.capture_compiler_namespace(
                    "noncertifying-donor-probe",
                    source=source.snapshot,
                    authority=authority.snapshot,
                )
                compiler_epoch = ClassicActiveCompilerEpoch(
                    namespace.evidence.namespace_id,
                    self.producer.include_authority(),
                    source_seal,
                    bool(self.overlay.generated_translation_units),
                )
                cancellation = CancellationToken()
                for ordinal, donor_id in enumerate(requested):
                    unit, donor_index = prepared[donor_id]
                    donor = unit.donors[donor_index]
                    invocation = self.donors.invoke_donor_compiler(
                        supervisor,
                        unit,
                        donor_index,
                        cancellation,
                        step_id=f"probe.donor.{ordinal:04d}.{donor_id}",
                        compiler_epoch=compiler_epoch,
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
                self.close_all()
            except BaseException as cleanup_error:
                original.add_note(f"classic donor probe cleanup also failed: {cleanup_error}")
            raise
        self.close_all()
        return tuple(outputs)


__all__ = [
    "ClassicCompilerProbeOutput",
    "ClassicDeveloperExecution",
    "ClassicDonorProbeInput",
    "ClassicDonorProbeOutput",
    "ClassicWarmCompilerReplay",
    "ClassicWarmCompilerTransformResult",
]
