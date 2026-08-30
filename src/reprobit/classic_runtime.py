"""Certifying orchestration and publication for classic producer graphs."""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

from reprobit.binary import ByteIdentityError
from reprobit.build import BuildPlan
from reprobit.classic.semantic_contracts import (
    revalidate_classic_validator_implementation,
)
from reprobit.classic_evidence import (
    CLASSIC_RUNTIME_EVIDENCE_PROVIDER_ID,
    assemble_classic_runtime_evidence,
)
from reprobit.classic_execution_records import (
    ClassicActiveCompilerEpoch,
    ClassicProducedDebugCompanion,
    ClassicProducedImage,
    ClassicProducerGraphExecutionRecord,
    ClassicRuntimeEvidenceInputs,
)
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
    apply_classic_terminal_pipeline,
    classic_rdata_repack,
)
from reprobit.classic_project import (
    ClassicProjectError,
    InterventionWitness,
    _effective_source_seal,
)
from reprobit.classic_publication import (
    ClassicPublicationError,
    ClassicPublicationRequest,
    publish_classic_output_set,
)
from reprobit.classic_runtime_environment import (
    _toolchain_tree_files,
)
from reprobit.classic_runtime_files import (
    _digest_path,
    _require_declared_tree_writes,
    _require_unchanged_tree,
    _safe_relative,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
    ClassicCompileRecord,
    ClassicProducerTarget,
)
from reprobit.execution import (
    BuildExecutionReceipt,
    FileReceipt,
    RuntimeEvidence,
    RuntimeEvidenceContext,
    StepExecutionReceipt,
)
from reprobit.model import Digest
from reprobit.msvc42_debug_companion import (
    StabilizedMsvc42DebugCompanion,
    stabilize_msvc42_debug_companion,
)
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
    classic_debug_companion_paths,
)
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths import reseal_relative_file

if TYPE_CHECKING:
    pass


from reprobit.classic_runtime_donor import ClassicDonorComposition
from reprobit.classic_runtime_overlay import ClassicOverlayEpochs
from reprobit.classic_runtime_producer import (
    ClassicAnalysisLinkExecution,
    ClassicProducerExecution,
    ClassicProgressReporter,
)
from reprobit.classic_runtime_receipts import (
    _internal_step,
    _receipt,
    _step_receipt,
)


@dataclass(frozen=True, slots=True)
class _ClassicPendingImage:
    """Validated terminal bytes awaiting coordinated target-set publication."""

    target: ClassicProducerTarget
    logical_path: str
    payload: bytes
    witnesses: tuple[InterventionWitness, ...]
    raw_digest: Digest
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class _ClassicPendingDebugCompanion:
    """Validated private diagnostic pair awaiting canonical publication."""

    target: ClassicProducerTarget
    logical_image_path: str
    logical_pdb_path: str
    execution: ClassicAnalysisLinkExecution
    link_receipt: StepExecutionReceipt
    stabilized: StabilizedMsvc42DebugCompanion
    stabilization_elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class _ClassicGraphPhases:
    """Producer nodes partitioned into their ordered certifying phases."""

    counterfactual_compilers: tuple[ProducerNode, ...]
    ordinary: tuple[ProducerNode, ...]
    generated: tuple[ProducerNode, ...]
    librarians: tuple[ProducerNode, ...]
    linkers: tuple[ProducerNode, ...]


@dataclass(frozen=True, slots=True)
class _ClassicPendingPublication:
    """Validated private outputs awaiting one atomic public commit."""

    images: tuple[_ClassicPendingImage, ...]
    debug_companions: tuple[_ClassicPendingDebugCompanion, ...]
    physical_graph_outputs: frozenset[Path]
    requests: tuple[ClassicPublicationRequest, ...]


def _reseal_published_targets(
    bundle: ProjectBundle,
    project_root: Path,
    record: ClassicProducerGraphExecutionRecord,
) -> None:
    """Require every public target to retain its publication identity/content."""

    artifacts = {target.id: target.artifact for target in bundle.spec.targets}
    for image in record.images:
        artifact = artifacts.get(image.target_id)
        if artifact is None:
            raise ClassicProjectError(f"published target {image.target_id!r} is no longer declared")
        try:
            reseal_relative_file(
                project_root,
                artifact,
                expected=image.final_snapshot,
            )
        except SecurePathError as exc:
            raise ClassicProjectError(
                f"published target {image.target_id!r} changed before report commit"
            ) from exc
    target_ids = {image.target_id for image in record.images}
    companion_ids = [item.target_id for item in record.debug_companions]
    if companion_ids and (
        len(companion_ids) != len(set(companion_ids)) or set(companion_ids) != target_ids
    ):
        raise ClassicProjectError(
            "published debug-companion set differs from the certified target set"
        )
    for companion in record.debug_companions:
        for kind, relative, snapshot in (
            ("image", companion.image_logical_path, companion.image_snapshot),
            ("PDB", companion.pdb_logical_path, companion.pdb_snapshot),
        ):
            try:
                reseal_relative_file(project_root, relative, expected=snapshot)
            except SecurePathError as exc:
                raise ClassicProjectError(
                    f"published debug-companion {kind} {companion.target_id!r} "
                    "changed before report commit"
                ) from exc


class ClassicProducerGraphRuntimeEvidenceProvider:
    """Issue evidence from one frozen, successfully completed runtime snapshot."""

    name = CLASSIC_RUNTIME_EVIDENCE_PROVIDER_ID

    def __init__(
        self,
        bundle: ProjectBundle,
        project_root: Path,
        progress: ClassicProgressReporter,
    ) -> None:
        self._bundle = bundle
        self._project_root = project_root
        self._progress = progress
        self._inputs: ClassicRuntimeEvidenceInputs | None = None

    def bind(self, inputs: ClassicRuntimeEvidenceInputs) -> None:
        if self._inputs is not None:
            raise ClassicProjectError("classic runtime evidence was already bound")
        self._inputs = inputs

    def issue(self, context: RuntimeEvidenceContext) -> RuntimeEvidence:
        inputs = self._inputs
        if inputs is None:
            raise ClassicProjectError("classic producer-graph evidence requested before execution")
        message = "assembling and auditing authenticity evidence"
        self._progress.activity("phase_started", "evidence", message)
        try:
            _reseal_published_targets(self._bundle, self._project_root, inputs.record)
            evidence = assemble_classic_runtime_evidence(inputs, context)
        except BaseException as exc:
            self._progress.activity(
                "phase_failed",
                "evidence",
                message,
                str(exc) or type(exc).__name__,
            )
            raise
        self._progress.activity("phase_finished", "evidence", message)
        return evidence


class ClassicProducerGraphBuildExecutor:
    """Coordinate one certifying classic producer run and atomic publication."""

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
        role_tool_ids: Mapping[ProducerRole, str],
        wrapper_runtime_files: Sequence[Path],
        authority_inputs: Sequence[Path],
        targets: Sequence[ClassicProducerTarget],
        compile_records: Sequence[ClassicCompileRecord],
        units: Sequence[ClassicPreparedUnit],
        overlay_witnesses: Sequence[InterventionWitness],
        system_libraries: Mapping[str, Path],
        analysis_link_options: Sequence[str],
        producer: ClassicProducerExecution,
        overlay: ClassicOverlayEpochs,
        donors: ClassicDonorComposition,
        evidence_provider: ClassicProducerGraphRuntimeEvidenceProvider,
        progress: ClassicProgressReporter,
    ) -> None:
        self.bundle = bundle
        self.project_root = project_root
        self.session_root = session_root
        self.build_root = build_root
        self.effective_root = effective_root
        self.toolchain_root = toolchain_root
        self.graph = graph
        self.role_tool_ids = MappingProxyType(dict(role_tool_ids))
        self.wrapper_runtime_files = tuple(wrapper_runtime_files)
        self.authority_inputs = tuple(authority_inputs)
        self.targets = tuple(targets)
        self.compile_records = tuple(compile_records)
        self.units = tuple(units)
        self.overlay_witnesses = tuple(overlay_witnesses)
        self.system_libraries = MappingProxyType(dict(system_libraries))
        self.analysis_link_options = tuple(analysis_link_options)
        if self.analysis_link_options not in {(), ("/DEBUG",)}:
            raise ClassicProjectError("classic analysis-link options are not closed")
        try:
            self.debug_companion_paths = MappingProxyType(
                {
                    item.target_id: item
                    for item in classic_debug_companion_paths(bundle)
                }
            )
        except ValueError as exc:
            raise ClassicProjectError(
                f"classic debug-companion output policy is malformed: {exc}"
            ) from exc
        if bool(self.debug_companion_paths) != bool(self.analysis_link_options):
            raise ClassicProjectError(
                "classic debug-companion output set differs from its link policy"
            )
        self.producer = producer
        self.overlay = overlay
        self.donors = donors
        self.evidence_provider = evidence_provider
        self._progress = progress
        self.record: ClassicProducerGraphExecutionRecord | None = None

    def close(self) -> None:
        self.producer.close()

    def evidence_inputs(self) -> ClassicRuntimeEvidenceInputs:
        if self.record is None:
            raise ClassicProjectError("classic producer-graph evidence requested before execution")
        return ClassicRuntimeEvidenceInputs(
            record=self.record,
            effective_root=self.effective_root,
            build_root=self.build_root,
            toolchain_root=self.toolchain_root,
            logical_drive_root=self.producer.logical_drive_root,
            logical_drive_letter=self.producer.logical_drive_letter,
            graph=self.graph,
            role_tool_ids=self.role_tool_ids,
            units=self.units,
            compile_records=self.compile_records,
            system_libraries=self.system_libraries,
        )

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
                    node.id: sorted(set(node.depends_on) - completed) for node in pending.values()
                }
                raise ClassicProjectError(f"linker graph phase cannot make progress: {waiting}")
            wave_seal = _tree_file_seal(self.build_root)
            receipts.extend(
                self.overlay.audit_link_controls(tuple(target_by_linker[node.id] for node in ready))
            )
            receipts.extend(
                self.producer.run_graph_nodes(
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
                allowed_outputs=(
                    path for node in ready for path in self.producer.node_outputs(node)
                ),
                phase="linker wave",
            )
            for node in ready:
                del pending[node.id]
        return receipts

    def _run_analysis_link(
        self,
        supervisor: ProcessSupervisor,
        target: ClassicProducerTarget,
        node: ProducerNode,
        certified_image: bytes,
        cancellation: CancellationToken,
    ) -> _ClassicPendingDebugCompanion:
        """Validate one private diagnostic pair before any public output changes."""

        step_id = f"analysis-link.{target.target_id}"
        execution = self.producer.execute_private_analysis_link(
            supervisor,
            target,
            node,
            cancellation,
            log_namespace="analysis-link",
        )
        link_receipt = _step_receipt(step_id, execution.result, execution.spec)
        companion_paths = self.debug_companion_paths.get(target.target_id)
        if companion_paths is None:
            raise ClassicProjectError(
                f"analysis relink lacks a debug-companion output seat for {target.target_id!r}"
            )
        stabilization_started = time.monotonic()
        try:
            stabilized = stabilize_msvc42_debug_companion(
                certified_image,
                execution.image.read_bytes(),
                execution.pdb.read_bytes(),
                expected_pdb_path=self.producer.logical_for_host_path(execution.plan.pdb),
            )
        except (ByteIdentityError, OSError) as exc:
            raise ClassicProjectError(
                f"analysis relink {target.target_id!r} is not a valid MSVC 4.2 "
                f"debug companion: {exc}"
            ) from exc
        stabilization_elapsed_seconds = time.monotonic() - stabilization_started
        self._progress.emit("analysis-link", step_id)
        return _ClassicPendingDebugCompanion(
            target=target,
            logical_image_path=companion_paths.image,
            logical_pdb_path=companion_paths.pdb,
            execution=execution,
            link_receipt=link_receipt,
            stabilized=stabilized,
            stabilization_elapsed_seconds=stabilization_elapsed_seconds,
        )

    def execute(
        self,
        plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: Iterable[Path] = (),
    ) -> BuildExecutionReceipt:
        revalidate_classic_validator_implementation()
        self.producer.begin_certifying()
        try:
            receipt = self._execute(plan, cold=cold, required_outputs=required_outputs)
        except BaseException as original:
            try:
                self.producer.close()
            except BaseException as cleanup_error:
                original.add_note(f"classic runtime cleanup also failed: {cleanup_error}")
            raise
        else:
            self.producer.close()
        self.reseal_published_targets()
        self._progress.emit("validation", "execution-record")
        if self._progress.completed != self._progress.total:
            raise ClassicProjectError(
                "classic progress did not cover every successful execution step"
            )
        self.evidence_provider.bind(self.evidence_inputs())
        return receipt

    def reseal_published_targets(self) -> None:
        """Require every public target to retain its publication identity/content."""

        record = self.record
        if record is None:
            raise ClassicProjectError(
                "classic targets cannot be resealed before successful execution"
            )
        _reseal_published_targets(self.bundle, self.project_root, record)

    def _graph_phases(self) -> _ClassicGraphPhases:
        """Partition the sealed graph into its ordered certifying phases."""

        counterfactual_compilers = tuple(
            node
            for node in self.graph.nodes
            if node.role is ProducerRole.COMPILER
            and node.id in self.overlay.compiler_epoch_plan.audit_node_ids
        )
        ordinary = tuple(
            node
            for node in self.graph.nodes
            if node.role in {ProducerRole.COMPILER, ProducerRole.RESOURCE}
            and node.id not in self.overlay.generated_node_inputs
        )
        generated = tuple(
            node
            for node in self.graph.nodes
            if node.role is ProducerRole.COMPILER and node.id in self.overlay.generated_node_inputs
        )
        librarians = tuple(node for node in self.graph.nodes if node.role is ProducerRole.LIBRARIAN)
        linkers = tuple(node for node in self.graph.nodes if node.role is ProducerRole.LINKER)
        if len(ordinary) + len(generated) + len(librarians) + len(linkers) != len(self.graph.nodes):
            raise ClassicProjectError("producer graph contains an unsupported role")
        return _ClassicGraphPhases(
            counterfactual_compilers,
            ordinary,
            generated,
            librarians,
            linkers,
        )

    def _run_compiler_epochs(
        self,
        namespace_stack: ExitStack,
        supervisor: ProcessSupervisor,
        phases: _ClassicGraphPhases,
        *,
        source_tree_before: Mapping[Path, tuple[int, Digest]],
        steps: list[StepExecutionReceipt],
        completed: set[str],
        output_steps: dict[Path, str],
        cancellation: CancellationToken,
    ) -> tuple[ClassicActiveCompilerEpoch, Mapping[Path, tuple[int, Digest]]]:
        """Execute and seal the clean, counterfactual, effective, and generated epochs."""

        counterfactual_compilers = phases.counterfactual_compilers
        ordinary = phases.ordinary
        generated = phases.generated
        authority_namespace = namespace_stack.enter_context(
            self.producer.authority_namespace_lease()
        )
        effective_ordinary_source_seal = source_tree_before
        if self.overlay_witnesses:
            steps.append(self.overlay.capture_clean_source_inputs(source_tree_before))
            effective_preimage: Literal["clean", "counterfactual"] = "clean"
            if counterfactual_compilers:
                counterfactual_step, counterfactual_source_seal = (
                    self.overlay.materialize_project_overlay_counterfactual_epoch(
                        source_tree_before
                    )
                )
                steps.append(counterfactual_step)
                counterfactual_source_namespace = namespace_stack.enter_context(
                    self.producer.source_namespace_lease()
                )
                counterfactual_namespace = self.producer.capture_compiler_namespace(
                    "declaration-counterfactual-epoch",
                    source=counterfactual_source_namespace.snapshot,
                    authority=authority_namespace.snapshot,
                )
                self.overlay.bind_counterfactual_namespace(
                    counterfactual_namespace.evidence.namespace_id
                )
                steps.extend(
                    self.overlay.run_counterfactual_compiler_audit(
                        supervisor,
                        counterfactual_compilers,
                        source_seal=counterfactual_source_seal,
                        cancellation=cancellation,
                        compiler_namespace_id=(counterfactual_namespace.evidence.namespace_id),
                    )
                )
                counterfactual_source_namespace.close()
                effective_ordinary_source_seal = counterfactual_source_seal
                effective_preimage = "counterfactual"
            overlay_step, effective_ordinary_source_seal = (
                self.overlay.materialize_certified_project_overlay_epoch(
                    effective_ordinary_source_seal,
                    preimage=effective_preimage,
                )
            )
            steps.append(overlay_step)
        ordinary_source_namespace = namespace_stack.enter_context(
            self.producer.source_namespace_lease()
        )
        ordinary_namespace = self.producer.capture_compiler_namespace(
            "effective-project-epoch",
            source=ordinary_source_namespace.snapshot,
            authority=authority_namespace.snapshot,
        )
        if self.overlay_witnesses and not counterfactual_compilers:
            self.overlay.bind_counterfactual_namespace(ordinary_namespace.evidence.namespace_id)
        ordinary_include_authority = self.producer.include_authority()
        ordinary_seal = _tree_file_seal(self.build_root)
        steps.extend(
            self.producer.run_graph_nodes(
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
            allowed_outputs=(
                path for node in ordinary for path in self.producer.node_outputs(node)
            ),
            phase="ordinary compiler/resource phase",
        )
        _require_unchanged_tree(
            effective_ordinary_source_seal,
            root=self.effective_root,
            label="certified project-overlay compiler epoch",
        )
        source_tree_after_generation = effective_ordinary_source_seal
        if self.overlay.generated_translation_units:
            ordinary_source_namespace.close()
            generated_step, source_tree_after_generation = (
                self.overlay.materialize_generated_input_epoch(effective_ordinary_source_seal)
            )
            steps.append(generated_step)
            generated_include_authority = self.producer.include_authority()
            generated_source_namespace = namespace_stack.enter_context(
                self.producer.source_namespace_lease()
            )
            generated_namespace = self.producer.capture_compiler_namespace(
                "generated-project-epoch",
                source=generated_source_namespace.snapshot,
                authority=authority_namespace.snapshot,
            )
        else:
            generated_include_authority = ordinary_include_authority
            generated_namespace = ordinary_namespace
        if bool(generated) != bool(self.overlay.generated_translation_units):
            raise ClassicProjectError(
                "generated compiler epoch differs from overlay input authority"
            )
        generated_seal = _tree_file_seal(self.build_root)
        steps.extend(
            self.producer.run_graph_nodes(
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
            allowed_outputs=(
                path for node in generated for path in self.producer.node_outputs(node)
            ),
            phase="generated compiler phase",
        )
        steps.append(self.overlay.capture_effective_compiler_products())
        if self.overlay_witnesses:
            steps.append(self.overlay.validate_project_overlay_compiler_epoch())
        active_epoch = ClassicActiveCompilerEpoch(
            generated_namespace.evidence.namespace_id,
            generated_include_authority,
            source_tree_after_generation,
            bool(self.overlay.generated_translation_units),
        )
        return active_epoch, source_tree_after_generation

    def _run_composition_and_link(
        self,
        supervisor: ProcessSupervisor,
        phases: _ClassicGraphPhases,
        *,
        active_epoch: ClassicActiveCompilerEpoch,
        graph_outputs: set[Path],
        steps: list[StepExecutionReceipt],
        witnesses: list[InterventionWitness],
        completed: set[str],
        output_steps: dict[Path, str],
        cancellation: CancellationToken,
    ) -> None:
        """Compose translation units, transform objects, and run archive/link phases."""

        librarians = phases.librarians
        linkers = phases.linkers
        composition_seal = _tree_file_seal(self.build_root)
        with ThreadPoolExecutor(
            max_workers=min(self.producer.jobs, max(1, len(self.units)))
        ) as pool:
            futures = {
                pool.submit(
                    self.donors.compose_unit,
                    supervisor,
                    unit,
                    cancellation,
                    compiler_epoch=active_epoch,
                ): unit
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
            allowed_outputs=(self.donors.record_for_unit(unit).object_path for unit in self.units),
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
                raise ClassicProjectError("rdata repack object is not a committed producer output")
            self.producer.require_regular(object_path, label="rdata repack object")
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
            self.producer.run_graph_nodes(
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
            allowed_outputs=(
                path for node in librarians for path in self.producer.node_outputs(node)
            ),
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
        self.overlay.apply_semantic_proofs(
            witnesses,
            donor_semantic_lanes=self.donors.semantic_lanes(),
        )

    def _prepare_pending_publication(
        self,
        *,
        inputs: tuple[FileReceipt, ...],
        source_tree_after_generation: Mapping[Path, tuple[int, Digest]],
        toolchain_tree_before: Mapping[Path, tuple[int, Digest]],
        steps: list[StepExecutionReceipt],
        witnesses: list[InterventionWitness],
        cancellation: CancellationToken,
    ) -> _ClassicPendingPublication:
        """Validate terminal products and assemble the exact atomic publication set."""

        pending_images: list[_ClassicPendingImage] = []
        target_specs = {item.id: item for item in self.bundle.spec.targets}
        for target in self.targets:
            self.producer.require_regular(
                target.output, label=f"linked target {target.target_id!r}"
            )
            started = time.monotonic()
            terminal = apply_classic_terminal_pipeline(
                self.bundle,
                target_id=target.target_id,
                candidate=target.output.read_bytes(),
            )
            logical_artifact = target_specs[target.target_id].artifact
            witnesses.extend(terminal.witnesses)
            pending_images.append(
                _ClassicPendingImage(
                    target,
                    logical_artifact,
                    terminal.output,
                    terminal.witnesses,
                    _digest_path(target.output),
                    time.monotonic() - started,
                )
            )

        pending_debug_companions: list[_ClassicPendingDebugCompanion] = []
        if self.analysis_link_options:
            nodes_by_id = {node.id: node for node in self.graph.nodes}
            certified_images = {
                item.target.target_id: item.payload for item in pending_images
            }
            with ProcessSupervisor() as analysis_supervisor:
                for target in self.targets:
                    node = nodes_by_id.get(target.link_node_id)
                    if node is None:
                        raise ClassicProjectError(
                            f"analysis relink lacks exact target state for {target.target_id!r}"
                        )
                    pending_companion = self._run_analysis_link(
                        analysis_supervisor,
                        target,
                        node,
                        certified_images[target.target_id],
                        cancellation,
                    )
                    steps.append(pending_companion.link_receipt)
                    pending_debug_companions.append(pending_companion)
            if {item.target.target_id for item in pending_debug_companions} != {
                target.target_id for target in self.targets
            } or len(pending_debug_companions) != len(self.targets):
                raise ClassicProjectError(
                    "analysis relink did not produce exactly one debug companion per target"
                )

        physical_graph_outputs = {
            path.resolve(strict=True)
            for node in self.graph.nodes
            for path in self.producer.node_outputs(node)
        }
        if len(physical_graph_outputs) != sum(len(node.outputs) for node in self.graph.nodes):
            raise ClassicProjectError("producer graph aliases physical outputs")
        mutable_clean_inputs = {
            self.effective_root.joinpath(*PurePosixPath(item.path).parts).resolve(
                strict=False
            ): item
            for item in self.overlay.project_source_pairs
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
        pending_publication_steps = len(pending_images) + len(pending_debug_companions)
        if self._progress.completed != self._progress.total - pending_publication_steps - 1:
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
            item.reference.casefold() for item in self.overlay.captured_compiler_outputs
        }
        if actual_compiler_outputs != expected_compiler_outputs:
            raise ClassicProjectError("raw compiler output capture differs from the producer graph")
        expected_donors = {donor.intervention.id for unit in self.units for donor in unit.donors}
        if (
            len(self.donors.donor_outputs()) != len(expected_donors)
            or {item.intervention_id for item in self.donors.donor_outputs()} != expected_donors
        ):
            raise ClassicProjectError(
                "private donor output capture differs from prepared donor lanes"
            )
        expected_object_transforms = {
            unit.plan.id for unit in self.units if unit.plan.group_order is not None
        }
        object_transforms = self.donors.object_transforms()
        if (
            len(object_transforms) != len(expected_object_transforms)
            or {item.unit_id for item in object_transforms} != expected_object_transforms
        ):
            raise ClassicProjectError(
                "object transform receipts differ from planned group-order stages"
            )
        publication_requests = [
            ClassicPublicationRequest(
                owner_id=item.target.target_id,
                kind="target",
                producer_step=f"publish.{item.target.target_id}",
                relative=item.logical_path,
                payload=item.payload,
                mode=0o644 if os.name == "posix" else None,
            )
            for item in pending_images
        ]
        publication_requests.extend(
            ClassicPublicationRequest(
                owner_id=item.target.target_id,
                kind="debug companion image",
                producer_step=f"publish-analysis.{item.target.target_id}",
                relative=item.logical_image_path,
                payload=item.stabilized.image,
                mode=0o644 if os.name == "posix" else None,
            )
            for item in pending_debug_companions
        )
        publication_requests.extend(
            ClassicPublicationRequest(
                owner_id=item.target.target_id,
                kind="debug companion PDB",
                producer_step=f"publish-analysis.{item.target.target_id}",
                relative=item.logical_pdb_path,
                payload=item.stabilized.pdb,
                mode=0o644 if os.name == "posix" else None,
            )
            for item in pending_debug_companions
        )
        return _ClassicPendingPublication(
            tuple(pending_images),
            tuple(pending_debug_companions),
            frozenset(physical_graph_outputs),
            tuple(publication_requests),
        )

    def _publish_atomically(
        self,
        pending: _ClassicPendingPublication,
        *,
        expected: set[Path],
        inputs: tuple[FileReceipt, ...],
        steps: list[StepExecutionReceipt],
        witnesses: list[InterventionWitness],
        output_steps: dict[Path, str],
    ) -> BuildExecutionReceipt:
        """Commit the validated target set and issue its immutable execution record."""

        pending_images = pending.images
        pending_debug_companions = pending.debug_companions
        physical_graph_outputs = pending.physical_graph_outputs
        publication_requests = pending.requests
        state_root = self.project_root.joinpath(
            *PurePosixPath(self.bundle.spec.state_dir).parts
        ).resolve(strict=True)
        try:
            with publish_classic_output_set(
                self.project_root,
                state_root,
                publication_requests,
            ) as published:
                published_by_relative = {
                    item.request.relative.casefold(): item.snapshot for item in published
                }
                images: list[ClassicProducedImage] = []
                for pending_image in pending_images:
                    final_snapshot = published_by_relative[pending_image.logical_path.casefold()]
                    step_id = f"publish.{pending_image.target.target_id}"
                    steps.append(
                        _internal_step(
                            step_id,
                            {
                                "link_node": pending_image.target.link_node_id,
                                "raw": pending_image.raw_digest.model_dump(mode="json"),
                                "final": sha256(pending_image.payload).hexdigest(),
                                "witnesses": [
                                    witness.evidence_digest.value
                                    for witness in pending_image.witnesses
                                ],
                            },
                            pending_image.elapsed_seconds,
                        )
                    )
                    images.append(
                        ClassicProducedImage(
                            pending_image.target.target_id,
                            pending_image.target.output,
                            final_snapshot.path,
                            pending_image.target.link_node_id,
                            self.role_tool_ids[ProducerRole.LINKER],
                            pending_image.witnesses,
                            final_snapshot,
                        )
                    )
                    self._progress.emit("terminal", step_id)

                images_by_target = {item.target_id: item for item in images}
                debug_companions: list[ClassicProducedDebugCompanion] = []
                for pending_companion in pending_debug_companions:
                    target_id = pending_companion.target.target_id
                    image_snapshot = published_by_relative[
                        pending_companion.logical_image_path.casefold()
                    ]
                    pdb_snapshot = published_by_relative[
                        pending_companion.logical_pdb_path.casefold()
                    ]
                    certified_image = images_by_target[target_id]
                    publish_step_id = f"publish-analysis.{target_id}"
                    audit = pending_companion.stabilized.audit
                    if (
                        audit.certified_image_sha256
                        != certified_image.final_snapshot.digest.value
                        or audit.image_metadata_output_sha256
                        != image_snapshot.digest.value
                        or audit.pdb.output_sha256 != pdb_snapshot.digest.value
                    ):
                        raise ClassicProjectError(
                            f"debug-companion audit for {target_id!r} differs from its "
                            "atomic publication"
                        )
                    steps.append(
                        _internal_step(
                            publish_step_id,
                            {
                                "schema": 2,
                                "policy": audit.policy_version,
                                "analysis_link_step": pending_companion.link_receipt.step_id,
                                "raw_image": {
                                    "sha256": audit.image_debug.raw_sha256,
                                    "size": audit.image_debug.size,
                                },
                                "raw_pdb": {
                                    "sha256": audit.pdb.raw_sha256,
                                    "size": audit.pdb.size,
                                },
                                "certified_image": (
                                    certified_image.final_snapshot.digest.model_dump(mode="json")
                                ),
                                "companion_image": {
                                    "digest": image_snapshot.digest.model_dump(mode="json"),
                                    "size": image_snapshot.size,
                                },
                                "companion_pdb": {
                                    "digest": pdb_snapshot.digest.model_dump(mode="json"),
                                    "size": pdb_snapshot.size,
                                },
                                "changed_bytes": {
                                    "image_identity": audit.image_debug.changed_bytes,
                                    "pdb_bookkeeping": audit.pdb.changed_bytes,
                                },
                            },
                            pending_companion.stabilization_elapsed_seconds,
                        )
                    )
                    debug_companions.append(
                        ClassicProducedDebugCompanion(
                            target_id=target_id,
                            image_logical_path=pending_companion.logical_image_path,
                            pdb_logical_path=pending_companion.logical_pdb_path,
                            raw_image_digest=Digest(
                                value=audit.image_debug.raw_sha256
                            ),
                            raw_image_size=audit.image_debug.size,
                            raw_pdb_digest=Digest(value=audit.pdb.raw_sha256),
                            raw_pdb_size=audit.pdb.size,
                            link_step_id=pending_companion.link_receipt.step_id,
                            publish_step_id=publish_step_id,
                            image_snapshot=image_snapshot,
                            pdb_snapshot=pdb_snapshot,
                            audit=audit,
                        )
                    )
                    self._progress.emit("analysis-pair", publish_step_id)

                if self._progress.completed != self._progress.total - 1:
                    raise ClassicProjectError(
                        "classic progress did not cover every successful publication step"
                    )
                output_receipts = [
                    _receipt(
                        path,
                        fresh=True,
                        producer_step=output_steps.get(path.resolve(strict=False)),
                    )
                    for path in sorted(physical_graph_outputs, key=str)
                ]
                output_receipts.extend(
                    _receipt(path, fresh=True, producer_step=None)
                    for path in sorted(expected, key=str)
                )
                output_receipts.extend(
                    _receipt(
                        path,
                        fresh=True,
                        producer_step=companion.publish_step_id,
                    )
                    for companion in sorted(
                        debug_companions,
                        key=lambda value: value.target_id.casefold(),
                    )
                    for path in (
                        companion.image_snapshot.path,
                        companion.pdb_snapshot.path,
                    )
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
                            f"published target {image.target_id!r} receipt differs "
                            "from its atomic publication"
                        )
                for companion in debug_companions:
                    for kind, snapshot in (
                        ("image", companion.image_snapshot),
                        ("PDB", companion.pdb_snapshot),
                    ):
                        receipt = output_receipts_by_path.get(
                            snapshot.path.resolve(strict=False)
                        )
                        if receipt is None or (
                            receipt.digest != snapshot.digest
                            or receipt.size != snapshot.size
                            or receipt.device != snapshot.device
                            or receipt.inode != snapshot.inode
                        ):
                            raise ClassicProjectError(
                                f"published debug-companion {kind} "
                                f"{companion.target_id!r} receipt differs from its "
                                "atomic publication"
                            )
                self.record = ClassicProducerGraphExecutionRecord(
                    images=tuple(images),
                    witnesses=tuple(witnesses),
                    producer_reads=tuple(
                        sorted(
                            (*self.producer.producer_reads(), *self.donors.producer_reads()),
                            key=lambda value: (
                                value.role.value,
                                value.node_id.casefold(),
                                value.epoch.casefold(),
                                value.step_id.casefold(),
                            ),
                        )
                    ),
                    compiler_outputs=tuple(
                        sorted(
                            self.overlay.captured_compiler_outputs,
                            key=lambda value: (
                                value.node_id.casefold(),
                                value.reference.casefold(),
                            ),
                        )
                    ),
                    donor_outputs=tuple(
                        sorted(
                            self.donors.donor_outputs(),
                            key=lambda value: value.intervention_id.casefold(),
                        )
                    ),
                    compiler_namespaces=tuple(
                        self.producer.compiler_namespaces()[key]
                        for key in sorted(self.producer.compiler_namespaces(), key=str.casefold)
                    ),
                    debug_companions=tuple(
                        sorted(
                            debug_companions,
                            key=lambda value: value.target_id.casefold(),
                        )
                    ),
                    object_transforms=tuple(
                        sorted(
                            self.donors.object_transforms(),
                            key=lambda value: value.unit_id.casefold(),
                        )
                    ),
                )
                return BuildExecutionReceipt(
                    True,
                    inputs,
                    tuple(sorted(output_receipts, key=lambda item: str(item.path))),
                    tuple(sorted(steps, key=lambda item: item.step_id)),
                )
        except ClassicPublicationError as exc:
            raise ClassicProjectError(
                f"classic target/PDB set could not be published safely: {exc}"
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
            for path in self.producer.declared_outputs(node)
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
        phases = self._graph_phases()
        with ExitStack() as namespace_stack, ProcessSupervisor() as supervisor:
            active_epoch, source_tree_after_generation = self._run_compiler_epochs(
                namespace_stack,
                supervisor,
                phases,
                source_tree_before=source_tree_before,
                steps=steps,
                completed=completed,
                output_steps=output_steps,
                cancellation=cancellation,
            )
            self._run_composition_and_link(
                supervisor,
                phases,
                active_epoch=active_epoch,
                graph_outputs=graph_outputs,
                steps=steps,
                witnesses=witnesses,
                completed=completed,
                output_steps=output_steps,
                cancellation=cancellation,
            )
        if completed != {node.id for node in self.graph.nodes}:
            raise ClassicProjectError("producer graph execution was incomplete")
        pending = self._prepare_pending_publication(
            inputs=inputs,
            source_tree_after_generation=source_tree_after_generation,
            toolchain_tree_before=toolchain_tree_before,
            steps=steps,
            witnesses=witnesses,
            cancellation=cancellation,
        )
        return self._publish_atomically(
            pending,
            expected=expected,
            inputs=inputs,
            steps=steps,
            witnesses=witnesses,
            output_steps=output_steps,
        )


__all__ = [
    "ClassicProducerGraphBuildExecutor",
    "ClassicProducerGraphRuntimeEvidenceProvider",
]
