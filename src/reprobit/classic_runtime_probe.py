"""Non-certifying compiler and donor probes for classic projects."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
from reprobit.classic_orchestration import (
    ClassicPreparedUnit,
)
from reprobit.classic_project import (
    ClassicProjectError,
)
from reprobit.classic_runtime_donor import (
    ClassicDonorComposition,
)
from reprobit.classic_runtime_files import (
    _require_declared_tree_writes,
    _require_unchanged_tree,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
    classic_compiler_product_refs,
)
from reprobit.classic_runtime_overlay import ClassicOverlayEpochs
from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
)
from reprobit.classic_runtime_receipts import (
    _step_receipt,
)
from reprobit.classic_runtime_warm import ClassicWarmExecution
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
    ProducerRole,
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


ClassicDonorProbeProgress = Callable[[int, int, str], None]


class ClassicProbeExecution:
    """Own bounded, non-certifying probes that consume a prepared runtime."""

    def __init__(
        self,
        *,
        graph: ProducerGraphDocument,
        units: Sequence[ClassicPreparedUnit],
        producer: ClassicProducerExecution,
        overlay: ClassicOverlayEpochs,
        donors: ClassicDonorComposition,
        warm: ClassicWarmExecution,
    ) -> None:
        self.graph = graph
        self.units = tuple(units)
        self.producer = producer
        self.overlay = overlay
        self.donors = donors
        self.effective_root = warm.effective_root
        self.build_root = warm.build_root
        self.warm = warm

    def _close_all(self) -> None:
        try:
            self.warm.close()
        finally:
            self.producer.close()

    def probe_compiler_nodes(
        self,
        node_ids: Sequence[str],
        *,
        source_epoch: Literal["clean", "effective"] = "effective",
    ) -> tuple[ClassicCompilerProbeOutput, ...]:
        """Run a bounded non-certifying exact-node compiler probe.

        This developer diagnostic invokes only the selected committed compiler
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
                self._close_all()
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
            self._close_all()

    def probe_donor_compilers(
        self,
        donor_ids: Sequence[str],
        *,
        progress: ClassicDonorProbeProgress | None = None,
    ) -> tuple[ClassicDonorProbeOutput, ...]:
        """Run exact prepared private-donor compilers as a consumed diagnostic.

        The caller may select only donor requests already rendered by the
        committed project plan.  Each request is invoked through its owning
        compiler node's command and the normal locked execution lane.  Raw
        products and immutable rendered inputs are returned solely for
        developer diagnosis; no evidence, proof, cache entry, or report is
        issued.  ``progress`` runs on the coordinating thread after each
        successful donor and receives ``(completed, total, donor_id)``.  The
        prepared run is consumed and its backend is closed on success and
        failure.
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

                def probe_one(ordinal: int, donor_id: str) -> ClassicDonorProbeOutput:
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
                    return ClassicDonorProbeOutput(
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

                # Keep only one bounded window submitted at a time.  A failed
                # candidate therefore cancels active siblings without starting
                # another donor merely because a worker became free first.
                worker_count = min(self.producer.jobs, len(requested))
                outputs_by_ordinal: dict[int, ClassicDonorProbeOutput] = {}
                running: dict[Future[ClassicDonorProbeOutput], tuple[int, str]] = {}
                next_ordinal = 0
                completed = 0

                def replenish(pool: ThreadPoolExecutor) -> None:
                    nonlocal next_ordinal
                    while len(running) < worker_count and next_ordinal < len(requested):
                        ordinal = next_ordinal
                        donor_id = requested[ordinal]
                        next_ordinal += 1
                        running[pool.submit(probe_one, ordinal, donor_id)] = (
                            ordinal,
                            donor_id,
                        )

                with ThreadPoolExecutor(
                    max_workers=worker_count,
                    thread_name_prefix="reprobit-donor-probe",
                ) as pool:
                    replenish(pool)
                    try:
                        while running:
                            finished, _ = wait(tuple(running), return_when=FIRST_COMPLETED)
                            for future in sorted(finished, key=lambda item: running[item][0]):
                                ordinal, donor_id = running.pop(future)
                                outputs_by_ordinal[ordinal] = future.result()
                                completed += 1
                                if progress is not None:
                                    progress(completed, len(requested), donor_id)
                            replenish(pool)
                    except BaseException as original:
                        cancellation.cancel("classic donor probe sibling failed")
                        try:
                            supervisor.cancel_all()
                        except BaseException as cleanup_error:
                            original.add_note(
                                "classic donor probe process cancellation also failed: "
                                f"{cleanup_error}"
                            )
                        for future in running:
                            future.cancel()
                        raise
                outputs = tuple(outputs_by_ordinal[index] for index in range(len(requested)))
            _require_unchanged_tree(
                source_seal,
                root=self.effective_root,
                label="donor compiler probe source epoch",
            )
        except BaseException as original:
            try:
                self._close_all()
            except BaseException as cleanup_error:
                original.add_note(f"classic donor probe cleanup also failed: {cleanup_error}")
            raise
        self._close_all()
        return outputs


__all__ = [
    "ClassicCompilerProbeOutput",
    "ClassicDonorProbeInput",
    "ClassicDonorProbeOutput",
    "ClassicDonorProbeProgress",
    "ClassicProbeExecution",
]
