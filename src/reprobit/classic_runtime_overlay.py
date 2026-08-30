"""Project-overlay source epochs and semantic proof execution."""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from reprobit.classic.compiler_epoch import (
    validate_project_overlay_compiler_epoch,
)
from reprobit.classic.project_overlay import (
    overlay_semantic_run_binding,
    prove_source_overlay_semantics,
)
from reprobit.classic.semantic_contracts import (
    CLASSIC_SEMANTIC_CONTRACTS,
    ArchiveInput,
    CleanSourceInput,
    CompilerEpochInvocation,
    CompilerNamespaceEvidence,
    CompilerProduct,
    DonorSemanticLane,
    EffectiveOverlayReceipt,
    OverlaySemanticSnapshot,
    PrimarySourceOrigin,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
    SourceInputReceipt,
    TargetLinkClosure,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic_execution_records import (
    ClassicCapturedProducerOutput,
)
from reprobit.classic_link_closure import (
    ClassicLinkClosureError,
    ClassicLinkDirectiveClosure,
    MissingDirectiveInputsError,
    ModuleDefinitionReceipt,
    audit_classic_link_directives,
    direct_terminal_link_control_references,
    link_directive_closure_material,
    module_definition_material,
    parse_classic_module_definition,
)
from reprobit.classic_link_topology import (
    ClassicLinkTopologyError,
    terminal_link_input_topology,
)
from reprobit.classic_project import (
    ClassicProjectError,
    InterventionWitness,
    _effective_source_seal,
)
from reprobit.classic_resources import ResourceDependencyReceipt
from reprobit.classic_runtime_environment import (
    _logical_join,
)
from reprobit.classic_runtime_files import (
    _require_declared_tree_writes,
    _require_unchanged_tree,
    _safe_relative,
    _tree_file_seal,
)
from reprobit.classic_runtime_graph import (
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
    producer_graph_digest,
)
from reprobit.schema import (
    ProjectBundle,
)

if TYPE_CHECKING:
    pass


from reprobit.classic_runtime_producer import (
    ClassicProducerExecution,
    ClassicProgressReporter,
)
from reprobit.classic_runtime_receipts import (
    _internal_step,
)


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


class ClassicOverlayEpochs:
    """Own project-overlay source epochs and their semantic proof material."""

    def __init__(
        self,
        *,
        bundle: ProjectBundle,
        effective_root: Path,
        build_root: Path,
        graph: ProducerGraphDocument,
        targets: Sequence[ClassicProducerTarget],
        overlay_witnesses: Sequence[InterventionWitness],
        overlay_effective_outputs: Mapping[str, bytes],
        project_source_pairs: Sequence[ProjectOverlaySourcePair],
        compiler_epoch_plan: ProjectOverlayCompilerEpochPlan,
        generated_inputs: frozenset[str],
        carrier_input_seals: Mapping[str, tuple[str, ...]],
        system_libraries: Mapping[str, Path],
        producer: ClassicProducerExecution,
        progress: ClassicProgressReporter,
    ) -> None:
        self.bundle = bundle
        self.effective_root = effective_root
        self.build_root = build_root
        self.graph = graph
        self.targets = tuple(targets)
        self.overlay_witnesses = tuple(overlay_witnesses)
        self.overlay_effective_outputs = MappingProxyType(dict(overlay_effective_outputs))
        self.project_source_pairs = tuple(project_source_pairs)
        self.compiler_epoch_plan = compiler_epoch_plan
        self.generated_inputs = generated_inputs
        self.carrier_input_seals = MappingProxyType(dict(carrier_input_seals))
        self.system_libraries = MappingProxyType(dict(system_libraries))
        self.producer = producer
        self._progress = progress
        generated_nodes: dict[str, tuple[str, ...]] = {}
        carrier_sources = {
            path.casefold(): inputs for path, inputs in self.carrier_input_seals.items()
        }
        seen_carriers: set[str] = set()
        for node in graph.nodes:
            if node.role is not ProducerRole.COMPILER:
                continue
            source_ref, _ = classic_compiler_product_refs(node)
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
        self._counterfactual_compiler_audits: tuple[ProjectOverlayCounterfactualAudit, ...] = ()
        self._counterfactual_namespace_id: str | None = None
        self._clean_source_inputs: tuple[CleanSourceInput, ...] = ()
        self._effective_compiler_products: tuple[CompilerProduct, ...] = ()
        self._captured_compiler_outputs: tuple[ClassicCapturedProducerOutput, ...] = ()
        self._link_directive_closures: Mapping[str, ClassicLinkDirectiveClosure] = MappingProxyType(
            {}
        )
        self._module_definition_receipts: Mapping[str, ModuleDefinitionReceipt] = MappingProxyType(
            {}
        )

    @property
    def counterfactual_namespace_id(self) -> str | None:
        return self._counterfactual_namespace_id

    def bind_counterfactual_namespace(self, namespace_id: str) -> None:
        self._counterfactual_namespace_id = namespace_id

    @property
    def captured_compiler_outputs(self) -> tuple[ClassicCapturedProducerOutput, ...]:
        return self._captured_compiler_outputs

    def _primary_source_receipts(self) -> tuple[SourceInputReceipt, ...]:
        manifest = self.bundle.source_manifest
        if manifest is None or not manifest.complete:
            raise ClassicProjectError("overlay semantics require a complete source manifest")
        receipts: list[SourceInputReceipt] = []
        expected: set[str] = set()
        pairs = {item.path.casefold(): item for item in self.project_source_pairs}
        for entry in manifest.entries:
            path = self.effective_root.joinpath(*PurePosixPath(entry.path).parts)
            self.producer.require_regular(path, label="primary compiler source")
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
            self.producer.require_regular(path, label="certified project-overlay header")
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
            self.producer.require_regular(path, label="generated carrier source")
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

    def capture_clean_source_inputs(
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
            self.producer.require_regular(path, label="clean project-overlay source")
            payload = path.read_bytes()
            if Digest.from_bytes(payload) != entry.digest or len(payload) != entry.size:
                raise ClassicProjectError(f"clean project-overlay source changed: {entry.path!r}")
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

    def run_counterfactual_compiler_audit(
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
            raise ClassicProjectError("counterfactual compiler audit requires a project overlay")
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
        receipts = self.producer.run_graph_nodes(
            supervisor,
            nodes,
            completed=completed,
            output_steps=output_steps,
            cancellation=cancellation,
            step_id_prefix="audit.counterfactual.",
            progress_phase="counterfactual-audit",
            log_namespace="counterfactual-audit",
            include_authority=self.producer.include_authority(),
            include_trace_epoch="declaration-counterfactual",
            compiler_namespace_id=compiler_namespace_id,
        )
        if completed != expected:
            raise ClassicProjectError("counterfactual compiler audit execution was incomplete")
        _require_declared_tree_writes(
            build_seal,
            root=self.build_root,
            allowed_outputs=(path for node in nodes for path in self.producer.node_outputs(node)),
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
            source_ref, object_ref = classic_compiler_product_refs(node)
            declared_outputs = self.producer.declared_outputs(node)
            if any(
                path.suffix.casefold() not in {".obj", ".o", ".pdb"} for path in declared_outputs
            ):
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} declares a non-OBJ/PDB output"
                )
            declared_object = self.producer.reference(object_ref)
            if declared_object is None:
                raise ClassicProjectError(
                    f"counterfactual compiler audit {node.id!r} object is unresolved"
                )
            registered_outputs = self.producer.registered_outputs()
            physical_outputs = {
                declared: registered_outputs.get(declared) for declared in declared_outputs
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
            self.producer.require_regular(
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
                    self.producer.compiler_epoch_invocation(
                        node, epoch="declaration-counterfactual"
                    ),
                )
            )
            node_outputs: list[dict[str, object]] = []
            for reference, declared in zip(node.outputs, declared_outputs, strict=True):
                actual = physical_outputs[declared]
                if actual is None:
                    raise AssertionError("physical compiler output was not narrowed")
                self.producer.require_regular(
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
        if set(self.producer.registered_outputs()) != declared_universe:
            raise ClassicProjectError(
                "counterfactual compiler audit physical-output registry is not isolated"
            )
        for path in sorted(physical_universe, key=str):
            self.producer.require_regular(path, label="counterfactual compiler audit erase target")
            path.unlink()
        for declared in sorted(declared_universe, key=str):
            actual = self.producer.clear_output(declared)
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
        if self.producer.registered_outputs():
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
            self.producer.require_regular(destination, label=f"{epoch} source preimage")
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
            if os.path.lexists(directory) and (directory.is_symlink() or not directory.is_dir()):
                raise ClassicProjectError(f"{epoch} source parent is redirected: {relative!r}")
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
        self.producer.require_regular(destination, label=f"{epoch} installed source")
        if destination.read_bytes() != payload:
            raise ClassicProjectError(f"{epoch} source changed after install: {relative!r}")
        return destination, True

    def materialize_project_overlay_counterfactual_epoch(
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
                    {"path": path, "size": size, "digest": digest} for path, size, digest in before
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

    def materialize_certified_project_overlay_epoch(
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

    def capture_effective_compiler_products(self) -> StepExecutionReceipt:
        """Freeze raw effective CL outputs before candidate composition mutates them."""

        started = time.monotonic()
        products: list[CompilerProduct] = []
        captured_outputs: list[ClassicCapturedProducerOutput] = []
        material: list[dict[str, object]] = []
        ordinary_visibility = self.ordinary_generated_inputs
        for node in sorted(self.graph.nodes, key=lambda item: item.id.casefold()):
            if node.role is not ProducerRole.COMPILER:
                continue
            source_ref, object_ref = classic_compiler_product_refs(node)
            declared_object = self.producer.reference(object_ref)
            if declared_object is None:
                raise ClassicProjectError("compiler semantic output is not a file")
            object_path = self.producer.registered_outputs().get(declared_object)
            if object_path is None:
                raise ClassicProjectError(f"compiler {node.id!r} lacks a physical object receipt")
            self.producer.require_regular(object_path, label="raw effective compiler object")
            payload = object_path.read_bytes()
            generated_inputs = self.generated_node_inputs.get(node.id, ordinary_visibility)
            compiler_invocation = self.producer.compiler_epoch_invocation(
                node,
                epoch=("generated" if node.id in self.generated_node_inputs else "effective"),
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
            declared_outputs = self.producer.declared_outputs(node)
            for reference, declared in zip(node.outputs, declared_outputs, strict=True):
                if not reference.startswith("build/"):
                    raise ClassicProjectError(
                        f"compiler {node.id!r} has a non-build output reference"
                    )
                physical_output = self.producer.registered_outputs().get(declared)
                if physical_output is None:
                    raise ClassicProjectError(
                        f"compiler {node.id!r} lacks an output capture receipt"
                    )
                self.producer.require_regular(physical_output, label="raw compiler output capture")
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

    def materialize_generated_input_epoch(
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
            self.producer.require_regular(destination, label="generated compiler input")
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
            path = self.producer.reference(reference)
        if path is None:
            raise ClassicProjectError(f"semantic archive reference is unresolved: {reference!r}")
        self.producer.require_regular(path, label=f"semantic archive {reference!r}")
        return path

    def audit_link_controls(
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
            terminal = by_id[target.link_node_id]
            try:
                references = direct_terminal_link_control_references(terminal)
            except ClassicLinkClosureError as exc:
                raise ClassicProjectError(
                    f"target {target.target_id!r} linker-control references failed: {exc}"
                ) from exc
            object_inputs: dict[str, bytes] = {}
            for reference in references.objects:
                path = self.producer.reference(reference)
                if path is None:
                    raise ClassicProjectError("linker OBJ input is not materializable")
                self.producer.require_regular(path, label=f"directive input {reference!r}")
                object_inputs[reference] = path.read_bytes()
            archive_refs = references.archives
            archive_inputs = {
                reference: self._archive_path(reference).read_bytes() for reference in archive_refs
            }
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
                    f"rerun rbit graph extract ... {suggestions}"
                ) from exc
            except Exception as exc:
                raise ClassicProjectError(
                    f"target {target.target_id!r} linker-control closure failed: {exc}"
                ) from exc

            definition_refs = references.definitions
            definition: ModuleDefinitionReceipt | None = None
            if definition_refs:
                path = self.producer.reference(definition_refs[0])
                if path is None:
                    raise ClassicProjectError("module-definition input is unresolved")
                self.producer.require_regular(path, label="module-definition input")
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
            audited_compilers: set[str] = set()
            try:
                for target_id in all_target_ids:
                    audited_compilers.update(
                        terminal_link_input_topology(
                            self.graph,
                            target_id,
                        ).compiler_node_ids
                    )
            except ClassicLinkTopologyError as exc:
                raise ClassicProjectError(str(exc)) from exc
            if audited_compilers != all_compilers:
                missing = sorted(all_compilers - audited_compilers, key=str.casefold)
                raise ClassicProjectError(
                    f"compiler outputs lack terminal link-input ancestry: {missing}"
                )
        self._link_directive_closures = MappingProxyType(closures)
        self._module_definition_receipts = MappingProxyType(definitions)
        for step in steps:
            self._progress.emit("link-controls", step.step_id)
        return tuple(steps)

    def _link_root_sets(self, node: ProducerNode) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Separate initial LINK demand from export-only retention controls."""

        demand: set[str] = set()
        retention: set[str] = set()
        explicit_entry = False
        no_entry = False
        for argument in node.arguments:
            folded = argument.casefold()
            if folded.startswith(("/entry:", "-entry:")):
                demand.add(argument.split(":", 1)[1])
                explicit_entry = True
            elif folded.startswith(("/include:", "-include:")):
                demand.add(argument.split(":", 1)[1])
            elif folded.startswith(("/export:", "-export:")):
                declaration = argument.split(":", 1)[1].split(",", 1)[0]
                retention.add(declaration.split("=", 1)[-1])
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
                demand.add("__DllMainCRTStartup@12")
            else:
                # The selected CRT startup depends on subsystem and source-level
                # entry spelling.  Keeping the complete closed MSVC 4.x set is a
                # conservative reachability root for carrier isolation.
                demand.update(
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
        # Object-carried /INCLUDE controls are positional linker demand.  The
        # semantic validator binds them to their exact object/library ordinal;
        # flattening them here would incorrectly make a later directive early.
        retention.update(directive_closure.export_symbols)
        definition = self._module_definition_receipts.get(target_id)
        if definition is not None:
            retention.update(definition.exports)
        if any(not value or "\0" in value for value in demand | retention):
            raise ClassicProjectError("linker root-symbol declaration is malformed")
        return (
            tuple(sorted(demand, key=str.casefold)),
            tuple(sorted(retention, key=str.casefold)),
        )

    def _target_link_closures(self) -> tuple[TargetLinkClosure, ...]:
        by_id = {node.id: node for node in self.graph.nodes}
        closures: list[TargetLinkClosure] = []
        for target in self.targets:
            try:
                topology = terminal_link_input_topology(self.graph, target.target_id)
            except ClassicLinkTopologyError as exc:
                raise ClassicProjectError(str(exc)) from exc
            compiler_ids = topology.compiler_node_ids
            archive_refs = topology.archive_refs
            archives = tuple(
                ArchiveInput(reference, self._archive_path(reference).read_bytes())
                for reference in archive_refs
            )
            terminal = by_id[target.link_node_id]
            demand_roots, retention_roots = self._link_root_sets(terminal)
            closures.append(
                TargetLinkClosure(
                    target.target_id,
                    compiler_ids,
                    archive_refs,
                    archives,
                    demand_roots,
                    retention_roots,
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
            raise ClassicProjectError("project-overlay proof lacks its counterfactual namespace")
        semantic_namespace_ids.add(self._counterfactual_namespace_id)
        missing = semantic_namespace_ids - set(self.producer.compiler_namespaces())
        if missing:
            raise ClassicProjectError(
                "project-overlay proof lacks compiler namespaces: "
                + ", ".join(sorted(missing, key=str.casefold))
            )
        return tuple(
            self.producer.compiler_namespaces()[namespace_id].evidence
            for namespace_id in sorted(semantic_namespace_ids, key=str.casefold)
        )

    def validate_project_overlay_compiler_epoch(self) -> StepExecutionReceipt:
        """Reject compiler-epoch divergence before any candidate composition."""

        started = time.monotonic()
        compiler_products = self._compiler_products()
        compiler_namespaces = self._semantic_compiler_namespaces(compiler_products)
        resource_receipts = dict(self.producer.resource_dependency_receipts())
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

    def apply_semantic_proofs(
        self,
        witnesses: list[InterventionWitness],
        *,
        donor_semantic_lanes: Sequence[DonorSemanticLane],
    ) -> None:
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
        donor_lanes = tuple(
            sorted(
                donor_semantic_lanes,
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


__all__ = [
    "ClassicOverlayEpochs",
]
