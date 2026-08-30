"""Classic producer evidence records and causal proof assembly."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Literal

from reprobit.classic_execution_records import (
    ClassicProducerRead,
    ClassicProducerReadReceipt,
    ClassicRuntimeEvidenceInputs,
)
from reprobit.classic_includes import IncludeOrigin
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicProjectError, InterventionWitness
from reprobit.classic_runtime_files import _safe_relative
from reprobit.classic_runtime_graph import (
    ClassicCompileRecord,
    classic_compiler_product_refs,
)
from reprobit.costs import calculate_intervention_cost, intervention_cost_row_digest
from reprobit.execution import (
    FileReceipt,
    ObjectTransformAttestation,
    ObjectTransformOperation,
    ProducerAttestation,
    ProducerKind,
    RuntimeEvidence,
    RuntimeEvidenceContext,
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
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import (
    ProducerNode,
    ProducerRole,
    materialize_reference,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    LegacyOracleInstallIntervention,
    intervention_authority_digest,
)
from reprobit.strict_json import canonical_json

CLASSIC_RUNTIME_EVIDENCE_PROVIDER_ID = "classic-msvc-producer-graph-v1"


def _reference(inputs: ClassicRuntimeEvidenceInputs, value: str) -> Path | None:
    return materialize_reference(
        value,
        source_root=inputs.effective_root,
        build_root=inputs.build_root,
        toolchain_root=inputs.toolchain_root,
    )


def _logical_for_host_path(inputs: ClassicRuntimeEvidenceInputs, path: Path) -> str:
    resolved = path.resolve(strict=False)
    try:
        relative = resolved.relative_to(inputs.logical_drive_root)
    except ValueError as exc:
        raise ClassicProjectError(f"compiler path escapes the logical drive: {path}") from exc
    if not relative.parts:
        return normalize_logical_path(f"{inputs.logical_drive_letter}:\\")
    return normalize_logical_path(f"{inputs.logical_drive_letter}:\\" + "\\".join(relative.parts))


def _archive_path(inputs: ClassicRuntimeEvidenceInputs, reference: str) -> Path:
    path = (
        inputs.system_libraries.get(reference)
        if reference.startswith("system-library/")
        else _reference(inputs, reference)
    )
    if path is None or path.is_symlink() or not path.is_file():
        raise ClassicProjectError(f"semantic archive is unresolved or redirected: {reference!r}")
    return path


def _record_for_unit(
    inputs: ClassicRuntimeEvidenceInputs,
    unit: ClassicPreparedUnit,
) -> ClassicCompileRecord:
    source = (inputs.effective_root / unit.plan.source).resolve(strict=True)
    matches = tuple(
        item
        for item in inputs.compile_records
        if item.source == source and item.build_target == unit.plan.build_target
    )
    if len(matches) != 1:
        raise ClassicProjectError(f"TU {unit.plan.id!r} has {len(matches)} committed compile lanes")
    return matches[0]


def _terminal_stage_logical_path(
    *,
    target_id: str,
    public_path: str,
    intervention_id: str,
    index: int,
    count: int,
) -> str:
    if index == count - 1:
        return public_path
    suffix = PurePosixPath(public_path).suffix
    return f".reprobit/stages/terminal/{target_id}/{index:04d}-{intervention_id}{suffix}"


def _evidence_identifier(prefix: str, *material: object) -> str:
    suffix = Digest.from_bytes(canonical_json(material)).value[:24]
    return f"{prefix}.{suffix}"


def _statement_receipt_keys(statement: object) -> frozenset[tuple[str, int]]:
    receipts: set[tuple[str, int]] = set()

    def collect(value: object) -> None:
        if isinstance(value, Mapping):
            raw_digest = value.get("digest")
            raw_size = value.get("size")
            if isinstance(raw_size, int):
                with suppress(ValueError):
                    receipts.add((Digest.model_validate(raw_digest).value, raw_size))
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    collect(statement)
    return frozenset(receipts)


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


def _named_statement_receipt(
    statement: Mapping[str, object],
    name: str,
) -> tuple[Digest, int]:
    value = statement.get(name)
    if not isinstance(value, Mapping):
        raise ClassicProjectError(f"semantic {name} receipt is absent")
    size = value.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ClassicProjectError(f"semantic {name} size is malformed")
    try:
        digest = Digest.model_validate(value.get("digest"))
    except ValueError as exc:
        raise ClassicProjectError(f"semantic {name} digest is malformed") from exc
    return digest, size


class _ClassicEvidenceAssembler:
    """Translate one closed classic execution into its causal proof DAG."""

    def __init__(
        self,
        inputs: ClassicRuntimeEvidenceInputs,
        context: RuntimeEvidenceContext,
    ) -> None:
        record = inputs.record
        self.inputs = inputs
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
        self.nodes = {item.id: item for item in inputs.graph.nodes}
        self.interventions = {item.id: item for item in context.bundle.interventions}
        self.witnesses = {item.intervention_id: item for item in record.witnesses}
        if set(self.witnesses) != set(self.interventions):
            missing = sorted(set(self.interventions) - set(self.witnesses))
            extra = sorted(set(self.witnesses) - set(self.interventions))
            raise ClassicProjectError(
                f"runtime witnesses differ from interventions; missing={missing}, extra={extra}"
            )
        self.object_transforms = {
            item.unit_id.casefold(): item for item in record.object_transforms
        }
        if len(self.object_transforms) != len(record.object_transforms):
            raise ClassicProjectError("runtime repeats an object transform receipt")
        self.object_repacks = self._object_repack_interventions()
        self.artifacts: dict[str, Artifact] = {}
        self.artifact_ids_by_receipt: dict[tuple[str, int], list[str]] = {}
        self.semantic_receipt_keys: dict[str, frozenset[tuple[str, int]]] = {}
        self.provenance: dict[str, ProvenanceNode] = {}
        self.terminal_node: dict[str, str] = {}
        self.producers: list[ProducerAttestation] = []
        self.object_transform_attestations: list[ObjectTransformAttestation] = []
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
            provider_id=CLASSIC_RUNTIME_EVIDENCE_PROVIDER_ID,
            run_binding=self.context.run_binding,
            artifacts=tuple(self.artifacts.values()),
            provenance=tuple(self.provenance.values()),
            certificates=tuple(self.certificates.values()),
            producers=tuple(self.producers),
            object_transforms=tuple(self.object_transform_attestations),
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

    def _object_repack_interventions(
        self,
    ) -> dict[str, tuple[str, ClassicRecipeIntervention]]:
        repacks: dict[str, tuple[str, ClassicRecipeIntervention]] = {}
        for intervention in self.interventions.values():
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
            identity = reference.casefold()
            if identity in repacks:
                raise ClassicProjectError(f"multiple rdata repacks own object {reference!r}")
            repacks[identity] = (reference, intervention)
        return repacks

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
        self.artifact_ids_by_receipt.setdefault((artifact.digest.value, artifact.size), []).append(
            artifact.id
        )
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
            relative = path.relative_to(self.inputs.effective_root).as_posix()
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
        effective = self.inputs.effective_root.resolve(strict=False)
        for receipt in sorted(self.input_receipts.values(), key=lambda item: str(item.path)):
            try:
                receipt.path.resolve(strict=False).relative_to(effective)
            except ValueError:
                continue
            result.append(
                self._leaf_artifact(
                    path=receipt.path,
                    logical_path=_logical_for_host_path(self.inputs, receipt.path),
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
        tool_id = self.inputs.role_tool_ids[role]
        tool = self.locked.get(tool_id)
        if tool is None:
            raise ClassicProjectError(f"producer role {role.value!r} names an unlocked tool")
        path = self.inputs.toolchain_root.joinpath(*PurePosixPath(tool.path).parts).resolve(
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
            logical_path=_logical_for_host_path(self.inputs, path),
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
            path = _archive_path(self.inputs, reference)
            kind = ArtifactKind.EXTERNAL
            origin = ArtifactOrigin.EXTERNAL
            first_party = False
        else:
            resolved = _reference(self.inputs, reference)
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
        tool_id = self.inputs.role_tool_ids[node.role]
        tool = self.locked[tool_id]
        path = _reference(self.inputs, reference)
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
        for node in self.inputs.graph.nodes:
            if node.role is ProducerRole.COMPILER:
                inputs = self._node_inputs(node)
                for reference in node.outputs:
                    captured = captures.get(reference.casefold())
                    if captured is None or captured.node_id != node.id:
                        raise ClassicProjectError(
                            f"compiler output lacks its raw capture: {reference!r}"
                        )
                    path = _reference(self.inputs, reference)
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
            path = _reference(self.inputs, reference)
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
        pending = {node.id: node for node in self.inputs.graph.nodes if node.role is role}
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
        output_receipts = self._proof_receipt_keys(proof, "output")
        input_receipts = self._proof_receipt_keys(proof, "input")
        for artifact_id in artifact_ids:
            artifact = self.artifacts[artifact_id]
            receipt = (artifact.digest.value, artifact.size)
            if receipt in output_receipts:
                relation: Literal["input", "output"] = "output"
            elif receipt in input_receipts:
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

    def _proof_receipt_keys(
        self,
        proof: SemanticProof,
        relation: Literal["input", "output"],
    ) -> frozenset[tuple[str, int]]:
        key = (
            proof.input_statement_digest.value
            if relation == "input"
            else proof.output_statement_digest.value
        )
        cached = self.semantic_receipt_keys.get(key)
        if cached is not None:
            return cached
        statement = proof.input_statement if relation == "input" else proof.output_statement
        receipts = _statement_receipt_keys(statement)
        self.semantic_receipt_keys[key] = receipts
        return receipts

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
            intervention_authority_digest=intervention_authority_digest(intervention),
            intervention_cost_digest=intervention_cost_row_digest(
                calculate_intervention_cost(intervention)
            ),
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
        current = self.artifacts[current_id]
        if proof is not None and (
            current.digest.value,
            current.size,
        ) not in self._proof_receipt_keys(proof, "input"):
            raise ClassicProjectError(
                f"intervention {witness.intervention_id!r} semantic input does not "
                "bind the current artifact"
            )
        legacy_inputs: tuple[str, ...] = ()
        if witness.legacy_oracle_install:
            legacy_statement = witness.semantic_output_statement
            if legacy_statement is None or (
                Digest.from_bytes(canonical_json(legacy_statement)) != witness.evidence_digest
            ):
                raise ClassicProjectError(
                    f"legacy intervention {witness.intervention_id!r} has unbound evidence"
                )
            if (
                witness.output_digest is None
                or legacy_statement.get("output_sha256") != witness.output_digest.value
                or legacy_statement.get("output_size") != witness.output_size
            ):
                raise ClassicProjectError(
                    f"legacy intervention {witness.intervention_id!r} output receipt "
                    "differs from its evidence"
                )
            legacy_inputs = self._legacy_input_artifacts(
                witness,
                current_id=current_id,
                statement=legacy_statement,
            )
        proof_candidate = (
            _statement_candidate_receipt(proof.output_statement) if proof is not None else None
        )
        statement_candidate = _statement_candidate_receipt(witness.semantic_output_statement)
        if (
            proof_candidate is not None
            and statement_candidate is not None
            and proof_candidate != statement_candidate
        ):
            raise ClassicProjectError(
                f"intervention {witness.intervention_id!r} has conflicting output statements"
            )
        semantic_candidate = proof_candidate or statement_candidate
        if (witness.output_digest is None) != (witness.output_size is None):
            raise ClassicProjectError(
                f"intervention {witness.intervention_id!r} has a partial output receipt"
            )
        if witness.output_size is not None and (
            isinstance(witness.output_size, bool) or witness.output_size < 0
        ):
            raise ClassicProjectError(
                f"intervention {witness.intervention_id!r} has an invalid output size"
            )
        declared_candidate = (
            None
            if witness.output_digest is None or witness.output_size is None
            else (witness.output_digest, witness.output_size)
        )
        if (
            declared_candidate is not None
            and semantic_candidate is not None
            and declared_candidate != semantic_candidate
        ):
            raise ClassicProjectError(
                f"intervention {witness.intervention_id!r} output receipt conflicts "
                "with its semantic statement"
            )
        candidate = declared_candidate or semantic_candidate
        if candidate is None:
            if fallback_receipt is None:
                raise ClassicProjectError(
                    f"intervention {witness.intervention_id!r} lacks an output receipt"
                )
            digest, size = fallback_receipt.digest, fallback_receipt.size
        else:
            digest, size = candidate
        inputs = tuple(dict.fromkeys((current_id, *additional_inputs, *legacy_inputs)))
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

    def _legacy_input_artifacts(
        self,
        witness: InterventionWitness,
        *,
        current_id: str,
        statement: Mapping[str, object],
    ) -> tuple[str, ...]:
        intervention = self.interventions.get(witness.intervention_id)
        if not isinstance(intervention, LegacyOracleInstallIntervention) or (
            len(intervention.dependencies) != 1
        ):
            raise ClassicProjectError("legacy evidence lacks one declared donor dependency")
        seed_receipt = _named_statement_receipt(statement, "seed_object")
        donor_receipt = _named_statement_receipt(statement, "donor_object")
        current = self.artifacts[current_id]
        if seed_receipt != (current.digest, current.size):
            raise ClassicProjectError(
                f"legacy intervention {witness.intervention_id!r} seed receipt differs "
                "from the current artifact"
            )
        dependency_id = intervention.dependencies[0]
        expected_logical = f".reprobit/private-donors/{dependency_id}.obj"
        donor_matches = [
            artifact_id
            for artifact_id in self.artifact_ids_by_receipt.get(
                (donor_receipt[0].value, donor_receipt[1]), ()
            )
            if (
                self.artifacts[artifact_id].kind is ArtifactKind.OBJECT
                and self.artifacts[artifact_id].logical_path == expected_logical
            )
        ]
        if len(donor_matches) != 1:
            raise ClassicProjectError(
                f"legacy intervention {witness.intervention_id!r} donor receipt resolves "
                f"to {len(donor_matches)} private donor artifacts"
            )
        return (donor_matches[0],)

    def _semantic_input_artifacts(self, witness: InterventionWitness) -> tuple[str, ...]:
        proof = witness.semantic_proof
        if proof is None:
            return ()
        matches = {
            artifact_id
            for receipt in self._proof_receipt_keys(proof, "input")
            for artifact_id in self.artifact_ids_by_receipt.get(receipt, ())
        }
        return tuple(sorted(matches))

    def _apply_group_order_transform(
        self,
        *,
        unit: ClassicPreparedUnit,
        object_reference: str,
        current_id: str,
    ) -> str:
        receipt = self.object_transforms.get(unit.plan.id.casefold())
        if receipt is None or receipt.unit_id != unit.plan.id:
            raise ClassicProjectError(
                f"group-order unit {unit.plan.id!r} lacks its object transform receipt"
            )
        group_order = unit.plan.group_order
        if group_order is None:
            raise ClassicProjectError(
                f"group-order unit {unit.plan.id!r} lacks its transform authority"
            )
        expected_operation = group_order.operation
        if (
            receipt.object_reference.casefold() != object_reference.casefold()
            or receipt.step_id != f"compose.{unit.plan.id}"
            or receipt.operation != expected_operation
            or receipt.input_size < 0
            or receipt.output_size < 0
        ):
            raise ClassicProjectError(
                f"group-order unit {unit.plan.id!r} has an inexact transform receipt"
            )
        current = self.artifacts[current_id]
        if current.digest != receipt.input_digest or current.size != receipt.input_size:
            raise ClassicProjectError(
                f"group-order input differs from semantic object stages: {object_reference!r}"
            )
        record = _record_for_unit(self.inputs, unit)
        expected_step_digest = Digest.from_bytes(
            canonical_json(
                {
                    "producer_node": record.node_id,
                    "unit": unit.plan.model_dump(mode="json"),
                    "output": receipt.output_digest.value,
                    "witnesses": [
                        self.witnesses[action.id].evidence_digest.value for action in unit.actions
                    ],
                    "group_order": receipt.evidence_digest.value,
                }
            )
        )
        step = self.steps.get(receipt.step_id)
        if step is None or (
            step.returncode != 0
            or step.attempts != 1
            or step.command_digest != expected_step_digest
            or step.output_digest != expected_step_digest
        ):
            raise ClassicProjectError(
                f"group-order unit {unit.plan.id!r} differs from its execution step"
            )
        path = _reference(self.inputs, object_reference)
        if path is None:
            raise ClassicProjectError("group-order output is not materializable")
        artifact_id = _evidence_identifier(
            "artifact",
            "object-transform",
            unit.plan.id,
            receipt.output_digest,
            receipt.output_size,
        )
        self._add_artifact(
            Artifact(
                id=artifact_id,
                kind=current.kind,
                logical_path=current.logical_path,
                digest=receipt.output_digest,
                size=receipt.output_size,
                origin=ArtifactOrigin.COMPOSED,
                inputs=(current_id,),
                receipt_path=str(path.resolve(strict=False)),
            ),
            kind=ProvenanceKind.OBJECT_TRANSFORM,
            operation=receipt.operation,
            origin=ArtifactOrigin.COMPOSED,
            parent_artifacts=(current_id,),
        )
        self.object_transform_attestations.append(
            ObjectTransformAttestation(
                id=_evidence_identifier("object-transform", artifact_id, receipt.step_id),
                artifact_id=artifact_id,
                input_artifact_id=current_id,
                step_id=receipt.step_id,
                operation=ObjectTransformOperation(receipt.operation),
                input_digest=receipt.input_digest,
                input_size=receipt.input_size,
                artifact_digest=receipt.output_digest,
                artifact_size=receipt.output_size,
                evidence_digest=receipt.evidence_digest,
                step_binding_digest=expected_step_digest,
            )
        )
        return artifact_id

    def _apply_translation_unit_transforms(self) -> None:
        applied_object_transforms: set[str] = set()
        for unit in sorted(self.inputs.units, key=lambda item: item.plan.id.casefold()):
            record = _record_for_unit(self.inputs, unit)
            node = self.nodes[record.node_id]
            _, object_reference = classic_compiler_product_refs(node)
            current = self.current_by_reference[object_reference.casefold()]
            for action in unit.actions:
                witness = self.witnesses[action.id]
                current = self._stage_artifact(
                    witness=witness,
                    current_id=current,
                    logical_path=self.artifacts[current].logical_path,
                    additional_inputs=self._semantic_input_artifacts(witness),
                )
            if unit.plan.group_order is not None:
                current = self._apply_group_order_transform(
                    unit=unit,
                    object_reference=object_reference,
                    current_id=current,
                )
                applied_object_transforms.add(unit.plan.id.casefold())
            if object_reference.casefold() not in self.object_repacks:
                path = _reference(self.inputs, object_reference)
                assert path is not None
                receipt = self.output_receipts[path.resolve(strict=False)]
                if self.artifacts[current].digest != receipt.digest or (
                    self.artifacts[current].size != receipt.size
                ):
                    raise ClassicProjectError(
                        f"semantic object stages differ from the final output: {object_reference!r}"
                    )
            self.current_by_reference[object_reference.casefold()] = current
        if applied_object_transforms != set(self.object_transforms):
            raise ClassicProjectError(
                "runtime object transform receipts differ from prepared group-order units"
            )

    def _apply_object_repack_transforms(self) -> None:
        for reference, intervention in sorted(
            self.object_repacks.values(),
            key=lambda item: item[1].id.casefold(),
        ):
            current = self.current_by_reference.get(reference.casefold())
            if current is None:
                raise ClassicProjectError("rdata object has no compiler ancestry")
            path = _reference(self.inputs, reference)
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
            path = _reference(self.inputs, reference)
            return path is not None and path.resolve(strict=False) == raw_path.resolve(strict=False)

        link_outputs = {
            item.raw_path.resolve(strict=False): self.current_by_reference[
                next(
                    reference.casefold()
                    for node in self.inputs.graph.nodes
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
            for index, witness in enumerate(image.witnesses):
                final_stage = index == len(image.witnesses) - 1
                current = self._stage_artifact(
                    witness=witness,
                    current_id=current,
                    logical_path=_terminal_stage_logical_path(
                        target_id=image.target_id,
                        public_path=specs[image.target_id].artifact,
                        intervention_id=witness.intervention_id,
                        index=index,
                        count=len(image.witnesses),
                    ),
                    additional_inputs=self._semantic_input_artifacts(witness),
                    fallback_receipt=final_receipt if final_stage else None,
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


def assemble_classic_runtime_evidence(
    inputs: ClassicRuntimeEvidenceInputs,
    context: RuntimeEvidenceContext,
) -> RuntimeEvidence:
    """Translate one completed classic execution into its causal proof DAG."""

    return _ClassicEvidenceAssembler(inputs, context).assemble()


__all__ = [
    "CLASSIC_RUNTIME_EVIDENCE_PROVIDER_ID",
    "assemble_classic_runtime_evidence",
]
