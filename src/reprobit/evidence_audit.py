"""Evidence graph auditing for trustworthy reproduction results."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Protocol, TypeVar

from reprobit.classic.semantic_contracts import (
    CLASSIC_SEMANTIC_CONTRACTS,
    RegisteredSemanticContract,
    semantic_proof_matches,
)
from reprobit.costs import calculate_intervention_cost, intervention_cost_row_digest
from reprobit.execution import (
    BuildExecutionReceipt,
    ObjectTransformAttestation,
    ObjectTransformOperation,
    ProducerAttestation,
    RuntimeEvidence,
    TargetVerification,
    classic_semantic_obligation_name,
)
from reprobit.formats import FormatError, parse_pe32
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    ByteRange,
    Certificate,
    ProvenanceKind,
    ProvenanceNode,
    Quarantine,
    quarantine_proof_binding,
)
from reprobit.paths import normalize_logical_path
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    LegacyOracleInstallIntervention,
    ProjectBundle,
    intervention_authority_digest,
)
from reprobit.toolchains import ToolchainError, portable_tree_receipt


class EvidenceClaim(StrEnum):
    LOGIC = "logic"
    ORIGIN = "origin"


def _toolchain_tree_member_is_locked(
    bundle: ProjectBundle,
    artifact: Artifact,
    path: Path,
    cache: dict[tuple[Path, str], bool],
) -> bool:
    """Verify one toolchain leaf against exactly one portable input-tree lock."""

    try:
        logical = PureWindowsPath(normalize_logical_path(artifact.logical_path))
        logical_root = PureWindowsPath(normalize_logical_path(bundle.spec.paths.toolchain))
    except Exception:
        return False
    if len(logical.parts) <= len(logical_root.parts) or tuple(
        item.casefold() for item in logical.parts[: len(logical_root.parts)]
    ) != tuple(item.casefold() for item in logical_root.parts):
        return False
    relative = tuple(logical.parts[len(logical_root.parts) :])
    matches = 0
    for tree in bundle.toolchain_lock.input_trees:
        tree_parts = PurePosixPath(tree.path).parts
        if len(relative) <= len(tree_parts) or tuple(
            item.casefold() for item in relative[: len(tree_parts)]
        ) != tuple(item.casefold() for item in tree_parts):
            continue
        member_parts = relative[len(tree_parts) :]
        tree_root = path
        for _ in member_parts:
            tree_root = tree_root.parent
        key = (tree_root.resolve(strict=False), tree.id)
        valid = cache.get(key)
        if valid is None:
            try:
                received = portable_tree_receipt(tree_root, tree.path)
            except (OSError, ToolchainError):
                valid = False
            else:
                valid = (
                    received.path == tree.path
                    and received.entry_count == tree.entry_count
                    and received.max_depth == tree.max_depth
                    and received.membership_sha256 == tree.membership_digest.value
                    and received.content_sha256 == tree.content_digest.value
                    and received.algorithm == tree.algorithm
                )
            cache[key] = valid
        if valid:
            matches += 1
    return matches == 1


def _has_registered_semantic_proof(
    certificate: Certificate,
    family: ClassicRecipeFamily,
    contract: RegisteredSemanticContract,
) -> bool:
    obligation_name = classic_semantic_obligation_name(family)
    matching_obligations = tuple(
        obligation
        for obligation in certificate.obligations
        if obligation.name == obligation_name
        and obligation.passed
        and obligation.evidence_digest is not None
    )
    if len(matching_obligations) != 1:
        return False
    evidence_digest = matching_obligations[0].evidence_digest
    return any(
        semantic_proof_matches(proof, family, contract) and proof.evidence_digest == evidence_digest
        for proof in certificate.semantic_proofs
    )


class _HasId(Protocol):
    id: str


_Indexed = TypeVar("_Indexed", bound=_HasId)
_IssueSink = Callable[[EvidenceClaim, str, str], None]


@dataclass(frozen=True, order=True, slots=True)
class EvidenceIssue:
    claim: EvidenceClaim
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class EvidenceAudit:
    issues: tuple[EvidenceIssue, ...]
    quarantines: tuple[Quarantine, ...]

    @property
    def logic_certified(self) -> bool:
        return not any(issue.claim is EvidenceClaim.LOGIC for issue in self.issues)

    @property
    def origin_integrity(self) -> bool:
        """Whether every non-quarantined origin claim is complete and valid."""

        return not any(issue.claim is EvidenceClaim.ORIGIN for issue in self.issues)

    @property
    def toolchain_origin(self) -> bool:
        return not self.quarantines and self.origin_integrity


def _logical_path(value: str) -> str:
    return value.replace("\\", "/").casefold()


def _legacy_quarantine_ranges(
    intervention: LegacyOracleInstallIntervention,
    target: TargetVerification | None,
) -> tuple[tuple[ByteRange, ...], Literal["artifact-file", "function-body"]]:
    """Translate body-relative legacy ranges into final PE file offsets.

    Reports must never silently label a function offset as an artifact offset.
    Mapping therefore succeeds only when every byte is backed by one contiguous
    PE section.  Generic/non-PE targets retain an explicit function-body
    coordinate space instead.
    """

    relative = tuple(item.output_range for item in intervention.ranges)
    # A generic target-scoped legacy action declares artifact offsets
    # directly. Only function-scoped actions need VA translation.
    if intervention.scope.function is None:
        return relative, "artifact-file"
    if target is None:
        return relative, "function-body"
    try:
        data = target.artifact.read_bytes()
        image = parse_pe32(data)
        mapped: list[ByteRange] = []
        for item in relative:
            address = intervention.oracle_address + item.offset
            rva = address - image.image_base
            if rva < 0:
                raise FormatError("legacy VA precedes the candidate image base")
            start = image.rva_to_file_offset(rva)
            last = image.rva_to_file_offset(rva + item.length - 1)
            if last != start + item.length - 1:
                raise FormatError("legacy VA range is not file-contiguous")
            mapped.append(ByteRange(offset=start, length=item.length))
        return tuple(mapped), "artifact-file"
    except (FormatError, OSError):
        return relative, "function-body"


class EvidenceAuditor:
    """Cross-validate certificates, artifact ancestry, and target receipts."""

    def audit(
        self,
        bundle: ProjectBundle,
        build: BuildExecutionReceipt,
        targets: tuple[TargetVerification, ...],
        runtime: tuple[RuntimeEvidence, ...],
        project_root: Path,
    ) -> EvidenceAudit:
        issues: set[EvidenceIssue] = set()

        def issue(claim: EvidenceClaim, code: str, message: str) -> None:
            issues.add(EvidenceIssue(claim, code, message))

        artifacts = self._unique_index(
            (artifact for evidence in runtime for artifact in evidence.artifacts),
            "artifact",
            issue,
        )
        nodes = self._unique_index(
            (node for evidence in runtime for node in evidence.provenance),
            "provenance",
            issue,
        )
        certificates = self._unique_index(
            (certificate for evidence in runtime for certificate in evidence.certificates),
            "certificate",
            issue,
        )
        interventions = {item.id: item for item in bundle.interventions}
        classic_interventions = {
            item.id: item
            for item in bundle.interventions
            if isinstance(item, ClassicRecipeIntervention)
        }
        legacy_intervention_ids = frozenset(
            item.id
            for item in bundle.interventions
            if isinstance(item, LegacyOracleInstallIntervention)
        )

        certificates_by_intervention: dict[str, list[Certificate]] = defaultdict(list)
        for certificate in certificates.values():
            certificates_by_intervention[certificate.intervention_id].append(certificate)
            intervention = interventions.get(certificate.intervention_id)
            if intervention is None:
                issue(
                    EvidenceClaim.LOGIC,
                    "certificate-intervention",
                    f"certificate {certificate.id!r} names a missing intervention",
                )
            elif certificate.intervention_authority_digest != intervention_authority_digest(
                intervention
            ):
                issue(
                    EvidenceClaim.LOGIC,
                    "certificate-intervention-authority",
                    f"certificate {certificate.id!r} binds different intervention authority",
                )
            if intervention is not None and (
                certificate.intervention_cost_digest
                != intervention_cost_row_digest(calculate_intervention_cost(intervention))
            ):
                issue(
                    EvidenceClaim.LOGIC,
                    "certificate-intervention-cost",
                    f"certificate {certificate.id!r} binds a different intervention cost row",
                )
            if any(
                obligation.passed and obligation.evidence_digest is None
                for obligation in certificate.obligations
            ):
                issue(
                    EvidenceClaim.LOGIC,
                    "unbound-obligation",
                    f"certificate {certificate.id!r} has a passing obligation without evidence",
                )
            for artifact_id in certificate.artifact_ids:
                if artifact_id not in artifacts:
                    issue(
                        EvidenceClaim.LOGIC,
                        "certificate-artifact",
                        f"certificate {certificate.id!r} names missing artifact {artifact_id!r}",
                    )
        for intervention_id in sorted(interventions):
            receipts = certificates_by_intervention.get(intervention_id, [])
            if not receipts:
                issue(
                    EvidenceClaim.LOGIC,
                    "missing-certificate",
                    f"intervention {intervention_id!r} has no certificate",
                )
            elif not all(receipt.passed for receipt in receipts):
                issue(
                    EvidenceClaim.LOGIC,
                    "failed-certificate",
                    f"intervention {intervention_id!r} has a failed certificate",
                )
            classic_intervention = classic_interventions.get(intervention_id)
            contract = (
                CLASSIC_SEMANTIC_CONTRACTS.get(classic_intervention.family)
                if classic_intervention is not None
                else None
            )
            if classic_intervention is not None and contract is None:
                issue(
                    EvidenceClaim.LOGIC,
                    "unsupported-semantic-family",
                    f"classic family {classic_intervention.family.value!r} has no "
                    "registered semantic validator",
                )
            elif (
                classic_intervention is not None
                and contract is not None
                and not any(
                    _has_registered_semantic_proof(receipt, classic_intervention.family, contract)
                    for receipt in receipts
                )
            ):
                issue(
                    EvidenceClaim.LOGIC,
                    "missing-semantic-proof",
                    f"classic intervention {intervention_id!r} lacks a typed proof from "
                    f"registered validator {contract.validator_id!r}",
                )

        referenced_certificates: set[str] = set()
        children_by_artifact: dict[str, set[str]] = defaultdict(set)
        for node in nodes.values():
            if node.artifact_id not in artifacts:
                issue(
                    EvidenceClaim.ORIGIN,
                    "provenance-artifact",
                    f"provenance {node.id!r} names missing artifact {node.artifact_id!r}",
                )
            for parent_id in node.parents:
                parent = nodes.get(parent_id)
                if parent is None:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "provenance-parent",
                        f"provenance {node.id!r} names missing parent {parent_id!r}",
                    )
                elif parent.artifact_id == node.artifact_id:
                    children_by_artifact[parent.artifact_id].add(parent.id)
            if node.intervention_id is not None and node.intervention_id not in interventions:
                issue(
                    EvidenceClaim.LOGIC,
                    "provenance-intervention",
                    f"provenance {node.id!r} names missing intervention {node.intervention_id!r}",
                )
            for certificate_id in node.certificate_ids:
                referenced_certificates.add(certificate_id)
                bound_certificate = certificates.get(certificate_id)
                if bound_certificate is None:
                    issue(
                        EvidenceClaim.LOGIC,
                        "provenance-certificate",
                        f"provenance {node.id!r} names missing certificate {certificate_id!r}",
                    )
                elif (
                    node.intervention_id is not None
                    and bound_certificate.intervention_id != node.intervention_id
                ):
                    issue(
                        EvidenceClaim.LOGIC,
                        "certificate-mismatch",
                        f"provenance {node.id!r} uses a certificate for another intervention",
                    )
                elif node.artifact_id not in bound_certificate.artifact_ids:
                    issue(
                        EvidenceClaim.LOGIC,
                        "certificate-artifact-mismatch",
                        f"provenance {node.id!r} uses a certificate for another artifact",
                    )
            if node.kind in {
                ProvenanceKind.INTERVENTION,
                ProvenanceKind.METADATA_TRANSFORM,
                ProvenanceKind.ORACLE_INSTALL,
            }:
                if not node.certificate_ids:
                    issue(
                        EvidenceClaim.LOGIC,
                        "uncertified-transform",
                        f"provenance transform {node.id!r} has no certificate",
                    )
                elif any(
                    certificate_id in certificates and not certificates[certificate_id].passed
                    for certificate_id in node.certificate_ids
                ):
                    issue(
                        EvidenceClaim.LOGIC,
                        "failed-transform",
                        f"provenance transform {node.id!r} has failed proof obligations",
                    )
                classic_intervention = classic_interventions.get(node.intervention_id or "")
                contract = (
                    CLASSIC_SEMANTIC_CONTRACTS.get(classic_intervention.family)
                    if classic_intervention is not None
                    else None
                )
                if (
                    classic_intervention is not None
                    and contract is not None
                    and node.certificate_ids
                    and not any(
                        certificate_id in certificates
                        and certificates[certificate_id].intervention_id == node.intervention_id
                        and node.artifact_id in certificates[certificate_id].artifact_ids
                        and _has_registered_semantic_proof(
                            certificates[certificate_id],
                            classic_intervention.family,
                            contract,
                        )
                        for certificate_id in node.certificate_ids
                    )
                ):
                    issue(
                        EvidenceClaim.LOGIC,
                        "semantic-certificate-mismatch",
                        f"provenance transform {node.id!r} is not bound to a typed proof "
                        f"from registered validator {contract.validator_id!r}",
                    )
        for certificate_id in set(certificates).difference(referenced_certificates):
            issue(
                EvidenceClaim.LOGIC,
                "unbound-certificate",
                f"certificate {certificate_id!r} is not bound into provenance",
            )

        self._validate_node_cycles(nodes, issue)
        self._validate_artifact_graph(artifacts, issue)
        self._validate_provenance_artifact_edges(artifacts, nodes, issue)
        self._validate_input_roots(bundle, build, artifacts, nodes, issue)
        attested_artifacts = self._validate_producers(
            bundle,
            build,
            runtime,
            artifacts,
            project_root,
            issue,
        )
        self._validate_object_transforms(build, runtime, artifacts, nodes, issue)

        nodes_by_artifact: dict[str, list[ProvenanceNode]] = defaultdict(list)
        for node in nodes.values():
            nodes_by_artifact[node.artifact_id].append(node)
        terminal_by_artifact: dict[str, tuple[ProvenanceNode, ...]] = {}
        for artifact_id, artifact in artifacts.items():
            terminal = tuple(
                node
                for node in nodes_by_artifact.get(artifact_id, [])
                if node.id not in children_by_artifact.get(artifact_id, set())
            )
            terminal_by_artifact[artifact_id] = terminal
            self._validate_terminal_coverage(artifact, terminal, issue)

        target_receipts = {target.target_id: target for target in targets}
        target_artifacts: dict[str, Artifact] = {}
        for target in bundle.spec.targets:
            matches = [
                artifact
                for artifact in artifacts.values()
                if _logical_path(artifact.logical_path) == _logical_path(target.artifact)
            ]
            if len(matches) != 1:
                issue(
                    EvidenceClaim.ORIGIN,
                    "target-artifact",
                    f"target {target.id!r} resolves to {len(matches)} proof artifacts",
                )
                continue
            artifact = matches[0]
            target_artifacts[target.id] = artifact
            receipt = target_receipts.get(target.id)
            if receipt is None:
                issue(
                    EvidenceClaim.LOGIC,
                    "target-receipt",
                    f"target {target.id!r} has no verification receipt",
                )
            elif (
                receipt.comparison.candidate_size != artifact.size
                or receipt.comparison.candidate_digest != artifact.digest.value
            ):
                issue(
                    EvidenceClaim.LOGIC,
                    "stale-artifact-proof",
                    f"target {target.id!r} content differs from its proof artifact",
                )
                issue(
                    EvidenceClaim.ORIGIN,
                    "stale-artifact-proof",
                    f"target {target.id!r} content differs from its proof artifact",
                )
            self._validate_target_origins(
                target.id,
                artifact,
                terminal_by_artifact.get(artifact.id, ()),
                artifacts,
                nodes,
                certificates,
                attested_artifacts,
                legacy_intervention_ids,
                issue,
            )

        quarantines: list[Quarantine] = []
        for intervention in bundle.interventions:
            if not isinstance(intervention, LegacyOracleInstallIntervention):
                continue
            quarantine_artifact = target_artifacts.get(intervention.scope.target)
            artifact_id = (
                quarantine_artifact.id
                if quarantine_artifact is not None
                else intervention.scope.target
            )
            mapped_ranges, coordinate_space = _legacy_quarantine_ranges(
                intervention,
                target_receipts.get(intervention.scope.target),
            )
            coordinate_detail = (
                "final artifact-file offsets mapped from the declared function VA"
                if coordinate_space == "artifact-file"
                else "function-body-relative offsets (the artifact was not safely PE-mappable)"
            )
            quarantine = Quarantine(
                id=intervention.id,
                kind="legacy.oracle_install",
                artifact_id=artifact_id,
                ranges=mapped_ranges,
                byte_count=intervention.byte_count,
                reason=(
                    "declared output ranges have frozen reference-oracle ancestry; "
                    + coordinate_detail
                ),
                coordinate_space=coordinate_space,
                scope=intervention.scope,
                base_address=intervention.oracle_address,
            )
            receipts = certificates_by_intervention.get(intervention.id, [])
            execution_obligations = tuple(
                obligation
                for certificate in receipts
                for obligation in certificate.obligations
                if obligation.name == "quarantined_oracle_install"
                and obligation.passed
                and obligation.evidence_digest is not None
            )
            if len(receipts) == 1 and len(execution_obligations) == 1:
                evidence_digest = execution_obligations[0].evidence_digest
                assert evidence_digest is not None
                quarantine = quarantine.model_copy(
                    update={
                        "proof_binding": quarantine_proof_binding(
                            quarantine,
                            certificate_id=receipts[0].id,
                            evidence_digest=evidence_digest,
                        )
                    }
                )
            else:
                issue(
                    EvidenceClaim.LOGIC,
                    "quarantine-proof-binding",
                    f"legacy intervention {intervention.id!r} lacks one exact "
                    "oracle-install proof obligation",
                )
            quarantines.append(quarantine)
        return EvidenceAudit(
            tuple(sorted(issues)),
            tuple(sorted(quarantines, key=lambda item: item.id)),
        )

    @staticmethod
    def _unique_index(
        items: Iterable[_Indexed],
        label: str,
        issue: _IssueSink,
    ) -> dict[str, _Indexed]:
        result: dict[str, _Indexed] = {}
        for item in items:
            item_id = item.id
            if item_id in result:
                issue(
                    EvidenceClaim.LOGIC,
                    f"duplicate-{label}",
                    f"duplicate {label} id {item_id!r}",
                )
                issue(
                    EvidenceClaim.ORIGIN,
                    f"duplicate-{label}",
                    f"duplicate {label} id {item_id!r}",
                )
            else:
                result[item_id] = item
        return result

    @staticmethod
    def _validate_node_cycles(nodes: Mapping[str, ProvenanceNode], issue: _IssueSink) -> None:
        visiting: set[str] = set()
        complete: set[str] = set()
        cycle_reported = False

        def visit(node_id: str) -> None:
            nonlocal cycle_reported
            if node_id in complete or node_id not in nodes:
                return
            if node_id in visiting:
                if not cycle_reported:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "provenance-cycle",
                        "provenance graph contains a cycle",
                    )
                    cycle_reported = True
                return
            visiting.add(node_id)
            for parent in nodes[node_id].parents:
                visit(parent)
            visiting.remove(node_id)
            complete.add(node_id)

        for node_id in nodes:
            visit(node_id)

    @staticmethod
    def _validate_artifact_graph(artifacts: Mapping[str, Artifact], issue: _IssueSink) -> None:
        visiting: set[str] = set()
        complete: set[str] = set()
        for artifact in artifacts.values():
            for input_id in artifact.inputs:
                if input_id not in artifacts:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "artifact-input",
                        f"artifact {artifact.id!r} names missing input {input_id!r}",
                    )
            if (
                artifact.origin
                in {
                    ArtifactOrigin.COMPOSED,
                    ArtifactOrigin.CERTIFIED_POSTLINK,
                }
                and not artifact.inputs
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "artifact-root",
                    f"derived artifact {artifact.id!r} has no inputs",
                )

        def visit(artifact_id: str) -> None:
            if artifact_id in complete or artifact_id not in artifacts:
                return
            if artifact_id in visiting:
                issue(
                    EvidenceClaim.ORIGIN,
                    "artifact-cycle",
                    "artifact input graph contains a cycle",
                )
                return
            visiting.add(artifact_id)
            for input_id in artifacts[artifact_id].inputs:
                visit(input_id)
            visiting.remove(artifact_id)
            complete.add(artifact_id)

        for artifact_id in artifacts:
            visit(artifact_id)

    @staticmethod
    def _validate_input_roots(
        bundle: ProjectBundle,
        build: BuildExecutionReceipt,
        artifacts: Mapping[str, Artifact],
        nodes: Mapping[str, ProvenanceNode],
        issue: _IssueSink,
    ) -> None:
        """Bind every declared source/tool/external root to a sealed input receipt."""

        inputs = {item.path.resolve(strict=False): item for item in build.inputs}
        locked = {
            (item.digest, item.size)
            for item in (
                *bundle.toolchain_lock.tools,
                *bundle.toolchain_lock.runtime_files,
            )
        }
        tree_cache: dict[tuple[Path, str], bool] = {}
        for node in nodes.values():
            if node.parents or node.kind not in {
                ProvenanceKind.SOURCE,
                ProvenanceKind.TOOLCHAIN,
                ProvenanceKind.EXTERNAL,
            }:
                continue
            artifact = artifacts.get(node.artifact_id)
            if artifact is None:
                continue
            if node.kind is ProvenanceKind.SOURCE and artifact.origin is ArtifactOrigin.FRESH_DONOR:
                # Donor arenas are created and recursively sealed inside the
                # closed runtime; they deliberately do not predate the run.
                continue
            if (
                node.kind is ProvenanceKind.TOOLCHAIN
                and artifact.kind is not ArtifactKind.TOOLCHAIN
            ):
                # Historical whole-artifact producer roots are validated by
                # their producer attestation instead of as input leaves.
                continue
            path = Path(artifact.receipt_path or artifact.logical_path)
            if not path.is_absolute():
                issue(
                    EvidenceClaim.ORIGIN,
                    "input-root-path",
                    f"input root {artifact.id!r} does not carry its sealed receipt path",
                )
                continue
            receipt = inputs.get(path.resolve(strict=False))
            if receipt is None or (
                receipt.digest != artifact.digest or receipt.size != artifact.size
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "input-root-receipt",
                    f"input root {artifact.id!r} differs from the build receipt",
                )
                continue
            if node.kind is ProvenanceKind.SOURCE and (
                artifact.kind is not ArtifactKind.SOURCE
                or artifact.origin is not ArtifactOrigin.FRESH_SEED
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "source-root-kind",
                    f"source root {artifact.id!r} has inconsistent evidence types",
                )
            elif (
                node.kind is ProvenanceKind.TOOLCHAIN
                and artifact.kind is ArtifactKind.TOOLCHAIN
                and (artifact.digest, artifact.size) not in locked
                and not _toolchain_tree_member_is_locked(bundle, artifact, path, tree_cache)
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "toolchain-root-lock",
                    f"toolchain root {artifact.id!r} is absent from every exact "
                    "file or portable input-tree lock",
                )

    @staticmethod
    def _validate_provenance_artifact_edges(
        artifacts: Mapping[str, Artifact],
        nodes: Mapping[str, ProvenanceNode],
        issue: _IssueSink,
    ) -> None:
        """Bind provenance edges to the artifact DAG they claim to explain.

        The two graphs intentionally carry different detail, but they cannot be
        independent declarations. Otherwise a provider could list a real donor
        in ``Artifact.inputs`` while presenting an unrelated clean provenance
        root for the output.
        """

        cross_artifact_parents: dict[str, set[str]] = defaultdict(set)
        for node in nodes.values():
            artifact = artifacts.get(node.artifact_id)
            if artifact is None:
                continue
            if node.kind in {
                ProvenanceKind.SOURCE,
                ProvenanceKind.TOOLCHAIN,
                ProvenanceKind.EXTERNAL,
            }:
                if node.parents:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "root-provenance-parents",
                        f"root provenance {node.id!r} unexpectedly has parents",
                    )
            elif not node.parents:
                issue(
                    EvidenceClaim.ORIGIN,
                    "transform-provenance-root",
                    f"transform provenance {node.id!r} has no parents",
                )
            for parent_id in node.parents:
                parent = nodes.get(parent_id)
                if parent is None or parent.artifact_id == node.artifact_id:
                    continue
                cross_artifact_parents[node.artifact_id].add(parent.artifact_id)
                if parent.artifact_id not in artifact.inputs:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "undeclared-provenance-input",
                        f"provenance {node.id!r} reads artifact "
                        f"{parent.artifact_id!r} absent from {artifact.id!r} inputs",
                    )
        for artifact in artifacts.values():
            missing = set(artifact.inputs).difference(
                cross_artifact_parents.get(artifact.id, set())
            )
            if missing:
                issue(
                    EvidenceClaim.ORIGIN,
                    "unproven-artifact-input",
                    f"artifact {artifact.id!r} has inputs absent from provenance: "
                    f"{sorted(missing)!r}",
                )

    @staticmethod
    def _validate_producers(
        bundle: ProjectBundle,
        build: BuildExecutionReceipt,
        runtime: tuple[RuntimeEvidence, ...],
        artifacts: Mapping[str, Artifact],
        project_root: Path,
        issue: _IssueSink,
    ) -> frozenset[str]:
        attestations: dict[str, ProducerAttestation] = {}
        for evidence in runtime:
            for attestation in evidence.producers:
                if attestation.id in attestations:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "duplicate-producer-attestation",
                        f"duplicate producer attestation {attestation.id!r}",
                    )
                else:
                    attestations[attestation.id] = attestation

        locked_tools = {
            tool.id: tool
            for tool in (
                *bundle.toolchain_lock.tools,
                *bundle.toolchain_lock.runtime_files,
            )
        }
        steps = {step.step_id: step for step in build.steps}
        output_receipts = {item.path.resolve(strict=False): item for item in build.outputs}
        valid: dict[str, list[ProducerAttestation]] = defaultdict(list)
        for attestation in attestations.values():
            artifact = artifacts.get(attestation.artifact_id)
            if artifact is None:
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-artifact",
                    f"producer attestation {attestation.id!r} names a missing artifact",
                )
                continue
            accepted = True
            tool = locked_tools.get(attestation.tool_id)
            if tool is None or tool.digest != attestation.tool_digest:
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-tool",
                    f"producer attestation {attestation.id!r} does not name a locked tool",
                )
                accepted = False
            if attestation.step_id not in steps:
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-step",
                    f"producer attestation {attestation.id!r} names a missing build step",
                )
                accepted = False
            if (
                artifact.digest != attestation.artifact_digest
                or artifact.size != attestation.artifact_size
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-content",
                    f"producer attestation {attestation.id!r} differs from its artifact",
                )
                accepted = False
            logical = artifact.logical_path.replace("\\", "/")
            if artifact.receipt_path is None and (
                logical.startswith("/") or re.match(r"^[A-Za-z]:/", logical)
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-path",
                    f"producer artifact {artifact.id!r} lacks a project-relative receipt path",
                )
                accepted = False
            elif not attestation.captured_before_overwrite:
                artifact_path = (
                    Path(artifact.receipt_path).resolve(strict=False)
                    if artifact.receipt_path is not None
                    else (project_root / logical).resolve(strict=False)
                )
                receipt = output_receipts.get(artifact_path)
                if (
                    receipt is None
                    or receipt.digest != attestation.artifact_digest
                    or receipt.size != attestation.artifact_size
                    or receipt.producer_step != attestation.step_id
                ):
                    issue(
                        EvidenceClaim.ORIGIN,
                        "producer-receipt",
                        f"producer attestation {attestation.id!r} is not bound to a fresh output",
                    )
                    accepted = False
                elif not receipt.fresh or not build.cold:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "producer-freshness",
                        f"producer attestation {attestation.id!r} is not from a cold fresh output",
                    )
                    accepted = False
            elif not build.cold:
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-freshness",
                    f"captured producer attestation {attestation.id!r} is not cold",
                )
                accepted = False
            if accepted:
                valid[artifact.id].append(attestation)

        completely_attested: set[str] = set()
        for artifact_id, items in valid.items():
            artifact = artifacts[artifact_id]
            whole = [item for item in items if not item.ranges]
            ranged = [item for item in items if item.ranges]
            if whole and (len(whole) != 1 or ranged):
                issue(
                    EvidenceClaim.ORIGIN,
                    "producer-coverage",
                    f"artifact {artifact_id!r} has ambiguous producer coverage",
                )
                continue
            if whole:
                completely_attested.add(artifact_id)
                continue
            spans = sorted(
                (span for item in ranged for span in item.ranges),
                key=lambda span: span.offset,
            )
            cursor = 0
            for span in spans:
                if span.offset != cursor:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "producer-coverage",
                        f"artifact {artifact_id!r} has a producer range gap or overlap",
                    )
                    break
                cursor = span.end
            else:
                if cursor == artifact.size:
                    completely_attested.add(artifact_id)
                else:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "producer-coverage",
                        f"artifact {artifact_id!r} producer coverage is incomplete",
                    )
        return frozenset(completely_attested)

    @staticmethod
    def _validate_object_transforms(
        build: BuildExecutionReceipt,
        runtime: tuple[RuntimeEvidence, ...],
        artifacts: Mapping[str, Artifact],
        nodes: Mapping[str, ProvenanceNode],
        issue: _IssueSink,
    ) -> None:
        """Require a closed, exact attestation for every COMDAT order rewrite."""

        attestations: dict[str, ObjectTransformAttestation] = {}
        for evidence in runtime:
            for attestation in evidence.object_transforms:
                if attestation.id in attestations:
                    issue(
                        EvidenceClaim.ORIGIN,
                        "duplicate-object-transform-attestation",
                        f"duplicate object-transform attestation {attestation.id!r}",
                    )
                else:
                    attestations[attestation.id] = attestation

        steps = {step.step_id: step for step in build.steps}
        nodes_by_artifact: dict[str, list[ProvenanceNode]] = defaultdict(list)
        for node in nodes.values():
            nodes_by_artifact[node.artifact_id].append(node)
        valid_nodes: set[str] = set()
        for attestation in attestations.values():
            output = artifacts.get(attestation.artifact_id)
            transform_input = artifacts.get(attestation.input_artifact_id)
            matching_nodes = [
                node
                for node in nodes_by_artifact.get(attestation.artifact_id, [])
                if node.kind is ProvenanceKind.OBJECT_TRANSFORM
            ]
            accepted = True
            if output is None or transform_input is None:
                issue(
                    EvidenceClaim.ORIGIN,
                    "object-transform-artifact",
                    f"object-transform attestation {attestation.id!r} names a missing artifact",
                )
                accepted = False
            elif (
                output.kind is not ArtifactKind.OBJECT
                or transform_input.kind is not ArtifactKind.OBJECT
                or output.origin is not ArtifactOrigin.COMPOSED
                or output.inputs != (attestation.input_artifact_id,)
                or output.digest != attestation.artifact_digest
                or output.size != attestation.artifact_size
                or transform_input.digest != attestation.input_digest
                or transform_input.size != attestation.input_size
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "object-transform-content",
                    f"object-transform attestation {attestation.id!r} differs from its artifacts",
                )
                accepted = False
            step = steps.get(attestation.step_id)
            if step is None or (
                step.returncode != 0
                or step.attempts != 1
                or step.command_digest != attestation.step_binding_digest
                or step.output_digest != attestation.step_binding_digest
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "object-transform-step",
                    f"object-transform attestation {attestation.id!r} differs from its build step",
                )
                accepted = False
            if len(matching_nodes) != 1:
                issue(
                    EvidenceClaim.ORIGIN,
                    "object-transform-provenance",
                    f"object-transform attestation {attestation.id!r} resolves to "
                    f"{len(matching_nodes)} provenance nodes",
                )
                accepted = False
            else:
                node = matching_nodes[0]
                parent = nodes.get(node.parents[0]) if len(node.parents) == 1 else None
                if (
                    node.operation != attestation.operation.value
                    or parent is None
                    or parent.artifact_id != attestation.input_artifact_id
                ):
                    issue(
                        EvidenceClaim.ORIGIN,
                        "object-transform-provenance",
                        f"object-transform attestation {attestation.id!r} differs from provenance",
                    )
                    accepted = False
                elif accepted:
                    valid_nodes.add(node.id)

        operations = {operation.value for operation in ObjectTransformOperation}
        for node in nodes.values():
            if node.kind is ProvenanceKind.OBJECT_TRANSFORM and node.id not in valid_nodes:
                issue(
                    EvidenceClaim.ORIGIN,
                    "unattested-object-transform",
                    f"object transform {node.id!r} lacks one exact current-run attestation",
                )
            if node.operation in operations and node.kind is not ProvenanceKind.OBJECT_TRANSFORM:
                issue(
                    EvidenceClaim.ORIGIN,
                    "misclassified-object-transform",
                    f"object transform {node.id!r} is not typed as an object transform",
                )
            if node.kind is ProvenanceKind.PRODUCER and node.origin is ArtifactOrigin.COMPOSED:
                artifact = artifacts.get(node.artifact_id)
                parent = nodes.get(node.parents[0]) if len(node.parents) == 1 else None
                parent_artifact = artifacts.get(parent.artifact_id) if parent is not None else None
                if (
                    node.operation != "publish"
                    or artifact is None
                    or parent_artifact is None
                    or artifact.inputs != (parent_artifact.id,)
                    or artifact.digest != parent_artifact.digest
                    or artifact.size != parent_artifact.size
                ):
                    issue(
                        EvidenceClaim.ORIGIN,
                        "unattested-composed-producer",
                        f"composed producer {node.id!r} is not a byte-preserving publication",
                    )

    @staticmethod
    def _validate_terminal_coverage(
        artifact: Artifact,
        terminal: tuple[ProvenanceNode, ...],
        issue: _IssueSink,
    ) -> None:
        if not terminal:
            issue(
                EvidenceClaim.ORIGIN,
                "missing-provenance",
                f"artifact {artifact.id!r} has no terminal provenance",
            )
            return
        ranged = [node for node in terminal if node.byte_range is not None]
        if ranged and len(ranged) != len(terminal):
            issue(
                EvidenceClaim.ORIGIN,
                "mixed-provenance-ranges",
                f"artifact {artifact.id!r} mixes whole and ranged terminal provenance",
            )
            return
        if not ranged:
            if len(terminal) != 1:
                issue(
                    EvidenceClaim.ORIGIN,
                    "ambiguous-provenance",
                    f"artifact {artifact.id!r} has multiple whole-artifact terminals",
                )
            return
        cursor = 0
        for node in sorted(ranged, key=lambda item: item.byte_range.offset):  # type: ignore[union-attr]
            span = node.byte_range
            assert span is not None
            if span.offset != cursor:
                issue(
                    EvidenceClaim.ORIGIN,
                    "provenance-coverage",
                    f"artifact {artifact.id!r} has a range gap or overlap at {cursor}",
                )
                return
            cursor = span.end
        if cursor != artifact.size:
            issue(
                EvidenceClaim.ORIGIN,
                "provenance-coverage",
                f"artifact {artifact.id!r} provenance covers {cursor} of {artifact.size} bytes",
            )

    @staticmethod
    def _validate_target_origins(
        target_id: str,
        artifact: Artifact,
        terminal: tuple[ProvenanceNode, ...],
        artifacts: Mapping[str, Artifact],
        nodes: Mapping[str, ProvenanceNode],
        certificates: Mapping[str, Certificate],
        attested_artifacts: frozenset[str],
        legacy_intervention_ids: frozenset[str],
        issue: _IssueSink,
    ) -> None:
        if not artifact.first_party:
            issue(
                EvidenceClaim.ORIGIN,
                "external-target",
                f"target {target_id!r} is not a first-party artifact",
            )
        ancestry: set[str] = set()
        pending = [node.id for node in terminal]
        while pending:
            node_id = pending.pop()
            if node_id in ancestry or node_id not in nodes:
                continue
            ancestry.add(node_id)
            pending.extend(nodes[node_id].parents)
        for node_id in sorted(ancestry):
            node = nodes[node_id]
            disclosed_legacy = (
                node.kind is ProvenanceKind.ORACLE_INSTALL
                and node.origin is ArtifactOrigin.ORACLE
                and node.intervention_id in legacy_intervention_ids
            )
            if node.origin is ArtifactOrigin.STALE_REFUSED or (
                node.origin is ArtifactOrigin.ORACLE and not disclosed_legacy
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "forbidden-origin",
                    f"target {target_id!r} descends from {node.origin.value} at {node.id!r}",
                )
            if not node.parents:
                root_artifact = artifacts.get(node.artifact_id)
                valid_toolchain = (
                    node.kind is ProvenanceKind.TOOLCHAIN
                    and node.origin in {ArtifactOrigin.FRESH_SEED, ArtifactOrigin.FRESH_DONOR}
                    and node.artifact_id in attested_artifacts
                )
                valid_source = (
                    node.kind is ProvenanceKind.SOURCE
                    and node.origin in {ArtifactOrigin.FRESH_SEED, ArtifactOrigin.FRESH_DONOR}
                    and root_artifact is not None
                    and root_artifact.kind is ArtifactKind.SOURCE
                    and root_artifact.first_party
                )
                valid_locked_tool = (
                    node.kind is ProvenanceKind.TOOLCHAIN
                    and node.origin is ArtifactOrigin.FRESH_SEED
                    and root_artifact is not None
                    and root_artifact.kind is ArtifactKind.TOOLCHAIN
                )
                valid_external = (
                    node.kind is ProvenanceKind.EXTERNAL
                    and node.origin is ArtifactOrigin.EXTERNAL
                    and root_artifact is not None
                    and not root_artifact.first_party
                )
                if not (valid_toolchain or valid_source or valid_locked_tool or valid_external):
                    issue(
                        EvidenceClaim.ORIGIN,
                        "invalid-root-origin",
                        f"target {target_id!r} has invalid provenance root {node.id!r}",
                    )
            if node.kind in {
                ProvenanceKind.INTERVENTION,
                ProvenanceKind.METADATA_TRANSFORM,
            } and (
                not node.certificate_ids
                or any(
                    certificate_id not in certificates or not certificates[certificate_id].passed
                    for certificate_id in node.certificate_ids
                )
            ):
                issue(
                    EvidenceClaim.ORIGIN,
                    "uncertified-origin-transform",
                    f"target {target_id!r} has uncertified transform {node.id!r}",
                )


__all__ = [
    "EvidenceAudit",
    "EvidenceAuditor",
    "EvidenceClaim",
    "EvidenceIssue",
]
