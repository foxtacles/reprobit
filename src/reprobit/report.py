"""Canonical machine report and deterministic self-contained HTML rendering."""

from __future__ import annotations

import html
import os
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from reprobit.costs import CostBreakdown, calculate_cost
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    ByteRange,
    Certificate,
    Digest,
    Identifier,
    ProvenanceKind,
    ProvenanceNode,
    StrictModel,
    Verdict,
    quarantine_proof_binding,
)
from reprobit.schema import MsvcRelease, ProjectBundle
from reprobit.secure_paths import atomic_publish_relative
from reprobit.strict_json import JsonValue, StrictJSONError, canonical_json, strict_load


class ToolSummary(StrictModel):
    id: Identifier
    digest: Digest
    size: Annotated[int, Field(gt=0)] | None = None


class ToolchainTreeSummary(StrictModel):
    """Compact public identity for one locked portable toolchain tree."""

    id: Identifier
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    entry_count: Annotated[int, Field(ge=0)]
    max_depth: Annotated[int, Field(ge=0)]
    membership_digest: Digest
    content_digest: Digest


class ToolchainSummary(StrictModel):
    profile: Identifier
    release: MsvcRelease
    tools: tuple[ToolSummary, ...]
    input_trees: tuple[ToolchainTreeSummary, ...] = ()

    @model_validator(mode="after")
    def contents_are_canonical(self) -> ToolchainSummary:
        if self.tools != tuple(sorted(self.tools, key=lambda item: item.id)):
            raise ValueError("toolchain tools must be in canonical order")
        if self.input_trees != tuple(sorted(self.input_trees, key=lambda item: item.id)):
            raise ValueError("toolchain input trees must be in canonical order")
        if len({item.id for item in self.tools}) != len(self.tools):
            raise ValueError("toolchain tool identities must be unique")
        if len({item.id for item in self.input_trees}) != len(self.input_trees):
            raise ValueError("toolchain input-tree identities must be unique")
        return self


class LogicalPathSummary(StrictModel):
    profile: Identifier
    source: str
    build: str
    toolchain: str


class TargetSummary(StrictModel):
    id: Identifier
    artifact: str
    candidate_size: Annotated[int, Field(gt=0)] | None = None
    candidate_digest: Digest | None = None
    oracle_size: Annotated[int, Field(gt=0)]
    oracle_digest: Digest
    byte_exact: bool

    @model_validator(mode="after")
    def candidate_receipt_is_complete(self) -> TargetSummary:
        if (self.candidate_size is None) != (self.candidate_digest is None):
            raise ValueError("candidate size and digest must be recorded together")
        receipt_is_exact = (
            self.candidate_size is not None
            and self.candidate_digest is not None
            and self.candidate_size == self.oracle_size
            and self.candidate_digest == self.oracle_digest
        )
        if self.byte_exact != receipt_is_exact:
            raise ValueError("target byte-exact claim differs from its candidate/oracle receipts")
        return self


class EvidenceSummary(StrictModel):
    artifacts: Annotated[int, Field(ge=0)] = 0
    provenance_nodes: Annotated[int, Field(ge=0)] = 0
    certificates: Annotated[int, Field(ge=0)] = 0
    passed_certificates: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def passed_is_bounded(self) -> EvidenceSummary:
        if self.passed_certificates > self.certificates:
            raise ValueError("passed certificates cannot exceed certificate count")
        return self


class ProducerSummary(StrictModel):
    """Canonical wire form of a locked-producer attestation."""

    id: Annotated[str, Field(min_length=1, max_length=1024)]
    artifact_id: Annotated[str, Field(min_length=1, max_length=1024)]
    step_id: Annotated[str, Field(min_length=1, max_length=1024)]
    producer_kind: Literal["compiler", "linker", "librarian", "resource"]
    tool_id: Annotated[str, Field(min_length=1, max_length=1024)]
    tool_digest: Digest
    artifact_digest: Digest
    artifact_size: Annotated[int, Field(ge=0)]
    ranges: tuple[ByteRange, ...] = ()
    captured_before_overwrite: bool = False


class ExecutionFileReceipt(StrictModel):
    """Canonical wire form of one file in a build execution receipt."""

    path: Annotated[str, Field(min_length=1, max_length=8192)]
    digest: Digest
    size: Annotated[int, Field(ge=0)]
    fresh: bool
    producer_step: Annotated[str, Field(min_length=1, max_length=1024)] | None = None
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=0)]

    @field_validator("path")
    @classmethod
    def path_has_no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("execution receipt path contains NUL")
        return value


class ExecutionStepReceipt(StrictModel):
    """Canonical wire form of one executed or trusted-internal step."""

    id: Annotated[str, Field(min_length=1, max_length=1024)]
    returncode: int
    attempts: Annotated[int, Field(ge=1)]
    duration_seconds: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    output_digest: Digest
    command_digest: Digest


class BuildExecutionSummary(StrictModel):
    """Complete consumable form of :class:`BuildExecutionReceipt`."""

    cold: bool
    inputs: tuple[ExecutionFileReceipt, ...]
    outputs: tuple[ExecutionFileReceipt, ...]
    steps: tuple[ExecutionStepReceipt, ...]

    @model_validator(mode="after")
    def canonical_and_closed(self) -> BuildExecutionSummary:
        def file_key(item: ExecutionFileReceipt) -> tuple[str, str]:
            return item.path.casefold(), item.path

        def step_key(item: ExecutionStepReceipt) -> tuple[str, str]:
            return item.id.casefold(), item.id

        for label, values in (("inputs", self.inputs), ("outputs", self.outputs)):
            key = file_key
            if tuple(sorted(values, key=key)) != values:
                raise ValueError(f"build execution {label} must be in canonical order")
            identities = [item.path.casefold() for item in values]
            if len(identities) != len(set(identities)):
                raise ValueError(f"build execution {label} identities must be unique")
        if tuple(sorted(self.steps, key=step_key)) != self.steps:
            raise ValueError("build execution steps must be in canonical order")
        step_identities = [step_key(item) for item in self.steps]
        if len(step_identities) != len(set(step_identities)):
            raise ValueError("build execution step identities must be unique")
        step_ids = {item.id for item in self.steps}
        if any(item.producer_step is not None for item in self.inputs):
            raise ValueError("build input receipts cannot claim a current-run producer")
        if any(
            item.producer_step is not None and item.producer_step not in step_ids
            for item in self.outputs
        ):
            raise ValueError("build output receipt names a missing execution step")
        if self.cold and any(not item.fresh for item in self.outputs):
            raise ValueError("cold build output receipts must be fresh")
        if any(item.returncode != 0 for item in self.steps):
            raise ValueError("build execution contains an unsuccessful step")
        return self


class TargetComparisonSummary(StrictModel):
    """Consumable literal-comparison receipt in the runtime binding."""

    id: Identifier
    logical_artifact: Annotated[str, Field(min_length=1, max_length=4096)]
    artifact: Annotated[str, Field(min_length=1, max_length=8192)]
    candidate_digest: Digest
    candidate_size: Annotated[int, Field(ge=0)]
    oracle_digest: Digest
    oracle_size: Annotated[int, Field(ge=0)]
    byte_exact: bool
    first_difference_offset: Annotated[int, Field(ge=0)] | None = None
    candidate_device: Annotated[int, Field(ge=0)]
    candidate_inode: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def exactness_matches_receipts(self) -> TargetComparisonSummary:
        exact = (
            self.candidate_digest == self.oracle_digest
            and self.candidate_size == self.oracle_size
        )
        if self.byte_exact != exact:
            raise ValueError("target comparison exactness differs from its receipts")
        if self.byte_exact != (self.first_difference_offset is None):
            raise ValueError("target comparison difference offset contradicts exactness")
        if "\x00" in self.artifact or "\x00" in self.logical_artifact:
            raise ValueError("target comparison artifact path contains NUL")
        if any(
            part == ".."
            for part in self.logical_artifact.replace("\\", "/").split("/")
        ):
            raise ValueError("target comparison logical artifact escapes its root")
        return self


class RuntimeBindingPreimage(StrictModel):
    """The complete canonical material hashed into a runtime binding."""

    build: BuildExecutionSummary
    targets: Annotated[tuple[TargetComparisonSummary, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def targets_are_canonical(self) -> RuntimeBindingPreimage:
        ordered = tuple(sorted(self.targets, key=lambda item: item.id))
        if ordered != self.targets:
            raise ValueError("runtime-binding targets must be in canonical order")
        ids = [item.id for item in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("runtime-binding target ids must be unique")
        output_paths = {item.path for item in self.build.outputs}
        if any(item.artifact not in output_paths for item in self.targets):
            raise ValueError("runtime-binding target is absent from build outputs")
        return self


class RuntimeProofBinding(StrictModel):
    """Self-verifying runtime binding and its public preimage."""

    digest: Digest
    preimage: RuntimeBindingPreimage

    @model_validator(mode="after")
    def digest_binds_preimage(self) -> RuntimeProofBinding:
        if self.digest != Digest.from_bytes(canonical_json(self.preimage)):
            raise ValueError("runtime binding digest does not bind its preimage")
        return self

    @classmethod
    def create(cls, preimage: RuntimeBindingPreimage) -> RuntimeProofBinding:
        return cls(digest=Digest.from_bytes(canonical_json(preimage)), preimage=preimage)


class AuditIssueSummary(StrictModel):
    """One independently reportable defect found by the evidence auditor."""

    claim: Literal["logic", "origin"]
    code: Identifier
    message: Annotated[str, Field(min_length=1, max_length=4096)]


class ComponentIdentity(StrictModel):
    """Content identity for code inside the authenticity trust boundary."""

    role: Literal["adapter", "evidence-provider", "package"]
    id: Annotated[str, Field(min_length=1, max_length=1024)]
    implementation: Annotated[str, Field(min_length=1, max_length=1024)]
    package: Identifier
    version: Annotated[str, Field(min_length=1, max_length=256)]
    digest: Digest


def _canonical_item_key(item: StrictModel) -> tuple[str, bytes]:
    identifier = getattr(item, "id", "")
    return str(identifier), canonical_json(item)


def _contains_content_receipt(value: object, digest: Digest, size: int) -> bool:
    """Find one exact ``{digest, size}`` receipt in a canonical statement."""

    if isinstance(value, Mapping):
        raw_digest = value.get("digest")
        raw_size = value.get("size")
        if raw_size == size:
            try:
                if Digest.model_validate(raw_digest) == digest:
                    return True
            except ValueError:
                pass
        return any(_contains_content_receipt(item, digest, size) for item in value.values())
    if isinstance(value, list):
        return any(_contains_content_receipt(item, digest, size) for item in value)
    return False


def _require_acyclic(edges: Mapping[str, tuple[str, ...]], *, label: str) -> None:
    visiting: set[str] = set()
    complete: set[str] = set()

    def visit(item_id: str) -> None:
        if item_id in complete:
            return
        if item_id in visiting:
            raise ValueError(f"proof-report {label} graph contains a cycle")
        visiting.add(item_id)
        for parent_id in edges[item_id]:
            visit(parent_id)
        visiting.remove(item_id)
        complete.add(item_id)

    for item_id in edges:
        visit(item_id)


class ProofReport(StrictModel):
    """The complete runtime proof payload carried by a machine report."""

    digest: Digest
    runtime: RuntimeProofBinding
    artifacts: tuple[Artifact, ...]
    provenance: tuple[ProvenanceNode, ...]
    certificates: tuple[Certificate, ...]
    producers: tuple[ProducerSummary, ...]
    audit_issues: tuple[AuditIssueSummary, ...]
    adapter: ComponentIdentity
    providers: tuple[ComponentIdentity, ...]
    package: ComponentIdentity

    @property
    def summary(self) -> EvidenceSummary:
        """Return deterministic unique-ID counts for the full payload."""

        certificates = {item.id: item for item in self.certificates}
        return EvidenceSummary(
            artifacts=len({item.id for item in self.artifacts}),
            provenance_nodes=len({item.id for item in self.provenance}),
            certificates=len(certificates),
            passed_certificates=sum(item.passed for item in certificates.values()),
        )

    @model_validator(mode="after")
    def canonical_and_bound(self) -> ProofReport:
        collections = (
            ("artifacts", self.artifacts),
            ("provenance", self.provenance),
            ("certificates", self.certificates),
            ("producers", self.producers),
            ("audit issues", self.audit_issues),
            ("providers", self.providers),
        )
        for label, values in collections:
            if tuple(sorted(values, key=_canonical_item_key)) != values:
                raise ValueError(f"proof-report {label} must be in canonical order")
        identified_collections = (
            ("artifacts", self.artifacts),
            ("provenance", self.provenance),
            ("certificates", self.certificates),
            ("producers", self.producers),
            ("providers", self.providers),
        )
        for label, values in identified_collections:
            identities = [str(item.id) for item in values]
            if len(identities) != len(set(identities)):
                raise ValueError(f"proof-report {label} identities must be unique")
        issue_identities = [canonical_json(item) for item in self.audit_issues]
        if len(issue_identities) != len(set(issue_identities)):
            raise ValueError("proof-report audit issues must be unique")
        if self.adapter.role != "adapter":
            raise ValueError("proof-report adapter has the wrong component role")
        if self.package.role != "package":
            raise ValueError("proof-report package has the wrong component role")
        if any(provider.role != "evidence-provider" for provider in self.providers):
            raise ValueError("proof-report provider has the wrong component role")
        artifacts = {item.id: item for item in self.artifacts}
        nodes = {item.id: item for item in self.provenance}
        certificates = {item.id: item for item in self.certificates}
        steps = {item.id for item in self.runtime.preimage.build.steps}
        producers_by_artifact: dict[str, list[ProducerSummary]] = {}
        for producer in self.producers:
            artifact = artifacts.get(producer.artifact_id)
            if artifact is None:
                raise ValueError("proof-report producer names a missing artifact")
            if (
                artifact.digest != producer.artifact_digest
                or artifact.size != producer.artifact_size
            ):
                raise ValueError("proof-report producer content differs from its artifact")
            if artifact.producer != producer.tool_id:
                raise ValueError("proof-report producer tool differs from its artifact")
            if producer.step_id not in steps:
                raise ValueError("proof-report producer names a missing execution step")
            producers_by_artifact.setdefault(artifact.id, []).append(producer)
        for artifact in self.artifacts:
            if any(input_id not in artifacts for input_id in artifact.inputs):
                raise ValueError("proof-report artifact names a missing input")
            if artifact.producer is not None and len(
                producers_by_artifact.get(artifact.id, ())
            ) != 1:
                raise ValueError(
                    "proof-report produced artifact must have one producer receipt"
                )
        provenance_by_artifact: dict[str, list[ProvenanceNode]] = {}
        for node in self.provenance:
            if node.artifact_id not in artifacts:
                raise ValueError("proof-report provenance names a missing artifact")
            if any(parent not in nodes for parent in node.parents):
                raise ValueError("proof-report provenance names a missing parent")
            if any(item not in certificates for item in node.certificate_ids):
                raise ValueError("proof-report provenance names a missing certificate")
            for certificate_id in node.certificate_ids:
                if node.artifact_id not in certificates[certificate_id].artifact_ids:
                    raise ValueError(
                        "proof-report provenance certificate differs from its artifact"
                    )
            provenance_by_artifact.setdefault(node.artifact_id, []).append(node)
        if any(
            artifact.id not in provenance_by_artifact for artifact in self.artifacts
        ):
            raise ValueError("proof-report artifact has no provenance")
        for certificate in self.certificates:
            if any(item not in artifacts for item in certificate.artifact_ids):
                raise ValueError("proof-report certificate names a missing artifact")
            for semantic in certificate.semantic_proofs:
                semantic_obligations = tuple(
                    item
                    for item in certificate.obligations
                    if item.evidence_digest == semantic.evidence_digest
                )
                if len(semantic_obligations) != 1 or not semantic_obligations[0].passed:
                    raise ValueError(
                        "proof-report semantic proof differs from its obligation"
                    )
                if semantic.input_statement is None or semantic.output_statement is None:
                    raise ValueError("proof-report semantic proof omits its statements")
                if not semantic.artifact_claims:
                    raise ValueError("proof-report semantic proof omits artifact claims")
                for claim in semantic.artifact_claims:
                    artifact = artifacts.get(claim.artifact_id)
                    if artifact is None or claim.artifact_id not in certificate.artifact_ids:
                        raise ValueError(
                            "proof-report semantic claim is outside its certificate"
                        )
                    if artifact.digest != claim.digest or artifact.size != claim.size:
                        raise ValueError(
                            "proof-report semantic claim differs from its artifact"
                        )
                    statement = (
                        semantic.input_statement
                        if claim.relation == "input"
                        else semantic.output_statement
                    )
                    if not _contains_content_receipt(statement, claim.digest, claim.size):
                        raise ValueError(
                            "proof-report semantic claim is absent from its statement"
                        )
        self._require_acyclic_artifacts(artifacts)
        self._require_forward_producer_stages(artifacts)
        self._require_acyclic_provenance(nodes)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"digest"},
            exclude_none=True,
            exclude_computed_fields=True,
        )
        expected = Digest.from_bytes(canonical_json(material))
        if self.digest != expected:
            raise ValueError("proof-report evidence digest does not bind its payload")
        return self

    @staticmethod
    def _require_acyclic_artifacts(artifacts: Mapping[str, Artifact]) -> None:
        _require_acyclic(
            {item.id: item.inputs for item in artifacts.values()},
            label="artifact",
        )

    @staticmethod
    def _require_acyclic_provenance(nodes: Mapping[str, ProvenanceNode]) -> None:
        _require_acyclic(
            {item.id: item.parents for item in nodes.values()},
            label="provenance",
        )

    @staticmethod
    def _require_forward_producer_stages(artifacts: Mapping[str, Artifact]) -> None:
        early = {ArtifactKind.OBJECT, ArtifactKind.PDB, ArtifactKind.RESOURCE}
        for artifact in artifacts.values():
            forbidden = (
                {ArtifactKind.ARCHIVE, ArtifactKind.IMAGE}
                if artifact.kind in early
                else ({ArtifactKind.IMAGE} if artifact.kind is ArtifactKind.ARCHIVE else set())
            )
            if not forbidden:
                continue
            pending = list(artifact.inputs)
            visited: set[str] = set()
            while pending:
                input_id = pending.pop()
                if input_id in visited:
                    continue
                visited.add(input_id)
                ancestor = artifacts[input_id]
                if ancestor.kind in forbidden:
                    raise ValueError("proof-report artifact causality runs after link")
                pending.extend(ancestor.inputs)

    @classmethod
    def create(
        cls,
        *,
        runtime: RuntimeProofBinding,
        artifacts: tuple[Artifact, ...],
        provenance: tuple[ProvenanceNode, ...],
        certificates: tuple[Certificate, ...],
        producers: tuple[ProducerSummary, ...],
        audit_issues: tuple[AuditIssueSummary, ...],
        adapter: ComponentIdentity,
        providers: tuple[ComponentIdentity, ...],
        package: ComponentIdentity,
    ) -> ProofReport:
        """Canonicalize a runtime proof payload and bind it to one digest."""

        ordered_artifacts = tuple(sorted(artifacts, key=_canonical_item_key))
        ordered_provenance = tuple(sorted(provenance, key=_canonical_item_key))
        ordered_certificates = tuple(sorted(certificates, key=_canonical_item_key))
        ordered_producers = tuple(sorted(producers, key=_canonical_item_key))
        ordered_issues = tuple(sorted(audit_issues, key=_canonical_item_key))
        ordered_providers = tuple(sorted(providers, key=_canonical_item_key))
        digest = Digest.from_bytes(
            canonical_json(
                {
                    "runtime": runtime,
                    "artifacts": ordered_artifacts,
                    "provenance": ordered_provenance,
                    "certificates": ordered_certificates,
                    "producers": ordered_producers,
                    "audit_issues": ordered_issues,
                    "adapter": adapter,
                    "providers": ordered_providers,
                    "package": package,
                }
            )
        )
        return cls(
            digest=digest,
            runtime=runtime,
            artifacts=ordered_artifacts,
            provenance=ordered_provenance,
            certificates=ordered_certificates,
            producers=ordered_producers,
            audit_issues=ordered_issues,
            adapter=adapter,
            providers=ordered_providers,
            package=package,
        )


class StageTiming(StrictModel):
    stage: Identifier
    seconds: Annotated[float, Field(ge=0, allow_inf_nan=False)]


class CacheMode(StrEnum):
    """Closed cache policy for certified report generation."""

    BYPASSED = "bypassed"


class CacheSummary(StrictModel):
    mode: CacheMode = CacheMode.BYPASSED
    hits: Annotated[int, Field(ge=0)] = 0
    misses: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def bypass_has_no_activity(self) -> CacheSummary:
        if self.hits or self.misses:
            raise ValueError("bypassed report cache cannot record activity")
        return self


class PreviousComparison(StrictModel):
    report_digest: Digest
    cost_delta: int
    clean_changed: bool
    byte_exact_changed: bool


class Report(StrictModel):
    """The self-authenticating report-v2 wire model."""

    schema_version: Literal[2] = 2
    project_id: Identifier
    run_id: Digest
    runtime_binding: Digest
    toolchain: ToolchainSummary
    paths: LogicalPathSummary
    verdict: Verdict
    costs: CostBreakdown
    targets: tuple[TargetSummary, ...]
    evidence: EvidenceSummary
    proof: ProofReport
    timings: tuple[StageTiming, ...] = ()
    cache: CacheSummary = Field(default_factory=CacheSummary)
    previous: PreviousComparison | None = None

    @model_validator(mode="after")
    def evidence_summary_matches_payload(self) -> Report:
        if self.targets != tuple(sorted(self.targets, key=lambda item: item.id)) or len(
            {item.id for item in self.targets}
        ) != len(self.targets):
            raise ValueError("report targets must be unique and canonical")
        if self.timings != tuple(sorted(self.timings, key=lambda item: item.stage)) or len(
            {item.stage for item in self.timings}
        ) != len(self.timings):
            raise ValueError("report timings must be unique and canonical")
        if self.verdict.quarantines != tuple(
            sorted(self.verdict.quarantines, key=lambda item: item.id)
        ) or len({item.id for item in self.verdict.quarantines}) != len(
            self.verdict.quarantines
        ):
            raise ValueError("report quarantines must be unique and canonical")
        if any(
            quarantine.ranges
            != tuple(sorted(quarantine.ranges, key=lambda item: item.offset))
            for quarantine in self.verdict.quarantines
        ):
            raise ValueError("report quarantine ranges must be canonical")
        if self.runtime_binding != self.proof.runtime.digest:
            raise ValueError("report runtime binding differs from its proof preimage")
        if self.verdict.cold != self.proof.runtime.preimage.build.cold:
            raise ValueError("report cold verdict differs from its build receipt")
        if self.evidence != self.proof.summary:
            raise ValueError("evidence summary differs from the proof-carrying payload")
        if not self.targets or any(
            target.candidate_size is None or target.candidate_digest is None
            for target in self.targets
        ):
            raise ValueError("proof-carrying reports require candidate receipts for every target")
        all_targets_exact = all(target.byte_exact for target in self.targets)
        if self.verdict.byte_exact != all_targets_exact:
            raise ValueError("report byte-exact verdict differs from target receipts")
        issue_claims = {item.claim for item in self.proof.audit_issues}
        if "logic" in issue_claims and self.verdict.logic_certified:
            raise ValueError("logic audit issues contradict the certified-logic verdict")
        if "origin" in issue_claims and self.verdict.toolchain_origin:
            raise ValueError("origin audit issues contradict the toolchain-origin verdict")
        if any(not certificate.passed for certificate in self.proof.certificates) and (
            self.verdict.logic_certified
        ):
            raise ValueError("failed proof certificates contradict the certified-logic verdict")
        if self.proof.audit_issues and self.verdict.clean:
            raise ValueError("a clean report cannot carry unresolved audit issues")
        comparisons = {
            item.id: item for item in self.proof.runtime.preimage.targets
        }
        proof_artifacts: dict[str, list[Artifact]] = {}
        for item in self.proof.artifacts:
            proof_artifacts.setdefault(item.logical_path, []).append(item)
        for target in self.targets:
            comparison = comparisons.get(target.id)
            if comparison is None or (
                comparison.logical_artifact != target.artifact
                or comparison.candidate_size != target.candidate_size
                or comparison.candidate_digest != target.candidate_digest
                or comparison.oracle_size != target.oracle_size
                or comparison.oracle_digest != target.oracle_digest
                or comparison.byte_exact != target.byte_exact
            ):
                raise ValueError(
                    "report target differs from its runtime comparison receipt"
                )
            matches = proof_artifacts.get(target.artifact, [])
            artifact_matches = [
                item
                for item in matches
                if item.size == target.candidate_size
                and item.digest == target.candidate_digest
            ]
            if len(artifact_matches) != 1 and "origin" not in issue_claims:
                raise ValueError("report target differs from its proof artifact")
        if set(comparisons) != {item.id for item in self.targets}:
            raise ValueError("report targets differ from runtime-binding targets")
        locked_tools = {item.id: item for item in self.toolchain.tools}
        for producer in self.proof.producers:
            tool = locked_tools.get(producer.tool_id)
            if tool is None or tool.digest != producer.tool_digest:
                raise ValueError("report producer differs from its locked tool")
        self._require_bound_quarantines()
        identity_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"run_id"},
            exclude_none=True,
            exclude_computed_fields=True,
        )
        expected_run_id = Digest.from_bytes(canonical_json(identity_material))
        if self.run_id != expected_run_id:
            raise ValueError("report run_id does not bind its complete public payload")
        return self

    def _require_bound_quarantines(self) -> None:
        if not self.verdict.quarantines:
            return
        artifacts = {item.id: item for item in self.proof.artifacts}
        nodes = {item.id: item for item in self.proof.provenance}
        certificates = {item.id: item for item in self.proof.certificates}
        for quarantine in self.verdict.quarantines:
            if quarantine.kind != "legacy.oracle_install":
                raise ValueError("report quarantine has an unrecognized authority kind")
            if quarantine.artifact_id not in artifacts:
                raise ValueError("report quarantine names a missing proof artifact")
            ancestors: set[str] = set()
            pending = [quarantine.artifact_id]
            while pending:
                artifact_id = pending.pop()
                if artifact_id in ancestors:
                    continue
                artifact = artifacts.get(artifact_id)
                if artifact is None:
                    raise ValueError("report quarantine artifact ancestry is incomplete")
                ancestors.add(artifact_id)
                pending.extend(artifact.inputs)
            provenance_ancestors: set[str] = set()
            pending_nodes = [
                node.id
                for node in nodes.values()
                if node.artifact_id == quarantine.artifact_id
            ]
            while pending_nodes:
                node_id = pending_nodes.pop()
                if node_id in provenance_ancestors:
                    continue
                node = nodes.get(node_id)
                if node is None:
                    raise ValueError("report quarantine provenance ancestry is incomplete")
                provenance_ancestors.add(node_id)
                pending_nodes.extend(node.parents)
            installs = [
                node
                for node_id, node in nodes.items()
                if node_id in provenance_ancestors
                if node.kind is ProvenanceKind.ORACLE_INSTALL
                and node.origin is ArtifactOrigin.ORACLE
                and node.artifact_id in ancestors
                and node.intervention_id == quarantine.id
            ]
            if len(installs) != 1:
                raise ValueError(
                    "report quarantine is not bound to exactly one oracle-install ancestor"
                )
            install = installs[0]
            if len(install.certificate_ids) != 1:
                raise ValueError(
                    "report quarantine oracle-install ancestor lacks one exact proof"
                )
            certificate = certificates.get(install.certificate_ids[0])
            if (
                certificate is None
                or certificate.intervention_id != quarantine.id
                or install.artifact_id not in certificate.artifact_ids
                or not certificate.passed
            ):
                raise ValueError(
                    "report quarantine oracle-install ancestor lacks its passing proof"
                )
            obligations = tuple(
                obligation
                for obligation in certificate.obligations
                if obligation.name == "quarantined_oracle_install"
                and obligation.passed
                and obligation.evidence_digest is not None
            )
            if len(obligations) != 1:
                raise ValueError(
                    "report quarantine lacks one exact oracle-install proof obligation"
                )
            evidence_digest = obligations[0].evidence_digest
            assert evidence_digest is not None
            expected_binding = quarantine_proof_binding(
                quarantine,
                certificate_id=certificate.id,
                evidence_digest=evidence_digest,
            )
            if quarantine.proof_binding != expected_binding:
                raise ValueError(
                    "report quarantine coordinates differ from their oracle-install proof"
                )

    @classmethod
    def create(
        cls,
        *,
        project_id: Identifier,
        runtime_binding: Digest,
        toolchain: ToolchainSummary,
        paths: LogicalPathSummary,
        verdict: Verdict,
        costs: CostBreakdown,
        targets: tuple[TargetSummary, ...],
        evidence: EvidenceSummary,
        proof: ProofReport,
        timings: tuple[StageTiming, ...] = (),
        cache: CacheSummary | None = None,
        previous: PreviousComparison | None = None,
    ) -> Report:
        """Bind every public report field into a consumer-recomputable run ID."""

        ordered_timings = tuple(sorted(timings, key=lambda item: item.stage))
        cache_summary = cache or CacheSummary()
        identity_material = {
            "schema_version": 2,
            "project_id": project_id,
            "runtime_binding": runtime_binding,
            "toolchain": toolchain,
            "paths": paths,
            "verdict": verdict,
            "costs": costs,
            "targets": targets,
            "evidence": evidence,
            "proof": proof,
            "timings": ordered_timings,
            "cache": cache_summary,
        }
        if previous is not None:
            identity_material["previous"] = previous
        return cls(
            project_id=project_id,
            run_id=Digest.from_bytes(canonical_json(identity_material)),
            runtime_binding=runtime_binding,
            toolchain=toolchain,
            paths=paths,
            verdict=verdict,
            costs=costs,
            targets=targets,
            evidence=evidence,
            proof=proof,
            timings=ordered_timings,
            cache=cache_summary,
            previous=previous,
        )

    @classmethod
    def from_bundle(
        cls,
        bundle: ProjectBundle,
        verdict: Verdict,
        *,
        evidence: EvidenceSummary,
        proof: ProofReport,
        target_results: Mapping[str, bool],
        target_artifacts: Mapping[str, tuple[int, Digest]],
        timings: tuple[StageTiming, ...] = (),
        cache: CacheSummary | None = None,
        previous: Report | None = None,
        run_binding: Digest | None = None,
    ) -> Report:
        """Build a deterministic report from a validated project tree."""

        target_ids = {target.id for target in bundle.spec.targets}
        if set(target_results) != target_ids:
            missing = sorted(target_ids - set(target_results))
            extra = sorted(set(target_results) - target_ids)
            raise ValueError(f"target result mismatch; missing={missing}, extra={extra}")
        if set(target_artifacts) != target_ids:
            missing = sorted(target_ids - set(target_artifacts))
            extra = sorted(set(target_artifacts) - target_ids)
            raise ValueError(f"target artifact mismatch; missing={missing}, extra={extra}")
        evidence_summary = evidence
        if evidence_summary != proof.summary:
            raise ValueError("evidence summary differs from the proof-carrying payload")
        if run_binding is not None and run_binding != proof.runtime.digest:
            raise ValueError("supplied runtime binding differs from proof preimage")
        oracles = {document.target_id: document for document in bundle.oracle_documents}
        targets = tuple(
            TargetSummary(
                id=target.id,
                artifact=target.artifact,
                candidate_size=target_artifacts[target.id][0],
                candidate_digest=target_artifacts[target.id][1],
                oracle_size=oracles[target.id].image_size,
                oracle_digest=oracles[target.id].image_digest,
                byte_exact=target_results[target.id],
            )
            for target in sorted(bundle.spec.targets, key=lambda item: item.id)
        )
        all_tools = (*bundle.toolchain_lock.tools, *bundle.toolchain_lock.runtime_files)
        toolchain = ToolchainSummary(
            profile=bundle.toolchain_lock.profile,
            release=bundle.toolchain_lock.release,
            tools=tuple(
                ToolSummary(id=tool.id, digest=tool.digest, size=tool.size)
                for tool in sorted(all_tools, key=lambda item: item.id)
            ),
            input_trees=tuple(
                ToolchainTreeSummary(
                    id=tree.id,
                    path=tree.path,
                    entry_count=tree.entry_count,
                    max_depth=tree.max_depth,
                    membership_digest=tree.membership_digest,
                    content_digest=tree.content_digest,
                )
                for tree in sorted(
                    bundle.toolchain_lock.input_trees, key=lambda item: item.id
                )
            ),
        )
        paths = LogicalPathSummary(
            profile=bundle.spec.paths.id,
            source=bundle.spec.paths.source,
            build=bundle.spec.paths.build,
            toolchain=bundle.spec.paths.toolchain,
        )
        costs = calculate_cost(bundle.interventions)
        previous_comparison = None
        if previous is not None:
            previous_comparison = PreviousComparison(
                report_digest=Digest.from_bytes(canonical_json(previous)),
                cost_delta=costs.project_total - previous.costs.project_total,
                clean_changed=verdict.clean != previous.verdict.clean,
                byte_exact_changed=verdict.byte_exact != previous.verdict.byte_exact,
            )
        return cls.create(
            project_id=bundle.spec.project_id,
            runtime_binding=proof.runtime.digest,
            toolchain=toolchain,
            paths=paths,
            verdict=verdict,
            costs=costs,
            targets=targets,
            evidence=evidence_summary,
            proof=proof,
            timings=tuple(sorted(timings, key=lambda item: item.stage)),
            cache=cache or CacheSummary(),
            previous=previous_comparison,
        )


def _atomic_write(path: str | Path, data: bytes) -> None:
    destination = Path(os.path.abspath(path))
    if not destination.anchor or len(destination.parts) < 2:
        raise OSError(f"report destination has no secure relative path: {path}")
    root = Path(destination.anchor)
    relative = PurePosixPath(*destination.parts[1:]).as_posix()
    atomic_publish_relative(root, relative, data)


def write_report_json(report: Report, path: str | Path) -> None:
    """Write canonical report JSON atomically."""

    _atomic_write(path, canonical_json(report))


def read_report_json(path: str | Path) -> Report:
    """Read and strictly validate a canonical report-v2 document."""

    source = Path(path)
    try:
        value = strict_load(source)
        return Report.model_validate_json(canonical_json(value))
    except (StrictJSONError, ValueError) as exc:
        raise ValueError(f"invalid report {source}: {exc}") from exc


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _table(headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...]) -> str:
    head = "".join(f'<th scope="col">{html.escape(value)}</th>' for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(value)}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_report_html(report: Report) -> str:
    """Render a deterministic report with no network or script dependency."""

    verdict_rows = tuple(
        (label, _yes_no(value))
        for label, value in (
            ("Cold build", report.verdict.cold),
            ("Byte exact", report.verdict.byte_exact),
            ("Logic certified", report.verdict.logic_certified),
            ("Toolchain origin", report.verdict.toolchain_origin),
            ("Quarantined", report.verdict.quarantined),
            ("Clean", report.verdict.clean),
        )
    )
    target_rows = tuple(
        (
            item.id,
            item.artifact,
            str(item.candidate_size) if item.candidate_size is not None else "not recorded",
            item.candidate_digest.value if item.candidate_digest is not None else "not recorded",
            str(item.oracle_size),
            item.oracle_digest.value,
            _yes_no(item.byte_exact),
        )
        for item in report.targets
    )
    class_rows = tuple(
        (
            item.cost_class.value,
            str(item.interventions),
            str(item.units),
            str(item.cost),
        )
        for item in report.costs.by_class
    )
    function_rows = tuple(
        (
            item.scope.target,
            item.scope.translation_unit or "",
            item.scope.function or "",
            str(item.direct_cost),
            f"{item.allocated_shared_cost.numerator}/{item.allocated_shared_cost.denominator}",
            str(item.exposure_cost),
        )
        for item in report.costs.by_function
    )
    intervention_rows = tuple(
        (
            item.intervention_id,
            item.kind,
            item.cost_class.value,
            item.scope.target,
            item.scope.translation_unit or "",
            item.scope.function or "",
            ", ".join(f"{unit.kind.value} x {unit.count}" for unit in item.units),
            str(item.cost),
        )
        for item in report.costs.interventions
    )
    quarantine = ""
    if report.verdict.quarantined:
        ranges = sum(len(item.ranges) for item in report.verdict.quarantines)
        bytes_installed = sum(item.byte_count for item in report.verdict.quarantines)
        quarantine_rows = tuple(
            (
                item.id,
                item.artifact_id,
                item.scope.function if item.scope is not None and item.scope.function else "",
                item.coordinate_space,
                f"0x{item.base_address:08x}" if item.base_address is not None else "",
                ", ".join(f"[0x{span.offset:x}, 0x{span.end:x})" for span in item.ranges),
                str(item.byte_count),
                item.reason,
            )
            for item in report.verdict.quarantines
        )
        quarantine = (
            '<section class="warning" role="alert"><h2>Authenticity quarantine</h2>'
            f"<p>{len(report.verdict.quarantines)} action(s), {ranges} range(s), "
            f"{bytes_installed} byte(s). This output is not clean and does not have "
            "toolchain-origin authenticity.</p>"
            + _table(
                (
                    "Action",
                    "Artifact",
                    "Function",
                    "Coordinates",
                    "Function VA",
                    "Ranges",
                    "Bytes",
                    "Reason",
                ),
                quarantine_rows,
            )
            + "</section>"
        )
    embedded = canonical_json(report).decode("utf-8").strip()
    embedded = embedded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    title = html.escape(f"{report.project_id} — ReproBit report")
    verdict_table = _table(("Claim", "Result"), verdict_rows)
    targets_table = _table(
        (
            "Target",
            "Artifact",
            "Candidate bytes",
            "Candidate SHA-256",
            "Oracle bytes",
            "Oracle SHA-256",
            "Exact",
        ),
        target_rows,
    )
    classes_table = _table(("Class", "Interventions", "Units", "Cost"), class_rows)
    functions_table = _table(
        (
            "Target",
            "Translation unit",
            "Function",
            "Direct",
            "Allocated shared",
            "Exposure",
        ),
        function_rows,
    )
    interventions_table = _table(
        (
            "ID",
            "Kind",
            "Class",
            "Target",
            "Translation unit",
            "Function",
            "Units",
            "Cost",
        ),
        intervention_rows,
    )
    component_rows = (
        (
            report.proof.adapter.role,
            report.proof.adapter.id,
            report.proof.adapter.implementation,
            report.proof.adapter.version,
            report.proof.adapter.digest.value,
        ),
        *(
            (
                item.role,
                item.id,
                item.implementation,
                item.version,
                item.digest.value,
            )
            for item in report.proof.providers
        ),
        (
            report.proof.package.role,
            report.proof.package.id,
            report.proof.package.implementation,
            report.proof.package.version,
            report.proof.package.digest.value,
        ),
    )
    components_table = _table(
        ("Role", "ID", "Implementation", "Version", "SHA-256"),
        component_rows,
    )
    tool_rows = tuple(
        (
            item.id,
            str(item.size) if item.size is not None else "not recorded",
            item.digest.value,
        )
        for item in report.toolchain.tools
    )
    tree_rows = tuple(
        (
            item.id,
            item.path,
            str(item.entry_count),
            str(item.max_depth),
            item.membership_digest.value,
            item.content_digest.value,
        )
        for item in report.toolchain.input_trees
    )
    tools_table = _table(("Tool", "Bytes", "SHA-256"), tool_rows)
    trees_table = _table(
        ("Tree", "Path", "Entries", "Depth", "Membership SHA-256", "Content SHA-256"),
        tree_rows,
    )
    issues_table = _table(
        ("Claim", "Code", "Message"),
        tuple((item.claim, item.code, item.message) for item in report.proof.audit_issues),
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#f7f8fa;--panel:#fff;--ink:#17202a;--muted:#5d6d7e;--line:#d5d8dc;
--ok:#176b3a;--bad:#a61b1b}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto;padding:2rem}}
h1,h2{{line-height:1.15}} .lede{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:1rem;margin:1rem 0;overflow:auto}}
.warning{{border:3px solid var(--bad);background:#fff1f1;color:#690f0f}}
.metric{{font-size:2rem;font-weight:700}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th,td{{border-bottom:1px solid var(--line);padding:.5rem;text-align:left;vertical-align:top}}
th{{background:#eef1f4}}
code{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}
.ok{{color:var(--ok)}} .bad{{color:var(--bad)}}
</style>
</head>
<body><main>
<h1>{title}</h1>
<p class="lede">Run <code>{report.run_id.value}</code> ·
cost model v{report.costs.model_version}</p>
{quarantine}
<div class="grid">
<section><h2>Verdict</h2>{verdict_table}</section>
<section><h2>Total cost</h2><div class="metric">{report.costs.project_total}</div>
<p>Unallocated shared cost: {report.costs.unallocated_shared_cost}</p></section>
<section><h2>Evidence</h2><p>{report.evidence.artifacts} artifacts<br>
{report.evidence.provenance_nodes} provenance nodes<br>
{report.evidence.passed_certificates}/{report.evidence.certificates}
certificates passed<br>{len(report.proof.producers)} producer attestations<br>
{len(report.proof.audit_issues)} audit issues</p>
<p>Evidence SHA-256<br><code>{report.proof.digest.value}</code></p></section>
</div>
<section><h2>Targets</h2>{targets_table}</section>
<section><h2>Locked toolchain</h2>
<p>Profile <code>{html.escape(report.toolchain.profile)}</code> ·
MSVC {html.escape(report.toolchain.release.value)}</p>
<h3>Executable and runtime files</h3>{tools_table}
<h3>Portable input trees</h3>{trees_table}</section>
<section><h2>Trusted components</h2>{components_table}</section>
<section><h2>Audit issues</h2>{issues_table}</section>
<section><h2>Costs by class</h2>{classes_table}</section>
<section><h2>Function costs</h2>{functions_table}</section>
<section><h2>Interventions</h2>{interventions_table}</section>
<script type="application/json" id="reprobit-report">{embedded}</script>
</main></body></html>
"""


def write_report_html(report: Report, path: str | Path) -> None:
    """Write a self-contained report atomically."""

    _atomic_write(path, render_report_html(report).encode("utf-8"))


def report_json_schema() -> JsonValue:
    """Return the self-contained, stably identified report schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:reprobit:schema:report:2",
        **Report.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        ),
    }


def write_report_json_schema(path: str | Path) -> None:
    """Write the canonical report schema atomically."""

    _atomic_write(path, canonical_json(report_json_schema()))


__all__ = [
    "AuditIssueSummary",
    "BuildExecutionSummary",
    "CacheMode",
    "CacheSummary",
    "ComponentIdentity",
    "EvidenceSummary",
    "ExecutionFileReceipt",
    "ExecutionStepReceipt",
    "LogicalPathSummary",
    "PreviousComparison",
    "ProducerSummary",
    "ProofReport",
    "Report",
    "RuntimeBindingPreimage",
    "RuntimeProofBinding",
    "StageTiming",
    "TargetComparisonSummary",
    "TargetSummary",
    "ToolSummary",
    "ToolchainSummary",
    "ToolchainTreeSummary",
    "read_report_json",
    "render_report_html",
    "report_json_schema",
    "write_report_html",
    "write_report_json",
    "write_report_json_schema",
]
