"""Immutable evidence and verdict types shared by ReproBit subsystems."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from reprobit.strict_json import canonical_json, strict_loads

Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
BuildTarget = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    """Base for immutable evidence models with a closed field set."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Digest(StrictModel):
    """A content digest with an explicit algorithm."""

    algorithm: Literal["sha256"] = "sha256"
    value: Sha256Hex

    @classmethod
    def from_bytes(cls, data: bytes) -> Digest:
        return cls(value=hashlib.sha256(data).hexdigest())

    @classmethod
    def from_path(cls, path: str | Path, *, chunk_size: int = 1024 * 1024) -> Digest:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            while chunk := stream.read(chunk_size):
                digest.update(chunk)
        return cls(value=digest.hexdigest())


class ByteRange(StrictModel):
    """A non-empty half-open byte range."""

    offset: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(gt=0)]

    @property
    def end(self) -> int:
        return self.offset + self.length

    def overlaps(self, other: ByteRange) -> bool:
        return self.offset < other.end and other.offset < self.end


class Scope(StrictModel):
    """The target, translation unit, and optional function affected by evidence."""

    target: Identifier
    translation_unit: Identifier | None = None
    function: Annotated[str, Field(min_length=1, max_length=2048)] | None = None

    @model_validator(mode="after")
    def require_parent_scope(self) -> Scope:
        if self.function is not None and self.translation_unit is None:
            raise ValueError("function scope requires translation_unit")
        return self


class ArtifactKind(StrEnum):
    SOURCE = "source"
    TOOLCHAIN = "toolchain"
    OBJECT = "object"
    PDB = "pdb"
    ARCHIVE = "archive"
    IMAGE = "image"
    RESOURCE = "resource"
    GENERATED = "generated"
    RECEIPT = "receipt"
    EXTERNAL = "external"


class ArtifactOrigin(StrEnum):
    FRESH_SEED = "fresh_seed"
    FRESH_DONOR = "fresh_donor"
    COMPOSED = "composed"
    CERTIFIED_POSTLINK = "certified_postlink"
    EXTERNAL = "external"
    ORACLE = "oracle"
    STALE_REFUSED = "stale/refused"


class Artifact(StrictModel):
    """A content-addressed build artifact and its immediate ancestry."""

    id: Identifier
    kind: ArtifactKind
    logical_path: Annotated[str, Field(min_length=1, max_length=4096)]
    digest: Digest
    size: Annotated[int, Field(ge=0)]
    origin: ArtifactOrigin
    first_party: bool = True
    producer: Identifier | None = None
    inputs: tuple[Identifier, ...] = ()
    receipt_path: Annotated[str, Field(min_length=1, max_length=8192)] | None = None

    @field_validator("logical_path")
    @classmethod
    def logical_path_is_safe(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("logical_path contains NUL")
        if any(part == ".." for part in value.replace("\\", "/").split("/")):
            raise ValueError("logical_path must not escape its logical root")
        return value

    @field_validator("receipt_path")
    @classmethod
    def receipt_path_has_no_nul(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("receipt_path contains NUL")
        return value

    @model_validator(mode="after")
    def origin_is_consistent(self) -> Artifact:
        if self.origin is ArtifactOrigin.EXTERNAL and self.first_party:
            raise ValueError("external artifacts cannot be first-party")
        if self.origin is ArtifactOrigin.ORACLE and self.first_party:
            raise ValueError("oracle artifacts cannot be first-party")
        if self.origin in {ArtifactOrigin.EXTERNAL, ArtifactOrigin.ORACLE} and self.producer:
            raise ValueError("external and oracle artifacts cannot name a producer")
        if self.id in self.inputs:
            raise ValueError("artifact cannot be its own input")
        return self


class ProvenanceKind(StrEnum):
    SOURCE = "source"
    TOOLCHAIN = "toolchain"
    PRODUCER = "producer"
    OBJECT_TRANSFORM = "object_transform"
    INTERVENTION = "intervention"
    METADATA_TRANSFORM = "metadata_transform"
    EXTERNAL = "external"
    ORACLE_INSTALL = "oracle_install"


class ProvenanceNode(StrictModel):
    """One node in the artifact ancestry DAG."""

    id: Identifier
    kind: ProvenanceKind
    operation: Identifier
    origin: ArtifactOrigin
    parents: tuple[Identifier, ...] = ()
    artifact_id: Identifier
    byte_range: ByteRange | None = None
    intervention_id: Identifier | None = None
    certificate_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def kind_is_consistent(self) -> ProvenanceNode:
        if self.id in self.parents:
            raise ValueError("provenance node cannot be its own parent")
        if self.kind is ProvenanceKind.ORACLE_INSTALL:
            if self.origin is not ArtifactOrigin.ORACLE:
                raise ValueError("oracle_install provenance must have oracle origin")
            if self.intervention_id is None:
                raise ValueError("oracle_install provenance requires intervention_id")
        elif self.origin is ArtifactOrigin.ORACLE:
            raise ValueError("oracle origin is restricted to oracle_install provenance")
        if self.kind is ProvenanceKind.OBJECT_TRANSFORM:
            if self.origin is not ArtifactOrigin.COMPOSED:
                raise ValueError("object_transform provenance must have composed origin")
            if self.operation not in {
                "restore_comdat_group_order",
                "swap_comdat_group_order",
            }:
                raise ValueError("object_transform provenance has an unsupported operation")
            if len(self.parents) != 1:
                raise ValueError("object_transform provenance requires one parent")
            if self.intervention_id is not None or self.certificate_ids:
                raise ValueError(
                    "object_transform provenance uses its dedicated attestation"
                )
        if self.kind is ProvenanceKind.INTERVENTION and self.intervention_id is None:
            raise ValueError("intervention provenance requires intervention_id")
        return self


class ProofObligation(StrictModel):
    """A named, independently reportable proof obligation."""

    name: Identifier
    passed: bool
    evidence_digest: Digest | None = None
    detail: Annotated[str, Field(max_length=4096)] | None = None


class SemanticArtifactClaim(StrictModel):
    """Bridge one semantic statement receipt to a proof-DAG artifact."""

    artifact_id: Identifier
    relation: Literal["input", "output"]
    digest: Digest
    size: Annotated[int, Field(ge=0)]


class SemanticProof(StrictModel):
    """Typed output of one closed semantic validator.

    The input/output statement digests bind the validator's normalized
    semantic representations, not merely the edited byte strings.  The
    evidence digest binds the complete validator trace and must also be the
    digest carried by the matching certificate obligation.
    """

    kind: Literal["classic_semantic"] = "classic_semantic"
    family: Identifier
    validator_id: Identifier
    validator_digest: Digest
    input_statement_digest: Digest
    output_statement_digest: Digest
    obligations: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    evidence_digest: Digest
    input_statement: object | None = None
    output_statement: object | None = None
    artifact_claims: tuple[SemanticArtifactClaim, ...] = ()

    @field_validator("input_statement", "output_statement", mode="before")
    @classmethod
    def statement_is_canonical_json(cls, value: object | None) -> object | None:
        if value is None:
            return None
        return strict_loads(canonical_json(value))

    @model_validator(mode="after")
    def obligations_are_canonical(self) -> SemanticProof:
        if self.obligations != tuple(sorted(set(self.obligations))):
            raise ValueError("semantic-proof obligations must be unique and canonical")
        if (self.input_statement is None) != (self.output_statement is None):
            raise ValueError("semantic-proof statements must be carried together")
        if self.input_statement is not None and (
            Digest.from_bytes(canonical_json(self.input_statement))
            != self.input_statement_digest
            or Digest.from_bytes(canonical_json(self.output_statement))
            != self.output_statement_digest
        ):
            raise ValueError("semantic-proof statements differ from their digests")
        claim_keys = [
            (item.relation, item.artifact_id, item.digest.value, item.size)
            for item in self.artifact_claims
        ]
        if claim_keys != sorted(set(claim_keys)):
            raise ValueError("semantic-proof artifact claims must be unique and canonical")
        return self


class Certificate(StrictModel):
    """Proof receipt for one intervention."""

    id: Identifier
    intervention_id: Identifier
    obligations: Annotated[tuple[ProofObligation, ...], Field(min_length=1)]
    artifact_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    semantic_proofs: tuple[SemanticProof, ...] = ()

    @model_validator(mode="after")
    def semantic_proofs_are_canonical(self) -> Certificate:
        keys = [
            (proof.family, proof.validator_id, proof.evidence_digest.value)
            for proof in self.semantic_proofs
        ]
        if keys != sorted(set(keys)):
            raise ValueError("certificate semantic proofs must be unique and canonical")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return all(obligation.passed for obligation in self.obligations)


class Quarantine(StrictModel):
    """Disclosed byte ancestry that prevents a clean verdict.

    ``artifact-file`` ranges are offsets in the final reported artifact.
    ``function-body`` is the explicit fallback for a non-PE artifact or an
    image whose declared virtual-address range cannot be mapped safely.  The
    coordinate space is never implicit: consumers must not mistake a
    function-relative offset for an artifact-file offset.
    """

    id: Identifier
    kind: Identifier
    artifact_id: Identifier
    ranges: Annotated[tuple[ByteRange, ...], Field(min_length=1)]
    byte_count: Annotated[int, Field(gt=0)]
    reason: Annotated[str, Field(min_length=1, max_length=4096)]
    coordinate_space: Literal["artifact-file", "function-body"] = "artifact-file"
    scope: Scope | None = None
    base_address: Annotated[int, Field(ge=0)] | None = None
    proof_binding: Digest | None = None

    @model_validator(mode="after")
    def validate_ranges(self) -> Quarantine:
        ordered = sorted(self.ranges, key=lambda item: item.offset)
        if any(left.overlaps(right) for left, right in pairwise(ordered)):
            raise ValueError("quarantine ranges overlap")
        if sum(item.length for item in ordered) != self.byte_count:
            raise ValueError("byte_count must equal the sum of quarantine range lengths")
        if self.coordinate_space == "function-body" and (
            self.scope is None or self.scope.function is None or self.base_address is None
        ):
            raise ValueError("function-body quarantine requires function scope and base address")
        return self


def quarantine_proof_binding(
    quarantine: Quarantine,
    *,
    certificate_id: Identifier,
    evidence_digest: Digest,
) -> Digest:
    """Bind exact quarantine coordinates to one oracle-install proof receipt."""

    material = quarantine.model_dump(
        mode="json",
        exclude={"proof_binding"},
        exclude_none=True,
        exclude_computed_fields=True,
    )
    return Digest.from_bytes(
        canonical_json(
            {
                "schema": "quarantine-proof-binding-v1",
                "certificate_id": certificate_id,
                "evidence_digest": evidence_digest,
                "quarantine": material,
            }
        )
    )


class AuthenticityPolicy(StrEnum):
    CLEAN = "clean"
    ALLOW_QUARANTINE = "allow-quarantine"


class Verdict(StrictModel):
    """Independent build claims and their derived clean result."""

    cold: bool
    byte_exact: bool
    logic_certified: bool
    toolchain_origin: bool
    quarantines: tuple[Quarantine, ...] = ()

    @model_validator(mode="after")
    def quarantine_invalidates_origin(self) -> Verdict:
        if self.quarantines and self.toolchain_origin:
            raise ValueError("a quarantined verdict cannot claim toolchain_origin")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def quarantined(self) -> bool:
        return bool(self.quarantines)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clean(self) -> bool:
        return (
            self.cold
            and self.byte_exact
            and self.logic_certified
            and self.toolchain_origin
            and not self.quarantined
        )

    def accepts(self, policy: AuthenticityPolicy) -> bool:
        """Evaluate claims that are self-contained in the verdict.

        A quarantined verdict cannot reveal whether its failed origin claim is
        explained *only* by the disclosed ranges. The engine's evidence audit
        owns that distinction, so callers evaluating ``allow-quarantine`` must
        use :meth:`reprobit.engine.EngineResult.accepts`. This method therefore
        fails closed for every non-clean verdict under either policy.
        """

        del policy
        return self.clean


__all__ = [
    "Artifact",
    "ArtifactKind",
    "ArtifactOrigin",
    "AuthenticityPolicy",
    "BuildTarget",
    "ByteRange",
    "Certificate",
    "Digest",
    "Identifier",
    "ProofObligation",
    "ProvenanceKind",
    "ProvenanceNode",
    "Quarantine",
    "Scope",
    "SemanticArtifactClaim",
    "SemanticProof",
    "StrictModel",
    "Verdict",
    "quarantine_proof_binding",
]
