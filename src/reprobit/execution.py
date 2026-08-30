"""Canonical execution receipts and runtime-evidence contracts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from pathlib import Path
from typing import Protocol

from reprobit.build import BuildPlan
from reprobit.model import Artifact, ByteRange, Certificate, Digest, ProvenanceNode
from reprobit.schema import ClassicRecipeFamily, ProjectBundle
from reprobit.verify import ComparisonReceipt, SealedFileOracle


class EngineError(RuntimeError):
    """Raised when execution cannot produce a trustworthy engine result."""


def classic_semantic_obligation_name(family: ClassicRecipeFamily) -> str:
    """Return the authoritative runtime obligation for one classic family."""

    return f"semantic_equivalence.{family.value}"


@dataclass(frozen=True, slots=True)
class FileReceipt:
    path: Path
    digest: Digest
    size: int
    fresh: bool
    producer_step: str | None = None
    device: int = 0
    inode: int = 0


@dataclass(frozen=True, slots=True)
class StepExecutionReceipt:
    step_id: str
    returncode: int
    attempts: int
    duration_seconds: float
    output_digest: Digest
    command_digest: Digest


@dataclass(frozen=True, slots=True)
class BuildExecutionReceipt:
    cold: bool
    inputs: tuple[FileReceipt, ...]
    outputs: tuple[FileReceipt, ...]
    steps: tuple[StepExecutionReceipt, ...]


@dataclass(frozen=True, slots=True)
class TargetOracle:
    target_id: str
    capability: SealedFileOracle


@dataclass(frozen=True, slots=True)
class TargetVerification:
    target_id: str
    artifact: Path
    comparison: ComparisonReceipt


class ProducerKind(StrEnum):
    COMPILER = "compiler"
    LINKER = "linker"
    LIBRARIAN = "librarian"
    RESOURCE = "resource"


class ObjectTransformOperation(StrEnum):
    """Closed set of deterministic object rewrites issued by the classic runtime."""

    RESTORE_COMDAT_GROUP_ORDER = "restore_comdat_group_order"
    SWAP_COMDAT_GROUP_ORDER = "swap_comdat_group_order"


@dataclass(frozen=True, slots=True)
class ProducerAttestation:
    """Fresh trusted claim binding artifact ranges to a locked producer."""

    id: str
    artifact_id: str
    step_id: str
    producer_kind: ProducerKind
    tool_id: str
    tool_digest: Digest
    artifact_digest: Digest
    artifact_size: int
    ranges: tuple[ByteRange, ...] = ()
    captured_before_overwrite: bool = False

    def __post_init__(self) -> None:
        if not self.id or not self.artifact_id or not self.step_id or not self.tool_id:
            raise EngineError("producer-attestation identifiers cannot be empty")
        if self.artifact_size < 0:
            raise EngineError("producer-attestation size cannot be negative")
        ordered = tuple(sorted(self.ranges, key=lambda item: item.offset))
        if ordered != self.ranges:
            raise EngineError("producer-attestation ranges must be in canonical order")
        for left, right in pairwise(ordered):
            if left.overlaps(right):
                raise EngineError("producer-attestation ranges overlap")


@dataclass(frozen=True, slots=True)
class ObjectTransformAttestation:
    """Exact current-run receipt for one supported deterministic object rewrite."""

    id: str
    artifact_id: str
    input_artifact_id: str
    step_id: str
    operation: ObjectTransformOperation
    input_digest: Digest
    input_size: int
    artifact_digest: Digest
    artifact_size: int
    evidence_digest: Digest
    step_binding_digest: Digest

    def __post_init__(self) -> None:
        if not self.id or not self.artifact_id or not self.input_artifact_id or not self.step_id:
            raise EngineError("object-transform attestation identifiers cannot be empty")
        if self.artifact_id == self.input_artifact_id:
            raise EngineError("object-transform input and output artifacts must differ")
        if not isinstance(self.operation, ObjectTransformOperation):
            raise EngineError("object-transform operation is unsupported")
        if self.input_size < 0 or self.artifact_size < 0:
            raise EngineError("object-transform attestation sizes cannot be negative")


@dataclass(frozen=True, slots=True)
class NormalizationCategoryAttestation:
    """Compact accounting for one named supplemental normalization policy."""

    category: str
    normalized_bytes: int
    changed_bytes: int
    changed_range_count: int
    changed_ranges: tuple[ByteRange, ...] = ()
    omitted_changed_ranges: int = 0

    def __post_init__(self) -> None:
        if not self.category:
            raise EngineError("normalization category cannot be empty")
        if self.normalized_bytes < 0 or self.changed_bytes < 0:
            raise EngineError("normalization byte counts cannot be negative")
        if self.changed_bytes > self.normalized_bytes:
            raise EngineError("changed normalization bytes exceed eligible bytes")
        if self.changed_range_count < 0 or self.omitted_changed_ranges < 0:
            raise EngineError("normalization range counts cannot be negative")
        if self.changed_range_count != len(self.changed_ranges) + self.omitted_changed_ranges:
            raise EngineError("normalization range summary is incomplete")
        if (self.changed_range_count == 0) != (self.changed_bytes == 0):
            raise EngineError("normalization changed-byte and range counts disagree")
        if self.changed_ranges != tuple(
            sorted(self.changed_ranges, key=lambda item: (item.offset, item.length))
        ):
            raise EngineError("normalization ranges must be in canonical order")
        for left, right in pairwise(self.changed_ranges):
            if left.overlaps(right):
                raise EngineError("normalization ranges overlap")
        preview_bytes = sum(item.length for item in self.changed_ranges)
        if preview_bytes + self.omitted_changed_ranges > self.changed_bytes:
            raise EngineError("normalization range summary exceeds changed bytes")
        if self.omitted_changed_ranges == 0 and preview_bytes != self.changed_bytes:
            raise EngineError("normalization ranges do not exhaust changed bytes")


@dataclass(frozen=True, slots=True)
class SupplementalOutputFileAttestation:
    """One noncertifying output bound to a current build receipt."""

    role: str
    logical_path: str
    path: Path
    digest: Digest
    size: int
    raw_digest: Digest
    raw_size: int
    changed_bytes: int
    categories: tuple[NormalizationCategoryAttestation, ...] = ()

    def __post_init__(self) -> None:
        if not self.role or not self.logical_path:
            raise EngineError("supplemental output role and logical path cannot be empty")
        if self.size < 0 or self.raw_size < 0 or self.changed_bytes < 0:
            raise EngineError("supplemental output sizes cannot be negative")
        if self.size != self.raw_size:
            raise EngineError("supplemental normalization must preserve file size")
        if self.changed_bytes > self.size:
            raise EngineError("supplemental changed-byte count exceeds file size")
        if (self.changed_bytes == 0) != (self.digest == self.raw_digest):
            raise EngineError("supplemental raw/final identity contradicts changed-byte count")
        if self.categories != tuple(sorted(self.categories, key=lambda item: item.category)):
            raise EngineError("supplemental normalization categories must be canonical")
        if len({item.category for item in self.categories}) != len(self.categories):
            raise EngineError("supplemental normalization categories must be unique")
        if sum(item.changed_bytes for item in self.categories) != self.changed_bytes:
            raise EngineError("supplemental category byte counts differ from the output total")
        if any(
            span.end > self.size for category in self.categories for span in category.changed_ranges
        ):
            raise EngineError("supplemental normalization range exceeds the file")


@dataclass(frozen=True, slots=True)
class SupplementalOutputAttestation:
    """Receipt-bound evidence for outputs outside the authenticity artifact DAG."""

    id: str
    target_id: str
    policy: str
    source_step_id: str
    publish_step_id: str
    files: tuple[SupplementalOutputFileAttestation, ...]

    def __post_init__(self) -> None:
        if not all(
            (self.id, self.target_id, self.policy, self.source_step_id, self.publish_step_id)
        ):
            raise EngineError("supplemental output identifiers cannot be empty")
        if self.source_step_id == self.publish_step_id:
            raise EngineError("supplemental source and publication steps must differ")
        if not self.files:
            raise EngineError("supplemental output attestation has no files")
        if self.files != tuple(sorted(self.files, key=lambda item: item.role)):
            raise EngineError("supplemental output files must be in canonical order")
        if len({item.role for item in self.files}) != len(self.files):
            raise EngineError("supplemental output roles must be unique")


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    """Evidence freshly issued by one trusted code-side provider."""

    provider_id: str
    run_binding: Digest
    artifacts: tuple[Artifact, ...] = ()
    provenance: tuple[ProvenanceNode, ...] = ()
    certificates: tuple[Certificate, ...] = ()
    producers: tuple[ProducerAttestation, ...] = ()
    object_transforms: tuple[ObjectTransformAttestation, ...] = ()
    supplemental_outputs: tuple[SupplementalOutputAttestation, ...] = ()

    def __post_init__(self) -> None:
        if not self.provider_id:
            raise EngineError("runtime evidence provider id cannot be empty")


@dataclass(frozen=True, slots=True)
class RuntimeEvidenceContext:
    """Oracle-free current-run material supplied to trusted providers."""

    bundle: ProjectBundle
    build: BuildExecutionReceipt
    targets: tuple[TargetVerification, ...]
    run_binding: Digest


class RuntimeEvidenceProvider(Protocol):
    @property
    def name(self) -> str: ...

    def issue(self, context: RuntimeEvidenceContext) -> RuntimeEvidence: ...


class BuildExecutor(Protocol):
    """Trusted project adapter that returns the same receipts as the DAG executor."""

    def execute(
        self,
        plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: Iterable[Path] = (),
    ) -> BuildExecutionReceipt: ...


__all__ = [
    "BuildExecutionReceipt",
    "BuildExecutor",
    "EngineError",
    "FileReceipt",
    "NormalizationCategoryAttestation",
    "ObjectTransformAttestation",
    "ObjectTransformOperation",
    "ProducerAttestation",
    "ProducerKind",
    "RuntimeEvidence",
    "RuntimeEvidenceContext",
    "RuntimeEvidenceProvider",
    "StepExecutionReceipt",
    "SupplementalOutputAttestation",
    "SupplementalOutputFileAttestation",
    "TargetOracle",
    "TargetVerification",
    "classic_semantic_obligation_name",
]
