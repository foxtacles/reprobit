"""Data-only records shared by classic execution and evidence assembly."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from reprobit.classic.semantic_contracts import CompilerNamespaceEvidence
from reprobit.classic_includes import IncludeOrigin, SealedIncludeAuthority
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import InterventionWitness
from reprobit.classic_runtime_graph import ClassicCompileRecord
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerRole
from reprobit.secure_path_contracts import SecureFileSnapshot


@dataclass(frozen=True, slots=True)
class ClassicProducedImage:
    target_id: str
    raw_path: Path
    final_path: Path
    link_step_id: str
    linker_tool_id: str
    witnesses: tuple[InterventionWitness, ...]
    final_snapshot: SecureFileSnapshot


@dataclass(frozen=True, slots=True)
class ClassicProducedPdb:
    """Analysis-only PDB published without admitting its image as a candidate."""

    target_id: str
    logical_path: str
    analysis_image_path: Path
    raw_path: Path
    final_path: Path
    link_step_id: str
    publish_step_id: str
    final_snapshot: SecureFileSnapshot


@dataclass(frozen=True, slots=True)
class ClassicProducerRead:
    """One sealed file visible to a compiler or read by a resource producer."""

    logical_path: str
    physical_path: Path
    digest: Digest
    size: int
    origin: IncludeOrigin
    parent_index: int | None
    parent_path: str | None
    kind: str
    payload: bytes | None = None


@dataclass(frozen=True, slots=True)
class ClassicProducerReadReceipt:
    """Closed readable-input set for one producer execution."""

    node_id: str
    step_id: str
    role: ProducerRole
    epoch: str
    reads: tuple[ClassicProducerRead, ...]
    coverage: str = "recursive-read-v1"
    namespace_id: str | None = None
    namespace_digest: Digest | None = None
    namespace_count: int | None = None


@dataclass(frozen=True, slots=True)
class ClassicCompilerNamespaceReceipt:
    """One shared complete namespace plus physical ancestry leaves."""

    evidence: CompilerNamespaceEvidence
    reads: tuple[ClassicProducerRead, ...]


@dataclass(frozen=True, slots=True)
class ClassicCapturedProducerOutput:
    """Immutable content receipt captured before a later in-place transform."""

    node_id: str
    step_id: str
    role: ProducerRole
    reference: str
    logical_path: str
    digest: Digest
    size: int


@dataclass(frozen=True, slots=True)
class ClassicDonorOutputReceipt:
    """Private compiler object consumed only by certified composition."""

    intervention_id: str
    node_id: str
    step_id: str
    logical_path: str
    digest: Digest
    size: int


@dataclass(frozen=True, slots=True)
class ClassicObjectTransformReceipt:
    """One deterministic post-intervention object transform."""

    unit_id: str
    object_reference: str
    step_id: str
    operation: str
    input_digest: Digest
    input_size: int
    output_digest: Digest
    output_size: int
    evidence_digest: Digest


@dataclass(frozen=True, slots=True)
class ClassicProducerGraphExecutionRecord:
    images: tuple[ClassicProducedImage, ...]
    witnesses: tuple[InterventionWitness, ...]
    producer_reads: tuple[ClassicProducerReadReceipt, ...] = ()
    compiler_outputs: tuple[ClassicCapturedProducerOutput, ...] = ()
    donor_outputs: tuple[ClassicDonorOutputReceipt, ...] = ()
    compiler_namespaces: tuple[ClassicCompilerNamespaceReceipt, ...] = ()
    analysis_pdbs: tuple[ClassicProducedPdb, ...] = ()
    object_transforms: tuple[ClassicObjectTransformReceipt, ...] = ()


@dataclass(frozen=True, slots=True)
class ClassicRuntimeEvidenceInputs:
    """Immutable runtime facts consumed by the classic evidence assembler."""

    record: ClassicProducerGraphExecutionRecord
    effective_root: Path
    build_root: Path
    toolchain_root: Path
    logical_drive_root: Path
    logical_drive_letter: str
    graph: ProducerGraphDocument
    role_tool_ids: Mapping[ProducerRole, str]
    units: tuple[ClassicPreparedUnit, ...]
    compile_records: tuple[ClassicCompileRecord, ...]
    system_libraries: Mapping[str, Path]


@dataclass(frozen=True, slots=True)
class ClassicActiveCompilerEpoch:
    namespace_id: str
    include_authority: SealedIncludeAuthority
    source_seal: Mapping[Path, tuple[int, Digest]]
    generated: bool


__all__ = [
    "ClassicActiveCompilerEpoch",
    "ClassicCapturedProducerOutput",
    "ClassicCompilerNamespaceReceipt",
    "ClassicDonorOutputReceipt",
    "ClassicObjectTransformReceipt",
    "ClassicProducedImage",
    "ClassicProducedPdb",
    "ClassicProducerGraphExecutionRecord",
    "ClassicProducerRead",
    "ClassicProducerReadReceipt",
    "ClassicRuntimeEvidenceInputs",
]
