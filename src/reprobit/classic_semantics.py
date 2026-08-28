"""Closed semantic ancestry proofs for migrated classic source overlays.

Source rendering is not a semantic proof.  This module admits an overlay only
when current-run evidence establishes a closed source theorem, compiler-input
congruence, and a strict COFF/link projection for every effective primary
input.  Donor-only renderings remain private, and generated carrier objects
must be proven unreachable and non-contributing.

The validator is intentionally conservative.  Unknown COFF constructs and
incomplete link closures are errors, never best-effort evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Protocol, TypeVar

from reprobit.classic.foundation import ByteIdentityError
from reprobit.classic.ia32 import supported_ia32_instruction_length
from reprobit.classic.source_proofs import iter_source_overlay_tokens, source_overlay_tokens
from reprobit.classic_overlay import (
    ClassicOverlayDialect,
    ClassicOverlayOutputReceipt,
    infer_classic_overlay_dialect,
    render_classic_overlay,
    render_classic_overlay_leaf_subset,
)
from reprobit.formats import FormatError, parse_coff_archive
from reprobit.model import Digest, SemanticProof
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    producer_graph_digest,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ProjectBundle,
)
from reprobit.strict_json import canonical_json
from reprobit.toolchains import ToolchainError
from reprobit.toolchains import profile as toolchain_profile


class ClassicSemanticError(ValueError):
    """Current-run evidence cannot establish semantic ancestry."""


class SemanticValidatorContract(Protocol):
    """Structural contract accepted by :func:`semantic_proof_matches`."""

    @property
    def validator_id(self) -> str: ...

    @property
    def validator_digest(self) -> Digest: ...

    @property
    def obligations(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class RegisteredSemanticContract:
    """One reviewed family validator admitted by the engine."""

    validator_id: str
    validator_digest: Digest
    obligations: tuple[str, ...]


class PrimarySourceOrigin(StrEnum):
    CLEAN_MANIFEST = "clean-manifest"
    GENERATED_CARRIER = "generated-carrier"
    EFFECTIVE_OVERLAY = "effective-overlay"
    CERTIFIED_PROJECT_OVERLAY = "certified-project-overlay"


class CompilerInputEvidenceKind(StrEnum):
    """Closed authority represented by a compiler epoch input census."""

    COMPLETE_READABLE_NAMESPACE = "complete-readable-namespace-v1"


@dataclass(frozen=True, slots=True)
class SourceInputReceipt:
    """One regular file in the sealed source seat used by primary producers."""

    path: str
    digest: Digest
    size: int
    origin: PrimarySourceOrigin


@dataclass(frozen=True, slots=True)
class EffectiveOverlayReceipt:
    """One rendered overlay output in the private donor workspace."""

    path: str
    digest: Digest
    size: int


@dataclass(frozen=True, slots=True)
class CompilerProduct:
    """Current-run object bytes produced by one committed compiler node."""

    node_id: str
    source_ref: str
    object_ref: str
    payload: bytes
    generated_inputs: tuple[str, ...] = ()
    compiler_invocation: CompilerEpochInvocation | None = None


@dataclass(frozen=True, slots=True)
class ProjectOverlaySourcePair:
    """One exact clean-to-effective project-overlay source transition.

    ``clean_payload`` is absent only for an output whose clean state is absent
    in the complete source manifest.  Donor-private renderings never appear in
    this collection.
    """

    path: str
    clean_payload: bytes | None
    effective_payload: bytes


@dataclass(frozen=True, slots=True)
class CleanSourceInput:
    """One immutable file from the complete clean source-manifest epoch."""

    path: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class CompilerSourceRead:
    """One file in the complete compiler-readable namespace of a sealed epoch.

    ``reference`` is a portable producer reference beneath either the complete
    project source authority or the locked toolchain tree.  ``parent_index`` is
    reserved for a future independently observed ancestry mode and must be
    ``None`` for the complete namespace census used by cold certification.
    """

    reference: str
    digest: Digest
    size: int
    parent_index: int | None
    payload: bytes


@dataclass(frozen=True, slots=True)
class CompilerNamespaceEvidence:
    """One shared immutable compiler-readable namespace census."""

    namespace_id: str
    namespace_digest: Digest
    members: tuple[CompilerSourceRead, ...]
    input_evidence_kind: CompilerInputEvidenceKind = (
        CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
    )


@dataclass(frozen=True, slots=True)
class CompilerEpochInvocation:
    """Normalized, independently receipted compiler execution statement.

    Transport-only host details (for example a private Wine prefix) are not
    compiler inputs.  The executor hashes the declared frontend search-path
    presentation and output-critical DLL selection into ``environment_digest``;
    the locked runtime namespace binds the selected DLL bytes.  The logical
    path/case mapping is bound separately in ``path_profile_digest``.  The
    remaining fields are deliberately explicit so this module can bind the
    locked compiler and committed argv without trusting an opaque command hash.
    """

    tool_id: str
    tool_digest: Digest
    arguments: tuple[str, ...]
    working_directory: str
    environment_digest: Digest
    path_profile_digest: Digest
    invocation_digest: Digest
    namespace_id: str
    namespace_digest: Digest
    namespace_count: int
    input_evidence_kind: CompilerInputEvidenceKind = (
        CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
    )


@dataclass(frozen=True, slots=True)
class ProjectOverlayCounterfactualAudit:
    """One derived declaration-counterfactual object for a sparse audit node."""

    node_id: str
    source_ref: str
    object_ref: str
    counterfactual_payload: bytes
    counterfactual_invocation: CompilerEpochInvocation | None = None


@dataclass(frozen=True, slots=True)
class ProjectOverlayCompilerEpochPlan:
    """Pure, deterministic plan for one derived project-overlay compiler epoch.

    ``declaration_outputs`` is re-rendered from immutable clean inputs and the
    committed overlay grammar.  It is runtime material, never a third source
    authority or a schema field.  Carrier translation units are deliberately
    absent; generated declaration headers remain present for ordinary readers.
    """

    declaration_outputs: Mapping[str, bytes]
    audit_node_ids: frozenset[str]
    runtime_projection_node_ids: frozenset[str]
    declaration_leaf_keys: Mapping[str, tuple[tuple[str, int], ...]]
    reader_closure_fallbacks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DonorSemanticLane:
    """Overlay inputs and the certified transform that consumes their donor."""

    target_id: str
    donor_intervention_id: str
    consumer_intervention_id: str
    overlay_inputs: tuple[EffectiveOverlayReceipt, ...]
    seed_object_digest: Digest
    donor_object_digest: Digest
    candidate_object_digest: Digest
    consumer_input_statement: Mapping[str, object]
    consumer_output_statement: Mapping[str, object]
    semantic_proof: SemanticProof
    input_name: str = ""


@dataclass(frozen=True, slots=True)
class ArchiveInput:
    """One complete current-run archive; members are parsed only by this module."""

    archive_ref: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class CoffDirectiveReceipt:
    """Strict linker controls carried by one ordinary COFF object."""

    tokens: tuple[str, ...]
    default_libraries: tuple[str, ...]
    include_symbols: tuple[str, ...]
    export_symbols: tuple[str, ...]
    merge_sections: tuple[tuple[str, str], ...] = ()
    disallowed_libraries: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ClassicLinkRelevantCoffProjection:
    """Exact link-relevant projection of one strict i386 COFF object.

    The projection omits only producer timestamps and sections whose names
    begin with ``.debug`` (including type-server records).  An external PDB is
    outside the COFF object and is therefore never an input to this function.
    Every remaining section byte, section characteristic and relative order,
    relocation, line-number record, COMDAT relation, linker directive, and
    external-linkage fact is retained in ``statement``.
    """

    object_digest: Digest
    projection_digest: Digest
    statement: Mapping[str, object]
    excluded_section_names: tuple[str, ...]
    normalizations: tuple[str, ...] = (
        "coff-time-date-stamp",
        "debug-section-bytes-relocations-and-symbols",
        "external-program-database",
    )


@dataclass(frozen=True, slots=True)
class ClassicCoffLineNumberDelta:
    """One ordinary retained-section COFF line-number value change."""

    section_index: int
    section_name: str
    record_index: int
    address: int
    baseline_line: int
    candidate_line: int


@dataclass(frozen=True, slots=True)
class ClassicCoffLineNumberCorrespondence:
    """Typed equality modulo ordinary COFF line-number metadata values.

    Both exact objects and both strict link-relevant projections remain bound.
    The shared invariant projection replaces only the nonzero 16-bit source
    line value of an ordinary line-table row.  Row count/order, row address,
    zero-line function targets, and every other retained projection field are
    exact.
    """

    baseline_object_digest: Digest
    baseline_size: int
    candidate_object_digest: Digest
    candidate_size: int
    baseline_projection_digest: Digest
    candidate_projection_digest: Digest
    invariant_projection_digest: Digest
    line_number_deltas: tuple[ClassicCoffLineNumberDelta, ...]
    statement_digest: Digest
    statement: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class TargetLinkClosure:
    """Complete object/archive semantic input closure for one terminal link."""

    target_id: str
    compiler_node_ids: tuple[str, ...]
    archive_refs: tuple[str, ...] = ()
    archives: tuple[ArchiveInput, ...] = ()
    root_symbols: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OverlaySemanticSnapshot:
    """Immutable current-run material consumed by the overlay validator."""

    run_binding: Digest
    primary_sources: tuple[SourceInputReceipt, ...]
    effective_outputs: tuple[EffectiveOverlayReceipt, ...]
    compiler_products: tuple[CompilerProduct, ...]
    donor_lanes: tuple[DonorSemanticLane, ...]
    link_closures: tuple[TargetLinkClosure, ...]
    project_source_pairs: tuple[ProjectOverlaySourcePair, ...] = ()
    counterfactual_compiler_audits: tuple[ProjectOverlayCounterfactualAudit, ...] = ()
    counterfactual_namespace_id: str | None = None
    clean_source_inputs: tuple[CleanSourceInput, ...] = ()
    compiler_namespaces: tuple[CompilerNamespaceEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class OverlaySemanticValidation:
    """Typed proofs plus the full canonical trace bound by those proofs."""

    proofs: Mapping[str, SemanticProof]
    trace: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ClassicCandidateSemanticValidation:
    """Proof plus the canonical statements needed by downstream ancestry checks."""

    proof: SemanticProof
    input_statement: Mapping[str, object]
    output_statement: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class DonorSemanticUse:
    """One downstream candidate whose closed validator consumed a donor."""

    intervention_id: str
    proof: SemanticProof
    input_statement: Mapping[str, object]
    output_statement: Mapping[str, object]
    input_name: str = ""


SOURCE_OVERLAY_OBLIGATIONS = (
    "overlay.carrier_isolation",
    "overlay.donor_semantics",
    "overlay.dual_compile_epoch",
    "overlay.effective_confinement",
    "overlay.primary_source_clean",
    "overlay.project_source_semantics",
)

DONOR_OBLIGATIONS = (
    "donor.fresh_compile",
    "donor.private_artifact",
    "donor.runtime_inputs_bound",
)

BINARY_TRANSFORM_OBLIGATIONS = (
    "binary.closed_validator",
    "binary.input_closure",
    "binary.semantic_equivalence",
)

IMAGE_METADATA_OBLIGATIONS = (
    "image.candidate_only",
    "image.logic_bytes_unchanged",
    "image.metadata_only",
)

IMAGE_LINK_ORDER_OBLIGATIONS = (
    "image.candidate_only",
    "image.import_binding_preserved",
    "image.semantic_equivalence",
)

IMAGE_BINARY_REPACK_OBLIGATIONS = (
    "image.byte_conservation",
    "image.candidate_only",
    "image.fixups_preserved",
    "image.semantic_equivalence",
)


def _classic_implementation_digest() -> Digest:
    """Content-identify the complete code closure behind classic validators."""

    package = Path(__file__).resolve(strict=True).parent
    selected = {
        package / "assets.py",
        package / "classic_runtime.py",
        package / "classic_project.py",
        package / "classic_orchestration.py",
        package / "classic_donors.py",
        package / "classic_overlay.py",
        package / "classic_semantics.py",
        package / "formats.py",
        package / "model.py",
        package / "producer_graph.py",
        package / "schema.py",
        package / "strict_json.py",
    }
    selected.update((package / "classic").glob("*.py"))
    paths = tuple(sorted(selected, key=lambda item: item.relative_to(package).as_posix()))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise RuntimeError("classic semantic validator implementation is not regular")
    return Digest.from_bytes(
        canonical_json(
            [
                {
                    "path": path.relative_to(package).as_posix(),
                    "digest": Digest.from_path(path).model_dump(mode="json"),
                    "size": path.stat().st_size,
                }
                for path in paths
            ]
        )
    )


CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST = _classic_implementation_digest()

SOURCE_OVERLAY_VALIDATOR_ID = "classic.source-overlay-ancestry.v1"
_SOURCE_OVERLAY_SPEC = {
    "schema": 1,
    "validator": SOURCE_OVERLAY_VALIDATOR_ID,
    "obligations": list(SOURCE_OVERLAY_OBLIGATIONS),
    "primary": "complete clean manifest plus declared generated carriers",
    "ordinary_overlay": "private donor lanes ending in registered semantic proofs",
    "carrier": (
        "closed COFF link graph with no inbound roots, startup sections, exports, "
        "novel dependencies, unsafe directives, or divergent duplicate COMDATs"
    ),
    "timestamp_policy": "COFF producer timestamps are parsed but excluded from semantics",
}
SOURCE_OVERLAY_VALIDATOR_DIGEST = Digest.from_bytes(
    canonical_json(
        {
            "specification": _SOURCE_OVERLAY_SPEC,
            "implementation": CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST.model_dump(mode="json"),
        }
    )
)

_DONOR_FAMILIES = frozenset(
    {
        ClassicRecipeFamily.DECLARATION_SHAPE,
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
        ClassicRecipeFamily.PAD_SHAPE,
        ClassicRecipeFamily.EXTERN_RUN_PAIR,
        ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE,
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
        ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN,
    }
)

_FUNCTION_FAMILIES = frozenset(
    {
        ClassicRecipeFamily.EQUAL_BODY_STRICT,
        ClassicRecipeFamily.EQUAL_BODY_EH_STRUCTURAL_LOCAL,
        ClassicRecipeFamily.SAME_SLOT_RESIZE,
        ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT,
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
        ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION,
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY,
        ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING,
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE,
        ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR,
        ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE,
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING,
        ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE,
    }
)


def _registered_contracts() -> Mapping[ClassicRecipeFamily, RegisteredSemanticContract]:
    result: dict[ClassicRecipeFamily, RegisteredSemanticContract] = {}
    for family in _DONOR_FAMILIES:
        result[family] = RegisteredSemanticContract(
            f"classic.donor-isolation.{family.value}.v1",
            CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST,
            DONOR_OBLIGATIONS,
        )
    for family in _FUNCTION_FAMILIES:
        result[family] = RegisteredSemanticContract(
            f"classic.binary-transform.{family.value}.v1",
            CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST,
            BINARY_TRANSFORM_OBLIGATIONS,
        )
    result[ClassicRecipeFamily.IMAGE_METADATA] = RegisteredSemanticContract(
        "classic.image-metadata.v1",
        CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST,
        IMAGE_METADATA_OBLIGATIONS,
    )
    result[ClassicRecipeFamily.IMAGE_LINK_ORDER] = RegisteredSemanticContract(
        "classic.image-link-order.v1",
        CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST,
        IMAGE_LINK_ORDER_OBLIGATIONS,
    )
    result[ClassicRecipeFamily.IMAGE_BINARY_REPACK] = RegisteredSemanticContract(
        "classic.image-binary-repack.v1",
        CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST,
        IMAGE_BINARY_REPACK_OBLIGATIONS,
    )
    result[ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH] = RegisteredSemanticContract(
        SOURCE_OVERLAY_VALIDATOR_ID,
        SOURCE_OVERLAY_VALIDATOR_DIGEST,
        SOURCE_OVERLAY_OBLIGATIONS,
    )
    return MappingProxyType(result)


CLASSIC_SEMANTIC_CONTRACTS = _registered_contracts()

_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})
_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"})
_OBJECT_SUFFIXES = frozenset({".obj", ".o"})
_ARCHIVE_SUFFIXES = frozenset({".lib", ".a"})
_FORBIDDEN_RUNTIME_SECTION_PREFIXES = (
    ".crt",
    ".edata",
    ".idata",
    ".rsrc",
    ".tls",
)
_ADMITTED_SECTION_PREFIXES = (
    ".bss",
    ".data",
    ".debug",
    ".drectve",
    ".rdata",
    ".text",
    ".xdata",
)
_DEFAULTLIB = re.compile(r"(?i)^[/-]defaultlib:([a-z0-9_.+@-]+)$")
_DISALLOWLIB = re.compile(r"(?i)^[/-]disallowlib:([a-z0-9_.+@-]+)$")
_MERGE_SECTION = re.compile(r"(?i)^[/-]merge:([.$?@_a-z0-9-]+)=([.$?@_a-z0-9-]+)$")
_LINK_SYMBOL_CONTROL = re.compile(r"(?i)^[/-](include|export):([a-z0-9_?$@.]+)(?:,(data|noname))?$")


def _relative(value: str, *, label: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ClassicSemanticError(f"{label} is not a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ClassicSemanticError(f"{label} is not a normalized relative path")
    return path.as_posix()


_Item = TypeVar("_Item")


def _unique(items: Sequence[_Item], key: Callable[[_Item], str], label: str) -> dict[str, _Item]:
    result: dict[str, _Item] = {}
    for item in items:
        item_key = str(key(item)).casefold()
        if item_key in result:
            raise ClassicSemanticError(f"{label} repeats {key(item)!r}")
        result[item_key] = item
    return result


def semantic_proof_evidence_digest(
    *,
    family: str,
    validator_id: str,
    validator_digest: Digest,
    input_statement_digest: Digest,
    output_statement_digest: Digest,
    obligations: tuple[str, ...],
) -> Digest:
    """Bind the complete typed semantic-proof envelope."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "family": family,
                "validator_id": validator_id,
                "validator_digest": validator_digest.model_dump(mode="json"),
                "input_statement_digest": input_statement_digest.model_dump(mode="json"),
                "output_statement_digest": output_statement_digest.model_dump(mode="json"),
                "obligations": list(obligations),
            }
        )
    )


def issue_semantic_proof(
    *,
    family: ClassicRecipeFamily,
    contract: SemanticValidatorContract,
    input_statement: object,
    output_statement: object,
) -> SemanticProof:
    """Issue one canonical proof after a closed validator has passed."""

    input_digest = Digest.from_bytes(canonical_json(input_statement))
    output_digest = Digest.from_bytes(canonical_json(output_statement))
    evidence = semantic_proof_evidence_digest(
        family=family.value,
        validator_id=contract.validator_id,
        validator_digest=contract.validator_digest,
        input_statement_digest=input_digest,
        output_statement_digest=output_digest,
        obligations=contract.obligations,
    )
    return SemanticProof(
        family=family.value,
        validator_id=contract.validator_id,
        validator_digest=contract.validator_digest,
        input_statement_digest=input_digest,
        output_statement_digest=output_digest,
        obligations=contract.obligations,
        evidence_digest=evidence,
        input_statement=input_statement,
        output_statement=output_statement,
    )


def semantic_proof_matches(
    proof: SemanticProof,
    family: ClassicRecipeFamily,
    contract: SemanticValidatorContract,
) -> bool:
    """Validate contract identity and the canonical proof envelope."""

    return (
        proof.family == family.value
        and proof.validator_id == contract.validator_id
        and proof.validator_digest == contract.validator_digest
        and proof.obligations == contract.obligations
        and proof.input_statement is not None
        and proof.output_statement is not None
        and proof.evidence_digest
        == semantic_proof_evidence_digest(
            family=proof.family,
            validator_id=proof.validator_id,
            validator_digest=proof.validator_digest,
            input_statement_digest=proof.input_statement_digest,
            output_statement_digest=proof.output_statement_digest,
            obligations=proof.obligations,
        )
    )


def _payload_receipts(values: Mapping[str, bytes], *, label: str) -> list[dict[str, object]]:
    """Normalize a closed named byte-input universe without retaining payloads."""

    folded: set[str] = set()
    result: list[dict[str, object]] = []
    for name, payload in sorted(values.items(), key=lambda item: item[0].casefold()):
        if not isinstance(name, str) or not name or name.casefold() in folded:
            raise ClassicSemanticError(f"{label} names are empty or DOS-case-colliding")
        if not isinstance(payload, bytes):
            raise ClassicSemanticError(f"{label} {name!r} is not immutable bytes")
        folded.add(name.casefold())
        result.append(
            {
                "name": name,
                "digest": Digest.from_bytes(payload).model_dump(mode="json"),
                "size": len(payload),
            }
        )
    return result


def classic_candidate_input_statement(
    intervention: ClassicRecipeIntervention,
    *,
    seed_input: bytes,
    binary_inputs: Mapping[str, bytes],
    source_inputs: Mapping[str, bytes],
    candidate_constraints: Mapping[str, object],
) -> Mapping[str, object]:
    """Seal every material visible to one closed classic candidate validator."""

    if intervention.role not in {ClassicRecipeRole.FUNCTION, ClassicRecipeRole.PROJECT}:
        raise ClassicSemanticError("candidate semantics require a function or project recipe")
    if not isinstance(seed_input, bytes):
        raise ClassicSemanticError("candidate seed is not immutable bytes")
    # Canonicalizing here rejects bytes, non-string keys, cycles, and non-finite
    # declaration values before a proof statement can be issued.
    constraints = dict(candidate_constraints)
    canonical_json(constraints)
    value: dict[str, object] = {
        "schema": 1,
        "kind": "classic-closed-candidate-input",
        "intervention": intervention.model_dump(mode="json"),
        "seed": {
            "digest": Digest.from_bytes(seed_input).model_dump(mode="json"),
            "size": len(seed_input),
        },
        "binary_inputs": _payload_receipts(binary_inputs, label="binary input"),
        "source_inputs": _payload_receipts(source_inputs, label="source input"),
        "candidate_constraints": constraints,
    }
    canonical_json(value)
    return MappingProxyType(value)


def issue_classic_candidate_semantics(
    intervention: ClassicRecipeIntervention,
    *,
    seed_input: bytes,
    binary_inputs: Mapping[str, bytes],
    source_inputs: Mapping[str, bytes],
    candidate_constraints: Mapping[str, object],
    output: bytes,
    validator_trace: Mapping[str, object],
) -> ClassicCandidateSemanticValidation:
    """Issue a family proof from one successful closed binary/image validator.

    The low-level validator trace is part of the output statement; the complete
    seed, donor/source material universe, declaration, and intervention are in
    the input statement.  Hash-only execution receipts cannot satisfy this API.
    """

    contract = CLASSIC_SEMANTIC_CONTRACTS.get(intervention.family)
    if (
        contract is None
        or intervention.family in _DONOR_FAMILIES
        or (intervention.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH)
    ):
        raise ClassicSemanticError(
            f"family {intervention.family.value!r} is not a candidate validator"
        )
    if intervention.role is ClassicRecipeRole.FUNCTION and (
        intervention.family not in _FUNCTION_FAMILIES
    ):
        raise ClassicSemanticError("function family is not a closed binary validator")
    if intervention.role is ClassicRecipeRole.PROJECT and intervention.family not in {
        ClassicRecipeFamily.IMAGE_METADATA,
        ClassicRecipeFamily.IMAGE_LINK_ORDER,
        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
    }:
        raise ClassicSemanticError("project family is not a closed image validator")
    if not isinstance(output, bytes) or not isinstance(validator_trace, Mapping):
        raise ClassicSemanticError("candidate validator returned malformed material")
    trace = dict(validator_trace)
    canonical_json(trace)
    input_statement = classic_candidate_input_statement(
        intervention,
        seed_input=seed_input,
        binary_inputs=binary_inputs,
        source_inputs=source_inputs,
        candidate_constraints=candidate_constraints,
    )
    output_statement: Mapping[str, object] = MappingProxyType(
        {
            "schema": 1,
            "kind": "classic-closed-candidate-output",
            "candidate": {
                "digest": Digest.from_bytes(output).model_dump(mode="json"),
                "size": len(output),
            },
            "validator_trace": trace,
        }
    )
    proof = issue_semantic_proof(
        family=intervention.family,
        contract=contract,
        input_statement=input_statement,
        output_statement=output_statement,
    )
    return ClassicCandidateSemanticValidation(
        proof=proof,
        input_statement=input_statement,
        output_statement=output_statement,
    )


def _statement_payload_digest(statement: Mapping[str, object], *, name: str) -> Digest | None:
    values = statement.get("binary_inputs")
    if not isinstance(values, list):
        return None
    matches = [item for item in values if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1 or not isinstance(matches[0].get("digest"), dict):
        return None
    try:
        return Digest.model_validate(matches[0]["digest"])
    except ValueError:
        return None


def _donor_legacy_id(intervention: ClassicRecipeIntervention) -> str | None:
    matches = [field.value for field in intervention.parameters if field.name == "legacy_recipe_id"]
    if len(matches) != 1 or not isinstance(matches[0], str) or not matches[0]:
        return None
    return matches[0]


def _donor_input_is_authorized(
    donor: ClassicRecipeIntervention,
    consumer: ClassicRecipeIntervention,
    statement: Mapping[str, object],
    *,
    input_name: str,
) -> bool:
    """Recognize the exact candidate seat through which ``donor`` was consumed."""

    if input_name == f"dependency:{donor.id}":
        return bool(consumer.dependencies) and consumer.dependencies[0] == donor.id
    constraints = statement.get("candidate_constraints")
    if not isinstance(constraints, Mapping):
        return False
    legacy_id = _donor_legacy_id(donor)
    if legacy_id is None:
        return False
    named_constraints = {
        "target_donor_object": "target_donor",
        "complete_donor_object": "complete_donor",
        "instruction_donor_object": "instruction_donor",
    }
    constraint_name = named_constraints.get(input_name)
    if constraint_name is not None:
        return constraints.get(constraint_name) == legacy_id
    if input_name != f"additional_donor:{legacy_id}":
        return False
    variants = constraints.get("donor_variants")
    return isinstance(variants, list) and any(
        isinstance(item, Mapping) and item.get("donor") == legacy_id for item in variants
    )


def _statement_named_digest(statement: Mapping[str, object], *path: str) -> Digest | None:
    current: object = statement
    for component in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(component)
    if not isinstance(current, Mapping):
        return None
    try:
        return Digest.model_validate(dict(current))
    except ValueError:
        return None


def issue_classic_donor_semantics(
    intervention: ClassicRecipeIntervention,
    *,
    donor_object: bytes,
    source_inputs: Mapping[str, bytes],
    compiler_statement: Mapping[str, object],
    downstream_uses: Sequence[DonorSemanticUse],
    quarantined_consumers: Mapping[str, Digest] = MappingProxyType({}),
) -> ClassicCandidateSemanticValidation:
    """Prove that one fresh donor stays private until a reviewed consumer.

    A donor is not itself linked.  It is either discarded or consumed only by
    candidate validators whose exact input statement binds this object's
    digest.  Legacy-oracle consumers are recorded as quarantined dispositions,
    never promoted to semantic validators.
    """

    contract = CLASSIC_SEMANTIC_CONTRACTS.get(intervention.family)
    if (
        intervention.role is not ClassicRecipeRole.DONOR
        or (intervention.family not in _DONOR_FAMILIES)
        or contract is None
    ):
        raise ClassicSemanticError("donor semantics require a registered donor recipe")
    if not isinstance(donor_object, bytes):
        raise ClassicSemanticError("donor object is not immutable bytes")
    compiler_trace = dict(compiler_statement)
    canonical_json(compiler_trace)
    donor_digest = Digest.from_bytes(donor_object)

    uses: list[dict[str, object]] = []
    seen: set[str] = set()
    for use in sorted(
        downstream_uses,
        key=lambda item: (item.intervention_id.casefold(), item.input_name.casefold()),
    ):
        folded = use.intervention_id.casefold()
        if not use.intervention_id or folded in seen:
            raise ClassicSemanticError("donor downstream identities repeat")
        seen.add(folded)
        raw_consumer = use.input_statement.get("intervention")
        if not isinstance(raw_consumer, Mapping):
            raise ClassicSemanticError("donor consumer statement omits its intervention")
        try:
            consumer = ClassicRecipeIntervention.model_validate_json(canonical_json(raw_consumer))
        except ValueError as exc:
            raise ClassicSemanticError("donor consumer intervention is malformed") from exc
        consumer_contract = CLASSIC_SEMANTIC_CONTRACTS.get(consumer.family)
        if (
            consumer.id != use.intervention_id
            or consumer.role is not ClassicRecipeRole.FUNCTION
            or consumer.scope.target != intervention.scope.target
            or consumer_contract is None
            or not semantic_proof_matches(use.proof, consumer.family, consumer_contract)
        ):
            raise ClassicSemanticError(
                f"donor {intervention.id!r} has an invalid consumer {use.intervention_id!r}"
            )
        if use.proof.input_statement_digest != Digest.from_bytes(
            canonical_json(use.input_statement)
        ) or use.proof.output_statement_digest != Digest.from_bytes(
            canonical_json(use.output_statement)
        ):
            raise ClassicSemanticError(f"donor consumer {consumer.id!r} proof statements changed")
        if not _donor_input_is_authorized(
            intervention,
            consumer,
            use.input_statement,
            input_name=use.input_name,
        ):
            raise ClassicSemanticError(
                f"donor consumer {consumer.id!r} uses an unauthorized candidate input"
            )
        if _statement_payload_digest(use.input_statement, name=use.input_name) != donor_digest:
            raise ClassicSemanticError(
                f"donor consumer {consumer.id!r} is not bound to its fresh object"
            )
        uses.append(
            {
                "kind": "typed-semantic-consumer",
                "intervention": consumer.id,
                "family": consumer.family.value,
                "input_name": use.input_name,
                "proof": use.proof.model_dump(mode="json"),
            }
        )
    for consumer_id, evidence in sorted(
        quarantined_consumers.items(), key=lambda item: item[0].casefold()
    ):
        folded = consumer_id.casefold()
        if not consumer_id or folded in seen or not isinstance(evidence, Digest):
            raise ClassicSemanticError("quarantined donor consumer is malformed")
        seen.add(folded)
        uses.append(
            {
                "kind": "quarantined-legacy-consumer",
                "intervention": consumer_id,
                "evidence_digest": evidence.model_dump(mode="json"),
            }
        )

    input_statement: Mapping[str, object] = MappingProxyType(
        {
            "schema": 1,
            "kind": "classic-private-donor-input",
            "intervention": intervention.model_dump(mode="json"),
            "donor_object": {
                "digest": donor_digest.model_dump(mode="json"),
                "size": len(donor_object),
            },
            "source_inputs": _payload_receipts(source_inputs, label="donor source input"),
            "compiler_statement": compiler_trace,
        }
    )
    output_statement: Mapping[str, object] = MappingProxyType(
        {
            "schema": 1,
            "kind": "classic-private-donor-output",
            "private_artifact": True,
            "direct_link_admissions": [],
            "disposition": "downstream-only" if uses else "discarded",
            "downstream_uses": uses,
        }
    )
    proof = issue_semantic_proof(
        family=intervention.family,
        contract=contract,
        input_statement=input_statement,
        output_statement=output_statement,
    )
    return ClassicCandidateSemanticValidation(
        proof=proof,
        input_statement=input_statement,
        output_statement=output_statement,
    )


def donor_lane_statement(
    *,
    target_id: str,
    donor_intervention_id: str,
    consumer_intervention_id: str,
    overlay_inputs: Sequence[EffectiveOverlayReceipt],
    seed_object_digest: Digest,
    donor_object_digest: Digest,
    candidate_object_digest: Digest,
) -> dict[str, object]:
    """Build the statement a downstream binary validator must consume."""

    return {
        "schema": 1,
        "kind": "classic-donor-semantic-lane",
        "target": target_id,
        "donor_intervention": donor_intervention_id,
        "consumer_intervention": consumer_intervention_id,
        "overlay_inputs": [
            {
                "path": item.path,
                "digest": item.digest.model_dump(mode="json"),
                "size": item.size,
            }
            for item in overlay_inputs
        ],
        "seed_object_digest": seed_object_digest.model_dump(mode="json"),
        "donor_object_digest": donor_object_digest.model_dump(mode="json"),
        "candidate_object_digest": candidate_object_digest.model_dump(mode="json"),
    }


def donor_lane_input_statement(lane: DonorSemanticLane) -> dict[str, object]:
    """Return the exact candidate input statement bound by a donor lane."""

    return dict(lane.consumer_input_statement)


@dataclass(frozen=True, slots=True)
class _CoffSymbol:
    index: int
    name: str
    value: int
    section: int
    symbol_type: int
    storage: int
    auxiliary_count: int
    auxiliary: bytes


@dataclass(frozen=True, slots=True)
class _CoffRelocation:
    offset: int
    relocation_type: int
    target: str
    target_section: int
    target_value: int
    target_type: int
    target_storage: int
    addend: bytes


@dataclass(frozen=True, slots=True)
class _CoffLineNumber:
    line_number: int
    address: int | None
    target: str | None
    target_section: int | None
    target_value: int | None
    target_type: int | None
    target_storage: int | None


@dataclass(frozen=True, slots=True)
class _CoffSection:
    number: int
    name: str
    body: bytes
    characteristics: int
    line_numbers: tuple[_CoffLineNumber, ...]
    relocations: tuple[_CoffRelocation, ...]
    comdat_selection: int | None
    comdat_associated: int | None


@dataclass(frozen=True, slots=True)
class _CoffObject:
    label: str
    digest: Digest
    header_characteristics: int
    sections: tuple[_CoffSection, ...]
    symbols: tuple[_CoffSymbol, ...]


@dataclass(frozen=True, slots=True)
class ClassicImportObjectReceipt:
    """Strict disposition for one i386 IMPORT_OBJECT_HEADER member."""

    label: str
    digest: Digest
    symbol: str
    dll: str
    import_type: int
    name_type: int

    @property
    def definitions(self) -> frozenset[str]:
        # IMPORT_OBJECT_HEADER causes the linker to synthesize the public
        # import and its address-table form.  Over-approximating both is safe
        # for carrier collision analysis.
        return frozenset({self.symbol, f"__imp_{self.symbol}"})


def _slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ClassicSemanticError(f"{label} is outside the COFF object")
    return data[offset : offset + size]


def _decode_name(raw: bytes, string_table: bytes, label: str) -> str:
    if raw[:4] == b"\0\0\0\0":
        offset = int.from_bytes(raw[4:8], "little")
        if offset < 4 or offset >= len(string_table):
            raise ClassicSemanticError(f"{label} string offset is invalid")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ClassicSemanticError(f"{label} is not NUL-terminated")
        encoded = string_table[offset:end]
    else:
        encoded = raw.rstrip(b"\0")
    # COFF symbol names are byte strings.  Latin-1 is a lossless one-byte
    # projection used only for equality/reachability; no locale decoding is
    # permitted here.
    return encoded.decode("latin-1")


def _decode_section_name(raw: bytes, string_table: bytes, label: str) -> str:
    short = raw.rstrip(b"\0")
    if short.startswith(b"/"):
        if not short[1:].isdigit():
            raise ClassicSemanticError(f"{label} long-name offset is malformed")
        offset = int(short[1:])
        if offset < 4 or offset >= len(string_table):
            raise ClassicSemanticError(f"{label} long-name offset is invalid")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ClassicSemanticError(f"{label} is not NUL-terminated")
        short = string_table[offset:end]
    try:
        return short.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClassicSemanticError(f"{label} is not ASCII") from exc


def _parse_coff(
    payload: bytes,
    label: str,
    *,
    allow_archive_extensions: bool = False,
) -> _CoffObject:
    """Parse the strict i386 COFF subset needed for reachability evidence."""

    if len(payload) < 20:
        raise ClassicSemanticError(f"{label} has a truncated COFF header")
    (
        machine,
        section_count,
        _timestamp,
        symbol_offset,
        symbol_count,
        optional_size,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", payload)
    if machine not in ({0, 0x14C} if allow_archive_extensions else {0x14C}) or (
        (not section_count or optional_size) and not allow_archive_extensions
    ):
        raise ClassicSemanticError(f"{label} is not a supported i386 COFF object")
    if optional_size:
        optional_header = _slice(payload, 20, optional_size, f"{label} optional header")
        if len(optional_header) < 2 or int.from_bytes(optional_header[:2], "little") != 0x10B:
            raise ClassicSemanticError(f"{label} has an unknown COFF optional header")
    section_table_at = 20 + optional_size
    section_table_end = section_table_at + section_count * 40
    _slice(
        payload,
        section_table_at,
        section_count * 40,
        f"{label} section table",
    )
    if not symbol_offset or not symbol_count:
        raise ClassicSemanticError(f"{label} has no closed COFF symbol table")
    symbols_end = symbol_offset + symbol_count * 18
    _slice(payload, symbol_offset, symbol_count * 18, f"{label} symbol table")
    string_size = int.from_bytes(
        _slice(payload, symbols_end, 4, f"{label} string-table size"), "little"
    )
    if string_size < 4 or symbols_end + string_size != len(payload):
        raise ClassicSemanticError(f"{label} has a non-canonical COFF string table")
    string_table = _slice(payload, symbols_end, string_size, f"{label} string table")

    symbols: list[_CoffSymbol] = []
    auxiliary_indexes: set[int] = set()
    auxiliary_records: dict[int, bytes] = {}
    index = 0
    while index < symbol_count:
        raw = _slice(payload, symbol_offset + index * 18, 18, f"{label} symbol {index}")
        name = _decode_name(raw[:8], string_table, f"{label} symbol {index}")
        value, section, symbol_type, storage, auxiliary_count = struct.unpack_from("<IhHBB", raw, 8)
        if index + auxiliary_count >= symbol_count:
            raise ClassicSemanticError(f"{label} symbol {index} auxiliaries are truncated")
        symbol = _CoffSymbol(
            index,
            name,
            value,
            section,
            symbol_type,
            storage,
            auxiliary_count,
            _slice(
                payload,
                symbol_offset + (index + 1) * 18,
                auxiliary_count * 18,
                f"{label} symbol {index} auxiliaries",
            )
            if auxiliary_count
            else b"",
        )
        symbols.append(symbol)
        if auxiliary_count:
            auxiliary_records[index] = _slice(
                payload,
                symbol_offset + (index + 1) * 18,
                auxiliary_count * 18,
                f"{label} symbol {index} auxiliaries",
            )
            auxiliary_indexes.update(range(index + 1, index + 1 + auxiliary_count))
        index += 1 + auxiliary_count
    by_index = {item.index: item for item in symbols}

    raw_sections: list[tuple[str, bytes, int, int, int, int, int]] = []
    for section_index in range(section_count):
        at = section_table_at + section_index * 40
        raw = _slice(payload, at, 40, f"{label} section {section_index + 1}")
        name = _decode_section_name(raw[:8], string_table, f"{label} section {section_index + 1}")
        (
            _virtual_size,
            _virtual_address,
            raw_size,
            raw_offset,
            relocation_offset,
            line_offset,
            relocation_count,
            line_count,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", raw, 8)
        uninitialized = bool(characteristics & 0x00000080)
        if raw_size and not raw_offset and not uninitialized:
            raise ClassicSemanticError(f"{label} section {name!r} has no raw data offset")
        if raw_size and raw_offset and raw_offset < section_table_end:
            raise ClassicSemanticError(f"{label} section {name!r} overlaps its headers")
        body = (
            bytes(raw_size)
            if raw_size and not raw_offset and uninitialized
            else _slice(payload, raw_offset, raw_size, f"{label} section {name!r} body")
        )
        if relocation_count and relocation_offset < section_table_end:
            raise ClassicSemanticError(
                f"{label} section {name!r} relocation table overlaps its headers"
            )
        if bool(line_offset) != bool(line_count):
            raise ClassicSemanticError(
                f"{label} section {name!r} has a non-canonical COFF line table"
            )
        if line_count:
            if line_offset < section_table_end:
                raise ClassicSemanticError(
                    f"{label} section {name!r} line table overlaps its headers"
                )
            _slice(
                payload,
                line_offset,
                line_count * 6,
                f"{label} section {name!r} line table",
            )
        raw_sections.append(
            (
                name,
                body,
                characteristics,
                relocation_offset,
                relocation_count,
                line_offset,
                line_count,
            )
        )

    definitions: dict[int, tuple[int, int]] = {}
    for symbol in symbols:
        if not (0 < symbol.section <= section_count and symbol.storage == 3):
            continue
        section_name = raw_sections[symbol.section - 1][0]
        if symbol.name != section_name or not symbol.auxiliary_count:
            continue
        auxiliary = auxiliary_records[symbol.index][:18]
        associated = int.from_bytes(auxiliary[12:14], "little") | (
            int.from_bytes(auxiliary[16:18], "little") << 16
        )
        definitions[symbol.section] = (auxiliary[14], associated)

    sections: list[_CoffSection] = []
    for section_index, raw_section in enumerate(raw_sections):
        (
            name,
            body,
            characteristics,
            relocation_offset,
            relocation_count,
            line_offset,
            line_count,
        ) = raw_section
        relocations: list[_CoffRelocation] = []
        for relocation_index in range(relocation_count):
            at = relocation_offset + relocation_index * 10
            offset, target_index, relocation_type = struct.unpack(
                "<IIH", _slice(payload, at, 10, f"{label} relocation")
            )
            if target_index in auxiliary_indexes or target_index not in by_index:
                raise ClassicSemanticError(f"{label} relocation names an auxiliary symbol")
            target = by_index[target_index]
            width = {6: 4, 7: 4, 10: 2, 11: 4, 20: 4}.get(relocation_type)
            if width is None:
                raise ClassicSemanticError(
                    f"{label} has unsupported relocation type 0x{relocation_type:04x}"
                )
            addend = _slice(body, offset, width, f"{label} relocation addend")
            relocations.append(
                _CoffRelocation(
                    offset,
                    relocation_type,
                    target.name,
                    target.section,
                    target.value,
                    target.symbol_type,
                    target.storage,
                    addend,
                )
            )
        line_numbers: list[_CoffLineNumber] = []
        for line_index in range(line_count):
            value, line_number = struct.unpack(
                "<IH",
                _slice(
                    payload,
                    line_offset + line_index * 6,
                    6,
                    f"{label} section {name!r} line record",
                ),
            )
            if line_number:
                if value > len(body):
                    raise ClassicSemanticError(
                        f"{label} section {name!r} line address is outside its body"
                    )
                line_numbers.append(
                    _CoffLineNumber(line_number, value, None, None, None, None, None)
                )
                continue
            if value in auxiliary_indexes or value not in by_index:
                raise ClassicSemanticError(
                    f"{label} section {name!r} line record names an invalid symbol"
                )
            target = by_index[value]
            line_numbers.append(
                _CoffLineNumber(
                    0,
                    None,
                    target.name,
                    target.section,
                    target.value,
                    target.symbol_type,
                    target.storage,
                )
            )
        selection = definitions.get(section_index + 1)
        sections.append(
            _CoffSection(
                section_index + 1,
                name,
                body,
                characteristics,
                tuple(line_numbers),
                tuple(relocations),
                selection[0] if selection is not None else None,
                selection[1] if selection is not None else None,
            )
        )
    return _CoffObject(
        label,
        Digest.from_bytes(payload),
        characteristics,
        tuple(sections),
        tuple(symbols),
    )


def _parse_import_object(payload: bytes, label: str) -> ClassicImportObjectReceipt | None:
    """Recognize one strict i386 IMPORT_OBJECT_HEADER archive member."""

    if len(payload) < 20 or payload[:4] != b"\0\0\xff\xff":
        return None
    (
        signature_one,
        signature_two,
        version,
        machine,
        _timestamp,
        data_size,
        _ordinal_or_hint,
        type_info,
    ) = struct.unpack_from("<HHHHIIHH", payload)
    if signature_one != 0 or signature_two != 0xFFFF:
        raise ClassicSemanticError(f"{label} has a malformed import-object signature")
    if version not in {0, 1} or machine != 0x14C or data_size != len(payload) - 20:
        raise ClassicSemanticError(f"{label} is not a supported i386 import object")
    import_type = type_info & 0x3
    name_type = (type_info >> 2) & 0x7
    reserved = type_info >> 5
    if import_type > 2 or name_type > 4 or reserved:
        raise ClassicSemanticError(f"{label} has unsupported import-object flags")
    data = payload[20:]
    values = data.split(b"\0")
    expected_strings = 3 if name_type == 4 else 2
    if (
        len(values) != expected_strings + 1
        or values[-1] != b""
        or any(not item for item in values[:-1])
    ):
        raise ClassicSemanticError(f"{label} import strings are not canonical")
    try:
        symbol = values[0].decode("ascii")
        dll = values[1].decode("ascii")
        if name_type == 4:
            values[2].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClassicSemanticError(f"{label} import strings are not ASCII") from exc
    if any(character.isspace() for character in symbol + dll):
        raise ClassicSemanticError(f"{label} import strings contain whitespace")
    return ClassicImportObjectReceipt(
        label,
        Digest.from_bytes(payload),
        symbol,
        dll.casefold(),
        import_type,
        name_type,
    )


def parse_classic_import_object(payload: bytes, *, label: str) -> ClassicImportObjectReceipt | None:
    """Classify a raw archive member as a strict import object or ordinary COFF."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable archive-member bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("import-object label is malformed")
    return _parse_import_object(payload, label)


def _coff_directive_receipt(coff: _CoffObject) -> CoffDirectiveReceipt:
    tokens: list[str] = []
    libraries: list[str] = []
    includes: list[str] = []
    exports: list[str] = []
    merges: list[tuple[str, str]] = []
    disallowed: list[str] = []
    for section in coff.sections:
        if section.name.casefold() != ".drectve":
            continue
        body = section.body
        # LINK 4.x libraries contain one observed, semantically inert terminal
        # NUL on a directive section.  Admit exactly one padding byte; multiple
        # or embedded NULs remain malformed rather than becoming token separators.
        if body.endswith(b"\0"):
            body = body[:-1]
        if b"\0" in body:
            raise ClassicSemanticError(
                f"{coff.label} linker directives contain malformed NUL padding"
            )
        try:
            text = body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ClassicSemanticError(f"{coff.label} linker directives are not ASCII") from exc
        if any(ord(character) < 0x20 and character not in "\t\r\n" for character in text):
            raise ClassicSemanticError(
                f"{coff.label} linker directives contain a control character"
            )
        for token in text.split():
            default_library = _DEFAULTLIB.fullmatch(token)
            if default_library is not None:
                tokens.append(token)
                libraries.append(default_library.group(1))
                continue
            disallow_library = _DISALLOWLIB.fullmatch(token)
            if disallow_library is not None:
                tokens.append(token)
                disallowed.append(disallow_library.group(1))
                continue
            merge = _MERGE_SECTION.fullmatch(token)
            if merge is not None:
                tokens.append(token)
                merges.append((merge.group(1), merge.group(2)))
                continue
            control = _LINK_SYMBOL_CONTROL.fullmatch(token)
            if control is None or (
                control.group(1).casefold() == "include" and control.group(3) is not None
            ):
                raise ClassicSemanticError(
                    f"{coff.label} contains unsafe linker directive {token!r}"
                )
            tokens.append(token)
            if control.group(1).casefold() == "include":
                includes.append(control.group(2))
            else:
                exports.append(control.group(2))
    return CoffDirectiveReceipt(
        tuple(tokens),
        tuple(libraries),
        tuple(includes),
        tuple(exports),
        tuple(merges),
        tuple(disallowed),
    )


def parse_classic_coff_directives(payload: bytes, *, label: str) -> CoffDirectiveReceipt:
    """Parse the complete closed `.drectve` language of one i386 COFF object."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable COFF bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("COFF directive label is malformed")
    return _coff_directive_receipt(_parse_coff(payload, label))


def parse_classic_archive_member_directives(payload: bytes, *, label: str) -> CoffDirectiveReceipt:
    """Parse directives from a classified ordinary COFF archive member."""

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable archive-member bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("archive-member directive label is malformed")
    if _parse_import_object(payload, label) is not None:
        raise ClassicSemanticError(f"{label} is an import object, not ordinary COFF")
    return _coff_directive_receipt(_parse_coff(payload, label, allow_archive_extensions=True))


def _archive_semantics(
    target: TargetLinkClosure,
    *,
    compiler_digests: frozenset[Digest],
    carrier_digests: frozenset[Digest],
) -> tuple[
    list[_CoffObject],
    list[ClassicImportObjectReceipt],
    list[dict[str, object]],
]:
    """Completely parse every raw archive and classify every non-linker member."""

    archives = _unique(target.archives, lambda item: item.archive_ref, "archive input")
    expected = {item.casefold() for item in target.archive_refs}
    if set(archives) != expected:
        missing = sorted(expected - set(archives))
        extra = sorted(set(archives) - expected)
        raise ClassicSemanticError(
            f"target {target.target_id!r} raw archive closure differs; "
            f"missing={missing}, extra={extra}"
        )
    objects: list[_CoffObject] = []
    imports: list[ClassicImportObjectReceipt] = []
    traces: list[dict[str, object]] = []
    for archive_ref in target.archive_refs:
        raw_archive = archives[archive_ref.casefold()]
        if (
            not isinstance(raw_archive, ArchiveInput)
            or not isinstance(raw_archive.payload, bytes)
            or not raw_archive.payload
        ):
            raise ClassicSemanticError(f"archive {archive_ref!r} is not immutable bytes")
        try:
            parsed = parse_coff_archive(raw_archive.payload)
        except FormatError as exc:
            raise ClassicSemanticError(f"cannot parse archive {archive_ref!r}: {exc}") from exc
        ordinary_count = 0
        import_count = 0
        carrier_clone_count = 0
        compiler_clone_count = 0
        content_members = 0
        for index, member in enumerate(parsed.members):
            if member.name in {"/", "//", "/SYM64/"}:
                continue
            content_members += 1
            label = f"{archive_ref}({index}:{member.name})"
            digest = Digest.from_bytes(member.data)
            if digest in carrier_digests:
                carrier_clone_count += 1
                continue
            if digest in compiler_digests:
                compiler_clone_count += 1
                continue
            import_object = _parse_import_object(member.data, label)
            if import_object is not None:
                imports.append(import_object)
                import_count += 1
                continue
            objects.append(_parse_coff(member.data, label, allow_archive_extensions=True))
            ordinary_count += 1
        if not content_members:
            raise ClassicSemanticError(f"archive {archive_ref!r} has no content members")
        traces.append(
            {
                "archive_ref": archive_ref,
                "digest": Digest.from_bytes(raw_archive.payload).model_dump(mode="json"),
                "size": len(raw_archive.payload),
                "member_count": len(parsed.members),
                "content_member_count": content_members,
                "ordinary_coff_members": ordinary_count,
                "import_object_members": import_count,
                "carrier_object_clones": carrier_clone_count,
                "compiler_object_clones": compiler_clone_count,
            }
        )
    return objects, imports, traces


def _external_definitions(coff: _CoffObject) -> dict[str, _CoffSection]:
    result: dict[str, _CoffSection] = {}
    for symbol in coff.symbols:
        if symbol.storage != 2 or symbol.section <= 0:
            continue
        if symbol.section > len(coff.sections):
            raise ClassicSemanticError(f"{coff.label} definition has an invalid section")
        previous = result.setdefault(symbol.name, coff.sections[symbol.section - 1])
        if previous.number != symbol.section:
            raise ClassicSemanticError(
                f"{coff.label} defines external symbol {symbol.name!r} more than once"
            )
    return result


def _external_references(coff: _CoffObject) -> set[str]:
    return {
        relocation.target
        for section in coff.sections
        for relocation in section.relocations
        if relocation.target_section == 0 and relocation.target_storage in {2, 105}
    }


def _canonical_runtime_section(section: _CoffSection) -> object:
    return {
        "name": section.name,
        "body": section.body.hex(),
        "characteristics": section.characteristics,
        "selection": section.comdat_selection,
        "associated": section.comdat_associated,
        "relocations": [
            {
                "offset": item.offset,
                "type": item.relocation_type,
                "target": item.target,
                "target_value": item.target_value,
                "target_type": item.target_type,
                "target_storage": item.target_storage,
                "addend": item.addend.hex(),
            }
            for item in section.relocations
        ],
    }


def _default_libraries(coff: _CoffObject) -> set[str]:
    for section in coff.sections:
        folded = section.name.casefold()
        if any(folded.startswith(prefix) for prefix in _FORBIDDEN_RUNTIME_SECTION_PREFIXES):
            raise ClassicSemanticError(
                f"carrier {coff.label!r} contains runtime-root section {section.name!r}"
            )
        if not any(folded.startswith(prefix) for prefix in _ADMITTED_SECTION_PREFIXES):
            raise ClassicSemanticError(
                f"carrier {coff.label!r} contains unknown section {section.name!r}"
            )
    directives = _coff_directive_receipt(coff)
    if directives.include_symbols or directives.export_symbols:
        raise ClassicSemanticError(f"carrier {coff.label!r} contains a rooted linker control")
    return {item.casefold() for item in directives.default_libraries}


def _carrier_isolation_trace(
    *,
    target: TargetLinkClosure,
    products: Mapping[str, CompilerProduct],
    carrier_node_ids: frozenset[str],
) -> dict[str, object]:
    if tuple(sorted(set(target.compiler_node_ids), key=str.casefold)) != (target.compiler_node_ids):
        raise ClassicSemanticError(f"target {target.target_id!r} compiler closure is not canonical")
    if not carrier_node_ids.issubset(target.compiler_node_ids):
        raise ClassicSemanticError(
            f"target {target.target_id!r} omits a generated carrier from its link closure"
        )
    unknown_nodes = set(target.compiler_node_ids) - set(products)
    if unknown_nodes:
        raise ClassicSemanticError(
            f"target {target.target_id!r} names unknown compiler nodes {sorted(unknown_nodes)}"
        )
    if tuple(sorted(set(target.archive_refs), key=str.casefold)) != target.archive_refs:
        raise ClassicSemanticError(f"target {target.target_id!r} archives are not canonical")

    carrier_objects = [
        _parse_coff(products[node_id].payload, products[node_id].object_ref)
        for node_id in sorted(carrier_node_ids)
    ]
    ordinary_objects = [
        _parse_coff(products[node_id].payload, products[node_id].object_ref)
        for node_id in target.compiler_node_ids
        if node_id not in carrier_node_ids
    ]
    archive_objects, import_objects, archive_trace = _archive_semantics(
        target,
        compiler_digests=frozenset(
            Digest.from_bytes(products[node_id].payload) for node_id in target.compiler_node_ids
        ),
        carrier_digests=frozenset(item.digest for item in carrier_objects),
    )
    ordinary_objects.extend(archive_objects)
    if not ordinary_objects:
        raise ClassicSemanticError(f"target {target.target_id!r} has no ordinary object ancestry")

    ordinary_definitions: dict[str, list[tuple[_CoffObject, _CoffSection]]] = defaultdict(list)
    ordinary_references: set[str] = set()
    ordinary_libraries: set[str] = set()
    ordinary_directive_roots: set[str] = set()
    for coff in ordinary_objects:
        for name, section in _external_definitions(coff).items():
            ordinary_definitions[name].append((coff, section))
        ordinary_references.update(_external_references(coff))
        ordinary_libraries.update(_default_libraries_for_ordinary(coff))
        directives = _coff_directive_receipt(coff)
        ordinary_directive_roots.update(directives.include_symbols)
        ordinary_directive_roots.update(directives.export_symbols)
    import_definitions = {definition for item in import_objects for definition in item.definitions}

    carrier_definitions: dict[str, list[tuple[_CoffObject, _CoffSection]]] = defaultdict(list)
    carrier_references: set[str] = set()
    carrier_libraries: set[str] = set()
    for coff in carrier_objects:
        for name, section in _external_definitions(coff).items():
            carrier_definitions[name].append((coff, section))
        carrier_references.update(_external_references(coff))
        carrier_libraries.update(_default_libraries(coff))

    imported_collisions = set(carrier_definitions) & import_definitions
    if imported_collisions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers collide with imported symbols: "
            f"{sorted(imported_collisions)}"
        )

    roots = set(target.root_symbols) | ordinary_directive_roots
    unique_carrier = set(carrier_definitions) - set(ordinary_definitions)
    if not roots.isdisjoint(unique_carrier):
        raise ClassicSemanticError(
            f"target {target.target_id!r} roots a carrier definition: "
            f"{sorted(roots & unique_carrier)}"
        )
    inbound = unique_carrier & ordinary_references
    if inbound:
        raise ClassicSemanticError(
            f"target {target.target_id!r} has inbound carrier references: {sorted(inbound)}"
        )
    novel_dependencies = carrier_references - ordinary_references - set(carrier_definitions)
    if novel_dependencies:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers add external dependencies: "
            f"{sorted(novel_dependencies)}"
        )
    novel_libraries = carrier_libraries - ordinary_libraries
    if novel_libraries:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers add default libraries: {sorted(novel_libraries)}"
        )

    duplicate_receipts: list[dict[str, object]] = []
    for name in sorted(set(carrier_definitions) & set(ordinary_definitions)):
        carrier_rows = carrier_definitions[name]
        ordinary_rows = ordinary_definitions[name]
        if any(
            relocation.target_section > 0 and relocation.target_storage != 2
            for _, section in (*ordinary_rows, *carrier_rows)
            for relocation in section.relocations
        ):
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "has an object-local relocation"
            )
        baseline = _canonical_runtime_section(ordinary_rows[0][1])
        all_rows = [*ordinary_rows, *carrier_rows]
        if any(_canonical_runtime_section(section) != baseline for _, section in all_rows):
            raise ClassicSemanticError(
                f"target {target.target_id!r} has divergent duplicate carrier symbol {name!r}"
            )
        if any(section.comdat_selection in {None, 0, 5} for _, section in all_rows):
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "is not a primary COMDAT"
            )
        duplicate_receipts.append(
            {
                "symbol": name,
                "section_digest": Digest.from_bytes(canonical_json(baseline)).value,
                "definitions": sorted(coff.label for coff, _ in all_rows),
            }
        )

    return {
        "target": target.target_id,
        "carrier_objects": [
            {"label": item.label, "digest": item.digest.value}
            for item in sorted(carrier_objects, key=lambda item: item.label.casefold())
        ],
        "ordinary_object_count": len(ordinary_objects),
        "archive_count": len(target.archive_refs),
        "archives": archive_trace,
        "import_object_count": len(import_objects),
        "root_symbols": sorted(roots),
        "unique_unreferenced_definitions": sorted(unique_carrier),
        "existing_external_dependencies": sorted(carrier_references),
        "existing_default_libraries": sorted(carrier_libraries),
        "identical_duplicate_comdats": duplicate_receipts,
    }


def _default_libraries_for_ordinary(coff: _CoffObject) -> set[str]:
    return {item.casefold() for item in _coff_directive_receipt(coff).default_libraries}


def overlay_semantic_run_binding(
    graph: ProducerGraphDocument, snapshot: OverlaySemanticSnapshot
) -> Digest:
    """Recompute the executor's immutable semantic-snapshot binding.

    This is ancestry integrity, not a logic theorem: it prevents a caller from
    swapping an OBJ, source epoch, or archive after the current-run receipts
    were sealed.  Logic equivalence is established separately by the source
    and COFF theorems.
    """

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "producer_graph": producer_graph_digest(graph).model_dump(mode="json"),
                "primary_sources": [
                    {
                        "path": item.path,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                        "origin": item.origin.value,
                    }
                    for item in snapshot.primary_sources
                ],
                "compiler_products": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                        "generated_inputs": list(item.generated_inputs),
                        "compiler_invocation": (
                            _compiler_epoch_wire(item.compiler_invocation)
                            if item.compiler_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.compiler_products
                ],
                "project_source_pairs": [
                    {
                        "path": item.path,
                        "clean_digest": (
                            Digest.from_bytes(item.clean_payload).model_dump(mode="json")
                            if item.clean_payload is not None
                            else None
                        ),
                        "clean_size": (
                            len(item.clean_payload) if item.clean_payload is not None else None
                        ),
                        "effective_digest": Digest.from_bytes(item.effective_payload).model_dump(
                            mode="json"
                        ),
                        "effective_size": len(item.effective_payload),
                    }
                    for item in snapshot.project_source_pairs
                ],
                "counterfactual_compiler_audits": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.counterfactual_payload).model_dump(
                            mode="json"
                        ),
                        "size": len(item.counterfactual_payload),
                        "counterfactual_invocation": (
                            _compiler_epoch_wire(item.counterfactual_invocation)
                            if item.counterfactual_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.counterfactual_compiler_audits
                ],
                "counterfactual_namespace_id": snapshot.counterfactual_namespace_id,
                "clean_source_inputs": [
                    {
                        "path": item.path,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                    }
                    for item in snapshot.clean_source_inputs
                ],
                "compiler_namespaces": [
                    {
                        "namespace_id": item.namespace_id,
                        "namespace_digest": item.namespace_digest.model_dump(mode="json"),
                        "input_evidence_kind": item.input_evidence_kind.value,
                        "members": [
                            _compiler_namespace_member_wire(member) for member in item.members
                        ],
                    }
                    for item in snapshot.compiler_namespaces
                ],
                "archives": [
                    {
                        "target": closure.target_id,
                        "values": [
                            {
                                "reference": archive.archive_ref,
                                "digest": Digest.from_bytes(archive.payload).model_dump(
                                    mode="json"
                                ),
                                "size": len(archive.payload),
                            }
                            for archive in closure.archives
                        ],
                    }
                    for closure in snapshot.link_closures
                ],
            }
        )
    )


def _compiler_epoch_wire(value: CompilerEpochInvocation) -> dict[str, object]:
    return {
        "input_evidence_kind": value.input_evidence_kind.value,
        "tool_id": value.tool_id,
        "tool_digest": value.tool_digest.model_dump(mode="json"),
        "arguments": list(value.arguments),
        "working_directory": value.working_directory,
        "environment_digest": value.environment_digest.model_dump(mode="json"),
        "path_profile_digest": value.path_profile_digest.model_dump(mode="json"),
        "invocation_digest": value.invocation_digest.model_dump(mode="json"),
        "namespace_id": value.namespace_id,
        "namespace_digest": value.namespace_digest.model_dump(mode="json"),
        "namespace_count": value.namespace_count,
    }


def _overlay_interventions(
    bundle: ProjectBundle,
) -> tuple[ClassicRecipeIntervention, ...]:
    return tuple(
        item
        for item in bundle.interventions
        if isinstance(item, ClassicRecipeIntervention)
        and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
    )


def _overlay_declaration(
    intervention: ClassicRecipeIntervention,
) -> tuple[
    dict[str, dict[str, object]],
    frozenset[str],
    frozenset[str],
]:
    values = {item.name: item.value for item in intervention.parameters}
    if (
        set(values)
        not in (
            {"graph", "outputs", "schema"},
            {"graph", "outputs", "schema", "semantic_claims"},
        )
        or values["schema"] != 2
    ):
        raise ClassicSemanticError(f"overlay {intervention.id!r} declaration is not closed")
    graph = values["graph"]
    outputs = values["outputs"]
    if not isinstance(graph, dict) or set(graph) != {"generated_tus", "link_admissions"}:
        raise ClassicSemanticError(f"overlay {intervention.id!r} graph is malformed")
    if graph["link_admissions"] != [] or not isinstance(graph["generated_tus"], list):
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} has unsupported direct link admissions"
        )
    generated: set[str] = set()
    for item in graph["generated_tus"]:
        path_value = item.get("path") if isinstance(item, dict) else None
        if not isinstance(path_value, str):
            raise ClassicSemanticError(f"overlay {intervention.id!r} carrier is malformed")
        generated.add(_relative(path_value, label="generated carrier path"))
    if not isinstance(outputs, list):
        raise ClassicSemanticError(f"overlay {intervention.id!r} outputs are malformed")
    result: dict[str, dict[str, object]] = {}
    for item in outputs:
        if not isinstance(item, dict):
            raise ClassicSemanticError(f"overlay {intervention.id!r} output is malformed")
        path_value = item.get("path")
        if not isinstance(path_value, str):
            raise ClassicSemanticError(f"overlay {intervention.id!r} output is malformed")
        path = _relative(path_value, label="overlay output path")
        if path.casefold() in {key.casefold() for key in result}:
            raise ClassicSemanticError(f"overlay {intervention.id!r} repeats {path!r}")
        effective = item.get("effective")
        size = item.get("size")
        if not isinstance(effective, str) or re.fullmatch(r"[0-9a-f]{64}", effective) is None:
            raise ClassicSemanticError(f"overlay {intervention.id!r} has an invalid digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ClassicSemanticError(f"overlay {intervention.id!r} has an invalid size")
        result[path] = {str(key): value for key, value in item.items()}
    generated_inputs = {path for path, declaration in result.items() if "clean" not in declaration}
    if generated_inputs and not generated:
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} generated inputs have no carrier TU"
        )
    if not generated.issubset(generated_inputs):
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} carrier TUs are not generated outputs"
        )
    for path in generated_inputs:
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix in _SOURCE_SUFFIXES:
            if path not in generated:
                raise ClassicSemanticError(
                    f"overlay {intervention.id!r} generated source is not a carrier TU: {path!r}"
                )
        elif suffix not in _HEADER_SUFFIXES:
            raise ClassicSemanticError(
                f"overlay {intervention.id!r} has unsupported generated input {path!r}"
            )
    return result, frozenset(generated), frozenset(generated_inputs)


def _compiler_shape(node: ProducerNode) -> tuple[str, str]:
    source_refs = [
        item
        for item in node.inputs
        if PurePosixPath(item.split("/", 1)[-1]).suffix.casefold() in _SOURCE_SUFFIXES
    ]
    object_refs = [
        item
        for item in node.outputs
        if PurePosixPath(item.split("/", 1)[-1]).suffix.casefold() in _OBJECT_SUFFIXES
    ]
    if len(source_refs) != 1 or len(object_refs) != 1:
        raise ClassicSemanticError(
            f"compiler node {node.id!r} does not have one source and one object"
        )
    return source_refs[0], object_refs[0]


def _ancestor_compilers(graph: ProducerGraphDocument, target_id: str) -> frozenset[str]:
    by_id = {node.id: node for node in graph.nodes}
    terminal = [
        node
        for node in graph.nodes
        if node.role is ProducerRole.LINKER and node.target_id == target_id
    ]
    if len(terminal) != 1:
        raise ClassicSemanticError(f"target {target_id!r} has no unique linker node")
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited:
            return
        visited.add(node_id)
        for dependency in by_id[node_id].depends_on:
            visit(dependency)

    visit(terminal[0].id)
    return frozenset(node_id for node_id in visited if by_id[node_id].role is ProducerRole.COMPILER)


def _graph_archives(graph: ProducerGraphDocument, target_id: str) -> tuple[str, ...]:
    by_id = {node.id: node for node in graph.nodes}
    terminal = next(
        node
        for node in graph.nodes
        if node.role is ProducerRole.LINKER and node.target_id == target_id
    )
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited:
            return
        visited.add(node_id)
        for dependency in by_id[node_id].depends_on:
            visit(dependency)

    visit(terminal.id)
    values = {
        item
        for node_id in visited
        for item in (
            *by_id[node_id].inputs,
            *by_id[node_id].directive_inputs,
        )
        if PurePosixPath(item.split("/", 1)[-1]).suffix.casefold() in _ARCHIVE_SUFFIXES
    }
    return tuple(sorted(values, key=str.casefold))


def _receipt_trace(receipt: ClassicOverlayOutputReceipt) -> dict[str, object]:
    return {
        "path": receipt.path,
        "input_digest": receipt.input_digest,
        "input_size": receipt.input_size,
        "output_digest": receipt.output_digest,
        "output_size": receipt.output_size,
        "operations": [
            {
                "operation_id": operation.operation_id,
                "action": operation.action,
                "fragment_digest": operation.fragment_digest,
                "fragment_size": operation.fragment_size,
                "removed_digest": operation.removed_digest,
                "removed_size": operation.removed_size,
                "anchors": [
                    {
                        "role": anchor.role,
                        "context_digest": anchor.context_digest,
                        "token_boundary": anchor.token_boundary,
                        "byte_offset": anchor.byte_offset,
                    }
                    for anchor in operation.anchors
                ],
            }
            for operation in receipt.operations
        ],
    }


_DECLARATION_GENERATORS = frozenset(
    {
        "class",
        "empty_class",
        "enum",
        "extern_run",
        "fwd",
        "fwd_run",
        "fwd_seq",
        "proto",
        "typedef",
    }
)
_GENERATED_CARRIER_GENERATORS = frozenset(
    {"call_supplier", "const_pool", "reloc_ring", "template_supplier"}
)
_UNREACHABLE_HELPER_GENERATORS = frozenset(
    {"crt_pull", "cursor_probe", "local_probe", "member_probe", "seed_seq"}
)
_FUNCTION_CLAIM_GENERATORS = frozenset(
    {"assert_reseat", "empty_scopes", "literal_alias", "local_ids", "noop_assign"}
)
_CPP_SOURCE_SUFFIXES = _SOURCE_SUFFIXES | _HEADER_SUFFIXES
_INTEGRAL_TYPE_TOKENS = frozenset(
    {"bool", "char", "int", "long", "short", "signed", "unsigned", "wchar_t"}
)
_TYPE_QUALIFIERS = frozenset({"const", "volatile"})


@dataclass(frozen=True, slots=True)
class _ScalarBinding:
    identifier: str
    type_spelling: str
    initialized: bool


@dataclass(frozen=True, slots=True)
class _FunctionScopeClaim:
    operation_id: str
    leaf_index: int
    function: str
    range_digest: Digest
    range_size: int
    bindings: tuple[_ScalarBinding, ...]


@dataclass(frozen=True, slots=True)
class _LogicalHeaderClaim:
    operation_id: str
    leaf_index: int
    logical_path: str


_SemanticClaim = _FunctionScopeClaim | _LogicalHeaderClaim


@dataclass(frozen=True, slots=True)
class _DeclarationEntity:
    """One entity introduced by the closed declaration grammar."""

    primary_identifier: str
    introduced_identifiers: tuple[str, ...]
    disposition: str
    tag: str | None
    semantic_digest: Digest


@dataclass(frozen=True, slots=True)
class _DeclarationFact:
    """One target-exposed spelling used for ODR compatibility checks."""

    identifier: str
    primary_identifier: str
    disposition: str
    tag: str | None
    semantic_digest: Digest
    source_path: str
    targets: frozenset[str]


def _claim_key(operation_id: str, leaf_index: int) -> str:
    return f"{operation_id.casefold()}\0{leaf_index:08d}"


@dataclass(frozen=True, slots=True)
class _OverlaySourceValidation:
    traces: Mapping[str, object]
    compiler_epoch_plan: ProjectOverlayCompilerEpochPlan
    generated_headers: frozenset[str]
    logical_headers: frozenset[str]
    unused_typedef_sources: frozenset[str]
    projection_sources: frozenset[str]
    projection_all: bool
    helper_identifiers: frozenset[str]
    helpers_by_source: Mapping[str, tuple[str, ...]]
    global_declaration_identifiers: frozenset[str]
    macro_sensitive_identifiers: frozenset[str]
    intrinsic_macro_mutations: frozenset[tuple[str, str, str]]


def _overlay_document(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    values = {item.name: item.value for item in intervention.parameters}
    return {
        "schema": values.get("schema"),
        "outputs": values.get("outputs"),
        "graph": values.get("graph"),
    }


def _generator_leaves(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, dict) or not isinstance(value.get("k"), str):
        raise ClassicSemanticError("source-overlay generator is malformed")
    normalized = {str(key): item for key, item in value.items()}
    if normalized["k"] != "seq":
        return (normalized,)
    raw_items = normalized.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ClassicSemanticError("source-overlay sequence is empty")
    result: list[dict[str, object]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            raise ClassicSemanticError("source-overlay sequence item is malformed")
        child = {str(key): item for key, item in raw_item.items() if key != "line"}
        result.extend(_generator_leaves(child))
    return tuple(result)


def _expanded_names(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        if (
            set(value) != {"count", "first", "kind", "stem", "width"}
            or value.get("kind") != "identifier_run"
        ):
            raise ClassicSemanticError("source-overlay identifier run is malformed")
        stem = value.get("stem")
        first = value.get("first")
        count = value.get("count")
        width = value.get("width")
        if (
            not isinstance(stem, str)
            or not isinstance(first, int)
            or isinstance(first, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or first < 0
            or count < 1
            or not 1 <= width <= 8
        ):
            raise ClassicSemanticError("source-overlay identifier run is malformed")
        return tuple(stem + str(index).zfill(width) for index in range(first, first + count))
    if not isinstance(value, list):
        raise ClassicSemanticError("source-overlay declaration name run is malformed")
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
            continue
        if not isinstance(item, dict):
            raise ClassicSemanticError("source-overlay declaration name run is malformed")
        stem = item.get("stem")
        first = item.get("first")
        count = item.get("count")
        width = item.get("width", len(str(first)))
        if (
            not isinstance(stem, str)
            or not isinstance(first, int)
            or isinstance(first, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
        ):
            raise ClassicSemanticError("source-overlay declaration name run is malformed")
        if first < 0 or count < 1 or not 1 <= width <= 8:
            raise ClassicSemanticError("source-overlay declaration name run is out of range")
        result.extend(stem + str(index).zfill(width) for index in range(first, first + count))
    if len(result) != len(set(result)):
        raise ClassicSemanticError("source-overlay declaration name run repeats")
    return tuple(result)


_DECLARATION_LAYOUT_KEYS = frozenset({"at", "blank_indent", "indent", "lines", "nl"})


def _declaration_statement(
    generator: Mapping[str, object],
    *,
    disposition: str,
    primary_identifier: str,
) -> dict[str, object]:
    """Return the layout-free statement whose equality discharges ODR identity."""

    return {
        "disposition": disposition,
        "primary_identifier": primary_identifier,
        "generator": {
            key: value
            for key, value in sorted(generator.items())
            if key not in _DECLARATION_LAYOUT_KEYS
        },
    }


def _declaration_entity(
    *,
    primary_identifier: str,
    introduced_identifiers: tuple[str, ...],
    disposition: str,
    tag: str | None,
    statement: Mapping[str, object],
) -> _DeclarationEntity:
    if len(introduced_identifiers) != len(set(introduced_identifiers)):
        raise ClassicSemanticError(
            f"declaration {primary_identifier!r} repeats an introduced spelling"
        )
    return _DeclarationEntity(
        primary_identifier,
        introduced_identifiers,
        disposition,
        tag,
        Digest.from_bytes(canonical_json(statement)),
    )


def _forward_run_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    stem = generator.get("stem")
    first = generator.get("first")
    count = generator.get("count")
    width = generator.get("width", len(str(first)))
    if (
        not isinstance(stem, str)
        or not isinstance(first, int)
        or isinstance(first, bool)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not isinstance(width, int)
        or isinstance(width, bool)
        or first < 0
        or count < 1
        or not 1 <= width <= 8
    ):
        raise ClassicSemanticError("source-overlay forward run is malformed")
    return tuple(stem + str(index).zfill(width) for index in range(first, first + count))


def _declaration_entities(
    generator: Mapping[str, object],
) -> tuple[_DeclarationEntity, ...]:
    """Expand the closed generator grammar into declaration entities."""

    kind = generator["k"]
    if kind in {"fwd", "fwd_seq", "fwd_run"}:
        identifiers: tuple[str, ...]
        if kind == "fwd":
            identifier = generator.get("id")
            if not isinstance(identifier, str):
                raise ClassicSemanticError("forward declaration lacks its identifier")
            identifiers = (identifier,)
        elif kind == "fwd_seq":
            identifiers = _expanded_names(generator.get("identifiers"))
        else:
            identifiers = _forward_run_identifiers(generator)
        tag = generator.get("tag", "class")
        if tag not in {"class", "struct", "union"}:
            raise ClassicSemanticError("forward declaration tag is outside the closed enum")
        return tuple(
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="record-forward",
                tag=str(tag),
                statement={
                    "disposition": "record-forward",
                    "primary_identifier": identifier,
                    "tag": tag,
                },
            )
            for identifier in identifiers
        )
    if kind in {"empty_class", "class"}:
        identifier = generator.get("id")
        tag = generator.get("tag", "class")
        if not isinstance(identifier, str) or tag not in {"class", "struct"}:
            raise ClassicSemanticError(f"{kind} declaration is malformed")
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="record-definition",
                tag=str(tag),
                statement=_declaration_statement(
                    generator,
                    disposition="record-definition",
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind == "enum":
        identifier = generator.get("id")
        if not isinstance(identifier, str):
            raise ClassicSemanticError("source-overlay enum lacks its identifier")
        enum_identifiers = (identifier, *_expanded_names(generator.get("members")))
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=enum_identifiers,
                disposition="enum-definition",
                tag=None,
                statement=_declaration_statement(
                    generator,
                    disposition="enum-definition",
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind in {"typedef", "proto"}:
        identifier = generator.get("id")
        if not isinstance(identifier, str):
            raise ClassicSemanticError(f"{kind} declaration lacks its identifier")
        disposition = "alias-declaration" if kind == "typedef" else "function-declaration"
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition=disposition,
                tag=None,
                statement=_declaration_statement(
                    generator,
                    disposition=disposition,
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind == "extern_run":
        prefix = generator.get("prefix")
        count = generator.get("count")
        width = generator.get("width")
        if (
            not isinstance(prefix, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or count < 1
            or not 1 <= width <= 3
        ):
            raise ClassicSemanticError("source-overlay extern run is malformed")
        extern_identifiers = tuple(prefix + str(index).zfill(width) for index in range(count))
        return tuple(
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="object-declaration",
                tag=None,
                statement={
                    "disposition": "object-declaration",
                    "primary_identifier": identifier,
                    "type": "int",
                },
            )
            for identifier in extern_identifiers
        )
    if kind == "record_header":
        recipe = generator.get("typed_recipe")
        if not isinstance(recipe, dict) or not isinstance(recipe.get("items"), list):
            raise ClassicSemanticError("source-overlay record header is malformed")
        recipe_kind = recipe.get("kind")
        result: list[_DeclarationEntity] = []
        if recipe_kind == "enum_one_enumerator":
            for item in recipe["items"]:
                if not isinstance(item, dict):
                    raise ClassicSemanticError("record-header enum item is malformed")
                name = item.get("name")
                enumerator = item.get("enumerator")
                if not isinstance(name, str) or not isinstance(enumerator, str):
                    raise ClassicSemanticError("record-header enum item is malformed")
                result.append(
                    _declaration_entity(
                        primary_identifier=name,
                        introduced_identifiers=(name, enumerator),
                        disposition="enum-definition",
                        tag=None,
                        statement={
                            "disposition": "enum-definition",
                            "primary_identifier": name,
                            "members": [enumerator],
                        },
                    )
                )
        elif recipe_kind == "unused_class_with_inline_void_methods":
            methods = recipe.get("methods_per_class")
            policy = recipe.get("method_identifier_policy")
            if (
                not isinstance(methods, int)
                or isinstance(methods, bool)
                or methods < 1
                or policy not in {"single_unindexed_record", "zero_based_indexed_record"}
            ):
                raise ClassicSemanticError("record-header class recipe is malformed")
            for item in recipe["items"]:
                if not isinstance(item, str):
                    raise ClassicSemanticError("record-header class item is malformed")
                result.append(
                    _declaration_entity(
                        primary_identifier=item,
                        introduced_identifiers=(item,),
                        disposition="record-definition",
                        tag="class",
                        statement={
                            "disposition": "record-definition",
                            "primary_identifier": item,
                            "method_identifier_policy": policy,
                            "methods_per_class": methods,
                            "tag": "class",
                        },
                    )
                )
        else:
            raise ClassicSemanticError("record-header recipe kind is unsupported")
        return tuple(result)
    raise ClassicSemanticError(f"generator {kind!r} is not a declaration generator")


def _declared_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        identifier
        for entity in _declaration_entities(generator)
        for identifier in entity.introduced_identifiers
    )


def _declaration_owned_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    """Return every identifier whose spelling is owned by a declaration generator.

    Entity identifiers participate in the global origin/ODR theorem.  Member
    and parameter identifiers have narrower C++ scopes, but they remain macro
    capture surfaces and therefore belong to the compiler-namespace census.
    """

    owned = list(_declared_identifiers(generator))
    kind = generator.get("k")
    if kind == "class":
        raw_members = generator.get("members")
        if not isinstance(raw_members, list):
            raise ClassicSemanticError("class declaration member list is malformed")
        for raw_member in raw_members:
            if isinstance(raw_member, str):
                owned.append(raw_member)
            elif isinstance(raw_member, dict) and isinstance(raw_member.get("decl"), str):
                owned.append(str(raw_member["decl"]))
            elif isinstance(raw_member, dict) and isinstance(raw_member.get("id"), str):
                owned.append(str(raw_member["id"]))
            elif isinstance(raw_member, dict) and "stem" in raw_member:
                owned.extend(_expanded_names([raw_member]))
            else:
                raise ClassicSemanticError("class declaration member is malformed")
    elif kind == "proto":
        raw_parameters = generator.get("parameters")
        if not isinstance(raw_parameters, list):
            raise ClassicSemanticError("function declaration parameters are malformed")
        for raw_parameter in raw_parameters:
            if not isinstance(raw_parameter, dict):
                raise ClassicSemanticError("function declaration parameter is malformed")
            identifier = raw_parameter.get("identifier")
            if identifier is not None:
                if not isinstance(identifier, str):
                    raise ClassicSemanticError(
                        "function declaration parameter identifier is malformed"
                    )
                owned.append(identifier)
    elif kind == "record_header":
        recipe = generator.get("typed_recipe")
        if not isinstance(recipe, dict):
            raise ClassicSemanticError("record-header recipe is malformed")
        guard = recipe.get("guard")
        if not isinstance(guard, str):
            raise ClassicSemanticError("record-header guard is malformed")
        owned.append(guard)
        if recipe.get("kind") == "unused_class_with_inline_void_methods":
            methods = recipe.get("methods_per_class")
            policy = recipe.get("method_identifier_policy")
            if not isinstance(methods, int) or isinstance(methods, bool) or methods < 1:
                raise ClassicSemanticError("record-header method count is malformed")
            if policy == "single_unindexed_record":
                owned.append("Record")
            elif policy == "zero_based_indexed_record":
                owned.extend(f"Record{index}" for index in range(methods))
            else:
                raise ClassicSemanticError("record-header method policy is malformed")
    return tuple(dict.fromkeys(owned))


def _declaration_facts_compatible(left: _DeclarationFact, right: _DeclarationFact) -> bool:
    """Return whether two same-target global declarations satisfy the ODR."""

    defining = frozenset({"record-definition", "enum-definition", "enumerator-definition"})
    if (
        left.source_path.casefold() == right.source_path.casefold()
        and left.disposition in defining
        and right.disposition in defining
    ):
        return False
    if not left.targets.intersection(right.targets):
        return True
    dispositions = {left.disposition, right.disposition}
    if dispositions <= {"record-forward", "record-definition"}:
        if left.tag != right.tag:
            return False
        if left.disposition == right.disposition == "record-forward":
            return True
        if left.disposition == right.disposition == "record-definition":
            return (
                left.source_path.casefold() != right.source_path.casefold()
                and left.semantic_digest == right.semantic_digest
            )
        return True
    if left.disposition != right.disposition:
        return False
    if left.disposition in {
        "alias-declaration",
        "function-declaration",
        "object-declaration",
    }:
        return left.semantic_digest == right.semantic_digest
    if left.disposition in {"enum-definition", "enumerator-definition"}:
        return (
            left.source_path.casefold() != right.source_path.casefold()
            and left.primary_identifier == right.primary_identifier
            and left.semantic_digest == right.semantic_digest
        )
    return False


def _declaration_odr_analysis(
    facts_by_identifier: Mapping[str, Sequence[_DeclarationFact]],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    repeated = 0
    canonical_facts: list[dict[str, object]] = []
    conflicts: list[dict[str, object]] = []
    for identifier, facts in sorted(facts_by_identifier.items()):
        if len(facts) > 1:
            repeated += 1
        for index, left in enumerate(facts):
            canonical_facts.append(
                {
                    "identifier": identifier,
                    "primary_identifier": left.primary_identifier,
                    "disposition": left.disposition,
                    "tag": left.tag,
                    "semantic_digest": left.semantic_digest.model_dump(mode="json"),
                    "source_path": left.source_path,
                    "targets": sorted(left.targets, key=str.casefold),
                }
            )
            for right in facts[index + 1 :]:
                if not _declaration_facts_compatible(left, right):
                    overlap = sorted(left.targets.intersection(right.targets), key=str.casefold)
                    conflicts.append(
                        {
                            "identifier": identifier,
                            "left_source": left.source_path,
                            "right_source": right.source_path,
                            "left_disposition": left.disposition,
                            "right_disposition": right.disposition,
                            "targets": overlap,
                        }
                    )
    statement = {
        "schema": 1,
        "facts": sorted(
            canonical_facts,
            key=lambda item: (
                str(item["identifier"]).casefold(),
                str(item["source_path"]).casefold(),
                str(item["disposition"]),
                str(item["semantic_digest"]),
            ),
        ),
    }
    return (
        {
            "theorem": "target-closed-global-declaration-odr-v1",
            "fact_count": len(canonical_facts),
            "identifier_count": len(facts_by_identifier),
            "repeated_identifier_count": repeated,
            "statement_digest": Digest.from_bytes(canonical_json(statement)).model_dump(
                mode="json"
            ),
        },
        tuple(conflicts),
    )


def _odr_conflict_summary(conflicts: Sequence[Mapping[str, object]]) -> str:
    identifiers = sorted({str(item["identifier"]) for item in conflicts}, key=str.casefold)
    sources = sorted(
        {str(item[key]) for item in conflicts for key in ("left_source", "right_source")},
        key=str.casefold,
    )
    return f"pair_count={len(conflicts)}, identifiers={identifiers}, sources={sources}"


def _validate_declaration_odr(
    facts_by_identifier: Mapping[str, Sequence[_DeclarationFact]],
) -> dict[str, object]:
    trace, conflicts = _declaration_odr_analysis(facts_by_identifier)
    if conflicts:
        raise ClassicSemanticError(
            "generated global declarations violate target ODR compatibility: "
            + _odr_conflict_summary(conflicts)
        )
    return trace


def _parse_semantic_claims(
    intervention: ClassicRecipeIntervention,
) -> dict[str, _SemanticClaim]:
    values = {item.name: item.value for item in intervention.parameters}
    raw = values.get("semantic_claims")
    if not isinstance(raw, dict) or set(raw) != {"bindings", "schema"} or raw.get("schema") != 1:
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} lacks closed semantic_claims schema 1"
        )
    bindings = raw.get("bindings")
    if not isinstance(bindings, list):
        raise ClassicSemanticError(f"overlay {intervention.id!r} semantic claims are malformed")
    result: dict[str, _SemanticClaim] = {}
    order: list[tuple[str, str]] = []
    for index, item in enumerate(bindings):
        if not isinstance(item, dict):
            raise ClassicSemanticError(
                f"overlay {intervention.id!r} semantic claim {index} is malformed"
            )
        kind = item.get("kind")
        operation = item.get("operation")
        if not isinstance(operation, str) or not operation or "\x00" in operation:
            raise ClassicSemanticError("semantic claim operation identity is malformed")
        leaf = item.get("leaf")
        if not isinstance(leaf, int) or isinstance(leaf, bool) or leaf < 0:
            raise ClassicSemanticError("semantic claim leaf index is malformed")
        key = _claim_key(operation, leaf)
        if key in result:
            raise ClassicSemanticError("semantic claims repeat an operation leaf")
        if kind == "logical_header":
            if set(item) != {"kind", "leaf", "logical_path", "operation"} or not isinstance(
                item.get("logical_path"), str
            ):
                raise ClassicSemanticError("logical-header claim is malformed")
            claim: _SemanticClaim = _LogicalHeaderClaim(
                operation,
                leaf,
                _relative(str(item["logical_path"]), label="logical header claim"),
            )
        elif kind == "function_scope":
            if set(item) != {
                "bindings",
                "function",
                "kind",
                "leaf",
                "operation",
                "range_sha256",
                "range_size",
            }:
                raise ClassicSemanticError("function-scope claim is not closed")
            function = item.get("function")
            digest = item.get("range_sha256")
            size = item.get("range_size")
            raw_scalar_bindings = item.get("bindings")
            if (
                not isinstance(function, str)
                or not function
                or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                or not isinstance(raw_scalar_bindings, list)
            ):
                raise ClassicSemanticError("function-scope claim is malformed")
            scalar_bindings: list[_ScalarBinding] = []
            for raw_binding in raw_scalar_bindings:
                if not isinstance(raw_binding, dict) or set(raw_binding) != {
                    "identifier",
                    "initialized",
                    "type",
                }:
                    raise ClassicSemanticError("scalar binding claim is malformed")
                identifier = raw_binding.get("identifier")
                type_spelling = raw_binding.get("type")
                initialized = raw_binding.get("initialized")
                if (
                    not isinstance(identifier, str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier) is None
                    or not isinstance(type_spelling, str)
                    or not type_spelling
                    or not isinstance(initialized, bool)
                ):
                    raise ClassicSemanticError("scalar binding claim is malformed")
                scalar_bindings.append(_ScalarBinding(identifier, type_spelling, initialized))
            if scalar_bindings != sorted(
                scalar_bindings, key=lambda binding: binding.identifier.casefold()
            ) or len({binding.identifier.casefold() for binding in scalar_bindings}) != len(
                scalar_bindings
            ):
                raise ClassicSemanticError("scalar bindings are not canonical")
            claim = _FunctionScopeClaim(
                operation,
                leaf,
                function,
                Digest(value=str(digest)),
                size,
                tuple(scalar_bindings),
            )
        else:
            raise ClassicSemanticError(f"unknown semantic claim kind {kind!r}")
        result[key] = claim
        order.append((operation.casefold(), f"{leaf:08d}:{kind}"))
    if order != sorted(order):
        raise ClassicSemanticError("semantic claims are not canonically ordered")
    return result


def _clean_source_authority(
    bundle: ProjectBundle,
    snapshot: OverlaySemanticSnapshot,
) -> dict[str, CleanSourceInput]:
    manifest = bundle.source_manifest
    if manifest is None:
        raise ClassicSemanticError("clean source authority has no manifest")
    inputs = _unique(snapshot.clean_source_inputs, lambda item: item.path, "clean source input")
    expected = {item.path.casefold(): item for item in manifest.entries}
    if set(inputs) != set(expected):
        missing = sorted(set(expected) - set(inputs))
        extra = sorted(set(inputs) - set(expected))
        raise ClassicSemanticError(
            f"clean source input census differs; missing={missing}, extra={extra}"
        )
    for folded, value in inputs.items():
        if not isinstance(value, CleanSourceInput) or type(value.payload) is not bytes:
            raise ClassicSemanticError("clean source input is not immutable bytes")
        entry = expected[folded]
        if (
            value.path != entry.path
            or len(value.payload) != entry.size
            or Digest.from_bytes(value.payload) != entry.digest
        ):
            raise ClassicSemanticError(f"clean source input changed: {value.path!r}")
    return {folded: value for folded, value in inputs.items()}


def _token_texts(payload: bytes) -> tuple[str, ...]:
    return tuple(token for token, _start, _end in source_overlay_tokens(payload))


def _matching_token_index(
    tokens: Sequence[tuple[str, int, int]], start: int, opening: str, closing: str
) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index][0]
        if token == opening:
            depth += 1
        elif token == closing:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _function_body_range(payload: bytes, function: str) -> tuple[int, int]:
    tokens = source_overlay_tokens(payload)
    name_tokens = tuple(part for part in re.split(r"(::)", function) if part)
    if not name_tokens or any(not part for part in name_tokens):
        raise ClassicSemanticError(f"function claim has an invalid name: {function!r}")
    candidates: list[tuple[int, int]] = []
    for index in range(len(tokens) - len(name_tokens)):
        if tuple(item[0] for item in tokens[index : index + len(name_tokens)]) != name_tokens:
            continue
        opening_paren = index + len(name_tokens)
        if opening_paren >= len(tokens) or tokens[opening_paren][0] != "(":
            continue
        closing_paren = _matching_token_index(tokens, opening_paren, "(", ")")
        if closing_paren is None:
            continue
        opening_brace: int | None = None
        cursor = closing_paren + 1
        while cursor < len(tokens) and tokens[cursor][0] not in {";", "{"}:
            cursor += 1
        if cursor < len(tokens) and tokens[cursor][0] == "{":
            opening_brace = cursor
        if opening_brace is None:
            continue
        closing_brace = _matching_token_index(tokens, opening_brace, "{", "}")
        if closing_brace is None:
            raise ClassicSemanticError(f"function {function!r} has unbalanced braces")
        candidates.append((tokens[opening_brace][1], tokens[closing_brace][2]))
    if len(candidates) != 1:
        raise ClassicSemanticError(
            f"function claim {function!r} resolves {len(candidates)} definitions"
        )
    return candidates[0]


def _validate_function_claim(
    *,
    claim: _FunctionScopeClaim,
    payload: bytes,
    anchor_offsets: Sequence[int],
) -> tuple[int, int]:
    start, end = _function_body_range(payload, claim.function)
    selected = payload[start:end]
    if len(selected) != claim.range_size or Digest.from_bytes(selected) != claim.range_digest:
        raise ClassicSemanticError(f"function claim range changed for {claim.function!r}")
    if not anchor_offsets or any(offset < start or offset > end for offset in anchor_offsets):
        raise ClassicSemanticError(
            f"operation {claim.operation_id!r} is outside function {claim.function!r}"
        )
    return start, end


def _type_tokens(type_spelling: str) -> tuple[str, ...]:
    try:
        encoded = type_spelling.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ClassicSemanticError("scalar type spelling is not ASCII") from exc
    tokens = _token_texts(encoded)
    if not tokens or any(token in {";", "{", "}"} for token in tokens):
        raise ClassicSemanticError("scalar type spelling is malformed")
    return tokens


def _typedef_underlyings(
    clean_sources: Mapping[str, CleanSourceInput], alias: str
) -> set[tuple[str, ...]]:
    results: set[tuple[str, ...]] = set()
    for source in clean_sources.values():
        tokens = source_overlay_tokens(source.payload)
        for index, (token, _start, _end) in enumerate(tokens):
            if token != alias:
                continue
            left = index - 1
            while left >= 0 and tokens[left][0] not in {";", "{", "}"}:
                left -= 1
            right = index + 1
            while right < len(tokens) and tokens[right][0] != ";":
                if tokens[right][0] in {"{", "}"}:
                    break
                right += 1
            statement = tuple(item[0] for item in tokens[left + 1 : right])
            typedef_index = max(
                (offset for offset, item in enumerate(statement) if item == "typedef"),
                default=-1,
            )
            if typedef_index >= 0 and statement[-1] == alias:
                underlying = statement[typedef_index + 1 : -1]
                if underlying and all(token not in {"(", ")", "[", "]"} for token in underlying):
                    results.add(underlying)
            using_index = max(
                (offset for offset, item in enumerate(statement) if item == "using"),
                default=-1,
            )
            if statement[using_index : using_index + 3] == ("using", alias, "="):
                results.add(statement[using_index + 3 :])
    return results


def _is_nonvolatile_integral_type(
    type_spelling: str,
    clean_sources: Mapping[str, CleanSourceInput],
    *,
    seen: frozenset[str] = frozenset(),
) -> bool:
    tokens = tuple(token for token in _type_tokens(type_spelling) if token != "const")
    if "volatile" in tokens or any(token in {"*", "&", "[", "]"} for token in tokens):
        return False
    if tokens and set(tokens) <= _INTEGRAL_TYPE_TOKENS:
        return True
    if len(tokens) != 1 or tokens[0] in seen:
        return False
    alias = tokens[0]
    underlyings = _typedef_underlyings(clean_sources, alias)
    return bool(underlyings) and all(
        _is_nonvolatile_integral_type(" ".join(underlying), clean_sources, seen=seen | {alias})
        for underlying in underlyings
    )


def _validate_scalar_binding(
    *,
    claim: _ScalarBinding,
    payload: bytes,
    function_range: tuple[int, int],
    before_offset: int,
    clean_sources: Mapping[str, CleanSourceInput],
) -> None:
    if not _is_nonvolatile_integral_type(claim.type_spelling, clean_sources):
        raise ClassicSemanticError(
            f"scalar binding {claim.identifier!r} is not a proven integral type"
        )
    tokens = source_overlay_tokens(payload)
    type_tokens = _type_tokens(claim.type_spelling)
    candidates = 0
    for index, (token, start, _end) in enumerate(tokens):
        if token != claim.identifier or not (
            function_range[0] < start < min(function_range[1], before_offset)
        ):
            continue
        left = index - 1
        while left >= 0 and tokens[left][0] not in {";", "{", "}"}:
            left -= 1
        right = index + 1
        while right < len(tokens) and tokens[right][0] not in {";", "{", "}"}:
            right += 1
        statement = tuple(item[0] for item in tokens[left + 1 : right])
        prefix = statement[: statement.index(claim.identifier)]
        if not any(
            prefix[offset : offset + len(type_tokens)] == type_tokens
            for offset in range(len(prefix) - len(type_tokens) + 1)
        ):
            continue
        if "volatile" in statement:
            continue
        suffix = statement[statement.index(claim.identifier) + 1 :]
        initialized = "=" in suffix
        if initialized != claim.initialized:
            continue
        candidates += 1
    if candidates != 1:
        raise ClassicSemanticError(
            f"scalar binding {claim.identifier!r} resolves {candidates} declarations"
        )


def _compiler_include_roots(node: ProducerNode) -> tuple[str, ...]:
    roots: list[str] = []
    arguments = node.arguments
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        value: str | None = None
        folded = argument.casefold()
        if folded in {"-i", "/i"} and index + 1 < len(arguments):
            index += 1
            value = arguments[index]
        elif folded.startswith("-i") or folded.startswith("/i"):
            value = argument[2:]
        if value is not None and value.startswith("${SOURCE}/"):
            roots.append(_relative(value.removeprefix("${SOURCE}/"), label="include root"))
        index += 1
    return tuple(roots)


def _resolve_logical_header(
    *,
    source_path: str,
    header: str,
    style: object,
    compiler_nodes: Sequence[ProducerNode],
    authority_paths: Mapping[str, str],
) -> str:
    candidates: set[str] = set()
    for node in compiler_nodes:
        search_roots: list[str] = []
        if style == "quote":
            parent = PurePosixPath(source_path).parent.as_posix()
            if parent != ".":
                search_roots.append(parent)
        elif style != "angle":
            raise ClassicSemanticError("include style is outside the closed enum")
        search_roots.extend(_compiler_include_roots(node))
        resolved: str | None = None
        for root in search_roots:
            candidate = PurePosixPath(root, header).as_posix()
            actual = authority_paths.get(candidate.casefold())
            if actual is not None:
                resolved = actual
                break
        if resolved is None:
            raise ClassicSemanticError(
                f"include {header!r} from {source_path!r} has no admitted resolution"
            )
        candidates.add(resolved)
    if len(candidates) != 1:
        raise ClassicSemanticError(
            f"include {header!r} from {source_path!r} resolves inconsistently"
        )
    return next(iter(candidates))


def _runtime_projection(
    coff: _CoffObject, *, excluded_sections: frozenset[int] = frozenset()
) -> dict[str, object]:
    runtime_sections = [
        section
        for section in coff.sections
        if not section.name.casefold().startswith(".debug")
        and section.number not in excluded_sections
    ]
    section_map = {section.number: index + 1 for index, section in enumerate(runtime_sections)}
    sections: list[dict[str, object]] = []
    for section in runtime_sections:
        associated = section.comdat_associated
        if associated and associated not in section_map:
            raise ClassicSemanticError(
                f"{coff.label} runtime section associates with omitted debug state"
            )
        relocations: list[dict[str, object]] = []
        for relocation in section.relocations:
            target_section = relocation.target_section
            if target_section > 0:
                if target_section not in section_map:
                    raise ClassicSemanticError(
                        f"{coff.label} runtime relocation targets debug state"
                    )
                target_section = section_map[target_section]
            relocations.append(
                {
                    "offset": relocation.offset,
                    "type": relocation.relocation_type,
                    "target": relocation.target,
                    "target_section": target_section,
                    "target_value": relocation.target_value,
                    "target_type": relocation.target_type,
                    "target_storage": relocation.target_storage,
                    "addend": relocation.addend.hex(),
                }
            )
        line_numbers: list[dict[str, object]] = []
        for line in section.line_numbers:
            if line.line_number:
                line_numbers.append(
                    {
                        "line": line.line_number,
                        "address": line.address,
                    }
                )
                continue
            line_target_section = line.target_section
            if line_target_section is not None and line_target_section > 0:
                if line_target_section not in section_map:
                    raise ClassicSemanticError(
                        f"{coff.label} runtime line table targets debug state"
                    )
                line_target_section = section_map[line_target_section]
            line_numbers.append(
                {
                    "line": 0,
                    "target": line.target,
                    "target_section": line_target_section,
                    "target_value": line.target_value,
                    "target_type": line.target_type,
                    "target_storage": line.target_storage,
                }
            )
        sections.append(
            {
                "name": section.name,
                "body": section.body.hex(),
                "characteristics": section.characteristics,
                "selection": section.comdat_selection,
                "associated": section_map.get(associated) if associated else None,
                "relocations": relocations,
                "line_numbers": line_numbers,
            }
        )
    referenced_undefined = {
        relocation.target
        for section in runtime_sections
        for relocation in section.relocations
        if relocation.target_section == 0
    }
    symbols = [
        {
            "name": symbol.name,
            "value": symbol.value,
            "section": section_map.get(symbol.section, symbol.section),
            "type": symbol.symbol_type,
            "storage": symbol.storage,
        }
        for symbol in coff.symbols
        if symbol.section < 0
        or (symbol.section == 0 and symbol.name in referenced_undefined)
        or (symbol.section in section_map and symbol.section not in excluded_sections)
    ]
    return {"sections": sections, "symbols": symbols}


_CODE_SECTION_PREFIXES = (".text",)
_COMPILER_CONTROL_SECTION_PREFIXES = (".pdata", ".xdata")
_INITIALIZED_DATA_SECTION_PREFIXES = (".data", ".rdata")
_UNINITIALIZED_DATA_SECTION_PREFIXES = (".bss",)
_RELOCATION_WIDTHS = MappingProxyType({6: 4, 7: 4, 10: 2, 11: 4, 20: 4})
_IA32_DIRECTION_EQUIVALENTS = MappingProxyType(
    {
        0x03: 0x01,  # ADD r32,r/m32 <-> ADD r/m32,r32
        0x0B: 0x09,  # OR
        0x13: 0x11,  # ADC
        0x1B: 0x19,  # SBB
        0x23: 0x21,  # AND
        0x2B: 0x29,  # SUB
        0x33: 0x31,  # XOR
        0x3B: 0x39,  # CMP
        0x8B: 0x89,  # MOV
    }
)


def _is_section_symbol(symbol: _CoffSymbol, section: _CoffSection) -> bool:
    return (
        symbol.storage == 3
        and symbol.name == section.name
        and symbol.value == 0
        and bool(symbol.auxiliary_count)
    )


def _symbols_by_section(coff: _CoffObject) -> dict[int, tuple[_CoffSymbol, ...]]:
    result: dict[int, list[_CoffSymbol]] = defaultdict(list)
    for symbol in coff.symbols:
        if symbol.section > 0:
            if symbol.section > len(coff.sections):
                raise ClassicSemanticError(
                    f"{coff.label} symbol {symbol.name!r} has an invalid section"
                )
            result[symbol.section].append(symbol)
    return {
        number: tuple(
            sorted(
                values,
                key=lambda item: (
                    item.name,
                    item.value,
                    item.symbol_type,
                    item.storage,
                ),
            )
        )
        for number, values in result.items()
    }


def _section_owner_statement(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> list[dict[str, object]]:
    return [
        {
            "name": symbol.name,
            "type": symbol.symbol_type,
            "storage": symbol.storage,
        }
        for symbol in symbols.get(section.number, ())
        if not _is_section_symbol(symbol, section)
    ]


def _association_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    associated = section.comdat_associated
    if not associated:
        return None
    if not 0 < associated <= len(coff.sections):
        raise ClassicSemanticError(
            f"{coff.label} section {section.name!r} has an invalid COMDAT association"
        )
    target = coff.sections[associated - 1]
    return {
        "name": target.name,
        "selection": target.comdat_selection,
        "owners": _section_owner_statement(target, symbols),
    }


def _section_topology_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    return {
        "name": section.name,
        "characteristics": section.characteristics,
        "selection": section.comdat_selection,
        "association": _association_statement(coff, section, symbols),
        "owners": _section_owner_statement(section, symbols),
    }


def _preliminary_section_identity(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    folded = section.name.casefold()
    topology = _section_topology_statement(coff, section, symbols)
    if folded.startswith(_CODE_SECTION_PREFIXES):
        return {"kind": "code", "topology": topology}
    if folded.startswith(_COMPILER_CONTROL_SECTION_PREFIXES):
        return {"kind": "compiler-control", "topology": topology}
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS.get(relocation.relocation_type)
        if width is None or relocation.offset + width > len(masked):
            raise ClassicSemanticError(
                f"{coff.label} section {section.name!r} has an invalid relocation field"
            )
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    return {
        "kind": "data",
        "topology": topology,
        "masked_body": bytes(masked).hex(),
    }


def _relocation_target_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    if relocation.target_section == 0:
        kind = (
            "weak"
            if relocation.target_storage == 105
            else "common"
            if relocation.target_storage == 2 and relocation.target_value > 0
            else "undefined"
        )
        return {
            "kind": kind,
            "name": relocation.target,
            "value": relocation.target_value,
            "type": relocation.target_type,
            "storage": relocation.target_storage,
        }
    if not 0 < relocation.target_section <= len(coff.sections):
        raise ClassicSemanticError(f"{coff.label} relocation target has an invalid section")
    target = coff.sections[relocation.target_section - 1]
    statement: dict[str, object] = {
        "kind": "defined",
        "symbol": {
            "name": relocation.target,
            "type": relocation.target_type,
            "storage": relocation.target_storage,
            "section_symbol": (relocation.target_storage == 3 and relocation.target == target.name),
        },
        "section": _preliminary_section_identity(coff, target, symbols),
    }
    if not target.name.casefold().startswith(_CODE_SECTION_PREFIXES):
        # Named code owners may move when a preceding function is re-encoded;
        # data/control offsets select object state and must remain exact.
        target_symbol = statement["symbol"]
        assert isinstance(target_symbol, dict)
        target_symbol["value"] = relocation.target_value
    return statement


def _relocation_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
    *,
    include_offset: bool,
) -> dict[str, object]:
    result: dict[str, object] = {
        "type": relocation.relocation_type,
        "target": _relocation_target_statement(coff, relocation, symbols),
        "addend": relocation.addend.hex(),
    }
    if include_offset:
        result["offset"] = relocation.offset
    return result


def _canonical_multiset(values: Sequence[object]) -> list[dict[str, object]]:
    counts: dict[bytes, int] = defaultdict(int)
    for value in values:
        counts[canonical_json(value)] += 1
    return [
        {
            "value": Digest.from_bytes(encoded).model_dump(mode="json"),
            "count": count,
        }
        for encoded, count in sorted(counts.items())
    ]


def _canonical_ia32_instruction(encoded: bytes) -> str:
    """Normalize only proven direction-bit register/register encodings."""

    result = bytearray(encoded)
    opcode_index = 0
    while opcode_index < len(result) and result[opcode_index] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        opcode_index += 1
    if opcode_index + 1 >= len(result):
        return result.hex()
    canonical_opcode = _IA32_DIRECTION_EQUIVALENTS.get(result[opcode_index])
    if canonical_opcode is None:
        return result.hex()
    modrm_index = opcode_index + 1
    modrm = result[modrm_index]
    if modrm >> 6 != 3:
        # Swapping a register with a memory operand is not the same operation.
        return result.hex()
    result[opcode_index] = canonical_opcode
    result[modrm_index] = (modrm & 0xC0) | ((modrm & 0x07) << 3) | ((modrm >> 3) & 0x07)
    return result.hex()


def _semantic_code_stream(
    coff: _CoffObject, section: _CoffSection
) -> tuple[list[str], tuple[tuple[int, int], ...]]:
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS[relocation.relocation_type]
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    result: list[str] = []
    boundaries: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(masked):
        try:
            length = supported_ia32_instruction_length(
                bytes(masked[cursor:]),
                f"{coff.label} section {section.name!r} at {cursor}",
            )
        except ByteIdentityError as exc:
            raise ClassicSemanticError(
                f"{coff.label} code section has no closed IA-32 partition"
            ) from exc
        if length <= 0 or cursor + length > len(masked):
            raise ClassicSemanticError(f"{coff.label} code section has an invalid IA-32 partition")
        result.append(_canonical_ia32_instruction(bytes(masked[cursor : cursor + length])))
        boundaries.append((cursor, cursor + length))
        cursor += length
    return result, tuple(boundaries)


def _weak_external_statement(coff: _CoffObject, symbol: _CoffSymbol) -> object:
    if (
        symbol.section != 0
        or symbol.value != 0
        or symbol.auxiliary_count != 1
        or (len(symbol.auxiliary) != 18)
    ):
        raise ClassicSemanticError(f"{coff.label} weak external {symbol.name!r} is malformed")
    tag_index, characteristics = struct.unpack_from("<II", symbol.auxiliary)
    by_index = {item.index: item for item in coff.symbols}
    fallback = by_index.get(tag_index)
    if fallback is None or fallback.storage not in {2, 105}:
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has an invalid fallback"
        )
    if any(symbol.auxiliary[8:]):
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has unknown auxiliary state"
        )
    return {
        "name": symbol.name,
        "fallback": fallback.name,
        "characteristics": characteristics,
        "type": symbol.symbol_type,
    }


def _linkage_statement(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int],
) -> dict[str, object]:
    symbols = _symbols_by_section(coff)
    definitions: list[dict[str, object]] = []
    undefineds: list[dict[str, object]] = []
    commons: list[dict[str, object]] = []
    weaks: list[object] = []
    absolute: list[dict[str, object]] = []
    for symbol in coff.symbols:
        if symbol.storage == 105:
            weaks.append(_weak_external_statement(coff, symbol))
            continue
        if symbol.storage != 2:
            continue
        if symbol.section > 0:
            if symbol.section in excluded_sections:
                continue
            section = coff.sections[symbol.section - 1]
            definitions.append(
                {
                    "name": symbol.name,
                    "type": symbol.symbol_type,
                    "section": _section_topology_statement(coff, section, symbols),
                }
            )
        elif symbol.section == 0 and symbol.value > 0:
            commons.append(
                {
                    "name": symbol.name,
                    "size": symbol.value,
                    "type": symbol.symbol_type,
                }
            )
        elif symbol.section == 0:
            undefineds.append(
                {
                    "name": symbol.name,
                    "type": symbol.symbol_type,
                }
            )
        elif symbol.section < 0:
            absolute.append(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "section": symbol.section,
                    "type": symbol.symbol_type,
                }
            )
    relocation_dependencies = sorted(
        {
            relocation.target
            for section in coff.sections
            if section.number not in excluded_sections
            for relocation in section.relocations
            if relocation.target_section == 0
            and relocation.target_storage in {2, 105}
            and not (relocation.target_storage == 2 and relocation.target_value > 0)
        }
    )
    return {
        "definitions": sorted(definitions, key=lambda item: str(item["name"])),
        "undefineds": sorted(undefineds, key=lambda item: canonical_json(item)),
        "relocation_dependencies": relocation_dependencies,
        "commons": sorted(commons, key=lambda item: str(item["name"])),
        "weaks": sorted(weaks, key=lambda item: canonical_json(item)),
        "absolutes": sorted(absolute, key=lambda item: str(item["name"])),
    }


def classic_link_relevant_coff_projection(
    payload: bytes,
    *,
    label: str,
) -> ClassicLinkRelevantCoffProjection:
    """Return the exact non-debug linker view of one strict i386 COFF object.

    This is a diagnostic correspondence primitive, not a source-semantics
    proof.  Equality establishes that the linker receives the same ordinary
    COFF state after explicitly documented debug/timestamp normalization; it
    cannot establish that two source programs have the same behavior.
    """

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable COFF bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("COFF projection label is malformed")
    coff = _parse_coff(payload, label)
    excluded_sections = frozenset(
        section.number
        for section in coff.sections
        if section.name.casefold().startswith(".debug")
    )
    runtime = _runtime_projection(coff)
    directives = _coff_directive_receipt(coff)
    statement: dict[str, object] = {
        "schema": 1,
        "kind": "classic-coff-link-relevant-projection",
        "coff_header": {
            "machine": "i386",
            "characteristics": coff.header_characteristics,
        },
        # `_runtime_projection` retains original relative section order and
        # exact bodies/relocations while renumbering only across omitted debug
        # sections.  Its broader local-symbol view is intentionally not used:
        # all external linkage is closed below and every referenced local
        # symbol is already bound by the exact relocation statement.
        "sections": runtime["sections"],
        "linkage": _linkage_statement(coff, excluded_sections=excluded_sections),
        "directives": {
            "tokens": list(directives.tokens),
            "default_libraries": list(directives.default_libraries),
            "include_symbols": list(directives.include_symbols),
            "export_symbols": list(directives.export_symbols),
            "merge_sections": [list(item) for item in directives.merge_sections],
            "disallowed_libraries": list(directives.disallowed_libraries),
        },
    }
    return ClassicLinkRelevantCoffProjection(
        object_digest=coff.digest,
        projection_digest=Digest.from_bytes(canonical_json(statement)),
        statement=statement,
        excluded_section_names=tuple(
            section.name for section in coff.sections if section.number in excluded_sections
        ),
    )


def _coff_line_number_invariant_projection(
    projection: ClassicLinkRelevantCoffProjection,
) -> tuple[dict[str, object], tuple[tuple[int, str, int, int, int], ...]]:
    """Copy a strict projection while replacing only ordinary line values."""

    statement = dict(projection.statement)
    raw_sections = statement.get("sections")
    if not isinstance(raw_sections, list):
        raise AssertionError("strict COFF projection has no section list")
    sections: list[dict[str, object]] = []
    values: list[tuple[int, str, int, int, int]] = []
    for section_index, raw_section in enumerate(raw_sections, start=1):
        if not isinstance(raw_section, dict):
            raise AssertionError("strict COFF projection section is malformed")
        section = dict(raw_section)
        section_name = section.get("name")
        raw_lines = section.get("line_numbers")
        if not isinstance(section_name, str) or not isinstance(raw_lines, list):
            raise AssertionError("strict COFF projection line table is malformed")
        line_numbers: list[dict[str, object]] = []
        for record_index, raw_line in enumerate(raw_lines):
            if not isinstance(raw_line, dict):
                raise AssertionError("strict COFF projection line record is malformed")
            line = dict(raw_line)
            line_number = line.get("line")
            if (
                not isinstance(line_number, int)
                or isinstance(line_number, bool)
                or not 0 <= line_number <= 0xFFFF
            ):
                raise AssertionError("strict COFF projection line value is malformed")
            if line_number:
                address = line.get("address")
                if set(line) != {"address", "line"} or not isinstance(address, int) or isinstance(
                    address, bool
                ):
                    raise AssertionError("ordinary COFF line record is malformed")
                values.append(
                    (section_index, section_name, record_index, address, line_number)
                )
                line["line"] = "ordinary-coff-line-number-value"
            elif set(line) != {
                "line",
                "target",
                "target_section",
                "target_storage",
                "target_type",
                "target_value",
            }:
                raise AssertionError("COFF function line record is malformed")
            line_numbers.append(line)
        section["line_numbers"] = line_numbers
        sections.append(section)
    statement["sections"] = sections
    return statement, tuple(values)


def _coff_retained_symbol_records(coff: _CoffObject) -> list[dict[str, object]]:
    """Bind every non-debug symbol record beyond the public linker projection."""

    retained_sections = [
        section
        for section in coff.sections
        if not section.name.casefold().startswith(".debug")
    ]
    section_map = {
        section.number: index + 1 for index, section in enumerate(retained_sections)
    }
    return [
        {
            "name": symbol.name,
            "value": symbol.value,
            "section": section_map.get(symbol.section, symbol.section),
            "type": symbol.symbol_type,
            "storage": symbol.storage,
            "auxiliary_count": symbol.auxiliary_count,
            "auxiliary": symbol.auxiliary.hex(),
        }
        for symbol in coff.symbols
        if symbol.section <= 0 or symbol.section in section_map
    ]


def prove_classic_coff_line_number_correspondence(
    baseline: bytes,
    candidate: bytes,
    *,
    baseline_label: str,
    candidate_label: str,
) -> ClassicCoffLineNumberCorrespondence:
    """Prove strict COFF equality modulo ordinary source-line values only.

    Timestamp, whole ``.debug*`` state, and an external PDB are normalized by
    :func:`classic_link_relevant_coff_projection`.  Within every retained
    section, this theorem additionally permits only the nonzero 16-bit source
    line value in a COFF line-table row to change.  In particular, it binds
    every row address and zero-line function-symbol target exactly.

    This receipt is not independently a source-semantics proof.  A caller must
    pair it with a closed source theorem, such as the complete-census fresh and
    unused ``typedef int`` theorem issued by the project-overlay validator.
    """

    baseline_projection = classic_link_relevant_coff_projection(
        baseline, label=baseline_label
    )
    candidate_projection = classic_link_relevant_coff_projection(
        candidate, label=candidate_label
    )
    baseline_coff = _parse_coff(baseline, baseline_label)
    candidate_coff = _parse_coff(candidate, candidate_label)
    baseline_invariant, baseline_values = _coff_line_number_invariant_projection(
        baseline_projection
    )
    candidate_invariant, candidate_values = _coff_line_number_invariant_projection(
        candidate_projection
    )
    # The public projection deliberately excludes unreferenced local symbols.
    # This narrower theorem is stronger: aside from symbols owned by normalized
    # debug sections, every primary symbol record and auxiliary payload is exact.
    baseline_invariant["retained_symbol_records"] = _coff_retained_symbol_records(
        baseline_coff
    )
    candidate_invariant["retained_symbol_records"] = _coff_retained_symbol_records(
        candidate_coff
    )
    if baseline_invariant != candidate_invariant:
        raise ClassicSemanticError(
            f"{candidate_label} differs from {baseline_label} outside ordinary "
            "COFF line-number metadata values"
        )
    if len(baseline_values) != len(candidate_values):
        raise AssertionError("equal line-number invariants have unequal ordinary rows")
    deltas: list[ClassicCoffLineNumberDelta] = []
    for baseline_value, candidate_value in zip(
        baseline_values, candidate_values, strict=True
    ):
        if baseline_value[:4] != candidate_value[:4]:
            raise AssertionError("equal line-number invariants have unequal row identities")
        if baseline_value[4] == candidate_value[4]:
            continue
        deltas.append(
            ClassicCoffLineNumberDelta(
                section_index=baseline_value[0],
                section_name=baseline_value[1],
                record_index=baseline_value[2],
                address=baseline_value[3],
                baseline_line=baseline_value[4],
                candidate_line=candidate_value[4],
            )
        )
    invariant_digest = Digest.from_bytes(canonical_json(baseline_invariant))
    statement: dict[str, object] = {
        "schema": 1,
        "kind": "classic-coff-line-number-correspondence",
        "baseline_object": {
            "digest": baseline_projection.object_digest.model_dump(mode="json"),
            "size": len(baseline),
        },
        "candidate_object": {
            "digest": candidate_projection.object_digest.model_dump(mode="json"),
            "size": len(candidate),
        },
        "strict_projections": {
            "baseline_digest": baseline_projection.projection_digest.model_dump(mode="json"),
            "candidate_digest": candidate_projection.projection_digest.model_dump(mode="json"),
            "shared_invariant_digest": invariant_digest.model_dump(mode="json"),
        },
        "inherited_normalizations": list(baseline_projection.normalizations),
        "excluded_debug_sections": {
            "baseline": list(baseline_projection.excluded_section_names),
            "candidate": list(candidate_projection.excluded_section_names),
        },
        "allowed_delta": "retained-section-ordinary-coff-line-number-value",
        "line_number_deltas": [
            {
                "section_index": delta.section_index,
                "section_name": delta.section_name,
                "record_index": delta.record_index,
                "address": delta.address,
                "baseline_line": delta.baseline_line,
                "candidate_line": delta.candidate_line,
            }
            for delta in deltas
        ],
    }
    statement_digest = Digest.from_bytes(canonical_json(statement))
    return ClassicCoffLineNumberCorrespondence(
        baseline_object_digest=baseline_projection.object_digest,
        baseline_size=len(baseline),
        candidate_object_digest=candidate_projection.object_digest,
        candidate_size=len(candidate),
        baseline_projection_digest=baseline_projection.projection_digest,
        candidate_projection_digest=candidate_projection.projection_digest,
        invariant_projection_digest=invariant_digest,
        line_number_deltas=tuple(deltas),
        statement_digest=statement_digest,
        statement=MappingProxyType(statement),
    )


def _coff_semantic_envelope(
    coff: _CoffObject, *, excluded_sections: frozenset[int] = frozenset()
) -> dict[str, object]:
    symbols = _symbols_by_section(coff)
    topology: list[object] = []
    code_relocations: list[object] = []
    initialized_data: list[object] = []
    uninitialized_data: list[object] = []
    compiler_control: list[object] = []
    runtime_roots: list[object] = []
    code_bodies: list[tuple[bytes, int]] = []
    for section in coff.sections:
        if section.number in excluded_sections or section.name.casefold().startswith(".debug"):
            continue
        folded = section.name.casefold()
        section_topology = _section_topology_statement(coff, section, symbols)
        if folded == ".drectve":
            topology.append(section_topology)
            continue
        topology.append(section_topology)
        relocations = [
            _relocation_statement(
                coff,
                item,
                symbols,
                include_offset=not folded.startswith(_CODE_SECTION_PREFIXES),
            )
            for item in section.relocations
        ]
        if folded.startswith(_FORBIDDEN_RUNTIME_SECTION_PREFIXES):
            runtime_roots.append(
                {
                    "topology": section_topology,
                    "body": section.body.hex(),
                    "relocations": relocations,
                }
            )
        elif folded.startswith(_CODE_SECTION_PREFIXES):
            if not section_topology["owners"]:
                raise ClassicSemanticError(f"{coff.label} code section has no closed symbol owner")
            instruction_stream, instruction_boundaries = _semantic_code_stream(coff, section)
            seated_relocations: list[dict[str, object]] = []
            for relocation, statement in zip(section.relocations, relocations, strict=True):
                width = _RELOCATION_WIDTHS[relocation.relocation_type]
                seats = [
                    (index, start)
                    for index, (start, end) in enumerate(instruction_boundaries)
                    if start <= relocation.offset and relocation.offset + width <= end
                ]
                if len(seats) != 1:
                    raise ClassicSemanticError(
                        f"{coff.label} code relocation has no unique instruction seat"
                    )
                instruction_index, instruction_start = seats[0]
                seated_relocations.append(
                    {
                        **statement,
                        "instruction_index": instruction_index,
                        "field_offset": relocation.offset - instruction_start,
                    }
                )
            code_relocations.append(
                {
                    "section": section_topology,
                    "instruction_stream": instruction_stream,
                    "relocations": _canonical_multiset(seated_relocations),
                }
            )
            code_bodies.append((section.body, section.number))
        elif folded.startswith(_INITIALIZED_DATA_SECTION_PREFIXES):
            masked = bytearray(section.body)
            for relocation in section.relocations:
                width = _RELOCATION_WIDTHS[relocation.relocation_type]
                masked[relocation.offset : relocation.offset + width] = bytes(width)
            initialized_data.append(
                {
                    "section": section_topology,
                    "masked_body": bytes(masked).hex(),
                    "relocations": relocations,
                }
            )
        elif folded.startswith(_UNINITIALIZED_DATA_SECTION_PREFIXES):
            uninitialized_data.append(
                {
                    "section": section_topology,
                    "size": len(section.body),
                    "relocations": relocations,
                }
            )
        elif folded.startswith(_COMPILER_CONTROL_SECTION_PREFIXES):
            compiler_control.append(
                {
                    "section": section_topology,
                    # Procedure/unwind byte offsets are compiler layout state;
                    # their link targets and COMDAT parent remain semantic.
                    "relocations": _canonical_multiset(relocations),
                }
            )
        else:
            raise ClassicSemanticError(
                f"{coff.label} contains unknown runtime section {section.name!r}"
            )
    directives = _coff_directive_receipt(coff)
    statement = {
        "linkage": _linkage_statement(coff, excluded_sections=excluded_sections),
        "directives": {
            "tokens": list(directives.tokens),
            "default_libraries": list(directives.default_libraries),
            "include_symbols": list(directives.include_symbols),
            "export_symbols": list(directives.export_symbols),
            "merge_sections": [list(item) for item in directives.merge_sections],
            "disallowed_libraries": list(directives.disallowed_libraries),
        },
        "topology": _canonical_multiset(topology),
        "code_relocations": _canonical_multiset(code_relocations),
        "initialized_data": _canonical_multiset(initialized_data),
        "uninitialized_data": _canonical_multiset(uninitialized_data),
        "compiler_control": _canonical_multiset(compiler_control),
        "runtime_roots": _canonical_multiset(runtime_roots),
    }
    return {
        "statement": statement,
        "digest": Digest.from_bytes(canonical_json(statement)),
        "code_bodies": tuple(code_bodies),
    }


def _coff_compiler_congruence_trace(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> dict[str, object]:
    clean_envelope = _coff_semantic_envelope(clean)
    effective_envelope = _coff_semantic_envelope(
        effective, excluded_sections=excluded_effective_sections
    )
    if clean_envelope["statement"] != effective_envelope["statement"]:
        clean_statement = clean_envelope["statement"]
        effective_statement = effective_envelope["statement"]
        assert isinstance(clean_statement, dict)
        assert isinstance(effective_statement, dict)
        changed = sorted(
            key for key in clean_statement if clean_statement[key] != effective_statement[key]
        )
        raise ClassicSemanticError(
            f"{effective.label} changes the closed COFF semantic envelope: {changed}"
        )
    clean_code = clean_envelope["code_bodies"]
    effective_code = effective_envelope["code_bodies"]
    assert isinstance(clean_code, tuple)
    assert isinstance(effective_code, tuple)
    changed_code_sections = sum(
        1
        for (clean_body, _), (effective_body, _) in zip(clean_code, effective_code, strict=False)
        if clean_body != effective_body
    ) + abs(len(clean_code) - len(effective_code))
    digest = clean_envelope["digest"]
    assert isinstance(digest, Digest)
    return {
        "theorem": "closed-source-compiler-congruence-coff-envelope-v1",
        "semantic_envelope_digest": digest.model_dump(mode="json"),
        "changed_code_section_count": changed_code_sections,
        "allowed_deltas": [
            "proven-direction-bit-register-code-encoding",
            "code-relocation-seat-preserving-offset",
            "runtime-section-seat-and-order",
            "compiler-control-layout-bytes-with-fixed-relocation-seats",
        ],
        "preserved": [
            "exports-and-linker-directives",
            "external-common-weak-and-absolute-linkage",
            "undefined-dependency-set",
            "comdat-selection-and-association",
            "relocation-target-type-addend-semantics",
            "relocation-aware-initialized-data",
            "uninitialized-data-size",
            "startup-crt-tls-and-runtime-root-sections",
        ],
    }


def _brace_depth_at(payload: bytes, offset: int) -> int:
    depth = 0
    for token, start, _end in source_overlay_tokens(payload):
        if start >= offset:
            break
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth < 0:
                raise ClassicSemanticError("clean source has unbalanced braces")
    return depth


def _source_neighbors(payload: bytes, offset: int) -> tuple[str | None, str | None, int, int]:
    """Return significant neighbors and expression nesting at a byte boundary."""

    tokens = source_overlay_tokens(payload)
    previous: str | None = None
    following: str | None = None
    parenthesis_depth = 0
    bracket_depth = 0
    for token, start, end in tokens:
        if start < offset < end:
            raise ClassicSemanticError("source-overlay seat splits a significant token")
        if end <= offset:
            previous = token
            if token == "(":
                parenthesis_depth += 1
            elif token == ")":
                parenthesis_depth -= 1
            elif token == "[":
                bracket_depth += 1
            elif token == "]":
                bracket_depth -= 1
            if parenthesis_depth < 0 or bracket_depth < 0:
                raise ClassicSemanticError("source-overlay seat has unbalanced delimiters")
            continue
        following = token
        break
    return previous, following, parenthesis_depth, bracket_depth


def _previous_physical_line_is_directive(payload: bytes, offset: int) -> bool:
    line_start = payload.rfind(b"\n", 0, offset) + 1
    if payload[line_start:offset].strip():
        return False
    end = line_start - 1
    while end >= 0:
        start = payload.rfind(b"\n", 0, end) + 1
        raw_line = payload[start:end].removesuffix(b"\r")
        line = raw_line.strip()
        if line:
            return line.startswith(b"#") and not _contains_physical_line_splice((raw_line,))
        end = start - 1
    return False


def _previous_significant_physical_line(
    payload: bytes, offset: int
) -> tuple[tuple[str, ...], tuple[bytes, ...]]:
    """Return the nearest earlier token-bearing physical line.

    Comments and blank lines have no source-overlay tokens, so this remains a
    lexical query instead of growing a second comment parser.  The raw line is
    retained to reject phase-one trigraph and phase-two backslash/newline
    splicing across intervening comment or blank lines.
    """

    current_line_start = payload.rfind(b"\n", 0, offset) + 1
    if payload[current_line_start:offset].strip():
        return (), ()
    tokens = tuple(source_overlay_tokens(payload))
    previous = next(
        (
            (token, start, end)
            for token, start, end in reversed(tokens)
            if end <= current_line_start
        ),
        None,
    )
    if previous is None:
        return (), ()
    previous_line_start = payload.rfind(b"\n", 0, previous[1]) + 1
    previous_line_end = payload.find(b"\n", previous[2])
    if previous_line_end < 0:
        previous_line_end = len(payload)
    line_tokens = tuple(
        token
        for token, start, _end in tokens
        if previous_line_start <= start < previous_line_end
    )
    physical_lines = tuple(
        line.removesuffix(b"\r")
        for line in payload[previous_line_start:current_line_start].split(b"\n")[:-1]
    )
    return line_tokens, physical_lines


def _contains_physical_line_splice(lines: Sequence[bytes]) -> bool:
    return any(line.endswith((b"\\", b"??/")) for line in lines)


def _complete_function_like_macro_line(tokens: Sequence[str]) -> bool:
    """Recognize one complete, semicolon-less function-like macro seat."""

    if (
        len(tokens) < 3
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]) is None
        or tokens[1] != "("
        or tokens[-1] != ")"
        or any(token in {"#", ";", "{", "}"} for token in tokens)
    ):
        return False
    depth = 0
    for index, token in enumerate(tokens[1:], start=1):
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth < 0:
                return False
            if depth == 0 and index != len(tokens) - 1:
                return False
    return depth == 0


def _extended_global_declaration_line_seat(payload: bytes, offset: int) -> str | None:
    """Recognize one narrow global line seat outside token-neighbor grammar.

    Old projects commonly place declarations after a function-like assertion
    macro whose expansion owns its terminator, or after comments following a
    preprocessor directive.  Raw significant-token neighbors cannot prove
    those boundaries alone.  Both forms require a distinct, unspliced
    physical line at global scope.  The caller additionally requires a direct
    compiler owner and exact runtime projection for the macro-expansion form.
    """

    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    if (
        previous is None
        or parentheses
        or brackets
        or _brace_depth_at(payload, offset) != 0
        or following in _CONTROL_CONTINUATIONS
    ):
        return None
    line_tokens, physical_lines = _previous_significant_physical_line(payload, offset)
    if not line_tokens or not physical_lines or _contains_physical_line_splice(physical_lines):
        return None
    if line_tokens[0] == "#":
        return "preprocessor-directive"
    if _complete_function_like_macro_line(line_tokens):
        return "function-like-macro-invocation"
    return None


_CONTROL_CONTINUATIONS = frozenset({"else", "while", "catch", "__except", "__finally"})
_FRAME_OBSERVATION_TOKENS = frozenset(
    {
        "asm",
        "_asm",
        "__asm",
        "alloca",
        "_alloca",
        "setjmp",
        "_setjmp",
        "longjmp",
        "_longjmp",
        "reinterpret_cast",
        "_AddressOfReturnAddress",
        "_ReturnAddress",
        "_emit",
        "__emit",
    }
)


def _require_declaration_seat(payload: bytes, offset: int, *, operation: str) -> None:
    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    boundary = previous in {None, "{", "}", ";"} or (
        _previous_physical_line_is_directive(payload, offset)
    )
    if parentheses or brackets or not boundary or following in _CONTROL_CONTINUATIONS:
        raise ClassicSemanticError(
            f"operation {operation!r} is not at a closed declaration boundary"
        )


def _require_statement_list_seat(
    payload: bytes,
    offset: int,
    *,
    function_range: tuple[int, int],
    operation: str,
) -> None:
    if not function_range[0] < offset < function_range[1]:
        raise ClassicSemanticError(
            f"operation {operation!r} is outside its function statement list"
        )
    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    if (
        parentheses
        or brackets
        or previous not in {"{", "}", ";"}
        or following in _CONTROL_CONTINUATIONS
    ):
        raise ClassicSemanticError(
            f"operation {operation!r} is not at a closed compound-statement boundary"
        )


def _require_no_frame_observation(
    payload: bytes,
    *,
    function_range: tuple[int, int],
    operation: str,
) -> None:
    function_tokens = set(_token_texts(payload[function_range[0] : function_range[1]]))
    hazards = sorted(function_tokens & _FRAME_OBSERVATION_TOKENS)
    if hazards:
        raise ClassicSemanticError(
            f"operation {operation!r} can perturb observed frame state: {hazards}"
        )


def _preprocessor_mutations(
    clean_sources: Mapping[str, CleanSourceInput],
) -> frozenset[tuple[str, str]]:
    return _payload_preprocessor_mutations(source.payload for source in clean_sources.values())


_PREPROCESSOR_DIRECTIVE_CANDIDATE = re.compile(
    rb"(?<![A-Za-z0-9_])(?:define|undef)(?![A-Za-z0-9_])"
)


def _translation_phase_preprocessor_payload(payload: bytes) -> bytes:
    """Normalize the spellings that can form directives before tokenization.

    VC4 accepts the standard trigraph/digraph spellings and removes escaped
    physical newlines before recognizing directives.  The semantic census is
    conservative, so normalizing these spellings before the existing lexer is
    preferable to silently treating them as ordinary source text.
    """

    normalized = payload.replace(b"??=", b"#").replace(b"??/", b"\\")
    normalized = re.sub(rb"\\(?:\r\n|\n|\r)", b"", normalized)
    normalized = normalized.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return normalized.replace(b"%:", b"#")


def _preprocessor_include_operands(payload: bytes) -> tuple[str | None, ...]:
    """Return literal include operands; ``None`` denotes a dynamic include."""

    if not any(marker in payload for marker in (b"#", b"??=", b"%:")):
        return ()
    normalized = _translation_phase_preprocessor_payload(payload)
    if b"include" not in normalized:
        return ()
    tokens = tuple(iter_source_overlay_tokens(normalized))
    operands: list[str | None] = []
    previous_line_start: int | None = None
    for index, (token, start, _end) in enumerate(tokens):
        line_start = normalized.rfind(b"\n", 0, start) + 1
        first_on_line = previous_line_start != line_start
        previous_line_start = line_start
        if token != "#":
            continue
        if not first_on_line:
            continue
        if index + 2 >= len(tokens) or tokens[index + 1][0] != "include":
            continue
        operand, operand_start, _operand_end = tokens[index + 2]
        line_end = normalized.find(b"\n", operand_start)
        if line_end < 0:
            line_end = len(normalized)
        if operand_start >= line_end:
            operands.append(None)
            continue
        if len(operand) >= 2 and operand.startswith('"') and operand.endswith('"'):
            operands.append(operand[1:-1])
            continue
        if operand == "<":
            pieces: list[str] = []
            closed = False
            for following, following_start, _following_end in tokens[index + 3 :]:
                if following_start >= line_end:
                    break
                if following == ">":
                    closed = True
                    break
                pieces.append(following)
            operands.append("".join(pieces) if closed and pieces else None)
            continue
        operands.append(None)
    return tuple(operands)


def _compiler_force_include_operands(node: ProducerNode) -> tuple[str, ...]:
    operands: list[str] = []
    arguments = node.arguments
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        folded = argument.casefold()
        if folded in {"/fi", "-fi"}:
            if index + 1 >= len(arguments):
                raise ClassicSemanticError(
                    f"compiler {node.id!r} has an incomplete force-include option"
                )
            operands.append(arguments[index + 1])
            index += 2
            continue
        if folded.startswith(("/fi", "-fi")) and len(argument) > 3:
            operands.append(argument[3:])
        index += 1
    return tuple(operands)


def _reader_operand_matches_path(operand: str, relative: str) -> bool:
    normalized = operand.strip().strip('"<>').replace("\\", "/").casefold()
    normalized = normalized.replace("${source}/", "").removeprefix("source/")
    target = relative.replace("\\", "/").casefold()
    return (
        normalized == target
        or normalized.endswith("/" + target)
        or PurePosixPath(normalized).name == PurePosixPath(target).name
    )


def _sparse_source_reader_fallbacks(
    *,
    graph: ProducerGraphDocument,
    effective_sources: Mapping[str, bytes],
    strict_paths: frozenset[str],
) -> tuple[str, ...]:
    """Explain when a strict source requires the all-reader fallback.

    Header deltas already audit every ordinary compiler.  A strict C/C++
    source normally has one graph owner, but C permits textual and forced
    inclusion of another source file.  Any uncertain or secondary-reader form
    widens the audit to every ordinary compiler instead of rejecting an
    otherwise valid project.
    """

    strict_sources = tuple(
        sorted(
            (
                path
                for path in strict_paths
                if PurePosixPath(path).suffix.casefold() in _SOURCE_SUFFIXES
            ),
            key=str.casefold,
        )
    )
    if not strict_sources:
        return ()
    fallback_reasons: set[str] = set()
    for source_path, payload in sorted(effective_sources.items(), key=lambda item: item[0]):
        for operand in _preprocessor_include_operands(payload):
            if operand is None:
                fallback_reasons.add(f"dynamic-include:{source_path}")
                break
            matched = tuple(
                path for path in strict_sources if _reader_operand_matches_path(operand, path)
            )
            if matched:
                fallback_reasons.add(
                    f"textual-secondary:{source_path}:{','.join(matched)}"
                )
    for node in sorted(
        (item for item in graph.nodes if item.role is ProducerRole.COMPILER),
        key=lambda item: item.id.casefold(),
    ):
        for operand in _compiler_force_include_operands(node):
            matched = tuple(
                path for path in strict_sources if _reader_operand_matches_path(operand, path)
            )
            if matched:
                fallback_reasons.add(
                    f"forced-secondary:{node.id}:{','.join(matched)}"
                )
    return tuple(sorted(fallback_reasons, key=str.casefold))


def _payload_preprocessor_mutations(
    payloads: Iterable[bytes],
    *,
    prevalidated_digests: Iterable[Digest] | None = None,
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] | None = None,
) -> frozenset[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    digest_iterator = iter(prevalidated_digests) if prevalidated_digests is not None else None
    for payload in payloads:
        if type(payload) is not bytes:
            raise ClassicSemanticError("preprocessor census input is not immutable bytes")
        digest: Digest | None = None
        if digest_iterator is not None:
            try:
                digest = next(digest_iterator)
            except StopIteration as exc:
                raise ClassicSemanticError(
                    "preprocessor census has fewer prevalidated digests than payloads"
                ) from exc
            if not isinstance(digest, Digest):
                raise ClassicSemanticError("preprocessor census digest is malformed")
        elif cache is not None:
            digest = Digest.from_bytes(payload)
        cache_key = (digest, len(payload)) if digest is not None else None
        if cache is not None and cache_key is not None and cache_key in cache:
            result.update(cache[cache_key])
            continue
        mutations: set[tuple[str, str]] = set()
        # Both byte patterns are necessary for the existing Latin-1 lexer to
        # produce the significant-token window ``# (define|undef) ID``.  This
        # filter may deliberately admit comments, strings, and high-byte word
        # continuations as false positives; every candidate still goes through
        # the exact lexer below.  It therefore avoids pointless binary-archive
        # tokenization without narrowing the conservative namespace theorem.
        normalized = _translation_phase_preprocessor_payload(payload)
        if b"#" in normalized and _PREPROCESSOR_DIRECTIVE_CANDIDATE.search(normalized):
            previous: str | None = None
            directive: str | None = None
            for token, _start, _end in iter_source_overlay_tokens(normalized):
                if previous == "#" and token in {"define", "undef"}:
                    directive = token
                elif directive is not None:
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                        mutations.add((directive, token))
                    directive = None
                else:
                    directive = None
                previous = token
        frozen = frozenset(mutations)
        if cache is not None and cache_key is not None:
            cache[cache_key] = frozen
        result.update(frozen)
    if digest_iterator is not None:
        try:
            next(digest_iterator)
        except StopIteration:
            pass
        else:
            raise ClassicSemanticError(
                "preprocessor census has more prevalidated digests than payloads"
            )
    return frozenset(result)


def _compiler_has_define(node: ProducerNode, identifier: str) -> bool:
    def name(value: str) -> str:
        return re.split(r"[=#]", value, maxsplit=1)[0]

    arguments = node.arguments
    for index, argument in enumerate(arguments):
        folded = argument.casefold()
        if (
            folded in {"/d", "-d"}
            and index + 1 < len(arguments)
            and name(arguments[index + 1]) == identifier
        ):
            return True
        if (
            folded.startswith(("/d", "-d"))
            and len(argument) > 2
            and name(argument[2:]) == identifier
        ):
            return True
    return False


def _require_no_compiler_macro_capture(
    nodes: Iterable[ProducerNode],
    sensitive_identifiers: frozenset[str],
) -> None:
    """Reject command-line definitions on every compiler epoch, including carriers."""

    for node in sorted(nodes, key=lambda item: item.id.casefold()):
        collisions = sorted(
            identifier
            for identifier in sensitive_identifiers
            if _compiler_has_define(node, identifier)
        )
        if collisions:
            raise ClassicSemanticError(
                f"compiler {node.id!r} can macro-capture source-overlay identifiers; "
                f"command_line={collisions}"
            )


def _reserved_cpp_identifier(identifier: str) -> bool:
    """Return whether an injected spelling is reserved to the implementation."""

    return identifier.startswith("_") or "__" in identifier


def _validate_project_overlay_sources(
    *,
    overlays: Sequence[ClassicRecipeIntervention],
    graph: ProducerGraphDocument,
    source_pairs: Mapping[str, ProjectOverlaySourcePair],
    clean_sources: Mapping[str, CleanSourceInput],
    declaration_by_id: Mapping[
        str,
        tuple[dict[str, dict[str, object]], frozenset[str], frozenset[str]],
    ],
    secondary_reader_payloads: Mapping[str, bytes] | None,
) -> _OverlaySourceValidation:
    """Prove project-agnostic source theorems selected by the closed grammar."""

    generated_tus = frozenset(
        path for overlay in overlays for path in declaration_by_id[overlay.id][1]
    )
    generated_tu_folded = {path.casefold() for path in generated_tus}
    no_clean = frozenset(path for overlay in overlays for path in declaration_by_id[overlay.id][2])
    generated_headers = no_clean - generated_tus
    token_census: dict[str, int] = defaultdict(int)
    for source in clean_sources.values():
        for token in _token_texts(source.payload):
            token_census[token] += 1
    effective_sources = {
        source.path.casefold(): source.payload for source in clean_sources.values()
    }
    effective_sources.update(
        {pair.path.casefold(): pair.effective_payload for pair in source_pairs.values()}
    )
    effective_token_census: dict[str, int] = defaultdict(int)
    for payload in effective_sources.values():
        for token in _token_texts(payload):
            effective_token_census[token] += 1
    ordinary_effective_token_census: dict[str, int] = defaultdict(int)
    for path, payload in effective_sources.items():
        if path in generated_tu_folded:
            continue
        for token in _token_texts(payload):
            ordinary_effective_token_census[token] += 1
    preprocessor_mutations = _preprocessor_mutations(clean_sources)
    introduced: set[str] = set()
    declaration_origin_identifiers: set[str] = set()
    exclusive_declaration_identifiers: set[str] = set()
    declaration_facts: dict[str, list[_DeclarationFact]] = defaultdict(list)
    declaration_seat_failures: set[tuple[str, str, str, str]] = set()
    introduced_locals: set[tuple[str, str, str]] = set()
    helper_identifiers: set[str] = set()
    helpers_by_source: dict[str, list[str]] = defaultdict(list)
    macro_sensitive_identifiers: set[str] = set()
    intrinsic_macro_mutations: set[tuple[str, str, str]] = set()
    logical_headers: set[str] = set()
    unused_typedef_sources: set[str] = set()
    projection_sources: set[str] = set()
    projection_all = False
    traces: dict[str, object] = {}
    render_contexts: dict[
        str,
        tuple[dict[str, object], Mapping[str, bytes], ClassicOverlayDialect],
    ] = {}
    all_counterfactual_leaves: set[tuple[str, str, int]] = set()
    selected_counterfactual_leaves: set[tuple[str, str, int]] = set()
    leaf_paths: dict[tuple[str, str, int], str] = {}
    declaration_identifier_leaves: dict[
        str, set[tuple[str, str, int]]
    ] = defaultdict(set)
    declaration_fragment_token_census: dict[str, int] = defaultdict(int)

    compiler_nodes_by_source: dict[str, list[ProducerNode]] = defaultdict(list)
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_ref, _object_ref = _compiler_shape(node)
        kind, relative = source_ref.split("/", 1)
        if kind == "source":
            compiler_nodes_by_source[relative.casefold()].append(node)
    graph_targets = tuple(
        sorted(
            (
                str(node.target_id)
                for node in graph.nodes
                if node.role is ProducerRole.LINKER and node.target_id is not None
            ),
            key=str.casefold,
        )
    )
    targets_by_compiler: dict[str, set[str]] = defaultdict(set)
    for target_id in graph_targets:
        for node_id in _ancestor_compilers(graph, target_id):
            targets_by_compiler[node_id].add(target_id)
    authority_paths = {source.path.casefold(): source.path for source in clean_sources.values()}
    authority_paths.update(
        {
            pair.path.casefold(): pair.path
            for pair in source_pairs.values()
            if pair.clean_payload is None
        }
    )

    for overlay in overlays:
        outputs, _generated, _generated_inputs = declaration_by_id[overlay.id]
        claims = _parse_semantic_claims(overlay)
        clean_inputs = {
            path: pair.clean_payload
            for path in outputs
            if (pair := source_pairs.get(path.casefold())) is not None
            and pair.clean_payload is not None
        }
        if set(clean_inputs) != {
            path for path, declaration in outputs.items() if "clean" in declaration
        }:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} lacks immutable clean render inputs"
            )
        clean_cpp = {source.path: source.payload for source in clean_sources.values()}
        document = _overlay_document(overlay)
        render_clean_inputs = {
            path: payload
            for path, payload in clean_inputs.items()
            if isinstance(payload, bytes)
        }
        try:
            dialect = infer_classic_overlay_dialect(document, clean_cpp)
            rendered = render_classic_overlay(
                document,
                render_clean_inputs,
                dialect=dialect,
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} cannot be re-rendered from clean authority: {exc}"
            ) from exc
        if set(rendered.outputs) != set(outputs):
            raise ClassicSemanticError(f"overlay {overlay.id!r} render universe changed")
        render_contexts[overlay.id] = (document, render_clean_inputs, dialect)
        for path, payload in rendered.outputs.items():
            pair = source_pairs.get(path.casefold())
            if not isinstance(pair, ProjectOverlaySourcePair) or pair.effective_payload != payload:
                raise ClassicSemanticError(f"project overlay rendering changed: {path!r}")

        receipt_by_path = {item.path: item for item in rendered.receipts}
        consumed_claims: set[str] = set()
        operation_census: dict[str, int] = defaultdict(int)
        literal_aliases: dict[tuple[str, str, str, str], dict[str, int]] = defaultdict(
            lambda: {"definition": 0, "use": 0}
        )
        assert_insertions: list[tuple[str, frozenset[str]]] = []
        assert_deletions: list[tuple[str, str]] = []
        unused_typedefs: list[dict[str, object]] = []
        extended_declaration_line_seats: set[tuple[str, str, str, str, bool]] = set()
        for path, declaration in outputs.items():
            raw_operations = declaration.get("ops")
            if not isinstance(raw_operations, list):
                raise ClassicSemanticError(f"source-overlay operations are malformed: {path}")
            receipt = receipt_by_path[path]
            if len(raw_operations) != len(receipt.operations):
                raise ClassicSemanticError(f"source-overlay receipt is incomplete: {path}")
            pair = source_pairs[path.casefold()]
            clean_payload = pair.clean_payload
            clean_tokens = () if clean_payload is None else _token_texts(clean_payload)
            line_sensitive = "__LINE__" in clean_tokens or any(
                clean_tokens[index : index + 2] == ("#", "line")
                for index in range(len(clean_tokens) - 1)
            )
            is_carrier_tu = path in generated_tus
            is_generated_header = path in generated_headers
            source_compilers = compiler_nodes_by_source.get(path.casefold(), [])
            declaration_targets = frozenset(
                target
                for node in source_compilers
                for target in targets_by_compiler.get(node.id, set())
            )
            if not source_compilers:
                # Header exposure is narrowed later by exact compiler namespace
                # receipts.  The source-only theorem deliberately uses every
                # target as its fail-closed over-approximation.
                declaration_targets = frozenset(graph_targets)
            for raw_operation, operation_receipt in zip(
                raw_operations, receipt.operations, strict=True
            ):
                if not isinstance(raw_operation, dict) or not isinstance(
                    raw_operation.get("op"), str
                ):
                    raise ClassicSemanticError(f"source-overlay operation is malformed: {path}")
                action = raw_operation["op"]
                leaves = _generator_leaves(raw_operation.get("gen"))
                anchor_offsets = tuple(anchor.byte_offset for anchor in operation_receipt.anchors)
                if action in {"replace", "delete"} and operation_receipt.removed_digest is None:
                    raise ClassicSemanticError(
                        f"destructive operation lacks removed-byte evidence: {path}"
                    )
                if line_sensitive:
                    raise ClassicSemanticError(
                        f"source-overlay operation changes line-sensitive input {path!r}"
                    )
                if is_carrier_tu:
                    if action != "append" or any(
                        leaf["k"] not in _GENERATED_CARRIER_GENERATORS for leaf in leaves
                    ):
                        raise ClassicSemanticError(
                            f"generated carrier {path!r} uses an ordinary source operation"
                        )
                    continue
                if is_generated_header and (
                    action != "append" or len(leaves) != 1 or leaves[0]["k"] != "record_header"
                ):
                    raise ClassicSemanticError(f"generated header {path!r} is not declaration-only")
                if clean_payload is not None and action == "append":
                    raise ClassicSemanticError(
                        f"clean-backed source overlay {path!r} appends a new owner"
                    )
                for leaf_index, leaf in enumerate(leaves):
                    kind = str(leaf["k"])
                    leaf_key = (overlay.id, operation_receipt.operation_id, leaf_index)
                    all_counterfactual_leaves.add(leaf_key)
                    leaf_paths[leaf_key] = path
                    operation_census[kind] += 1
                    claim_key = _claim_key(operation_receipt.operation_id, leaf_index)
                    claim = claims.get(claim_key)
                    if kind in _DECLARATION_GENERATORS | {"record_header"}:
                        if claim is not None or action not in {"insert", "append"}:
                            raise ClassicSemanticError(
                                f"declaration generator {kind!r} has an invalid claim or seat"
                            )
                        entities = _declaration_entities(leaf)
                        declared = tuple(
                            identifier
                            for entity in entities
                            for identifier in entity.introduced_identifiers
                        )
                        declaration_depth: int | None = None
                        declaration_projection_required = False
                        if clean_payload is not None:
                            if not anchor_offsets:
                                raise ClassicSemanticError(
                                    f"declaration generator {kind!r} has no source seat"
                                )
                            seat_offset = min(anchor_offsets)
                            try:
                                _require_declaration_seat(
                                    clean_payload,
                                    seat_offset,
                                    operation=operation_receipt.operation_id,
                                )
                            except ClassicSemanticError as exc:
                                predecessor = _extended_global_declaration_line_seat(
                                    clean_payload, seat_offset
                                )
                                projection_required = (
                                    predecessor == "function-like-macro-invocation"
                                )
                                declaration_projection_required = projection_required
                                if predecessor is None:
                                    declaration_seat_failures.add(
                                        (
                                            path,
                                            operation_receipt.operation_id,
                                            kind,
                                            str(exc),
                                        )
                                    )
                                else:
                                    if projection_required:
                                        projection_sources.add(path.casefold())
                                    extended_declaration_line_seats.add(
                                        (
                                            path,
                                            operation_receipt.operation_id,
                                            kind,
                                            predecessor,
                                            projection_required,
                                        )
                                    )
                            declaration_depth = _brace_depth_at(clean_payload, seat_offset)
                            if declaration_depth != 0 and kind != "typedef":
                                declaration_seat_failures.add(
                                    (
                                        path,
                                        operation_receipt.operation_id,
                                        kind,
                                        "declaration is not at global scope",
                                    )
                                )
                        guard: str | None = None
                        if kind == "record_header":
                            recipe = leaf.get("typed_recipe")
                            if isinstance(recipe, dict) and isinstance(recipe.get("guard"), str):
                                guard = str(recipe["guard"])
                            else:
                                raise ClassicSemanticError("record-header guard is malformed")
                        fresh = all(
                            token_census.get(identifier, 0) == 0
                            and identifier not in exclusive_declaration_identifiers
                            and identifier not in helper_identifiers
                            and all(
                                mutation[1] != identifier for mutation in preprocessor_mutations
                            )
                            for identifier in declared
                        )
                        if not fresh:
                            raise ClassicSemanticError(
                                f"declaration generator {kind!r} is not globally fresh: "
                                f"{sorted(declared)}"
                            )
                        if kind == "typedef":
                            aliased_type = leaf.get("aliased_type")
                            if (
                                action != "insert"
                                or clean_payload is None
                                or aliased_type != "int"
                                or declaration_depth is None
                            ):
                                raise ClassicSemanticError(
                                    "unused typedef theorem admits only a clean-backed "
                                    "exact 'typedef int' insertion"
                                )
                            used_identifiers = sorted(
                                identifier
                                for identifier in declared
                                if effective_token_census.get(identifier, 0) != 1
                            )
                            if used_identifiers:
                                raise ClassicSemanticError(
                                    "generated typedef is not target-closed and unused: "
                                    f"{used_identifiers}"
                                )
                            macro_sensitive_identifiers.update(("typedef", "int"))
                            unused_typedef_sources.add(path.casefold())
                            unused_typedefs.extend(
                                {
                                    "theorem": (
                                        "complete-census-fresh-unused-typedef-int-v1"
                                    ),
                                    "identifier": identifier,
                                    "aliased_type": "int",
                                    "source_path": path,
                                    "clean_occurrences": 0,
                                    "effective_occurrences": 1,
                                    "closed_declaration_boundary": True,
                                    "lexical_brace_depth": declaration_depth,
                                    "macro_sensitive_tokens": [
                                        "typedef",
                                        "int",
                                        identifier,
                                    ],
                                }
                                for identifier in declared
                            )
                        if guard is not None and (
                            token_census.get(guard, 0)
                            or effective_token_census.get(guard, 0) != 2
                            or guard in introduced
                            or any(mutation[1] == guard for mutation in preprocessor_mutations)
                        ):
                            raise ClassicSemanticError(
                                f"record-header guard is not globally fresh: {guard!r}"
                            )
                        if guard is not None:
                            exclusive_declaration_identifiers.add(guard)
                            introduced.add(guard)
                            macro_sensitive_identifiers.add(guard)
                            intrinsic_macro_mutations.add((path.casefold(), "define", guard))
                        if declaration_depth in {None, 0}:
                            for entity in entities:
                                for identifier in entity.introduced_identifiers:
                                    disposition = (
                                        entity.disposition
                                        if identifier == entity.primary_identifier
                                        else "enumerator-definition"
                                    )
                                    declaration_facts[identifier].append(
                                        _DeclarationFact(
                                            identifier,
                                            entity.primary_identifier,
                                            disposition,
                                            entity.tag,
                                            entity.semantic_digest,
                                            path,
                                            declaration_targets,
                                        )
                                    )
                        introduced.update(declared)
                        declaration_origin_identifiers.update(declared)
                        if guard is not None:
                            declaration_origin_identifiers.add(guard)
                        declaration_family_identifiers = declared + (
                            (guard,) if guard is not None else ()
                        )
                        for identifier in declaration_family_identifiers:
                            declaration_identifier_leaves[identifier].add(leaf_key)
                        for identifier in declared:
                            declaration_fragment_token_census[identifier] += 1
                        if guard is not None:
                            declaration_fragment_token_census[guard] += 2
                        macro_sensitive_identifiers.update(
                            _declaration_owned_identifiers(leaf)
                        )
                        if not declaration_projection_required:
                            selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "lines":
                        if claim is not None:
                            raise ClassicSemanticError("layout-only generator cannot carry a claim")
                        if action in {"insert", "append"}:
                            selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "cond":
                        if (
                            claim is not None
                            or action != "insert"
                            or leaf.get("branch_policy") != "typed_declarations_only"
                        ):
                            raise ClassicSemanticError("conditional declaration seat is unsafe")
                        if clean_payload is not None:
                            _require_declaration_seat(
                                clean_payload,
                                min(anchor_offsets),
                                operation=operation_receipt.operation_id,
                            )
                        selected_counterfactual_leaves.add(leaf_key)
                        continue
                    if kind == "size_asserts":
                        if claim is not None or action != "insert":
                            raise ClassicSemanticError("compile-time assertion seat is unsafe")
                        if clean_payload is None or not anchor_offsets:
                            raise ClassicSemanticError("compile-time assertion lacks a source seat")
                        _require_declaration_seat(
                            clean_payload,
                            min(anchor_offsets),
                            operation=operation_receipt.operation_id,
                        )
                        projection_sources.add(path.casefold())
                        continue
                    if kind in {"include", "include_seat"}:
                        if action != "insert" or clean_payload is None or not source_compilers:
                            raise ClassicSemanticError("include generator lacks a compiler owner")
                        expected_logical: object
                        if kind == "include":
                            if not isinstance(claim, _LogicalHeaderClaim):
                                raise ClassicSemanticError(
                                    f"include operation {operation_receipt.operation_id!r} lacks "
                                    "a logical-header binding"
                                )
                            header = leaf.get("header")
                            expected_logical = claim.logical_path
                            consumed_claims.add(claim_key)
                        else:
                            if claim is not None:
                                raise ClassicSemanticError(
                                    "include_seat cannot override its logical header"
                                )
                            header = leaf.get("basename")
                            expected_logical = leaf.get("logical_header")
                        if not isinstance(header, str) or not isinstance(expected_logical, str):
                            raise ClassicSemanticError("logical include binding is malformed")
                        _require_declaration_seat(
                            clean_payload,
                            min(anchor_offsets),
                            operation=operation_receipt.operation_id,
                        )
                        resolved = _resolve_logical_header(
                            source_path=path,
                            header=header,
                            style=leaf.get("style"),
                            compiler_nodes=source_compilers,
                            authority_paths=authority_paths,
                        )
                        if resolved != expected_logical:
                            raise ClassicSemanticError(
                                f"logical include binding changed for {path!r}: {resolved!r}"
                            )
                        logical_headers.add(resolved)
                        projection_sources.add(path.casefold())
                        continue
                    if kind in _FUNCTION_CLAIM_GENERATORS:
                        if clean_payload is None or not isinstance(claim, _FunctionScopeClaim):
                            raise ClassicSemanticError(
                                f"operation leaf {operation_receipt.operation_id!r}/{leaf_index} "
                                "lacks a function-scope binding"
                            )
                        function_range = _validate_function_claim(
                            claim=claim,
                            payload=clean_payload,
                            anchor_offsets=anchor_offsets,
                        )
                        consumed_claims.add(claim_key)
                        if kind != "literal_alias" or "type" in leaf:
                            _require_statement_list_seat(
                                clean_payload,
                                min(anchor_offsets),
                                function_range=function_range,
                                operation=operation_receipt.operation_id,
                            )
                        if kind == "noop_assign":
                            target = leaf.get("assignment_target")
                            if (
                                action != "insert"
                                or not isinstance(target, str)
                                or len(claim.bindings) != 1
                                or claim.bindings[0].identifier != target
                                or not claim.bindings[0].initialized
                            ):
                                raise ClassicSemanticError("scalar identity claim differs")
                            _validate_scalar_binding(
                                claim=claim.bindings[0],
                                payload=clean_payload,
                                function_range=function_range,
                                before_offset=min(anchor_offsets),
                                clean_sources=clean_sources,
                            )
                            macro_sensitive_identifiers.add(target)
                        elif claim.bindings:
                            raise ClassicSemanticError(
                                f"{kind} function claim has unauthorized scalar bindings"
                            )
                        if kind == "empty_scopes":
                            if action != "insert":
                                raise ClassicSemanticError("empty scopes are not an insertion")
                        elif kind == "local_ids":
                            _require_no_frame_observation(
                                clean_payload,
                                function_range=function_range,
                                operation=operation_receipt.operation_id,
                            )
                            identifiers = leaf.get("identifiers")
                            type_spelling = leaf.get("type")
                            if (
                                action != "insert"
                                or claim.function != leaf.get("function")
                                or not isinstance(identifiers, list)
                                or not isinstance(type_spelling, str)
                                or not _is_nonvolatile_integral_type(type_spelling, clean_sources)
                            ):
                                raise ClassicSemanticError("dead-local theorem differs")
                            function_tokens = _token_texts(
                                clean_payload[function_range[0] : function_range[1]]
                            )
                            for identifier in identifiers:
                                local_key = (path.casefold(), claim.function, str(identifier))
                                if (
                                    not isinstance(identifier, str)
                                    or identifier in function_tokens
                                    or any(
                                        mutation[1] == identifier
                                        for mutation in preprocessor_mutations
                                    )
                                    or any(
                                        _compiler_has_define(node, identifier)
                                        for node in source_compilers
                                    )
                                    or local_key in introduced_locals
                                ):
                                    raise ClassicSemanticError(
                                        f"dead local is not fresh in its bound function: "
                                        f"{identifier!r}"
                                    )
                                introduced_locals.add(local_key)
                                macro_sensitive_identifiers.add(identifier)
                        elif kind == "literal_alias":
                            # Pointer identity, pooling, overload resolution, and
                            # unevaluated-context rules are not inferred from a
                            # textual alias shape.  This family is admitted only
                            # when the exact runtime projection is unchanged.
                            projection_sources.add(path.casefold())
                            owner = leaf.get("owner_function")
                            literal = leaf.get("literal")
                            local = leaf.get("local_identifier")
                            if (
                                claim.function != owner
                                or not isinstance(owner, str)
                                or not isinstance(literal, str)
                                or not isinstance(local, str)
                            ):
                                raise ClassicSemanticError("literal-alias owner differs")
                            key = (path, owner, literal, local)
                            if "type" in leaf:
                                _require_no_frame_observation(
                                    clean_payload,
                                    function_range=function_range,
                                    operation=operation_receipt.operation_id,
                                )
                                if (
                                    action != "insert"
                                    or tuple(_type_tokens(str(leaf["type"])))
                                    not in {("const", "char", "*"), ("char", "const", "*")}
                                    or local
                                    in _token_texts(
                                        clean_payload[function_range[0] : function_range[1]]
                                    )
                                    or any(
                                        mutation[1] == local for mutation in preprocessor_mutations
                                    )
                                    or any(
                                        _compiler_has_define(node, local)
                                        for node in source_compilers
                                    )
                                    or (path.casefold(), claim.function, local) in introduced_locals
                                ):
                                    raise ClassicSemanticError("literal alias definition is unsafe")
                                introduced_locals.add((path.casefold(), claim.function, local))
                                macro_sensitive_identifiers.add(local)
                                literal_aliases[key]["definition"] += 1
                            else:
                                if action != "replace" or leaf.get("use_ordinal") != 1:
                                    raise ClassicSemanticError("literal alias use is unsafe")
                                literal_aliases[key]["use"] += 1
                        elif kind == "assert_reseat":
                            if (
                                any(
                                    mutation in preprocessor_mutations
                                    for mutation in {
                                        ("undef", "NDEBUG"),
                                        ("define", "assert"),
                                        ("undef", "assert"),
                                    }
                                )
                                or not source_compilers
                                or any(
                                    not _compiler_has_define(node, "NDEBUG")
                                    for node in source_compilers
                                )
                                or any(
                                    _compiler_has_define(node, "assert")
                                    for node in source_compilers
                                )
                            ):
                                raise ClassicSemanticError(
                                    "assert reseat lacks a closed NDEBUG compiler universe"
                                )
                            if action == "insert":
                                _require_no_frame_observation(
                                    clean_payload,
                                    function_range=function_range,
                                    operation=operation_receipt.operation_id,
                                )
                                authentic = leaf.get("authentic_function")
                                carrier = leaf.get("carrier_function")
                                carrier_conditions = leaf.get("carrier_conditions")
                                restored = leaf.get("restored_conditions")
                                dead = leaf.get("dead_local")
                                dead_identifiers = (
                                    dead.get("identifiers") if isinstance(dead, dict) else None
                                )
                                if (
                                    claim.function != carrier
                                    or not isinstance(authentic, str)
                                    or not isinstance(restored, list)
                                    or not restored
                                    or any(
                                        not isinstance(item, str) or not item for item in restored
                                    )
                                    or len(set(restored)) != len(restored)
                                    or not isinstance(carrier_conditions, list)
                                    or not carrier_conditions
                                    or any(
                                        not isinstance(item, str) or not item
                                        for item in carrier_conditions
                                    )
                                    or len(set(carrier_conditions)) != len(carrier_conditions)
                                    or not isinstance(dead, dict)
                                    or not isinstance(dead.get("type"), str)
                                    or not isinstance(dead_identifiers, list)
                                    or not dead_identifiers
                                    or any(
                                        not isinstance(identifier, str)
                                        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier)
                                        is None
                                        or identifier
                                        in _token_texts(
                                            clean_payload[function_range[0] : function_range[1]]
                                        )
                                        or any(
                                            mutation[1] == identifier
                                            for mutation in preprocessor_mutations
                                        )
                                        or any(
                                            _compiler_has_define(node, identifier)
                                            for node in source_compilers
                                        )
                                        or (
                                            path.casefold(),
                                            claim.function,
                                            identifier,
                                        )
                                        in introduced_locals
                                        for identifier in dead_identifiers
                                    )
                                    or len(set(dead_identifiers)) != len(dead_identifiers)
                                    or not _is_nonvolatile_integral_type(
                                        str(dead["type"]), clean_sources
                                    )
                                ):
                                    raise ClassicSemanticError("assert carrier theorem differs")
                                introduced_locals.update(
                                    (path.casefold(), claim.function, identifier)
                                    for identifier in dead_identifiers
                                )
                                macro_sensitive_identifiers.update(dead_identifiers)
                                assert_insertions.append(
                                    (
                                        authentic,
                                        frozenset(restored),
                                    )
                                )
                            elif action == "delete" and isinstance(leaf.get("condition"), str):
                                assert_deletions.append((claim.function, str(leaf["condition"])))
                            else:
                                raise ClassicSemanticError("assert reseat action differs")
                        continue
                    if kind in _UNREACHABLE_HELPER_GENERATORS:
                        helper = leaf.get("function_identifier")
                        if PurePosixPath(path).suffix.casefold() in _HEADER_SUFFIXES:
                            raise ClassicSemanticError(
                                "unreachable helper generators require a primary source owner; "
                                f"header helpers are unsupported: {path!r}"
                            )
                        if (
                            claim is not None
                            or action != "insert"
                            or clean_payload is None
                            or not anchor_offsets
                            or _brace_depth_at(clean_payload, anchor_offsets[0]) != 0
                            or not isinstance(helper, str)
                            or token_census.get(helper, 0)
                            or helper in introduced
                        ):
                            raise ClassicSemanticError(
                                f"unreachable helper theorem is unsafe: {helper!r}"
                            )
                        introduced.add(helper)
                        macro_sensitive_identifiers.add(helper)
                        helper_identifiers.add(helper)
                        helpers_by_source[path.casefold()].append(helper)
                        last_clean_token = max(
                            (end for _token, _start, end in source_overlay_tokens(clean_payload)),
                            default=0,
                        )
                        if anchor_offsets[0] < last_clean_token:
                            projection_sources.add(path.casefold())
                        continue
                    raise ClassicSemanticError(
                        f"source-overlay generator has no semantic theorem: {kind!r}"
                    )
        if any(values != {"definition": 1, "use": 1} for values in literal_aliases.values()):
            raise ClassicSemanticError("literal alias does not form one closed definition/use pair")
        if assert_insertions:
            if len(assert_insertions) != 1:
                raise ClassicSemanticError("assert reseat has no unique carrier")
            authentic, restored = assert_insertions[0]
            deleted = {
                condition for function, condition in assert_deletions if function == authentic
            }
            if deleted != set(restored) or len(deleted) != len(assert_deletions):
                raise ClassicSemanticError("assert reseat deletion closure differs")
        elif assert_deletions:
            raise ClassicSemanticError("assert deletions have no carrier insertion")
        if consumed_claims != set(claims):
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} has unused or missing semantic claims"
            )
        traces[overlay.id] = {
            "dialect": {
                "qualified_member_probe_return_type": (dialect.qualified_member_probe_return_type)
            },
            "render_receipts": [
                _receipt_trace(item)
                for item in sorted(rendered.receipts, key=lambda item: item.path.casefold())
            ],
            "operation_census": dict(sorted(operation_census.items())),
            "semantic_claim_count": len(claims),
            "unused_typedefs": sorted(
                unused_typedefs,
                key=lambda item: (str(item["source_path"]).casefold(), str(item["identifier"])),
            ),
            "extended_global_declaration_line_seats": [
                {
                    "theorem": (
                        "compiler-projected-global-declaration-line-seat-v1"
                        if projection_required
                        else "comment-separated-preprocessor-declaration-line-seat-v1"
                    ),
                    "source_path": path,
                    "operation": operation,
                    "generator": kind,
                    "predecessor": predecessor,
                    "runtime_projection_required": projection_required,
                }
                for path, operation, kind, predecessor, projection_required in sorted(
                    extended_declaration_line_seats,
                    key=lambda item: (
                        item[0].casefold(),
                        item[1].casefold(),
                        item[2],
                        item[3],
                        item[4],
                    ),
                )
            ],
        }
    declaration_odr, odr_conflicts = _declaration_odr_analysis(declaration_facts)
    if declaration_seat_failures or odr_conflicts:
        blocked_paths = sorted(
            {path for path, _operation, _kind, _reason in declaration_seat_failures}
            | {
                str(conflict[key])
                for conflict in odr_conflicts
                for key in ("left_source", "right_source")
            },
            key=str.casefold,
        )
        seat_trace = [
            {
                "path": path,
                "operation": operation,
                "generator": kind,
                "reason": reason,
            }
            for path, operation, kind, reason in sorted(declaration_seat_failures)
        ]
        odr_summary = _odr_conflict_summary(odr_conflicts) if odr_conflicts else "none"
        raise ClassicSemanticError(
            "project overlay declaration theorem is quarantined; "
            f"blocked_paths={blocked_paths}, seat_failures={seat_trace}, "
            f"odr_conflicts={odr_summary}"
        )

    origin_failures = [
        {
            "identifier": identifier,
            "clean_occurrences": token_census.get(identifier, 0),
            "ordinary_effective_occurrences": ordinary_effective_token_census.get(
                identifier, 0
            ),
            "declaration_fragment_occurrences": declaration_fragment_token_census.get(
                identifier, 0
            ),
        }
        for identifier in sorted(declaration_origin_identifiers)
        if token_census.get(identifier, 0) != 0
        or declaration_fragment_token_census.get(identifier, 0) == 0
        or ordinary_effective_token_census.get(identifier, 0)
        != declaration_fragment_token_census.get(identifier, 0)
    ]
    if origin_failures:
        raise ClassicSemanticError(
            "source-overlay declaration identifier escapes its closed fragment family: "
            f"{origin_failures}"
        )

    # A repeated compatible declaration family is one theorem unit.  If any
    # occurrence needs compiler projection, keep every occurrence out of the
    # counterfactual and audit all of their compiler owners together.
    changed = True
    while changed:
        changed = False
        for family_leaves in declaration_identifier_leaves.values():
            if family_leaves.issubset(selected_counterfactual_leaves):
                continue
            newly_blocked = family_leaves & selected_counterfactual_leaves
            if not newly_blocked:
                continue
            selected_counterfactual_leaves.difference_update(newly_blocked)
            projection_sources.update(leaf_paths[key].casefold() for key in family_leaves)
            changed = True

    declaration_outputs: dict[str, bytes] = {}
    declaration_leaf_keys: dict[str, tuple[tuple[str, int], ...]] = {}
    for overlay in overlays:
        document, context_clean_inputs, dialect = render_contexts[overlay.id]
        selected_keys = frozenset(
            (operation_id, leaf_index)
            for overlay_id, operation_id, leaf_index in selected_counterfactual_leaves
            if overlay_id == overlay.id
        )
        try:
            counterfactual = render_classic_overlay_leaf_subset(
                document,
                context_clean_inputs,
                selected_keys,
                dialect=dialect,
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"overlay {overlay.id!r} declaration counterfactual cannot be derived: {exc}"
            ) from exc
        declaration_leaf_keys[overlay.id] = tuple(sorted(selected_keys))
        for path, payload in counterfactual.outputs.items():
            if path.casefold() in generated_tu_folded:
                continue
            if path in declaration_outputs:
                raise ClassicSemanticError(
                    f"declaration counterfactual output is owned more than once: {path!r}"
                )
            declaration_outputs[path] = payload

    strict_paths = {
        leaf_paths[key].casefold()
        for key in all_counterfactual_leaves - selected_counterfactual_leaves
    }
    reader_closure_fallbacks: tuple[str, ...]
    if secondary_reader_payloads is None:
        reader_closure_fallbacks = ("toolchain-include-namespace-unavailable",)
    else:
        reader_payloads = dict(effective_sources)
        reader_payloads.update(secondary_reader_payloads)
        reader_closure_fallbacks = _sparse_source_reader_fallbacks(
            graph=graph,
            effective_sources=reader_payloads,
            strict_paths=frozenset(strict_paths),
        )
    ordinary_compilers: dict[str, ProducerNode] = {}
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_ref, _object_ref = _compiler_shape(node)
        relative = source_ref.removeprefix("source/")
        if relative.casefold() not in generated_tu_folded:
            ordinary_compilers[node.id] = node
    audit_node_ids: set[str] = set()
    projection_node_ids: set[str] = set()
    projection_header = False
    for folded_path in sorted(strict_paths):
        suffix = PurePosixPath(folded_path).suffix.casefold()
        if suffix in _HEADER_SUFFIXES:
            owners = set(ordinary_compilers)
            projection_header = projection_header or folded_path in projection_sources
        elif suffix in _SOURCE_SUFFIXES:
            owners = (
                set(ordinary_compilers)
                if reader_closure_fallbacks
                else {
                    node.id
                    for node in compiler_nodes_by_source.get(folded_path, ())
                    if node.id in ordinary_compilers
                }
            )
            if not owners:
                raise ClassicSemanticError(
                    f"source-overlay semantic delta has no compiler owner: {folded_path!r}"
                )
        else:
            raise ClassicSemanticError(
                f"source-overlay semantic delta has an unsupported source kind: {folded_path!r}"
            )
        if not owners:
            raise ClassicSemanticError(
                f"source-overlay semantic delta has no ordinary compiler reader: {folded_path!r}"
            )
        audit_node_ids.update(owners)
        if folded_path in projection_sources:
            projection_node_ids.update(owners)
    if projection_all or projection_header:
        projection_node_ids.update(audit_node_ids)

    compiler_epoch_plan = ProjectOverlayCompilerEpochPlan(
        MappingProxyType(
            dict(sorted(declaration_outputs.items(), key=lambda item: item[0].casefold()))
        ),
        frozenset(audit_node_ids),
        frozenset(projection_node_ids),
        MappingProxyType(
            dict(sorted(declaration_leaf_keys.items(), key=lambda item: item[0].casefold()))
        ),
        reader_closure_fallbacks,
    )
    for trace in traces.values():
        if not isinstance(trace, dict):
            raise AssertionError("source validation trace is not mutable")
        trace["global_declaration_odr"] = declaration_odr
    for overlay_id, trace in traces.items():
        if not isinstance(trace, dict):
            raise AssertionError("source validation trace is not mutable")
        trace["declaration_counterfactual"] = {
            "theorem": "derived-closed-declaration-family-counterfactual-v1",
            "selected_leaf_keys": [
                {"operation_id": operation_id, "leaf_index": leaf_index}
                for operation_id, leaf_index in compiler_epoch_plan.declaration_leaf_keys[
                    overlay_id
                ]
            ],
            "audit_node_ids": sorted(compiler_epoch_plan.audit_node_ids, key=str.casefold),
            "runtime_projection_node_ids": sorted(
                compiler_epoch_plan.runtime_projection_node_ids,
                key=str.casefold,
            ),
            "reader_closure_fallbacks": list(
                compiler_epoch_plan.reader_closure_fallbacks
            ),
        }
    reserved_identifiers = sorted(
        identifier
        for identifier in macro_sensitive_identifiers
        if _reserved_cpp_identifier(identifier)
    )
    if reserved_identifiers:
        raise ClassicSemanticError(
            "source-overlay identifiers enter the implementation-reserved namespace: "
            f"{reserved_identifiers}"
        )
    return _OverlaySourceValidation(
        MappingProxyType(traces),
        compiler_epoch_plan,
        generated_headers,
        frozenset(logical_headers),
        frozenset(unused_typedef_sources),
        frozenset(projection_sources),
        projection_all,
        frozenset(helper_identifiers),
        MappingProxyType(
            {path: tuple(identifiers) for path, identifiers in sorted(helpers_by_source.items())}
        ),
        frozenset(declaration_origin_identifiers),
        frozenset(macro_sensitive_identifiers),
        frozenset(intrinsic_macro_mutations),
    )


def _derive_project_overlay_compiler_epoch(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    source_pairs: Sequence[ProjectOverlaySourcePair],
    clean_source_inputs: Sequence[CleanSourceInput],
    *,
    secondary_reader_payloads: Mapping[str, bytes] | None = None,
) -> tuple[
    ProjectOverlayCompilerEpochPlan,
    _OverlaySourceValidation | None,
    frozenset[str],
]:
    """Derive and validate the declaration counterfactual execution theorem.

    The optional validation is absent only when the project has no overlay.
    Generated carrier paths are returned separately because they never belong
    to the ordinary sparse-audit universe.
    """

    overlays = _overlay_interventions(bundle)
    if not overlays:
        if source_pairs or clean_source_inputs:
            raise ClassicSemanticError(
                "compiler epoch planning received source evidence without a project overlay"
            )
        return (
            ProjectOverlayCompilerEpochPlan(
                MappingProxyType({}),
                frozenset(),
                frozenset(),
                MappingProxyType({}),
            ),
            None,
            frozenset(),
        )
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicSemanticError(
            "project-overlay compiler epoch planning requires a complete source manifest"
        )
    clean_sources = _unique(clean_source_inputs, lambda item: item.path, "clean source input")
    manifest_by_path = {item.path.casefold(): item for item in manifest.entries}
    if set(clean_sources) != set(manifest_by_path):
        missing = sorted(set(manifest_by_path) - set(clean_sources))
        extra = sorted(set(clean_sources) - set(manifest_by_path))
        raise ClassicSemanticError(
            f"clean source authority differs during compiler epoch planning; "
            f"missing={missing}, extra={extra}"
        )
    for folded, source in clean_sources.items():
        if not isinstance(source, CleanSourceInput):
            raise ClassicSemanticError("clean source authority contains an invalid record")
        entry = manifest_by_path[folded]
        if (
            source.path != entry.path
            or len(source.payload) != entry.size
            or Digest.from_bytes(source.payload) != entry.digest
        ):
            raise ClassicSemanticError(
                f"clean source authority changed during compiler epoch planning: {source.path!r}"
            )

    declaration_by_id: dict[
        str,
        tuple[dict[str, dict[str, object]], frozenset[str], frozenset[str]],
    ] = {}
    output_paths: set[str] = set()
    for overlay in overlays:
        declaration = _overlay_declaration(overlay)
        declaration_by_id[overlay.id] = declaration
        outputs, _generated, _generated_inputs = declaration
        folded_outputs = {path.casefold() for path in outputs}
        overlap = folded_outputs & output_paths
        if overlap:
            raise ClassicSemanticError(
                f"project-overlay compiler epoch outputs overlap: {sorted(overlap)}"
            )
        output_paths.update(folded_outputs)

    pairs = _unique(source_pairs, lambda item: item.path, "project overlay source pair")
    if set(pairs) != output_paths:
        missing = sorted(output_paths - set(pairs))
        extra = sorted(set(pairs) - output_paths)
        raise ClassicSemanticError(
            f"project-overlay compiler epoch source pairs differ; "
            f"missing={missing}, extra={extra}"
        )
    for overlay in overlays:
        outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
        for path, output_declaration in outputs.items():
            pair = pairs[path.casefold()]
            if not isinstance(pair, ProjectOverlaySourcePair) or pair.path != path:
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch source pair changed: {path!r}"
                )
            if (
                Digest.from_bytes(pair.effective_payload).value
                != output_declaration["effective"]
                or len(pair.effective_payload) != output_declaration["size"]
            ):
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch effective source changed: {path!r}"
                )
            if path in generated_inputs:
                if pair.clean_payload is not None:
                    raise ClassicSemanticError(
                        f"generated compiler epoch source has a clean preimage: {path!r}"
                    )
                continue
            clean = clean_sources.get(path.casefold())
            if (
                not isinstance(clean, CleanSourceInput)
                or pair.clean_payload != clean.payload
                or output_declaration.get("clean") != Digest.from_bytes(clean.payload).value
            ):
                raise ClassicSemanticError(
                    f"project-overlay compiler epoch clean source changed: {path!r}"
                )

    validation = _validate_project_overlay_sources(
        overlays=overlays,
        graph=graph,
        source_pairs={
            key: value
            for key, value in pairs.items()
            if isinstance(value, ProjectOverlaySourcePair)
        },
        clean_sources={
            key: value
            for key, value in clean_sources.items()
            if isinstance(value, CleanSourceInput)
        },
        declaration_by_id=declaration_by_id,
        secondary_reader_payloads=(
            None
            if _toolchain_include_roots(bundle) and not secondary_reader_payloads
            else (secondary_reader_payloads or {})
        ),
    )
    generated_tus = frozenset(
        path
        for _outputs, generated, _generated_inputs in declaration_by_id.values()
        for path in generated
    )
    return validation.compiler_epoch_plan, validation, generated_tus


def plan_project_overlay_compiler_epochs(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    source_pairs: Sequence[ProjectOverlaySourcePair],
    clean_source_inputs: Sequence[CleanSourceInput],
    *,
    secondary_reader_payloads: Mapping[str, bytes] | None = None,
) -> ProjectOverlayCompilerEpochPlan:
    """Derive the declaration counterfactual and its exact sparse audit set.

    Runtime uses this pure planner to decide which compiler nodes to execute.
    Semantic validation invokes the same theorem independently and rejects any
    missing or extra runtime evidence; the returned bytes are therefore a
    derived execution plan, not caller-supplied proof authority.
    """

    plan, _validation, _generated_tus = _derive_project_overlay_compiler_epoch(
        bundle,
        graph,
        source_pairs,
        clean_source_inputs,
        secondary_reader_payloads=secondary_reader_payloads,
    )
    return plan


def _helper_delta_sections(
    *,
    clean: _CoffObject,
    effective: _CoffObject,
    helper_identifiers: Sequence[str],
) -> tuple[frozenset[int], frozenset[str]]:
    clean_definitions = _external_definitions(clean)
    effective_definitions = _external_definitions(effective)
    extra_names = frozenset(set(effective_definitions) - set(clean_definitions))
    if not extra_names:
        raise ClassicSemanticError(
            f"helper source {effective.label!r} introduces no external definition"
        )
    for identifier in helper_identifiers:
        if not any(identifier in name for name in extra_names):
            raise ClassicSemanticError(
                f"helper {identifier!r} has no independently derived COFF definition"
            )
    clean_names = set(clean_definitions)
    by_section: dict[int, set[str]] = defaultdict(set)
    for name, section in effective_definitions.items():
        by_section[section.number].add(name)
    excluded = {effective_definitions[name].number for name in extra_names}
    if any(by_section[number] & clean_names for number in excluded):
        raise ClassicSemanticError(
            f"helper source {effective.label!r} shares a section with baseline definitions"
        )

    changed = True
    while changed:
        changed = False
        inbound: dict[int, set[int]] = defaultdict(set)
        for source in effective.sections:
            if source.name.casefold().startswith(".debug"):
                continue
            for relocation in source.relocations:
                if relocation.target_section > 0:
                    inbound[relocation.target_section].add(source.number)
        for section in effective.sections:
            if section.number in excluded or section.name.casefold().startswith(".debug"):
                continue
            associated = section.comdat_associated
            referenced_only_by_helpers = bool(inbound.get(section.number)) and inbound[
                section.number
            ].issubset(excluded)
            if associated in excluded or (
                referenced_only_by_helpers and not (by_section[section.number] & clean_names)
            ):
                excluded.add(section.number)
                changed = True
    return frozenset(excluded), extra_names


def _compiler_namespace_member_wire(
    value: CompilerSourceRead,
) -> dict[str, object]:
    return {
        "reference": value.reference,
        "digest": value.digest.model_dump(mode="json"),
        "size": value.size,
        "parent_index": value.parent_index,
    }


def compiler_namespace_evidence_digest(value: CompilerNamespaceEvidence) -> Digest:
    """Content-identify one complete shared compiler namespace census."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "namespace_id": value.namespace_id,
                "input_evidence_kind": value.input_evidence_kind.value,
                "members": [_compiler_namespace_member_wire(item) for item in value.members],
            }
        )
    )


def _compiler_epoch_command_statement(
    value: CompilerEpochInvocation,
) -> dict[str, object]:
    return {
        "schema": 3,
        "input_evidence_kind": value.input_evidence_kind.value,
        "tool_id": value.tool_id,
        "tool_digest": value.tool_digest.model_dump(mode="json"),
        "arguments": list(value.arguments),
        "working_directory": value.working_directory,
        "environment_digest": value.environment_digest.model_dump(mode="json"),
        "path_profile_digest": value.path_profile_digest.model_dump(mode="json"),
    }


def compiler_epoch_invocation_digest(value: CompilerEpochInvocation) -> Digest:
    """Digest one command and its referenced shared compiler namespace."""

    return Digest.from_bytes(
        canonical_json(
            {
                **_compiler_epoch_command_statement(value),
                "namespace_id": value.namespace_id,
                "namespace_digest": value.namespace_digest.model_dump(mode="json"),
                "namespace_count": value.namespace_count,
            }
        )
    )


def classic_compiler_path_profile_digest(
    bundle: ProjectBundle, graph: ProducerGraphDocument
) -> Digest:
    """Bind the logical source/build/toolchain seats used by compiler epochs."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "profile_id": graph.path_profile_id,
                "paths": bundle.spec.paths.model_dump(mode="json"),
            }
        )
    )


def _portable_tree_statement(
    *,
    relative_root: str,
    files: Mapping[str, CompilerSourceRead],
) -> dict[str, object]:
    """Rebuild one locked portable-tree-v1 receipt from immutable file bytes."""

    directory_children: dict[str, set[tuple[str, str]]] = defaultdict(set)
    file_by_relative: dict[str, CompilerSourceRead] = {}
    for relative, receipt in files.items():
        path = PurePosixPath(relative)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ClassicSemanticError(
                f"toolchain tree {relative_root!r} has a malformed member {relative!r}"
            )
        file_by_relative[relative] = receipt
        parent = "."
        for index, part in enumerate(path.parts):
            kind = "file" if index + 1 == len(path.parts) else "directory"
            directory_children[parent].add((part, kind))
            if kind == "directory":
                parent = part if parent == "." else f"{parent}/{part}"

    records: list[dict[str, object]] = [{"path": ".", "type": "directory"}]
    maximum_depth = 0

    def emit(directory: str, depth: int) -> None:
        nonlocal maximum_depth
        maximum_depth = max(maximum_depth, depth)
        children = sorted(
            directory_children.get(directory, set()),
            key=lambda item: (item[0].casefold(), item[0]),
        )
        folded = [name.casefold() for name, _kind in children]
        if len(folded) != len(set(folded)):
            raise ClassicSemanticError(f"toolchain tree {relative_root!r} has a casefold collision")
        for name, kind in children:
            relative = name if directory == "." else f"{directory}/{name}"
            if kind == "directory":
                records.append({"path": relative, "type": "directory"})
                emit(relative, depth + 1)
            else:
                receipt = file_by_relative.get(relative)
                if receipt is None:
                    raise AssertionError("portable-tree file receipt disappeared")
                records.append(
                    {
                        "path": relative,
                        "type": "file",
                        "executable": False,
                        "size": receipt.size,
                        "sha256": receipt.digest.value,
                    }
                )

    emit(".", 0)
    membership_records = [
        {key: value for key, value in record.items() if key != "sha256"} for record in records
    ]
    membership = hashlib.sha256(
        json.dumps(membership_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    content = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "path": relative_root,
        "entry_count": len(records),
        "max_depth": maximum_depth,
        "membership_digest": membership,
        "content_digest": content,
    }


def _toolchain_namespace_trace(
    *,
    bundle: ProjectBundle,
    reads: Sequence[CompilerSourceRead],
    node_id: str,
    epoch: str,
) -> dict[str, object]:
    toolchain_reads: dict[str, CompilerSourceRead] = {}
    for read in reads:
        if not read.reference.startswith("toolchain/"):
            continue
        relative = read.reference.removeprefix("toolchain/")
        previous = toolchain_reads.setdefault(relative.casefold(), read)
        if previous is not read:
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} repeats a toolchain namespace path"
            )
    covered: set[str] = set()
    direct_trace: list[dict[str, object]] = []
    for item in (*bundle.toolchain_lock.tools, *bundle.toolchain_lock.runtime_files):
        locked_read = toolchain_reads.get(item.path.casefold())
        if (
            locked_read is None
            or locked_read.reference != f"toolchain/{item.path}"
            or (
                locked_read.digest != item.digest
                or (item.size is not None and locked_read.size != item.size)
            )
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} omits locked toolchain file {item.path!r}"
            )
        covered.add(item.path.casefold())
        direct_trace.append(
            {
                "id": item.id,
                "path": item.path,
                "digest": item.digest.model_dump(mode="json"),
                "size": locked_read.size,
            }
        )

    tree_trace: list[dict[str, object]] = []
    tree_owners: dict[str, str] = {}
    for tree in bundle.toolchain_lock.input_trees:
        prefix = tree.path.rstrip("/") + "/"
        members: dict[str, CompilerSourceRead] = {}
        for folded, read in toolchain_reads.items():
            relative = read.reference.removeprefix("toolchain/")
            if not relative.startswith(prefix):
                continue
            member = relative[len(prefix) :]
            if not member:
                continue
            previous_owner = tree_owners.setdefault(folded, tree.id)
            if previous_owner != tree.id:
                raise ClassicSemanticError(
                    f"toolchain namespace path {relative!r} belongs to overlapping trees"
                )
            members[member] = read
            covered.add(folded)
        statement = _portable_tree_statement(
            relative_root=tree.path,
            files=members,
        )
        if (
            statement["entry_count"] != tree.entry_count
            or statement["max_depth"] != tree.max_depth
            or statement["membership_digest"] != tree.membership_digest.value
            or statement["content_digest"] != tree.content_digest.value
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} {epoch} toolchain tree {tree.id!r} "
                "differs from its locked complete namespace"
            )
        tree_trace.append({"id": tree.id, **statement})
    if set(toolchain_reads) != covered:
        raise ClassicSemanticError(
            f"compiler {node_id!r} {epoch} toolchain namespace has undeclared files: "
            f"{sorted(set(toolchain_reads) - covered)}"
        )
    return {
        "locked_files": direct_trace,
        "input_trees": tree_trace,
        "file_count": len(toolchain_reads),
    }


@dataclass(frozen=True, slots=True)
class _ValidatedCompilerNamespace:
    namespace_id: str
    namespace_digest: Digest
    member_count: int
    members_trace_digest: Digest
    source_members: Mapping[str, tuple[str, Digest, int]]
    toolchain_trace: Mapping[str, object]
    macro_mutations: frozenset[tuple[str, str]]
    sensitive_macro_mutation_origins: frozenset[tuple[str, str, str]]
    global_declaration_origins: frozenset[tuple[str, str]]


def _namespace_preprocessor_mutations(
    members: Sequence[CompilerSourceRead],
    *,
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]],
    sensitive_identifiers: frozenset[str],
) -> tuple[frozenset[tuple[str, str]], frozenset[tuple[str, str, str]]]:
    """Census all mutations and retain origins only for sensitive names."""

    result: set[tuple[str, str]] = set()
    sensitive_origins: set[tuple[str, str, str]] = set()
    for member in members:
        mutations = _payload_preprocessor_mutations(
            (member.payload,),
            prevalidated_digests=(member.digest,),
            cache=cache,
        )
        result.update(mutations)
        sensitive_origins.update(
            (member.reference, action, identifier)
            for action, identifier in mutations
            if identifier in sensitive_identifiers
        )
    return frozenset(result), frozenset(sensitive_origins)


def _toolchain_include_roots(bundle: ProjectBundle) -> tuple[str, ...]:
    """Return the exact locked trees that can supply preprocessor inputs."""

    try:
        roots = set(toolchain_profile(bundle.toolchain_lock.profile).include_roots)
    except ToolchainError:
        roots = set()
    roots.update(
        tree.path
        for tree in bundle.toolchain_lock.input_trees
        if "include" in {part.casefold() for part in PurePosixPath(tree.path).parts}
    )
    return tuple(sorted(roots, key=str.casefold))


def _compiler_namespace_toolchain_readers(
    bundle: ProjectBundle,
    evidences: Sequence[CompilerNamespaceEvidence],
) -> Mapping[str, bytes]:
    """Project complete namespaces down to locked preprocessor include trees."""

    prefixes = tuple(
        f"toolchain/{root.rstrip('/')}/".casefold()
        for root in _toolchain_include_roots(bundle)
    )
    readers: dict[str, bytes] = {}
    for evidence in evidences:
        for member in evidence.members:
            if not member.reference.casefold().startswith(prefixes):
                continue
            existing = readers.setdefault(member.reference, member.payload)
            if existing != member.payload:
                raise ClassicSemanticError(
                    f"toolchain namespace member changes between epochs: {member.reference!r}"
                )
    return MappingProxyType(readers)


def _namespace_global_declaration_origins(
    members: Sequence[CompilerSourceRead],
    *,
    bundle: ProjectBundle,
    identifiers: frozenset[str],
    cache: dict[tuple[Digest, int], frozenset[str]],
) -> frozenset[tuple[str, str]]:
    """Find generated entity spellings in every locked compiler include tree."""

    origins: set[tuple[str, str]] = set()
    if not identifiers:
        return frozenset()
    folded_roots = tuple(
        root.casefold().rstrip("/") for root in _toolchain_include_roots(bundle)
    )
    for member in members:
        if not member.reference.startswith("toolchain/"):
            continue
        relative = member.reference.removeprefix("toolchain/").casefold()
        if not any(
            relative.startswith(root + "/")
            for root in folded_roots
        ):
            continue
        key = (member.digest, member.size)
        hits = cache.get(key)
        if hits is None:
            hits = frozenset(
                token for token in _token_texts(member.payload) if token in identifiers
            )
            cache[key] = hits
        origins.update((member.reference, identifier) for identifier in hits)
    return frozenset(origins)


def _macro_capture_collisions(
    mutations: Iterable[tuple[str, str, str]],
    *,
    sensitive_identifiers: frozenset[str],
    intrinsic_source_mutations: frozenset[tuple[str, str, str]],
) -> tuple[str, ...]:
    """Find hostile mutations while admitting a record header's own guard."""

    collisions: set[str] = set()
    for reference, action, identifier in mutations:
        if identifier not in sensitive_identifiers:
            continue
        kind, separator, relative = reference.partition("/")
        if (
            separator
            and kind == "source"
            and (
                relative.casefold(),
                action,
                identifier,
            )
            in intrinsic_source_mutations
        ):
            continue
        collisions.add(identifier)
    return tuple(sorted(collisions))


def _compiler_namespace_member_trace(
    evidence: CompilerNamespaceEvidence,
) -> tuple[list[dict[str, object]], dict[str, tuple[str, Digest, int]]]:
    reads = evidence.members
    references = tuple(read.reference for read in reads)
    folded_references = {reference.casefold() for reference in references}
    if len(folded_references) != len(references) or references != tuple(
        sorted(references, key=lambda item: (item.casefold(), item))
    ):
        raise ClassicSemanticError(
            f"compiler namespace {evidence.namespace_id!r} census is not canonical"
        )
    result: list[dict[str, object]] = []
    source_members: dict[str, tuple[str, Digest, int]] = {}
    for index, raw in enumerate(reads):
        if not isinstance(raw, CompilerSourceRead):
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} is malformed"
            )
        if raw.size < 0 or raw.parent_index is not None:
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} "
                "claims observed include ancestry"
            )
        if (
            type(raw.payload) is not bytes
            or len(raw.payload) != raw.size
            or Digest.from_bytes(raw.payload) != raw.digest
        ):
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} bytes changed"
            )
        if "/" not in raw.reference:
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} member {index} has no authority"
            )
        kind, relative = raw.reference.split("/", 1)
        _relative(relative, label="compiler namespace member")
        if kind == "source":
            source_members[relative.casefold()] = (
                relative,
                raw.digest,
                raw.size,
            )
        elif kind != "toolchain":
            raise ClassicSemanticError(
                f"compiler namespace {evidence.namespace_id!r} escapes source/toolchain authority"
            )
        result.append(_compiler_namespace_member_wire(raw))
    return result, source_members


def _require_namespace_source_authority(
    namespace: _ValidatedCompilerNamespace,
    authority: Mapping[str, tuple[str, Digest, int]],
    *,
    epoch: str,
) -> None:
    if namespace.source_members != authority:
        missing = sorted(set(authority) - set(namespace.source_members))
        extra = sorted(set(namespace.source_members) - set(authority))
        changed = sorted(
            key
            for key in set(authority) & set(namespace.source_members)
            if namespace.source_members[key] != authority[key]
        )
        raise ClassicSemanticError(
            f"compiler namespace {namespace.namespace_id!r} differs from the "
            f"{epoch} source authority; missing={missing}, extra={extra}, "
            f"changed={changed}"
        )


def _validate_compiler_namespaces(
    *,
    bundle: ProjectBundle,
    evidences: Sequence[CompilerNamespaceEvidence],
    referenced_ids: frozenset[str],
    sensitive_identifiers: frozenset[str],
    global_declaration_identifiers: frozenset[str] = frozenset(),
) -> dict[str, _ValidatedCompilerNamespace]:
    indexed = _unique(evidences, lambda item: item.namespace_id, "compiler namespace")
    expected_ids = {item.casefold() for item in referenced_ids}
    if set(indexed) != expected_ids:
        missing = sorted(expected_ids - set(indexed))
        extra = sorted(set(indexed) - expected_ids)
        raise ClassicSemanticError(
            f"shared compiler namespace universe differs; missing={missing}, extra={extra}"
        )
    result: dict[str, _ValidatedCompilerNamespace] = {}
    preprocessor_cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] = {}
    identifier_cache: dict[tuple[Digest, int], frozenset[str]] = {}
    for folded, raw in indexed.items():
        if (
            not isinstance(raw, CompilerNamespaceEvidence)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", raw.namespace_id) is None
            or raw.input_evidence_kind is not CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
            or raw.namespace_digest != compiler_namespace_evidence_digest(raw)
        ):
            raise ClassicSemanticError(
                f"compiler namespace evidence {getattr(raw, 'namespace_id', None)!r} changed"
            )
        members_trace, source_members = _compiler_namespace_member_trace(raw)
        toolchain_trace = _toolchain_namespace_trace(
            bundle=bundle,
            reads=raw.members,
            node_id=raw.namespace_id,
            epoch="shared",
        )
        macro_mutations, sensitive_macro_mutation_origins = _namespace_preprocessor_mutations(
            raw.members,
            cache=preprocessor_cache,
            sensitive_identifiers=sensitive_identifiers,
        )
        global_declaration_origins = _namespace_global_declaration_origins(
            raw.members,
            bundle=bundle,
            identifiers=global_declaration_identifiers,
            cache=identifier_cache,
        )
        if global_declaration_origins:
            raise ClassicSemanticError(
                "generated global declaration identifier already exists in the readable "
                f"toolchain namespace: {sorted(global_declaration_origins)}"
            )
        result[folded] = _ValidatedCompilerNamespace(
            raw.namespace_id,
            raw.namespace_digest,
            len(raw.members),
            Digest.from_bytes(canonical_json(members_trace)),
            MappingProxyType(source_members),
            MappingProxyType(toolchain_trace),
            macro_mutations,
            sensitive_macro_mutation_origins,
            global_declaration_origins,
        )
    return result


def _validate_compiler_invocation(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    invocation: CompilerEpochInvocation,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
    epoch: str,
) -> Digest:
    compiler_tools = [tool for tool in bundle.toolchain_lock.tools if "compiler" in tool.roles]
    if len(compiler_tools) != 1:
        raise ClassicSemanticError("toolchain does not lock exactly one compiler")
    tool = compiler_tools[0]
    expected_path_profile = classic_compiler_path_profile_digest(bundle, graph)
    namespace = namespaces.get(invocation.namespace_id.casefold())
    if (
        invocation.input_evidence_kind is not CompilerInputEvidenceKind.COMPLETE_READABLE_NAMESPACE
        or namespace is None
        or invocation.namespace_id != namespace.namespace_id
        or invocation.namespace_digest != namespace.namespace_digest
        or invocation.namespace_count != namespace.member_count
        or invocation.tool_id != tool.id
        or invocation.tool_digest != tool.digest
        or invocation.arguments != node.arguments
        or invocation.working_directory != bundle.spec.paths.build
        or invocation.path_profile_digest != expected_path_profile
        or invocation.invocation_digest != compiler_epoch_invocation_digest(invocation)
    ):
        raise ClassicSemanticError(
            f"compiler {node.id!r} {epoch} invocation differs from its locked graph"
        )
    return expected_path_profile


def _counterfactual_compiler_congruence_trace(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    audit: ProjectOverlayCounterfactualAudit,
    effective_invocation: CompilerEpochInvocation,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
) -> dict[str, object]:
    counterfactual_invocation = audit.counterfactual_invocation
    if not isinstance(counterfactual_invocation, CompilerEpochInvocation):
        raise ClassicSemanticError(
            f"compiler {node.id!r} lacks its declaration-counterfactual invocation"
        )
    expected_path_profile: Digest | None = None
    for epoch, invocation in (
        ("declaration-counterfactual", counterfactual_invocation),
        ("effective", effective_invocation),
    ):
        expected_path_profile = _validate_compiler_invocation(
            bundle=bundle,
            graph=graph,
            node=node,
            invocation=invocation,
            namespaces=namespaces,
            epoch=epoch,
        )
    if expected_path_profile is None:
        raise AssertionError("compiler invocation validation did not run")
    if _compiler_epoch_command_statement(
        counterfactual_invocation
    ) != _compiler_epoch_command_statement(effective_invocation):
        raise ClassicSemanticError(
            f"compiler {node.id!r} counterfactual/effective invocation differs"
        )
    return {
        "input_evidence_kind": counterfactual_invocation.input_evidence_kind.value,
        "counterfactual_invocation_digest": (
            counterfactual_invocation.invocation_digest.model_dump(mode="json")
        ),
        "effective_invocation_digest": effective_invocation.invocation_digest.model_dump(
            mode="json"
        ),
        "tool": {
            "id": counterfactual_invocation.tool_id,
            "digest": counterfactual_invocation.tool_digest.model_dump(mode="json"),
        },
        "arguments_digest": Digest.from_bytes(canonical_json(list(node.arguments))).model_dump(
            mode="json"
        ),
        "working_directory": bundle.spec.paths.build,
        "environment_digest": counterfactual_invocation.environment_digest.model_dump(
            mode="json"
        ),
        "path_profile_digest": expected_path_profile.model_dump(mode="json"),
        "counterfactual_namespace": {
            "id": counterfactual_invocation.namespace_id,
            "digest": counterfactual_invocation.namespace_digest.model_dump(mode="json"),
            "count": counterfactual_invocation.namespace_count,
        },
        "effective_namespace": {
            "id": effective_invocation.namespace_id,
            "digest": effective_invocation.namespace_digest.model_dump(mode="json"),
            "count": effective_invocation.namespace_count,
        },
    }


def _project_compiler_audit_trace(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    products: Mapping[str, CompilerProduct],
    audits: Mapping[str, ProjectOverlayCounterfactualAudit],
    source_pairs: Mapping[str, ProjectOverlaySourcePair],
    clean_sources: Mapping[str, CleanSourceInput],
    generated_tus: frozenset[str],
    source_validation: _OverlaySourceValidation,
    namespace_evidences: Sequence[CompilerNamespaceEvidence],
    counterfactual_namespace_id: str,
) -> tuple[
    dict[str, _CoffObject],
    dict[str, _CoffObject],
    dict[str, frozenset[int]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    graph_compilers = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    generated_tu_folded = {path.casefold() for path in generated_tus}
    _require_no_compiler_macro_capture(
        graph_compilers.values(),
        source_validation.macro_sensitive_identifiers,
    )
    ordinary_ids = {
        node_id
        for node_id, node in graph_compilers.items()
        if _compiler_shape(node)[0].removeprefix("source/").casefold()
        not in generated_tu_folded
    }
    generated_ids = set(graph_compilers) - ordinary_ids
    planned_audits = {
        node_id.casefold() for node_id in source_validation.compiler_epoch_plan.audit_node_ids
    }
    if set(audits) != planned_audits:
        missing = sorted(planned_audits - set(audits))
        extra = sorted(set(audits) - planned_audits)
        raise ClassicSemanticError(
            "declaration-counterfactual compiler audit universe differs; "
            f"missing={missing}, extra={extra}"
        )
    product_invocations: dict[str, CompilerEpochInvocation] = {}
    for node_id in graph_compilers:
        product = products.get(node_id.casefold())
        if not isinstance(product, CompilerProduct) or not isinstance(
            product.compiler_invocation, CompilerEpochInvocation
        ):
            raise ClassicSemanticError(
                f"compiler {node_id!r} lacks its effective namespace invocation evidence"
            )
        product_invocations[node_id] = product.compiler_invocation
    invocations = [
        invocation
        for audit in audits.values()
        for invocation in (audit.counterfactual_invocation,)
        if isinstance(invocation, CompilerEpochInvocation)
    ] + list(product_invocations.values())
    referenced_namespace_ids = frozenset(
        [counterfactual_namespace_id, *(invocation.namespace_id for invocation in invocations)]
    )
    namespaces = _validate_compiler_namespaces(
        bundle=bundle,
        evidences=namespace_evidences,
        referenced_ids=referenced_namespace_ids,
        sensitive_identifiers=source_validation.macro_sensitive_identifiers,
        global_declaration_identifiers=(
            source_validation.global_declaration_identifiers
        ),
    )
    clean_authority = {
        item.path.casefold(): (
            item.path,
            Digest.from_bytes(item.payload),
            len(item.payload),
        )
        for item in clean_sources.values()
    }
    effective_authority = dict(clean_authority)
    for pair in source_pairs.values():
        if pair.path.casefold() in generated_tu_folded:
            continue
        effective_authority[pair.path.casefold()] = (
            pair.path,
            Digest.from_bytes(pair.effective_payload),
            len(pair.effective_payload),
        )
    generated_authority = dict(clean_authority)
    for pair in source_pairs.values():
        generated_authority[pair.path.casefold()] = (
            pair.path,
            Digest.from_bytes(pair.effective_payload),
            len(pair.effective_payload),
        )
    counterfactual_authority = dict(clean_authority)
    for path, payload in source_validation.compiler_epoch_plan.declaration_outputs.items():
        counterfactual_authority[path.casefold()] = (
            path,
            Digest.from_bytes(payload),
            len(payload),
        )
    counterfactual_id = counterfactual_namespace_id.casefold()
    if counterfactual_id not in namespaces:
        raise ClassicSemanticError(
            "declaration-counterfactual namespace evidence is absent"
        )
    _require_namespace_source_authority(
        namespaces[counterfactual_id],
        counterfactual_authority,
        epoch="declaration-counterfactual",
    )

    epoch_bindings: set[tuple[str, str]] = {
        ("declaration-counterfactual", counterfactual_id)
    }
    for node_id, invocation in product_invocations.items():
        epoch = "generated" if node_id in generated_ids else "effective"
        epoch_bindings.add((epoch, invocation.namespace_id.casefold()))
        _validate_compiler_invocation(
            bundle=bundle,
            graph=graph,
            node=graph_compilers[node_id],
            invocation=invocation,
            namespaces=namespaces,
            epoch=epoch,
        )
        _require_namespace_source_authority(
            namespaces[invocation.namespace_id.casefold()],
            generated_authority if epoch == "generated" else effective_authority,
            epoch=epoch,
        )
    effective_namespace_ids = {
        product_invocations[node_id].namespace_id.casefold() for node_id in ordinary_ids
    }
    for effective_id in effective_namespace_ids:
        if set(namespaces[counterfactual_id].source_members) != set(
            namespaces[effective_id].source_members
        ):
            raise ClassicSemanticError(
                "counterfactual/effective compiler source namespace path universe differs"
            )
    for audit in audits.values():
        audit_invocation = audit.counterfactual_invocation
        if not isinstance(audit_invocation, CompilerEpochInvocation) or (
            audit_invocation.namespace_id.casefold() != counterfactual_id
        ):
            raise ClassicSemanticError(
                f"compiler {audit.node_id!r} has the wrong counterfactual namespace"
            )
    sensitive_macro_mutation_origins = frozenset(
        mutation
        for namespace in namespaces.values()
        for mutation in namespace.sensitive_macro_mutation_origins
    )
    macro_collisions = _macro_capture_collisions(
        sensitive_macro_mutation_origins,
        sensitive_identifiers=source_validation.macro_sensitive_identifiers,
        intrinsic_source_mutations=source_validation.intrinsic_macro_mutations,
    )
    if macro_collisions:
        raise ClassicSemanticError(
            "shared compiler namespace can macro-capture source-overlay identifiers; "
            f"read_definitions={macro_collisions}"
        )
    namespace_trace = [
        {
            "namespace_id": namespace.namespace_id,
            "namespace_digest": namespace.namespace_digest.model_dump(mode="json"),
            "member_count": namespace.member_count,
            "members_trace_digest": namespace.members_trace_digest.model_dump(mode="json"),
            "source_count": len(namespace.source_members),
            "epochs": sorted(
                epoch
                for epoch, namespace_id in epoch_bindings
                if namespace_id == namespace.namespace_id.casefold()
            ),
            "generated_compiler_nodes": sorted(
                node_id
                for node_id, invocation in product_invocations.items()
                if node_id in generated_ids
                if invocation.namespace_id.casefold() == namespace.namespace_id.casefold()
            ),
            "effective_compiler_nodes": sorted(
                node_id
                for node_id, invocation in product_invocations.items()
                if node_id in ordinary_ids
                if invocation.namespace_id.casefold() == namespace.namespace_id.casefold()
            ),
            "toolchain_namespace": namespace.toolchain_trace,
            "preprocessor_census_digest": Digest.from_bytes(
                canonical_json([list(item) for item in sorted(namespace.macro_mutations)])
            ).model_dump(mode="json"),
            "preprocessor_sensitive_origin_census_digest": Digest.from_bytes(
                canonical_json(
                    [
                        list(item)
                        for item in sorted(
                            namespace.sensitive_macro_mutation_origins,
                            key=lambda item: (
                                item[0].casefold(),
                                item[0],
                                item[1],
                                item[2],
                            ),
                        )
                    ]
                )
            ).model_dump(mode="json"),
            "global_declaration_toolchain_origin_census_digest": Digest.from_bytes(
                canonical_json(
                    [list(item) for item in sorted(namespace.global_declaration_origins)]
                )
            ).model_dump(mode="json"),
        }
        for namespace in sorted(namespaces.values(), key=lambda item: item.namespace_id.casefold())
    ]
    counterfactual_objects: dict[str, _CoffObject] = {}
    effective_objects: dict[str, _CoffObject] = {}
    helper_sections: dict[str, frozenset[int]] = {}
    trace: list[dict[str, object]] = []
    for node_id in sorted(ordinary_ids, key=str.casefold):
        product = products[node_id.casefold()]
        if not isinstance(product, CompilerProduct):
            raise ClassicSemanticError(f"effective compiler product changed: {node_id!r}")
        effective_objects[node_id] = _parse_coff(
            product.payload,
            f"effective:{product.object_ref}",
        )
    for node_id in sorted(source_validation.compiler_epoch_plan.audit_node_ids, key=str.casefold):
        node = graph_compilers[node_id]
        source_ref, object_ref = _compiler_shape(node)
        raw_audit = audits[node_id.casefold()]
        raw_product = products[node_id.casefold()]
        if not isinstance(raw_audit, ProjectOverlayCounterfactualAudit) or (
            raw_audit.node_id != node_id
            or raw_audit.source_ref != source_ref
            or raw_audit.object_ref != object_ref
            or type(raw_audit.counterfactual_payload) is not bytes
            or not raw_audit.counterfactual_payload
        ):
            raise ClassicSemanticError(
                f"declaration-counterfactual compiler audit changed: {node_id!r}"
            )
        if not isinstance(raw_product, CompilerProduct):
            raise ClassicSemanticError(f"effective compiler product changed: {node_id!r}")
        counterfactual = _parse_coff(
            raw_audit.counterfactual_payload,
            f"counterfactual:{object_ref}",
        )
        effective = effective_objects[node_id]
        counterfactual_objects[node_id] = counterfactual
        relative = source_ref.removeprefix("source/")
        helpers = source_validation.helpers_by_source.get(relative.casefold(), ())
        excluded: frozenset[int] = frozenset()
        extra_definitions: frozenset[str] = frozenset()
        if helpers:
            excluded, extra_definitions = _helper_delta_sections(
                clean=counterfactual,
                effective=effective,
                helper_identifiers=helpers,
            )
            helper_sections[node_id] = excluded
        effective_invocation = raw_product.compiler_invocation
        if not isinstance(effective_invocation, CompilerEpochInvocation):
            raise ClassicSemanticError(
                f"effective compiler {node_id!r} lacks invocation evidence"
            )
        invocation_trace = _counterfactual_compiler_congruence_trace(
            bundle=bundle,
            graph=graph,
            node=node,
            audit=raw_audit,
            effective_invocation=effective_invocation,
            namespaces=namespaces,
        )
        projection_required = (
            node_id in source_validation.compiler_epoch_plan.runtime_projection_node_ids
        )
        counterfactual_projection = _runtime_projection(counterfactual)
        effective_projection = _runtime_projection(effective, excluded_sections=excluded)
        projection_equal = counterfactual_projection == effective_projection
        if projection_required and not projection_equal:
            raise ClassicSemanticError(
                f"effective compiler {node_id!r} changes runtime state for a "
                "source operation without a closed theorem"
            )
        coff_trace = _coff_compiler_congruence_trace(
            counterfactual,
            effective,
            excluded_effective_sections=excluded,
        )
        trace.append(
            {
                "node_id": node_id,
                "source_ref": source_ref,
                "object_ref": object_ref,
                "counterfactual_digest": counterfactual.digest.value,
                "counterfactual_size": len(raw_audit.counterfactual_payload),
                "counterfactual_object": {
                    "digest": counterfactual.digest.model_dump(mode="json"),
                    "size": len(raw_audit.counterfactual_payload),
                },
                "effective_digest": effective.digest.value,
                "effective_size": len(raw_product.payload),
                "effective_object": {
                    "digest": effective.digest.model_dump(mode="json"),
                    "size": len(raw_product.payload),
                },
                "runtime_projection_required": projection_required,
                "runtime_projection_equal": projection_equal,
                "compiler_congruence": invocation_trace,
                "coff_semantic_theorem": coff_trace,
                "helper_sections": sorted(excluded),
                "helper_definitions": sorted(extra_definitions),
            }
        )
    return (
        counterfactual_objects,
        effective_objects,
        helper_sections,
        trace,
        namespace_trace,
    )


def validate_project_overlay_compiler_epoch(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    compiler_products: Sequence[CompilerProduct],
    project_source_pairs: Sequence[ProjectOverlaySourcePair],
    counterfactual_compiler_audits: Sequence[ProjectOverlayCounterfactualAudit],
    counterfactual_namespace_id: str,
    clean_source_inputs: Sequence[CleanSourceInput],
    compiler_namespaces: Sequence[CompilerNamespaceEvidence],
) -> Mapping[str, object]:
    """Fail fast on the independently derived project-overlay compiler theorem.

    This preflight intentionally recomputes the source plan instead of trusting
    the runtime's execution plan.  It validates every effective invocation and
    only compares object payloads for the exact sparse counterfactual audit set.
    The complete overlay proof repeats these checks after composition/linking.
    """

    plan, validation, generated_tus = _derive_project_overlay_compiler_epoch(
        bundle,
        graph,
        project_source_pairs,
        clean_source_inputs,
        secondary_reader_payloads=_compiler_namespace_toolchain_readers(
            bundle, compiler_namespaces
        ),
    )
    if validation is None:
        raise ClassicSemanticError("compiler epoch preflight requires a project overlay")
    products = _unique(compiler_products, lambda item: item.node_id, "compiler product")
    graph_compiler_ids = {
        node.id.casefold() for node in graph.nodes if node.role is ProducerRole.COMPILER
    }
    if set(products) != graph_compiler_ids:
        missing = sorted(graph_compiler_ids - set(products))
        extra = sorted(set(products) - graph_compiler_ids)
        raise ClassicSemanticError(
            "compiler epoch preflight product universe differs; "
            f"missing={missing}, extra={extra}"
        )
    audits = _unique(
        counterfactual_compiler_audits,
        lambda item: item.node_id,
        "declaration-counterfactual compiler audit",
    )
    (
        _counterfactual_objects,
        _effective_objects,
        _helper_sections,
        compiler_audit_trace,
        compiler_namespace_trace,
    ) = _project_compiler_audit_trace(
        bundle=bundle,
        graph=graph,
        products={
            key: value
            for key, value in products.items()
            if isinstance(value, CompilerProduct)
        },
        audits={
            key: value
            for key, value in audits.items()
            if isinstance(value, ProjectOverlayCounterfactualAudit)
        },
        source_pairs={item.path.casefold(): item for item in project_source_pairs},
        clean_sources={item.path.casefold(): item for item in clean_source_inputs},
        generated_tus=generated_tus,
        source_validation=validation,
        namespace_evidences=compiler_namespaces,
        counterfactual_namespace_id=counterfactual_namespace_id,
    )
    return MappingProxyType(
        {
            "schema": 1,
            "theorem": "sparse-project-overlay-compiler-epoch-preflight-v1",
            "counterfactual_output_count": len(plan.declaration_outputs),
            "audit_node_ids": sorted(plan.audit_node_ids, key=str.casefold),
            "runtime_projection_node_ids": sorted(
                plan.runtime_projection_node_ids,
                key=str.casefold,
            ),
            "compiler_audits": compiler_audit_trace,
            "compiler_namespaces": compiler_namespace_trace,
        }
    )


def _helper_isolation_trace(
    *,
    target: TargetLinkClosure,
    products: Mapping[str, CompilerProduct],
    counterfactual_objects: Mapping[str, _CoffObject],
    effective_objects: Mapping[str, _CoffObject],
    helper_sections: Mapping[str, frozenset[int]],
) -> dict[str, object]:
    target_helpers = {
        node_id: helper_sections[node_id]
        for node_id in target.compiler_node_ids
        if node_id in helper_sections
    }
    if not target_helpers:
        return {
            "target": target.target_id,
            "helper_objects": [],
            "unique_unreferenced_definitions": [],
        }
    archive_objects, import_objects, archive_trace = _archive_semantics(
        target,
        compiler_digests=frozenset(
            Digest.from_bytes(products[node_id].payload) for node_id in target.compiler_node_ids
        ),
        carrier_digests=frozenset(),
    )
    baseline_references: set[str] = set()
    baseline_definitions: set[str] = set()
    baseline_libraries: set[str] = set()
    baseline_directive_roots: set[str] = set()
    for node_id in target.compiler_node_ids:
        baseline = counterfactual_objects.get(node_id, effective_objects.get(node_id))
        if baseline is None:
            continue
        baseline_references.update(_external_references(baseline))
        baseline_definitions.update(_external_definitions(baseline))
        baseline_libraries.update(_default_libraries_for_ordinary(baseline))
        baseline_directives = _coff_directive_receipt(baseline)
        baseline_directive_roots.update(baseline_directives.include_symbols)
        baseline_directive_roots.update(baseline_directives.export_symbols)
    for archive in archive_objects:
        baseline_references.update(_external_references(archive))
        baseline_definitions.update(_external_definitions(archive))
        baseline_libraries.update(_default_libraries_for_ordinary(archive))
        archive_directives = _coff_directive_receipt(archive)
        baseline_directive_roots.update(archive_directives.include_symbols)
        baseline_directive_roots.update(archive_directives.export_symbols)
    import_definitions = {definition for item in import_objects for definition in item.definitions}

    helper_definitions: set[str] = set()
    helper_references: set[str] = set()
    helper_libraries: set[str] = set()
    inbound_references: set[str] = set()
    helper_objects_trace: list[dict[str, object]] = []
    helper_control_roots: set[str] = set()
    for node_id in target.compiler_node_ids:
        if node_id in target_helpers:
            continue
        effective = effective_objects.get(node_id)
        if effective is not None:
            inbound_references.update(_external_references(effective))
    for node_id, excluded in sorted(target_helpers.items()):
        effective = effective_objects[node_id]
        counterfactual = counterfactual_objects[node_id]
        definitions = _external_definitions(effective)
        names = {name for name, section in definitions.items() if section.number in excluded}
        if not names:
            raise ClassicSemanticError(f"helper compiler {node_id!r} has no definitions")
        helper_definitions.update(names)
        for section in effective.sections:
            if section.number in excluded:
                folded = section.name.casefold()
                if any(folded.startswith(prefix) for prefix in _FORBIDDEN_RUNTIME_SECTION_PREFIXES):
                    raise ClassicSemanticError(
                        f"helper compiler {node_id!r} introduces runtime-root section "
                        f"{section.name!r}"
                    )
                helper_references.update(
                    relocation.target
                    for relocation in section.relocations
                    if relocation.target_section == 0 and relocation.target_storage in {2, 105}
                )
            else:
                inbound_references.update(
                    relocation.target
                    for relocation in section.relocations
                    if relocation.target_section == 0
                )
        helper_libraries.update(_default_libraries_for_ordinary(effective))
        counterfactual_directives = _coff_directive_receipt(counterfactual)
        effective_directives = _coff_directive_receipt(effective)
        helper_control_roots.update(
            set(effective_directives.include_symbols)
            - set(counterfactual_directives.include_symbols)
        )
        helper_control_roots.update(
            set(effective_directives.export_symbols)
            - set(counterfactual_directives.export_symbols)
        )
        helper_objects_trace.append(
            {
                "node_id": node_id,
                "object_digest": effective.digest.value,
                "sections": sorted(excluded),
                "definitions": sorted(names),
            }
        )

    inbound_references.update(
        reference for archive in archive_objects for reference in _external_references(archive)
    )
    imported_collisions = helper_definitions & import_definitions
    if imported_collisions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers collide with imports: "
            f"{sorted(imported_collisions)}"
        )
    if helper_control_roots:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add rooted linker controls: "
            f"{sorted(helper_control_roots)}"
        )
    roots = set(target.root_symbols) | baseline_directive_roots
    if roots & helper_definitions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} roots helper definitions: "
            f"{sorted(roots & helper_definitions)}"
        )
    inbound = helper_definitions & inbound_references
    if inbound:
        raise ClassicSemanticError(
            f"target {target.target_id!r} has inbound helper references: {sorted(inbound)}"
        )
    novel_dependencies = (
        helper_references
        - baseline_references
        - baseline_definitions
        - helper_definitions
        - import_definitions
    )
    if novel_dependencies:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add external dependencies: "
            f"{sorted(novel_dependencies)}"
        )
    novel_libraries = helper_libraries - baseline_libraries
    if novel_libraries:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add default libraries: {sorted(novel_libraries)}"
        )
    return {
        "target": target.target_id,
        "helper_objects": helper_objects_trace,
        "unique_unreferenced_definitions": sorted(helper_definitions),
        "existing_external_dependencies": sorted(helper_references),
        "existing_default_libraries": sorted(helper_libraries),
        "archives": archive_trace,
    }


def prove_source_overlay_semantics(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    snapshot: OverlaySemanticSnapshot,
    *,
    semantic_contracts: Mapping[ClassicRecipeFamily, SemanticValidatorContract],
) -> OverlaySemanticValidation:
    """Prove every source-overlay intervention in one current-run snapshot.

    This function performs no I/O.  The classic executor must build the
    snapshot from immutable bytes while the private logical-path runtime is
    still sealed.
    """

    if snapshot.run_binding != overlay_semantic_run_binding(graph, snapshot):
        raise ClassicSemanticError("semantic snapshot differs from its run binding")

    overlays = _overlay_interventions(bundle)
    if not overlays:
        return OverlaySemanticValidation(MappingProxyType({}), MappingProxyType({}))
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicSemanticError("source-overlay proof requires a complete source manifest")

    primary = _unique(snapshot.primary_sources, lambda item: item.path, "primary source")
    effective = _unique(snapshot.effective_outputs, lambda item: item.path, "effective output")
    products = _unique(snapshot.compiler_products, lambda item: item.node_id, "compiler product")
    closures = _unique(snapshot.link_closures, lambda item: item.target_id, "link closure")
    source_pairs = _unique(
        snapshot.project_source_pairs, lambda item: item.path, "project overlay source pair"
    )
    counterfactual_audits = _unique(
        snapshot.counterfactual_compiler_audits,
        lambda item: item.node_id,
        "declaration-counterfactual compiler audit",
    )
    manifest_by_path = {item.path.casefold(): item for item in manifest.entries}
    interventions = {item.id: item for item in bundle.interventions}
    certified_primary = any(
        item.origin is PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
        for item in snapshot.primary_sources
    )
    certified_evidence = bool(
        snapshot.project_source_pairs
        or snapshot.counterfactual_compiler_audits
        or snapshot.counterfactual_namespace_id is not None
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    )
    if certified_primary != certified_evidence:
        raise ClassicSemanticError(
            "certified project-overlay origin and counterfactual evidence must appear together"
        )
    if certified_primary:
        if (
            not isinstance(snapshot.counterfactual_namespace_id, str)
            or not snapshot.counterfactual_namespace_id
        ):
            raise ClassicSemanticError(
                "certified project overlay lacks its counterfactual namespace identity"
            )
    elif snapshot.counterfactual_namespace_id is not None:
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot name a counterfactual namespace"
        )

    graph_compilers = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    if set(products) != {item.casefold() for item in graph_compilers}:
        raise ClassicSemanticError("compiler products do not exactly cover the producer graph")
    for raw_product in products.values():
        product = raw_product
        if not isinstance(product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        source_ref, object_ref = _compiler_shape(graph_compilers[product.node_id])
        if product.source_ref != source_ref or product.object_ref != object_ref:
            raise ClassicSemanticError(
                f"compiler product {product.node_id!r} differs from committed graph paths"
            )
        if not product.payload:
            raise ClassicSemanticError(f"compiler product {product.node_id!r} is empty")

    all_output_paths: set[str] = set()
    all_generated_paths: set[str] = set()
    all_generated_inputs: set[str] = set()
    carrier_input_seals: dict[str, tuple[str, ...]] = {}
    output_owner: dict[str, str] = {}
    declaration_by_id: dict[
        str,
        tuple[
            dict[str, dict[str, object]],
            frozenset[str],
            frozenset[str],
        ],
    ] = {}
    for overlay in overlays:
        overlay_declaration = _overlay_declaration(overlay)
        declaration_by_id[overlay.id] = overlay_declaration
        paths, generated, generated_inputs = overlay_declaration
        overlap = {item.casefold() for item in paths} & {
            item.casefold() for item in all_output_paths
        }
        if overlap:
            raise ClassicSemanticError(f"overlay outputs overlap: {sorted(overlap)}")
        all_output_paths.update(paths)
        all_generated_paths.update(generated)
        all_generated_inputs.update(generated_inputs)
        generated_seal = tuple(sorted(generated_inputs, key=str.casefold))
        for carrier_path in generated:
            carrier_input_seals[carrier_path.casefold()] = generated_seal
        output_owner.update({path.casefold(): overlay.scope.target for path in paths})

    clean_sources: dict[str, CleanSourceInput] = {}
    semantic_clean_sources: dict[str, CleanSourceInput] = {}
    source_validation: _OverlaySourceValidation | None = None
    if certified_primary:
        if set(source_pairs) != {path.casefold() for path in all_output_paths}:
            missing = sorted({path.casefold() for path in all_output_paths} - set(source_pairs))
            extra = sorted(set(source_pairs) - {path.casefold() for path in all_output_paths})
            raise ClassicSemanticError(
                f"project overlay source-pair universe differs; missing={missing}, extra={extra}"
            )
        clean_sources = _clean_source_authority(bundle, snapshot)
        semantic_clean_sources = dict(clean_sources)
        for overlay in overlays:
            outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
            for path, declaration in outputs.items():
                raw_pair = source_pairs[path.casefold()]
                if not isinstance(raw_pair, ProjectOverlaySourcePair) or raw_pair.path != path:
                    raise ClassicSemanticError(f"project overlay source pair changed: {path!r}")
                if (
                    Digest.from_bytes(raw_pair.effective_payload).value != declaration["effective"]
                    or len(raw_pair.effective_payload) != declaration["size"]
                ):
                    raise ClassicSemanticError(
                        f"project overlay effective source changed: {path!r}"
                    )
                if path in generated_inputs:
                    if raw_pair.clean_payload is not None:
                        raise ClassicSemanticError(
                            f"generated overlay source has a clean preimage: {path!r}"
                        )
                else:
                    clean = clean_sources.get(path.casefold())
                    if (
                        clean is None
                        or raw_pair.clean_payload != clean.payload
                        or declaration.get("clean") != Digest.from_bytes(clean.payload).value
                    ):
                        raise ClassicSemanticError(
                            f"project overlay clean preimage changed: {path!r}"
                        )
        source_validation = _validate_project_overlay_sources(
            overlays=overlays,
            graph=graph,
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=semantic_clean_sources,
            declaration_by_id=declaration_by_id,
            secondary_reader_payloads=_compiler_namespace_toolchain_readers(
                bundle, snapshot.compiler_namespaces
            ),
        )
    elif (
        source_pairs
        or counterfactual_audits
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    ):
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot carry project-overlay epoch evidence"
        )

    expected_primary = set(manifest_by_path) | {item.casefold() for item in all_generated_inputs}
    if set(primary) != expected_primary:
        missing = sorted(expected_primary - set(primary))
        extra = sorted(set(primary) - expected_primary)
        raise ClassicSemanticError(
            f"primary source seat is not closed; missing={missing}, extra={extra}"
        )
    if set(effective) != {item.casefold() for item in all_output_paths}:
        raise ClassicSemanticError("effective output receipts do not exactly cover overlays")

    for folded, raw_receipt in primary.items():
        receipt = raw_receipt
        if not isinstance(receipt, SourceInputReceipt):
            raise AssertionError("primary source index has an invalid value")
        _relative(receipt.path, label="primary source path")
        if receipt.size < 0:
            raise ClassicSemanticError(f"primary source {receipt.path!r} has invalid size")
        manifest_entry = manifest_by_path.get(folded)
        declared_output = next(
            (
                declaration
                for outputs, _generated, _inputs in declaration_by_id.values()
                for path, declaration in outputs.items()
                if path.casefold() == folded
            ),
            None,
        )
        if manifest_entry is not None:
            if certified_primary and declared_output is not None:
                if (
                    receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    or receipt.digest.value != declared_output["effective"]
                    or receipt.size != declared_output["size"]
                ):
                    raise ClassicSemanticError(
                        f"primary source {receipt.path!r} is not a certified project overlay"
                    )
            elif receipt.origin is not PrimarySourceOrigin.CLEAN_MANIFEST or (
                receipt.digest != manifest_entry.digest or receipt.size != manifest_entry.size
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not the clean manifest input"
                )
        elif receipt.path in all_generated_paths:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier TU"
                )
        elif certified_primary and receipt.path in all_generated_inputs:
            if (
                receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                or not isinstance(declared_output, dict)
                or receipt.digest.value != declared_output["effective"]
                or receipt.size != declared_output["size"]
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a certified generated header"
                )
        elif receipt.path in all_generated_inputs:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier input"
                )
        else:
            raise ClassicSemanticError(
                f"primary source {receipt.path!r} is an unclassified effective input"
            )

    for overlay in overlays:
        outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
        for path, output_declaration in outputs.items():
            effective_receipt = effective[path.casefold()]
            if (
                effective_receipt.digest.value != output_declaration["effective"]
                or effective_receipt.size != output_declaration["size"]
            ):
                raise ClassicSemanticError(f"effective overlay output changed: {path!r}")
            clean_value = output_declaration.get("clean")
            manifest_entry = manifest_by_path.get(path.casefold())
            if path in generated_inputs:
                primary_receipt = primary[path.casefold()]
                if not isinstance(primary_receipt, SourceInputReceipt):
                    raise AssertionError("carrier source index has an invalid value")
                expected_origin = (
                    PrimarySourceOrigin.GENERATED_CARRIER
                    if path in all_generated_paths
                    else PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    if certified_primary
                    else PrimarySourceOrigin.GENERATED_CARRIER
                )
                if (
                    primary_receipt.origin is not expected_origin
                    or primary_receipt.digest != effective_receipt.digest
                    or primary_receipt.size != effective_receipt.size
                ):
                    raise ClassicSemanticError(f"generated carrier changed: {path!r}")
            elif manifest_entry is None or clean_value != manifest_entry.digest.value:
                raise ClassicSemanticError(
                    f"ordinary overlay {path!r} lacks its exact clean manifest preimage"
                )

    compiler_by_source: dict[str, list[CompilerProduct]] = defaultdict(list)
    for raw_product in products.values():
        if not isinstance(raw_product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        kind, relative = raw_product.source_ref.split("/", 1)
        if kind != "source":
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} reads a non-source primary input"
            )
        source_receipt = primary.get(relative.casefold())
        if source_receipt is None:
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} source is absent from primary seal"
            )
        normalized_generated_inputs = tuple(
            _relative(item, label="compiler generated-input path")
            for item in raw_product.generated_inputs
        )
        if normalized_generated_inputs != tuple(
            sorted(set(normalized_generated_inputs), key=str.casefold)
        ):
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} generated-input seal is not canonical"
            )
        expected_generated_inputs = carrier_input_seals.get(relative.casefold())
        if expected_generated_inputs is None:
            expected_generated_inputs = (
                tuple(sorted(source_validation.generated_headers, key=str.casefold))
                if source_validation is not None
                else ()
            )
        if normalized_generated_inputs != expected_generated_inputs:
            if relative.casefold() in carrier_input_seals:
                raise ClassicSemanticError(
                    f"carrier compiler {raw_product.node_id!r} lacks its exact generated epoch"
                )
            raise ClassicSemanticError(
                f"ordinary compiler {raw_product.node_id!r} has the wrong generated-header epoch"
            )
        compiler_by_source[relative.casefold()].append(raw_product)

    counterfactual_objects: dict[str, _CoffObject] = {}
    effective_objects: dict[str, _CoffObject] = {}
    helper_sections: dict[str, frozenset[int]] = {}
    compiler_audit_trace: list[dict[str, object]] = []
    compiler_namespace_trace: list[dict[str, object]] = []
    if source_validation is not None:
        (
            counterfactual_objects,
            effective_objects,
            helper_sections,
            compiler_audit_trace,
            compiler_namespace_trace,
        ) = _project_compiler_audit_trace(
            bundle=bundle,
            graph=graph,
            products={
                value.node_id.casefold(): value
                for value in products.values()
                if isinstance(value, CompilerProduct)
            },
            audits={
                value.node_id.casefold(): value
                for value in counterfactual_audits.values()
                if isinstance(value, ProjectOverlayCounterfactualAudit)
            },
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=clean_sources,
            generated_tus=frozenset(all_generated_paths),
            source_validation=source_validation,
            namespace_evidences=snapshot.compiler_namespaces,
            counterfactual_namespace_id=(
                snapshot.counterfactual_namespace_id
                if isinstance(snapshot.counterfactual_namespace_id, str)
                else ""
            ),
        )

    lanes_by_target: dict[str, list[DonorSemanticLane]] = defaultdict(list)
    lane_inputs: set[tuple[str, str]] = set()
    for lane in snapshot.donor_lanes:
        if (
            tuple(
                sorted(
                    lane.overlay_inputs,
                    key=lambda item: (item.path.casefold(), item.digest.value),
                )
            )
            != lane.overlay_inputs
        ):
            raise ClassicSemanticError(
                f"donor lane {lane.donor_intervention_id!r} inputs are not canonical"
            )
        donor = interventions.get(lane.donor_intervention_id)
        consumer = interventions.get(lane.consumer_intervention_id)
        if not isinstance(donor, ClassicRecipeIntervention) or (
            donor.role is not ClassicRecipeRole.DONOR
        ):
            raise ClassicSemanticError(
                f"donor lane names invalid intervention {lane.donor_intervention_id!r}"
            )
        if not isinstance(consumer, ClassicRecipeIntervention) or (
            consumer.role is not ClassicRecipeRole.FUNCTION
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {lane.consumer_intervention_id!r} is invalid"
            )
        if donor.scope.target != lane.target_id or consumer.scope.target != lane.target_id:
            raise ClassicSemanticError("donor lane crosses target boundaries")
        raw_statement_consumer = lane.consumer_input_statement.get("intervention")
        if not isinstance(raw_statement_consumer, Mapping):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} statement omits its intervention"
            )
        try:
            statement_consumer = ClassicRecipeIntervention.model_validate_json(
                canonical_json(raw_statement_consumer)
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} intervention is malformed"
            ) from exc
        if statement_consumer != consumer or not _donor_input_is_authorized(
            donor,
            consumer,
            lane.consumer_input_statement,
            input_name=lane.input_name,
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} uses an unauthorized candidate input"
            )
        contract = semantic_contracts.get(consumer.family)
        if contract is None or not semantic_proof_matches(
            lane.semantic_proof, consumer.family, contract
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} lacks a registered semantic proof"
            )
        expected_input = Digest.from_bytes(canonical_json(lane.consumer_input_statement))
        expected_output = Digest.from_bytes(canonical_json(lane.consumer_output_statement))
        if lane.semantic_proof.input_statement_digest != expected_input or (
            lane.semantic_proof.output_statement_digest != expected_output
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} proof statements changed"
            )
        if (
            _statement_payload_digest(
                lane.consumer_input_statement,
                name=lane.input_name,
            )
            != lane.donor_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} is not bound to its donor object"
            )
        if (
            _statement_named_digest(lane.consumer_input_statement, "seed", "digest")
            != lane.seed_object_digest
            or _statement_named_digest(lane.consumer_output_statement, "candidate", "digest")
            != lane.candidate_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} object lineage changed"
            )
        for item in lane.overlay_inputs:
            lane_receipt = effective.get(item.path.casefold())
            if lane_receipt != item:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} names an unsealed overlay input {item.path!r}"
                )
            if output_owner.get(item.path.casefold()) != lane.target_id:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} consumes a cross-target overlay"
                )
            lane_inputs.add((lane.target_id.casefold(), item.path.casefold()))
        lanes_by_target[lane.target_id].append(lane)

    overlay_traces: dict[str, object] = {}
    proofs: dict[str, SemanticProof] = {}
    source_contract = _SourceOverlayContract()
    for overlay in overlays:
        outputs, generated, generated_inputs = declaration_by_id[overlay.id]
        closure_value = closures.get(overlay.scope.target.casefold())
        if not isinstance(closure_value, TargetLinkClosure):
            raise ClassicSemanticError(
                f"overlay target {overlay.scope.target!r} lacks a complete link closure"
            )
        graph_compiler_ids = _ancestor_compilers(graph, overlay.scope.target)
        if closure_value.compiler_node_ids != tuple(sorted(graph_compiler_ids, key=str.casefold)):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} compiler closure differs from graph"
            )
        if closure_value.archive_refs != _graph_archives(graph, overlay.scope.target):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} archive closure differs from graph"
            )
        carrier_node_ids: set[str] = set()
        for path in generated:
            candidates = compiler_by_source.get(path.casefold(), [])
            if len(candidates) != 1:
                raise ClassicSemanticError(
                    f"generated carrier {path!r} has {len(candidates)} compiler products"
                )
            carrier_node_ids.add(candidates[0].node_id)
        carrier_trace = _carrier_isolation_trace(
            target=closure_value,
            products={
                key: value for key, value in products.items() if isinstance(value, CompilerProduct)
            },
            carrier_node_ids=frozenset(carrier_node_ids),
        )
        helper_trace = (
            _helper_isolation_trace(
                target=closure_value,
                products={
                    value.node_id: value
                    for value in products.values()
                    if isinstance(value, CompilerProduct)
                },
                counterfactual_objects=counterfactual_objects,
                effective_objects=effective_objects,
                helper_sections=helper_sections,
            )
            if source_validation is not None
            else {
                "target": overlay.scope.target,
                "helper_objects": [],
                "unique_unreferenced_definitions": [],
            }
        )
        lanes = sorted(
            lanes_by_target.get(overlay.scope.target, []),
            key=lambda item: (
                item.donor_intervention_id,
                item.consumer_intervention_id,
                item.input_name,
            ),
        )
        ordinary = set(outputs) - set(generated_inputs)
        used = {
            item.path for lane in lanes for item in lane.overlay_inputs if item.path in ordinary
        }
        # Ordinary outputs that do not enter any donor lane are harmlessly
        # discarded: the exact primary seat check above proves their effective
        # bytes are absent from every primary compiler input.
        discarded = [] if certified_primary else sorted(ordinary - used)
        trace = {
            "schema": 1,
            "run_binding": snapshot.run_binding.model_dump(mode="json"),
            "overlay_intervention": overlay.model_dump(mode="json"),
            "producer_graph_digest": producer_graph_digest(graph).model_dump(mode="json"),
            "primary_source_seal": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "origin": item.origin.value,
                }
                for item in sorted(snapshot.primary_sources, key=lambda item: item.path.casefold())
            ],
            "effective_outputs": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "disposition": (
                        "generated-carrier-tu"
                        if item.path in generated
                        else "certified-project-primary"
                        if certified_primary
                        else "generated-carrier-input"
                        if item.path in generated_inputs
                        else "certified-donor"
                        if item.path in used
                        else "discarded"
                    ),
                }
                for item in sorted(
                    (
                        value
                        for key, value in effective.items()
                        if key in {path.casefold() for path in outputs}
                        and isinstance(value, EffectiveOverlayReceipt)
                    ),
                    key=lambda item: item.path.casefold(),
                )
            ],
            "carrier_compile_epoch": {
                "generated_inputs": sorted(generated_inputs, key=str.casefold),
                "carrier_compilers": sorted(carrier_node_ids, key=str.casefold),
                "ordinary_generated_inputs": (
                    sorted(source_validation.generated_headers, key=str.casefold)
                    if source_validation is not None
                    else []
                ),
            },
            "project_overlay_epoch": {
                "enabled": source_validation is not None,
                "compiler_namespaces": compiler_namespace_trace,
                "compiler_audits": compiler_audit_trace,
                "source_validation": (
                    source_validation.traces.get(overlay.id)
                    if source_validation is not None
                    else None
                ),
            },
            "donor_lanes": [
                {
                    "donor": lane.donor_intervention_id,
                    "consumer": lane.consumer_intervention_id,
                    "input_name": lane.input_name,
                    "consumer_proof": lane.semantic_proof.evidence_digest.value,
                    "input_statement": lane.semantic_proof.input_statement_digest.value,
                }
                for lane in lanes
            ],
            "discarded_outputs": discarded,
            "carrier_isolation": carrier_trace,
            "project_helper_isolation": helper_trace,
        }
        input_statement = {
            "schema": 1,
            "intervention": overlay.model_dump(mode="json"),
            "clean_manifest": {
                item.path: item.digest.model_dump(mode="json") for item in manifest.entries
            },
            "effective_outputs": {
                path: {
                    "digest": declaration["effective"],
                    "size": declaration["size"],
                }
                for path, declaration in outputs.items()
            },
        }
        proof = issue_semantic_proof(
            family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
            contract=source_contract,
            input_statement=input_statement,
            output_statement=trace,
        )
        proofs[overlay.id] = proof
        overlay_traces[overlay.id] = trace
    return OverlaySemanticValidation(MappingProxyType(proofs), MappingProxyType(overlay_traces))


@dataclass(frozen=True, slots=True)
class _SourceOverlayContract:
    validator_id: str = SOURCE_OVERLAY_VALIDATOR_ID
    validator_digest: Digest = SOURCE_OVERLAY_VALIDATOR_DIGEST
    obligations: tuple[str, ...] = SOURCE_OVERLAY_OBLIGATIONS


__all__ = [
    "BINARY_TRANSFORM_OBLIGATIONS",
    "CLASSIC_SEMANTIC_CONTRACTS",
    "CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST",
    "DONOR_OBLIGATIONS",
    "IMAGE_BINARY_REPACK_OBLIGATIONS",
    "IMAGE_LINK_ORDER_OBLIGATIONS",
    "IMAGE_METADATA_OBLIGATIONS",
    "SOURCE_OVERLAY_OBLIGATIONS",
    "SOURCE_OVERLAY_VALIDATOR_DIGEST",
    "SOURCE_OVERLAY_VALIDATOR_ID",
    "ArchiveInput",
    "ClassicCandidateSemanticValidation",
    "ClassicCoffLineNumberCorrespondence",
    "ClassicCoffLineNumberDelta",
    "ClassicImportObjectReceipt",
    "ClassicLinkRelevantCoffProjection",
    "ClassicSemanticError",
    "CleanSourceInput",
    "CoffDirectiveReceipt",
    "CompilerEpochInvocation",
    "CompilerInputEvidenceKind",
    "CompilerNamespaceEvidence",
    "CompilerProduct",
    "CompilerSourceRead",
    "DonorSemanticLane",
    "DonorSemanticUse",
    "EffectiveOverlayReceipt",
    "OverlaySemanticSnapshot",
    "OverlaySemanticValidation",
    "PrimarySourceOrigin",
    "ProjectOverlayCompilerEpochPlan",
    "ProjectOverlayCounterfactualAudit",
    "ProjectOverlaySourcePair",
    "RegisteredSemanticContract",
    "SemanticValidatorContract",
    "SourceInputReceipt",
    "TargetLinkClosure",
    "classic_candidate_input_statement",
    "classic_compiler_path_profile_digest",
    "classic_link_relevant_coff_projection",
    "compiler_epoch_invocation_digest",
    "compiler_namespace_evidence_digest",
    "donor_lane_input_statement",
    "donor_lane_statement",
    "issue_classic_candidate_semantics",
    "issue_classic_donor_semantics",
    "issue_semantic_proof",
    "overlay_semantic_run_binding",
    "parse_classic_archive_member_directives",
    "parse_classic_coff_directives",
    "parse_classic_import_object",
    "plan_project_overlay_compiler_epochs",
    "prove_classic_coff_line_number_correspondence",
    "prove_source_overlay_semantics",
    "semantic_proof_evidence_digest",
    "semantic_proof_matches",
    "validate_project_overlay_compiler_epoch",
]
