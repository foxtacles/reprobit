"""Canonical contracts and receipts for classic semantic proof issuance."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.implementation import scoped_package_import_closure_digest
from reprobit.model import Digest, SemanticProof
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import canonical_json


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
    """One complete current-run archive used by a semantic link closure."""

    archive_ref: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class TargetLinkClosure:
    """Complete object/archive semantic input closure for one terminal link."""

    target_id: str
    compiler_node_ids: tuple[str, ...]
    archive_refs: tuple[str, ...] = ()
    archives: tuple[ArchiveInput, ...] = ()
    demand_root_symbols: tuple[str, ...] = ()
    retention_root_symbols: tuple[str, ...] = ()


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


_CLASSIC_SEMANTIC_ISSUER = object()


@dataclass(frozen=True, slots=True)
class _ClassicCandidateSemanticMaterial:
    """Candidate bytes and trace admitted by the exhaustive family dispatcher."""

    intervention: ClassicRecipeIntervention
    seed_input: bytes
    binary_inputs: Mapping[str, bytes]
    source_inputs: Mapping[str, bytes]
    candidate_constraints: Mapping[str, object]
    output: bytes
    validator_trace: Mapping[str, object]
    _issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _ClassicDonorSemanticMaterial:
    """Fresh donor bytes admitted after compiler and namespace receipts close."""

    intervention: ClassicRecipeIntervention
    donor_object: bytes
    source_inputs: Mapping[str, bytes]
    compiler_statement: Mapping[str, object]
    _issuer: object = field(repr=False, compare=False)


def _require_classic_candidate_semantic_material(
    material: object,
    intervention: ClassicRecipeIntervention,
) -> _ClassicCandidateSemanticMaterial:
    """Enforce nominal internal provenance without claiming a security boundary."""

    if type(material) is not _ClassicCandidateSemanticMaterial:
        raise ClassicSemanticError("candidate semantic material lacks internal provenance")
    candidate = material
    if candidate._issuer is not _CLASSIC_SEMANTIC_ISSUER:
        raise ClassicSemanticError("candidate semantic material lacks internal provenance")
    if candidate.intervention != intervention:
        raise ClassicSemanticError("candidate semantic material names a different intervention")
    return candidate


def _require_classic_donor_semantic_material(
    material: object,
    intervention: ClassicRecipeIntervention,
) -> _ClassicDonorSemanticMaterial:
    """Enforce nominal internal provenance without claiming a security boundary."""

    if type(material) is not _ClassicDonorSemanticMaterial:
        raise ClassicSemanticError("donor semantic material lacks internal provenance")
    donor = material
    if donor._issuer is not _CLASSIC_SEMANTIC_ISSUER:
        raise ClassicSemanticError("donor semantic material lacks internal provenance")
    if donor.intervention != intervention:
        raise ClassicSemanticError("donor semantic material names a different intervention")
    return donor


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

    return scoped_package_import_closure_digest(
        (
            "reprobit.classic.semantic_contracts",
            "reprobit.classic_runtime_preparation",
        )
    )


CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST = _classic_implementation_digest()


def revalidate_classic_validator_implementation() -> None:
    """Fail if the imported classic validator no longer matches its code closure."""

    if _classic_implementation_digest() != CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST:
        raise ClassicSemanticError(
            "classic semantic validator implementation changed during execution; "
            "rerun the build"
        )

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
def _source_overlay_validator_digest(implementation_digest: Digest) -> Digest:
    return Digest.from_bytes(
        canonical_json(
            {
                "specification": _SOURCE_OVERLAY_SPEC,
                "implementation": implementation_digest.model_dump(mode="json"),
            }
        )
    )


SOURCE_OVERLAY_VALIDATOR_DIGEST = _source_overlay_validator_digest(
    CLASSIC_VALIDATOR_IMPLEMENTATION_DIGEST
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


def _issue_semantic_proof(
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
    material: _ClassicCandidateSemanticMaterial,
) -> ClassicCandidateSemanticValidation:
    """Issue a family proof from one successful closed binary/image validator.

    The low-level validator trace is part of the output statement; the complete
    seed, donor/source material universe, declaration, and intervention are in
    the input statement.  Hash-only execution receipts cannot satisfy this API.
    """

    candidate = _require_classic_candidate_semantic_material(material, intervention)
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
    if not isinstance(candidate.output, bytes) or not isinstance(
        candidate.validator_trace, Mapping
    ):
        raise ClassicSemanticError("candidate validator returned malformed material")
    trace = dict(candidate.validator_trace)
    canonical_json(trace)
    input_statement = classic_candidate_input_statement(
        intervention,
        seed_input=candidate.seed_input,
        binary_inputs=candidate.binary_inputs,
        source_inputs=candidate.source_inputs,
        candidate_constraints=candidate.candidate_constraints,
    )
    output_statement: Mapping[str, object] = MappingProxyType(
        {
            "schema": 1,
            "kind": "classic-closed-candidate-output",
            "candidate": {
                "digest": Digest.from_bytes(candidate.output).model_dump(mode="json"),
                "size": len(candidate.output),
            },
            "validator_trace": trace,
        }
    )
    proof = _issue_semantic_proof(
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
    named_constraints = {
        "target_donor_object": "target_donor",
        "complete_donor_object": "complete_donor",
        "instruction_donor_object": "instruction_donor",
    }
    constraint_name = named_constraints.get(input_name)
    if constraint_name is not None:
        return constraints.get(constraint_name) == donor.id
    if input_name != f"additional_donor:{donor.id}":
        return False
    variants = constraints.get("donor_variants")
    return isinstance(variants, list) and any(
        isinstance(item, Mapping) and item.get("donor") == donor.id for item in variants
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
    material: _ClassicDonorSemanticMaterial,
    downstream_uses: Sequence[DonorSemanticUse],
    quarantined_consumers: Mapping[str, Digest] = MappingProxyType({}),
) -> ClassicCandidateSemanticValidation:
    """Prove that one fresh donor stays private until a reviewed consumer.

    A donor is not itself linked.  It is either discarded or consumed only by
    candidate validators whose exact input statement binds this object's
    digest.  Legacy-oracle consumers are recorded as quarantined dispositions,
    never promoted to semantic validators.
    """

    donor = _require_classic_donor_semantic_material(material, intervention)
    contract = CLASSIC_SEMANTIC_CONTRACTS.get(intervention.family)
    if (
        intervention.role is not ClassicRecipeRole.DONOR
        or (intervention.family not in _DONOR_FAMILIES)
        or contract is None
    ):
        raise ClassicSemanticError("donor semantics require a registered donor recipe")
    if not isinstance(donor.donor_object, bytes):
        raise ClassicSemanticError("donor object is not immutable bytes")
    compiler_trace = dict(donor.compiler_statement)
    canonical_json(compiler_trace)
    donor_digest = Digest.from_bytes(donor.donor_object)

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
                "size": len(donor.donor_object),
            },
            "source_inputs": _payload_receipts(
                donor.source_inputs, label="donor source input"
            ),
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
    proof = _issue_semantic_proof(
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
    "CleanSourceInput",
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
    "donor_lane_input_statement",
    "donor_lane_statement",
    "issue_classic_candidate_semantics",
    "issue_classic_donor_semantics",
    "revalidate_classic_validator_implementation",
    "semantic_proof_evidence_digest",
    "semantic_proof_matches",
]
