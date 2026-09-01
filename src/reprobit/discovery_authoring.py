"""Pure authority construction for admitted declaration-shape discoveries.

Discovery reports are non-authoritative.  This module is the deliberately
small boundary that can turn one project-owned seed/private-donor COFF pair
into the two closed classic records the runtime already understands.  It does
not read a project, compile a donor, write authority, or claim certification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from reprobit.binary import ByteIdentityError
from reprobit.classic.composition import compose_equal_body_comdat, measure_composition_pins
from reprobit.classic_donors import (
    DonorSourceError,
    generate_declaration_shape,
    merge_candidate_constraints,
    validate_donor_recipe,
)
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    ProofDocument,
)
from reprobit.strict_json import JsonValue, canonical_json

_DONOR_RATIONALE = (
    "Framework-generated declaration-only compiler state; emits no program code or data."
)
_FUNCTION_RATIONALE = (
    "Strict equal-size COMDAT body selection from a freshly compiled private donor."
)
_EXPECTED_EQUAL_BODY_PINS = frozenset(
    {"expected_body_length", "expected_body_sha256", "expected_changed_offsets"}
)


class DiscoveryAuthoringError(ValueError):
    """A discovery result cannot be represented by the narrow admitted recipe."""


@dataclass(frozen=True, slots=True)
class AuthoredClassicRecord:
    """One classic intervention and its matching expected-observations receipt."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt


@dataclass(frozen=True, slots=True)
class StrictEqualBodyCompositionProof:
    """Typed structural proof returned by the closed strict composer."""

    mangled: str
    section_number: int
    body_length: int
    body_changed_offsets: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DeclarationShapeEqualBodyAuthoring:
    """Authority records plus the candidate-only composed COFF and its proof."""

    donor: AuthoredClassicRecord
    function: AuthoredClassicRecord
    candidate_object: bytes
    composition_proof: StrictEqualBodyCompositionProof

    @property
    def records(self) -> tuple[AuthoredClassicRecord, AuthoredClassicRecord]:
        return (self.donor, self.function)


def _stable_id(kind: str, material: object) -> str:
    suffix = Digest.from_bytes(canonical_json(material)).value[:16]
    return f"discovery.{kind}.{suffix}"


def _record_receipt(
    intervention: ClassicRecipeIntervention,
    expected_values: dict[str, JsonValue],
) -> ClassicProofReceipt:
    receipt_id = _stable_id(
        "proof",
        {
            "family": intervention.family.value,
            "intervention_id": intervention.id,
            "expected_values": expected_values,
        },
    )
    return ClassicProofReceipt(
        id=receipt_id,
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values={name: expected_values[name] for name in sorted(expected_values)},
    )


def _beneficiary_scopes(
    *,
    target_id: str,
    translation_unit_id: str,
    symbols: tuple[str, ...],
) -> tuple[Scope, ...]:
    if len(symbols) != len(set(symbols)):
        raise DiscoveryAuthoringError("donor beneficiary symbols must be unique")
    try:
        return tuple(
            Scope(target=target_id, translation_unit=translation_unit_id, function=symbol)
            for symbol in sorted(symbols)
        )
    except ValidationError as exc:
        raise DiscoveryAuthoringError(f"invalid donor beneficiary scope: {exc}") from exc


def _typed_composition_proof(
    raw: dict[str, Any],
    *,
    symbol: str,
    expected_values: dict[str, JsonValue],
) -> StrictEqualBodyCompositionProof:
    expected_keys = {
        "body_changed_offsets",
        "body_length",
        "code_renames",
        "mangled",
        "section_number",
        "splice_class",
    }
    if set(raw) != expected_keys:
        raise DiscoveryAuthoringError("strict composer returned an unexpected proof shape")
    section_number = raw["section_number"]
    body_length = raw["body_length"]
    changed_offsets = raw["body_changed_offsets"]
    if raw["mangled"] != symbol or raw["splice_class"] != "equal_body_strict":
        raise DiscoveryAuthoringError("strict composer proof names a different function")
    if type(section_number) is not int or section_number < 1:
        raise DiscoveryAuthoringError("strict composer returned an invalid section number")
    if type(body_length) is not int or body_length != expected_values["expected_body_length"]:
        raise DiscoveryAuthoringError("strict composer body length differs from its pin")
    if changed_offsets != expected_values["expected_changed_offsets"]:
        raise DiscoveryAuthoringError("strict composer changed offsets differ from their pin")
    if (
        not isinstance(changed_offsets, list)
        or not all(type(offset) is int for offset in changed_offsets)
        or raw["code_renames"] != []
    ):
        raise DiscoveryAuthoringError("strict composer returned malformed structural proof")
    return StrictEqualBodyCompositionProof(
        mangled=symbol,
        section_number=section_number,
        body_length=body_length,
        body_changed_offsets=tuple(changed_offsets),
    )


def build_declaration_shape_donor(
    *,
    target_id: str,
    translation_unit_id: str,
    build_target: str,
    classes: int,
    functions: int,
    beneficiary_symbols: tuple[str, ...] = (),
) -> AuthoredClassicRecord:
    """Build one deterministic, payload-free declaration-shape donor record.

    The caller remains responsible for compiling this recipe through the
    project producer graph.  ``beneficiary_symbols`` may be empty while a
    bounded campaign probes donors, but final admitted donors must name their
    exact consumers.
    """

    try:
        generated = generate_declaration_shape(classes, functions)
        generated_digest = Digest.from_bytes(generated).value
        beneficiaries = _beneficiary_scopes(
            target_id=target_id,
            translation_unit_id=translation_unit_id,
            symbols=beneficiary_symbols,
        )
        parameters: dict[str, JsonValue] = {
            "classes": classes,
            "emission_policy": "non_emitting_declarations_only",
            "functions": functions,
            "generated_header_sha256": generated_digest,
        }
        intervention_id = _stable_id(
            "donor",
            {
                "build_target": build_target,
                "family": ClassicRecipeFamily.DECLARATION_SHAPE.value,
                "parameters": parameters,
                "target_id": target_id,
                "translation_unit_id": translation_unit_id,
            },
        )
        intervention = ClassicRecipeIntervention(
            id=intervention_id,
            scope=Scope(target=target_id, translation_unit=translation_unit_id),
            rationale=_DONOR_RATIONALE,
            beneficiaries=beneficiaries,
            family=ClassicRecipeFamily.DECLARATION_SHAPE,
            role=ClassicRecipeRole.DONOR,
            build_target=build_target,
            parameters=tuple(
                ClassicField(name=name, value=value) for name, value in sorted(parameters.items())
            ),
        )
        receipt = _record_receipt(intervention, {})
        constraints = merge_candidate_constraints(intervention, receipt)
        validation = validate_donor_recipe(intervention, constraints)
        if validation.generated_declarations != generated:
            raise DiscoveryAuthoringError("validated donor declarations differ from their recipe")
        return AuthoredClassicRecord(intervention, receipt)
    except DiscoveryAuthoringError:
        raise
    except (DonorSourceError, ValidationError) as exc:
        raise DiscoveryAuthoringError(f"invalid declaration-shape donor: {exc}") from exc


def build_declaration_shape_equal_body(
    *,
    target_id: str,
    translation_unit_id: str,
    build_target: str,
    symbol: str,
    classes: int,
    functions: int,
    seed_object: bytes,
    donor_object: bytes,
) -> DeclarationShapeEqualBodyAuthoring:
    """Author a declaration-shape donor and strict equal-body consumer.

    Both objects must be fresh COFF bytes from the caller's project-aware
    compiler lane.  The composer rechecks equal size, COMDAT selection,
    relocation identity, line rows, and the closed FPO debug-child shape.
    """

    if type(seed_object) is not bytes or not seed_object:
        raise DiscoveryAuthoringError("seed_object must be non-empty immutable bytes")
    if type(donor_object) is not bytes or not donor_object:
        raise DiscoveryAuthoringError("donor_object must be non-empty immutable bytes")

    donor = build_declaration_shape_donor(
        target_id=target_id,
        translation_unit_id=translation_unit_id,
        build_target=build_target,
        classes=classes,
        functions=functions,
        beneficiary_symbols=(symbol,),
    )
    template: dict[str, Any] = {
        "mangled": symbol,
        "splice_class": ClassicRecipeFamily.EQUAL_BODY_STRICT.value,
        "expected_body_length": 0,
        "expected_body_sha256": "0" * 64,
        "expected_changed_offsets": [],
    }
    try:
        expected_values = measure_composition_pins(
            seed_object,
            donor_object,
            template,
            f"discovery authoring for {symbol}",
        )
        if set(expected_values) != _EXPECTED_EQUAL_BODY_PINS:
            raise DiscoveryAuthoringError("equal-body measurement returned an incomplete pin set")
        changed_offsets = expected_values["expected_changed_offsets"]
        if not isinstance(changed_offsets, list) or not changed_offsets:
            raise DiscoveryAuthoringError("seed and donor function bodies are identical")

        scope = Scope(target=target_id, translation_unit=translation_unit_id, function=symbol)
        intervention_id = _stable_id(
            "function",
            {
                "build_target": build_target,
                "dependency": donor.intervention.id,
                "expected_values": expected_values,
                "family": ClassicRecipeFamily.EQUAL_BODY_STRICT.value,
                "scope": scope.model_dump(mode="json"),
            },
        )
        intervention = ClassicRecipeIntervention(
            id=intervention_id,
            scope=scope,
            rationale=_FUNCTION_RATIONALE,
            dependencies=(donor.intervention.id,),
            family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
            role=ClassicRecipeRole.FUNCTION,
            build_target=build_target,
            symbol=symbol,
        )
        receipt = _record_receipt(intervention, expected_values)
        constraints = merge_candidate_constraints(intervention, receipt).materialize()
        candidate_object, raw_proof = compose_equal_body_comdat(
            seed_object,
            donor_object,
            {
                **constraints,
                "mangled": symbol,
                "splice_class": ClassicRecipeFamily.EQUAL_BODY_STRICT.value,
            },
        )
        if type(candidate_object) is not bytes or candidate_object == seed_object:
            raise DiscoveryAuthoringError("strict composer did not return a changed COFF candidate")
        composition_proof = _typed_composition_proof(
            raw_proof,
            symbol=symbol,
            expected_values=expected_values,
        )
        return DeclarationShapeEqualBodyAuthoring(
            donor=donor,
            function=AuthoredClassicRecord(intervention, receipt),
            candidate_object=candidate_object,
            composition_proof=composition_proof,
        )
    except DiscoveryAuthoringError:
        raise
    except (ByteIdentityError, DonorSourceError, ValidationError) as exc:
        raise DiscoveryAuthoringError(
            f"cannot author strict equal-body intervention: {exc}"
        ) from exc


def merge_authored_records(
    intervention_document: InterventionDocument,
    proof_document: ProofDocument,
    records: tuple[AuthoredClassicRecord, ...],
) -> tuple[InterventionDocument, ProofDocument]:
    """Merge new records and an identical shared donor, or fail closed.

    The helper performs no I/O.  Callers can therefore validate and cold-build
    the returned documents in private staging before a separate CAS commit. A
    donor ID may already exist only when its full recipe identity matches; its
    canonical beneficiary set is then widened without duplicating its proof.
    """

    if not records:
        raise DiscoveryAuthoringError("at least one authored record is required")
    shard = (intervention_document.target_id, intervention_document.translation_unit_id)
    if shard != (proof_document.target_id, proof_document.translation_unit_id):
        raise DiscoveryAuthoringError("intervention and proof documents name different shards")
    if intervention_document.translation_unit_id is None:
        raise DiscoveryAuthoringError("discovery authoring requires a translation-unit shard")
    if intervention_document.build_target is None:
        raise DiscoveryAuthoringError("discovery authoring requires a shard build target")

    interventions = list(intervention_document.interventions)
    intervention_indexes = {item.id: index for index, item in enumerate(interventions)}
    receipts = list(proof_document.expected_observations)
    receipt_indexes = {item.id: index for index, item in enumerate(receipts)}
    receipt_interventions = {item.intervention_id: index for index, item in enumerate(receipts)}
    for record in records:
        intervention = record.intervention
        receipt = record.receipt
        record_shard = (intervention.scope.target, intervention.scope.translation_unit)
        if record_shard != shard:
            raise DiscoveryAuthoringError(
                f"authored intervention {intervention.id!r} belongs to a different shard"
            )
        if intervention.build_target != intervention_document.build_target:
            raise DiscoveryAuthoringError(
                f"authored intervention {intervention.id!r} names a different build target"
            )
        if receipt.intervention_id != intervention.id or receipt.family is not intervention.family:
            raise DiscoveryAuthoringError(
                f"authored receipt {receipt.id!r} does not match its intervention"
            )
        existing_index = intervention_indexes.get(intervention.id)
        if existing_index is None:
            interventions.append(intervention)
            intervention_indexes[intervention.id] = len(interventions) - 1
        else:
            existing = interventions[existing_index]
            if not (
                isinstance(existing, ClassicRecipeIntervention)
                and existing.role is ClassicRecipeRole.DONOR
                and intervention.role is ClassicRecipeRole.DONOR
                and existing.model_dump(exclude={"beneficiaries"})
                == intervention.model_dump(exclude={"beneficiaries"})
            ):
                raise DiscoveryAuthoringError(
                    f"intervention identifier collision: {intervention.id!r}"
                )
            beneficiaries = {
                (scope.target, scope.translation_unit or "", scope.function or ""): scope
                for scope in (*existing.beneficiaries, *intervention.beneficiaries)
            }
            interventions[existing_index] = ClassicRecipeIntervention.model_validate(
                {
                    **intervention.model_dump(mode="python"),
                    "beneficiaries": tuple(beneficiaries[key] for key in sorted(beneficiaries)),
                }
            )

        existing_receipt_index = receipt_interventions.get(intervention.id)
        if existing_receipt_index is not None:
            if receipts[existing_receipt_index] != receipt:
                raise DiscoveryAuthoringError(f"intervention proof collision: {intervention.id!r}")
            continue
        if receipt.id in receipt_indexes:
            raise DiscoveryAuthoringError(f"receipt identifier collision: {receipt.id!r}")
        receipts.append(receipt)
        receipt_indexes[receipt.id] = len(receipts) - 1
        receipt_interventions[intervention.id] = len(receipts) - 1

    try:
        merged_interventions = InterventionDocument(
            schema_version=intervention_document.schema_version,
            target_id=intervention_document.target_id,
            translation_unit_id=intervention_document.translation_unit_id,
            source=intervention_document.source,
            source_digest=intervention_document.source_digest,
            build_target=intervention_document.build_target,
            interventions=tuple(interventions),
        )
        merged_proofs = ProofDocument(
            schema_version=proof_document.schema_version,
            target_id=proof_document.target_id,
            translation_unit_id=proof_document.translation_unit_id,
            expected_observations=tuple(receipts),
        )
    except ValidationError as exc:
        raise DiscoveryAuthoringError(f"merged discovery authority is invalid: {exc}") from exc
    return merged_interventions, merged_proofs


__all__ = [
    "AuthoredClassicRecord",
    "DeclarationShapeEqualBodyAuthoring",
    "DiscoveryAuthoringError",
    "StrictEqualBodyCompositionProof",
    "build_declaration_shape_donor",
    "build_declaration_shape_equal_body",
    "merge_authored_records",
]
