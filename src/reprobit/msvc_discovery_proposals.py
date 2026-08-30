"""Materialize qualified MSVC discovery proposals and their artifacts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence

import reprobit.msvc_discovery_coff as msvc_coff
import reprobit.msvc_discovery_mosaic as mosaic
from reprobit.discovery_contracts import (
    DiscoveryArtifactPayload,
    DiscoveryArtifactRole,
    DiscoveryError,
    DiscoveryFindingKind,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryProposal,
    MosaicRangeProposal,
    declaration_state_id,
)
from reprobit.model import Digest, Scope
from reprobit.msvc_compile import render_msvc_declaration_state
from reprobit.schema import (
    BinarySurgeryIntervention,
    BinarySurgeryMethod,
    EqualBodyDonorIntervention,
    StateCarrierIntervention,
)
from reprobit.strict_json import canonical_json


def _identifier(prefix: str, material: object) -> str:
    digest = hashlib.sha256(canonical_json(material)).hexdigest()
    return f"{prefix}.{digest[:24]}"


def _artifact_id(cell_id: str, role: str, symbol: str) -> str:
    return _identifier("artifact", {"cell": cell_id, "role": role, "symbol": symbol})


def whole_body_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: msvc_coff.MsvcFunctionReference,
    product: DiscoveryProduct,
) -> DiscoveryProposal:
    """Describe an exact whole-body compiler result."""

    state_id = declaration_state_id(product.state)
    scope = Scope(target=plan.target, translation_unit=plan.translation_unit)
    beneficiary = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    carrier = _artifact_id(product.observation.cell_id, "carrier", symbol)
    intervention_id = _identifier(
        "intervention",
        {"campaign": campaign_id, "kind": "state-carrier", "state": state_id, "symbol": symbol},
    )
    rationale = (
        "This declaration combination produced an exact function-body match. "
        "Review the rest of the object file for unintended differences."
    )
    intervention = StateCarrierIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        beneficiaries=(beneficiary,),
        carrier=carrier,
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "whole-body"},
        ),
        kind=DiscoveryFindingKind.WHOLE_BODY,
        scope=scope,
        symbol=symbol,
        state_ids=(state_id,),
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=(carrier,),
        rationale=rationale,
    )


def private_donor_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: msvc_coff.MsvcFunctionReference,
    product: DiscoveryProduct,
) -> DiscoveryProposal:
    """Describe a structurally compatible same-symbol donor."""

    state_id = declaration_state_id(product.state)
    scope = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    donor = _artifact_id(product.observation.cell_id, "private-donor", symbol)
    intervention_id = _identifier(
        "intervention",
        {"campaign": campaign_id, "kind": "private-donor", "state": state_id, "symbol": symbol},
    )
    rationale = (
        "This private same-symbol donor has the sealed body and compatible "
        "COMDAT and relocation structure; unrelated donor output is not adopted."
    )
    intervention = EqualBodyDonorIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        donor_artifact=donor,
        donor_symbol=symbol,
        expected_size=len(reference.body),
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "private-donor"},
        ),
        kind=DiscoveryFindingKind.PRIVATE_DONOR,
        scope=scope,
        symbol=symbol,
        state_ids=(state_id,),
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=(donor,),
        rationale=rationale,
    )


def mosaic_proposal(
    *,
    campaign_id: str,
    plan: DiscoveryPlan,
    symbol: str,
    reference: msvc_coff.MsvcFunctionReference,
    seed_body: bytes,
    ranges: tuple[mosaic.MosaicRangeCandidate, ...],
) -> DiscoveryProposal:
    """Describe a bounded instruction-range mosaic."""

    scope = Scope(
        target=plan.target,
        translation_unit=plan.translation_unit,
        function=symbol,
    )
    range_models = tuple(
        MosaicRangeProposal(
            donor_cell_id=item.product.observation.cell_id,
            offset=item.start,
            length=item.end - item.start,
            seed=Digest.from_bytes(seed_body[item.start : item.end]),
            donor=Digest.from_bytes(item.donor_body[item.start : item.end]),
            seed_instruction_lengths=item.seed_lengths,
            donor_instruction_lengths=item.donor_lengths,
        )
        for item in ranges
    )
    donor_products = {item.product.observation.cell_id: item.product for item in ranges}
    state_ids = tuple(sorted(declaration_state_id(item.state) for item in donor_products.values()))
    source_artifacts = tuple(
        sorted(
            (
                _identifier(
                    "artifact",
                    {"campaign": campaign_id, "role": "mosaic-seed", "symbol": symbol},
                ),
                *(_artifact_id(cell_id, "mosaic-donor", symbol) for cell_id in donor_products),
            )
        )
    )
    intervention_id = _identifier(
        "intervention",
        {
            "campaign": campaign_id,
            "kind": "instruction-mosaic",
            "states": state_ids,
            "symbol": symbol,
            "ranges": tuple((item.offset, item.length) for item in range_models),
        },
    )
    rationale = (
        "These bounded same-symbol donor ranges cover every remaining byte "
        "difference on complete IA-32 instruction boundaries without relocations."
    )
    intervention = BinarySurgeryIntervention(
        id=intervention_id,
        scope=scope,
        rationale=rationale,
        method=BinarySurgeryMethod.INSTRUCTION_MOSAIC,
        source_artifacts=source_artifacts,
        output_digest=Digest.from_bytes(reference.body),
    )
    return DiscoveryProposal(
        campaign_id=campaign_id,
        finding_id=_identifier(
            "finding",
            {"intervention": intervention_id, "kind": "instruction-mosaic"},
        ),
        kind=DiscoveryFindingKind.INSTRUCTION_MOSAIC,
        scope=scope,
        symbol=symbol,
        state_ids=state_ids,
        reference_body=Digest.from_bytes(reference.body),
        proposed_output=Digest.from_bytes(reference.body),
        intervention=intervention,
        artifact_ids=source_artifacts,
        ranges=range_models,
        rationale=rationale,
    )


def build_msvc_discovery_artifacts(
    *,
    source: bytes,
    seed_objects: Mapping[str, bytes],
    campaign_id: str,
    proposals: Sequence[DiscoveryProposal],
    products: Sequence[DiscoveryProduct],
) -> tuple[DiscoveryArtifactPayload, ...]:
    """Return only objects and declaration states named by findings."""

    by_cell = {item.observation.cell_id: item for item in products}
    by_state = {declaration_state_id(item.state): item for item in products}
    if len(by_cell) != len(products) or len(by_state) != len(products):
        raise DiscoveryError("discovery products are not uniquely addressable")
    payloads: dict[str, DiscoveryArtifactPayload] = {}

    def add_candidate(
        *,
        artifact_id: str,
        role: DiscoveryArtifactRole,
        symbol: str,
        product: DiscoveryProduct,
    ) -> None:
        object_bytes = product.object_path.read_bytes()
        if Digest.from_bytes(object_bytes) != product.observation.object:
            raise DiscoveryError(
                f"selected discovery object changed: {product.observation.cell_id}"
            )
        rendered = render_msvc_declaration_state(source, product.state)
        payload = DiscoveryArtifactPayload(
            artifact_id=artifact_id,
            role=role,
            symbol=symbol,
            object_bytes=object_bytes,
            cell_id=product.observation.cell_id,
            state=product.state,
            generated_declarations=rendered.generated_declarations,
        )
        prior = payloads.setdefault(artifact_id, payload)
        if prior != payload:
            raise DiscoveryError(f"proposal artifact has conflicting sources: {artifact_id}")

    for proposal in proposals:
        if proposal.campaign_id != campaign_id:
            raise DiscoveryError("proposal artifact belongs to another campaign")
        if proposal.kind is DiscoveryFindingKind.WHOLE_BODY:
            product = by_state.get(proposal.state_ids[0])
            if product is None:
                raise DiscoveryError("whole-body proposal state is unavailable")
            add_candidate(
                artifact_id=proposal.artifact_ids[0],
                role=DiscoveryArtifactRole.STATE_CARRIER,
                symbol=proposal.symbol,
                product=product,
            )
            continue
        if proposal.kind is DiscoveryFindingKind.PRIVATE_DONOR:
            product = by_state.get(proposal.state_ids[0])
            if product is None:
                raise DiscoveryError("private-donor proposal state is unavailable")
            add_candidate(
                artifact_id=proposal.artifact_ids[0],
                role=DiscoveryArtifactRole.PRIVATE_DONOR,
                symbol=proposal.symbol,
                product=product,
            )
            continue
        donor_ids: set[str] = set()
        for item in proposal.ranges:
            product = by_cell.get(item.donor_cell_id)
            if product is None:
                raise DiscoveryError("mosaic proposal donor cell is unavailable")
            artifact_id = _artifact_id(
                item.donor_cell_id,
                "mosaic-donor",
                proposal.symbol,
            )
            donor_ids.add(artifact_id)
            add_candidate(
                artifact_id=artifact_id,
                role=DiscoveryArtifactRole.MOSAIC_DONOR,
                symbol=proposal.symbol,
                product=product,
            )
        seed_ids = set(proposal.artifact_ids) - donor_ids
        seed_bytes = seed_objects.get(proposal.symbol)
        if len(seed_ids) != 1 or seed_bytes is None:
            raise DiscoveryError("mosaic proposal seed artifact is unresolved")
        seed_id = next(iter(seed_ids))
        seed_payload = DiscoveryArtifactPayload(
            artifact_id=seed_id,
            role=DiscoveryArtifactRole.MOSAIC_SEED,
            symbol=proposal.symbol,
            object_bytes=seed_bytes,
        )
        prior = payloads.setdefault(seed_id, seed_payload)
        if prior != seed_payload:
            raise DiscoveryError(f"proposal artifact has conflicting sources: {seed_id}")

    expected = {artifact_id for proposal in proposals for artifact_id in proposal.artifact_ids}
    if set(payloads) != expected:
        raise DiscoveryError("proposal artifact export is incomplete")
    return tuple(sorted(payloads.values(), key=lambda item: item.artifact_id))


__all__ = [
    "build_msvc_discovery_artifacts",
    "mosaic_proposal",
    "private_donor_proposal",
    "whole_body_proposal",
]
