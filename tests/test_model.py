from __future__ import annotations

import pytest
from pydantic import ValidationError

from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    AuthenticityPolicy,
    ByteRange,
    Certificate,
    Digest,
    ProofObligation,
    ProvenanceKind,
    ProvenanceNode,
    Quarantine,
    Scope,
    Verdict,
)


def digest(seed: bytes = b"evidence") -> Digest:
    return Digest.from_bytes(seed)


def test_digest_and_range_helpers() -> None:
    assert Digest.from_bytes(b"abc").value == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    left = ByteRange(offset=10, length=5)
    assert left.end == 15
    assert left.overlaps(ByteRange(offset=14, length=3))
    assert not left.overlaps(ByteRange(offset=15, length=1))


def test_scope_requires_translation_unit_for_function() -> None:
    with pytest.raises(ValidationError, match="requires translation_unit"):
        Scope(target="app", function="run()")


def test_artifact_rejects_unsafe_or_inconsistent_ancestry() -> None:
    with pytest.raises(ValidationError, match="cannot be first-party"):
        Artifact(
            id="runtime",
            kind=ArtifactKind.EXTERNAL,
            logical_path="vendor/runtime.lib",
            digest=digest(),
            size=1,
            origin=ArtifactOrigin.EXTERNAL,
            first_party=True,
        )
    with pytest.raises(ValidationError, match="escape"):
        Artifact(
            id="obj",
            kind=ArtifactKind.OBJECT,
            logical_path="../obj/a.obj",
            digest=digest(),
            size=1,
            origin=ArtifactOrigin.FRESH_SEED,
        )


def test_oracle_provenance_is_explicit_and_cannot_hide() -> None:
    node = ProvenanceNode(
        id="legacy-node",
        kind=ProvenanceKind.ORACLE_INSTALL,
        operation="legacy-install",
        origin=ArtifactOrigin.ORACLE,
        artifact_id="image",
        byte_range=ByteRange(offset=4, length=2),
        intervention_id="legacy-action",
    )
    assert node.origin is ArtifactOrigin.ORACLE
    with pytest.raises(ValidationError, match="restricted"):
        ProvenanceNode(
            id="ordinary-node",
            kind=ProvenanceKind.TOOLCHAIN,
            operation="compile",
            origin=ArtifactOrigin.ORACLE,
            artifact_id="object",
        )


def test_certificate_passed_is_derived() -> None:
    certificate = Certificate(
        id="proof-one",
        intervention_id="action-one",
        intervention_authority_digest=Digest.from_bytes(b"action-one authority"),
        intervention_cost_digest=Digest.from_bytes(b"action-one cost"),
        obligations=(
            ProofObligation(name="body-equal", passed=True, evidence_digest=digest()),
            ProofObligation(name="relocations-equal", passed=False),
        ),
        artifact_ids=("object",),
    )
    assert not certificate.passed
    assert certificate.model_dump()["passed"] is False


def test_verdict_keeps_claims_independent_and_derives_clean() -> None:
    clean = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=True,
    )
    assert clean.clean
    assert clean.accepts(AuthenticityPolicy.CLEAN)

    quarantine = Quarantine(
        id="legacy-action",
        kind="oracle-install",
        artifact_id="image",
        ranges=(ByteRange(offset=1, length=2), ByteRange(offset=10, length=3)),
        byte_count=5,
        reason="temporary disclosed ancestry exception",
    )
    disclosed = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=False,
        quarantines=(quarantine,),
    )
    assert disclosed.quarantined
    assert not disclosed.clean
    assert not disclosed.accepts(AuthenticityPolicy.CLEAN)
    # A verdict alone cannot distinguish disclosed quarantine from unrelated
    # broken ancestry; EngineResult performs the authoritative policy check.
    assert not disclosed.accepts(AuthenticityPolicy.ALLOW_QUARANTINE)

    with pytest.raises(ValidationError, match="cannot claim toolchain_origin"):
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
            quarantines=(quarantine,),
        )


def test_quarantine_rejects_overlap_and_incorrect_count() -> None:
    with pytest.raises(ValidationError, match="overlap"):
        Quarantine(
            id="q",
            kind="oracle-install",
            artifact_id="image",
            ranges=(ByteRange(offset=0, length=4), ByteRange(offset=3, length=2)),
            byte_count=6,
            reason="test",
        )
    with pytest.raises(ValidationError, match="sum"):
        Quarantine(
            id="q",
            kind="oracle-install",
            artifact_id="image",
            ranges=(ByteRange(offset=0, length=4),),
            byte_count=3,
            reason="test",
        )


def test_function_body_quarantine_requires_explicit_coordinates() -> None:
    with pytest.raises(ValidationError, match="function scope and base address"):
        Quarantine(
            id="q",
            kind="oracle-install",
            artifact_id="image",
            ranges=(ByteRange(offset=4, length=2),),
            byte_count=2,
            reason="test",
            coordinate_space="function-body",
        )

    quarantine = Quarantine(
        id="q",
        kind="oracle-install",
        artifact_id="image",
        ranges=(ByteRange(offset=4, length=2),),
        byte_count=2,
        reason="test",
        coordinate_space="function-body",
        scope=Scope(target="program", translation_unit="unit", function="symbol"),
        base_address=0x401000,
    )
    assert quarantine.coordinate_space == "function-body"
