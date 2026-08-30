from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.classic_evidence as classic_evidence
from reprobit.classic_project import ClassicProjectError, InterventionWitness
from reprobit.evidence_audit import EvidenceAuditor, EvidenceClaim
from reprobit.execution import (
    BuildExecutionReceipt,
    ObjectTransformAttestation,
    ObjectTransformOperation,
    RuntimeEvidence,
    RuntimeEvidenceContext,
    StepExecutionReceipt,
)
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    ByteRange,
    Digest,
    ProvenanceKind,
    ProvenanceNode,
    Scope,
    SemanticProof,
)
from reprobit.schema import LegacyOracleInstallIntervention, OracleInstallRange
from reprobit.strict_json import canonical_json


def _semantic_proof(*, seed: bytes, candidate: bytes, evidence: bytes) -> SemanticProof:
    input_statement = {
        "seed": {
            "digest": Digest.from_bytes(seed).model_dump(mode="json"),
            "size": len(seed),
        }
    }
    output_statement = {
        "candidate": {
            "digest": Digest.from_bytes(candidate).model_dump(mode="json"),
            "size": len(candidate),
        }
    }
    return SemanticProof(
        family="equal_body_strict",
        validator_id="classic.equal_body",
        validator_digest=Digest.from_bytes(b"validator"),
        input_statement_digest=Digest.from_bytes(canonical_json(input_statement)),
        output_statement_digest=Digest.from_bytes(canonical_json(output_statement)),
        obligations=("semantic_equivalence",),
        evidence_digest=Digest.from_bytes(evidence),
        input_statement=input_statement,
        output_statement=output_statement,
    )


def test_semantic_receipt_cache_is_keyed_by_statement_digest() -> None:
    assembler = object.__new__(classic_evidence._ClassicEvidenceAssembler)
    assembler.semantic_receipt_keys = {}
    first = _semantic_proof(seed=b"first", candidate=b"candidate", evidence=b"same")
    second = _semantic_proof(seed=b"second", candidate=b"candidate", evidence=b"same")

    assert assembler._proof_receipt_keys(first, "input") == frozenset(
        {(Digest.from_bytes(b"first").value, 5)}
    )
    assert assembler._proof_receipt_keys(second, "input") == frozenset(
        {(Digest.from_bytes(b"second").value, 6)}
    )
    assert len(assembler.semantic_receipt_keys) == 2


def _debug_companion_assembler(*, pdb_changed_bytes: int = 10) -> object:
    raw_image_digest = Digest.from_bytes(b"raw image")
    image_digest = Digest.from_bytes(b"stable image")
    raw_pdb_digest = Digest.from_bytes(b"raw pdb")
    pdb_digest = Digest.from_bytes(b"stable pdb")
    image_snapshot = SimpleNamespace(
        path=Path("/work/build/reprobit-debug/program.exe"),
        digest=image_digest,
        size=64,
    )
    pdb_snapshot = SimpleNamespace(
        path=Path("/work/build/reprobit-debug/program.pdb"),
        digest=pdb_digest,
        size=64,
    )
    pdb_ranges = tuple(
        SimpleNamespace(start=20 + index * 2, end=21 + index * 2) for index in range(10)
    )
    audit = SimpleNamespace(
        policy_version="msvc42-debug-pair-v1",
        image_bytes_outside_policy_ranges_sha256=Digest.from_bytes(b"image outside policy").value,
        image_debug=SimpleNamespace(
            changed_bytes=1,
            writes=(
                SimpleNamespace(
                    category=SimpleNamespace(value="pe.coff_timestamp"),
                    file_offset=4,
                    before=1,
                    after=2,
                ),
            ),
        ),
        image_metadata_writes=(SimpleNamespace(file_offset=8, before=3, after=4),),
        pdb=SimpleNamespace(
            bytes_outside_policy_ranges_sha256=Digest.from_bytes(b"pdb outside policy").value,
            changed_bytes=pdb_changed_bytes,
            stats=(
                SimpleNamespace(
                    category=SimpleNamespace(value="pdb.signature"),
                    normalized_bytes=40,
                    changed_ranges=pdb_ranges,
                ),
            ),
        ),
    )
    companion = SimpleNamespace(
        target_id="program",
        image_logical_path="build/reprobit-debug/program.exe",
        pdb_logical_path="build/reprobit-debug/program.pdb",
        raw_image_digest=raw_image_digest,
        raw_image_size=64,
        raw_pdb_digest=raw_pdb_digest,
        raw_pdb_size=64,
        link_step_id="analysis-link.program",
        publish_step_id="publish-analysis.program",
        image_snapshot=image_snapshot,
        pdb_snapshot=pdb_snapshot,
        audit=audit,
    )
    assembler = object.__new__(classic_evidence._ClassicEvidenceAssembler)
    assembler.record = SimpleNamespace(debug_companions=(companion,))
    return assembler


def test_debug_companion_audit_becomes_bounded_receipt_attestation() -> None:
    assembler = cast(classic_evidence._ClassicEvidenceAssembler, _debug_companion_assembler())

    attestation = assembler._supplemental_output_attestations()[0]

    assert attestation.target_id == "program"
    assert attestation.policy == "msvc42-debug-pair-v1"
    image, pdb = attestation.files
    assert image.role == "image"
    assert image.raw_digest == Digest.from_bytes(b"raw image")
    assert image.outside_policy_digest == Digest.from_bytes(b"image outside policy")
    assert image.changed_bytes == 2
    assert tuple(item.category for item in image.categories) == (
        "pe.coff_timestamp",
        "pe.metadata_timestamp",
    )
    assert pdb.role == "pdb"
    assert pdb.raw_digest == Digest.from_bytes(b"raw pdb")
    assert pdb.outside_policy_digest == Digest.from_bytes(b"pdb outside policy")
    assert pdb.changed_bytes == 10
    assert pdb.categories[0].changed_range_count == 10
    assert len(pdb.categories[0].changed_ranges) == 8
    assert pdb.categories[0].omitted_changed_ranges == 2


def test_debug_companion_rejects_inconsistent_audit_byte_counts() -> None:
    assembler = cast(
        classic_evidence._ClassicEvidenceAssembler,
        _debug_companion_assembler(pdb_changed_bytes=9),
    )

    with pytest.raises(ClassicProjectError, match="inconsistent changed-byte accounting"):
        assembler._supplemental_output_attestations()


def test_typed_semantic_stage_rejects_an_unbound_current_artifact() -> None:
    assembler = object.__new__(classic_evidence._ClassicEvidenceAssembler)
    assembler.semantic_receipt_keys = {}
    assembler.artifacts = {
        "current.object": Artifact(
            id="current.object",
            kind=ArtifactKind.OBJECT,
            logical_path="build/current.obj",
            digest=Digest.from_bytes(b"current"),
            size=7,
            origin=ArtifactOrigin.FRESH_SEED,
        )
    }
    witness = InterventionWitness(
        "function.rewrite",
        "program",
        Digest.from_bytes(b"evidence"),
        semantic_proof=_semantic_proof(
            seed=b"different",
            candidate=b"candidate",
            evidence=b"evidence",
        ),
    )

    with pytest.raises(ClassicProjectError, match="does not bind the current artifact"):
        assembler._stage_artifact(
            witness=witness,
            current_id="current.object",
            logical_path="build/current.obj",
        )


def _legacy_intervention() -> LegacyOracleInstallIntervention:
    return LegacyOracleInstallIntervention.freeze(
        id="legacy.install",
        scope=Scope(
            target="program",
            translation_unit="unit.main",
            function="?Function@@YAXXZ",
        ),
        rationale="bounded legacy quarantine",
        dependencies=("donor.private",),
        proof_receipt_digest=Digest.from_bytes(b"receipt"),
        preimage_digest=Digest.from_bytes(b"preimage"),
        oracle_body_digest=Digest.from_bytes(b"oracle"),
        oracle_target="program",
        oracle_address=1,
        ranges=(
            OracleInstallRange(
                preimage_range=ByteRange(offset=0, length=1),
                output_range=ByteRange(offset=0, length=1),
                oracle_range=ByteRange(offset=0, length=1),
            ),
        ),
        byte_count=1,
        maximum_oracle_payload_bytes=1,
    )


def _legacy_assembler() -> classic_evidence._ClassicEvidenceAssembler:
    current = Artifact(
        id="current.object",
        kind=ArtifactKind.OBJECT,
        logical_path="build/current.obj",
        digest=Digest.from_bytes(b"seed object"),
        size=len(b"seed object"),
        origin=ArtifactOrigin.FRESH_SEED,
    )
    donor = Artifact(
        id="donor.object",
        kind=ArtifactKind.OBJECT,
        logical_path=".reprobit/private-donors/donor.private.obj",
        digest=Digest.from_bytes(b"donor object"),
        size=len(b"donor object"),
        origin=ArtifactOrigin.FRESH_SEED,
    )
    assembler = object.__new__(classic_evidence._ClassicEvidenceAssembler)
    assembler.artifacts = {current.id: current, donor.id: donor}
    assembler.artifact_ids_by_receipt = {
        (current.digest.value, current.size): [current.id],
        (donor.digest.value, donor.size): [donor.id],
    }
    assembler.semantic_receipt_keys = {}
    assembler.context = cast(
        RuntimeEvidenceContext,
        SimpleNamespace(run_binding=Digest.from_bytes(b"run")),
    )
    assembler.interventions = {"legacy.install": _legacy_intervention()}
    assembler.certificates = {}
    assembler.provenance = {
        "current.origin": ProvenanceNode(
            id="current.origin",
            kind=ProvenanceKind.PRODUCER,
            operation="compile",
            origin=ArtifactOrigin.FRESH_SEED,
            artifact_id=current.id,
        ),
        "donor.origin": ProvenanceNode(
            id="donor.origin",
            kind=ProvenanceKind.PRODUCER,
            operation="compile",
            origin=ArtifactOrigin.FRESH_SEED,
            artifact_id=donor.id,
        ),
    }
    assembler.terminal_node = {
        current.id: "current.origin",
        donor.id: "donor.origin",
    }
    return assembler


def _legacy_statement(*, seed: bytes = b"seed object") -> dict[str, object]:
    output = b"legacy output"
    return {
        "schema": "legacy-simulated-elision-evidence-v1",
        "seed_object": {
            "digest": Digest.from_bytes(seed).model_dump(mode="json"),
            "size": len(seed),
        },
        "donor_object": {
            "digest": Digest.from_bytes(b"donor object").model_dump(mode="json"),
            "size": len(b"donor object"),
        },
        "output_sha256": Digest.from_bytes(output).value,
        "output_size": len(output),
        "candidate": {
            "digest": Digest.from_bytes(output).model_dump(mode="json"),
            "size": len(output),
        },
    }


def test_legacy_stage_binds_full_seed_and_donor_as_provenance_parents() -> None:
    assembler = _legacy_assembler()
    statement = _legacy_statement()
    witness = InterventionWitness(
        "legacy.install",
        "program",
        Digest.from_bytes(canonical_json(statement)),
        legacy_oracle_install=True,
        semantic_output_statement=statement,
        output_digest=Digest.from_bytes(b"legacy output"),
        output_size=len(b"legacy output"),
    )

    artifact_id = assembler._stage_artifact(
        witness=witness,
        current_id="current.object",
        logical_path="build/current.obj",
    )

    assert assembler.artifacts[artifact_id].inputs == (
        "current.object",
        "donor.object",
    )
    assert assembler.provenance[assembler.terminal_node[artifact_id]].parents == (
        "current.origin",
        "donor.origin",
    )


def test_legacy_stage_rejects_a_noncurrent_full_seed_receipt() -> None:
    assembler = _legacy_assembler()
    statement = _legacy_statement(seed=b"different seed")
    witness = InterventionWitness(
        "legacy.install",
        "program",
        Digest.from_bytes(canonical_json(statement)),
        legacy_oracle_install=True,
        semantic_output_statement=statement,
        output_digest=Digest.from_bytes(b"legacy output"),
        output_size=len(b"legacy output"),
    )

    with pytest.raises(ClassicProjectError, match="seed receipt differs"):
        assembler._stage_artifact(
            witness=witness,
            current_id="current.object",
            logical_path="build/current.obj",
        )


def _object_transform_evidence() -> tuple[
    BuildExecutionReceipt,
    RuntimeEvidence,
    dict[str, Artifact],
    dict[str, ProvenanceNode],
]:
    seed = Artifact(
        id="seed.object",
        kind=ArtifactKind.OBJECT,
        logical_path="build/seed.obj",
        digest=Digest.from_bytes(b"seed"),
        size=4,
        origin=ArtifactOrigin.FRESH_SEED,
    )
    output = Artifact(
        id="ordered.object",
        kind=ArtifactKind.OBJECT,
        logical_path="build/seed.obj",
        digest=Digest.from_bytes(b"ordered"),
        size=7,
        origin=ArtifactOrigin.COMPOSED,
        inputs=(seed.id,),
    )
    nodes = {
        "seed.origin": ProvenanceNode(
            id="seed.origin",
            kind=ProvenanceKind.PRODUCER,
            operation="compile",
            origin=ArtifactOrigin.FRESH_SEED,
            artifact_id=seed.id,
        ),
        "ordered.transform": ProvenanceNode(
            id="ordered.transform",
            kind=ProvenanceKind.OBJECT_TRANSFORM,
            operation="restore_comdat_group_order",
            origin=ArtifactOrigin.COMPOSED,
            parents=("seed.origin",),
            artifact_id=output.id,
        ),
    }
    step_digest = Digest.from_bytes(b"step binding")
    build = BuildExecutionReceipt(
        cold=True,
        inputs=(),
        outputs=(),
        steps=(
            StepExecutionReceipt(
                step_id="compose.unit",
                returncode=0,
                attempts=1,
                duration_seconds=0.1,
                output_digest=step_digest,
                command_digest=step_digest,
            ),
        ),
    )
    attestation = ObjectTransformAttestation(
        id="transform.unit",
        artifact_id=output.id,
        input_artifact_id=seed.id,
        step_id="compose.unit",
        operation=ObjectTransformOperation.RESTORE_COMDAT_GROUP_ORDER,
        input_digest=seed.digest,
        input_size=seed.size,
        artifact_digest=output.digest,
        artifact_size=output.size,
        evidence_digest=Digest.from_bytes(b"group-order proof"),
        step_binding_digest=step_digest,
    )
    runtime = RuntimeEvidence(
        provider_id="classic",
        run_binding=Digest.from_bytes(b"run"),
        artifacts=(seed, output),
        provenance=tuple(nodes.values()),
        object_transforms=(attestation,),
    )
    return build, runtime, {seed.id: seed, output.id: output}, nodes


def _object_transform_issues(
    build: BuildExecutionReceipt,
    runtime: RuntimeEvidence,
    artifacts: dict[str, Artifact],
    nodes: dict[str, ProvenanceNode],
) -> list[tuple[EvidenceClaim, str, str]]:
    issues: list[tuple[EvidenceClaim, str, str]] = []
    EvidenceAuditor._validate_object_transforms(
        build,
        (runtime,),
        artifacts,
        nodes,
        lambda claim, code, message: issues.append((claim, code, message)),
    )
    return issues


def test_object_transform_attestation_closes_exact_stage_provenance() -> None:
    build, runtime, artifacts, nodes = _object_transform_evidence()

    assert _object_transform_issues(build, runtime, artifacts, nodes) == []


def test_object_transform_audit_rejects_changed_input_or_step_binding() -> None:
    build, runtime, artifacts, nodes = _object_transform_evidence()
    attestation = runtime.object_transforms[0]
    changed = replace(
        attestation,
        input_digest=Digest.from_bytes(b"different"),
        step_binding_digest=Digest.from_bytes(b"different step"),
    )
    runtime = replace(runtime, object_transforms=(changed,))

    codes = {item[1] for item in _object_transform_issues(build, runtime, artifacts, nodes)}

    assert {"object-transform-content", "object-transform-step"} <= codes
    assert "unattested-object-transform" in codes


def test_group_order_cannot_be_disguised_as_a_composed_producer() -> None:
    build, runtime, artifacts, nodes = _object_transform_evidence()
    disguised = ProvenanceNode(
        id="ordered.transform",
        kind=ProvenanceKind.PRODUCER,
        operation="restore_comdat_group_order",
        origin=ArtifactOrigin.COMPOSED,
        parents=("seed.origin",),
        artifact_id="ordered.object",
    )
    nodes[disguised.id] = disguised
    runtime = replace(runtime, provenance=tuple(nodes.values()), object_transforms=())

    codes = {item[1] for item in _object_transform_issues(build, runtime, artifacts, nodes)}

    assert "misclassified-object-transform" in codes
    assert "unattested-composed-producer" in codes
