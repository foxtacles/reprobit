from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.discovery_grind as grind
from reprobit.discovery_authoring import DeclarationShapeEqualBodyAuthoring
from reprobit.discovery_grind import ColdTrialEvidence
from reprobit.discovery_project import (
    ProjectDirectorySnapshot,
    ProjectFileSnapshot,
    ProjectGrindContext,
)
from reprobit.execution import classic_semantic_obligation_name
from reprobit.model import Digest
from reprobit.report import Report
from reprobit.schema import (
    ClassicRecipeFamily,
    InterventionDocument,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import TransactionConflict


@dataclass(frozen=True, slots=True)
class _Intervention:
    id: str
    family: ClassicRecipeFamily


@dataclass(frozen=True, slots=True)
class _Record:
    intervention: _Intervention


@dataclass(frozen=True, slots=True)
class _Obligation:
    name: str


@dataclass(frozen=True, slots=True)
class _SemanticProof:
    family: str


@dataclass(frozen=True, slots=True)
class _Certificate:
    intervention_id: str
    passed: bool
    obligations: tuple[_Obligation, ...]
    semantic_proofs: tuple[_SemanticProof, ...]


def _certificate(intervention: _Intervention) -> _Certificate:
    return _Certificate(
        intervention_id=intervention.id,
        passed=True,
        obligations=(
            _Obligation("fresh_execution"),
            _Obligation(classic_semantic_obligation_name(intervention.family)),
        ),
        semantic_proofs=(_SemanticProof(intervention.family.value),),
    )


def _cold_boundary(
    failure: str | None = None,
) -> tuple[ColdTrialEvidence, ProjectGrindContext, DeclarationShapeEqualBodyAuthoring]:
    interventions = (
        _Intervention("discovery.donor", ClassicRecipeFamily.DECLARATION_SHAPE),
        _Intervention("discovery.function", ClassicRecipeFamily.EQUAL_BODY_STRICT),
    )
    certificates = [_certificate(intervention) for intervention in interventions]

    project_id = "sample.project"
    accepted = True
    cold = True
    byte_exact = True
    logic_certified = True
    target_exact = True
    quarantine_ids: tuple[str, ...] = ()
    project_total = 31

    if failure == "project":
        project_id = "other.project"
    elif failure == "policy":
        accepted = False
    elif failure == "cold":
        cold = False
    elif failure == "verdict_exact":
        byte_exact = False
    elif failure == "logic":
        logic_certified = False
    elif failure == "target_exact":
        target_exact = False
    elif failure == "quarantine":
        quarantine_ids = ("new.exception",)
    elif failure == "cost":
        project_total += 1
    elif failure == "missing_certificate":
        certificates.pop(0)
    elif failure == "failed_certificate":
        certificates[0] = replace(certificates[0], passed=False)
    elif failure == "fresh_execution":
        certificates[0] = replace(
            certificates[0],
            obligations=certificates[0].obligations[1:],
        )
    elif failure == "semantic_obligation":
        certificates[0] = replace(
            certificates[0],
            obligations=certificates[0].obligations[:1],
        )
    elif failure == "semantic_proof_missing":
        certificates[0] = replace(certificates[0], semantic_proofs=())
    elif failure == "semantic_proof_multiple":
        certificates[0] = replace(
            certificates[0],
            semantic_proofs=(
                certificates[0].semantic_proofs[0],
                certificates[0].semantic_proofs[0],
            ),
        )
    elif failure == "semantic_proof_family":
        certificates[0] = replace(
            certificates[0],
            semantic_proofs=(_SemanticProof("wrong_family"),),
        )
    elif failure is not None:
        raise AssertionError(f"unknown cold-boundary fixture: {failure}")

    context = SimpleNamespace(
        bundle=SimpleNamespace(
            spec=SimpleNamespace(project_id="sample.project"),
            interventions=(),
        )
    )
    authored = SimpleNamespace(
        records=tuple(_Record(intervention) for intervention in interventions)
    )
    report = SimpleNamespace(
        project_id=project_id,
        verdict=SimpleNamespace(
            cold=cold,
            byte_exact=byte_exact,
            logic_certified=logic_certified,
            quarantines=tuple(SimpleNamespace(id=item) for item in quarantine_ids),
        ),
        targets=(SimpleNamespace(byte_exact=target_exact),),
        costs=SimpleNamespace(project_total=project_total),
        proof=SimpleNamespace(certificates=tuple(certificates)),
    )
    evidence = ColdTrialEvidence(
        accepted=accepted,
        report=cast(Report, report),
    )
    return (
        evidence,
        cast(ProjectGrindContext, context),
        cast(DeclarationShapeEqualBodyAuthoring, authored),
    )


def test_cold_report_accepts_only_the_complete_exact_proof_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        grind,
        "calculate_cost",
        lambda _interventions: SimpleNamespace(project_total=5),
    )
    evidence, context, authored = _cold_boundary()

    assert (
        grind._validate_cold_report(
            evidence,
            context=context,
            authored=authored,
            added_cost=26,
        )
        is None
    )


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        ("project", "cold report belongs to a different project"),
        (
            "policy",
            "cold verification did not satisfy the committed authenticity policy",
        ),
        (
            "cold",
            "cold verification did not reproduce every target byte-identically",
        ),
        (
            "verdict_exact",
            "cold verification did not reproduce every target byte-identically",
        ),
        ("logic", "cold verification did not certify intervention logic"),
        ("target_exact", "cold report contains a non-exact target"),
        ("quarantine", "candidate introduced an authenticity exception"),
        ("cost", "cold report cost differs from the admitted intervention delta"),
        (
            "missing_certificate",
            "cold report lacks a passing certificate for discovery.donor",
        ),
        (
            "failed_certificate",
            "cold report lacks a passing certificate for discovery.donor",
        ),
        (
            "fresh_execution",
            "cold report lacks closed execution proof for discovery.donor",
        ),
        (
            "semantic_obligation",
            "cold report lacks closed execution proof for discovery.donor",
        ),
        (
            "semantic_proof_missing",
            "cold report lacks typed semantic proof for discovery.donor",
        ),
        (
            "semantic_proof_multiple",
            "cold report lacks typed semantic proof for discovery.donor",
        ),
        (
            "semantic_proof_family",
            "cold report lacks typed semantic proof for discovery.donor",
        ),
    ),
)
def test_cold_report_rejects_each_incomplete_admission_claim(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        grind,
        "calculate_cost",
        lambda _interventions: SimpleNamespace(project_total=5),
    )
    evidence, context, authored = _cold_boundary(failure)

    assert (
        grind._validate_cold_report(
            evidence,
            context=context,
            authored=authored,
            added_cost=26,
        )
        == expected
    )


def _write_and_snapshot(root: Path, relative: str, payload: bytes) -> ProjectFileSnapshot:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return ProjectFileSnapshot(
        relative_path=relative,
        digest=Digest.from_bytes(payload),
        payload=payload,
    )


def _authority_directories(root: Path) -> tuple[ProjectDirectorySnapshot, ...]:
    result: list[ProjectDirectorySnapshot] = []
    for relative in (
        "reprobit/interventions",
        "reprobit/proofs",
        "reprobit/oracles",
    ):
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        members = tuple(
            sorted(
                path.relative_to(directory).as_posix()
                for path in directory.rglob("*.json")
                if path.is_file()
            )
        )
        result.append(ProjectDirectorySnapshot(relative, members))
    return tuple(result)


@pytest.mark.parametrize(
    "changed_relative",
    (
        "reprobit/interventions/sample.json",
        "reprobit/proofs/sample.json",
        "reprobit/project.json",
        "src/sample.cpp",
    ),
)
def test_publication_conflict_never_partially_writes_authority(
    tmp_path: Path,
    changed_relative: str,
) -> None:
    root = tmp_path.resolve()
    intervention_relative = "reprobit/interventions/sample.json"
    proof_relative = "reprobit/proofs/sample.json"
    old_interventions = InterventionDocument(schema_version=3, target_id="sample.target")
    old_proofs = ProofDocument(schema_version=3, target_id="sample.target")
    new_interventions = InterventionDocument(
        schema_version=3,
        target_id="sample.target",
        translation_unit_id="sample.tu",
    )
    new_proofs = ProofDocument(
        schema_version=3,
        target_id="sample.target",
        translation_unit_id="sample.tu",
    )
    original = {
        intervention_relative: canonical_json(old_interventions),
        proof_relative: canonical_json(old_proofs),
        "reprobit/project.json": b"sealed project authority\n",
        "src/sample.cpp": b"int sample() { return 1; }\n",
    }
    snapshots = tuple(
        _write_and_snapshot(root, relative, payload) for relative, payload in original.items()
    )
    authority_directories = _authority_directories(root)
    concurrent = b"concurrent edit after grind capture\n"
    root.joinpath(*changed_relative.split("/")).write_bytes(concurrent)
    expected_after_conflict = {**original, changed_relative: concurrent}

    with pytest.raises(TransactionConflict, match="transaction preimage conflict"):
        grind._publish_solution(
            root,
            snapshots,
            authority_directories,
            intervention_relative,
            proof_relative,
            new_interventions,
            new_proofs,
        )

    for relative, payload in expected_after_conflict.items():
        assert root.joinpath(*relative.split("/")).read_bytes() == payload
    assert root.joinpath(*intervention_relative.split("/")).read_bytes() != canonical_json(
        new_interventions
    )
    assert root.joinpath(*proof_relative.split("/")).read_bytes() != canonical_json(new_proofs)
    transaction_root = root / ".reprobit-transactions"
    assert not any(path.is_dir() for path in transaction_root.iterdir())


@pytest.mark.parametrize(
    "directory_relative",
    (
        "reprobit/interventions",
        "reprobit/proofs",
        "reprobit/oracles",
    ),
)
def test_publication_rejects_concurrent_authority_insertion(
    tmp_path: Path,
    directory_relative: str,
) -> None:
    root = tmp_path.resolve()
    intervention_relative = "reprobit/interventions/sample.json"
    proof_relative = "reprobit/proofs/sample.json"
    old_interventions = InterventionDocument(schema_version=3, target_id="sample.target")
    old_proofs = ProofDocument(schema_version=3, target_id="sample.target")
    snapshots = (
        _write_and_snapshot(root, intervention_relative, canonical_json(old_interventions)),
        _write_and_snapshot(root, proof_relative, canonical_json(old_proofs)),
    )
    authority_directories = _authority_directories(root)
    inserted = root / directory_relative / "concurrent.json"
    inserted.write_bytes(b"concurrent authority\n")

    with pytest.raises(TransactionConflict, match="authority membership conflict"):
        grind._publish_solution(
            root,
            snapshots,
            authority_directories,
            intervention_relative,
            proof_relative,
            InterventionDocument(
                schema_version=3,
                target_id="sample.target",
                translation_unit_id="sample.tu",
            ),
            ProofDocument(
                schema_version=3,
                target_id="sample.target",
                translation_unit_id="sample.tu",
            ),
        )

    assert inserted.read_bytes() == b"concurrent authority\n"
    assert root.joinpath(intervention_relative).read_bytes() == canonical_json(old_interventions)
    assert root.joinpath(proof_relative).read_bytes() == canonical_json(old_proofs)
