"""Private staging and atomic publication for guided CMake source-set refreshes."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING

from reprobit.authority_snapshot import (
    AuthoritySnapshotError,
    JsonAuthorityDirectorySnapshot,
    capture_json_authority_directories,
    json_authority_members,
)
from reprobit.cli_paths import CLIError, safe_project_path
from reprobit.cli_project import SourceLockPlan
from reprobit.cmake_import import json_authority_paths
from reprobit.composition_ledger import COMPOSED_BODY_LEDGER_RELATIVE
from reprobit.model import Digest
from reprobit.project_loader import load_project_tree
from reprobit.publication_evidence import (
    PublicationEvidenceError,
    SealedProjectPostimage,
    VerifiedPublicationEvidence,
    capture_project_postimage,
    collect_verified_publication_evidence,
    require_project_postimage,
)
from reprobit.schema import (
    BuildPlanDocument,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    ProjectSpec,
    ProofDocument,
    source_manifest_digest,
)
from reprobit.source_lock import SourceLockError, receipt_source_input
from reprobit.staged_project import ProjectFileSnapshot, StagedProject
from reprobit.state import KeepWorkspace, report_publication_lease
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction, TransactionResult

if TYPE_CHECKING:
    from reprobit.cli_build import VerifyResult


@dataclass(frozen=True, slots=True)
class CMakeRefreshSnapshot:
    """Every real-project byte consumed by one private refresh."""

    root: Path
    spec: ProjectSpec
    files: tuple[ProjectFileSnapshot, ...]
    authority_directories: tuple[JsonAuthorityDirectorySnapshot, ...]
    outputs: tuple[CMakeRefreshOutputSnapshot, ...]
    reports: tuple[CMakeRefreshOutputSnapshot, ...]
    ledger: CMakeRefreshOutputSnapshot

    @property
    def files_by_path(self) -> dict[str, ProjectFileSnapshot]:
        return {item.relative_path: item for item in self.files}


@dataclass(frozen=True, slots=True)
class SavedTranslationUnitAuthority:
    """One old TU binding and its exact intervention/proof documents."""

    unit: ClassicTranslationUnitPlan
    intervention_path: str
    intervention: InterventionDocument
    intervention_payload: bytes
    proof_path: str
    proof: ProofDocument
    proof_payload: bytes

    @property
    def empty(self) -> bool:
        return not self.intervention.interventions and not self.proof.expected_observations


@dataclass(frozen=True, slots=True)
class CMakeRefreshOutputSnapshot:
    """The start-of-refresh state of one verified result seat."""

    relative_path: str
    digest: Digest | None


CMakeRefreshEvidence = VerifiedPublicationEvidence


@dataclass(frozen=True, slots=True)
class CMakeRefreshCandidateSeal:
    """Candidate authority bytes sealed before the cold verification starts."""

    postimages: tuple[SealedProjectPostimage, ...]
    authority_members: tuple[tuple[str, tuple[str, ...]], ...]
    records: Mapping[str, bytes | None]
    record_digests: Mapping[str, Digest | None]

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", MappingProxyType(dict(self.records)))
        object.__setattr__(self, "record_digests", MappingProxyType(dict(self.record_digests)))


@dataclass(frozen=True, slots=True)
class CMakeRefreshResult:
    """Published authority counts for one verified refresh."""

    transaction: TransactionResult
    preserved_translation_units: int
    reset_translation_units: int
    added_translation_units: int
    retired_translation_units: int
    outputs: tuple[Path, ...]
    report_json: Path
    report_html: Path


def _capture_file(root: Path, relative: str) -> ProjectFileSnapshot:
    try:
        size, digest, payload = receipt_source_input(root, relative, capture=True)
    except SourceLockError as exc:
        raise CLIError(f"cannot seal CMake refresh input {relative!r}: {exc}") from exc
    assert payload is not None
    if size != len(payload):
        raise CLIError(f"CMake refresh input changed while it was read: {relative!r}")
    return ProjectFileSnapshot(relative, digest, payload)


def _capture_optional_output(root: Path, relative: str) -> CMakeRefreshOutputSnapshot:
    path = safe_project_path(root, relative)
    if not os.path.lexists(path):
        return CMakeRefreshOutputSnapshot(relative, None)
    if path.is_symlink() or not path.is_file():
        raise CLIError(f"CMake refresh output is not a regular file: {relative!r}")
    try:
        _size, digest, _payload = receipt_source_input(root, relative)
    except SourceLockError as exc:
        raise CLIError(f"cannot seal CMake refresh output {relative!r}: {exc}") from exc
    return CMakeRefreshOutputSnapshot(relative, digest)


def _output_paths(source_plan: SourceLockPlan) -> tuple[str, ...]:
    values = {target.artifact for target in source_plan.spec.targets}
    plan = source_plan.build_plan
    if plan is not None and plan.analysis_link_options:
        for target in source_plan.spec.targets:
            artifact = PurePosixPath(target.artifact)
            companion_root = artifact.parent / "reprobit-debug"
            values.add((companion_root / artifact.name).as_posix())
            values.add((companion_root / artifact.with_suffix(".PDB").name).as_posix())
    return tuple(sorted(values, key=lambda value: (value.casefold(), value)))


def capture_cmake_refresh_snapshot(source_plan: SourceLockPlan) -> CMakeRefreshSnapshot:
    """Capture the current authority plus every file selected by the new source plan."""

    root = source_plan.root
    spec = source_plan.spec
    if source_plan.build_plan is None:
        raise CLIError("--refresh needs an existing CMake build plan")
    graph = safe_project_path(root, spec.layout.producer_graph)
    if graph.is_symlink() or not graph.is_file():
        raise CLIError("--refresh needs an existing recorded CMake build")
    if source_plan.authority_error is not None:
        raise CLIError(
            "CMake refresh cannot safely reconcile the saved source records: "
            f"{source_plan.authority_error}"
        )
    try:
        authority = capture_json_authority_directories(
            root,
            (spec.layout.interventions, spec.layout.proofs, spec.layout.oracles),
        )
    except AuthoritySnapshotError as exc:
        raise CLIError(f"cannot seal CMake refresh authority: {exc}") from exc
    authority_paths = {
        relative for directory in authority for relative, _digest in directory.file_digests
    }
    required = {
        "reprobit.toml",
        spec.toolchain.lock_file,
        spec.layout.source_manifest,
        spec.layout.build_plan,
        spec.layout.producer_graph,
        *(entry.path for entry in source_plan.document.entries),
        *(target.oracle for target in spec.targets),
        *authority_paths,
    }
    relatives = tuple(sorted(required, key=lambda value: (value.casefold(), value)))
    if len({relative.casefold() for relative in relatives}) != len(relatives):
        raise CLIError("CMake refresh inputs collide under case-insensitive path rules")
    files = tuple(_capture_file(root, relative) for relative in relatives)
    captured = {item.relative_path: item.digest.value for item in files}
    for entry in source_plan.document.entries:
        if captured.get(entry.path) != entry.digest.value:
            raise CLIError(
                f"selected source changed while CMake refresh was starting: {entry.path}"
            )
    for directory in authority:
        if any(captured.get(relative) != digest for relative, digest in directory.file_digests):
            raise CLIError(f"CMake refresh authority changed: {directory.relative_path!r}")
    report_root = PurePosixPath(spec.state_dir) / "reports"
    report_paths = tuple((report_root / name).as_posix() for name in ("report.html", "report.json"))
    ledger_path = PurePosixPath(spec.state_dir).joinpath(*COMPOSED_BODY_LEDGER_RELATIVE).as_posix()
    return CMakeRefreshSnapshot(
        root,
        spec,
        files,
        authority,
        tuple(_capture_optional_output(root, relative) for relative in _output_paths(source_plan)),
        tuple(_capture_optional_output(root, relative) for relative in report_paths),
        _capture_optional_output(root, ledger_path),
    )


def stage_cmake_refresh(
    snapshot: CMakeRefreshSnapshot,
    *,
    keep: KeepWorkspace,
) -> StagedProject:
    return StagedProject(
        snapshot.root / snapshot.spec.state_dir,
        snapshot.files,
        kind="cmakerefresh",
        keep=keep,
        error=lambda relative: CLIError(f"staged CMake refresh input differs: {relative!r}"),
    )


def _documents_by_translation_unit(
    root: Path,
    spec: ProjectSpec,
) -> tuple[
    dict[str, tuple[str, InterventionDocument, bytes]], dict[str, tuple[str, ProofDocument, bytes]]
]:
    interventions: dict[str, tuple[str, InterventionDocument, bytes]] = {}
    for path in json_authority_paths(root, spec.layout.interventions):
        payload = path.read_bytes()
        intervention = InterventionDocument.model_validate_json(payload)
        if intervention.translation_unit_id is not None:
            interventions[intervention.translation_unit_id] = (
                path.relative_to(root).as_posix(),
                intervention,
                payload,
            )
    proofs: dict[str, tuple[str, ProofDocument, bytes]] = {}
    for path in json_authority_paths(root, spec.layout.proofs):
        payload = path.read_bytes()
        proof = ProofDocument.model_validate_json(payload)
        if proof.translation_unit_id is not None:
            proofs[proof.translation_unit_id] = (
                path.relative_to(root).as_posix(),
                proof,
                payload,
            )
    return interventions, proofs


def prepare_cmake_refresh_authority(root: Path) -> tuple[SavedTranslationUnitAuthority, ...]:
    """Temporarily remove TU records so CMake can derive a fresh unambiguous set."""

    bundle = load_project_tree(root, verify_source_authority=False, include_producer_graph=False)
    plan = bundle.build_plan
    if plan is None:
        raise CLIError("CMake refresh has no build plan")
    intervention_by_unit, proof_by_unit = _documents_by_translation_unit(root, bundle.spec)
    saved: list[SavedTranslationUnitAuthority] = []
    for unit in plan.translation_units:
        try:
            intervention_path, intervention, intervention_payload = intervention_by_unit[unit.id]
            proof_path, proof, proof_payload = proof_by_unit[unit.id]
        except KeyError as exc:
            raise CLIError(
                f"CMake refresh cannot find both authority files for {unit.id!r}"
            ) from exc
        saved.append(
            SavedTranslationUnitAuthority(
                unit,
                intervention_path,
                intervention,
                intervention_payload,
                proof_path,
                proof,
                proof_payload,
            )
        )

    temporary_plan = plan.model_copy(update={"translation_units": ()})
    transaction = CASTransaction(root)
    transaction.write(
        bundle.spec.layout.build_plan,
        canonical_json(temporary_plan),
        expected_sha256=Digest.from_path(
            safe_project_path(root, bundle.spec.layout.build_plan)
        ).value,
    )
    for item in saved:
        transaction.delete(
            item.intervention_path,
            expected_sha256=Digest.from_bytes(item.intervention_payload).value,
        )
        transaction.delete(
            item.proof_path,
            expected_sha256=Digest.from_bytes(item.proof_payload).value,
        )
    transaction.commit()
    try:
        load_project_tree(root, include_producer_graph=False)
    except ValueError as exc:
        raise CLIError(
            f"CMake refresh cannot safely carry the remaining source-derived authority: {exc}"
        ) from exc
    return tuple(saved)


def restore_compatible_translation_unit_authority(
    root: Path,
    saved: tuple[SavedTranslationUnitAuthority, ...],
) -> tuple[int, int, int, int]:
    """Restore compatible TU records and leave changed lanes fresh for verification."""

    bundle = load_project_tree(root)
    plan = bundle.build_plan
    if plan is None:
        raise CLIError("CMake refresh did not produce a build plan")
    old = {item.unit.id: item for item in saved}
    new = {item.id: item for item in plan.translation_units}
    preserved = 0
    reset = 0
    retired = 0
    restorable_ids: set[str] = set()
    for unit_id, item in old.items():
        replacement = new.get(unit_id)
        if replacement is None:
            retired += 1
            continue
        if (
            replacement.group_order is not None
            or replacement.model_copy(update={"group_order": item.unit.group_order}) != item.unit
        ):
            reset += 1
        else:
            restorable_ids.add(unit_id)
            preserved += 1

    intervention_by_unit, proof_by_unit = _documents_by_translation_unit(root, bundle.spec)
    fresh_ids = set(new) - restorable_ids
    for unit_id in sorted(fresh_ids, key=lambda value: (value.casefold(), value)):
        _intervention_path, intervention, _intervention_payload = intervention_by_unit[unit_id]
        _proof_path, proof, _proof_payload = proof_by_unit[unit_id]
        if intervention.interventions or proof.expected_observations:
            raise CLIError(f"new CMake authority for {unit_id!r} is not empty")
    restored_units = tuple(
        old[unit.id].unit if unit.id in restorable_ids else unit for unit in plan.translation_units
    )
    restored_plan = plan.model_copy(update={"translation_units": restored_units})
    transaction = CASTransaction(root)
    if restored_plan != plan:
        plan_path = safe_project_path(root, bundle.spec.layout.build_plan)
        transaction.write(
            bundle.spec.layout.build_plan,
            canonical_json(restored_plan),
            expected_sha256=Digest.from_path(plan_path).value,
        )
    for unit_id in sorted(restorable_ids, key=lambda value: (value.casefold(), value)):
        item = old[unit_id]
        fresh_intervention_path, fresh_intervention, fresh_intervention_payload = (
            intervention_by_unit[unit_id]
        )
        fresh_proof_path, fresh_proof, fresh_proof_payload = proof_by_unit[unit_id]
        if fresh_intervention.interventions or fresh_proof.expected_observations:
            raise CLIError(f"new CMake authority for {unit_id!r} is not empty")
        for fresh_path, fresh_payload, old_path, old_payload in (
            (
                fresh_intervention_path,
                fresh_intervention_payload,
                item.intervention_path,
                item.intervention_payload,
            ),
            (fresh_proof_path, fresh_proof_payload, item.proof_path, item.proof_payload),
        ):
            if fresh_path == old_path:
                transaction.write(
                    old_path,
                    old_payload,
                    expected_sha256=Digest.from_bytes(fresh_payload).value,
                )
                continue
            old_seat = safe_project_path(root, old_path)
            if os.path.lexists(old_seat):
                raise CLIError(f"CMake refresh cannot restore occupied authority {old_path!r}")
            transaction.delete(
                fresh_path,
                expected_sha256=Digest.from_bytes(fresh_payload).value,
            )
            transaction.write(old_path, old_payload, expected_sha256=None)
    transaction.commit()
    try:
        load_project_tree(root)
    except ValueError as exc:
        raise CLIError(f"refreshed CMake authority is not self-consistent: {exc}") from exc
    return preserved, reset, len(set(new) - set(old)), retired


def capture_cmake_refresh_candidate(
    snapshot: CMakeRefreshSnapshot,
    staged_root: Path,
    *,
    saved_translation_units: tuple[SavedTranslationUnitAuthority, ...],
) -> CMakeRefreshCandidateSeal:
    """Validate and seal the complete authority candidate before verification."""

    bundle = load_project_tree(staged_root)
    if bundle.source_manifest is None or bundle.build_plan is None:
        raise CLIError("CMake refresh candidate is missing source/build authority")
    before = snapshot.files_by_path
    old_plan = BuildPlanDocument.model_validate_json(
        before[snapshot.spec.layout.build_plan].payload
    )
    expected_plan = old_plan.model_copy(
        update={
            "source_manifest_digest": source_manifest_digest(bundle.source_manifest),
            "translation_units": bundle.build_plan.translation_units,
        }
    )
    if bundle.build_plan != expected_plan:
        raise CLIError("CMake refresh changed build authority outside the source-unit list")

    intervention_by_unit, proof_by_unit = _documents_by_translation_unit(
        staged_root,
        snapshot.spec,
    )
    new_unit_ids = {unit.id for unit in bundle.build_plan.translation_units}
    mutable = {
        snapshot.spec.layout.source_manifest,
        snapshot.spec.layout.build_plan,
        snapshot.spec.layout.producer_graph,
        *(item.intervention_path for item in saved_translation_units),
        *(item.proof_path for item in saved_translation_units),
        *(intervention_by_unit[unit_id][0] for unit_id in new_unit_ids),
        *(proof_by_unit[unit_id][0] for unit_id in new_unit_ids),
    }
    candidate_paths = _candidate_authority_paths(snapshot, staged_root)
    postimages: list[SealedProjectPostimage] = []
    records: dict[str, bytes | None] = {}
    record_digests: dict[str, Digest | None] = {}
    for relative in candidate_paths:
        try:
            postimage = capture_project_postimage(staged_root, relative)
        except PublicationEvidenceError as exc:
            raise CLIError(str(exc)) from exc
        postimages.append(postimage)
        old = before.get(relative)
        old_payload = old.payload if old is not None else None
        if relative not in mutable and postimage.payload != old_payload:
            raise CLIError(f"CMake refresh changed unrelated authority: {relative!r}")
        if postimage.payload != old_payload:
            records[relative] = postimage.payload
            record_digests[relative] = postimage.digest

    publishable = set(candidate_paths)
    for item in snapshot.files:
        if item.relative_path in publishable:
            continue
        candidate = safe_project_path(staged_root, item.relative_path)
        if not candidate.is_file() or Digest.from_path(candidate) != item.digest:
            raise CLIError(f"CMake refresh modified a sealed input: {item.relative_path!r}")
    members = tuple(
        (directory.relative_path, json_authority_members(staged_root, directory.relative_path))
        for directory in snapshot.authority_directories
    )
    return CMakeRefreshCandidateSeal(
        tuple(postimages),
        members,
        records,
        record_digests,
    )


def collect_cmake_refresh_evidence(
    snapshot: CMakeRefreshSnapshot,
    staged_root: Path,
    *,
    candidate: CMakeRefreshCandidateSeal,
    verified: VerifyResult,
) -> CMakeRefreshEvidence:
    """Bind accepted verification evidence to the sealed candidate bytes."""

    try:
        for relative, members in candidate.authority_members:
            if json_authority_members(staged_root, relative) != members:
                raise CLIError(f"CMake refresh authority changed after verification: {relative!r}")
        for postimage in candidate.postimages:
            require_project_postimage(staged_root, postimage)
        report_preimages = {item.relative_path for item in snapshot.reports}
        report_json_relative = next(
            relative for relative in report_preimages if relative.endswith("report.json")
        )
        report_html_relative = next(
            relative for relative in report_preimages if relative.endswith("report.html")
        )
        return collect_verified_publication_evidence(
            verified,
            staged_root=staged_root,
            output_paths=tuple(item.relative_path for item in snapshot.outputs),
            target_paths=tuple(target.artifact for target in snapshot.spec.targets),
            report_json=safe_project_path(staged_root, report_json_relative),
            report_html=safe_project_path(staged_root, report_html_relative),
            ledger_path=safe_project_path(staged_root, snapshot.ledger.relative_path),
        )
    except (AuthoritySnapshotError, PublicationEvidenceError) as exc:
        raise CLIError(str(exc)) from exc


def _candidate_authority_paths(
    snapshot: CMakeRefreshSnapshot,
    staged_root: Path,
) -> tuple[str, ...]:
    values = {
        snapshot.spec.layout.source_manifest,
        snapshot.spec.layout.build_plan,
        snapshot.spec.layout.producer_graph,
    }
    for relative in (snapshot.spec.layout.interventions, snapshot.spec.layout.proofs):
        values.update(
            f"{relative.rstrip('/')}/{member}"
            for member in json_authority_members(staged_root, relative)
        )
        original = next(
            directory
            for directory in snapshot.authority_directories
            if directory.relative_path == relative
        )
        values.update(f"{relative.rstrip('/')}/{member}" for member in original.json_members)
    return tuple(sorted(values, key=lambda value: (value.casefold(), value)))


def publish_cmake_refresh(
    snapshot: CMakeRefreshSnapshot,
    *,
    candidate: CMakeRefreshCandidateSeal,
    evidence: CMakeRefreshEvidence,
    preserved_translation_units: int,
    reset_translation_units: int,
    added_translation_units: int,
    retired_translation_units: int,
) -> CMakeRefreshResult:
    """Publish only the verified source/build records in one real-project CAS."""

    before = snapshot.files_by_path
    transaction = CASTransaction(snapshot.root)
    for directory in snapshot.authority_directories:
        transaction.assert_json_members(
            directory.relative_path,
            expected_members=directory.json_members,
        )
    for relative, payload in sorted(candidate.records.items()):
        digest = candidate.record_digests.get(relative)
        if (Digest.from_bytes(payload) if payload is not None else None) != digest:
            raise CLIError(f"CMake refresh record payload differs from its seal: {relative!r}")
        old = before.get(relative)
        expected = old.digest.value if old is not None else None
        if payload is None:
            transaction.delete(relative, expected_sha256=expected)
        else:
            transaction.write(relative, payload, expected_sha256=expected)
    for item in snapshot.files:
        if item.relative_path not in candidate.records:
            transaction.assert_unchanged(item.relative_path, expected_sha256=item.digest.value)

    output_preimages = {item.relative_path: item.digest for item in snapshot.outputs}
    if set(output_preimages) != set(evidence.outputs):
        raise CLIError("cold verification produced a different refresh output set")
    for relative, payload in sorted(evidence.outputs.items()):
        preimage = output_preimages[relative]
        transaction.write(
            relative,
            payload,
            expected_sha256=preimage.value if preimage is not None else None,
        )

    report_preimages = {item.relative_path: item.digest for item in snapshot.reports}
    report_payloads = {
        next(relative for relative in report_preimages if relative.endswith("report.json")): (
            evidence.report_json
        ),
        next(relative for relative in report_preimages if relative.endswith("report.html")): (
            evidence.report_html
        ),
    }
    for relative, payload in sorted(report_payloads.items()):
        preimage = report_preimages[relative]
        transaction.write(
            relative,
            payload,
            expected_sha256=preimage.value if preimage is not None else None,
        )

    ledger_preimage = snapshot.ledger.digest
    if evidence.composed_body_ledger is not None:
        transaction.write(
            snapshot.ledger.relative_path,
            evidence.composed_body_ledger,
            expected_sha256=ledger_preimage.value if ledger_preimage is not None else None,
        )
    elif ledger_preimage is not None:
        transaction.delete(
            snapshot.ledger.relative_path,
            expected_sha256=ledger_preimage.value,
        )
    else:
        transaction.assert_unchanged(snapshot.ledger.relative_path, expected_sha256=None)
    with report_publication_lease(snapshot.root / snapshot.spec.state_dir):
        result = transaction.commit()
    return CMakeRefreshResult(
        result,
        preserved_translation_units,
        reset_translation_units,
        added_translation_units,
        retired_translation_units,
        tuple(safe_project_path(snapshot.root, relative) for relative in sorted(evidence.outputs)),
        safe_project_path(
            snapshot.root,
            next(relative for relative in report_preimages if relative.endswith("report.json")),
        ),
        safe_project_path(
            snapshot.root,
            next(relative for relative in report_preimages if relative.endswith("report.html")),
        ),
    )


__all__ = [
    "CMakeRefreshCandidateSeal",
    "CMakeRefreshEvidence",
    "CMakeRefreshOutputSnapshot",
    "CMakeRefreshResult",
    "CMakeRefreshSnapshot",
    "SavedTranslationUnitAuthority",
    "capture_cmake_refresh_candidate",
    "capture_cmake_refresh_snapshot",
    "collect_cmake_refresh_evidence",
    "prepare_cmake_refresh_authority",
    "publish_cmake_refresh",
    "restore_compatible_translation_unit_authority",
    "stage_cmake_refresh",
]
