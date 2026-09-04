"""Private project staging and atomic publication for source repair."""

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
    resolve_project_path,
)
from reprobit.cli_paths import report_output_conflict
from reprobit.composition_ledger import COMPOSED_BODY_LEDGER_RELATIVE
from reprobit.model import Digest
from reprobit.project_loader import load_project
from reprobit.publication_evidence import (
    PublicationEvidenceError,
    SealedProjectPostimage,
    capture_project_postimage,
    collect_verified_publication_evidence,
    require_project_postimage,
)
from reprobit.schema import BuildPlanDocument, ProjectSpec, SourceManifestDocument
from reprobit.source_lock import (
    SourceLockError,
    receipt_source_input,
)
from reprobit.staged_project import ProjectFileSnapshot, StagedProject
from reprobit.state import KeepWorkspace, report_publication_lease
from reprobit.transactions import CASTransaction, TransactionResult

if TYPE_CHECKING:
    from reprobit.project_execution import VerifyResult


class RepairError(RuntimeError):
    """A repair cannot be staged or published without weakening its boundary."""


@dataclass(frozen=True, slots=True)
class RepairOutputSnapshot:
    """The start-of-run state of one public output repair may replace."""

    relative_path: str
    digest: Digest | None


RepairRecordPostimage = SealedProjectPostimage


@dataclass(frozen=True, slots=True)
class RepairRecordSeal:
    """All staged authority bytes and memberships sealed before verification."""

    postimages: tuple[RepairRecordPostimage, ...]
    authority_members: tuple[tuple[str, tuple[str, ...]], ...]
    authorized_paths: frozenset[str]


@dataclass(frozen=True, slots=True)
class RepairSnapshot:
    """Complete inputs and publishable records for one private repair run."""

    root: Path
    spec: ProjectSpec
    source_manifest: SourceManifestDocument
    files: tuple[ProjectFileSnapshot, ...]
    authority_directories: tuple[JsonAuthorityDirectorySnapshot, ...]
    outputs: tuple[RepairOutputSnapshot, ...]
    ledger: RepairOutputSnapshot

    @property
    def files_by_path(self) -> dict[str, ProjectFileSnapshot]:
        return {item.relative_path: item for item in self.files}


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    """Verified project-record and report bytes ready for one CAS publish."""

    records: Mapping[str, bytes | None]
    record_digests: Mapping[str, Digest | None]
    outputs: Mapping[str, bytes]
    report_json: bytes
    report_html: bytes
    composed_body_ledger: bytes | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", MappingProxyType(dict(self.records)))
        object.__setattr__(self, "record_digests", MappingProxyType(dict(self.record_digests)))
        object.__setattr__(self, "outputs", MappingProxyType(dict(self.outputs)))


def _safe_path(root: Path, relative: str) -> Path:
    return resolve_project_path(root, relative, error=RepairError, subject="repair input")


def _capture_file(root: Path, relative: str) -> ProjectFileSnapshot:
    try:
        size, digest, payload = receipt_source_input(root, relative, capture=True)
    except SourceLockError as exc:
        raise RepairError(f"cannot seal repair input {relative!r}: {exc}") from exc
    assert payload is not None
    if size != len(payload):
        raise RepairError(f"repair input changed while it was read: {relative!r}")
    return ProjectFileSnapshot(relative, digest, payload)


def _capture_optional_output(root: Path, relative: str) -> RepairOutputSnapshot:
    path = _safe_path(root, relative)
    if not os.path.lexists(path):
        return RepairOutputSnapshot(relative, None)
    if path.is_symlink() or not path.is_file():
        raise RepairError(f"repair output is not a regular file: {relative!r}")
    try:
        _size, digest, _payload = receipt_source_input(root, relative)
    except SourceLockError as exc:
        raise RepairError(f"cannot seal repair output {relative!r}: {exc}") from exc
    return RepairOutputSnapshot(relative, digest)


def _repair_output_paths(spec: ProjectSpec, plan: BuildPlanDocument) -> tuple[str, ...]:
    values = {target.artifact for target in spec.targets}
    if plan.analysis_link_options:
        for target in spec.targets:
            artifact = PurePosixPath(target.artifact)
            companion_root = artifact.parent / "reprobit-debug"
            values.add((companion_root / artifact.name).as_posix())
            values.add((companion_root / artifact.with_suffix(".PDB").name).as_posix())
    return tuple(sorted(values, key=lambda item: (item.casefold(), item)))


def _missing_locked_sources(
    root: Path,
    manifest: SourceManifestDocument,
) -> tuple[str, ...]:
    """Require the exact locked read set without silently selecting new files."""

    locked = {entry.path for entry in manifest.entries}
    missing_or_unsafe = {
        relative for relative in locked if not _safe_path(root, relative).is_file()
    }
    return tuple(sorted(missing_or_unsafe, key=lambda item: (item.casefold(), item)))


def _require_stable_source_membership(
    root: Path,
    manifest: SourceManifestDocument,
) -> None:
    removed = _missing_locked_sources(root, manifest)
    if not removed:
        return
    details = ["Removed: " + ", ".join(removed)]
    details.extend(
        (
            "From the project root, review this list with: rbit source preview .",
            "Follow the safe next command printed by preview to update the source and "
            "build records together.",
        )
    )
    raise RepairError(
        "repair cannot start because the reviewed source-file list changed "
        f"(+0 -{len(removed)}).\n" + "\n".join(details)
    )


def capture_repair_snapshot(project_root: Path) -> RepairSnapshot:
    """Capture every project byte that private verification may consume."""

    root = project_root.resolve(strict=True)
    config = _capture_file(root, "reprobit.toml")
    spec = load_project(root)
    if _capture_file(root, "reprobit.toml").digest != config.digest:
        raise RepairError("reprobit.toml changed while repair was starting")

    manifest_relative = spec.layout.source_manifest
    manifest_snapshot = _capture_file(root, manifest_relative)
    try:
        manifest = SourceManifestDocument.model_validate_json(manifest_snapshot.payload)
    except ValueError as exc:
        raise RepairError(f"repair source lock is invalid: {exc}") from exc
    if not manifest.complete:
        raise RepairError("repair needs a complete source lock; run rbit setup first")
    _require_stable_source_membership(root, manifest)

    try:
        directories = capture_json_authority_directories(
            root,
            (
                spec.layout.interventions,
                spec.layout.proofs,
                spec.layout.oracles,
            ),
        )
    except AuthoritySnapshotError as exc:
        raise RepairError(f"cannot seal repair authority: {exc}") from exc
    authority_relatives: set[str] = set()
    for directory in directories:
        authority_relatives.update(path for path, _digest in directory.file_digests)

    required = {
        "reprobit.toml",
        spec.toolchain.lock_file,
        manifest_relative,
        spec.layout.build_plan,
        *(entry.path for entry in manifest.entries),
        *(target.oracle for target in spec.targets),
        *authority_relatives,
    }
    if _safe_path(root, spec.layout.producer_graph).is_file():
        required.add(spec.layout.producer_graph)
    canonical = tuple(sorted(required, key=lambda item: (item.casefold(), item)))
    if len({item.casefold() for item in canonical}) != len(canonical):
        raise RepairError("repair inputs collide under case-insensitive path rules")

    files: list[ProjectFileSnapshot] = []
    for relative in canonical:
        files.append(config if relative == "reprobit.toml" else _capture_file(root, relative))
    for directory in directories:
        try:
            members = json_authority_members(root, directory.relative_path)
        except AuthoritySnapshotError as exc:
            raise RepairError(f"cannot recheck repair authority: {exc}") from exc
        if members != directory.json_members:
            raise RepairError(f"repair authority membership changed: {directory.relative_path!r}")
    by_path = {item.relative_path: item for item in files}
    try:
        plan = BuildPlanDocument.model_validate_json(by_path[spec.layout.build_plan].payload)
    except (KeyError, ValueError) as exc:
        raise RepairError(f"repair build plan is invalid: {exc}") from exc
    outputs = tuple(
        _capture_optional_output(root, relative) for relative in _repair_output_paths(spec, plan)
    )
    ledger_relative = (
        PurePosixPath(spec.state_dir).joinpath(*COMPOSED_BODY_LEDGER_RELATIVE).as_posix()
    )
    return RepairSnapshot(
        root=root,
        spec=spec,
        source_manifest=manifest,
        files=tuple(files),
        authority_directories=tuple(directories),
        outputs=outputs,
        ledger=_capture_optional_output(root, ledger_relative),
    )


def stage_repair_project(snapshot: RepairSnapshot, *, keep: KeepWorkspace) -> StagedProject:
    """Stage every sealed repair input inside a run-private ``repair`` arena."""

    return StagedProject(
        snapshot.root / snapshot.spec.state_dir,
        snapshot.files,
        kind="repair",
        keep=keep,
        error=lambda relative: RepairError(f"staged repair input differs: {relative!r}"),
    )


def _publishable_paths(snapshot: RepairSnapshot, staged_root: Path) -> tuple[str, ...]:
    values = {
        "reprobit.toml",
        snapshot.spec.layout.source_manifest,
        snapshot.spec.layout.build_plan,
        snapshot.spec.layout.producer_graph,
    }
    writable_directories = {
        snapshot.spec.layout.interventions,
        snapshot.spec.layout.proofs,
    }
    for directory in snapshot.authority_directories:
        try:
            staged_members = json_authority_members(staged_root, directory.relative_path)
        except AuthoritySnapshotError as exc:
            raise RepairError(f"cannot inspect staged repair authority: {exc}") from exc
        if directory.relative_path not in writable_directories:
            if staged_members != directory.json_members:
                raise RepairError(
                    f"repair modified sealed authority membership: {directory.relative_path!r}"
                )
            continue
        values.update(
            f"{directory.relative_path.rstrip('/')}/{member}" for member in directory.json_members
        )
        values.update(
            f"{directory.relative_path.rstrip('/')}/{member}" for member in staged_members
        )
    return tuple(sorted(values, key=lambda item: (item.casefold(), item)))


def collect_repair_candidate(
    snapshot: RepairSnapshot,
    staged_root: Path,
    *,
    report_directory: str,
    verified: VerifyResult | None = None,
    record_postimages: RepairRecordSeal | None = None,
) -> RepairCandidate:
    """Collect only verified records and reports, refusing other input mutation."""

    by_path = snapshot.files_by_path
    publishable = set(_publishable_paths(snapshot, staged_root))
    if record_postimages is None:
        # Direct boundary tests may intentionally fail before a verifier exists.
        records: dict[str, bytes | None] = {}
        record_digests: dict[str, Digest | None] = {}
        for relative in sorted(publishable, key=lambda item: (item.casefold(), item)):
            try:
                postimage = capture_project_postimage(staged_root, relative)
            except PublicationEvidenceError as exc:
                raise RepairError(str(exc)) from exc
            before = by_path.get(relative)
            if postimage.payload != (before.payload if before is not None else None):
                records[relative] = postimage.payload
                record_digests[relative] = postimage.digest
        if records:
            raise RepairError(
                f"repair modified records outside its mutation ledger: {sorted(records)}"
            )
    else:
        sealed = {item.relative_path: item for item in record_postimages.postimages}
        if len(sealed) != len(record_postimages.postimages):
            raise RepairError("repair record postimages repeat a path")
        if set(sealed) != publishable:
            raise RepairError("repair authority membership changed after verification")
        for relative, members in record_postimages.authority_members:
            try:
                actual_members = json_authority_members(staged_root, relative)
            except AuthoritySnapshotError as exc:
                raise RepairError(f"cannot recheck staged repair authority: {exc}") from exc
            if actual_members != members:
                raise RepairError(
                    f"repair authority membership changed after verification: {relative!r}"
                )
        try:
            for postimage in record_postimages.postimages:
                require_project_postimage(staged_root, postimage)
        except PublicationEvidenceError as exc:
            raise RepairError(str(exc).replace("publication", "repair record", 1)) from exc
        records = {}
        record_digests = {}
        for relative, postimage in sealed.items():
            before = by_path.get(relative)
            if postimage.payload != (before.payload if before is not None else None):
                records[relative] = postimage.payload
                record_digests[relative] = postimage.digest
        unauthorized = set(records) - record_postimages.authorized_paths
        if unauthorized:
            raise RepairError(
                f"repair modified records outside its mutation ledger: {sorted(unauthorized)}"
            )

    for snapshot_file in snapshot.files:
        if snapshot_file.relative_path in publishable:
            continue
        candidate = _safe_path(staged_root, snapshot_file.relative_path)
        if not candidate.is_file() or Digest.from_path(candidate) != snapshot_file.digest:
            raise RepairError(f"repair modified a sealed input: {snapshot_file.relative_path!r}")

    if verified is None:
        raise RepairError("repair candidate has no verification result")
    report_root = _safe_path(staged_root, report_directory)
    try:
        evidence = collect_verified_publication_evidence(
            verified,
            staged_root=staged_root,
            output_paths=tuple(item.relative_path for item in snapshot.outputs),
            target_paths=tuple(target.artifact for target in snapshot.spec.targets),
            report_json=report_root / "report.json",
            report_html=report_root / "report.html",
            ledger_path=_safe_path(staged_root, snapshot.ledger.relative_path),
        )
    except PublicationEvidenceError as exc:
        raise RepairError(str(exc)) from exc
    return RepairCandidate(
        records=records,
        record_digests=record_digests,
        outputs=evidence.outputs,
        report_json=evidence.report_json,
        report_html=evidence.report_html,
        composed_body_ledger=evidence.composed_body_ledger,
    )


def capture_repair_record_postimages(
    snapshot: RepairSnapshot,
    staged_root: Path,
    relative_paths: set[str],
) -> RepairRecordSeal:
    """Seal the exact postimages that typed staged repair steps may publish."""

    publishable = set(_publishable_paths(snapshot, staged_root))
    unknown = relative_paths - publishable
    if unknown:
        raise RepairError(f"repair mutation ledger names unknown records: {sorted(unknown)}")
    postimages: list[RepairRecordPostimage] = []
    for relative in sorted(publishable, key=lambda item: (item.casefold(), item)):
        try:
            postimages.append(capture_project_postimage(staged_root, relative))
        except PublicationEvidenceError as exc:
            raise RepairError(str(exc)) from exc
    by_path = snapshot.files_by_path
    changed = {
        item.relative_path
        for item in postimages
        if item.payload
        != (by_path[item.relative_path].payload if item.relative_path in by_path else None)
    }
    unauthorized = changed - relative_paths
    if unauthorized:
        raise RepairError(
            f"repair modified records outside its mutation ledger: {sorted(unauthorized)}"
        )
    members = tuple(
        (directory.relative_path, json_authority_members(staged_root, directory.relative_path))
        for directory in snapshot.authority_directories
    )
    return RepairRecordSeal(tuple(postimages), members, frozenset(relative_paths))


def publish_repair_candidate(
    snapshot: RepairSnapshot,
    candidate: RepairCandidate,
    *,
    report_directory: str,
    report_preimages: tuple[RepairOutputSnapshot, ...],
) -> TransactionResult:
    """Publish verified records and canonical reports in one compare-and-swap."""

    by_path = snapshot.files_by_path
    transaction = CASTransaction(snapshot.root)
    for relative, payload in sorted(candidate.records.items()):
        digest = candidate.record_digests.get(relative)
        if (Digest.from_bytes(payload) if payload is not None else None) != digest:
            raise RepairError(f"repair record payload differs from its seal: {relative!r}")
        original = by_path.get(relative)
        expected = original.digest.value if original is not None else None
        if payload is None:
            transaction.delete(relative, expected_sha256=expected)
        else:
            transaction.write(relative, payload, expected_sha256=expected)

    for snapshot_file in snapshot.files:
        if snapshot_file.relative_path in candidate.records:
            continue
        transaction.assert_unchanged(
            snapshot_file.relative_path,
            expected_sha256=snapshot_file.digest.value,
        )
    for directory in snapshot.authority_directories:
        transaction.assert_json_members(
            directory.relative_path,
            expected_members=directory.json_members,
        )

    output_preimages = {item.relative_path: item.digest for item in snapshot.outputs}
    if set(candidate.outputs) != set(output_preimages):
        raise RepairError("cold verification produced a different repair output set")
    for relative, payload in sorted(candidate.outputs.items()):
        output_preimage = output_preimages[relative]
        transaction.write(
            relative,
            payload,
            expected_sha256=output_preimage.value if output_preimage is not None else None,
        )

    report_root = PurePosixPath(report_directory)
    if (
        report_root.is_absolute()
        or not report_root.parts
        or any(part in {"", ".", ".."} for part in report_root.parts)
    ):
        raise RepairError(f"repair report directory is not canonical: {report_directory!r}")
    report_expected = {item.relative_path: item.digest for item in report_preimages}
    report_payloads = {
        (report_root / "report.json").as_posix(): candidate.report_json,
        (report_root / "report.html").as_posix(): candidate.report_html,
    }
    if set(report_expected) != set(report_payloads):
        raise RepairError("repair report preimages name a different output set")
    for relative, payload in sorted(report_payloads.items()):
        preimage = report_expected[relative]
        transaction.write(
            relative,
            payload,
            expected_sha256=preimage.value if preimage is not None else None,
        )
    ledger_preimage = snapshot.ledger.digest
    if candidate.composed_body_ledger is not None:
        transaction.write(
            snapshot.ledger.relative_path,
            candidate.composed_body_ledger,
            expected_sha256=ledger_preimage.value if ledger_preimage is not None else None,
        )
    elif ledger_preimage is not None:
        transaction.delete(
            snapshot.ledger.relative_path,
            expected_sha256=ledger_preimage.value,
        )
    else:
        transaction.assert_unchanged(
            snapshot.ledger.relative_path,
            expected_sha256=None,
        )
    with report_publication_lease(snapshot.root / snapshot.spec.state_dir):
        return transaction.commit()


def validate_repair_report_directory(snapshot: RepairSnapshot, relative: str) -> None:
    """Keep report artifacts outside project authority and public output seats."""

    report_root = PurePosixPath(relative)
    if (
        report_root.is_absolute()
        or not report_root.parts
        or any(part in {"", ".", ".."} for part in report_root.parts)
    ):
        raise RepairError("repair report directory must be a canonical project-relative path")
    physical = _safe_path(snapshot.root, relative)
    if physical.exists() and not physical.is_dir():
        raise RepairError(f"repair report destination is not a directory: {relative!r}")
    folded = relative.casefold().rstrip("/")
    for directory in snapshot.authority_directories:
        protected = directory.relative_path.casefold().rstrip("/")
        if folded == protected or folded.startswith(protected + "/"):
            raise RepairError(
                f"repair report directory enters saved authority: {directory.relative_path!r}"
            )
    report_files = {
        (report_root / "report.json").as_posix().casefold(),
        (report_root / "report.html").as_posix().casefold(),
    }
    protected_files = {item.relative_path.casefold() for item in snapshot.files}
    protected_files.update(item.relative_path.casefold() for item in snapshot.outputs)
    if report_files & protected_files:
        raise RepairError("repair report files overlap a protected project input or output")
    conflict = report_output_conflict(
        snapshot.root,
        snapshot.spec,
        (
            ("JSON report", _safe_path(snapshot.root, (report_root / "report.json").as_posix())),
            ("HTML report", _safe_path(snapshot.root, (report_root / "report.html").as_posix())),
        ),
        source_paths=(entry.path for entry in snapshot.source_manifest.entries),
    )
    if conflict is not None:
        raise RepairError(conflict)


def capture_repair_report_preimages(
    snapshot: RepairSnapshot,
    relative: str,
) -> tuple[RepairOutputSnapshot, ...]:
    """Seal both canonical report seats before a long repair starts."""

    validate_repair_report_directory(snapshot, relative)
    root = PurePosixPath(relative)
    return tuple(
        _capture_optional_output(snapshot.root, (root / name).as_posix())
        for name in ("report.html", "report.json")
    )


__all__ = [
    "RepairCandidate",
    "RepairError",
    "RepairOutputSnapshot",
    "RepairRecordPostimage",
    "RepairRecordSeal",
    "RepairSnapshot",
    "capture_repair_record_postimages",
    "capture_repair_report_preimages",
    "capture_repair_snapshot",
    "collect_repair_candidate",
    "publish_repair_candidate",
    "stage_repair_project",
    "validate_repair_report_directory",
]
