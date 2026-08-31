"""Private project staging and atomic publication for source repair."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType

from reprobit.authority_snapshot import (
    AuthoritySnapshotError,
    JsonAuthorityDirectorySnapshot,
    capture_json_authority_directories,
    json_authority_members,
)
from reprobit.model import Digest
from reprobit.project_loader import load_project
from reprobit.schema import BuildPlanDocument, ProjectSpec, SourceManifestDocument
from reprobit.source_lock import SourceLockError, receipt_source_input
from reprobit.state import KeepWorkspace, RunArena, report_publication_lease
from reprobit.transactions import CASTransaction, TransactionResult


class RepairError(RuntimeError):
    """A repair cannot be staged or published without weakening its boundary."""


@dataclass(frozen=True, slots=True)
class RepairFileSnapshot:
    """One immutable project input captured before repair begins."""

    relative_path: str
    digest: Digest
    payload: bytes


@dataclass(frozen=True, slots=True)
class RepairOutputSnapshot:
    """The start-of-run state of one public output repair may replace."""

    relative_path: str
    digest: Digest | None


@dataclass(frozen=True, slots=True)
class RepairSnapshot:
    """Complete inputs and publishable records for one private repair run."""

    root: Path
    spec: ProjectSpec
    source_manifest: SourceManifestDocument
    files: tuple[RepairFileSnapshot, ...]
    authority_directories: tuple[JsonAuthorityDirectorySnapshot, ...]
    outputs: tuple[RepairOutputSnapshot, ...]

    @property
    def files_by_path(self) -> dict[str, RepairFileSnapshot]:
        return {item.relative_path: item for item in self.files}


@dataclass(frozen=True, slots=True)
class RepairCandidate:
    """Verified project-record and report bytes ready for one CAS publish."""

    records: dict[str, bytes | None]
    outputs: dict[str, bytes]
    report_json: bytes
    report_html: bytes


def _safe_path(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RepairError(f"repair input path is not canonical: {relative!r}")
    candidate = root.joinpath(*path.parts)
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise RepairError(f"repair input is redirected: {relative!r}")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise RepairError(f"repair input escapes the project: {relative!r}") from exc
    return candidate


def _capture_file(root: Path, relative: str) -> RepairFileSnapshot:
    try:
        size, digest, payload = receipt_source_input(root, relative, capture=True)
    except SourceLockError as exc:
        raise RepairError(f"cannot seal repair input {relative!r}: {exc}") from exc
    assert payload is not None
    if size != len(payload):
        raise RepairError(f"repair input changed while it was read: {relative!r}")
    return RepairFileSnapshot(relative, digest, payload)


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

    files: list[RepairFileSnapshot] = []
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
    return RepairSnapshot(root, spec, manifest, tuple(files), tuple(directories), outputs)


class StagedRepairProject:
    """A run-private project copy containing only sealed certification inputs."""

    def __init__(self, snapshot: RepairSnapshot, *, keep: KeepWorkspace) -> None:
        self.snapshot = snapshot
        self.arena = RunArena(
            snapshot.root / snapshot.spec.state_dir,
            kind="repair",
            keep=keep,
        )
        self.root: Path | None = None

    @property
    def retained_path(self) -> Path:
        return self.arena.path

    def __enter__(self) -> Path:
        arena = self.arena.__enter__()
        root = arena.path / "project"
        self.root = root
        try:
            root.mkdir()
            for snapshot in self.snapshot.files:
                destination = root.joinpath(*PurePosixPath(snapshot.relative_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(snapshot.payload)
                if Digest.from_path(destination) != snapshot.digest:
                    raise RepairError(f"staged repair input differs: {snapshot.relative_path!r}")
        except BaseException:
            self.arena.finish(succeeded=False)
            raise
        return root

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.arena.__exit__(exc_type, exc, traceback)


def _publishable_paths(snapshot: RepairSnapshot, staged_root: Path) -> tuple[str, ...]:
    values = {
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
) -> RepairCandidate:
    """Collect only verified records and reports, refusing other input mutation."""

    by_path = snapshot.files_by_path
    publishable = set(_publishable_paths(snapshot, staged_root))
    records: dict[str, bytes | None] = {}
    for relative in sorted(publishable, key=lambda item: (item.casefold(), item)):
        candidate = _safe_path(staged_root, relative)
        payload = candidate.read_bytes() if candidate.is_file() else None
        before = by_path.get(relative)
        if payload != (before.payload if before is not None else None):
            records[relative] = payload

    for snapshot_file in snapshot.files:
        if snapshot_file.relative_path in publishable:
            continue
        candidate = _safe_path(staged_root, snapshot_file.relative_path)
        if not candidate.is_file() or Digest.from_path(candidate) != snapshot_file.digest:
            raise RepairError(f"repair modified a sealed input: {snapshot_file.relative_path!r}")

    report_root = _safe_path(staged_root, report_directory)
    report_json = report_root / "report.json"
    report_html = report_root / "report.html"
    if not report_json.is_file() or not report_html.is_file():
        raise RepairError("exact verification did not produce both repair reports")
    outputs: dict[str, bytes] = {}
    for output in snapshot.outputs:
        candidate = _safe_path(staged_root, output.relative_path)
        if not candidate.is_file():
            raise RepairError(f"exact verification did not produce {output.relative_path!r}")
        outputs[output.relative_path] = candidate.read_bytes()
    return RepairCandidate(
        records,
        outputs,
        report_json.read_bytes(),
        report_html.read_bytes(),
    )


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
    "RepairFileSnapshot",
    "RepairOutputSnapshot",
    "RepairSnapshot",
    "StagedRepairProject",
    "capture_repair_report_preimages",
    "capture_repair_snapshot",
    "collect_repair_candidate",
    "publish_repair_candidate",
    "validate_repair_report_directory",
]
