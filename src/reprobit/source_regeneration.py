"""Plan and publish reviewed source-derived authority regeneration.

``rbit source lock`` refuses to bless stale pins.  This module captures one
immutable project snapshot, delegates the closed classic derivations to
``reprobit.classic.source_regeneration``, and returns a reviewable plan whose
publication is guarded by compare-and-swap preconditions.

The derivation only refreshes mechanical identities.  It never deletes an
unknown record or bypasses a validator, and the result must still pass source
locking and a from-scratch byte verification before it can be certified.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from reprobit.authority_snapshot import AuthoritySnapshotError, json_authority_members
from reprobit.classic.source_regeneration import derive_classic_source_regeneration
from reprobit.project_loader import load_project
from reprobit.schema import BuildPlanDocument, InterventionDocument, ProofDocument
from reprobit.source_lock import SourceLockError, receipt_source_input
from reprobit.strict_json import canonical_json, strict_loads
from reprobit.transactions import CASTransaction, TransactionResult


class SourceRegenerationError(ValueError):
    """Regeneration cannot propose a provable replacement for a stale pin."""


@dataclass(frozen=True, slots=True)
class RegenerationChange:
    """One recorded field replacement inside one committed document."""

    document: str
    location: str
    before: str
    after: str


@dataclass(frozen=True, slots=True)
class RegenerationPlan:
    """A reviewed set of document rewrites plus the exact bytes they assume."""

    changes: tuple[RegenerationChange, ...]
    documents: Mapping[str, bytes]
    document_preimages: Mapping[str, str]
    control_preimages: Mapping[str, str | None]
    authority_directories: Mapping[str, tuple[str, ...]]
    read_sources: Mapping[str, str]

    @property
    def changed_documents(self) -> tuple[str, ...]:
        return tuple(sorted({change.document for change in self.changes}))


class ProjectSourceReader:
    """Read project-relative source files once, remembering the exact bytes."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._cache: dict[str, bytes] = {}
        self._digests: dict[str, str] = {}

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        cached = self._cache.get(relative)
        if cached is not None:
            return cached
        try:
            _size, digest, data = receipt_source_input(self._root, relative, capture=True)
        except SourceLockError as exc:
            raise SourceRegenerationError(f"{wanted_by} cannot read {relative!r}: {exc}") from exc
        assert data is not None
        self._cache[relative] = data
        self._digests[relative] = digest.value
        return data

    @property
    def digests(self) -> dict[str, str]:
        return dict(self._digests)


def _authority_members(root: Path, relative: str) -> tuple[str, ...]:
    try:
        members = json_authority_members(root, relative)
    except AuthoritySnapshotError as exc:
        raise SourceRegenerationError(
            f"cannot inspect source-regeneration authority {relative!r}: {exc}"
        ) from exc
    directory = root.joinpath(*PurePosixPath(relative).parts)
    if not directory.is_dir():
        raise SourceRegenerationError(
            f"source-regeneration authority directory is unavailable: {relative!r}"
        )
    return members


def _read_project_file(root: Path, relative: str, *, wanted_by: str) -> tuple[bytes, str]:
    try:
        _size, digest, data = receipt_source_input(root, relative, capture=True)
    except SourceLockError as exc:
        raise SourceRegenerationError(f"{wanted_by} cannot read {relative!r}: {exc}") from exc
    assert data is not None
    return data, digest.value


def _read_json_document(
    root: Path,
    relative: str,
    model: type[BuildPlanDocument] | type[InterventionDocument] | type[ProofDocument],
) -> tuple[Any, str]:
    data, digest = _read_project_file(
        root,
        relative,
        wanted_by="source regeneration",
    )
    try:
        value = strict_loads(data)
    except ValueError as exc:
        raise SourceRegenerationError(
            f"source-regeneration authority {relative!r} is invalid: {exc}"
        ) from exc
    _validate_json_document(relative, value, model)
    return value, digest


def _validate_json_document(
    relative: str,
    value: Any,
    model: type[BuildPlanDocument] | type[InterventionDocument] | type[ProofDocument],
) -> None:
    try:
        model.model_validate_json(canonical_json(value))
    except ValueError as exc:
        raise SourceRegenerationError(
            f"source-regeneration authority {relative!r} is invalid: {exc}"
        ) from exc


def plan_source_regeneration(project_root: Path | str) -> RegenerationPlan:
    """Propose pin regenerations for every stale mechanical derivation."""

    root = Path(project_root).resolve(strict=True)
    config_relative = "reprobit.toml"
    config_data, config_digest = _read_project_file(
        root,
        config_relative,
        wanted_by="source regeneration",
    )
    spec = load_project(root)
    if (
        _read_project_file(
            root,
            config_relative,
            wanted_by="source regeneration",
        )[0]
        != config_data
    ):
        raise SourceRegenerationError("reprobit.toml changed while regeneration was planned")

    intervention_members = _authority_members(root, spec.layout.interventions)
    proof_members = _authority_members(root, spec.layout.proofs)
    authority_directories = {
        spec.layout.interventions: intervention_members,
        spec.layout.proofs: proof_members,
    }
    documents: dict[str, Any] = {}
    document_models: dict[
        str,
        type[BuildPlanDocument] | type[InterventionDocument] | type[ProofDocument],
    ] = {}
    document_preimages: dict[str, str] = {}
    control_preimages: dict[str, str | None] = {config_relative: config_digest}
    for directory, members, model in (
        (spec.layout.interventions, intervention_members, InterventionDocument),
        (spec.layout.proofs, proof_members, ProofDocument),
    ):
        for member in members:
            name = (PurePosixPath(directory) / member).as_posix()
            documents[name], document_preimages[name] = _read_json_document(
                root,
                name,
                model,
            )
            document_models[name] = model

    plan_relative = spec.layout.build_plan
    plan_path = root / plan_relative
    if os.path.lexists(plan_path):
        documents[plan_relative], document_preimages[plan_relative] = _read_json_document(
            root,
            plan_relative,
            BuildPlanDocument,
        )
        document_models[plan_relative] = BuildPlanDocument
    else:
        control_preimages[plan_relative] = None

    reader = ProjectSourceReader(root)
    derived = derive_classic_source_regeneration(
        documents=documents,
        plan_relative=plan_relative,
        reader=reader,
        error_type=SourceRegenerationError,
    )
    for name in derived.updated_documents:
        _validate_json_document(name, documents[name], document_models[name])
    for relative, expected_members in authority_directories.items():
        if _authority_members(root, relative) != expected_members:
            raise SourceRegenerationError(
                f"source-regeneration authority membership changed: {relative!r}"
            )
    changes = tuple(
        RegenerationChange(change.document, change.location, change.before, change.after)
        for change in derived.changes
    )
    return RegenerationPlan(
        changes=changes,
        documents=MappingProxyType(
            {name: canonical_json(documents[name]) for name in derived.updated_documents}
        ),
        document_preimages=MappingProxyType(dict(document_preimages)),
        control_preimages=MappingProxyType(control_preimages),
        authority_directories=MappingProxyType(authority_directories),
        read_sources=MappingProxyType(reader.digests),
    )


def apply_source_regeneration(
    project_root: Path | str,
    plan: RegenerationPlan,
) -> TransactionResult | None:
    """Write a regeneration plan transactionally against the bytes it read."""

    if not plan.changes:
        return None
    root = Path(project_root).resolve(strict=True)
    transaction = CASTransaction(root)
    for name in plan.changed_documents:
        transaction.write(
            name,
            plan.documents[name],
            expected_sha256=plan.document_preimages[name],
        )
    for name, digest in sorted(plan.document_preimages.items()):
        if name not in plan.documents:
            transaction.assert_unchanged(name, expected_sha256=digest)
    for name, control_digest in sorted(plan.control_preimages.items()):
        transaction.assert_unchanged(name, expected_sha256=control_digest)
    for relative, members in sorted(plan.authority_directories.items()):
        transaction.assert_json_members(relative, expected_members=members)
    for path, source_digest in sorted(plan.read_sources.items()):
        transaction.assert_unchanged(path, expected_sha256=source_digest)
    return transaction.commit()


__all__ = [
    "ProjectSourceReader",
    "RegenerationChange",
    "RegenerationPlan",
    "SourceRegenerationError",
    "apply_source_regeneration",
    "plan_source_regeneration",
]
