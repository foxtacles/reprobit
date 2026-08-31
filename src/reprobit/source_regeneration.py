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

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from reprobit.classic.source_regeneration import _derive_classic_source_regeneration
from reprobit.project_loader import load_project
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


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _SourceReader:
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
            from reprobit.source_lock import SourceLockError, receipt_source_input

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


def _document_paths(root: Path, relative: str) -> tuple[Path, ...]:
    directory = root / relative
    if not directory.is_dir():
        return ()
    return tuple(sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()))


def plan_source_regeneration(project_root: Path | str) -> RegenerationPlan:
    """Propose pin regenerations for every stale mechanical derivation."""

    root = Path(project_root).resolve(strict=True)
    config_relative = "reprobit.toml"
    config_path = root / config_relative
    config_data = config_path.read_bytes()
    spec = load_project(root)
    if config_path.read_bytes() != config_data:
        raise SourceRegenerationError("reprobit.toml changed while regeneration was planned")

    intervention_paths = _document_paths(root, spec.layout.interventions)
    proof_paths = _document_paths(root, spec.layout.proofs)
    authority_directories = {
        spec.layout.interventions: tuple(
            sorted(
                (
                    path.relative_to(root / spec.layout.interventions).as_posix()
                    for path in intervention_paths
                ),
                key=lambda item: (item.casefold(), item),
            )
        ),
        spec.layout.proofs: tuple(
            sorted(
                (path.relative_to(root / spec.layout.proofs).as_posix() for path in proof_paths),
                key=lambda item: (item.casefold(), item),
            )
        ),
    }
    documents: dict[str, Any] = {}
    document_preimages: dict[str, str] = {}
    control_preimages: dict[str, str | None] = {config_relative: _digest(config_data)}
    for document_path in (*intervention_paths, *proof_paths):
        name = document_path.relative_to(root).as_posix()
        data = document_path.read_bytes()
        documents[name] = strict_loads(data)
        document_preimages[name] = _digest(data)

    plan_relative = spec.layout.build_plan
    plan_path = root / plan_relative
    if plan_path.is_file():
        data = plan_path.read_bytes()
        documents[plan_relative] = strict_loads(data)
        document_preimages[plan_relative] = _digest(data)
    else:
        control_preimages[plan_relative] = None

    reader = _SourceReader(root)
    derived = _derive_classic_source_regeneration(
        documents=documents,
        plan_relative=plan_relative,
        reader=reader,
        error_type=SourceRegenerationError,
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
    "RegenerationChange",
    "RegenerationPlan",
    "SourceRegenerationError",
    "apply_source_regeneration",
    "plan_source_regeneration",
]
