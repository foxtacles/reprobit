"""Seal staged postimages and verified bytes before atomic publication."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING

from reprobit.composition_ledger import ComposedBodyLedger, canonical_ledger_payload
from reprobit.model import Digest
from reprobit.source_lock import SourceLockError, receipt_source_input

if TYPE_CHECKING:
    from reprobit.cli_build import VerifyResult


class PublicationEvidenceError(RuntimeError):
    """Verified publication material no longer matches its sealed evidence."""


@dataclass(frozen=True, slots=True)
class SealedProjectPostimage:
    """One project-relative file state captured as bytes and their digest."""

    relative_path: str
    digest: Digest | None
    payload: bytes | None

    def __post_init__(self) -> None:
        if (self.digest is None) != (self.payload is None):
            raise ValueError("sealed postimage presence is incomplete")


@dataclass(frozen=True, slots=True)
class VerifiedPublicationEvidence:
    """Output, report, and repair-ledger bytes bound to one VerifyResult."""

    outputs: Mapping[str, bytes]
    report_json: bytes
    report_html: bytes
    composed_body_ledger: bytes | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", MappingProxyType(dict(self.outputs)))


def capture_project_postimage(root: Path, relative: str) -> SealedProjectPostimage:
    """Capture one regular project file without following redirects, or its absence."""

    value = PurePosixPath(relative.replace("\\", "/"))
    if (
        value.is_absolute()
        or not value.parts
        or any(part in {"", ".", ".."} for part in value.parts)
    ):
        raise PublicationEvidenceError(f"publication postimage is not canonical: {relative!r}")
    path = root.joinpath(*value.parts)
    if not os.path.lexists(path):
        return SealedProjectPostimage(relative, None, None)
    if path.is_symlink() or not path.is_file():
        raise PublicationEvidenceError(f"publication postimage is not regular: {relative!r}")
    try:
        size, digest, payload = receipt_source_input(root, relative, capture=True)
    except SourceLockError as exc:
        raise PublicationEvidenceError(
            f"cannot seal publication postimage {relative!r}: {exc}"
        ) from exc
    assert payload is not None
    if size != len(payload):
        raise PublicationEvidenceError(
            f"publication postimage changed while it was read: {relative!r}"
        )
    return SealedProjectPostimage(relative, digest, payload)


def require_project_postimage(
    root: Path,
    expected: SealedProjectPostimage,
) -> None:
    """Require a staged file to retain the exact state captured before verification."""

    path = root.joinpath(*PurePosixPath(expected.relative_path).parts)
    if expected.payload is None:
        unchanged = not os.path.lexists(path)
    elif not os.path.lexists(path) or path.is_symlink() or not path.is_file():
        unchanged = False
    else:
        try:
            size, digest, _payload = receipt_source_input(
                root,
                expected.relative_path,
                capture=False,
            )
        except SourceLockError:
            unchanged = False
        else:
            unchanged = size == len(expected.payload) and digest == expected.digest
    if not unchanged:
        raise PublicationEvidenceError(
            f"publication postimage changed after verification: {expected.relative_path!r}"
        )


def _absolute(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(path))


def _verified_receipts(verified: VerifyResult) -> tuple[dict[Path, tuple[int, Digest]], set[Path]]:
    """Index immutable output receipts carried by the finished verifier."""

    receipts: dict[Path, tuple[int, Digest]] = {}
    targets: set[Path] = set()

    def add(path: str | os.PathLike[str], size: int, digest: Digest) -> None:
        key = _absolute(path)
        value = (size, digest)
        previous = receipts.get(key)
        if previous is not None and previous != value:
            raise PublicationEvidenceError(
                f"verification carries conflicting output receipts for {key}"
            )
        receipts[key] = value

    for receipt in verified.engine.build.outputs:
        add(receipt.path, receipt.size, receipt.digest)
    for target in verified.engine.targets:
        comparison = target.comparison
        if comparison.candidate_size is None or comparison.candidate_digest is None:
            raise PublicationEvidenceError(
                f"verification target has no candidate receipt: {target.target_id!r}"
            )
        path = _absolute(target.artifact)
        targets.add(path)
        add(
            path,
            comparison.candidate_size,
            Digest(value=comparison.candidate_digest),
        )
    proof = getattr(verified.engine.report, "proof", None)
    for supplemental in getattr(proof, "supplemental_outputs", ()):
        for item in supplemental.files:
            add(item.path, item.size, item.digest)
    return receipts, targets


def collect_verified_publication_evidence(
    verified: VerifyResult,
    *,
    staged_root: Path,
    output_paths: tuple[str, ...],
    target_paths: tuple[str, ...],
    report_json: Path,
    report_html: Path,
    ledger_path: Path,
) -> VerifiedPublicationEvidence:
    """Collect only bytes whose identity is carried by the finished verifier."""

    root = _absolute(staged_root)
    if _absolute(verified.project) != root:
        raise PublicationEvidenceError("verification result belongs to another staged project")
    if _absolute(verified.report_json) != _absolute(report_json):
        raise PublicationEvidenceError("verification result names another JSON report")
    if _absolute(verified.report_html) != _absolute(report_html):
        raise PublicationEvidenceError("verification result names another HTML report")

    receipts, target_receipts = _verified_receipts(verified)
    required_targets = {_absolute(staged_root / relative) for relative in target_paths}
    if not required_targets.issubset(target_receipts):
        missing = sorted(str(path) for path in required_targets - target_receipts)
        raise PublicationEvidenceError(
            f"verification result omits declared target receipts: {missing}"
        )

    outputs: dict[str, bytes] = {}
    for relative in output_paths:
        path = _absolute(staged_root / relative)
        expected = receipts.get(path)
        if expected is None:
            raise PublicationEvidenceError(
                f"verification result has no output receipt for {relative!r}"
            )
        try:
            size, digest, payload = receipt_source_input(staged_root, relative, capture=True)
        except SourceLockError as exc:
            raise PublicationEvidenceError(
                f"cannot read verified output {relative!r}: {exc}"
            ) from exc
        assert payload is not None
        if (size, digest) != expected or len(payload) != size:
            raise PublicationEvidenceError(
                f"verified output changed after verification: {relative!r}"
            )
        outputs[relative] = payload

    json_payload = verified.report_json_payload
    html_payload = verified.report_html_payload
    engine_payloads = verified.engine.report_payloads
    if engine_payloads.get(verified.report_json) != json_payload:
        raise PublicationEvidenceError("verification JSON report differs from engine evidence")
    if engine_payloads.get(verified.report_html) != html_payload:
        raise PublicationEvidenceError("verification HTML report differs from engine evidence")

    ledger_payload: bytes | None = None
    ledger = verified.ledger
    if ledger is not None and ledger.outcome == "succeeded":
        if _absolute(ledger.path) != _absolute(ledger_path):
            raise PublicationEvidenceError("verification result names another repair ledger")
        if ledger.payload is None:
            raise PublicationEvidenceError("verification result omitted its repair ledger bytes")
        try:
            document = ComposedBodyLedger.model_validate_json(ledger.payload)
        except ValueError as exc:
            raise PublicationEvidenceError(f"verified repair data is invalid: {exc}") from exc
        ledger_payload = canonical_ledger_payload(document)
        if ledger_payload != ledger.payload:
            raise PublicationEvidenceError("verification repair ledger is not canonical")

    return VerifiedPublicationEvidence(outputs, json_payload, html_payload, ledger_payload)


__all__ = [
    "PublicationEvidenceError",
    "SealedProjectPostimage",
    "VerifiedPublicationEvidence",
    "capture_project_postimage",
    "collect_verified_publication_evidence",
    "require_project_postimage",
]
