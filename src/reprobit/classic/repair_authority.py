"""Typed edits to classic intervention and proof authority in private staging."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reprobit.authority_snapshot import AuthoritySnapshotError, json_authority_members
from reprobit.model import Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    InterventionDocument,
    ProjectSpec,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction


class ClassicAuthorityRepairError(RuntimeError):
    """A staged classic authority edit is ambiguous or broader than declared."""


@dataclass(frozen=True, slots=True)
class ClassicInterventionEdit:
    before: ClassicRecipeIntervention
    after: ClassicRecipeIntervention | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        if (
            self.after.id != self.before.id
            or self.after.role is not self.before.role
            or self.after.family is not self.before.family
            or self.after.scope != self.before.scope
            or self.after.build_target != self.before.build_target
        ):
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement changes its identity or scope"
            )
        if self.after == self.before:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement makes no change"
            )


@dataclass(frozen=True, slots=True)
class ClassicReceiptEdit:
    before: ClassicProofReceipt
    after: ClassicProofReceipt | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        if (
            self.after.id != self.before.id
            or self.after.intervention_id != self.before.intervention_id
            or self.after.family is not self.before.family
        ):
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement changes its identity"
            )
        if self.after == self.before:
            raise ClassicAuthorityRepairError(f"receipt {self.before.id!r} makes no change")


def _authority_path(root: Path, directory: str, member: str) -> tuple[str, Path]:
    relative = (PurePosixPath(directory) / PurePosixPath(member)).as_posix()
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or not path.is_file():
        raise ClassicAuthorityRepairError(f"classic authority is unavailable: {relative!r}")
    return relative, path


def _members(root: Path, directory: str) -> tuple[str, ...]:
    try:
        return json_authority_members(root, directory)
    except AuthoritySnapshotError as exc:
        raise ClassicAuthorityRepairError(
            f"cannot inspect classic authority {directory!r}: {exc}"
        ) from exc


def apply_classic_authority_edits(
    root: Path,
    spec: ProjectSpec,
    *,
    interventions: tuple[ClassicInterventionEdit, ...] = (),
    receipts: tuple[ClassicReceiptEdit, ...] = (),
) -> tuple[str, ...]:
    """Apply exact typed edits atomically inside a private staged project."""

    intervention_edits = {item.before.id: item for item in interventions}
    receipt_edits = {item.before.id: item for item in receipts}
    if len(intervention_edits) != len(interventions):
        raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
    if len(receipt_edits) != len(receipts):
        raise ClassicAuthorityRepairError("receipt edits repeat an identifier")
    if not intervention_edits and not receipt_edits:
        return ()

    transaction = CASTransaction(root)
    changed_paths: list[str] = []
    found_interventions: set[str] = set()
    found_receipts: set[str] = set()
    intervention_members = _members(root, spec.layout.interventions)
    proof_members = _members(root, spec.layout.proofs)

    for member in intervention_members:
        relative, path = _authority_path(root, spec.layout.interventions, member)
        payload = path.read_bytes()
        try:
            intervention_document = InterventionDocument.model_validate_json(payload)
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"invalid intervention authority {relative!r}: {exc}"
            ) from exc
        intervention_values = list(intervention_document.interventions)
        changed = False
        for index in range(len(intervention_values) - 1, -1, -1):
            current = intervention_values[index]
            intervention_edit = intervention_edits.get(current.id)
            if intervention_edit is None:
                continue
            if (
                not isinstance(current, ClassicRecipeIntervention)
                or current != intervention_edit.before
            ):
                raise ClassicAuthorityRepairError(
                    f"intervention {current.id!r} changed before repair was applied"
                )
            if current.id in found_interventions:
                raise ClassicAuthorityRepairError(
                    f"intervention {current.id!r} appears more than once"
                )
            found_interventions.add(current.id)
            if intervention_edit.after is None:
                del intervention_values[index]
            else:
                intervention_values[index] = intervention_edit.after
            changed = True
        digest = Digest.from_bytes(payload).value
        if not changed:
            transaction.assert_unchanged(relative, expected_sha256=digest)
            continue
        intervention_candidate = InterventionDocument.model_validate(
            {
                **intervention_document.model_dump(mode="python"),
                "interventions": tuple(intervention_values),
            }
        )
        transaction.write(
            relative,
            canonical_json(intervention_candidate),
            expected_sha256=digest,
        )
        changed_paths.append(relative)

    for member in proof_members:
        relative, path = _authority_path(root, spec.layout.proofs, member)
        payload = path.read_bytes()
        try:
            proof_document = ProofDocument.model_validate_json(payload)
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"invalid proof authority {relative!r}: {exc}"
            ) from exc
        receipt_values = list(proof_document.expected_observations)
        changed = False
        for index in range(len(receipt_values) - 1, -1, -1):
            receipt_current = receipt_values[index]
            receipt_edit = receipt_edits.get(receipt_current.id)
            if receipt_edit is None:
                continue
            if receipt_current != receipt_edit.before:
                raise ClassicAuthorityRepairError(
                    f"proof receipt {receipt_current.id!r} changed before repair was applied"
                )
            if receipt_current.id in found_receipts:
                raise ClassicAuthorityRepairError(
                    f"proof receipt {receipt_current.id!r} appears more than once"
                )
            found_receipts.add(receipt_current.id)
            if receipt_edit.after is None:
                del receipt_values[index]
            else:
                receipt_values[index] = receipt_edit.after
            changed = True
        digest = Digest.from_bytes(payload).value
        if not changed:
            transaction.assert_unchanged(relative, expected_sha256=digest)
            continue
        proof_candidate = ProofDocument.model_validate(
            {
                **proof_document.model_dump(mode="python"),
                "expected_observations": tuple(receipt_values),
            }
        )
        transaction.write(relative, canonical_json(proof_candidate), expected_sha256=digest)
        changed_paths.append(relative)

    missing_interventions = sorted(
        set(intervention_edits) - found_interventions,
        key=str.casefold,
    )
    missing_receipts = sorted(set(receipt_edits) - found_receipts, key=str.casefold)
    if missing_interventions or missing_receipts:
        raise ClassicAuthorityRepairError(
            "classic authority edits are absent: "
            f"interventions={missing_interventions}, receipts={missing_receipts}"
        )
    transaction.assert_json_members(
        spec.layout.interventions,
        expected_members=intervention_members,
    )
    transaction.assert_json_members(spec.layout.proofs, expected_members=proof_members)
    transaction.commit()
    return tuple(sorted(changed_paths, key=lambda item: (item.casefold(), item)))


__all__ = [
    "ClassicAuthorityRepairError",
    "ClassicInterventionEdit",
    "ClassicReceiptEdit",
    "apply_classic_authority_edits",
]
