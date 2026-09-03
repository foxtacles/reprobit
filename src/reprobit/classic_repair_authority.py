"""Typed edits to classic intervention and proof authority in private staging."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reprobit.authority_snapshot import AuthoritySnapshotError, json_authority_members
from reprobit.model import Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InterventionDocument,
    ProjectSpec,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction


class ClassicAuthorityRepairError(RuntimeError):
    """A staged classic authority edit is ambiguous or broader than declared."""


DROPPABLE_MOVE_PARAMETERS = frozenset({"debug_representation_delta"})


@dataclass(frozen=True, slots=True)
class ClassicInterventionEdit:
    before: ClassicRecipeIntervention
    after: ClassicRecipeIntervention | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        try:
            after = ClassicRecipeIntervention.model_validate(
                self.after.model_dump(mode="python", warnings=False)
            )
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement is invalid: {exc}"
            ) from exc
        object.__setattr__(self, "after", after)
        if (
            after.id != self.before.id
            or after.role is not self.before.role
            or after.family is not self.before.family
            or after.scope != self.before.scope
            or after.build_target != self.before.build_target
        ):
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement changes its identity or scope"
            )
        if after == self.before:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement makes no change"
            )
        if self.before.role is not ClassicRecipeRole.DONOR:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement is not a donor adjustment"
            )
        unchanged = after.model_copy(
            update={
                "parameters": self.before.parameters,
                "beneficiaries": self.before.beneficiaries,
            }
        )
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} replacement changes fields outside "
                "donor parameters or beneficiaries"
            )


@dataclass(frozen=True, slots=True)
class ClassicDependencyEdit:
    """Move one saved function record onto another donor of its translation unit.

    Everything about the record stays: identity, family, scope, symbol and
    parameters.  Only its primary dependency changes, and the new donor must be
    named so the caller can prove it exists in the same unit.  The receipt's
    donor-side measurements are refreshed separately through the ordinary
    measured-pin repair.
    """

    before: ClassicRecipeIntervention
    donor_id: str
    dropped_parameters: tuple[str, ...] = ()
    """Parameters that described the previous donor pair and go with the move.

    Only the closed set below may be dropped: a debug representation delta
    pairs the record's debug stream with one particular donor's, so it cannot
    survive a move and is re-derived by the measured-pin repair instead.
    """

    def __post_init__(self) -> None:
        if self.before.role is not ClassicRecipeRole.FUNCTION or not self.before.dependencies:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} is not a function record with a primary donor"
            )
        if not self.donor_id or self.donor_id == self.before.dependencies[0]:
            raise ClassicAuthorityRepairError(
                f"intervention {self.before.id!r} dependency edit names no new donor"
            )
        names = {field.name for field in self.before.parameters}
        for name in self.dropped_parameters:
            if name not in DROPPABLE_MOVE_PARAMETERS or name not in names:
                raise ClassicAuthorityRepairError(
                    f"intervention {self.before.id!r} dependency edit drops {name!r}, which is "
                    "not a parameter bound to the previous donor"
                )

    @property
    def after(self) -> ClassicRecipeIntervention:
        if self.dropped_parameters:
            return self.before.model_copy(
                update={
                    "dependencies": (self.donor_id, *self.before.dependencies[1:]),
                    "parameters": tuple(
                        field
                        for field in self.before.parameters
                        if field.name not in self.dropped_parameters
                    ),
                }
            )
        return self.before.model_copy(
            update={"dependencies": (self.donor_id, *self.before.dependencies[1:])}
        )


@dataclass(frozen=True, slots=True)
class ClassicReceiptEdit:
    before: ClassicProofReceipt
    after: ClassicProofReceipt | None

    def __post_init__(self) -> None:
        if self.after is None:
            return
        try:
            after = ClassicProofReceipt.model_validate(
                self.after.model_dump(mode="python", warnings=False)
            )
        except ValueError as exc:
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement is invalid: {exc}"
            ) from exc
        object.__setattr__(self, "after", after)
        if (
            after.id != self.before.id
            or after.intervention_id != self.before.intervention_id
            or after.family is not self.before.family
        ):
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement changes its identity"
            )
        if after == self.before:
            raise ClassicAuthorityRepairError(f"receipt {self.before.id!r} makes no change")
        unchanged = after.model_copy(update={"expected_values": self.before.expected_values})
        if unchanged != self.before:
            raise ClassicAuthorityRepairError(
                f"receipt {self.before.id!r} replacement changes fields outside expected values"
            )


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


@dataclass(frozen=True, slots=True)
class ClassicRecordAddition:
    """One new function or donor record (intervention plus receipt) for an existing TU shard."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt

    def __post_init__(self) -> None:
        if (
            self.receipt.intervention_id != self.intervention.id
            or self.receipt.family is not self.intervention.family
        ):
            raise ClassicAuthorityRepairError(
                f"added receipt {self.receipt.id!r} does not describe {self.intervention.id!r}"
            )
        if self.intervention.role not in (ClassicRecipeRole.FUNCTION, ClassicRecipeRole.DONOR):
            raise ClassicAuthorityRepairError(
                f"added record {self.intervention.id!r} is not a function or donor record"
            )
        if self.intervention.scope.translation_unit is None:
            raise ClassicAuthorityRepairError(
                f"added record {self.intervention.id!r} names no translation-unit shard"
            )


def apply_classic_authority_edits(
    root: Path,
    spec: ProjectSpec,
    *,
    interventions: tuple[ClassicInterventionEdit, ...] = (),
    receipts: tuple[ClassicReceiptEdit, ...] = (),
    additions: tuple[ClassicRecordAddition, ...] = (),
    dependencies: tuple[ClassicDependencyEdit, ...] = (),
) -> tuple[str, ...]:
    """Apply exact typed edits atomically inside a private staged project.

    ``additions`` append new function records to the shard documents of their
    translation unit; every other change is an edit or removal of an existing
    record, checked against its saved state before it is applied.
    """

    intervention_edits: dict[str, ClassicInterventionEdit | ClassicDependencyEdit] = {
        item.before.id: item for item in interventions
    }
    for edit in dependencies:
        if edit.before.id in intervention_edits:
            raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
        intervention_edits[edit.before.id] = edit
    receipt_edits = {item.before.id: item for item in receipts}
    if len(intervention_edits) != len(interventions) + len(dependencies):
        raise ClassicAuthorityRepairError("intervention edits repeat an identifier")
    if len(receipt_edits) != len(receipts):
        raise ClassicAuthorityRepairError("receipt edits repeat an identifier")
    added_ids = [item.intervention.id for item in additions]
    if len(set(added_ids)) != len(added_ids) or set(added_ids) & set(intervention_edits):
        raise ClassicAuthorityRepairError("record additions repeat an identifier")
    additions_by_shard: dict[tuple[str, str], list[ClassicRecordAddition]] = {}
    for item in additions:
        shard = (item.intervention.scope.target, item.intervention.scope.translation_unit or "")
        additions_by_shard.setdefault(shard, []).append(item)
    if not intervention_edits and not receipt_edits and not additions:
        return ()
    placed_shards: set[tuple[str, str]] = set()
    donors_by_shard: dict[tuple[str, str], set[str]] = {}

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
        shard = (intervention_document.target_id, intervention_document.translation_unit_id or "")
        donors_by_shard[shard] = {
            item.id
            for item in intervention_values
            if isinstance(item, ClassicRecipeIntervention) and item.role is ClassicRecipeRole.DONOR
        } | {
            item.intervention.id
            for item in additions_by_shard.get(shard, ())
            if item.intervention.role is ClassicRecipeRole.DONOR
        }
        for edit in dependencies:
            if (
                edit.before.scope.target == shard[0]
                and edit.before.scope.translation_unit == shard[1]
                and edit.donor_id not in donors_by_shard[shard]
            ):
                raise ClassicAuthorityRepairError(
                    f"dependency edit for {edit.before.id!r} names donor {edit.donor_id!r} "
                    f"outside its translation unit"
                )
        shard_additions = (
            additions_by_shard.get(shard, ()) if intervention_document.translation_unit_id else ()
        )
        for addition in shard_additions:
            if any(item.id == addition.intervention.id for item in intervention_values):
                raise ClassicAuthorityRepairError(
                    f"added record {addition.intervention.id!r} already exists in {relative!r}"
                )
            intervention_values.append(addition.intervention)
            placed_shards.add(shard)
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
        shard = (proof_document.target_id, proof_document.translation_unit_id or "")
        shard_additions = (
            additions_by_shard.get(shard, ()) if proof_document.translation_unit_id else ()
        )
        for addition in shard_additions:
            if any(item.id == addition.receipt.id for item in receipt_values):
                raise ClassicAuthorityRepairError(
                    f"added receipt {addition.receipt.id!r} already exists in {relative!r}"
                )
            receipt_values.append(addition.receipt)
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

    unplaced = sorted(set(additions_by_shard) - placed_shards)
    if unplaced:
        raise ClassicAuthorityRepairError(
            f"record additions name translation-unit shards without documents: {unplaced}"
        )
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
    "DROPPABLE_MOVE_PARAMETERS",
    "ClassicAuthorityRepairError",
    "ClassicDependencyEdit",
    "ClassicInterventionEdit",
    "ClassicReceiptEdit",
    "ClassicRecordAddition",
    "apply_classic_authority_edits",
]
