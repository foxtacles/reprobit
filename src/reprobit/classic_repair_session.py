"""Conservative in-memory classic repair collection and staged persistence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Lock
from typing import cast

from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import (
    DROPPABLE_MOVE_PARAMETERS,
    ClassicDependencyEdit,
    ClassicReceiptEdit,
    apply_classic_authority_edits,
)
from reprobit.classic_repair_dispatch import ClassicMeasuredReceiptRepairRequest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ProjectSpec,
)


class ClassicRepairSessionError(RuntimeError):
    """A proposed classic repair is ambiguous or cannot be persisted safely."""


@dataclass(frozen=True, slots=True)
class ClassicReceiptRepair:
    """One ordinary-composer-validated measured receipt replacement."""

    unit_id: str
    action_index: int
    before: ClassicProofReceipt
    after: ClassicProofReceipt
    changed_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            self.after.id != self.before.id
            or self.after.intervention_id != self.before.intervention_id
            or self.after.family is not self.before.family
            or self.after.expected_values.keys() != self.before.expected_values.keys()
            or self.after.model_copy(update={"expected_values": self.before.expected_values})
            != self.before
        ):
            raise ClassicRepairSessionError(
                f"receipt {self.before.id!r} repair changes more than expected values"
            )
        actual = tuple(
            sorted(
                key
                for key in self.before.expected_values
                if self.before.expected_values[key] != self.after.expected_values[key]
            )
        )
        if not actual or self.changed_keys != actual:
            raise ClassicRepairSessionError(
                f"receipt {self.before.id!r} changed-key declaration differs"
            )


@dataclass(frozen=True, slots=True)
class ClassicRepairRefusal:
    """Sanitized action fallout retained for bounded structural repair."""

    unit_id: str
    action_index: int
    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    materials: ClassicDispatchMaterials
    unit: ClassicPreparedUnit
    reason: str
    unit_donor_objects: Mapping[str, bytes] = field(default_factory=dict)


def repoint_refusal_materials(
    refusal: ClassicRepairRefusal, donor_id: str, payload: bytes
) -> ClassicDispatchMaterials:
    """The refusal's materials with ``payload`` standing in for its previous primary donor.

    Every donor role the receipt resolved to the previous primary donor (the
    target, complete or instruction donor) follows onto the new object; roles
    naming another donor keep their captured objects.
    """

    materials = refusal.materials
    values = refusal.receipt.expected_values
    previous = refusal.intervention.dependencies[0] if refusal.intervention.dependencies else None
    named = {
        key: values.get(key) for key in ("target_donor", "complete_donor", "instruction_donor")
    }
    return replace(
        materials,
        donor_object=payload,
        target_donor_object=(
            payload if named["target_donor"] in {None, previous} else materials.target_donor_object
        ),
        complete_donor_object=(
            payload if named["complete_donor"] == previous else materials.complete_donor_object
        ),
        instruction_donor_object=(
            payload
            if named["instruction_donor"] == previous
            else materials.instruction_donor_object
        ),
    )


def dropped_move_parameters(action: ClassicRecipeIntervention) -> tuple[str, ...]:
    """The parameters a move of ``action`` onto another donor leaves behind."""

    return tuple(
        field.name for field in action.parameters if field.name in DROPPABLE_MOVE_PARAMETERS
    )


def repointed_action(action: ClassicRecipeIntervention, donor_id: str) -> ClassicRecipeIntervention:
    """The saved record moved onto ``donor_id``.

    A declared debug representation delta described the record's previous
    donor against the seed; with another donor it is meaningless and is
    dropped, so the measured-pin repair re-derives the delta from the fresh
    pair and carries it in the receipt.  Every other parameter stays.
    """

    return ClassicDependencyEdit(action, donor_id, dropped_move_parameters(action)).after


class ClassicRepairSession:
    """Collect safe repairs from parallel TU composition without publishing them."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._repairs: dict[str, ClassicReceiptRepair] = {}
        self._refusals: dict[tuple[str, int, str], ClassicRepairRefusal] = {}

    @staticmethod
    def _refusal(
        request: ClassicMeasuredReceiptRepairRequest,
        reason: str,
    ) -> ClassicRepairRefusal:
        unit = cast(ClassicPreparedUnit, request.unit)
        return ClassicRepairRefusal(
            unit.plan.id,
            request.action_index,
            request.intervention,
            request.receipt,
            request.materials,
            unit,
            reason,
            dict(request.unit_donor_objects),
        )

    def __call__(self, request: ClassicMeasuredReceiptRepairRequest) -> ClassicProofReceipt | None:
        try:
            repaired = repair_measured_pins(
                request.intervention,
                request.receipt,
                request.materials,
            )
        except MeasuredPinRepairError as exc:
            refusal = self._refusal(request, str(exc))
            key = (request.unit.plan.id, request.action_index, request.intervention.id)
            with self._lock:
                self._refusals.setdefault(key, refusal)
            return None

        if not repaired.changed_keys:
            refusal = self._refusal(
                request,
                "fresh measurements did not change any saved field",
            )
            key = (request.unit.plan.id, request.action_index, request.intervention.id)
            with self._lock:
                self._refusals.setdefault(key, refusal)
            return None

        record = ClassicReceiptRepair(
            request.unit.plan.id,
            request.action_index,
            request.receipt,
            repaired.receipt,
            repaired.changed_keys,
        )
        with self._lock:
            existing = self._repairs.get(record.before.id)
            if existing is not None and existing != record:
                raise ClassicRepairSessionError(
                    f"receipt {record.before.id!r} produced conflicting repairs"
                )
            self._repairs[record.before.id] = record
        return repaired.receipt

    @property
    def repairs(self) -> tuple[ClassicReceiptRepair, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._repairs.values(),
                    key=lambda item: (
                        item.unit_id.casefold(),
                        item.action_index,
                        item.before.id.casefold(),
                    ),
                )
            )

    @property
    def refusals(self) -> tuple[ClassicRepairRefusal, ...]:
        with self._lock:
            return tuple(
                self._refusals[key]
                for key in sorted(
                    self._refusals,
                    key=lambda item: (item[0].casefold(), item[1], item[2].casefold()),
                )
            )


def apply_classic_receipt_repairs(
    root: Path,
    spec: ProjectSpec,
    repairs: tuple[ClassicReceiptRepair, ...],
) -> tuple[str, ...]:
    """Persist validated receipt replacements inside a private staged project."""

    if not repairs:
        return ()
    try:
        return apply_classic_authority_edits(
            root,
            spec,
            receipts=tuple(ClassicReceiptEdit(item.before, item.after) for item in repairs),
        )
    except RuntimeError as exc:
        raise ClassicRepairSessionError(str(exc)) from exc


__all__ = [
    "ClassicReceiptRepair",
    "ClassicRepairRefusal",
    "ClassicRepairSession",
    "ClassicRepairSessionError",
    "apply_classic_receipt_repairs",
    "dropped_move_parameters",
    "repoint_refusal_materials",
]
