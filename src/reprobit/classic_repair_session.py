"""Conservative in-memory classic repair collection and staged persistence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from reprobit.classic_donors import DonorSourceError, matching_candidate_constraints
from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_legacy_repair import (
    LegacyInstallRepair,
    LegacyOracleMaterial,
    LegacyRepairError,
    capture_legacy_oracle_material,
)
from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_authority import (
    DROPPABLE_MOVE_PARAMETERS,
    ClassicAuthorityRepairError,
    ClassicDependencyEdit,
    ClassicReceiptEdit,
    apply_classic_authority_edits,
)
from reprobit.classic_repair_dispatch import (
    ADMITTED_ADDED_PIN_KEYS,
    ClassicMeasuredReceiptRepairRequest,
    LegacyOracleInstallRepairRequest,
)
from reprobit.classic_retail_repair import (
    RetailRepairError,
    authenticated_retail_body_available,
    capture_authenticated_retail_body,
)
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    LegacyOracleInstallIntervention,
    ProjectSpec,
    classic_function_donor_ids,
)

if TYPE_CHECKING:
    from reprobit.oracle_pe32 import PE32VirtualAddressReader


class ClassicRepairSessionError(RuntimeError):
    """A proposed classic repair is ambiguous or cannot be persisted safely."""


_MAX_RETAIL_BODIES_PER_UNIT = 256


@dataclass(frozen=True, slots=True)
class ClassicReceiptRepair:
    """One ordinary-composer-validated measured receipt replacement."""

    unit_id: str
    action_index: int
    before: ClassicProofReceipt
    after: ClassicProofReceipt
    changed_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        # A measured repair refreshes the values of saved pins; it never adds or
        # drops a pin, with one closed exception: the debug representation delta
        # is an observation of the fresh seed/donor pair that the same-slot
        # validator consumes, so a repair may state it on a receipt that never
        # carried one, and must then declare it among its changed keys.
        added = self.after.expected_values.keys() - self.before.expected_values.keys()
        if (
            self.after.id != self.before.id
            or self.after.intervention_id != self.before.intervention_id
            or self.after.family is not self.before.family
            or self.before.expected_values.keys() - self.after.expected_values.keys()
            or added - ADMITTED_ADDED_PIN_KEYS
            or self.after.model_copy(update={"expected_values": self.before.expected_values})
            != self.before
        ):
            raise ClassicRepairSessionError(
                f"receipt {self.before.id!r} repair changes more than expected values"
            )
        actual = tuple(
            sorted(
                key
                for key in self.after.expected_values
                if key not in self.before.expected_values
                or self.before.expected_values[key] != self.after.expected_values[key]
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
    retail_body: bytes | None = None
    """Finite digest-checked target body captured during repair; never an oracle handle."""
    unit_retail_bodies: Mapping[str, bytes] = field(default_factory=dict)
    """Bounded mosaic goals for sibling consumers in this refused unit."""
    action_preimages: Mapping[str, bytes] = field(default_factory=dict)
    """Exact composed input captured immediately before each action in this unit."""
    # A census entry stands for a function that never had a record: nothing is
    # retired when it settles, and the probe binds it to its fresh unit by id alone.
    synthetic: bool = False


@dataclass(frozen=True, slots=True)
class LegacyRepairRefusal:
    """One failed existing legacy action with its finite sealed oracle bytes."""

    unit_id: str
    action_index: int
    intervention: LegacyOracleInstallIntervention
    receipt: ClassicProofReceipt
    materials: ClassicDispatchMaterials
    unit: ClassicPreparedUnit
    reason: str
    unit_donor_objects: Mapping[str, bytes] = field(default_factory=dict)
    legacy_oracle: LegacyOracleMaterial | None = None
    baseline_repair: LegacyInstallRepair | None = None
    """Safe repair for the current donor; retunes must make this authority smaller."""
    unit_retail_bodies: Mapping[str, bytes] = field(default_factory=dict)
    """Bounded mosaic goals for sibling consumers in this refused unit."""
    action_preimages: Mapping[str, bytes] = field(default_factory=dict)
    """Exact composed input captured immediately before each action in this unit."""


RepairRefusal = ClassicRepairRefusal | LegacyRepairRefusal


def repoint_refusal_materials(
    refusal: ClassicRepairRefusal,
    moved: ClassicRecipeIntervention,
    donor: ClassicPreparedDonor,
    payload: bytes,
) -> ClassicDispatchMaterials:
    """Rebuild fresh materials for exactly one saved record moved to ``donor``.

    The primary object, source and carrier shape follow the move.  An implicit
    target role follows the primary too; explicit roles remain attached to the
    donors named by the record's merged candidate constraints.
    """

    donor_id = donor.intervention.id
    if donor.request.intervention_id != donor_id:
        raise ClassicRepairSessionError(
            f"prepared donor {donor_id!r} has a request for {donor.request.intervention_id!r}"
        )
    try:
        expected = repointed_action(refusal.intervention, donor_id)
    except ClassicAuthorityRepairError as exc:
        raise ClassicRepairSessionError(str(exc)) from exc
    if moved != expected:
        raise ClassicRepairSessionError(
            f"moved action {moved.id!r} differs from its exact dependency edit"
        )
    try:
        values = matching_candidate_constraints(moved, (refusal.receipt,)).materialize()
        graph = classic_function_donor_ids(moved, refusal.receipt)
    except (DonorSourceError, ValueError) as exc:
        raise ClassicRepairSessionError(
            f"moved action {moved.id!r} has an invalid donor graph: {exc}"
        ) from exc

    prepared = {item.intervention.id: item for item in refusal.unit.donors}
    previous = prepared.get(donor_id)
    if previous is not None and previous != donor:
        raise ClassicRepairSessionError(
            f"prepared donor {donor_id!r} differs from the refusal's donor authority"
        )
    prepared[donor_id] = donor
    objects = dict(refusal.unit_donor_objects)
    objects[donor_id] = payload
    missing = graph - (prepared.keys() & objects.keys())
    if missing:
        raise ClassicRepairSessionError(
            f"moved action {moved.id!r} names unavailable donors: {sorted(missing)}"
        )
    sources = {
        item_id: item.request.logical_outputs.get(refusal.unit.plan.source)
        for item_id, item in prepared.items()
    }

    def named(name: str) -> str | None:
        value = values.get(name)
        if value is None:
            return None
        if not isinstance(value, str) or value not in graph:
            raise ClassicRepairSessionError(
                f"moved action {moved.id!r} names an invalid {name}: {value!r}"
            )
        return value

    target_id = named("target_donor")
    complete_id = named("complete_donor")
    instruction_id = named("instruction_donor")
    raw_variants = values.get("donor_variants", [])
    if not isinstance(raw_variants, list):
        raise ClassicRepairSessionError(f"moved action {moved.id!r} has malformed donor variants")
    variant_ids = tuple(
        cast(str, item["donor"])
        for item in raw_variants
        if isinstance(item, dict) and isinstance(item.get("donor"), str)
    )
    if len(variant_ids) != len(raw_variants):
        raise ClassicRepairSessionError(f"moved action {moved.id!r} has malformed donor variants")
    return replace(
        refusal.materials,
        donor_object=payload,
        target_donor_object=objects[target_id] if target_id is not None else payload,
        complete_donor_object=objects[complete_id] if complete_id is not None else None,
        instruction_donor_object=(objects[instruction_id] if instruction_id is not None else None),
        donor_source=sources[donor_id],
        target_donor_source=sources[target_id if target_id is not None else donor_id],
        instruction_donor_source=(sources[instruction_id] if instruction_id is not None else None),
        additional_donor_objects={item_id: objects[item_id] for item_id in variant_ids},
        shape_identifiers=donor.request.carrier_identifiers,
        candidate_constraints=values,
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
        self._refusals: dict[tuple[str, int, str], RepairRefusal] = {}
        self._seed_objects: dict[str, SeedObject] = {}
        self._unit_retail_bodies: dict[str, tuple[Mapping[str, bytes], Mapping[str, str]]] = {}
        self._unit_action_preimages: dict[str, dict[str, tuple[int, bytes]]] = {}

    def record_action_preimage(
        self,
        unit_id: str,
        action_index: int,
        intervention_id: str,
        preimage: bytes,
    ) -> None:
        """Retain the exact repair-only composition input for one action."""

        if type(action_index) is not int or action_index < 0 or not isinstance(preimage, bytes):
            raise ClassicRepairSessionError("action preimage capture is malformed")
        with self._lock:
            if any(
                key_unit == unit_id and key_index < action_index
                for key_unit, key_index, _action_id in self._refusals
            ):
                return
            unit = self._unit_action_preimages.setdefault(unit_id, {})
            captured = (action_index, preimage)
            previous = unit.get(intervention_id)
            if previous is not None and previous != captured:
                raise ClassicRepairSessionError(
                    f"action {intervention_id!r} produced conflicting composition preimages"
                )
            unit[intervention_id] = captured

    def _action_preimages_unlocked(self, unit_id: str) -> Mapping[str, bytes]:
        return MappingProxyType(
            {
                action_id: value
                for action_id, (_index, value) in self._unit_action_preimages.get(
                    unit_id, {}
                ).items()
            }
        )

    def _action_preimages(self, unit_id: str) -> Mapping[str, bytes]:
        with self._lock:
            return self._action_preimages_unlocked(unit_id)

    def release_completed_unit_preimages(self, unit_id: str) -> None:
        """Release repair-only inputs after one unit has completed safely."""

        with self._lock:
            if any(key_unit == unit_id for key_unit, _index, _action_id in self._refusals):
                raise ClassicRepairSessionError(
                    f"cannot release action preimages for refused unit {unit_id!r}"
                )
            self._unit_action_preimages.pop(unit_id, None)

    def record_seed_objects(self, objects: Mapping[str, SeedObject]) -> None:
        """Keep the fresh compiled objects the analysis captured for the census."""

        with self._lock:
            self._seed_objects.update(objects)

    @property
    def seed_objects(self) -> Mapping[str, SeedObject]:
        with self._lock:
            return MappingProxyType(dict(self._seed_objects))

    def _capture_unit_retail_bodies(
        self,
        unit: ClassicPreparedUnit,
        oracle: PE32VirtualAddressReader | None,
    ) -> tuple[Mapping[str, bytes], Mapping[str, str]]:
        """Capture bounded retail goals once while a repair-only reader is live."""

        with self._lock:
            cached = self._unit_retail_bodies.get(unit.plan.id)
        if cached is not None or oracle is None:
            return cached or ({}, {})
        receipts: dict[str, list[ClassicProofReceipt]] = {}
        for receipt in unit.receipts:
            receipts.setdefault(receipt.intervention_id, []).append(receipt)
        eligible = tuple(
            (action, matches[0])
            for action in unit.functions
            if len(matches := receipts.get(action.id, [])) == 1
            and authenticated_retail_body_available(action, matches[0])
        )
        bodies: dict[str, bytes] = {}
        errors: dict[str, str] = {}
        if len(eligible) > _MAX_RETAIL_BODIES_PER_UNIT:
            message = "unit has too many retail bodies for bounded oracle capture"
            errors.update((action.id, message) for action, _receipt in eligible)
        else:
            for action, receipt in eligible:
                try:
                    bodies[action.id] = capture_authenticated_retail_body(
                        action,
                        receipt,
                        oracle,
                    )
                except RetailRepairError as exc:
                    errors[action.id] = str(exc)
        captured = (MappingProxyType(bodies), MappingProxyType(errors))
        with self._lock:
            return self._unit_retail_bodies.setdefault(unit.plan.id, captured)

    def _refusal(
        self,
        request: ClassicMeasuredReceiptRepairRequest,
        reason: str,
    ) -> ClassicRepairRefusal:
        unit = cast(ClassicPreparedUnit, request.unit)
        unit_retail_bodies, capture_errors = self._capture_unit_retail_bodies(unit, request.oracle)
        retail_body = unit_retail_bodies.get(request.intervention.id)
        capture_error = capture_errors.get(request.intervention.id)
        if capture_error is not None:
            reason = f"{reason}; retail oracle capture failed: {capture_error}"
        return ClassicRepairRefusal(
            unit.plan.id,
            request.action_index,
            request.intervention,
            request.receipt,
            request.materials,
            unit,
            reason,
            dict(request.unit_donor_objects),
            retail_body,
            dict(unit_retail_bodies),
            self._action_preimages(unit.plan.id),
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

    def record_legacy_failure(self, request: LegacyOracleInstallRepairRequest) -> None:
        """Capture finite oracle material while its sealed capability is live."""

        try:
            oracle = capture_legacy_oracle_material(
                request.intervention,
                request.receipt,
                request.oracle,
            )
        except LegacyRepairError as exc:
            reason = f"{request.failure}; oracle capture failed: {exc}"
            oracle = None
        else:
            reason = str(request.failure)
        unit = cast(ClassicPreparedUnit, request.unit)
        unit_retail_bodies, _capture_errors = self._capture_unit_retail_bodies(unit, request.oracle)
        refusal = LegacyRepairRefusal(
            unit_id=unit.plan.id,
            action_index=request.action_index,
            intervention=request.intervention,
            receipt=request.receipt,
            materials=request.materials,
            unit=unit,
            reason=reason,
            unit_donor_objects=dict(request.unit_donor_objects),
            legacy_oracle=oracle,
            unit_retail_bodies=dict(unit_retail_bodies),
            action_preimages=self._action_preimages(unit.plan.id),
        )
        key = (unit.plan.id, request.action_index, request.intervention.id)
        with self._lock:
            self._refusals.setdefault(key, refusal)

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
    def refusals(self) -> tuple[RepairRefusal, ...]:
        with self._lock:
            return tuple(
                replace(
                    self._refusals[key],
                    action_preimages=self._action_preimages_unlocked(key[0]),
                )
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
    "LegacyRepairRefusal",
    "RepairRefusal",
    "apply_classic_receipt_repairs",
    "dropped_move_parameters",
    "repoint_refusal_materials",
]
