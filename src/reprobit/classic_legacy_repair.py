"""Bounded re-authoring for an existing classic legacy installation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.coff import (
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from reprobit.classic.composition_mosaic import instruction_mosaic_metadata_sha256
from reprobit.classic.foundation import RelocationView
from reprobit.classic.ia32 import require_declared_relocation_semantics
from reprobit.classic.legacy_elision import (
    SIMULATED_ELISION_CLASS,
    SIMULATED_ELISION_KIND,
    ElisionInput,
    apply_simulated_elision,
    compose_retail_exact_simulated_elision,
    require_retail_relocation_oracle,
)
from reprobit.classic.register_semantics import decode_ia32_bijection_body
from reprobit.classic.relational import relational_form_external_entries
from reprobit.classic_repair_authority import (
    ClassicInterventionEdit,
    ClassicReceiptEdit,
    ClassicRecordAddition,
    LegacyInterventionEdit,
)
from reprobit.classic_retail_repair import (
    refresh_retail_relocations,
    restore_retail_relocation_addends,
)
from reprobit.coff_format import CoffObject, coff_body, detailed_relocations, section_definitions
from reprobit.discovery_authoring import (
    REAUTHORABLE_FAMILIES,
    DiscoveryAuthoringError,
    build_measured_function_record,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.model import ByteRange, Digest, Scope
from reprobit.oracle_pe32 import LegacyInstallError, PE32VirtualAddressReader
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    Intervention,
    LegacyOracleInstallIntervention,
    OracleInstallRange,
    classic_function_donor_ids,
)
from reprobit.strict_json import canonical_json


class LegacyRepairError(RuntimeError):
    """An existing quarantine could not be refreshed without broadening it."""


class LegacyNoWindowError(LegacyRepairError):
    """Fresh material needs none of an existing legacy action's byte windows."""


@dataclass(frozen=True, slots=True)
class LegacyInstallRepair:
    """One strictly composed replacement for an existing legacy action."""

    intervention: LegacyOracleInstallIntervention
    receipt: ClassicProofReceipt
    output: bytes


@dataclass(frozen=True, slots=True)
class LegacyOracleMaterial:
    """Finite bytes read from the existing action's sealed VA oracle."""

    retail_body: bytes
    auxiliary_bodies: Mapping[str, bytes]


@dataclass(frozen=True, slots=True)
class LegacyNoWindowResolution:
    """Exact authority changes that retire or replace one zero-window quarantine."""

    legacy_edit: LegacyInterventionEdit
    receipt_edits: tuple[ClassicReceiptEdit, ...]
    donor_edits: tuple[ClassicInterventionEdit, ...]
    addition: ClassicRecordAddition | None
    removed_donors: tuple[str, ...]

    @property
    def replaced(self) -> bool:
        return self.addition is not None


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LegacyRepairError(f"{label} is not an object")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise LegacyRepairError(f"{label} is not an integer")
    return value


def capture_legacy_oracle_material(
    intervention: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    oracle: PE32VirtualAddressReader,
) -> LegacyOracleMaterial:
    """Read exactly the oracle ranges already pinned by a legacy receipt."""

    if (
        receipt.intervention_id != intervention.id
        or Digest.from_bytes(canonical_json(receipt)) != intervention.proof_receipt_digest
    ):
        raise LegacyRepairError("legacy repair receipt differs from its existing action")
    values = receipt.expected_values
    retail = _mapping(values.get("retail_oracle"), "legacy retail oracle")
    address_value = retail.get("address")
    length = retail.get("length")
    try:
        address = int(address_value, 16) if isinstance(address_value, str) else -1
    except ValueError as exc:
        raise LegacyRepairError("legacy retail oracle address is invalid") from exc
    if address != intervention.oracle_address or type(length) is not int or length < 1:
        raise LegacyRepairError("legacy retail oracle differs from its existing action")
    try:
        main = oracle.read_virtual_address(address, length)
    except LegacyInstallError as exc:
        raise LegacyRepairError(f"cannot read the existing legacy oracle: {exc}") from exc
    try:
        restored_main = restore_retail_relocation_addends(
            main,
            values.get("retail_relocations"),
            "legacy retail relocation declaration",
        )
    except (ByteIdentityError, ValueError) as exc:
        raise LegacyRepairError(f"legacy retail relocation declaration is invalid: {exc}") from exc
    if sha256(restored_main).hexdigest() != intervention.oracle_body_digest.value:
        raise LegacyRepairError("existing legacy oracle differs from its pinned body")
    simulated = _mapping(values.get("simulated_elision"), "legacy simulated-elision proof")
    auxiliary: dict[str, bytes] = {}
    payload_bytes = len(main)
    for key in ("callee_oracles", "vtable_oracles"):
        raw_items = simulated.get(key, [])
        if not isinstance(raw_items, list):
            raise LegacyRepairError(f"legacy {key} declaration is not an array")
        for raw in raw_items:
            item = _mapping(raw, f"legacy {key} entry")
            symbol = item.get("symbol")
            aux_address = item.get("address")
            aux_length = item.get("length")
            digest = item.get("body_sha256")
            if (
                not isinstance(symbol, str)
                or not symbol
                or symbol in auxiliary
                or not isinstance(aux_address, str)
                or type(aux_length) is not int
                or aux_length < 1
                or not isinstance(digest, str)
            ):
                raise LegacyRepairError(f"legacy {key} entry is invalid")
            try:
                payload = oracle.read_virtual_address(int(aux_address, 16), aux_length)
            except (LegacyInstallError, ValueError) as exc:
                raise LegacyRepairError(
                    f"cannot read existing legacy oracle {symbol!r}: {exc}"
                ) from exc
            if sha256(payload).hexdigest() != digest:
                raise LegacyRepairError(f"existing legacy oracle {symbol!r} differs from its pin")
            auxiliary[symbol] = payload
            payload_bytes += len(payload)
    if payload_bytes != intervention.maximum_oracle_payload_bytes:
        raise LegacyRepairError("legacy oracle payload differs from its existing ceiling")
    return LegacyOracleMaterial(main, MappingProxyType(auxiliary))


def _candidate_regions(
    intervention: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    preimage_body: bytes,
    retail_body: bytes,
    relocation_symbols: Mapping[int, object],
) -> list[dict[str, Any]]:
    """Keep only old oracle windows that the fresh pre-image still needs.

    Oracle/output positions never move.  The fresh pre-image side is the
    smallest whole-instruction span covering the old output window.  This is
    intentionally narrow: a source change may make an old window redundant,
    but repair may not invent a new reference-byte seat.
    """

    values = receipt.expected_values
    simulated = _mapping(values.get("simulated_elision"), "legacy simulated-elision proof")
    raw_regions = simulated.get("regions")
    if not isinstance(raw_regions, list) or len(raw_regions) != len(intervention.ranges):
        raise LegacyRepairError("legacy receipt regions differ from the existing action")
    code_length_value = simulated.get("expected_code_length")
    code_length = (
        _integer(code_length_value, "legacy code length") if code_length_value is not None else None
    )
    try:
        decoded = decode_ia32_bijection_body(
            preimage_body,
            "legacy repair pre-image",
            dict(relocation_symbols),
            code_length,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise LegacyRepairError(f"cannot decode the fresh legacy pre-image: {exc}") from exc
    limit = len(preimage_body) if code_length is None else code_length
    boundaries = sorted({*(int(item["offset"]) for item in decoded), limit})
    candidates: list[dict[str, Any]] = []
    previous_end = 0
    for index, (authority, raw) in enumerate(zip(intervention.ranges, raw_regions, strict=True)):
        region = dict(_mapping(raw, f"legacy receipt region {index}"))
        old_binding = (
            authority.preimage_range.offset,
            authority.preimage_range.end,
            authority.output_range.offset,
            authority.output_range.length,
        )
        received = tuple(
            region.get(key) for key in ("region_start", "region_end", "image_start", "image_length")
        )
        if received != old_binding or authority.output_range != authority.oracle_range:
            raise LegacyRepairError(f"legacy receipt region {index} is not its frozen range")
        image_start = authority.output_range.offset
        image_end = authority.output_range.end
        if image_end > len(retail_body) or image_start >= limit:
            raise LegacyRepairError(f"legacy region {index} leaves the fresh function")
        starts = [offset for offset in boundaries if offset <= image_start]
        ends = [offset for offset in boundaries if offset >= image_end]
        if not starts or not ends:
            raise LegacyRepairError(f"legacy region {index} has no fresh instruction cover")
        start, end = starts[-1], ends[0]
        if start <= 0 or end <= start or end > limit:
            raise LegacyRepairError(f"legacy region {index} has an invalid instruction cover")
        # An exact fresh slice needs no oracle installation.  Dropping it can
        # only narrow the old authority.
        if preimage_body[start:end] == retail_body[image_start:image_end]:
            continue
        if start < previous_end:
            raise LegacyRepairError("fresh legacy instruction covers overlap")
        previous_end = end
        region.update(
            region_start=start,
            region_end=end,
            image_start=image_start,
            image_length=authority.output_range.length,
        )
        candidates.append(region)
    if not candidates:
        raise LegacyNoWindowError("fresh material needs none of the saved legacy byte windows")
    return candidates


def _function_retail_equivalence(
    payload: bytes,
    symbol: str,
    label: str,
    *,
    retail_body: bytes,
    retail_address: int,
    relocation_declaration: object,
) -> tuple[bytes, bool]:
    """Return one fresh body and whether it is the sealed retail goal in COFF form."""

    if type(payload) is not bytes or not payload:
        raise LegacyRepairError(f"{label} is unavailable")
    try:
        parsed = CoffObject(payload)
        primary = parsed.function_section(symbol)
        body = bytes(coff_body(parsed, primary))
        rows = detailed_relocations(parsed, primary)
    except (ByteIdentityError, KeyError, ValueError) as exc:
        raise LegacyRepairError(f"{label} does not expose the quarantined function") from exc
    try:
        fresh_declaration = refresh_retail_relocations(
            relocation_declaration,
            parsed,
            primary,
            retail_address,
            f"{label} retail relocation declaration",
        )
        if any(row["type"] not in (0x0006, 0x0014) for row in rows):
            return body, False
        require_declared_relocation_semantics(
            rows,
            cast(list[dict[str, Any]], fresh_declaration),
            f"{label} ordinary relocation semantics",
        )
        require_retail_relocation_oracle(
            rows,
            retail_body,
            retail_address,
            cast(list[dict[str, Any]], fresh_declaration),
            f"{label} retail equivalence",
        )
        restored = restore_retail_relocation_addends(
            retail_body,
            fresh_declaration,
            f"{label} retail relocation declaration",
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError):
        return body, False
    return body, body == restored


def _receipt_index(
    receipts: Sequence[ClassicProofReceipt],
) -> dict[str, ClassicProofReceipt]:
    result: dict[str, ClassicProofReceipt] = {}
    for receipt in receipts:
        if receipt.intervention_id in result:
            raise LegacyRepairError(
                f"intervention {receipt.intervention_id!r} has ambiguous proof receipts"
            )
        result[receipt.intervention_id] = receipt
    return result


def _consumer_donor_ids(
    intervention: Intervention,
    receipts: Mapping[str, ClassicProofReceipt],
) -> set[str]:
    if not (
        isinstance(intervention, ClassicRecipeIntervention)
        and intervention.role is ClassicRecipeRole.FUNCTION
    ):
        return set(intervention.dependencies)
    receipt = receipts.get(intervention.id)
    if receipt is None:
        raise LegacyRepairError(f"classic function {intervention.id!r} lacks one proof receipt")
    try:
        return set(classic_function_donor_ids(intervention, receipt))
    except ValueError as exc:
        raise LegacyRepairError(
            f"classic function {intervention.id!r} has invalid donor authority: {exc}"
        ) from exc


def plan_legacy_no_window_resolution(
    interventions: Sequence[Intervention],
    receipts: Sequence[ClassicProofReceipt],
    *,
    intervention: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    seed_object: bytes,
    donor_object: bytes,
    retail_body: bytes,
    build_target: str,
) -> LegacyNoWindowResolution:
    """Retire or replace one quarantine after its saved windows become empty.

    Fresh source wins when it already carries the immutable goal. Otherwise
    the current donor may replace the quarantine only through the cheapest
    ordinary measured family accepted by the normal dispatcher.
    """

    matches = [item for item in interventions if item.id == intervention.id]
    if matches != [intervention]:
        raise LegacyRepairError("legacy action differs from saved authority")
    receipt_matches = [item for item in receipts if item.intervention_id == intervention.id]
    if receipt_matches != [receipt]:
        raise LegacyRepairError("legacy proof differs from saved authority")
    if Digest.from_bytes(canonical_json(receipt)) != intervention.proof_receipt_digest:
        raise LegacyRepairError("legacy proof differs from its existing action")
    if len(intervention.dependencies) != 1:
        raise LegacyRepairError("legacy action does not name exactly one current donor")
    symbol = intervention.scope.function
    unit_id = intervention.scope.translation_unit
    if symbol is None or unit_id is None:
        raise LegacyRepairError("legacy action has no exact function scope")
    goal = receipt.expected_values.get("expected_body_sha256")
    if goal != intervention.oracle_body_digest.value:
        raise LegacyRepairError("legacy proof has no matching immutable body goal")
    if type(retail_body) is not bytes:
        raise LegacyRepairError("captured retail body differs from the immutable body goal")
    relocation_declaration = receipt.expected_values.get("retail_relocations")
    try:
        restored_retail_body = restore_retail_relocation_addends(
            retail_body,
            relocation_declaration,
            "legacy retail relocation declaration",
        )
    except (ByteIdentityError, ValueError) as exc:
        raise LegacyRepairError(f"legacy retail relocation declaration is invalid: {exc}") from exc
    if sha256(restored_retail_body).hexdigest() != goal:
        raise LegacyRepairError("captured retail body differs from the immutable body goal")
    retail_oracle = _mapping(receipt.expected_values.get("retail_oracle"), "legacy retail oracle")
    address_value = retail_oracle.get("address")
    try:
        retail_address = int(address_value, 16) if isinstance(address_value, str) else -1
    except ValueError as exc:
        raise LegacyRepairError("legacy retail oracle address is invalid") from exc
    if (
        retail_address != intervention.oracle_address
        or retail_oracle.get("length") != len(retail_body)
        or retail_oracle.get("verdict") != "MATCH"
    ):
        raise LegacyRepairError("captured retail body differs from its sealed oracle")
    seed_body, seed_exact = _function_retail_equivalence(
        seed_object,
        symbol,
        "fresh seed object",
        retail_body=retail_body,
        retail_address=retail_address,
        relocation_declaration=relocation_declaration,
    )
    donor_body, donor_exact = _function_retail_equivalence(
        donor_object,
        symbol,
        "current donor object",
        retail_body=retail_body,
        retail_address=retail_address,
        relocation_declaration=relocation_declaration,
    )
    expected_length = receipt.expected_values.get("expected_body_length")
    if expected_length is not None and type(expected_length) is not int:
        raise LegacyRepairError("legacy proof has an invalid immutable body length")

    addition: ClassicRecordAddition | None = None
    if seed_exact and expected_length is not None and expected_length != len(seed_body):
        raise LegacyRepairError("fresh seed body length differs from the immutable goal")
    if not seed_exact:
        if not donor_exact:
            raise LegacyRepairError(
                "neither fresh source nor the current donor carries the immutable body goal"
            )
        if expected_length is not None and expected_length != len(donor_body):
            raise LegacyRepairError("current donor body length differs from the immutable goal")
        failures: list[str] = []
        donor_id = intervention.dependencies[0]
        for family in REAUTHORABLE_FAMILIES:
            try:
                authored = build_measured_function_record(
                    target_id=intervention.scope.target,
                    translation_unit_id=unit_id,
                    build_target=build_target,
                    symbol=symbol,
                    family=family,
                    donor_id=donor_id,
                    seed_object=seed_object,
                    donor_object=donor_object,
                )
            except DiscoveryAuthoringError as exc:
                failures.append(str(exc))
                continue
            addition = ClassicRecordAddition(
                authored.intervention,
                authored.receipt,
                replaces_intervention_id=intervention.id,
            )
            break
        if addition is None:
            detail = failures[-1] if failures else "no closed family was available"
            raise LegacyRepairError(
                "current donor carries the goal but no ordinary measured record accepts it: "
                + detail
            )

    remaining = [item for item in interventions if item.id != intervention.id]
    if addition is not None:
        if any(item.id == addition.intervention.id for item in remaining):
            raise LegacyRepairError("ordinary replacement identifier already exists")
        remaining.append(addition.intervention)
    receipt_by_intervention = _receipt_index(
        [item for item in receipts if item.intervention_id != intervention.id]
        + ([] if addition is None else [addition.receipt])
    )
    affected_donors = set(intervention.dependencies)
    if addition is not None:
        affected_donors.update(addition.intervention.dependencies)
    references: set[str] = set()
    consumers: dict[str, dict[tuple[str, str, str], Scope]] = {}
    for item in remaining:
        donor_ids = _consumer_donor_ids(item, receipt_by_intervention)
        references.update(donor_ids)
        scope = item.scope
        if scope.translation_unit is None or scope.function is None:
            continue
        key = (scope.target, scope.translation_unit, scope.function)
        for donor_id in donor_ids:
            consumers.setdefault(donor_id, {})[key] = scope

    donor_edits: list[ClassicInterventionEdit] = []
    receipt_edits = [ClassicReceiptEdit(receipt, None)]
    removed_donors: list[str] = []
    saved_receipts = _receipt_index(receipts)
    for donor_id in sorted(affected_donors, key=str.casefold):
        donor_matches = [
            item
            for item in interventions
            if isinstance(item, ClassicRecipeIntervention)
            and item.role is ClassicRecipeRole.DONOR
            and item.id == donor_id
        ]
        if len(donor_matches) != 1:
            raise LegacyRepairError(f"legacy donor {donor_id!r} differs from saved authority")
        donor = donor_matches[0]
        expected = tuple(
            consumers.get(donor_id, {})[key] for key in sorted(consumers.get(donor_id, {}))
        )
        if donor_id not in references:
            if expected:
                raise LegacyRepairError(f"orphaned donor {donor_id!r} still has beneficiaries")
            donor_receipt = saved_receipts.get(donor_id)
            if donor_receipt is None:
                raise LegacyRepairError(f"orphaned donor {donor_id!r} has no proof receipt")
            donor_edits.append(ClassicInterventionEdit(donor, None))
            receipt_edits.append(ClassicReceiptEdit(donor_receipt, None))
            removed_donors.append(donor_id)
        elif expected != donor.beneficiaries:
            donor_edits.append(
                ClassicInterventionEdit(donor, donor.model_copy(update={"beneficiaries": expected}))
            )

    return LegacyNoWindowResolution(
        LegacyInterventionEdit(intervention, None),
        tuple(receipt_edits),
        tuple(donor_edits),
        addition,
        tuple(removed_donors),
    )


def _retail_relocations(
    rows: list[dict[str, Any]],
    *,
    section_number: int,
    proof: Mapping[str, object],
    retail_body: bytes,
    retail_address: int,
) -> list[dict[str, Any]]:
    raw_moved = proof.get("relocation_reseat")
    raw_offset_map = proof.get("offset_map")
    if not isinstance(raw_moved, list) or not isinstance(raw_offset_map, Mapping):
        raise LegacyRepairError("legacy composer returned an invalid boundary map")
    moved = dict(raw_moved)
    offset_map = {int(key): value for key, value in raw_offset_map.items()}
    result: list[dict[str, Any]] = []
    fields = (
        "addend",
        "offset",
        "target",
        "target_section",
        "target_storage",
        "target_type",
        "target_value",
        "type",
    )
    for source in rows:
        row = {key: source[key] for key in fields}
        row["offset"] = moved.get(source["offset"], source["offset"])
        if source["target_section"] == section_number:
            target = offset_map.get(source["target_value"])
            if target is None:
                raise LegacyRepairError(
                    "fresh legacy relocation target is not an instruction boundary"
                )
            row["target_value"] = target
        offset = row["offset"]
        raw = retail_body[offset : offset + 4]
        if len(raw) != 4:
            raise LegacyRepairError("fresh legacy relocation leaves the retail body")
        if row["type"] == 0x0006:
            resolved = int.from_bytes(raw, "little")
        else:
            displacement = int.from_bytes(raw, "little", signed=True)
            resolved = (retail_address + offset + 4 + displacement) & 0xFFFFFFFF
        base = (resolved - row["addend"]) & 0xFFFFFFFF
        row["retail_target"] = f"0x{base:08x}"
        result.append(row)
    return result


def reauthor_legacy_simulated_elision(
    intervention: LegacyOracleInstallIntervention,
    receipt: ClassicProofReceipt,
    seed_object: bytes,
    donor_object: bytes,
    retail_body: bytes,
    auxiliary_oracles: Mapping[str, bytes] | None = None,
) -> LegacyInstallRepair:
    """Refresh one existing action using only its old oracle byte windows."""

    if receipt.intervention_id != intervention.id or (
        receipt.family is not ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION
    ):
        raise LegacyRepairError("legacy repair receipt names different authority")
    if len(intervention.dependencies) != 1 or not seed_object or not donor_object:
        raise LegacyRepairError("legacy repair lacks its fresh seed or donor object")
    old_values = deepcopy(receipt.expected_values)
    retail_oracle = _mapping(old_values.get("retail_oracle"), "legacy retail oracle")
    address_value = retail_oracle.get("address")
    try:
        retail_address = int(address_value, 16) if isinstance(address_value, str) else -1
    except ValueError as exc:
        raise LegacyRepairError("legacy retail oracle address is invalid") from exc
    if retail_address != intervention.oracle_address or retail_oracle.get("length") != len(
        retail_body
    ):
        raise LegacyRepairError("legacy retail oracle differs from its existing action")

    try:
        seed = CoffObject(seed_object)
        donor = CoffObject(donor_object)
        symbol = intervention.scope.function
        if symbol is None:
            raise LegacyRepairError("legacy action has no function scope")
        seed_section = seed.function_section(symbol)
        donor_section = donor.function_section(symbol)
        seed_body = bytes(coff_body(seed, seed_section))
        donor_body = bytes(coff_body(donor, donor_section))
        rows = detailed_relocations(donor, donor_section)
        relocation_offsets = frozenset(
            row["offset"] + byte for row in rows for byte in range(row["width"])
        )
        relocation_symbols = {
            row["offset"]: {"width": row["width"], "target": row["target"]} for row in rows
        }
        internal_targets = frozenset(
            row["target_value"] for row in rows if row["target_section"] == donor_section["number"]
        )
        external_entries = relational_form_external_entries(
            donor, donor_section, "legacy repair external entries"
        )
        regions = _candidate_regions(
            intervention,
            receipt,
            donor_body,
            retail_body,
            relocation_symbols,
        )

        def shifted(offset: int) -> int:
            return offset + sum(
                _integer(region["image_length"], "legacy image length")
                - (
                    _integer(region["region_end"], "legacy region end")
                    - _integer(region["region_start"], "legacy region start")
                )
                for region in regions
                if offset >= _integer(region["region_end"], "legacy region end")
            )

        image_relocations = {shifted(row["offset"]): row["target"] for row in rows}
        image, proof = apply_simulated_elision(
            donor_body,
            deepcopy(regions),
            relocation_offsets,
            "legacy repair",
            ElisionInput(
                retail_body=retail_body,
                image_relocations=image_relocations,
                branch_widenings=[],
                oracles=None,
            ),
            view=RelocationView(
                relocations=relocation_symbols,
                code_length=None,
                internal_targets=internal_targets,
            ),
            external_entries=frozenset(external_entries),
        )
    except LegacyRepairError:
        raise
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise LegacyRepairError(f"fresh legacy ranges did not prove equivalent: {exc}") from exc

    if sha256(image).hexdigest() != intervention.oracle_body_digest.value:
        raise LegacyRepairError("fresh legacy composition changes the pinned oracle body")
    raw_spec = _mapping(old_values.get("simulated_elision"), "legacy simulated-elision proof")
    if raw_spec.get("line_row_positions"):
        raise LegacyRepairError("automatic legacy repair cannot move saved line rows")
    spec = dict(raw_spec)
    spec.update(
        kind=SIMULATED_ELISION_KIND,
        pre_image="donor",
        regions=regions,
        branch_widenings=proof["branch_widenings"],
        expected_branch_repairs=proof["branch_repairs"],
        expected_branch_widenings=proof["branch_widenings"],
        expected_external_entries=sorted(external_entries),
        expected_image_code_length=proof["image_code_length"],
        expected_instruction_count=proof["instruction_count"],
        expected_relocation_reseat=proof["relocation_reseat"],
    )
    seed_closure = _comdat_child_closure(seed, seed_section)
    donor_closure = _comdat_child_closure(donor, donor_section)
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    if (
        seed_closure != donor_closure
        or seed_functions != donor_functions
        or seed_comdats != donor_comdats
    ):
        raise LegacyRepairError("fresh seed and donor no longer share the legacy object shape")
    seed_selection = section_definitions(seed)[seed_section["number"]]["selection"]
    donor_selection = section_definitions(donor)[donor_section["number"]]["selection"]
    if seed_selection != donor_selection:
        raise LegacyRepairError("fresh seed and donor no longer share the legacy COMDAT seat")
    retail_rows = _retail_relocations(
        rows,
        section_number=donor_section["number"],
        proof=proof,
        retail_body=retail_body,
        retail_address=retail_address,
    )
    expected_values: dict[str, Any] = dict(old_values)
    expected_values.update(
        expected_body_sha256=intervention.oracle_body_digest.value,
        expected_characteristics=seed_section["characteristics"],
        expected_closure=list(seed_closure[1]),
        expected_comdat_count=sum(seed_comdats.values()),
        expected_donor_body_sha256=sha256(donor_body).hexdigest(),
        expected_donor_length=len(image),
        expected_donor_line_count=donor_section["line_count"],
        expected_donor_metadata_sha256=instruction_mosaic_metadata_sha256(donor, donor_section),
        expected_donor_relocation_count=donor_section["relocation_count"],
        expected_donor_section_count=len(donor.sections),
        expected_donor_section_number=donor_section["number"],
        expected_function_count=sum(seed_functions.values()),
        expected_linked_span=(len(image) + 15) // 16 * 16,
        expected_pre_image_length=len(donor_body),
        expected_relocation_count=seed_section["relocation_count"],
        expected_section_count=len(seed.sections),
        expected_section_number=seed_section["number"],
        expected_seed_body_sha256=sha256(seed_body).hexdigest(),
        expected_seed_length=len(seed_body),
        expected_seed_line_count=seed_section["line_count"],
        expected_seed_metadata_sha256=instruction_mosaic_metadata_sha256(seed, seed_section),
        expected_selection=seed_selection,
        retail_relocations=retail_rows,
        simulated_elision=spec,
    )
    repaired_receipt = receipt.model_copy(update={"expected_values": expected_values})
    proof_digest = Digest.from_bytes(canonical_json(repaired_receipt))
    ranges = tuple(
        OracleInstallRange(
            preimage_range=ByteRange(
                offset=region["region_start"],
                length=region["region_end"] - region["region_start"],
            ),
            output_range=ByteRange(offset=region["image_start"], length=region["image_length"]),
            oracle_range=ByteRange(offset=region["image_start"], length=region["image_length"]),
        )
        for region in regions
    )
    fields = {
        name: getattr(intervention, name)
        for name in type(intervention).model_fields
        if name != "allowlist_digest"
    }
    fields.update(
        proof_receipt_digest=proof_digest,
        preimage_digest=Digest.from_bytes(donor_body),
        ranges=ranges,
        byte_count=sum(item.output_range.length for item in ranges),
    )
    repaired_intervention = LegacyOracleInstallIntervention.freeze(**fields)
    try:
        output, detail = compose_retail_exact_simulated_elision(
            seed_object,
            donor_object,
            {
                **deepcopy(expected_values),
                "mangled": symbol,
                "splice_class": SIMULATED_ELISION_CLASS,
            },
            retail_body,
            dict(auxiliary_oracles or {}),
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise LegacyRepairError(f"strict legacy composer rejected the repair: {exc}") from exc
    if detail.get("retail_exact") is not True:
        raise LegacyRepairError("strict legacy composer did not prove retail exactness")
    return LegacyInstallRepair(repaired_intervention, repaired_receipt, output)


def covered_output_ranges(
    intervention: LegacyOracleInstallIntervention,
) -> tuple[ByteRange, ...]:
    """Return the canonical oracle/output authority of a legacy action."""

    return tuple(item.output_range for item in intervention.ranges)


__all__ = [
    "LegacyInstallRepair",
    "LegacyNoWindowError",
    "LegacyNoWindowResolution",
    "LegacyOracleMaterial",
    "LegacyRepairError",
    "covered_output_ranges",
    "plan_legacy_no_window_resolution",
    "reauthor_legacy_simulated_elision",
]
