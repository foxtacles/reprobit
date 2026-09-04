"""Bounded re-authoring of an existing instruction-mosaic function record."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any, cast

from reprobit.binary import ByteIdentityError
from reprobit.classic.coff import (
    _coff_table_bytes,
    canonical_counter_receipt_sha256,
    comdat_primary_identity_multiset,
    function_multiset,
    section_shape_receipt_sha256,
)
from reprobit.classic.composition_fpo_identity import (
    donor_source_compiler_state_carrier_identifiers,
    measure_fpo_mosaic_identity,
    validate_donor_source_compiler_state_carrier,
)
from reprobit.classic.composition_mosaic import instruction_mosaic_metadata_sha256
from reprobit.classic.composition_relocations import (
    MOSAIC_PERMUTED_RELOCATION_ORDER,
    require_instruction_mosaic_semantic_relocations,
)
from reprobit.classic.debug import linker_payload_multiset
from reprobit.classic.ia32 import validate_instruction_self_permutation
from reprobit.classic_donors import DonorSourceError
from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepair,
    MeasuredPinRepairError,
    measure_mosaic_seat_observations,
    repair_measured_pins,
)
from reprobit.classic_project import ClassicDispatchMaterials, ClassicProjectError
from reprobit.classic_retail_repair import (
    RetailRepairError,
    capture_authenticated_retail_body,
    refresh_retail_relocations,
    retail_oracle_span,
)
from reprobit.coff_format import CoffMetadataIndex, CoffObject, coff_body, detailed_relocations
from reprobit.discovery_contracts import DiscoveryError
from reprobit.model import Digest
from reprobit.msvc_discovery_coff import (
    msvc_relocation_spans,
    unique_isolated_msvc_function,
)
from reprobit.msvc_discovery_mosaic import (
    MosaicDonorCandidate,
    MosaicSearchBudget,
    instruction_boundaries,
    mosaic_range_donor_id,
    mosaic_ranges_for_donor,
    select_mosaic_ranges,
)
from reprobit.oracle_pe32 import PE32VirtualAddressReader
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue, canonical_json

_MAX_BODY_BYTES = 64 * 1024
_MAX_CANDIDATES = 64
_DEFAULT_MAX_DONORS = 2
_DEFAULT_MAX_RANGES = 8
_MAX_SEARCH_STEPS = 10_000
_PRESERVED_PARAMETERS = frozenset(
    {
        "instruction_self_permutation",
        "ordinary_fpo_identity",
        "relocation_order",
        "same_function_source_identity",
        "source_fpo_identity",
        "target_source_refactor",
    }
)
_SEAT_RECEIPT_KEYS = (
    "expected_body_length",
    "expected_donor_body_sha256",
    "expected_donor_line_count",
    "expected_donor_metadata_sha256",
    "expected_line_count",
    "expected_relocation_count",
    "expected_section_count",
    "expected_section_number",
    "expected_seed_body_sha256",
    "expected_seed_metadata_sha256",
)
_RATIONALE = (
    "Fresh compiler objects re-derived this bounded instruction mosaic while preserving its "
    "existing source and function semantics."
)


class MosaicRepairError(RuntimeError):
    """Fresh compiler products cannot safely re-author a saved mosaic."""


@dataclass(frozen=True, slots=True)
class MosaicReauthoring:
    """A deterministic replacement record accepted by the ordinary composer."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    measured: MeasuredPinRepair
    donor_ids: frozenset[str]


def _parameter_map(action: ClassicRecipeIntervention) -> dict[str, JsonValue]:
    return {item.name: deepcopy(item.value) for item in action.parameters}


def instruction_mosaic_semantics_required(action: ClassicRecipeIntervention) -> bool:
    """Return whether replacing this mosaic with an equal-body family loses intent."""

    if action.family is not ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC:
        return False
    return bool(set(_parameter_map(action)) - {"instruction_ranges", "donor_variants"})


def _saved_search_limits(parameters: Mapping[str, JsonValue]) -> tuple[int, int]:
    raw_ranges = parameters.get("instruction_ranges")
    if not isinstance(raw_ranges, list) or len(raw_ranges) > 64:
        raise MosaicRepairError("saved mosaic instruction ranges are malformed")
    raw_variants = parameters.get("donor_variants", [])
    if not isinstance(raw_variants, list) or len(raw_variants) >= _MAX_CANDIDATES:
        raise MosaicRepairError("saved mosaic donor variants are malformed")
    variants: list[str] = []
    for item in raw_variants:
        if (
            not isinstance(item, dict)
            or set(item) != {"donor"}
            or not isinstance(item.get("donor"), str)
        ):
            raise MosaicRepairError("saved mosaic donor variant is malformed")
        variants.append(cast(str, item["donor"]))
    if len(variants) != len(set(variants)):
        raise MosaicRepairError("saved mosaic donor variants repeat")
    return (
        max(_DEFAULT_MAX_DONORS, 1 + len(variants)),
        max(_DEFAULT_MAX_RANGES, len(raw_ranges)),
    )


def _retail_oracle(receipt: ClassicProofReceipt) -> tuple[int, int, dict[str, JsonValue]]:
    try:
        return retail_oracle_span(receipt)
    except RetailRepairError as exc:
        raise MosaicRepairError(f"mosaic {exc}") from exc


def capture_instruction_mosaic_retail_body(
    action: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    oracle: PE32VirtualAddressReader,
) -> bytes:
    """Capture one finite, already-authorized body from a sealed PE oracle.

    Linked relocation operands are restored to their declared COFF addends and
    the resulting body must reproduce the saved immutable goal.  Only these
    finite bytes leave this function; the oracle capability is never retained.
    """

    if (
        action.family is not ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC
        or action.role is not ClassicRecipeRole.FUNCTION
        or receipt.intervention_id != action.id
        or receipt.family is not action.family
    ):
        raise MosaicRepairError("oracle capture requires one matching instruction mosaic")
    _address, length, _declaration = _retail_oracle(receipt)
    if receipt.expected_values.get("expected_body_length") != length:
        raise MosaicRepairError("mosaic retail oracle length differs from its body pin")
    try:
        return capture_authenticated_retail_body(action, receipt, oracle)
    except RetailRepairError as exc:
        raise MosaicRepairError(str(exc)) from exc


def _normalized_body(body: bytes, spans: tuple[tuple[int, int], ...]) -> bytes:
    result = bytearray(body)
    for start, end in spans:
        result[start:end] = b"\0" * (end - start)
    return bytes(result)


def _compatible_primary_shape(seed: Any, donor: Any) -> bool:
    """Keep the structural half of the discovery gate; relocations are checked later."""

    return bool(
        seed.isolated_primary
        and donor.isolated_primary
        and len(seed.body) == len(donor.body)
        and seed.selection == donor.selection
        and seed.section["characteristics"] == donor.section["characteristics"]
    )


def _composed_reseated_seed(
    seed: CoffObject,
    primary: dict[str, Any],
    moves: Mapping[int, int],
    body: bytes,
    symbol: str,
) -> tuple[CoffObject, dict[str, Any]]:
    """Return the exact composed body with selected relocation offsets updated."""

    payload = bytearray(seed.data)
    raw_offset = cast(int, primary["raw_offset"])
    if len(body) != len(coff_body(seed, primary)):
        raise MosaicRepairError("composed mosaic body length differs from the seed section")
    payload[raw_offset : raw_offset + len(body)] = body
    table_offset = cast(int, primary["relocation_offset"])
    for ordinal, offset in sorted(moves.items()):
        at = table_offset + ordinal * 10
        payload[at : at + 4] = offset.to_bytes(4, "little")
    output = CoffObject(bytes(payload))
    return output, output.function_section(symbol)


def _fresh_retail_relocations(
    receipt: ClassicProofReceipt,
    seed: CoffObject,
    primary: dict[str, Any],
    retail_address: int,
) -> list[JsonValue]:
    declared = receipt.expected_values.get("retail_relocations")
    try:
        return refresh_retail_relocations(
            declared,
            seed,
            primary,
            retail_address,
            "mosaic retail relocation declaration",
        )
    except (ByteIdentityError, ValueError) as exc:
        raise MosaicRepairError(str(exc)) from exc


def _carrier_descriptor(donor: ClassicRecipeIntervention) -> dict[str, JsonValue]:
    values = _parameter_map(donor)
    if donor.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        descriptor = values.get("compiler_state_carrier")
    else:
        generated = values.get("generated_header_sha256")
        if not isinstance(generated, str):
            raise MosaicRepairError("same-function donor has no generated declaration pin")
        if donor.family is ClassicRecipeFamily.EXTERN_RUN_PAIR:
            kind = "extern_run_pair_v1"
            placement = "after_includes_and_eof_v1"
            names: tuple[str, ...] = ("header", "seat")
        elif donor.family is ClassicRecipeFamily.DECLARATION_RUN_TRIPLE:
            kind = "declaration_run_triple_v1"
            placement = "start_after_includes_and_eof_v1"
            names = ("pre", "post", "eof")
        else:
            raise MosaicRepairError(
                "same-function mosaic donor has no supported compiler-state carrier"
            )
        descriptor = {
            "generated_declarations_sha256": generated,
            "kind": kind,
            "placement": placement,
            "width": values.get("width"),
        }
        for name in names:
            descriptor[f"{name}_count"] = values.get(f"{name}_count")
            descriptor[f"{name}_prefix"] = values.get(f"{name}_prefix")
    try:
        return cast(
            dict[str, JsonValue],
            validate_donor_source_compiler_state_carrier(
                descriptor, "same-function mosaic donor carrier"
            ),
        )
    except ByteIdentityError as exc:
        raise MosaicRepairError(str(exc)) from exc


def _refreshed_same_function_identity(
    saved: JsonValue,
    donor: ClassicRecipeIntervention,
    seed_source: bytes | None,
    donor_source: bytes | None,
) -> JsonValue:
    if not isinstance(saved, dict) or seed_source is None or donor_source is None:
        raise MosaicRepairError("same-function source identity lacks fresh source renderings")
    identity = deepcopy(saved)
    carrier = _carrier_descriptor(donor)
    identity["carrier"] = carrier
    identity["effective_source_sha256"] = sha256(seed_source).hexdigest()
    identity["rendered_source_sha256"] = sha256(donor_source).hexdigest()
    identity["rendered_source_size"] = len(donor_source)
    if "carrier_identifiers" in identity:
        identity["carrier_identifiers"] = [
            *donor_source_compiler_state_carrier_identifiers(
                carrier, "same-function mosaic donor carrier"
            )
        ]
    return cast(JsonValue, identity)


def _stable_id(kind: str, material: object) -> str:
    return f"discovery.{kind}.{Digest.from_bytes(canonical_json(material)).value[:16]}"


def _self_permutation_pins(
    seed: CoffObject,
    seed_body: bytes,
    target_body: bytes,
) -> dict[str, JsonValue]:
    functions = function_multiset(seed)
    comdats = comdat_primary_identity_multiset(seed)
    linker = linker_payload_multiset(seed)
    return {
        "instruction_self_permutation.expected_changed_offsets": [
            index
            for index, (left, right) in enumerate(zip(seed_body, target_body, strict=True))
            if left != right
        ],
        "instruction_self_permutation.expected_comdat_multiset_sha256": (
            canonical_counter_receipt_sha256(comdats)
        ),
        "instruction_self_permutation.expected_function_multiset_sha256": (
            canonical_counter_receipt_sha256(functions)
        ),
        "instruction_self_permutation.expected_linker_payload_count": sum(linker.values()),
        "instruction_self_permutation.expected_linker_payload_sha256": (
            canonical_counter_receipt_sha256(linker)
        ),
        "instruction_self_permutation.expected_section_shape_sha256": (
            section_shape_receipt_sha256(seed)
        ),
    }


def reauthor_instruction_mosaic(
    action: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    materials: ClassicDispatchMaterials,
    retail_body: bytes,
    *,
    donor_objects: Mapping[str, bytes],
    donor_interventions: Mapping[str, ClassicRecipeIntervention],
    donor_sources: Mapping[str, bytes | None] = {},
    donor_shape_identifiers: Mapping[str, frozenset[str]] = {},
) -> MosaicReauthoring:
    """Re-derive bounded ranges and prove the replacement through normal dispatch."""

    if (
        action.family is not ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC
        or action.role is not ClassicRecipeRole.FUNCTION
        or action.symbol is None
        or not action.dependencies
        or receipt.intervention_id != action.id
        or receipt.family is not action.family
        or type(materials.seed_object) is not bytes
        or type(retail_body) is not bytes
    ):
        raise MosaicRepairError("mosaic re-authoring requires one matching function record")
    if not retail_body or len(retail_body) > _MAX_BODY_BYTES:
        raise MosaicRepairError("mosaic retail body is outside repair bounds")
    if (
        receipt.expected_values.get("expected_body_length") != len(retail_body)
        or receipt.expected_values.get("expected_body_sha256") != sha256(retail_body).hexdigest()
    ):
        raise MosaicRepairError("mosaic retail body differs from its immutable goal")
    parameters = _parameter_map(action)
    unknown = (
        set(parameters)
        - _PRESERVED_PARAMETERS
        - {
            "instruction_ranges",
            "donor_variants",
        }
    )
    if unknown:
        raise MosaicRepairError(
            "mosaic re-authoring does not support parameters: " + ", ".join(sorted(unknown))
        )
    max_donors, max_ranges = _saved_search_limits(parameters)

    symbol = action.symbol
    try:
        seed = CoffObject(materials.seed_object)
        seed_index = CoffMetadataIndex(seed)
        seed_record = unique_isolated_msvc_function(seed, symbol, "mosaic repair seed", seed_index)
        if seed_record is None:
            raise MosaicRepairError("fresh seed omits the mosaic's isolated function COMDAT")
        seed_body = bytes(seed_record.body)
        if len(seed_body) != len(retail_body):
            raise MosaicRepairError("fresh seed and retail body lengths differ")
        seed_spans = msvc_relocation_spans(seed, seed_record, seed_index)
        seed_normalized = _normalized_body(seed_body, seed_spans)
        target_normalized = _normalized_body(retail_body, seed_spans)
    except (ByteIdentityError, DiscoveryError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, MosaicRepairError):
            raise
        raise MosaicRepairError(f"cannot prepare the fresh mosaic seed: {exc}") from exc

    source_refactor = "target_source_refactor" in parameters
    self_permutation = "instruction_self_permutation" in parameters
    same_function = "same_function_source_identity" in parameters
    ordinary_fpo = "ordinary_fpo_identity" in parameters
    source_fpo = "source_fpo_identity" in parameters
    permuted_relocations = "relocation_order" in parameters
    if permuted_relocations and parameters["relocation_order"] != MOSAIC_PERMUTED_RELOCATION_ORDER:
        raise MosaicRepairError("instruction mosaic names an unknown relocation order")
    raw_saved_ranges = cast(list[object], parameters["instruction_ranges"])
    saved_reseat = any(
        isinstance(item, dict) and bool(item.get("relocation_reseat")) for item in raw_saved_ranges
    )
    if permuted_relocations and (
        ordinary_fpo
        or source_fpo
        or self_permutation
        or source_refactor
        or "donor_variants" in parameters
    ):
        raise MosaicRepairError(
            "permuted relocation order requires the plain single-donor "
            "declaration-carrier mosaic class"
        )
    if saved_reseat and (source_fpo or self_permutation or source_refactor or permuted_relocations):
        raise MosaicRepairError(
            "relocation reseat requires the plain or ordinary-FPO declaration-carrier mosaic class"
        )
    forced_primary = (
        action.dependencies[0]
        if source_refactor or self_permutation or same_function or permuted_relocations
        else None
    )
    if permuted_relocations:
        max_donors = 1
    if forced_primary is not None and forced_primary not in donor_objects:
        raise MosaicRepairError("mosaic's source-bound primary donor was not captured")
    if source_refactor:
        donor = donor_interventions.get(cast(str, forced_primary))
        if donor is None or donor.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
            raise MosaicRepairError(
                "target source refactor is not bound to its source-overlay donor"
            )

    excluded: set[tuple[int, int]] = set()
    mismatch = {
        index
        for index, (left, right) in enumerate(zip(seed_normalized, target_normalized, strict=True))
        if left != right
    }
    prepared: dict[str, tuple[CoffObject, dict[str, Any], bytes, bytes]] = {}
    if self_permutation:
        if forced_primary is None:
            raise MosaicRepairError("instruction self-permutation has no primary donor")
        try:
            primary_payload = donor_objects[forced_primary]
            primary_coff = CoffObject(primary_payload)
            primary_section = primary_coff.function_section(symbol)
            primary_body = bytes(coff_body(primary_coff, primary_section))
            permutation_document = deepcopy(parameters["instruction_self_permutation"])
            if not isinstance(permutation_document, dict):
                raise MosaicRepairError("instruction self-permutation declaration is malformed")
            for path, value in _self_permutation_pins(seed, seed_body, retail_body).items():
                permutation_document[path.rsplit(".", 1)[-1]] = value
            permutation = validate_instruction_self_permutation(
                permutation_document,
                "mosaic repair instruction self-permutation",
                primary_body,
            )
        except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
            raise MosaicRepairError(
                f"saved instruction self-permutation no longer proves: {exc}"
            ) from exc
        target_start = cast(int, permutation["target_start"])
        target_end = cast(int, permutation["target_end"])
        excluded.add((target_start, target_end))
        permuted = bytearray(seed_body)
        for move in cast(list[dict[str, Any]], permutation["moves"]):
            permuted[move["target_start"] : move["target_end"]] = primary_body[
                move["donor_start"] : move["donor_end"]
            ]
        if bytes(permuted[target_start:target_end]) != retail_body[target_start:target_end]:
            raise MosaicRepairError("saved instruction self-permutation no longer reaches the goal")
        mismatch.difference_update(range(target_start, target_end))

    donors: list[MosaicDonorCandidate] = []
    for donor_id, payload in sorted(donor_objects.items(), key=lambda item: item[0]):
        donor_action = donor_interventions.get(donor_id)
        if donor_action is None:
            continue
        if permuted_relocations and donor_id != forced_primary:
            continue
        if (
            donor_action.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
            and donor_id != forced_primary
        ):
            continue
        try:
            coff = CoffObject(payload)
            index = CoffMetadataIndex(coff)
            record = unique_isolated_msvc_function(
                coff, symbol, f"mosaic repair donor {donor_id}", index
            )
            if record is None:
                continue
            if not _compatible_primary_shape(seed_record, record):
                continue
            spans = tuple(sorted(set(seed_spans) | set(msvc_relocation_spans(coff, record, index))))
            normalized_seed = _normalized_body(seed_body, spans)
            normalized = _normalized_body(bytes(record.body), spans)
            normalized_target = _normalized_body(retail_body, spans)
            pair_seed_boundaries = frozenset(
                instruction_boundaries(normalized_seed, f"mosaic repair seed for {donor_id}")
            )
            pair_target_boundaries = frozenset(
                instruction_boundaries(normalized_target, f"mosaic repair target for {donor_id}")
            )
            ranges = mosaic_ranges_for_donor(
                product=None,
                candidate_id=donor_id,
                seed_body=normalized_seed,
                donor_body=normalized,
                reference_body=normalized_target,
                seed_boundaries=pair_seed_boundaries,
                reference_boundaries=pair_target_boundaries,
                excluded_spans=tuple(sorted(excluded)),
                mismatch=frozenset(mismatch),
            )
            if ranges and not (permuted_relocations or saved_reseat):
                require_instruction_mosaic_semantic_relocations(
                    seed,
                    seed_record.section,
                    coff,
                    record.section,
                    f"mosaic repair donor {donor_id}",
                )
        except (ByteIdentityError, DiscoveryError, KeyError, TypeError, ValueError):
            continue
        if not ranges:
            continue
        prepared[donor_id] = (coff, record.section, bytes(record.body), normalized)
        donors.append(
            MosaicDonorCandidate(
                None,
                normalized,
                ranges,
                frozenset().union(*(item.coverage for item in ranges)),
                donor_id,
            )
        )
    if not mismatch:
        raise MosaicRepairError("mosaic range re-derivation would produce no instruction range")
    try:
        selected = select_mosaic_ranges(
            donors,
            frozenset(mismatch),
            max_candidates_per_symbol=_MAX_CANDIDATES,
            max_donors=max_donors,
            max_ranges=max_ranges,
            budget=MosaicSearchBudget(_MAX_SEARCH_STEPS),
            required_donor_ids=(
                frozenset({forced_primary}) if forced_primary is not None else frozenset()
            ),
        )
    except DiscoveryError as exc:
        raise MosaicRepairError(str(exc)) from exc
    if selected is None:
        raise MosaicRepairError("no bounded fresh donor mosaic covers the retail goal")
    used_ids = frozenset(mosaic_range_donor_id(item) for item in selected)
    if forced_primary is not None:
        primary_id = forced_primary
    elif action.dependencies[0] in used_ids:
        primary_id = action.dependencies[0]
    else:
        primary_id = min(used_ids)
    variants = tuple(sorted(used_ids - {primary_id}))

    selected_windows = [(item.start, item.end) for item in selected]
    range_reseats: dict[tuple[str, int, int], tuple[list[int], list[int]]] = {}
    reseat_moves: dict[int, int] = {}
    seed_rows = detailed_relocations(seed, seed_record.section)
    if saved_reseat:
        for item in selected:
            donor_id = mosaic_range_donor_id(item)
            donor_coff, donor_section, _body, _normalized = prepared[donor_id]
            donor_rows = detailed_relocations(donor_coff, donor_section)
            if len(seed_rows) != len(donor_rows):
                continue
            moved = [
                (ordinal, left, right)
                for ordinal, (left, right) in enumerate(zip(seed_rows, donor_rows, strict=True))
                if left["offset"] != right["offset"]
                and item.start <= left["offset"]
                and left["offset"] + left["width"] <= item.end
                and item.start <= right["offset"]
                and right["offset"] + right["width"] <= item.end
            ]
            if not moved:
                continue
            seed_contained = [
                row["offset"]
                for row in seed_rows
                if item.start <= row["offset"] and row["offset"] + row["width"] <= item.end
            ]
            donor_contained = [
                row["offset"]
                for row in donor_rows
                if item.start <= row["offset"] and row["offset"] + row["width"] <= item.end
            ]
            range_reseats[(donor_id, item.start, item.end)] = (
                seed_contained,
                donor_contained,
            )
            for ordinal, _left, right in moved:
                reseat_moves[ordinal] = cast(int, right["offset"])

    reseat_windows = [(start, end) for _donor_id, start, end in range_reseats]
    try:
        for donor_id in sorted(used_ids):
            donor_coff, donor_section, _body, _normalized = prepared[donor_id]
            require_instruction_mosaic_semantic_relocations(
                seed,
                seed_record.section,
                donor_coff,
                donor_section,
                f"mosaic repair donor {donor_id}",
                permuted_ranges=selected_windows if permuted_relocations else None,
                reseat_windows=reseat_windows if reseat_windows else None,
            )
    except ByteIdentityError as exc:
        raise MosaicRepairError(f"fresh mosaic relocations are incompatible: {exc}") from exc

    range_values: list[JsonValue] = []
    composed = bytearray(seed_body)
    for item in selected:
        donor_id = mosaic_range_donor_id(item)
        donor_body = prepared[donor_id][2]
        composed[item.start : item.end] = donor_body[item.start : item.end]
        range_value: dict[str, JsonValue] = {
            "donor": donor_id,
            "donor_instruction_lengths": list(item.donor_lengths),
            "donor_sha256": sha256(donor_body[item.start : item.end]).hexdigest(),
            "end": item.end,
            "kind": "same_offset_complete_x86_instruction_sequence_v1",
            "seed_instruction_lengths": list(item.seed_lengths),
            "seed_sha256": sha256(seed_body[item.start : item.end]).hexdigest(),
            "start": item.start,
        }
        reseat = range_reseats.get((donor_id, item.start, item.end))
        if reseat is not None:
            range_value.update(
                {
                    "donor_relocation_offsets": cast(JsonValue, reseat[1]),
                    "relocation_reseat": True,
                    "seed_relocation_offsets": cast(JsonValue, reseat[0]),
                }
            )
        range_values.append(range_value)
    if self_permutation:
        permutation = cast(dict[str, Any], parameters["instruction_self_permutation"])
        primary_body = prepared[primary_id][2]
        for move in cast(list[dict[str, Any]], permutation["moves"]):
            composed[move["target_start"] : move["target_end"]] = primary_body[
                move["donor_start"] : move["donor_end"]
            ]
    if bytes(composed) != retail_body:
        raise MosaicRepairError("bounded mosaic selection does not reproduce the retail goal")

    fresh_parameters = {
        name: value for name, value in parameters.items() if name in _PRESERVED_PARAMETERS
    }
    fresh_parameters["instruction_ranges"] = range_values
    if variants:
        fresh_parameters["donor_variants"] = [{"donor": donor_id} for donor_id in variants]
    primary_action = donor_interventions[primary_id]
    if same_function:
        fresh_parameters["same_function_source_identity"] = _refreshed_same_function_identity(
            fresh_parameters["same_function_source_identity"],
            primary_action,
            materials.seed_source,
            donor_sources.get(primary_id),
        )

    primary_coff, primary_section, primary_body, _normalized = prepared[primary_id]
    try:
        relocation_output, relocation_output_section = (
            _composed_reseated_seed(
                seed,
                seed_record.section,
                reseat_moves,
                bytes(composed),
                symbol,
            )
            if reseat_moves
            else (seed, seed_record.section)
        )
        observations = measure_mosaic_seat_observations(seed, primary_coff, symbol)
        expected: dict[str, JsonValue] = {
            key: cast(JsonValue, observations[key]) for key in _SEAT_RECEIPT_KEYS
        }
        address, oracle_length, oracle_declaration = _retail_oracle(receipt)
        if oracle_length != len(retail_body):
            raise MosaicRepairError("mosaic retail oracle length differs from its body goal")
        expected.update(
            {
                "expected_body_sha256": sha256(retail_body).hexdigest(),
                "expected_donor_body_length": len(primary_body),
                "retail_oracle": oracle_declaration,
                "retail_relocations": _fresh_retail_relocations(
                    receipt,
                    relocation_output,
                    relocation_output_section,
                    address,
                ),
            }
        )
        if range_reseats:
            expected["expected_output_relocation_sha256"] = sha256(
                _coff_table_bytes(
                    relocation_output,
                    relocation_output_section,
                    "relocations",
                )
            ).hexdigest()
            if ordinary_fpo:
                expected["expected_output_metadata_sha256"] = instruction_mosaic_metadata_sha256(
                    relocation_output,
                    relocation_output_section,
                )
        if variants:
            combined = bytearray(primary_body)
            for item in selected:
                donor_id = mosaic_range_donor_id(item)
                combined[item.start : item.end] = prepared[donor_id][2][item.start : item.end]
            expected["expected_mosaic_donor_body_sha256"] = sha256(combined).hexdigest()
            for variant_index, donor_id in enumerate(variants):
                variant_coff, variant_section, variant_body, _ = prepared[donor_id]
                prefix = f"donor_variants[{variant_index}]"
                expected[f"{prefix}.expected_body_length"] = len(variant_body)
                expected[f"{prefix}.expected_body_sha256"] = sha256(variant_body).hexdigest()
                expected[f"{prefix}.expected_line_count"] = variant_section["line_count"]
                expected[f"{prefix}.expected_metadata_sha256"] = instruction_mosaic_metadata_sha256(
                    variant_coff, variant_section
                )
    except MosaicRepairError:
        raise
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise MosaicRepairError(f"cannot measure the fresh mosaic authority: {exc}") from exc
    for key, source_refactor_fpo in (
        ("ordinary_fpo_identity", False),
        ("source_fpo_identity", True),
    ):
        if key not in fresh_parameters:
            continue
        try:
            measured_identity, pins = measure_fpo_mosaic_identity(
                seed,
                seed_record.section,
                primary_coff,
                primary_section,
                receipt_prefix=key,
                source_refactor=source_refactor_fpo,
            )
        except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
            raise MosaicRepairError(f"fresh {key} cannot be measured: {exc}") from exc
        saved_identity = fresh_parameters[key]
        if not isinstance(saved_identity, dict) or saved_identity.get(
            "kind"
        ) != measured_identity.get("kind"):
            raise MosaicRepairError(f"fresh {key} changes the saved identity class")
        fresh_parameters[key] = cast(JsonValue, measured_identity)
        expected.update(cast(dict[str, JsonValue], pins))
    if self_permutation:
        expected.update(_self_permutation_pins(seed, seed_body, retail_body))

    parameter_fields = tuple(
        ClassicField(name=name, value=value) for name, value in sorted(fresh_parameters.items())
    )
    temporary = action.model_copy(
        update={
            "dependencies": (primary_id,),
            "parameters": parameter_fields,
            "rationale": _RATIONALE,
        }
    )
    temporary_receipt = receipt.model_copy(
        update={"expected_values": dict(sorted(expected.items())), "redactions": ()}
    )
    dispatch_materials = replace(
        materials,
        donor_object=donor_objects[primary_id],
        target_donor_object=donor_objects[primary_id],
        donor_source=donor_sources.get(primary_id),
        target_donor_source=donor_sources.get(primary_id),
        additional_donor_objects={donor_id: donor_objects[donor_id] for donor_id in variants},
        shape_identifiers=donor_shape_identifiers.get(primary_id, frozenset()),
        candidate_constraints=None,
    )
    try:
        first = repair_measured_pins(temporary, temporary_receipt, dispatch_materials)
    except (MeasuredPinRepairError, ClassicProjectError, DonorSourceError) as exc:
        raise MosaicRepairError(
            f"ordinary mosaic validation refused the replacement: {exc}"
        ) from exc

    final_values = dict(first.receipt.expected_values)
    intervention_id = _stable_id(
        "function",
        {
            "build_target": action.build_target,
            "dependency": primary_id,
            "expected_values": final_values,
            "family": action.family.value,
            "parameters": [item.model_dump(mode="json") for item in parameter_fields],
            "scope": action.scope.model_dump(mode="json"),
        },
    )
    final_action = temporary.model_copy(update={"id": intervention_id})
    receipt_id = _stable_id(
        "proof",
        {
            "family": action.family.value,
            "intervention_id": intervention_id,
            "expected_values": final_values,
        },
    )
    final_receipt = first.receipt.model_copy(
        update={
            "id": receipt_id,
            "intervention_id": intervention_id,
            "expected_values": dict(sorted(final_values.items())),
            "redactions": (),
            "status": None,
            "authenticity": None,
        }
    )
    try:
        measured = repair_measured_pins(final_action, final_receipt, dispatch_materials)
    except MeasuredPinRepairError as exc:
        raise MosaicRepairError(
            f"ordinary mosaic validation refused final authority: {exc}"
        ) from exc
    return MosaicReauthoring(final_action, measured.receipt, measured, used_ids)


__all__ = [
    "MosaicReauthoring",
    "MosaicRepairError",
    "capture_instruction_mosaic_retail_body",
    "instruction_mosaic_semantics_required",
    "reauthor_instruction_mosaic",
]
