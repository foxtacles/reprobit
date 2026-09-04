"""Repair-only reconciliation of sealed retail bytes with fresh COFF relocations."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, cast

from reprobit.binary import ByteIdentityError, require
from reprobit.classic.foundation import declared_symbol_kind
from reprobit.coff_format import RELOCATION_WIDTHS, CoffObject, detailed_relocations
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.oracle_pe32 import LegacyInstallError, PE32VirtualAddressReader
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
)
from reprobit.strict_json import JsonValue

_MAX_RETAIL_BODY_BYTES = 64 * 1024

_RETAIL_RELOCATION_FIELDS = frozenset(
    {
        "addend",
        "offset",
        "retail_target",
        "target",
        "target_section",
        "target_storage",
        "target_type",
        "target_value",
        "type",
    }
)


class RetailRepairError(RuntimeError):
    """A sealed retail span cannot be used as finite repair evidence."""


def _retail_goal_key(family: ClassicRecipeFamily) -> str:
    if family is ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE:
        return "expected_normalized_body_sha256"
    return "expected_body_sha256"


def retail_body_goal_digest(
    action: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> str:
    """Return the immutable relocatable-body goal for one matching function record."""

    if (
        action.role is not ClassicRecipeRole.FUNCTION
        or receipt.intervention_id != action.id
        or receipt.family is not action.family
    ):
        raise RetailRepairError("retail body capture requires one matching function record")
    value = receipt.expected_values.get(_retail_goal_key(action.family))
    if not isinstance(value, str) or len(value) != 64:
        raise RetailRepairError("record has no immutable retail body goal")
    return value


def retail_oracle_span(
    receipt: ClassicProofReceipt,
) -> tuple[int, int, dict[str, JsonValue]]:
    """Return one well-formed finite retail MATCH span from a saved receipt."""

    value = receipt.expected_values.get("retail_oracle")
    if (
        not isinstance(value, dict)
        or set(value) != {"address", "image", "length", "verdict"}
        or value.get("verdict") != "MATCH"
        or not isinstance(value.get("image"), str)
        or not value["image"]
    ):
        raise RetailRepairError("receipt has no finite retail MATCH oracle")
    address_value = value.get("address")
    length = value.get("length")
    if not isinstance(address_value, str) or type(length) is not int:
        raise RetailRepairError("retail oracle range is malformed")
    try:
        address = int(address_value, 16)
    except ValueError as exc:
        raise RetailRepairError("retail oracle address is malformed") from exc
    if address < 0 or not 1 <= length <= _MAX_RETAIL_BODY_BYTES:
        raise RetailRepairError("retail oracle range is outside repair bounds")
    return address, length, deepcopy(value)


def authenticated_retail_body_available(
    action: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> bool:
    """Return whether repair may capture this record's finite retail body."""

    if not isinstance(receipt.expected_values.get("retail_relocations"), list):
        return False
    try:
        retail_body_goal_digest(action, receipt)
        retail_oracle_span(receipt)
    except RetailRepairError:
        return False
    return True


def capture_authenticated_retail_body(
    action: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    oracle: PE32VirtualAddressReader,
) -> bytes:
    """Capture only finite retail bytes that reproduce a saved immutable goal.

    Linked operands are restored to their declared COFF addends before the
    digest check.  The reader itself never crosses this repair-only boundary.
    """

    if not authenticated_retail_body_available(action, receipt):
        raise RetailRepairError("record has no authenticated finite retail body")
    address, length, _declaration = retail_oracle_span(receipt)
    try:
        raw_body = oracle.read_virtual_address(address, length)
    except LegacyInstallError as exc:
        raise RetailRepairError(f"cannot read the sealed retail oracle: {exc}") from exc
    try:
        restored = restore_retail_relocation_addends(
            raw_body,
            receipt.expected_values.get("retail_relocations"),
            "retail relocation declaration",
        )
    except (ByteIdentityError, ValueError) as exc:
        raise RetailRepairError(str(exc)) from exc
    goal = retail_body_goal_digest(action, receipt)
    if sha256(restored).hexdigest() != goal:
        raise RetailRepairError("sealed retail body does not reproduce its immutable body goal")
    return restored


def _declared_relocations(value: object, context: str) -> list[dict[str, JsonValue]]:
    require(isinstance(value, list), f"{context} is not an array")
    result: list[dict[str, JsonValue]] = []
    previous_end = 0
    for index, raw in enumerate(cast(list[object], value)):
        require(
            isinstance(raw, dict) and set(raw) == _RETAIL_RELOCATION_FIELDS,
            f"{context} relocation {index} has an unknown shape",
        )
        item = cast(dict[str, JsonValue], raw)
        require(
            all(
                type(item[field]) is int
                for field in (
                    "addend",
                    "offset",
                    "target_section",
                    "target_storage",
                    "target_type",
                    "target_value",
                    "type",
                )
            )
            and isinstance(item["retail_target"], str)
            and isinstance(item["target"], str),
            f"{context} relocation {index} is malformed",
        )
        relocation_type = cast(int, item["type"])
        width = RELOCATION_WIDTHS.get(relocation_type)
        offset = cast(int, item["offset"])
        require(width is not None, f"{context} relocation {index} has an unknown type")
        assert width is not None
        require(
            offset >= previous_end,
            f"{context} relocations are unsorted or overlapping",
        )
        previous_end = offset + width
        try:
            target = int(cast(str, item["retail_target"]), 16)
        except ValueError as exc:
            raise ValueError(f"{context} relocation {index} has an invalid retail target") from exc
        require(
            0 <= target <= 0xFFFFFFFF,
            f"{context} relocation {index} has an invalid retail target",
        )
        result.append(dict(item))
    return result


def restore_retail_relocation_addends(
    retail_body: bytes,
    declaration: object,
    context: str,
) -> bytes:
    """Return sealed retail bytes in their declared relocatable COFF form."""

    require(type(retail_body) is bytes, f"{context} body is not immutable bytes")
    restored = bytearray(retail_body)
    for index, item in enumerate(_declared_relocations(declaration, context)):
        relocation_type = cast(int, item["type"])
        width = RELOCATION_WIDTHS[relocation_type]
        offset = cast(int, item["offset"])
        end = offset + width
        require(end <= len(restored), f"{context} relocation {index} leaves the body")
        mask = (1 << (width * 8)) - 1
        restored[offset:end] = (cast(int, item["addend"]) & mask).to_bytes(width, "little")
    return bytes(restored)


def refresh_retail_relocations(
    declaration: object,
    coff: CoffObject,
    primary: dict[str, Any],
    retail_address: int,
    context: str,
) -> list[JsonValue]:
    """Carry saved retail targets onto compatible fresh COFF relocation rows."""

    require(
        type(retail_address) is int and 0 <= retail_address <= 0xFFFFFFFF,
        f"{context} retail address is invalid",
    )
    declared = _declared_relocations(declaration, context)
    fresh = detailed_relocations(coff, primary)
    require(
        len(fresh) == len(declared),
        f"{context} fresh relocation count differs",
    )
    by_offset = {cast(int, item["offset"]): item for item in declared}
    by_target: dict[str, str] = {}
    ambiguous_targets: set[str] = set()
    for item in declared:
        target = cast(str, item["target"])
        retail_target = cast(str, item["retail_target"])
        if target in ambiguous_targets:
            continue
        previous = by_target.setdefault(target, retail_target)
        if previous != retail_target:
            by_target.pop(target, None)
            ambiguous_targets.add(target)

    result: list[JsonValue] = []
    for row in fresh:
        target = cast(str, row["target"])
        if row["target_section"] == primary["number"]:
            retail_target = f"0x{retail_address + cast(int, row['target_value']):08x}"
        else:
            at_offset = by_offset.get(cast(int, row["offset"]))
            same_local = (
                at_offset is not None
                and declared_symbol_kind(target) is not None
                and declared_symbol_kind(target)
                == declared_symbol_kind(cast(str, at_offset.get("target")))
            )
            if at_offset is not None and (at_offset.get("target") == target or same_local):
                retail_target = cast(str, at_offset["retail_target"])
            elif target in by_target:
                retail_target = by_target[target]
            else:
                require(
                    False,
                    f"{context} fresh relocation at {row['offset']} has no retail target",
                )
        result.append(
            {
                field: cast(JsonValue, retail_target if field == "retail_target" else row[field])
                for field in sorted(_RETAIL_RELOCATION_FIELDS)
            }
        )
    return result


__all__ = [
    "RetailRepairError",
    "authenticated_retail_body_available",
    "capture_authenticated_retail_body",
    "refresh_retail_relocations",
    "restore_retail_relocation_addends",
    "retail_body_goal_digest",
    "retail_oracle_span",
]
