"""Classic compiler algorithms: composed and donor rewriting certificate validators."""

from __future__ import annotations

from typing import Any, cast

from reprobit.binary import require

from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_sha,
)
from .register_semantics import (
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
)
from .relational import (
    IA32_RELATIONAL_MIRROR,
)
from .scheduling_certificates import _validate_schedule_windows

COMPOSED_REWRITING_KIND = "schedule_bijection_relational_v1"


def _validate_commutative_operand_forms(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any]]:
    """Validate the `commutative_operand_forms` list of a seam declaration.

    Shape only -- K1..K8 are discharged by `apply_commutative_operand_form`
    on the measured body.  Returns (normalized_sites, rewritten_bytes)."""
    normalized_forms = []
    form_bytes = []
    previous_offset = -1
    for index, item in enumerate(value.get("commutative_operand_forms") or []):
        item_context = f"{context}.commutative_operand_forms[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"pair_offset", "operation", "expected_rewritten_offsets"}, item_context
        )
        at = require_exact_int(
            item.get("pair_offset"),
            f"{item_context}.pair_offset",
            minimum=0,
            maximum=body_length - 4,
        )
        require(at > previous_offset, f"{item_context}: sites are unsorted")
        previous_offset = at
        require(
            item.get("operation") in ("fadd", "fmul"),
            f"{item_context}.operation is not a commutative x87 binary operation",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(
                type(offset) is int and at <= offset < min(at + 12, body_length)
                for offset in offsets
            ),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        form_bytes.extend(offsets)
        normalized_forms.append(
            {
                "pair_offset": at,
                "operation": item["operation"],
                "expected_rewritten_offsets": list(offsets),
            }
        )
    require(
        len(set(form_bytes)) == len(form_bytes),
        f"{context}: two commutative forms rewrite the same byte",
    )
    return (normalized_forms, form_bytes)


def _validate_esp_argument_exchanges(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any]]:
    """Validate the `esp_argument_exchanges` list of a seam declaration.

    Shape only -- E1..E8 are discharged by `apply_esp_argument_exchange`
    on the measured body, and E8's pairing with a declared register
    bijection is checked where the seam applies the certificates.
    Returns (normalized_items, rewritten_bytes)."""
    normalized_items = []
    exchange_bytes = []
    previous_offset = -1
    for index, item in enumerate(value.get("esp_argument_exchanges") or []):
        item_context = f"{context}.esp_argument_exchanges[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"first_offset", "second_offset", "expected_rewritten_offsets"}, item_context
        )
        first = require_exact_int(
            item.get("first_offset"),
            f"{item_context}.first_offset",
            minimum=0,
            maximum=body_length - 4,
        )
        second = require_exact_int(
            item.get("second_offset"),
            f"{item_context}.second_offset",
            minimum=0,
            maximum=body_length - 4,
        )
        require(first > previous_offset and first < second, f"{item_context}: sites are unsorted")
        previous_offset = second
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and len(offsets) >= 2
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and 0 <= offset < body_length for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        exchange_bytes.extend(offsets)
        normalized_items.append(
            {
                "first_offset": first,
                "second_offset": second,
                "expected_rewritten_offsets": list(offsets),
            }
        )
    require(
        len(set(exchange_bytes)) == len(exchange_bytes),
        f"{context}: two argument exchanges rewrite the same byte",
    )
    return (normalized_items, exchange_bytes)


def _validate_rewriting_scope(
    value: dict[str, Any], context: str, body_length: int, kind: str
) -> tuple[int | None, list[Any] | None, list[Any]]:
    """Validate the kind, the optional code-length and internal-target pins and
    the reordering windows a seam declaration opens with.

    Returns (code_length, internal_relocation_targets, normalized_windows); the
    first two stay ``None`` when the declaration omits them."""
    require(value.get("kind") == kind, f"{context}.kind differs")
    code_length = value.get("expected_code_length")
    if code_length is not None:
        code_length = require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=2, maximum=body_length
        )
    targets = value.get("expected_internal_relocation_targets")
    if targets is not None:
        require(
            isinstance(targets, list)
            and targets == sorted(set(targets))
            and all(type(item) is int and 0 <= item < body_length for item in targets),
            f"{context}.expected_internal_relocation_targets is invalid",
        )
    normalized_windows = []
    if value.get("windows") is not None:
        windows = value["windows"]
        require(
            isinstance(windows, list) and 1 <= len(windows) <= 32,
            f"{context}.windows must contain 1..32 windows",
        )
        normalized_windows = _validate_schedule_windows(
            windows, context, body_length, code_length, targets
        )
        require(
            not any(window.get("relocation_reseat") for window in normalized_windows),
            f"{context}: this class refuses to move a relocation",
        )
    return (code_length, targets, normalized_windows)


def _validate_fp_sum_rotations(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any], set[int]]:
    """Validate the `fp_sum_rotations` list of a seam declaration.

    Shape only -- F1..F3 are discharged by `apply_fp_sum_reassociation` on the
    measured body.  Returns (normalized_rotations, rewritten_bytes, chain_bytes)
    where chain_bytes is every offset inside a declared chain."""
    normalized_rotations = []
    rotation_bytes = []
    rotation_regions: set[int] = set()
    previous_chain_end = 0
    for index, item in enumerate(value.get("fp_sum_rotations") or []):
        item_context = f"{context}.fp_sum_rotations[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"chain_start", "chain_end", "order", "expected_rewritten_offsets"}, item_context
        )
        start = require_exact_int(
            item.get("chain_start"),
            f"{item_context}.chain_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("chain_end"), f"{item_context}.chain_end", minimum=2, maximum=body_length
        )
        require(
            previous_chain_end <= start < end, f"{item_context}: chains are unsorted or overlapping"
        )
        previous_chain_end = end
        order = item.get("order")
        require(
            isinstance(order, list)
            and len(order) >= 2
            and (sorted(order) == list(range(len(order))))
            and (order != list(range(len(order)))),
            f"{item_context}.order is not a non-identity permutation",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        rotation_bytes.extend(offsets)
        rotation_regions.update(range(start, end))
        normalized_rotations.append(
            {
                "chain_start": start,
                "chain_end": end,
                "order": list(order),
                "expected_rewritten_offsets": list(offsets),
            }
        )
    return (normalized_rotations, rotation_bytes, rotation_regions)


def _validate_x87_squared_addend_exchanges(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any], set[int]]:
    """Validate the `x87_squared_addend_exchanges` list of a seam declaration.

    Shape only -- the exchange obligations are discharged by
    `apply_x87_squared_addend_exchange` on the measured body.  Returns
    (normalized_exchanges, rewritten_bytes, chain_bytes) where chain_bytes is
    every offset inside a declared chain."""
    normalized_x87 = []
    x87_bytes = []
    x87_regions: set[int] = set()
    previous_x87_end = 0
    for index, item in enumerate(value.get("x87_squared_addend_exchanges") or []):
        item_context = f"{context}.x87_squared_addend_exchanges[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "chain_start",
                "chain_end",
                "order",
                "expected_rewritten_offsets",
                "relocation_reseat",
            },
            item_context,
            optional={"relocation_reseat"},
        )
        start = require_exact_int(
            item.get("chain_start"),
            f"{item_context}.chain_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("chain_end"), f"{item_context}.chain_end", minimum=2, maximum=body_length
        )
        require(
            previous_x87_end <= start < end, f"{item_context}: chains are unsorted or overlapping"
        )
        previous_x87_end = end
        order = item.get("order")
        require(
            isinstance(order, list)
            and len(order) >= 2
            and (sorted(order) == list(range(len(order))))
            and (order != list(range(len(order)))),
            f"{item_context}.order is not a non-identity permutation",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        normalized_item = {
            "chain_start": start,
            "chain_end": end,
            "order": list(order),
            "expected_rewritten_offsets": list(offsets),
        }
        reseat = item.get("relocation_reseat")
        if reseat is not None:
            require(
                isinstance(reseat, list)
                and bool(reseat)
                and all(
                    isinstance(pair, list)
                    and len(pair) == 2
                    and all(type(offset) is int and start <= offset < end for offset in pair)
                    for pair in reseat
                )
                and (len({pair[0] for pair in reseat}) == len(reseat))
                and (len({pair[1] for pair in reseat}) == len(reseat)),
                f"{item_context}.relocation_reseat is invalid",
            )
            normalized_item["relocation_reseat"] = [list(pair) for pair in reseat]
        x87_bytes.extend(offsets)
        x87_regions.update(range(start, end))
        normalized_x87.append(normalized_item)
    return (normalized_x87, x87_bytes, x87_regions)


def _validate_simulated_region_rewrites(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any], set[int]]:
    """Validate the `simulated_region_rewrites` list of a seam declaration.

    Shape only -- the simulation obligations are discharged by
    `apply_simulated_region_rewrite` on the measured body.  Returns
    (normalized_rewrites, rewritten_bytes, region_bytes) where region_bytes
    is every offset inside a declared region."""
    normalized_rewrites = []
    rewrite_bytes = []
    rewrite_regions: set[int] = set()
    previous_rewrite_end = 0
    for index, item in enumerate(value.get("simulated_region_rewrites") or []):
        item_context = f"{context}.simulated_region_rewrites[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "region_start",
                "region_end",
                "target_order",
                "field_rewrites",
                "dead_registers",
                "dead_slots",
                "relocation_reseat",
                "expected_rewritten_offsets",
            },
            item_context,
            optional={"field_rewrites", "dead_registers", "dead_slots", "relocation_reseat"},
        )
        start = require_exact_int(
            item.get("region_start"),
            f"{item_context}.region_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("region_end"), f"{item_context}.region_end", minimum=2, maximum=body_length
        )
        require(
            previous_rewrite_end <= start < end,
            f"{item_context}: regions are unsorted or overlapping",
        )
        previous_rewrite_end = end
        order = item.get("target_order")
        require(
            isinstance(order, list)
            and len(order) >= 2
            and (sorted(order) == list(range(len(order)))),
            f"{item_context}.target_order is not a permutation",
        )
        for rewrite in item.get("field_rewrites") or []:
            require(
                isinstance(rewrite, list)
                and len(rewrite) == 3
                and (type(rewrite[0]) is int)
                and (type(rewrite[1]) is int)
                and (rewrite[2] in _IA32_REGISTER_NUMBERS)
                and (rewrite[2] not in ("esp", "ebp")),
                f"{item_context}: field rewrite {rewrite} is invalid",
            )
        dead = item.get("dead_registers") or []
        require(
            isinstance(dead, list)
            and dead == sorted(set(dead))
            and all(name in _IA32_REGISTER_NUMBERS for name in dead)
            and (not set(dead) & _IA32_STRUCTURAL_REGISTERS),
            f"{item_context}.dead_registers is invalid",
        )
        slots_dead = item.get("dead_slots") or []
        require(
            isinstance(slots_dead, list)
            and slots_dead == sorted(set(slots_dead))
            and all(type(d) is int and -body_length < d < 0 for d in slots_dead),
            f"{item_context}.dead_slots is invalid",
        )
        reseat = item.get("relocation_reseat") or []
        require(
            isinstance(reseat, list)
            and all(
                isinstance(pair, list)
                and len(pair) == 2
                and all(type(x) is int and start <= x < end for x in pair)
                for pair in reseat
            ),
            f"{item_context}.relocation_reseat is invalid",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        rewrite_bytes.extend(offsets)
        rewrite_regions.update(range(start, end))
        normalized_rewrites.append(
            {
                "region_start": start,
                "region_end": end,
                "target_order": list(order),
                "field_rewrites": [list(r) for r in item.get("field_rewrites") or []],
                "dead_registers": list(dead),
                "dead_slots": list(slots_dead),
                "relocation_reseat": [list(p) for p in reseat],
                "expected_rewritten_offsets": list(offsets),
            }
        )
    return (normalized_rewrites, rewrite_bytes, rewrite_regions)


def _validate_register_bijections(
    value: dict[str, Any], context: str, body_length: int, *, composed: bool
) -> tuple[list[Any], list[Any]]:
    """Validate the `register_bijections` list of a seam declaration.

    Shape only -- the bijection obligations are discharged by
    `apply_register_bijection` on the measured body.  The composed seam
    (``composed=True``) requires sorted, disjoint regions and carries the
    `.debug$S` S_REGISTER claims each bijection makes; the donor seam lets
    regions overlap when they rename disjoint registers and makes no
    `.debug$S` claim.  Returns (normalized_bijections, rewritten_bytes)."""
    normalized_bijections: list[dict[str, Any]] = []
    bijection_bytes = []
    previous_end = 0
    for index, item in enumerate(value.get("register_bijections") or []):
        item_context = f"{context}.register_bijections[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        keys = {
            "mapping",
            "region_start",
            "region_end",
            "expected_region_instruction_count",
            "expected_rewritten_offsets",
        }
        if composed:
            keys.add("debug_s_register_map")
        exact_audit_keys(item, keys, item_context)
        mapping = item.get("mapping")
        require(
            isinstance(mapping, dict)
            and 2 <= len(mapping) <= 8
            and all(
                (
                    isinstance(key, str)
                    and isinstance(name, str)
                    and (key in _IA32_REGISTER_NUMBERS)
                    and (name in _IA32_REGISTER_NUMBERS)
                    for key, name in mapping.items()
                )
            ),
            f"{item_context}.mapping is invalid",
        )
        require(
            set(mapping) == set(mapping.values())
            and len(set(mapping.values())) == len(mapping)
            and all((key != name for key, name in mapping.items())),
            f"{item_context}.mapping is not a fixed-point-free bijection",
        )
        require(
            not set(mapping) & _IA32_STRUCTURAL_REGISTERS,
            f"{item_context}.mapping touches ESP or EBP",
        )
        start = require_exact_int(
            item.get("region_start"),
            f"{item_context}.region_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("region_end"), f"{item_context}.region_end", minimum=2, maximum=body_length - 1
        )
        if composed:
            require(
                previous_end <= start < end, f"{item_context}: regions are unsorted or overlapping"
            )
            previous_end = end
        else:
            require(start < end, f"{item_context}: the region is empty or inverted")
            for earlier in normalized_bijections:
                if start < earlier["region_end"] and earlier["region_start"] < end:
                    require(
                        not set(mapping) & set(earlier["mapping"]),
                        f"{item_context}: overlapping regions rename a common register",
                    )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        bijection_bytes.extend(offsets)
        normalized_map = []
        if composed:
            declared = item.get("debug_s_register_map")
            require(
                isinstance(declared, list) and len(declared) <= 8,
                f"{item_context}.debug_s_register_map is invalid",
            )
            for position, record in enumerate(declared):
                record_context = f"{item_context}.debug_s_register_map[{position}]"
                require(isinstance(record, dict), f"{record_context} must be an object")
                exact_audit_keys(
                    record,
                    {"name", "record_offset", "donor_register", "image_register"},
                    record_context,
                )
                require(
                    isinstance(record.get("name"), str) and record["name"],
                    f"{record_context}.name is invalid",
                )
                require(
                    record.get("donor_register") in mapping
                    and mapping[record["donor_register"]] == record.get("image_register"),
                    f"{record_context} is not the declared mapping",
                )
                normalized_map.append(
                    {
                        "name": record["name"],
                        "record_offset": require_exact_int(
                            record.get("record_offset"),
                            f"{record_context}.record_offset",
                            minimum=0,
                        ),
                        "donor_register": record["donor_register"],
                        "image_register": record["image_register"],
                    }
                )
        normalized_item = {
            "mapping": dict(sorted(mapping.items())),
            "region_start": start,
            "region_end": end,
            "expected_region_instruction_count": require_exact_int(
                item.get("expected_region_instruction_count"),
                f"{item_context}.expected_region_instruction_count",
                minimum=1,
            ),
            "expected_rewritten_offsets": list(offsets),
        }
        if composed:
            normalized_item["debug_s_register_map"] = normalized_map
        normalized_bijections.append(normalized_item)
    return (normalized_bijections, bijection_bytes)


def _validate_relational_sites(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any]]:
    """Validate the `relational_sites` list of a seam declaration.

    Shape only -- the mirror obligations are discharged by
    `apply_relational_form` on the measured body.  Returns
    (normalized_sites, rewritten_bytes)."""
    normalized_sites = []
    relational_bytes = []
    previous = -1
    for index, site in enumerate(value.get("relational_sites") or []):
        site_context = f"{context}.relational_sites[{index}]"
        require(isinstance(site, dict), f"{site_context} must be an object")
        exact_audit_keys(
            site,
            {
                "compare_offset",
                "branch_offset",
                "seed_condition",
                "image_condition",
                "expected_rewritten_offsets",
                "reencode",
            },
            site_context,
            optional={"reencode"},
        )
        compare_at = require_exact_int(
            site.get("compare_offset"),
            f"{site_context}.compare_offset",
            minimum=0,
            maximum=body_length - 2,
        )
        branch_at = require_exact_int(
            site.get("branch_offset"),
            f"{site_context}.branch_offset",
            minimum=1,
            maximum=body_length - 1,
        )
        require(compare_at > previous, f"{site_context}: sites are unsorted or overlapping")
        require(compare_at < branch_at, f"{site_context}: the branch does not follow the compare")
        previous = branch_at
        seed_condition = site.get("seed_condition")
        require(
            seed_condition in IA32_RELATIONAL_MIRROR,
            f"{site_context}.seed_condition has no mirror in the closed table",
        )
        require(
            site.get("image_condition") == IA32_RELATIONAL_MIRROR[seed_condition],
            f"{site_context}.image_condition is not the closed table's mirror",
        )
        offsets = site.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and len(offsets) == 2
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and 0 <= offset < body_length for offset in offsets),
            f"{site_context}.expected_rewritten_offsets is invalid",
        )
        relational_bytes.extend(offsets)
        normalized_site = {
            "compare_offset": compare_at,
            "branch_offset": branch_at,
            "seed_condition": seed_condition,
            "image_condition": IA32_RELATIONAL_MIRROR[seed_condition],
            "expected_rewritten_offsets": list(offsets),
        }
        if site.get("reencode"):
            require(site["reencode"] is True, f"{site_context}.reencode must be true when present")
            normalized_site["reencode"] = True
        normalized_sites.append(normalized_site)
    return (normalized_sites, relational_bytes)


def _validate_equality_load_exchanges(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[Any], list[Any]]:
    """Validate the `equality_load_exchanges` list of a seam declaration.

    Shape only -- the exchange obligations are discharged by
    `apply_equality_load_exchange` on the measured body.  Returns
    (normalized_exchanges, rewritten_bytes)."""
    normalized_exchanges = []
    exchange_bytes = []
    previous = -1
    for index, item in enumerate(value.get("equality_load_exchanges") or []):
        item_context = f"{context}.equality_load_exchanges[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {"load_offset", "compare_offset", "branch_offset", "expected_rewritten_offsets"},
            item_context,
        )
        load_at = require_exact_int(
            item.get("load_offset"),
            f"{item_context}.load_offset",
            minimum=0,
            maximum=body_length - 3,
        )
        compare_at = require_exact_int(
            item.get("compare_offset"),
            f"{item_context}.compare_offset",
            minimum=1,
            maximum=body_length - 2,
        )
        branch_at = require_exact_int(
            item.get("branch_offset"),
            f"{item_context}.branch_offset",
            minimum=2,
            maximum=body_length - 1,
        )
        require(load_at > previous, f"{item_context}: exchanges are unsorted or overlapping")
        require(
            load_at < compare_at < branch_at,
            f"{item_context}: the load, compare and branch are not in order",
        )
        previous = branch_at
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and len(offsets) in (2, 8)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and load_at < offset < branch_at for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        exchange_bytes.extend(offsets)
        normalized_exchanges.append(
            {
                "load_offset": load_at,
                "compare_offset": compare_at,
                "branch_offset": branch_at,
                "expected_rewritten_offsets": list(offsets),
            }
        )
    return (normalized_exchanges, exchange_bytes)


def _validate_slot_bijections(value: dict[str, Any], context: str, body_length: int) -> list[Any]:
    """Validate the `slot_bijections` list of a seam declaration.

    Shape only -- the slot obligations are discharged by
    `apply_slot_bijection` on the measured body.  Returns the normalized
    list; each caller derives the rewritten byte set it needs."""
    normalized_slots = []
    for index, item in enumerate(value.get("slot_bijections") or []):
        item_context = f"{context}.slot_bijections[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"mapping", "expected_rewritten_offsets", "debug_s_bprel_offsets"}, item_context
        )
        slot_mapping = item.get("mapping")
        require(
            isinstance(slot_mapping, dict)
            and 2 <= len(slot_mapping) <= 8
            and all(
                (
                    isinstance(key, str)
                    and type(slot_value) is int
                    and (slot_value < 0)
                    and (int(key) < 0)
                    for key, slot_value in slot_mapping.items()
                )
            ),
            f"{item_context}.mapping is invalid",
        )
        slot_keys = {int(key) for key in slot_mapping}
        require(
            slot_keys == set(slot_mapping.values())
            and len(set(slot_mapping.values())) == len(slot_mapping)
            and all((int(key) != slot_value for key, slot_value in slot_mapping.items())),
            f"{item_context}.mapping is not a fixed-point-free bijection",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and 0 <= offset < body_length for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        records = item.get("debug_s_bprel_offsets")
        require(
            isinstance(records, list)
            and records == sorted(set(records))
            and all(type(offset) is int and offset >= 0 for offset in records),
            f"{item_context}.debug_s_bprel_offsets is invalid",
        )
        normalized_slots.append(
            {
                "mapping": dict(sorted(slot_mapping.items())),
                "expected_rewritten_offsets": list(offsets),
                "debug_s_bprel_offsets": list(records),
            }
        )
    return normalized_slots


def _require_changed_offsets(value: dict[str, Any], context: str, body_length: int) -> list[int]:
    """Return the sorted, in-range `expected_changed_offsets` list."""
    changed = value.get("expected_changed_offsets")
    require(
        isinstance(changed, list)
        and bool(changed)
        and (changed == sorted(set(changed)))
        and all(type(offset) is int and 0 <= offset < body_length for offset in changed),
        f"{context}.expected_changed_offsets is invalid",
    )
    return cast("list[int]", changed)


def _validate_rewriting_envelope(
    value: dict[str, Any], context: str, body_length: int
) -> tuple[list[int], list[Any], list[int], str]:
    """Validate the procedure range, code-symbol references, external entries
    and authenticity rationale every seam declaration ends with.  Returns them
    in that order."""
    procedure = value.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all(type(item) is int and item >= 0 for item in procedure)
        and (procedure[0] == body_length)
        and (procedure[1] <= procedure[2] <= body_length),
        f"{context}.expected_procedure_range is invalid",
    )
    references = value.get("expected_code_symbol_references")
    require(
        isinstance(references, list)
        and all(
            isinstance(item, list)
            and len(item) == 3
            and isinstance(item[0], str)
            and isinstance(item[1], str)
            and (type(item[2]) is int)
            and (0 <= item[2] <= body_length)
            for item in references
        ),
        f"{context}.expected_code_symbol_references is invalid",
    )
    external = value.get("expected_external_entries")
    require(
        isinstance(external, list)
        and external == sorted(set(external))
        and all(type(item) is int and 0 < item < body_length for item in external),
        f"{context}.expected_external_entries is invalid",
    )
    rationale = value.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    return (
        cast("list[int]", procedure),
        cast("list[Any]", references),
        cast("list[int]", external),
        cast("str", rationale),
    )


def validate_composed_rewriting(
    value: object, context: str, body_length: int, lone_statement_ok: bool = False
) -> dict[str, Any]:
    """Validate one composed-rewriting certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    document = cast(dict[str, Any], value)
    exact_audit_keys(
        document,
        {
            "kind",
            "windows",
            "register_bijections",
            "relational_sites",
            "fp_sum_rotations",
            "simulated_region_rewrites",
            "slot_bijections",
            "commutative_operand_forms",
            "esp_argument_exchanges",
            "x87_squared_addend_exchanges",
            "equality_load_exchanges",
            "expected_instruction_count",
            "expected_changed_offsets",
            "expected_procedure_range",
            "expected_code_symbol_references",
            "expected_external_entries",
            "expected_seed_debug_s_sha256",
            "expected_image_debug_s_sha256",
            "expected_code_length",
            "expected_internal_relocation_targets",
            "authenticity_rationale",
        },
        context,
        optional={
            "windows",
            "register_bijections",
            "relational_sites",
            "fp_sum_rotations",
            "simulated_region_rewrites",
            "slot_bijections",
            "commutative_operand_forms",
            "esp_argument_exchanges",
            "x87_squared_addend_exchanges",
            "equality_load_exchanges",
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
    )
    code_length, targets, normalized_windows = _validate_rewriting_scope(
        document, context, body_length, COMPOSED_REWRITING_KIND
    )
    normalized_rotations, rotation_bytes, rotation_regions = _validate_fp_sum_rotations(
        document, context, body_length
    )
    normalized_x87, x87_bytes, x87_regions = _validate_x87_squared_addend_exchanges(
        document, context, body_length
    )
    normalized_region_rewrites = []
    region_rewrite_bytes = []
    region_rewrite_regions: set[int] = set()
    previous_region_end = 0
    for index, item in enumerate(document.get("simulated_region_rewrites") or []):
        item_context = f"{context}.simulated_region_rewrites[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "region_start",
                "region_end",
                "target_order",
                "field_rewrites",
                "dead_registers",
                "dead_slots",
                "relocation_reseat",
                "expected_rewritten_offsets",
            },
            item_context,
            optional={"field_rewrites", "dead_registers", "dead_slots", "relocation_reseat"},
        )
        start = require_exact_int(
            item.get("region_start"),
            f"{item_context}.region_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("region_end"), f"{item_context}.region_end", minimum=2, maximum=body_length
        )
        require(
            previous_region_end <= start < end,
            f"{item_context}: regions are unsorted or overlapping",
        )
        previous_region_end = end
        order = item.get("target_order")
        require(
            isinstance(order, list)
            and len(order) >= 2
            and (sorted(order) == list(range(len(order)))),
            f"{item_context}.target_order is not a permutation",
        )
        require(
            not item.get("relocation_reseat"),
            f"{item_context}: this class installs the seed's own relocation table "
            "and admits no reseat",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        region_rewrite_bytes.extend(offsets)
        region_rewrite_regions.update(range(start, end))
        normalized_region_rewrites.append(
            {
                "region_start": start,
                "region_end": end,
                "target_order": list(order),
                "field_rewrites": [list(r) for r in item.get("field_rewrites") or []],
                "dead_registers": list(item.get("dead_registers") or []),
                "dead_slots": list(item.get("dead_slots") or []),
                "expected_rewritten_offsets": list(offsets),
            }
        )
    normalized_bijections, bijection_bytes = _validate_register_bijections(
        document, context, body_length, composed=True
    )
    # The class-specific loop above refuses a reseat and keeps its own
    # normalized shape; the shared validator still runs so that the
    # field-rewrite, dead-register, dead-slot and reseat-shape obligations
    # every region rewrite carries are checked for this class as well.
    _validate_simulated_region_rewrites(document, context, body_length)
    normalized_sites, relational_bytes = _validate_relational_sites(document, context, body_length)
    normalized_equalities, equality_bytes = _validate_equality_load_exchanges(
        document, context, body_length
    )
    normalized_forms, form_bytes = _validate_commutative_operand_forms(
        document, context, body_length
    )
    normalized_exchange_items, exchange_bytes = _validate_esp_argument_exchanges(
        document, context, body_length
    )
    declared_slots = document.get("slot_bijections") or []
    require(
        bool(
            normalized_windows
            or normalized_bijections
            or normalized_sites
            or normalized_equalities
            or normalized_rotations
            or normalized_region_rewrites
            or normalized_forms
            or declared_slots
            or normalized_x87
        ),
        f"{context} declares no certificate",
    )
    require(
        bool(
            normalized_region_rewrites
            or normalized_forms
            or normalized_x87
            or lone_statement_ok
            or (
                len(normalized_windows)
                + len(normalized_bijections)
                + len(normalized_sites)
                + len(normalized_equalities)
                + len(normalized_rotations)
                + len(declared_slots)
                >= 2
            )
        ),
        f"{context} composes nothing: a single statement belongs to its own class",
    )
    window_bytes = {
        offset for window in normalized_windows for offset in range(window["start"], window["end"])
    }
    require(
        len(set(bijection_bytes)) == len(bijection_bytes),
        f"{context}: two bijections rewrite the same byte",
    )
    require(
        len(set(relational_bytes)) == len(relational_bytes),
        f"{context}: two relational sites rewrite the same byte",
    )
    require(
        not set(bijection_bytes) & set(relational_bytes),
        f"{context}: a bijection and a relational reversal rewrite the same byte",
    )
    require(
        len(set(equality_bytes)) == len(equality_bytes)
        and not set(equality_bytes) & (set(bijection_bytes) | set(relational_bytes)),
        f"{context}: an equality exchange rewrites a byte another certificate rewrites",
    )
    require(
        not window_bytes & (set(bijection_bytes) | set(relational_bytes) | set(equality_bytes)),
        f"{context}: a byte-local certificate rewrites a byte inside a reordered window",
    )
    require(
        not rotation_regions
        & (
            window_bytes
            | set(bijection_bytes)
            | set(relational_bytes)
            | set(equality_bytes)
            | set(form_bytes)
            | region_rewrite_regions
        ),
        f"{context}: an fp-sum chain overlaps another certificate's bytes",
    )
    require(
        not region_rewrite_regions
        & (
            window_bytes
            | set(bijection_bytes)
            | set(form_bytes)
            | set(relational_bytes)
            | set(equality_bytes)
        ),
        f"{context}: a simulated region rewrite overlaps another certificate's bytes",
    )
    require(
        not x87_regions
        & (
            window_bytes
            | set(bijection_bytes)
            | set(relational_bytes)
            | set(equality_bytes)
            | set(form_bytes)
            | rotation_regions
            | region_rewrite_regions
        ),
        f"{context}: an x87 exchange chain overlaps another certificate's bytes",
    )
    require(
        not set(form_bytes)
        & (window_bytes | set(bijection_bytes) | set(relational_bytes) | set(equality_bytes)),
        f"{context}: a commutative operand form overlaps another certificate's bytes",
    )
    changed = _require_changed_offsets(document, context, body_length)
    slot_bytes = {
        offset
        for item in declared_slots
        if isinstance(item, dict)
        for offset in item.get("expected_rewritten_offsets") or []
        if type(offset) is int
    }
    strict_union = (
        set(bijection_bytes)
        | set(relational_bytes)
        | set(equality_bytes)
        | set(rotation_bytes)
        | set(region_rewrite_bytes)
        | set(x87_bytes)
        | slot_bytes
    )
    if not normalized_exchange_items:
        strict_union |= set(form_bytes)
    require(
        strict_union <= set(changed), f"{context}.expected_changed_offsets omits a rewritten byte"
    )
    require(
        all(
            offset in window_bytes
            or offset in rotation_regions
            or offset in region_rewrite_regions
            or (offset in slot_bytes)
            or (offset in x87_regions)
            or (
                offset
                in set(bijection_bytes)
                | set(relational_bytes)
                | set(equality_bytes)
                | set(form_bytes)
                | set(exchange_bytes)
            )
            for offset in changed
        ),
        f"{context}.expected_changed_offsets names a byte no declared certificate can move",
    )
    procedure, references, external, rationale = _validate_rewriting_envelope(
        document, context, body_length
    )
    normalized = {
        "kind": COMPOSED_REWRITING_KIND,
        "expected_instruction_count": require_exact_int(
            document.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_changed_offsets": list(changed),
        "expected_procedure_range": list(procedure),
        "expected_code_symbol_references": [list(item) for item in references],
        "expected_external_entries": list(external),
        "expected_seed_debug_s_sha256": require_sha(
            document.get("expected_seed_debug_s_sha256"), f"{context}.expected_seed_debug_s_sha256"
        ),
        "expected_image_debug_s_sha256": require_sha(
            document.get("expected_image_debug_s_sha256"),
            f"{context}.expected_image_debug_s_sha256",
        ),
        "authenticity_rationale": rationale,
    }
    normalized_slots = _validate_slot_bijections(document, context, body_length)
    normalized["windows"] = normalized_windows
    normalized["register_bijections"] = normalized_bijections
    normalized["relational_sites"] = normalized_sites
    if normalized_equalities:
        normalized["equality_load_exchanges"] = normalized_equalities
    normalized["fp_sum_rotations"] = normalized_rotations
    normalized["simulated_region_rewrites"] = normalized_region_rewrites
    normalized["slot_bijections"] = normalized_slots
    normalized["commutative_operand_forms"] = normalized_forms
    normalized["esp_argument_exchanges"] = normalized_exchange_items
    normalized["x87_squared_addend_exchanges"] = normalized_x87
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    return normalized


DONOR_REWRITING_KIND = "donor_fp_bijection_rewriting_v1"


def validate_donor_rewriting(value: object, context: str, body_length: int) -> dict[str, Any]:
    """Validate one donor-rewriting certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    document = cast(dict[str, Any], value)
    exact_audit_keys(
        document,
        {
            "kind",
            "windows",
            "fp_sum_rotations",
            "register_bijections",
            "fp_pointer_exchanges",
            "simulated_region_rewrites",
            "relational_sites",
            "commutative_operand_forms",
            "slot_bijections",
            "x87_squared_addend_exchanges",
            "equality_load_exchanges",
            "expected_instruction_count",
            "expected_changed_offsets",
            "expected_procedure_range",
            "expected_code_symbol_references",
            "expected_external_entries",
            "expected_code_length",
            "expected_internal_relocation_targets",
            "authenticity_rationale",
        },
        context,
        optional={
            "windows",
            "fp_sum_rotations",
            "register_bijections",
            "fp_pointer_exchanges",
            "simulated_region_rewrites",
            "relational_sites",
            "commutative_operand_forms",
            "slot_bijections",
            "x87_squared_addend_exchanges",
            "equality_load_exchanges",
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
    )
    code_length, targets, normalized_windows = _validate_rewriting_scope(
        document, context, body_length, DONOR_REWRITING_KIND
    )
    normalized_rotations, rotation_bytes, rotation_regions = _validate_fp_sum_rotations(
        document, context, body_length
    )
    normalized_x87, x87_bytes, x87_regions = _validate_x87_squared_addend_exchanges(
        document, context, body_length
    )
    rotation_bytes.extend(x87_bytes)
    require(
        not x87_regions & rotation_regions,
        f"{context}: an x87 exchange chain overlaps an fp-sum chain",
    )
    rotation_regions |= x87_regions
    normalized_bijections, bijection_bytes = _validate_register_bijections(
        document, context, body_length, composed=False
    )
    normalized_exchanges = []
    exchange_bytes = []
    previous_exchange_end = 0
    for index, item in enumerate(document.get("fp_pointer_exchanges") or []):
        item_context = f"{context}.fp_pointer_exchanges[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "region_start",
                "region_end",
                "swap_offsets",
                "dead_registers",
                "expected_rewritten_offsets",
            },
            item_context,
        )
        start = require_exact_int(
            item.get("region_start"),
            f"{item_context}.region_start",
            minimum=1,
            maximum=body_length - 1,
        )
        end = require_exact_int(
            item.get("region_end"), f"{item_context}.region_end", minimum=2, maximum=body_length
        )
        require(
            previous_exchange_end <= start < end,
            f"{item_context}: exchanges are unsorted or overlapping",
        )
        previous_exchange_end = end
        swap = item.get("swap_offsets")
        require(
            isinstance(swap, list)
            and len(swap) == 2
            and all(type(offset) is int for offset in swap)
            and (start <= swap[0] < swap[1] < end),
            f"{item_context}.swap_offsets is invalid",
        )
        dead = item.get("dead_registers")
        require(
            isinstance(dead, list)
            and dead == sorted(set(dead))
            and all(name in _IA32_REGISTER_NUMBERS for name in dead)
            and (not set(dead) & _IA32_STRUCTURAL_REGISTERS),
            f"{item_context}.dead_registers is invalid",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and all(type(offset) is int and start <= offset < end for offset in offsets),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        exchange_bytes.extend(offsets)
        normalized_exchanges.append(
            {
                "region_start": start,
                "region_end": end,
                "swap_offsets": list(swap),
                "dead_registers": list(dead),
                "expected_rewritten_offsets": list(offsets),
            }
        )
    normalized_rewrites, rewrite_bytes, rewrite_regions = _validate_simulated_region_rewrites(
        document, context, body_length
    )
    normalized_sites, relational_bytes = _validate_relational_sites(document, context, body_length)
    normalized_equalities, equality_bytes = _validate_equality_load_exchanges(
        document, context, body_length
    )
    normalized_slots = _validate_slot_bijections(document, context, body_length)
    normalized_forms, form_bytes = _validate_commutative_operand_forms(
        document, context, body_length
    )
    require(
        bool(
            normalized_windows
            or normalized_rotations
            or normalized_bijections
            or normalized_exchanges
            or normalized_rewrites
            or normalized_sites
            or normalized_equalities
            or normalized_forms
            or normalized_slots
            or normalized_x87
        ),
        f"{context} declares no certificate",
    )
    window_bytes = {
        offset for window in normalized_windows for offset in range(window["start"], window["end"])
    }
    require(
        len(set(bijection_bytes)) == len(bijection_bytes),
        f"{context}: two bijections rewrite the same byte",
    )
    require(
        len(set(relational_bytes)) == len(relational_bytes),
        f"{context}: two relational sites rewrite the same byte",
    )
    require(
        len({*bijection_bytes} & {*exchange_bytes}) == 0
        and len({*bijection_bytes} & {*relational_bytes}) == 0
        and (len({*bijection_bytes} & {*form_bytes}) == 0)
        and (len({*exchange_bytes} & {*relational_bytes}) == 0)
        and (len({*exchange_bytes} & {*form_bytes}) == 0)
        and (len({*relational_bytes} & {*form_bytes}) == 0)
        and (
            len(
                {*equality_bytes}
                & ({*bijection_bytes} | {*exchange_bytes} | {*relational_bytes} | {*form_bytes})
            )
            == 0
        ),
        f"{context}: two certificates rewrite the same byte",
    )
    require(
        len(set(equality_bytes)) == len(equality_bytes),
        f"{context}: two equality exchanges rewrite the same byte",
    )
    require(
        not rotation_regions
        & (
            set(bijection_bytes)
            | set(exchange_bytes)
            | set(relational_bytes)
            | set(equality_bytes)
            | set(form_bytes)
            | window_bytes
            | rewrite_regions
        ),
        f"{context}: another certificate reaches inside an fp-sum chain",
    )
    require(
        not rewrite_regions
        & (
            set(exchange_bytes)
            | set(relational_bytes)
            | set(equality_bytes)
            | set(form_bytes)
            | window_bytes
        ),
        f"{context}: another certificate reaches inside a simulated region rewrite",
    )
    require(
        not set(form_bytes) & window_bytes,
        f"{context}: a commutative operand form rewrites a byte inside a reordered window",
    )
    require(
        not window_bytes & set(relational_bytes),
        f"{context}: a relational reversal rewrites a byte inside a reordered window",
    )
    require(
        not window_bytes & set(equality_bytes),
        f"{context}: an equality exchange rewrites a byte inside a reordered window",
    )
    changed = _require_changed_offsets(document, context, body_length)
    identity_relational = {
        offset
        for site in normalized_sites
        if site["seed_condition"] == site["image_condition"]
        for offset in site["expected_rewritten_offsets"]
    }
    slot_bytes = {
        offset for item in normalized_slots for offset in item["expected_rewritten_offsets"]
    }
    require(
        set(rotation_bytes)
        | set(bijection_bytes)
        | set(exchange_bytes)
        | set(rewrite_bytes)
        | set(form_bytes)
        | slot_bytes
        | set(equality_bytes)
        | set(relational_bytes) - identity_relational
        <= set(changed),
        f"{context}.expected_changed_offsets omits a rewritten byte",
    )
    require(
        all(
            offset in rotation_regions
            or offset in window_bytes
            or offset in rewrite_regions
            or (
                offset
                in set(bijection_bytes)
                | set(exchange_bytes)
                | set(relational_bytes)
                | set(equality_bytes)
                | set(form_bytes)
                | slot_bytes
            )
            for offset in changed
        ),
        f"{context}.expected_changed_offsets names a byte no declared certificate can move",
    )
    procedure, references, external, rationale = _validate_rewriting_envelope(
        document, context, body_length
    )
    normalized = {
        "kind": DONOR_REWRITING_KIND,
        "expected_instruction_count": require_exact_int(
            document.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_changed_offsets": list(changed),
        "expected_procedure_range": list(procedure),
        "expected_code_symbol_references": [list(item) for item in references],
        "expected_external_entries": list(external),
        "authenticity_rationale": rationale,
        "windows": normalized_windows,
        "fp_sum_rotations": normalized_rotations,
        "register_bijections": normalized_bijections,
        "fp_pointer_exchanges": normalized_exchanges,
        "simulated_region_rewrites": normalized_rewrites,
        "relational_sites": normalized_sites,
        "commutative_operand_forms": normalized_forms,
        "slot_bijections": normalized_slots,
        "x87_squared_addend_exchanges": normalized_x87,
    }
    if normalized_equalities:
        normalized["equality_load_exchanges"] = normalized_equalities
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    return normalized
