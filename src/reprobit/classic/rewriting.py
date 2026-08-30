from __future__ import annotations

from reprobit.binary import ByteIdentityError, require
from reprobit.coff_format import CoffObject, coff_body, detailed_relocations, section_definitions
from reprobit.ia32_decode import supported_ia32_instruction_length

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .commutative import apply_commutative_operand_form
from .composition import (
    compose_equal_body_comdat,
    compose_same_slot_resize,
    instruction_mosaic_metadata_sha256,
)
from .compiler_identity import Msvc420CompilerIdentity
from .debug import parse_codeview_symbol_stream
from .floating import apply_fp_sum_reassociation, apply_x87_squared_addend_exchange
from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)
from .ia32 import require_declared_relocation_semantics
from .register_bijection import (
    CODEVIEW_REGISTER_RECORD_TYPE,
    REGISTER_BIJECTION_FPO_CLOSURE,
    _codeview_register_field,
    _codeview_register_name,
    apply_codeview_register_bijection,
    apply_register_bijection,
)
from .register_reencoding import apply_slot_bijection
from .register_semantics import (
    IA32_GENERAL_REGISTER_NAMES,
    _IA32_ATOMS_OF,
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
    decode_ia32_bijection_instruction,
)
from .relational import (
    IA32_RELATIONAL_MIRROR,
    apply_relational_form,
    ia32_relational_flag_liveness,
    ia32_relational_flow_walk,
    relational_form_external_entries,
)
from .scheduling import (
    INSTRUCTION_SCHEDULE_EH_CLOSURE,
    INSTRUCTION_SCHEDULE_FPO_CLOSURE,
    _validate_schedule_windows,
    apply_instruction_schedule,
    require_instruction_schedule_debug_fidelity,
)

"""Classic compiler algorithms: rewriting."""
COMPOSED_REWRITING_CLASS = "retail_exact_composed_rewriting"
COMPOSED_REWRITING_KIND = "schedule_bijection_relational_v1"


def composed_rewriting_delegate(expected_closure: object) -> str:
    """Name the installation delegate from the closure pin alone.

    The installed object is the SEED with its own body replaced, so there is
    no donor rename to express and no relocation to move: the FPO closure
    takes the strict primitive and the EH closure takes the structural-local
    one, whose rename and xdata-rename sets are then required to be empty.
    """
    if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE:
        return "equal_body_strict"
    return "equal_body_eh_structural_local"


def _validate_commutative_operand_forms(
    value: object, context: str, body_length: int
) -> tuple[list, list]:
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all(
                (
                    type(offset) is int and at <= offset < min(at + 12, body_length)
                    for offset in offsets
                )
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
    value: object, context: str, body_length: int
) -> tuple[list, list]:
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
            and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
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


def validate_composed_rewriting(
    value: object, context: str, body_length: int, lone_statement_ok: bool = False
) -> dict:
    """Validate one composed-rewriting certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
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
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
    )
    require(value.get("kind") == COMPOSED_REWRITING_KIND, f"{context}.kind differs")
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
            and all((type(item) is int and 0 <= item < body_length for item in targets)),
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
            not any((window.get("relocation_reseat") for window in normalized_windows)),
            f"{context}: this class refuses to move a relocation",
        )
    normalized_rotations = []
    rotation_bytes = []
    rotation_regions = set()
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
    normalized_x87 = []
    x87_bytes = []
    x87_regions = set()
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
                and reseat
                and all(
                    (
                        isinstance(pair, list)
                        and len(pair) == 2
                        and all((type(offset) is int and start <= offset < end for offset in pair))
                        for pair in reseat
                    )
                )
                and (len({pair[0] for pair in reseat}) == len(reseat))
                and (len({pair[1] for pair in reseat}) == len(reseat)),
                f"{item_context}.relocation_reseat is invalid",
            )
            normalized_item["relocation_reseat"] = [list(pair) for pair in reseat]
        x87_bytes.extend(offsets)
        x87_regions.update(range(start, end))
        normalized_x87.append(normalized_item)
    normalized_region_rewrites = []
    region_rewrite_bytes = []
    region_rewrite_regions = set()
    previous_region_end = 0
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
            f"{item_context}: this class installs the seed's own relocation table and admits no reseat",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
    normalized_bijections = []
    bijection_bytes = []
    previous_end = 0
    for index, item in enumerate(value.get("register_bijections") or []):
        item_context = f"{context}.register_bijections[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "mapping",
                "region_start",
                "region_end",
                "expected_region_instruction_count",
                "expected_rewritten_offsets",
                "debug_s_register_map",
            },
            item_context,
        )
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
        require(previous_end <= start < end, f"{item_context}: regions are unsorted or overlapping")
        previous_end = end
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        bijection_bytes.extend(offsets)
        declared = item.get("debug_s_register_map")
        require(
            isinstance(declared, list) and len(declared) <= 8,
            f"{item_context}.debug_s_register_map is invalid",
        )
        normalized_map = []
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
                        record.get("record_offset"), f"{record_context}.record_offset", minimum=0
                    ),
                    "donor_register": record["donor_register"],
                    "image_register": record["image_register"],
                }
            )
        normalized_bijections.append(
            {
                "mapping": dict(sorted(mapping.items())),
                "region_start": start,
                "region_end": end,
                "expected_region_instruction_count": require_exact_int(
                    item.get("expected_region_instruction_count"),
                    f"{item_context}.expected_region_instruction_count",
                    minimum=1,
                ),
                "expected_rewritten_offsets": list(offsets),
                "debug_s_register_map": normalized_map,
            }
        )
    normalized_rewrites = []
    rewrite_bytes = []
    rewrite_regions = set()
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
            and all((name in _IA32_REGISTER_NUMBERS for name in dead))
            and (not set(dead) & _IA32_STRUCTURAL_REGISTERS),
            f"{item_context}.dead_registers is invalid",
        )
        slots_dead = item.get("dead_slots") or []
        require(
            isinstance(slots_dead, list)
            and slots_dead == sorted(set(slots_dead))
            and all((type(d) is int and -body_length < d < 0 for d in slots_dead)),
            f"{item_context}.dead_slots is invalid",
        )
        reseat = item.get("relocation_reseat") or []
        require(
            isinstance(reseat, list)
            and all(
                (
                    isinstance(pair, list)
                    and len(pair) == 2
                    and all((type(x) is int and start <= x < end for x in pair))
                    for pair in reseat
                )
            ),
            f"{item_context}.relocation_reseat is invalid",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
            and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
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
    normalized_forms, form_bytes = _validate_commutative_operand_forms(value, context, body_length)
    normalized_exchange_items, exchange_bytes = _validate_esp_argument_exchanges(
        value, context, body_length
    )
    declared_slots = value.get("slot_bijections") or []
    require(
        normalized_windows
        or normalized_bijections
        or normalized_sites
        or normalized_rotations
        or normalized_region_rewrites
        or normalized_forms
        or declared_slots
        or normalized_x87,
        f"{context} declares no certificate",
    )
    require(
        normalized_region_rewrites
        or normalized_forms
        or normalized_x87
        or lone_statement_ok
        or (
            len(normalized_windows)
            + len(normalized_bijections)
            + len(normalized_sites)
            + len(normalized_rotations)
            + len(declared_slots)
            >= 2
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
        not window_bytes & (set(bijection_bytes) | set(relational_bytes)),
        f"{context}: a byte-local certificate rewrites a byte inside a reordered window",
    )
    require(
        not rotation_regions
        & (
            window_bytes
            | set(bijection_bytes)
            | set(relational_bytes)
            | set(form_bytes)
            | region_rewrite_regions
        ),
        f"{context}: an fp-sum chain overlaps another certificate's bytes",
    )
    require(
        not region_rewrite_regions
        & (window_bytes | set(bijection_bytes) | set(form_bytes) | set(relational_bytes)),
        f"{context}: a simulated region rewrite overlaps another certificate's bytes",
    )
    require(
        not x87_regions
        & (
            window_bytes
            | set(bijection_bytes)
            | set(relational_bytes)
            | set(form_bytes)
            | rotation_regions
            | region_rewrite_regions
        ),
        f"{context}: an x87 exchange chain overlaps another certificate's bytes",
    )
    require(
        not set(form_bytes) & (window_bytes | set(bijection_bytes) | set(relational_bytes)),
        f"{context}: a commutative operand form overlaps another certificate's bytes",
    )
    changed = value.get("expected_changed_offsets")
    require(
        isinstance(changed, list)
        and changed
        and (changed == sorted(set(changed)))
        and all((type(offset) is int and 0 <= offset < body_length for offset in changed)),
        f"{context}.expected_changed_offsets is invalid",
    )
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
            (
                offset in window_bytes
                or offset in rotation_regions
                or offset in region_rewrite_regions
                or (offset in slot_bytes)
                or (offset in x87_regions)
                or (
                    offset
                    in set(bijection_bytes)
                    | set(relational_bytes)
                    | set(form_bytes)
                    | set(exchange_bytes)
                )
                for offset in changed
            )
        ),
        f"{context}.expected_changed_offsets names a byte no declared certificate can move",
    )
    procedure = value.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all((type(item) is int and item >= 0 for item in procedure))
        and (procedure[0] == body_length)
        and (procedure[1] <= procedure[2] <= body_length),
        f"{context}.expected_procedure_range is invalid",
    )
    references = value.get("expected_code_symbol_references")
    require(
        isinstance(references, list)
        and all(
            (
                isinstance(item, list)
                and len(item) == 3
                and isinstance(item[0], str)
                and isinstance(item[1], str)
                and (type(item[2]) is int)
                and (0 <= item[2] <= body_length)
                for item in references
            )
        ),
        f"{context}.expected_code_symbol_references is invalid",
    )
    external = value.get("expected_external_entries")
    require(
        isinstance(external, list)
        and external == sorted(set(external))
        and all((type(item) is int and 0 < item < body_length for item in external)),
        f"{context}.expected_external_entries is invalid",
    )
    rationale = value.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    normalized = {
        "kind": COMPOSED_REWRITING_KIND,
        "expected_instruction_count": require_exact_int(
            value.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_changed_offsets": list(changed),
        "expected_procedure_range": list(procedure),
        "expected_code_symbol_references": [list(item) for item in references],
        "expected_external_entries": list(external),
        "expected_seed_debug_s_sha256": require_sha(
            value.get("expected_seed_debug_s_sha256"), f"{context}.expected_seed_debug_s_sha256"
        ),
        "expected_image_debug_s_sha256": require_sha(
            value.get("expected_image_debug_s_sha256"), f"{context}.expected_image_debug_s_sha256"
        ),
        "authenticity_rationale": rationale,
    }
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        records = item.get("debug_s_bprel_offsets")
        require(
            isinstance(records, list)
            and records == sorted(set(records))
            and all((type(offset) is int and offset >= 0 for offset in records)),
            f"{item_context}.debug_s_bprel_offsets is invalid",
        )
        normalized_slots.append(
            {
                "mapping": dict(sorted(slot_mapping.items())),
                "expected_rewritten_offsets": list(offsets),
                "debug_s_bprel_offsets": list(records),
            }
        )
    normalized["windows"] = normalized_windows
    normalized["register_bijections"] = normalized_bijections
    normalized["relational_sites"] = normalized_sites
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


def produce_composed_rewriting_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict]:
    """Apply a reordering, then regional bijections, then reversed compares.

    See the class comment above.  Each primitive is the LANDED one, called
    unchanged; C1 fixes the order, C2 the disjointness, C3 the debug$S
    claims and C4 the provenance. Literal comparison is verifier-only.
    """
    require_payload_free_declaration(function, "composed-rewriting declaration")
    require(
        function.get("splice_class") == COMPOSED_REWRITING_CLASS,
        "splice class is not retail_exact_composed_rewriting",
    )
    require(
        "target_source_refactor" not in function,
        "composed-rewriting functions carry no source refactor",
    )
    spec = function["composed_rewriting"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == function["expected_section_number"]
        and dp["number"] == function["expected_donor_section_number"],
        f"composed-rewriting target section seat changed: seed {sp['number']} donor {dp['number']}",
    )
    require(
        len(seed.sections) == function["expected_section_count"]
        and len(donor.sections) == function["expected_donor_section_count"],
        f"composed-rewriting global section count changed: seed {len(seed.sections)} donor {len(donor.sections)}",
    )
    seed_functions = function_multiset(seed)
    require(
        seed_functions == function_multiset(donor)
        and sum(seed_functions.values()) == function["expected_function_count"],
        f"composed-rewriting witness function set differs: {sum(seed_functions.values())} vs {sum(function_multiset(donor).values())}",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(
        seed_comdats == comdat_primary_identity_multiset(donor)
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        f"composed-rewriting witness COMDAT identity set differs: {sum(seed_comdats.values())} vs {sum(comdat_primary_identity_multiset(donor).values())}",
    )
    require(
        sp["raw_size"] == dp["raw_size"] == function["expected_body_length"]
        and sp["relocation_count"]
        == dp["relocation_count"]
        == function["expected_relocation_count"]
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        f"composed-rewriting target header/count pins changed: raw {sp['raw_size']}/{dp['raw_size']} relocations {sp['relocation_count']}/{dp['relocation_count']} lines {sp['line_count']}/{dp['line_count']} characteristics {sp['characteristics']}/{dp['characteristics']}",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        f"composed-rewriting COMDAT selection changed: {section_definitions(seed)[sp['number']]['selection']}",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        f"composed-rewriting target closure changed: seed {_comdat_child_closure(seed, sp)} donor {_comdat_child_closure(donor, dp)}",
    )
    require(
        list(expected_closure)
        in (INSTRUCTION_SCHEDULE_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "composed-rewriting closure pin names no installation delegate",
    )
    delegate = composed_rewriting_delegate(function["expected_closure"])
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        f"composed-rewriting metadata differs from its pin: seed {instruction_mosaic_metadata_sha256(seed, sp)} donor {instruction_mosaic_metadata_sha256(donor, dp)}",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        f"composed-rewriting seed/witness body differs from its pin: seed {sha256_bytes(seed_body)} witness {sha256_bytes(donor_body)}",
    )
    require(
        donor_body == seed_body, "composed-rewriting witness does not reproduce the seed's body"
    )
    seed_rows = detailed_relocations(seed, sp)
    relocation_offsets = frozenset(
        (row["offset"] + byte for row in seed_rows for byte in range(row["width"]))
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in seed_rows
    }
    internal_targets = frozenset(
        (row["target_value"] for row in seed_rows if row["target_section"] == sp["number"])
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "composed-rewriting in-body relocated target set changed",
        )
    code_length = spec.get("expected_code_length")
    image = seed_body
    external_entries = relational_form_external_entries(
        seed, sp, "composed-rewriting external entries"
    )
    require(
        sorted(external_entries) == spec["expected_external_entries"],
        "composed-rewriting external entry set differs from its declaration",
    )
    schedule_detail = []
    windows = spec.get("windows") or []
    if windows:
        image, schedule_proof = apply_instruction_schedule(
            image,
            windows,
            relocation_offsets,
            "composed-rewriting schedule",
            relocation_symbols,
            code_length,
            internal_targets,
            frozenset(external_entries),
            compiler_identity,
        )
        require(
            not schedule_proof["relocation_reseat"],
            "composed-rewriting refuses to move a relocation",
        )
        schedule_detail = schedule_proof["windows"]
    fp_detail = []
    if spec.get("fp_sum_rotations"):
        image, fp_proof = apply_fp_sum_reassociation(
            image,
            spec["fp_sum_rotations"],
            relocation_offsets,
            "composed-rewriting fp-sum",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, chain) in enumerate(zip(spec["fp_sum_rotations"], fp_proof["chains"])):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting fp-sum chain {index} rewrote a different byte set from its declaration",
            )
        fp_detail = fp_proof["chains"]
    x87_detail = []
    x87_relocation_moves = {}
    if spec.get("x87_squared_addend_exchanges"):
        image, x87_proof = apply_x87_squared_addend_exchange(
            image,
            spec["x87_squared_addend_exchanges"],
            relocation_offsets,
            "composed-rewriting x87 exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        seed_row_offsets = {row["offset"] for row in seed_rows}
        for index, (item, chain) in enumerate(
            zip(spec["x87_squared_addend_exchanges"], x87_proof["chains"])
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting x87 exchange {index} rewrote a different byte set from its declaration",
            )
            for old_at, new_at in chain["relocation_reseat"]:
                require(
                    old_at in seed_row_offsets,
                    f"composed-rewriting x87 exchange {index} reseats an offset that heads no seed relocation record",
                )
                require(
                    old_at not in x87_relocation_moves,
                    f"composed-rewriting x87 exchange {index} reseats a relocation twice",
                )
                x87_relocation_moves[old_at] = new_at
        x87_detail = x87_proof["chains"]
    region_rewrite_detail = []
    if spec.get("simulated_region_rewrites"):
        image, region_proof = apply_simulated_region_rewrite(
            image,
            spec["simulated_region_rewrites"],
            relocation_offsets,
            "composed-rewriting simulated rewrite",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        require(
            not region_proof["relocation_reseat"], "composed-rewriting refuses to move a relocation"
        )
        for index, (item, region) in enumerate(
            zip(spec["simulated_region_rewrites"], region_proof["regions"])
        ):
            require(
                region["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting simulated rewrite {index} rewrote a different byte set from its declaration",
            )
        region_rewrite_detail = region_proof["regions"]
    form_detail = []
    if spec.get("commutative_operand_forms"):
        image, form_proof = apply_commutative_operand_form(
            image,
            spec["commutative_operand_forms"],
            relocation_offsets,
            "composed-rewriting commutative form",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, site) in enumerate(
            zip(spec["commutative_operand_forms"], form_proof["sites"])
        ):
            require(
                site["expected_rewritten_offsets"] == item["expected_rewritten_offsets"]
                and site["pair_offset"] == item["pair_offset"]
                and (site["operation"] == item["operation"]),
                f"composed-rewriting commutative form {index} rewrote a different site from its declaration",
            )
        form_detail = form_proof["sites"]
    exchange_site_detail = []
    if spec.get("esp_argument_exchanges"):
        image, exchange_site_proof = apply_esp_argument_exchange(
            image,
            spec["esp_argument_exchanges"],
            relocation_offsets,
            "composed-rewriting argument exchange",
            relocation_symbols,
            code_length,
        )
        for index, (item, site) in enumerate(
            zip(spec["esp_argument_exchanges"], exchange_site_proof["sites"])
        ):
            require(
                site["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"composed-rewriting argument exchange {index} rewrote a different byte set from its declaration",
            )
        exchange_site_detail = exchange_site_proof["sites"]
    bijection_detail = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        image, proof = apply_register_bijection(
            image,
            item["mapping"],
            (item["region_start"], item["region_end"]),
            relocation_offsets,
            f"composed-rewriting bijection {index}",
            relocation_symbols,
            code_length,
            internal_targets,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"composed-rewriting bijection {index} rewrote a different byte set from its declaration",
        )
        require(
            proof["region_instruction_count"] == item["expected_region_instruction_count"],
            f"composed-rewriting bijection {index} region instruction count differs from its declaration",
        )
        bijection_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "region": [item["region_start"], item["region_end"]],
                "rewritten_offsets": proof["rewritten_offsets"],
                "region_instruction_count": proof["region_instruction_count"],
            }
        )
    slot_detail = []
    for index, item in enumerate(spec.get("slot_bijections") or []):
        image, proof = apply_slot_bijection(
            image,
            item["mapping"],
            relocation_offsets,
            f"composed-rewriting slot bijection {index}",
            relocation_symbols,
            code_length,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"composed-rewriting slot bijection {index} rewrote a different byte set from its declaration",
        )
        slot_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "rewritten_offsets": proof["rewritten_offsets"],
            }
        )
    relational_detail = []
    if spec.get("relational_sites"):
        sites = [
            {
                key: item[key]
                for key in (
                    "compare_offset",
                    "branch_offset",
                    "seed_condition",
                    "image_condition",
                    "reencode",
                )
                if key in item
            }
            for item in spec["relational_sites"]
        ]
        image, proof = apply_relational_form(
            image,
            sites,
            relocation_offsets,
            "composed-rewriting relational",
            relocation_symbols,
            code_length,
            external_entries,
        )
        require(
            proof["rewritten_offsets"]
            == sorted(
                (
                    offset
                    for item in spec["relational_sites"]
                    for offset in item["expected_rewritten_offsets"]
                )
            ),
            "composed-rewriting relational rewrite set differs from its declaration",
        )
        relational_detail = proof["sites"]
    require(image != seed_body, "composed-rewriting image does not move the seed body")
    image_instructions = decode_ia32_bijection_body(
        image, "composed-rewriting image", relocation_symbols, code_length
    )
    require(
        len(image_instructions) == spec["expected_instruction_count"],
        "composed-rewriting instruction count differs from its declaration",
    )
    changed = sorted((index for index in range(len(seed_body)) if seed_body[index] != image[index]))
    require(
        changed == spec["expected_changed_offsets"],
        "composed-rewriting image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "composed-rewriting image differs from its pin",
    )
    require(
        changed == function["expected_changed_offsets"],
        "composed-rewriting changed offsets differ from their pin",
    )
    line_moves = {}
    for region in region_rewrite_detail:
        for old_at, new_at in region["instruction_moves"]:
            line_moves[old_at] = new_at
    for chain in x87_detail:
        for old_at, new_at in chain["instruction_moves"]:
            line_moves[old_at] = new_at
    lined_seed_bytes = bytearray(seed_bytes)
    if line_moves:
        table_at = sp["line_offset"]
        rows_lined = []
        for position in range(1, sp["line_count"]):
            entry_at = table_at + position * 6
            old_off = int.from_bytes(lined_seed_bytes[entry_at : entry_at + 4], "little")
            line_no = int.from_bytes(lined_seed_bytes[entry_at + 4 : entry_at + 6], "little")
            rows_lined.append((line_moves.get(old_off, old_off), line_no))
        rows_lined.sort()
        for position, (offset, line_no) in enumerate(rows_lined, start=1):
            entry_at = table_at + position * 6
            lined_seed_bytes[entry_at : entry_at + 4] = offset.to_bytes(4, "little")
            lined_seed_bytes[entry_at + 4 : entry_at + 6] = line_no.to_bytes(2, "little")
    installed_rows = seed_rows
    if x87_relocation_moves:
        table_at = sp["relocation_offset"]
        records = []
        for position in range(sp["relocation_count"]):
            entry_at = table_at + position * 10
            record = bytearray(lined_seed_bytes[entry_at : entry_at + 10])
            old_at = int.from_bytes(record[0:4], "little")
            if old_at in x87_relocation_moves:
                record[0:4] = x87_relocation_moves[old_at].to_bytes(4, "little")
            records.append(bytes(record))
        records.sort(key=lambda record: int.from_bytes(record[0:4], "little"))
        lined_seed_bytes[table_at : table_at + sp["relocation_count"] * 10] = b"".join(records)
        installed_rows = sorted(
            [
                {**row, "offset": x87_relocation_moves.get(row["offset"], row["offset"])}
                for row in seed_rows
            ],
            key=lambda row: row["offset"],
        )
        installed_rows = [
            {**row, "ordinal": position} for position, row in enumerate(installed_rows)
        ]
    moved_tables = bool(line_moves) or bool(x87_relocation_moves)
    lined_seed = CoffObject(bytes(lined_seed_bytes)) if moved_tables else seed
    lined_sp = lined_seed.function_section(mangled) if moved_tables else sp
    debug_detail = require_instruction_schedule_debug_fidelity(
        lined_seed,
        lined_sp,
        image,
        windows,
        spec,
        mangled,
        "composed-rewriting debug fidelity",
        relocation_symbols,
        code_length,
        internal_targets,
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "composed-rewriting linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "composed-rewriting candidate relocation semantics",
    )
    derived = bytearray(lined_seed_bytes)
    derived[sp["raw_offset"] : sp["raw_offset"] + sp["raw_size"]] = image
    effective = {
        "mangled": mangled,
        "splice_class": delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    require(
        function["expected_code_renames"] == [] and function["expected_xdata_rename_offsets"] == [],
        "composed-rewriting installs the seed's own tables and can declare no rename",
    )
    if delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = []
        effective["expected_xdata_rename_offsets"] = []
    composed, detail = compose_equal_body_comdat(bytes(lined_seed_bytes), bytes(derived), effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(
        coff_body(checked, cp) == image, "composed-rewriting composed body differs from the image"
    )
    require(
        detailed_relocations(checked, cp) == installed_rows
        and _coff_table_bytes(checked, cp, "relocations")
        == _coff_table_bytes(lined_seed, lined_sp, "relocations")
        and (
            _coff_table_bytes(checked, cp, "lines")
            == _coff_table_bytes(lined_seed, lined_sp, "lines")
        ),
        "composed-rewriting output changed seed relocation/line bytes",
    )
    debug_child = _comdat_child(checked, cp, ".debug$S")
    debug_stream = coff_body(checked, debug_child)
    require(
        sha256_bytes(debug_stream) == spec["expected_seed_debug_s_sha256"],
        "composed-rewriting debug$S differs from its pin",
    )
    claimed = {}
    for index, item in enumerate(spec.get("register_bijections") or []):
        for record in parse_codeview_symbol_stream(debug_stream, "composed-rewriting debug$S"):
            if record["type"] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(record, "composed-rewriting debug$S")
            try:
                name = _codeview_register_name(debug_stream, field_at, "composed-rewriting debug$S")
            except ByteIdentityError:
                continue
            if name not in item["mapping"]:
                continue
            require(
                record["offset"] not in claimed,
                f"composed-rewriting bijections {claimed.get(record['offset'])} and {index} both name the S_REGISTER record {record['name']!r}",
            )
            claimed[record["offset"]] = index
    debug_image = debug_stream
    debug_maps = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        mapped = apply_codeview_register_bijection(
            debug_stream,
            item["mapping"],
            item["debug_s_register_map"],
            f"composed-rewriting debug$S bijection {index}",
        )
        moved = bytearray(debug_image)
        for position in range(len(debug_stream)):
            if mapped[position] != debug_stream[position]:
                moved[position] = mapped[position]
        debug_image = bytes(moved)
        debug_maps.append(item["debug_s_register_map"])
    for index, item in enumerate(spec.get("slot_bijections") or []):
        slot_map = {int(key): value for key, value in item["mapping"].items()}
        declared = set(item["debug_s_bprel_offsets"])
        moved = bytearray(debug_image)
        seen = set()
        for record in parse_codeview_symbol_stream(
            debug_stream, "composed-rewriting debug$S bprel"
        ):
            if record["type"] != 512:
                continue
            field_at = record["offset"] + 4
            off_value = int.from_bytes(debug_stream[field_at : field_at + 4], "little", signed=True)
            if off_value in slot_map:
                require(
                    record["offset"] in declared,
                    f"composed-rewriting slot bijection misses the S_BPREL32 record at {record['offset']}",
                )
                seen.add(record["offset"])
                moved[field_at : field_at + 4] = slot_map[off_value].to_bytes(
                    4, "little", signed=True
                )
        require(
            seen == declared,
            "composed-rewriting slot bijection declares an S_BPREL32 record that names no mapped slot",
        )
        debug_image = bytes(moved)
    require(
        sha256_bytes(debug_image) == spec["expected_image_debug_s_sha256"],
        "composed-rewriting mapped debug$S differs from its pin",
    )
    composed = bytearray(composed)
    composed[debug_child["raw_offset"] : debug_child["raw_offset"] + debug_child["raw_size"]] = (
        debug_image
    )
    composed = bytes(composed)
    final = CoffObject(composed)
    fp = final.function_section(mangled)
    require(coff_body(final, fp) == image, "composed-rewriting output changed the installed body")
    for child_name in expected_closure:
        if child_name == ".debug$S":
            continue
        require(
            coff_body(final, _comdat_child(final, fp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"composed-rewriting output changed its {child_name} child",
        )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    allowed |= set(
        range(debug_child["raw_offset"], debug_child["raw_offset"] + debug_child["raw_size"])
    )
    if line_moves:
        allowed |= set(range(sp["line_offset"], sp["line_offset"] + sp["line_count"] * 6))
        require(
            _coff_table_bytes(
                CoffObject(composed), CoffObject(composed).function_section(mangled), "lines"
            )
            == _coff_table_bytes(lined_seed, lined_sp, "lines"),
            "composed-rewriting line rows differ from the proved moves",
        )
    if x87_relocation_moves:
        allowed |= set(
            range(sp["relocation_offset"], sp["relocation_offset"] + sp["relocation_count"] * 10)
        )
        require(
            _coff_table_bytes(
                CoffObject(composed), CoffObject(composed).function_section(mangled), "relocations"
            )
            == _coff_table_bytes(lined_seed, lined_sp, "relocations"),
            "composed-rewriting relocation records differ from the proved reseat",
        )
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "composed-rewriting changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": COMPOSED_REWRITING_CLASS,
            "instruction_schedule": schedule_detail,
            "fp_sum_reassociation": fp_detail,
            "commutative_operand_forms": form_detail,
            "esp_argument_exchanges": exchange_site_detail,
            "x87_squared_addend_exchanges": x87_detail,
            "simulated_region_rewrites": region_rewrite_detail,
            "register_bijections": bijection_detail,
            "slot_bijections": slot_detail,
            "relational_form": relational_detail,
            "instruction_count": len(image_instructions),
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "debug_s_register_maps": debug_maps,
            "external_entries": sorted(external_entries),
            "candidate_only": True,
            **semantic_detail,
        },
    )


DONOR_REWRITING_CLASS = "retail_exact_donor_rewriting"
DONOR_REWRITING_KIND = "donor_fp_bijection_rewriting_v1"


def validate_donor_rewriting(value: object, context: str, body_length: int) -> dict:
    """Validate one donor-rewriting certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
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
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
    )
    require(value.get("kind") == DONOR_REWRITING_KIND, f"{context}.kind differs")
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
            and all((type(item) is int and 0 <= item < body_length for item in targets)),
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
            not any((window.get("relocation_reseat") for window in normalized_windows)),
            f"{context}: this class refuses to move a relocation",
        )
    normalized_rotations = []
    rotation_bytes = []
    rotation_regions = set()
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
    normalized_x87 = []
    x87_regions = set()
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
                and reseat
                and all(
                    (
                        isinstance(pair, list)
                        and len(pair) == 2
                        and all((type(offset) is int and start <= offset < end for offset in pair))
                        for pair in reseat
                    )
                )
                and (len({pair[0] for pair in reseat}) == len(reseat))
                and (len({pair[1] for pair in reseat}) == len(reseat)),
                f"{item_context}.relocation_reseat is invalid",
            )
            normalized_item["relocation_reseat"] = [list(pair) for pair in reseat]
        rotation_bytes.extend(offsets)
        x87_regions.update(range(start, end))
        normalized_x87.append(normalized_item)
    require(
        not x87_regions & rotation_regions,
        f"{context}: an x87 exchange chain overlaps an fp-sum chain",
    )
    rotation_regions |= x87_regions
    normalized_bijections = []
    bijection_bytes = []
    previous_end = 0
    for index, item in enumerate(value.get("register_bijections") or []):
        item_context = f"{context}.register_bijections[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item,
            {
                "mapping",
                "region_start",
                "region_end",
                "expected_region_instruction_count",
                "expected_rewritten_offsets",
            },
            item_context,
        )
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        bijection_bytes.extend(offsets)
        normalized_bijections.append(
            {
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
        )
    normalized_exchanges = []
    exchange_bytes = []
    previous_exchange_end = 0
    for index, item in enumerate(value.get("fp_pointer_exchanges") or []):
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
            and all((type(offset) is int for offset in swap))
            and (start <= swap[0] < swap[1] < end),
            f"{item_context}.swap_offsets is invalid",
        )
        dead = item.get("dead_registers")
        require(
            isinstance(dead, list)
            and dead == sorted(set(dead))
            and all((name in _IA32_REGISTER_NUMBERS for name in dead))
            and (not set(dead) & _IA32_STRUCTURAL_REGISTERS),
            f"{item_context}.dead_registers is invalid",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
    normalized_rewrites = []
    rewrite_bytes = []
    rewrite_regions = set()
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
            and all((name in _IA32_REGISTER_NUMBERS for name in dead))
            and (not set(dead) & _IA32_STRUCTURAL_REGISTERS),
            f"{item_context}.dead_registers is invalid",
        )
        slots_dead = item.get("dead_slots") or []
        require(
            isinstance(slots_dead, list)
            and slots_dead == sorted(set(slots_dead))
            and all((type(d) is int and -body_length < d < 0 for d in slots_dead)),
            f"{item_context}.dead_slots is invalid",
        )
        reseat = item.get("relocation_reseat") or []
        require(
            isinstance(reseat, list)
            and all(
                (
                    isinstance(pair, list)
                    and len(pair) == 2
                    and all((type(x) is int and start <= x < end for x in pair))
                    for pair in reseat
                )
            ),
            f"{item_context}.relocation_reseat is invalid",
        )
        offsets = item.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and start <= offset < end for offset in offsets)),
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
            and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
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
            and offsets
            and (offsets == sorted(set(offsets)))
            and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
            f"{item_context}.expected_rewritten_offsets is invalid",
        )
        records = item.get("debug_s_bprel_offsets")
        require(
            isinstance(records, list)
            and records == sorted(set(records))
            and all((type(offset) is int and offset >= 0 for offset in records)),
            f"{item_context}.debug_s_bprel_offsets is invalid",
        )
        normalized_slots.append(
            {
                "mapping": dict(sorted(slot_mapping.items())),
                "expected_rewritten_offsets": list(offsets),
                "debug_s_bprel_offsets": list(records),
            }
        )
    normalized_forms, form_bytes = _validate_commutative_operand_forms(value, context, body_length)
    require(
        normalized_windows
        or normalized_rotations
        or normalized_bijections
        or normalized_exchanges
        or normalized_rewrites
        or normalized_sites
        or normalized_forms
        or normalized_slots
        or normalized_x87,
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
        and (len({*relational_bytes} & {*form_bytes}) == 0),
        f"{context}: two certificates rewrite the same byte",
    )
    require(
        not rotation_regions
        & (
            set(bijection_bytes)
            | set(exchange_bytes)
            | set(relational_bytes)
            | set(form_bytes)
            | window_bytes
            | rewrite_regions
        ),
        f"{context}: another certificate reaches inside an fp-sum chain",
    )
    require(
        not rewrite_regions
        & (set(exchange_bytes) | set(relational_bytes) | set(form_bytes) | window_bytes),
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
    changed = value.get("expected_changed_offsets")
    require(
        isinstance(changed, list)
        and changed
        and (changed == sorted(set(changed)))
        and all((type(offset) is int and 0 <= offset < body_length for offset in changed)),
        f"{context}.expected_changed_offsets is invalid",
    )
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
        | set(relational_bytes) - identity_relational
        <= set(changed),
        f"{context}.expected_changed_offsets omits a rewritten byte",
    )
    require(
        all(
            (
                offset in rotation_regions
                or offset in window_bytes
                or offset in rewrite_regions
                or (
                    offset
                    in set(bijection_bytes)
                    | set(exchange_bytes)
                    | set(relational_bytes)
                    | set(form_bytes)
                    | slot_bytes
                )
                for offset in changed
            )
        ),
        f"{context}.expected_changed_offsets names a byte no declared certificate can move",
    )
    procedure = value.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all((type(item) is int and item >= 0 for item in procedure))
        and (procedure[0] == body_length)
        and (procedure[1] <= procedure[2] <= body_length),
        f"{context}.expected_procedure_range is invalid",
    )
    references = value.get("expected_code_symbol_references")
    require(
        isinstance(references, list)
        and all(
            (
                isinstance(item, list)
                and len(item) == 3
                and isinstance(item[0], str)
                and isinstance(item[1], str)
                and (type(item[2]) is int)
                and (0 <= item[2] <= body_length)
                for item in references
            )
        ),
        f"{context}.expected_code_symbol_references is invalid",
    )
    external = value.get("expected_external_entries")
    require(
        isinstance(external, list)
        and external == sorted(set(external))
        and all((type(item) is int and 0 < item < body_length for item in external)),
        f"{context}.expected_external_entries is invalid",
    )
    rationale = value.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    normalized = {
        "kind": DONOR_REWRITING_KIND,
        "expected_instruction_count": require_exact_int(
            value.get("expected_instruction_count"),
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
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    return normalized


def produce_donor_rewriting_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict,
    *,
    compiler_identity: Msvc420CompilerIdentity | None = None,
) -> tuple[bytes, dict]:
    """Produce REWRITE(donor body) from a fresh compiler artifact."""
    require_payload_free_declaration(function, "donor-rewriting declaration")
    require(
        function.get("splice_class") == DONOR_REWRITING_CLASS,
        "splice class is not retail_exact_donor_rewriting",
    )
    require(
        "target_source_refactor" not in function,
        "donor-rewriting functions carry no source refactor",
    )
    spec = function["donor_rewriting"]
    require(spec["kind"] == DONOR_REWRITING_KIND, "donor-rewriting kind differs")
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    declared_donor_seat = function.get("expected_donor_section_number")
    if declared_donor_seat is None:
        require(
            sp["number"] == dp["number"] == function["expected_section_number"],
            "donor-rewriting target section seat changed",
        )
    else:
        require(
            sp["number"] == function["expected_section_number"]
            and dp["number"] == declared_donor_seat,
            "donor-rewriting declared donor seat changed",
        )
    require(
        len(seed.sections) == function["expected_section_count"]
        and len(donor.sections)
        == function.get("expected_donor_section_count", function["expected_section_count"]),
        "donor-rewriting global section count changed",
    )
    extras = sorted(function.get("expected_donor_extra_functions") or [])
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    measured_extra = []
    for name in set(seed_functions) | set(donor_functions):
        left = seed_functions.get(name, 0)
        right = donor_functions.get(name, 0)
        if right == left:
            continue
        require(right == left + 1, f"donor-rewriting donor function census diverges at {name}")
        measured_extra.append(name)
    require(
        sorted(measured_extra) == extras
        and sum(seed_functions.values()) == function["expected_function_count"],
        "donor-rewriting donor function set differs from its declared extras",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    extra_heads = []
    for key in set(seed_comdats) | set(donor_comdats):
        left = seed_comdats.get(key, 0)
        right = donor_comdats.get(key, 0)
        if right == left:
            continue
        require(right == left + 1, f"donor-rewriting donor COMDAT census diverges at {key}")
        extra_heads.append(key[0])
    require(
        sorted(extra_heads) == extras
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "donor-rewriting donor COMDAT identity set differs from its declared extras",
    )
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_donor_length"]
        and (
            sp["relocation_count"]
            == dp["relocation_count"]
            == function["expected_relocation_count"]
        )
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        "donor-rewriting target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "donor-rewriting COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure)
        and list(expected_closure)
        in (REGISTER_BIJECTION_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE),
        "donor-rewriting target closure is neither the FPO debug pair nor the EH pair",
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "donor-rewriting metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = bytes(coff_body(donor, dp))
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "donor-rewriting seed/donor body differs from its pin",
    )
    donor_rows = detailed_relocations(donor, dp)

    def _relocation_identity(row: dict) -> tuple:
        if row["target_storage"] in (3, 6) and row["target"].startswith("$"):
            return (
                "static",
                row["type"],
                row["addend"],
                row["target_section"],
                row["target_value"],
                row["target_type"],
            )
        if row["target_storage"] == 3:
            base, sep, serial = row["target"].rpartition("$S")
            if sep and base and serial.isdigit():
                return (
                    "static-s",
                    row["type"],
                    row["addend"],
                    base,
                    row["target_section"],
                    row["target_value"],
                    row["target_type"],
                )
        return (
            "named",
            row["type"],
            row["addend"],
            row["target"],
            row["target_type"],
            row["target_storage"],
        )

    seed_rows_d1 = detailed_relocations(seed, sp)
    divergences = {
        tuple(item[:1])[0]: (item[1], item[2])
        for item in function.get("expected_relocation_divergences") or []
    }
    require(
        len(donor_rows) == len(seed_rows_d1),
        "donor-rewriting relocation count differs from the seed",
    )
    for ordinal, (donor_row, seed_row) in enumerate(zip(donor_rows, seed_rows_d1)):
        if ordinal in divergences:
            expected_seed, expected_donor = divergences[ordinal]
            require(
                seed_row["target"] == expected_seed and donor_row["target"] == expected_donor,
                f"donor-rewriting declared divergence {ordinal} differs ({seed_row['target']} -> {donor_row['target']})",
            )
            continue
        require(
            _relocation_identity(donor_row) == _relocation_identity(seed_row),
            f"donor-rewriting donor relocation target {ordinal} differs from the seed",
        )
    relocation_offsets = frozenset(
        (row["offset"] + byte for row in donor_rows for byte in range(row["width"]))
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in donor_rows
    }
    internal_targets = frozenset(
        (row["target_value"] for row in donor_rows if row["target_section"] == dp["number"])
    )
    declared_targets = spec.get("expected_internal_relocation_targets")
    if declared_targets is not None:
        require(
            sorted(internal_targets) == declared_targets,
            "donor-rewriting in-body relocated target set changed",
        )
    code_length = spec.get("expected_code_length")
    external_entries = relational_form_external_entries(
        donor, dp, "donor-rewriting external entries"
    )
    require(
        sorted(external_entries) == spec["expected_external_entries"],
        "donor-rewriting external entry set differs from its declaration",
    )
    image = donor_body
    bijection_detail = []
    for index, item in enumerate(spec.get("register_bijections") or []):
        image, proof = apply_register_bijection(
            image,
            item["mapping"],
            (item["region_start"], item["region_end"]),
            relocation_offsets,
            f"donor-rewriting bijection {index}",
            relocation_symbols,
            code_length,
            internal_targets,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"donor-rewriting bijection {index} rewrote a different byte set from its declaration",
        )
        require(
            proof["region_instruction_count"] == item["expected_region_instruction_count"],
            f"donor-rewriting bijection {index} region instruction count differs from its declaration",
        )
        bijection_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "region": [item["region_start"], item["region_end"]],
                "rewritten_offsets": proof["rewritten_offsets"],
                "region_instruction_count": proof["region_instruction_count"],
            }
        )
    slot_detail = []
    for index, item in enumerate(spec.get("slot_bijections") or []):
        image, proof = apply_slot_bijection(
            image,
            item["mapping"],
            relocation_offsets,
            f"donor-rewriting slot bijection {index}",
            relocation_symbols,
            code_length,
        )
        require(
            proof["rewritten_offsets"] == item["expected_rewritten_offsets"],
            f"donor-rewriting slot bijection {index} rewrote a different byte set from its declaration",
        )
        slot_detail.append(
            {
                "mapping": dict(sorted(item["mapping"].items())),
                "rewritten_offsets": proof["rewritten_offsets"],
            }
        )
    fp_detail = []
    if spec.get("fp_sum_rotations"):
        image, fp_proof = apply_fp_sum_reassociation(
            image,
            spec["fp_sum_rotations"],
            relocation_offsets,
            "donor-rewriting fp-sum",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, chain) in enumerate(zip(spec["fp_sum_rotations"], fp_proof["chains"])):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting fp-sum chain {index} rewrote a different byte set from its declaration",
            )
        fp_detail = fp_proof["chains"]
    exchange_detail = []
    if spec.get("fp_pointer_exchanges"):
        image, exchange_proof = apply_fp_pointer_exchange(
            image,
            spec["fp_pointer_exchanges"],
            relocation_offsets,
            "donor-rewriting fp-exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, exchange) in enumerate(
            zip(spec["fp_pointer_exchanges"], exchange_proof["exchanges"])
        ):
            require(
                exchange["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting fp-exchange {index} rewrote a different byte set from its declaration",
            )
        exchange_detail = exchange_proof["exchanges"]
    form_detail = []
    if spec.get("commutative_operand_forms"):
        image, form_proof = apply_commutative_operand_form(
            image,
            spec["commutative_operand_forms"],
            relocation_offsets,
            "donor-rewriting commutative form",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, site) in enumerate(
            zip(spec["commutative_operand_forms"], form_proof["sites"])
        ):
            require(
                site["expected_rewritten_offsets"] == item["expected_rewritten_offsets"]
                and site["pair_offset"] == item["pair_offset"]
                and (site["operation"] == item["operation"]),
                f"donor-rewriting commutative form {index} rewrote a different site from its declaration",
            )
        form_detail = form_proof["sites"]
    rewrite_detail = []
    relocation_moves = {}
    if spec.get("simulated_region_rewrites"):
        image, rewrite_proof = apply_simulated_region_rewrite(
            image,
            spec["simulated_region_rewrites"],
            relocation_offsets,
            "donor-rewriting simulated rewrite",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, region) in enumerate(
            zip(spec["simulated_region_rewrites"], rewrite_proof["regions"])
        ):
            require(
                region["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting simulated rewrite {index} rewrote a different byte set from its declaration",
            )
            require(
                [list(pair) for pair in region["relocation_reseat"]]
                == [list(pair) for pair in item.get("relocation_reseat") or []],
                f"donor-rewriting simulated rewrite {index} reseated a different relocation set from its declaration",
            )
        rewrite_detail = rewrite_proof["regions"]
        relocation_moves = dict(((old, new) for old, new in rewrite_proof["relocation_reseat"]))
    x87_detail = []
    if spec.get("x87_squared_addend_exchanges"):
        image, x87_proof = apply_x87_squared_addend_exchange(
            image,
            spec["x87_squared_addend_exchanges"],
            relocation_offsets,
            "donor-rewriting x87 exchange",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
            internal_targets,
        )
        for index, (item, chain) in enumerate(
            zip(spec["x87_squared_addend_exchanges"], x87_proof["chains"])
        ):
            require(
                chain["rewritten_offsets"] == item["expected_rewritten_offsets"],
                f"donor-rewriting x87 exchange {index} rewrote a different byte set from its declaration",
            )
            for old, new in chain["relocation_reseat"]:
                require(
                    old not in relocation_moves,
                    f"donor-rewriting x87 exchange {index} reseats a relocation another certificate already moved",
                )
                relocation_moves[old] = new
        x87_detail = x87_proof["chains"]
    schedule_detail = []
    windows = spec.get("windows") or []
    if windows:
        image, schedule_proof = apply_instruction_schedule(
            image,
            windows,
            relocation_offsets,
            "donor-rewriting schedule",
            relocation_symbols,
            code_length,
            internal_targets,
            frozenset(external_entries),
            compiler_identity,
        )
        require(
            not schedule_proof["relocation_reseat"],
            "donor-rewriting refuses to move a relocation inside a window",
        )
        schedule_detail = schedule_proof["windows"]
    relational_detail = []
    if spec.get("relational_sites"):
        sites = [
            {
                key: item[key]
                for key in (
                    "compare_offset",
                    "branch_offset",
                    "seed_condition",
                    "image_condition",
                    "reencode",
                )
                if key in item
            }
            for item in spec["relational_sites"]
        ]
        image, proof = apply_relational_form(
            image,
            sites,
            relocation_offsets,
            "donor-rewriting relational",
            relocation_symbols,
            code_length,
            frozenset(external_entries),
        )
        require(
            proof["rewritten_offsets"]
            == sorted(
                (
                    offset
                    for item in spec["relational_sites"]
                    for offset in item["expected_rewritten_offsets"]
                )
            ),
            "donor-rewriting relational rewrite set differs from its declaration",
        )
        relational_detail = proof["sites"]
    require(image != donor_body, "donor-rewriting image does not move the donor body")
    donor_instructions = decode_ia32_bijection_body(
        donor_body, "donor-rewriting pre-image", relocation_symbols, code_length
    )
    image_instructions = decode_ia32_bijection_body(
        image, "donor-rewriting image", relocation_symbols, code_length
    )
    require(
        len(image_instructions) == len(donor_instructions) == spec["expected_instruction_count"],
        "donor-rewriting image instruction count differs from its declaration",
    )
    window_bytes = {
        offset for window in windows for offset in range(window["start"], window["end"])
    }
    for item in spec.get("simulated_region_rewrites") or []:
        window_bytes |= set(range(item["region_start"], item["region_end"]))
    for item in spec.get("x87_squared_addend_exchanges") or []:
        window_bytes |= set(range(item["chain_start"], item["chain_end"]))
    require(
        all(
            (
                left["offset"] == right["offset"] and left["length"] == right["length"]
                for left, right in zip(donor_instructions, image_instructions)
                if left["offset"] not in window_bytes
            )
        ),
        "donor-rewriting image does not preserve the donor's instruction grid outside the declared windows and rewrite regions",
    )
    line_moves = {}
    for window in windows:
        cursor = window["start"]
        starts = []
        for length in window["source_instruction_lengths"]:
            starts.append(cursor)
            cursor += length
        cursor = window["start"]
        for source_index in window["target_order"]:
            if starts[source_index] != cursor:
                line_moves[starts[source_index]] = cursor
            cursor += window["source_instruction_lengths"][source_index]
    for region in rewrite_detail:
        for old, new in region["instruction_moves"]:
            line_moves[old] = new
    for chain in x87_detail:
        for old, new in chain["instruction_moves"]:
            line_moves[old] = new
    lined_donor = bytearray(donor_bytes)
    if line_moves:
        table_at = dp["line_offset"]
        rows_lined = []
        for position in range(1, dp["line_count"]):
            entry_at = table_at + position * 6
            old = int.from_bytes(lined_donor[entry_at : entry_at + 4], "little")
            line_no = int.from_bytes(lined_donor[entry_at + 4 : entry_at + 6], "little")
            rows_lined.append((line_moves.get(old, old), line_no))
        rows_lined.sort()
        for position, (offset, line_no) in enumerate(rows_lined, start=1):
            entry_at = table_at + position * 6
            lined_donor[entry_at : entry_at + 4] = offset.to_bytes(4, "little")
            lined_donor[entry_at + 4 : entry_at + 6] = line_no.to_bytes(2, "little")
    lined = CoffObject(bytes(lined_donor))
    lp = lined.function_section(mangled)
    debug_detail = require_instruction_schedule_debug_fidelity(
        lined,
        lp,
        image,
        windows,
        spec,
        mangled,
        "donor-rewriting debug fidelity",
        relocation_symbols,
        code_length,
        internal_targets,
    )
    changed = sorted(
        (index for index in range(len(donor_body)) if donor_body[index] != image[index])
    )
    require(
        changed == spec["expected_changed_offsets"],
        "donor-rewriting image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "donor-rewriting image differs from its pin",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(
        pinned_length == len(image) == function["expected_donor_length"],
        "donor-rewriting linked length changed",
    )
    installed_rows = [
        {**row, "offset": relocation_moves.get(row["offset"], row["offset"])} for row in donor_rows
    ]
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "donor-rewriting candidate relocation semantics",
    )
    derived = bytearray(lined_donor)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    if relocation_moves:
        table_at = dp["relocation_offset"]
        for position in range(dp["relocation_count"]):
            entry_at = table_at + position * 10
            old = int.from_bytes(derived[entry_at : entry_at + 4], "little")
            if old in relocation_moves:
                derived[entry_at : entry_at + 4] = relocation_moves[old].to_bytes(4, "little")
    effective = {
        "mangled": mangled,
        "splice_class": "retail_exact_reloc_divergent",
        "expected_seed_length": function["expected_seed_length"],
        "expected_donor_length": function["expected_donor_length"],
        "expected_linked_span": function["expected_linked_span"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_seed_line_count": function["expected_seed_line_count"],
        "expected_donor_line_count": function["expected_donor_line_count"],
        "retail_oracle": function["retail_oracle"],
        "retail_relocations": function["retail_relocations"],
    }
    if "debug_representation_delta" in function:
        effective["debug_representation_delta"] = function["debug_representation_delta"]
    if "expected_donor_section_number" in function:
        effective["expected_donor_section_number"] = function["expected_donor_section_number"]
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        bytes(derived),
        effective,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
    )
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, "donor-rewriting composed body differs from the image")
    require(
        [_relocation_identity(row) for row in detailed_relocations(checked, cp)]
        == [_relocation_identity(row) for row in installed_rows],
        "donor-rewriting composed relocation table is not the proved reseat",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": DONOR_REWRITING_CLASS,
            "instruction_schedule": schedule_detail,
            "fp_sum_reassociation": fp_detail,
            "fp_pointer_exchanges": exchange_detail,
            "commutative_operand_forms": form_detail,
            "simulated_region_rewrites": rewrite_detail,
            "x87_squared_addend_exchanges": x87_detail,
            "register_bijections": bijection_detail,
            "slot_bijections": slot_detail,
            "relational_form": relational_detail,
            "instruction_count": len(image_instructions),
            "changed_offsets": changed,
            "debug_fidelity": debug_detail,
            "external_entries": sorted(external_entries),
            "candidate_only": True,
            **semantic_detail,
        },
    )


def apply_esp_argument_exchange(
    body: bytes,
    exchanges: list,
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
) -> tuple[bytes, dict]:
    """Exchange two incoming pointer arguments' roles, or refuse.

    The certificate: two `mov r32, [esp+disp8]` argument loads in the
    function's linear prologue prefix take each other's incoming argument
    slot, and every later use of either destination register is renamed
    under the corresponding two-register bijection.  The pair composes to
    an isomorphism of the machine function: the same two argument values
    flow through exchanged register names.

    Obligations, all discharged here on the measured body:
      E1  both offsets decode as `8B /r` with mod=01, rm=100, SIB=24 --
          `mov r32, [esp+disp8]` -- inside a totally decoded prefix;
      E2  the destinations are distinct and neither is ESP or EBP;
      E3  the prefix from entry through the second load consists ONLY of
          `push r32`, `sub esp, imm8`, and `mov r32, [esp+disp8]`
          instructions, so the ESP depth at each site is exact and no
          instruction can have consumed either destination register;
      E4  no relocation byte lies inside either instruction;
      E5  the two loads address DIFFERENT incoming argument slots (the
          slot is disp MINUS the tracked ESP depth, entry-relative), both
          above the return address;
      E6  the exchanged displacements still encode as disp8;
      E7  no other prologue load addresses either exchanged slot, and no
          instruction after the prologue prefix has an ESP-based memory
          operand at all (so nothing else can alias an argument slot);
      E8  after the prefix, neither destination register is WRITTEN again
          (a `pop r32` restoring a prologue `push r32` is the structural
          exception and is left unrenamed), every register field naming
          either destination is flipped to the other, instruction
          boundaries survive re-decoding, and each rewritten
          instruction's read/write sets are exactly the originals with
          the two registers exchanged.
    """
    require_payload_free_declaration(exchanges, f"{context} ESP argument declaration")
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    require(
        isinstance(exchanges, list) and len(exchanges) == 1,
        f"{context}: exactly one exchange must be declared",
    )
    item = exchanges[0]
    item_context = f"{context} exchange 0"
    first, second = (item["first_offset"], item["second_offset"])
    require(
        type(first) is int and type(second) is int and (0 <= first < second < len(body)),
        f"{item_context}: offsets are out of range",
    )
    depth = 0
    at = 0
    depths = {}
    loads = {}
    pushed = []
    while at < len(body):
        opcode = body[at]
        if 80 <= opcode <= 87:
            depth += 4
            pushed.append(opcode - 80)
            at += 1
            continue
        if opcode == 131 and at + 3 <= len(body) and (body[at + 1] == 236):
            depth += body[at + 2]
            at += 3
            continue
        if (
            opcode == 139
            and at + 4 <= len(body)
            and (body[at + 1] >> 6 == 1)
            and (body[at + 1] & 7 == 4)
            and (body[at + 2] == 36)
        ):
            register = body[at + 1] >> 3 & 7
            displacement = body[at + 3]
            loads[at] = (register, displacement)
            depths[at] = depth
            at += 4
            continue
        require(
            at > second,
            f"{item_context}: the prologue prefix holds an instruction outside the closed form at {at}",
        )
        break
    prefix_end = at
    require(
        first in loads and second in loads,
        f"{item_context}: a declared offset is not an argument load",
    )
    first_register, first_disp = loads[first]
    second_register, second_disp = loads[second]
    require(
        first_register != second_register
        and first_register not in (4, 5)
        and (second_register not in (4, 5)),
        f"{item_context}: destination registers are not two distinct general registers",
    )
    for offset in (first + 3, second + 3):
        require(
            offset not in relocation_offsets,
            f"{item_context}: a relocation lies under the displacement",
        )
    first_slot = first_disp - depths[first]
    second_slot = second_disp - depths[second]
    require(
        first_slot != second_slot and first_slot >= 4 and (second_slot >= 4),
        f"{item_context}: the loads do not take two distinct incoming argument slots",
    )
    for load_at, (_, load_disp) in loads.items():
        if load_at in (first, second):
            continue
        require(
            load_disp - depths[load_at] not in (first_slot, second_slot),
            f"{item_context}: another prefix load addresses an exchanged slot",
        )
    new_first = second_slot + depths[first]
    new_second = first_slot + depths[second]
    require(
        0 <= new_first <= 127 and 0 <= new_second <= 127,
        f"{item_context}: an exchanged displacement does not encode as disp8",
    )
    decoded = decode_ia32_bijection_body(body, f"{context} body", relocations, code_length)
    numbers = {first_register: second_register, second_register: first_register}
    names = {
        IA32_GENERAL_REGISTER_NAMES[first_register]: IA32_GENERAL_REGISTER_NAMES[second_register],
        IA32_GENERAL_REGISTER_NAMES[second_register]: IA32_GENERAL_REGISTER_NAMES[first_register],
    }
    exchanged_names = frozenset(names)
    remaining_pops = list(pushed)
    structural_pops = set()
    image = bytearray(body)
    image[first + 3] = new_first
    image[second + 3] = new_second
    rewritten = [first + 3, second + 3]
    for instruction in decoded:
        offset = instruction["offset"]
        if offset < prefix_end:
            continue
        memory = instruction.get("memory")
        require(
            memory is None or memory.get("base") != "esp",
            f"{item_context}: an ESP-based memory operand after the prologue prefix could alias an argument slot (at {offset})",
        )
        opcode = instruction["opcode"]
        if (
            instruction["length"] == 1
            and 88 <= body[offset] <= 95
            and (body[offset] - 88 in remaining_pops)
        ):
            remaining_pops.remove(body[offset] - 88)
            structural_pops.add(offset)
            continue
        require(
            not instruction["writes"] & exchanged_names or instruction["flow"] in ("ret", "exit"),
            f"{item_context}: an instruction at {offset} writes an exchanged register after the prologue prefix",
        )
        for byte_index, shift in instruction["fields"]:
            value = image[byte_index] >> shift & 7
            if value not in numbers:
                continue
            require(
                byte_index not in relocation_offsets,
                f"{item_context}: a rewritten register field overlaps a relocation",
            )
            image[byte_index] = (image[byte_index] & ~(7 << shift) | numbers[value] << shift) & 255
            rewritten.append(byte_index)
    image = bytes(image)
    image_instructions = decode_ia32_bijection_body(
        image, f"{context} image", relocations, code_length
    )
    require(
        [(entry["offset"], entry["length"]) for entry in image_instructions]
        == [(entry["offset"], entry["length"]) for entry in decoded],
        f"{item_context}: the exchange changed an instruction boundary",
    )
    for left, right in zip(image_instructions, decoded):
        if (
            right["offset"] < prefix_end
            or right["offset"] in structural_pops
            or right["offset"] in (first, second)
        ):
            continue
        if right["flow"] in ("ret", "exit"):
            continue
        if not right["fields"]:
            require(
                not (right["reads"] | right["writes"]) & exchanged_names,
                f"{item_context}: an implicit use of an exchanged register at {right['offset']} cannot be renamed",
            )
            continue
        expected_reads = frozenset((names.get(name, name) for name in right["reads"]))
        expected_writes = frozenset((names.get(name, name) for name in right["writes"]))
        require(
            left["reads"] == expected_reads and left["writes"] == expected_writes,
            f"{item_context}: the rewrite at {right['offset']} is not the declared two-register exchange",
        )
    rewritten = sorted(set((offset for offset in rewritten if image[offset] != body[offset])))
    sites = [
        {
            "first_offset": first,
            "second_offset": second,
            "registers": [
                IA32_GENERAL_REGISTER_NAMES[first_register],
                IA32_GENERAL_REGISTER_NAMES[second_register],
            ],
            "rewritten_offsets": rewritten,
        }
    ]
    return (image, {"sites": sites})


FP_POINTER_EXCHANGE_KIND = "fp_pointer_addend_exchange_v1"


def apply_imul_operand_exchange(
    body: bytes,
    sites: list,
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
    external_entries: frozenset | None = None,
    internal_targets: frozenset | None = None,
) -> tuple[bytes, dict]:
    """Exchange each declared integer-multiply load form, or refuse."""
    require_payload_free_declaration(sites, f"{context} IMUL operand declaration")
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(sites, list) and sites, f"{context}: no site is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    entry_offsets = {items[entry]["offset"] for entry in entries[1:]}
    decoded = decode_ia32_bijection_body(body, f"{context} decode", relocations, code_length)
    index_of = {item["offset"]: index for index, item in enumerate(decoded)}
    number_of = {name: number for name, number in _IA32_REGISTER_NUMBERS.items()}
    name_of = {number: name for name, number in number_of.items()}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, site in enumerate(sites):
        site_context = f"{context} site {ordinal}"
        mov_at = site["mov_offset"]
        imul_at = site["imul_offset"]
        require(
            type(mov_at) is int
            and type(imul_at) is int
            and (mov_at in index_of)
            and (imul_at in index_of)
            and (mov_at < imul_at),
            f"{site_context}: offsets are not ordered instruction boundaries",
        )
        require(previous_end <= mov_at, f"{site_context}: sites are unsorted or overlapping")
        mov = decoded[index_of[mov_at]]
        imul = decoded[index_of[imul_at]]
        require(
            mov["length"] == 2 and body[mov_at] == 139 and (body[mov_at + 1] >> 6 == 3),
            f"{site_context}: the load is not mov r32, r32",
        )
        rt = body[mov_at + 1] >> 3 & 7
        rs = body[mov_at + 1] & 7
        require(rt != rs, f"{site_context}: the pair names one register")
        require(
            name_of[rt] != "esp" and name_of[rs] != "esp", f"{site_context}: the pair touches ESP"
        )
        require(
            imul["length"] == 5
            and body[imul_at] == 15
            and (body[imul_at + 1] == 175)
            and (body[imul_at + 2] >> 6 == 1)
            and (body[imul_at + 2] & 7 == 4)
            and (body[imul_at + 3] == 36),
            f"{site_context}: the operator is not imul r32, [esp+disp8]",
        )
        require(
            body[imul_at + 2] >> 3 & 7 == rt,
            f"{site_context}: the operator does not name the load's target",
        )
        disp8 = body[imul_at + 4]
        end = imul_at + 5
        previous_end = end
        between = [decoded[i] for i in range(index_of[mov_at] + 1, index_of[imul_at])]
        require(
            len(between) <= 2, f"{site_context}: more than two instructions lie between the pair"
        )
        rt_atoms = _IA32_ATOMS_OF[name_of[rt]]
        rs_atoms = _IA32_ATOMS_OF[name_of[rs]]
        esp_atoms = _IA32_ATOMS_OF["esp"]
        for inner in between:
            require(
                inner["flow"] == "straight", f"{site_context}: an intervening instruction branches"
            )
            reads = frozenset(inner["read_atoms"])
            writes = frozenset(inner["write_atoms"])
            require(
                not reads & rt_atoms and (not writes & rt_atoms),
                f"{site_context}: an intervening instruction touches the load target",
            )
            require(
                not writes & rs_atoms,
                f"{site_context}: an intervening instruction writes the exchanged register",
            )
            require(
                not reads & esp_atoms or not inner["memory_write"],
                f"{site_context}: an intervening instruction writes through ESP",
            )
            require(
                not inner["memory_write"],
                f"{site_context}: an intervening instruction writes memory",
            )
            require(not writes & esp_atoms, f"{site_context}: an intervening instruction moves ESP")
            require(
                "flags" not in inner["read_atoms"]
                and (not reads & frozenset({"eflags"}))
                and (not inner.get("reads_flags")),
                f"{site_context}: an intervening instruction reads flags",
            )
        require(
            all((offset not in relocation_offsets for offset in range(mov_at, end))),
            f"{site_context}: the site overlaps a relocation",
        )
        require(
            not any((mov_at < target < end for target in branch_targets)),
            f"{site_context}: a branch target lies inside the site",
        )
        require(
            not any((mov_at < offset < end for offset in entry_offsets)),
            f"{site_context}: an entry point lies inside the site",
        )
        require(
            not any((mov_at < target < end for target in internal_targets or frozenset())),
            f"{site_context}: an internal relocation target lies inside the site",
        )
        carried = b"".join(
            (body[inner["offset"] : inner["offset"] + inner["length"]] for inner in between)
        )
        new_site = (
            bytes([139, 64 | rt << 3 | 4, 36, disp8])
            + carried
            + bytes([15, 175, 192 | rt << 3 | rs])
        )
        require(
            len(new_site) == end - mov_at, f"{site_context}: the exchange changed the site length"
        )
        image[mov_at:end] = new_site
        rewritten = [offset for offset in range(mov_at, end) if image[offset] != body[offset]]
        require(
            rewritten == site["expected_rewritten_offsets"],
            f"{site_context}: the exchange rewrote a different byte set from its declaration",
        )
        proved.append(
            {
                "mov_offset": mov_at,
                "imul_offset": imul_at,
                "target": name_of[rt],
                "exchanged": name_of[rs],
                "slot_displacement": disp8,
                "rewritten_offsets": rewritten,
            }
        )
    reencoded = decode_ia32_bijection_body(
        bytes(image), f"{context} image", relocations, code_length
    )
    require(
        len(reencoded) == len(decoded), f"{context}: the exchange changed the instruction count"
    )
    site_spans = [(site["mov_offset"], site["imul_offset"] + 5) for site in sites]
    for left, right in zip(decoded, reencoded):
        inside = any((start <= left["offset"] < stop for start, stop in site_spans))
        if not inside:
            require(
                left["offset"] == right["offset"] and left["length"] == right["length"],
                f"{context}: the exchange moved an instruction outside its sites",
            )
    return (bytes(image), {"sites": proved})


_SIMULATOR_REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def _fp_exchange_simulate(body: bytes, start: int, end: int, context: str):
    """Symbolically execute [start, end); return the end state."""
    regs = {name: ("reg0", name) for name in _SIMULATOR_REGS}
    stack = []
    last_flags = None
    offset = start

    def norm_sum(left, right):
        parts = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "fsum":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("fsum", tuple(sorted(parts, key=repr)))

    while offset < end:
        length = supported_ia32_instruction_length(body[offset:], context)
        require(
            offset + length <= end,
            f"{context}: an instruction straddles the region boundary at {offset}",
        )
        encoded = body[offset : offset + length]
        op = encoded[0]
        modrm = encoded[1] if length >= 2 else None
        mod = modrm >> 6 if modrm is not None else None
        reg_field = modrm >> 3 & 7 if modrm is not None else None
        rm = modrm & 7 if modrm is not None else None

        def mem_operand(cursor_base):
            require(rm != 4, f"{context}: SIB addressing at {offset} is outside the simulator set")
            base = regs[_SIMULATOR_REGS[rm]]
            cursor = cursor_base
            if mod == 1:
                disp = int.from_bytes(encoded[cursor : cursor + 1], "little", signed=True)
            elif mod == 2:
                disp = int.from_bytes(encoded[cursor : cursor + 4], "little", signed=True)
            elif mod == 0 and rm == 5:
                require(False, f"{context}: absolute address at {offset}")
            else:
                disp = 0
            return ("addr", base, disp)

        if op == 139 and mod != 3:
            regs[_SIMULATOR_REGS[reg_field]] = ("load", mem_operand(2))
        elif op == 139 and mod == 3:
            regs[_SIMULATOR_REGS[reg_field]] = regs[_SIMULATOR_REGS[rm]]
        elif op == 137 and mod == 3:
            regs[_SIMULATOR_REGS[rm]] = regs[_SIMULATOR_REGS[reg_field]]
        elif op == 131 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:3], "little", signed=True)
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("add", regs[name], value)
            last_flags = (offset - start, ("addflags", regs[name]))
        elif op == 129 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:6], "little", signed=True)
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("add", regs[name], value)
            last_flags = (offset - start, ("addflags", regs[name]))
        elif op == 133 and mod == 3:
            last_flags = (
                offset - start,
                ("test", regs[_SIMULATOR_REGS[rm]], regs[_SIMULATOR_REGS[reg_field]]),
            )
        elif op == 217 and mod != 3 and (reg_field == 0):
            stack.append(("load32", mem_operand(2)))
        elif op == 216 and mod != 3 and (reg_field == 1):
            require(stack, f"{context}: fmul at {offset} multiplies the unknown stack base")
            stack[-1] = ("fmul", stack[-1], ("load32", mem_operand(2)))
        elif encoded == b"\xde\xc1":
            require(len(stack) >= 2, f"{context}: faddp at {offset} reaches the unknown stack base")
            right = stack.pop()
            stack[-1] = norm_sum(stack[-1], right)
        else:
            require(
                False,
                f"{context}: the instruction at {offset} is outside the simulator's closed set",
            )
        offset += length
    require(offset == end, f"{context}: the region does not end on an instruction boundary")
    return (regs, stack, last_flags)


def apply_fp_pointer_exchange(
    body: bytes,
    exchanges: list,
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
    external_entries: frozenset | None = None,
    internal_targets: frozenset | None = None,
) -> tuple[bytes, dict]:
    """Exchange declared pointer-setup immediates, or refuse."""
    require_payload_free_declaration(exchanges, f"{context} FP pointer declaration")
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(exchanges, list) and exchanges, f"{context}: no exchange is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    flag_live = ia32_relational_flag_liveness(items, successors, context)
    walk_index = {item["offset"]: index for index, item in enumerate(items)}
    decoded = decode_ia32_bijection_body(body, f"{context} liveness", relocations, code_length)
    live, _live_successors = _register_bijection_live_sets(decoded, f"{context} liveness")
    exit_index = {item["offset"]: index for index, item in enumerate(decoded)}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, item in enumerate(exchanges):
        item_context = f"{context} exchange {ordinal}"
        start, end = (item["region_start"], item["region_end"])
        require(
            type(start) is int and type(end) is int and (0 < start < end <= len(body)),
            f"{item_context}: bounds are out of range",
        )
        require(previous_end <= start, f"{item_context}: exchanges are unsorted or overlapping")
        previous_end = end
        require(
            not any((start <= offset < end for offset in relocation_offsets)),
            f"{item_context}: a relocation lies inside the region",
        )
        require(
            not any((start < target < end for target in branch_targets)),
            f"{item_context}: a branch targets the region interior",
        )
        require(
            not any((start < items[entry]["offset"] < end for entry in entries[1:])),
            f"{item_context}: an external entry lies inside the region",
        )
        require(
            not any((start < target < end for target in internal_targets or frozenset())),
            f"{item_context}: a relocated target lies inside the region",
        )
        first, second = item["swap_offsets"]
        require(
            start <= first < second < end,
            f"{item_context}: the swapped adds are outside the region",
        )
        forms = []
        for at in (first, second):
            length = supported_ia32_instruction_length(body[at:], item_context)
            encoded = body[at : at + length]
            require(
                encoded[0] in (129, 131) and encoded[1] >> 6 == 3 and (encoded[1] >> 3 & 7 == 0),
                f"{item_context}: the instruction at {at} is not add r32, imm",
            )
            forms.append((encoded[0], length))
        require(forms[0] == forms[1], f"{item_context}: the two adds have different forms")
        width = 1 if forms[0][0] == 131 else 4
        imm_a = image[first + 2 : first + 2 + width]
        imm_b = image[second + 2 : second + 2 + width]
        require(imm_a != imm_b, f"{item_context}: the immediates are already equal")
        image[first + 2 : first + 2 + width] = imm_b
        image[second + 2 : second + 2 + width] = imm_a
        seed_state = _fp_exchange_simulate(body, start, end, f"{item_context} seed")
        image_state = _fp_exchange_simulate(bytes(image), start, end, f"{item_context} image")
        seed_regs, seed_stack, seed_flags = seed_state
        image_regs, image_stack, image_flags = image_state
        require(
            seed_stack == image_stack,
            f"{item_context}: the two versions leave different FP stacks -- the exchange is not a reassociation of one sum",
        )
        if seed_flags != image_flags:
            require(end in walk_index, f"{item_context}: the region end is not a flow boundary")
            live_flags = flag_live[walk_index[end]]
            require(
                not live_flags,
                f"{item_context}: the two versions leave different flag state and {sorted(live_flags)} is live at the exit",
            )
        differing = sorted(
            (name for name in _SIMULATOR_REGS if seed_regs[name] != image_regs[name])
        )
        declared_dead = item["dead_registers"]
        require(
            differing == sorted(declared_dead),
            f"{item_context}: the registers left differing {differing} are not the declared dead set {sorted(declared_dead)}",
        )
        require(
            end in exit_index or end == len(body),
            f"{item_context}: the region end is not an instruction boundary of the body",
        )
        if end in exit_index:
            live_in = live[exit_index[end]]
            for name in declared_dead:
                overlap = _IA32_ATOMS_OF[name] & live_in
                require(
                    not overlap,
                    f"{item_context}: {name} is live on the region's exit edge ({sorted(overlap)})",
                )
        proved.append(
            {
                "region_start": start,
                "region_end": end,
                "swap_offsets": [first, second],
                "immediate_width": width,
                "dead_registers": sorted(declared_dead),
                "rewritten_offsets": sorted(
                    (offset for offset in range(start, end) if body[offset] != image[offset])
                ),
            }
        )
    image = bytes(image)
    require(image != body, f"{context}: the image does not move the body")
    changed = {offset for offset in range(len(body)) if body[offset] != image[offset]}
    declared = {offset for item in proved for offset in item["rewritten_offsets"]}
    require(
        changed <= declared, f"{context}: the image changed a byte outside the declared exchanges"
    )
    return (image, {"kind": FP_POINTER_EXCHANGE_KIND, "exchanges": proved})


SIMULATED_REGION_REWRITE_KIND = "simulated_region_rewrite_v1"


def _srr_simulate(
    body: bytes,
    start: int,
    end: int,
    context: str,
    relocations: dict | None = None,
    oracles: dict | None = None,
    entry_loads: dict | None = None,
):
    """Symbolically execute [start, end); return the end state.

    `relocations` maps a byte offset (of a relocated field inside the
    executed bytes) to its target symbol, so a relocated immediate reads as
    the SYMBOL rather than its raw bytes and two versions that name the same
    target through different encodings still compare equal.  `oracles`, when
    present, carries verified callee bodies ({"callees": {symbol: bytes}})
    and vtable slot maps ({"vtables": {symbol: {slot: symbol}}}); a direct
    call whose relocation names an oracle callee -- or an indirect call
    through a register holding an oracle vtable symbol -- is executed by
    stepping INTO the callee's own bytes, so the region's proof carries the
    callee's real effect instead of an assumption about it.  Everything
    outside the closed set still refuses.
    """
    relocations = relocations or {}
    oracles = oracles or {}
    oracle_callees = oracles.get("callees") or {}
    oracle_vtables = oracles.get("vtables") or {}
    regs = {name: ("reg0", name) for name in _SIMULATOR_REGS}
    for name, disp in (entry_loads or {}).items():
        regs[name] = ("load", ("addr", ("reg0", "ebp"), disp))
    stack = []
    pushes = []
    slots = {}
    widths = {}
    heap_slots = {}
    heap_base = [None]
    last_flags = None
    frames = []
    cur_body, offset, cur_end = (body, start, end)
    reloc_base = 0
    reloc_maps = [relocations]

    def norm_isub(left, right):
        if isinstance(left, tuple) and left[0] == "isub":
            base, parts = (left[1], left[2])
        else:
            base, parts = (left, ())
        return ("isub", base, tuple(sorted(parts + (right,), key=repr)))

    def norm_iadd(left, right):
        parts = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "iadd":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("iadd", tuple(sorted(parts, key=repr)))

    def norm_sum(left, right):
        parts = []
        for item in (left, right):
            if isinstance(item, tuple) and item[0] == "fsum":
                parts.extend(item[1])
            else:
                parts.append(item)
        return ("fsum", tuple(sorted(parts, key=repr)))

    def flatten_add(value):
        total = 0
        while isinstance(value, tuple) and value[0] == "add" and isinstance(value[2], int):
            total += value[2]
            value = value[1]
        return (value, total)

    def frame_address(value):
        base, extra = flatten_add(value)
        if isinstance(base, tuple) and base[0] == "lea":
            addr = base[1]
            if addr[1] == ("reg0", "ebp") and isinstance(addr[2], int):
                return addr[2] + extra
        return None

    while True:
        if offset >= cur_end:
            require(
                offset == cur_end, f"{context}: the region does not end on an instruction boundary"
            )
            require(
                not frames, f"{context}: an inlined callee runs past its body without returning"
            )
            intervals = sorted(((key, key + widths[key]) for key in slots if isinstance(key, int)))
            for former, latter in zip(intervals, intervals[1:]):
                require(
                    former[1] <= latter[0],
                    f"{context}: the frame stores at {former[0]:#x} and {latter[0]:#x} overlap; the slot map cannot represent their order",
                )
            break
        length = supported_ia32_instruction_length(cur_body[offset:], context)
        require(
            offset + length <= cur_end,
            f"{context}: an instruction straddles the region boundary at {offset}",
        )
        encoded = cur_body[offset : offset + length]
        op = encoded[0]
        modrm = encoded[1] if length >= 2 else None
        mod = modrm >> 6 if modrm is not None else None
        reg_field = modrm >> 3 & 7 if modrm is not None else None
        rm = modrm & 7 if modrm is not None else None
        cur_relocs = reloc_maps[-1]

        def reloc_symbol(field_offset):
            entry = cur_relocs.get(reloc_base + field_offset)
            if entry is None:
                return None
            return entry["target"] if isinstance(entry, dict) else entry

        def mem_operand(cursor_base):
            require(not (mod == 0 and rm == 5), f"{context}: absolute address at {offset}")
            cursor = cursor_base
            if rm == 4:
                sib = encoded[cursor]
                cursor += 1
                require(
                    sib >> 3 & 7 == 4 and sib >> 6 == 0,
                    f"{context}: an indexed SIB at {offset} is outside the simulator set",
                )
                base = regs[_SIMULATOR_REGS[sib & 7]]
            else:
                base = regs[_SIMULATOR_REGS[rm]]
            if mod == 1:
                disp = int.from_bytes(encoded[cursor : cursor + 1], "little", signed=True)
            elif mod == 2:
                disp = int.from_bytes(encoded[cursor : cursor + 4], "little", signed=True)
            else:
                disp = 0
            if isinstance(base, tuple) and base[0] == "add" and isinstance(base[2], int):
                return ("addr", base[1], disp + base[2])
            return ("addr", base, disp)

        def frame_disp(addr):
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp"):
                require(
                    addr[2] >= 0,
                    f"{context}: an esp store below the region-entry stack pointer at {offset} aliases the push sequence",
                )
                return ("esp", addr[2])
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def heap_key(addr):
            """The single-base heap map's key, or None for a frame address.

            Non-frame stores are admitted under two invariants the emitting
            compiler itself relies on: (a) every non-frame access in one
            region goes through ONE common symbolic base, so two keys with
            different displacements name provably different bytes, and
            (b) the compiler's own esp/ebp frame addressing is private --
            no indirect pointer aliases it -- which is exactly the license
            MSVC uses to reorder its own spill traffic around such stores.
            A second, different non-frame base in the same region refuses.
            """
            if frame_disp_quiet(addr) is not None:
                return None
            base = addr[1]
            if heap_base[0] is None:
                heap_base[0] = base
            require(
                base == heap_base[0],
                f"{context}: a second non-frame base at {offset} leaves the single-base heap set",
            )
            return addr[2]

        def frame_disp_quiet(addr):
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp") and addr[2] >= 0:
                return ("esp", addr[2])
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def heap_store(addr, value, width):
            key = heap_key(addr)
            for other, (_, other_width) in heap_slots.items():
                if other == key:
                    continue
                require(
                    key + width <= other or other + other_width <= key,
                    f"{context}: overlapping heap stores at {offset}",
                )
            require(
                heap_slots.get(key, (None, width))[1] == width,
                f"{context}: the heap store at {offset} resizes a slot",
            )
            heap_slots[key] = (value, width)

        def heap_load(addr, width):
            key = heap_key(addr)
            held = heap_slots.get(key)
            if held is not None and held[1] == width:
                return held[0]
            return None

        def read_disp(addr):
            if addr[1] == ("reg0", "ebp"):
                return addr[2]
            if addr[1] == ("reg0", "esp"):
                return ("esp", addr[2]) if addr[2] >= 0 else None
            pointed = frame_address(addr[1])
            if pointed is not None:
                return pointed + addr[2]
            return None

        def read_slot(addr):
            disp = read_disp(addr)
            if disp is not None and disp in slots:
                return slots[disp]
            return None

        def resolve_pushed(addr):
            base, extra = flatten_add(regs["esp"])
            if base != ("reg0", "esp") or addr[1] != ("reg0", "esp"):
                return None
            if addr[2] >= 0 or addr[2] % 4 != 0:
                return None
            index = -(addr[2] // 4) - 1
            if 0 <= index < len(pushes):
                return pushes[index]
            return None

        def do_push(value):
            pushes.append(value)
            esp = regs["esp"]
            if isinstance(esp, tuple) and esp[0] == "add" and isinstance(esp[2], int):
                regs["esp"] = ("add", esp[1], esp[2] - 4)
            else:
                regs["esp"] = ("add", esp, -4)

        def enter_callee(symbol):
            callee = oracle_callees.get(symbol)
            require(
                callee is not None,
                f"{context}: the call at {offset} names '{symbol}', which no verified callee oracle covers",
            )
            require(len(frames) < 4, f"{context}: callee inlining exceeds the depth bound")
            do_push(("return_to", len(frames), offset + length))
            frames.append((cur_body, offset + length, cur_end, reloc_base))
            reloc_maps.append((oracles.get("callee_relocations") or {}).get(symbol, {}))
            return callee

        advanced = False
        if op == 139 and mod != 3:
            addr = mem_operand(2)
            pushed = resolve_pushed(addr)
            forwarded = read_slot(addr) if pushed is None else None
            if forwarded is not None:
                regs[_SIMULATOR_REGS[reg_field]] = forwarded
            elif pushed is not None:
                regs[_SIMULATOR_REGS[reg_field]] = pushed
            elif heap_slots and frame_disp_quiet(addr) is None:
                held = heap_load(addr, 4)
                regs[_SIMULATOR_REGS[reg_field]] = held if held is not None else ("load", addr)
            else:
                regs[_SIMULATOR_REGS[reg_field]] = ("load", addr)
        elif op in (139, 137) and mod == 3:
            if op == 139:
                regs[_SIMULATOR_REGS[reg_field]] = regs[_SIMULATOR_REGS[rm]]
            else:
                regs[_SIMULATOR_REGS[rm]] = regs[_SIMULATOR_REGS[reg_field]]
        elif op == 137 and mod != 3:
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            if disp is None:
                heap_store(addr, regs[_SIMULATOR_REGS[reg_field]], 4)
            else:
                require(
                    widths.get(disp, 4) == 4, f"{context}: the store at {offset} resizes a slot"
                )
                slots[disp] = regs[_SIMULATOR_REGS[reg_field]]
                widths[disp] = 4
        elif op == 138 and mod != 3:
            addr = mem_operand(2)
            disp = read_disp(addr)
            forwarded = slots.get(disp) if disp is not None and widths.get(disp) == 1 else None
            name = _SIMULATOR_REGS[reg_field & 3]
            value = forwarded if forwarded is not None else ("load8", addr)
            regs[name] = ("setbyte", regs[name], reg_field >> 2, value)
        elif op == 136 and mod != 3:
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            if disp is None:
                heap_store(addr, ("byte", regs[_SIMULATOR_REGS[reg_field & 3]], reg_field >> 2), 1)
            else:
                require(
                    widths.get(disp, 1) == 1,
                    f"{context}: the byte store at {offset} resizes a slot",
                )
                slots[disp] = ("byte", regs[_SIMULATOR_REGS[reg_field & 3]], reg_field >> 2)
                widths[disp] = 1
        elif 184 <= op <= 191:
            require(
                length == 5,
                f"{context}: an operand-size-prefixed immediate move at {offset} is outside the simulator set",
            )
            symbol = reloc_symbol(offset + 1)
            regs[_SIMULATOR_REGS[op - 184]] = (
                ("sym", symbol)
                if symbol is not None
                else ("imm", int.from_bytes(encoded[1:5], "little"))
            )
        elif op == 199 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            imm_at = length - 4
            symbol = reloc_symbol(offset + imm_at)
            value = (
                ("sym", symbol)
                if symbol is not None
                else ("imm", bytes(encoded[imm_at : imm_at + 4]))
            )
            if disp is None:
                heap_store(addr, value, 4)
            else:
                require(
                    widths.get(disp, 4) == 4, f"{context}: the store at {offset} resizes a slot"
                )
                slots[disp] = value
                widths[disp] = 4
        elif op == 198 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp_quiet(addr)
            value = ("imm8", encoded[length - 1])
            if disp is None:
                heap_store(addr, value, 1)
            else:
                require(
                    widths.get(disp, 1) == 1,
                    f"{context}: the byte store at {offset} resizes a slot",
                )
                slots[disp] = value
                widths[disp] = 1
        elif op == 141 and mod != 3:
            regs[_SIMULATOR_REGS[reg_field]] = ("lea", mem_operand(2))
        elif op == 131 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame read-modify-write at {offset} is outside the simulator set",
            )
            require(widths.get(disp, 4) == 4, f"{context}: the add at {offset} resizes a slot")
            current = slots.get(disp, ("load", addr))
            value = int.from_bytes(encoded[length - 1 : length], "little", signed=True)
            slots[disp] = norm_iadd(current, value)
            widths[disp] = 4
            last_flags = ("addflags", slots[disp])
        elif op == 255 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame increment at {offset} is outside the simulator set",
            )
            require(
                widths.get(disp, 4) == 4, f"{context}: the increment at {offset} resizes a slot"
            )
            current = slots.get(disp, ("load", addr))
            slots[disp] = norm_iadd(current, 1)
            widths[disp] = 4
            last_flags = ("incflags", slots[disp])
        elif op == 131 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:3], "little", signed=True)
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("add", regs[name], value)
            last_flags = ("addflags", regs[name])
        elif op == 129 and mod == 3 and (reg_field == 0):
            value = int.from_bytes(encoded[2:6], "little", signed=True)
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("add", regs[name], value)
            last_flags = ("addflags", regs[name])
        elif op == 133 and mod == 3:
            last_flags = ("test", regs[_SIMULATOR_REGS[rm]], regs[_SIMULATOR_REGS[reg_field]])
        elif op == 128 and mod != 3 and (reg_field == 7):
            last_flags = ("cmp8", mem_operand(2), encoded[length - 1])
        elif op == 131 and mod != 3 and (reg_field == 7):
            addr = mem_operand(2)
            left = read_slot(addr)
            last_flags = (
                "cmp",
                left if left is not None else ("load", addr),
                ("imm", int.from_bytes(encoded[length - 1 : length], "little", signed=True)),
            )
        elif op == 57 and mod == 3:
            last_flags = ("cmp", regs[_SIMULATOR_REGS[rm]], regs[_SIMULATOR_REGS[reg_field]])
        elif op == 57 and mod != 3:
            addr = mem_operand(2)
            left = read_slot(addr)
            last_flags = (
                "cmp",
                left if left is not None else ("load", addr),
                regs[_SIMULATOR_REGS[reg_field]],
            )
        elif op == 59 and mod == 3:
            last_flags = ("cmp", regs[_SIMULATOR_REGS[reg_field]], regs[_SIMULATOR_REGS[rm]])
        elif op == 59 and mod != 3:
            addr = mem_operand(2)
            right = read_slot(addr)
            last_flags = (
                "cmp",
                regs[_SIMULATOR_REGS[reg_field]],
                right if right is not None else ("load", addr),
            )
        elif op == 43 and mod != 3:
            name = _SIMULATOR_REGS[reg_field]
            regs[name] = norm_isub(regs[name], ("load", mem_operand(2)))
            last_flags = ("subflags", regs[name])
        elif op == 43 and mod == 3:
            name = _SIMULATOR_REGS[reg_field]
            regs[name] = norm_isub(regs[name], regs[_SIMULATOR_REGS[rm]])
            last_flags = ("subflags", regs[name])
        elif 64 <= op <= 71:
            name = _SIMULATOR_REGS[op - 64]
            regs[name] = ("add", regs[name], 1)
            last_flags = ("incflags", regs[name])
        elif 72 <= op <= 79:
            name = _SIMULATOR_REGS[op - 72]
            regs[name] = norm_iadd(regs[name], -1)
            last_flags = ("decflags", regs[name])
        elif op == 3 and mod == 3:
            name = _SIMULATOR_REGS[reg_field]
            regs[name] = norm_iadd(regs[name], regs[_SIMULATOR_REGS[rm]])
            last_flags = ("addflags", regs[name])
        elif op == 3 and mod != 3:
            name = _SIMULATOR_REGS[reg_field]
            regs[name] = norm_iadd(regs[name], ("load", mem_operand(2)))
            last_flags = ("addflags", regs[name])
        elif op == 51 and mod == 3 and (reg_field == rm):
            name = _SIMULATOR_REGS[reg_field]
            regs[name] = ("imm", 0)
            last_flags = ("zeroflags",)
        elif op == 193 and mod == 3 and (reg_field == 4):
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("shl", regs[name], encoded[length - 1])
            last_flags = ("shlflags", regs[name])
        elif op == 193 and mod == 3 and (reg_field == 5):
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("shr", regs[name], encoded[length - 1])
            last_flags = ("shrflags", regs[name])
        elif op == 193 and mod == 3 and (reg_field == 7):
            name = _SIMULATOR_REGS[rm]
            regs[name] = ("sar", regs[name], encoded[length - 1])
            last_flags = ("sarflags", regs[name])
        elif 80 <= op <= 87:
            do_push(regs[_SIMULATOR_REGS[op - 80]])
        elif op == 106:
            do_push(("imm", int.from_bytes(encoded[1:2], "little", signed=True)))
        elif op == 104:
            symbol = reloc_symbol(offset + 1)
            do_push(
                ("sym", symbol)
                if symbol is not None
                else ("imm", int.from_bytes(encoded[1:5], "little"))
            )
        elif op == 232:
            symbol = reloc_symbol(offset + 1)
            require(
                symbol is not None,
                f"{context}: a direct call at {offset} carries no relocation to name its target",
            )
            callee = enter_callee(symbol)
            cur_body, offset, cur_end = (callee, 0, len(callee))
            reloc_base = 0
            advanced = True
        elif op == 255 and mod != 3 and (reg_field == 2):
            operand = mem_operand(2)
            base_probe, extra_probe = flatten_add(operand[1])
            covered = (
                isinstance(base_probe, tuple)
                and base_probe[0] == "sym"
                and (base_probe[1] in oracle_vtables)
            )
            if not covered and offset + length == cur_end and (not frames):
                last_flags = ("terminal_call", operand, tuple(pushes))
                for name in ("eax", "ecx", "edx"):
                    regs[name] = ("call_clobber", name)
                regs["esp"] = ("call_balanced", regs["esp"])
            else:
                base_value, extra = flatten_add(operand[1])
                slot = operand[2] + extra
                require(
                    isinstance(base_value, tuple)
                    and base_value[0] == "sym"
                    and (base_value[1] in oracle_vtables),
                    f"{context}: the indirect call at {offset} does not dispatch through a verified vtable oracle",
                )
                table = oracle_vtables[base_value[1]]
                target = table.get(slot) or table.get(str(slot))
                require(
                    target is not None,
                    f"{context}: vtable slot {slot} of '{base_value[1]}' has no verified target",
                )
                callee = enter_callee(target)
                cur_body, offset, cur_end = (callee, 0, len(callee))
                reloc_base = 0
                advanced = True
        elif op in (194, 195):
            require(frames, f"{context}: a return at {offset} outside any inlined callee")
            popped = int.from_bytes(encoded[1:3], "little") if op == 194 else 0
            require(popped % 4 == 0, f"{context}: the callee pops a non-dword argument size")
            count = popped // 4 + 1
            require(
                len(pushes) >= count, f"{context}: the callee at {offset} pops more than was pushed"
            )
            ret_slot = pushes[-1]
            require(
                isinstance(ret_slot, tuple) and ret_slot[0] == "return_to",
                f"{context}: the callee's return slot was overwritten",
            )
            del pushes[-count:]
            base_value, extra = flatten_add(regs["esp"])
            new_extra = extra + 4 * count
            regs["esp"] = base_value if new_extra == 0 else ("add", base_value, new_extra)
            cur_body, ret_offset, cur_end, reloc_base = frames.pop()
            reloc_maps.pop()
            require(
                ret_slot[1] == len(frames) and ret_slot[2] == ret_offset,
                f"{context}: the callee returns somewhere else than its call site",
            )
            offset = ret_offset
            advanced = True
        elif op == 217 and mod != 3 and (reg_field == 0):
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack.append(forwarded if forwarded is not None else ("load32", addr))
        elif op == 217 and mod != 3 and (reg_field == 3):
            require(stack, f"{context}: fstp at {offset} pops the unknown stack base")
            addr = mem_operand(2)
            disp = frame_disp(addr)
            require(
                disp is not None,
                f"{context}: a non-frame fstp at {offset} is outside the simulator set",
            )
            require(widths.get(disp, 4) == 4, f"{context}: the fstp at {offset} resizes a slot")
            slots[disp] = ("f32", stack.pop())
            widths[disp] = 4
        elif op == 217 and mod == 3 and (encoded[:2] == b"\xd9\xfa"):
            require(stack, f"{context}: fsqrt at {offset} reads the unknown stack base")
            stack[-1] = ("fsqrt", stack[-1])
        elif op == 216 and mod != 3 and (reg_field == 0):
            require(stack, f"{context}: fadd at {offset} adds to the unknown stack base")
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = norm_sum(
                stack[-1], forwarded if forwarded is not None else ("load32", addr)
            )
        elif op == 216 and mod != 3 and (reg_field == 4):
            require(stack, f"{context}: fsub at {offset} subtracts from the unknown stack base")
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = (
                "fsub",
                stack[-1],
                forwarded if forwarded is not None else ("load32", addr),
            )
        elif op == 216 and mod != 3 and (reg_field == 1):
            require(stack, f"{context}: fmul at {offset} multiplies the unknown stack base")
            addr = mem_operand(2)
            forwarded = read_slot(addr)
            stack[-1] = (
                "fmul",
                stack[-1],
                forwarded if forwarded is not None else ("load32", addr),
            )
        elif op == 221 and mod != 3 and (reg_field == 0):
            stack.append(("load64", mem_operand(2)))
        elif op == 220 and mod != 3 and (reg_field == 1):
            require(stack, f"{context}: fmul at {offset} multiplies the unknown stack base")
            stack[-1] = ("fmul", stack[-1], ("load64", mem_operand(2)))
        elif encoded == b"\xde\xc1":
            require(len(stack) >= 2, f"{context}: faddp at {offset} reaches the unknown stack base")
            right = stack.pop()
            stack[-1] = norm_sum(stack[-1], right)
        else:
            require(
                False,
                f"{context}: the instruction at {offset} is outside the simulator's closed set",
            )
        if not advanced:
            offset += length
    return (regs, stack, pushes, slots, last_flags, heap_base[0], heap_slots)


def _srr_slot_scratch_proof(
    decoded: list,
    items: list,
    successors: list,
    entries: list,
    exit_offset: int,
    disp: int,
    context: str,
    body_bytes: bytes = b"",
) -> None:
    """R5: [ebp+disp] is written before read on every path from the exit,
    and its address is never taken anywhere in the body."""
    lea_offsets = set()
    for item in decoded:
        if item["opcode"] != 141:
            continue
        enc = item.get("encoding") or {}
        if (
            enc.get("mode") not in (1, 2)
            or enc.get("rm") != 5
            or enc.get("sib_at") is not None
            or enc.get("absolute")
        ):
            continue
        at, size = (enc["displacement_at"], enc["displacement_size"])
        lea_disp = int.from_bytes(body_bytes[at : at + size], "little", signed=True)
        if lea_disp == disp:
            lea_offsets.add(item["offset"])
    index_of = {item["offset"]: index for index, item in enumerate(items)}
    require(exit_offset in index_of, f"{context}: the region exit is not a flow boundary")
    decoded_at = {item["offset"]: item for item in decoded}
    seen = set()
    frontier = [index_of[exit_offset]]
    while frontier:
        index = frontier.pop()
        if index in seen:
            continue
        seen.add(index)
        item = items[index]
        require(
            item["offset"] not in lea_offsets,
            f"{context}: the scratch slot's address is taken at {item['offset']} before any write",
        )
        info = decoded_at.get(item["offset"])
        if info is not None:
            mem = info.get("memory")
            if mem and mem.get("base") == "ebp" and (mem.get("displacement") in (disp, disp - 4)):
                covers = mem.get("displacement") == disp or mem.get("width", 0) >= 8
                if covers:
                    opcode = info["opcode"]
                    enc = info.get("encoding") or {}
                    reg = enc.get("reg")
                    if opcode == 217 and reg in (2, 3):
                        kills = mem.get("displacement") == disp
                    elif opcode == 221 and reg in (2, 3):
                        kills = True
                    elif opcode in (216, 220, 217, 221, 219, 223, 218, 222):
                        kills = False
                    else:
                        kills = (
                            mem.get("write")
                            and (not mem.get("read"))
                            and (mem.get("width") == 4)
                            and (mem.get("displacement") == disp)
                        )
                    if kills:
                        continue
                    require(
                        False,
                        f"{context}: the scratch slot is read at {item['offset']} before any write",
                    )
        for edge in successors[index]:
            if edge not in seen:
                frontier.append(edge)
        if item["flow"] in ("ret", "exit"):
            continue


def apply_simulated_region_rewrite(
    body: bytes,
    regions: list,
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
    external_entries: frozenset | None = None,
    internal_targets: frozenset | None = None,
) -> tuple[bytes, dict]:
    """Apply declared permutation+field rewrites, proved by simulation."""
    require_payload_free_declaration(regions, f"{context} simulated-region declaration")
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(regions, list) and regions, f"{context}: no region is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    flag_live = ia32_relational_flag_liveness(items, successors, context)
    walk_index = {item["offset"]: index for index, item in enumerate(items)}
    decoded = decode_ia32_bijection_body(body, f"{context} liveness", relocations, code_length)
    refined = []
    for entry in decoded:
        if entry["flow"] == "call" and entry["opcode"] == 255:
            entry = {**entry, "read_atoms": frozenset(entry["read_atoms"]) - _IA32_ATOMS_OF["eax"]}
        refined.append(entry)
    live, _succ = _register_bijection_live_sets(refined, f"{context} liveness")
    exit_index = {item["offset"]: index for index, item in enumerate(decoded)}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, item in enumerate(regions):
        item_context = f"{context} region {ordinal}"
        start, end = (item["region_start"], item["region_end"])
        require(
            type(start) is int and type(end) is int and (0 < start < end <= len(body)),
            f"{item_context}: bounds are out of range",
        )
        require(previous_end <= start, f"{item_context}: regions are unsorted or overlapping")
        previous_end = end
        require(
            not any((start < target < end for target in branch_targets)),
            f"{item_context}: a branch targets the region interior",
        )
        require(
            not any((start < items[entry]["offset"] < end for entry in entries[1:])),
            f"{item_context}: an external entry lies inside the region",
        )
        require(
            not any((start < target < end for target in internal_targets or frozenset())),
            f"{item_context}: a relocated target lies inside the region",
        )
        pieces = []
        offset = start
        while offset < end:
            length = supported_ia32_instruction_length(body[offset:], item_context)
            require(offset + length <= end, f"{item_context}: an instruction straddles the region")
            pieces.append((offset, bytes(body[offset : offset + length])))
            offset += length
        order = item["target_order"]
        require(
            isinstance(order, list) and sorted(order) == list(range(len(pieces))),
            f"{item_context}: the order is not a permutation of the {len(pieces)} instructions",
        )
        rewrites = {}
        for rewrite in item.get("field_rewrites") or []:
            index, field_ordinal, register = rewrite
            require(
                type(index) is int
                and 0 <= index < len(pieces)
                and (type(field_ordinal) is int)
                and (register in _IA32_REGISTER_NUMBERS)
                and (register not in ("esp", "ebp")),
                f"{item_context}: field rewrite {rewrite} is invalid",
            )
            rewrites.setdefault(index, []).append((field_ordinal, register))
        rebuilt = []
        cursor = start
        moved_offsets = {}
        region_reseat = []
        for position, source_index in enumerate(order):
            source_offset, encoded = pieces[source_index]
            carried = [
                offs
                for offs in range(source_offset, source_offset + len(encoded))
                if offs in relocation_offsets
            ]
            if carried and cursor != source_offset:
                starts = sorted({offs - (offs - source_offset) % 1 for offs in carried})
                heads = sorted({offs for offs in carried})
                for offs in heads:
                    if offs - 1 in carried:
                        continue
                    region_reseat.append([offs, cursor + (offs - source_offset)])
            if source_index in rewrites:
                info = decode_ia32_bijection_instruction(
                    body, source_offset, item_context, relocations
                )
                fields = info["fields"]
                mutable = bytearray(encoded)
                for field_ordinal, register in rewrites[source_index]:
                    require(
                        0 <= field_ordinal < len(fields),
                        f"{item_context}: instruction {source_index} has no field {field_ordinal}",
                    )
                    byte_at, shift = fields[field_ordinal]
                    local = byte_at - source_offset
                    mutable[local] = (
                        mutable[local] & ~(7 << shift) | _IA32_REGISTER_NUMBERS[register] << shift
                    )
                encoded = bytes(mutable)
            moved_offsets[pieces[source_index][0]] = cursor
            rebuilt.append(encoded)
            cursor += len(encoded)
        rebuilt = b"".join(rebuilt)
        require(len(rebuilt) == end - start, f"{item_context}: the permuted region changed length")
        image[start:end] = rebuilt
        seed_state = _srr_simulate(body, start, end, f"{item_context} seed")
        image_state = _srr_simulate(bytes(image), start, end, f"{item_context} image")
        for label, seed_part, image_part in (
            ("FP stack", seed_state[1], image_state[1]),
            ("push sequence", seed_state[2], image_state[2]),
        ):
            require(
                seed_part == image_part,
                f"{item_context}: the two versions leave a different {label}",
            )
        seed_slots, image_slots = (seed_state[3], image_state[3])
        dead_slots = item.get("dead_slots") or []
        require(
            isinstance(dead_slots, list) and all((type(d) is int for d in dead_slots)),
            f"{item_context}.dead_slots is invalid",
        )
        require(
            set(seed_slots) == set(image_slots),
            f"{item_context}: the two versions write different frame slots",
        )
        differing_slots = sorted((d for d in seed_slots if seed_slots[d] != image_slots[d]))
        require(
            differing_slots == sorted(dead_slots),
            f"{item_context}: the slots left differing {differing_slots} are not the declared dead set {sorted(dead_slots)}",
        )
        seed_flags, image_flags = (seed_state[4], image_state[4])
        if seed_flags != image_flags:
            require(
                end in walk_index and (not flag_live[walk_index[end]]),
                f"{item_context}: the two versions leave different flag state and a flag is live at the exit",
            )
        differing = sorted(
            (name for name in _SIMULATOR_REGS if seed_state[0][name] != image_state[0][name])
        )
        declared_dead = item.get("dead_registers") or []
        require(
            differing == sorted(declared_dead),
            f"{item_context}: the registers left differing {differing} are not the declared dead set {sorted(declared_dead)}",
        )
        require(
            end in exit_index,
            f"{item_context}: the region end is not an instruction boundary of the body",
        )
        live_in = live[exit_index[end]]
        for name in declared_dead:
            overlap = _IA32_ATOMS_OF[name] & live_in
            require(
                not overlap,
                f"{item_context}: {name} is live on the region's exit edge ({sorted(overlap)})",
            )
        for disp in dead_slots:
            _srr_slot_scratch_proof(
                decoded,
                items,
                successors,
                entries,
                end,
                disp,
                f"{item_context} slot {disp:#x}",
                body,
            )
        proved.append(
            {
                "region_start": start,
                "region_end": end,
                "target_order": list(order),
                "field_rewrites": [
                    [index, ordinal, register]
                    for index, pairs in sorted(rewrites.items())
                    for ordinal, register in pairs
                ],
                "dead_registers": sorted(declared_dead),
                "dead_slots": sorted(dead_slots),
                "relocation_reseat": sorted(region_reseat),
                "instruction_moves": sorted(
                    ([old, new] for old, new in moved_offsets.items() if old != new)
                ),
                "rewritten_offsets": sorted(
                    (offs for offs in range(start, end) if body[offs] != image[offs])
                ),
            }
        )
    image = bytes(image)
    require(image != body, f"{context}: the image does not move the body")
    changed = {offs for offs in range(len(body)) if body[offs] != image[offs]}
    declared = {offs for region in proved for offs in region["rewritten_offsets"]}
    require(
        changed <= declared, f"{context}: the image changed a byte outside the declared regions"
    )
    return (
        image,
        {
            "kind": SIMULATED_REGION_REWRITE_KIND,
            "regions": proved,
            "relocation_reseat": sorted(
                (pair for region in proved for pair in region["relocation_reseat"])
            ),
        },
    )
