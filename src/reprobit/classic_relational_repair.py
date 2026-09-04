"""Repair-only authoring of a relational donor-rewriting record."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from itertools import pairwise
from typing import Any, cast

from pydantic import ValidationError

from reprobit.binary import ByteIdentityError
from reprobit.classic.candidate_recipe import (
    internal_relocation_targets,
    relocated_byte_offsets,
    relocation_symbol_map,
)
from reprobit.classic.coff import (
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from reprobit.classic.composition_mosaic import instruction_mosaic_metadata_sha256
from reprobit.classic.relational import (
    IA32_CONDITION_CODES,
    IA32_CONDITION_NAMES,
    IA32_RELATIONAL_COMPARE_PAIRS,
    IA32_RELATIONAL_MIRROR,
    apply_relational_form,
    ia32_relational_flow_walk,
    relational_form_external_entries,
)
from reprobit.classic.rewriting_certificates import DONOR_REWRITING_KIND
from reprobit.classic.scheduling_certificates import (
    measure_instruction_schedule_debug_envelope,
)
from reprobit.classic_donors import DonorSourceError
from reprobit.classic_measured_pin_repair import (
    MeasuredPinRepair,
    MeasuredPinRepairError,
    repair_measured_pins,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_retail_repair import (
    RetailRepairError,
    refresh_retail_relocations,
    retail_body_goal_digest,
    retail_oracle_span,
)
from reprobit.coff_format import (
    CoffObject,
    Relocation,
    coff_body,
    detailed_relocations,
    section_definitions,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue, canonical_json

_MAX_BODY_BYTES = 64 * 1024
_MAX_SITES = 64
_AUTHENTICITY_RATIONALE = (
    "Fresh compiler output differs from the sealed retail body only by proved mirrored "
    "comparisons whose operand order is reversed."
)
_INTERVENTION_RATIONALE = (
    "Fresh compiler output is rewritten through bounded mirrored comparisons to reproduce "
    "the saved retail body."
)


class RelationalRepairError(RuntimeError):
    """Fresh compiler output cannot safely author a relational rewrite."""


@dataclass(frozen=True, slots=True)
class RelationalDonorReauthoring:
    """A deterministic replacement accepted by the ordinary family dispatcher."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    measured: MeasuredPinRepair


def _stable_id(kind: str, material: object) -> str:
    return f"discovery.{kind}.{Digest.from_bytes(canonical_json(material)).value[:16]}"


def _matches_target(
    body: bytes,
    target: bytes,
    transformed: bytearray,
    offsets: tuple[int, int],
) -> bool:
    return any(body[offset] != target[offset] for offset in offsets) and all(
        transformed[offset] == target[offset] for offset in offsets
    )


def derive_relational_sites(
    body: bytes,
    target: bytes,
    relocations: Sequence[Relocation] = (),
    *,
    external_entries: frozenset[int] = frozenset(),
) -> tuple[list[dict[str, JsonValue]], dict[str, Any]]:
    """Derive only cmp+jcc operand mirrors that reproduce ``target`` exactly."""

    if (
        type(body) is not bytes
        or type(target) is not bytes
        or not body
        or len(body) != len(target)
        or len(body) > _MAX_BODY_BYTES
    ):
        raise RelationalRepairError("relational repair requires equal finite body lengths")
    if body == target:
        raise RelationalRepairError("relational repair would not change the donor body")
    rows = list(relocations)
    relocation_offsets = relocated_byte_offsets(rows)
    relocation_symbols = relocation_symbol_map(rows)
    try:
        items, _successors, _entries = ia32_relational_flow_walk(
            body,
            relocation_symbols,
            "relational repair discovery",
            external_entries=external_entries,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise RelationalRepairError(f"cannot decode the relational donor: {exc}") from exc

    sites: list[dict[str, JsonValue]] = []
    proof_sites: list[dict[str, JsonValue]] = []
    for compare, branch in pairwise(items):
        opcode = compare["opcode"]
        condition = branch["condition"]
        if (
            opcode not in IA32_RELATIONAL_COMPARE_PAIRS
            or branch["flow"] != "jcc"
            or condition is None
        ):
            continue
        seed_condition = IA32_CONDITION_NAMES[condition]
        image_condition = IA32_RELATIONAL_MIRROR.get(seed_condition)
        if image_condition is None:
            continue
        compare_byte = cast(int, compare["opcode_at"])
        branch_byte = cast(int, branch["opcode_at"]) + (1 if branch["opcode"] >= 3840 else 0)
        choices: list[tuple[bool, tuple[int, int]]] = []

        ordinary = bytearray(body)
        ordinary[compare_byte] = IA32_RELATIONAL_COMPARE_PAIRS[opcode]
        ordinary[branch_byte] = ordinary[branch_byte] & 0xF0 | IA32_CONDITION_CODES[image_condition]
        ordinary_offsets = (compare_byte, branch_byte)
        if target[branch_byte] & 0x0F == IA32_CONDITION_CODES[image_condition] and _matches_target(
            body, target, ordinary, ordinary_offsets
        ):
            choices.append((False, ordinary_offsets))

        modrm_at = compare_byte + 1
        if modrm_at < compare["offset"] + compare["length"] and body[modrm_at] >> 6 == 3:
            reencoded = bytearray(body)
            modrm = body[modrm_at]
            reencoded[modrm_at] = modrm & 0xC0 | (modrm & 7) << 3 | modrm >> 3 & 7
            reencoded[branch_byte] = (
                reencoded[branch_byte] & 0xF0 | IA32_CONDITION_CODES[image_condition]
            )
            reencoded_offsets = (modrm_at, branch_byte)
            if target[branch_byte] & 0x0F == IA32_CONDITION_CODES[
                image_condition
            ] and _matches_target(body, target, reencoded, reencoded_offsets):
                choices.append((True, reencoded_offsets))

        if len(choices) != 1:
            continue
        reencode, offsets = choices[0]
        proof_site: dict[str, JsonValue] = {
            "branch_offset": cast(int, branch["offset"]),
            "compare_offset": cast(int, compare["offset"]),
            "image_condition": image_condition,
            "seed_condition": seed_condition,
        }
        if reencode:
            proof_site["reencode"] = True
        proof_sites.append(proof_site)
        sites.append(
            {
                **proof_site,
                "expected_rewritten_offsets": cast(list[JsonValue], sorted(offsets)),
            }
        )
        if len(sites) > _MAX_SITES:
            raise RelationalRepairError("relational repair exceeds the 64-site bound")

    if not sites:
        raise RelationalRepairError("no proved mirrored comparison reaches the retail body")
    try:
        image, proof = apply_relational_form(
            body,
            proof_sites,
            relocation_offsets,
            "relational repair",
            relocation_symbols,
            external_entries=external_entries,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError) as exc:
        raise RelationalRepairError(f"relational proof refused the candidate: {exc}") from exc
    if image != target:
        raise RelationalRepairError("proved relational mirrors leave uncovered retail differences")
    return sites, proof


def _relocation_identity(row: Relocation) -> tuple[Any, ...]:
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
        base, separator, serial = row["target"].rpartition("$S")
        if separator and base and serial.isdigit():
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


def _require_equal_relocation_semantics(
    seed_rows: Sequence[Relocation], donor_rows: Sequence[Relocation]
) -> None:
    if len(seed_rows) != len(donor_rows):
        raise RelationalRepairError("relational donor relocation count differs from the seed")
    for ordinal, (seed_row, donor_row) in enumerate(zip(seed_rows, donor_rows, strict=True)):
        if _relocation_identity(seed_row) != _relocation_identity(donor_row):
            raise RelationalRepairError(
                f"relational donor relocation target {ordinal} differs from the seed"
            )


def _donor_extras(seed: CoffObject, donor: CoffObject) -> tuple[list[str], int, int]:
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    extra_functions: list[str] = []
    for name in set(seed_functions) | set(donor_functions):
        left, right = seed_functions.get(name, 0), donor_functions.get(name, 0)
        if left == right:
            continue
        if right != left + 1:
            raise RelationalRepairError(f"relational donor function census diverges at {name}")
        extra_functions.append(name)

    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    extra_heads: list[str] = []
    for identity in set(seed_comdats) | set(donor_comdats):
        left, right = seed_comdats.get(identity, 0), donor_comdats.get(identity, 0)
        if left == right:
            continue
        if right != left + 1:
            raise RelationalRepairError(f"relational donor COMDAT census diverges at {identity[0]}")
        extra_heads.append(identity[0])
    if sorted(extra_functions) != sorted(extra_heads):
        raise RelationalRepairError("relational donor function and COMDAT extras disagree")
    return sorted(extra_functions), sum(seed_functions.values()), sum(seed_comdats.values())


def _parameter_sites(sites: Sequence[dict[str, JsonValue]]) -> list[JsonValue]:
    return [
        {name: value for name, value in site.items() if name != "expected_rewritten_offsets"}
        for site in sites
    ]


def _new_action(
    previous: ClassicRecipeIntervention,
    donor_id: str,
    program: dict[str, JsonValue],
    expected_values: dict[str, JsonValue],
) -> ClassicRecipeIntervention:
    intervention_id = _stable_id(
        "function",
        {
            "build_target": previous.build_target,
            "dependency": donor_id,
            "expected_values": expected_values,
            "family": ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING.value,
            "parameters": program,
            "scope": previous.scope.model_dump(mode="json"),
        },
    )
    return ClassicRecipeIntervention(
        id=intervention_id,
        scope=previous.scope,
        rationale=_INTERVENTION_RATIONALE,
        dependencies=(donor_id,),
        family=ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
        role=ClassicRecipeRole.FUNCTION,
        build_target=previous.build_target,
        symbol=previous.symbol,
        parameters=(ClassicField(name="donor_rewriting", value=program),),
    )


def _new_receipt(
    action: ClassicRecipeIntervention,
    expected_values: dict[str, JsonValue],
) -> ClassicProofReceipt:
    receipt_id = _stable_id(
        "proof",
        {
            "family": action.family.value,
            "intervention_id": action.id,
            "expected_values": expected_values,
        },
    )
    return ClassicProofReceipt(
        id=receipt_id,
        intervention_id=action.id,
        family=action.family,
        expected_values=dict(sorted(expected_values.items())),
    )


def reauthor_relational_donor_rewriting(
    previous: ClassicRecipeIntervention,
    previous_receipt: ClassicProofReceipt,
    materials: ClassicDispatchMaterials,
    retail_body: bytes,
    *,
    donor_id: str,
    donor_object: bytes,
    donor_source: bytes | None = None,
    shape_identifiers: frozenset[str] = frozenset(),
) -> RelationalDonorReauthoring:
    """Author and ordinarily dispatch one relational-only donor rewrite."""

    if (
        previous.role is not ClassicRecipeRole.FUNCTION
        or previous.symbol is None
        or previous.scope.translation_unit is None
        or type(materials.seed_object) is not bytes
        or not materials.seed_object
        or type(donor_object) is not bytes
        or not donor_object
        or type(retail_body) is not bytes
        or not retail_body
    ):
        raise RelationalRepairError("relational re-authoring requires one complete function record")
    try:
        goal = retail_body_goal_digest(previous, previous_receipt)
        retail_address, retail_length, retail_oracle = retail_oracle_span(previous_receipt)
        if retail_length != len(retail_body) or sha256(retail_body).hexdigest() != goal:
            raise RelationalRepairError("retail body differs from the saved immutable goal")

        seed = CoffObject(materials.seed_object)
        donor = CoffObject(donor_object)
        seed_section = seed.function_section(previous.symbol)
        donor_section = donor.function_section(previous.symbol)
        seed_body = bytes(coff_body(seed, seed_section))
        donor_body = bytes(coff_body(donor, donor_section))
        if len(donor_body) != len(retail_body):
            raise RelationalRepairError("relational donor and retail body lengths differ")
        seed_rows = detailed_relocations(seed, seed_section)
        donor_rows = detailed_relocations(donor, donor_section)
        _require_equal_relocation_semantics(seed_rows, donor_rows)
        external_entries = relational_form_external_entries(
            donor, donor_section, "relational repair external entries"
        )
        sites, proof = derive_relational_sites(
            donor_body,
            retail_body,
            donor_rows,
            external_entries=external_entries,
        )
        extras, function_count, comdat_count = _donor_extras(seed, donor)
        envelope = measure_instruction_schedule_debug_envelope(
            donor, donor_section, "relational repair debug fidelity"
        )
        internal_targets = sorted(internal_relocation_targets(donor_rows, donor_section["number"]))
        expected_values: dict[str, JsonValue] = {
            "donor_rewriting.expected_changed_offsets": [
                index
                for index, (left, right) in enumerate(zip(donor_body, retail_body, strict=True))
                if left != right
            ],
            "donor_rewriting.expected_code_symbol_references": cast(
                list[JsonValue], envelope["code_symbol_references"]
            ),
            "donor_rewriting.expected_external_entries": cast(
                list[JsonValue], sorted(external_entries)
            ),
            "donor_rewriting.expected_instruction_count": cast(int, proof["instruction_count"]),
            "donor_rewriting.expected_procedure_range": cast(
                list[JsonValue], envelope["procedure_range"]
            ),
            "expected_body_sha256": sha256(retail_body).hexdigest(),
            "expected_characteristics": seed_section["characteristics"],
            "expected_closure": list(_comdat_child_closure(seed, seed_section)[1]),
            "expected_comdat_count": comdat_count,
            "expected_donor_body_sha256": sha256(donor_body).hexdigest(),
            "expected_donor_length": len(donor_body),
            "expected_donor_line_count": donor_section["line_count"],
            "expected_donor_metadata_sha256": instruction_mosaic_metadata_sha256(
                donor, donor_section
            ),
            "expected_donor_section_count": len(donor.sections),
            "expected_donor_section_number": donor_section["number"],
            "expected_function_count": function_count,
            "expected_linked_span": (len(donor_body) + 15) // 16 * 16,
            "expected_relocation_count": seed_section["relocation_count"],
            "expected_section_count": len(seed.sections),
            "expected_section_number": seed_section["number"],
            "expected_seed_body_sha256": sha256(seed_body).hexdigest(),
            "expected_seed_length": len(seed_body),
            "expected_seed_line_count": seed_section["line_count"],
            "expected_seed_metadata_sha256": instruction_mosaic_metadata_sha256(seed, seed_section),
            "expected_selection": cast(
                JsonValue, section_definitions(seed)[seed_section["number"]]["selection"]
            ),
            "retail_oracle": retail_oracle,
            "retail_relocations": refresh_retail_relocations(
                previous_receipt.expected_values.get("retail_relocations"),
                donor,
                donor_section,
                retail_address,
                "relational repair retail relocations",
            ),
        }
        for index, site in enumerate(sites):
            expected_values[
                f"donor_rewriting.relational_sites[{index}].expected_rewritten_offsets"
            ] = site["expected_rewritten_offsets"]
        if internal_targets:
            expected_values["donor_rewriting.expected_internal_relocation_targets"] = cast(
                list[JsonValue], internal_targets
            )
        if extras:
            expected_values["expected_donor_extra_functions"] = cast(list[JsonValue], extras)

        program: dict[str, JsonValue] = {
            "authenticity_rationale": _AUTHENTICITY_RATIONALE,
            "kind": DONOR_REWRITING_KIND,
            "relational_sites": _parameter_sites(sites),
        }
        first_action = _new_action(previous, donor_id, program, expected_values)
        first_receipt = _new_receipt(first_action, expected_values)
        dispatch_materials = ClassicDispatchMaterials(
            seed_object=materials.seed_object,
            donor_object=donor_object,
            seed_source=materials.seed_source,
            donor_source=donor_source,
            shape_identifiers=shape_identifiers,
            compiler_identity=materials.compiler_identity,
        )
        first = repair_measured_pins(first_action, first_receipt, dispatch_materials)
        final_values = cast(dict[str, JsonValue], dict(first.receipt.expected_values))
        final_action = _new_action(previous, donor_id, program, final_values)
        final_receipt = _new_receipt(final_action, final_values)
        measured = repair_measured_pins(final_action, final_receipt, dispatch_materials)
        if measured.changed_keys:
            raise RelationalRepairError("ordinary validation changed freshly measured authority")
        return RelationalDonorReauthoring(final_action, measured.receipt, measured)
    except RelationalRepairError:
        raise
    except (RetailRepairError, MeasuredPinRepairError) as exc:
        raise RelationalRepairError(str(exc)) from exc
    except (
        ByteIdentityError,
        DonorSourceError,
        KeyError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise RelationalRepairError(f"cannot author relational donor rewriting: {exc}") from exc


__all__ = [
    "RelationalDonorReauthoring",
    "RelationalRepairError",
    "derive_relational_sites",
    "reauthor_relational_donor_rewriting",
]
