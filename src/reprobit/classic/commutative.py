"""Closed x87 commutative-operand projections."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from reprobit.binary import ByteIdentityError, require

from .foundation import require_payload_free_declaration
from .register_semantics import decode_ia32_bijection_body
from .relational import ia32_relational_flow_walk

COMMUTATIVE_OPERAND_FORM_KIND = "commutative_operand_form_v1"
COMMUTATIVE_OPERAND_BOUNDARY_RESEAT_KIND = "commutative_operand_form_interior_boundary_reseat_v1"

_COMMUTATIVE_LOAD_WIDTH: dict[int, str] = {0xD9: "m32", 0xDD: "m64"}
_COMMUTATIVE_OPERATOR_WIDTH: dict[int, str] = {0xD8: "m32", 0xDC: "m64"}
_COMMUTATIVE_DIGIT: dict[int, str] = {0: "fadd", 1: "fmul"}


def _commutative_memory_operand(
    body: bytes,
    item: Mapping[str, Any],
    context: str,
) -> bytes:
    """Return one pure-memory x87 operand's complete ModRM/SIB/disp bytes."""

    encoding = item["encoding"]
    require(
        encoding is not None,
        f"{context}: the instruction at {item['offset']} has no ModRM operand",
    )
    require(
        encoding["mode"] != 3,
        f"{context}: the operand at {item['offset']} is a register, not memory",
    )
    require(
        not encoding["absolute"],
        f"{context}: the operand at {item['offset']} is an absolute address",
    )
    modrm_at = int(encoding["modrm_at"])
    end = int(item["offset"]) + int(item["length"])
    return body[modrm_at:end]


def _splice_operand(operand: bytes, digit: int) -> bytes:
    result = bytearray(operand)
    result[0] = (result[0] & 0xC7) | (digit << 3)
    return bytes(result)


def _commutative_pair_image(
    body: bytes,
    load: Mapping[str, Any],
    operator: Mapping[str, Any],
    context: str,
    *,
    allow_interior_boundary_reseat: bool,
) -> tuple[bytes, str, str, int, int]:
    """Build one locally proved ``fld X; op Y`` -> ``fld Y; op X`` pair."""

    width = _COMMUTATIVE_LOAD_WIDTH.get(int(load["opcode"]))
    require(
        width is not None,
        f"{context}: {load['opcode']:#x} is not an fld m32/m64",
    )
    assert width is not None
    load_encoding = cast(dict[str, Any] | None, load["encoding"])
    require(
        load_encoding is not None and load_encoding["reg"] == 0,
        f"{context}: the first instruction is not fld (/0)",
    )
    require(
        _COMMUTATIVE_OPERATOR_WIDTH.get(int(operator["opcode"])) == width,
        f"{context}: the operator at {operator['offset']} is not a {width} "
        "x87 memory binary operation",
    )
    operator_encoding = cast(dict[str, Any] | None, operator["encoding"])
    require(
        operator_encoding is not None,
        f"{context}: the operator at {operator['offset']} has no ModRM operand",
    )
    assert operator_encoding is not None
    digit_value = operator_encoding.get("reg")
    require(
        type(digit_value) is int,
        f"{context}: the operator at {operator['offset']} has no exact ModRM digit",
    )
    digit = cast(int, digit_value)
    operation = _COMMUTATIVE_DIGIT.get(digit)
    require(
        operation is not None,
        f"{context}: /{digit} is not a COMMUTATIVE x87 binary operation",
    )
    assert operation is not None

    load_operand = _commutative_memory_operand(body, load, context)
    operator_operand = _commutative_memory_operand(body, operator, context)
    require(
        _splice_operand(load_operand, 0) != _splice_operand(operator_operand, 0),
        f"{context}: the two operands are already equal",
    )
    new_load = bytes([int(load["opcode"])]) + _splice_operand(operator_operand, 0)
    new_operator = bytes([int(operator["opcode"])]) + _splice_operand(load_operand, digit)
    source_length = int(load["length"]) + int(operator["length"])
    require(
        len(new_load) + len(new_operator) == source_length,
        f"{context}: the exchange changed the pair span",
    )
    if not allow_interior_boundary_reseat:
        require(
            len(new_load) == int(load["length"]) and len(new_operator) == int(operator["length"]),
            f"{context}: the two instructions differ in length; the interior boundary would move",
        )
    return (
        new_load + new_operator,
        operation,
        width,
        int(operator["offset"]),
        int(load["offset"]) + len(new_load),
    )


def apply_commutative_operand_form(
    body: bytes,
    sites: list[dict[str, object]],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: Mapping[int, Mapping[str, object]] | None = None,
    code_length: int | None = None,
    external_entries: frozenset[int] | None = None,
    internal_targets: frozenset[int] | None = None,
    *,
    allow_interior_boundary_reseat: bool = False,
) -> tuple[bytes, dict[str, object]]:
    """Exchange adjacent x87 memory operands under a closed flow proof.

    The default preserves every instruction boundary for legacy object
    composition, whose seed debug records remain installed.  Compiler-state
    projection may explicitly reseat only the pair's interior boundary: the
    pair span, instruction count and exterior grid remain fixed, no control or
    relocation entry may name the interior, and the effective compiler product
    supplies its own debug representation.
    """

    require_payload_free_declaration(sites, f"{context} commutative operand declaration")
    require(
        isinstance(body, (bytes, bytearray)) and bool(body),
        f"{context}: body is empty",
    )
    require(isinstance(sites, list) and bool(sites), f"{context}: no site is declared")
    require(
        type(allow_interior_boundary_reseat) is bool,
        f"{context}: boundary-reseat policy is not an exact boolean",
    )
    source = bytes(body)
    relocation_map = dict(relocations or {})
    items, successors, entries = ia32_relational_flow_walk(
        source,
        relocation_map,
        context,
        code_length,
        external_entries,
    )
    if allow_interior_boundary_reseat:
        require(
            not any(item.get("flow") == "computed" for item in items),
            f"{context}: computed control flow leaves the interior entry set open",
        )
    branch_targets = {item["target"] for item in items if item.get("target") is not None}
    entry_offsets = {items[entry]["offset"] for entry in entries[1:]}
    decoded = decode_ia32_bijection_body(
        source,
        f"{context} decode",
        relocation_map,
        code_length,
    )
    index_of = {int(item["offset"]): index for index, item in enumerate(decoded)}
    image = bytearray(source)
    proved: list[dict[str, Any]] = []
    previous_end = 0
    for ordinal, site in enumerate(sites):
        site_context = f"{context} site {ordinal}"
        at_value = site["pair_offset"]
        require(
            type(at_value) is int and 0 <= at_value < len(source),
            f"{site_context}: the pair offset is out of range",
        )
        at = cast(int, at_value)
        require(previous_end <= at, f"{site_context}: sites are unsorted or overlapping")
        require(at in index_of, f"{site_context}: the pair offset is not an instruction boundary")
        load_index = index_of[at]
        require(load_index + 1 < len(decoded), f"{site_context}: the pair runs past the body")
        load = decoded[load_index]
        operator = decoded[load_index + 1]
        require(
            int(operator["offset"]) == at + int(load["length"]),
            f"{site_context}: the two instructions are not adjacent",
        )
        end = int(operator["offset"]) + int(operator["length"])
        previous_end = end
        pair_image, operation, width, seed_boundary, image_boundary = _commutative_pair_image(
            source,
            load,
            operator,
            site_context,
            allow_interior_boundary_reseat=allow_interior_boundary_reseat,
        )
        require(
            site.get("operation") == operation,
            f"{site_context}: the declared operation differs",
        )
        require(
            not any(at <= offset < end for offset in relocation_offsets),
            f"{site_context}: a relocation lies inside the pair",
        )
        require(
            seed_boundary not in branch_targets,
            f"{site_context}: a branch targets the operator, so the pair can be "
            "entered without its fld",
        )
        require(
            seed_boundary not in entry_offsets,
            f"{site_context}: an external entry lies inside the pair",
        )
        require(
            not any(at < target < end for target in internal_targets or frozenset()),
            f"{site_context}: a relocated target lies inside the pair",
        )
        image[at:end] = pair_image
        check = decode_ia32_bijection_body(
            bytes(image[at:end]),
            f"{site_context} image",
            None,
            None,
        )
        require(
            len(check) == 2
            and check[0]["opcode"] == load["opcode"]
            and check[1]["opcode"] == operator["opcode"]
            and int(check[0]["length"]) == image_boundary - at
            and int(check[1]["length"]) == end - image_boundary,
            f"{site_context}: the image pair does not re-decode",
        )
        expected_load_operand = _splice_operand(
            _commutative_memory_operand(source, operator, site_context),
            0,
        )
        source_operator_encoding = cast(dict[str, Any], operator["encoding"])
        expected_operator_operand = _splice_operand(
            _commutative_memory_operand(source, load, site_context),
            cast(int, source_operator_encoding["reg"]),
        )
        require(
            _commutative_memory_operand(bytes(image[at:end]), check[0], site_context)
            == expected_load_operand,
            f"{site_context}: the image fld does not carry the operator's operand",
        )
        require(
            _commutative_memory_operand(bytes(image[at:end]), check[1], site_context)
            == expected_operator_operand,
            f"{site_context}: the image operator does not carry the fld's operand",
        )
        rewritten = sorted(offset for offset in range(at, end) if source[offset] != image[offset])
        declared_value = site.get("expected_rewritten_offsets")
        require(
            isinstance(declared_value, list),
            f"{site_context}: expected rewritten offsets are not a list",
        )
        declared = cast(list[object], declared_value)
        require(
            declared == rewritten,
            f"{site_context}: the rewritten offsets {rewritten} are not the declared {declared}",
        )
        proved.append(
            {
                "pair_offset": at,
                "pair_end": end,
                "operation": operation,
                "width": width,
                "seed_operator_offset": seed_boundary,
                "image_operator_offset": image_boundary,
                "expected_rewritten_offsets": rewritten,
            }
        )

    result = bytes(image)
    require(result != source, f"{context}: the image does not move the body")
    changed = {offset for offset in range(len(source)) if source[offset] != result[offset]}
    declared_offsets = {
        offset for site in proved for offset in cast(list[int], site["expected_rewritten_offsets"])
    }
    require(
        changed == declared_offsets,
        f"{context}: the image changed a byte outside the declared sites",
    )
    image_items, image_successors, image_entries = ia32_relational_flow_walk(
        result,
        relocation_map,
        f"{context} image",
        code_length,
        external_entries,
    )
    seed_interior = {
        int(site["seed_operator_offset"])
        for site in proved
        if site["seed_operator_offset"] != site["image_operator_offset"]
    }
    image_interior = {
        int(site["image_operator_offset"])
        for site in proved
        if site["seed_operator_offset"] != site["image_operator_offset"]
    }
    seed_exterior = [int(item["offset"]) for item in items if item["offset"] not in seed_interior]
    image_exterior = [
        int(item["offset"]) for item in image_items if item["offset"] not in image_interior
    ]
    require(
        seed_exterior == image_exterior
        and len(items) == len(image_items)
        and image_successors == successors
        and {item["target"] for item in image_items if item.get("target") is not None}
        == branch_targets
        and image_entries == entries,
        f"{context}: the image moved an exterior boundary, control edge, target, or entry",
    )
    boundary_moves = [
        {
            "pair_offset": site["pair_offset"],
            "seed_operator_offset": site["seed_operator_offset"],
            "image_operator_offset": site["image_operator_offset"],
        }
        for site in proved
        if site["seed_operator_offset"] != site["image_operator_offset"]
    ]
    return result, {
        "kind": (
            COMMUTATIVE_OPERAND_BOUNDARY_RESEAT_KIND
            if boundary_moves
            else COMMUTATIVE_OPERAND_FORM_KIND
        ),
        "sites": proved,
        "instruction_count": len(image_items),
        "interior_boundary_moves": boundary_moves,
    }


def derive_commutative_operand_forms(
    source: bytes,
    target: bytes,
    relocations: Mapping[int, Mapping[str, object]],
    external_entries: frozenset[int],
    context: str,
) -> tuple[bytes, list[dict[str, object]], dict[str, object]] | None:
    """Derive every x87 operand exchange that exactly rejoins ``target``."""

    if len(source) != len(target) or source == target:
        return None
    relocation_map = {offset: dict(record) for offset, record in relocations.items()}
    try:
        flow_items, _successors, _entries = ia32_relational_flow_walk(
            source,
            relocation_map,
            context,
            len(source),
            external_entries,
        )
        if any(item.get("flow") == "computed" for item in flow_items):
            return None
        decoded = decode_ia32_bijection_body(
            source,
            f"{context} derive",
            relocation_map,
            len(source),
        )
    except ByteIdentityError:
        return None

    sites: list[dict[str, object]] = []
    for index, load in enumerate(decoded[:-1]):
        operator = decoded[index + 1]
        at = int(load["offset"])
        end = int(operator["offset"]) + int(operator["length"])
        if int(operator["offset"]) != at + int(load["length"]):
            continue
        try:
            pair_image, operation, _width, _seed_boundary, _image_boundary = (
                _commutative_pair_image(
                    source,
                    load,
                    operator,
                    f"{context} candidate at {at}",
                    allow_interior_boundary_reseat=True,
                )
            )
        except (ByteIdentityError, KeyError, TypeError, ValueError):
            # Every adjacent pair is tried.  A pair that is not ``fld m; op m``
            # fails a requirement, or has no ModRM/displacement fields at all
            # (KeyError, TypeError, ValueError from the decoded records); either
            # way it is simply not a candidate site.
            continue
        if source[at:end] == target[at:end] or pair_image != target[at:end]:
            continue
        sites.append(
            {
                "pair_offset": at,
                "operation": operation,
                "expected_rewritten_offsets": [
                    offset for offset in range(at, end) if source[offset] != target[offset]
                ],
            }
        )
    if not sites:
        return None

    relocation_offsets: set[int] = set()
    for offset, record in relocations.items():
        width = record.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            return None
        relocation_offsets.update(offset + byte for byte in range(width))
    try:
        image, proof = apply_commutative_operand_form(
            source,
            sites,
            frozenset(relocation_offsets),
            context,
            relocation_map,
            len(source),
            external_entries,
            external_entries,
            allow_interior_boundary_reseat=True,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError):
        return None
    if image != target:
        return None
    return image, sites, proof


__all__ = [
    "COMMUTATIVE_OPERAND_BOUNDARY_RESEAT_KIND",
    "COMMUTATIVE_OPERAND_FORM_KIND",
    "apply_commutative_operand_form",
    "derive_commutative_operand_forms",
]
