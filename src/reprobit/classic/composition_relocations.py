"""Classic compiler algorithms: relocation-semantics requirements shared by the composers."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    detailed_relocations,
)

from .coff import (
    comdat_primary_identity,
)
from .foundation import (
    local_symbol_kind,
)


def _normalized_relocation_renames(
    seed: CoffObject,
    seed_section: dict[str, Any],
    donor: CoffObject,
    donor_section: dict[str, Any],
    context: str,
    seat_map: dict[str, Any] | None = None,
) -> list[tuple[int, str]]:
    """Require literal relocation equality except paired object-local $L/$T
    serial renames whose targets are structurally identical.

    seat_map maps a declared cross-lane donor's spliced-group section
    numbers onto the seed's, so in-group targets compare structurally."""
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    renames = []
    for a, b in zip(left, right):
        require(
            (a["offset"], a["type"], a["addend"]) == (b["offset"], b["type"], b["addend"]),
            f"{context}: relocation offset/type/addend differs",
        )
        if a["target"] == b["target"]:
            continue
        kind = local_symbol_kind(a["target"])
        if kind is None:
            left_base, _, left_serial = a["target"].rpartition("$S")
            right_base, _, right_serial = b["target"].rpartition("$S")
            require(
                left_base
                and left_base == right_base
                and left_serial.isdigit()
                and right_serial.isdigit()
                and (a["target_type"] == b["target_type"])
                and (a["target_storage"] == b["target_storage"]),
                f"{context}: non-local relocation rename {a['target']!r} -> {b['target']!r}",
            )
            renames.append((a["offset"], "S"))
            continue
        require(
            kind == local_symbol_kind(b["target"]),
            f"{context}: non-local relocation rename {a['target']!r} -> {b['target']!r}",
        )
        donor_target_section = b["target_section"]
        if seat_map:
            donor_target_section = seat_map.get(donor_target_section, donor_target_section)
        require(
            a["target_section"] == donor_target_section
            and all(
                a["target_" + field] == b["target_" + field]
                for field in ("value", "type", "storage")
            ),
            f"{context}: renamed local relocation target structure differs",
        )
        renames.append((a["offset"], kind))
    return renames


def require_same_semantic_relocations(
    seed: CoffObject,
    seed_section: dict[str, Any],
    donor: CoffObject,
    donor_section: dict[str, Any],
    context: str,
) -> list[tuple[int, str]]:
    """Require identical resolved relocation semantics at identical offsets.

    Compiler-local ``$L``/``$T`` serials may be renamed, but only when their
    section seat, value, type, and storage class are unchanged.  Ordinary
    symbols must retain their literal identity and the same structural target.
    This is deliberately stricter than the relocation pairing used by resize
    composers: an instruction mosaic retains the seed table verbatim.
    """
    renames = _normalized_relocation_renames(seed, seed_section, donor, donor_section, context)
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    target_fields = ("target_section", "target_value", "target_type", "target_storage")
    for index, (seed_row, donor_row) in enumerate(zip(left, right)):
        require(
            seed_row["width"] == donor_row["width"], f"{context}: relocation {index} width differs"
        )
        if seed_row["target"] != donor_row["target"]:
            seed_kind = local_symbol_kind(seed_row["target"])
            require(
                seed_kind is not None and seed_kind == local_symbol_kind(donor_row["target"]),
                f"{context}: relocation {index} changes symbol identity",
            )
        require(
            all(seed_row[field] == donor_row[field] for field in target_fields),
            f"{context}: relocation {index} target structure differs",
        )
    return renames


MOSAIC_PERMUTED_RELOCATION_ORDER = "permuted_outside_ranges"


def _mosaic_relocation_pair_rename(
    seed: CoffObject, donor: CoffObject, a: dict[str, Any], b: dict[str, Any]
) -> tuple[bool, tuple[int, str] | None]:
    """Judge one same-offset seed/donor relocation pair under the strict
    instruction-mosaic rule (``require_instruction_mosaic_semantic_relocations``
    plus ``_normalized_relocation_renames``) without raising.

    Returns ``(ok, rename)`` where ``rename`` is the recorded local
    ``$L``/``$T`` serial rename, if any."""
    if (a["offset"], a["type"], a["addend"], a["width"]) != (
        b["offset"],
        b["type"],
        b["addend"],
        b["width"],
    ):
        return (False, None)
    if a["target"] == b["target"]:
        if any(a[field] != b[field] for field in ("target_value", "target_type", "target_storage")):
            return (False, None)
        if a["target_section"] == b["target_section"]:
            return (True, None)
        if (
            local_symbol_kind(a["target"]) is not None
            or a["target_section"] <= 0
            or b["target_section"] <= 0
        ):
            return (False, None)
        seed_target = seed.sections[a["target_section"] - 1]
        donor_target = donor.sections[b["target_section"] - 1]
        return (
            comdat_primary_identity(seed, seed_target)
            == comdat_primary_identity(donor, donor_target),
            None,
        )
    kind = local_symbol_kind(a["target"])
    if kind is None:
        return (False, None)
    if kind != local_symbol_kind(b["target"]):
        return (False, None)
    if a["target_section"] != b["target_section"] or any(
        a["target_" + field] != b["target_" + field] for field in ("value", "type", "storage")
    ):
        return (False, None)
    return (True, (a["offset"], kind))


def _permuted_relocation_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Offset-free identity of one relocation record for the multiset rule.

    Compiler-local ``$L``/``$T`` serials are reduced to their kind; their
    structural target (section seat, value, type, storage) stays literal."""
    kind = local_symbol_kind(row["target"])
    target = row["target"] if kind is None else "$" + kind
    return (
        row["width"],
        row["type"],
        row["addend"],
        target,
        row["target_section"],
        row["target_value"],
        row["target_type"],
        row["target_storage"],
    )


def _require_permuted_instruction_mosaic_relocations(
    seed: CoffObject,
    seed_section: dict[str, Any],
    donor: CoffObject,
    donor_section: dict[str, Any],
    permuted_ranges: list[tuple[int, int]],
    context: str,
) -> list[tuple[int, str]]:
    """The ``permuted_outside_ranges`` relocation-order rule.

    A declaration-only carrier may re-order otherwise identical constant
    stores, so the donor's relocation records outside the imported ranges may
    stand at other offsets and in another order.  The output still retains
    the seed relocation table verbatim; the donor only proves that it is the
    same compiler output of the same source: every same-offset pair obeys the
    strict rule, and the remaining records are an exact offset-free multiset
    permutation of each other that touches no imported range.  A donor that
    satisfies the strict rule must be declared under it (an empty permutation
    is refused), so this mode is never a silent relaxation.
    """
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    right_by_offset = {}
    for index, row in enumerate(right):
        require(
            row["offset"] not in right_by_offset, f"{context}: donor relocation offsets collide"
        )
        right_by_offset[row["offset"]] = index
    renames = []
    unmatched_left = []
    matched_right = set()
    for a in left:
        index = right_by_offset.get(a["offset"])
        if index is not None and index not in matched_right:
            ok, rename = _mosaic_relocation_pair_rename(seed, donor, a, right[index])
            if ok:
                matched_right.add(index)
                if rename is not None:
                    renames.append(rename)
                continue
        unmatched_left.append(a)
    unmatched_right = [row for index, row in enumerate(right) if index not in matched_right]
    require(
        unmatched_left,
        f"{context}: relocation permutation is empty; the strict relocation order applies",
    )
    require(
        sorted(_permuted_relocation_key(row) for row in unmatched_left)
        == sorted(_permuted_relocation_key(row) for row in unmatched_right),
        f"{context}: relocations outside the imported ranges are not a permutation of the seed's",
    )
    for role, rows in (("seed", unmatched_left), ("donor", unmatched_right)):
        for row in rows:
            operand_start = row["offset"]
            operand_end = operand_start + row["width"]
            require(
                all(
                    (operand_end <= start or operand_start >= end for start, end in permuted_ranges)
                ),
                f"{context}: permuted {role} relocation at offset {operand_start} lies inside an imported range",
            )
    return renames


def _require_reseat_instruction_mosaic_relocations(
    seed: CoffObject,
    seed_section: dict[str, Any],
    donor: CoffObject,
    donor_section: dict[str, Any],
    reseat_windows: list[tuple[int, int]],
    context: str,
) -> list[tuple[int, str]]:
    """The ``relocation_reseat`` relocation rule.

    Records pair by ordinal exactly as under the strict rule; the only
    relaxation is that a paired record may carry its operand at another
    offset when both the seed's and the donor's operand lie inside the same
    declared reseat window.  Everything else about the pair (type, width,
    addend, target identity and structure, COMDAT seat) is the strict rule.
    """
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    require(len(left) == len(right), f"{context}: relocation counts differ")
    renames = []
    for index, (a, b) in enumerate(zip(left, right)):
        if a["offset"] != b["offset"]:
            window = next(
                (
                    (start, end)
                    for start, end in reseat_windows
                    if start <= a["offset"] and a["offset"] + a["width"] <= end
                ),
                None,
            )
            require(
                window is not None
                and window[0] <= b["offset"]
                and (b["offset"] + b["width"] <= window[1]),
                f"{context}: relocation {index} moves outside a declared reseat window",
            )
            b = dict(b)
            b["offset"] = a["offset"]
        ok, rename = _mosaic_relocation_pair_rename(seed, donor, a, b)
        require(ok, f"{context}: relocation {index} differs from the seed")
        if rename is not None:
            renames.append(rename)
    return renames


def require_instruction_mosaic_semantic_relocations(
    seed: CoffObject,
    seed_section: dict[str, Any],
    donor: CoffObject,
    donor_section: dict[str, Any],
    context: str,
    *,
    permuted_ranges: list[tuple[int, int]] | None = None,
    reseat_windows: list[tuple[int, int]] | None = None,
) -> list[tuple[int, str]]:
    """Compare mosaic relocations while permitting benign COMDAT reseating.

    With ``reseat_windows`` (the declared ``relocation_reseat`` ranges) the
    ordinal rule still applies to every record, but a paired record may stand
    at another offset when both operands lie inside the same declared window
    (``_require_reseat_instruction_mosaic_relocations``).

    With ``permuted_ranges`` (the imported instruction ranges of a mosaic
    declared ``relocation_order: permuted_outside_ranges``) the offset-free
    multiset rule of ``_require_permuted_instruction_mosaic_relocations``
    applies instead of the ordinal rule.

    A declaration-only carrier can reorder otherwise identical vtable/data
    COMDATs.  The output retains the seed relocation table, so a same-named
    ordinary target may move seats only when both seats describe the exact
    same primary COMDAT identity.  Compiler-local symbols remain under the
    stricter ordinary mosaic rule.
    """
    require(
        permuted_ranges is None or reseat_windows is None,
        f"{context}: relocation permutation and reseat are exclusive",
    )
    if permuted_ranges is not None:
        return _require_permuted_instruction_mosaic_relocations(
            seed, seed_section, donor, donor_section, permuted_ranges, context
        )
    if reseat_windows is not None:
        return _require_reseat_instruction_mosaic_relocations(
            seed, seed_section, donor, donor_section, reseat_windows, context
        )
    renames = _normalized_relocation_renames(seed, seed_section, donor, donor_section, context)
    left = detailed_relocations(seed, seed_section)
    right = detailed_relocations(donor, donor_section)
    for index, (seed_row, donor_row) in enumerate(zip(left, right)):
        require(
            seed_row["width"] == donor_row["width"], f"{context}: relocation {index} width differs"
        )
        same_name = seed_row["target"] == donor_row["target"]
        local = (
            local_symbol_kind(seed_row["target"]) is not None
            or local_symbol_kind(donor_row["target"]) is not None
        )
        common_fields = ("target_value", "target_type", "target_storage")
        require(same_name or local, f"{context}: relocation {index} changes symbol identity")
        require(
            all(seed_row[field] == donor_row[field] for field in common_fields),
            f"{context}: relocation {index} target structure differs",
        )
        if seed_row["target_section"] == donor_row["target_section"]:
            continue
        require(
            same_name
            and (not local)
            and (seed_row["target_section"] > 0)
            and (donor_row["target_section"] > 0),
            f"{context}: relocation {index} changes target seat",
        )
        seed_target = seed.sections[seed_row["target_section"] - 1]
        donor_target = donor.sections[donor_row["target_section"] - 1]
        require(
            comdat_primary_identity(seed, seed_target)
            == comdat_primary_identity(donor, donor_target),
            f"{context}: relocation {index} reseats a different COMDAT",
        )
    return renames
