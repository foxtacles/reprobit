"""Derived equality-compare projections shared by COFF and compiler-state proofs."""

from __future__ import annotations

from collections.abc import Mapping

from reprobit.binary import ByteIdentityError

from .relational import (
    IA32_CONDITION_NAMES,
    IA32_RELATIONAL_COMPARE_PAIRS,
    apply_relational_form,
    ia32_relational_flow_walk,
)


def derive_equality_compare_reversals(
    source: bytes,
    target: bytes,
    relocations: Mapping[int, Mapping[str, object]],
    external_entries: frozenset[int],
    context: str,
) -> tuple[bytes, list[dict[str, object]], dict[str, object]] | None:
    """Derive every same-seat JE/JNE compare reversal visible in ``target``.

    The reusable relational primitive remains the proof authority.  This
    adapter contributes no declaration: it derives candidate sites from the
    two compiler images, admits only an unchanged immediately following JE or
    JNE, and asks the primitive to prove complete control flow and flag
    liveness before returning an image.
    """

    if len(source) != len(target):
        return None
    relocation_symbols = {offset: dict(record) for offset, record in relocations.items()}
    try:
        items, _successors, _entries = ia32_relational_flow_walk(
            source,
            relocation_symbols,
            context,
            len(source),
            external_entries,
        )
    except ByteIdentityError:
        return None
    if any(item.get("flow") == "computed" for item in items):
        # Relocation-derived external entries do not close a computed jump
        # table, whose hidden targets could observe the flags changed here.
        return None

    sites: list[dict[str, object]] = []
    for index, compare in enumerate(items[:-1]):
        branch = items[index + 1]
        condition = branch.get("condition")
        condition_name = IA32_CONDITION_NAMES.get(condition) if isinstance(condition, int) else None
        if (
            compare.get("opcode") not in IA32_RELATIONAL_COMPARE_PAIRS
            or compare.get("flow") != "fall"
            or branch.get("flow") != "jcc"
            or condition_name not in {"e", "ne"}
        ):
            continue
        compare_at = int(compare["offset"])
        compare_end = compare_at + int(compare["length"])
        branch_at = int(branch["offset"])
        branch_end = branch_at + int(branch["length"])
        source_compare = source[compare_at:compare_end]
        target_compare = target[compare_at:compare_end]
        if (
            source_compare == target_compare
            or source[branch_at:branch_end] != target[branch_at:branch_end]
        ):
            continue

        opcode_at = int(compare["opcode_at"])
        direction_image = bytearray(source)
        direction_image[opcode_at] = IA32_RELATIONAL_COMPARE_PAIRS[int(compare["opcode"])]
        variants: list[tuple[bool, bytes]] = [
            (False, bytes(direction_image[compare_at:compare_end]))
        ]
        modrm_at = opcode_at + 1
        if modrm_at < compare_end and source[modrm_at] >> 6 == 3:
            register_image = bytearray(source)
            modrm = register_image[modrm_at]
            register_image[modrm_at] = (
                (modrm & 0xC0) | ((modrm & 0x07) << 3) | ((modrm >> 3) & 0x07)
            )
            variants.append((True, bytes(register_image[compare_at:compare_end])))
        matches = [reencode for reencode, body in variants if body == target_compare]
        if len(matches) != 1:
            continue
        site: dict[str, object] = {
            "compare_offset": compare_at,
            "branch_offset": branch_at,
            "seed_condition": condition_name,
            "image_condition": condition_name,
        }
        if matches[0]:
            site["reencode"] = True
        sites.append(site)
    if not sites:
        return None

    relocation_offsets: set[int] = set()
    for offset, record in relocations.items():
        width = record.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            return None
        relocation_offsets.update(offset + byte for byte in range(width))
    try:
        image, proof = apply_relational_form(
            source,
            sites,
            frozenset(relocation_offsets),
            context,
            relocation_symbols,
            len(source),
            external_entries,
        )
    except (ByteIdentityError, KeyError, TypeError, ValueError):
        return None
    if image != target:
        return None
    return image, sites, proof


__all__ = ["derive_equality_compare_reversals"]
