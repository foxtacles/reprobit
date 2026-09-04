"""Derived equality-compare projections shared by COFF and compiler-state proofs."""

from __future__ import annotations

from collections.abc import Mapping
from itertools import pairwise, product
from typing import Any

from reprobit.binary import ByteIdentityError

from .relational import (
    IA32_CONDITION_NAMES,
    IA32_RELATIONAL_COMPARE_PAIRS,
    apply_relational_form,
    ia32_relational_flow_walk,
)

_MAX_EQUALITY_CANDIDATES = 32


def _equality_compare_reversal_variants(
    body: bytes,
    compare: Mapping[str, Any],
) -> tuple[tuple[bool, bytes], ...]:
    """Return the exact IA-32 encodings that reverse one compare."""

    compare_at = int(compare["offset"])
    compare_end = compare_at + int(compare["length"])
    opcode_at = int(compare["opcode_at"])
    direction_image = bytearray(body)
    direction_image[opcode_at] = IA32_RELATIONAL_COMPARE_PAIRS[int(compare["opcode"])]
    variants: list[tuple[bool, bytes]] = [(False, bytes(direction_image[compare_at:compare_end]))]
    modrm_at = opcode_at + 1
    if modrm_at < compare_end and body[modrm_at] >> 6 == 3:
        register_image = bytearray(body)
        modrm = register_image[modrm_at]
        register_image[modrm_at] = (modrm & 0xC0) | ((modrm & 0x07) << 3) | ((modrm >> 3) & 0x07)
        variants.append((True, bytes(register_image[compare_at:compare_end])))
    return tuple(variants)


def _equality_compare_sites(
    body: bytes,
    relocations: Mapping[int, Mapping[str, object]],
    external_entries: frozenset[int],
    context: str,
) -> tuple[tuple[Mapping[str, Any], Mapping[str, Any]], ...] | None:
    relocation_map = {offset: dict(record) for offset, record in relocations.items()}
    try:
        items, _successors, _entries = ia32_relational_flow_walk(
            body,
            relocation_map,
            context,
            len(body),
            external_entries,
        )
    except ByteIdentityError:
        return None
    if any(item.get("flow") == "computed" for item in items):
        return None
    result: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for compare, branch in pairwise(items):
        condition = branch.get("condition")
        if (
            compare.get("opcode") in IA32_RELATIONAL_COMPARE_PAIRS
            and compare.get("flow") == "fall"
            and branch.get("flow") == "jcc"
            and isinstance(condition, int)
            and IA32_CONDITION_NAMES.get(condition) in {"e", "ne"}
        ):
            result.append((compare, branch))
    return tuple(result)


def _equality_reversal_images(
    body: bytes,
    compares: tuple[Mapping[str, Any], ...],
) -> tuple[bytes, ...]:
    sites: list[tuple[int, int, tuple[bytes, ...]]] = []
    candidate_count = 1
    for compare in compares:
        compare_at = int(compare["offset"])
        compare_end = compare_at + int(compare["length"])
        alternatives = tuple(
            dict.fromkeys(
                encoded
                for _reencode, encoded in _equality_compare_reversal_variants(body, compare)
                if encoded != body[compare_at:compare_end]
            )
        )
        if not alternatives:
            continue
        candidate_count *= len(alternatives) + 1
        if candidate_count - 1 > _MAX_EQUALITY_CANDIDATES:
            return ()
        sites.append((compare_at, compare_end, alternatives))
    if not sites:
        return ()

    candidates: set[bytes] = set()
    for choices in product(*(range(len(alternatives) + 1) for _, _, alternatives in sites)):
        if not any(choices):
            continue
        image = bytearray(body)
        for choice, (compare_at, compare_end, alternatives) in zip(choices, sites, strict=True):
            if choice:
                image[compare_at:compare_end] = alternatives[choice - 1]
        candidates.add(bytes(image))
    return tuple(sorted(candidates))


def equality_compare_reversal_images(
    body: bytes,
    relocations: Mapping[int, Mapping[str, object]],
    external_entries: frozenset[int],
    context: str,
) -> tuple[bytes, ...]:
    """Enumerate bounded images for later independent relational proofs."""

    measured = _equality_compare_sites(body, relocations, external_entries, context)
    if measured is None:
        return ()
    return _equality_reversal_images(body, tuple(compare for compare, _branch in measured))


def equality_compare_reversal_preimages(
    source: bytes,
    target: bytes,
    relocations: Mapping[int, Mapping[str, object]],
    external_entries: frozenset[int],
    context: str,
) -> tuple[bytes, ...]:
    """Enumerate bounded target preimages for a later equality proof.

    These images are discovery candidates only.  Callers must independently
    prove both the projection into a candidate and its relational rejoin to
    ``target``.
    """

    if len(source) != len(target):
        return ()
    measured = _equality_compare_sites(target, relocations, external_entries, context)
    if measured is None:
        return ()

    compares: list[Mapping[str, Any]] = []
    for compare, branch in measured:
        compare_at = int(compare["offset"])
        compare_end = compare_at + int(compare["length"])
        branch_at = int(branch["offset"])
        branch_end = branch_at + int(branch["length"])
        if (
            source[compare_at:compare_end] == target[compare_at:compare_end]
            or source[branch_at:branch_end] != target[branch_at:branch_end]
        ):
            continue
        compares.append(compare)
    return _equality_reversal_images(target, tuple(compares))


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
    measured = _equality_compare_sites(source, relocations, external_entries, context)
    if measured is None:
        # Relocation-derived entries do not close computed jump tables, whose
        # hidden targets could observe the flags changed here.
        return None

    sites: list[dict[str, object]] = []
    for compare, branch in measured:
        condition = branch.get("condition")
        condition_name = IA32_CONDITION_NAMES.get(condition) if isinstance(condition, int) else None
        assert condition_name in {"e", "ne"}
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

        variants = _equality_compare_reversal_variants(source, compare)
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


__all__ = [
    "derive_equality_compare_reversals",
    "equality_compare_reversal_images",
    "equality_compare_reversal_preimages",
]
