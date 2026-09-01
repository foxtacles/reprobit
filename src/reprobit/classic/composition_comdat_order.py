"""Classic compiler algorithms: COMDAT group order swap and restore composers."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    section_definitions,
)

from .coff import (
    comdat_primary_section,
)
from .foundation import (
    require_payload_free_declaration,
)


def compose_swap_comdat_group_order(
    seed_bytes: bytes, specification: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Swap the link-visible order of two complete compiler-produced COMDAT
    groups (primary + associated children) inside one object, renumbering
    section ordinals and associations only.

    No raw code, relocation, xdata, data, line, or debug payload byte moves;
    every symbol keeps its exact raw contribution.  The permutation makes
    the `first` function's group precede the `second` function's group; the
    intervening contributions keep their relative order.
    """
    require_payload_free_declaration(specification, "COMDAT group-order declaration")
    seed = CoffObject(seed_bytes)
    first = seed.function_section(specification["first"])
    second = seed.function_section(specification["second"])
    definitions = section_definitions(seed)

    def group(primary: dict[str, Any]) -> list[int]:
        children = [
            section["number"]
            for section in seed.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"] == primary["number"]
        ]
        return [primary["number"], *children]

    first_group = group(first)
    second_group = group(second)
    require(not set(first_group) & set(second_group), "COMDAT groups overlap")
    require(second["number"] < first["number"], "the requested group order already holds")
    window = sorted(set(first_group) | set(second_group))
    low, high = (min(window), max(max(first_group), max(second_group)))
    window_numbers = list(range(low, high + 1))
    rest = [
        number
        for number in window_numbers
        if number not in first_group and number not in second_group
    ]
    new_order = first_group + second_group + rest
    require(sorted(new_order) == window_numbers, "group window is not a permutation")
    old_to_new = {old: window_numbers[index] for index, old in enumerate(new_order)}

    def mapped(number: int) -> int:
        return old_to_new.get(number, number)

    work = bytearray(seed_bytes)
    original_headers = {
        number: seed_bytes[20 + (number - 1) * 40 : 20 + number * 40] for number in window_numbers
    }
    for old, new in old_to_new.items():
        start = 20 + (new - 1) * 40
        work[start : start + 40] = original_headers[old]
    symbol_writes = 0
    association_writes = 0
    for index, symbol in seed.symbols.items():
        if symbol["section"] > 0 and mapped(symbol["section"]) != symbol["section"]:
            offset = seed.symbol_offset + index * 18 + 12
            work[offset : offset + 2] = mapped(symbol["section"]).to_bytes(2, "little", signed=True)
            symbol_writes += 1
        definition = definitions.get(symbol["section"])
        if (
            definition is not None
            and symbol["storage"] == 3
            and symbol["aux_count"]
            and (symbol["name"] == seed.sections[symbol["section"] - 1]["name"])
            and (definition["selection"] == 5)
            and (mapped(definition["associated"]) != definition["associated"])
        ):
            aux = seed.symbol_offset + (index + 1) * 18
            parent = mapped(definition["associated"])
            work[aux + 12 : aux + 14] = (parent & 65535).to_bytes(2, "little")
            work[aux + 16 : aux + 18] = (parent >> 16).to_bytes(2, "little")
            association_writes += 1
    composed = bytes(work)
    require(len(composed) == len(seed_bytes), "object size changed")
    checked = CoffObject(composed)
    checked_definitions = section_definitions(checked)
    section_fields = (
        "name",
        "raw_size",
        "raw_offset",
        "relocation_offset",
        "relocation_count",
        "line_offset",
        "line_count",
        "characteristics",
    )
    for section in seed.sections:
        peer = checked.sections[mapped(section["number"]) - 1]
        require(
            all(section[field] == peer[field] for field in section_fields),
            f"semantic section changed: old {section['number']}",
        )
    require(seed.symbols.keys() == checked.symbols.keys(), "symbol index set changed")
    for index, symbol in seed.symbols.items():
        peer = checked.symbols[index]
        require(
            all(
                symbol[field] == peer[field]
                for field in ("name", "value", "type", "storage", "aux_count")
            )
            and peer["section"] == mapped(symbol["section"]),
            f"symbol identity changed at {index}",
        )
    for old_number, definition in definitions.items():
        peer = checked_definitions.get(mapped(old_number))
        require(
            peer is not None
            and peer["selection"] == definition["selection"]
            and (peer["associated"] == mapped(definition["associated"])),
            f"section definition mapping changed: {old_number}",
        )
    checked_first = checked.function_section(specification["first"])
    checked_second = checked.function_section(specification["second"])
    require(
        checked_first["number"] < checked_second["number"], "target group order was not swapped"
    )
    for name in sorted(
        {section["name"] for section in seed.sections if not section["name"].startswith(".debug$")}
    ):
        before = [section["raw_offset"] for section in seed.sections if section["name"] == name]
        after = [section["raw_offset"] for section in checked.sections if section["name"] == name]
        if name == first["name"]:
            expected = list(before)
            left = expected.index(first["raw_offset"])
            right = expected.index(second["raw_offset"])
            require(left > right, "target contributions were already ordered")
            expected[left], expected[right] = (expected[right], expected[left])
            require(after == expected, "more than the target contribution pair moved")
        else:
            require(after == before, f"link-visible {name} contribution order changed")
    return (
        composed,
        {
            "first": specification["first"],
            "second": specification["second"],
            "window": [low, high],
            "symbol_section_writes": symbol_writes,
            "association_writes": association_writes,
        },
    )


def compose_restore_comdat_group_order(
    seed_bytes: bytes, specification: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Restore the link-visible order of several complete compiler-produced
    `.text` COMDAT groups (primary + associated children) inside one object.

    This is the list form of :func:`compose_swap_comdat_group_order`: the
    ``group_order`` list names `.text` COMDAT primaries in the desired
    (retail-anchored) first-to-last order.  The permutation window is the
    contiguous section-number range spanned by the listed groups.  Every
    `.text` COMDAT group inside that window must be listed (fail-closed), so
    the transform is a pure whole-group permutation of text contributions.
    Sections of any other kind that sit inside the window (string literals,
    data, vftables and their children) keep their own relative order and are
    reseated after the listed groups, so no other link-visible contribution
    order changes.  Only section ordinals and associations are renumbered;
    no raw code, relocation, xdata, data, line, or debug payload byte moves
    and every symbol keeps its exact raw contribution.
    """
    require_payload_free_declaration(specification, "COMDAT group-order declaration")
    order = specification["group_order"]
    require(
        isinstance(order, list) and 2 <= len(order) <= 512 and (len(set(order)) == len(order)),
        "group_order must be a list of 2..512 distinct names",
    )
    require(
        all(isinstance(name, str) and name for name in order),
        "group_order names must be non-empty strings",
    )
    seed = CoffObject(seed_bytes)
    definitions = section_definitions(seed)

    def group(primary: dict[str, Any]) -> list[int]:
        children = [
            section["number"]
            for section in seed.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"] == primary["number"]
        ]
        return [primary["number"], *children]

    groups = []
    listed = set()
    kinds = set()
    for name in order:
        primary = comdat_primary_section(seed, name)
        members = group(primary)
        require(not set(members) & listed, f"COMDAT groups overlap: {name}")
        listed.update(members)
        kinds.add(primary["name"].split("$")[0])
        groups.append((name, primary, members))
    require(len(kinds) == 1, "group_order must name COMDATs of one section kind")
    kind = next(iter(kinds))
    low = min((min(members) for _, _, members in groups))
    high = max((max(members) for _, _, members in groups))
    window_numbers = list(range(low, high + 1))
    unlisted = [number for number in window_numbers if number not in listed]
    for number in unlisted:
        section = seed.sections[number - 1]
        require(
            section["name"].split("$")[0] != kind,
            f"unlisted {kind} contribution inside the window: section {number}",
        )
        definition = definitions.get(number)
        if definition is not None and definition.get("selection") == 5:
            require(
                definition["associated"] not in listed,
                f"orphaned associated section inside the window: section {number}",
            )
    new_order = [number for _, _, members in groups for number in members]
    new_order += unlisted
    require(sorted(new_order) == window_numbers, "group window is not a permutation")
    old_to_new = {old: window_numbers[index] for index, old in enumerate(new_order)}
    require(
        any((old != new for old, new in old_to_new.items())),
        "the requested group order already holds",
    )

    def mapped(number: int) -> int:
        return old_to_new.get(number, number)

    work = bytearray(seed_bytes)
    original_headers = {
        number: seed_bytes[20 + (number - 1) * 40 : 20 + number * 40] for number in window_numbers
    }
    for old, new in old_to_new.items():
        start = 20 + (new - 1) * 40
        work[start : start + 40] = original_headers[old]
    symbol_writes = 0
    association_writes = 0
    for index, symbol in seed.symbols.items():
        if symbol["section"] > 0 and mapped(symbol["section"]) != symbol["section"]:
            offset = seed.symbol_offset + index * 18 + 12
            work[offset : offset + 2] = mapped(symbol["section"]).to_bytes(2, "little", signed=True)
            symbol_writes += 1
        definition = definitions.get(symbol["section"])
        if (
            definition is not None
            and symbol["storage"] == 3
            and symbol["aux_count"]
            and (symbol["name"] == seed.sections[symbol["section"] - 1]["name"])
            and (definition["selection"] == 5)
            and (mapped(definition["associated"]) != definition["associated"])
        ):
            aux = seed.symbol_offset + (index + 1) * 18
            parent = mapped(definition["associated"])
            work[aux + 12 : aux + 14] = (parent & 65535).to_bytes(2, "little")
            work[aux + 16 : aux + 18] = (parent >> 16).to_bytes(2, "little")
            association_writes += 1
    composed = bytes(work)
    require(len(composed) == len(seed_bytes), "object size changed")
    checked = CoffObject(composed)
    checked_definitions = section_definitions(checked)
    section_fields = (
        "name",
        "raw_size",
        "raw_offset",
        "relocation_offset",
        "relocation_count",
        "line_offset",
        "line_count",
        "characteristics",
    )
    for section in seed.sections:
        peer = checked.sections[mapped(section["number"]) - 1]
        require(
            all(section[field] == peer[field] for field in section_fields),
            f"semantic section changed: old {section['number']}",
        )
    require(seed.symbols.keys() == checked.symbols.keys(), "symbol index set changed")
    for index, symbol in seed.symbols.items():
        peer = checked.symbols[index]
        require(
            all(
                symbol[field] == peer[field]
                for field in ("name", "value", "type", "storage", "aux_count")
            )
            and peer["section"] == mapped(symbol["section"]),
            f"symbol identity changed at {index}",
        )
    for old_number, definition in definitions.items():
        peer = checked_definitions.get(mapped(old_number))
        require(
            peer is not None
            and peer["selection"] == definition["selection"]
            and (peer["associated"] == mapped(definition["associated"])),
            f"section definition mapping changing: {old_number}",
        )
    final_numbers = [comdat_primary_section(checked, name)["number"] for name in order]
    require(final_numbers == sorted(final_numbers), "target group order was not restored")
    listed_offsets = {
        seed.sections[number - 1]["raw_offset"] for _, _, members in groups for number in members
    }
    for name in sorted(
        {section["name"] for section in seed.sections if not section["name"].startswith(".debug$")}
    ):
        before = [section["raw_offset"] for section in seed.sections if section["name"] == name]
        after = [section["raw_offset"] for section in checked.sections if section["name"] == name]
        require(sorted(before) == sorted(after), f"{name} contribution set changed")
        require(
            [offset for offset in before if offset not in listed_offsets]
            == [offset for offset in after if offset not in listed_offsets],
            f"an unlisted {name} contribution moved",
        )
        if name.split("$")[0] != kind:
            group_rank = {}
            for rank, (_, _, members) in enumerate(groups):
                for number in members:
                    group_rank[seed.sections[number - 1]["raw_offset"]] = rank
            ranks = [group_rank[offset] for offset in after if offset in listed_offsets]
            require(ranks == sorted(ranks), f"listed {name} children do not follow the group order")
    return (
        composed,
        {
            "group_order": list(order),
            "window": [low, high],
            "unlisted_reseated": len(unlisted),
            "symbol_section_writes": symbol_writes,
            "association_writes": association_writes,
        },
    )
