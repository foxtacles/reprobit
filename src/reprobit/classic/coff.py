from __future__ import annotations

from collections import Counter
from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject as _CoffObject,
)
from reprobit.coff_format import (
    coff_body as _coff_body,
)
from reprobit.coff_format import (
    section_definitions as _section_definitions,
)

from .foundation import canonical_json_bytes, sha256_bytes

"""Classic compiler algorithms: coff."""


def comdat_primary_section(coff: _CoffObject, name: str) -> dict[str, Any]:
    """Return the unique COMDAT primary section defined by symbol ``name``.

    Unlike :meth:`reprobit.coff_format.CoffObject.function_section` this accepts any section kind
    (``.text`` functions, ``.rdata`` vftables and literals, ``.data``); the
    symbol must be an external or static definition at offset 0 of a COMDAT
    section that is not an associated (selection 5) child.
    """
    matches = [
        symbol
        for symbol in coff.symbols.values()
        if symbol["name"] == name
        and symbol["section"] > 0
        and (symbol["value"] == 0)
        and (symbol["storage"] in (2, 3))
    ]
    require(len(matches) == 1, f"expected one definition of {name!r}, found {len(matches)}")
    section = coff.sections[matches[0]["section"] - 1]
    require(section["characteristics"] & 4096, f"{name!r} is not in a COMDAT section")
    definition = _section_definitions(coff).get(section["number"])
    require(
        definition is not None and definition.get("selection") != 5,
        f"{name!r} is not a COMDAT primary",
    )
    return section


def unique_symbol(coff: _CoffObject, predicate, description: str) -> tuple[int, dict[str, Any]]:
    matches = [(index, symbol) for index, symbol in coff.symbols.items() if predicate(symbol)]
    require(len(matches) == 1, f"expected one {description}, found {len(matches)}")
    return matches[0]


def function_symbol(
    coff: _CoffObject, mangled: str, section_number: int
) -> tuple[int, dict[str, Any]]:
    return unique_symbol(
        coff,
        lambda symbol: (
            symbol["name"] == mangled
            and symbol["section"] == section_number
            and (symbol["value"] == 0)
            and (symbol["type"] == 32)
            and (symbol["storage"] in (2, 3))
        ),
        f"function symbol {mangled!r}",
    )


def section_symbol(coff: _CoffObject, section: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    return unique_symbol(
        coff,
        lambda symbol: (
            symbol["name"] == section["name"]
            and symbol["section"] == section["number"]
            and (symbol["storage"] == 3)
            and (symbol["aux_count"] >= 1)
        ),
        f"section-definition symbol for section {section['number']}",
    )


def associated_sections(
    coff: _CoffObject, definitions: dict[int, dict[str, Any]], parent: int
) -> tuple[tuple[int, str], ...]:
    return tuple(
        (section["number"], section["name"])
        for section in coff.sections
        if definitions.get(section["number"], {}).get("selection") == 5
        and definitions[section["number"]]["associated"] == parent
    )


def function_multiset(coff: _CoffObject) -> Counter[str]:
    return Counter(
        symbol["name"]
        for symbol in coff.symbols.values()
        if symbol["type"] == 32
        and symbol["section"] > 0
        and (symbol["value"] == 0)
        and (symbol["storage"] in (2, 3))
        and coff.sections[symbol["section"] - 1]["name"].startswith(".text")
        and (coff.sections[symbol["section"] - 1]["raw_size"] > 0)
    )


def comdat_primary_identity(coff: _CoffObject, section: dict[str, Any]) -> tuple[Any, ...]:
    """Return one non-associative COMDAT group's structural identity."""
    definitions = _section_definitions(coff)
    definition = definitions.get(section["number"])
    require(
        definition is not None and definition["selection"] not in (0, 5),
        f"section {section['number']} is not a primary COMDAT",
    )
    owners = [
        symbol
        for symbol in coff.symbols.values()
        if symbol["section"] == section["number"]
        and symbol["value"] == 0
        and (symbol["name"] != section["name"])
        and (symbol["storage"] in (2, 3))
    ]
    external = [symbol for symbol in owners if symbol["storage"] == 2]
    owners = external or owners
    require(len(owners) == 1, f"COMDAT section {section['number']} has no unique owner")
    owner = owners[0]
    return (
        owner["name"],
        owner["type"],
        owner["storage"],
        section["name"],
        definition["selection"],
        tuple(
            sorted((name for _, name in associated_sections(coff, definitions, section["number"])))
        ),
    )


def comdat_primary_identity_multiset(coff: _CoffObject) -> Counter[tuple[Any, ...]]:
    """Name every non-associative COMDAT group by its defining symbol.

    Raw sizes are intentionally absent: the target function is allowed to
    resize.  Symbol identity, selection policy, section kind, and complete
    associative-child shape still prevent a donor from adding or exchanging
    a code/data group under cover of an omitted function.
    """
    definitions = _section_definitions(coff)
    identities = [
        comdat_primary_identity(coff, section)
        for section in coff.sections
        if definitions.get(section["number"], {}).get("selection") not in (None, 0, 5)
    ]
    return Counter(identities)


def canonical_identity_receipt_sha256(value: object) -> str:
    """Hash a structural identity using the manifest's canonical JSON form."""

    def json_value(item):
        if isinstance(item, (tuple, list)):
            return [json_value(child) for child in item]
        if isinstance(item, dict):
            return {key: json_value(child) for key, child in item.items()}
        return item

    return sha256_bytes(canonical_json_bytes(json_value(value)))


def canonical_counter_receipt_sha256(value: Counter[Any]) -> str:
    """Hash every repeated Counter identity in deterministic repr order."""
    require(isinstance(value, Counter), "canonical identity receipt requires a Counter")
    return canonical_identity_receipt_sha256(sorted(value.elements(), key=repr))


def section_shape_receipt_sha256(coff: _CoffObject) -> str:
    """Hash the ordered section name/characteristics sequence."""
    return canonical_identity_receipt_sha256(
        [(section["name"], section["characteristics"]) for section in coff.sections]
    )


def require_target_closure_extraction_topology(
    seed: _CoffObject, donor: _CoffObject, function: dict[str, Any], context: str
) -> dict[str, Any]:
    """Replace whole-object equality with a pinned strict-subset proof.

    The donor is allowed to omit only the explicitly named definitions that
    the seed object continues to carry.  It may add none.  The final composer
    still proves that every non-target seed section and the seed function set
    survive unchanged.
    """
    require(
        len(seed.sections) == function["expected_seed_section_count"],
        f"{context} seed section count changed",
    )
    require(
        len(donor.sections) == function["expected_donor_section_count"],
        f"{context} donor section count changed",
    )
    require(
        len(seed.sections) > len(donor.sections), f"{context} donor is not a strict section subset"
    )
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    donor_only = donor_functions - seed_functions
    require(not donor_only, f"{context} donor adds functions absent from the seed")
    seed_only = sorted((seed_functions - donor_functions).elements())
    require(
        seed_only == function["expected_seed_only_functions"],
        f"{context} seed-only function set differs",
    )
    require(seed_only, f"{context} target-closure extraction declares no omitted function")
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(not donor_comdats - seed_comdats, f"{context} donor adds or exchanges a COMDAT group")
    omitted_comdats = list((seed_comdats - donor_comdats).elements())
    require(
        sorted(identity[0] for identity in omitted_comdats) == seed_only,
        f"{context} omitted COMDAT groups differ from the declared seed-only functions",
    )
    return {
        "seed_section_count": len(seed.sections),
        "donor_section_count": len(donor.sections),
        "seed_only_functions": seed_only,
        "seed_comdat_count": sum(seed_comdats.values()),
        "donor_comdat_count": sum(donor_comdats.values()),
    }


def require_source_target_closure_topology(
    seed: _CoffObject, donor: _CoffObject, function: dict[str, Any], context: str
) -> dict[str, Any]:
    """Pin one same-name target closure while ignoring donor-only COMDATs."""
    require(
        len(seed.sections) == function["expected_seed_section_count"]
        and len(donor.sections) == function["expected_donor_section_count"],
        f"{context} section census changed",
    )
    mangled = function["mangled"]
    sp, dp = (seed.function_section(mangled), donor.function_section(mangled))
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        f"{context} target section seat changed",
    )
    seed_id = [
        item for item in comdat_primary_identity_multiset(seed).elements() if item[0] == mangled
    ]
    donor_id = [
        item for item in comdat_primary_identity_multiset(donor).elements() if item[0] == mangled
    ]
    require(
        len(seed_id) == len(donor_id) == 1 and seed_id == donor_id,
        f"{context} target is not the same mangled COMDAT",
    )
    require(
        sha256_bytes(_coff_body(seed, sp)) == function["expected_seed_body_sha256"],
        f"{context} seed target body changed",
    )
    expected = {
        ".xdata$x": (
            "expected_xdata_section_number",
            "expected_seed_xdata_sha256",
            "expected_donor_xdata_sha256",
        ),
        ".debug$S": (
            "expected_debug_section_number",
            "expected_seed_debug_sha256",
            "expected_donor_debug_sha256",
        ),
    }
    for name, (seat_key, seed_sha_key, donor_sha_key) in expected.items():
        left, right = (_comdat_child(seed, sp, name), _comdat_child(donor, dp, name))
        require(
            left["number"] == right["number"] == function[seat_key]
            and sha256_bytes(_coff_body(seed, left)) == function[seed_sha_key]
            and (sha256_bytes(_coff_body(donor, right)) == function[donor_sha_key]),
            f"{context} pinned {name} closure changed",
        )
    require(
        sp["relocation_count"] == dp["relocation_count"] == function["expected_relocation_count"]
        and sp["line_count"] == dp["line_count"] == function["expected_line_count"],
        f"{context} target relocation/line census changed",
    )
    return {
        "seed_section_count": len(seed.sections),
        "donor_section_count": len(donor.sections),
        "donor_only_function_count": sum(
            (function_multiset(donor) - function_multiset(seed)).values()
        ),
    }


def _comdat_child_closure(coff: _CoffObject, primary: dict[str, Any]) -> tuple[Any, ...]:
    """Return (count, sorted child section names) of a COMDAT's selection-5
    associates."""
    definitions = _section_definitions(coff)
    children = tuple(
        sorted(
            section["name"]
            for section in coff.sections
            if definitions.get(section["number"], {}).get("selection") == 5
            and definitions[section["number"]]["associated"] == primary["number"]
        )
    )
    return (len(children), children)


def _comdat_child(coff: _CoffObject, primary: dict[str, Any], name: str) -> dict[str, Any]:
    definitions = _section_definitions(coff)
    matches = [
        section
        for section in coff.sections
        if section["name"] == name
        and definitions.get(section["number"], {}).get("selection") == 5
        and (definitions[section["number"]]["associated"] == primary["number"])
    ]
    require(len(matches) == 1, f"expected one {name} child, found {len(matches)}")
    return matches[0]


def _coff_table_bytes(coff: _CoffObject, section: dict[str, Any], kind: str) -> bytes:
    if kind == "relocations":
        start = section["relocation_offset"]
        size = section["relocation_count"] * 10
    else:
        start = section["line_offset"]
        size = section["line_count"] * 6
    return coff.data[start : start + size] if size else b""


def _coff_marker(coff: _CoffObject, name: str, section_number: int):
    matches = [
        (index, symbol)
        for index, symbol in coff.symbols.items()
        if symbol["name"] == name
        and symbol["section"] == section_number
        and (symbol["storage"] == 101)
        and (symbol["aux_count"] >= 1)
    ]
    require(len(matches) == 1, f"expected one {name} marker in section {section_number}")
    return matches[0]


def _coff_section_symbol(coff: _CoffObject, section: dict[str, Any]):
    matches = [
        (index, symbol)
        for index, symbol in coff.symbols.items()
        if symbol["name"] == section["name"]
        and symbol["section"] == section["number"]
        and (symbol["storage"] == 3)
        and (symbol["aux_count"] >= 1)
    ]
    require(len(matches) == 1, "expected one section definition symbol")
    return matches[0]
