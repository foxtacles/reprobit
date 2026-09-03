"""The COMDAT census helpers index each object once and answer exactly as before."""

from __future__ import annotations

from collections import Counter
from typing import Any

import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.binary import require
from reprobit.classic import coff as subject
from reprobit.coff_format import CoffObject, section_definitions


def _naive_identity(coff: CoffObject, section: dict[str, Any]) -> tuple[Any, ...]:
    definitions = section_definitions(coff)
    definition = definitions.get(section["number"])
    require(definition is not None and definition["selection"] not in (0, 5), "not primary")
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
    require(len(owners) == 1, "no unique owner")
    owner = owners[0]
    return (
        owner["name"],
        owner["type"],
        owner["storage"],
        section["name"],
        definition["selection"],  # type: ignore[index]
        tuple(
            sorted(
                name
                for _, name in subject.associated_sections(coff, definitions, section["number"])
            )
        ),
    )


def _naive_multiset(coff: CoffObject) -> Counter[tuple[Any, ...]]:
    definitions = section_definitions(coff)
    return Counter(
        _naive_identity(coff, section)
        for section in coff.sections
        if definitions.get(section["number"], {}).get("selection") not in (None, 0, 5)
    )


def test_indexed_census_matches_the_direct_computation_and_is_cached() -> None:
    coff = CoffObject(coff_fixture.make_coff())

    first = subject.comdat_primary_identity_multiset(coff)
    assert first == _naive_multiset(coff)
    assert sum(first.values()) >= 1
    for section in coff.sections:
        definition = section_definitions(coff).get(section["number"])
        if definition is None or definition["selection"] in (0, 5):
            continue
        assert subject.comdat_primary_identity(coff, section) == _naive_identity(coff, section)

    # A caller mutating the returned multiset never disturbs the cached answer.
    first[("bogus",)] += 1
    second = subject.comdat_primary_identity_multiset(coff)
    assert ("bogus",) not in second
    assert second == _naive_multiset(coff)
    assert section_definitions(coff) is section_definitions(coff)
