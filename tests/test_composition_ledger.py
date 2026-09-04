"""The composed-body ledger records linker-selected bodies and finds unrecorded fallout."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest
import test_classic_fpo_mosaic_identity as fixture
from pydantic import ValidationError

from reprobit import composition_ledger as subject

SYMBOL = fixture.TARGET_SYMBOL
GRAPH = "1" * 64


def _object(first_byte: int) -> bytes:
    body = bytearray(fixture.SEED_BODY)
    body[0] = first_byte
    return fixture.make_coff(body=bytes(body))


def _provided(name: str, first_byte: int, unit: str) -> subject.ProvidedObject:
    return subject.ProvidedObject(
        f"build/{name}.obj", subject.function_bodies(_object(first_byte)), unit
    )


def _digest(first_byte: int) -> str:
    body = bytearray(fixture.SEED_BODY)
    body[0] = first_byte
    return sha256(bytes(body)).hexdigest()


def test_function_bodies_lists_external_code_symbols_with_their_digests() -> None:
    bodies = subject.function_bodies(_object(0x90))

    assert set(bodies) == {SYMBOL}
    assert bodies[SYMBOL] == subject.FunctionBody(_digest(0x90), len(fixture.SEED_BODY))


def test_first_positional_definer_provides_the_function() -> None:
    first = _provided("a", 0x90, "tu.a")
    second = _provided("b", 0x91, "tu.b")

    selected = subject.select_providers((first, second))

    assert selected == {
        SYMBOL: subject.LedgerFunction(
            provider="build/a.obj",
            translation_unit_id="tu.a",
            body_sha256=_digest(0x90),
            body_length=len(fixture.SEED_BODY),
        )
    }
    assert subject.select_providers((second, first))[SYMBOL].provider == "build/b.obj"


def test_ledger_round_trips_canonically(tmp_path: Path) -> None:
    ledger = subject.build_ledger(
        GRAPH,
        {
            "program": (
                subject.ProvidedObject(
                    "build/a.obj", subject.function_bodies(_object(0x90)), "tu.a"
                ),
            )
        },
    )
    path = tmp_path / "ledger" / "composed-bodies.json"

    subject.write_ledger(path, ledger)
    subject.write_ledger(path, ledger)

    assert subject.read_ledger(path) == ledger
    assert not path.with_name(path.name + ".tmp").exists()
    assert ledger.schema_version == 1
    with pytest.raises(ValidationError):
        subject.ComposedBodyLedger(graph_digest="nope")


def test_census_reports_only_selected_unrecorded_functions_that_moved() -> None:
    ledger = subject.build_ledger(
        GRAPH,
        {
            "program": (
                subject.ProvidedObject(
                    "build/a.obj", subject.function_bodies(_object(0x90)), "tu.a"
                ),
                subject.ProvidedObject(
                    "build/b.obj", subject.function_bodies(_object(0x91)), "tu.b"
                ),
            )
        },
    )
    target = ledger.targets["program"]
    moved = subject.function_bodies(_object(0x92))

    # tu.a provides the symbol and moved: fallout.  tu.b also moved but the linker never
    # takes its copy.  A recorded function in tu.a is the repair's business, not the census's.
    assert subject.census_unrecorded_fallout(target, {"tu.a": moved, "tu.b": moved}, {}) == (
        subject.UnrecordedFallout(
            "tu.a", SYMBOL, _digest(0x90), len(fixture.SEED_BODY), _digest(0x92)
        ),
    )
    assert subject.census_unrecorded_fallout(target, {"tu.a": moved}, {"tu.a": {SYMBOL}}) == ()
    unchanged = subject.function_bodies(_object(0x90))
    assert subject.census_unrecorded_fallout(target, {"tu.a": unchanged}, {}) == ()
    assert set(subject.ledger_translation_units(ledger)) == {"tu.a"}
