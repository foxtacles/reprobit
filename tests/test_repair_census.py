"""The ledger census turns moved, unrecorded, linker-selected functions into synthetic refusals."""

from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace
from typing import Any, cast

import test_classic_register_bijection_reencoding_full as coff_fixture

from reprobit.classic_donors import generate_declaration_shape
from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_repair_dispatch import CapturedDonorObject, donor_recipe_identity
from reprobit.coff_format import CoffObject, coff_body
from reprobit.composition_ledger import ComposedBodyLedger, ComposedTargetLedger, LedgerFunction
from reprobit.model import Digest, Scope
from reprobit.repair_census import (
    CENSUS_DEPENDENCY_PLACEHOLDER,
    CENSUS_FAMILY,
    census_entry_id,
    plan_repair_census,
)
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
)

SYMBOL = coff_fixture.TARGET_SYMBOL
SOURCE = "src/unit.cpp"
OBJECT = "build/CMakeFiles/program.dir/src/unit.cpp.obj"
PLAN = ClassicTranslationUnitPlan(
    id="tu.fixture",
    target_id="program",
    build_target="program",
    source=SOURCE,
    source_digest=Digest.from_bytes(b"int reprobit_fixture;\n"),
)


def _body_digest(payload: bytes) -> str:
    obj = CoffObject(payload)
    return sha256(bytes(coff_body(obj, obj.function_section(SYMBOL)))).hexdigest()


def _ledger(payload: bytes, *, unit_id: str | None = "tu.fixture") -> ComposedBodyLedger:
    return ComposedBodyLedger(
        graph_digest="0" * 64,
        targets={
            "program": ComposedTargetLedger(
                functions={
                    SYMBOL: LedgerFunction(
                        provider=OBJECT,
                        translation_unit_id=unit_id,
                        body_sha256=_body_digest(payload),
                        body_length=len(coff_fixture.BODY),
                    )
                }
            )
        },
    )


def _bundle(
    *,
    planned: bool = True,
    recorded: tuple[str, ...] = (),
    donors: tuple[ClassicRecipeIntervention, ...] = (),
) -> Any:
    interventions = tuple(
        SimpleNamespace(
            scope=Scope(target="program", translation_unit=PLAN.id, function=symbol),
            role=ClassicRecipeRole.FUNCTION,
        )
        for symbol in recorded
    )
    return SimpleNamespace(
        build_plan=SimpleNamespace(translation_units=(PLAN,) if planned else ()),
        interventions=(*interventions, *donors),
    )


def _donor(donor_id: str, classes: int, functions: int) -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(classes, functions)
    return ClassicRecipeIntervention(
        id=donor_id,
        scope=Scope(target=PLAN.target_id, translation_unit=PLAN.id),
        rationale="Framework-generated declaration-only compiler-state shape for the fixture.",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target=PLAN.build_target,
        parameters=tuple(
            ClassicField(name=name, value=value)
            for name, value in sorted(
                {
                    "classes": classes,
                    "emission_policy": "non_emitting_declarations_only",
                    "functions": functions,
                    "generated_header_sha256": Digest.from_bytes(generated).value,
                }.items()
            )
        ),
    )


def _seed(payload: bytes, *, object_reference: str = OBJECT) -> dict[str, SeedObject]:
    return {
        "compiler.unit": SeedObject("compiler.unit", SOURCE, object_reference, "program", payload)
    }


VERIFIED = coff_fixture.make_coff()
MOVED = coff_fixture.make_coff(body=coff_fixture.BODY[:-1] + b"\x90" + coff_fixture.BODY[-1:])


def test_a_moved_unrecorded_function_becomes_a_synthetic_refusal() -> None:
    census = plan_repair_census(_bundle(), _ledger(VERIFIED), _seed(MOVED))

    (entry,) = census.entries
    assert entry.symbol == SYMBOL
    assert entry.translation_unit_id == PLAN.id
    assert entry.verified_body_sha256 == _body_digest(VERIFIED)
    assert entry.fresh_body_sha256 == _body_digest(MOVED)
    assert census.unplanned == () and census.unreadable == () and census.missing == ()
    (refusal,) = census.refusals
    assert refusal.synthetic
    assert refusal.unit_id == PLAN.id
    assert refusal.unit.plan == PLAN
    assert refusal.materials.seed_object == MOVED
    action = refusal.intervention
    assert action.id == census_entry_id(PLAN.id, SYMBOL)
    assert action.symbol == SYMBOL
    assert action.family is CENSUS_FAMILY
    assert action.role is ClassicRecipeRole.FUNCTION
    assert action.dependencies == (CENSUS_DEPENDENCY_PLACEHOLDER,)
    assert action.scope == Scope(target="program", translation_unit=PLAN.id, function=SYMBOL)
    assert refusal.receipt.intervention_id == action.id
    assert refusal.receipt.expected_values == {
        "expected_body_sha256": _body_digest(VERIFIED),
        "expected_body_length": len(coff_fixture.BODY),
    }


def test_an_unchanged_or_recorded_function_is_not_fallout() -> None:
    unchanged = plan_repair_census(_bundle(), _ledger(VERIFIED), _seed(VERIFIED))
    assert unchanged.entries == () and unchanged.refusals == ()

    recorded = plan_repair_census(_bundle(recorded=(SYMBOL,)), _ledger(VERIFIED), _seed(MOVED))
    assert recorded.entries == () and recorded.refusals == ()


def test_an_object_the_linker_took_nothing_from_is_ignored() -> None:
    census = plan_repair_census(
        _bundle(), _ledger(VERIFIED), _seed(MOVED, object_reference="build/other.obj")
    )
    assert census.entries == ()


def test_fallout_in_an_unplanned_unit_is_reported_not_recorded() -> None:
    census = plan_repair_census(
        _bundle(planned=False), _ledger(VERIFIED, unit_id=None), _seed(MOVED)
    )
    (entry,) = census.entries
    assert entry.translation_unit_id is None
    assert census.unplanned == (entry,)
    assert census.refusals == ()


def test_an_unreadable_object_and_a_vanished_function_are_reported() -> None:
    unreadable = plan_repair_census(_bundle(), _ledger(VERIFIED), _seed(b"raw:compiler.unit"))
    assert unreadable.unreadable == ("compiler.unit",)
    assert unreadable.entries == ()

    ledger = _ledger(VERIFIED)
    other = cast(Any, ledger.targets["program"].functions)
    other["?vanished@@YAXXZ"] = LedgerFunction(
        provider=OBJECT, translation_unit_id=PLAN.id, body_sha256="a" * 64, body_length=4
    )
    vanished = plan_repair_census(_bundle(), ledger, _seed(VERIFIED))
    (entry,) = vanished.entries
    assert entry.symbol == "?vanished@@YAXXZ"
    assert entry.fresh_body_sha256 == ""
    assert vanished.missing == (entry,)
    assert vanished.refusals == ()


def test_a_synthetic_refusal_carries_captured_objects_of_unchanged_donor_recipes() -> None:
    donor = _donor("donor.saved", 1, 2)
    bundle = _bundle(donors=(donor,))
    captured = {
        PLAN.id: {
            "donor.saved": CapturedDonorObject(donor_recipe_identity(donor), VERIFIED),
            "donor.gone": CapturedDonorObject("0" * 64, MOVED),
        },
        "tu.other": {"donor.x": CapturedDonorObject("1" * 64, MOVED)},
    }

    (refusal,) = plan_repair_census(
        bundle, _ledger(VERIFIED), _seed(MOVED), captured_donor_objects=captured
    ).refusals

    assert refusal.synthetic
    assert dict(refusal.unit_donor_objects) == {"donor.saved": VERIFIED}
    # A donor retuned since the capture no longer matches its recipe identity.
    stale = {PLAN.id: {"donor.saved": CapturedDonorObject("2" * 64, VERIFIED)}}
    (unbound,) = plan_repair_census(
        bundle, _ledger(VERIFIED), _seed(MOVED), captured_donor_objects=stale
    ).refusals
    assert dict(unbound.unit_donor_objects) == {}
    (bare,) = plan_repair_census(bundle, _ledger(VERIFIED), _seed(MOVED)).refusals
    assert dict(bare.unit_donor_objects) == {}
    # Widening a donor's beneficiaries does not change what it compiles.
    widened = donor.model_copy(
        update={
            "beneficiaries": (Scope(target="program", translation_unit=PLAN.id, function=SYMBOL),)
        }
    )
    assert donor_recipe_identity(widened) == donor_recipe_identity(donor)
