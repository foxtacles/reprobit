"""Carrier discovery settles a census entry by authoring records and retiring nothing."""

from __future__ import annotations

from dataclasses import replace

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture
from test_repair_census import MOVED, OBJECT, PLAN, SOURCE, SYMBOL, VERIFIED, _bundle, _ledger

from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_repair_discovery import _try_resolve, _unit_repair, _UnitWork
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.discovery_authoring import build_declaration_shape_donor
from reprobit.repair_census import plan_repair_census
from reprobit.repair_donor_analysis import _bind_refusals_to_probe_units
from reprobit.schema import ClassicRecipeRole


def _census_refusal() -> ClassicRepairRefusal:
    seeds = {"compiler.unit": SeedObject("compiler.unit", SOURCE, OBJECT, "program", MOVED)}
    (refusal,) = plan_repair_census(_bundle(), _ledger(VERIFIED), seeds).refusals
    return refusal


def test_a_census_entry_binds_to_its_fresh_unit_by_id_alone() -> None:
    refusal = _census_refusal()
    fresh = ClassicPreparedUnit(PLAN, (), (), (), (), ())

    (bound,) = _bind_refusals_to_probe_units((refusal,), (fresh,))

    assert bound.unit is fresh
    assert bound.synthetic
    stranger = replace(refusal, unit_id="tu.other")
    with pytest.raises(ClassicProjectError, match="cannot find freshly prepared"):
        _bind_refusals_to_probe_units((stranger,), (fresh,))


def test_a_discovered_state_carrying_the_verified_body_only_adds_records() -> None:
    refusal = _census_refusal()
    unit = ClassicPreparedUnit(PLAN, (), (), (), (), ())
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})
    record = build_declaration_shape_donor(
        target_id=PLAN.target_id,
        translation_unit_id=PLAN.id,
        build_target=PLAN.build_target,
        classes=1,
        functions=3,
    )
    donor = record.intervention

    settled = _try_resolve(entry, refusal, donor, VERIFIED)

    assert settled is not None
    resolution, _product = settled
    assert resolution.how == "reauthor"
    assert resolution.symbol == SYMBOL
    entry.resolved[refusal.intervention.id] = settled
    entry.kept_donors[donor.id] = donor
    entry.receipts[donor.id] = record.receipt

    repair = _unit_repair(entry)

    assert repair is not None
    assert repair.intervention_edits == ()
    assert repair.receipt_edits == ()
    assert repair.dependency_edits == ()
    families = {item.intervention.role: item.intervention for item in repair.additions}
    function = families[ClassicRecipeRole.FUNCTION]
    assert function.symbol == SYMBOL
    assert function.dependencies == (donor.id,)
    assert function.id != refusal.intervention.id
    kept = families[ClassicRecipeRole.DONOR]
    assert [scope.function for scope in kept.beneficiaries] == [SYMBOL]


def test_a_discovered_state_without_the_verified_body_does_not_settle_a_census_entry() -> None:
    refusal = _census_refusal()
    unit = ClassicPreparedUnit(PLAN, (), (), (), (), ())
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})
    record = build_declaration_shape_donor(
        target_id=PLAN.target_id,
        translation_unit_id=PLAN.id,
        build_target=PLAN.build_target,
        classes=1,
        functions=3,
    )
    other = coff_fixture.make_coff(body=coff_fixture.BODY[:-1] + b"\xcc" + coff_fixture.BODY[-1:])

    assert _try_resolve(entry, refusal, record.intervention, other) is None
    assert _unit_repair(entry) is None
