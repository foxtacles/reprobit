"""Carrier discovery settles a census entry by authoring records and retiring nothing."""

from __future__ import annotations

from dataclasses import replace

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture
from test_repair_census import MOVED, OBJECT, PLAN, SOURCE, SYMBOL, VERIFIED, _bundle, _ledger

from reprobit.classic_donors import generate_declaration_shape, prepare_donor_compile_request
from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_repair_discovery import (
    _prepare_attempts,
    _saved_state_identity,
    _settle_attempt,
    _try_resolve,
    _unit_repair,
    _UnitWork,
)
from reprobit.classic_repair_dispatch import CapturedDonorObject, donor_recipe_identity
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.discovery_authoring import build_declaration_shape_donor
from reprobit.model import Digest, Scope
from reprobit.repair_census import plan_repair_census
from reprobit.repair_donor_analysis import _bind_refusals_to_probe_units
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)

SOURCE_TEXT = b"int reprobit_fixture;\n"


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


def _saved_shape_donor(donor_id: str, classes: int, functions: int) -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(classes, functions)
    return ClassicRecipeIntervention(
        id=donor_id,
        scope=Scope(target=PLAN.target_id, translation_unit=PLAN.id),
        rationale="Framework-generated declaration-only compiler-state shape for the fixture.",
        beneficiaries=(
            Scope(target=PLAN.target_id, translation_unit=PLAN.id, function="?other@@YAXXZ"),
        ),
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


def _prepared_saved(donor: ClassicRecipeIntervention) -> ClassicPreparedDonor:
    receipt = ClassicProofReceipt(
        id=f"proof.{donor.id}", intervention_id=donor.id, family=donor.family, expected_values={}
    )
    return ClassicPreparedDonor(
        donor,
        prepare_donor_compile_request(
            donor,
            source_path=SOURCE,
            clean_source=SOURCE_TEXT,
            effective_source=SOURCE_TEXT,
            receipts=(receipt,),
        ),
    )


def _unit_with_saved_carriers() -> tuple[ClassicPreparedUnit, ClassicPreparedDonor]:
    saved = _prepared_saved(_saved_shape_donor("donor.saved", 1, 2))
    overlay = ClassicRecipeIntervention(
        id="donor.overlay",
        scope=Scope(target=PLAN.target_id, translation_unit=PLAN.id),
        rationale="Donor-private overlay rendering of the fixture translation unit.",
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        role=ClassicRecipeRole.DONOR,
        build_target=PLAN.build_target,
    )
    unit = ClassicPreparedUnit(
        PLAN,
        (saved, ClassicPreparedDonor(overlay, saved.request)),
        (),
        (),
        (),
        (saved.request.receipt,),
    )
    return unit, saved


def test_a_census_entry_tries_the_units_saved_carriers_before_any_fresh_state() -> None:
    refusal = _census_refusal()
    unit, saved = _unit_with_saved_carriers()
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})

    order = _prepare_attempts(
        {PLAN.id: entry},
        clean_sources={SOURCE: SOURCE_TEXT},
        effective_sources={SOURCE: SOURCE_TEXT},
        per_unit=2,
    )

    first_probe, _unit_id = order[0]
    first_intervention = next(donor for probe, donor, _p in entry.attempts if probe == first_probe)
    assert first_intervention is saved.intervention
    assert entry.saved_attempts == {first_probe}
    assert entry.identities[first_probe] == _saved_state_identity(saved.intervention)
    # The overlay donor cannot host a new consumer; only the shape was enqueued,
    # and the per-unit budget still buys two fresh states after it.
    assert next(donor.id for _probe, donor, _p in entry.attempts) == "donor.saved"
    assert "donor.overlay" not in {donor.id for _probe, donor, _p in entry.attempts}
    assert len(entry.attempts) == 3


def test_a_saved_carrier_carrying_the_verified_body_hosts_the_census_entry() -> None:
    refusal = _census_refusal()
    unit, saved = _unit_with_saved_carriers()
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})
    entry.saved_attempts.add("discovery_probe_0000")

    _settle_attempt(entry, "discovery_probe_0000", saved.intervention, saved, VERIFIED)

    assert refusal.intervention.id in entry.resolved
    assert entry.kept_donors == {}
    repair = _unit_repair(entry)

    assert repair is not None
    (addition,) = repair.additions
    assert addition.intervention.role is ClassicRecipeRole.FUNCTION
    assert addition.intervention.symbol == SYMBOL
    assert addition.intervention.dependencies == ("donor.saved",)
    assert addition.replaces_intervention_id is None
    (edit,) = repair.intervention_edits
    assert edit.before is saved.intervention
    assert edit.after is not None
    assert sorted(scope.function or "" for scope in edit.after.beneficiaries) == sorted(
        ["?other@@YAXXZ", SYMBOL]
    )
    assert repair.receipt_edits == ()
    assert repair.dependency_edits == ()


def test_a_fresh_state_settling_a_census_entry_is_still_kept_as_a_new_donor() -> None:
    refusal = _census_refusal()
    unit, _saved = _unit_with_saved_carriers()
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})
    record = build_declaration_shape_donor(
        target_id=PLAN.target_id,
        translation_unit_id=PLAN.id,
        build_target=PLAN.build_target,
        classes=3,
        functions=3,
    )
    fresh = _prepared_saved(record.intervention)

    _settle_attempt(entry, "discovery_probe_0007", record.intervention, fresh, VERIFIED)

    assert refusal.intervention.id in entry.resolved
    assert set(entry.kept_donors) == {record.intervention.id}


def test_a_replayed_later_candidate_cannot_overtake_a_saved_carrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outcomes are settled in preference order, not in the order they land."""

    from test_classic_repair_discovery import _Handle, _probe_output

    import reprobit.classic_repair_discovery as subject

    refusal = _census_refusal()
    unit, saved = _unit_with_saved_carriers()
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    delivered: list[str] = []

    def fake_windows(
        _probes: object,
        units: tuple[ClassicPreparedUnit, ...],
        windows: object,
        *,
        evaluate: object,
        progress: object = None,
        planned_candidates: int,
        cache: object = None,
        close_runtime: bool = True,
        materialize_source_epoch: bool = True,
        source_seal: object | None = None,
        namespace_id: str = "noncertifying-donor-repair-probe",
    ) -> tuple[str, ...]:
        del progress, planned_candidates, cache, close_runtime
        del materialize_source_epoch, source_seal, namespace_id
        by_id = {item.donors[0].intervention.id: item for item in units}
        for window in windows:  # type: ignore[attr-defined]
            # Every candidate carries the verified body; the later ones land first,
            # the way replayed candidates do.
            batch = tuple(_probe_output(donor_id, by_id[donor_id], VERIFIED) for donor_id in window)
            delivered.extend(item.donor_id for item in reversed(batch))
            if evaluate(tuple(reversed(batch))):  # type: ignore[operator]
                break
        return tuple(delivered)

    monkeypatch.setattr(subject, "probe_donor_compile_windows", fake_windows)
    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={SOURCE: SOURCE_TEXT},
        effective_sources={SOURCE: SOURCE_TEXT},
        per_unit=3,
        window_size=4,
    )

    assert delivered[0] != "discovery_probe_0000"
    (repair,) = result.repairs
    (resolution,) = repair.resolutions
    assert resolution.donor_id == saved.intervention.id
    assert resolution.how == "reauthor"
    assert all(item.intervention.role is ClassicRecipeRole.FUNCTION for item in repair.additions)
    assert [edit.before.id for edit in repair.intervention_edits] == [saved.intervention.id]
    # The saved carrier was compiled, but it is not a fresh state this command tried.
    assert _saved_state_identity(saved.intervention) not in result.tried_states.get(
        PLAN.id, frozenset()
    )


def test_a_captured_saved_carrier_object_hosts_the_census_entry_without_any_compile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_classic_repair_discovery import _Handle

    import reprobit.classic_repair_discovery as subject

    unit, saved = _unit_with_saved_carriers()
    seeds = {"compiler.unit": SeedObject("compiler.unit", SOURCE, OBJECT, "program", MOVED)}
    (refusal,) = plan_repair_census(
        _bundle(donors=(saved.intervention,)),
        _ledger(VERIFIED),
        seeds,
        captured_donor_objects={
            PLAN.id: {
                saved.intervention.id: CapturedDonorObject(
                    donor_recipe_identity(saved.intervention), VERIFIED
                )
            }
        },
    ).refusals
    assert dict(refusal.unit_donor_objects) == {saved.intervention.id: VERIFIED}
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))

    def never_compile(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise AssertionError("captured objects must settle the entry without a compile")

    monkeypatch.setattr(subject, "probe_donor_compile_windows", never_compile)
    handle = _Handle()
    result = subject.probe_carrier_discovery(
        handle,  # type: ignore[arg-type]
        (refusal,),
        clean_sources={SOURCE: SOURCE_TEXT},
        effective_sources={SOURCE: SOURCE_TEXT},
    )

    assert result.compiled_candidates == 0
    assert result.unresolved == ()
    assert result.tried_states == {}
    assert handle.closed == 1
    (repair,) = result.repairs
    (resolution,) = repair.resolutions
    assert resolution.donor_id == saved.intervention.id
    assert [edit.before.id for edit in repair.intervention_edits] == [saved.intervention.id]
    assert all(item.intervention.role is ClassicRecipeRole.FUNCTION for item in repair.additions)


def test_a_saved_carrier_with_a_captured_object_is_not_compiled_again() -> None:
    unit, saved = _unit_with_saved_carriers()
    other = _prepared_saved(_saved_shape_donor("donor.uncaptured", 2, 2))
    unit = ClassicPreparedUnit(PLAN, (*unit.donors, other), (), (), (), unit.receipts)
    seeds = {"compiler.unit": SeedObject("compiler.unit", SOURCE, OBJECT, "program", MOVED)}
    (refusal,) = plan_repair_census(
        _bundle(donors=(saved.intervention, other.intervention)),
        _ledger(VERIFIED),
        seeds,
        captured_donor_objects={
            PLAN.id: {
                saved.intervention.id: CapturedDonorObject(
                    donor_recipe_identity(saved.intervention), MOVED
                )
            }
        },
    ).refusals
    (refusal,) = _bind_refusals_to_probe_units((refusal,), (unit,))
    entry = _UnitWork(unit, [refusal], [], {}, {}, {})

    _prepare_attempts(
        {PLAN.id: entry},
        clean_sources={SOURCE: SOURCE_TEXT},
        effective_sources={SOURCE: SOURCE_TEXT},
        per_unit=1,
    )

    enqueued = [donor.id for probe, donor, _p in entry.attempts if probe in entry.saved_attempts]
    assert enqueued == ["donor.uncaptured"]
