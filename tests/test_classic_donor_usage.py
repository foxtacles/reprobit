"""Donor retirement stays sensitive to both beneficiaries and dependent carriers."""

from __future__ import annotations

from test_classic_repair_discovery_census import _saved_shape_donor

from reprobit.classic_donor_usage import beneficiary_keys, donor_after_usage


def test_donor_is_retired_only_after_all_changed_usage_disappears() -> None:
    donor = _saved_shape_donor("donor.saved", 1, 2)
    assert donor.beneficiaries
    assert donor_after_usage(donor, (), ()) is None
    retained = donor_after_usage(donor, (), {"dependent.donor"})
    assert retained is not None and retained.beneficiaries == ()
    assert retained.parameters == donor.parameters


def test_donor_usage_preserves_unchanged_authority_and_orders_scope_updates() -> None:
    donor = _saved_shape_donor("donor.saved", 1, 2)
    assert donor_after_usage(donor, beneficiary_keys(donor), ()) is donor
    scopes = {("program", "tu.second", "_z"), ("program", "tu.first", "_a")}
    updated = donor_after_usage(donor, scopes, {"function.new"})
    assert updated is not None
    assert beneficiary_keys(updated) == scopes
    assert tuple(scope.function for scope in updated.beneficiaries) == ("_a", "_z")
    assert donor.beneficiaries != updated.beneficiaries
