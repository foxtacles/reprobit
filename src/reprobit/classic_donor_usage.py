"""Shared donor usage bookkeeping for otherwise independent repair planners."""

from __future__ import annotations

from collections.abc import Collection, Iterable

from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.model import Scope
from reprobit.schema import ClassicRecipeIntervention

Beneficiary = tuple[str, str, str]


def beneficiary_keys(donor: ClassicRecipeIntervention) -> set[Beneficiary]:
    return {
        (scope.target, scope.translation_unit or "", scope.function or "")
        for scope in donor.beneficiaries
    }


def direct_donor_consumers(unit: ClassicPreparedUnit, donor_id: str) -> set[str]:
    """Include dependent donors as well as function actions when keeping a carrier."""

    return {
        consumer.id
        for consumer in (*unit.actions, *(item.intervention for item in unit.donors))
        if donor_id in consumer.dependencies
    }


def donor_after_usage(
    donor: ClassicRecipeIntervention,
    beneficiaries: Iterable[Beneficiary],
    consumers: Collection[str],
) -> ClassicRecipeIntervention | None:
    """Keep, update, or retire a donor after its callers have been re-pointed.

    Return the original object for unchanged usage.  Retire only when a changed
    beneficiary set is empty and no action or dependent donor still consumes it.
    Callers retain ownership of receipt edits and family-specific recipe changes.
    """

    desired = set(beneficiaries)
    if desired == beneficiary_keys(donor):
        return donor
    if not desired and not consumers:
        return None
    return donor.model_copy(
        update={
            "beneficiaries": tuple(
                Scope(target=target, translation_unit=unit, function=symbol)
                for target, unit, symbol in sorted(desired)
            )
        }
    )
