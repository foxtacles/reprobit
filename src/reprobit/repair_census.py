"""Unrecorded-fallout census: fresh seed objects against the composed-body ledger.

A source edit does not only disturb functions that carry saved records.  A
function without any record whose fresh seed body left the body the linker
selected at the last accepted verify changes the image exactly like a refused
record does, yet nothing in the saved guidance names it.  The census compares
every fresh compiler output of a repair analysis with the ledger of verified
bodies, keeps only the functions the linker took from that very object, and
turns each moved, unrecorded one into a *synthetic* refusal: a placeholder
``equal_body_strict`` record whose receipt pins the verified body.  Carrier
discovery then treats it like any refused record, except that settling it only
adds records and retires nothing.

Fallout in a translation unit the build plan does not list cannot be recorded
without a plan entry; it is reported separately so the operator adds the unit
instead of the repair silently succeeding with a changed image.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from reprobit.binary import ByteIdentityError
from reprobit.classic_incremental_context import SeedObject
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.composition_ledger import (
    ComposedBodyLedger,
    FunctionBody,
    LedgerFunction,
    function_bodies,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeIntervention,
    ClassicTranslationUnitPlan,
    ProjectBundle,
)

CENSUS_DEPENDENCY_PLACEHOLDER = "census.pending"
"""A function record must name one primary donor; a census entry has none yet."""
CENSUS_FAMILY = ClassicRecipeFamily.EQUAL_BODY_STRICT


@dataclass(frozen=True, slots=True)
class RepairCensusEntry:
    """One linker-selected, unrecorded function whose fresh seed body moved."""

    source: str
    object_reference: str
    symbol: str
    verified_body_sha256: str
    verified_body_length: int
    fresh_body_sha256: str
    translation_unit_id: str | None = None
    target_id: str = ""
    """The target whose linker selected the function (its image is the one that moves)."""
    build_target: str = ""
    """The compiler node's owning build target, as the translation-unit plan names it."""


@dataclass(frozen=True, slots=True)
class RepairCensus:
    entries: tuple[RepairCensusEntry, ...]
    """Every moved, unrecorded function, planned or not."""
    refusals: tuple[ClassicRepairRefusal, ...]
    """Synthetic refusals for the entries whose translation unit the build plan lists."""
    unplanned: tuple[RepairCensusEntry, ...]
    """Entries in translation units without a plan entry: nothing can record them yet."""
    unreadable: tuple[str, ...]
    """Compiler nodes whose captured object is not a COFF object."""
    missing: tuple[RepairCensusEntry, ...]
    """Selected functions the fresh object no longer defines at all."""


def census_entry_id(unit_id: str, symbol: str) -> str:
    digest = sha256(f"{unit_id}\0{symbol}".encode()).hexdigest()[:16]
    return f"census.{digest}"


def _normalized(path: str) -> str:
    return path.replace("\\", "/").casefold()


def _provider_functions(
    ledger: ComposedBodyLedger,
) -> dict[str, dict[str, tuple[str, LedgerFunction]]]:
    """Per provider object, the functions some target's linker selected from it, with the target."""

    providers: dict[str, dict[str, tuple[str, LedgerFunction]]] = {}
    for target_id, target in sorted(ledger.targets.items()):
        for symbol, function in target.functions.items():
            providers.setdefault(_normalized(function.provider), {}).setdefault(
                symbol, (target_id, function)
            )
    return providers


def _planned_units(bundle: ProjectBundle) -> dict[tuple[str, str], ClassicTranslationUnitPlan]:
    plan = bundle.build_plan
    if plan is None:
        return {}
    return {
        (unit.build_target.casefold(), _normalized(unit.source)): unit
        for unit in plan.translation_units
    }


def _recorded_symbols(bundle: ProjectBundle) -> dict[str, set[str]]:
    """Function symbols that already carry a record (of any role) per translation unit."""

    recorded: dict[str, set[str]] = {}
    for intervention in bundle.interventions:
        scope = getattr(intervention, "scope", None)
        unit_id = getattr(scope, "translation_unit", None)
        function = getattr(scope, "function", None)
        if isinstance(unit_id, str) and isinstance(function, str) and function:
            recorded.setdefault(unit_id, set()).add(function)
    return recorded


def _seed_bodies(data: bytes) -> Mapping[str, FunctionBody] | None:
    try:
        return function_bodies(data)
    except (ByteIdentityError, ValueError, IndexError, KeyError, struct.error):
        return None


def synthetic_census_refusal(
    plan: ClassicTranslationUnitPlan, entry: RepairCensusEntry, seed_object: bytes
) -> ClassicRepairRefusal:
    """A placeholder refusal that carrier discovery settles by authoring a fresh record."""

    intervention = ClassicRecipeIntervention(
        id=census_entry_id(plan.id, entry.symbol),
        scope=Scope(target=plan.target_id, translation_unit=plan.id, function=entry.symbol),
        rationale=(
            "Unrecorded fallout of a source edit: the linker-selected body of this "
            "function left the body verified last; a fresh carrier state must restore it."
        ),
        dependencies=(CENSUS_DEPENDENCY_PLACEHOLDER,),
        family=CENSUS_FAMILY,
        role=ClassicRecipeRole.FUNCTION,
        build_target=plan.build_target,
        symbol=entry.symbol,
    )
    receipt = ClassicProofReceipt(
        id=f"proof.{intervention.id}",
        intervention_id=intervention.id,
        family=CENSUS_FAMILY,
        expected_values={
            "expected_body_sha256": entry.verified_body_sha256,
            "expected_body_length": entry.verified_body_length,
        },
    )
    return ClassicRepairRefusal(
        unit_id=plan.id,
        action_index=-1,
        intervention=intervention,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=seed_object, donor_object=seed_object),
        unit=ClassicPreparedUnit(plan, (), (), (), (), ()),
        reason=(
            f"unrecorded function {entry.symbol!r} of {entry.source} left its verified body "
            f"{entry.verified_body_sha256[:16]}"
        ),
        synthetic=True,
    )


def plan_repair_census(
    bundle: ProjectBundle,
    ledger: ComposedBodyLedger,
    seed_objects: Mapping[str, SeedObject],
) -> RepairCensus:
    """Compare every captured seed object with the ledger and plan the synthetic refusals.

    Only functions the linker selected from the very object a seed stands for
    are compared: a body the linker takes from another object cannot change
    the image.  Functions that already carry a record in their translation
    unit are the ordinary repair's business and are skipped.
    """

    providers = _provider_functions(ledger)
    planned = _planned_units(bundle)
    recorded = _recorded_symbols(bundle)
    entries: list[RepairCensusEntry] = []
    refusals: list[ClassicRepairRefusal] = []
    unplanned: list[RepairCensusEntry] = []
    unreadable: list[str] = []
    missing: list[RepairCensusEntry] = []
    for node_id, seed in sorted(seed_objects.items()):
        verified_functions = providers.get(_normalized(seed.object_reference))
        if not verified_functions:
            continue
        bodies = _seed_bodies(seed.data)
        if bodies is None:
            unreadable.append(node_id)
            continue
        plan = planned.get((seed.build_target.casefold(), _normalized(seed.source)))
        known = recorded.get(plan.id, set()) if plan is not None else set()
        for symbol, (target_id, verified) in sorted(verified_functions.items()):
            if symbol in known:
                continue
            fresh = bodies.get(symbol)
            if fresh is not None and fresh.sha256 == verified.body_sha256:
                continue
            entry = RepairCensusEntry(
                seed.source,
                seed.object_reference,
                symbol,
                verified.body_sha256,
                verified.body_length,
                fresh.sha256 if fresh is not None else "",
                plan.id if plan is not None else None,
                target_id,
                seed.build_target,
            )
            entries.append(entry)
            if fresh is None:
                missing.append(entry)
            elif plan is None:
                unplanned.append(entry)
            else:
                refusals.append(synthetic_census_refusal(plan, entry, seed.data))
    return RepairCensus(
        tuple(entries), tuple(refusals), tuple(unplanned), tuple(unreadable), tuple(missing)
    )


__all__ = [
    "CENSUS_DEPENDENCY_PLACEHOLDER",
    "CENSUS_FAMILY",
    "RepairCensus",
    "RepairCensusEntry",
    "census_entry_id",
    "plan_repair_census",
    "synthetic_census_refusal",
]
