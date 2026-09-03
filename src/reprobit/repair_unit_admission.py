"""Admit translation units that carry unrecorded fallout but no build-plan entry.

The composed-body ledger census can find a moved function in a source file
the build plan never listed: nothing about that unit was ever recorded, so the
saved guidance has no shard to receive the records carrier discovery would
author.  Admission writes exactly what a CMake import would have written for
the unit -- one plan entry whose source digest pins the effective bytes, one
empty intervention shard and one empty proof shard -- in a single guarded
transaction, so the next repair pass can discover and record the fallout
like any other.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from reprobit.authority_snapshot import AuthoritySnapshotError, json_authority_members
from reprobit.model import Digest
from reprobit.repair_census import RepairCensusEntry
from reprobit.schema import (
    BuildPlanDocument,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
)
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

_SOURCE_OVERLAY_FAMILY = "source_overlay_graph"
_SHARD_SUBDIRECTORY = "tus"


class TranslationUnitAdmissionError(RuntimeError):
    """A translation unit cannot be admitted from the census evidence."""


def _normalized(path: str) -> str:
    return path.replace("\\", "/").casefold()


def _effective_digests(bundle: ProjectBundle) -> dict[str, str]:
    """Effective source digests of every project overlay output, keyed by normalized path."""

    digests: dict[str, str] = {}
    for intervention in bundle.interventions:
        family = getattr(intervention, "family", None)
        if getattr(family, "value", family) != _SOURCE_OVERLAY_FAMILY:
            continue
        for parameter in getattr(intervention, "parameters", ()):
            if getattr(parameter, "name", None) != "outputs":
                continue
            outputs = getattr(parameter, "value", None)
            if not isinstance(outputs, list | tuple):
                continue
            for output in outputs:
                if not isinstance(output, Mapping):
                    continue
                path, effective = output.get("path"), output.get("effective")
                if isinstance(path, str) and isinstance(effective, str):
                    digests[_normalized(path)] = effective
    return digests


def plan_translation_unit_admissions(
    bundle: ProjectBundle, entries: Sequence[RepairCensusEntry]
) -> tuple[ClassicTranslationUnitPlan, ...]:
    """Derive one plan entry per unplanned (build target, source) the census named.

    The identity follows the CMake import exactly, so a unit admitted here has
    the id an import would have given it.  The source digest pins the bytes the
    compiler reads: the project overlay's effective output when the source is
    one, the clean manifest digest otherwise.
    """

    plan = bundle.build_plan
    if plan is None:
        raise TranslationUnitAdmissionError("the project has no build plan to admit units into")
    manifest_entries = {
        _normalized(entry.path): entry
        for entry in (bundle.source_manifest.entries if bundle.source_manifest else ())
    }
    effective = _effective_digests(bundle)
    existing_ids = {unit.id.casefold() for unit in plan.translation_units}
    existing_units = {
        (unit.build_target.casefold(), _normalized(unit.source)) for unit in plan.translation_units
    }
    admitted: dict[tuple[str, str], ClassicTranslationUnitPlan] = {}
    for entry in entries:
        if not entry.target_id or not entry.build_target:
            raise TranslationUnitAdmissionError(
                f"census entry for {entry.source}:{entry.symbol} names no target"
            )
        key = (entry.build_target.casefold(), _normalized(entry.source))
        if key in admitted:
            continue
        if key in existing_units:
            raise TranslationUnitAdmissionError(
                f"{entry.source} of {entry.build_target} is already planned"
            )
        manifest_entry = manifest_entries.get(_normalized(entry.source))
        if manifest_entry is None:
            raise TranslationUnitAdmissionError(
                f"{entry.source} is not in the locked source manifest"
            )
        identity = Digest.from_bytes(
            canonical_json(
                {
                    "schema": 1,
                    "target": entry.target_id,
                    "build_target": entry.build_target,
                    "source": manifest_entry.path,
                }
            )
        ).value
        unit_id = f"tu.{identity[:24]}"
        if unit_id.casefold() in existing_ids:
            raise TranslationUnitAdmissionError(
                f"admitted translation-unit identity {unit_id!r} collides with the plan"
            )
        existing_ids.add(unit_id.casefold())
        digest = effective.get(_normalized(manifest_entry.path), manifest_entry.digest.value)
        admitted[key] = ClassicTranslationUnitPlan(
            id=unit_id,
            target_id=entry.target_id,
            build_target=entry.build_target,
            source=manifest_entry.path,
            source_digest=Digest(algorithm="sha256", value=digest),
        )
    return tuple(admitted[key] for key in sorted(admitted))


def _members(root: Path, directory: str) -> tuple[str, ...]:
    try:
        return json_authority_members(root, directory)
    except AuthoritySnapshotError as exc:
        raise TranslationUnitAdmissionError(
            f"cannot inspect classic authority {directory!r}: {exc}"
        ) from exc


def _shard_relative(
    directory: str, members: Sequence[str], unit: ClassicTranslationUnitPlan
) -> str:
    """Place the shard where the project keeps its unit shards.

    A tree whose shards live under a ``tus`` subdirectory with ``<target>--<unit>``
    names keeps that convention; otherwise the shard is named by the unit id at
    the directory root, as the CMake import writes it.
    """

    base = PurePosixPath(directory.replace("\\", "/"))
    prefix = f"{_SHARD_SUBDIRECTORY}/"
    if any(member.replace("\\", "/").startswith(prefix) for member in members):
        return (base / _SHARD_SUBDIRECTORY / f"{unit.target_id}--{unit.id}.json").as_posix()
    return (base / f"{unit.id}.json").as_posix()


def apply_translation_unit_admissions(
    root: Path,
    spec: ProjectSpec,
    units: Sequence[ClassicTranslationUnitPlan],
) -> tuple[str, ...]:
    """Write the plan entries and empty shards of ``units`` in one guarded transaction."""

    unit_tuple = tuple(units)
    if not unit_tuple:
        return ()
    plan_relative = spec.layout.build_plan.replace("\\", "/")
    plan_path = root.joinpath(*PurePosixPath(plan_relative).parts)
    if plan_path.is_symlink() or not plan_path.is_file():
        raise TranslationUnitAdmissionError(f"build plan is unavailable: {plan_relative!r}")
    payload = plan_path.read_bytes()
    try:
        current = BuildPlanDocument.model_validate_json(payload)
    except ValueError as exc:
        raise TranslationUnitAdmissionError(f"invalid build plan {plan_relative!r}: {exc}") from exc
    known = {unit.id.casefold() for unit in current.translation_units}
    for unit in unit_tuple:
        if unit.id.casefold() in known:
            raise TranslationUnitAdmissionError(
                f"translation unit {unit.id!r} is already in the build plan"
            )
        known.add(unit.id.casefold())
    plan_data = current.model_dump(mode="python")
    plan_data["translation_units"] = tuple(
        sorted(
            (*current.translation_units, *unit_tuple),
            key=lambda item: (item.id.casefold(), item.id),
        )
    )
    try:
        updated = BuildPlanDocument.model_validate(plan_data)
    except ValueError as exc:
        raise TranslationUnitAdmissionError(f"admitted build plan is invalid: {exc}") from exc

    intervention_members = _members(root, spec.layout.interventions)
    proof_members = _members(root, spec.layout.proofs)
    transaction = CASTransaction(root)
    changed: list[str] = []
    transaction.write(
        plan_relative, canonical_json(updated), expected_sha256=Digest.from_bytes(payload).value
    )
    changed.append(plan_relative)
    for unit in unit_tuple:
        intervention_relative = _shard_relative(
            spec.layout.interventions, intervention_members, unit
        )
        proof_relative = _shard_relative(spec.layout.proofs, proof_members, unit)
        for relative in (intervention_relative, proof_relative):
            if root.joinpath(*PurePosixPath(relative).parts).exists():
                raise TranslationUnitAdmissionError(
                    f"admission will not replace an existing authority file: {relative!r}"
                )
        transaction.write(
            intervention_relative,
            canonical_json(
                InterventionDocument(
                    schema_version=3,
                    target_id=unit.target_id,
                    translation_unit_id=unit.id,
                    source=unit.source,
                    source_digest=unit.source_digest,
                    build_target=unit.build_target,
                )
            ),
            expected_sha256=None,
        )
        transaction.write(
            proof_relative,
            canonical_json(
                ProofDocument(
                    schema_version=3, target_id=unit.target_id, translation_unit_id=unit.id
                )
            ),
            expected_sha256=None,
        )
        changed.extend((intervention_relative, proof_relative))
    transaction.commit()
    return tuple(sorted(changed, key=lambda item: (item.casefold(), item)))


__all__ = [
    "TranslationUnitAdmissionError",
    "apply_translation_unit_admissions",
    "plan_translation_unit_admissions",
]
