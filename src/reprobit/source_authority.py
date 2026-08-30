"""Read-only checks for committed source and effective translation-unit authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from reprobit.model import Digest
from reprobit.schema import (
    BuildPlanDocument,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProjectBundle,
    SourceManifestDocument,
)
from reprobit.source_lock import SourceLockError, receipt_source_input

if TYPE_CHECKING:
    from reprobit.classic_overlay_tokens import ClassicOverlayRenderSession


class SourceAuthorityError(ValueError):
    """Committed source or overlay authority no longer describes current bytes."""


@dataclass(frozen=True, slots=True)
class TranslationUnitPinStatus:
    translation_unit_id: str
    source: str
    expected_digest: str
    actual_digest: str | None

    @property
    def stale(self) -> bool:
        return self.actual_digest != self.expected_digest


@dataclass(frozen=True, slots=True)
class SourceAuthorityReport:
    verified_inputs: int
    overlay_outputs: tuple[str, ...]
    translation_units: tuple[TranslationUnitPinStatus, ...]

    @property
    def stale_translation_units(self) -> tuple[TranslationUnitPinStatus, ...]:
        return tuple(item for item in self.translation_units if item.stale)


@dataclass(frozen=True, slots=True)
class _DonorOverlayInputPin:
    intervention_id: str
    path: str
    digest: Digest


def _relative_path(value: str) -> str:
    rendered = value.replace("\\", "/")
    path = PurePosixPath(rendered)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != rendered
    ):
        raise SourceAuthorityError(f"source-overlay path is unsafe: {value!r}")
    return rendered


def _parameter_map(intervention: ClassicRecipeIntervention) -> dict[str, Any]:
    return {item.name: item.value for item in intervention.parameters}


def _donor_overlay_input_pins(
    intervention: ClassicRecipeIntervention,
    receipts: tuple[ClassicProofReceipt, ...],
) -> tuple[_DonorOverlayInputPin, ...]:
    """Resolve donor-private clean-input pins, including receipt constraints."""

    from reprobit.classic_donors import donor_overlay_clean_input_pins

    try:
        pins = donor_overlay_clean_input_pins(intervention, receipts)
    except ValueError as exc:
        raise SourceAuthorityError(
            f"donor source-overlay authority {intervention.id!r} is malformed: {exc}"
        ) from exc
    return tuple(
        _DonorOverlayInputPin(intervention.id, path, digest)
        for path, digest in pins.items()
    )


def inspect_source_authority(
    bundle: ProjectBundle,
    project_root: Path,
    *,
    source_manifest: SourceManifestDocument | None = None,
    build_plan: BuildPlanDocument | None = None,
    render_session: ClassicOverlayRenderSession | None = None,
    preflight_classic_recipes: bool = False,
) -> SourceAuthorityReport:
    """Check admitted bytes and optionally all source-derived recipe pins without writing."""

    root = project_root.resolve(strict=True)
    if root != Path(bundle.root).resolve(strict=True):
        raise SourceAuthorityError("source authority project root differs from loaded bundle")
    manifest = source_manifest if source_manifest is not None else bundle.source_manifest
    plan = build_plan if build_plan is not None else bundle.build_plan
    if manifest is None or not manifest.complete:
        raise SourceAuthorityError("source authority requires a complete portable manifest")

    classic_interventions = tuple(
        intervention
        for intervention in bundle.interventions
        if isinstance(intervention, ClassicRecipeIntervention)
    )
    tu_classic_interventions = tuple(
        intervention
        for intervention in classic_interventions
        if intervention.scope.translation_unit is not None
    )
    if (
        preflight_classic_recipes
        and plan is None
        and tu_classic_interventions
    ):
        raise SourceAuthorityError(
            "a build plan is required to validate TU-scoped source-derived authority"
        )

    overlays: list[tuple[ClassicRecipeIntervention, list[object], dict[object, object], int]] = []
    donor_overlay_pins: list[_DonorOverlayInputPin] = []
    receipts_by_intervention: dict[str, list[ClassicProofReceipt]] = {}
    for document in bundle.proof_documents:
        for expected_receipt in document.expected_observations:
            receipts_by_intervention.setdefault(expected_receipt.intervention_id, []).append(
                expected_receipt
            )
    capture_paths = {unit.source for unit in plan.translation_units} if plan is not None else set()
    run_classic_preflight = (
        preflight_classic_recipes and plan is not None and bool(tu_classic_interventions)
    )
    if run_classic_preflight:
        capture_paths.update(entry.path for entry in manifest.entries)
    forbidden_outputs = {
        target.oracle.replace("\\", "/").casefold() for target in bundle.spec.targets
    }
    for intervention in classic_interventions:
        if intervention.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
            pins = _donor_overlay_input_pins(
                intervention,
                tuple(receipts_by_intervention.get(intervention.id, ())),
            )
            donor_overlay_pins.extend(pins)
            continue
        if intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH:
            continue
        values = _parameter_map(intervention)
        outputs = values.get("outputs")
        graph = values.get("graph")
        schema = values.get("schema")
        if not isinstance(outputs, list) or not isinstance(graph, dict) or schema != 2:
            raise SourceAuthorityError(f"source-overlay authority {intervention.id!r} is malformed")
        for raw in outputs:
            if not isinstance(raw, dict):
                raise SourceAuthorityError(
                    f"source-overlay output for {intervention.id!r} is not an object"
                )
            relative = _relative_path(str(raw.get("path", "")))
            if relative.casefold() in forbidden_outputs:
                raise SourceAuthorityError("source overlay cannot write a verification oracle")
            if "clean" in raw:
                capture_paths.add(relative)
        overlays.append((intervention, outputs, graph, schema))

    verified_digests: dict[str, Digest] = {}
    effective: dict[str, bytes] = {}
    for entry in manifest.entries:
        try:
            size, digest, data = receipt_source_input(
                root,
                entry.path,
                capture=entry.path in capture_paths,
            )
        except SourceLockError as exc:
            raise SourceAuthorityError(str(exc)) from exc
        if size != entry.size or digest != entry.digest:
            raise SourceAuthorityError(
                "source input differs from portable manifest: "
                f"{entry.path!r} (expected {entry.digest.value}, found {digest.value})"
            )
        verified_digests[entry.path] = digest
        if data is not None:
            effective[entry.path] = data

    clean_sources = dict(effective)

    for pin in donor_overlay_pins:
        found_digest = verified_digests.get(pin.path)
        if found_digest is None:
            raise SourceAuthorityError(
                "donor source-overlay authority requires regeneration for "
                f"{pin.intervention_id!r}: clean input is absent for {pin.path!r}"
            )
        if found_digest != pin.digest:
            raise SourceAuthorityError(
                "donor source-overlay authority requires regeneration for "
                f"{pin.intervention_id!r}: clean input differs for {pin.path!r} "
                f"(expected {pin.digest.value}, found {found_digest.value})"
            )

    overlay_outputs: list[str] = []
    from reprobit.classic_overlay_document import render_classic_overlay
    from reprobit.classic_overlay_tokens import ClassicOverlayRenderSession

    owns_render_session = render_session is None
    active_render_session = render_session or ClassicOverlayRenderSession()
    try:
        for intervention, outputs, graph, schema in overlays:
            clean_inputs: dict[str, bytes] = {}
            for raw in outputs:
                assert isinstance(raw, dict)
                relative = _relative_path(str(raw.get("path", "")))
                if "clean" not in raw:
                    continue
                clean = effective.get(relative)
                if clean is None:
                    raise SourceAuthorityError(
                        "source-overlay authority requires regeneration for "
                        f"{intervention.id!r}: clean input is absent for {relative!r}"
                    )
                clean_inputs[relative] = clean
            try:
                rendered = render_classic_overlay(
                    {"schema": schema, "outputs": outputs, "graph": graph},
                    clean_inputs,
                    session=active_render_session,
                )
            except ValueError as exc:
                raise SourceAuthorityError(
                    f"source-overlay authority requires regeneration for {intervention.id!r}: {exc}"
                ) from exc
            for receipt in rendered.receipts:
                effective[receipt.path] = rendered.outputs[receipt.path]
                overlay_outputs.append(receipt.path)
    finally:
        if owns_render_session:
            active_render_session.close()

    if run_classic_preflight:
        from reprobit.classic_orchestration import prepare_classic_units
        from reprobit.classic_project import ClassicProjectError

        try:
            prepare_classic_units(
                bundle,
                clean_sources=clean_sources,
                effective_sources=effective,
            )
        except (ClassicProjectError, ValueError) as exc:
            raise SourceAuthorityError(
                f"classic source-derived authority requires regeneration: {exc}"
            ) from exc

    statuses: list[TranslationUnitPinStatus] = []
    for unit in plan.translation_units if plan is not None else ():
        data = effective.get(unit.source)
        actual = Digest.from_bytes(data).value if data is not None else None
        statuses.append(
            TranslationUnitPinStatus(
                translation_unit_id=unit.id,
                source=unit.source,
                expected_digest=unit.source_digest.value,
                actual_digest=actual,
            )
        )
    return SourceAuthorityReport(
        verified_inputs=len(manifest.entries),
        overlay_outputs=tuple(overlay_outputs),
        translation_units=tuple(sorted(statuses, key=lambda item: item.translation_unit_id)),
    )


def validate_source_authority(
    bundle: ProjectBundle,
    project_root: Path,
    *,
    render_session: ClassicOverlayRenderSession | None = None,
    preflight_classic_recipes: bool = False,
) -> None:
    """Fail closed when current source bytes differ from reviewed authority."""

    report = inspect_source_authority(
        bundle,
        project_root,
        render_session=render_session,
        preflight_classic_recipes=preflight_classic_recipes,
    )
    stale = report.stale_translation_units
    if not stale:
        return
    details = ", ".join(
        f"{item.translation_unit_id} ({item.source}: expected {item.expected_digest}, "
        f"found {item.actual_digest or 'absent'})"
        for item in stale
    )
    raise SourceAuthorityError(
        "effective translation-unit source differs from its reviewed pin; "
        f"regenerate intervention and proof authority instead of repinning: {details}"
    )


__all__ = [
    "SourceAuthorityError",
    "SourceAuthorityReport",
    "TranslationUnitPinStatus",
    "inspect_source_authority",
    "validate_source_authority",
]
