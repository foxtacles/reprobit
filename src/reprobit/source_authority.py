"""Read-only checks for committed source and effective translation-unit authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from reprobit.model import Digest
from reprobit.schema import (
    BuildPlanDocument,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ProjectBundle,
    SourceManifestDocument,
)
from reprobit.source_lock import SourceLockError, receipt_source_input

if TYPE_CHECKING:
    from reprobit.classic_overlay import ClassicOverlayRenderSession


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


def _overlay_dialect(bundle: ProjectBundle) -> object:
    from reprobit.classic_overlay import ClassicOverlayDialect

    policy = bundle.build_plan.toolchain_policy if bundle.build_plan is not None else None
    raw = policy.get("classic_overlay_dialect") if isinstance(policy, dict) else None
    if raw is None:
        return ClassicOverlayDialect()
    if not isinstance(raw, dict) or set(raw) != {"qualified_member_probe_return_type"}:
        raise SourceAuthorityError("classic overlay dialect policy is malformed")
    return_type = raw["qualified_member_probe_return_type"]
    if not isinstance(return_type, str) or not return_type:
        raise SourceAuthorityError("classic overlay dialect return type is invalid")
    return ClassicOverlayDialect(qualified_member_probe_return_type=return_type)


def inspect_source_authority(
    bundle: ProjectBundle,
    project_root: Path,
    *,
    source_manifest: SourceManifestDocument | None = None,
    build_plan: BuildPlanDocument | None = None,
    render_session: ClassicOverlayRenderSession | None = None,
) -> SourceAuthorityReport:
    """Check current admitted bytes, overlays, and effective TU pins without writing."""

    root = project_root.resolve(strict=True)
    if root != Path(bundle.root).resolve(strict=True):
        raise SourceAuthorityError("source authority project root differs from loaded bundle")
    manifest = source_manifest if source_manifest is not None else bundle.source_manifest
    plan = build_plan if build_plan is not None else bundle.build_plan
    if manifest is None or not manifest.complete:
        raise SourceAuthorityError("source authority requires a complete portable manifest")

    overlays: list[tuple[ClassicRecipeIntervention, list[object], dict[object, object], int]] = []
    capture_paths = {unit.source for unit in plan.translation_units} if plan is not None else set()
    forbidden_outputs = {
        target.oracle.replace("\\", "/").casefold() for target in bundle.spec.targets
    }
    for intervention in bundle.interventions:
        if not isinstance(intervention, ClassicRecipeIntervention):
            continue
        if intervention.family is not ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH:
            continue
        values = _parameter_map(intervention)
        outputs = values.get("outputs")
        graph = values.get("graph")
        schema = values.get("schema")
        if not isinstance(outputs, list) or not isinstance(graph, dict) or schema != 2:
            raise SourceAuthorityError(
                f"source-overlay authority {intervention.id!r} is malformed"
            )
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
        if data is not None:
            effective[entry.path] = data

    dialect = _overlay_dialect(bundle)
    overlay_outputs: list[str] = []
    from reprobit.classic_overlay import (
        ClassicOverlayRenderSession,
        render_classic_overlay,
    )

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
                    dialect=dialect,  # type: ignore[arg-type]
                    session=active_render_session,
                )
            except ValueError as exc:
                raise SourceAuthorityError(
                    "source-overlay authority requires regeneration for "
                    f"{intervention.id!r}: {exc}"
                ) from exc
            for receipt in rendered.receipts:
                effective[receipt.path] = rendered.outputs[receipt.path]
                overlay_outputs.append(receipt.path)
    finally:
        if owns_render_session:
            active_render_session.close()

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
) -> None:
    """Fail closed when current effective TU bytes differ from reviewed authority."""

    report = inspect_source_authority(
        bundle,
        project_root,
        render_session=render_session,
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
