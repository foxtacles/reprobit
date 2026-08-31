"""Reviewed regeneration of source-derived authority after admitted source edits.

``rbit source lock`` refuses to bless stale pins: when an admitted source file
changes, every reviewed record that derived digests from that file must be
regenerated, not repinned.  This module implements that regeneration for the
record families whose derivations are fully mechanical:

* ``source_overlay_graph`` outputs — the clean digest, clean size, and the
  effective digest of the re-rendered overlay output;
* ``donor_source_overlay`` renderings — the proof-carried clean and rendered
  digests, and the intervention's rendering identity over the merged claim;
* translation-unit ``source_digest`` pins in the build plan and in
  translation-unit intervention documents.

Every proposed digest is recomputed by re-running the same renderer the
verifier uses, with every anchor resolved against the current bytes; an anchor
that no longer resolves aborts the whole plan.  Nothing is deleted, no
validator is bypassed, and the rewritten tree must still pass ``rbit source
lock`` and a from-scratch ``rbit verify`` — regeneration only proposes pins
that those gates then prove.  A digest of a changed file that survives in any
document at a location this module does not understand also aborts the plan,
so an unknown pin family can never ride along silently.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reprobit.project_loader import load_project
from reprobit.strict_json import canonical_json, strict_load
from reprobit.transactions import CASTransaction

_SOURCE_OVERLAY_FAMILY = "source_overlay_graph"
_DONOR_OVERLAY_FAMILY = "donor_source_overlay"


class SourceRegenerationError(ValueError):
    """Regeneration cannot propose a provable replacement for a stale pin."""


@dataclass(frozen=True, slots=True)
class RegenerationChange:
    """One recorded field replacement inside one committed document."""

    document: str
    location: str
    before: str
    after: str


@dataclass(frozen=True, slots=True)
class RegenerationPlan:
    """A reviewed set of document rewrites plus the exact bytes they assume."""

    changes: tuple[RegenerationChange, ...]
    documents: dict[str, Any]
    read_sources: dict[str, str]

    @property
    def changed_documents(self) -> tuple[str, ...]:
        return tuple(sorted({change.document for change in self.changes}))


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _legacy_identity(value: object) -> str:
    """Hash the historical, stable indented JSON identity claim."""

    return _digest((json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())


class _SourceReader:
    """Read project-relative source files once, remembering the exact bytes."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._cache: dict[str, bytes] = {}

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        cached = self._cache.get(relative)
        if cached is not None:
            return cached
        candidate = (self._root / relative).resolve()
        try:
            candidate.relative_to(self._root)
        except ValueError:
            raise SourceRegenerationError(
                f"{wanted_by} pins a path outside the project root: {relative!r}"
            ) from None
        if not candidate.is_file():
            raise SourceRegenerationError(
                f"{wanted_by} pins a source file that does not exist: {relative!r}"
            )
        data = candidate.read_bytes()
        self._cache[relative] = data
        return data

    @property
    def digests(self) -> dict[str, str]:
        return {path: _digest(data) for path, data in self._cache.items()}


def _parameter_map(intervention: dict[str, Any]) -> dict[str, Any]:
    parameters = intervention.get("parameters")
    if not isinstance(parameters, list):
        return {}
    values: dict[str, Any] = {}
    for field in parameters:
        if isinstance(field, dict) and isinstance(field.get("name"), str):
            values[field["name"]] = field.get("value")
    return values


def _set_parameter(intervention: dict[str, Any], name: str, value: Any) -> None:
    for field in intervention.get("parameters", []):
        if isinstance(field, dict) and field.get("name") == name:
            field["value"] = value
            return
    raise SourceRegenerationError(f"intervention parameter is missing: {name!r}")


def _document_paths(root: Path, relative: str) -> tuple[Path, ...]:
    directory = root / relative
    if not directory.is_dir():
        return ()
    return tuple(sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()))


def _render_single(
    declaration: dict[str, Any],
    clean: bytes,
    *,
    context: str,
) -> tuple[str, int, bytes]:
    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    try:
        result = render_classic_overlay_proposal([declaration], {str(declaration["path"]): clean})
    except ValueError as exc:
        raise SourceRegenerationError(f"{context} cannot be re-rendered: {exc}") from exc
    receipt = result.receipts[0]
    return receipt.output_digest, receipt.output_size, result.outputs[receipt.path]


def plan_source_regeneration(project_root: Path | str) -> RegenerationPlan:
    """Propose pin regenerations for every stale mechanical derivation."""

    root = Path(project_root).resolve(strict=True)
    spec = load_project(root)
    reader = _SourceReader(root)
    changes: list[RegenerationChange] = []
    updated: dict[str, Any] = {}

    intervention_paths = _document_paths(root, spec.layout.interventions)
    proof_paths = _document_paths(root, spec.layout.proofs)
    documents: dict[str, Any] = {}
    for document_path in (*intervention_paths, *proof_paths):
        documents[document_path.relative_to(root).as_posix()] = strict_load(document_path)
    plan_relative = spec.layout.build_plan
    plan_path = root / plan_relative
    if plan_path.is_file():
        documents[plan_relative] = strict_load(plan_path)

    def record(document: str, location: str, before: str, after: str) -> None:
        changes.append(RegenerationChange(document, location, before, after))
        updated[document] = documents[document]

    stale_paths: dict[str, str] = {}

    # Pass A: project-level source overlays own the effective text of their
    # outputs.  Re-render each stale output and propose clean/size/effective.
    effective_by_path: dict[str, str] = {}
    effective_bytes_by_path: dict[str, bytes] = {}
    for name, document in documents.items():
        if not isinstance(document, dict):
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            if intervention.get("family") != _SOURCE_OVERLAY_FAMILY:
                continue
            values = _parameter_map(intervention)
            outputs = values.get("outputs")
            if not isinstance(outputs, list):
                continue
            for output in outputs:
                if not isinstance(output, dict):
                    continue
                path = str(output.get("path"))
                context = f"overlay output {path!r}"
                if "clean" not in output:
                    # Generated-only outputs have no clean input on disk; their
                    # effective bytes derive from generators alone and cannot
                    # go stale under a source edit.
                    effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                current = reader.read(path, wanted_by=f"{name} {context}")
                current_digest = _digest(current)
                if current_digest == output.get("clean"):
                    effective_by_path.setdefault(path, str(output.get("effective")))
                    continue
                declaration = dict(output)
                declaration["clean"] = current_digest
                declaration["size"] = len(current)
                new_effective, new_size, rendered_bytes = _render_single(
                    declaration, current, context=context
                )
                effective_bytes_by_path[path] = rendered_bytes
                stale_paths[path] = str(output["clean"])
                record(name, f"{context} clean", str(output["clean"]), current_digest)
                record(name, f"{context} effective", str(output["effective"]), new_effective)
                if output.get("size") != new_size:
                    record(name, f"{context} size", str(output.get("size")), str(new_size))
                output["clean"] = current_digest
                output["effective"] = new_effective
                output["size"] = new_size
                effective_by_path[path] = new_effective

    # Pass B: donor-private overlays carry their clean and rendered digests in
    # proof expected values; the intervention identity covers the merged claim.
    receipts_by_intervention: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for name, document in documents.items():
        if not isinstance(document, dict):
            continue
        for observation in document.get("expected_observations", []) or []:
            if isinstance(observation, dict) and isinstance(
                observation.get("intervention_id"), str
            ):
                receipts_by_intervention.setdefault(observation["intervention_id"], []).append(
                    (name, observation)
                )

    for name, document in documents.items():
        if not isinstance(document, dict):
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            if intervention.get("family") != _DONOR_OVERLAY_FAMILY:
                continue
            identifier = str(intervention.get("id"))
            values = _parameter_map(intervention)
            renderings = values.get("renderings")
            if not isinstance(renderings, list):
                continue
            receipts = receipts_by_intervention.get(identifier, [])
            expected_receipts = [
                (proof_name, observation)
                for proof_name, observation in receipts
                if isinstance(observation.get("expected_values"), dict)
            ]
            if len(expected_receipts) != 1:
                raise SourceRegenerationError(
                    f"donor overlay {identifier!r} requires exactly one proof "
                    f"receipt with expected values, found {len(expected_receipts)}"
                )
            proof_name, observation = expected_receipts[0]
            expected_values = observation["expected_values"]
            merged: list[dict[str, Any]] = []
            donor_changed = False
            for index, rendering in enumerate(renderings):
                if not isinstance(rendering, dict):
                    raise SourceRegenerationError(
                        f"donor overlay {identifier!r} rendering {index} is malformed"
                    )
                clean_key = f"renderings[{index}].clean_sha256"
                rendered_key = f"renderings[{index}].rendered_sha256"
                if clean_key not in expected_values or rendered_key not in expected_values:
                    raise SourceRegenerationError(
                        f"donor overlay {identifier!r} rendering {index} carries no "
                        "proof-pinned digests; its claim form is not regenerable here"
                    )
                path = str(rendering.get("path"))
                context = f"{name} donor {identifier} rendering {path!r}"
                current = reader.read(path, wanted_by=context)
                current_digest = _digest(current)
                pinned_clean = str(expected_values[clean_key])
                pinned_rendered = str(expected_values[rendered_key])
                if current_digest != pinned_clean:
                    operations = rendering.get("operations")
                    if isinstance(operations, list) and not operations:
                        # An empty operation list under owning-TU replay means
                        # the donor renders the canonical overlay's effective
                        # text for this path verbatim.
                        if values.get("canonical_overlay_replay") != "owning_translation_unit_v1":
                            raise SourceRegenerationError(
                                f"{context} has no operations and no replay policy; "
                                "its rendered bytes cannot be re-derived here"
                            )
                        replayed = effective_by_path.get(path)
                        if replayed is None:
                            raise SourceRegenerationError(
                                f"{context} replays a canonical overlay output that "
                                "no source overlay declares"
                            )
                        new_rendered = replayed
                    else:
                        declaration = {
                            "path": path,
                            "clean": current_digest,
                            "effective": pinned_rendered,
                            "ops": operations,
                        }
                        new_rendered, _size, _bytes = _render_single(
                            declaration, current, context=context
                        )
                    stale_paths[path] = pinned_clean
                    record(
                        proof_name,
                        f"{identifier} {clean_key}",
                        pinned_clean,
                        current_digest,
                    )
                    record(
                        proof_name,
                        f"{identifier} {rendered_key}",
                        pinned_rendered,
                        new_rendered,
                    )
                    expected_values[clean_key] = current_digest
                    expected_values[rendered_key] = new_rendered
                    pinned_clean = current_digest
                    pinned_rendered = new_rendered
                    donor_changed = True
                merged.append(
                    {
                        **rendering,
                        "clean_sha256": pinned_clean,
                        "rendered_sha256": pinned_rendered,
                    }
                )
            if not donor_changed:
                continue
            claim: object = merged
            replay = values.get("canonical_overlay_replay")
            if "compiler_state_carrier" in values or replay is not None:
                wrapped: dict[str, Any] = {"renderings": merged}
                if "compiler_state_carrier" in values:
                    wrapped["compiler_state_carrier"] = values["compiler_state_carrier"]
                if replay is not None:
                    wrapped["canonical_overlay_replay"] = replay
                claim = wrapped
            identity = _legacy_identity(claim)
            pinned_identity = str(values.get("rendering_identity_sha256"))
            if identity != pinned_identity:
                record(
                    name,
                    f"{identifier} rendering_identity_sha256",
                    pinned_identity,
                    identity,
                )
                _set_parameter(intervention, "rendering_identity_sha256", identity)

    # Pass C: translation-unit source digests pin the effective text of the
    # unit's primary source — the overlay-rendered bytes when an overlay owns
    # the path, the clean bytes otherwise.
    def expected_source_digest(source: str, *, wanted_by: str) -> str:
        overlaid = effective_by_path.get(source)
        if overlaid is not None:
            return overlaid
        return _digest(reader.read(source, wanted_by=wanted_by))

    for name, document in documents.items():
        if not isinstance(document, dict) or name == plan_relative:
            continue
        source = document.get("source")
        digest_field = document.get("source_digest")
        if not isinstance(source, str) or not isinstance(digest_field, dict):
            continue
        expected = expected_source_digest(source, wanted_by=f"{name} source_digest")
        before = str(digest_field.get("value"))
        if before != expected:
            stale_paths.setdefault(source, before)
            record(name, f"source_digest ({source})", before, expected)
            digest_field["value"] = expected

    plan_document = documents.get(plan_relative)
    if isinstance(plan_document, dict):
        for unit in plan_document.get("translation_units", []) or []:
            if not isinstance(unit, dict):
                continue
            source = str(unit.get("source"))
            digest_field = unit.get("source_digest")
            if not isinstance(digest_field, dict):
                continue
            context = f"unit {unit.get('id')}"
            expected = expected_source_digest(source, wanted_by=f"{plan_relative} {context}")
            before = str(digest_field.get("value"))
            if before != expected:
                stale_paths.setdefault(source, before)
                record(plan_relative, f"{context} source_digest ({source})", before, expected)
                digest_field["value"] = expected

    # Pass D: declaration-carrier donors render generated declarations into
    # the effective text of their translation unit and pin the rendered bytes
    # (and, for special-seat families, content witnesses around the seats).
    from reprobit.classic_donors import (
        DonorSourceError,
        derive_special_seat_proof,
        render_declaration_carrier_source,
    )
    from reprobit.schema import ClassicProofReceipt, ClassicRecipeIntervention

    _DONOR_SOURCE_PIN_NAMES = frozenset(
        {"rendered_source_sha256", "donor_effective_source_sha256", "seat_proof"}
    )

    def effective_bytes_for(source: str, *, wanted_by: str) -> bytes:
        rendered = effective_bytes_by_path.get(source)
        if rendered is not None:
            return rendered
        if source in effective_by_path:
            raise SourceRegenerationError(
                f"{wanted_by} needs the effective bytes of {source!r}, but its "
                "overlay output was not re-rendered in this plan"
            )
        return reader.read(source, wanted_by=wanted_by)

    for name, document in documents.items():
        if not isinstance(document, dict) or name == plan_relative:
            continue
        source = document.get("source")
        if not isinstance(source, str) or source not in stale_paths:
            continue
        for intervention in document.get("interventions", []) or []:
            if not isinstance(intervention, dict):
                continue
            values = _parameter_map(intervention)
            pinned_names = _DONOR_SOURCE_PIN_NAMES & values.keys()
            if not pinned_names:
                continue
            identifier = str(intervention.get("id"))
            context = f"{name} donor {identifier}"
            effective = effective_bytes_for(source, wanted_by=context)
            candidate = json.loads(json.dumps(intervention))
            try:
                if "seat_proof" in pinned_names:
                    _set_parameter(candidate, "seat_proof", derive_special_seat_proof(effective))
                if "donor_effective_source_sha256" in pinned_names:
                    _set_parameter(candidate, "donor_effective_source_sha256", _digest(effective))
                typed = ClassicRecipeIntervention.model_validate_json(canonical_json(candidate))
                typed_receipts = tuple(
                    ClassicProofReceipt.model_validate_json(canonical_json(observation))
                    for _proof_name, observation in receipts_by_intervention.get(identifier, [])
                )
                rendered = render_declaration_carrier_source(typed, typed_receipts, effective)
            except (DonorSourceError, ValueError) as exc:
                raise SourceRegenerationError(f"{context} cannot be re-rendered: {exc}") from exc

            replacements: dict[str, Any] = {}
            if "seat_proof" in pinned_names:
                replacements["seat_proof"] = _parameter_map(candidate)["seat_proof"]
            if "donor_effective_source_sha256" in pinned_names:
                replacements["donor_effective_source_sha256"] = _digest(effective)
            if "rendered_source_sha256" in values:
                replacements["rendered_source_sha256"] = _digest(rendered)
                if "rendered_source_size" in values:
                    replacements["rendered_source_size"] = len(rendered)
                if "rendered_source_line_count" in values:
                    replacements["rendered_source_line_count"] = rendered.count(b"\n")
            for parameter_name, after_value in replacements.items():
                before_value = values.get(parameter_name)
                if before_value == after_value:
                    continue
                record(
                    name,
                    f"{identifier} {parameter_name}",
                    json.dumps(before_value, sort_keys=True)
                    if not isinstance(before_value, str)
                    else before_value,
                    json.dumps(after_value, sort_keys=True)
                    if not isinstance(after_value, str)
                    else after_value,
                )
                _set_parameter(intervention, parameter_name, after_value)

    # Completeness sweep: a digest this plan replaced must not survive anywhere
    # in the committed authority, or an unhandled pin family is riding along.
    replaced = {change.before for change in changes if len(change.before) == 64}
    replaced.update(stale_paths.values())
    if replaced:
        for name, document in documents.items():
            serialized = canonical_json(document).decode("utf-8")
            for old in sorted(replaced):
                if old in serialized:
                    raise SourceRegenerationError(
                        f"stale digest {old} survives in {name} at a location this "
                        "regeneration does not understand; regenerate that record "
                        "with its own adapter first"
                    )

    return RegenerationPlan(
        changes=tuple(changes),
        documents=updated,
        read_sources=reader.digests,
    )


def apply_source_regeneration(project_root: Path | str, plan: RegenerationPlan) -> None:
    """Write a regeneration plan transactionally against the bytes it read."""

    if not plan.changes:
        return
    root = Path(project_root).resolve(strict=True)
    transaction = CASTransaction(root)
    for name in plan.changed_documents:
        transaction.write(name, canonical_json(plan.documents[name]))
    for path, digest in sorted(plan.read_sources.items()):
        transaction.assert_unchanged(path, expected_sha256=digest)
    transaction.commit()


__all__ = [
    "RegenerationChange",
    "RegenerationPlan",
    "SourceRegenerationError",
    "apply_source_regeneration",
    "plan_source_regeneration",
]
