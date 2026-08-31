"""Materialize classic donor retunes and recompute their derived pins."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import cast

from reprobit.classic.donor_retune_candidates import (
    MAX_RETUNE_RADIUS,
    DonorRetuneCandidate,
    DonorRetuneChange,
    DonorRetuneError,
    RetunePathPart,
    RetuneScalar,
    _copy_with_parameters,
    _parameter_values,
)
from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic_donors import (
    DonorSourceError,
    merge_candidate_constraints,
    validate_donor_recipe,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue


@dataclass(frozen=True, slots=True)
class MaterializedDonorRetuneCandidate:
    """A candidate whose derived pins are ready for ordinary verification."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    distance: int
    changes: tuple[DonorRetuneChange, ...]


def _replace_candidate_path(
    intervention: ClassicRecipeIntervention,
    path: tuple[RetunePathPart, ...],
    *,
    expected: RetuneScalar,
    replacement: RetuneScalar,
) -> ClassicRecipeIntervention:
    if len(path) < 2 or path[0] != "parameters":
        raise DonorRetuneError("candidate change leaves donor parameters")
    parameters = _parameter_values(intervention)
    current: JsonValue = parameters
    for part in path[1:-1]:
        if isinstance(part, str):
            if not isinstance(current, dict) or part not in current:
                raise DonorRetuneError(f"candidate change path is absent: {path!r}")
            current = current[part]
        else:
            if not isinstance(current, list) or not 0 <= part < len(current):
                raise DonorRetuneError(f"candidate change path is absent: {path!r}")
            current = current[part]
    final = path[-1]
    if isinstance(final, str):
        if not isinstance(current, dict) or final not in current:
            raise DonorRetuneError(f"candidate change path is absent: {path!r}")
        actual = current[final]
        if actual != expected:
            raise DonorRetuneError(f"candidate change does not describe its value: {path!r}")
        current[final] = replacement
    else:
        if not isinstance(current, list) or not 0 <= final < len(current):
            raise DonorRetuneError(f"candidate change path is absent: {path!r}")
        actual = current[final]
        if actual != expected:
            raise DonorRetuneError(f"candidate change does not describe its value: {path!r}")
        current[final] = replacement
    return _copy_with_parameters(intervention, parameters)


def _saved_intervention(candidate: DonorRetuneCandidate) -> ClassicRecipeIntervention:
    if type(candidate.distance) is not int or not 1 <= candidate.distance <= MAX_RETUNE_RADIUS:
        raise DonorRetuneError("candidate distance is outside the bounded retune radius")
    if not candidate.changes:
        raise DonorRetuneError("candidate has no declared changes")
    if len({change.path for change in candidate.changes}) != len(candidate.changes):
        raise DonorRetuneError("candidate change paths repeat")
    saved = candidate.intervention
    for change in reversed(candidate.changes):
        if type(change.before) not in {int, str} or type(change.after) not in {int, str}:
            raise DonorRetuneError("candidate changes must contain integer or string scalars")
        saved = _replace_candidate_path(
            saved,
            change.path,
            expected=change.after,
            replacement=change.before,
        )
    return saved


def _validate_recipe(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
    *,
    context: str,
) -> None:
    try:
        constraints = merge_candidate_constraints(intervention, receipt)
        validate_donor_recipe(intervention, constraints)
    except DonorSourceError as exc:
        raise DonorRetuneError(f"{context} donor authority is invalid: {exc}") from exc


def _rendering_identity(parameters: dict[str, JsonValue]) -> str:
    raw_renderings = parameters.get("renderings")
    if not isinstance(raw_renderings, list):
        raise DonorRetuneError("materialized renderings must be an array")
    claim: JsonValue = raw_renderings
    replay = parameters.get("canonical_overlay_replay")
    if "compiler_state_carrier" in parameters or replay is not None:
        wrapped: dict[str, JsonValue] = {"renderings": raw_renderings}
        if "compiler_state_carrier" in parameters:
            wrapped["compiler_state_carrier"] = parameters["compiler_state_carrier"]
        if replay is not None:
            wrapped["canonical_overlay_replay"] = replay
        claim = wrapped
    payload = (json.dumps(claim, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    return Digest.from_bytes(payload).value


def _digest_pin(value: object, *, context: str) -> str:
    if not isinstance(value, str):
        raise DonorRetuneError(f"{context} must be a lowercase SHA-256")
    try:
        return Digest(value=value).value
    except ValueError as exc:
        raise DonorRetuneError(f"{context} must be a lowercase SHA-256") from exc


def _derived_change(
    changes: list[DonorRetuneChange],
    path: tuple[RetunePathPart, ...],
    before: str,
    after: str,
) -> None:
    if before == after:
        return
    if any(change.path == path for change in changes):
        raise DonorRetuneError(f"materialized derived pin repeats a candidate change: {path!r}")
    changes.append(DonorRetuneChange(path, before, after, "derived"))


def _materialize_overlay_candidate(
    candidate: DonorRetuneCandidate,
    receipt: ClassicProofReceipt,
    *,
    clean_sources: Mapping[str, bytes] | None,
    canonical_overlay_operations: Sequence[Mapping[str, object]] | None,
) -> MaterializedDonorRetuneCandidate:
    if len(candidate.changes) != 1 or candidate.changes[0].kind != "knob":
        raise DonorRetuneError("overlay retuning must change exactly one admitted knob")
    knob = candidate.changes[0]
    if (
        len(knob.path) != 9
        or knob.path[:3] != ("parameters", "renderings", knob.path[2])
        or knob.path[3] != "operations"
        or knob.path[5:8] != ("gen", "items", knob.path[7])
        or knob.path[-1] != "count"
        or type(knob.before) is not int
        or type(knob.after) is not int
        or abs(knob.after - knob.before) != candidate.distance
    ):
        raise DonorRetuneError("overlay candidate is not one bounded declaration-run count")

    try:
        merged = merge_candidate_constraints(candidate.intervention, receipt).materialize()
    except DonorSourceError as exc:
        raise DonorRetuneError(f"candidate donor authority is invalid: {exc}") from exc
    raw_renderings = merged.get("renderings")
    if not isinstance(raw_renderings, list) or not raw_renderings:
        raise DonorRetuneError("overlay candidate has no renderings")

    replay = merged.get("canonical_overlay_replay")
    if replay is None:
        if canonical_overlay_operations is not None:
            raise DonorRetuneError("canonical overlay operations lack a replay declaration")
    elif replay == "owning_translation_unit_v1":
        if canonical_overlay_operations is None:
            raise DonorRetuneError("canonical overlay replay operations are required")
    else:  # The saved recipe validator normally rejects this first.
        raise DonorRetuneError("canonical overlay replay policy is unsupported")

    if clean_sources is None:
        raise DonorRetuneError("overlay candidate requires authenticated clean sources")
    supplied = dict(clean_sources)
    if any(
        not isinstance(path, str) or not isinstance(data, bytes) for path, data in supplied.items()
    ):
        raise DonorRetuneError("overlay clean sources must map paths to immutable bytes")

    declarations: list[dict[str, object]] = []
    paths: list[str] = []
    old_rendered_pins: list[str] = []
    for index, raw in enumerate(raw_renderings):
        if not isinstance(raw, dict):
            raise DonorRetuneError(f"renderings[{index}] must be an object")
        path = raw.get("path")
        operations = raw.get("operations")
        if not isinstance(path, str) or not isinstance(operations, list):
            raise DonorRetuneError(f"renderings[{index}] is malformed")
        clean_key = f"renderings[{index}].clean_sha256"
        rendered_key = f"renderings[{index}].rendered_sha256"
        if clean_key not in receipt.expected_values or rendered_key not in receipt.expected_values:
            raise DonorRetuneError(
                f"overlay receipt lacks existing derived pins for renderings[{index}]"
            )
        clean_pin = _digest_pin(receipt.expected_values[clean_key], context=clean_key)
        rendered_pin = _digest_pin(receipt.expected_values[rendered_key], context=rendered_key)
        data = supplied.get(path)
        if data is None:
            raise DonorRetuneError(f"authenticated overlay clean source is absent: {path!r}")
        if Digest.from_bytes(data).value != clean_pin:
            raise DonorRetuneError(f"authenticated overlay clean source differs: {path!r}")
        rendered_operations = deepcopy(operations)
        if index == 0 and canonical_overlay_operations is not None:
            canonical_operations = [
                cast(JsonValue, deepcopy(dict(operation)))
                for operation in canonical_overlay_operations
            ]
            rendered_operations = [
                *canonical_operations,
                *rendered_operations,
            ]
        declarations.append(
            {
                "path": path,
                "clean": clean_pin,
                "effective": rendered_pin,
                "ops": rendered_operations,
            }
        )
        paths.append(path)
        old_rendered_pins.append(rendered_pin)
    if set(supplied) != set(paths):
        missing = sorted(set(paths) - set(supplied))
        extra = sorted(set(supplied) - set(paths))
        raise DonorRetuneError(
            f"overlay clean-source universe differs; missing={missing}, extra={extra}"
        )

    try:
        rendered = render_classic_overlay_proposal(declarations, supplied)
    except ValueError as exc:
        raise DonorRetuneError(f"cannot render overlay retune candidate: {exc}") from exc

    changes = list(candidate.changes)
    expected_values = deepcopy(receipt.expected_values)
    candidate_parameters = _parameter_values(candidate.intervention)
    candidate_renderings = candidate_parameters.get("renderings")
    if not isinstance(candidate_renderings, list):
        raise DonorRetuneError("overlay candidate renderings must be an array")
    for index, (path, old_pin) in enumerate(zip(paths, old_rendered_pins, strict=True)):
        new_pin = Digest.from_bytes(rendered.outputs[path]).value
        rendered_key = f"renderings[{index}].rendered_sha256"
        expected_values[rendered_key] = new_pin
        _derived_change(
            changes,
            ("receipt", "expected_values", rendered_key),
            old_pin,
            new_pin,
        )
        raw_candidate = candidate_renderings[index]
        if isinstance(raw_candidate, dict) and "rendered_sha256" in raw_candidate:
            embedded_pin = _digest_pin(
                raw_candidate["rendered_sha256"],
                context=f"renderings[{index}].rendered_sha256",
            )
            raw_candidate["rendered_sha256"] = new_pin
            _derived_change(
                changes,
                ("parameters", "renderings", index, "rendered_sha256"),
                embedded_pin,
                new_pin,
            )

    materialized_receipt = receipt.model_copy(
        update={"expected_values": dict(sorted(expected_values.items()))},
        deep=True,
    )
    interim = _copy_with_parameters(candidate.intervention, candidate_parameters)
    try:
        identity_parameters = merge_candidate_constraints(
            interim, materialized_receipt
        ).materialize()
    except DonorSourceError as exc:
        raise DonorRetuneError(f"materialized overlay pins conflict: {exc}") from exc
    old_identity = _digest_pin(
        candidate_parameters.get("rendering_identity_sha256"),
        context="rendering_identity_sha256",
    )
    new_identity = _rendering_identity(identity_parameters)
    candidate_parameters["rendering_identity_sha256"] = new_identity
    _derived_change(
        changes,
        ("parameters", "rendering_identity_sha256"),
        old_identity,
        new_identity,
    )
    intervention = _copy_with_parameters(candidate.intervention, candidate_parameters)
    _validate_recipe(intervention, materialized_receipt, context="materialized")
    return MaterializedDonorRetuneCandidate(
        intervention,
        materialized_receipt,
        candidate.distance,
        tuple(changes),
    )


def materialize_donor_retune_candidate(
    candidate: DonorRetuneCandidate,
    receipt: ClassicProofReceipt,
    *,
    clean_sources: Mapping[str, bytes] | None = None,
    canonical_overlay_operations: Sequence[Mapping[str, object]] | None = None,
) -> MaterializedDonorRetuneCandidate:
    """Close one retune proposal into publishable authority without compiling it.

    The saved recipe is reconstructed from the proposal's complete change list
    and authenticated with its existing receipt before any derived pin is
    refreshed.  Overlay rendering uses only receipt-pinned clean bytes.  The
    returned record must still pass the ordinary donor compiler and composition
    gates before repair can publish it.
    """

    if candidate.intervention.role is not ClassicRecipeRole.DONOR:
        raise DonorRetuneError("retune candidate is not a donor")
    saved = _saved_intervention(candidate)
    _validate_recipe(saved, receipt, context="saved")
    if candidate.intervention.family in {
        ClassicRecipeFamily.DECLARATION_SHAPE,
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
    }:
        if clean_sources or canonical_overlay_operations is not None:
            raise DonorRetuneError("declaration materialization accepts no overlay inputs")
        _validate_recipe(candidate.intervention, receipt, context="candidate")
        return MaterializedDonorRetuneCandidate(
            candidate.intervention,
            receipt,
            candidate.distance,
            candidate.changes,
        )
    if candidate.intervention.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return _materialize_overlay_candidate(
            candidate,
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=canonical_overlay_operations,
        )
    raise DonorRetuneError("retune candidate family is unsupported")


__all__ = [
    "MaterializedDonorRetuneCandidate",
    "materialize_donor_retune_candidate",
]
