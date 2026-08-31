"""Bounded, deterministic repair candidates for existing classic donors.

Enumeration only proposes nearby authority states; it never compiles a donor
or claims that a candidate restores byte identity.  A separate pure step can
refresh an overlay candidate's derived rendering pins from authenticated clean
bytes.  The repair runtime must still compile and admit only an ordinarily
verified candidate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal, TypeAlias, cast

from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic_donors import (
    DonorSourceError,
    generate_declaration_shape,
    generate_forward_run,
    merge_candidate_constraints,
    validate_donor_recipe,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue

DEFAULT_RETUNE_RADIUS = 4
MAX_RETUNE_RADIUS = 8
DEFAULT_RETUNE_CANDIDATES = 64
MAX_RETUNE_CANDIDATES = 64

RetunePathPart: TypeAlias = str | int
RetuneScalar: TypeAlias = int | str


class DonorRetuneError(ValueError):
    """An eligible donor does not have the closed shape required for retuning."""


@dataclass(frozen=True, slots=True)
class DonorRetuneChange:
    """One exact, reviewable difference from the saved donor authority."""

    path: tuple[RetunePathPart, ...]
    before: RetuneScalar
    after: RetuneScalar
    kind: Literal["knob", "derived"] = "knob"


@dataclass(frozen=True, slots=True)
class DonorRetuneCandidate:
    """One nearby donor proposal and the complete list of intended changes."""

    intervention: ClassicRecipeIntervention
    distance: int
    changes: tuple[DonorRetuneChange, ...]


@dataclass(frozen=True, slots=True)
class MaterializedDonorRetuneCandidate:
    """A candidate whose derived pins are ready for ordinary verification."""

    intervention: ClassicRecipeIntervention
    receipt: ClassicProofReceipt
    distance: int
    changes: tuple[DonorRetuneChange, ...]


def _checked_bounds(radius: int, limit: int) -> None:
    if type(radius) is not int or not 1 <= radius <= MAX_RETUNE_RADIUS:
        raise DonorRetuneError(f"radius must be an integer from 1 to {MAX_RETUNE_RADIUS}")
    if type(limit) is not int or not 1 <= limit <= MAX_RETUNE_CANDIDATES:
        raise DonorRetuneError(f"limit must be an integer from 1 to {MAX_RETUNE_CANDIDATES}")


def _parameter_values(intervention: ClassicRecipeIntervention) -> dict[str, JsonValue]:
    return {field.name: deepcopy(field.value) for field in intervention.parameters}


def _copy_with_parameters(
    intervention: ClassicRecipeIntervention,
    parameters: dict[str, JsonValue],
) -> ClassicRecipeIntervention:
    return intervention.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value) for name, value in sorted(parameters.items())
            )
        },
        deep=True,
    )


def _required_integer(parameters: dict[str, JsonValue], name: str) -> int:
    value = parameters.get(name)
    if type(value) is not int:
        raise DonorRetuneError(f"{name} must be an integer")
    return value


def _required_string(parameters: dict[str, JsonValue], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str):
        raise DonorRetuneError(f"{name} must be a string")
    return value


def _declaration_shape_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    classes = _required_integer(parameters, "classes")
    functions = _required_integer(parameters, "functions")
    old_digest = _required_string(parameters, "generated_header_sha256")
    try:
        expected_digest = Digest.from_bytes(generate_declaration_shape(classes, functions)).value
    except ValueError as exc:
        raise DonorRetuneError(f"saved declaration shape is invalid: {exc}") from exc
    if old_digest != expected_digest:
        raise DonorRetuneError("saved declaration-shape digest differs from its parameters")

    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        shell: set[tuple[int, int]] = set()
        for class_delta in range(-distance, distance + 1):
            function_distance = distance - abs(class_delta)
            function_deltas = (
                (0,) if function_distance == 0 else (-function_distance, function_distance)
            )
            for function_delta in function_deltas:
                candidate_classes = classes + class_delta
                candidate_functions = functions + function_delta
                if (
                    1 <= candidate_classes <= 10
                    and candidate_classes <= candidate_functions <= 10 * candidate_classes
                ):
                    shell.add((candidate_classes, candidate_functions))

        for candidate_classes, candidate_functions in sorted(shell):
            generated_digest = Digest.from_bytes(
                generate_declaration_shape(candidate_classes, candidate_functions)
            ).value
            changed = deepcopy(parameters)
            changed["classes"] = candidate_classes
            changed["functions"] = candidate_functions
            changed["generated_header_sha256"] = generated_digest
            changes: list[DonorRetuneChange] = []
            if candidate_classes != classes:
                changes.append(
                    DonorRetuneChange(("parameters", "classes"), classes, candidate_classes)
                )
            if candidate_functions != functions:
                changes.append(
                    DonorRetuneChange(("parameters", "functions"), functions, candidate_functions)
                )
            changes.append(
                DonorRetuneChange(
                    ("parameters", "generated_header_sha256"),
                    old_digest,
                    generated_digest,
                    "derived",
                )
            )
            candidates.append(
                DonorRetuneCandidate(
                    intervention=_copy_with_parameters(intervention, changed),
                    distance=distance,
                    changes=tuple(changes),
                )
            )
            if len(candidates) == limit:
                return tuple(candidates)
    return tuple(candidates)


_TRIPLE_SEATS = ("pre", "post", "eof")


def _declaration_run_triple_payload(parameters: dict[str, JsonValue]) -> bytes:
    width = _required_integer(parameters, "width")
    if not 1 <= width <= 3:
        raise DonorRetuneError("width must be an integer from 1 to 3")
    maximum = min(999, 10**width)
    pieces: list[bytes] = []
    active_prefixes: set[str] = set()
    for seat in _TRIPLE_SEATS:
        prefix = _required_string(parameters, f"{seat}_prefix")
        count = _required_integer(parameters, f"{seat}_count")
        if not 0 <= count <= maximum:
            raise DonorRetuneError(
                f"{seat}_count must be an integer from 0 to {maximum}"
            )
        if not count:
            continue
        if prefix in active_prefixes:
            raise DonorRetuneError("active declaration-run prefixes repeat")
        active_prefixes.add(prefix)
        try:
            pieces.append(generate_forward_run(prefix, count, width))
        except ValueError as exc:
            raise DonorRetuneError(f"saved declaration run is invalid: {exc}") from exc
    if not pieces:
        raise DonorRetuneError("declaration triple must contain a declaration")
    return b"".join(pieces)


def _declaration_run_triple_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    old_digest = _required_string(parameters, "generated_header_sha256")
    if old_digest != Digest.from_bytes(_declaration_run_triple_payload(parameters)).value:
        raise DonorRetuneError("saved declaration-run digest differs from its parameters")
    width = _required_integer(parameters, "width")
    maximum = min(999, 10**width)
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        for seat in _TRIPLE_SEATS:
            count_name = f"{seat}_count"
            count = _required_integer(parameters, count_name)
            for candidate_count in sorted({count - distance, count + distance}):
                if not 0 <= candidate_count <= maximum:
                    continue
                changed = deepcopy(parameters)
                changed[count_name] = candidate_count
                try:
                    generated_digest = Digest.from_bytes(
                        _declaration_run_triple_payload(changed)
                    ).value
                except DonorRetuneError:
                    continue
                changed["generated_header_sha256"] = generated_digest
                candidates.append(
                    DonorRetuneCandidate(
                        intervention=_copy_with_parameters(intervention, changed),
                        distance=distance,
                        changes=(
                            DonorRetuneChange(
                                ("parameters", count_name),
                                count,
                                candidate_count,
                            ),
                            DonorRetuneChange(
                                ("parameters", "generated_header_sha256"),
                                old_digest,
                                generated_digest,
                                "derived",
                            ),
                        ),
                    )
                )
                if len(candidates) == limit:
                    return tuple(candidates)
    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class _DeclarationRunSeat:
    rendering_index: int
    operation_index: int
    item_index: int
    count: int
    maximum: int

    @property
    def path(self) -> tuple[RetunePathPart, ...]:
        return (
            "parameters",
            "renderings",
            self.rendering_index,
            "operations",
            self.operation_index,
            "gen",
            "items",
            self.item_index,
            "count",
        )


def _overlay_declaration_run_seats(
    renderings: list[JsonValue],
) -> tuple[_DeclarationRunSeat, ...]:
    seats: list[_DeclarationRunSeat] = []
    for rendering_index, raw_rendering in enumerate(renderings):
        if not isinstance(raw_rendering, dict):
            raise DonorRetuneError(f"renderings[{rendering_index}] must be an object")
        operations = raw_rendering.get("operations")
        if not isinstance(operations, list):
            raise DonorRetuneError(f"renderings[{rendering_index}].operations must be an array")
        for operation_index, raw_operation in enumerate(operations):
            if not isinstance(raw_operation, dict):
                raise DonorRetuneError(
                    f"renderings[{rendering_index}].operations[{operation_index}] must be an object"
                )
            generator = raw_operation.get("gen")
            if not isinstance(generator, dict) or generator.get("k") != "seq":
                continue
            items = generator.get("items")
            if not isinstance(items, list):
                raise DonorRetuneError(
                    f"renderings[{rendering_index}].operations[{operation_index}].gen.items "
                    "must be an array"
                )
            for item_index, raw_item in enumerate(items):
                if not isinstance(raw_item, dict) or raw_item.get("k") not in {
                    "extern_run",
                    "fwd_run",
                }:
                    continue
                count = raw_item.get("count")
                if type(count) is not int:
                    raise DonorRetuneError(
                        "an existing sequence declaration-run count must be an integer"
                    )
                if raw_item["k"] == "extern_run":
                    width = raw_item.get("width")
                    if type(width) is not int or not 1 <= width <= 3:
                        raise DonorRetuneError(
                            "an existing sequence extern-run width is outside its bounds"
                        )
                    maximum = min(999, 10**width)
                else:
                    maximum = 4096
                if not 1 <= count <= maximum:
                    raise DonorRetuneError(
                        "an existing sequence declaration run is outside its bounds"
                    )
                seats.append(
                    _DeclarationRunSeat(
                        rendering_index,
                        operation_index,
                        item_index,
                        count,
                        maximum,
                    )
                )
    return tuple(seats)


def _overlay_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    raw_renderings = parameters.get("renderings")
    if not isinstance(raw_renderings, list):
        raise DonorRetuneError("renderings must be an array")
    seats = _overlay_declaration_run_seats(raw_renderings)
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        for seat in seats:
            for candidate_count in sorted({seat.count - distance, seat.count + distance}):
                if not 1 <= candidate_count <= seat.maximum:
                    continue
                changed = deepcopy(parameters)
                changed_renderings = cast(list[JsonValue], changed["renderings"])
                rendering = cast(dict[str, JsonValue], changed_renderings[seat.rendering_index])
                operations = cast(list[JsonValue], rendering["operations"])
                operation = cast(dict[str, JsonValue], operations[seat.operation_index])
                generator = cast(dict[str, JsonValue], operation["gen"])
                items = cast(list[JsonValue], generator["items"])
                item = cast(dict[str, JsonValue], items[seat.item_index])
                item["count"] = candidate_count
                candidates.append(
                    DonorRetuneCandidate(
                        intervention=_copy_with_parameters(intervention, changed),
                        distance=distance,
                        changes=(DonorRetuneChange(seat.path, seat.count, candidate_count),),
                    )
                )
                if len(candidates) == limit:
                    return tuple(candidates)
    return tuple(candidates)


def enumerate_donor_retune_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int = DEFAULT_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
) -> tuple[DonorRetuneCandidate, ...]:
    """Enumerate nearby states for one already-saved classic donor.

    Unsupported families and non-donor records produce no candidates.  An
    eligible but malformed record is refused instead of being silently
    broadened or repaired.
    """

    _checked_bounds(radius, limit)
    if intervention.role is not ClassicRecipeRole.DONOR:
        return ()
    if intervention.family is ClassicRecipeFamily.DECLARATION_SHAPE:
        return _declaration_shape_candidates(intervention, radius=radius, limit=limit)
    if intervention.family is ClassicRecipeFamily.DECLARATION_RUN_TRIPLE:
        return _declaration_run_triple_candidates(
            intervention,
            radius=radius,
            limit=limit,
        )
    if intervention.family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return _overlay_candidates(intervention, radius=radius, limit=limit)
    return ()


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
    "DEFAULT_RETUNE_CANDIDATES",
    "DEFAULT_RETUNE_RADIUS",
    "MAX_RETUNE_CANDIDATES",
    "MAX_RETUNE_RADIUS",
    "DonorRetuneCandidate",
    "DonorRetuneChange",
    "DonorRetuneError",
    "MaterializedDonorRetuneCandidate",
    "enumerate_donor_retune_candidates",
    "materialize_donor_retune_candidate",
]
