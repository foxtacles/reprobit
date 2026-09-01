"""Bounded, deterministic candidate enumeration for existing classic donors.

Enumeration proposes nearby authority states only. It never compiles a donor
or claims that a candidate restores byte identity.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Literal, TypeAlias, cast

from reprobit.classic_donors import generate_declaration_shape, generate_forward_run
from reprobit.model import Digest
from reprobit.schema import (
    ClassicField,
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
            raise DonorRetuneError(f"{seat}_count must be an integer from 0 to {maximum}")
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


__all__ = [
    "DEFAULT_RETUNE_CANDIDATES",
    "DEFAULT_RETUNE_RADIUS",
    "MAX_RETUNE_CANDIDATES",
    "MAX_RETUNE_RADIUS",
    "DonorRetuneCandidate",
    "DonorRetuneChange",
    "DonorRetuneError",
    "RetunePathPart",
    "RetuneScalar",
    "enumerate_donor_retune_candidates",
]
