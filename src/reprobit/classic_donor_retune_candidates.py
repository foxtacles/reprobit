"""Bounded, deterministic candidate enumeration for existing classic donors.

Enumeration proposes nearby authority states only. It never compiles a donor
or claims that a candidate restores byte identity.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Literal, TypeAlias, cast

from reprobit.classic.overlay_generator import render_classic_overlay_generator
from reprobit.classic.overlay_tokens import _build_token_index, _seat_digest_from_index
from reprobit.classic_donors import (
    generate_declaration_shape,
    generate_extern_run,
    generate_forward_run,
    generate_pad_shape,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue, canonical_json

DEFAULT_RETUNE_RADIUS = 4
DEFAULT_REPAIR_RETUNE_RADIUS = 8
MAX_RETUNE_RADIUS = 64
DEFAULT_RETUNE_CANDIDATES = 64
MAX_RETUNE_CANDIDATES = 4096

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
    kind: Literal["knob", "derived", "insert"] = "knob"
    """``insert`` adds one whole operation at ``path``; ``after`` is its canonical JSON."""


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

    def admit(moves: dict[str, int], distance: int) -> bool:
        changed = deepcopy(parameters)
        changes: list[DonorRetuneChange] = []
        for count_name, candidate_count in moves.items():
            changed[count_name] = candidate_count
            changes.append(
                DonorRetuneChange(
                    ("parameters", count_name),
                    _required_integer(parameters, count_name),
                    candidate_count,
                )
            )
        try:
            generated_digest = Digest.from_bytes(_declaration_run_triple_payload(changed)).value
        except DonorRetuneError:
            return False
        changed["generated_header_sha256"] = generated_digest
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
        return len(candidates) == limit

    # Every single-seat move of a distance precedes the two-seat moves of that
    # distance: a per-donor limit never trades a nearby single for a farther pair.
    for distance in range(1, radius + 1):
        for seat in _TRIPLE_SEATS:
            count_name = f"{seat}_count"
            count = _required_integer(parameters, count_name)
            for candidate_count in sorted({count - distance, count + distance}):
                if not 0 <= candidate_count <= maximum:
                    continue
                if admit({count_name: candidate_count}, distance):
                    return tuple(candidates)
        if distance < 2:
            continue
        for index, first in enumerate(_TRIPLE_SEATS):
            for second in _TRIPLE_SEATS[index + 1 :]:
                first_count = _required_integer(parameters, f"{first}_count")
                second_count = _required_integer(parameters, f"{second}_count")
                for first_value, second_value in _manhattan_shell(
                    first_count,
                    second_count,
                    distance,
                    accept=lambda a, b: 0 <= a <= maximum and 0 <= b <= maximum,
                ):
                    if first_value == first_count or second_value == second_count:
                        continue  # Single-seat moves were admitted above.
                    if admit(
                        {f"{first}_count": first_value, f"{second}_count": second_value},
                        distance,
                    ):
                        return tuple(candidates)
    return tuple(candidates)


def _manhattan_shell(
    first: int,
    second: int,
    distance: int,
    *,
    accept: Callable[[int, int], bool],
) -> list[tuple[int, int]]:
    """Every integer pair at exact Manhattan distance ``distance`` that ``accept`` admits."""

    shell: set[tuple[int, int]] = set()
    for first_delta in range(-distance, distance + 1):
        remaining = distance - abs(first_delta)
        for second_delta in (0,) if remaining == 0 else (-remaining, remaining):
            candidate = (first + first_delta, second + second_delta)
            if accept(*candidate):
                shell.add(candidate)
    return sorted(shell)


def _knob_candidate(
    intervention: ClassicRecipeIntervention,
    parameters: dict[str, JsonValue],
    changes: dict[str, tuple[RetuneScalar, RetuneScalar]],
    *,
    distance: int,
    digest_of: Callable[[dict[str, JsonValue]], bytes],
) -> DonorRetuneCandidate:
    changed = deepcopy(parameters)
    recorded: list[DonorRetuneChange] = []
    for name, (before, after) in changes.items():
        changed[name] = after
        recorded.append(DonorRetuneChange(("parameters", name), before, after))
    old_digest = _required_string(parameters, "generated_header_sha256")
    generated_digest = Digest.from_bytes(digest_of(changed)).value
    changed["generated_header_sha256"] = generated_digest
    recorded.append(
        DonorRetuneChange(
            ("parameters", "generated_header_sha256"),
            old_digest,
            generated_digest,
            "derived",
        )
    )
    return DonorRetuneCandidate(
        intervention=_copy_with_parameters(intervention, changed),
        distance=distance,
        changes=tuple(recorded),
    )


def _require_saved_digest(
    parameters: dict[str, JsonValue],
    digest_of: Callable[[dict[str, JsonValue]], bytes],
    *,
    label: str,
) -> None:
    try:
        expected = Digest.from_bytes(digest_of(parameters)).value
    except ValueError as exc:
        raise DonorRetuneError(f"saved {label} is invalid: {exc}") from exc
    if _required_string(parameters, "generated_header_sha256") != expected:
        raise DonorRetuneError(f"saved {label} digest differs from its parameters")


def _forward_run_payload(parameters: dict[str, JsonValue]) -> bytes:
    return generate_forward_run(
        _required_string(parameters, "prefix"),
        _required_integer(parameters, "count"),
        _required_integer(parameters, "width"),
    )


def _forward_declaration_run_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    _require_saved_digest(parameters, _forward_run_payload, label="forward declaration run")
    count = _required_integer(parameters, "count")
    maximum = min(999, 10 ** _required_integer(parameters, "width"))
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        for candidate_count in sorted({count - distance, count + distance}):
            if not 1 <= candidate_count <= maximum:
                continue
            candidates.append(
                _knob_candidate(
                    intervention,
                    parameters,
                    {"count": (count, candidate_count)},
                    distance=distance,
                    digest_of=_forward_run_payload,
                )
            )
            if len(candidates) == limit:
                return tuple(candidates)
    return tuple(candidates)


def _pad_shape_payload(parameters: dict[str, JsonValue]) -> bytes:
    return generate_pad_shape(
        _required_integer(parameters, "classes"),
        _required_integer(parameters, "functions_per_class"),
    )


def _pad_shape_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    _require_saved_digest(parameters, _pad_shape_payload, label="pad shape")
    classes = _required_integer(parameters, "classes")
    per_class = _required_integer(parameters, "functions_per_class")
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        for candidate_classes, candidate_per_class in _manhattan_shell(
            classes,
            per_class,
            distance,
            accept=lambda first, second: 1 <= first <= 99 and 1 <= second <= 99,
        ):
            changes: dict[str, tuple[RetuneScalar, RetuneScalar]] = {}
            if candidate_classes != classes:
                changes["classes"] = (classes, candidate_classes)
            if candidate_per_class != per_class:
                changes["functions_per_class"] = (per_class, candidate_per_class)
            candidates.append(
                _knob_candidate(
                    intervention,
                    parameters,
                    changes,
                    distance=distance,
                    digest_of=_pad_shape_payload,
                )
            )
            if len(candidates) == limit:
                return tuple(candidates)
    return tuple(candidates)


def _extern_run_pair_payload(parameters: dict[str, JsonValue]) -> bytes:
    width = _required_integer(parameters, "width")
    pieces: list[bytes] = []
    for seat in ("header", "seat"):
        count = _required_integer(parameters, f"{seat}_count")
        if count:
            pieces.append(
                generate_extern_run(_required_string(parameters, f"{seat}_prefix"), count, width)
            )
    if not pieces:
        raise ValueError("extern-run pair must contain a declaration")
    return b"".join(pieces)


def _extern_run_pair_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    _require_saved_digest(parameters, _extern_run_pair_payload, label="extern run pair")
    header = _required_integer(parameters, "header_count")
    seat = _required_integer(parameters, "seat_count")
    maximum = min(999, 10 ** _required_integer(parameters, "width"))
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        for candidate_header, candidate_seat in _manhattan_shell(
            header,
            seat,
            distance,
            accept=lambda first, second: (
                0 <= first <= maximum and 0 <= second <= maximum and (first or second) > 0
            ),
        ):
            changes: dict[str, tuple[RetuneScalar, RetuneScalar]] = {}
            if candidate_header != header:
                changes["header_count"] = (header, candidate_header)
            if candidate_seat != seat:
                changes["seat_count"] = (seat, candidate_seat)
            candidates.append(
                _knob_candidate(
                    intervention,
                    parameters,
                    changes,
                    distance=distance,
                    digest_of=_extern_run_pair_payload,
                )
            )
            if len(candidates) == limit:
                return tuple(candidates)
    return tuple(candidates)


_CROSS_TU_CARRIER_FIELDS = frozenset(
    {
        "donor_source",
        "donor_effective_source_sha256",
        "rendered_source_sha256",
        "rendered_source_size",
        "rendered_source_line_count",
    }
)


def _forward_run_with_shape_payload(parameters: dict[str, JsonValue]) -> bytes:
    return _forward_run_payload(parameters) + generate_declaration_shape(
        _required_integer(parameters, "classes"),
        _required_integer(parameters, "functions"),
    )


def _forward_run_with_shape_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
) -> tuple[DonorRetuneCandidate, ...]:
    parameters = _parameter_values(intervention)
    if _CROSS_TU_CARRIER_FIELDS.intersection(parameters):
        raise DonorRetuneError(
            "cross-TU forward-run-with-shape carriers pin a rendered donor source and "
            "cannot be retuned without re-rendering it"
        )
    _require_saved_digest(parameters, _forward_run_with_shape_payload, label="forward run shape")
    count = _required_integer(parameters, "count")
    maximum = min(999, 10 ** _required_integer(parameters, "width"))
    classes = _required_integer(parameters, "classes")
    functions = _required_integer(parameters, "functions")
    candidates: list[DonorRetuneCandidate] = []
    for distance in range(1, radius + 1):
        proposals: list[dict[str, tuple[RetuneScalar, RetuneScalar]]] = []
        for candidate_count in sorted({count - distance, count + distance}):
            if 1 <= candidate_count <= maximum:
                proposals.append({"count": (count, candidate_count)})
        for candidate_classes, candidate_functions in _manhattan_shell(
            classes,
            functions,
            distance,
            accept=lambda first, second: 1 <= first <= 10 and first <= second <= 10 * first,
        ):
            changes: dict[str, tuple[RetuneScalar, RetuneScalar]] = {}
            if candidate_classes != classes:
                changes["classes"] = (classes, candidate_classes)
            if candidate_functions != functions:
                changes["functions"] = (functions, candidate_functions)
            proposals.append(changes)
        for changes in proposals:
            candidates.append(
                _knob_candidate(
                    intervention,
                    parameters,
                    changes,
                    distance=distance,
                    digest_of=_forward_run_with_shape_payload,
                )
            )
            if len(candidates) == limit:
                return tuple(candidates)
    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class _OverlayKnobSeat:
    """One integer declaration knob inside a rendered overlay sequence.

    ``member_index`` is ``None`` for sequence items whose own ``key`` holds the
    knob (``extern_run``/``fwd_run`` counts, ``lines`` heights) and names the
    stem-expanded member group for ``class`` member counts.
    """

    rendering_index: int
    operation_index: int
    item_index: int
    member_index: int | None
    key: str
    value: int
    minimum: int
    maximum: int
    line: int

    @property
    def item_path(self) -> tuple[RetunePathPart, ...]:
        return (
            "parameters",
            "renderings",
            self.rendering_index,
            "operations",
            self.operation_index,
            "gen",
            "items",
            self.item_index,
        )

    @property
    def path(self) -> tuple[RetunePathPart, ...]:
        if self.member_index is None:
            return (*self.item_path, self.key)
        return (*self.item_path, "members", self.member_index, "count")


def _overlay_sequence_items(
    renderings: list[JsonValue],
) -> list[tuple[int, int, dict[str, JsonValue], list[JsonValue]]]:
    """Every ``seq`` generator of the renderings with its item list."""

    found: list[tuple[int, int, dict[str, JsonValue], list[JsonValue]]] = []
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
            found.append((rendering_index, operation_index, generator, items))
    return found


def _overlay_knob_seats(renderings: list[JsonValue]) -> tuple[_OverlayKnobSeat, ...]:
    """Every admitted integer knob of the overlay's rendered declaration sequences.

    Declaration-run counts, padding-line heights and stem-expanded class member
    counts are the knobs the grind varied when it authored the overlay; every
    other item field is part of the overlay's identity and never moves.
    """

    seats: list[_OverlayKnobSeat] = []
    for rendering_index, operation_index, _generator, items in _overlay_sequence_items(renderings):
        for item_index, raw_item in enumerate(items):
            if not isinstance(raw_item, dict):
                continue
            kind = raw_item.get("k")
            line = raw_item.get("line")
            if kind not in {"extern_run", "fwd_run", "lines", "class"}:
                continue
            if type(line) is not int or line < 1:
                raise DonorRetuneError("an existing sequence item must sit on a positive line")
            if kind == "extern_run":
                count = raw_item.get("count")
                width = raw_item.get("width")
                if type(count) is not int:
                    raise DonorRetuneError(
                        "an existing sequence declaration-run count must be an integer"
                    )
                if type(width) is not int or not 1 <= width <= 3:
                    raise DonorRetuneError(
                        "an existing sequence extern-run width is outside its bounds"
                    )
                maximum = min(999, 10**width)
                if not 1 <= count <= maximum:
                    raise DonorRetuneError(
                        "an existing sequence declaration run is outside its bounds"
                    )
                seats.append(
                    _OverlayKnobSeat(
                        rendering_index,
                        operation_index,
                        item_index,
                        None,
                        "count",
                        count,
                        1,
                        maximum,
                        line,
                    )
                )
            elif kind == "fwd_run":
                count = raw_item.get("count")
                if type(count) is not int:
                    raise DonorRetuneError(
                        "an existing sequence declaration-run count must be an integer"
                    )
                if not 1 <= count <= 4096:
                    raise DonorRetuneError(
                        "an existing sequence declaration run is outside its bounds"
                    )
                seats.append(
                    _OverlayKnobSeat(
                        rendering_index,
                        operation_index,
                        item_index,
                        None,
                        "count",
                        count,
                        1,
                        4096,
                        line,
                    )
                )
            elif kind == "lines":
                height = raw_item.get("n")
                if type(height) is not int or not 1 <= height <= 4096:
                    raise DonorRetuneError(
                        "an existing sequence padding height is outside its bounds"
                    )
                seats.append(
                    _OverlayKnobSeat(
                        rendering_index,
                        operation_index,
                        item_index,
                        None,
                        "n",
                        height,
                        1,
                        4096,
                        line,
                    )
                )
            else:
                members = raw_item.get("members")
                if not isinstance(members, list):
                    continue
                for member_index, raw_member in enumerate(members):
                    if not isinstance(raw_member, dict) or "stem" not in raw_member:
                        continue
                    count = raw_member.get("count")
                    if type(count) is not int or not 1 <= count <= 4096:
                        raise DonorRetuneError("an existing class member run is outside its bounds")
                    seats.append(
                        _OverlayKnobSeat(
                            rendering_index,
                            operation_index,
                            item_index,
                            member_index,
                            "count",
                            count,
                            1,
                            4096,
                            line,
                        )
                    )
    return tuple(seats)


def _rendered_extent(generator: dict[str, JsonValue]) -> int | None:
    """The last nonblank line of one rendered ``seq`` canvas, or ``None`` if it cannot render."""

    try:
        rendered = render_classic_overlay_generator(generator)
    except Exception:
        return None
    extent = 0
    for index, line in enumerate(rendered.split(b"\n"), start=1):
        if line.strip():
            extent = index
    # Blank padding renders invisibly but still occupies its lines of the canvas.
    for raw_item in cast(list[JsonValue], generator.get("items", [])):
        if isinstance(raw_item, dict) and raw_item.get("k") == "lines":
            pad_line, pad_height = raw_item.get("line"), raw_item.get("n")
            if type(pad_line) is int and type(pad_height) is int:
                extent = max(extent, pad_line + pad_height - 1)
    return extent


_SequenceLayouts = dict[tuple[int, int], tuple[int, int] | None]


def _sequence_layouts(parameters: dict[str, JsonValue]) -> _SequenceLayouts:
    """(canvas, rendered extent) per ``seq`` generator, or ``None`` when it cannot render."""

    layouts: _SequenceLayouts = {}
    raw_renderings = parameters.get("renderings")
    if not isinstance(raw_renderings, list):
        raise DonorRetuneError("renderings must be an array")
    for rendering_index, operation_index, generator, _items in _overlay_sequence_items(
        raw_renderings
    ):
        canvas = generator.get("lines")
        extent = _rendered_extent(generator)
        layouts[(rendering_index, operation_index)] = (
            None if extent is None or type(canvas) is not int else (canvas, extent)
        )
    return layouts


def _apply_overlay_moves(
    parameters: dict[str, JsonValue],
    moves: Sequence[tuple[_OverlayKnobSeat, int]],
    layouts: _SequenceLayouts,
    *,
    preserve_canvas_slack: bool = False,
) -> tuple[dict[str, JsonValue], tuple[DonorRetuneChange, ...]] | None:
    """Move the given knobs and keep each sequence's line layout consistent.

    A knob that grows or shrinks a declaration run by ``delta`` lines pushes
    every later item of the same sequence by ``delta`` and lets a canvas that
    exactly fitted its items keep fitting them; by default, a canvas with slack
    grows only when the items would otherwise leave it.  Project-source moves
    can instead preserve their existing trailing slack.  Returns ``None`` when
    the moved layout is impossible (a line or canvas would drop below one).
    """

    changed = deepcopy(parameters)
    renderings = cast(list[JsonValue], changed["renderings"])
    changes: list[DonorRetuneChange] = []
    line_shifts: dict[tuple[int, int, int], int] = {}
    canvas_deltas: dict[tuple[int, int], int] = {}
    packed = layouts
    for seat, delta in moves:
        rendering = cast(dict[str, JsonValue], renderings[seat.rendering_index])
        operations = cast(list[JsonValue], rendering["operations"])
        operation = cast(dict[str, JsonValue], operations[seat.operation_index])
        generator = cast(dict[str, JsonValue], operation["gen"])
        sequence_key = (seat.rendering_index, seat.operation_index)
        items = cast(list[JsonValue], generator["items"])
        item = cast(dict[str, JsonValue], items[seat.item_index])
        if seat.member_index is None:
            item[seat.key] = seat.value + delta
        else:
            members = cast(list[JsonValue], item["members"])
            member = cast(dict[str, JsonValue], members[seat.member_index])
            member["count"] = seat.value + delta
        changes.append(DonorRetuneChange(seat.path, seat.value, seat.value + delta))
        if packed.get(sequence_key) is None:
            continue  # Unknown layout: the knob moves alone, as saved overlays always did.
        for item_index, raw_later in enumerate(items):
            if not isinstance(raw_later, dict) or item_index == seat.item_index:
                continue
            later_line = raw_later.get("line")
            if type(later_line) is int and later_line > seat.line:
                line_shifts[(*sequence_key, item_index)] = (
                    line_shifts.get((*sequence_key, item_index), 0) + delta
                )
        canvas_deltas[sequence_key] = canvas_deltas.get(sequence_key, 0) + delta
    for (rendering_index, operation_index, item_index), shift in sorted(line_shifts.items()):
        if shift == 0:
            continue
        rendering = cast(dict[str, JsonValue], renderings[rendering_index])
        operation = cast(
            dict[str, JsonValue], cast(list[JsonValue], rendering["operations"])[operation_index]
        )
        items = cast(list[JsonValue], cast(dict[str, JsonValue], operation["gen"])["items"])
        item = cast(dict[str, JsonValue], items[item_index])
        before = cast(int, item["line"])
        if before + shift < 1:
            return None
        item["line"] = before + shift
        changes.append(
            DonorRetuneChange(
                (
                    "parameters",
                    "renderings",
                    rendering_index,
                    "operations",
                    operation_index,
                    "gen",
                    "items",
                    item_index,
                    "line",
                ),
                before,
                before + shift,
                "derived",
            )
        )
    for (rendering_index, operation_index), _delta in sorted(canvas_deltas.items()):
        layout = packed[(rendering_index, operation_index)]
        if layout is None:
            continue
        canvas, extent = layout
        rendering = cast(dict[str, JsonValue], renderings[rendering_index])
        operation = cast(
            dict[str, JsonValue], cast(list[JsonValue], rendering["operations"])[operation_index]
        )
        generator = cast(dict[str, JsonValue], operation["gen"])
        moved_extent = _rendered_extent({**generator, "lines": max(canvas, 1) + 8192})
        if moved_extent is None:
            return None
        if preserve_canvas_slack:
            if canvas < extent:
                return None
            new_canvas = moved_extent + canvas - extent
        else:
            new_canvas = moved_extent if canvas == extent else max(canvas, moved_extent)
        if new_canvas < 1:
            return None
        if new_canvas != canvas:
            generator["lines"] = new_canvas
            changes.append(
                DonorRetuneChange(
                    (
                        "parameters",
                        "renderings",
                        rendering_index,
                        "operations",
                        operation_index,
                        "gen",
                        "lines",
                    ),
                    canvas,
                    new_canvas,
                    "derived",
                )
            )
    return changed, tuple(changes)


INSERTED_RUN_STEM = "RbCarrierRun"
INSERTED_RUN_WIDTH = 3
MAX_INSERTED_RUN_COUNT = 500
_INSERTION_PLACEMENTS: tuple[tuple[str, str], ...] = (("end", "suffix"), ("start", "prefix"))
_INSERTED_OPERATION_PREFIX = "op_rbit_carrier_"
_SEAT_WINDOW = 32


def _boundary_anchor(data: bytes, placement: str) -> dict[str, JsonValue]:
    """The file-boundary seat the overlay renderer resolves without a line pair."""

    index = _build_token_index(data)
    window = min(_SEAT_WINDOW, index.token_count)
    if window < 1:
        raise DonorRetuneError("source has no token to witness a file-boundary carrier seat")
    if placement == "end":
        anchor: dict[str, JsonValue] = {
            "a": 0,
            "at": "end",
            "ctx": _seat_digest_from_index(index, index.token_count, window, 0),
        }
    else:
        anchor = {
            "at": "start",
            "b": 0,
            "ctx": _seat_digest_from_index(index, 0, 0, window),
        }
    if window != _SEAT_WINDOW:
        anchor["b" if placement == "end" else "a"] = window
    return anchor


def inserted_run_operation(data: bytes, placement: str, count: int) -> dict[str, JsonValue]:
    """One anchored forward-declaration run of ``count`` names at a file boundary."""

    if placement not in {"end", "start"}:
        raise DonorRetuneError("carrier insertion placement must be 'end' or 'start'")
    if type(count) is not int or not 1 <= count <= 4096:
        raise DonorRetuneError("carrier insertion count must be an integer from 1 to 4096")
    return {
        "anchor": _boundary_anchor(data, placement),
        "gen": {
            "items": [
                {
                    "count": count,
                    "first": 0,
                    "k": "fwd_run",
                    "line": 1,
                    "stem": INSERTED_RUN_STEM,
                    "width": INSERTED_RUN_WIDTH,
                }
            ],
            "k": "seq",
            "lines": count,
        },
        "id": f"{_INSERTED_OPERATION_PREFIX}{placement}",
        "op": "insert",
    }


def _overlay_insertion_candidates(
    intervention: ClassicRecipeIntervention,
    parameters: dict[str, JsonValue],
    *,
    distance: int,
    carrier_sources: Mapping[str, bytes],
) -> list[DonorRetuneCandidate]:
    """Add a fresh forward-declaration run of ``distance`` names at each file boundary.

    An overlay whose sequences carry no knob (only semantic rewrites and
    include swaps) has no nearby state to move to; a declaration-only run
    appended at a file boundary is the closed carrier every other donor
    family offers, rendered together with the overlay's own operations.
    """

    raw_renderings = parameters.get("renderings")
    if not isinstance(raw_renderings, list) or not raw_renderings:
        return []
    rendering = raw_renderings[0]
    if not isinstance(rendering, dict):
        return []
    path = rendering.get("path")
    operations = rendering.get("operations")
    if not isinstance(path, str) or not isinstance(operations, list):
        return []
    data = carrier_sources.get(path)
    if data is None:
        return []
    existing_ids = {
        str(item.get("id")) for item in operations if isinstance(item, dict) and "id" in item
    }
    if any(name.startswith(_INSERTED_OPERATION_PREFIX) for name in existing_ids):
        return []  # A carrier inserted by an earlier retune is an ordinary knob now.
    candidates: list[DonorRetuneCandidate] = []
    for placement, _name in _INSERTION_PLACEMENTS:
        try:
            operation = inserted_run_operation(data, placement, distance)
        except DonorRetuneError:
            continue
        changed = deepcopy(parameters)
        changed_renderings = cast(list[JsonValue], changed["renderings"])
        changed_rendering = cast(dict[str, JsonValue], changed_renderings[0])
        cast(list[JsonValue], changed_rendering["operations"]).append(cast(JsonValue, operation))
        change = DonorRetuneChange(
            ("parameters", "renderings", 0, "operations", len(operations)),
            "",
            canonical_json(operation).decode().rstrip("\n"),
            "insert",
        )
        candidates.append(
            DonorRetuneCandidate(
                intervention=_copy_with_parameters(intervention, changed),
                distance=distance,
                changes=(change,),
            )
        )
    return candidates


def _overlay_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int,
    limit: int,
    carrier_sources: Mapping[str, bytes] | None = None,
) -> tuple[DonorRetuneCandidate, ...]:
    """Nearby overlay states, cheapest first.

    Per distance: every one-knob move, then a boundary carrier insertion of
    that many names (when ``carrier_sources`` is given); after every distance,
    two knobs of one rendering moved together.
    """

    parameters = _parameter_values(intervention)
    raw_renderings = parameters.get("renderings")
    if not isinstance(raw_renderings, list):
        raise DonorRetuneError("renderings must be an array")
    seats = _overlay_knob_seats(raw_renderings)
    layouts = _sequence_layouts(parameters)
    pairs = [
        (first, second)
        for index, first in enumerate(seats)
        for second in seats[index + 1 :]
        if first.rendering_index == second.rendering_index
    ]
    candidates: list[DonorRetuneCandidate] = []

    def admit(moves: list[tuple[_OverlayKnobSeat, int]], distance: int) -> bool:
        moved = _apply_overlay_moves(parameters, moves, layouts)
        if moved is None:
            return False
        changed, changes = moved
        candidates.append(
            DonorRetuneCandidate(
                intervention=_copy_with_parameters(intervention, changed),
                distance=distance,
                changes=changes,
            )
        )
        return len(candidates) == limit

    # Every single-knob move (cheapest neighbourhood) precedes any two-knob move so a
    # per-donor candidate limit never trades a nearby single move for a distant pair.
    # A boundary carrier insertion of ``distance`` names follows the singles of its tier.
    for distance in range(1, radius + 1):
        for seat in seats:
            for delta in (-distance, distance):
                if not seat.minimum <= seat.value + delta <= seat.maximum:
                    continue
                if admit([(seat, delta)], distance):
                    return tuple(candidates)
        if carrier_sources is not None:
            for inserted in _overlay_insertion_candidates(
                intervention, parameters, distance=distance, carrier_sources=carrier_sources
            ):
                candidates.append(inserted)
                if len(candidates) == limit:
                    return tuple(candidates)
    for distance in range(2, radius + 1):
        for first, second in pairs:

            def within(
                a: int,
                b: int,
                first: _OverlayKnobSeat = first,
                second: _OverlayKnobSeat = second,
            ) -> bool:
                return first.minimum <= a <= first.maximum and second.minimum <= b <= second.maximum

            for first_value, second_value in _manhattan_shell(
                first.value, second.value, distance, accept=within
            ):
                if first_value == first.value or second_value == second.value:
                    continue  # Single-knob moves were already admitted above.
                moves = [
                    (first, first_value - first.value),
                    (second, second_value - second.value),
                ]
                if admit(moves, distance):
                    return tuple(candidates)
    # A boundary carrier is a fresh declaration run, not a move of a saved knob, so
    # its length is not bounded by the retune radius: longer runs follow, up to the
    # per-donor limit, the way discovery tries longer forward runs after shapes.
    if carrier_sources is not None:
        for count in range(radius + 1, MAX_INSERTED_RUN_COUNT + 1):
            for inserted in _overlay_insertion_candidates(
                intervention, parameters, distance=count, carrier_sources=carrier_sources
            ):
                candidates.append(inserted)
                if len(candidates) == limit:
                    return tuple(candidates)
    return tuple(candidates)


def enumerate_donor_retune_candidates(
    intervention: ClassicRecipeIntervention,
    *,
    radius: int = DEFAULT_RETUNE_RADIUS,
    limit: int = DEFAULT_RETUNE_CANDIDATES,
    carrier_sources: Mapping[str, bytes] | None = None,
) -> tuple[DonorRetuneCandidate, ...]:
    """Enumerate nearby states for one already-saved classic donor.

    Every closed declaration-only carrier family is eligible: declaration
    shapes, pad shapes, forward declaration runs, extern run pairs, forward
    runs with a shape (when they carry no cross-TU rendering pins),
    declaration run triples, and the declaration-run, padding and class-member
    counts of donor source overlays (one knob, or two knobs of one rendering
    together, with the rendered line layout kept consistent).  When
    ``carrier_sources`` supplies the authenticated clean bytes of the overlay's
    owning source, an overlay also offers a fresh forward-declaration run of
    ``distance`` names inserted at the file end or start.  Other families and
    non-donor records produce no candidates.  An eligible but malformed record
    is refused instead of being silently broadened or repaired.
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
        return _overlay_candidates(
            intervention, radius=radius, limit=limit, carrier_sources=carrier_sources
        )
    if intervention.family is ClassicRecipeFamily.FORWARD_DECLARATION_RUN:
        return _forward_declaration_run_candidates(intervention, radius=radius, limit=limit)
    if intervention.family is ClassicRecipeFamily.PAD_SHAPE:
        return _pad_shape_candidates(intervention, radius=radius, limit=limit)
    if intervention.family is ClassicRecipeFamily.EXTERN_RUN_PAIR:
        return _extern_run_pair_candidates(intervention, radius=radius, limit=limit)
    if intervention.family is ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE:
        return _forward_run_with_shape_candidates(intervention, radius=radius, limit=limit)
    return ()


__all__ = [
    "DEFAULT_REPAIR_RETUNE_RADIUS",
    "DEFAULT_RETUNE_CANDIDATES",
    "DEFAULT_RETUNE_RADIUS",
    "INSERTED_RUN_STEM",
    "INSERTED_RUN_WIDTH",
    "MAX_RETUNE_CANDIDATES",
    "MAX_RETUNE_RADIUS",
    "DonorRetuneCandidate",
    "DonorRetuneChange",
    "DonorRetuneError",
    "RetunePathPart",
    "RetuneScalar",
    "enumerate_donor_retune_candidates",
    "inserted_run_operation",
]
