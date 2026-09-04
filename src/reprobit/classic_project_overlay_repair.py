"""Bounded repair of project source-overlay compiler state."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

from reprobit.classic.coff_evidence import _CoffObject, _CoffSection, _parse_coff
from reprobit.classic.coff_projection_data import _section_permutation_identity
from reprobit.classic.coff_projection_statements import _symbols_by_section
from reprobit.classic.compiler_epoch import (
    _ProjectCompilerEpochPair,
    _require_namespace_source_authority,
    _validate_compiler_namespaces,
    _validate_project_compiler_epoch_pair,
    _ValidatedCompilerNamespace,
)
from reprobit.classic.overlay_document import (
    render_classic_overlay_leaf_subset,
    render_classic_overlay_proposal,
)
from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession
from reprobit.classic.semantic_contracts import (
    CleanSourceInput,
    CompilerEpochInvocation,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import (
    _derive_project_overlay_compiler_epoch,
    _OverlaySourceValidation,
)
from reprobit.classic.source_overlay_claims import _HEADER_SUFFIXES, _SOURCE_SUFFIXES
from reprobit.classic_donor_retune_candidates import (
    _apply_overlay_moves,
    _overlay_knob_seats,
    _OverlayKnobSeat,
    _rendered_extent,
    _sequence_layouts,
)
from reprobit.classic_link_layout_repair import ClassicLinkLayoutHint
from reprobit.classic_orchestration import compiler_terminal_consumer_targets
from reprobit.classic_repair_authority import (
    ClassicProjectOverlayEdit,
    _inert_project_generator,
)
from reprobit.classic_runtime_environment import _toolchain_include_reader_payloads
from reprobit.classic_runtime_graph import classic_compiler_product_refs
from reprobit.classic_runtime_probe import (
    ClassicCompilerProbeOutput,
    ClassicCompilerSourceEpoch,
    ClassicCompilerSourceEpochOutput,
    ClassicProbeExecution,
)
from reprobit.intervention_metadata import (
    ClassicRecipeFamily,
    ClassicRecipeRole,
)
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import (
    ClassicField,
    ClassicRecipeIntervention,
    ProjectBundle,
)
from reprobit.search_limits import DEFAULT_REPAIR_RETUNE_RADIUS, DEFAULT_RETUNE_CANDIDATES
from reprobit.strict_json import JsonValue, canonical_json


class ClassicProjectOverlayRepairError(RuntimeError):
    """A source-layout repair could not be derived without broadening authority."""


@dataclass(frozen=True, slots=True)
class ClassicProjectOverlayRepair:
    """One fully planned and compiler-proven project-overlay adjustment."""

    edit: ClassicProjectOverlayEdit
    source_path: str
    affected_node_ids: tuple[str, ...]
    distance: int
    description: str


@dataclass(frozen=True, slots=True)
class ClassicProjectOverlayRepairResult:
    """Result of one bounded non-certifying source-layout search."""

    checked: bool
    repair: ClassicProjectOverlayRepair | None
    compiled_candidates: int
    source_path: str | None = None
    reason: str | None = None
    exhausted: bool = False


@dataclass(frozen=True, slots=True)
class _RawCandidate:
    operations: tuple[dict[str, object], ...]
    selected_leaf_keys: frozenset[tuple[str, int]]
    distance: int
    description: str


@dataclass(frozen=True, slots=True)
class _LinkLayoutObjectState:
    order: tuple[str, ...]
    identities: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class _AdditionSeat:
    operation_index: int
    operation_id: str
    declaration_kind: str
    declaration_tag: str | None
    leaf_count: int
    extent: int
    canvas: int
    first_identifiers: tuple[str, ...]
    has_unselected_leaf: bool
    label: str


@dataclass(frozen=True, slots=True)
class _RawProposal:
    operations: Sequence[Mapping[str, object]]
    selected_leaf_keys: frozenset[tuple[str, int]]
    description: str


def _knob_name(seat: _OverlayKnobSeat) -> str:
    if seat.key == "n":
        return "blank-line count"
    if seat.member_index is not None:
        return "class member count"
    return "declaration count"


@dataclass(frozen=True, slots=True)
class _Candidate:
    raw: _RawCandidate
    edit: ClassicProjectOverlayEdit
    bundle: ProjectBundle
    source_pairs: tuple[ProjectOverlaySourcePair, ...]
    effective_outputs: Mapping[str, bytes]
    counterfactual_outputs: Mapping[str, bytes]
    affected_node_ids: tuple[str, ...]
    source_path: str


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    return {field.name: field.value for field in intervention.parameters}


def _project_overlays(bundle: ProjectBundle) -> tuple[ClassicRecipeIntervention, ...]:
    return tuple(
        item
        for item in bundle.interventions
        if isinstance(item, ClassicRecipeIntervention)
        and item.role is ClassicRecipeRole.PROJECT
        and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
    )


def _operation_id(path: str, index: int, operation: Mapping[str, object]) -> str:
    value = operation.get("id")
    return value if isinstance(value, str) and value else f"{path}#{index}"


def _operation_label(index: int, operation: Mapping[str, object]) -> str:
    value = operation.get("id")
    return value if isinstance(value, str) and value else f"layout {index + 1}"


def _leaf_count(value: object) -> int:
    if not isinstance(value, Mapping):
        return 0
    if value.get("k") != "seq":
        return 1
    items = value.get("items")
    if not isinstance(items, list):
        return 0
    return sum(
        _leaf_count({key: child for key, child in item.items() if key != "line"})
        for item in items
        if isinstance(item, Mapping)
    )


def _flat_inert_knob(
    operations: Sequence[Mapping[str, object]],
    operation_index: int,
    item_index: int,
) -> bool:
    if not 0 <= operation_index < len(operations):
        return False
    generator = operations[operation_index].get("gen")
    if not isinstance(generator, Mapping) or generator.get("k") != "seq":
        return False
    items = generator.get("items")
    if not isinstance(items, list) or not 0 <= item_index < len(items):
        return False
    if any(_leaf_count(item) != 1 for item in items):
        return False
    item = items[item_index]
    return isinstance(item, dict) and _inert_project_generator(
        {key: value for key, value in item.items() if key != "line"}
    )


def _identifier_census(payloads: Iterable[bytes], value: object) -> frozenset[str]:
    identifiers: set[str] = set()
    token = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
    for payload in payloads:
        identifiers.update(match.decode("ascii") for match in token.findall(payload))
    identifiers.update(match.decode("ascii") for match in token.findall(canonical_json(value)))
    return frozenset(identifiers)


@dataclass(frozen=True, slots=True)
class _IdentifierFamily:
    stem: str
    width: int
    last: int
    alphabetic: bool


def _parse_identifier_family(identifier: str) -> _IdentifierFamily | None:
    numeric = re.fullmatch(r"(.+?)(\d+)", identifier)
    if numeric is not None:
        return _IdentifierFamily(
            numeric.group(1),
            len(numeric.group(2)),
            int(numeric.group(2)),
            False,
        )
    alphabetic = re.fullmatch(r"(.+?)([A-Z]+)", identifier)
    if alphabetic is None:
        return None
    ordinal = 0
    for character in alphabetic.group(2):
        ordinal = ordinal * 26 + ord(character) - ord("A")
    return _IdentifierFamily(
        alphabetic.group(1),
        len(alphabetic.group(2)),
        ordinal,
        True,
    )


def _declaration_identifier_family(
    local_value: object,
    declaration_kind: str,
) -> _IdentifierFamily | None:
    nearby: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            if value.get("k") == declaration_kind and isinstance(value.get("id"), str):
                nearby.append(cast(str, value["id"]))
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(local_value)
    if not nearby:
        return None
    family = _parse_identifier_family(nearby[-1])
    if family is None:
        return None
    if declaration_kind == "fwd":
        signatures = {
            (parsed.stem, parsed.width, parsed.alphabetic)
            for identifier in nearby
            if (parsed := _parse_identifier_family(identifier)) is not None
        }
        if len(signatures) != 1 or any(
            _parse_identifier_family(identifier) is None for identifier in nearby
        ):
            return None
    return family


def _family_identifier(family: _IdentifierFamily, ordinal: int) -> str:
    if not family.alphabetic:
        return f"{family.stem}{ordinal:0{family.width}d}"
    suffix = ""
    for _index in range(family.width):
        ordinal, remainder = divmod(ordinal, 26)
        suffix = chr(ord("A") + remainder) + suffix
    return family.stem + suffix


def _declaration_identifier_candidates(
    declaration_kind: str,
    local_value: object,
    identifiers: frozenset[str],
    reusable_identifiers: frozenset[str],
    *,
    excluded_local_value: object | None = None,
    limit: int,
) -> tuple[str, ...]:
    family = _declaration_identifier_family(local_value, declaration_kind)
    if family is None:
        if declaration_kind != "empty_class":
            return ()
        family = _IdentifierFamily("ReprobitUnusedClass", 3, -1, False)
    local_identifiers = set(
        _identifier_census(
            (),
            local_value if excluded_local_value is None else excluded_local_value,
        )
    )
    reusable: list[tuple[int, str]] = []
    reusable_pool = () if declaration_kind == "fwd" else reusable_identifiers
    for identifier in reusable_pool:
        parsed = _parse_identifier_family(identifier)
        if (
            parsed is None
            or parsed.stem != family.stem
            or parsed.width != family.width
            or parsed.alphabetic != family.alphabetic
            or identifier in local_identifiers
        ):
            continue
        reusable.append((parsed.last, identifier))
    reusable.sort(
        key=lambda item: (
            abs(item[0] - family.last),
            item[0] < family.last,
            item[0],
            item[1],
        )
    )
    family_size = (26 if family.alphabetic else 10) ** family.width
    for index in range(min(family_size, len(identifiers) + 1)):
        candidate = _family_identifier(family, index)
        if candidate not in identifiers:
            return (*tuple(identifier for _index, identifier in reusable[:limit]), candidate)
    raise ClassicProjectOverlayRepairError("no fresh inert declaration identifier is available")


def _addition_declaration_template(
    generator: Mapping[str, object],
) -> tuple[str, str | None]:
    items = generator.get("items")
    if isinstance(items, list):
        for item in reversed(items):
            if not isinstance(item, Mapping):
                continue
            kind = item.get("k")
            if kind == "fwd" and _declaration_identifier_family(item, "fwd") is not None:
                tag = item.get("tag")
                return "fwd", tag if isinstance(tag, str) else None
            if kind == "empty_class":
                tag = item.get("tag")
                return "empty_class", tag if isinstance(tag, str) else None
    return "empty_class", None


def _raw_candidates(
    *,
    path: str,
    operations: Sequence[Mapping[str, object]],
    selected_leaf_keys: frozenset[tuple[str, int]],
    identifiers: frozenset[str],
    reusable_identifiers: frozenset[str] = frozenset(),
    radius: int,
    limit: int,
) -> tuple[_RawCandidate, ...]:
    """Reuse the donor overlay's exact knob/layout mechanics, plus leaf edges."""

    if limit <= 0:
        return ()

    operation_values = cast(list[JsonValue], deepcopy(list(operations)))
    parameters: dict[str, JsonValue] = {
        "renderings": cast(
            JsonValue,
            [{"path": path, "operations": operation_values}],
        )
    }
    seats = tuple(
        seat
        for seat in _overlay_knob_seats(cast(list[JsonValue], parameters["renderings"]))
        if _flat_inert_knob(
            operations,
            seat.operation_index,
            seat.item_index,
        )
    )
    layouts = _sequence_layouts(parameters)
    addition_seats: list[_AdditionSeat] = []
    for operation_index, operation in enumerate(operations):
        # ``empty_class`` is a C++ declaration.  Existing C overlays may still
        # move or remove their own proven inert leaves, but repair must not
        # invent C++ syntax in a C source file.
        if PurePosixPath(path).suffix.casefold() == ".c":
            continue
        generator = operation.get("gen")
        if not isinstance(generator, dict) or generator.get("k") != "seq":
            continue
        items = generator.get("items")
        if not isinstance(items, list) or not items:
            continue
        operation_id = _operation_id(path, operation_index, operation)
        leaf_count = _leaf_count(generator)
        canvas = generator.get("lines")
        if (
            leaf_count != len(items)
            or operation.get("op") not in {"insert", "append"}
            or not isinstance(canvas, int)
        ):
            continue
        extent = _rendered_extent(cast(dict[str, JsonValue], generator))
        declaration_kind, declaration_tag = _addition_declaration_template(generator)
        identifier_context: object = (
            generator
            if _declaration_identifier_family(generator, declaration_kind) is not None
            else operations
        )
        first_identifiers = _declaration_identifier_candidates(
            declaration_kind,
            identifier_context,
            identifiers,
            reusable_identifiers,
            excluded_local_value=operations,
            limit=limit,
        )
        if not first_identifiers:
            continue
        addition_seats.append(
            _AdditionSeat(
                operation_index,
                operation_id,
                declaration_kind,
                declaration_tag,
                leaf_count,
                canvas if extent is None else extent,
                canvas,
                first_identifiers,
                any(
                    (operation_id, leaf_index) not in selected_leaf_keys
                    for leaf_index in range(leaf_count)
                ),
                _operation_label(operation_index, operation),
            )
        )
    addition_seats.sort(key=lambda seat: (not seat.has_unselected_leaf, -seat.operation_index))
    candidates: list[_RawCandidate] = []
    seen: set[bytes] = set()

    def admit(
        candidate_operations: Sequence[Mapping[str, object]],
        keys: frozenset[tuple[str, int]],
        distance: int,
        description: str,
    ) -> bool:
        payload = canonical_json(candidate_operations)
        if payload in seen:
            return False
        seen.add(payload)
        candidates.append(
            _RawCandidate(
                tuple(deepcopy(dict(item)) for item in candidate_operations),
                keys,
                distance,
                description,
            )
        )
        return len(candidates) >= limit

    def additions() -> Iterator[tuple[int, _RawProposal]]:
        maximum_identifier_variants = max(
            (len(seat.first_identifiers) for seat in addition_seats), default=0
        )
        coordinates = (
            ((0, distance) for distance in range(1, radius + 1)),
            ((identifier_index, 1) for identifier_index in range(1, maximum_identifier_variants)),
            (
                (identifier_index, distance)
                for distance in range(2, radius + 1)
                for identifier_index in range(1, maximum_identifier_variants)
            ),
        )
        for phase in coordinates:
            for identifier_index, distance in phase:
                for addition_seat in addition_seats:
                    if identifier_index >= len(addition_seat.first_identifiers):
                        continue
                    first_identifier = addition_seat.first_identifiers[identifier_index]
                    changed_operations = deepcopy(list(operations))
                    changed_generator = cast(
                        dict[str, object],
                        changed_operations[addition_seat.operation_index]["gen"],
                    )
                    changed_items = cast(list[object], changed_generator["items"])
                    generated_identifiers = set(identifiers)
                    generated_identifiers.discard(first_identifier)
                    identifier = first_identifier
                    for addition_index in range(distance):
                        if addition_index:
                            next_identifiers = _declaration_identifier_candidates(
                                addition_seat.declaration_kind,
                                changed_generator,
                                frozenset(generated_identifiers),
                                reusable_identifiers,
                                excluded_local_value=changed_operations,
                                limit=limit,
                            )
                            if not next_identifiers:
                                break
                            identifier = next_identifiers[0]
                        generated_identifiers.add(identifier)
                        declaration: dict[str, object] = {
                            "id": identifier,
                            "k": addition_seat.declaration_kind,
                            "line": addition_seat.extent + addition_index + 1,
                        }
                        if addition_seat.declaration_tag is not None:
                            declaration["tag"] = addition_seat.declaration_tag
                        changed_items.append(declaration)
                    if len(changed_items) != addition_seat.leaf_count + distance:
                        continue
                    changed_generator["lines"] = addition_seat.canvas + distance
                    yield (
                        distance,
                        _RawProposal(
                            changed_operations,
                            selected_leaf_keys
                            | {
                                (
                                    addition_seat.operation_id,
                                    addition_seat.leaf_count + addition_index,
                                )
                                for addition_index in range(distance)
                            },
                            (
                                f"added {first_identifier} to {addition_seat.label}"
                                if distance == 1
                                else (
                                    f"added {distance} inert declarations to "
                                    f"{addition_seat.label}, starting with {first_identifier}"
                                )
                            ),
                        ),
                    )

    def knob_moves(distance: int) -> Iterator[_RawProposal]:
        for knob_seat in seats:
            label = _operation_label(
                knob_seat.operation_index,
                operations[knob_seat.operation_index],
            )
            for delta in (-distance, distance):
                if not knob_seat.minimum <= knob_seat.value + delta <= knob_seat.maximum:
                    continue
                moved = _apply_overlay_moves(
                    parameters,
                    ((knob_seat, delta),),
                    layouts,
                    preserve_canvas_slack=True,
                )
                if moved is None:
                    continue
                changed, _changes = moved
                renderings = cast(list[JsonValue], changed["renderings"])
                rendering = cast(dict[str, JsonValue], renderings[0])
                changed_operations = cast(list[Mapping[str, object]], rendering["operations"])
                yield _RawProposal(
                    changed_operations,
                    selected_leaf_keys,
                    f"adjusted {_knob_name(knob_seat)} by {delta:+d} in {label}",
                )

    def removals(distance: int) -> Iterator[_RawProposal]:
        for operation_index, operation in enumerate(operations):
            generator = operation.get("gen")
            if not isinstance(generator, dict) or generator.get("k") != "seq":
                continue
            items = generator.get("items")
            if not isinstance(items, list) or not items:
                continue
            operation_id = _operation_id(path, operation_index, operation)
            leaf_count = _leaf_count(generator)
            canvas = generator.get("lines")
            extent = _rendered_extent(cast(dict[str, JsonValue], generator))
            if (
                leaf_count != len(items)
                or not isinstance(canvas, int)
                or extent is None
                or canvas < extent
            ):
                continue
            removable = 0
            for leaf_index in range(len(items) - 1, -1, -1):
                item = items[leaf_index]
                child = (
                    {key: value for key, value in item.items() if key != "line"}
                    if isinstance(item, dict)
                    else None
                )
                if child is None or not _inert_project_generator(child):
                    break
                removable += 1
                if removable != distance:
                    continue
                changed_operations = deepcopy(list(operations))
                changed_generator = cast(
                    dict[str, object], changed_operations[operation_index]["gen"]
                )
                changed_items = cast(list[object], changed_generator["items"])
                del changed_items[-distance:]
                changed_keys = frozenset(
                    key
                    for key in selected_leaf_keys
                    if key[0] != operation_id or key[1] < leaf_count - distance
                )
                if changed_items:
                    canvas_extent = _rendered_extent(
                        cast(dict[str, JsonValue], {**changed_generator, "lines": 8192})
                    )
                    if canvas_extent is None:
                        continue
                    changed_generator["lines"] = max(1, canvas_extent + canvas - extent)
                elif operation_index == len(operations) - 1:
                    del changed_operations[operation_index]
                else:
                    continue
                yield _RawProposal(
                    changed_operations,
                    changed_keys,
                    (
                        f"removed {distance} inert declaration"
                        + ("s" if distance != 1 else "")
                        + f" from {_operation_label(operation_index, operation)}"
                    ),
                )
                break

    def distance_first(
        factory: Callable[[int], Iterator[_RawProposal]],
    ) -> Iterator[tuple[int, _RawProposal]]:
        for distance in range(1, radius + 1):
            for proposal in factory(distance):
                yield distance, proposal

    addition_family = additions()
    # Reusing this iterator gives additions a 3:1:1 share without a scheduler.
    families = (
        addition_family,
        distance_first(knob_moves),
        addition_family,
        distance_first(removals),
        addition_family,
    )
    active = True
    while active:
        active = False
        for family in families:
            item = next(family, None)
            if item is None:
                continue
            active = True
            distance, proposal = item
            if admit(
                proposal.operations,
                proposal.selected_leaf_keys,
                distance,
                proposal.description,
            ):
                return tuple(candidates)
    return tuple(candidates)


def _with_candidate_output(
    bundle: ProjectBundle,
    intervention: ClassicRecipeIntervention,
    *,
    path: str,
    operations: Sequence[Mapping[str, object]],
    clean_payload: bytes,
    session: ClassicOverlayRenderSession,
) -> tuple[ClassicProjectOverlayEdit, ProjectBundle, bytes]:
    parameters = _parameters(intervention)
    outputs = deepcopy(parameters.get("outputs"))
    if not isinstance(outputs, list):
        raise ClassicProjectOverlayRepairError("source-overlay outputs are malformed")
    matches = [
        item
        for item in outputs
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and cast(str, item["path"]).casefold() == path.casefold()
    ]
    if len(matches) != 1:
        raise ClassicProjectOverlayRepairError("source-overlay output is not uniquely owned")
    output = matches[0]
    output["ops"] = deepcopy(list(operations))
    rendered = render_classic_overlay_proposal([output], {path: clean_payload}, session=session)
    receipt = rendered.receipts[0]
    output["effective"] = receipt.output_digest
    output["size"] = receipt.output_size
    parameters["outputs"] = outputs
    proven_after = ClassicRecipeIntervention.model_validate(
        {
            **intervention.model_dump(mode="python", warnings=False),
            "parameters": tuple(
                ClassicField(name=name, value=value)  # type: ignore[arg-type]
                for name, value in sorted(parameters.items())
            ),
        }
    )
    publication_parameters = _parameters(proven_after)
    publication_outputs = deepcopy(publication_parameters.get("outputs"))
    original_outputs = _parameters(intervention).get("outputs")
    if not isinstance(publication_outputs, list) or not isinstance(original_outputs, list):
        raise ClassicProjectOverlayRepairError("source-overlay outputs are malformed")
    original_by_path = {
        cast(str, item["path"]).casefold(): item
        for item in original_outputs
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    for item in publication_outputs:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ClassicProjectOverlayRepairError("source-overlay output is malformed")
        if cast(str, item["path"]).casefold() != path.casefold():
            continue
        original = original_by_path.get(path.casefold())
        if not isinstance(original, dict):
            raise ClassicProjectOverlayRepairError("source-overlay output is not uniquely owned")
        item["effective"] = original.get("effective")
        if "size" in original:
            item["size"] = original["size"]
        else:
            item.pop("size", None)
    publication_parameters["outputs"] = publication_outputs
    publication_after = ClassicRecipeIntervention.model_validate(
        {
            **proven_after.model_dump(mode="python", warnings=False),
            "parameters": tuple(
                ClassicField(name=name, value=value)  # type: ignore[arg-type]
                for name, value in sorted(publication_parameters.items())
            ),
        }
    )
    edit = ClassicProjectOverlayEdit(intervention, publication_after)
    documents = tuple(
        document.model_copy(
            update={
                "interventions": tuple(
                    proven_after if item == intervention else item
                    for item in document.interventions
                )
            }
        )
        for document in bundle.intervention_documents
    )
    candidate_bundle = bundle.model_copy(update={"intervention_documents": documents})
    return edit, candidate_bundle, rendered.outputs[path]


def _source_pairs_with(
    pairs: Sequence[ProjectOverlaySourcePair], path: str, payload: bytes
) -> tuple[ProjectOverlaySourcePair, ...]:
    changed = tuple(
        ProjectOverlaySourcePair(item.path, item.clean_payload, payload)
        if item.path.casefold() == path.casefold()
        else item
        for item in pairs
    )
    if sum(item.path.casefold() == path.casefold() for item in changed) != 1:
        raise ClassicProjectOverlayRepairError("candidate source pair is not uniquely owned")
    return changed


def _source_epoch_outputs(
    pairs: Sequence[ProjectOverlaySourcePair], generated_tus: frozenset[str]
) -> dict[str, bytes]:
    generated = {path.casefold() for path in generated_tus}
    return {
        item.path: item.effective_payload for item in pairs if item.path.casefold() not in generated
    }


def _candidate_counterfactual_outputs(
    *,
    baseline: ProjectOverlayCompilerEpochPlan,
    intervention: ClassicRecipeIntervention,
    candidate_bundle: ProjectBundle,
    path: str,
    selected_leaf_keys: frozenset[tuple[str, int]],
    clean_inputs: Mapping[str, bytes],
    session: ClassicOverlayRenderSession,
) -> dict[str, bytes]:
    candidate = next(
        item for item in _project_overlays(candidate_bundle) if item.id == intervention.id
    )
    candidate_values = _parameters(candidate)
    candidate_outputs = candidate_values.get("outputs")
    if not isinstance(candidate_outputs, list):
        raise ClassicProjectOverlayRepairError("source-overlay outputs are malformed")
    selected_outputs = [
        item
        for item in candidate_outputs
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and cast(str, item["path"]).casefold() == path.casefold()
    ]
    if len(selected_outputs) != 1:
        raise ClassicProjectOverlayRepairError("source-overlay output is not uniquely owned")
    selected_output = selected_outputs[0]
    operations = selected_output.get("ops")
    if not isinstance(operations, list):
        raise ClassicProjectOverlayRepairError("source-overlay operations are malformed")
    operation_ids = {
        _operation_id(path, index, operation)
        for index, operation in enumerate(operations)
        if isinstance(operation, Mapping)
    }
    document = {
        "schema": candidate_values.get("schema"),
        "outputs": [selected_output],
        "graph": {"generated_tus": [], "link_admissions": []},
    }
    clean_path = next((item for item in clean_inputs if item.casefold() == path.casefold()), None)
    if clean_path is None:
        raise ClassicProjectOverlayRepairError("source-overlay clean input is missing")
    rendered = render_classic_overlay_leaf_subset(
        document,
        {path: clean_inputs[clean_path]},
        frozenset(key for key in selected_leaf_keys if key[0] in operation_ids),
        session=session,
    )
    result = dict(baseline.declaration_outputs)
    if set(rendered.outputs) != {path}:
        raise ClassicProjectOverlayRepairError("candidate counterfactual output changed scope")
    result[path] = rendered.outputs[path]
    return result


def _affected_nodes(
    graph: ProducerGraphDocument,
    plan: ProjectOverlayCompilerEpochPlan,
    path: str,
) -> tuple[str, ...]:
    if (
        plan.reader_closure_fallbacks
        or PurePosixPath(path).suffix.casefold() not in _SOURCE_SUFFIXES
    ):
        return tuple(sorted(plan.audit_node_ids, key=str.casefold))
    source_ref = f"source/{path}".casefold()
    return tuple(
        sorted(
            (
                node.id
                for node in graph.nodes
                if node.role is ProducerRole.COMPILER
                and node.id in plan.audit_node_ids
                and classic_compiler_product_refs(node)[0].casefold() == source_ref
            ),
            key=str.casefold,
        )
    )


def _candidate_plan_reduction(
    baseline: ProjectOverlayCompilerEpochPlan,
    candidate: ProjectOverlayCompilerEpochPlan,
    *,
    baseline_generated_tus: frozenset[str],
    candidate_generated_tus: frozenset[str],
    affected_node_ids: Sequence[str],
    source_path: str,
    effective_outputs: Mapping[str, bytes],
    counterfactual_outputs: Mapping[str, bytes],
) -> frozenset[str] | None:
    """Return the compiler readers safely removed by one settled source view."""

    if (
        candidate_generated_tus != baseline_generated_tus
        or candidate.reader_closure_fallbacks != baseline.reader_closure_fallbacks
        or dict(candidate.declaration_outputs) != dict(counterfactual_outputs)
    ):
        return None
    if (
        candidate.audit_node_ids == baseline.audit_node_ids
        and candidate.runtime_projection_node_ids == baseline.runtime_projection_node_ids
    ):
        return frozenset()
    if not candidate.audit_node_ids.issubset(baseline.audit_node_ids):
        return None
    removed = baseline.audit_node_ids - candidate.audit_node_ids
    if (
        not removed
        or not removed.issubset(affected_node_ids)
        or candidate.runtime_projection_node_ids != baseline.runtime_projection_node_ids - removed
    ):
        return None
    effective = [
        payload
        for path, payload in effective_outputs.items()
        if path.casefold() == source_path.casefold()
    ]
    counterfactual = [
        payload
        for path, payload in counterfactual_outputs.items()
        if path.casefold() == source_path.casefold()
    ]
    if len(effective) != 1 or len(counterfactual) != 1 or effective != counterfactual:
        return None
    return removed


def _validate_pair(
    *,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    node: ProducerNode,
    counterfactual: ClassicCompilerProbeOutput,
    effective: ClassicCompilerProbeOutput,
    namespaces: Mapping[str, _ValidatedCompilerNamespace],
    validation: _OverlaySourceValidation,
) -> _ProjectCompilerEpochPair:
    counterfactual_invocation = counterfactual.compiler_invocation
    effective_invocation = effective.compiler_invocation
    if not isinstance(counterfactual_invocation, CompilerEpochInvocation) or not isinstance(
        effective_invocation,
        CompilerEpochInvocation,
    ):
        raise ClassicSemanticError(f"compiler {node.id!r} lacks invocation evidence")
    clean_object = _parse_coff(counterfactual.object_payload, "source-layout-counterfactual")
    effective_object = _parse_coff(effective.object_payload, "source-layout-effective")
    source_ref, object_ref = classic_compiler_product_refs(node)
    return _validate_project_compiler_epoch_pair(
        bundle=bundle,
        graph=graph,
        node=node,
        audit=ProjectOverlayCounterfactualAudit(
            node.id,
            source_ref,
            object_ref,
            counterfactual.object_payload,
            counterfactual_invocation,
        ),
        effective_invocation=effective_invocation,
        namespaces=namespaces,
        source_validation=validation,
        counterfactual=clean_object,
        effective=effective_object,
    )


def _epoch_compiler_outputs(
    epoch: ClassicCompilerSourceEpochOutput,
) -> dict[str, ClassicCompilerProbeOutput]:
    outputs = {item.node_id: item for item in epoch.compiler_outputs}
    if len(outputs) != len(epoch.compiler_outputs):
        raise ClassicSemanticError("compiler source probe repeats an output node")
    for item in outputs.values():
        invocation = item.compiler_invocation
        if not isinstance(invocation, CompilerEpochInvocation) or (
            invocation.namespace_id != epoch.namespace.namespace_id
        ):
            raise ClassicSemanticError(
                f"compiler {item.node_id!r} belongs to the wrong source epoch"
            )
    return outputs


def _retained_code_is_byte_equal(pair: _ProjectCompilerEpochPair) -> bool:
    """Return whether the shared COFF proof found no retained code delta."""

    changed = pair.coff_trace.get("changed_code_section_count")
    return type(changed) is int and changed == 0


def _link_layout_object_state(
    coff: _CoffObject,
    hint: ClassicLinkLayoutHint,
) -> _LinkLayoutObjectState:
    """Bind the named independent COMDATs without depending on section ordinals."""

    names = hint.desired_symbol_order
    if len(names) < 2 or len(set(names)) != len(names):
        raise ClassicSemanticError("link-layout symbol order is not a unique sequence")
    symbols = _symbols_by_section(coff)
    sections: dict[str, _CoffSection] = {}
    for name in names:
        definitions = tuple(
            symbol
            for symbol in coff.symbols
            if symbol.name == name and symbol.storage == 2 and symbol.section > 0
        )
        if len(definitions) != 1 or definitions[0].value != 0:
            raise ClassicSemanticError(
                f"{coff.label} does not define link-layout symbol {name!r} uniquely "
                "at its section start"
            )
        section = coff.sections[definitions[0].section - 1]
        if (
            section.name.casefold() not in {".data", ".rdata"}
            or section.comdat_selection != 2
            or section.comdat_associated not in {None, 0}
            or section.line_numbers
            or not section.characteristics & 0x00001000
            or not section.characteristics & 0x00000040
            or section.characteristics & (0x00000020 | 0x00000080)
        ):
            raise ClassicSemanticError(
                f"{coff.label} link-layout symbol {name!r} is not an independent COMDAT"
            )
        owners = tuple(
            symbol
            for symbol in symbols.get(section.number, ())
            if symbol.storage == 2 and symbol.value == 0
        )
        if len(owners) != 1 or owners[0].name != name:
            raise ClassicSemanticError(
                f"{coff.label} link-layout symbol {name!r} is not the unique COMDAT owner"
            )
        sections[name] = section
    section_numbers = [sections[name].number for name in names]
    if len(set(section_numbers)) != len(section_numbers):
        raise ClassicSemanticError(f"{coff.label} link-layout symbols do not own distinct sections")
    identities = tuple(
        (name, _section_permutation_identity(coff, sections[name], symbols)) for name in names
    )
    return _LinkLayoutObjectState(
        tuple(sorted(names, key=lambda name: sections[name].number)),
        identities,
    )


def _retained_pair_regressed(
    baseline: _ProjectCompilerEpochPair,
    candidate: _ProjectCompilerEpochPair,
) -> bool:
    """Keep both exact projections and exact retained code from moving backward."""

    return (baseline.projection.byte_equal and not candidate.projection.byte_equal) or (
        _retained_code_is_byte_equal(baseline) and not _retained_code_is_byte_equal(candidate)
    )


def probe_project_overlay_repair(
    probes: ClassicProbeExecution,
    bundle: ProjectBundle,
    *,
    clean_sources: Mapping[str, bytes],
    candidate_budget: int,
    radius: int = DEFAULT_REPAIR_RETUNE_RADIUS,
    candidate_limit: int = DEFAULT_RETUNE_CANDIDATES,
    settle_target_ids: frozenset[str] = frozenset(),
    link_layout_hint: ClassicLinkLayoutHint | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> ClassicProjectOverlayRepairResult:
    """Consume one prepared runtime while checking and repairing source layout."""

    plan = probes.overlay.compiler_epoch_plan
    if not plan.audit_node_ids:
        probes.close()
        return ClassicProjectOverlayRepairResult(False, None, 0)
    secondary = _toolchain_include_reader_payloads(bundle, probes.producer.toolchain_root)
    clean_inputs = tuple(
        CleanSourceInput(path, payload)
        for path, payload in sorted(clean_sources.items(), key=lambda item: item[0].casefold())
    )
    derived_plan, baseline_validation, generated_tus = _derive_project_overlay_compiler_epoch(
        bundle,
        probes.graph,
        probes.overlay.project_source_pairs,
        clean_inputs,
        secondary_reader_payloads=secondary,
    )
    if baseline_validation is None or derived_plan != plan:
        raise ClassicProjectOverlayRepairError("prepared source-overlay plan changed")
    baseline_effective = _source_epoch_outputs(probes.overlay.project_source_pairs, generated_tus)
    baseline_counterfactual = dict(plan.declaration_outputs)
    full_clean_sources = dict(clean_sources)
    by_node = {node.id: node for node in probes.graph.nodes}
    pending: dict[str, ClassicCompilerSourceEpochOutput] = {}
    baseline_failure: list[tuple[str, str]] = []
    baseline_pairs: dict[str, _ProjectCompilerEpochPair] = {}
    link_state_target: list[str] = []
    link_layout_target: list[str] = []
    link_layout_baseline: list[_LinkLayoutObjectState] = []
    candidate_by_id: dict[str, _Candidate] = {}
    candidate_reasons: list[str] = []
    winner: list[ClassicProjectOverlayRepair] = []
    compiled_candidates = 0
    search_truncated = False
    preprocessor_cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] = {}
    identifier_caches: dict[frozenset[str], dict[tuple[Digest, int], frozenset[str]]] = {}

    def validate_epoch_pair(
        first: ClassicCompilerSourceEpochOutput,
        second: ClassicCompilerSourceEpochOutput,
        validation: _OverlaySourceValidation,
        effective_outputs: Mapping[str, bytes],
        counterfactual_outputs: Mapping[str, bytes],
    ) -> tuple[tuple[str, str] | None, dict[str, _ProjectCompilerEpochPair]]:
        effective_source_view = {**full_clean_sources, **effective_outputs}
        counterfactual_source_view = {**full_clean_sources, **counterfactual_outputs}
        identifier_cache = identifier_caches.setdefault(
            validation.global_declaration_identifiers, {}
        )
        namespaces = _validate_compiler_namespaces(
            bundle=bundle,
            evidences=(first.namespace, second.namespace),
            referenced_ids=frozenset({first.namespace.namespace_id, second.namespace.namespace_id}),
            sensitive_identifiers=validation.macro_sensitive_identifiers,
            global_declaration_identifiers=validation.global_declaration_identifiers,
            preprocessor_cache=preprocessor_cache,
            identifier_cache=identifier_cache,
        )
        _require_namespace_source_authority(
            namespaces[first.namespace.namespace_id.casefold()],
            {
                path.casefold(): (path, Digest.from_bytes(payload), len(payload))
                for path, payload in effective_source_view.items()
            },
            epoch="effective",
        )
        _require_namespace_source_authority(
            namespaces[second.namespace.namespace_id.casefold()],
            {
                path.casefold(): (path, Digest.from_bytes(payload), len(payload))
                for path, payload in counterfactual_source_view.items()
            },
            epoch="declaration-counterfactual",
        )
        first_outputs = _epoch_compiler_outputs(first)
        second_outputs = _epoch_compiler_outputs(second)
        if set(first_outputs) != set(second_outputs):
            raise ClassicSemanticError("compiler source probe output universe differs")
        pair_proofs: dict[str, _ProjectCompilerEpochPair] = {}
        first_failure: tuple[str, str] | None = None
        for node_id in sorted(first_outputs, key=str.casefold):
            try:
                pair_proofs[node_id] = _validate_pair(
                    bundle=bundle,
                    graph=probes.graph,
                    node=by_node[node_id],
                    counterfactual=second_outputs[node_id],
                    effective=first_outputs[node_id],
                    namespaces=namespaces,
                    validation=validation,
                )
            except ClassicSemanticError as exc:
                if first_failure is None:
                    first_failure = (node_id, str(exc))
        return first_failure, pair_proofs

    def retain(output: ClassicCompilerSourceEpochOutput) -> bool:
        nonlocal compiled_candidates
        if output.epoch_id.endswith(".effective"):
            pending[output.epoch_id.removesuffix(".effective")] = output
            return False
        key = output.epoch_id.removesuffix(".counterfactual")
        effective = pending.pop(key)
        if key == "baseline":
            failure, pair_proofs = validate_epoch_pair(
                effective,
                output,
                baseline_validation,
                baseline_effective,
                baseline_counterfactual,
            )
            baseline_pairs.update(pair_proofs)
            if failure is not None:
                baseline_failure.append(failure)
            elif link_layout_hint is not None:
                node_id = link_layout_hint.compiler_node_id
                pair = pair_proofs.get(node_id)
                if pair is None:
                    raise ClassicProjectOverlayRepairError(
                        "the link-layout hint is outside the audited source plan"
                    )
                try:
                    layout = _link_layout_object_state(pair.effective, link_layout_hint)
                except ClassicSemanticError as exc:
                    raise ClassicProjectOverlayRepairError(
                        f"the link-layout hint no longer matches its compiler output: {exc}"
                    ) from exc
                link_layout_baseline.append(layout)
                if layout.order != link_layout_hint.desired_symbol_order:
                    link_layout_target.append(node_id)
            if failure is None and settle_target_ids and not link_layout_target:
                terminal_targets = compiler_terminal_consumer_targets(probes.graph)
                for node_id in sorted(
                    plan.runtime_projection_node_ids,
                    key=str.casefold,
                ):
                    pair = pair_proofs[node_id]
                    if (
                        terminal_targets.get(node_id, frozenset()) & settle_target_ids
                        and pair.decision.proven
                        and not _retained_code_is_byte_equal(pair)
                        and (pair.crt_pull_dependencies or pair.ordered_archive_seed_dependencies)
                    ):
                        link_state_target.append(node_id)
                        break
            return False
        candidate = candidate_by_id.pop(key)
        compiled_candidates += 1
        if progress is not None:
            progress(
                compiled_candidates,
                candidate_budget,
                f"{candidate.source_path}: {candidate.raw.description}",
            )
        failure, initial_pairs = validate_epoch_pair(
            effective,
            output,
            baseline_validation,
            candidate.effective_outputs,
            candidate.counterfactual_outputs,
        )
        if failure is not None:
            candidate_reasons.append(failure[1])
            return False
        if link_layout_target:
            assert link_layout_hint is not None and link_layout_baseline
            target_pair = initial_pairs.get(link_layout_target[0])
            if target_pair is None:
                candidate_reasons.append("the target compiler was not checked")
                return False
            try:
                layout = _link_layout_object_state(target_pair.effective, link_layout_hint)
            except ClassicSemanticError as exc:
                candidate_reasons.append(str(exc))
                return False
            if layout.identities != link_layout_baseline[0].identities:
                candidate_reasons.append("the target compiler data changed")
                return False
            if layout.order != link_layout_hint.desired_symbol_order:
                candidate_reasons.append("the target compiler data order did not settle")
                return False
        if link_state_target:
            target_pair = initial_pairs.get(link_state_target[0])
            if target_pair is None or not _retained_code_is_byte_equal(target_pair):
                candidate_reasons.append("the retained compiler code did not settle")
                return False
        try:
            candidate_plan, candidate_validation, candidate_generated = (
                _derive_project_overlay_compiler_epoch(
                    candidate.bundle,
                    probes.graph,
                    candidate.source_pairs,
                    clean_inputs,
                    secondary_reader_payloads=secondary,
                )
            )
        except (ClassicSemanticError, ValueError) as exc:
            candidate_reasons.append(str(exc))
            return False
        if candidate_validation is None:
            candidate_reasons.append("full source plan changed outside the probed layout")
            return False
        removed_node_ids = _candidate_plan_reduction(
            plan,
            candidate_plan,
            baseline_generated_tus=generated_tus,
            candidate_generated_tus=candidate_generated,
            affected_node_ids=candidate.affected_node_ids,
            source_path=candidate.source_path,
            effective_outputs=candidate.effective_outputs,
            counterfactual_outputs=candidate.counterfactual_outputs,
        )
        if removed_node_ids is None:
            candidate_reasons.append("full source plan changed outside the probed layout")
            return False
        failure, candidate_pairs = validate_epoch_pair(
            effective,
            output,
            candidate_validation,
            candidate.effective_outputs,
            candidate.counterfactual_outputs,
        )
        if failure is not None:
            candidate_reasons.append(failure[1])
            return False
        if any(
            node_id not in candidate_pairs or not candidate_pairs[node_id].projection.byte_equal
            for node_id in removed_node_ids
        ):
            candidate_reasons.append("the removed compiler projection did not settle")
            return False
        if link_state_target:
            target_pair = candidate_pairs.get(link_state_target[0])
            if target_pair is None or not _retained_code_is_byte_equal(target_pair):
                candidate_reasons.append("the retained compiler code did not settle")
                return False
        if link_state_target or link_layout_target:
            regressed = sorted(
                (
                    node_id
                    for node_id, pair in candidate_pairs.items()
                    if node_id in plan.runtime_projection_node_ids
                    and _retained_pair_regressed(baseline_pairs[node_id], pair)
                ),
                key=str.casefold,
            )
            if regressed:
                candidate_reasons.append(
                    "the source layout unsettled an existing compiler projection"
                )
                return False
        elif baseline_failure:
            target_id = baseline_failure[0][0]
            if target_id in plan.runtime_projection_node_ids:
                target_pair = candidate_pairs.get(target_id)
                if target_pair is None or not target_pair.projection.equivalent:
                    candidate_reasons.append("the retained compiler projection remains unsettled")
                    return False
            regressed = sorted(
                (
                    node_id
                    for node_id, pair in candidate_pairs.items()
                    if node_id in plan.runtime_projection_node_ids
                    and node_id in baseline_pairs
                    and baseline_pairs[node_id].projection.equivalent
                    and not pair.projection.equivalent
                ),
                key=str.casefold,
            )
            if regressed:
                candidate_reasons.append(
                    "the source layout unsettled an existing compiler projection"
                )
                return False
        repair = ClassicProjectOverlayRepair(
            candidate.edit,
            candidate.source_path,
            candidate.affected_node_ids,
            candidate.raw.distance,
            candidate.raw.description,
        )
        # This is a private search step, not a publication decision.  The typed
        # edit admits only inert declaration/layout changes, both source views
        # have passed the shared compiler proof for every affected reader, and
        # the full planner independently reproduced the candidate.  Accept the
        # first such state so the ordinary repair/census loop can settle any
        # downstream compiler fallout; the outer transaction still publishes
        # nothing unless the final cold build verifies every target exactly.
        winner.append(repair)
        return True

    def epochs() -> Iterable[ClassicCompilerSourceEpoch]:
        nonlocal search_truncated
        yield ClassicCompilerSourceEpoch(
            "baseline.effective",
            tuple(sorted(plan.audit_node_ids, key=str.casefold)),
            baseline_effective,
        )
        yield ClassicCompilerSourceEpoch(
            "baseline.counterfactual",
            tuple(sorted(plan.audit_node_ids, key=str.casefold)),
            baseline_counterfactual,
        )
        if (
            not baseline_failure and not link_state_target and not link_layout_target
        ) or candidate_budget <= 0:
            return
        failed_node_id = (
            baseline_failure[0][0]
            if baseline_failure
            else (link_layout_target or link_state_target)[0]
        )
        failed_node = by_node[failed_node_id]
        failed_source = classic_compiler_product_refs(failed_node)[0].removeprefix("source/")
        terminal_targets = compiler_terminal_consumer_targets(probes.graph).get(
            failed_node.id, frozenset()
        )
        pair_by_path = {item.path.casefold(): item for item in probes.overlay.project_source_pairs}
        overlay_values = [_parameters(item).get("outputs") for item in _project_overlays(bundle)]
        identifiers = _identifier_census(
            (
                *clean_sources.values(),
                *(item.effective_payload for item in probes.overlay.project_source_pairs),
                *secondary.values(),
            ),
            overlay_values,
        )
        reusable_identifiers = _identifier_census(
            plan.declaration_outputs.values(), ()
        ) - _identifier_census((*clean_sources.values(), *secondary.values()), ())
        owners: list[
            tuple[
                int,
                str,
                ClassicRecipeIntervention,
                dict[str, object],
            ]
        ] = []
        for intervention in _project_overlays(bundle):
            outputs = _parameters(intervention).get("outputs")
            if not isinstance(outputs, list):
                continue
            for output in outputs:
                if not isinstance(output, dict) or not isinstance(output.get("path"), str):
                    continue
                path = cast(str, output["path"])
                suffix = PurePosixPath(path).suffix.casefold()
                if path.casefold() == failed_source.casefold():
                    rank = 0
                elif suffix in _HEADER_SUFFIXES:
                    rank = 1 if intervention.scope.target in terminal_targets else 2
                elif plan.reader_closure_fallbacks:
                    rank = 3
                else:
                    continue
                clean_pair = pair_by_path.get(path.casefold())
                if clean_pair is None or clean_pair.clean_payload is None:
                    continue
                owners.append((rank, path, intervention, output))
        if not owners:
            candidate_reasons.append("the failing compiler has no retunable overlay reader")
            return
        overlay_clean_inputs = {
            item.path: item.clean_payload
            for item in probes.overlay.project_source_pairs
            if item.clean_payload is not None
        }
        ordinal = 0
        found_work = False
        for tier_rank in sorted({item[0] for item in owners}):
            remaining = candidate_budget - compiled_candidates
            if remaining <= 0:
                return
            tier_owners = sorted(
                (item for item in owners if item[0] == tier_rank),
                key=lambda item: item[1].casefold(),
            )
            raw_work: list[
                tuple[
                    int,
                    int,
                    str,
                    ClassicRecipeIntervention,
                    dict[str, object],
                    _RawCandidate,
                ]
            ] = []
            for rank, path, intervention, output in tier_owners:
                operations = output.get("ops")
                if not isinstance(operations, list) or any(
                    not isinstance(item, Mapping) for item in operations
                ):
                    continue
                try:
                    owner_limit = min(candidate_limit, remaining)
                    raw_candidates = _raw_candidates(
                        path=path,
                        operations=cast(Sequence[Mapping[str, object]], operations),
                        selected_leaf_keys=frozenset(
                            plan.declaration_leaf_keys.get(intervention.id, ())
                        ),
                        identifiers=identifiers,
                        reusable_identifiers=reusable_identifiers,
                        radius=radius,
                        limit=owner_limit + 1,
                    )
                except (ClassicProjectOverlayRepairError, ValueError) as exc:
                    candidate_reasons.append(str(exc))
                    continue
                if len(raw_candidates) > owner_limit:
                    search_truncated = True
                    raw_candidates = raw_candidates[:owner_limit]
                raw_work.extend(
                    (rank, local_rank, path, intervention, output, raw)
                    for local_rank, raw in enumerate(raw_candidates)
                )
            raw_work.sort(
                key=lambda item: (
                    item[1],
                    item[2].casefold(),
                    item[5].description,
                    canonical_json(item[5].operations),
                )
            )
            found_work = found_work or bool(raw_work)
            for _rank, _local_rank, path, intervention, _output, raw in raw_work:
                if compiled_candidates >= candidate_budget:
                    search_truncated = True
                    return
                clean_pair = pair_by_path[path.casefold()]
                assert clean_pair.clean_payload is not None
                try:
                    edit, candidate_bundle, payload = _with_candidate_output(
                        bundle,
                        intervention,
                        path=path,
                        operations=raw.operations,
                        clean_payload=clean_pair.clean_payload,
                        session=render_session,
                    )
                    source_pairs = _source_pairs_with(
                        probes.overlay.project_source_pairs,
                        path,
                        payload,
                    )
                    effective_outputs = _source_epoch_outputs(source_pairs, generated_tus)
                    counterfactual_outputs = _candidate_counterfactual_outputs(
                        baseline=plan,
                        intervention=intervention,
                        candidate_bundle=candidate_bundle,
                        path=path,
                        selected_leaf_keys=raw.selected_leaf_keys,
                        clean_inputs=cast(Mapping[str, bytes], overlay_clean_inputs),
                        session=render_session,
                    )
                except (
                    ClassicProjectOverlayRepairError,
                    ClassicSemanticError,
                    ValueError,
                    KeyError,
                ) as exc:
                    candidate_reasons.append(str(exc))
                    continue
                affected = _affected_nodes(probes.graph, plan, path)
                if not affected:
                    candidate_reasons.append("the changed source has no audited compiler reader")
                    continue
                key = f"candidate.{ordinal:04d}"
                ordinal += 1
                candidate_by_id[key] = _Candidate(
                    raw,
                    edit,
                    candidate_bundle,
                    source_pairs,
                    effective_outputs,
                    counterfactual_outputs,
                    affected,
                    path,
                )
                yield ClassicCompilerSourceEpoch(f"{key}.effective", affected, effective_outputs)
                yield ClassicCompilerSourceEpoch(
                    f"{key}.counterfactual", affected, counterfactual_outputs
                )
        if not found_work:
            candidate_reasons.append("no nearby inert source layout is available")

    with ClassicOverlayRenderSession() as render_session:
        probes.probe_compiler_source_epochs(epochs(), retain=retain)
    if winner:
        repair = winner[0]
        return ClassicProjectOverlayRepairResult(
            True,
            repair,
            compiled_candidates,
            repair.source_path,
        )
    if not baseline_failure and not link_state_target and not link_layout_target:
        return ClassicProjectOverlayRepairResult(True, None, compiled_candidates)
    unresolved_node_id = (
        baseline_failure[0][0] if baseline_failure else (link_layout_target or link_state_target)[0]
    )
    source_path = classic_compiler_product_refs(by_node[unresolved_node_id])[0].removeprefix(
        "source/"
    )
    exhausted = candidate_budget <= 0 or compiled_candidates >= candidate_budget
    if exhausted:
        tested = f"tested {compiled_candidates} nearby source layouts"
        reason = tested + "; the --candidate-limit was reached"
    elif search_truncated:
        reason = (
            f"tested {compiled_candidates} nearby source layouts; "
            "the --retune-candidates limit was reached"
        )
    elif compiled_candidates == 0 and candidate_reasons:
        first_reason = next(iter(dict.fromkeys(candidate_reasons)))
        reason = f"no nearby source layout could be prepared safely: {first_reason}"
    elif link_state_target or link_layout_target:
        reason = (
            f"tested {compiled_candidates} nearby source layouts; "
            "none settled the remaining link layout"
        )
    else:
        reason = (
            f"tested {compiled_candidates} nearby source layouts; "
            "none fixed the source-view mismatch without changing the program"
        )
    return ClassicProjectOverlayRepairResult(
        True,
        None,
        compiled_candidates,
        source_path,
        reason,
        exhausted,
    )


__all__ = [
    "ClassicProjectOverlayRepair",
    "ClassicProjectOverlayRepairError",
    "ClassicProjectOverlayRepairResult",
    "probe_project_overlay_repair",
]
