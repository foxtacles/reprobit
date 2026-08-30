"""Parsing, applying, and receipt publication for classic overlay documents."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath

from reprobit.artifacts import digest_bytes
from reprobit.classic.overlay_types import (
    ClassicOverlayAnchorReceipt,
    ClassicOverlayOperationReceipt,
    ClassicOverlayOutputReceipt,
    ClassicOverlayRenderResult,
    _Operation,
    _Output,
    _ResolvedOperation,
    _ValidatedOverlay,
)
from reprobit.classic_overlay_generator import _render_generator
from reprobit.classic_overlay_relocation import (
    _relocation_spec,
    _RelocationSpec,
    _require_relocation_pin,
)
from reprobit.classic_overlay_tokens import (
    ClassicOverlayRenderSession,
    _anchor,
    _anchor_resolver,
    _resolve_anchor,
)
from reprobit.classic_overlay_validation import (
    _COMPILE_SUFFIXES,
    _TARGET_RE,
    _array,
    _digest,
    _fail,
    _identifier,
    _integer,
    _keys,
    _object,
    _operation_id,
    _relative_path,
)


def _validate_generator_owner(generator: Mapping[str, object], path: str, context: str) -> None:
    kind = generator.get("k")
    if (
        kind in {"template_supplier", "call_supplier", "reloc_ring", "record_header", "const_pool"}
        and generator.get("logical_path") != path
    ):
        _fail(f"{context}.logical_path differs from its output owner")
    if kind == "seq":
        for index, raw in enumerate(
            _array(generator.get("items"), f"{context}.items", minimum=1, maximum=100_000)
        ):
            item = _object(raw, f"{context}.items[{index}]")
            child = dict(item)
            child.pop("line", None)
            if child.get("k") != "fwd_run":
                _validate_generator_owner(child, path, f"{context}.items[{index}]")


def _parse_operation(
    raw: object,
    *,
    path: str,
    index: int,
) -> _Operation:
    context = f"overlay output {path!r} operation[{index}]"
    value = _object(raw, context)
    action = value.get("op")
    fallback = f"{path}#{index}"
    operation_id = _operation_id(value.get("id"), f"{context}.id", fallback)
    if action == "insert":
        _keys(value, {"op", "anchor", "gen"}, context, optional={"id"})
        start = _anchor(value.get("anchor"), f"{context}.anchor")
        generator = _object(value.get("gen"), f"{context}.gen")
        _render_generator(
            generator,
            f"{context}.gen",
            allow_unresolved_relocation=True,
        )
        _validate_generator_owner(generator, path, f"{context}.gen")
        return _Operation(operation_id, "insert", generator, start=start)
    if action in {"replace", "delete"}:
        _keys(value, {"op", "from", "to", "removed", "gen"}, context, optional={"id"})
        removed = _object(value.get("removed"), f"{context}.removed")
        _keys(removed, {"sha256", "size"}, f"{context}.removed")
        generator = _object(value.get("gen"), f"{context}.gen")
        _render_generator(
            generator,
            f"{context}.gen",
            allow_unresolved_relocation=True,
        )
        _validate_generator_owner(generator, path, f"{context}.gen")
        return _Operation(
            operation_id,
            action,
            generator,
            start=_anchor(value.get("from"), f"{context}.from"),
            end=_anchor(value.get("to"), f"{context}.to"),
            removed_digest=_digest(removed.get("sha256"), f"{context}.removed.sha256"),
            removed_size=_integer(
                removed.get("size"),
                f"{context}.removed.size",
                minimum=0,
                maximum=64 * 1024 * 1024,
            ),
        )
    if action == "append":
        _keys(value, {"op", "gen"}, context, optional={"id"})
        generator = _object(value.get("gen"), f"{context}.gen")
        _render_generator(
            generator,
            f"{context}.gen",
            allow_unresolved_relocation=True,
        )
        _validate_generator_owner(generator, path, f"{context}.gen")
        return _Operation(operation_id, "append", generator)
    _fail(f"{context}.op is unsupported")


def _validate_relocation_closure(outputs: Sequence[_Output]) -> None:
    producers: dict[tuple[str, str], _RelocationSpec] = {}
    consumers: dict[tuple[str, str], list[_RelocationSpec]] = defaultdict(list)
    for output in outputs:
        for operation in output.operations:
            if operation.generator.get("k") != "reloc":
                continue
            context = (
                f"overlay output {output.path!r} operation {operation.operation_id!r} relocation"
            )
            spec = _relocation_spec(operation.generator, context)
            key = (spec.source_operation_id, spec.range_dependency_id)
            if operation.action == "delete":
                if (
                    operation.operation_id != spec.source_operation_id
                    or output.path != spec.ordinary_owner
                    or operation.removed_digest != spec.baseline_digest
                    or operation.removed_size != spec.baseline_size
                ):
                    _fail(f"{context} producer identity differs")
                if key in producers:
                    _fail(f"{context} producer dependency is duplicated")
                producers[key] = spec
            else:
                if operation.action != "insert" or output.path != spec.byte_destination:
                    _fail(f"{context} consumer must be an insert on its byte destination")
                consumers[key].append(spec)
    if set(producers) != set(consumers):
        _fail("source relocation producer/consumer dependency universe differs")
    for key, producer in producers.items():
        matches = consumers[key]
        if len(matches) != 1 or matches[0] != producer:
            _fail(f"source relocation producer/consumer closure differs: {key}")


def _parse_declarations(
    declarations: object,
    *,
    require_sizes: bool,
) -> tuple[_Output, ...]:
    raw_outputs = _array(declarations, "overlay.outputs", minimum=1, maximum=2000)
    outputs: list[_Output] = []
    paths: set[str] = set()
    folded: dict[str, str] = {}
    operation_ids: set[str] = set()
    operation_keys: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_outputs):
        context = f"overlay.outputs[{index}]"
        value = _object(raw, context)
        required = {"path", "effective", "ops"} | ({"size"} if require_sizes else set())
        optional = {"clean"} | (set() if require_sizes else {"size"})
        _keys(value, required, context, optional=optional)
        path = _relative_path(value.get("path"), f"{context}.path")
        if path in paths:
            _fail(f"overlay path is duplicated: {path}")
        prior = folded.get(path.casefold())
        if prior is not None:
            _fail(f"overlay path has a casefold collision: {prior} / {path}")
        paths.add(path)
        folded[path.casefold()] = path
        clean_digest = _digest(value.get("clean"), f"{context}.clean") if "clean" in value else None
        operations = tuple(
            _parse_operation(operation, path=path, index=operation_index)
            for operation_index, operation in enumerate(
                _array(value.get("ops"), f"{context}.ops", minimum=1, maximum=100_000)
            )
        )
        for operation in operations:
            operation_key = (path, operation.operation_id)
            if operation_key in operation_keys or (
                require_sizes and operation.operation_id in operation_ids
            ):
                _fail(f"overlay operation id is duplicated: {operation.operation_id}")
            operation_keys.add(operation_key)
            operation_ids.add(operation.operation_id)
        if clean_digest is None:
            if any(operation.action != "append" for operation in operations):
                _fail(f"generated-only output {path} contains a non-append operation")
        elif require_sizes and any(operation.action == "append" for operation in operations):
            _fail(f"present clean output {path} contains a whole-file append")
        size = None
        if "size" in value:
            size = _integer(
                value.get("size"), f"{context}.size", minimum=0, maximum=64 * 1024 * 1024
            )
        outputs.append(
            _Output(
                path,
                clean_digest,
                _digest(value.get("effective"), f"{context}.effective"),
                size,
                operations,
            )
        )
    if require_sizes and [output.path for output in outputs] != sorted(paths):
        _fail("overlay outputs must be sorted by canonical path")
    outputs.sort(key=lambda output: output.path)
    _validate_relocation_closure(outputs)
    return tuple(outputs)


def _validate_graph(value: object, outputs: tuple[_Output, ...]) -> tuple[str, ...]:
    context = "overlay.graph"
    graph = _object(value, context)
    _keys(graph, {"generated_tus", "link_admissions"}, context)
    output_by_path = {output.path: output for output in outputs}
    raw_units = _array(graph.get("generated_tus"), f"{context}.generated_tus", maximum=2000)
    units: list[tuple[int, str, str, str | None]] = []
    unit_paths: set[str] = set()
    ordinals: set[int] = set()
    for index, raw in enumerate(raw_units):
        item_context = f"{context}.generated_tus[{index}]"
        item = _object(raw, item_context)
        _keys(item, {"path", "ordinal", "after"}, item_context, optional={"before"})
        path = _relative_path(item.get("path"), f"{item_context}.path")
        after = _relative_path(item.get("after"), f"{item_context}.after")
        before = (
            _relative_path(item.get("before"), f"{item_context}.before")
            if "before" in item
            else None
        )
        ordinal = _integer(
            item.get("ordinal"), f"{item_context}.ordinal", minimum=1, maximum=100_000
        )
        output = output_by_path.get(path)
        if (
            output is None
            or output.clean_digest is not None
            or PurePosixPath(path).suffix.casefold() not in _COMPILE_SUFFIXES
        ):
            _fail(f"{item_context} does not own a generated-only translation unit")
        if path in unit_paths or ordinal in ordinals:
            _fail(f"{item_context} duplicates a path or ordinal")
        if path == after or (before is not None and (path == before or after == before)):
            _fail(f"{item_context} has invalid neighbor anchors")
        unit_paths.add(path)
        ordinals.add(ordinal)
        units.append((ordinal, path, after, before))
    if units != sorted(units):
        _fail(f"{context}.generated_tus must be sorted by ordinal")
    tails = [unit for unit in units if unit[3] is None]
    if units and (len(tails) != 1 or tails[0] != units[-1]):
        _fail(f"{context}.generated_tus lacks one final unbounded seat")
    expected_generated = {
        output.path
        for output in outputs
        if output.clean_digest is None
        and PurePosixPath(output.path).suffix.casefold() in _COMPILE_SUFFIXES
    }
    if unit_paths != expected_generated:
        _fail(f"{context}.generated_tus does not own the generated TU universe")

    operation_ids = {
        operation.operation_id for output in outputs for operation in output.operations
    }
    for index, raw in enumerate(
        _array(graph.get("link_admissions"), f"{context}.link_admissions", maximum=1024)
    ):
        item_context = f"{context}.link_admissions[{index}]"
        item = _object(raw, item_context)
        _keys(
            item,
            {
                "admission_id",
                "target",
                "visibility",
                "library",
                "insert_after",
                "insert_before",
                "source_output",
                "required_operation_ids",
            },
            item_context,
        )
        _identifier(item.get("admission_id"), f"{item_context}.admission_id")
        target = item.get("target")
        if not isinstance(target, str) or _TARGET_RE.fullmatch(target) is None:
            _fail(f"{item_context}.target is invalid")
        if item.get("visibility") not in {"PRIVATE", "PUBLIC", "INTERFACE"}:
            _fail(f"{item_context}.visibility differs")
        for field in ("library", "insert_after", "insert_before"):
            token = item.get(field)
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 256
                or any(character in token for character in "\0\r\n;\"'")
            ):
                _fail(f"{item_context}.{field} is unsafe")
        source_output = _relative_path(item.get("source_output"), f"{item_context}.source_output")
        if source_output not in output_by_path:
            _fail(f"{item_context}.source_output is not an overlay output")
        required_ids = [
            _operation_id(raw_id, f"{item_context}.required_operation_ids[{required_index}]", "")
            for required_index, raw_id in enumerate(
                _array(
                    item.get("required_operation_ids"),
                    f"{item_context}.required_operation_ids",
                    minimum=1,
                    maximum=1024,
                )
            )
        ]
        if len(set(required_ids)) != len(required_ids) or not set(required_ids) <= operation_ids:
            _fail(f"{item_context}.required_operation_ids are duplicated or unknown")
    return tuple(unit[1] for unit in units)


def _parse_document(value: object) -> _ValidatedOverlay:
    document = _object(value, "overlay")
    _keys(document, {"schema", "outputs", "graph"}, "overlay")
    if _integer(document.get("schema"), "overlay.schema", minimum=2, maximum=2) != 2:
        _fail("overlay.schema differs")
    outputs = _parse_declarations(document.get("outputs"), require_sizes=True)
    generated = _validate_graph(document.get("graph"), outputs)
    return _ValidatedOverlay(outputs, generated)


def validate_classic_overlay(
    document: Mapping[str, object],
) -> None:
    """Validate a complete generic schema-v2 overlay document fail-closed."""

    _parse_document(document)


def _apply_edits(data: bytes, operations: Sequence[_ResolvedOperation], context: str) -> bytes:
    grouped: dict[tuple[int, int], list[_ResolvedOperation]] = defaultdict(list)
    for operation in operations:
        if not 0 <= operation.start <= operation.end <= len(data):
            _fail(f"{context} edit range is invalid: {operation.operation.operation_id}")
        grouped[(operation.start, operation.end)].append(operation)
    ranges = sorted(grouped)
    previous_end = -1
    for start, end in ranges:
        if start < previous_end:
            _fail(f"{context} edits overlap at byte {start}")
        if end > start:
            if len(grouped[(start, end)]) != 1:
                _fail(f"{context} replacement range is duplicated")
            previous_end = end
        else:
            previous_end = max(previous_end, start)
    result = data
    for start, end in sorted(ranges, reverse=True):
        payload = b"".join(
            operation.payload
            for operation in sorted(grouped[(start, end)], key=lambda item: item.ordinal)
        )
        result = result[:start] + payload + result[end:]
    return result


def _validate_clean_inputs(
    outputs: tuple[_Output, ...], clean_inputs: Mapping[str, bytes]
) -> dict[str, bytes]:
    expected = {output.path for output in outputs if output.clean_digest is not None}
    actual: set[str] = set()
    folded: dict[str, str] = {}
    result: dict[str, bytes] = {}
    for raw_path, raw_data in clean_inputs.items():
        path = _relative_path(raw_path, "clean_inputs path")
        prior = folded.get(path.casefold())
        if prior is not None:
            _fail(f"clean_inputs has a casefold collision: {prior} / {path}")
        if type(raw_data) is not bytes:
            _fail(f"clean_inputs[{path!r}] must be immutable bytes")
        folded[path.casefold()] = path
        actual.add(path)
        result[path] = raw_data
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"clean_inputs path universe differs: missing={missing}, extra={extra}")
    return result


def _render_outputs(
    outputs: tuple[_Output, ...],
    clean_inputs: Mapping[str, bytes],
    *,
    session: ClassicOverlayRenderSession,
    verify_output_identity: bool = True,
) -> ClassicOverlayRenderResult:
    clean = _validate_clean_inputs(outputs, clean_inputs)
    for output in outputs:
        base = clean.get(output.path, b"")
        if output.clean_digest is not None and digest_bytes(base) != output.clean_digest:
            _fail(f"clean source overlay input differs from its pin: {output.path}")

    resolvers = {
        output.path: _anchor_resolver(clean.get(output.path, b""), output, session)
        for output in outputs
    }

    relocation_ranges: dict[tuple[str, str], bytes] = {}
    for output in outputs:
        base = clean.get(output.path, b"")
        resolver = resolvers[output.path]
        for operation in output.operations:
            if operation.action != "delete" or operation.generator.get("k") != "reloc":
                continue
            context = f"overlay output {output.path!r} operation {operation.operation_id!r}"
            if operation.start is None or operation.end is None:
                _fail(f"{context} relocation producer lacks its range anchors")
            if resolver is None:
                _fail(f"{context} relocation producer lacks an anchor resolver")
            start, _ = _resolve_anchor(
                resolver, operation.start, f"{context} start anchor", "start"
            )
            end, _ = _resolve_anchor(resolver, operation.end, f"{context} end anchor", "end")
            if end <= start:
                _fail(f"{context} relocation producer range is empty or reversed")
            held_range = base[start:end]
            if (
                len(held_range) != operation.removed_size
                or digest_bytes(held_range) != operation.removed_digest
            ):
                _fail(f"{context} removed range differs from its byte pin")
            spec = _relocation_spec(operation.generator, f"{context} generator")
            _require_relocation_pin(held_range, spec, f"{context} held source range")
            key = (spec.source_operation_id, spec.range_dependency_id)
            if key in relocation_ranges:
                _fail(f"{context} relocation dependency is duplicated")
            relocation_ranges[key] = held_range

    rendered_outputs: dict[str, bytes] = {}
    output_receipts: list[ClassicOverlayOutputReceipt] = []
    for output in outputs:
        base = clean.get(output.path, b"")
        resolver = resolvers[output.path]
        resolved: list[_ResolvedOperation] = []
        for ordinal, operation in enumerate(output.operations):
            context = f"overlay output {output.path!r} operation {operation.operation_id!r}"
            anchors: list[ClassicOverlayAnchorReceipt] = []
            if operation.action == "append":
                start = end = len(base)
            else:
                if operation.start is None:
                    _fail(f"{context} lacks a start anchor")
                if resolver is None:
                    _fail(f"{context} lacks an anchor resolver")
                start, start_receipt = _resolve_anchor(
                    resolver, operation.start, f"{context} start anchor", "start"
                )
                anchors.append(start_receipt)
                if operation.action == "insert":
                    end = start
                else:
                    if operation.end is None:
                        _fail(f"{context} lacks an end anchor")
                    end, end_receipt = _resolve_anchor(
                        resolver, operation.end, f"{context} end anchor", "end"
                    )
                    anchors.append(end_receipt)
            if end < start:
                _fail(f"{context} range is reversed")
            removed: bytes | None = None
            if operation.action in {"replace", "delete"}:
                removed = base[start:end]
                if (
                    len(removed) != operation.removed_size
                    or digest_bytes(removed) != operation.removed_digest
                ):
                    _fail(f"{context} removed range differs from its byte pin")
            if operation.action == "delete" and operation.generator.get("k") == "reloc":
                if removed is None:
                    _fail(f"{context} relocation producer has no held source range")
                fragment = removed
            else:
                fragment = _render_generator(
                    operation.generator,
                    f"{context} generator",
                    relocation_ranges=relocation_ranges,
                )
            if operation.action == "delete":
                if fragment and operation.generator.get("k") != "reloc":
                    _fail(f"{context} delete generator rendered a payload")
                payload = b""
            else:
                payload = fragment
            resolved.append(
                _ResolvedOperation(
                    ordinal,
                    operation,
                    start,
                    end,
                    fragment,
                    payload,
                    tuple(anchors),
                    removed,
                )
            )
        if output.clean_digest is None:
            effective = b"".join(
                operation.payload for operation in sorted(resolved, key=lambda item: item.ordinal)
            )
        else:
            effective = _apply_edits(base, resolved, f"overlay output {output.path!r}")
        effective_digest = digest_bytes(effective)
        if (
            verify_output_identity
            and output.effective_size is not None
            and len(effective) != output.effective_size
        ):
            _fail(
                f"source overlay output size differs for {output.path}: "
                f"expected {output.effective_size}, got {len(effective)}"
            )
        if verify_output_identity and effective_digest != output.effective_digest:
            _fail(f"source overlay output digest differs from its pin: {output.path}")
        operation_receipts = tuple(
            ClassicOverlayOperationReceipt(
                item.operation.operation_id,
                item.operation.action,
                digest_bytes(item.fragment),
                len(item.fragment),
                item.anchors,
                digest_bytes(item.removed) if item.removed is not None else None,
                len(item.removed) if item.removed is not None else None,
            )
            for item in sorted(resolved, key=lambda item: item.ordinal)
        )
        rendered_outputs[output.path] = effective
        output_receipts.append(
            ClassicOverlayOutputReceipt(
                output.path,
                digest_bytes(base) if output.clean_digest is not None else None,
                len(base) if output.clean_digest is not None else None,
                effective_digest,
                len(effective),
                operation_receipts,
            )
        )
    return ClassicOverlayRenderResult(rendered_outputs, tuple(output_receipts))


def render_classic_overlay_declarations(
    declarations: Sequence[Mapping[str, object]],
    clean_inputs: Mapping[str, bytes],
    *,
    session: ClassicOverlayRenderSession | None = None,
) -> ClassicOverlayRenderResult:
    """Render a declaration list without graph policy.

    This is the shared seam for canonical overlays and donor-private overlay
    renderings.  A declaration is ``{path, clean?, effective, size?, ops}``.
    ``size`` is mandatory in complete schema-v2 documents, but may be absent
    in donor proof records whose expected digest already binds the full byte
    string.
    """

    outputs = _parse_declarations(list(declarations), require_sizes=False)
    if session is None:
        with ClassicOverlayRenderSession() as invocation:
            return _render_outputs(outputs, clean_inputs, session=invocation)
    return _render_outputs(outputs, clean_inputs, session=session)


def render_classic_overlay(
    document: Mapping[str, object],
    clean_inputs: Mapping[str, bytes],
    *,
    session: ClassicOverlayRenderSession | None = None,
) -> ClassicOverlayRenderResult:
    """Validate and render one complete generic schema-v2 overlay document."""

    validated = _parse_document(document)
    if session is None:
        with ClassicOverlayRenderSession() as invocation:
            return _render_outputs(validated.outputs, clean_inputs, session=invocation)
    return _render_outputs(validated.outputs, clean_inputs, session=session)


def render_classic_overlay_subset(
    document: Mapping[str, object],
    clean_inputs: Mapping[str, bytes],
    operation_ids: frozenset[str],
    *,
    session: ClassicOverlayRenderSession | None = None,
) -> ClassicOverlayRenderResult:
    """Render a validated operation subset against the immutable clean inputs.

    The complete document is validated first, including its pinned full output
    identities and graph policy.  The returned identities are freshly computed
    for the selected counterfactual and are intentionally not compared with the
    full-output pins.  This narrow seam lets semantic validators hold one class
    of already-proved source operations constant while auditing another class;
    it is not a general unpinned overlay renderer.
    """

    if not isinstance(operation_ids, frozenset) or any(
        not isinstance(item, str) or not item for item in operation_ids
    ):
        _fail("overlay subset operation_ids must be a frozenset of non-empty strings")
    validated = _parse_document(document)
    available = {
        operation.operation_id for output in validated.outputs for operation in output.operations
    }
    unknown = sorted(operation_ids - available)
    if unknown:
        _fail(f"overlay subset names unknown operations: {unknown}")
    selected = tuple(
        _Output(
            output.path,
            output.clean_digest,
            output.effective_digest,
            None,
            tuple(
                operation
                for operation in output.operations
                if operation.operation_id in operation_ids
            ),
        )
        for output in validated.outputs
    )
    if session is None:
        with ClassicOverlayRenderSession() as invocation:
            return _render_outputs(
                selected,
                clean_inputs,
                session=invocation,
                verify_output_identity=False,
            )
    return _render_outputs(
        selected,
        clean_inputs,
        session=session,
        verify_output_identity=False,
    )


def _generator_leaf_count(value: Mapping[str, object]) -> int:
    if value.get("k") != "seq":
        return 1
    raw_items = value.get("items")
    if not isinstance(raw_items, list):
        raise AssertionError("validated sequence has no item list")
    return sum(
        _generator_leaf_count({str(key): child for key, child in item.items() if key != "line"})
        for item in raw_items
        if isinstance(item, Mapping)
    )


def _project_generator_leaves(
    value: Mapping[str, object],
    selected_indexes: frozenset[int],
    *,
    first_index: int = 0,
) -> tuple[dict[str, object] | None, int]:
    if value.get("k") != "seq":
        return (
            (dict(value) if first_index in selected_indexes else None),
            first_index + 1,
        )
    raw_items = value.get("items")
    lines = value.get("lines")
    if not isinstance(raw_items, list) or not isinstance(lines, int):
        raise AssertionError("validated sequence shape changed")
    projected_items: list[dict[str, object]] = []
    cursor = first_index
    for raw_item in raw_items:
        if not isinstance(raw_item, Mapping) or not isinstance(raw_item.get("line"), int):
            raise AssertionError("validated sequence item shape changed")
        child = {str(key): item for key, item in raw_item.items() if key != "line"}
        projected, cursor = _project_generator_leaves(
            child,
            selected_indexes,
            first_index=cursor,
        )
        if projected is not None:
            projected_items.append({"line": raw_item["line"], **projected})
    if not projected_items:
        return None, cursor
    return {"k": "seq", "items": projected_items, "lines": lines}, cursor


def render_classic_overlay_leaf_subset(
    document: Mapping[str, object],
    clean_inputs: Mapping[str, bytes],
    leaf_keys: frozenset[tuple[str, int]],
    *,
    session: ClassicOverlayRenderSession | None = None,
) -> ClassicOverlayRenderResult:
    """Render selected generator leaves while retaining their sequence canvases.

    Leaf indexes use the same depth-first order as the semantic validator.  A
    partially selected ``seq`` keeps its declared physical-line canvas, so
    declaration/layout entropy is held constant without admitting the omitted
    semantic or helper leaves.  Destructive operations must be selected whole.
    """

    if not isinstance(leaf_keys, frozenset) or any(
        not isinstance(key, tuple)
        or len(key) != 2
        or not isinstance(key[0], str)
        or not key[0]
        or not isinstance(key[1], int)
        or isinstance(key[1], bool)
        or key[1] < 0
        for key in leaf_keys
    ):
        _fail("overlay leaf subset keys must be a frozenset of (operation_id, index)")
    validated = _parse_document(document)
    available: set[tuple[str, int]] = set()
    selected_outputs: list[_Output] = []
    for output in validated.outputs:
        selected_operations: list[_Operation] = []
        for operation in output.operations:
            leaf_count = _generator_leaf_count(operation.generator)
            operation_available = {(operation.operation_id, index) for index in range(leaf_count)}
            available.update(operation_available)
            selected_indexes = frozenset(
                index for operation_id, index in leaf_keys if operation_id == operation.operation_id
            )
            if not selected_indexes:
                continue
            if max(selected_indexes) >= leaf_count:
                continue
            if operation.action in {"replace", "delete"} and len(selected_indexes) != leaf_count:
                _fail(
                    "overlay leaf subset cannot partially select destructive operation "
                    f"{operation.operation_id!r}"
                )
            projected, cursor = _project_generator_leaves(
                operation.generator,
                selected_indexes,
            )
            if cursor != leaf_count or projected is None:
                raise AssertionError("validated leaf projection changed")
            selected_operations.append(
                _Operation(
                    operation.operation_id,
                    operation.action,
                    projected,
                    operation.start,
                    operation.end,
                    operation.removed_digest,
                    operation.removed_size,
                )
            )
        selected_outputs.append(
            _Output(
                output.path,
                output.clean_digest,
                output.effective_digest,
                None,
                tuple(selected_operations),
            )
        )
    unknown = sorted(leaf_keys - available)
    if unknown:
        _fail(f"overlay leaf subset names unknown leaves: {unknown}")
    selected = tuple(selected_outputs)
    if session is None:
        with ClassicOverlayRenderSession() as invocation:
            return _render_outputs(
                selected,
                clean_inputs,
                session=invocation,
                verify_output_identity=False,
            )
    return _render_outputs(
        selected,
        clean_inputs,
        session=session,
        verify_output_identity=False,
    )
