from __future__ import annotations

from hashlib import sha256
from typing import Any

import pytest

from reprobit.classic.overlay_document import render_classic_overlay_declarations
from reprobit.classic.overlay_generator import render_classic_overlay_generator
from reprobit.classic.overlay_types import (
    ClassicOverlayAnchorReceipt,
    ClassicOverlayOperationReceipt,
    ClassicOverlayOutputReceipt,
)
from reprobit.classic.source_proofs import (
    select_source_permutation_window,
    source_overlay_significant_sha256,
)
from reprobit.classic.source_refactor_semantics import (
    SourceRefactorSemanticError,
    _require_identifier_fresh_at_seat,
    _require_integral_type,
    validate_donor_source_semantics,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _seat_digest(tokens: list[str]) -> str:
    return _digest("\0".join(tokens).encode("ascii"))


def _range_pin(data: bytes) -> dict[str, object]:
    return {
        "baseline_sha256": _digest(data),
        "baseline_size": len(data),
        "baseline_line_count": data.count(b"\n"),
        "baseline_significant_token_sha256": source_overlay_significant_sha256(data),
    }


def _source_spec(path: str, data: bytes, **witnesses: object) -> dict[str, object]:
    return {"path": path, "source_sha256": _digest(data), **witnesses}


def _target_refactor_proof(
    *,
    kind: str,
    symbol: str,
    clean: bytes,
    rendered: bytes,
    operation_ids: list[str],
    **witnesses: object,
) -> dict[str, object]:
    selector = {
        "kind": kind,
        "selector": "brace_balanced_function_after_marker_v1",
        "start_marker": "// TARGET",
    }
    clean_target = select_source_permutation_window(clean, selector, "toy clean")
    rendered_target = select_source_permutation_window(rendered, selector, "toy rendered")
    return {
        **selector,
        "source_owner_mangled": symbol,
        "seed_range_pin": _range_pin(clean_target),
        "donor_range_pin": _range_pin(rendered_target),
        "operation_ids": operation_ids,
        **witnesses,
    }


def _manual_receipts(
    *,
    clean_sources: dict[str, bytes],
    rendered_sources: dict[str, bytes],
    operations: list[tuple[str, dict[str, object], int]],
) -> tuple[ClassicOverlayOutputReceipt, ...]:
    """Build fresh renderer-shaped receipts for validator-only fixtures."""

    by_path: dict[str, list[ClassicOverlayOperationReceipt]] = {}
    for path, operation, seat in operations:
        generator = operation["gen"]
        assert isinstance(generator, dict)
        fragment = render_classic_overlay_generator(generator)
        removed = operation.get("removed")
        removed_digest = removed_size = None
        if isinstance(removed, dict):
            removed_digest = removed.get("sha256")
            removed_size = removed.get("size")
            assert isinstance(removed_digest, str)
            assert isinstance(removed_size, int)
        operation_id = operation["id"]
        action = operation["op"]
        assert isinstance(operation_id, str)
        assert isinstance(action, str)
        by_path.setdefault(path, []).append(
            ClassicOverlayOperationReceipt(
                operation_id=operation_id,
                action=action,
                fragment_digest=_digest(fragment),
                fragment_size=len(fragment),
                anchors=(
                    ClassicOverlayAnchorReceipt(
                        role="anchor",
                        context_digest="0" * 64,
                        token_boundary=0,
                        byte_offset=seat,
                    ),
                ),
                removed_digest=removed_digest,
                removed_size=removed_size,
            )
        )
    return tuple(
        ClassicOverlayOutputReceipt(
            path=path,
            input_digest=_digest(clean_sources[path]),
            input_size=len(clean_sources[path]),
            output_digest=_digest(rendered_sources[path]),
            output_size=len(rendered_sources[path]),
            operations=tuple(receipts),
        )
        for path, receipts in sorted(by_path.items())
    )


def _recipe(
    *,
    recipe_id: str,
    role: ClassicRecipeRole,
    family: ClassicRecipeFamily,
    parameters: dict[str, Any],
    dependencies: tuple[str, ...] = (),
    symbol: str | None = None,
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=recipe_id,
        scope=Scope(
            target="sample",
            translation_unit="unit",
            function=symbol if role is ClassicRecipeRole.FUNCTION else None,
        ),
        rationale="Typed toy source-refactor theorem fixture.",
        dependencies=dependencies,
        family=family,
        role=role,
        build_target="sample",
        symbol=symbol,
        parameters=tuple(
            ClassicField(name=name, value=value) for name, value in sorted(parameters.items())
        ),
    )


def _private_dead_update_case() -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    path = "include/widget.h"
    clean_header = b"class Widget { public: void Touch() {} };\n"
    generator = {
        "k": "dead_updates",
        "id": "compilerState",
        "initial": 0,
        "increment": 1,
        "repeat": 2,
        "nl": False,
    }
    fragment = render_classic_overlay_generator(generator)
    rendered_header = clean_header.replace(b"{}", fragment)
    operation: dict[str, object] = {
        "id": "op_dead_update",
        "op": "replace",
        "from": {
            "ctx": _seat_digest(["Touch", "(", ")", "<SEAT>", "{", "}"]),
            "b": 3,
            "a": 2,
            "at": "before_token",
        },
        "to": {
            "ctx": _seat_digest(["{", "}", "<SEAT>", "}", ";"]),
            "b": 2,
            "a": 2,
            "at": "after_token",
        },
        "removed": {"sha256": _digest(b"{}"), "size": 2},
        "gen": generator,
    }
    rendering = {"path": path, "operations": [operation]}
    rendered = render_classic_overlay_declarations(
        [
            {
                "path": path,
                "clean": _digest(clean_header),
                "effective": _digest(rendered_header),
                "ops": [operation],
            }
        ],
        {path: clean_header},
    )
    donor = _recipe(
        recipe_id="donor.private",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [rendering]},
    )
    consumer = _recipe(
        recipe_id="function.private",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE,
        parameters={},
        dependencies=(donor.id,),
        symbol="?Touch@Widget@@QAEXXZ",
    )
    return (
        donor,
        consumer,
        {"src/unit.cpp": b'#include "widget.h"\n', path: clean_header},
        dict(rendered.outputs),
        rendered.receipts,
    )


def _default_constructor_case(
    *, already_declared: bool = False
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    path = "include/widget.h"
    existing = b"\tWidget() {}\n" if already_declared else b""
    clean_header = b"class Widget {\npublic:\n" + existing + b"};\n"
    generator = {
        "k": "default_ctor_dead_updates",
        "class": "Widget",
        "id": "compilerState",
        "initial": 1,
        "increment": 2,
        "repeat": 2,
    }
    fragment = render_classic_overlay_generator(generator)
    seat = clean_header.index(b"};")
    rendered_header = clean_header[:seat] + fragment + clean_header[seat:]
    operation: dict[str, object] = {
        "id": "op_default_constructor",
        "op": "insert",
        "anchor": {"at": "toy_class_end"},
        "gen": generator,
    }
    clean_sources = {path: clean_header}
    rendered_sources = {path: rendered_header}
    donor = _recipe(
        recipe_id="donor.default-constructor",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [{"path": path, "operations": [operation]}]},
    )
    consumer = _recipe(
        recipe_id="function.default-constructor",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE,
        parameters={},
        dependencies=(donor.id,),
        symbol="??0Widget@@QAE@XZ",
    )
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[(path, operation, seat)],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def _for_initializer_case(
    *, escape: bool = False, overlapping_entropy: bool = False
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    path = "src/unit.cpp"
    baseline = b"\tfor (Cursor it = items.begin(); it != items.end(); it++) {\n"
    clean = (
        b"// TARGET\n"
        b"void Widget::Run() {\n" + baseline + b"use(it);\n"
        b"\t}\n" + (b"use(it);\n" if escape else b"") + b"}\n"
    )
    generator = {
        "k": "for_init_decl",
        "form": "standalone_then_assignment_v1",
        "type": "Cursor",
        "id": "it",
        "container": "items",
        "begin": "begin",
        "end": "end",
        "declaration_indent": "\t",
    }
    fragment = render_classic_overlay_generator(generator)
    rendered_source = clean.replace(baseline, fragment)
    operation: dict[str, object] = {
        "id": "op_for_initializer",
        "op": "replace",
        "from": {
            "ctx": _seat_digest(["Run", "(", ")", "{", "<SEAT>", "for", "("]),
            "b": 4,
            "a": 2,
            "line_before": _digest(b"void Widget::Run() {"),
            "line_after": _digest(baseline.rstrip(b"\n")),
        },
        "to": {
            "ctx": _seat_digest(["++", ")", "{", "<SEAT>", "use", "("]),
            "b": 3,
            "a": 2,
            "line_before": _digest(baseline.rstrip(b"\n")),
            "line_after": _digest(b"use(it);"),
        },
        "removed": {"sha256": _digest(baseline), "size": len(baseline)},
        "gen": generator,
    }
    operations = [operation]
    if overlapping_entropy:
        entropy: dict[str, object] = {
            "id": "op_overlapping_entropy",
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["++", ")", "{", "<SEAT>", "use", "("]),
                "b": 3,
                "a": 2,
                "at": "before_token",
            },
            "gen": {"k": "fwd", "id": "Extra"},
        }
        operations.append(entropy)
        rendered_source = rendered_source.replace(b"use(it);", b"class Extra;\nuse(it);", 1)
    rendering = {"path": path, "operations": operations}
    result = render_classic_overlay_declarations(
        [
            {
                "path": path,
                "clean": _digest(clean),
                "effective": _digest(rendered_source),
                "ops": operations,
            }
        ],
        {path: clean},
    )
    selector = {
        "kind": "for_initializer_declaration_reseat_v1",
        "selector": "brace_balanced_function_after_marker_v1",
        "start_marker": "// TARGET",
    }
    clean_target = select_source_permutation_window(clean, selector, "toy clean")
    donor_target = select_source_permutation_window(result.outputs[path], selector, "toy donor")
    proof = {
        **selector,
        "source_owner_mangled": "?Run@Widget@@QAEXXZ",
        "seed_range_pin": _range_pin(clean_target),
        "donor_range_pin": _range_pin(donor_target),
        "operation_ids": ["op_for_initializer"],
    }
    donor = _recipe(
        recipe_id="donor.for",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [rendering]},
    )
    consumer = _recipe(
        recipe_id="function.for",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        parameters={"target_source_refactor": proof},
        dependencies=(donor.id,),
        symbol="?Run@Widget@@QAEXXZ",
    )
    return donor, consumer, {path: clean}, dict(result.outputs), result.receipts


def _fixed_array_fill_case(
    *, witness_extent: int = 3
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    source_path = "src/widget.cpp"
    header_path = "include/widget.h"
    include_line = b'#include "widget.h"\n'
    declaration_line = b"\tint values[3];\n"
    header = b"class Widget {\npublic:\n" + declaration_line + b"};\n"
    baseline = b"\tmemset(values, -1, sizeof(values));\n"
    clean = include_line + b"// TARGET\n" + b"void Widget::Reset() {\n" + baseline + b"}\n"
    generator = {
        "k": "fixed_array_fill",
        "array": "values",
        "index": "index",
        "index_type": "int",
        "count": 3,
        "value": -1,
        "declaration_indent": "\t",
    }
    rendered = clean.replace(baseline, render_classic_overlay_generator(generator))
    operation: dict[str, object] = {
        "id": "op_fixed_fill",
        "op": "replace",
        "from": {"at": "toy_start"},
        "to": {"at": "toy_end"},
        "removed": {"sha256": _digest(baseline), "size": len(baseline)},
        "gen": generator,
    }
    symbol = "?Reset@Widget@@QAEXXZ"
    witness = _source_spec(
        header_path,
        header,
        owner="Widget",
        array="values",
        element_type="int",
        extent=witness_extent,
        direct_include_range_pin=_range_pin(include_line),
        declaration_range_pin=_range_pin(declaration_line),
    )
    proof = _target_refactor_proof(
        kind="fixed_array_fill_loop_v1",
        symbol=symbol,
        clean=clean,
        rendered=rendered,
        operation_ids=["op_fixed_fill"],
        array_declaration=witness,
    )
    donor = _recipe(
        recipe_id="donor.fixed-fill",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [{"path": source_path, "operations": [operation]}]},
    )
    consumer = _recipe(
        recipe_id="function.fixed-fill",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        parameters={"target_source_refactor": proof},
        dependencies=(donor.id,),
        symbol=symbol,
    )
    clean_sources = {source_path: clean, header_path: header}
    rendered_sources = {source_path: rendered, header_path: header}
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[(source_path, operation, clean.index(baseline))],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def _fixed_array_shuffle_case() -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    source_path = "src/deck.cpp"
    owner_path = "include/deck.h"
    base_path = "include/base.h"
    types_path = "include/types.h"
    unit_include = b'#include "deck.h"\n'
    owner_include = b'#include "base.h"\n'
    base_include = b'#include "types.h"\n'
    declaration_line = b"\tElement values[4];\n"
    member_block = b"public:\n" + declaration_line + b"\tint marker;\n"
    owner_header = owner_include + b"class Deck {\n" + member_block + b"};\n"
    base_header = base_include + b"class DeckBase {};\n"
    element_typedef = b"typedef unsigned short Element;\n"
    index_typedef = b"typedef signed int Index;\n"
    types_header = element_typedef + index_typedef
    baseline = (
        b"\tfor (i = 0; i < 4; i++) {\n"
        b"\t\tIndex swap = randomValue() % 4;\n"
        b"\t\tElement temporary = values[i];\n"
        b"\t\tvalues[i] = values[swap];\n"
        b"\t\tvalues[swap] = temporary;\n"
        b"\t}\n"
    )
    next_overwrite = b"\tfor (i = 0; i < 1; i++) {\n"
    clean = (
        unit_include
        + b"// TARGET\n"
        + b"void Deck::Shuffle() {\n"
        + b"\tIndex i;\n"
        + baseline
        + next_overwrite
        + b"\t\tuse(i);\n\t}\n}\n"
    )
    generator = {
        "k": "fixed_array_shuffle_countdown",
        "array": "values",
        "index": "i",
        "index_type": "Index",
        "pointer": "cursor",
        "element_type": "Element",
        "swap": "swap",
        "swap_type": "Index",
        "temporary": "temporary",
        "temporary_type": "Element",
        "random_function": "randomValue",
        "count": 4,
        "declaration_indent": "\t",
    }
    rendered = clean.replace(baseline, render_classic_overlay_generator(generator))
    operation: dict[str, object] = {
        "id": "op_shuffle",
        "op": "replace",
        "from": {"at": "toy_start"},
        "to": {"at": "toy_end"},
        "removed": {"sha256": _digest(baseline), "size": len(baseline)},
        "gen": generator,
    }
    witness = {
        "source_owner": "Deck",
        "array_member": "values",
        "element_type": "Element",
        "extent": 4,
        "index_identifier": "i",
        "index_type": "Index",
        "owner_header": _source_spec(
            owner_path,
            owner_header,
            unit_include_range_pin=_range_pin(unit_include),
            base_include_range_pin=_range_pin(owner_include),
            array_declaration_range_pin=_range_pin(declaration_line),
            member_block_range_pin=_range_pin(member_block),
        ),
        "base_header": _source_spec(
            base_path,
            base_header,
            types_include_range_pin=_range_pin(base_include),
        ),
        "types_header": _source_spec(
            types_path,
            types_header,
            element_typedef_range_pin=_range_pin(element_typedef),
            index_typedef_range_pin=_range_pin(index_typedef),
        ),
        "next_index_overwrite_range_pin": _range_pin(next_overwrite),
    }
    symbol = "?Shuffle@Deck@@QAEXXZ"
    proof = _target_refactor_proof(
        kind="fixed_array_shuffle_pointer_countdown_v1",
        symbol=symbol,
        clean=clean,
        rendered=rendered,
        operation_ids=["op_shuffle"],
        semantic_witness=witness,
    )
    donor = _recipe(
        recipe_id="donor.shuffle",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [{"path": source_path, "operations": [operation]}]},
    )
    consumer = _recipe(
        recipe_id="function.shuffle",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY,
        parameters={
            "target_source_refactor": proof,
            "source_fpo_identity": {"kind": "toy_source_fpo"},
        },
        dependencies=(donor.id,),
        symbol=symbol,
    )
    clean_sources = {
        source_path: clean,
        owner_path: owner_header,
        base_path: base_header,
        types_path: types_header,
    }
    rendered_sources = {**clean_sources, source_path: rendered}
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[(source_path, operation, clean.index(baseline))],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def _inclusive_extent_case(
    *, shadow_inherited_accessor: bool = False
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    source_path = "src/painter.cpp"
    owner_path = "include/painter.h"
    accessor_path = "include/box.h"
    extent_path = "include/bounds.h"
    unit_include = b'#include "painter.h"\n'
    owner_include = b'#include "box.h"\n'
    accessor_include = b'#include "bounds.h"\n'
    source_member_line = b"\tBox box;\n"
    owner_header = owner_include + b"class Painter {\npublic:\n" + source_member_line + b"};\n"
    accessor_line = b"\tBounds& bounds() { return region; }\n"
    accessor_header = (
        accessor_include
        + b"class Box {\npublic:\n"
        + accessor_line
        + b"private:\n\tBounds region;\n};\n"
    )
    lower_line = b"\tT left() const { return low; }\n"
    upper_line = b"\tT right() const { return high; }\n"
    extent_line = b"\tT extent() const { return (high - low + 1); }\n"
    extent_template = (
        b"typedef signed int Coord;\n"
        b"template <class T>\n"
        b"class Extent {\npublic:\n"
        + lower_line
        + upper_line
        + extent_line
        + b"private:\n\tT low;\n\tT high;\n};\n"
    )
    shadow = b"\tCoord extent;\n" if shadow_inherited_accessor else b""
    concrete_class = b"class Bounds : public Extent<Coord> {\n" + shadow + b"};\n"
    extent_header = extent_template + concrete_class
    baseline = b"\tsurface.widthValue = box.bounds().extent();\n"
    clean = unit_include + b"// TARGET\n" + b"void Painter::Resize() {\n" + baseline + b"}\n"
    generator = {
        "k": "inclusive_extent",
        "type": "Coord",
        "id": "width",
        "source": {"object": "box", "aggregate_accessor": "bounds"},
        "seed_extent_accessor": "extent",
        "upper_endpoint_accessor": "right",
        "lower_endpoint_accessor": "left",
        "destination": {"object": "surface", "member": "widthValue"},
        "declaration_indent": "\t",
        "barrier": "msvc_i386_empty_inline_assembly_v1",
    }
    rendered = clean.replace(baseline, render_classic_overlay_generator(generator))
    operation: dict[str, object] = {
        "id": "op_inclusive_extent",
        "op": "replace",
        "from": {"at": "toy_start"},
        "to": {"at": "toy_end"},
        "removed": {"sha256": _digest(baseline), "size": len(baseline)},
        "gen": generator,
    }
    witness = {
        "source_owner": "Painter",
        "source_member": "box",
        "source_member_type": "Box",
        "aggregate_accessor": "bounds",
        "aggregate_member": "region",
        "aggregate_type": "Bounds",
        "coordinate_type": "Coord",
        "lower_accessor": "left",
        "lower_member": "low",
        "upper_accessor": "right",
        "upper_member": "high",
        "extent_accessor": "extent",
        "source_owner_header": _source_spec(
            owner_path,
            owner_header,
            unit_include_range_pin=_range_pin(unit_include),
            member_declaration_range_pin=_range_pin(source_member_line),
        ),
        "source_accessor_header": _source_spec(
            accessor_path,
            accessor_header,
            owner_include_range_pin=_range_pin(owner_include),
            accessor_range_pin=_range_pin(accessor_line),
        ),
        "extent_header": _source_spec(
            extent_path,
            extent_header,
            accessor_include_range_pin=_range_pin(accessor_include),
            concrete_inheritance_range_pin=_range_pin(b"class Bounds : public Extent<Coord> {\n"),
            concrete_class_range_pin=_range_pin(concrete_class),
            lower_accessor_range_pin=_range_pin(lower_line),
            upper_accessor_range_pin=_range_pin(upper_line),
            extent_accessor_range_pin=_range_pin(extent_line),
        ),
    }
    symbol = "?Resize@Painter@@QAEXXZ"
    proof = _target_refactor_proof(
        kind="inclusive_extent_assignment_v1",
        symbol=symbol,
        clean=clean,
        rendered=rendered,
        operation_ids=["op_inclusive_extent"],
        semantic_witness=witness,
    )
    donor = _recipe(
        recipe_id="donor.inclusive-extent",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [{"path": source_path, "operations": [operation]}]},
    )
    consumer = _recipe(
        recipe_id="function.inclusive-extent",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        parameters={"target_source_refactor": proof},
        dependencies=(donor.id,),
        symbol=symbol,
    )
    clean_sources = {
        source_path: clean,
        owner_path: owner_header,
        accessor_path: accessor_header,
        extent_path: extent_header,
    }
    rendered_sources = {**clean_sources, source_path: rendered}
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[(source_path, operation, clean.index(baseline))],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def _captured_tail_case(
    *, visible_capture: bool = False
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    path = "src/finder.cpp"
    prefix = b"Node* found;\n" if visible_capture else b""
    clean = (
        prefix
        + b"// TARGET\n"
        + b"Node* Finder::Find() {\n"
        + b"\tNode* current = head;\n"
        + b"\tuse(current);\n"
        + b"\tinspect(current);\n"
        + b"\treturn current;\n"
        + b"}\n"
    )
    generators: dict[str, dict[str, object]] = {
        "capture_declaration": {
            "k": "capture_tail",
            "role": "capture_declaration",
            "type": "Node*",
            "capture": "found",
            "declaration_indent": "\t",
        },
        "capture_assignment": {
            "k": "capture_tail",
            "role": "capture_assignment",
            "capture": "found",
            "source": "current",
            "declaration_indent": "\t",
        },
        "read_reseat": {
            "k": "capture_tail",
            "role": "read_reseat",
            "capture": "found",
            "source": "current",
            "nl": False,
        },
        "return_to_goto": {
            "k": "capture_tail",
            "role": "return_to_goto",
            "source": "current",
            "label": "done",
            "nl": False,
        },
        "tail_return": {
            "k": "capture_tail",
            "role": "tail_return",
            "capture": "found",
            "label": "done",
            "declaration_indent": "\t",
        },
    }
    rendered = clean.replace(
        b"\tNode* current = head;\n",
        render_classic_overlay_generator(generators["capture_declaration"])
        + b"\tNode* current = head;\n",
    )
    rendered = rendered.replace(
        b"\tuse(current);\n",
        render_classic_overlay_generator(generators["capture_assignment"]) + b"\tuse(current);\n",
    )
    rendered = rendered.replace(b"inspect(current)", b"inspect(found)")
    rendered = rendered.replace(b"return current;", b"goto done;")
    rendered = (
        rendered[: rendered.rfind(b"}")]
        + render_classic_overlay_generator(generators["tail_return"])
        + rendered[rendered.rfind(b"}") :]
    )
    roles = [
        "capture_declaration",
        "capture_assignment",
        "read_reseat",
        "return_to_goto",
        "tail_return",
    ]
    operations: list[dict[str, object]] = []
    for role in roles:
        action = "replace" if role in {"read_reseat", "return_to_goto"} else "insert"
        operation: dict[str, object] = {
            "id": f"op_{role}",
            "op": action,
            "anchor": {"at": f"toy_{role}"},
            "gen": generators[role],
        }
        if role == "read_reseat":
            operation["removed"] = {"sha256": _digest(b"current"), "size": 7}
        elif role == "return_to_goto":
            removed = b"return current;"
            operation["removed"] = {"sha256": _digest(removed), "size": len(removed)}
        operations.append(operation)
    seats = {
        "capture_declaration": clean.index(b"\tNode* current"),
        "capture_assignment": clean.index(b"\tuse(current)"),
        "read_reseat": clean.index(b"current", clean.index(b"inspect(")),
        "return_to_goto": clean.index(b"return current;"),
        "tail_return": clean.rfind(b"}"),
    }
    symbol = "?Find@Finder@@QAEPAVNode@@XZ"
    proof = _target_refactor_proof(
        kind="captured_pointer_tail_return_v1",
        symbol=symbol,
        clean=clean,
        rendered=rendered,
        operation_ids=[f"op_{role}" for role in roles],
    )
    donor = _recipe(
        recipe_id="donor.capture-tail",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": [{"path": path, "operations": operations}]},
    )
    consumer = _recipe(
        recipe_id="function.capture-tail",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        parameters={"target_source_refactor": proof},
        dependencies=(donor.id,),
        symbol=symbol,
    )
    clean_sources = {path: clean}
    rendered_sources = {path: rendered}
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[
            (path, operation, seats[role])
            for role, operation in zip(roles, operations, strict=True)
        ],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def _constructor_allocation_lift_case(
    *, overload_already_declared: bool = False
) -> tuple[
    ClassicRecipeIntervention,
    ClassicRecipeIntervention,
    dict[str, bytes],
    dict[str, bytes],
    tuple[ClassicOverlayOutputReceipt, ...],
]:
    source_path = "src/store.cpp"
    header_path = "include/entry.h"
    unit_include = b'#include "entry.h"\n'
    new_declaration = b"\tEntry(const char* key);\n"
    existing = new_declaration if overload_already_declared else b""
    buffer_line = b"\tconst char* buffer;\n"
    null_line = b"\tPayload* payload;\n"
    baseline_constructor = (
        b"\tEntry(Payload* payloadValue, const char* bufferValue) "
        b": payload(payloadValue), buffer(bufferValue) {}\n"
    )
    destructor_body = (
        b"{ if (payload == NULL && buffer != NULL) { delete[] const_cast<char*>(buffer); } }"
    )
    destructor_line = b"\t~Entry() " + destructor_body + b"\n"
    header = (
        b"class Entry {\npublic:\n"
        + existing
        + buffer_line
        + null_line
        + baseline_constructor
        + destructor_line
        + b"};\n"
    )
    baseline = (
        b"\tchar* raw = new char[textLength(key) + 1];\n"
        b"\tcopyText(raw, key);\n\n"
        b"\tCursor it = entries.find(Entry(NULL, raw));\n"
    )
    parameter_line = b"Cursor Store::Lookup(const char* key) {\n"
    clean = unit_include + b"// TARGET\n" + parameter_line + baseline + b"\treturn it;\n" + b"}\n"
    signature_parameter = {"type": "const char*", "identifier": "key"}
    declaration_generator = {
        "k": "member_sig",
        "class_identifier": "Entry",
        "member_identifier": "Entry",
        "kind": "constructor",
        "form": "in_class_declaration",
        "parameters": [signature_parameter],
    }
    definition_generator = {
        **declaration_generator,
        "form": "qualified_definition_header",
    }
    common_lift = {
        "k": "ctor_alloc_lift",
        "class_identifier": "Entry",
        "parameter_identifier": "key",
        "buffer_member": "buffer",
        "buffer_cast_type": "char*",
        "element_type": "char",
        "extent_function": "textLength",
        "copy_function": "copyText",
        "null_members": ["payload"],
        "caller_result_identifier": "raw",
        "caller_result_type": "char*",
        "null_argument_position": 0,
        "iterator_type": "Cursor",
        "iterator_identifier": "it",
        "container_identifier": "entries",
        "find_member": "find",
        "declaration_indent": "\t",
    }
    body_generator = {**common_lift, "role": "constructor_body"}
    call_generator = {**common_lift, "role": "call_site"}
    definition_seat = clean.index(b"// TARGET")
    definition_fragment = render_classic_overlay_generator(definition_generator)
    body_fragment = render_classic_overlay_generator(body_generator)
    rendered_source = (
        clean[:definition_seat] + definition_fragment + body_fragment + clean[definition_seat:]
    )
    rendered_source = rendered_source.replace(
        baseline, render_classic_overlay_generator(call_generator)
    )
    declaration_fragment = render_classic_overlay_generator(declaration_generator)
    header_seat = header.index(buffer_line)
    rendered_header = header[:header_seat] + declaration_fragment + header[header_seat:]
    shared_anchor = {"at": "toy_constructor_definition"}
    declaration_operation: dict[str, object] = {
        "id": "op_constructor_declaration",
        "op": "insert",
        "anchor": {"at": "toy_class_declaration"},
        "gen": declaration_generator,
    }
    definition_operation: dict[str, object] = {
        "id": "op_constructor_definition",
        "op": "insert",
        "anchor": shared_anchor,
        "gen": definition_generator,
    }
    body_operation: dict[str, object] = {
        "id": "op_constructor_body",
        "op": "insert",
        "anchor": shared_anchor,
        "gen": body_generator,
    }
    call_operation: dict[str, object] = {
        "id": "op_constructor_call",
        "op": "replace",
        "from": {"at": "toy_call_start"},
        "to": {"at": "toy_call_end"},
        "removed": {"sha256": _digest(baseline), "size": len(baseline)},
        "gen": call_generator,
    }
    witness = {
        "source_owner": "Store",
        "entry_class": "Entry",
        "buffer_member": "buffer",
        "buffer_member_type": "const char*",
        "null_members": [{"identifier": "payload", "type": "Payload*"}],
        "null_argument_position": 0,
        "baseline_constructor_parameter_identifiers": ["payloadValue", "bufferValue"],
        "owner_header": _source_spec(
            header_path,
            header,
            unit_include_range_pin=_range_pin(unit_include),
            class_body_range_pin=_range_pin(header),
            buffer_member_declaration_range_pin=_range_pin(buffer_line),
            null_member_declaration_range_pins=[_range_pin(null_line)],
            baseline_constructor_range_pin=_range_pin(baseline_constructor),
            destructor_body_range_pin=_range_pin(destructor_body),
        ),
        "target_parameter_range_pin": _range_pin(parameter_line),
    }
    symbol = "?Lookup@Store@@QAEXXZ"
    operation_ids = [
        "op_constructor_declaration",
        "op_constructor_definition",
        "op_constructor_body",
        "op_constructor_call",
    ]
    proof = _target_refactor_proof(
        kind="constructor_allocation_lift_v1",
        symbol=symbol,
        clean=clean,
        rendered=rendered_source,
        operation_ids=operation_ids,
        semantic_witness=witness,
        constructor_signature={
            "class_identifier": "Entry",
            "parameters": [signature_parameter],
        },
    )
    renderings = [
        {"path": header_path, "operations": [declaration_operation]},
        {
            "path": source_path,
            "operations": [definition_operation, body_operation, call_operation],
        },
    ]
    donor = _recipe(
        recipe_id="donor.constructor-lift",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": renderings},
    )
    consumer = _recipe(
        recipe_id="function.constructor-lift",
        role=ClassicRecipeRole.FUNCTION,
        family=ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        parameters={
            "target_source_refactor": proof,
            "local_set_delta": {
                "kind": "removed_caller_locals_v1",
                "removed_records": [{"identifier": "raw"}],
            },
        },
        dependencies=(donor.id,),
        symbol=symbol,
    )
    clean_sources = {source_path: clean, header_path: header}
    rendered_sources = {source_path: rendered_source, header_path: rendered_header}
    receipts = _manual_receipts(
        clean_sources=clean_sources,
        rendered_sources=rendered_sources,
        operations=[
            (header_path, declaration_operation, header_seat),
            (source_path, definition_operation, definition_seat),
            (source_path, body_operation, definition_seat),
            (source_path, call_operation, clean.index(baseline)),
        ],
    )
    return donor, consumer, clean_sources, rendered_sources, receipts


def test_private_dead_update_is_classified_without_claiming_source_equivalence() -> None:
    donor, consumer, clean, rendered, receipts = _private_dead_update_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/unit.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.classification == "donor_private_compiler_state_v1"
    assert proof.generator_kinds == ("dead_updates",)


def test_default_constructor_dead_update_is_private_compiler_state() -> None:
    donor, consumer, clean, rendered, receipts = _default_constructor_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/unit.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.classification == "donor_private_compiler_state_v1"
    assert proof.generator_kinds == ("default_ctor_dead_updates",)


def test_default_constructor_dead_update_rejects_an_existing_constructor() -> None:
    donor, consumer, clean, rendered, receipts = _default_constructor_case(already_declared=True)

    with pytest.raises(SourceRefactorSemanticError, match="already declares a constructor"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/unit.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_source_mutation_requires_fresh_renderer_receipts() -> None:
    donor, consumer, clean, rendered, _receipts = _private_dead_update_case()

    with pytest.raises(SourceRefactorSemanticError, match="lacks overlay operation receipts"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/unit.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
        )


def test_source_mutation_requires_exactly_one_bound_consumer() -> None:
    donor, consumer, clean, rendered, receipts = _private_dead_update_case()

    with pytest.raises(SourceRefactorSemanticError, match="exactly one consumer"):
        validate_donor_source_semantics(
            donor,
            [consumer, consumer.model_copy(update={"id": "function.second"})],
            owning_source="src/unit.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_for_initializer_refactor_proves_its_complete_target() -> None:
    donor, consumer, clean, rendered, receipts = _for_initializer_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/unit.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.classification == "logic_equivalent_target_source_refactor_v1"
    assert proof.generator_kinds == ("for_init_decl",)


def test_for_initializer_refactor_rejects_an_escaping_local() -> None:
    donor, consumer, clean, rendered, receipts = _for_initializer_case(escape=True)

    with pytest.raises(SourceRefactorSemanticError, match="escapes its loop"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/unit.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_fixed_array_fill_is_bound_to_its_member_extent() -> None:
    donor, consumer, clean, rendered, receipts = _fixed_array_fill_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/widget.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.generator_kinds == ("fixed_array_fill",)


def test_fixed_array_fill_rejects_a_witness_with_another_extent() -> None:
    donor, consumer, clean, rendered, receipts = _fixed_array_fill_case(witness_extent=4)

    with pytest.raises(SourceRefactorSemanticError, match="bound differs"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/widget.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_fixed_array_shuffle_is_bound_to_its_header_chain_and_fpo_lane() -> None:
    donor, consumer, clean, rendered, receipts = _fixed_array_shuffle_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/deck.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.generator_kinds == ("fixed_array_shuffle_countdown",)


def test_fixed_array_shuffle_rejects_an_overlaid_witness_header() -> None:
    donor, consumer, clean, rendered, receipts = _fixed_array_shuffle_case()

    with pytest.raises(SourceRefactorSemanticError, match=r"witness header .* is overlaid"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/deck.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlaid_paths=frozenset({"include/deck.h"}),
            overlay_receipts=receipts,
        )


def test_inclusive_extent_is_bound_to_inherited_endpoint_accessors() -> None:
    donor, consumer, clean, rendered, receipts = _inclusive_extent_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/painter.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.generator_kinds == ("inclusive_extent",)


def test_inclusive_extent_rejects_a_concrete_accessor_shadow() -> None:
    donor, consumer, clean, rendered, receipts = _inclusive_extent_case(
        shadow_inherited_accessor=True
    )

    with pytest.raises(SourceRefactorSemanticError, match="shadows an inherited accessor"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/painter.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_captured_tail_is_bound_to_all_five_ordered_roles() -> None:
    donor, consumer, clean, rendered, receipts = _captured_tail_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/finder.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.generator_kinds == ("capture_tail",)
    assert len(proof.operation_ids) == 5


def test_captured_tail_rejects_a_capture_visible_outside_the_target() -> None:
    donor, consumer, clean, rendered, receipts = _captured_tail_case(visible_capture=True)

    with pytest.raises(SourceRefactorSemanticError, match="capture identity is not fresh"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/finder.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_constructor_allocation_lift_binds_header_ownership_and_removed_local() -> None:
    donor, consumer, clean, rendered, receipts = _constructor_allocation_lift_case()

    proof = validate_donor_source_semantics(
        donor,
        [consumer],
        owning_source="src/store.cpp",
        clean_sources=clean,
        rendered_sources=rendered,
        overlay_receipts=receipts,
    )

    assert proof is not None
    assert proof.generator_kinds == ("ctor_alloc_lift",)
    assert len(proof.operation_ids) == 4


def test_constructor_allocation_lift_rejects_an_existing_overload() -> None:
    donor, consumer, clean, rendered, receipts = _constructor_allocation_lift_case(
        overload_already_declared=True
    )

    with pytest.raises(SourceRefactorSemanticError, match="overload already exists"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/store.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_source_refactor_rejects_unbound_entropy_inside_its_target() -> None:
    donor, consumer, clean, rendered, receipts = _for_initializer_case(overlapping_entropy=True)

    with pytest.raises(SourceRefactorSemanticError, match="entropy overlaps"):
        validate_donor_source_semantics(
            donor,
            [consumer],
            owning_source="src/unit.cpp",
            clean_sources=clean,
            rendered_sources=rendered,
            overlay_receipts=receipts,
        )


def test_integral_alias_must_resolve_through_its_include_closure() -> None:
    sources = {
        "include/shape.h": b'#include "types.h"\nclass Shape {};\n',
        "include/types.h": b"typedef signed int Coordinate;\n",
        "unrelated/types.h": b"typedef float OtherCoordinate;\n",
    }

    _require_integral_type(sources, "include/shape.h", "Coordinate", "coordinate type")
    with pytest.raises(SourceRefactorSemanticError, match="absent or ambiguous"):
        _require_integral_type(sources, "include/shape.h", "OtherCoordinate", "coordinate type")


def test_project_named_integral_alias_gets_no_implicit_authority() -> None:
    sources = {"include/shape.h": b"class Shape {};\n"}

    with pytest.raises(SourceRefactorSemanticError, match="absent or ambiguous"):
        _require_integral_type(
            sources,
            "include/shape.h",
            "ProjectInt32",
            "coordinate type",
        )


def test_fresh_local_allows_siblings_but_rejects_visible_scopes() -> None:
    sibling = b"void f() { { int width; } { target(); } }\n"
    _require_identifier_fresh_at_seat(sibling, sibling.index(b"target"), "width", "local")

    same_block = b"void f() { int width; target(); }\n"
    with pytest.raises(SourceRefactorSemanticError, match="destination block"):
        _require_identifier_fresh_at_seat(same_block, same_block.index(b"target"), "width", "local")

    ancestor = b"void f() { int width; { target(); } }\n"
    with pytest.raises(SourceRefactorSemanticError, match="visible ancestor"):
        _require_identifier_fresh_at_seat(ancestor, ancestor.index(b"target"), "width", "local")


def _entropy_only_donor(
    operations_by_path: dict[str, list[dict[str, object]]],
) -> ClassicRecipeIntervention:
    renderings = [{"path": path, "operations": ops} for path, ops in operations_by_path.items()]
    return _recipe(
        recipe_id="donor.entropy",
        role=ClassicRecipeRole.DONOR,
        family=ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        parameters={"renderings": renderings},
    )


def test_entropy_only_donor_may_remove_comment_text() -> None:
    """Destructive entropy that removes only comments and whitespace is inert."""
    clean = b"// build note\nint value = 5;\n"
    rendered = b"\nint value = 5;\n"
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_lines",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(b"// build note"), "size": 13},
                }
            ]
        }
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/unit.cpp",
        clean_sources={"src/unit.cpp": clean},
        rendered_sources={"src/unit.cpp": rendered},
    )

    assert proof is None


def test_entropy_only_donor_may_add_generated_declarations() -> None:
    """Additions come from the closed generators and preserve every clean token."""
    clean = b"int value = 5;\n"
    rendered = b"class Widget;\nint value = 5;\n"
    donor = _entropy_only_donor(
        {"src/unit.cpp": [{"id": "op_fwd", "op": "insert", "gen": {"k": "lines", "n": 1}}]}
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/unit.cpp",
        clean_sources={"src/unit.cpp": clean},
        rendered_sources={"src/unit.cpp": rendered},
    )

    assert proof is None


def test_entropy_only_donor_must_not_remove_program_text() -> None:
    """A destructive operation may not drop a significant token of the program."""
    clean = b"int a = 1;\nint value = 5;\n"
    rendered = b"\nint value = 5;\n"
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_lines",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(b"int a = 1;"), "size": 10},
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="non-prototype text"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": clean},
            rendered_sources={"src/unit.cpp": rendered},
        )


def test_entropy_only_donor_must_not_reorder_program_text() -> None:
    clean = b"int a;\nint b;\n"
    rendered = b"int b;\nint a;\n"
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_lines",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(b"int a;"), "size": 6},
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="non-prototype text"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": clean},
            rendered_sources={"src/unit.cpp": rendered},
        )


def test_entropy_only_donor_rejects_unadmitted_generator() -> None:
    donor = _entropy_only_donor(
        {"src/unit.cpp": [{"id": "op_odd", "op": "insert", "gen": {"k": "mystery"}}]}
    )

    with pytest.raises(SourceRefactorSemanticError, match="unadmitted generator"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": b"int value = 5;\n"},
            rendered_sources={"src/unit.cpp": b"int value = 5;\n"},
        )


def test_entropy_only_donor_extra_rendering_must_be_header() -> None:
    donor = _entropy_only_donor(
        {"src/extra.cpp": [{"id": "op_lines", "op": "insert", "gen": {"k": "lines", "n": 1}}]}
    )

    with pytest.raises(SourceRefactorSemanticError, match="not a header"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": b"int value = 5;\n"},
            rendered_sources={"src/unit.cpp": b"int value = 5;\n"},
        )


def test_entropy_only_donor_rendering_must_be_present() -> None:
    donor = _entropy_only_donor(
        {"src/unit.cpp": [{"id": "op_lines", "op": "replace", "gen": {"k": "lines", "n": 1}}]}
    )

    with pytest.raises(SourceRefactorSemanticError, match="is absent"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": b"int value = 5;\n"},
            rendered_sources={},
        )


def test_entropy_only_donor_may_exchange_include_directives() -> None:
    """Removed include directives are the admitted include-seat lever."""
    clean = b'#include "realtime/vector3d.inl.h"\nint value = 5;\n'
    rendered = b'#include "realtime/matrix4d.inl.h"\nint value = 5;\n'
    donor = _entropy_only_donor(
        {
            "include/math.h": [
                {
                    "id": "op_inc",
                    "op": "replace",
                    "gen": {"k": "include", "line": 1},
                    "removed": {
                        "sha256": _digest(b'#include "realtime/vector3d.inl.h"'),
                        "size": 34,
                    },
                }
            ]
        }
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/unit.cpp",
        clean_sources={"include/math.h": clean, "src/unit.cpp": b"int main;\n"},
        rendered_sources={"include/math.h": rendered},
    )

    assert proof is None


def test_entropy_only_donor_may_elide_unreferenced_prototype() -> None:
    """A non-virtual prototype whose name survives nowhere may be removed."""
    clean = b"class Actor {\npublic:\n\tfloat GetDistance(float p_time);\n\tvoid Act();\n};\n"
    rendered = b"class Actor {\npublic:\n\n\tvoid Act();\n};\n"
    donor = _entropy_only_donor(
        {
            "include/actor.h": [
                {
                    "id": "op_d1",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {
                        "sha256": _digest(b"\tfloat GetDistance(float p_time);\n"),
                        "size": 34,
                    },
                }
            ]
        }
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/unit.cpp",
        clean_sources={"include/actor.h": clean, "src/unit.cpp": b"int main;\n"},
        rendered_sources={"include/actor.h": rendered},
    )

    assert proof is None


def test_entropy_only_donor_must_not_elide_referenced_prototype() -> None:
    """The removed declaration's name may not survive in any rendered text."""
    clean = b"class Actor {\npublic:\n\tfloat GetDistance(float p_time);\n\tvoid Act();\n};\n"
    rendered = b"class Actor {\npublic:\n\n\tvoid Act();\n};\n"
    donor = _entropy_only_donor(
        {
            "include/actor.h": [
                {
                    "id": "op_d1",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {
                        "sha256": _digest(b"\tfloat GetDistance(float p_time);\n"),
                        "size": 34,
                    },
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="still referenced"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"include/actor.h": clean},
            rendered_sources={
                "include/actor.h": rendered,
                "src/unit.cpp": b"float d = actor->GetDistance(1.0f);\n",
            },
        )


def test_entropy_only_donor_must_not_elide_virtual_prototype() -> None:
    """A virtual declaration changes the vtable and is never entropy."""
    clean = b"class Actor {\npublic:\n\tvirtual float GetDistance(float p_time);\n};\n"
    rendered = b"class Actor {\npublic:\n\n};\n"
    donor = _entropy_only_donor(
        {
            "include/actor.h": [
                {
                    "id": "op_d1",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {
                        "sha256": _digest(b"\tvirtual float GetDistance(float p_time);\n"),
                        "size": 42,
                    },
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="non-prototype text"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"include/actor.h": clean},
            rendered_sources={"include/actor.h": rendered},
        )


def test_entropy_only_donor_may_relocate_member_definition() -> None:
    """A member_sig/reloc pair moves a definition; its tokens must reappear."""
    clean_header = b"class Entry {\npublic:\n\t~Entry() { Flush(); }\n};\n"
    rendered_header = b"class Entry {\npublic:\n\t~Entry();\n};\n"
    rendered_cpp = b'#include "entry.h"\n\nEntry::~Entry() { Flush(); }\n'
    donor = _entropy_only_donor(
        {
            "include/entry.h": [
                {
                    "id": "op_move",
                    "op": "replace",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "in_class_declaration",
                    },
                    "removed": {"sha256": _digest(b"~Entry()"), "size": 8},
                },
                {
                    "id": "op_body_source",
                    "op": "delete",
                    "gen": {"k": "reloc", "range_identity": "Entry::~Entry"},
                    "removed": {"sha256": _digest(b" { Flush(); }"), "size": 13},
                },
            ],
            "src/entry.cpp": [
                {
                    "id": "op_definition",
                    "op": "insert",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "qualified_definition_header",
                    },
                },
                {
                    "id": "op_dest",
                    "op": "insert",
                    "gen": {"k": "reloc", "range_identity": "Entry::~Entry"},
                },
            ],
        }
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/entry.cpp",
        clean_sources={"include/entry.h": clean_header, "src/entry.cpp": b""},
        rendered_sources={"include/entry.h": rendered_header, "src/entry.cpp": rendered_cpp},
    )

    assert proof is None


def test_entropy_only_donor_relocation_must_reappear() -> None:
    """A declared relocation whose tokens vanish is a disguised deletion."""
    clean_header = b"class Entry {\npublic:\n\t~Entry() { Flush(); }\n};\n"
    rendered_header = b"class Entry {\npublic:\n\t~Entry();\n};\n"
    donor = _entropy_only_donor(
        {
            "include/entry.h": [
                {
                    "id": "op_move",
                    "op": "replace",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "in_class_declaration",
                    },
                    "removed": {"sha256": _digest(b"~Entry() { Flush(); }"), "size": 21},
                }
            ],
            "src/entry.cpp": [
                {
                    "id": "op_definition",
                    "op": "insert",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "qualified_definition_header",
                    },
                },
                {
                    "id": "op_dest",
                    "op": "insert",
                    "gen": {"k": "reloc", "range_identity": "Entry::~Entry"},
                },
            ],
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="does not reappear"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/entry.cpp",
            clean_sources={"include/entry.h": clean_header, "src/entry.cpp": b""},
            rendered_sources={"include/entry.h": rendered_header, "src/entry.cpp": b""},
        )


def test_entropy_only_member_signature_requires_matching_relocation() -> None:
    """A typed signature alone cannot authenticate deletion as a move."""
    removed = b"~Entry() { Flush(); }"
    clean_header = b"class Entry { public: " + removed + b" };\n"
    rendered_header = b"class Entry { public: ~Entry(); };\n"
    rendered_cpp = b"Entry::~Entry() { Flush(); }\n"
    donor = _entropy_only_donor(
        {
            "include/entry.h": [
                {
                    "id": "op_move",
                    "op": "replace",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "in_class_declaration",
                    },
                    "removed": {"sha256": _digest(removed), "size": len(removed)},
                }
            ],
            "src/entry.cpp": [
                {
                    "id": "op_wrong_dest",
                    "op": "insert",
                    "gen": {"k": "reloc", "range_identity": "Other::~Other"},
                },
            ],
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="matching authenticated relocation"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/entry.cpp",
            clean_sources={"include/entry.h": clean_header, "src/entry.cpp": b""},
            rendered_sources={
                "include/entry.h": rendered_header,
                "src/entry.cpp": rendered_cpp,
            },
        )


@pytest.mark.parametrize(
    ("definition_path", "definition_class"),
    [
        pytest.param(None, None, id="missing"),
        pytest.param("src/entry.cpp", "Other", id="wrong-member"),
        pytest.param("include/other.h", "Entry", id="wrong-destination"),
    ],
)
def test_entropy_only_member_relocation_requires_qualified_definition_at_destination(
    definition_path: str | None,
    definition_class: str | None,
) -> None:
    """A copied body is not a destructor definition without its matching header."""

    relocation = {
        "k": "reloc",
        "range_identity": "Entry::~Entry",
        "byte_destination": "src/entry.cpp",
    }
    operations: dict[str, list[dict[str, object]]] = {
        "include/entry.h": [
            {
                "id": "op_declaration",
                "op": "replace",
                "gen": {
                    "k": "member_sig",
                    "kind": "destructor",
                    "class_identifier": "Entry",
                    "member_identifier": "Entry",
                    "form": "in_class_declaration",
                },
                "removed": {"sha256": _digest(b"~Entry()"), "size": 8},
            },
            {
                "id": "op_body_source",
                "op": "delete",
                "gen": relocation,
                "removed": {"sha256": _digest(b" { Flush(); }"), "size": 13},
            },
        ],
        "src/entry.cpp": [
            {"id": "op_body_destination", "op": "insert", "gen": relocation},
        ],
    }
    rendered_sources = {
        "include/entry.h": b"class Entry { public: ~Entry(); };\n",
        "src/entry.cpp": b"void Other() { Flush(); }\n",
    }
    clean_sources = {
        "include/entry.h": b"class Entry { public: ~Entry() { Flush(); } };\n",
        "src/entry.cpp": b"",
    }
    if definition_path is not None:
        assert definition_class is not None
        operations.setdefault(definition_path, []).insert(
            0,
            {
                "id": "op_definition",
                "op": "insert",
                "gen": {
                    "k": "member_sig",
                    "kind": "destructor",
                    "class_identifier": definition_class,
                    "member_identifier": definition_class,
                    "form": "qualified_definition_header",
                },
            },
        )
        if definition_path not in rendered_sources:
            rendered_sources[definition_path] = b"Entry::~Entry()\n"
            clean_sources[definition_path] = b""

    donor = _entropy_only_donor(operations)

    with pytest.raises(
        SourceRefactorSemanticError,
        match="qualified definition header at its relocation destination",
    ):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/entry.cpp",
            clean_sources=clean_sources,
            rendered_sources=rendered_sources,
        )


def test_entropy_only_relocation_must_reappear_as_contiguous_tokens() -> None:
    """Unrelated code cannot supply scattered tokens for a claimed move."""
    removed = b"~Entry() { Flush(); }"
    clean_header = b"class Entry { public: " + removed + b" void Other(); };\n"
    rendered_header = b"class Entry { public: ~Entry(); void Other() { Flush(); } };\n"
    donor = _entropy_only_donor(
        {
            "include/entry.h": [
                {
                    "id": "op_move",
                    "op": "replace",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "in_class_declaration",
                    },
                    "removed": {"sha256": _digest(removed), "size": len(removed)},
                }
            ],
            "src/entry.cpp": [
                {
                    "id": "op_definition",
                    "op": "insert",
                    "gen": {
                        "k": "member_sig",
                        "kind": "destructor",
                        "class_identifier": "Entry",
                        "member_identifier": "Entry",
                        "form": "qualified_definition_header",
                    },
                },
                {
                    "id": "op_dest",
                    "op": "insert",
                    "gen": {"k": "reloc", "range_identity": "Entry::~Entry"},
                },
            ],
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="does not reappear"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/entry.cpp",
            clean_sources={"include/entry.h": clean_header, "src/entry.cpp": b""},
            rendered_sources={"include/entry.h": rendered_header, "src/entry.cpp": b""},
        )


def test_entropy_only_donor_may_elide_unreferenced_definition() -> None:
    """A complete function definition whose name survives nowhere may be
    removed (e.g. a beta-only function absent from the retail image)."""
    removed = b"MxU32 Actor::BetaOnly(int p_x)\n{\n\treturn p_x != 0;\n}\n"
    clean = b'#include "actor.h"\n\n' + removed + b"\nvoid Keep() {}\n"
    rendered = b'#include "actor.h"\n\n\nvoid Keep() {}\n'
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_beta",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(removed), "size": len(removed)},
                }
            ]
        }
    )

    proof = validate_donor_source_semantics(
        donor,
        [],
        owning_source="src/unit.cpp",
        clean_sources={"src/unit.cpp": clean},
        rendered_sources={"src/unit.cpp": rendered},
    )

    assert proof is None


def test_entropy_only_donor_must_not_elide_referenced_definition() -> None:
    removed = b"MxU32 Actor::BetaOnly(int p_x)\n{\n\treturn p_x != 0;\n}\n"
    clean = b'#include "actor.h"\n\n' + removed + b"\nvoid Keep() { BetaOnly(1); }\n"
    rendered = b'#include "actor.h"\n\n\nvoid Keep() { BetaOnly(1); }\n'
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_beta",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(removed), "size": len(removed)},
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="still referenced"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": clean},
            rendered_sources={"src/unit.cpp": rendered},
        )


def test_entropy_only_donor_must_not_elide_statement_text() -> None:
    """Plain statements are never admitted, even in a braced block."""
    removed = b"value = ComputeValue(5);"
    clean = b"void Keep() {\n\tvalue = ComputeValue(5);\n}\n"
    rendered = b"void Keep() {\n}\n"
    donor = _entropy_only_donor(
        {
            "src/unit.cpp": [
                {
                    "id": "op_stmt",
                    "op": "replace",
                    "gen": {"k": "lines", "n": 1},
                    "removed": {"sha256": _digest(removed), "size": len(removed)},
                }
            ]
        }
    )

    with pytest.raises(SourceRefactorSemanticError, match="non-prototype text"):
        validate_donor_source_semantics(
            donor,
            [],
            owning_source="src/unit.cpp",
            clean_sources={"src/unit.cpp": clean},
            rendered_sources={"src/unit.cpp": rendered},
        )
