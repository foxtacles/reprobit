"""Closed dispatch for typed classic-overlay C++ generators."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath

from reprobit.classic_overlay_cpp import _cpp_type, _render_cpp_type, _render_parameter
from reprobit.classic_overlay_generator_common import _generator_contract, _string_array
from reprobit.classic_overlay_generator_declarations import (
    _condition_expression,
    _render_call_supplier,
    _render_declaration_generator,
    _render_record_header,
    _render_template_supplier,
)
from reprobit.classic_overlay_generator_seed import (
    _render_relocation_ring,
    _render_seed_sequence,
)
from reprobit.classic_overlay_generator_source import (
    _render_captured_tail,
    _render_constructor_allocation_lift,
    _render_dead_updates,
    _render_default_ctor_dead_updates,
    _render_fixed_array_fill,
    _render_fixed_array_shuffle_countdown,
    _render_for_initializer_declaration,
    _render_inclusive_extent,
    _render_member_signature,
)
from reprobit.classic_overlay_relocation import (
    _relocation_spec,
    _render_relocation_range,
)
from reprobit.classic.overlay_types import _Layout
from reprobit.classic_overlay_validation import (
    _array,
    _fail,
    _identifier,
    _integer,
    _keys,
    _object,
    _qualified,
    _relative_path,
    _safe_header,
    _seat_fragment,
    _string,
)


def _render_sequence(
    value: Mapping[str, object],
    context: str,
    *,
    relocation_ranges: Mapping[tuple[str, str], bytes] | None = None,
    allow_unresolved_relocation: bool = False,
) -> tuple[bytes, _Layout]:
    _keys(value, {"k", "items", "lines"}, context)
    physical_line_count = _integer(
        value.get("lines"), f"{context}.lines", minimum=1, maximum=2_000_000
    )
    raw_items = _array(value.get("items"), f"{context}.items", minimum=1, maximum=100_000)
    expanded: list[tuple[int, Mapping[str, object], str]] = []
    for index, raw in enumerate(raw_items):
        item_context = f"{context}.items[{index}]"
        item = _object(raw, item_context)
        if "line" not in item:
            _fail(f"{item_context} lacks its first line")
        first_line = _integer(
            item.get("line"), f"{item_context}.line", minimum=1, maximum=physical_line_count
        )
        child = dict(item)
        child.pop("line")
        if child.get("k") == "fwd_run":
            _keys(
                child,
                {"k", "stem", "first", "count"},
                item_context,
                optional={"width", "tag"},
            )
            stem = _identifier(child.get("stem"), f"{item_context}.stem")
            first = _integer(
                child.get("first"), f"{item_context}.first", minimum=0, maximum=1_000_000
            )
            count = _integer(child.get("count"), f"{item_context}.count", minimum=1, maximum=4096)
            width = _integer(
                child.get("width", len(str(first))),
                f"{item_context}.width",
                minimum=1,
                maximum=8,
            )
            for offset in range(count):
                forward: dict[str, object] = {
                    "k": "fwd",
                    "id": stem + str(first + offset).zfill(width),
                }
                if "tag" in child:
                    forward["tag"] = child["tag"]
                expanded.append((first_line + offset, forward, f"{item_context}[{offset}]"))
        else:
            expanded.append((first_line, child, item_context))
    grid = [b"\n"] * physical_line_count
    for first_line, expanded_child, item_context in expanded:
        fragment = _render_generator(
            expanded_child,
            item_context,
            relocation_ranges=relocation_ranges,
            allow_unresolved_relocation=allow_unresolved_relocation,
        )
        child_lines = fragment.splitlines(keepends=True)
        if first_line - 1 + len(child_lines) > len(grid) or any(
            not line.endswith(b"\n") for line in child_lines
        ):
            _fail(f"{item_context} leaves the sequence canvas")
        for offset, line in enumerate(child_lines, start=first_line - 1):
            if not line.strip():
                continue
            if grid[offset].strip() and grid[offset] != line:
                _fail(f"{item_context} conflicts with another nonblank child")
            grid[offset] = line
    return b"".join(grid), _Layout()


def _render_generator(
    raw: object,
    context: str,
    *,
    relocation_ranges: Mapping[tuple[str, str], bytes] | None = None,
    allow_unresolved_relocation: bool = False,
) -> bytes:
    value = _object(raw, context)
    kind = value.get("k")
    if not isinstance(kind, str):
        _fail(f"{context}.k must be a generator kind")
    if "line" in value:
        _fail(f"{context}.line is admitted only by a sequence parent")
    if kind == "member_sig":
        return _render_member_signature(value, context)
    if kind == "dead_updates":
        return _render_dead_updates(value, context)
    if kind == "default_ctor_dead_updates":
        return _render_default_ctor_dead_updates(value, context)
    if kind == "for_init_decl":
        return _render_for_initializer_declaration(value, context)
    if kind == "fixed_array_fill":
        return _render_fixed_array_fill(value, context)
    if kind == "fixed_array_shuffle_countdown":
        return _render_fixed_array_shuffle_countdown(value, context)
    if kind == "inclusive_extent":
        return _render_inclusive_extent(value, context)
    if kind == "ctor_alloc_lift":
        return _render_constructor_allocation_lift(value, context)
    if kind == "capture_tail":
        return _render_captured_tail(value, context)
    if kind == "reloc":
        spec = _relocation_spec(value, context)
        if relocation_ranges is None:
            if allow_unresolved_relocation:
                return b""
            _fail(f"{context} lacks an authenticated relocation range")
        payload = relocation_ranges.get((spec.source_operation_id, spec.range_dependency_id))
        if payload is None:
            _fail(f"{context} source relocation range is absent")
        return _render_relocation_range(payload, spec)
    if kind in {"fwd", "fwd_seq", "empty_class", "enum", "typedef", "proto", "class"}:
        semantic, layout = _render_declaration_generator(value, context, kind)
        return _seat_fragment(kind, semantic, layout)
    if kind == "seq":
        semantic, layout = _render_sequence(
            value,
            context,
            relocation_ranges=relocation_ranges,
            allow_unresolved_relocation=allow_unresolved_relocation,
        )
        return _seat_fragment(kind, semantic, layout)
    if kind == "lines":
        layout = _generator_contract(value, context, required={"n"})
        count = _integer(value.get("n"), f"{context}.n", minimum=1, maximum=4096)
        return _seat_fragment(kind, b"\n" * count, layout)
    if kind == "include":
        layout = _generator_contract(value, context, required={"header", "style"})
        header = _safe_header(value.get("header"), f"{context}.header")
        style = value.get("style")
        if style == "angle":
            semantic = f"#include <{header}>\n".encode()
        elif style == "quote":
            semantic = f'#include "{header}"\n'.encode()
        else:
            _fail(f"{context}.style is outside the closed enum")
        return _seat_fragment(kind, semantic, layout)
    if kind == "include_seat":
        layout = _generator_contract(
            value, context, required={"basename", "logical_header", "style"}
        )
        logical = _relative_path(value.get("logical_header"), f"{context}.logical_header")
        basename = _safe_header(value.get("basename"), f"{context}.basename")
        if PurePosixPath(logical).name != basename:
            _fail(f"{context}.basename differs from logical_header")
        style = value.get("style")
        if style == "quote":
            semantic = f'#include "{basename}"\n'.encode()
        elif style == "angle":
            semantic = f"#include <{basename}>\n".encode()
        else:
            _fail(f"{context}.style is outside the closed enum")
        return _seat_fragment(kind, semantic, layout)
    if kind == "empty_scopes":
        layout = _generator_contract(value, context, required={"scope_count"})
        count = _integer(
            value.get("scope_count"), f"{context}.scope_count", minimum=1, maximum=4096
        )
        return _seat_fragment(kind, b"\t{\n\t}\n" * count, layout)
    if kind == "noop_assign":
        layout = _generator_contract(value, context, required={"assignment_target", "repeat"})
        target = _identifier(value.get("assignment_target"), f"{context}.assignment_target")
        repeat = _integer(value.get("repeat"), f"{context}.repeat", minimum=1, maximum=4096)
        semantic = (f"\t{target} = {target} + 0;\n" * repeat).encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "size_asserts":
        layout = _generator_contract(value, context, required={"assertions"})
        rendered: list[bytes] = []
        for index, raw_assertion in enumerate(
            _array(value.get("assertions"), f"{context}.assertions", minimum=1, maximum=4096)
        ):
            item_context = f"{context}.assertions[{index}]"
            assertion = _object(raw_assertion, item_context)
            _keys(assertion, {"type", "size"}, item_context)
            type_name = _qualified(assertion.get("type"), f"{item_context}.type")
            size = _integer(
                assertion.get("size"), f"{item_context}.size", minimum=1, maximum=1 << 30
            )
            rendered.append(f"DECOMP_SIZE_ASSERT({type_name}, 0x{size:x})\n".encode())
        return _seat_fragment(kind, b"".join(rendered), layout)
    if kind == "cond":
        layout = _generator_contract(
            value,
            context,
            required={
                "branch_policy",
                "branch_topology",
                "condition",
                "directive_sequence",
                "physical_line_count",
            },
        )
        if value.get("branch_policy") != "typed_declarations_only":
            _fail(f"{context}.branch_policy differs")
        topology = value.get("branch_topology")
        if topology not in {"ifdef_endif", "ifdef_else_endif"}:
            _fail(f"{context}.branch_topology differs")
        condition = _object(value.get("condition"), f"{context}.condition")
        _keys(condition, {"macro_identifier", "polarity"}, f"{context}.condition")
        macro = _identifier(
            condition.get("macro_identifier"), f"{context}.condition.macro_identifier"
        )
        if condition.get("polarity") != "ifdef":
            _fail(f"{context}.condition.polarity differs")
        count = _integer(
            value.get("physical_line_count"),
            f"{context}.physical_line_count",
            minimum=2,
            maximum=4096,
        )
        canvas = [b""] * count
        directives: list[str] = []
        for index, raw_directive in enumerate(
            _array(
                value.get("directive_sequence"),
                f"{context}.directive_sequence",
                minimum=2,
                maximum=3,
            )
        ):
            item_context = f"{context}.directive_sequence[{index}]"
            directive = _object(raw_directive, item_context)
            directive_name = directive.get("directive")
            if directive_name == "ifdef":
                _keys(directive, {"directive", "macro_identifier", "relative_line"}, item_context)
                if directive.get("macro_identifier") != macro:
                    _fail(f"{item_context}.macro_identifier differs")
                text = f"#ifdef {macro}".encode()
            elif directive_name in {"else", "endif"}:
                _keys(directive, {"directive", "relative_line"}, item_context)
                text = f"#{directive_name}".encode()
            else:
                _fail(f"{item_context}.directive differs")
            line = _integer(
                directive.get("relative_line"),
                f"{item_context}.relative_line",
                minimum=1,
                maximum=count,
            )
            if canvas[line - 1]:
                _fail(f"{item_context}.relative_line is duplicated")
            canvas[line - 1] = text
            directives.append(directive_name)
        expected = ["ifdef", "endif"] if topology == "ifdef_endif" else ["ifdef", "else", "endif"]
        if directives != expected:
            _fail(f"{context}.directive_sequence differs from branch_topology")
        return _seat_fragment(kind, b"\n".join(canvas) + b"\n", layout)
    if kind == "local_ids":
        layout = _generator_contract(value, context, required={"function", "identifiers", "type"})
        _qualified(value.get("function"), f"{context}.function")
        identifiers = _string_array(
            value.get("identifiers"), f"{context}.identifiers", minimum=1, maximum=4096
        )
        type_text = _render_cpp_type(_cpp_type(value.get("type"), f"{context}.type"))
        return _seat_fragment(kind, f"\t{type_text} {', '.join(identifiers)};\n".encode(), layout)
    if kind == "member_probe":
        layout = _generator_contract(
            value,
            context,
            required={
                "arguments",
                "function_identifier",
                "inline_depth",
                "qualified_member",
                "receiver_type",
                "return_type",
            },
        )
        return_type = _render_cpp_type(
            _cpp_type(value.get("return_type"), f"{context}.return_type")
        )
        receiver = _render_cpp_type(
            _cpp_type(value.get("receiver_type"), f"{context}.receiver_type")
        )
        function = _identifier(value.get("function_identifier"), f"{context}.function_identifier")
        member = _string_array(
            value.get("qualified_member"), f"{context}.qualified_member", minimum=2, maximum=16
        )
        depth = _integer(
            value.get("inline_depth"), f"{context}.inline_depth", minimum=0, maximum=255
        )
        arguments = _array(value.get("arguments"), f"{context}.arguments", minimum=1, maximum=1)
        argument = _object(arguments[0], f"{context}.arguments[0]")
        _keys(argument, {"kind", "value"}, f"{context}.arguments[0]")
        if argument.get("kind") != "integer":
            _fail(f"{context}.arguments[0].kind differs")
        argument_value = _integer(
            argument.get("value"), f"{context}.arguments[0].value", minimum=0, maximum=(1 << 31) - 1
        )
        semantic = (
            f"#pragma inline_depth({depth})\n"
            f"{return_type} {function}({receiver}* p_bitmap)\n"
            "{\n"
            f"\treturn p_bitmap->{'::'.join(member)}({argument_value});\n"
            "}\n"
            "#pragma inline_depth()\n"
        ).encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "cursor_probe":
        layout = _generator_contract(
            value,
            context,
            required={
                "container_type",
                "cursor_type",
                "element_type",
                "function_identifier",
                "operation",
            },
        )
        if value.get("operation") != "delete_each_cursor_element":
            _fail(f"{context}.operation differs")
        container = _qualified(value.get("container_type"), f"{context}.container_type")
        cursor = _qualified(value.get("cursor_type"), f"{context}.cursor_type")
        element = _qualified(value.get("element_type"), f"{context}.element_type")
        function = _identifier(value.get("function_identifier"), f"{context}.function_identifier")
        semantic = (
            f"void {function}({container}* p_partlist)\n"
            "{\n"
            f"\t{cursor} cursor(p_partlist);\n"
            f"\t{element}* part;\n"
            "\twhile (cursor.Next(part)) {\n"
            "\t\tdelete part;\n"
            "\t}\n"
            "}\n"
        ).encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "local_probe":
        layout = _generator_contract(
            value,
            context,
            required={"function_identifier", "local_identifier", "local_type", "operation"},
        )
        if value.get("operation") != "emit_local_object_destructor":
            _fail(f"{context}.operation differs")
        function = _identifier(value.get("function_identifier"), f"{context}.function_identifier")
        local = _identifier(value.get("local_identifier"), f"{context}.local_identifier")
        local_type = _qualified(value.get("local_type"), f"{context}.local_type")
        semantic = f"void {function}()\n{{\n\t{local_type} {local};\n}}\n".encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "crt_pull":
        layout = _generator_contract(
            value, context, required={"deallocation_operator", "function_identifier", "parameter"}
        )
        if value.get("deallocation_operator") != "array_delete":
            _fail(f"{context}.deallocation_operator differs")
        function = _identifier(value.get("function_identifier"), f"{context}.function_identifier")
        parameter = _object(value.get("parameter"), f"{context}.parameter")
        rendered_parameter = _render_parameter(parameter, f"{context}.parameter")
        parameter_identifier = _identifier(
            parameter.get("identifier"), f"{context}.parameter.identifier"
        )
        semantic = (
            f"void {function}({rendered_parameter})\n{{\n\tdelete[] {parameter_identifier};\n}}\n"
        ).encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "seed_seq":
        layout = _generator_contract(
            value,
            context,
            required={
                "declarations",
                "function_identifier",
                "statements",
                "undefined_binding_order",
            },
        )
        return _seat_fragment(kind, _render_seed_sequence(value, context), layout)
    if kind == "template_supplier":
        layout = _generator_contract(
            value,
            context,
            required={
                "container_alias",
                "include_identity",
                "logical_path",
                "prefix_declarations",
                "probes",
            },
        )
        _relative_path(value.get("logical_path"), f"{context}.logical_path")
        return _seat_fragment(kind, _render_template_supplier(value, context), layout)
    if kind == "call_supplier":
        layout = _generator_contract(
            value,
            context,
            required={
                "global_definitions",
                "include_identity",
                "logical_path",
                "prefix_declarations",
                "relocated_ranges",
                "wrapper",
            },
        )
        _relative_path(value.get("logical_path"), f"{context}.logical_path")
        return _seat_fragment(kind, _render_call_supplier(value, context), layout)
    if kind == "reloc_ring":
        layout = _generator_contract(
            value,
            context,
            required={
                "cyclic_successor_reference_count",
                "function_count",
                "function_identifier_stem",
                "function_identifier_width",
                "logical_path",
            },
        )
        _relative_path(value.get("logical_path"), f"{context}.logical_path")
        return _seat_fragment(kind, _render_relocation_ring(value, context), layout)
    if kind == "record_header":
        layout = _generator_contract(value, context, required={"logical_path", "typed_recipe"})
        _relative_path(value.get("logical_path"), f"{context}.logical_path")
        return _seat_fragment(kind, _render_record_header(value, context), layout)
    if kind == "assert_reseat":
        insertion_fields = {
            "authentic_function",
            "carrier_conditions",
            "carrier_function",
            "dead_local",
            "restored_conditions",
        }
        if insertion_fields <= set(value):
            layout = _generator_contract(value, context, required=insertion_fields)
            _qualified(value.get("authentic_function"), f"{context}.authentic_function")
            _qualified(value.get("carrier_function"), f"{context}.carrier_function")
            carrier_conditions = [
                _condition_expression(item, f"{context}.carrier_conditions[{index}]")
                for index, item in enumerate(
                    _array(
                        value.get("carrier_conditions"),
                        f"{context}.carrier_conditions",
                        minimum=1,
                        maximum=64,
                    )
                )
            ]
            _string_array(
                value.get("restored_conditions"),
                f"{context}.restored_conditions",
                minimum=1,
                maximum=64,
            )
            dead_local = _object(value.get("dead_local"), f"{context}.dead_local")
            _keys(dead_local, {"identifiers", "type"}, f"{context}.dead_local")
            identifiers = _string_array(
                dead_local.get("identifiers"),
                f"{context}.dead_local.identifiers",
                minimum=1,
                maximum=64,
            )
            type_text = _render_cpp_type(
                _cpp_type(dead_local.get("type"), f"{context}.dead_local.type")
            )
            semantic = (
                f"\t{type_text} {', '.join(identifiers)};\n\n"
                + "".join(f"\tassert({condition});\n" for condition in carrier_conditions)
            ).encode()
            return _seat_fragment(kind, semantic, layout)
        layout = _generator_contract(value, context, required={"condition", "restore_seat"})
        _identifier(value.get("condition"), f"{context}.condition")
        restore = _object(value.get("restore_seat"), f"{context}.restore_seat")
        restore_kind = restore.get("kind")
        if restore_kind == "after_new_assignment":
            _keys(
                restore,
                {"constructed_type", "kind", "target_identifier"},
                f"{context}.restore_seat",
            )
            _cpp_type(restore.get("constructed_type"), f"{context}.restore_seat.constructed_type")
            _identifier(
                restore.get("target_identifier"), f"{context}.restore_seat.target_identifier"
            )
        elif restore_kind == "after_local_declaration":
            _keys(restore, {"identifier", "kind", "type"}, f"{context}.restore_seat")
            _identifier(restore.get("identifier"), f"{context}.restore_seat.identifier")
            _cpp_type(restore.get("type"), f"{context}.restore_seat.type")
        elif restore_kind == "after_local_declaration_sequence":
            _keys(restore, {"declarations", "kind"}, f"{context}.restore_seat")
            for index, raw_declaration in enumerate(
                _array(
                    restore.get("declarations"),
                    f"{context}.restore_seat.declarations",
                    minimum=1,
                    maximum=64,
                )
            ):
                declaration = _object(
                    raw_declaration, f"{context}.restore_seat.declarations[{index}]"
                )
                _keys(
                    declaration,
                    {"identifier", "type"},
                    f"{context}.restore_seat.declarations[{index}]",
                )
                _identifier(
                    declaration.get("identifier"),
                    f"{context}.restore_seat.declarations[{index}].identifier",
                )
                _cpp_type(
                    declaration.get("type"),
                    f"{context}.restore_seat.declarations[{index}].type",
                )
        else:
            _fail(f"{context}.restore_seat.kind is unsupported")
        return _seat_fragment(kind, b"", layout)
    if kind == "const_pool":
        layout = _generator_contract(value, context, required={"include_identity", "logical_path"})
        include_identity = _safe_header(
            value.get("include_identity"), f"{context}.include_identity"
        )
        _relative_path(value.get("logical_path"), f"{context}.logical_path")
        return _seat_fragment(kind, f'#include "{include_identity}"\n'.encode(), layout)
    if kind == "literal_alias":
        layout = _generator_contract(
            value,
            context,
            required={"literal", "local_identifier", "owner_function"},
            optional={"type", "use_ordinal"},
        )
        literal = _string(value.get("literal"), f"{context}.literal", maximum=256)
        if not literal.isascii() or any(character in literal for character in '"\\\n\r'):
            _fail(f"{context}.literal is not a safe string literal body")
        local_identifier = _identifier(value.get("local_identifier"), f"{context}.local_identifier")
        _qualified(value.get("owner_function"), f"{context}.owner_function")
        if ("type" in value) == ("use_ordinal" in value):
            _fail(f"{context} must declare exactly one alias definition or alias use")
        if "type" in value:
            type_text = _render_cpp_type(_cpp_type(value.get("type"), f"{context}.type"))
            semantic = f'\t{type_text} {local_identifier} = "{literal}";\n'.encode()
        else:
            _integer(value.get("use_ordinal"), f"{context}.use_ordinal", minimum=1, maximum=4096)
            semantic = local_identifier.encode()
        return _seat_fragment(kind, semantic, layout)
    if kind == "extern_run":
        layout = _generator_contract(value, context, required={"prefix", "count", "width"})
        prefix = _identifier(value.get("prefix"), f"{context}.prefix")
        count = _integer(value.get("count"), f"{context}.count", minimum=1, maximum=999)
        width = _integer(value.get("width"), f"{context}.width", minimum=1, maximum=3)
        if count > 10**width:
            _fail(f"{context}.width cannot represent the count")
        semantic = "".join(
            f"extern int {prefix}{number:0{width}d};\n" for number in range(count)
        ).encode()
        return _seat_fragment(kind, semantic, layout)
    _fail(f"{context}.k is unsupported: {kind!r}")


def render_classic_overlay_generator(
    generator: Mapping[str, object],
) -> bytes:
    """Validate and render one standalone typed schema-v2 generator."""

    return _render_generator(generator, "generator")
