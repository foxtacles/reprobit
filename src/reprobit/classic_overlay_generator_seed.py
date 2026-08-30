"""Seed and relocation-ring classic-overlay generators."""

from __future__ import annotations

import re
from collections.abc import Mapping

from reprobit.classic_overlay_cpp import _cpp_type, _render_cpp_type, _render_parameter
from reprobit.classic_overlay_generator_common import _string_array
from reprobit.classic_overlay_validation import (
    _array,
    _boolean,
    _fail,
    _identifier,
    _integer,
    _keys,
    _object,
)


def _member_identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"~?[A-Za-z_][A-Za-z0-9_]*", value) is None:
        _fail(f"{context} must be a C++ member identifier")
    return value


def _render_expression(value: object, context: str) -> str:
    expression = _object(value, context)
    kind = expression.get("kind")
    if kind == "integer_literal":
        _keys(expression, {"kind", "value"}, context)
        return str(
            _integer(expression.get("value"), f"{context}.value", minimum=0, maximum=(1 << 31) - 1)
        )
    if kind in {"null_cast", "null_cast_dereference"}:
        _keys(expression, {"kind", "type"}, context)
        rendered = f"({_render_cpp_type(_cpp_type(expression.get('type'), f'{context}.type'))}) 0"
        return "*" + rendered if kind == "null_cast_dereference" else rendered
    if kind == "identifier":
        _keys(expression, {"kind", "identifier"}, context)
        return _identifier(expression.get("identifier"), f"{context}.identifier")
    _fail(f"{context}.kind is unsupported")


def _render_seed_sequence(value: Mapping[str, object], context: str) -> bytes:
    declarations = _array(
        value.get("declarations"), f"{context}.declarations", minimum=1, maximum=4096
    )
    lines: list[str] = []
    for index, raw in enumerate(declarations):
        item_context = f"{context}.declarations[{index}]"
        item = _object(raw, item_context)
        kind = item.get("kind")
        if kind == "forward_record":
            _keys(item, {"kind", "tag", "identifier"}, item_context)
            tag = item.get("tag")
            if tag not in {"class", "struct", "union"}:
                _fail(f"{item_context}.tag differs")
            lines.append(
                f"{tag} {_identifier(item.get('identifier'), f'{item_context}.identifier')};"
            )
        elif kind == "extern_variable":
            _keys(item, {"kind", "identifier", "type"}, item_context)
            type_text = _render_cpp_type(_cpp_type(item.get("type"), f"{item_context}.type"))
            identifier = _identifier(item.get("identifier"), f"{item_context}.identifier")
            lines.append(f"extern {type_text} {identifier};")
        elif kind == "function_declaration":
            _keys(item, {"kind", "identifier", "parameters", "return_type"}, item_context)
            return_type = _render_cpp_type(
                _cpp_type(item.get("return_type"), f"{item_context}.return_type")
            )
            identifier = _identifier(item.get("identifier"), f"{item_context}.identifier")
            parameters = ", ".join(
                _render_parameter(parameter, f"{item_context}.parameters[{parameter_index}]")
                for parameter_index, parameter in enumerate(
                    _array(item.get("parameters"), f"{item_context}.parameters", maximum=16)
                )
            )
            lines.append(f"{return_type} {identifier}({parameters});")
        elif kind == "record_definition":
            _keys(item, {"kind", "identifier", "members", "tag"}, item_context)
            tag = item.get("tag")
            if tag not in {"class", "struct", "union"}:
                _fail(f"{item_context}.tag differs")
            identifier = _identifier(item.get("identifier"), f"{item_context}.identifier")
            lines.append(f"{tag} {identifier} {{")
            if tag == "class":
                lines.append("public:")
            for member_index, raw_member in enumerate(
                _array(item.get("members"), f"{item_context}.members", minimum=1, maximum=64)
            ):
                member_context = f"{item_context}.members[{member_index}]"
                member = _object(raw_member, member_context)
                _keys(
                    member,
                    {"identifier", "kind", "method_const", "parameters", "return_type", "storage"},
                    member_context,
                )
                member_kind = member.get("kind")
                if member_kind not in {"method", "constructor", "destructor"}:
                    _fail(f"{member_context}.kind differs")
                member_identifier = _member_identifier(
                    member.get("identifier"), f"{member_context}.identifier"
                )
                storage = member.get("storage")
                if storage not in {"ordinary", "static", "virtual"}:
                    _fail(f"{member_context}.storage differs")
                storage_text = f"{storage} " if storage in {"static", "virtual"} else ""
                raw_return = member.get("return_type")
                if raw_return is None:
                    if member_kind not in {"constructor", "destructor"}:
                        _fail(
                            f"{member_context}.return_type may be null only for "
                            "constructors/destructors"
                        )
                    return_text = ""
                else:
                    if member_kind != "method":
                        _fail(
                            f"{member_context}.return_type is invalid for a constructor/destructor"
                        )
                    return_text = (
                        _render_cpp_type(_cpp_type(raw_return, f"{member_context}.return_type"))
                        + " "
                    )
                parameters = ", ".join(
                    _render_parameter(parameter, f"{member_context}.parameters[{parameter_index}]")
                    for parameter_index, parameter in enumerate(
                        _array(member.get("parameters"), f"{member_context}.parameters", maximum=16)
                    )
                )
                method_const = (
                    " const"
                    if _boolean(member.get("method_const"), f"{member_context}.method_const")
                    else ""
                )
                lines.append(
                    f"\t{storage_text}{return_text}{member_identifier}({parameters}){method_const};"
                )
            lines.append("};")
        else:
            _fail(f"{item_context}.kind is unsupported")
    function_identifier = _identifier(
        value.get("function_identifier"), f"{context}.function_identifier"
    )
    lines.extend([f"void {function_identifier}()", "{"])
    for index, raw in enumerate(
        _array(value.get("statements"), f"{context}.statements", minimum=1, maximum=4096)
    ):
        item_context = f"{context}.statements[{index}]"
        item = _object(raw, item_context)
        kind = item.get("kind")
        if kind == "discarded_new":
            _keys(item, {"kind", "type"}, item_context)
            statement = "new " + _render_cpp_type(
                _cpp_type(item.get("type"), f"{item_context}.type")
            )
        elif kind == "free_call":
            _keys(item, {"kind", "function_identifier", "arguments"}, item_context)
            identifier = _identifier(
                item.get("function_identifier"), f"{item_context}.function_identifier"
            )
            arguments = ", ".join(
                _render_expression(argument, f"{item_context}.arguments[{argument_index}]")
                for argument_index, argument in enumerate(
                    _array(item.get("arguments"), f"{item_context}.arguments", maximum=16)
                )
            )
            statement = f"{identifier}({arguments})"
        elif kind in {"null_receiver_qualified_call", "qualified_call"}:
            required = {"kind", "qualifier", "member_identifier", "arguments"}
            if kind == "null_receiver_qualified_call":
                required.add("receiver_type")
            _keys(item, required, item_context)
            qualifier = _string_array(
                item.get("qualifier"), f"{item_context}.qualifier", minimum=1, maximum=16
            )
            statement_member = _member_identifier(
                item.get("member_identifier"), f"{item_context}.member_identifier"
            )
            arguments = ", ".join(
                _render_expression(argument, f"{item_context}.arguments[{argument_index}]")
                for argument_index, argument in enumerate(
                    _array(item.get("arguments"), f"{item_context}.arguments", maximum=16)
                )
            )
            call = f"{'::'.join(qualifier)}::{statement_member}({arguments})"
            if kind == "null_receiver_qualified_call":
                receiver = _render_cpp_type(
                    _cpp_type(item.get("receiver_type"), f"{item_context}.receiver_type")
                )
                statement = f"(({receiver}) 0)->{call}"
            else:
                statement = call
        elif kind == "volatile_local_binding":
            _keys(item, {"kind", "identifier", "initializer", "type"}, item_context)
            type_text = _render_cpp_type(_cpp_type(item.get("type"), f"{item_context}.type"))
            identifier = _identifier(item.get("identifier"), f"{item_context}.identifier")
            initializer = _render_expression(item.get("initializer"), f"{item_context}.initializer")
            statement = f"{type_text} volatile {identifier} = {initializer}"
        else:
            _fail(f"{item_context}.kind is unsupported")
        lines.append("\t" + statement + ";")
    lines.append("}")
    if value.get("undefined_binding_order") != "reverse_statement_order_msvc_4_20":
        _fail(f"{context}.undefined_binding_order differs")
    return ("\n".join(lines) + "\n").encode()


def _render_relocation_ring(value: Mapping[str, object], context: str) -> bytes:
    stem = _identifier(value.get("function_identifier_stem"), f"{context}.function_identifier_stem")
    count = _integer(
        value.get("function_count"), f"{context}.function_count", minimum=2, maximum=4096
    )
    width = _integer(
        value.get("function_identifier_width"),
        f"{context}.function_identifier_width",
        minimum=1,
        maximum=8,
    )
    reference_counts = _object(
        value.get("cyclic_successor_reference_count"),
        f"{context}.cyclic_successor_reference_count",
    )
    _keys(
        reference_counts,
        {"first_15", "remaining_9"},
        f"{context}.cyclic_successor_reference_count",
    )
    first_count = _integer(
        reference_counts.get("first_15"),
        f"{context}.cyclic_successor_reference_count.first_15",
        minimum=1,
        maximum=count - 1,
    )
    remaining_count = _integer(
        reference_counts.get("remaining_9"),
        f"{context}.cyclic_successor_reference_count.remaining_9",
        minimum=1,
        maximum=count - 1,
    )
    identifiers = [f"{stem}{index:0{width}d}" for index in range(count)]
    lines = [f"typedef void (*{stem}Fn)();", f"void {stem}Sink({stem}Fn);"]
    lines.extend(f"void {identifier}();" for identifier in identifiers)
    lines.extend([f"void {stem}Sink({stem}Fn p_fn)", "{", "\t(void) p_fn;", "}"])
    for index, identifier in enumerate(identifiers):
        references = first_count if index < 15 else remaining_count
        lines.extend([f"void {identifier}()", "{"])
        for distance in range(1, references + 1):
            lines.append(f"\t{stem}Sink({identifiers[(index + distance) % count]});")
        lines.append("}")
    return ("\n".join(lines) + "\n").encode()
