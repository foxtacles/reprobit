"""Declaration, template, and call-supplier classic-overlay generators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from reprobit.classic_overlay_cpp import (
    _cpp_type,
    _identifier_run,
    _render_cpp_type,
    _render_parameter,
)
from reprobit.classic_overlay_generator_common import _generator_contract, _string_array
from reprobit.classic_overlay_types import _Layout
from reprobit.classic_overlay_validation import (
    _array,
    _boolean,
    _fail,
    _identifier,
    _integer,
    _keys,
    _object,
    _safe_header,
)


def _expand_lean_names(value: object, context: str, *, maximum: int = 4096) -> list[str]:
    raw_items = _array(value, context, minimum=1, maximum=maximum)
    names: list[str] = []
    for index, raw in enumerate(raw_items):
        item_context = f"{context}[{index}]"
        if isinstance(raw, str):
            names.append(_identifier(raw, item_context))
            continue
        item = _object(raw, item_context)
        _keys(item, {"stem", "first", "count"}, item_context, optional={"width"})
        stem = _identifier(item.get("stem"), f"{item_context}.stem")
        first = _integer(item.get("first"), f"{item_context}.first", minimum=0, maximum=1_000_000)
        count = _integer(item.get("count"), f"{item_context}.count", minimum=1, maximum=4096)
        width = _integer(
            item.get("width", len(str(first))),
            f"{item_context}.width",
            minimum=1,
            maximum=8,
        )
        names.extend(stem + str(number).zfill(width) for number in range(first, first + count))
    if len(names) > maximum or len(set(names)) != len(names):
        _fail(f"{context} is too large or expands to duplicate identifiers")
    return names


def _render_declaration_generator(
    value: Mapping[str, object], context: str, kind: str
) -> tuple[bytes, _Layout]:
    if kind == "fwd":
        layout = _generator_contract(value, context, required={"id"}, optional={"tag"})
        tag = value.get("tag", "class")
        if tag not in {"class", "struct", "union"}:
            _fail(f"{context}.tag is outside the closed enum")
        return f"{tag} {_identifier(value.get('id'), f'{context}.id')};\n".encode(), layout
    if kind == "fwd_seq":
        layout = _generator_contract(value, context, required={"identifiers"}, optional={"tag"})
        tag = value.get("tag", "class")
        if tag not in {"class", "struct", "union"}:
            _fail(f"{context}.tag is outside the closed enum")
        identifiers = _identifier_run(value.get("identifiers"), f"{context}.identifiers")
        return (
            " ".join(f"{tag} {identifier};" for identifier in identifiers) + "\n"
        ).encode(), layout
    if kind == "empty_class":
        layout = _generator_contract(value, context, required={"id"}, optional={"tag"})
        tag = value.get("tag", "class")
        if tag not in {"class", "struct"}:
            _fail(f"{context}.tag is outside the closed enum")
        return f"{tag} {_identifier(value.get('id'), f'{context}.id')} {{}};\n".encode(), layout
    if kind == "enum":
        layout = _generator_contract(
            value, context, required={"id", "members"}, optional={"trailing_comma"}
        )
        identifier = _identifier(value.get("id"), f"{context}.id")
        enum_members = _expand_lean_names(value.get("members"), f"{context}.members")
        trailing = value.get("trailing_comma", False)
        if type(trailing) is not bool:
            _fail(f"{context}.trailing_comma must be boolean")
        lines = [f"enum {identifier} {{"]
        for index, member in enumerate(enum_members):
            comma = "," if index + 1 < len(enum_members) or trailing else ""
            lines.append(f"\t{member}{comma}")
        lines.append("};")
        return ("\n".join(lines) + "\n").encode(), layout
    if kind == "typedef":
        layout = _generator_contract(value, context, required={"id", "aliased_type"})
        identifier = _identifier(value.get("id"), f"{context}.id")
        aliased = _render_cpp_type(_cpp_type(value.get("aliased_type"), f"{context}.aliased_type"))
        return f"\ttypedef {aliased} {identifier};\n".encode(), layout
    if kind == "proto":
        layout = _generator_contract(value, context, required={"id", "return_type", "parameters"})
        identifier = _identifier(value.get("id"), f"{context}.id")
        return_type = _render_cpp_type(
            _cpp_type(value.get("return_type"), f"{context}.return_type")
        )
        parameters = ", ".join(
            _render_parameter(raw, f"{context}.parameters[{index}]")
            for index, raw in enumerate(
                _array(value.get("parameters"), f"{context}.parameters", maximum=16)
            )
        )
        return f"{return_type} {identifier}({parameters});\n".encode(), layout
    if kind != "class":
        _fail(f"{context}.k is not a declaration generator")
    layout = _generator_contract(
        value,
        context,
        required={"id", "members"},
        optional={"tag", "access", "inline"},
    )
    tag = value.get("tag", "class")
    if tag not in {"class", "struct"}:
        _fail(f"{context}.tag is outside the closed enum")
    identifier = _identifier(value.get("id"), f"{context}.id")
    inline_default = value.get("inline", False)
    if type(inline_default) is not bool:
        _fail(f"{context}.inline must be boolean")
    raw_members = _array(value.get("members"), f"{context}.members", minimum=1, maximum=4096)
    class_members: list[tuple[str, str, bool]] = []
    for index, raw in enumerate(raw_members):
        item_context = f"{context}.members[{index}]"
        if isinstance(raw, str):
            class_members.append(("definition", _identifier(raw, item_context), inline_default))
        else:
            item = _object(raw, item_context)
            if set(item) == {"decl"}:
                class_members.append(
                    ("declaration", _identifier(item.get("decl"), f"{item_context}.decl"), False)
                )
            elif set(item) == {"id", "inline"} and item.get("inline") is True:
                class_members.append(
                    ("definition", _identifier(item.get("id"), f"{item_context}.id"), True)
                )
            elif "stem" in item:
                for name in _expand_lean_names([dict(item)], item_context):
                    class_members.append(("definition", name, inline_default))
            else:
                _fail(f"{item_context} has an unsupported member form")
    transitions: dict[int, str] = {}
    for index, raw in enumerate(
        _array(
            value.get("access", []),
            f"{context}.access",
            maximum=len(class_members) + 1,
        )
    ):
        item = _object(raw, f"{context}.access[{index}]")
        _keys(item, {"access", "before_member_index"}, f"{context}.access[{index}]")
        access = item.get("access")
        if access not in {"public", "protected", "private"}:
            _fail(f"{context}.access[{index}].access differs")
        before = _integer(
            item.get("before_member_index"),
            f"{context}.access[{index}].before_member_index",
            minimum=0,
            maximum=len(class_members) - 1,
        )
        if before in transitions:
            _fail(f"{context}.access duplicates a transition")
        transitions[before] = access
    lines = [f"{tag} {identifier} {{"]
    for index, (member_kind, member_identifier, inline_member) in enumerate(class_members):
        if index in transitions:
            lines.append(f"{transitions[index]}:")
        if member_kind == "definition":
            lines.append(f"\t{'inline ' if inline_member else ''}void {member_identifier}() {{}}")
        else:
            lines.append(f"\tvoid {member_identifier}();")
    lines.append("};")
    return ("\n".join(lines) + "\n").encode(), layout


def _condition_expression(value: object, context: str) -> str:
    condition = _identifier(value, context)
    if condition.startswith("address_of_"):
        target = _identifier(condition.removeprefix("address_of_"), context)
        return f"&{target}"
    if condition.endswith("_null_tautology"):
        target = _identifier(condition.removesuffix("_null_tautology"), context)
        return f"{target} == NULL || {target} != NULL"
    return condition


def _render_record_header(value: Mapping[str, object], context: str) -> bytes:
    recipe = _object(value.get("typed_recipe"), f"{context}.typed_recipe")
    kind = recipe.get("kind")
    guard = _identifier(recipe.get("guard"), f"{context}.typed_recipe.guard")
    lines = [f"#ifndef {guard}", f"#define {guard}"]
    if kind == "enum_one_enumerator":
        _keys(recipe, {"guard", "items", "kind"}, f"{context}.typed_recipe")
        for index, raw in enumerate(
            _array(recipe.get("items"), f"{context}.typed_recipe.items", minimum=1, maximum=4096)
        ):
            item = _object(raw, f"{context}.typed_recipe.items[{index}]")
            _keys(item, {"name", "enumerator"}, f"{context}.typed_recipe.items[{index}]")
            name = _identifier(item.get("name"), f"{context}.typed_recipe.items[{index}].name")
            enumerator = _identifier(
                item.get("enumerator"), f"{context}.typed_recipe.items[{index}].enumerator"
            )
            lines.extend([f"enum {name} {{", f"\t{enumerator}", "};"])
    elif kind == "unused_class_with_inline_void_methods":
        _keys(
            recipe,
            {"guard", "items", "kind", "method_identifier_policy", "methods_per_class"},
            f"{context}.typed_recipe",
        )
        policy = recipe.get("method_identifier_policy")
        if policy not in {"single_unindexed_record", "zero_based_indexed_record"}:
            _fail(f"{context}.typed_recipe.method_identifier_policy differs")
        methods = _integer(
            recipe.get("methods_per_class"),
            f"{context}.typed_recipe.methods_per_class",
            minimum=1,
            maximum=4096,
        )
        identifiers = _string_array(recipe.get("items"), f"{context}.typed_recipe.items", minimum=1)
        for identifier in identifiers:
            lines.append(f"class {identifier} {{")
            for index in range(methods):
                method = "Record" if policy == "single_unindexed_record" else f"Record{index}"
                lines.append(f"\tinline void {method}() {{}}")
            lines.append("};")
    else:
        _fail(f"{context}.typed_recipe.kind is unsupported")
    lines.append("#endif")
    return ("\n".join(lines) + "\n").encode()


def _validate_prefix_declarations(value: object, context: str) -> dict[str, object]:
    prefix = _object(value, context)
    required = {
        "forward_class_identifiers",
        "empty_class_identifiers",
        "enum_declarations",
        "value_counter_class_identifiers",
        "range_class_identifiers",
    }
    _keys(prefix, required, context)
    result: dict[str, object] = {}
    for key in (
        "forward_class_identifiers",
        "empty_class_identifiers",
        "value_counter_class_identifiers",
        "range_class_identifiers",
    ):
        result[key] = _identifier_run(prefix.get(key), f"{context}.{key}", allow_list=True)
    enum_declarations: list[tuple[str, str, int, int]] = []
    for index, raw in enumerate(
        _array(prefix.get("enum_declarations"), f"{context}.enum_declarations", maximum=4096)
    ):
        item_context = f"{context}.enum_declarations[{index}]"
        item = _object(raw, item_context)
        _keys(item, {"identifier", "enumerator", "value"}, item_context)
        expression = _object(item.get("value"), f"{item_context}.value")
        _keys(expression, {"kind", "lhs", "rhs"}, f"{item_context}.value")
        if expression.get("kind") != "left_shift":
            _fail(f"{item_context}.value.kind differs")
        enum_declarations.append(
            (
                _identifier(item.get("identifier"), f"{item_context}.identifier"),
                _identifier(item.get("enumerator"), f"{item_context}.enumerator"),
                _integer(
                    expression.get("lhs"),
                    f"{item_context}.value.lhs",
                    minimum=0,
                    maximum=(1 << 31) - 1,
                ),
                _integer(expression.get("rhs"), f"{item_context}.value.rhs", minimum=0, maximum=31),
            )
        )
    result["enum_declarations"] = enum_declarations
    return result


def _render_template_supplier(value: Mapping[str, object], context: str) -> bytes:
    prefix = _validate_prefix_declarations(
        value.get("prefix_declarations"), f"{context}.prefix_declarations"
    )
    lines: list[str] = []
    for identifier in cast(list[str], prefix["forward_class_identifiers"]):
        lines.append(f"class {identifier};")
    for identifier in cast(list[str], prefix["empty_class_identifiers"]):
        lines.append(f"class {identifier} {{}};")
    for identifier, enumerator, lhs, rhs in cast(
        list[tuple[str, str, int, int]], prefix["enum_declarations"]
    ):
        lines.extend([f"enum {identifier} {{", f"\t{enumerator} = {lhs} << {rhs}", "};"])
    for identifier in cast(list[str], prefix["value_counter_class_identifiers"]):
        lines.extend(
            [
                f"class {identifier} {{",
                "public:",
                "\tint GetValue() { return m_value; }",
                "private:",
                "\tint m_value;",
                "};",
            ]
        )
    for identifier in cast(list[str], prefix["range_class_identifiers"]):
        lines.extend(
            [
                f"class {identifier} {{",
                "public:",
                "\tint GetFirst() { return m_first; }",
                "\tint GetLast() { return m_last; }",
                "private:",
                "\tint m_first;",
                "\tint m_last;",
                "};",
            ]
        )
    include_identity = _safe_header(value.get("include_identity"), f"{context}.include_identity")
    lines.append(f'#include "{include_identity}"')
    alias = _object(value.get("container_alias"), f"{context}.container_alias")
    _keys(alias, {"identifier", "type"}, f"{context}.container_alias")
    alias_identifier = _identifier(alias.get("identifier"), f"{context}.container_alias.identifier")
    alias_type = _cpp_type(alias.get("type"), f"{context}.container_alias.type")
    if (
        alias_type.base_kind == "template"
        and len(alias_type.arguments) > 1
        and not alias_type.base_const
        and not alias_type.indirection
        and not alias_type.trailing_const
    ):
        lines.append(f"typedef {'::'.join(alias_type.name)}<")
        lines.extend("\t" + _render_cpp_type(argument) + "," for argument in alias_type.arguments)
        lines[-1] = lines[-1][:-1]
        lines.append(f"> {alias_identifier};")
    else:
        lines.append(f"typedef {_render_cpp_type(alias_type)} {alias_identifier};")
    for index, raw in enumerate(
        _array(value.get("probes"), f"{context}.probes", minimum=1, maximum=64)
    ):
        item_context = f"{context}.probes[{index}]"
        probe = _object(raw, item_context)
        _keys(
            probe,
            {"base_type", "member_pointer", "probe_identifier", "target_qualified_identifier"},
            item_context,
        )
        probe_identifier = _identifier(
            probe.get("probe_identifier"), f"{item_context}.probe_identifier"
        )
        base_type = _render_cpp_type(_cpp_type(probe.get("base_type"), f"{item_context}.base_type"))
        target = _string_array(
            probe.get("target_qualified_identifier"),
            f"{item_context}.target_qualified_identifier",
            minimum=2,
            maximum=16,
        )
        pointer = _object(probe.get("member_pointer"), f"{item_context}.member_pointer")
        _keys(
            pointer,
            {"alias_identifier", "kind", "method_const", "owner_type", "parameters", "return_type"},
            f"{item_context}.member_pointer",
        )
        if pointer.get("kind") != "member_function_pointer":
            _fail(f"{item_context}.member_pointer.kind differs")
        pointer_alias = _identifier(
            pointer.get("alias_identifier"), f"{item_context}.member_pointer.alias_identifier"
        )
        owner_type = _render_cpp_type(
            _cpp_type(pointer.get("owner_type"), f"{item_context}.member_pointer.owner_type")
        )
        return_type = _render_cpp_type(
            _cpp_type(pointer.get("return_type"), f"{item_context}.member_pointer.return_type")
        )
        parameters = ", ".join(
            _render_parameter(
                parameter, f"{item_context}.member_pointer.parameters[{parameter_index}]"
            )
            for parameter_index, parameter in enumerate(
                _array(
                    pointer.get("parameters"),
                    f"{item_context}.member_pointer.parameters",
                    maximum=16,
                )
            )
        )
        method_const = (
            " const"
            if _boolean(pointer.get("method_const"), f"{item_context}.member_pointer.method_const")
            else ""
        )
        lines.extend(
            [
                f"struct {probe_identifier} : public {base_type} {{",
                f"\ttypedef {return_type} ({owner_type}::*{pointer_alias})"
                f"({parameters}){method_const};",
                f"\tstatic {pointer_alias} Get();",
                "};",
                f"{probe_identifier}::{pointer_alias} {probe_identifier}::Get()",
                "{",
                f"\treturn &{'::'.join(target)};",
                "}",
            ]
        )
    return ("\n".join(lines) + "\n").encode()


def _render_call_supplier(value: Mapping[str, object], context: str) -> bytes:
    prefix = _validate_prefix_declarations(
        value.get("prefix_declarations"), f"{context}.prefix_declarations"
    )
    if any(
        prefix[name]
        for name in (
            "empty_class_identifiers",
            "enum_declarations",
            "value_counter_class_identifiers",
            "range_class_identifiers",
        )
    ):
        _fail(f"{context}.prefix_declarations carries unsupported call-supplier declarations")
    relocated = _array(value.get("relocated_ranges"), f"{context}.relocated_ranges", maximum=64)
    globals_ = _array(value.get("global_definitions"), f"{context}.global_definitions", maximum=64)
    if relocated or globals_:
        _fail(
            f"{context} requests source-range/global-definition payloads; "
            "use the authenticated relocation facility instead"
        )
    lines = [
        f"class {identifier};"
        for identifier in cast(list[str], prefix["forward_class_identifiers"])
    ]
    include_identity = _safe_header(value.get("include_identity"), f"{context}.include_identity")
    lines.append(f'#include "{include_identity}"')
    wrapper = _object(value.get("wrapper"), f"{context}.wrapper")
    _keys(wrapper, {"function_identifier", "operation", "parameter"}, f"{context}.wrapper")
    if wrapper.get("operation") != "erase_begin_iterator":
        _fail(f"{context}.wrapper.operation differs")
    function_identifier = _identifier(
        wrapper.get("function_identifier"), f"{context}.wrapper.function_identifier"
    )
    parameter = _object(wrapper.get("parameter"), f"{context}.wrapper.parameter")
    rendered_parameter = _render_parameter(parameter, f"{context}.wrapper.parameter")
    parameter_identifier = _identifier(
        parameter.get("identifier"), f"{context}.wrapper.parameter.identifier"
    )
    lines.extend(
        [
            f"void {function_identifier}({rendered_parameter})",
            "{",
            f"\t{parameter_identifier}.erase({parameter_identifier}.begin());",
            "}",
        ]
    )
    return ("\n".join(lines) + "\n").encode()
