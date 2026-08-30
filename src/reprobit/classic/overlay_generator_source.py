"""Source-refactor classic-overlay generators."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from reprobit.classic.overlay_cpp import (
    _cpp_type,
    _CppType,
    _parameter,
    _render_cpp_type,
)
from reprobit.classic.overlay_generator_common import _generator_contract, _string_array
from reprobit.classic.overlay_validation import (
    _array,
    _fail,
    _identifier,
    _integer,
    _keys,
    _layout,
    _object,
    _seat_fragment,
    _string,
)


def _source_indentation(value: object, context: str) -> str:
    indentation = _string(value, context, maximum=32)
    if not indentation.isascii() or set(indentation) - {" ", "\t"}:
        _fail(f"{context} must contain only ASCII horizontal whitespace")
    return indentation


def _value_cpp_type(value: object, context: str, *, named: bool = False) -> _CppType:
    parsed = _cpp_type(value, context)
    if (
        parsed.base_const
        or parsed.indirection
        or parsed.trailing_const
        or (named and parsed.base_kind != "named")
    ):
        _fail(f"{context} must be a canonical non-const value type")
    return parsed


def _render_member_signature(value: Mapping[str, object], context: str) -> bytes:
    member_kind = value.get("kind")
    form = value.get("form")
    if member_kind not in {"constructor", "destructor"}:
        _fail(f"{context}.kind is outside the closed member-signature enum")
    if form not in {"in_class_declaration", "qualified_definition_header"}:
        _fail(f"{context}.form is outside the closed member-signature enum")
    required = {"class_identifier", "member_identifier", "kind", "form"}
    optional: set[str] = set()
    if member_kind == "constructor":
        required.add("parameters")
        optional.add("specifiers")
    layout = _generator_contract(value, context, required=required, optional=optional)
    class_identifier = _identifier(value.get("class_identifier"), f"{context}.class_identifier")
    member_identifier = _identifier(value.get("member_identifier"), f"{context}.member_identifier")
    if class_identifier != member_identifier:
        _fail(f"{context}.member_identifier must equal its class identifier")
    if member_kind == "destructor":
        semantic = (
            f"~{member_identifier}();"
            if form == "in_class_declaration"
            else f"{class_identifier}::~{member_identifier}()"
        ).encode()
        return _seat_fragment("member_sig", semantic, layout)

    parameters: list[str] = []
    identifiers: set[str] = set()
    for index, raw_parameter in enumerate(
        _array(value.get("parameters"), f"{context}.parameters", minimum=1, maximum=4)
    ):
        parameter_context = f"{context}.parameters[{index}]"
        parameter_type, identifier = _parameter(raw_parameter, parameter_context)
        if identifier is None or identifier in identifiers:
            _fail(f"{parameter_context} must have a distinct identifier")
        identifiers.add(identifier)
        parameters.append(f"{_render_cpp_type(parameter_type)} {identifier}")
    prefix = ""
    if "specifiers" in value:
        specifiers = _array(value.get("specifiers"), f"{context}.specifiers", minimum=1, maximum=1)
        if specifiers != ["inline"] or form != "qualified_definition_header":
            _fail(f"{context}.specifiers must be exactly ['inline'] on a qualified header")
        prefix = "inline "
    joined = ", ".join(parameters)
    semantic = (
        f"{member_identifier}({joined});"
        if form == "in_class_declaration"
        else f"{prefix}{class_identifier}::{member_identifier}({joined})"
    ).encode()
    return _seat_fragment("member_sig", semantic, layout)


def _render_dead_updates(value: Mapping[str, object], context: str) -> bytes:
    layout = _generator_contract(value, context, required={"id", "initial", "increment", "repeat"})
    identifier = _identifier(value.get("id"), f"{context}.id")
    initial = _integer(
        value.get("initial"), f"{context}.initial", minimum=-(1 << 31), maximum=(1 << 31) - 1
    )
    increment = _integer(
        value.get("increment"),
        f"{context}.increment",
        minimum=-(1 << 31),
        maximum=(1 << 31) - 1,
    )
    repeat = _integer(value.get("repeat"), f"{context}.repeat", minimum=0, maximum=64)
    if increment == 0 or not -(1 << 31) <= initial + increment * repeat <= (1 << 31) - 1:
        _fail(f"{context} update sequence is stationary or can overflow signed int")
    updates = f"{identifier} = {identifier} + {increment}; " * repeat
    semantic = f"{{ int {identifier} = {initial}; {updates}}}".encode()
    return _seat_fragment("dead_updates", semantic, layout)


def _render_default_ctor_dead_updates(value: Mapping[str, object], context: str) -> bytes:
    _keys(value, {"k", "class", "id", "initial", "increment", "repeat"}, context)
    class_identifier = _identifier(value.get("class"), f"{context}.class")
    identifier = _identifier(value.get("id"), f"{context}.id")
    initial = _integer(
        value.get("initial"), f"{context}.initial", minimum=-(1 << 31), maximum=(1 << 31) - 1
    )
    increment = _integer(
        value.get("increment"),
        f"{context}.increment",
        minimum=-(1 << 31),
        maximum=(1 << 31) - 1,
    )
    repeat = _integer(value.get("repeat"), f"{context}.repeat", minimum=0, maximum=64)
    if increment == 0 or not -(1 << 31) <= initial + increment * repeat <= (1 << 31) - 1:
        _fail(f"{context} update sequence is stationary or can overflow signed int")
    updates = f"{identifier} = {identifier} + {increment}; " * repeat
    return f"\t{class_identifier}() {{ int {identifier} = {initial}; {updates}}}\n".encode()


def _render_for_initializer_declaration(value: Mapping[str, object], context: str) -> bytes:
    _keys(
        value,
        {"k", "form", "type", "id", "container", "begin", "end", "declaration_indent"},
        context,
    )
    form = value.get("form")
    if form not in {"standalone_then_assignment_v1", "declaration_in_initializer_v1"}:
        _fail(f"{context}.form is outside the closed enum")
    indentation = _source_indentation(
        value.get("declaration_indent"), f"{context}.declaration_indent"
    )
    iterator_type = _render_cpp_type(_value_cpp_type(value.get("type"), f"{context}.type"))
    identifier = _identifier(value.get("id"), f"{context}.id")
    container = _identifier(value.get("container"), f"{context}.container")
    begin = _identifier(value.get("begin"), f"{context}.begin")
    end = _identifier(value.get("end"), f"{context}.end")
    if form == "declaration_in_initializer_v1":
        return (
            f"{indentation}for ({iterator_type} {identifier} = {container}.{begin}(); "
            f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
        ).encode()
    return (
        f"{indentation}{iterator_type} {identifier};\n\n"
        f"{indentation}for ({identifier} = {container}.{begin}(); "
        f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
    ).encode()


def _render_fixed_array_fill(value: Mapping[str, object], context: str) -> bytes:
    _keys(
        value,
        {"k", "array", "index", "index_type", "count", "value", "declaration_indent"},
        context,
    )
    array = _identifier(value.get("array"), f"{context}.array")
    index = _identifier(value.get("index"), f"{context}.index")
    if array == index:
        _fail(f"{context}.index must differ from the array")
    index_type = _render_cpp_type(_value_cpp_type(value.get("index_type"), f"{context}.index_type"))
    count = _integer(value.get("count"), f"{context}.count", minimum=1, maximum=4096)
    if type(value.get("value")) is not int or value.get("value") != -1:
        _fail(f"{context}.value must be exactly -1")
    indentation = _source_indentation(
        value.get("declaration_indent"), f"{context}.declaration_indent"
    )
    return (
        f"{indentation}for ({index_type} {index} = 0; {index} < {count}; "
        f"{index}++) {array}[{index}] = -1;\n"
    ).encode()


def _render_fixed_array_shuffle_countdown(value: Mapping[str, object], context: str) -> bytes:
    _keys(
        value,
        {
            "k",
            "array",
            "index",
            "index_type",
            "pointer",
            "element_type",
            "swap",
            "swap_type",
            "temporary",
            "temporary_type",
            "random_function",
            "count",
            "declaration_indent",
        },
        context,
    )
    names = {
        field: _identifier(value.get(field), f"{context}.{field}")
        for field in ("array", "index", "pointer", "swap", "temporary", "random_function")
    }
    if len(set(names.values())) != len(names):
        _fail(f"{context} shuffle identifier roles must be distinct")
    index_type = _value_cpp_type(value.get("index_type"), f"{context}.index_type")
    element_type = _value_cpp_type(value.get("element_type"), f"{context}.element_type")
    swap_type = _value_cpp_type(value.get("swap_type"), f"{context}.swap_type")
    temporary_type = _value_cpp_type(value.get("temporary_type"), f"{context}.temporary_type")
    if index_type != swap_type or element_type != temporary_type:
        _fail(f"{context} paired shuffle types differ")
    count = _integer(value.get("count"), f"{context}.count", minimum=2, maximum=4096)
    indentation = _source_indentation(
        value.get("declaration_indent"), f"{context}.declaration_indent"
    )
    inner = indentation + "\t"
    array = names["array"]
    index = names["index"]
    pointer = names["pointer"]
    swap = names["swap"]
    temporary = names["temporary"]
    random_function = names["random_function"]
    element_text = _render_cpp_type(element_type)
    swap_text = _render_cpp_type(swap_type)
    temporary_text = _render_cpp_type(temporary_type)
    return (
        f"{indentation}{element_text}* {pointer} = {array};\n"
        f"{indentation}for ({index} = {count}; {index} != 0; {index}--) {{\n"
        f"{inner}{pointer}++;\n"
        f"{inner}{swap_text} {swap} = {random_function}() % {count};\n"
        f"{inner}{temporary_text} {temporary} = {pointer}[-1];\n"
        f"{inner}{pointer}[-1] = {array}[{swap}];\n"
        f"{inner}{array}[{swap}] = {temporary};\n"
        f"{indentation}}}\n"
    ).encode()


def _render_inclusive_extent(value: Mapping[str, object], context: str) -> bytes:
    _keys(
        value,
        {
            "k",
            "type",
            "id",
            "source",
            "seed_extent_accessor",
            "upper_endpoint_accessor",
            "lower_endpoint_accessor",
            "destination",
            "declaration_indent",
            "barrier",
        },
        context,
    )
    if value.get("barrier") != "msvc_i386_empty_inline_assembly_v1":
        _fail(f"{context}.barrier is outside the closed enum")
    source = _object(value.get("source"), f"{context}.source")
    _keys(source, {"object", "aggregate_accessor"}, f"{context}.source")
    destination = _object(value.get("destination"), f"{context}.destination")
    _keys(destination, {"object", "member"}, f"{context}.destination")
    coordinate_type = _render_cpp_type(_value_cpp_type(value.get("type"), f"{context}.type"))
    identifier = _identifier(value.get("id"), f"{context}.id")
    source_object = _identifier(source.get("object"), f"{context}.source.object")
    aggregate = _identifier(
        source.get("aggregate_accessor"), f"{context}.source.aggregate_accessor"
    )
    destination_object = _identifier(destination.get("object"), f"{context}.destination.object")
    destination_member = _identifier(destination.get("member"), f"{context}.destination.member")
    accessors = [
        _identifier(value.get(field), f"{context}.{field}")
        for field in (
            "seed_extent_accessor",
            "upper_endpoint_accessor",
            "lower_endpoint_accessor",
        )
    ]
    if len(set(accessors)) != 3 or aggregate in accessors:
        _fail(f"{context} extent accessor roles must be distinct")
    if identifier in {source_object, aggregate, destination_object, *accessors}:
        _fail(f"{context}.id collides with another authenticated role")
    indentation = _source_indentation(
        value.get("declaration_indent"), f"{context}.declaration_indent"
    )
    seed_accessor, upper_accessor, lower_accessor = accessors
    del seed_accessor  # Authenticates the replaced seed form but is not emitted.
    source_expression = f"{source_object}.{aggregate}()"
    destination_expression = f"{destination_object}.{destination_member}"
    return (
        f"{indentation}{coordinate_type} {identifier} = "
        f"{source_expression}.{upper_accessor}() - "
        f"{source_expression}.{lower_accessor}();\n"
        f"{indentation}++{identifier};\n"
        "#if defined(_MSC_VER) && defined(_M_IX86)\n"
        f"{indentation}__asm {{\n"
        f"{indentation}}}\n"
        "#endif\n"
        f"{indentation}{destination_expression} = {identifier};\n"
    ).encode()


def _render_constructor_allocation_lift(value: Mapping[str, object], context: str) -> bytes:
    _keys(
        value,
        {
            "k",
            "role",
            "class_identifier",
            "parameter_identifier",
            "buffer_member",
            "buffer_cast_type",
            "element_type",
            "extent_function",
            "copy_function",
            "null_members",
            "caller_result_identifier",
            "caller_result_type",
            "null_argument_position",
            "iterator_type",
            "iterator_identifier",
            "container_identifier",
            "find_member",
            "declaration_indent",
        },
        context,
    )
    role = value.get("role")
    if role not in {"call_site", "constructor_body"}:
        _fail(f"{context}.role is outside the closed enum")
    identifier_fields = (
        "class_identifier",
        "parameter_identifier",
        "buffer_member",
        "extent_function",
        "copy_function",
        "caller_result_identifier",
        "iterator_identifier",
        "container_identifier",
        "find_member",
    )
    names = {
        field: _identifier(value.get(field), f"{context}.{field}") for field in identifier_fields
    }
    null_members = _string_array(
        value.get("null_members"), f"{context}.null_members", minimum=1, maximum=4
    )
    if len(set(names.values()) | set(null_members)) != len(names) + len(null_members):
        _fail(f"{context} allocation-lift identifier roles must be distinct")
    element_type = _value_cpp_type(value.get("element_type"), f"{context}.element_type")
    buffer_cast_type = _cpp_type(value.get("buffer_cast_type"), f"{context}.buffer_cast_type")
    caller_result_type = _cpp_type(value.get("caller_result_type"), f"{context}.caller_result_type")
    if (
        buffer_cast_type.base_kind != element_type.base_kind
        or buffer_cast_type.name != element_type.name
        or buffer_cast_type.arguments != element_type.arguments
        or buffer_cast_type.base_const != element_type.base_const
        or buffer_cast_type.indirection != ("pointer",)
        or buffer_cast_type.trailing_const
        or caller_result_type != buffer_cast_type
    ):
        _fail(f"{context} buffer types do not describe one pointer to the element type")
    iterator_type = _render_cpp_type(
        _value_cpp_type(value.get("iterator_type"), f"{context}.iterator_type", named=True)
    )
    _integer(
        value.get("null_argument_position"),
        f"{context}.null_argument_position",
        minimum=0,
        maximum=len(null_members),
    )
    indentation = _source_indentation(
        value.get("declaration_indent"), f"{context}.declaration_indent"
    )
    if role == "call_site":
        return (
            f"{indentation}{iterator_type} {names['iterator_identifier']} = "
            f"{names['container_identifier']}.{names['find_member']}"
            f"({names['class_identifier']}({names['parameter_identifier']}));\n"
        ).encode()
    element_text = _render_cpp_type(element_type)
    cast_text = _render_cpp_type(buffer_cast_type)
    lines = [
        f"\t{names['buffer_member']} = new {element_text}"
        f"[{names['extent_function']}({names['parameter_identifier']}) + 1];",
        f"\t{names['copy_function']}(({cast_text}) {names['buffer_member']}, "
        f"{names['parameter_identifier']});",
        *(f"\t{member} = NULL;" for member in null_members),
    ]
    return ("\n{\n" + "\n".join(lines) + "\n}\n\n").encode()


def _render_captured_tail(value: Mapping[str, object], context: str) -> bytes:
    role = value.get("role")
    role_fields = {
        "capture_declaration": {"role", "type", "capture", "declaration_indent"},
        "capture_assignment": {"role", "capture", "source", "declaration_indent"},
        "read_reseat": {"role", "capture", "source"},
        "return_to_goto": {"role", "source", "label"},
        "tail_return": {"role", "capture", "label", "declaration_indent"},
    }
    fields = role_fields.get(cast(str, role))
    if fields is None:
        _fail(f"{context}.role is outside the closed enum")
    expected = {"k", *fields}
    if role in {"read_reseat", "return_to_goto"}:
        expected.add("nl")
    _keys(value, expected, context)
    if role in {"read_reseat", "return_to_goto"} and value.get("nl") is not False:
        _fail(f"{context}.nl must be false for an inline tail fragment")
    layout = _layout(value, context)
    capture = (
        _identifier(value.get("capture"), f"{context}.capture") if "capture" in value else None
    )
    source = _identifier(value.get("source"), f"{context}.source") if "source" in value else None
    label = _identifier(value.get("label"), f"{context}.label") if "label" in value else None
    indentation = (
        _source_indentation(value.get("declaration_indent"), f"{context}.declaration_indent")
        if "declaration_indent" in value
        else None
    )
    if role == "capture_declaration":
        pointer_type = _cpp_type(value.get("type"), f"{context}.type")
        if pointer_type.indirection != ("pointer",) or pointer_type.trailing_const:
            _fail(f"{context}.type must be one writable pointer type")
        semantic = f"{indentation}{_render_cpp_type(pointer_type)} {capture};\n".encode()
    elif role == "capture_assignment":
        semantic = f"{indentation}{capture} = {source};\n".encode()
    elif role == "read_reseat":
        semantic = cast(str, capture).encode()
    elif role == "return_to_goto":
        semantic = f"goto {label};".encode()
    else:
        semantic = f"\n{label}:\n{indentation}return {capture};\n".encode()
    return _seat_fragment("capture_tail", semantic, layout)
