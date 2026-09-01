"""Donor-private source refactor semantics: for-initializer, fill, shuffle and range proofs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .source_refactor_semantics_schema import (
    _IDENTIFIER_RE,
    _identifier,
    _integer,
    _keys,
    _need,
    _object,
    _pin,
    _significant,
    _source,
    _string,
    _token_text,
    _type_text,
    _type_tokens,
)
from .source_refactor_semantics_seats import (
    _class_level_range,
    _include_edge,
    _lexical_stack,
    _line,
    _owner_from_mangled,
    _require_identifier_fresh_at_seat,
    _require_integral_type,
    _source_owner,
    _unique_bytes,
    _unique_class_body,
    _unique_tokens,
)


def _for_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes, str]:
    _keys(
        gen,
        {"k", "form", "type", "id", "container", "begin", "end", "declaration_indent"},
        "for-initializer refactor",
    )
    form = gen["form"]
    _need(
        form in {"standalone_then_assignment_v1", "declaration_in_initializer_v1"},
        "for-initializer form differs",
    )
    indent = _string(gen["declaration_indent"], "for-initializer indentation")
    type_text = _type_text(gen["type"], "for-initializer type")
    identifier = _identifier(gen["id"], "for-initializer identifier")
    container = _identifier(gen["container"], "for-initializer container")
    begin = _identifier(gen["begin"], "for-initializer begin member")
    end = _identifier(gen["end"], "for-initializer end member")
    in_initializer = (
        f"{indent}for ({type_text} {identifier} = {container}.{begin}(); "
        f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
    ).encode("ascii")
    standalone = (
        f"{indent}{type_text} {identifier};\n\n"
        f"{indent}for ({identifier} = {container}.{begin}(); "
        f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
    ).encode("ascii")
    return (
        (in_initializer, standalone, identifier)
        if form == "standalone_then_assignment_v1"
        else (standalone, in_initializer, identifier)
    )


def _prove_for_initializer(
    clean_target: bytes, donor_target: bytes, gen: Mapping[str, object]
) -> None:
    baseline, output, identifier = _for_fragments(gen)
    start = _unique_bytes(clean_target, baseline, "for-initializer seed form")
    _unique_bytes(donor_target, output, "for-initializer donor form")
    tokens = _significant(clean_target)
    opening_positions = [
        index
        for index, (token, token_start, _end) in enumerate(tokens)
        if token == "{" and start <= token_start < start + len(baseline)
    ]
    _need(len(opening_positions) == 1, "for-initializer loop opening differs")
    depth = 0
    loop_end = None
    for token, _token_start, token_end in tokens[opening_positions[0] :]:
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                loop_end = token_end
                break
    _need(loop_end is not None, "for-initializer loop is unbalanced")
    uses = [token_start for token, token_start, _end in tokens if token == identifier]
    _need(
        len(uses) >= 4 and all(start <= item < cast(int, loop_end) for item in uses),
        "for-initializer variable escapes its loop",
    )


def _fill_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    _keys(
        gen,
        {"k", "array", "index", "index_type", "count", "value", "declaration_indent"},
        "fixed-array fill",
    )
    array = _identifier(gen["array"], "fixed-array fill array")
    index = _identifier(gen["index"], "fixed-array fill index")
    index_type = _type_text(gen["index_type"], "fixed-array fill index type")
    count = _integer(gen["count"], "fixed-array fill count")
    _need(gen["value"] == -1 and count > 0, "fixed-array fill value/count differs")
    indent = _string(gen["declaration_indent"], "fixed-array fill indentation")
    return (
        f"{indent}memset({array}, -1, sizeof({array}));\n".encode("ascii"),
        (
            f"{indent}for ({index_type} {index} = 0; {index} < {count}; "
            f"{index}++) {array}[{index}] = -1;\n"
        ).encode("ascii"),
    )


def _prove_fixed_fill(
    *,
    clean_sources: Mapping[str, bytes],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _fill_fragments(gen)
    _unique_bytes(clean_target, baseline, "fixed-array fill seed form")
    _unique_bytes(donor_target, output, "fixed-array fill donor form")
    array = cast(str, gen["array"])
    index = cast(str, gen["index"])
    tokens = _significant(clean_target)
    _need(not any(token == index for token, _, _ in tokens), "fixed-array fill index is not fresh")
    expected_uses = sum(token == array for token, _, _ in _significant(baseline))
    _need(
        expected_uses == 2 and sum(token == array for token, _, _ in tokens) == 2,
        "fixed-array fill member is shadowed or used outside its statement",
    )

    declaration = _object(proof.get("array_declaration"), "fixed-array declaration witness")
    _keys(
        declaration,
        {
            "path",
            "source_sha256",
            "owner",
            "array",
            "element_type",
            "extent",
            "direct_include_range_pin",
            "declaration_range_pin",
        },
        "fixed-array declaration witness",
    )
    element_type = _type_text(declaration["element_type"], "fixed-array element type")
    _need(
        declaration["array"] == array and declaration["extent"] == gen["count"],
        "fixed-array bound differs from its declaration",
    )
    owner = _identifier(declaration["owner"], "fixed-array declaration owner")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "fixed-array owner"),
        "fixed-array declaration owner differs from the target",
    )
    _source_owner(clean_target, owner, "fixed-array target")
    header_path, header, _spec = _source(
        clean_sources, declaration, "fixed-array declaration header"
    )
    _require_integral_type(clean_sources, header_path, element_type, "fixed-array element type")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        header_path,
        declaration["direct_include_range_pin"],
        "fixed-array unit-to-header",
    )
    header_tokens, _start, opening, closing = _unique_class_body(
        header, owner, "fixed-array owner class"
    )
    member_range = _class_level_range(
        header_tokens,
        opening,
        closing,
        [
            *_type_tokens(element_type, "fixed-array element type"),
            array,
            "[",
            str(gen["count"]),
            "]",
            ";",
        ],
        "fixed-array member declaration",
    )
    _pin(
        _line(header, member_range),
        declaration["declaration_range_pin"],
        "fixed-array member declaration",
    )


def _shuffle_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    required = {
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
    }
    _keys(gen, required, "fixed-array shuffle")
    names = {
        name: _identifier(gen[name], f"fixed-array shuffle {name}")
        for name in ("array", "index", "pointer", "swap", "temporary", "random_function")
    }
    _need(len(set(names.values())) == len(names), "fixed-array shuffle roles collide")
    index_type = _type_text(gen["index_type"], "fixed-array shuffle index type")
    element_type = _type_text(gen["element_type"], "fixed-array shuffle element type")
    swap_type = _type_text(gen["swap_type"], "fixed-array shuffle swap type")
    temporary_type = _type_text(gen["temporary_type"], "fixed-array shuffle temporary type")
    _need(
        index_type == swap_type and element_type == temporary_type,
        "fixed-array shuffle paired types differ",
    )
    count = _integer(gen["count"], "fixed-array shuffle count")
    _need(count >= 2, "fixed-array shuffle count differs")
    indent = _string(gen["declaration_indent"], "fixed-array shuffle indentation")
    inner = indent + "\t"
    array, index, pointer = names["array"], names["index"], names["pointer"]
    swap, temporary, random_function = names["swap"], names["temporary"], names["random_function"]
    baseline = (
        f"{indent}for ({index} = 0; {index} < {count}; {index}++) {{\n"
        f"{inner}{swap_type} {swap} = {random_function}() % {count};\n"
        f"{inner}{temporary_type} {temporary} = {array}[{index}];\n"
        f"{inner}{array}[{index}] = {array}[{swap}];\n"
        f"{inner}{array}[{swap}] = {temporary};\n"
        f"{indent}}}\n"
    ).encode("ascii")
    output = (
        f"{indent}{element_type}* {pointer} = {array};\n"
        f"{indent}for ({index} = {count}; {index} != 0; {index}--) {{\n"
        f"{inner}{pointer}++;\n"
        f"{inner}{swap_type} {swap} = {random_function}() % {count};\n"
        f"{inner}{temporary_type} {temporary} = {pointer}[-1];\n"
        f"{inner}{pointer}[-1] = {array}[{swap}];\n"
        f"{inner}{array}[{swap}] = {temporary};\n"
        f"{indent}}}\n"
    ).encode("ascii")
    return baseline, output


def _prove_shuffle(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _shuffle_fragments(gen)
    input_start = _unique_bytes(clean_target, baseline, "fixed-array shuffle seed form")
    _unique_bytes(donor_target, output, "fixed-array shuffle donor form")
    input_end = input_start + len(baseline)
    witness = _object(proof.get("semantic_witness"), "fixed-array shuffle witness")
    _keys(
        witness,
        {
            "source_owner",
            "array_member",
            "element_type",
            "extent",
            "index_identifier",
            "index_type",
            "owner_header",
            "base_header",
            "types_header",
            "next_index_overwrite_range_pin",
        },
        "fixed-array shuffle witness",
    )
    _need(
        witness["array_member"] == gen["array"]
        and witness["element_type"] == gen["element_type"] == gen["temporary_type"]
        and witness["index_identifier"] == gen["index"]
        and witness["index_type"] == gen["index_type"] == gen["swap_type"]
        and witness["extent"] == gen["count"],
        "fixed-array shuffle roles/types/extent differ",
    )
    owner = _identifier(witness["source_owner"], "fixed-array shuffle owner")
    _need(
        owner
        == _owner_from_mangled(proof.get("source_owner_mangled"), "fixed-array shuffle owner"),
        "fixed-array shuffle target owner differs",
    )
    _source_owner(clean_target, owner, "fixed-array shuffle target")
    tokens = _significant(clean_target)
    pointer = cast(str, gen["pointer"])
    _need(
        not any(token == pointer for token, _, _ in tokens),
        "fixed-array shuffle pointer is not fresh",
    )
    for identifier in (cast(str, gen["swap"]), cast(str, gen["temporary"])):
        expected = sum(token == identifier for token, _, _ in _significant(baseline))
        positions = [start for token, start, _ in tokens if token == identifier]
        _need(
            expected > 0
            and len(positions) == expected
            and all(input_start <= item < input_end for item in positions),
            f"fixed-array shuffle local {identifier!r} escapes its loop",
        )
    index_type = cast(str, gen["index_type"])
    index_identifier = cast(str, gen["index"])
    _decl_index, declaration_start, _decl_end = _unique_tokens(
        tokens,
        [*_type_tokens(index_type, "fixed-array shuffle index type"), index_identifier, ";"],
        "fixed-array shuffle index declaration",
    )
    _need(declaration_start < input_start, "fixed-array shuffle index is declared after use")
    next_lines = [
        line for line in clean_target[input_end:].splitlines(keepends=True) if _token_text(line)
    ]
    _need(bool(next_lines), "fixed-array shuffle has no following index overwrite")
    next_line = next_lines[0]
    _pin(next_line, witness["next_index_overwrite_range_pin"], "fixed-array shuffle next overwrite")
    _need(
        _token_text(next_line)[:6] == ["for", "(", index_identifier, "=", "0", ";"],
        "fixed-array shuffle index is read before overwrite",
    )
    next_start = clean_target.index(next_line, input_end)
    _need(
        _lexical_stack(tokens, declaration_start, "fixed-array shuffle")
        == _lexical_stack(tokens, input_start, "fixed-array shuffle")
        == _lexical_stack(tokens, next_start, "fixed-array shuffle"),
        "fixed-array shuffle declaration/use/overwrite scopes differ",
    )

    header_specs: dict[str, tuple[set[str], dict[str, object]]] = {
        "owner_header": (
            {
                "path",
                "source_sha256",
                "unit_include_range_pin",
                "base_include_range_pin",
                "array_declaration_range_pin",
                "member_block_range_pin",
            },
            {},
        ),
        "base_header": ({"path", "source_sha256", "types_include_range_pin"}, {}),
        "types_header": (
            {
                "path",
                "source_sha256",
                "element_typedef_range_pin",
                "index_typedef_range_pin",
            },
            {},
        ),
    }
    loaded: dict[str, tuple[str, bytes, dict[str, object]]] = {}
    for name, (keys, _unused) in header_specs.items():
        path, data, spec = _source(clean_sources, witness.get(name), f"shuffle {name}")
        _keys(spec, keys, f"shuffle {name}")
        _need(path not in overlaid_paths, f"shuffle witness header {path!r} is overlaid")
        loaded[name] = (path, data, spec)
    owner_path, owner_data, owner_spec = loaded["owner_header"]
    base_path, base_data, base_spec = loaded["base_header"]
    types_path, types_data, types_spec = loaded["types_header"]
    _need(len({owner_path, base_path, types_path}) == 3, "shuffle witness headers repeat")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "shuffle unit-to-owner",
    )
    _include_edge(
        clean_sources,
        owner_path,
        owner_data,
        base_path,
        owner_spec["base_include_range_pin"],
        "shuffle owner-to-base",
    )
    _include_edge(
        clean_sources,
        base_path,
        base_data,
        types_path,
        base_spec["types_include_range_pin"],
        "shuffle base-to-types",
    )
    owner_tokens, _owner_start, owner_open, owner_close = _unique_class_body(
        owner_data, owner, "shuffle owner class"
    )
    member_range = _class_level_range(
        owner_tokens,
        owner_open,
        owner_close,
        [
            *_type_tokens(witness["element_type"], "shuffle element type"),
            cast(str, witness["array_member"]),
            "[",
            str(witness["extent"]),
            "]",
            ";",
        ],
        "shuffle array member",
    )
    declaration_line = _line(owner_data, member_range)
    _pin(declaration_line, owner_spec["array_declaration_range_pin"], "shuffle array member")
    declaration_line_start = owner_data.rfind(b"\n", 0, member_range[0]) + 1
    block_start = owner_data.rfind(b"\n", 0, max(0, declaration_line_start - 1)) + 1
    first_end = owner_data.find(b"\n", member_range[1])
    second_end = owner_data.find(b"\n", first_end + 1) if first_end >= 0 else -1
    _need(second_end >= 0, "shuffle member block is unterminated")
    _pin(
        owner_data[block_start : second_end + 1],
        owner_spec["member_block_range_pin"],
        "shuffle member block",
    )
    type_tokens = _significant(types_data)
    element = cast(str, witness["element_type"])
    index_type_text = cast(str, witness["index_type"])
    for name, underlying, pin_name in (
        (element, ["unsigned", "short"], "element_typedef_range_pin"),
        (index_type_text, ["signed", "int"], "index_typedef_range_pin"),
    ):
        _index, start, end = _unique_tokens(
            type_tokens, ["typedef", *underlying, name, ";"], f"shuffle typedef {name}"
        )
        _pin(_line(types_data, (start, end)), types_spec[pin_name], f"shuffle typedef {name}")


def _inclusive_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    _keys(
        gen,
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
        "inclusive extent",
    )
    _need(
        gen["barrier"] == "msvc_i386_empty_inline_assembly_v1", "inclusive-extent barrier differs"
    )
    source = _object(gen["source"], "inclusive-extent source")
    destination = _object(gen["destination"], "inclusive-extent destination")
    _keys(source, {"object", "aggregate_accessor"}, "inclusive-extent source")
    _keys(destination, {"object", "member"}, "inclusive-extent destination")
    coordinate_type = _type_text(gen["type"], "inclusive-extent coordinate type")
    identifier = _identifier(gen["id"], "inclusive-extent local")
    source_object = _identifier(source["object"], "inclusive-extent source object")
    aggregate = _identifier(source["aggregate_accessor"], "inclusive-extent aggregate accessor")
    destination_object = _identifier(destination["object"], "inclusive-extent destination object")
    destination_member = _identifier(destination["member"], "inclusive-extent destination member")
    seed = _identifier(gen["seed_extent_accessor"], "inclusive-extent seed accessor")
    upper = _identifier(gen["upper_endpoint_accessor"], "inclusive-extent upper accessor")
    lower = _identifier(gen["lower_endpoint_accessor"], "inclusive-extent lower accessor")
    indent = _string(gen["declaration_indent"], "inclusive-extent indentation")
    source_expression = f"{source_object}.{aggregate}()"
    destination_expression = f"{destination_object}.{destination_member}"
    baseline = f"{indent}{destination_expression} = {source_expression}.{seed}();\n".encode("ascii")
    output = (
        f"{indent}{coordinate_type} {identifier} = {source_expression}.{upper}() - "
        f"{source_expression}.{lower}();\n"
        f"{indent}++{identifier};\n"
        "#if defined(_MSC_VER) && defined(_M_IX86)\n"
        f"{indent}__asm {{\n"
        f"{indent}}}\n"
        "#endif\n"
        f"{indent}{destination_expression} = {identifier};\n"
    ).encode("ascii")
    return baseline, output


def _prove_inclusive(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _inclusive_fragments(gen)
    baseline_position = _unique_bytes(clean_target, baseline, "inclusive-extent seed form")
    _unique_bytes(donor_target, output, "inclusive-extent donor form")
    witness = _object(proof.get("semantic_witness"), "inclusive-extent witness")
    _keys(
        witness,
        {
            "source_owner",
            "source_member",
            "source_member_type",
            "aggregate_accessor",
            "aggregate_member",
            "aggregate_type",
            "coordinate_type",
            "lower_accessor",
            "lower_member",
            "upper_accessor",
            "upper_member",
            "extent_accessor",
            "source_owner_header",
            "source_accessor_header",
            "extent_header",
        },
        "inclusive-extent witness",
    )
    source = cast(Mapping[str, object], gen["source"])
    role_pairs = (
        (source["object"], witness["source_member"]),
        (source["aggregate_accessor"], witness["aggregate_accessor"]),
        (gen["seed_extent_accessor"], witness["extent_accessor"]),
        (gen["upper_endpoint_accessor"], witness["upper_accessor"]),
        (gen["lower_endpoint_accessor"], witness["lower_accessor"]),
        (gen["type"], witness["coordinate_type"]),
    )
    _need(all(left == right for left, right in role_pairs), "inclusive-extent roles differ")
    coordinate = _type_text(witness["coordinate_type"], "inclusive-extent coordinate type")
    owner = _identifier(witness["source_owner"], "inclusive-extent owner")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "inclusive-extent owner"),
        "inclusive-extent target owner differs",
    )
    _source_owner(clean_target, owner, "inclusive-extent target")
    local = cast(str, gen["id"])
    _require_identifier_fresh_at_seat(
        clean_target,
        baseline_position,
        local,
        "inclusive-extent local",
    )

    expected_specs = {
        "source_owner_header": {
            "path",
            "source_sha256",
            "unit_include_range_pin",
            "member_declaration_range_pin",
        },
        "source_accessor_header": {
            "path",
            "source_sha256",
            "owner_include_range_pin",
            "accessor_range_pin",
        },
        "extent_header": {
            "path",
            "source_sha256",
            "accessor_include_range_pin",
            "concrete_inheritance_range_pin",
            "concrete_class_range_pin",
            "lower_accessor_range_pin",
            "upper_accessor_range_pin",
            "extent_accessor_range_pin",
        },
    }
    loaded: dict[str, tuple[str, bytes, dict[str, object]]] = {}
    for name, keys in expected_specs.items():
        path, data, spec = _source(clean_sources, witness.get(name), f"inclusive {name}")
        _keys(spec, keys, f"inclusive {name}")
        _need(path not in overlaid_paths, f"inclusive witness header {path!r} is overlaid")
        loaded[name] = path, data, spec
    owner_path, owner_data, owner_spec = loaded["source_owner_header"]
    accessor_path, accessor_data, accessor_spec = loaded["source_accessor_header"]
    extent_path, extent_data, extent_spec = loaded["extent_header"]
    _require_integral_type(
        clean_sources,
        extent_path,
        coordinate,
        "inclusive-extent coordinate type",
    )
    _need(len({owner_path, accessor_path, extent_path}) == 3, "inclusive witness headers repeat")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "inclusive unit-to-owner",
    )
    _include_edge(
        clean_sources,
        owner_path,
        owner_data,
        accessor_path,
        accessor_spec["owner_include_range_pin"],
        "inclusive owner-to-accessor",
    )
    _include_edge(
        clean_sources,
        accessor_path,
        accessor_data,
        extent_path,
        extent_spec["accessor_include_range_pin"],
        "inclusive accessor-to-extent",
    )

    owner_tokens, _owner_start, owner_open, owner_close = _unique_class_body(
        owner_data, owner, "inclusive owner class"
    )
    member_range = _class_level_range(
        owner_tokens,
        owner_open,
        owner_close,
        [
            *_type_tokens(witness["source_member_type"], "inclusive source member type"),
            cast(str, witness["source_member"]),
            ";",
        ],
        "inclusive source member",
    )
    _pin(
        _line(owner_data, member_range),
        owner_spec["member_declaration_range_pin"],
        "inclusive source member",
    )
    accessor_tokens, _accessor_start, accessor_open, accessor_close = _unique_class_body(
        accessor_data, cast(str, witness["source_member_type"]), "inclusive accessor class"
    )
    accessor_range = _class_level_range(
        accessor_tokens,
        accessor_open,
        accessor_close,
        [
            cast(str, witness["aggregate_type"]),
            "&",
            cast(str, witness["aggregate_accessor"]),
            "(",
            ")",
            "{",
            "return",
            cast(str, witness["aggregate_member"]),
            ";",
            "}",
        ],
        "inclusive aggregate accessor",
    )
    _pin(
        _line(accessor_data, accessor_range),
        accessor_spec["accessor_range_pin"],
        "inclusive aggregate accessor",
    )
    aggregate_type = cast(str, witness["aggregate_type"])
    concrete_tokens, concrete_start, concrete_open, concrete_close = _unique_class_body(
        extent_data, aggregate_type, "inclusive concrete extent class"
    )
    coordinate_tokens = _type_tokens(coordinate, "inclusive coordinate type")
    inheritance_tail = [item[0] for item in concrete_tokens[concrete_start + 2 : concrete_open + 1]]
    _need(
        len(inheritance_tail) == len(coordinate_tokens) + 6
        and inheritance_tail[:2] == [":", "public"]
        and _IDENTIFIER_RE.fullmatch(inheritance_tail[2]) is not None
        and inheritance_tail[3:4] == ["<"]
        and inheritance_tail[4:-2] == coordinate_tokens
        and inheritance_tail[-2:] == [">", "{"],
        "inclusive concrete inheritance differs",
    )
    extent_template = inheritance_tail[2]
    extent_tokens, template_start, extent_open, extent_close = _unique_class_body(
        extent_data, extent_template, "inclusive extent template"
    )
    _need(
        template_start >= 5
        and [item[0] for item in extent_tokens[template_start - 5 : template_start - 2]]
        == ["template", "<", "class"]
        and _IDENTIFIER_RE.fullmatch(extent_tokens[template_start - 2][0]) is not None
        and extent_tokens[template_start - 1][0] == ">",
        "inclusive extent template declaration differs",
    )
    parameter = extent_tokens[template_start - 2][0]
    lower_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["lower_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            cast(str, witness["lower_member"]),
            ";",
            "}",
        ],
        "inclusive lower accessor",
    )
    upper_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["upper_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            cast(str, witness["upper_member"]),
            ";",
            "}",
        ],
        "inclusive upper accessor",
    )
    extent_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["extent_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            "(",
            cast(str, witness["upper_member"]),
            "-",
            cast(str, witness["lower_member"]),
            "+",
            "1",
            ")",
            ";",
            "}",
        ],
        "inclusive extent accessor",
    )
    inheritance = [
        "class",
        aggregate_type,
        ":",
        "public",
        extent_template,
        "<",
        *coordinate_tokens,
        ">",
        "{",
    ]
    _index, inheritance_start, inheritance_end = _unique_tokens(
        extent_tokens, inheritance, "inclusive concrete inheritance"
    )
    _pin(
        _line(extent_data, (inheritance_start, inheritance_end)),
        extent_spec["concrete_inheritance_range_pin"],
        "inclusive concrete inheritance",
    )
    _pin(
        _line(extent_data, lower_range),
        extent_spec["lower_accessor_range_pin"],
        "inclusive lower accessor",
    )
    _pin(
        _line(extent_data, upper_range),
        extent_spec["upper_accessor_range_pin"],
        "inclusive upper accessor",
    )
    _pin(
        _line(extent_data, extent_range),
        extent_spec["extent_accessor_range_pin"],
        "inclusive extent accessor",
    )
    _need(
        concrete_close + 1 < len(concrete_tokens) and concrete_tokens[concrete_close + 1][0] == ";",
        "inclusive concrete class terminator differs",
    )
    concrete_begin = extent_data.rfind(b"\n", 0, concrete_tokens[concrete_start][1]) + 1
    concrete_newline = extent_data.find(b"\n", concrete_tokens[concrete_close + 1][2])
    concrete_end = len(extent_data) if concrete_newline < 0 else concrete_newline + 1
    _pin(
        extent_data[concrete_begin:concrete_end],
        extent_spec["concrete_class_range_pin"],
        "inclusive concrete class",
    )
    direct = []
    depth = 1
    for token, _start, _end in concrete_tokens[concrete_open + 1 : concrete_close]:
        if depth == 1:
            direct.append(token)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
    _need(
        not set(direct).intersection(
            {
                cast(str, witness["lower_accessor"]),
                cast(str, witness["upper_accessor"]),
                cast(str, witness["extent_accessor"]),
            }
        ),
        "inclusive concrete class shadows an inherited accessor",
    )
