"""Donor-private source refactor semantics: capture, constructor-lift and private-state proofs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import PurePosixPath
from typing import cast

from reprobit.model import Digest
from reprobit.schema import (
    ClassicRecipeIntervention,
)
from reprobit.strict_json import canonical_json

from .source_refactor_semantics_schema import (
    _IDENTIFIER_RE,
    _PRIVATE_STATE_KINDS,
    SourceRefactorSemanticProof,
    _array,
    _identifier,
    _integer,
    _keys,
    _need,
    _object,
    _Operation,
    _pin,
    _safe_nonsemantic_operations,
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
    _line,
    _owner_from_mangled,
    _source_owner,
    _unique_bytes,
    _unique_class_body,
)


def _capture_fragment(gen: Mapping[str, object], *, output: bool) -> bytes:
    role = gen.get("role")
    if role == "capture_declaration":
        _keys(gen, {"k", "role", "type", "capture", "declaration_indent"}, "capture declaration")
        return (
            (
                f"{_string(gen['declaration_indent'], 'capture indentation')}"
                f"{_type_text(gen['type'], 'capture type')} "
                f"{_identifier(gen['capture'], 'capture identifier')};\n"
            ).encode("ascii")
            if output
            else b""
        )
    if role == "capture_assignment":
        _keys(gen, {"k", "role", "capture", "source", "declaration_indent"}, "capture assignment")
        return (
            (
                f"{_string(gen['declaration_indent'], 'capture indentation')}"
                f"{_identifier(gen['capture'], 'capture identifier')} = "
                f"{_identifier(gen['source'], 'capture source')};\n"
            ).encode("ascii")
            if output
            else b""
        )
    if role == "read_reseat":
        _keys(gen, {"k", "role", "capture", "source", "nl"}, "capture read reseat")
        _need(gen["nl"] is False, "capture read reseat must be unterminated")
        value = gen["capture"] if output else gen["source"]
        return _identifier(value, "capture read identity").encode("ascii")
    if role == "return_to_goto":
        _keys(gen, {"k", "role", "source", "label", "nl"}, "capture return branch")
        _need(gen["nl"] is False, "capture return branch must be unterminated")
        return (
            f"goto {_identifier(gen['label'], 'capture label')};"
            if output
            else f"return {_identifier(gen['source'], 'capture source')};"
        ).encode("ascii")
    _need(role == "tail_return", "capture tail role differs")
    _keys(gen, {"k", "role", "capture", "label", "declaration_indent"}, "capture tail return")
    if not output:
        return b""
    return (
        f"\n{_identifier(gen['label'], 'capture label')}:\n"
        f"{_string(gen['declaration_indent'], 'capture indentation')}"
        f"return {_identifier(gen['capture'], 'capture identifier')};\n"
    ).encode("ascii")


def _prove_capture(
    clean_target: bytes,
    donor_target: bytes,
    clean_unit: bytes,
    semantic_operations: Sequence[_Operation],
    clean_positions: Mapping[str, int],
) -> None:
    roles: dict[str, Mapping[str, object]] = {}
    donor_positions: dict[str, int] = {}
    for operation in semantic_operations:
        _need(len(operation.leaves) == 1, "capture operation must carry one generator")
        gen = operation.leaves[0]
        _need(gen.get("k") == "capture_tail", "capture operation kind differs")
        role = cast(str, gen.get("role"))
        _need(role not in roles, f"capture role repeats: {role!r}")
        expected_action = "replace" if role in {"read_reseat", "return_to_goto"} else "insert"
        _need(operation.action == expected_action, f"capture role {role!r} action differs")
        seed_fragment = _capture_fragment(gen, output=False)
        donor_fragment = _capture_fragment(gen, output=True)
        if seed_fragment:
            # The exact removed bytes are authenticated by the renderer
            # receipt.  Requiring their typed digest avoids pretending that a
            # common identifier must be globally unique in the function.
            removed = _object(operation.value.get("removed"), f"capture removed role {role}")
            _need(
                removed.get("sha256") == sha256(seed_fragment).hexdigest()
                and removed.get("size") == len(seed_fragment),
                f"capture seed role {role} differs",
            )
        # Common one-token fragments need not be unique.  The clean anchor
        # receipt supplies their authoritative order; the full donor target
        # pin and fragment digest still authenticate the rendered side.
        _need(donor_fragment in donor_target, f"capture donor role {role} is absent")
        donor_positions[role] = clean_positions[cast(str, operation.operation_id)]
        roles[role] = gen
    ordered = [
        "capture_declaration",
        "capture_assignment",
        "read_reseat",
        "return_to_goto",
        "tail_return",
    ]
    _need(set(roles) == set(ordered), "capture role set is incomplete")
    _need(
        [donor_positions[role] for role in ordered] == sorted(donor_positions.values()),
        "capture roles are reordered",
    )
    declaration, assignment, read, branch, tail = (roles[role] for role in ordered)
    capture = declaration["capture"]
    source = assignment["source"]
    label = branch["label"]
    _need(
        assignment["capture"] == capture
        and read["capture"] == capture
        and tail["capture"] == capture
        and read["source"] == source
        and branch["source"] == source
        and tail["label"] == label,
        "capture identities diverge",
    )
    clean_tokens = _token_text(clean_target)
    clean_unit_tokens = _token_text(clean_unit)
    _need(
        capture not in clean_tokens
        and label not in clean_tokens
        and capture not in clean_unit_tokens,
        "capture identity is not fresh",
    )


def _ctor_call_input(gen: Mapping[str, object]) -> bytes:
    indent = cast(str, gen["declaration_indent"])
    element = cast(str, gen["element_type"])
    caller = cast(str, gen["caller_result_identifier"])
    parameter = cast(str, gen["parameter_identifier"])
    null_position = cast(int, gen["null_argument_position"])
    null_members = cast(list[object], gen["null_members"])
    arguments = ", ".join(
        "NULL" if index == null_position else caller for index in range(len(null_members) + 1)
    )
    return (
        f"{indent}{element}* {caller} = new {element}[{gen['extent_function']}({parameter}) + 1];\n"
        f"{indent}{gen['copy_function']}({caller}, {parameter});\n\n"
        f"{indent}{gen['iterator_type']} {gen['iterator_identifier']} = "
        f"{gen['container_identifier']}.{gen['find_member']}({gen['class_identifier']}({arguments}));\n"
    ).encode("ascii")


def _ctor_call_output(gen: Mapping[str, object]) -> bytes:
    return (
        f"{gen['declaration_indent']}{gen['iterator_type']} {gen['iterator_identifier']} = "
        f"{gen['container_identifier']}.{gen['find_member']}({gen['class_identifier']}({gen['parameter_identifier']}));\n"
    ).encode("ascii")


def _ctor_body_output(gen: Mapping[str, object]) -> bytes:
    lines = [
        f"\t{gen['buffer_member']} = new {gen['element_type']}["
        f"{gen['extent_function']}({gen['parameter_identifier']}) + 1];",
        f"\t{gen['copy_function']}(({gen['buffer_cast_type']}) "
        f"{gen['buffer_member']}, {gen['parameter_identifier']});",
    ]
    lines.extend(f"\t{member} = NULL;" for member in cast(list[object], gen["null_members"]))
    return ("\n{\n" + "\n".join(lines) + "\n}\n\n").encode("ascii")


_CTOR_FIELDS = {
    "k",
    "role",
    "buffer_cast_type",
    "buffer_member",
    "caller_result_identifier",
    "caller_result_type",
    "class_identifier",
    "container_identifier",
    "copy_function",
    "declaration_indent",
    "element_type",
    "extent_function",
    "find_member",
    "iterator_identifier",
    "iterator_type",
    "null_argument_position",
    "null_members",
    "parameter_identifier",
}


def _prove_constructor_lift(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    donor_unit: bytes,
    proof: Mapping[str, object],
    consumer_parameters: Mapping[str, object],
    semantic_operations: Sequence[_Operation],
    rendered_sources: Mapping[str, bytes],
) -> None:
    roles: dict[str, tuple[_Operation, Mapping[str, object]]] = {}
    for operation in semantic_operations:
        _need(len(operation.leaves) == 1, "allocation-lift operation must carry one generator")
        gen = operation.leaves[0]
        if gen.get("k") == "member_sig":
            role = (
                "class_declaration"
                if gen.get("form") == "in_class_declaration"
                else "definition_header"
            )
        else:
            _need(gen.get("k") == "ctor_alloc_lift", "allocation-lift generator differs")
            role = cast(str, gen.get("role"))
        _need(role not in roles, f"allocation-lift role repeats: {role!r}")
        roles[role] = operation, gen
    _need(
        set(roles) == {"class_declaration", "definition_header", "constructor_body", "call_site"},
        "allocation-lift role set is incomplete",
    )
    declaration_op, declaration = roles["class_declaration"]
    definition_op, definition = roles["definition_header"]
    body_op, body = roles["constructor_body"]
    call_op, call = roles["call_site"]
    _need(
        declaration_op.action == definition_op.action == body_op.action == "insert"
        and call_op.action == "replace",
        "allocation-lift operation actions differ",
    )
    _need(
        definition_op.value.get("anchor") == body_op.value.get("anchor"),
        "allocation-lift definition header and body do not share one seat",
    )
    _keys(call, _CTOR_FIELDS, "allocation-lift call site")
    _keys(body, _CTOR_FIELDS, "allocation-lift constructor body")
    call_common = {key: value for key, value in call.items() if key != "role"}
    body_common = {key: value for key, value in body.items() if key != "role"}
    _need(call_common == body_common, "allocation-lift body and call roles diverge")
    baseline = _ctor_call_input(call)
    donor_call = _ctor_call_output(call)
    donor_body = _ctor_body_output(body)
    input_start = _unique_bytes(clean_target, baseline, "allocation-lift seed form")
    _unique_bytes(donor_target, donor_call, "allocation-lift donor call")
    _unique_bytes(donor_unit, donor_body, "allocation-lift donor body")
    input_end = input_start + len(baseline)

    witness = _object(proof.get("semantic_witness"), "allocation-lift witness")
    _keys(
        witness,
        {
            "source_owner",
            "entry_class",
            "buffer_member",
            "buffer_member_type",
            "null_members",
            "null_argument_position",
            "baseline_constructor_parameter_identifiers",
            "owner_header",
            "target_parameter_range_pin",
        },
        "allocation-lift witness",
    )
    null_members = _array(witness["null_members"], "allocation-lift null members")
    _need(len(null_members) == 1, "allocation-lift must null exactly one member")
    normalized_nulls = []
    for raw in null_members:
        item = _object(raw, "allocation-lift null member")
        _keys(item, {"identifier", "type"}, "allocation-lift null member")
        normalized_nulls.append(item)
    _need(
        witness["entry_class"] == call["class_identifier"]
        and witness["buffer_member"] == call["buffer_member"]
        and witness["null_argument_position"] == call["null_argument_position"]
        and [item["identifier"] for item in normalized_nulls] == call["null_members"],
        "allocation-lift witness roles differ",
    )
    member_type = _type_text(witness["buffer_member_type"], "allocation-lift buffer member type")
    cast_type = _type_text(call["buffer_cast_type"], "allocation-lift buffer cast type")
    _need(
        member_type.startswith("const ") and member_type[6:] == cast_type,
        "allocation-lift cast is not a const strip",
    )
    owner = _identifier(witness["source_owner"], "allocation-lift source owner")
    entry_class = _identifier(witness["entry_class"], "allocation-lift entry class")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "allocation-lift owner"),
        "allocation-lift target owner differs",
    )
    _source_owner(clean_target, owner, "allocation-lift target")
    target_tokens = _significant(clean_target)
    caller = cast(str, call["caller_result_identifier"])
    expected_count = sum(token == caller for token, _, _ in _significant(baseline))
    caller_positions = [start for token, start, _ in target_tokens if token == caller]
    _need(
        expected_count > 0
        and len(caller_positions) == expected_count
        and all(input_start <= item < input_end for item in caller_positions),
        "allocation-lift removed local escapes its range",
    )
    opening = next(index for index, item in enumerate(target_tokens) if item[0] == "{")
    open_paren = next(
        (index for index in range(opening - 1, -1, -1) if target_tokens[index][0] == "("), None
    )
    _need(open_paren is not None, "allocation-lift target has no parameter list")
    depth = 0
    close_paren = None
    for index in range(cast(int, open_paren), opening):
        if target_tokens[index][0] == "(":
            depth += 1
        elif target_tokens[index][0] == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    _need(close_paren is not None, "allocation-lift parameter list is unbalanced")
    parameter = cast(str, call["parameter_identifier"])
    parameter_tokens = [
        item[0] for item in target_tokens[cast(int, open_paren) + 1 : cast(int, close_paren)]
    ]
    _need(
        parameter_tokens.count(parameter) == 1,
        "allocation-lift substituted identifier is not a target parameter",
    )
    _pin(
        _line(
            clean_target,
            (target_tokens[cast(int, open_paren)][1], target_tokens[cast(int, close_paren)][2]),
        ),
        witness["target_parameter_range_pin"],
        "allocation-lift target parameter list",
    )

    owner_path, owner_data, owner_spec = _source(
        clean_sources, witness.get("owner_header"), "allocation-lift owner header"
    )
    _keys(
        owner_spec,
        {
            "path",
            "source_sha256",
            "unit_include_range_pin",
            "class_body_range_pin",
            "buffer_member_declaration_range_pin",
            "null_member_declaration_range_pins",
            "baseline_constructor_range_pin",
            "destructor_body_range_pin",
        },
        "allocation-lift owner header",
    )
    _need(owner_path not in overlaid_paths, "allocation-lift witness header is overlaid")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "allocation-lift unit-to-owner",
    )
    owner_tokens, class_start, class_open, class_close = _unique_class_body(
        owner_data, entry_class, "allocation-lift entry class"
    )
    class_begin = owner_data.rfind(b"\n", 0, owner_tokens[class_start][1]) + 1
    class_newline = owner_data.find(b"\n", owner_tokens[class_close][2])
    _need(class_newline >= 0, "allocation-lift entry class line is unterminated")
    _pin(
        owner_data[class_begin : class_newline + 1],
        owner_spec["class_body_range_pin"],
        "allocation-lift entry class",
    )
    buffer_range = _class_level_range(
        owner_tokens,
        class_open,
        class_close,
        [
            *_type_tokens(member_type, "allocation-lift buffer type"),
            cast(str, witness["buffer_member"]),
            ";",
        ],
        "allocation-lift buffer member",
    )
    _pin(
        _line(owner_data, buffer_range),
        owner_spec["buffer_member_declaration_range_pin"],
        "allocation-lift buffer member",
    )
    null_pins = _array(
        owner_spec["null_member_declaration_range_pins"], "allocation-lift null member pins"
    )
    _need(len(null_pins) == len(normalized_nulls), "allocation-lift null member pin count differs")
    for item, pin in zip(normalized_nulls, null_pins, strict=True):
        member_range = _class_level_range(
            owner_tokens,
            class_open,
            class_close,
            [
                *_type_tokens(item["type"], "allocation-lift null member type"),
                cast(str, item["identifier"]),
                ";",
            ],
            f"allocation-lift null member {item['identifier']}",
        )
        _pin(
            _line(owner_data, member_range),
            pin,
            f"allocation-lift null member {item['identifier']}",
        )
    parameter_ids = _array(
        witness["baseline_constructor_parameter_identifiers"],
        "allocation-lift constructor parameters",
    )
    _need(
        len(parameter_ids) == 2 and all(isinstance(item, str) for item in parameter_ids),
        "allocation-lift baseline constructor parameters differ",
    )
    argument_members = [
        normalized_nulls[0]
        if position == witness["null_argument_position"]
        else {"identifier": witness["buffer_member"], "type": witness["buffer_member_type"]}
        for position in range(2)
    ]
    wanted = [entry_class, "("]
    for position, member in enumerate(argument_members):
        if position:
            wanted.append(",")
        wanted.extend(_type_tokens(member["type"], "allocation-lift constructor argument type"))
        wanted.append(cast(str, parameter_ids[position]))
    wanted.extend([")", ":"])
    for position, member in enumerate(argument_members):
        if position:
            wanted.append(",")
        wanted.extend(
            [cast(str, member["identifier"]), "(", cast(str, parameter_ids[position]), ")"]
        )
    wanted.extend(["{", "}"])
    ctor_range = _class_level_range(
        owner_tokens, class_open, class_close, wanted, "allocation-lift baseline constructor"
    )
    _pin(
        _line(owner_data, ctor_range),
        owner_spec["baseline_constructor_range_pin"],
        "allocation-lift baseline constructor",
    )
    destructor_start, _destructor_end = _class_level_range(
        owner_tokens,
        class_open,
        class_close,
        ["~", entry_class, "(", ")"],
        "allocation-lift destructor",
    )
    body_open = next(
        (
            index
            for index, item in enumerate(owner_tokens)
            if item[1] >= destructor_start and item[0] == "{"
        ),
        None,
    )
    _need(body_open is not None, "allocation-lift destructor has no body")
    depth = 0
    body_close = None
    for index in range(cast(int, body_open), class_close):
        if owner_tokens[index][0] == "{":
            depth += 1
        elif owner_tokens[index][0] == "}":
            depth -= 1
            if depth == 0:
                body_close = index
                break
    _need(body_close is not None, "allocation-lift destructor is unbalanced")
    null_identifier = cast(str, normalized_nulls[0]["identifier"])
    expected_guard = [
        "if",
        "(",
        null_identifier,
        "==",
        "NULL",
        "&&",
        cast(str, witness["buffer_member"]),
        "!=",
        "NULL",
        ")",
        "{",
        "delete",
        "[",
        "]",
        "const_cast",
        "<",
        *_type_tokens(cast_type, "allocation-lift cast type"),
        ">",
        "(",
        cast(str, witness["buffer_member"]),
        ")",
        ";",
        "}",
    ]
    _need(
        [item[0] for item in owner_tokens[cast(int, body_open) + 1 : cast(int, body_close)]]
        == expected_guard,
        "allocation-lift destructor ownership guard differs",
    )
    _pin(
        owner_data[owner_tokens[cast(int, body_open)][1] : owner_tokens[cast(int, body_close)][2]],
        owner_spec["destructor_body_range_pin"],
        "allocation-lift destructor body",
    )

    signature = _object(proof.get("constructor_signature"), "allocation-lift constructor signature")
    _keys(signature, {"class_identifier", "parameters"}, "allocation-lift constructor signature")
    signature_parameters = _array(signature["parameters"], "allocation-lift signature parameters")
    _need(
        signature["class_identifier"] == entry_class and len(signature_parameters) == 1,
        "allocation-lift constructor signature differs",
    )
    signature_parameter = _object(signature_parameters[0], "allocation-lift signature parameter")
    _keys(signature_parameter, {"identifier", "type"}, "allocation-lift signature parameter")
    for member_signature, expected_form in (
        (declaration, "in_class_declaration"),
        (definition, "qualified_definition_header"),
    ):
        _need(
            member_signature.get("kind") == "constructor"
            and member_signature.get("form") == expected_form
            and member_signature.get("class_identifier") == entry_class
            and member_signature.get("member_identifier") == entry_class
            and member_signature.get("parameters") == signature_parameters,
            "allocation-lift member signature differs from its proof",
        )
    # The checked-in class must not already declare this new overload.
    signature_tokens = [
        entry_class,
        "(",
        *_type_tokens(signature_parameter["type"], "allocation-lift new parameter type"),
        cast(str, signature_parameter["identifier"]),
        ")",
    ]
    depth = 1
    overloads = 0
    for index in range(class_open + 1, class_close):
        if (
            depth == 1
            and [item[0] for item in owner_tokens[index : index + len(signature_tokens)]]
            == signature_tokens
        ):
            overloads += 1
        if owner_tokens[index][0] == "{":
            depth += 1
        elif owner_tokens[index][0] == "}":
            depth -= 1
    _need(overloads == 0, "allocation-lift constructor overload already exists")
    rendered_header = rendered_sources.get(owner_path)
    _need(rendered_header is not None, "allocation-lift rendered owner header is absent")
    rendered_tokens, _rendered_start, rendered_open, rendered_close = _unique_class_body(
        cast(bytes, rendered_header), entry_class, "allocation-lift rendered entry class"
    )
    _class_level_range(
        rendered_tokens,
        rendered_open,
        rendered_close,
        [*signature_tokens, ";"],
        "allocation-lift rendered constructor declaration",
    )
    baseline_tokens = _significant(baseline)
    called_seed = {
        token
        for index, (token, _start, _end) in enumerate(baseline_tokens)
        if _IDENTIFIER_RE.fullmatch(token)
        and index + 1 < len(baseline_tokens)
        and baseline_tokens[index + 1][0] == "("
    }
    body_tokens = _significant(donor_body)
    called_body = {
        token
        for index, (token, _start, _end) in enumerate(body_tokens)
        if _IDENTIFIER_RE.fullmatch(token)
        and index + 1 < len(body_tokens)
        and body_tokens[index + 1][0] == "("
    }
    _need(called_body <= called_seed, "allocation-lift body introduces a new call")
    local_delta = _object(
        consumer_parameters.get("local_set_delta"), "allocation-lift local-set delta"
    )
    _keys(local_delta, {"kind", "removed_records"}, "allocation-lift local-set delta")
    removed_records = _array(local_delta["removed_records"], "allocation-lift removed records")
    removed_ids = {
        _object(item, "allocation-lift removed record").get("identifier")
        for item in removed_records
    }
    _need(
        local_delta["kind"] == "removed_caller_locals_v1" and removed_ids == {caller},
        "allocation-lift local-set delta differs from its removed local",
    )


def _prove_private_state(
    *,
    donor: ClassicRecipeIntervention,
    operations: Sequence[_Operation],
    semantic_operations: Sequence[_Operation],
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    rendered_sources: Mapping[str, bytes],
) -> SourceRefactorSemanticProof:
    kinds: list[str] = []
    operation_ids: list[str] = []
    seen_paths: set[str] = set()
    for operation in semantic_operations:
        _need(
            len(operation.leaves) == 1, "private compiler-state operation must carry one generator"
        )
        gen = operation.leaves[0]
        kind = cast(str, gen.get("k"))
        _need(kind in _PRIVATE_STATE_KINDS, "private compiler-state donor mixes a source refactor")
        _need(operation.operation_id is not None, "private compiler-state operation lacks an id")
        _need(operation.path not in seen_paths, "private compiler-state header repeats")
        seen_paths.add(operation.path)
        _need(
            PurePosixPath(operation.path).suffix.casefold() in {".h", ".hh", ".hpp", ".hxx"},
            "private compiler-state mutation is not in a header",
        )
        clean = clean_sources.get(operation.path)
        rendered = rendered_sources.get(operation.path)
        _need(
            clean is not None and rendered is not None,
            "private compiler-state header bytes are absent",
        )
        local = _identifier(gen.get("id"), "private compiler-state local")
        _need(
            local not in _token_text(cast(bytes, clean)),
            "private compiler-state local is not fresh",
        )
        if kind == "dead_updates":
            _keys(gen, {"k", "id", "initial", "increment", "repeat", "nl"}, "dead-local update")
            _need(
                operation.action == "replace" and gen["nl"] is False,
                "dead-local update must replace one inline body",
            )
            removed = _object(operation.value.get("removed"), "dead-local removed range")
            _keys(removed, {"sha256", "size"}, "dead-local removed range")
            _need(
                removed == {"sha256": sha256(b"{}").hexdigest(), "size": 2},
                "dead-local update does not replace exactly '{}'",
            )
        else:
            _keys(
                gen,
                {"k", "class", "id", "initial", "increment", "repeat"},
                "default-constructor dead update",
            )
            _need(operation.action == "insert", "default-constructor dead update must be inserted")
            class_identifier = _identifier(gen["class"], "default-constructor class")
            clean_tokens, _start, clean_open, clean_close = _unique_class_body(
                cast(bytes, clean), class_identifier, "default-constructor class"
            )
            direct_constructor = 0
            depth = 1
            for index in range(clean_open + 1, clean_close):
                if (
                    depth == 1
                    and clean_tokens[index][0] == class_identifier
                    and index + 1 < clean_close
                    and clean_tokens[index + 1][0] == "("
                ):
                    direct_constructor += 1
                if clean_tokens[index][0] == "{":
                    depth += 1
                elif clean_tokens[index][0] == "}":
                    depth -= 1
            _need(
                direct_constructor == 0, "default-constructor class already declares a constructor"
            )
            rendered_tokens, _rendered_start, rendered_open, rendered_close = _unique_class_body(
                cast(bytes, rendered), class_identifier, "rendered default-constructor class"
            )
            _class_level_range(
                rendered_tokens,
                rendered_open,
                rendered_close,
                [class_identifier, "(", ")", "{", "int", local, "="],
                "rendered default constructor",
            )
        initial = _integer(gen.get("initial"), "private compiler-state initial value")
        increment = _integer(gen.get("increment"), "private compiler-state increment")
        repeat = _integer(gen.get("repeat"), "private compiler-state repeat")
        _need(
            increment != 0
            and 0 <= repeat <= 64
            and -(1 << 31) <= initial + increment * repeat < (1 << 31),
            "private compiler-state arithmetic can overflow",
        )
        kinds.append(kind)
        operation_ids.append(cast(str, operation.operation_id))
    _safe_nonsemantic_operations(operations, frozenset(map(id, semantic_operations)), owning_source)
    statement = {
        "intervention": donor.id,
        "classification": "donor_private_compiler_state_v1",
        "generator_kinds": sorted(kinds),
        "operation_ids": sorted(operation_ids),
    }
    return SourceRefactorSemanticProof(
        donor.id,
        "donor_private_compiler_state_v1",
        tuple(sorted(kinds)),
        tuple(sorted(operation_ids)),
        Digest.from_bytes(canonical_json(statement)),
    )
