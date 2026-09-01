"""Classic compiler algorithms: recolouring register webs in a function body."""

from __future__ import annotations

from typing import Any

from reprobit.binary import require

from .debug import parse_codeview_symbol_stream
from .foundation import (
    require_payload_free_declaration,
)
from .register_bijection import (
    CODEVIEW_REGISTER_RECORD_TYPE,
    _codeview_register_field,
    _codeview_register_name,
)
from .register_semantics import (
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
    _bijection_form_for,
    _ia32_atom_registers,
    _ia32_backward_liveness,
    _ia32_live_out,
    decode_ia32_bijection_body,
    ia32_register_atoms,
)
from .scheduling_webs import (
    _ia32_web_membership,
    _ia32_web_predecessors,
    _ia32_web_reached_uses,
    _ia32_web_reaching_definitions,
    ia32_web_control_flow,
)


def apply_web_recolour(
    body: bytes,
    webs: list[dict[str, Any]],
    relocation_offsets: frozenset[int],
    context: str,
    relocations: dict[int, Any] | None = None,
    code_length: int | None = None,
    internal_targets: frozenset[int] | None = None,
    frame_pointer_free: bool = False,
    entry_offsets: frozenset[int] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Recolour each declared web, proving W1..W7 on the body it is given.

    Webs are applied in order and each one's proof is measured on the body the
    previous ones produced, so a certificate that declares several is a
    composition of individually proved steps.
    """
    require_payload_free_declaration(webs, f"{context} web-recolour declaration")
    body = bytes(body)
    image = bytes(body)
    detail = []
    rewritten_all = []
    instruction_count = None
    for position, web in enumerate(webs):
        web_context = f"{context} web {position}"
        instructions = decode_ia32_bijection_body(image, web_context, relocations, code_length)
        instruction_count = len(instructions)
        successors = ia32_web_control_flow(
            instructions, web_context, internal_targets, entry_offsets
        )
        predecessors = _ia32_web_predecessors(successors)
        index_of = {item["offset"]: index for index, item in enumerate(instructions)}
        source = web["source_register"]
        target = web["image_register"]
        require(
            source in _IA32_REGISTER_NUMBERS
            and target in _IA32_REGISTER_NUMBERS
            and (source != target),
            f"{web_context}: the recolour names an unknown register",
        )
        structural = {"esp"} if frame_pointer_free else _IA32_STRUCTURAL_REGISTERS
        require(
            not {source, target} & structural,
            f"{web_context}: the recolour touches "
            + ("ESP" if frame_pointer_free else "ESP or EBP")
            + ", whose encodings carry ModRM/SIB structure",
        )
        source_atoms = ia32_register_atoms({source})
        target_atoms = ia32_register_atoms({target})
        source_number = _IA32_REGISTER_NUMBERS[source]
        target_number = _IA32_REGISTER_NUMBERS[target]
        definition_offsets, field_scopes = _ia32_web_membership(web, "definitions", web_context)
        use_offsets, use_scopes = _ia32_web_membership(web, "uses", web_context)
        for offset, ordinal in use_scopes.items():
            require(offset not in field_scopes, f"{web_context} scopes {offset} twice")
            field_scopes[offset] = ordinal
        for role, offsets in (("definitions", definition_offsets), ("uses", use_offsets)):
            for offset in offsets:
                require(
                    offset in index_of,
                    f"{web_context}: {role} names {offset}, which is not an instruction boundary of this body",
                )
        definitions = [index_of[offset] for offset in definition_offsets]
        uses = [index_of[offset] for offset in use_offsets]
        through = set(definitions) & set(uses)
        for index in sorted(through):
            item = instructions[index]
            require(
                source_atoms <= item["read_atoms"] and source_atoms <= item["write_atoms"],
                f"{web_context}: the instruction at {item['offset']} is declared as both a definition and a use but does not read and write the whole register",
            )
            require(
                item["offset"] not in field_scopes,
                f"{web_context}: the read-modify-write node at {item['offset']} carries the whole web, so it cannot also be field-scoped",
            )
        for index in definitions:
            item = instructions[index]
            require(
                source_atoms <= item["write_atoms"],
                f"{web_context}: the declared definition at {item['offset']} does not define the whole register",
            )
            require(
                not source_atoms & item["read_atoms"]
                or item["offset"] in field_scopes
                or index in through,
                f"{web_context}: the declared definition at {item['offset']} also reads the source register",
            )
            require(
                target not in item["writes"],
                f"{web_context}: the declared definition at {item['offset']} already writes the image register",
            )
        for index in uses:
            item = instructions[index]
            require(
                source_atoms <= item["read_atoms"]
                and (
                    not source_atoms & item["write_atoms"]
                    or item["offset"] in field_scopes
                    or index in through
                ),
                f"{web_context}: the declared use at {item['offset']} does not read the whole register without defining it",
            )
            require(
                target not in item["reads"] and target not in item["writes"],
                f"{web_context}: the declared use at {item['offset']} already names the image register",
            )
        reached, forward = _ia32_web_reached_uses(
            instructions, successors, definitions, source_atoms, web_context
        )
        require(
            reached == set(uses),
            f"{web_context}: the definitions reach the uses at {sorted(instructions[index]['offset'] for index in reached)}, which is not the declared use set",
        )
        reaching, backward = _ia32_web_reaching_definitions(
            instructions, predecessors, uses, source_atoms, web_context
        )
        require(
            reaching == set(definitions),
            f"{web_context}: the uses are reached by the definitions at {sorted(instructions[index]['offset'] for index in reaching)}, which is not the declared definition set",
        )
        interior = forward & backward | set(uses)
        live = _ia32_backward_liveness(instructions, successors, web_context)
        for index in definitions:
            leaking = target_atoms & _ia32_live_out(live, successors, index)
            require(
                not leaking,
                f"{web_context}: {_ia32_atom_registers(leaking)} is live on an out-edge of the definition at {instructions[index]['offset']}, so the two live ranges overlap and cannot be coalesced",
            )
        for index in sorted(interior):
            item = instructions[index]
            if index in uses:
                require(
                    not target_atoms & item["write_atoms"],
                    f"{web_context}: the use at {item['offset']} defines the image register",
                )
                continue
            touching = target_atoms & (item["read_atoms"] | item["write_atoms"])
            require(
                not touching,
                f"{web_context}: the instruction at {item['offset']} names {_ia32_atom_registers(touching)} inside the web's live range",
            )
            leaking = target_atoms & live[index]
            require(
                not leaking,
                f"{web_context}: {_ia32_atom_registers(leaking)} is live at {item['offset']}, inside the web's live range",
            )
        blind = _ia32_backward_liveness(
            instructions, successors, web_context, {index: source_atoms for index in uses}
        )
        for index in definitions:
            leaking = source_atoms & _ia32_live_out(blind, successors, index)
            require(
                not leaking,
                f"{web_context}: {_ia32_atom_registers(leaking)} still has a consumer outside the web at {instructions[index]['offset']}",
            )
        buffer = bytearray(image)
        rewritten = []
        for index in sorted(set(definitions) | set(uses)):
            item = instructions[index]
            blocked = {source, target} & set(item.get("frozen", frozenset()))
            require(
                not blocked,
                f"{web_context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that the recolour cannot rewrite",
            )
            ordinal = field_scopes.get(item["offset"])
            if ordinal is None:
                hits = [
                    (byte_index, shift)
                    for byte_index, shift in item["fields"]
                    if buffer[byte_index] >> shift & 7 == source_number
                ]
                require(
                    len(hits) == 1 or (len(hits) > 1 and (not item["writes"])),
                    f"{web_context}: the instruction at {item['offset']} names {source} in {len(hits)} register fields, so which occurrence belongs to the web is not decidable",
                )
                if len(hits) > 1:
                    for byte_index, shift in hits[1:]:
                        buffer[byte_index] = (
                            buffer[byte_index] & ~(7 << shift) | target_number << shift
                        )
                        rewritten.append(byte_index)
                byte_index, shift = hits[0]
            else:
                require(
                    ordinal < len(item["fields"]),
                    f"{web_context}: the instruction at {item['offset']} has no register field {ordinal}",
                )
                byte_index, shift = item["fields"][ordinal]
                require(
                    buffer[byte_index] >> shift & 7 == source_number,
                    f"{web_context}: register field {ordinal} at {item['offset']} does not name {source}",
                )
            require(
                byte_index not in relocation_offsets,
                f"{web_context}: a rewritten byte overlaps a relocation",
            )
            buffer[byte_index] = (buffer[byte_index] & ~(7 << shift) | target_number << shift) & 255
            rewritten.append(byte_index)
        require(rewritten, f"{web_context}: the recolour rewrites nothing")
        candidate = bytes(buffer)
        require(
            len(candidate) == len(image), f"{web_context}: the recolour changed the body length"
        )
        image_instructions = decode_ia32_bijection_body(
            candidate, f"{web_context} image", relocations, code_length
        )
        require(
            [(item["offset"], item["length"]) for item in image_instructions]
            == [(item["offset"], item["length"]) for item in instructions],
            f"{web_context}: the image changed an instruction boundary",
        )
        mapping = {source: target}
        for left, right in zip(image_instructions, instructions):
            form = _bijection_form_for(right["opcode"])
            opreg = form is not None and form["opreg"] is not None
            mask = 248 if opreg else 65535
            require(
                left["opcode"] & mask == right["opcode"] & mask
                and left["flow"] == right["flow"]
                and (left["target"] == right["target"]),
                f"{web_context}: the image changed an opcode or a branch",
            )
            offset = right["offset"]
            is_definition = offset in definition_offsets
            recoloured = is_definition or offset in use_offsets
            scoped = recoloured and offset in field_scopes
            rename_reads = recoloured and (not (scoped and is_definition))
            rename_writes = recoloured and (not (scoped and (not is_definition)))
            expected_reads = frozenset(
                mapping.get(name, name) if rename_reads else name for name in right["reads"]
            )
            expected_writes = frozenset(
                mapping.get(name, name) if rename_writes else name for name in right["writes"]
            )
            require(
                left["reads"] == expected_reads and left["writes"] == expected_writes,
                f"{web_context}: the image's operand set at {right['offset']} is not the recolour's image",
            )
        changed = sorted({index for index in range(len(image)) if image[index] != candidate[index]})
        require(
            changed == sorted(set(rewritten)),
            f"{web_context}: the image changed a byte the recolour did not name",
        )
        require(
            changed == list(web["expected_rewritten_offsets"]),
            f"{web_context}: the rewritten offset set {changed} differs from its declaration",
        )
        entry = {
            "source_register": source,
            "image_register": target,
            "definitions": list(definition_offsets),
            "uses": list(use_offsets),
            "live_range": sorted(instructions[index]["offset"] for index in interior),
            "rewritten_offsets": changed,
        }
        if field_scopes:
            entry["field_scopes"] = {
                str(offset): ordinal for offset, ordinal in sorted(field_scopes.items())
            }
        detail.append(entry)
        rewritten_all.extend(changed)
        image = candidate
    require(image != body, f"{context}: the recolour moves nothing")
    return (
        image,
        {
            "webs": detail,
            "instruction_count": instruction_count,
            "rewritten_offsets": sorted(set(rewritten_all)),
            "code_length": len(body) if code_length is None else code_length,
        },
    )


def require_web_recolour_debug_registers(
    stream: bytes, declared: list[Any], context: str
) -> list[Any]:
    """W8.  Pin the `.debug$S` S_REGISTER record list.

    The recolour leaves the stream alone.  That is sound rather than
    optimistic because of W4 and W5: no value of the image register is live
    anywhere in the web's range, and no value of the source register survives
    a definition, so no named register local can BE the web and none can span
    it.  What is pinned here is that the record list has not changed -- a
    different allocation would produce a different one and must be re-proved.
    """
    records = parse_codeview_symbol_stream(stream, context)
    measured = []
    for record in records:
        if record["type"] != CODEVIEW_REGISTER_RECORD_TYPE:
            continue
        field_at = _codeview_register_field(record, context)
        measured.append(
            [record["name"], record["offset"], _codeview_register_name(stream, field_at, context)]
        )
    require(
        measured == [list(item) for item in declared],
        f"{context}: the S_REGISTER record list {measured} differs from its declaration",
    )
    return measured
